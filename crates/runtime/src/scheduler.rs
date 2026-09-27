//! Decides who runs (§8). It owns admission — how many jobs at once, how many
//! connections in total, how many per origin — and the waiting: a retry deadline or
//! an origin standing down is slept through exactly, never polled.
//!
//! It never touches bytes, files or sockets. Every job transition goes through the
//! coordinator, so the decide → commit → apply path stays the only one there is.
use crate::{
    coordinator::{Clock, Control, Coordinator, RunError, SessionEnd},
    origin::OriginGovernor,
};
use fhd_app::transport::OriginId;
use fhd_domain::{Job, JobCommand, JobId, JobState};
use fhd_telemetry::{emit, Code, Event};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
};

#[derive(Clone, Copy, Debug)]
pub struct SchedulerConfig {
    /// Jobs transferring at once. Others wait in queue order.
    pub max_active: usize,
    /// Connections across every job; the engine-wide ceiling.
    pub connections: usize,
    /// Ceiling for one job, whatever the engine has spare.
    pub per_job: usize,
    /// A resident engine waits for more work instead of finishing when the queue
    /// empties; a one-shot run returns as soon as everything has settled.
    pub resident: bool,
}
impl SchedulerConfig {
    fn valid(&self) -> bool {
        (1..=4_096).contains(&self.max_active)
            && (1..=4_096).contains(&self.connections)
            && (1..=self.connections).contains(&self.per_job)
    }
}

#[derive(Debug)]
pub enum Command {
    /// A job admitted while the scheduler is already running: a resident engine
    /// takes work as it arrives, not only what it started with.
    Admit(Box<Job>),
    Pause(JobId, Option<oneshot::Sender<Applied>>),
    Cancel(JobId, Option<oneshot::Sender<Applied>>),
    /// Pauses what is running and returns; queued work is handed back untouched.
    Shutdown,
}

/// Commands a session's channel refused, waiting with the reply they owe.
type Deferred = VecDeque<(JobId, Control, Option<oneshot::Sender<Applied>>)>;

/// Callers waiting for a command a session was handed to actually take effect.
///
/// A session that is already finishing can end without reading its control
/// channel, and the command goes with the task. Answering on the hand-off
/// therefore told the client `Done` for a cancel that never happened -- CI caught
/// it on Windows, with the job resting in `NeedsAction` for 120 seconds. The reply
/// waits here until the session is reaped and the record can be consulted.
type Awaiting = HashMap<JobId, Vec<(JobCommand, oneshot::Sender<Applied>)>>;

/// Remembers a caller until the session that was handed its command has ended.
fn await_session(
    awaiting: &mut Awaiting,
    id: JobId,
    control: Control,
    reply: Option<oneshot::Sender<Applied>>,
) {
    let Some(reply) = reply else { return };
    let command = match control {
        Control::Pause => JobCommand::Pause,
        Control::Cancel => JobCommand::Cancel,
    };
    awaiting.entry(id).or_default().push((command, reply));
}

/// Whether a job actually reached where the command was taking it.
///
/// **Every site that answers a caller goes through this now.** Three of them used
/// to answer `Yes` on weaker evidence, and two independent reviews found all
/// three: a running job answered on the hand-off; a job left at `Cancelling`
/// answered because the coordinator treated that as settled; and a queued job
/// answered *before* its cleanup ran at all. A `Pause` that leaves a job in
/// `Stopping` is the same shape -- the command was accepted and the job is not
/// paused.
///
/// So the question is not "did a step succeed" but "is the job where the operator
/// asked for it to be". Anything else is `No`, which is what the IPC layer turns
/// into a failure the client can act on.
fn reached(job: &Job, command: JobCommand) -> bool {
    match command {
        JobCommand::Cancel => job.state() == JobState::Cancelled,
        JobCommand::Pause => job.state() == JobState::Paused,
        _ => false,
    }
}

/// Answers a caller once, if one is still waiting.
fn answer(reply: Option<oneshot::Sender<Applied>>, applied: Applied) {
    if let Some(reply) = reply {
        let _ = reply.send(applied);
    }
}

/// What became of an operator's command, for whoever asked.
///
/// The reply used to be sent on the strength of the channel send, so a command
/// this scheduler dropped was reported to the client as having been carried out.
/// Nothing could tell an ignored command from a done one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied {
    /// **The job is where the command asked for it to be, in the record.**
    ///
    /// This used to say "handed to the session that is running the job, which
    /// stops itself … accepted rather than finished". That was the semantics CI
    /// caught as a false report, and both reviews of the fix found the comment
    /// still publishing it. A `Yes` is now issued only after `reached` agrees with
    /// the record: `Cancelled` for a cancel, `Paused` for a pause.
    Yes,
    /// No such job, or a command its state refuses.
    No,
}

/// How one job left the scheduler, with the job as it now stands.
pub struct Outcome {
    pub id: JobId,
    /// `None` when a failure consumed the job, or left an in-memory job the
    /// repository would disagree with: reload it, the repository is the authority.
    pub job: Option<Job>,
    /// `None` for a job that never ran in this pass: shut down, or still waiting.
    pub result: Option<Result<SessionEnd, RunError>>,
}
impl Outcome {
    fn settled(job: Job) -> Self {
        Self {
            id: job.id(),
            job: Some(job),
            result: None,
        }
    }
    fn failed(id: JobId, error: RunError) -> Self {
        Self {
            id,
            job: None,
            result: Some(Err(error)),
        }
    }
}

/// A job waiting its turn, with the origin it was grouped under. Resolved once at
/// intake: an adapter that later rebinds the source must not move a live job to a
/// second bucket, where its grant would be released against the wrong one.
struct Entry {
    job: Job,
    origin: OriginId,
}

struct Active {
    control: mpsc::Sender<Control>,
    origin: OriginId,
    grant: usize,
}

pub struct Scheduler {
    coordinator: Arc<Coordinator>,
    governor: Arc<OriginGovernor>,
    clock: Arc<dyn Clock>,
    config: SchedulerConfig,
}

impl Scheduler {
    pub fn new(
        coordinator: Arc<Coordinator>,
        governor: Arc<OriginGovernor>,
        config: SchedulerConfig,
    ) -> Result<Self, RunError> {
        if !config.valid() || config.per_job > coordinator.config().connections {
            return Err(RunError::InvalidConfig);
        }
        let clock = coordinator.clock();
        Ok(Self {
            coordinator,
            governor,
            clock,
            config,
        })
    }

    /// Runs these jobs until each settles somewhere it will not leave by itself, or
    /// until `Shutdown`. Jobs are admitted in the order given; one that cannot run
    /// yet does not hold up the ones behind it. Every job given comes back exactly
    /// once, whether it ran, waited, failed or was never started.
    pub async fn run(&self, jobs: Vec<Job>, mut commands: mpsc::Receiver<Command>) -> Vec<Outcome> {
        let mut queue = Queue::default();
        let mut seen: Vec<JobId> = Vec::with_capacity(jobs.len());
        for job in jobs {
            let id = job.id();
            if seen.contains(&id) {
                // Two jobs with one identity would share admission state; the
                // second is refused rather than silently shadowing the first.
                queue.done.push(Outcome::failed(id, RunError::Invariant));
                continue;
            }
            seen.push(id);
            match self.settle(job).await {
                Ok(job) => self.enqueue(&mut queue, job),
                Err((id, error)) => queue.done.push(Outcome::failed(id, error)),
            }
        }
        let mut active: HashMap<JobId, Active> = HashMap::new();
        let mut owners: HashMap<tokio::task::Id, JobId> = HashMap::new();
        let mut sessions: JoinSet<(JobId, Job, Result<SessionEnd, RunError>)> = JoinSet::new();
        // How each job's last session ended. A session ending is not a job ending:
        // one that stopped to wait out a retry is classified and runs again here.
        let mut last: HashMap<JobId, Result<SessionEnd, RunError>> = HashMap::new();
        let mut deferred: Deferred = VecDeque::new();
        let mut awaiting: Awaiting = HashMap::new();
        let mut used = 0usize;
        let mut open = true;
        let mut stopping = false;
        loop {
            self.deliver(&mut deferred, &mut awaiting, &active, &mut queue)
                .await;
            let mut started = false;
            if !stopping {
                self.promote_due(&mut queue).await;
                started = self.admit(
                    &mut queue,
                    &mut active,
                    &mut owners,
                    &mut sessions,
                    &mut used,
                );
            }
            // A resident engine with nothing to do is waiting, not finished: it
            // ends only when told to stop or when no one can tell it anything.
            let waiting = self.config.resident && open;
            if sessions.is_empty() && (stopping || (queue.idle() && !waiting)) {
                break;
            }
            let deadline = self.next_deadline(&queue);
            // Nothing runs, nothing started, and no moment exists at which that
            // could change. Waiting on a command that may never come would strand
            // the queue, so it is handed back instead.
            if sessions.is_empty() && !started && deadline.is_none() && !waiting {
                break;
            }
            tokio::select! { biased;
                finished = sessions.join_next(), if !sessions.is_empty() => {
                    let Some(finished) = finished else { continue };
                    match finished {
                        Ok((id, job, result)) => {
                            let settled = self
                                .finish(&mut active, &mut awaiting, &mut used, id, &result)
                                .await;
                            match result {
                                // The job moved: classify it and let it run on. The
                                // record's copy wins over the session's wherever
                                // answering a caller moved it.
                                Ok(end) => {
                                    last.insert(id, Ok(end));
                                    self.enqueue(&mut queue, settled.unwrap_or(job));
                                }
                                // A failed session proves nothing about the job: the
                                // commit that failed is what the repository holds.
                                Err(error) => queue.done.push(Outcome::failed(id, error)),
                            }
                        }
                        Err(error) => {
                            // A session task is never aborted from here, so this is a
                            // panic. Only that job is lost; its peers keep running.
                            let Some(id) = owners.remove(&error.id()) else { continue };
                            self.finish(&mut active, &mut awaiting, &mut used, id, &Err(RunError::Invariant)).await;
                            queue.done.push(Outcome::failed(id, RunError::Invariant));
                        }
                    }
                }
                command = commands.recv(), if open => {
                    let Some(command) = command else { open = false; continue };
                    if self.on_command(command, &mut queue, &active, &mut deferred, &mut awaiting).await {
                        stopping = true;
                    }
                }
                _ = self.clock.sleep_until(deadline.unwrap_or(0)), if deadline.is_some() => {}
            }
        }
        let mut done = std::mem::take(&mut queue.done);
        for entry in queue.drain() {
            done.push(Outcome::settled(entry.job));
        }
        for outcome in &mut done {
            if outcome.result.is_none() {
                outcome.result = last.remove(&outcome.id);
            }
        }
        done.sort_by_key(|outcome| outcome.id.get());
        done
    }

    /// Brings a job restored from the repository to a state the scheduler can act on.
    async fn settle(&self, job: Job) -> Result<Job, (JobId, RunError)> {
        let id = job.id();
        if matches!(
            job.state(),
            JobState::Probing | JobState::Transferring | JobState::Stopping | JobState::Cancelling
        ) {
            return match self.coordinator.recover(job).await {
                Ok(job) => Ok(job),
                // The job is gone from this pass; the repository still holds it.
                Err(error) => Err((id, error)),
            };
        }
        Ok(job)
    }

    fn enqueue(&self, queue: &mut Queue, job: Job) {
        let origin = self.coordinator.origin_of(&job);
        queue.take(Entry { job, origin });
    }

    /// Releases the grant, answers whoever was waiting, and tells the governor how
    /// the origin behaved.
    ///
    /// **Returns the job as the record now holds it, when answering changed it.**
    /// Not a convenience: answering a waiting caller can commit a transition, and
    /// the run loop enqueues the `Job` the *session* returned one line later. That
    /// copy is then a version behind, and an engineering review traced the
    /// consequence -- the repository rejects the next transition on its version
    /// check, so a job the record calls `Cancelled`, whose part has already been
    /// deleted, comes back as a failed job; or, where the session ended `Queued`,
    /// gets re-admitted and has a whole session spawned for it, opening a part for a
    /// cancelled job.
    ///
    /// Before this change `finish` wrote nothing, so a stale copy was harmless.
    /// Making it a mutator of the record is what made it matter.
    async fn finish(
        &self,
        active: &mut HashMap<JobId, Active>,
        awaiting: &mut Awaiting,
        used: &mut usize,
        id: JobId,
        result: &Result<SessionEnd, RunError>,
    ) -> Option<Job> {
        // The session is gone, so every caller that was handed to it can finally
        // be answered -- from the record, not from the hand-off. This is the whole
        // fix for the race: a session that ended without reading its channel left
        // the command undone while the client had been told `Done`.
        //
        // Done first, so that a caller is answered even if the job was never in
        // `active` (a panicked session comes through here too).
        let mut settled = None;
        for (command, reply) in awaiting.remove(&id).into_iter().flatten() {
            match self.coordinator.confirm_command(id, command).await {
                Ok(Some(job)) => {
                    let applied = if reached(&job, command) {
                        Applied::Yes
                    } else {
                        emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1));
                        Applied::No
                    };
                    // The authoritative copy, for the loop to enqueue in place of
                    // the one the session returned.
                    settled = Some(job);
                    let _ = reply.send(applied);
                }
                Ok(None) => {
                    emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1));
                    let _ = reply.send(Applied::No);
                }
                // Unknown rather than invalid; the reply is dropped.
                Err(_) => emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1)),
            }
        }
        let Some(entry) = active.remove(&id) else {
            return settled;
        };
        *used -= entry.grant;
        let now = self.clock.now_ms();
        self.governor.release(entry.origin, entry.grant, now);
        // Any other ending says nothing about the origin: the coordinator already
        // reported throttling and connection failures as they happened.
        if matches!(result, Ok(SessionEnd::Published(_))) {
            self.governor.succeeded(entry.origin, now);
        }
        settled
    }

    /// Moves every job whose retry deadline has passed back into the ready queue.
    async fn promote_due(&self, queue: &mut Queue) {
        let now = self.clock.now_ms();
        let waiting: Vec<Entry> = queue.waiting.drain(..).collect();
        for entry in waiting {
            if entry.job.retry_at().is_some_and(|at| at > now) {
                queue.waiting.push_back(entry);
                continue;
            }
            let id = entry.job.id();
            match self
                .coordinator
                .command(entry.job, JobCommand::RetryDue { now_tick: now })
                .await
            {
                Ok(job) => queue.take(Entry {
                    job,
                    origin: entry.origin,
                }),
                Err(error) => queue.done.push(Outcome::failed(id, error)),
            }
        }
    }

    /// Starts every ready job the caps allow, in queue order, skipping the ones an
    /// origin is not taking now. A skipped job keeps its place. Returns whether any
    /// session started, which is what tells the loop progress is still possible.
    fn admit(
        &self,
        queue: &mut Queue,
        active: &mut HashMap<JobId, Active>,
        owners: &mut HashMap<tokio::task::Id, JobId>,
        sessions: &mut JoinSet<(JobId, Job, Result<SessionEnd, RunError>)>,
        used: &mut usize,
    ) -> bool {
        let now = self.clock.now_ms();
        let mut skipped = VecDeque::new();
        let mut started = false;
        while let Some(entry) = queue.ready.pop_front() {
            let spare = self.config.connections.saturating_sub(*used);
            if active.len() >= self.config.max_active || spare == 0 {
                skipped.push_back(entry);
                break;
            }
            let grant = self
                .governor
                .admit(entry.origin, self.config.per_job.min(spare), now);
            if grant == 0 {
                skipped.push_back(entry);
                continue;
            }
            let (id, origin) = (entry.job.id(), entry.origin);
            let (control, receiver) = mpsc::channel(4);
            active.insert(
                id,
                Active {
                    control,
                    origin,
                    grant,
                },
            );
            *used += grant;
            started = true;
            let coordinator = self.coordinator.clone();
            let job = entry.job;
            let handle = sessions.spawn(async move {
                let (job, result) = coordinator.run_with(job, receiver, grant, origin).await;
                (id, job, result)
            });
            owners.insert(handle.id(), id);
        }
        while let Some(entry) = skipped.pop_back() {
            queue.ready.push_front(entry);
        }
        started
    }

    /// Retries controls a full session channel refused earlier. A stop request that
    /// was dropped would leave a job running under a shutdown that claims to stop it.
    ///
    /// The caller's reply travels with the command rather than being sent when it
    /// was first queued. A review found that a full session channel answered
    /// `Applied::Yes` immediately and then deferred the command, so a client could
    /// be told its cancel had been taken while the command was still in this
    /// queue -- and be told it even when the session ended and the command was
    /// dropped here. It is answered where it is resolved.
    async fn deliver(
        &self,
        deferred: &mut Deferred,
        awaiting: &mut Awaiting,
        active: &HashMap<JobId, Active>,
        queue: &mut Queue,
    ) {
        for _ in 0..deferred.len() {
            let Some((id, control, reply)) = deferred.pop_front() else {
                break;
            };
            match active.get(&id) {
                Some(entry) if entry.control.try_send(control).is_err() => {
                    deferred.push_back((id, control, reply));
                }
                // Handed over. **Not answered here**: the session may end without
                // reading its channel, and the command would go with it. The caller
                // waits until the session is reaped and the record decides.
                Some(_) => await_session(awaiting, id, control, reply),
                // The session ended before the command reached it. That is not
                // "nothing to stop" -- the job is now resting in the record, and
                // that is exactly where a command for a stopped job belongs.
                None => {
                    let command = match control {
                        Control::Pause => JobCommand::Pause,
                        Control::Cancel => JobCommand::Cancel,
                    };
                    match self.coordinator.command_resting(id, command).await {
                        Ok(Some(job)) => {
                            let applied = if reached(&job, command) {
                                Applied::Yes
                            } else {
                                emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1));
                                Applied::No
                            };
                            // **The queue's copy is now stale, wherever it sits.**
                            // When the session ended, the run loop put the job it
                            // returned back in the queue; this call has since moved
                            // the record.
                            //
                            // In `ready` or `waiting` that copy is admitted and runs
                            // again, for a job the record may call `Cancelled` and
                            // whose part is gone. In `done` it is worse in a quieter
                            // way: it is the value `run` hands back, so the caller is
                            // told the cancel succeeded while the run reports the job
                            // resting at `NeedsAction`. The first version of this fix
                            // covered only the first two.
                            //
                            // So a stale copy is dropped from either place and the
                            // authoritative one enqueued, which `take` routes to
                            // `done` for a terminal state and to `ready` otherwise.
                            // If the queue held no copy at all, none is added: the job
                            // was not this pass's to report.
                            let held = queue.remove(id).is_some() || queue.drop_settled(id);
                            if held {
                                self.enqueue(queue, job);
                            }
                            answer(reply, applied);
                        }
                        Ok(None) => {
                            emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1));
                            answer(reply, Applied::No);
                        }
                        // Unknown, not invalid: the record could not be read, or the
                        // transition could not be committed after part of it already
                        // was. Dropping the reply is what the IPC layer reports as
                        // unknown, and a review pointed out that calling it invalid
                        // input manufactured a false negative.
                        Err(_) => {
                            emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1));
                        }
                    }
                }
            }
        }
    }

    /// Returns true when the scheduler should stop admitting and drain.
    async fn on_command(
        &self,
        command: Command,
        queue: &mut Queue,
        active: &HashMap<JobId, Active>,
        deferred: &mut Deferred,
        awaiting: &mut Awaiting,
    ) -> bool {
        let (id, control, reply) = match command {
            Command::Admit(job) => {
                self.enqueue(queue, *job);
                return false;
            }
            Command::Shutdown => {
                for (id, entry) in active {
                    if entry.control.try_send(Control::Pause).is_err() {
                        deferred.push_back((*id, Control::Pause, None));
                    }
                }
                return true;
            }
            Command::Pause(id, reply) => (id, Control::Pause, reply),
            Command::Cancel(id, reply) => (id, Control::Cancel, reply),
        };
        if let Some(entry) = active.get(&id) {
            // The session owns the job: it stops itself and reports back. If its
            // channel is full the command waits, and so does the reply -- saying
            // `Yes` here would be a claim about a command still sitting in a
            // queue, which is what it used to be.
            if entry.control.try_send(control).is_err() {
                deferred.push_back((id, control, reply));
            } else {
                // Handed to the session, which is not the same as done -- see
                // `Awaiting`.
                await_session(awaiting, id, control, reply);
            }
            return false;
        }
        let Some(entry) = queue.remove(id) else {
            // Nobody here is running or holding this job -- but that does not
            // mean it does not exist. A job that stopped for a reason rests in
            // the record and is in neither place, and this arm used to report
            // `CommandIgnored` and return, while the client that asked was told
            // `Done`. So every `Pause`/`Cancel` for a stopped job did nothing
            // and said it had worked, which is also what left a job stopped as
            // `Unconfirmed` with no reachable way out.
            let command = match control {
                Control::Pause => JobCommand::Pause,
                Control::Cancel => JobCommand::Cancel,
            };
            match self.coordinator.command_resting(id, command).await {
                // No such job, or a command its state refuses: now the report is
                // true rather than a description of this scheduler's bookkeeping.
                Ok(Some(job)) => {
                    let applied = if reached(&job, command) {
                        Applied::Yes
                    } else {
                        emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1));
                        Applied::No
                    };
                    // **The same staleness as in `deliver`, on the path that is far
                    // easier to reach.** A command for a job whose session already
                    // settled arrives here, and `take` has parked that session's copy
                    // in `done` as the value `run` will hand back. `queue.remove` does
                    // not look there, so the record moved to `Cancelled`, the caller
                    // was told so, and `run` still reported `NeedsAction`. The reviews
                    // found it in `deliver`; it was here too.
                    if queue.drop_settled(id) {
                        self.enqueue(queue, job);
                    }
                    answer(reply, applied);
                }
                Ok(None) => {
                    emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1));
                    answer(reply, Applied::No);
                }
                Err(_) => {
                    emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1));
                }
            }
            return false;
        };
        let command = match control {
            Control::Pause => JobCommand::Pause,
            Control::Cancel => JobCommand::Cancel,
        };
        match self.coordinator.command(entry.job, command).await {
            // Answered **after** settling, against what settling produced. This
            // used to answer here, before `settle` -> `recover` had dropped the
            // part and committed `CleanupFinished`, so a queued job could be
            // reported cancelled while it rested at `Cancelling` with its part on
            // disk. A security review found that the headline claim was therefore
            // not true engine-wide, only for the running-session path.
            Ok(job) => match self.settle(job).await {
                Ok(job) => {
                    answer(
                        reply,
                        if reached(&job, command) {
                            Applied::Yes
                        } else {
                            emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1));
                            Applied::No
                        },
                    );
                    queue.take(Entry {
                        job,
                        origin: entry.origin,
                    });
                }
                // Settling failed, so what became of the command is unknown: the
                // reply is dropped rather than guessed at.
                Err((id, error)) => queue.done.push(Outcome::failed(id, error)),
            },
            // **A save that failed is not a command that was refused.**
            // `coordinator::command` can fail *after* a transition was committed --
            // a commit that succeeded and could not be confirmed, or a second step
            // in the same command that did not land. Reporting `No` turned that
            // into `ENGINE-INVALID-INPUT`: "your input was wrong" for a command
            // whose outcome nobody knows.
            //
            // So `confirm_command` is asked -- and **it does more than read.** A
            // review corrected this comment, which used to say "the record is read
            // again": `confirm_command` reloads the job, and where the record does
            // *not* already show the command taken, it **applies it again** through
            // `command_resting`. So a failed first commit is retried here, which is
            // what makes the answer true rather than merely informed.
            //
            // That retry is safe in the direction that matters. It goes through the
            // domain, so a job whose file is already published refuses the cancel --
            // `Completed` has no `Cancel` arm and `Publishing` answers
            // `PublishInProgress` -- and the refusal propagates before any part is
            // opened. Nothing of the user's is touched by the second attempt.
            //
            // If the job reached where the command was taking it, that is reported.
            // If it did not, the answer is `No` on evidence rather than on the
            // failure of a write. And if the record cannot be read or the retry
            // cannot commit either, the reply is dropped, which the IPC layer
            // reports as unknown.
            Err(error) => {
                match self.coordinator.confirm_command(id, command).await {
                    Ok(Some(job)) if reached(&job, command) => {
                        answer(reply, Applied::Yes);
                        // **And the outcome is the record's, not the first
                        // attempt's.** Pushing `Outcome::failed` below would leave
                        // `run` reporting a failure for a job the caller was told was
                        // cancelled and the record calls `Cancelled` -- the same three
                        // disagreeing answers this whole change exists to remove,
                        // reintroduced on the path that fixes one of them. A review
                        // caught it here after the earlier ones were closed.
                        //
                        // The first attempt's error is not lost: the retry is what
                        // decided the job, so the job is what is reported.
                        queue.take(Entry {
                            job,
                            origin: entry.origin,
                        });
                        return false;
                    }
                    Ok(_) => {
                        emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1));
                        answer(reply, Applied::No);
                    }
                    Err(_) => emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1)),
                }
                queue.done.push(Outcome::failed(id, error));
            }
        }
        false
    }

    /// The soonest moment anything could change: a retry falling due, or an origin
    /// being approachable again.
    fn next_deadline(&self, queue: &Queue) -> Option<u64> {
        let now = self.clock.now_ms();
        let retry = queue
            .waiting
            .iter()
            .filter_map(|entry| entry.job.retry_at())
            .filter(|at| *at > now)
            .min();
        let origin = queue
            .ready
            .iter()
            .filter_map(|entry| self.governor.ready_at(entry.origin, now))
            .min();
        match (retry, origin) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

/// Jobs the scheduler still holds: runnable now, waiting for a deadline, or done.
#[derive(Default)]
struct Queue {
    ready: VecDeque<Entry>,
    waiting: VecDeque<Entry>,
    done: Vec<Outcome>,
}
impl Queue {
    fn take(&mut self, entry: Entry) {
        match entry.job.state() {
            JobState::Queued | JobState::Verifying | JobState::Publishing => {
                self.ready.push_back(entry)
            }
            JobState::RetryWait => self.waiting.push_back(entry),
            // Anything else rests until a user or another pass says otherwise.
            _ => self.done.push(Outcome::settled(entry.job)),
        }
    }
    /// Drops a **settled** outcome for this job, saying whether there was one.
    ///
    /// `take` parks a job that rests -- `NeedsAction`, `Paused`, `Cancelled` -- in
    /// `done` as the value `run` will hand back. So a command resolved after that
    /// point leaves a stale answer there, and the first version of this fix looked
    /// only in `ready` and `waiting`: the record said `Cancelled`, the caller was
    /// told so, and `run` still reported `NeedsAction`. Two reviews caught it.
    ///
    /// A **failed** outcome is left alone. Its `result` is an error this pass
    /// genuinely produced, and replacing it would turn a reported failure into a
    /// tidy answer that nothing observed.
    fn drop_settled(&mut self, id: JobId) -> bool {
        let before = self.done.len();
        self.done
            .retain(|outcome| outcome.id != id || outcome.result.is_some());
        before != self.done.len()
    }

    fn remove(&mut self, id: JobId) -> Option<Entry> {
        for queue in [&mut self.ready, &mut self.waiting] {
            if let Some(at) = queue.iter().position(|entry| entry.job.id() == id) {
                return queue.remove(at);
            }
        }
        None
    }
    fn idle(&self) -> bool {
        self.ready.is_empty() && self.waiting.is_empty()
    }
    fn drain(&mut self) -> Vec<Entry> {
        self.ready.drain(..).chain(self.waiting.drain(..)).collect()
    }
}
