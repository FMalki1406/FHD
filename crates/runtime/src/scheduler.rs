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
use tokio::{sync::mpsc, task::JoinSet};

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
    Pause(JobId),
    Cancel(JobId),
    /// Pauses what is running and returns; queued work is handed back untouched.
    Shutdown,
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
        let mut deferred: VecDeque<(JobId, Control)> = VecDeque::new();
        let mut used = 0usize;
        let mut open = true;
        let mut stopping = false;
        loop {
            self.deliver(&mut deferred, &active);
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
                            self.finish(&mut active, &mut used, id, &result);
                            match result {
                                // The job moved: classify it and let it run on.
                                Ok(end) => {
                                    last.insert(id, Ok(end));
                                    self.enqueue(&mut queue, job);
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
                            self.finish(&mut active, &mut used, id, &Err(RunError::Invariant));
                            queue.done.push(Outcome::failed(id, RunError::Invariant));
                        }
                    }
                }
                command = commands.recv(), if open => {
                    let Some(command) = command else { open = false; continue };
                    if self.on_command(command, &mut queue, &active, &mut deferred).await {
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

    /// Releases the grant and tells the governor how the origin behaved.
    fn finish(
        &self,
        active: &mut HashMap<JobId, Active>,
        used: &mut usize,
        id: JobId,
        result: &Result<SessionEnd, RunError>,
    ) {
        let Some(entry) = active.remove(&id) else {
            return;
        };
        *used -= entry.grant;
        let now = self.clock.now_ms();
        self.governor.release(entry.origin, entry.grant, now);
        // Any other ending says nothing about the origin: the coordinator already
        // reported throttling and connection failures as they happened.
        if matches!(result, Ok(SessionEnd::Published(_))) {
            self.governor.succeeded(entry.origin, now);
        }
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
    fn deliver(&self, deferred: &mut VecDeque<(JobId, Control)>, active: &HashMap<JobId, Active>) {
        for _ in 0..deferred.len() {
            let Some((id, control)) = deferred.pop_front() else {
                break;
            };
            match active.get(&id) {
                Some(entry) if entry.control.try_send(control).is_err() => {
                    deferred.push_back((id, control))
                }
                // The session ended before the command reached it: nothing to stop.
                _ => {}
            }
        }
    }

    /// Returns true when the scheduler should stop admitting and drain.
    async fn on_command(
        &self,
        command: Command,
        queue: &mut Queue,
        active: &HashMap<JobId, Active>,
        deferred: &mut VecDeque<(JobId, Control)>,
    ) -> bool {
        let (id, control) = match command {
            Command::Admit(job) => {
                self.enqueue(queue, *job);
                return false;
            }
            Command::Shutdown => {
                for (id, entry) in active {
                    if entry.control.try_send(Control::Pause).is_err() {
                        deferred.push_back((*id, Control::Pause));
                    }
                }
                return true;
            }
            Command::Pause(id) => (id, Control::Pause),
            Command::Cancel(id) => (id, Control::Cancel),
        };
        if let Some(entry) = active.get(&id) {
            // The session owns the job: it stops itself and reports back.
            if entry.control.try_send(control).is_err() {
                deferred.push_back((id, control));
            }
            return false;
        }
        let Some(entry) = queue.remove(id) else {
            // Nobody here owns this job: say so rather than drop it silently.
            emit(Event::new(Code::CommandIgnored).for_job(id.get(), 1));
            return false;
        };
        let command = match control {
            Control::Pause => JobCommand::Pause,
            Control::Cancel => JobCommand::Cancel,
        };
        match self.coordinator.command(entry.job, command).await {
            Ok(job) => match self.settle(job).await {
                Ok(job) => queue.take(Entry {
                    job,
                    origin: entry.origin,
                }),
                Err((id, error)) => queue.done.push(Outcome::failed(id, error)),
            },
            Err(error) => queue.done.push(Outcome::failed(id, error)),
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
