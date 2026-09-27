//! Runs one job session. The coordinator alone owns the `Job`: every transition is
//! decide → commit → apply. Workers only fetch and hand buffers to the writer lane.
//! A checkpoint is prepare_sync → sync → hash each range → commit extents → ack.
use crate::{
    buffers::{BufferPool, MAX_BUFFER},
    origin::OriginGovernor,
    writer::{Writer, WriterError},
    CancellationToken,
};
use fhd_app::{
    storage::{
        NameEvidence, Occupant, PartSpec, Publication, Published, SegmentFile, SegmentStore,
        StorageError,
    },
    transport::{OriginId, Transport, TransportError},
    CommitError, Destinations, DurableExtent, PortFuture, PublishIntent, TransferRepository,
};
use fhd_domain::{
    ByteRange, DomainError, ErrorClass, Job, JobCommand, JobState, Lease, RetryDecision,
    RetryPolicy, SegmentState, SourceRef, StopReason,
};
use fhd_telemetry::{emit, Code, Event};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::mpsc,
    task::{Id, JoinSet},
};

/// Wall-clock milliseconds (persisted retry deadlines) and caller-supplied jitter.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
    fn jitter(&self) -> u64;
    /// Waits until this wall-clock millisecond. The default reads `now_ms` once and
    /// waits the difference on the runtime timer; a test clock overrides it.
    fn sleep_until(&self, deadline_ms: u64) -> PortFuture<'_, ()> {
        let wait = deadline_ms.saturating_sub(self.now_ms());
        Box::pin(tokio::time::sleep(Duration::from_millis(wait)))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CoordinatorConfig {
    pub connections: usize,
    pub max_segments: usize,
    /// Split granularity; initial and stolen splits align to it.
    pub min_segment: u64,
    /// Written-but-unsynced bytes that trigger a checkpoint.
    pub checkpoint_bytes: u64,
    pub writer_capacity: usize,
    pub retry: RetryPolicy,
}
impl CoordinatorConfig {
    fn valid(&self) -> bool {
        (1..=16).contains(&self.connections)
            && (self.connections..=262_144).contains(&self.max_segments)
            && self.min_segment > 0
            && self.checkpoint_bytes > 0
            && (1..=256).contains(&self.writer_capacity)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]

pub enum Control {
    Pause,
    Cancel,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// The job rests in this state; the scheduler decides what happens next.
    Settled(JobState),
    /// Verified and published into the adopted folder; the job is Completed.
    ///
    /// Carries `Published` rather than a path, because "the file is in the
    /// folder you chose" and "this path reaches it" are different claims and
    /// the operator needs to be told which one holds.
    Published(fhd_app::storage::Published),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunError {
    InvalidConfig,
    NotRunnable(JobState),
    Domain(DomainError),
    /// The repository refused or could not confirm a commit. The session aborted;
    /// reload the job from the repository before any further decision.
    Commit(CommitError),
    Repository,
    Writer(WriterError),
    Storage(StorageError),
    /// Internal bookkeeping disagreed with itself; a bug, never an input problem.
    Invariant,
}

enum Failure {
    Cancelled,
    Transport(TransportError),
    Writer(WriterError),
    Panicked,
}

/// What asking about an unconfirmed job's destination established.
///
/// Three answers, not two, because "the destination does not hold it" and "this
/// is not a job that question applies to" are different things and only the
/// first is about the filesystem.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolved {
    /// The destination holds the file that was to be published, so the job is
    /// completed on that evidence.
    Published,
    /// The destination was looked at and does not hold it. **Not** evidence the
    /// file was never delivered: a folder can be renamed.
    NotAtDestination,
    /// No such job, or one this question cannot resolve -- another state,
    /// another reason, or no record of what it was about to publish. Nothing
    /// was looked at.
    NotThisJob,
}

/// Why a part is being dropped, which decides whether it may be kept.
///
/// A review warned that the retention guard would leak, because `drop_part` is
/// not only the cancel path: a publication reconciled against the destination
/// releases its part too, and a `Linked` part kept there would leave `.part` and
/// `.meta` behind on a completed job. Measured rather than assumed: that path
/// does not reach `drop_part`, because it still holds its writer and releases
/// through the lane. So the leak is not reachable today -- and the distinction
/// is made anyway, because "may this be kept?" and "why are we dropping it?" are
/// different questions and the first has no safe default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PartCleanup {
    /// A job cancelled or settled without the outcome of a publication being
    /// established. A part whose record says the link was begun is kept: it may
    /// be a second name for a file the user already has.
    Unknown,
    /// Publication was confirmed by this run. The destination holds the file and
    /// the record says so, so the part's name carries no evidence worth keeping
    /// and leaving it behind is a leak.
    Published,
}

/// The ports one coordinator drives.
#[derive(Clone)]
pub struct Ports {
    pub repository: Arc<dyn TransferRepository>,
    pub store: Arc<dyn SegmentStore>,
    pub transport: Arc<dyn Transport>,
    pub destinations: Arc<dyn Destinations>,
}

pub struct Coordinator {
    ports: Ports,
    buffers: BufferPool,
    clock: Arc<dyn Clock>,
    config: CoordinatorConfig,
    /// Told how each origin behaved. Admission is the scheduler's call, not a
    /// session's: a session that already started keeps the grant it was given.
    governor: Option<Arc<OriginGovernor>>,
}

async fn step(
    repository: &dyn TransferRepository,
    job: &mut Job,
    command: JobCommand,
) -> Result<(), RunError> {
    // **A part that may already be the user's file is not replaced, and that does not
    // depend on which reason the job is resting on.**
    //
    // The domain refuses this command for `Unconfirmed`, and every path that leaves an
    // attempt unanswered does come to rest on `Unconfirmed` -- a security review
    // checked each producer and so did I. But that is two records agreeing, not one
    // rule: a new `RequireAction` reason that forgets to join the list, or a
    // reordering that records the reason before the witness, reopens it with no test
    // failing. The review said exactly that, and it is the kind of coupling this
    // project has been caught by before.
    //
    // What makes it a rule is asking the witness itself, here, where every caller of
    // every command passes. A new generation is a new part **and the witness row goes
    // with it**, so a replacement would erase the doubt together with the only record
    // of it -- and then nothing stands between the old part and removal.
    //
    // A repository that cannot answer refuses the replacement. Not being able to ask
    // whether a part may be the user's file is not permission to start over it.
    if command == JobCommand::ReplaceRepresentation
        && repository
            .unresolved_publish_attempt(job.id(), job.generation())
            .await
            .unwrap_or(true)
    {
        // The same answer the domain gives for `Unconfirmed`, so no caller needs a
        // new case: this command is not available for this job.
        return Err(RunError::Domain(DomainError::InvalidTransition));
    }
    for event in job.decide(command).map_err(RunError::Domain)? {
        repository
            .commit_transition(event.clone())
            .await
            .map_err(RunError::Commit)?;
        job.apply(&event).map_err(RunError::Domain)?;
    }
    Ok(())
}

impl Coordinator {
    pub fn new(
        ports: Ports,
        buffers: BufferPool,
        clock: Arc<dyn Clock>,
        config: CoordinatorConfig,
    ) -> Result<Self, RunError> {
        let block = MAX_BUFFER.min(buffers.capacity());
        if !config.valid() || buffers.capacity() < config.connections * block {
            return Err(RunError::InvalidConfig);
        }
        Ok(Self {
            ports,
            buffers,
            clock,
            config,
            governor: None,
        })
    }

    /// Where this job's part file goes: beside the file it will become.
    ///
    /// Publication is a hard link, and a hard link cannot cross a volume. While
    /// every part lived under the engine's own directory, that directory decided
    /// which disk the user was allowed to download to -- put the state on `C:`
    /// and a destination on `D:` was refused before the transfer began. A part
    /// next to its destination keeps the link inside one directory, and the
    /// question stops arising.
    ///
    /// An error here is a stop, not a fallback. The port answers with an error
    /// both when the destination cannot be resolved and when the directory
    /// beside it could not be made private -- and quietly writing the part
    /// somewhere else then meant the download proceeded with the protection the
    /// caller was promised silently absent. A review measured the other half of
    /// it: with the destination's parent missing, a whole megabyte of the file
    /// landed under the state directory on another volume, and publication
    /// failed afterwards as a generic storage error. Saying so up front costs
    /// one failed job and buys a reason the operator can act on.
    fn part_directory(&self, job: &Job) -> Result<PathBuf, StorageError> {
        self.ports
            .destinations
            .parts_for(job.spec().destination())
            .map_err(|_| StorageError::InvalidInput)
    }

    /// Reports every origin outcome to this governor. Without one the coordinator
    /// still runs; only per-origin governing is then nobody's job.
    pub fn with_governor(mut self, governor: Arc<OriginGovernor>) -> Self {
        self.governor = Some(governor);
        self
    }

    pub fn clock(&self) -> Arc<dyn Clock> {
        self.clock.clone()
    }

    pub fn config(&self) -> CoordinatorConfig {
        self.config
    }

    /// The origin a job's source belongs to, as the transport adapter groups them.
    pub fn origin_of(&self, job: &Job) -> OriginId {
        self.ports.transport.origin(job.spec().source())
    }

    /// Applies one command through the same decide → commit → apply path the
    /// coordinator uses, so callers never invent a second protocol.
    pub async fn command(&self, mut job: Job, command: JobCommand) -> Result<Job, RunError> {
        step(self.ports.repository.as_ref(), &mut job, command).await?;
        Ok(job)
    }

    /// Drops a job's part through its own handle, for cases with no live writer:
    /// a publish reconciled from the destination, or a cancelled job being settled.
    /// Best effort: an orphan left behind is reported, never fatal.
    async fn drop_part(&self, job: &Job, why: PartCleanup) {
        let Some((total, _)) = job.plan() else {
            return;
        };
        // **The durable witness is asked first, before anything is opened.**
        //
        // The guard inside the blocking closure below reads the part's own state
        // byte, and that byte is one unauthenticated value in a directory beside the
        // user's download folder. A 3 (`Sealed | Attempted`) flipped to 0 (`Open`)
        // is still a legal value, so the part opens and the guard reads "nothing was
        // begun" -- and a cancel would remove a part that may be a second name for a
        // delivered file. Removing it does not take the user's file away, a hard
        // link survives either way; it destroys the only local evidence that
        // publication may have happened, which is the input to deciding what became
        // of it.
        //
        // **The publish intent cannot answer this, and the history is worth
        // keeping.** Consulting it was tried, the way `Session::may_be_published`
        // does, and it leaks: the intent is not cleared when publication is
        // definitively refused -- only on `PublishCommitted` or a generation
        // replacement -- so it is present both when the outcome is unknown *and*
        // when the linker reported that no name was created. Keeping the part
        // whenever an intent existed therefore left one behind after every ordinary
        // refusal, which `a_stopped_job_can_be_cancelled_and_an_unknown_one_is_refused`
        // measures as "a cancelled job left parts behind".
        //
        // What answers it is a witness that separates the two: an attempt is counted
        // when it begins and answered only when the linking call itself reported
        // that no name was created. "An attempt exists that was never answered" is
        // then a durable fact about *this* part, and a later attempt's refusal
        // cannot talk over an earlier attempt's silence.
        //
        // **Asked only for the cleanup that could be wrong.** After a publication this
        // run confirmed there is nothing to doubt, and reading the witness there would
        // only add a way to fail: a transient repository error would leave `.part` and
        // `.meta` behind on a completed job, which is exactly the leak `PartCleanup`
        // exists to prevent. So the question is put where its answer can matter.
        if why == PartCleanup::Unknown {
            let unresolved = self
                .ports
                .repository
                .unresolved_publish_attempt(job.id(), job.generation())
                .await;
            let keep = match unresolved {
                Ok(unresolved) => unresolved,
                // Not heard from. Nothing may be removed on the strength of a question
                // that went unanswered, and a part left behind is something the
                // operator should be able to find out about, so both facts are told.
                Err(_) => {
                    emit(
                        Event::new(Code::StorageFailed)
                            .for_job(job.id().get(), job.generation().get()),
                    );
                    true
                }
            };
            if keep {
                emit(
                    Event::new(Code::PartRetained).for_job(job.id().get(), job.generation().get()),
                );
                return;
            }
        }
        let Ok(spec) = PartSpec::new(job.id(), job.generation(), total) else {
            return;
        };
        let store = self.ports.store.clone();
        let Ok(directory) = self.part_directory(job) else {
            emit(Event::new(Code::StorageFailed).for_job(job.id().get(), job.generation().get()));
            return;
        };
        let removed = tokio::task::spawn_blocking(move || -> Result<bool, StorageError> {
            let mut file = store.open(&directory, spec)?;
            // A part whose record says the link was begun is left exactly where
            // it is -- but only when what became of that link is unknown. It may
            // be a second name for a file the user already has, and while
            // removing this name would not take the file away, it would destroy
            // the only local evidence that publication may have happened, which
            // is the input to deciding what actually became of it. A cancelled
            // job keeps nothing it downloaded; this is not that, it is a record
            // of something that may have been delivered.
            //
            // After a publication this run confirmed, there is nothing to keep
            // evidence of: the answer is known, the file is at the destination,
            // and the part's name is just a name. Keeping it there was a leak --
            // `.part` and `.meta` left behind on a completed job -- which a
            // review caught in the first version of this guard, where the reason
            // for the cleanup was not passed in and every caller got the
            // cautious answer.
            if why == PartCleanup::Unknown
                && matches!(
                    file.publication(),
                    Publication::Attempted | Publication::Linked
                )
            {
                return Ok(false);
            }
            file.abandon();
            file.discard()?;
            Ok(true)
        })
        .await;
        match removed {
            Ok(Ok(true)) => {}
            // Kept on purpose. Reported, because a part left behind after a
            // cancel is something the operator should be able to find out about.
            Ok(Ok(false)) => {
                emit(
                    Event::new(Code::PartRetained).for_job(job.id().get(), job.generation().get()),
                );
            }
            _ => emit(
                Event::new(Code::StorageFailed).for_job(job.id().get(), job.generation().get()),
            ),
        }
    }

    /// Applies an operator's command to a job no session is running.
    ///
    /// The scheduler owns what it is running and what is waiting in its queue. A
    /// job that stopped for a reason is in neither: it rests in the record. The
    /// command for such a job was being dropped -- reported as `CommandIgnored`
    /// while the client was told it had been done -- which is how `Unconfirmed`
    /// came to be a state with no way out, and `Pause`/`Cancel` came to be
    /// silently ignored for every stopped job.
    ///
    /// `Ok(None)` means no such job, which is the caller's to report. A cancel
    /// carries through its cleanup here, exactly as recovery does after a crash,
    /// because nothing else will come along to finish it.
    pub async fn command_resting(
        &self,
        id: fhd_domain::JobId,
        command: JobCommand,
    ) -> Result<Option<Job>, RunError> {
        let repository = self.ports.repository.as_ref();
        let jobs = repository
            .load_jobs()
            .await
            .map_err(|_| RunError::Repository)?;
        let Some(mut job) = jobs.into_iter().find(|job| job.id() == id) else {
            return Ok(None);
        };
        step(repository, &mut job, command).await?;
        if job.state() == JobState::Cancelling {
            // The part goes, and the record says so afterwards. A cancelled job
            // keeps nothing -- and a part that was published is a second name
            // for a file the user has, which this does not touch.
            self.drop_part(&job, PartCleanup::Unknown).await;
            step(repository, &mut job, JobCommand::CleanupFinished).await?;
        }
        Ok(Some(job))
    }

    /// Whether an operator's command has actually taken effect, applying it to a
    /// resting job when the session ended without doing so.
    ///
    /// **This exists because `Done` used to mean "the session was handed the
    /// command".** The scheduler answered the caller the moment a `Cancel` landed
    /// in a session's control channel, and a session that was already finishing
    /// could end without ever reading it -- the channel went with the task and the
    /// command with it. CI caught the race on Windows: the client was told `Done`
    /// and the job sat in `NeedsAction` for the full 120 seconds.
    ///
    /// So the answer is decided here, against the record, after the session is
    /// gone:
    ///
    /// * the session applied it -- the job already rests where the command asked
    ///   -- and the answer is yes without touching anything;
    /// * the session did not, and the job is resting, so the command is applied
    ///   here, which is where a command for a stopped job belongs anyway;
    /// * the job has published, and the domain refuses to cancel it. That is a
    ///   truthful no. **Nothing unseals and nothing of the user's is touched**:
    ///   the part is only dropped when the step actually reaches `Cancelling`, and
    ///   a part that published is a second name for a file the user already has.
    pub async fn confirm_command(
        &self,
        id: fhd_domain::JobId,
        command: JobCommand,
    ) -> Result<Option<Job>, RunError> {
        let repository = self.ports.repository.as_ref();
        let jobs = repository
            .load_jobs()
            .await
            .map_err(|_| RunError::Repository)?;
        let Some(job) = jobs.into_iter().find(|job| job.id() == id) else {
            return Ok(None);
        };
        // Already where the command was taking it. Stepping again would be
        // refused by the domain, and reporting that refusal as "your cancel did
        // not work" would be the same lie in the opposite direction.
        // `Cancelling` is **not** settled, and putting it here was a real defect.
        //
        // The first version of this treated it as settled, on the reasoning that
        // "stepping again would be refused by the domain". That reasoning was
        // wrong: `(Cancelling, Cancel)` is an accepted no-op, not a refusal. And a
        // job can be left at `Cancelling` -- a session commits it and then ends
        // before `CleanupFinished`, through a commit error, a domain error while
        // draining, or a panicked task. So the short-circuit answered `Yes` for a
        // job whose record still said `Cancelling`, with its part still on disk
        // beside the user's destination, and nothing in that pass to finish it:
        // only the next engine start would heal it through `recover`. That is
        // exactly the false report this whole change exists to stop, which an
        // engineering review demonstrated with a probe.
        //
        // Letting it fall through does the right thing by itself: `command_resting`
        // no-ops the `Cancel`, then its own `if job.state() == Cancelling` block
        // drops the part and commits `CleanupFinished` -- the same finish `recover`
        // performs after a crash.
        let settled = match command {
            JobCommand::Cancel => job.state() == JobState::Cancelled,
            JobCommand::Pause => job.state() == JobState::Paused,
            _ => false,
        };
        if settled {
            return Ok(Some(job));
        }
        self.command_resting(id, command).await
    }

    /// Answers, for a job stopped as `Unconfirmed`, whether the file is there.
    ///
    /// This is the one thing that could resolve that state and had no
    /// implementation: the contract said so, and said the operator's only exit
    /// was to cancel. The engine cannot decide it alone -- a destination that
    /// does not hold the file is not evidence it never did, because a folder can
    /// be renamed -- but it can decide it in the direction where evidence
    /// exists. If the destination holds a file of the recorded size whose digest
    /// is the recorded digest, then publication happened, and the job is
    /// completed on that evidence rather than left unknown for ever.
    ///
    /// The comparison is the same one a crash during `Publishing` already
    /// reconciles against, on the same intent, and it claims exactly what it
    /// proves: a content match, not an inode match. What it does not do is
    /// conclude anything from an absent or different file -- that stays unknown,
    /// which is the whole reason this state exists -- so `Ok(false)` means "not
    /// resolved", never "not delivered".
    pub async fn resolve_unconfirmed(&self, id: fhd_domain::JobId) -> Result<Resolved, RunError> {
        let repository = self.ports.repository.as_ref();
        let jobs = repository
            .load_jobs()
            .await
            .map_err(|_| RunError::Repository)?;
        // Each of these says something different, and answering them all with
        // one code told the caller a filesystem fact about four situations that
        // never touched the filesystem -- including a job that does not exist,
        // which every other command answers as such. A review named it as the
        // one place this surface claimed more than it had looked at.
        let Some(mut job) = jobs.into_iter().find(|job| job.id() == id) else {
            return Ok(Resolved::NotThisJob);
        };
        if job.state() != JobState::NeedsAction || job.reason() != Some(StopReason::Unconfirmed) {
            return Ok(Resolved::NotThisJob);
        }
        let Some(intent) = repository
            .publish_intent(id)
            .await
            .map_err(|_| RunError::Repository)?
            .filter(|intent| intent.generation() == job.generation())
        else {
            // No intent of this generation: nothing recorded what would have
            // been published, so there is nothing to compare against. Not a
            // statement about the destination either.
            return Ok(Resolved::NotThisJob);
        };
        let destination = self
            .ports
            .destinations
            .resolve(job.spec().destination())
            .map_err(|_| RunError::Repository)?;
        let store = self.ports.store.clone();
        let path = destination.clone();
        let size = intent.size();
        let found = tokio::task::spawn_blocking(move || store.inspect(&path, size))
            .await
            .map_err(|_| RunError::Writer(WriterError::WorkerFailed))?
            .map_err(RunError::Storage)?;
        match found {
            Some(Occupant::File { size, digest })
                if size == intent.size() && digest == intent.digest() =>
            {
                // The evidence the state was waiting for. The job completes, and
                // the part is removed: with the outcome established it is a name
                // and no longer a record of something that may have happened.
                step(repository, &mut job, JobCommand::PublishCommitted).await?;
                self.drop_part(&job, PartCleanup::Published).await;
                Ok(Resolved::Published)
            }
            // A file of another size, another content, or none at all. None of
            // those is evidence against delivery, so the state stands. This is
            // the only answer here that is about the destination.
            _ => Ok(Resolved::NotAtDestination),
        }
    }

    /// Settles a job restored after a crash (§5.2): nothing is resumed implicitly.
    pub async fn recover(&self, mut job: Job) -> Result<Job, RunError> {
        let repository = self.ports.repository.as_ref();
        match job.state() {
            JobState::Probing | JobState::Transferring | JobState::Verifying => {
                step(repository, &mut job, JobCommand::Pause).await?;
                if job.state() == JobState::Stopping {
                    step(repository, &mut job, JobCommand::WorkersDrained).await?;
                }
            }
            JobState::Stopping => {
                step(repository, &mut job, JobCommand::WorkersDrained).await?;
                // The drain lands on whichever stop target was persisted, and
                // one of them is `Verifying`: a job that had just committed its
                // last durable bytes when the crash came. That is not a state
                // anything rests in -- the service does not restore it, so the
                // job would sit there exactly as the crash left it, fully
                // downloaded and never verified. The `Pause` above is re-checked
                // for the same reason; this is the other place the same need
                // arises, and a review found it by driving the persisted form
                // through the one step this arm applies.
                if job.state() == JobState::Verifying {
                    step(repository, &mut job, JobCommand::Pause).await?;
                    if job.state() == JobState::Stopping {
                        step(repository, &mut job, JobCommand::WorkersDrained).await?;
                    }
                }
            }
            JobState::Cancelling => {
                // A cancellation interrupted by a crash still keeps nothing.
                self.drop_part(&job, PartCleanup::Unknown).await;
                let repository = self.ports.repository.as_ref();
                step(repository, &mut job, JobCommand::CleanupFinished).await?;
            }
            _ => {}
        }
        Ok(job)
    }

    /// Runs a Queued job (or re-verifies a Verifying one) until it settles.
    /// Drive the future to completion: dropping it aborts workers without draining
    /// the writer lane; use `Control::Pause` or `Control::Cancel` to stop instead.
    pub async fn run(
        &self,
        job: Job,
        control: mpsc::Receiver<Control>,
    ) -> Result<SessionEnd, RunError> {
        let origin = self.origin_of(&job);
        self.run_with(job, control, self.config.connections, origin)
            .await
            .1
    }

    /// Runs a session limited to `connections`, under the origin the caller admitted
    /// it against, and hands the job back however it ended: the scheduler decides
    /// what happens next, and needs the final state even when the session failed.
    pub async fn run_with(
        &self,
        job: Job,
        control: mpsc::Receiver<Control>,
        connections: usize,
        origin: OriginId,
    ) -> (Job, Result<SessionEnd, RunError>) {
        let state = job.state();
        if connections == 0 || connections > self.config.connections {
            return (job, Err(RunError::InvalidConfig));
        }
        if !matches!(
            state,
            JobState::Queued | JobState::Verifying | JobState::Publishing
        ) {
            return (job, Err(RunError::NotRunnable(state)));
        }
        let mut session = Session {
            c: self,
            source: job.spec().source(),
            origin,
            job,
            control,
            control_open: true,
            writer: None,
            workers: JoinSet::new(),
            leases: HashMap::new(),
            stop_workers: CancellationToken::new(),
            io: CancellationToken::new(),
            unsynced: 0,
            storage_failed: false,
            connections,
            next_worker: 0,
        };
        let result = session.drive().await;
        session.close().await;
        (session.job, result)
    }
}

struct Session<'c> {
    c: &'c Coordinator,
    source: SourceRef,
    origin: OriginId,
    job: Job,
    control: mpsc::Receiver<Control>,
    control_open: bool,
    writer: Option<Arc<Writer>>,
    workers: JoinSet<Result<(), Failure>>,
    leases: HashMap<Id, Lease>,
    /// Cancels network workers; never used for the coordinator's own writer calls.
    stop_workers: CancellationToken,
    io: CancellationToken,
    unsynced: u64,
    storage_failed: bool,
    connections: usize,
    next_worker: u64,
}

/// Numbers only: a job id, a generation, a byte count and a duration.
fn report(job: &Job, code: Code, value: u64, elapsed: Duration) {
    emit(
        Event::new(code)
            .for_job(job.id().get(), job.generation().get())
            .with_measurement(value, elapsed),
    );
}

impl Session<'_> {
    async fn step(&mut self, command: JobCommand) -> Result<(), RunError> {
        step(self.c.ports.repository.as_ref(), &mut self.job, command).await
    }

    async fn drive(&mut self) -> Result<SessionEnd, RunError> {
        if self.job.state() == JobState::Publishing {
            return self.resume_publish().await;
        }
        if self.job.state() == JobState::Verifying {
            self.open_part().await?;
            return self.verify().await;
        }
        self.step(JobCommand::Start).await?;
        let probe = loop {
            tokio::select! { biased;
                control = self.control.recv(), if self.control_open => {
                    if control.is_none() {
                        self.control_open = false;
                        continue;
                    }
                    self.on_control(control).await?;
                    return self.finish().await;
                }
                probe = self.c.ports.transport.probe(self.source) => break probe,
            }
        };
        let probe = match probe {
            Ok(probe) => probe,
            Err(error) => {
                self.on_transport_error(error).await?;
                return self.finish().await;
            }
        };
        // Existing bytes resume only under the identical representation: same size and
        // same strong validator. Anything else, including no validator, starts over.
        let changed = self.job.plan().is_some_and(|(total, _)| {
            total != probe.total()
                || probe.validator().is_none()
                || probe.validator() != self.job.validator()
        });
        if changed {
            self.step(JobCommand::RepresentationChanged).await?;
            return self.finish().await;
        }
        // The origin answered: whatever it did before no longer counts against it.
        if let Some(governor) = &self.c.governor {
            governor.succeeded(self.origin, self.c.clock.now_ms());
        }
        if !probe.ranges() {
            self.connections = 1;
        }
        let max_segments = if probe.ranges() {
            self.c.config.max_segments
        } else {
            1
        };
        self.step(JobCommand::ProbeSucceeded {
            total: probe.total(),
            max_segments,
            validator: probe.validator(),
        })
        .await?;
        self.open_part().await?;
        if self.job.state() != JobState::Transferring {
            return self.finish().await;
        }
        self.initial_split()?;
        self.transfer().await?;
        self.finish().await
    }

    /// Creates the part, or reopens it and re-proves every durable extent by digest.
    /// Comes to rest on the reason that says a publication may have happened and
    /// nothing can say whether it did.
    ///
    /// Shared by the two places that reach it, because they must agree: one asks
    /// before the part is opened, the other after the part's own record is read.
    async fn stop_unconfirmed(&mut self) -> Result<(), RunError> {
        let command = JobCommand::RequireAction {
            reason: StopReason::Unconfirmed,
        };
        if matches!(self.job.state(), JobState::Verifying | JobState::Publishing) {
            self.step(command).await
        } else {
            self.stop_with(command).await
        }
    }

    async fn open_part(&mut self) -> Result<(), RunError> {
        let (total, _) = self
            .job
            .plan()
            .ok_or(RunError::NotRunnable(self.job.state()))?;
        let spec =
            PartSpec::new(self.job.id(), self.job.generation(), total).map_err(RunError::Domain)?;
        let extents = self
            .c
            .ports
            .repository
            .durable_extents(self.job.id())
            .await
            .map_err(|_| RunError::Repository)?;
        let store = self.c.ports.store.clone();
        let directory = self
            .c
            .part_directory(&self.job)
            .map_err(RunError::Storage)?;
        // The moment the destination folder's identity is decided, and the
        // earliest the engine can decide it: the session is opening and not one
        // byte has been written. Everything done to that folder from here on is
        // defeated, because publication names the object, not the path. What
        // happened to it *before* now is not something the engine can see -- the
        // operator gave a path, and resolving a path is all anyone can do with
        // it. The window is moved to before the transfer, not closed.
        let destination = self
            .c
            .ports
            .destinations
            .resolve(self.job.spec().destination())
            .map_err(|_| RunError::Repository)?;
        // **The durable witness is asked before the part is opened at all**, and a
        // failure to read it stops the job rather than failing the session.
        //
        // Two findings put it here rather than after the open, and an independent
        // engineering review found both.
        //
        // *Opening rewrites the other witness.* A part found `Sealed` is unsealed by
        // `open_inner`, which writes the publication byte and syncs it. So a byte
        // corrupted from 3 to 1 -- also a legal value -- would be overwritten with 0
        // by the act of opening, and the part-local evidence destroyed before
        // anything consulted the record. Two independent witnesses that can be
        // reduced to one by opening the file are one witness.
        //
        // *And `?` here was a way to strand a job.* Propagating
        // `RunError::Repository` out of a session leaves the job durably
        // `Transferring`, `Verifying` or `Publishing` with no session and no
        // operator command able to move it -- the domain refuses `Pause` and
        // `Cancel` while publishing -- until the daemon restarts. One busy database,
        // on every job start, for a question whose conservative answer already
        // exists. Every other site treats "cannot ask" as "assume the worst", and
        // now so does this one.
        if self.delivery_unresolved().await.unwrap_or(true) {
            return self.stop_unconfirmed().await;
        }
        // The publication state is read first, and carried out even when what
        // follows fails.
        //
        // It used to be read only from a part that opened, recovered every extent
        // and adopted its destination. A security review showed what that costs:
        // re-proving the extents hashes the bytes, and a mismatch is
        // `StorageError::Integrity` -- which the arm below turned into a reason a
        // resume answers by fetching the file again. So a part that had been
        // sealed and linked, whose bytes then failed their digests, was replaced
        // and published a second time. Deciding the state before any byte is
        // re-proved is what closes that, and it is the same order the review
        // recommended.
        type Opened = (
            Option<Publication>,
            Result<Box<dyn SegmentFile>, StorageError>,
        );
        let (found, opened) = tokio::task::spawn_blocking(move || -> Opened {
            let file = if extents.is_empty() {
                match store.create(&directory, spec) {
                    Err(StorageError::Conflict) => store.open(&directory, spec),
                    other => other,
                }
            } else {
                store.open(&directory, spec)
            };
            // A record that could not be read or interpreted at all. There is no
            // state to carry, and that absence is itself the thing the caller
            // needs to know.
            let mut file = match file {
                Ok(file) => file,
                Err(error) => return (None, Err(error)),
            };
            let found = file.publication();
            if !extents.is_empty() {
                for extent in extents {
                    if let Err(error) = file.recover_extent(extent.range(), extent.digest()) {
                        return (Some(found), Err(error));
                    }
                }
            }
            match file.adopt_destination(&destination) {
                Ok(()) => (Some(found), Ok(file)),
                Err(error) => (Some(found), Err(error)),
            }
        })
        .await
        .map_err(|_| RunError::Writer(WriterError::WorkerFailed))?;
        // Whether this part may already be the user's file.
        //
        // Answered from the state the part carried, which is the finer witness:
        // it distinguishes a link that never began from one whose outcome is
        // unknown. Only when no state could be read is the job record consulted
        // instead -- and that is exactly the case the record is there for.
        //
        // Consulting the record *as well* for a part whose state reads `Open` or
        // `Sealed` was tried and is wrong: an intent exists from the moment
        // publication is attempted, including attempts that were **refused and
        // observed to be refused**. A publication blocked by an occupied
        // destination leaves such an intent, and treating that as unknown would
        // strand a job whose file demonstrably never landed -- a test of that
        // case is what caught it. The state byte says `Open` there, and it is
        // right.
        // The reason this open would otherwise carry, decided here because
        // whether the second witness is worth consulting depends on it.
        let refusal = opened.as_ref().err().map(|error| match error {
            // A record this build cannot interpret. Not corruption of the
            // downloaded bytes, and not a failure of the storage itself: the
            // part is intact and unreadable, and nothing may be retried on it.
            StorageError::Superseded => StopReason::Unreadable,
            StorageError::Integrity => StopReason::Integrity,
            _ => StopReason::Storage,
        });
        let unknown = match found {
            Some(state) => matches!(state, Publication::Attempted | Publication::Linked),
            // No state was read. The job record is consulted only where the
            // reason would otherwise be answered by **fetching the file again**,
            // which is the only answer that can deliver a second copy.
            //
            // An earlier version asked it for every storage error, and an
            // engineering review showed the cost: a transient sharing violation
            // on Windows -- a virus scanner, a preview pane, a backup agent --
            // turned a resumable `Storage` stop into `Unconfirmed` for a job
            // whose own record would have said the link never began. `Storage`
            // is never replaced, so it needs no second witness; asking anyway
            // only moved resumable jobs into a state with no way out.
            //
            // Asked here rather than for every open because a record read is not
            // free. An earlier version of this comment also said `dyn SegmentFile`
            // "is not `Sync` and cannot be held across an await", which is false:
            // `SegmentFile: Send`, and the await below holds `opened` across it and
            // compiles. An engineering review pointed out that a comment this much
            // of the design rests on has to be exact. Cost is the whole reason.
            None => {
                refusal.is_some_and(|reason| reason.needs_new_representation())
                    && self.may_be_published().await?
            }
        };
        // The durable witness has already spoken, above, before this part was
        // opened: reaching here means it said there was nothing outstanding, so what
        // is left to decide is what the part's own record says. A byte corrupted to
        // `Open` gets past *this* question and is stopped by that one.
        let file = match opened {
            // A part this run found part-way through publication, or one whose
            // record cannot be read while the job record says a publication was
            // begun for these bytes. Reaching here at all means the destination
            // did not hold the file -- the reconciliation above looks there
            // first -- and that is not evidence it was never delivered: a folder
            // can be renamed. So it stops with a reason of its own rather than
            // being discovered later as a generic storage failure, and that
            // reason is the one the replacement path deliberately does not act
            // on.
            _ if unknown => {
                self.storage_failed = true;
                // This arm matches `_`, so it also catches a failed open whose
                // part had already said `Attempted`. Stopping conservatively is
                // right, but the storage error that actually happened would
                // otherwise vanish, leaving a failing disk indistinguishable
                // from an unresolved publication. It is reported, not used.
                if refusal.is_some() {
                    emit(
                        Event::new(Code::StorageFailed)
                            .for_job(self.job.id().get(), self.job.generation().get()),
                    );
                }
                return self.stop_unconfirmed().await;
            }
            Ok(file) => file,
            Err(_) => {
                self.storage_failed = true;
                let reason = refusal.unwrap_or(StopReason::Storage);
                // Two of those are reasons a resume answers by fetching the file
                // again, and neither of them says anything about publication --
                // which is the defect an independent security review found in
                // the first version of this arm. The version byte is checked
                // before the publication byte, and a corrupt record is refused
                // before either, so a part that had been sealed and linked and
                // whose record then became unreadable arrived here as "replace
                // it": fetch the whole file again and publish a second copy of
                // what the user may already hold. One byte written at offset 8 of
                // the part's record was enough to ask for that, which is the harm
                // the version bump to `\x02` was made to close.
                //
                // That case no longer reaches this arm: with no state to read,
                // `unknown` above is decided by the job record and stops the job
                // as `Unconfirmed` before this runs. What is left here is a part
                // whose state *was* read and says the link never began.
                let command = JobCommand::RequireAction { reason };
                if matches!(self.job.state(), JobState::Verifying | JobState::Publishing) {
                    self.step(command).await?;
                } else {
                    self.stop_with(command).await?;
                }
                return Ok(());
            }
        };
        let writer =
            Writer::start(file, self.c.config.writer_capacity).map_err(RunError::Writer)?;
        self.writer = Some(Arc::new(writer));
        Ok(())
    }

    /// A fresh single-segment plan is cut into aligned pieces, one per connection.
    fn initial_split(&mut self) -> Result<(), RunError> {
        let Some(map) = self.job.segments() else {
            return Ok(());
        };
        let [only] = map.segments() else {
            return Ok(());
        };
        if only.state() != SegmentState::Pending || only.range().start() != 0 {
            return Ok(());
        }
        let (mut current, total) = (only.id(), only.range().end());
        let unit = self.c.config.min_segment;
        let pieces = (total / unit).min(self.connections as u64);
        if pieces < 2 {
            return Ok(());
        }
        let size = total.div_ceil(pieces).div_ceil(unit) * unit;
        let mut at = size;
        while at < total {
            current = match self.job.split_pending(current, at) {
                Ok(right) => right,
                Err(DomainError::Capacity) => break,
                Err(error) => return Err(RunError::Domain(error)),
            };
            at += size;
        }
        Ok(())
    }

    /// Next pending segment to lease. While idle connections outnumber pending
    /// pieces, the largest pending piece is halved (aligned) instead of waiting.
    fn next_pending(&mut self) -> Result<Option<fhd_domain::SegmentId>, RunError> {
        let Some(map) = self.job.segments() else {
            return Ok(None);
        };
        let pending: Vec<_> = map
            .segments()
            .iter()
            .filter(|s| s.state() == SegmentState::Pending)
            .map(|s| (s.id(), s.range()))
            .collect();
        let Some(&(first, _)) = pending.first() else {
            return Ok(None);
        };
        let idle = self.connections - self.workers.len();
        let unit = self.c.config.min_segment;
        if let Some(&(id, range)) = pending.iter().max_by_key(|(_, r)| r.len()) {
            let mid = range.start() + (range.len() / 2).div_ceil(unit) * unit;
            if pending.len() < idle && range.len() >= 2 * unit && mid < range.end() {
                match self.job.split_pending(id, mid) {
                    Ok(right) => return Ok(Some(right)),
                    Err(DomainError::Capacity) => {}
                    Err(error) => return Err(RunError::Domain(error)),
                }
            }
        }
        Ok(Some(self.cap_lease(first)?))
    }

    /// Leases at most `max(min_segment, checkpoint_bytes)` (aligned): a cancelled or
    /// failed connection then loses at most one bounded piece, not a whole share.
    fn cap_lease(&mut self, id: fhd_domain::SegmentId) -> Result<fhd_domain::SegmentId, RunError> {
        let unit = self.c.config.min_segment;
        let cap = self.c.config.checkpoint_bytes.max(unit).div_ceil(unit) * unit;
        let Some(range) = self
            .job
            .segments()
            .and_then(|m| m.segments().iter().find(|s| s.id() == id))
            .map(|s| s.range())
        else {
            return Ok(id);
        };
        if range.len() > cap {
            match self.job.split_pending(id, range.start() + cap) {
                Ok(_) | Err(DomainError::Capacity) => {}
                Err(error) => return Err(RunError::Domain(error)),
            }
        }
        Ok(id)
    }

    fn spawn_workers(&mut self) -> Result<(), RunError> {
        while self.job.state() == JobState::Transferring && self.workers.len() < self.connections {
            let Some(id) = self.next_pending()? else {
                break;
            };
            self.next_worker += 1;
            let lease = self
                .job
                .lease_segment(id, self.next_worker)
                .map_err(RunError::Domain)?;
            let writer = self
                .writer
                .clone()
                .ok_or(RunError::Writer(WriterError::Closed))?;
            let task = fetch(
                self.c.ports.transport.clone(),
                self.source,
                self.job.validator(),
                writer,
                self.c.buffers.clone(),
                lease,
                self.stop_workers.clone(),
            );
            let handle = self.workers.spawn(task);
            self.leases.insert(handle.id(), lease);
        }
        Ok(())
    }

    fn has_unsynced(&self) -> bool {
        self.job.segments().is_some_and(|m| m.has_unsynced())
    }

    async fn transfer(&mut self) -> Result<(), RunError> {
        loop {
            self.spawn_workers()?;
            let state = self.job.state();
            if self.workers.is_empty() {
                match state {
                    JobState::Transferring => {
                        if self.has_unsynced() {
                            self.checkpoint().await?;
                            continue;
                        }
                        if self.job.segments().is_some_and(|m| m.all_durable()) {
                            self.step(JobCommand::AllSegmentsDurable).await?;
                            continue;
                        }
                        // Nothing leasable and nothing running: cannot progress.
                        return Err(RunError::Invariant);
                    }
                    _ => return Ok(()),
                }
            }
            if state == JobState::Transferring && self.unsynced >= self.c.config.checkpoint_bytes {
                self.checkpoint().await?;
            }
            tokio::select! {
                Some(done) = self.workers.join_next_with_id() => self.on_worker(done).await?,
                control = self.control.recv(), if self.control_open => self.on_control(control).await?,
            }
        }
    }

    async fn on_worker(
        &mut self,
        done: Result<(Id, Result<(), Failure>), tokio::task::JoinError>,
    ) -> Result<(), RunError> {
        let (id, outcome) = match done {
            Ok((id, outcome)) => (id, outcome),
            Err(error) => (error.id(), Err(Failure::Panicked)),
        };
        let lease = self.leases.remove(&id).ok_or(RunError::Invariant)?;
        match outcome {
            Ok(()) => {
                self.job.mark_written(lease).map_err(RunError::Domain)?;
                self.unsynced += lease.range().len();
            }
            Err(failure) => {
                self.job.release(lease).map_err(RunError::Domain)?;
                match failure {
                    Failure::Cancelled => {}
                    Failure::Transport(error) => self.on_transport_error(error).await?,
                    Failure::Writer(WriterError::Cancelled) => {}
                    Failure::Writer(_) => self.on_storage_failure().await?,
                    Failure::Panicked => {
                        self.stop_with(JobCommand::Fail {
                            reason: StopReason::Unknown,
                        })
                        .await?
                    }
                }
            }
        }
        Ok(())
    }

    async fn on_control(&mut self, control: Option<Control>) -> Result<(), RunError> {
        match control {
            None => self.control_open = false,
            Some(Control::Pause) => self.stop_with(JobCommand::Pause).await?,
            Some(Control::Cancel) => {
                self.step(JobCommand::Cancel).await?;
                self.stop_workers.cancel();
            }
        }
        Ok(())
    }

    /// Enters or raises Stopping and stops the network workers.
    async fn stop_with(&mut self, command: JobCommand) -> Result<(), RunError> {
        if matches!(
            self.job.state(),
            JobState::Probing | JobState::Transferring | JobState::Stopping
        ) {
            self.step(command).await?;
        }
        self.stop_workers.cancel();
        Ok(())
    }

    async fn on_transport_error(&mut self, error: TransportError) -> Result<(), RunError> {
        let command = match error {
            TransportError::RepresentationChanged => {
                report(&self.job, Code::SourceChanged, 0, Duration::ZERO);
                JobCommand::RepresentationChanged
            }
            TransportError::UserAction(reason) => JobCommand::RequireAction { reason },
            TransportError::Fatal(reason) => JobCommand::Fail { reason },
            TransportError::Transient | TransportError::Throttled { .. } => {
                let code = match error {
                    TransportError::Throttled { .. } => Code::RequestThrottled,
                    _ => Code::ReadTimeout,
                };
                report(&self.job, code, 0, Duration::ZERO);
                let now = self.c.clock.now_ms();
                // The governor decides what the origin may be asked next, for every
                // job on it; the retry policy only decides when this job asks again.
                if let Some(governor) = &self.c.governor {
                    match error {
                        TransportError::Throttled { retry_after_ms } => {
                            governor.throttled(self.origin, retry_after_ms, now)
                        }
                        _ => governor.failed(self.origin, now),
                    }
                }
                let (class, deadline) = match error {
                    TransportError::Throttled { retry_after_ms } => (
                        ErrorClass::Throttled,
                        retry_after_ms.map(|ms| now.saturating_add(ms)),
                    ),
                    _ => (ErrorClass::Transient, None),
                };
                match self.c.config.retry.decide(
                    class,
                    self.job.attempts().max(1),
                    now,
                    deadline,
                    self.c.clock.jitter(),
                ) {
                    Ok(RetryDecision::RetryAt(at_tick)) => JobCommand::Retry { at_tick },
                    _ => JobCommand::RequireAction {
                        reason: StopReason::Network,
                    },
                }
            }
        };
        self.stop_with(command).await
    }

    async fn on_storage_failure(&mut self) -> Result<(), RunError> {
        report(&self.job, Code::StorageFailed, 0, Duration::ZERO);
        self.storage_failed = true;
        self.stop_with(JobCommand::RequireAction {
            reason: StopReason::Storage,
        })
        .await
    }

    async fn checkpoint(&mut self) -> Result<(), RunError> {
        if !self.has_unsynced() || self.storage_failed {
            return Ok(());
        }
        let writer = self
            .writer
            .clone()
            .ok_or(RunError::Writer(WriterError::Closed))?;
        let started = Instant::now();
        let ticket = self.job.prepare_sync().map_err(RunError::Domain)?;
        if writer.sync(&self.io).await.is_err() {
            self.job.abandon_checkpoint().map_err(RunError::Domain)?;
            return self.on_storage_failure().await;
        }
        let batch = self
            .job
            .acknowledge_sync(ticket)
            .map_err(RunError::Domain)?;
        let mut extents = Vec::with_capacity(batch.ranges().len());
        for range in batch.ranges() {
            match writer.hash(*range, &self.io).await {
                Ok(digest) => extents.push(DurableExtent::new(*range, digest)),
                Err(_) => {
                    self.job.abandon_checkpoint().map_err(RunError::Domain)?;
                    return self.on_storage_failure().await;
                }
            }
        }
        // Idempotent: an ambiguous failure is retried with identical extents.
        let mut attempt = 0;
        loop {
            match self
                .c
                .ports
                .repository
                .commit_extents(batch.job(), batch.generation(), extents.clone())
                .await
            {
                Ok(()) => break,
                Err(CommitError::Unavailable) if attempt < 2 => {
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(50 * attempt)).await;
                }
                Err(error) => {
                    self.job.abandon_checkpoint().map_err(RunError::Domain)?;
                    return Err(RunError::Commit(error));
                }
            }
        }
        self.job
            .acknowledge_commit(batch)
            .map_err(RunError::Domain)?;
        report(
            &self.job,
            Code::CheckpointCommitted,
            self.job.projection().durable_bytes,
            started.elapsed(),
        );
        self.unsynced = 0;
        Ok(())
    }

    /// Drains the stop: final checkpoint (or discard if storage failed), then settle.
    async fn finish(&mut self) -> Result<SessionEnd, RunError> {
        while let Some(done) = self.workers.join_next_with_id().await {
            self.on_worker(done).await?;
        }
        while self.control_open {
            match self.control.try_recv() {
                Ok(Control::Cancel)
                    if matches!(self.job.state(), JobState::Stopping | JobState::Paused) =>
                {
                    self.step(JobCommand::Cancel).await?
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        match self.job.state() {
            JobState::Stopping => {
                if self.has_unsynced() && !self.job.representation_change_pending() {
                    if self.storage_failed {
                        self.job.discard_unsynced().map_err(RunError::Domain)?;
                    } else {
                        self.checkpoint().await?;
                        if self.storage_failed {
                            self.job.discard_unsynced().map_err(RunError::Domain)?;
                        }
                    }
                }
                self.step(JobCommand::WorkersDrained).await?;
            }
            JobState::Cancelling => {
                // Cancelled work keeps nothing it downloaded -- but a part whose
                // record says a link was begun is not only downloaded work, and
                // `drop_part` decides that.
                self.release_part(true, PartCleanup::Unknown).await;
                self.step(JobCommand::CleanupFinished).await?;
            }
            _ => {}
        }
        if self.job.state() == JobState::Verifying {
            return self.verify().await;
        }
        Ok(SessionEnd::Settled(self.job.state()))
    }

    async fn verify(&mut self) -> Result<SessionEnd, RunError> {
        let Some(writer) = self.writer.clone() else {
            return Ok(SessionEnd::Settled(self.job.state()));
        };
        // A handle that wrote nothing this session (everything was already durable)
        // has never synced, and verification requires a synced file.
        if writer.sync(&self.io).await.is_err() {
            self.step(JobCommand::RequireAction {
                reason: StopReason::Storage,
            })
            .await?;
            return Ok(SessionEnd::Settled(self.job.state()));
        }
        // The committed extents are the prior evidence this check is made
        // against. Reading them from the repository rather than from the file
        // is the whole point: verifying against a digest taken from the file a
        // moment earlier is this code checking itself.
        let record: Vec<(ByteRange, [u8; 32])> =
            match self.c.ports.repository.durable_extents(self.job.id()).await {
                Ok(extents) => extents
                    .into_iter()
                    .map(|extent| (extent.range(), extent.digest()))
                    .collect(),
                Err(_) => return Err(RunError::Repository),
            };
        match writer
            .verify(self.job.spec().expected_sha256(), record, &self.io)
            .await
        {
            Ok(digest) => self.publish(digest).await,
            Err(error) => {
                let reason = if error == WriterError::Storage(StorageError::Integrity) {
                    StopReason::Integrity
                } else {
                    StopReason::Storage
                };
                self.step(JobCommand::RequireAction { reason }).await?;
                Ok(SessionEnd::Settled(self.job.state()))
            }
        }
    }

    /// Whether publication may already have happened for the bytes this job has.
    ///
    /// Answered from the publish intent, which is recorded durably **before** the
    /// seal and before the link, lives in the job record rather than in the
    /// user's download folder, and is dropped when the generation changes. So an
    /// intent for the current generation means a publication was begun for these
    /// bytes and nothing here can say how it ended.
    ///
    /// This is deliberately not a question about the part file. The part's record
    /// sits in a directory beside the user's download folder and its publication
    /// state is one unauthenticated byte; worse, the record can fail to be read
    /// at all, and then it says nothing. A witness that survives exactly the
    /// cases where the part record cannot be trusted is the one worth consulting.
    ///
    /// A `true` answer is a refusal to replace, never a licence to unseal.
    async fn may_be_published(&self) -> Result<bool, RunError> {
        let intent = self
            .c
            .ports
            .repository
            .publish_intent(self.job.id())
            .await
            .map_err(|_| RunError::Repository)?;
        Ok(intent.is_some_and(|intent| intent.generation() == self.job.generation()))
    }

    /// Whether a publication attempt for these bytes was begun and never answered.
    ///
    /// **What `true` forbids:** opening the part for writing, linking again, and
    /// removing the part or its record. The part may be a second name for a file the
    /// user already has. It is not a licence to unseal, and it is not a claim that
    /// the file was delivered -- it is the absence of an answer, which is a
    /// different thing from either answer.
    ///
    /// A repository that cannot be read is not a `false`. Every caller either
    /// propagates that or keeps the part.
    async fn delivery_unresolved(&self) -> Result<bool, RunError> {
        self.c
            .ports
            .repository
            .unresolved_publish_attempt(self.job.id(), self.job.generation())
            .await
            .map_err(|_| RunError::Repository)
    }

    /// Records the intent, then renames without replacing. A conflict or a crash is
    /// reconciled against the destination, never by overwriting it.
    async fn publish(&mut self, digest: [u8; 32]) -> Result<SessionEnd, RunError> {
        let size = self.job.plan().map_or(0, |(total, _)| total);
        let previous = self
            .c
            .ports
            .repository
            .publish_intent(self.job.id())
            .await
            .map_err(|_| RunError::Repository)?;
        let attempt = previous.map_or(1, |intent| intent.attempt().saturating_add(1));
        let intent =
            PublishIntent::new(self.job.id(), self.job.generation(), attempt, size, digest);
        self.c
            .ports
            .repository
            .record_publish_intent(intent)
            .await
            .map_err(RunError::Commit)?;
        self.step(JobCommand::VerificationPassed).await?;
        self.attempt_publish(intent).await
    }

    /// Restarted while Publishing: the rename may or may not have happened.
    async fn resume_publish(&mut self) -> Result<SessionEnd, RunError> {
        let Some(intent) = self
            .c
            .ports
            .repository
            .publish_intent(self.job.id())
            .await
            .map_err(|_| RunError::Repository)?
        else {
            // Publishing without a recorded intent: nothing proves what was renamed.
            self.step(JobCommand::RequireAction {
                reason: StopReason::Storage,
            })
            .await?;
            return Ok(SessionEnd::Settled(self.job.state()));
        };
        self.attempt_publish(intent).await
    }

    async fn attempt_publish(&mut self, intent: PublishIntent) -> Result<SessionEnd, RunError> {
        if intent.generation() != self.job.generation() {
            // An intent of an older representation proves nothing about these bytes.
            return self.publish_blocked(StopReason::Storage).await;
        }
        let destination = self
            .c
            .ports
            .destinations
            .resolve(self.job.spec().destination())
            .map_err(|_| RunError::Repository)?;
        match self.occupant(&destination, intent.size()).await? {
            // Our own bytes: the rename happened before the crash.
            //
            // `At` is claimed on different evidence here than after a live
            // publication, and the difference is worth naming. There, the path
            // is compared with the published handle by object identity. Here,
            // no handle survived the crash, so what is checked is that the file
            // at the path has the size and digest the intent recorded -- the
            // path leads to a file whose bytes are the proved bytes, which is
            // what `At` promises an operator. It is not weaker in what it
            // claims; it is a content match rather than an inode match, and a
            // reader who assumes otherwise would be wrong about which
            // substitutions it excludes.
            Some(Occupant::File { size, digest })
                if size == intent.size() && digest == intent.digest() =>
            {
                self.step(JobCommand::PublishCommitted).await?;
                // This handle never published, but the bytes are at the
                // destination and the record now says so: the outcome is known,
                // so the part's name is removed rather than kept as evidence.
                self.release_part(true, PartCleanup::Published).await;
                report(&self.job, Code::JobCompleted, intent.size(), Duration::ZERO);
                return Ok(SessionEnd::Published(Published::At(destination)));
            }
            Some(_) => return self.publish_blocked(StopReason::Destination).await,
            None => {}
        }
        // **Before a writable part is opened, and before a second name is made.**
        //
        // An unanswered attempt means this part may already be a name for the user's
        // file. Re-proving the bytes reads it, which is harmless; opening it for
        // writing and linking it again are not, and both are below this line. The
        // way out is the reconciliation just above -- a file at the destination with
        // the recorded size and digest commits the publication and clears the
        // witness. Reaching here means that did not happen, and the absence of a
        // file at the requested path is not evidence of non-delivery: the folder can
        // have been renamed after the file was put in it, which is what
        // `Unconfirmed` exists to say.
        //
        // A read that fails is a doubt, not a failed session: `?` here left the job
        // durably `Publishing` with nothing able to move it, which an engineering
        // review traced and which the line 40 below already gets right for the
        // witness's other operation.
        if self.delivery_unresolved().await.unwrap_or(true) {
            return self.publish_blocked(StopReason::Unconfirmed).await;
        }
        // A handle opened in this session never verified these bytes; a handle
        // reopened after a crash must prove them again before any rename.
        let reopened = self.writer.is_none();
        if reopened {
            self.open_part().await?;
        }
        let Some(writer) = self.writer.clone() else {
            return Ok(SessionEnd::Settled(self.job.state()));
        };
        if reopened {
            if writer.sync(&self.io).await.is_err() {
                return self.publish_blocked(StopReason::Storage).await;
            }
            let record: Vec<(ByteRange, [u8; 32])> =
                match self.c.ports.repository.durable_extents(self.job.id()).await {
                    Ok(extents) => extents
                        .into_iter()
                        .map(|extent| (extent.range(), extent.digest()))
                        .collect(),
                    Err(_) => return Err(RunError::Repository),
                };
            match writer
                .verify(self.job.spec().expected_sha256(), record, &self.io)
                .await
            {
                Ok(digest) if digest == intent.digest() => {}
                Ok(_) | Err(WriterError::Storage(StorageError::Integrity)) => {
                    return self.publish_blocked(StopReason::Integrity).await
                }
                Err(_) => return self.publish_blocked(StopReason::Storage).await,
            }
        }
        // Durable before the link, and the count is what makes a crash decidable:
        // without it, an interrupted publication is indistinguishable from one that
        // never began, and every one of them would have to be treated as possibly
        // delivered.
        if self
            .c
            .ports
            .repository
            .begin_publish_attempt(self.job.id(), self.job.generation())
            .await
            .is_err()
        {
            // Refusing to record that an attempt is beginning is refusing to begin
            // it. Linking with nothing durable saying an attempt was under way would
            // create exactly the silence this record exists to break.
            return self.publish_blocked(StopReason::Storage).await;
        }
        match writer.publish(&self.io).await {
            Ok(outcome) => {
                self.step(JobCommand::PublishCommitted).await?;
                self.release_part(false, PartCleanup::Published).await;
                report(&self.job, Code::JobCompleted, intent.size(), Duration::ZERO);
                Ok(SessionEnd::Published(outcome))
            }
            Err(failed) => {
                // **Answered only from the linking call's own answer.** `NoneCreated`
                // is set where the name would have been made -- the linker refused,
                // or the path never reached it -- and never inferred from the error
                // being returned, because publication records a state, syncs the
                // file and syncs the folder *after* the link returns, and a failure
                // in any of those is an error for a name that exists.
                // Whether the record now accounts for every attempt begun. Until it
                // does, the job must rest on the reason that says a publication may
                // have happened -- not on the reason this refusal would suggest.
                let settled = if failed.name() == NameEvidence::NoneCreated {
                    // **Retried, like every other write on this path.** One busy
                    // database would otherwise make an ordinary refusal permanent:
                    // the doubt stands for ever, the part is kept for ever, and the
                    // two ways out are both closed -- reconciliation cannot succeed
                    // because nothing was linked, and a replacement is refused while
                    // a doubt stands. An engineering review traced that, and
                    // the extent commit twenty lines up already does this.
                    //
                    // Safe to repeat: the statement advances the count only from one
                    // below the number begun to that number, so a retry after an
                    // ambiguous failure either does the same thing or nothing.
                    let mut attempt = 0;
                    loop {
                        match self
                            .c
                            .ports
                            .repository
                            .resolve_publish_attempt(self.job.id(), self.job.generation())
                            .await
                        {
                            Ok(settled) => break settled,
                            Err(CommitError::Unavailable) if attempt < 2 => {
                                attempt += 1;
                                tokio::time::sleep(Duration::from_millis(50 * attempt)).await;
                            }
                            Err(_) => {
                                // The answer was reached and could not be saved, so
                                // the record goes on saying an attempt is unanswered.
                                // That is the conservative side and the correct one:
                                // nothing may act on an answer only this process ever
                                // knew, and this process is about to stop.
                                report(&self.job, Code::StorageFailed, 0, Duration::ZERO);
                                break false;
                            }
                        }
                    }
                } else {
                    false
                };
                if !settled {
                    // The record holds a doubt, whatever this attempt's answer was.
                    // Reporting the destination or the disk here would send an
                    // operator to fix something and come back to a job that still
                    // refuses to move, which is the state this reason exists to name.
                    return self.publish_blocked(StopReason::Unconfirmed).await;
                }
                match (failed.name(), failed.error()) {
                    // Nobody can say whether a name was made. Not a storage failure
                    // to retry and not a reason to fetch the file again: the one
                    // reason that blocks a resume without offering a replacement.
                    (NameEvidence::Unknown, _) => {
                        self.publish_blocked(StopReason::Unconfirmed).await
                    }
                    // Lost a race for the name, or an unrelated file appeared
                    // meanwhile.
                    (_, WriterError::Storage(StorageError::Conflict)) => {
                        self.publish_blocked(StopReason::Destination).await
                    }
                    _ => self.publish_blocked(StopReason::Storage).await,
                }
            }
        }
    }

    async fn occupant(
        &mut self,
        destination: &std::path::Path,
        expected_size: u64,
    ) -> Result<Option<Occupant>, RunError> {
        let store = self.c.ports.store.clone();
        let path = destination.to_path_buf();
        tokio::task::spawn_blocking(move || store.inspect(&path, expected_size))
            .await
            .map_err(|_| RunError::Writer(WriterError::WorkerFailed))?
            .map_err(RunError::Storage)
    }

    /// Records why publication stopped. Publishing and Verifying both accept
    /// RequireAction directly, so the job never rests in a running state.
    async fn publish_blocked(&mut self, reason: StopReason) -> Result<SessionEnd, RunError> {
        if matches!(self.job.state(), JobState::Publishing | JobState::Verifying) {
            self.step(JobCommand::RequireAction { reason }).await?;
        }
        Ok(SessionEnd::Settled(self.job.state()))
    }

    /// Drops the part file: after publication its bytes live under the final name,
    /// and for a cancelled job they are not wanted. Best effort: a part left behind
    /// is recorded, never fatal, and the orphan stays visible to the repository.
    async fn release_part(&mut self, abandon: bool, why: PartCleanup) {
        // **The witness governs both ways of removing a part.** `drop_part` asks for
        // itself, and that is the path with no live writer; this is the other one,
        // where the lane still holds the file and would otherwise discard it with
        // nothing consulted. A cancel arriving while a session is still up takes
        // exactly this path.
        //
        // A repository that cannot answer keeps the part: not being able to ask
        // whether a file may already be the user's is not permission to remove the
        // evidence that it might be.
        if why == PartCleanup::Unknown {
            let keep = match self.delivery_unresolved().await {
                Ok(unresolved) => unresolved,
                // Both facts, as `drop_part` tells them: otherwise an operator
                // cannot tell "kept because the answer was yes" from "kept because
                // nobody answered", which is the difference between a part to
                // investigate and a database to fix.
                Err(_) => {
                    emit(
                        Event::new(Code::StorageFailed)
                            .for_job(self.job.id().get(), self.job.generation().get()),
                    );
                    true
                }
            };
            if keep {
                emit(
                    Event::new(Code::PartRetained)
                        .for_job(self.job.id().get(), self.job.generation().get()),
                );
                return;
            }
        }
        // The lane owns the file while it lives, so it must do the releasing;
        // only a session without one falls back to a standalone handle.
        let Some(writer) = self.writer.clone() else {
            self.c.drop_part(&self.job, why).await;
            return;
        };
        if writer.discard(abandon, &self.io).await.is_err() {
            report(&self.job, Code::StorageFailed, 0, Duration::ZERO);
        }
    }

    /// Stops workers and waits for the writer thread; accepted writes finish first.
    async fn close(&mut self) {
        self.stop_workers.cancel();
        while self.workers.join_next().await.is_some() {}
        self.leases.clear();
        if let Some(writer) = self.writer.take() {
            match Arc::try_unwrap(writer) {
                Ok(writer) => {
                    let _ = writer.shutdown().await;
                }
                // Every worker is joined, so no clone can remain.
                Err(_) => debug_assert!(false, "writer still shared after workers joined"),
            }
        }
    }
}

/// One connection: fetch the leased range and hand full buffers to the writer lane.
async fn fetch(
    transport: Arc<dyn Transport>,
    source: SourceRef,
    validator: Option<[u8; 32]>,
    writer: Arc<Writer>,
    buffers: BufferPool,
    lease: Lease,
    cancel: CancellationToken,
) -> Result<(), Failure> {
    let range: ByteRange = lease.range();
    let spec = writer.spec();
    let mut stream = tokio::select! { biased;
        _ = cancel.cancelled() => return Err(Failure::Cancelled),
        stream = transport.fetch(source, range, validator) => stream.map_err(Failure::Transport)?,
    };
    let block = MAX_BUFFER.min(buffers.capacity()) as u64;
    let mut offset = range.start();
    while offset < range.end() {
        let len = block.min(range.end() - offset) as usize;
        let mut buffer = buffers
            .acquire(len, &cancel)
            .await
            .map_err(|_| Failure::Cancelled)?;
        let mut filled = 0;
        while filled < len {
            let read = tokio::select! { biased;
                _ = cancel.cancelled() => return Err(Failure::Cancelled),
                read = stream.read(&mut buffer.as_mut_slice()[filled..]) => read.map_err(Failure::Transport)?,
            };
            if read == 0 {
                return Err(Failure::Transport(TransportError::Transient));
            }
            filled += read;
        }
        writer
            .write(spec, offset, buffer, &cancel)
            .await
            .map_err(Failure::Writer)?;
        offset += len as u64;
    }
    let mut probe = [0u8; 1];
    let tail = tokio::select! { biased;
        _ = cancel.cancelled() => return Err(Failure::Cancelled),
        read = stream.read(&mut probe) => read.map_err(Failure::Transport)?,
    };
    if tail != 0 {
        return Err(Failure::Transport(TransportError::Transient));
    }
    Ok(())
}
