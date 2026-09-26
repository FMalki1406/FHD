//! What the scheduler decides: how many connections exist at once across jobs, what
//! a throttled origin does to every job on it, and what a shutdown hands back.
use fhd_app::{
    transport::{ByteStream, OriginId, Probe, Transport, TransportError},
    AppError, Destinations, PortFuture, TransferRepository,
};
use fhd_domain::{
    ByteRange, DestinationRef, Job, JobCommand, JobId, JobSpec, JobState, Priority, RetryPolicy,
    SourceRef, StopReason,
};
use fhd_runtime::{
    buffers::BufferPool,
    coordinator::{Clock, Coordinator, CoordinatorConfig, Ports, RunError, SessionEnd},
    origin::{OriginGovernor, OriginLimits},
    scheduler::{Applied, Command, Outcome, Scheduler, SchedulerConfig},
};
use fhd_testkit::transfer::{MemoryStore, MemoryTransfers, ScriptedTransport};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tokio::sync::mpsc;

/// Time only moves when the scheduler decides to wait, so a test proves both that it
/// waited and how long for, without sleeping.
#[derive(Default)]
struct TestClock {
    now: AtomicU64,
}
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
    fn jitter(&self) -> u64 {
        0
    }
    fn sleep_until(&self, deadline_ms: u64) -> PortFuture<'_, ()> {
        self.now.fetch_max(deadline_ms, Ordering::SeqCst);
        Box::pin(std::future::ready(()))
    }
}

/// Counts how many fetches are in flight at once, which is what the engine-wide and
/// per-origin connection caps are about.
struct CountingTransport {
    inner: ScriptedTransport,
    origin: OriginId,
    live: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    touched: Mutex<Vec<SourceRef>>,
}
impl CountingTransport {
    fn new(body: Vec<u8>, tag: u8) -> Self {
        let mut bytes = [0; 16];
        bytes[0] = tag;
        Self {
            inner: ScriptedTransport::new(body, true, 4096),
            origin: OriginId::new(bytes),
            live: Arc::new(AtomicUsize::new(0)),
            peak: Arc::new(AtomicUsize::new(0)),
            touched: Mutex::new(Vec::new()),
        }
    }
    fn reached(&self, source: SourceRef) -> bool {
        self.touched.lock().unwrap().contains(&source)
    }
}
impl Transport for CountingTransport {
    fn origin(&self, _: SourceRef) -> OriginId {
        self.origin
    }
    fn probe(&self, source: SourceRef) -> PortFuture<'_, Result<Probe, TransportError>> {
        self.touched.lock().unwrap().push(source);
        self.inner.probe(source)
    }
    fn fetch(
        &self,
        source: SourceRef,
        range: ByteRange,
        validator: Option<[u8; 32]>,
    ) -> PortFuture<'_, Result<Box<dyn ByteStream>, TransportError>> {
        Box::pin(async move {
            let stream = self.inner.fetch(source, range, validator).await?;
            let live = self.live.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(live, Ordering::SeqCst);
            Ok(Box::new(Counted {
                stream,
                live: self.live.clone(),
            }) as Box<dyn ByteStream>)
        })
    }
}
struct Counted {
    stream: Box<dyn ByteStream>,
    live: Arc<AtomicUsize>,
}
impl ByteStream for Counted {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, TransportError>> {
        self.stream.read(buf)
    }
}
impl Drop for Counted {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

/// One destination per job, so several jobs can publish in the same run.
struct PerJob(PathBuf);
impl Destinations for PerJob {
    fn resolve(&self, destination: DestinationRef) -> Result<PathBuf, AppError> {
        Ok(self.0.join(format!("job-{}.bin", destination.get())))
    }
}

struct Rig {
    repo: Arc<MemoryTransfers>,
    transport: Arc<CountingTransport>,
    coordinator: Arc<Coordinator>,
    governor: Arc<OriginGovernor>,
    clock: Arc<TestClock>,
    directory: PathBuf,
}

fn body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 37 % 253) as u8).collect()
}

fn rig(jobs: u64, content: &[u8], limits: OriginLimits) -> Rig {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let repo = Arc::new(MemoryTransfers::default());
    let transport = Arc::new(CountingTransport::new(content.to_vec(), 1));
    let clock = Arc::new(TestClock::default());
    let governor = Arc::new(OriginGovernor::new(limits).unwrap());
    let directory = std::env::temp_dir().join(format!(
        "fhd-scheduler-{}",
        SEQUENCE.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&directory).unwrap();
    for id in 1..=jobs {
        let spec = JobSpec::new(
            SourceRef::new(id).unwrap(),
            DestinationRef::new(id).unwrap(),
            None,
            Priority::Normal,
            1 << 30,
        )
        .unwrap();
        repo.admit(&Job::new(JobId::new(id).unwrap(), spec));
    }
    let coordinator = Coordinator::new(
        Ports {
            repository: repo.clone(),
            store: Arc::new(MemoryStore::default()),
            transport: transport.clone(),
            destinations: Arc::new(PerJob(directory.clone())),
        },
        BufferPool::new(4 * 1024 * 1024).unwrap(),
        clock.clone(),
        CoordinatorConfig {
            connections: 4,
            max_segments: 64,
            min_segment: 4096,
            checkpoint_bytes: 32 * 1024,
            writer_capacity: 8,
            retry: RetryPolicy::new(4, 1000, 10_000).unwrap(),
        },
    )
    .unwrap()
    .with_governor(governor.clone());
    Rig {
        repo,
        transport,
        coordinator: Arc::new(coordinator),
        governor,
        clock,
        directory,
    }
}

impl Rig {
    async fn jobs(&self) -> Vec<Job> {
        let mut jobs = self.repo.load_jobs().await.unwrap();
        jobs.sort_by_key(|job| job.id().get());
        jobs
    }
    fn scheduler(&self, config: SchedulerConfig) -> Scheduler {
        Scheduler::new(self.coordinator.clone(), self.governor.clone(), config).unwrap()
    }
}
impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn published(outcomes: &[Outcome]) -> usize {
    outcomes
        .iter()
        .filter(|outcome| matches!(outcome.result, Some(Ok(SessionEnd::Published(_)))))
        .count()
}

#[tokio::test]
async fn every_job_runs_but_never_more_connections_than_the_engine_allows() {
    let rig = rig(4, &body(400_000), OriginLimits::default());
    let scheduler = rig.scheduler(SchedulerConfig {
        max_active: 4,
        connections: 3,
        per_job: 2,
        resident: false,
    });
    let (_keep, commands) = mpsc::channel(4);
    let outcomes = scheduler.run(rig.jobs().await, commands).await;
    assert_eq!(outcomes.len(), 4);
    assert_eq!(published(&outcomes), 4);
    let peak = rig.transport.peak.load(Ordering::SeqCst);
    assert!(peak <= 3, "peak connections {peak} exceeded the engine cap");
    assert!(
        peak >= 2,
        "only {peak} connection(s) ever ran: the cap is not the limit being tested"
    );
}

#[tokio::test]
async fn one_origin_serves_one_connection_at_a_time_when_that_is_its_cap() {
    let rig = rig(
        3,
        &body(200_000),
        OriginLimits {
            connections: 1,
            ..OriginLimits::default()
        },
    );
    let scheduler = rig.scheduler(SchedulerConfig {
        max_active: 3,
        connections: 8,
        per_job: 4,
        resident: false,
    });
    let (_keep, commands) = mpsc::channel(4);
    let outcomes = scheduler.run(rig.jobs().await, commands).await;
    assert_eq!(published(&outcomes), 3);
    assert_eq!(rig.transport.peak.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_throttled_origin_is_left_alone_until_the_delay_it_asked_for_has_passed() {
    let rig = rig(1, &body(100_000), OriginLimits::default());
    rig.transport.inner.fail_probe(TransportError::Throttled {
        retry_after_ms: Some(30_000),
    });
    let scheduler = rig.scheduler(SchedulerConfig {
        max_active: 2,
        connections: 4,
        per_job: 2,
        resident: false,
    });
    let (_keep, commands) = mpsc::channel(4);
    let outcomes = scheduler.run(rig.jobs().await, commands).await;
    // The scheduler waited out the server's delay and then finished the job.
    assert_eq!(published(&outcomes), 1);
    assert!(
        rig.clock.now_ms() >= 30_000,
        "resumed after {} ms, before the origin asked",
        rig.clock.now_ms()
    );
}

#[tokio::test]
async fn shutdown_hands_back_what_never_started_instead_of_running_it() {
    let rig = rig(
        3,
        &body(200_000),
        OriginLimits {
            connections: 1,
            ..OriginLimits::default()
        },
    );
    let scheduler = rig.scheduler(SchedulerConfig {
        max_active: 1,
        connections: 4,
        per_job: 1,
        resident: false,
    });
    let (commander, commands) = mpsc::channel(4);
    commander.send(Command::Shutdown).await.unwrap();
    let outcomes = scheduler.run(rig.jobs().await, commands).await;
    assert_eq!(outcomes.len(), 3);
    let untouched: Vec<_> = outcomes
        .iter()
        .filter(|outcome| outcome.result.is_none())
        .collect();
    assert!(untouched.len() >= 2, "shutdown kept running jobs");
    for outcome in untouched {
        assert_eq!(outcome.job.as_ref().unwrap().state(), JobState::Queued);
    }
}

#[tokio::test]
async fn a_queued_job_can_be_cancelled_before_it_ever_reaches_the_network() {
    let rig = rig(
        2,
        &body(200_000),
        OriginLimits {
            connections: 1,
            ..OriginLimits::default()
        },
    );
    let scheduler = rig.scheduler(SchedulerConfig {
        max_active: 1,
        connections: 4,
        per_job: 1,
        resident: false,
    });
    let (commander, commands) = mpsc::channel(4);
    commander
        .send(Command::Cancel(JobId::new(2).unwrap(), None))
        .await
        .unwrap();
    let outcomes = scheduler.run(rig.jobs().await, commands).await;
    let cancelled = outcomes
        .iter()
        .find(|outcome| outcome.id == JobId::new(2).unwrap())
        .unwrap();
    assert_eq!(
        cancelled.job.as_ref().unwrap().state(),
        JobState::Cancelled,
        "a cancelled job must not be left runnable"
    );
    assert_eq!(published(&outcomes), 1);
    assert!(
        !rig.transport.reached(SourceRef::new(2).unwrap()),
        "a cancelled job still reached the network"
    );
}

/// The governor is accounting, not a lock: nothing may be left held after a pass.
#[tokio::test]
async fn no_grant_survives_the_run_that_made_it() {
    let rig = rig(3, &body(120_000), OriginLimits::default());
    let scheduler = rig.scheduler(SchedulerConfig {
        max_active: 3,
        connections: 6,
        per_job: 2,
        resident: false,
    });
    let (_keep, commands) = mpsc::channel(4);
    let outcomes = scheduler.run(rig.jobs().await, commands).await;
    assert_eq!(published(&outcomes), 3);
    let origin = rig.transport.origin(SourceRef::new(1).unwrap());
    assert_eq!(rig.governor.admit(origin, 8, 0), 8);
}

#[tokio::test]
async fn a_throttled_origin_holds_back_every_job_on_it_not_just_the_one_it_answered() {
    let rig = rig(2, &body(100_000), OriginLimits::default());
    rig.transport.inner.fail_probe(TransportError::Throttled {
        retry_after_ms: Some(30_000),
    });
    let scheduler = rig.scheduler(SchedulerConfig {
        max_active: 2,
        connections: 4,
        per_job: 1,
        resident: false,
    });
    let (_keep, commands) = mpsc::channel(4);
    let outcomes = scheduler.run(rig.jobs().await, commands).await;
    assert_eq!(published(&outcomes), 2);
    // The second job has no retry state of its own: only the governor could have
    // held it back, and the clock proves the pass could not end before the delay.
    assert!(
        rig.clock.now_ms() >= 30_000,
        "the pass ended at {} ms, before the origin's delay",
        rig.clock.now_ms()
    );
}

#[tokio::test]
async fn a_job_that_is_resting_is_handed_back_untouched() {
    let rig = rig(1, &body(50_000), OriginLimits::default());
    let mut jobs = rig.jobs().await;
    let job = rig
        .coordinator
        .command(jobs.pop().unwrap(), JobCommand::Pause)
        .await
        .unwrap();
    assert_eq!(job.state(), JobState::Paused);
    let scheduler = rig.scheduler(SchedulerConfig {
        max_active: 2,
        connections: 4,
        per_job: 2,
        resident: false,
    });
    let (_keep, commands) = mpsc::channel(4);
    let outcomes = scheduler.run(vec![job], commands).await;
    assert_eq!(outcomes.len(), 1);
    assert!(outcomes[0].result.is_none());
    assert_eq!(outcomes[0].job.as_ref().unwrap().state(), JobState::Paused);
    assert!(!rig.transport.reached(SourceRef::new(1).unwrap()));
}

#[tokio::test]
async fn the_same_job_twice_is_refused_rather_than_run_twice() {
    let rig = rig(1, &body(50_000), OriginLimits::default());
    let job = rig.jobs().await.pop().unwrap();
    let twin = rig.jobs().await.pop().unwrap();
    let scheduler = rig.scheduler(SchedulerConfig {
        max_active: 2,
        connections: 4,
        per_job: 2,
        resident: false,
    });
    let (_keep, commands) = mpsc::channel(4);
    let outcomes = scheduler.run(vec![job, twin], commands).await;
    assert_eq!(outcomes.len(), 2);
    assert_eq!(published(&outcomes), 1);
    assert!(outcomes
        .iter()
        .any(|outcome| matches!(outcome.result, Some(Err(RunError::Invariant)))));
    assert_eq!(
        rig.governor
            .admit(rig.transport.origin(SourceRef::new(1).unwrap()), 8, 0),
        8
    );
}

/// A transport that parks inside `probe` until the test lets it go, then refuses
/// in a way that rests the job where an operator has to decide.
///
/// The parking is the point. While the session is inside this call it is **not**
/// polling its control channel, so a command handed to it during that window sits
/// in the channel unread -- which is the state the race needs.
struct ParkedThenRefused {
    inner: ScriptedTransport,
    origin: OriginId,
    reached: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    gate: tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}
impl Transport for ParkedThenRefused {
    fn origin(&self, _: SourceRef) -> OriginId {
        self.origin
    }
    fn probe(&self, source: SourceRef) -> PortFuture<'_, Result<Probe, TransportError>> {
        // Answers normally. Probing happens at intake, before any session exists,
        // so parking here would not put the scheduler in the state this measures.
        self.inner.probe(source)
    }
    fn fetch(
        &self,
        _: SourceRef,
        _: ByteRange,
        _: Option<[u8; 32]>,
    ) -> PortFuture<'_, Result<Box<dyn ByteStream>, TransportError>> {
        Box::pin(async move {
            if let Some(reached) = self.reached.lock().unwrap().take() {
                let _ = reached.send(());
            }
            if let Some(gate) = self.gate.lock().await.take() {
                let _ = gate.await;
            }
            // Not transient: the job rests at `NeedsAction`, which is where the
            // race left it while the client had been told the cancel was done.
            Err(TransportError::UserAction(StopReason::Authentication))
        })
    }
}

/// **`Done` for a cancel means the record says cancelled.**
///
/// The race CI caught on Windows. The scheduler answered the caller as soon as a
/// `Cancel` landed in the running session's control channel -- and a session that
/// is already finishing can end without ever reading it. The channel goes with the
/// task and the command with it, so the client was told `Done` while the job rested
/// in `NeedsAction`, for the whole 120 seconds the test waited on it.
///
/// The transport above parks the session inside `probe`, so the command is handed
/// over while nothing is reading. Then the gate opens, the probe is refused, and
/// the session ends.
///
/// **The assertion is the invariant, not the interleaving.** Whether the session
/// glances at its channel on the way out is a scheduling detail no test can pin;
/// what must hold either way is that the answer is backed by the record:
///
/// * `Applied::Yes` and the job is `Cancelled`. This is the assertion that fails
///   before the fix, with the job resting in `NeedsAction`.
/// * `Applied::No` and the job is not cancelled, so the refusal was honest.
///
/// And the reply must arrive at all: a caller left waiting for ever is the other
/// way this could go wrong, so it is bounded.
#[tokio::test]
async fn done_for_a_cancel_means_the_record_says_cancelled() {
    let directory = std::env::temp_dir().join(format!(
        "fhd-cancel-race-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();

    let (reached, parked) = tokio::sync::oneshot::channel();
    let (release, gate) = tokio::sync::oneshot::channel();
    let transport = Arc::new(ParkedThenRefused {
        inner: ScriptedTransport::new(body(64 * 1024), true, 4096),
        origin: OriginId::new([7; 16]),
        reached: Mutex::new(Some(reached)),
        gate: tokio::sync::Mutex::new(Some(gate)),
    });

    let repo = Arc::new(MemoryTransfers::default());
    let spec = JobSpec::new(
        SourceRef::new(1).unwrap(),
        DestinationRef::new(1).unwrap(),
        None,
        Priority::Normal,
        1 << 30,
    )
    .unwrap();
    repo.admit(&Job::new(JobId::new(1).unwrap(), spec));

    let governor = Arc::new(OriginGovernor::new(OriginLimits::default()).unwrap());
    let coordinator = Arc::new(
        Coordinator::new(
            Ports {
                repository: repo.clone(),
                store: Arc::new(MemoryStore::default()),
                transport: transport.clone(),
                destinations: Arc::new(PerJob(directory.clone())),
            },
            BufferPool::new(4 * 1024 * 1024).unwrap(),
            Arc::new(TestClock::default()),
            CoordinatorConfig {
                connections: 4,
                max_segments: 64,
                min_segment: 4096,
                checkpoint_bytes: 32 * 1024,
                writer_capacity: 8,
                retry: RetryPolicy::new(4, 1000, 10_000).unwrap(),
            },
        )
        .unwrap()
        .with_governor(governor.clone()),
    );
    let scheduler = Scheduler::new(
        coordinator,
        governor,
        SchedulerConfig {
            max_active: 1,
            connections: 4,
            per_job: 2,
            resident: false,
        },
    )
    .unwrap();

    let jobs = repo.load_jobs().await.unwrap();
    let (commands, receiver) = mpsc::channel(4);
    let run = tokio::spawn(async move { scheduler.run(jobs, receiver).await });

    // The session is inside `probe` now, so nothing is reading its control
    // channel. Everything below is ordered after this.
    parked
        .await
        .expect("the session never reached the transport");

    let (reply, mut applied) = tokio::sync::oneshot::channel();
    commands
        .send(Command::Cancel(JobId::new(1).unwrap(), Some(reply)))
        .await
        .expect("the scheduler is still accepting commands");
    // Turns for the scheduler to take the command off its queue and hand it to the
    // parked session. Without these the command could arrive after the session has
    // already ended, which is the path that always worked.
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }

    // **The discriminator, and it is deterministic.** The session is still parked
    // inside `probe` with the gate shut, so whatever the scheduler has answered by
    // now, it answered before the session stopped.
    //
    // An early answer is not itself wrong: a cancel applied to the record straight
    // away is answered straight away, and that is honest. What is wrong is a `Yes`
    // the record does not back -- which is precisely what the hand-off reply was,
    // because the command was sitting in a channel that goes away with the task.
    // So the question asked here is not "has it answered" but "if it has, is the
    // transition there".
    if let Ok(early) = applied.try_recv() {
        let recorded = repo
            .load_jobs()
            .await
            .unwrap()
            .into_iter()
            .find(|job| job.id() == JobId::new(1).unwrap())
            .expect("the job is in the record");
        assert_eq!(
            (early, recorded.state()),
            (Applied::Yes, JobState::Cancelled),
            "the cancel was answered {early:?} while the session was still parked \
             and the record says {:?}: the reply was sent for the hand-off rather \
             than for the transition",
            recorded.state()
        );
        // Answered and recorded, so the rest of this test has nothing left to
        // measure; the session is released so the scheduler can finish.
        let _ = release.send(());
        let outcomes = tokio::time::timeout(std::time::Duration::from_secs(30), run)
            .await
            .expect("the scheduler did not finish")
            .expect("the scheduler panicked");
        assert_eq!(outcomes.len(), 1);
        let _ = std::fs::remove_dir_all(&directory);
        return;
    }

    let _ = release.send(());

    let applied = tokio::time::timeout(std::time::Duration::from_secs(30), applied)
        .await
        .expect("the cancel was never answered, so a caller waits for ever")
        .expect("the scheduler dropped the reply without answering");

    let outcomes = tokio::time::timeout(std::time::Duration::from_secs(30), run)
        .await
        .expect("the scheduler did not finish")
        .expect("the scheduler panicked");
    assert_eq!(outcomes.len(), 1);

    let recorded = repo
        .load_jobs()
        .await
        .unwrap()
        .into_iter()
        .find(|job| job.id() == JobId::new(1).unwrap())
        .expect("the job is in the record");
    match applied {
        Applied::Yes => assert_eq!(
            recorded.state(),
            JobState::Cancelled,
            "the cancel was reported as done and the record says {:?}: the session \
             was handed the command and ended without reading it",
            recorded.state()
        ),
        Applied::No => assert_ne!(
            recorded.state(),
            JobState::Cancelled,
            "the cancel was refused and the record says it was cancelled anyway"
        ),
    }
    let _ = std::fs::remove_dir_all(&directory);
}
