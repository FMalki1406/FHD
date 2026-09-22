use fhd_app::{transport::TransportError, CommitError, DurableExtent, TransferRepository};
use fhd_domain::{
    DestinationRef, Job, JobCommand, JobId, JobSpec, JobState, Priority, RetryPolicy, SourceRef,
    StopReason,
};
use fhd_runtime::{
    buffers::BufferPool,
    coordinator::{Clock, Control, Coordinator, CoordinatorConfig, RunError, SessionEnd},
};
use fhd_testkit::transfer::{
    digest, FetchFault, MemoryStore, MemoryTransfers, ScriptedTransport, StoreFaults,
};
use std::sync::Arc;
use tokio::sync::mpsc;

struct FixedClock;
impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        1_000_000
    }
    fn jitter(&self) -> u64 {
        700
    }
}

fn body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

struct Rig {
    repo: Arc<MemoryTransfers>,
    store: MemoryStore,
    transport: Arc<ScriptedTransport>,
    coordinator: Coordinator,
    id: JobId,
}
fn config() -> CoordinatorConfig {
    CoordinatorConfig {
        connections: 4,
        max_segments: 64,
        min_segment: 4096,
        checkpoint_bytes: 16 * 1024,
        writer_capacity: 8,
        retry: RetryPolicy::new(3, 1000, 10_000).unwrap(),
    }
}
fn rig(content: &[u8], ranges: bool, expected: Option<[u8; 32]>) -> Rig {
    rig_with(content, ranges, expected, config())
}
fn rig_with(
    content: &[u8],
    ranges: bool,
    expected: Option<[u8; 32]>,
    config: CoordinatorConfig,
) -> Rig {
    let repo = Arc::new(MemoryTransfers::default());
    let store = MemoryStore::default();
    let transport = Arc::new(ScriptedTransport::new(content.to_vec(), ranges, 1500));
    let id = JobId::new(7).unwrap();
    let spec = JobSpec::new(
        SourceRef::new(1).unwrap(),
        DestinationRef::new(1).unwrap(),
        expected,
        Priority::Normal,
        1 << 30,
    )
    .unwrap();
    repo.admit(&Job::new(id, spec));
    let coordinator = Coordinator::new(
        repo.clone(),
        Arc::new(store.clone()),
        transport.clone(),
        // One 256 KiB block per connection: a stalled connection keeps only its own.
        BufferPool::new(1024 * 1024).unwrap(),
        Arc::new(FixedClock),
        config,
        std::env::temp_dir(),
    )
    .unwrap();
    Rig {
        repo,
        store,
        transport,
        coordinator,
        id,
    }
}
impl Rig {
    async fn job(&self) -> Job {
        self.repo
            .load_jobs()
            .await
            .unwrap()
            .into_iter()
            .find(|j| j.id() == self.id)
            .unwrap()
    }
    async fn command(&self, command: JobCommand) {
        let mut job = self.job().await;
        for event in job.decide(command).unwrap() {
            self.repo.commit_transition(event.clone()).await.unwrap();
            job.apply(&event).unwrap();
        }
    }
    async fn run(&self) -> Result<SessionEnd, RunError> {
        let (_keep, control) = mpsc::channel(1);
        self.coordinator.run(self.job().await, control).await
    }
    /// Waits (bounded) until another connection's checkpoint made bytes durable.
    async fn until_durable(&self) {
        for _ in 0..100_000 {
            if self.durable().await > 0 {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("no checkpoint happened");
    }
    async fn durable(&self) -> u64 {
        self.repo
            .durable_extents(self.id)
            .await
            .unwrap()
            .iter()
            .map(|e| e.range().len())
            .sum()
    }
}

#[tokio::test]
async fn parallel_transfer_writes_exact_bytes_and_verifies() {
    let content = body(100_003);
    let rig = rig(&content, true, None);
    assert_eq!(rig.run().await, Ok(SessionEnd::Verified(digest(&content))));
    let job = rig.job().await;
    assert_eq!(job.state(), JobState::Verifying);
    assert_eq!(rig.durable().await, content.len() as u64);
    assert_eq!(rig.store.bytes(rig.id, job.generation()).unwrap(), content);
    assert!(rig.transport.fetches() >= 4, "used parallel connections");
    // Every committed extent carries the digest of exactly its own bytes.
    for extent in rig.repo.durable_extents(rig.id).await.unwrap() {
        let r = extent.range();
        assert_eq!(
            extent.digest(),
            digest(&content[r.start() as usize..r.end() as usize])
        );
    }
}

#[tokio::test]
async fn server_without_ranges_uses_one_connection() {
    let content = body(20_000);
    let rig = rig(&content, false, None);
    assert_eq!(rig.run().await, Ok(SessionEnd::Verified(digest(&content))));
    assert_eq!(rig.transport.fetches(), 1);
}

#[tokio::test]
async fn transient_failure_waits_then_resumes_keeping_durable_bytes() {
    let content = body(60_000);
    let rig = rig(&content, true, None);
    rig.transport.fault(FetchFault::Truncate {
        after: 5000,
        error: TransportError::Transient,
    });
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::RetryWait))
    );
    let job = rig.job().await;
    let at = job.retry_at().unwrap();
    // First attempt: cap 1000 ms, full jitter 700 → a persisted wall-clock deadline.
    assert_eq!(at, 1_000_700);
    // Whether another lease finished first is scheduling-dependent; durable
    // retention across a stop is asserted deterministically by the pause tests.
    assert!(rig.durable().await < content.len() as u64);
    rig.command(JobCommand::RetryDue { now_tick: at }).await;
    let before = rig.transport.fetches();
    assert_eq!(rig.run().await, Ok(SessionEnd::Verified(digest(&content))));
    assert_eq!(
        rig.store
            .bytes(rig.id, rig.job().await.generation())
            .unwrap(),
        content
    );
    // Only the missing ranges are fetched again.
    assert!(rig.transport.fetches() - before < 4 + 64);
}

#[tokio::test]
async fn pause_mid_transfer_persists_progress_and_resume_completes() {
    let content = body(80_000);
    let rig = rig(&content, true, None);
    rig.transport.fault(FetchFault::Stall { after: 3000 });
    let (control, receiver) = mpsc::channel(1);
    let job = rig.job().await;
    let run = rig.coordinator.run(job, receiver);
    let pause = async {
        // Let the other connections make progress before pausing.
        rig.until_durable().await;
        control.send(Control::Pause).await.unwrap();
    };
    let (end, ()) = tokio::join!(run, pause);
    assert_eq!(end, Ok(SessionEnd::Settled(JobState::Paused)));
    let kept = rig.durable().await;
    assert!(kept > 0 && kept < content.len() as u64);
    rig.command(JobCommand::Resume).await;
    assert_eq!(rig.run().await, Ok(SessionEnd::Verified(digest(&content))));
}

#[tokio::test]
async fn cancel_passes_through_cleanup() {
    let content = body(50_000);
    let rig = rig(&content, true, None);
    rig.transport.fault(FetchFault::Stall { after: 0 });
    let (control, receiver) = mpsc::channel(1);
    control.try_send(Control::Cancel).unwrap();
    let end = rig.coordinator.run(rig.job().await, receiver).await;
    assert_eq!(end, Ok(SessionEnd::Settled(JobState::Cancelled)));
}

#[tokio::test]
async fn representation_change_restarts_under_a_new_generation() {
    let content = body(40_000);
    let rig = rig(&content, true, None);
    rig.transport.fault(FetchFault::Truncate {
        after: 2000,
        error: TransportError::RepresentationChanged,
    });
    assert_eq!(rig.run().await, Ok(SessionEnd::Settled(JobState::Queued)));
    let job = rig.job().await;
    assert_eq!(job.generation().get(), 2);
    assert_eq!(rig.durable().await, 0, "old generation extents are gone");
    assert_eq!(rig.run().await, Ok(SessionEnd::Verified(digest(&content))));
}

#[tokio::test]
async fn full_disk_needs_action_and_never_commits_unsynced_bytes() {
    let content = body(60_000);
    let rig = rig(&content, true, None);
    rig.store.set_faults(StoreFaults {
        fail_write_at: Some(50_000),
        ..Default::default()
    });
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction))
    );
    let job = rig.job().await;
    assert_eq!(job.reason(), Some(StopReason::Storage));
    let stored = rig.store.bytes(rig.id, job.generation()).unwrap();
    for extent in rig.repo.durable_extents(rig.id).await.unwrap() {
        let r = extent.range();
        assert!(r.end() <= 50_000 || r.start() > 50_000);
        assert_eq!(
            &stored[r.start() as usize..r.end() as usize],
            &content[r.start() as usize..r.end() as usize]
        );
    }
}

#[tokio::test]
async fn restart_reproves_durable_extents_and_rejects_corruption() {
    let content = body(90_000);
    let rig = rig(&content, true, None);
    rig.transport.fault(FetchFault::Stall { after: 1000 });
    let (control, receiver) = mpsc::channel(1);
    let run = rig.coordinator.run(rig.job().await, receiver);
    let pause = async {
        rig.until_durable().await;
        control.send(Control::Pause).await.unwrap();
    };
    let (end, ()) = tokio::join!(run, pause);
    assert_eq!(end, Ok(SessionEnd::Settled(JobState::Paused)));
    let extents: Vec<DurableExtent> = rig.repo.durable_extents(rig.id).await.unwrap();
    let first = extents.first().expect("some progress was durable").range();
    let generation = rig.job().await.generation();
    rig.store
        .corrupt(rig.id, generation, first.start() as usize);
    rig.command(JobCommand::Resume).await;
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction))
    );
    assert_eq!(rig.job().await.reason(), Some(StopReason::Integrity));
}

#[tokio::test]
async fn expected_digest_mismatch_needs_action() {
    let content = body(10_000);
    let rig = rig(&content, true, Some([0xAB; 32]));
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction))
    );
    assert_eq!(rig.job().await.reason(), Some(StopReason::Integrity));
}

#[tokio::test]
async fn crash_restored_job_settles_without_resuming() {
    let content = body(30_000);
    let rig = rig(&content, true, None);
    rig.command(JobCommand::Start).await;
    rig.command(JobCommand::ProbeSucceeded {
        total: 30_000,
        max_segments: 8,
    })
    .await;
    let recovered = rig.coordinator.recover(rig.job().await).await.unwrap();
    assert_eq!(recovered.state(), JobState::Paused);
    assert_eq!(rig.repo.state(rig.id), Some(JobState::Paused));
    assert_eq!(
        rig.coordinator.run(recovered, mpsc::channel(1).1).await,
        Err(RunError::NotRunnable(JobState::Paused))
    );
}

#[tokio::test]
async fn unavailable_extent_commit_is_retried_idempotently() {
    let content = body(30_000);
    let rig = rig(&content, false, None);
    rig.command(JobCommand::Start).await;
    rig.command(JobCommand::Pause).await;
    rig.command(JobCommand::WorkersDrained).await;
    rig.command(JobCommand::Resume).await;
    // Start and ProbeSucceeded commit first; fail those two, then succeed.
    let (_keep, control) = mpsc::channel(1);
    let job = rig.job().await;
    rig.repo.fail_next(1);
    assert_eq!(
        rig.coordinator.run(job, control).await,
        Err(RunError::Commit(CommitError::Unavailable)),
        "an unconfirmed transition aborts the session"
    );
    assert_eq!(rig.repo.state(rig.id), Some(JobState::Queued));
    assert_eq!(rig.run().await, Ok(SessionEnd::Verified(digest(&content))));
}

#[tokio::test]
async fn odd_split_never_exceeds_the_segment_budget() {
    let content = body(10_001);
    let rig = rig_with(
        &content,
        true,
        None,
        CoordinatorConfig {
            max_segments: 4,
            min_segment: 3000,
            checkpoint_bytes: 1,
            ..config()
        },
    );
    assert_eq!(rig.run().await, Ok(SessionEnd::Verified(digest(&content))));
    assert!(rig.job().await.segments().unwrap().segments().len() <= 4);
}

#[tokio::test]
async fn corruption_found_while_reverifying_needs_action() {
    let content = body(20_000);
    let rig = rig(&content, true, None);
    assert_eq!(rig.run().await, Ok(SessionEnd::Verified(digest(&content))));
    let generation = rig.job().await.generation();
    rig.store.corrupt(rig.id, generation, 12_345);
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction))
    );
    assert_eq!(rig.job().await.reason(), Some(StopReason::Integrity));
}

#[tokio::test]
async fn power_loss_keeps_only_synced_bytes_and_resume_is_exact() {
    let content = body(90_000);
    let rig = rig(&content, true, None);
    rig.transport.fault(FetchFault::Stall { after: 2000 });
    let (control, receiver) = mpsc::channel(1);
    let run = rig.coordinator.run(rig.job().await, receiver);
    let pause = async {
        rig.until_durable().await;
        control.send(Control::Pause).await.unwrap();
    };
    let (end, ()) = tokio::join!(run, pause);
    assert_eq!(end, Ok(SessionEnd::Settled(JobState::Paused)));
    // Everything not synced disappears; committed extents must still rehash.
    rig.store.crash();
    rig.command(JobCommand::Resume).await;
    assert_eq!(rig.run().await, Ok(SessionEnd::Verified(digest(&content))));
    assert_eq!(
        rig.store
            .bytes(rig.id, rig.job().await.generation())
            .unwrap(),
        content
    );
}

#[test]
fn buffer_budget_below_one_block_per_connection_is_rejected() {
    let result = Coordinator::new(
        Arc::new(MemoryTransfers::default()),
        Arc::new(MemoryStore::default()),
        Arc::new(ScriptedTransport::new(vec![], true, 1)),
        BufferPool::new(512 * 1024).unwrap(),
        Arc::new(FixedClock),
        config(),
        std::env::temp_dir(),
    );
    assert!(matches!(result, Err(RunError::InvalidConfig)));
}
