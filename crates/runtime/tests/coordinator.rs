use fhd_app::{
    storage::Published, transport::TransportError, CommitError, DurableExtent, TransferRepository,
};
use fhd_domain::{
    DestinationRef, Generation, Job, JobCommand, JobId, JobSpec, JobState, Priority, RetryPolicy,
    SourceRef, StopReason,
};
use fhd_runtime::{
    buffers::BufferPool,
    coordinator::{Clock, Control, Coordinator, CoordinatorConfig, Ports, RunError, SessionEnd},
};
use fhd_testkit::transfer::{
    digest, FetchFault, FixedDestination, MemoryStore, MemoryTransfers, ScriptedTransport,
    StoreFaults,
};
use std::{path::PathBuf, sync::Arc};
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
    destination: PathBuf,
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
    let destination = std::env::temp_dir().join("fhd-test-destination.bin");
    let coordinator = Coordinator::new(
        Ports {
            repository: repo.clone(),
            store: Arc::new(store.clone()),
            transport: transport.clone(),
            destinations: Arc::new(FixedDestination(destination.clone())),
        },
        // One 256 KiB block per connection: a stalled connection keeps only its own.
        BufferPool::new(1024 * 1024).unwrap(),
        Arc::new(FixedClock),
        config,
    )
    .unwrap();
    Rig {
        repo,
        store,
        transport,
        coordinator,
        id,
        destination,
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
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
    let job = rig.job().await;
    assert_eq!(job.state(), JobState::Completed);
    assert_eq!(rig.store.published(&rig.destination).unwrap(), content);
    assert_eq!(rig.durable().await, content.len() as u64);
    assert_eq!(rig.store.published(&rig.destination).unwrap(), content);
    assert!(
        rig.store.bytes(rig.id, job.generation()).is_none(),
        "the part is released once its bytes live under the final name"
    );
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
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
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
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
    assert_eq!(rig.store.published(&rig.destination).unwrap(), content);
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
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
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
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
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

/// **A storage error does not delete what was already durable.**
///
/// The binding criterion of the disk-failure work, in the words of
/// `docs/feature-download-to-a-different-disk.md`: no error path may delete
/// committed extents or a valid part file, and the evidence has to be a test that
/// injects the error and shows the durable bytes still there. Until now the disk
/// full test above stopped at the stop: it checked that nothing unsynced was
/// credited, which is the opposite direction -- that too little was kept, not that
/// too much was thrown away.
///
/// So this one measures the other side, end to end. The failure lands after a
/// checkpoint, the fault is then lifted the way a user frees space, and the job
/// finishes. **What proves the progress survived is the transport**: it counts the
/// bytes it handed out, and a job that had lost its durable extents would have to
/// ask for them again.
#[tokio::test]
async fn a_storage_error_keeps_the_durable_bytes_and_the_job_finishes_without_refetching_them() {
    let content = body(200_000);
    let rig = rig(&content, true, None);
    rig.store.set_faults(StoreFaults {
        fail_write_at: Some(150_000),
        ..Default::default()
    });
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction))
    );
    let job = rig.job().await;
    assert_eq!(job.reason(), Some(StopReason::Storage));

    // The premise: some bytes really were durable when the error struck.
    let kept: Vec<DurableExtent> = rig.repo.durable_extents(rig.id).await.unwrap();
    let durable = rig.durable().await;
    assert!(durable > 0, "the premise failed: nothing was durable yet");
    let part = rig
        .store
        .bytes(rig.id, job.generation())
        .expect("the part file was deleted by a storage error");
    for extent in &kept {
        let range = extent.range();
        assert_eq!(
            &part[range.start() as usize..range.end() as usize],
            &content[range.start() as usize..range.end() as usize],
            "a committed extent no longer holds its bytes"
        );
    }

    // The disk has room again, and the job is resumed -- not replaced: a storage
    // error is not a reason to fetch a second copy of anything.
    rig.store.set_faults(StoreFaults::default());
    let served_before = rig.transport.served();
    let generation = job.generation();
    rig.command(JobCommand::Resume).await;
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
    let finished = rig.job().await;
    assert_eq!(finished.state(), JobState::Completed);
    assert_eq!(
        finished.generation(),
        generation,
        "a storage error must not change the representation"
    );
    assert_eq!(rig.store.published(&rig.destination).unwrap(), content);

    // And nobody had to send the durable bytes twice. The second run may fetch
    // what was missing and no more -- had the error path dropped the extents, it
    // would have had to fetch the whole file again, and this is what says it did
    // not. The bound is exact rather than generous on purpose: a comfortable one
    // would pass for a job that refetched half of what it already had.
    let missing = content.len() as u64 - durable;
    let served_after = rig.transport.served() - served_before;
    assert!(
        served_after <= missing,
        "the resume fetched {served_after} bytes with only {missing} missing:          progress was lost to the error"
    );
}

/// A sync that fails keeps every byte that an earlier sync had already made durable.
///
/// The other half of the same criterion, on the path that had no test at all: the
/// fault existed in the double and no test ever set it, so `checkpoint` ->
/// `on_storage_failure` -> `discard_unsynced` was unmeasured. The fault is turned
/// on **after** a first checkpoint has succeeded, because a run whose every sync
/// fails has no durable bytes to lose and would prove nothing.
///
/// And it fails **once**. A permanent fault cannot tell this path from the one in
/// `verify`, which syncs too and stops the same way -- a mutation that swallowed
/// the checkpoint's error entirely would still land on `NeedsAction` there, and
/// this test would have called that a pass. With a single failure the two answers
/// separate: reported, the job rests here; swallowed, the next sync succeeds and
/// the job finishes.
#[tokio::test]
async fn a_failed_sync_discards_only_what_was_never_durable() {
    let content = body(200_000);
    let rig = rig(&content, true, None);
    let (control, receiver) = mpsc::channel(1);
    let run = rig.coordinator.run(rig.job().await, receiver);
    let fail_once_durable = async {
        rig.until_durable().await;
        rig.store.set_faults(StoreFaults {
            fail_sync_once: true,
            ..Default::default()
        });
        // Nothing is sent on the control channel; the fault is the whole event.
        drop(control);
    };
    let (end, ()) = tokio::join!(run, fail_once_durable);
    assert_eq!(end, Ok(SessionEnd::Settled(JobState::NeedsAction)));
    let job = rig.job().await;
    assert_eq!(job.reason(), Some(StopReason::Storage));

    let kept: Vec<DurableExtent> = rig.repo.durable_extents(rig.id).await.unwrap();
    assert!(
        !kept.is_empty(),
        "the premise failed: no checkpoint had succeeded before the sync fault"
    );
    let part = rig
        .store
        .bytes(rig.id, job.generation())
        .expect("the part file was deleted by a failed sync");
    for extent in &kept {
        let range = extent.range();
        assert_eq!(
            extent.digest(),
            digest(&content[range.start() as usize..range.end() as usize]),
            "an extent that survived a failed sync no longer describes its bytes"
        );
        assert_eq!(
            &part[range.start() as usize..range.end() as usize],
            &content[range.start() as usize..range.end() as usize]
        );
    }
}

/// A cancel arriving while storage is failing settles the job instead of hanging.
///
/// Neither review found this defect, and no test had put the two together: the
/// suite sets faults in one place and cancels in another. A cancel is the one
/// command that removes a part on purpose, so the interesting question is not
/// whether the bytes survive -- they are meant not to -- but whether the job
/// settles at all when the storage underneath it is refusing writes.
#[tokio::test]
async fn a_cancel_during_a_storage_failure_still_settles_the_job() {
    let content = body(200_000);
    let rig = rig(&content, true, None);
    rig.store.set_faults(StoreFaults {
        fail_write_at: Some(120_000),
        ..Default::default()
    });
    let (control, receiver) = mpsc::channel(1);
    let run = rig.coordinator.run(rig.job().await, receiver);
    let cancel = async {
        rig.until_durable().await;
        control.send(Control::Cancel).await.unwrap();
    };
    let (end, ()) = tokio::join!(run, cancel);
    let state = match end {
        Ok(SessionEnd::Settled(state)) => state,
        other => panic!("the session did not settle: {other:?}"),
    };
    assert!(
        matches!(state, JobState::Cancelled | JobState::NeedsAction),
        "settled at {state:?}"
    );
    // Whichever of the two it lands on, the job is at rest and the record says so.
    assert_eq!(rig.job().await.state(), state);
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
        validator: Some(digest(&content)),
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
    // The first transition commit (Start) fails: the session must abort.
    let (_keep, control) = mpsc::channel(1);
    let job = rig.job().await;
    rig.repo.fail_next(1);
    assert_eq!(
        rig.coordinator.run(job, control).await,
        Err(RunError::Commit(CommitError::Unavailable)),
        "an unconfirmed transition aborts the session"
    );
    assert_eq!(rig.repo.state(rig.id), Some(JobState::Queued));
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
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
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
    assert!(rig.job().await.segments().unwrap().segments().len() <= 4);
}

#[tokio::test]
async fn corruption_found_after_a_blocked_publish_needs_action() {
    let content = body(20_000);
    let rig = rig(&content, true, None);
    // Publication is blocked by a stranger, so the job waits with everything durable.
    rig.store.place(rig.destination.clone(), body(3_000));
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction))
    );
    let generation = rig.job().await.generation();
    rig.store.corrupt(rig.id, generation, 12_345);
    rig.command(JobCommand::Resume).await;
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
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
    assert_eq!(rig.store.published(&rig.destination).unwrap(), content);
}

#[test]
fn buffer_budget_below_one_block_per_connection_is_rejected() {
    let result = Coordinator::new(
        Ports {
            repository: Arc::new(MemoryTransfers::default()),
            store: Arc::new(MemoryStore::default()),
            transport: Arc::new(ScriptedTransport::new(vec![], true, 1)),
            destinations: Arc::new(FixedDestination(
                std::env::temp_dir().join("fhd-unused.bin"),
            )),
        },
        BufferPool::new(512 * 1024).unwrap(),
        Arc::new(FixedClock),
        config(),
    );
    assert!(matches!(result, Err(RunError::InvalidConfig)));
}

#[tokio::test]
async fn same_size_replacement_never_mixes_representations() {
    let old = body(70_000);
    let rig = rig(&old, true, None);
    rig.transport.fault(FetchFault::Stall { after: 1000 });
    let (control, receiver) = mpsc::channel(1);
    let run = rig.coordinator.run(rig.job().await, receiver);
    let pause = async {
        rig.until_durable().await;
        control.send(Control::Pause).await.unwrap();
    };
    let (end, ()) = tokio::join!(run, pause);
    assert_eq!(end, Ok(SessionEnd::Settled(JobState::Paused)));
    assert!(rig.durable().await > 0);
    // Same length, different bytes: only the validator can tell.
    let new: Vec<u8> = old.iter().map(|b| b.wrapping_add(1)).collect();
    rig.transport.replace_body(new.clone());
    rig.command(JobCommand::Resume).await;
    assert_eq!(rig.run().await, Ok(SessionEnd::Settled(JobState::Queued)));
    let job = rig.job().await;
    assert_eq!(job.generation().get(), 2);
    assert_eq!(rig.durable().await, 0);
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
    assert_eq!(rig.store.published(&rig.destination).unwrap(), new);
}

#[tokio::test]
async fn server_without_validator_restarts_from_zero_on_resume() {
    let content = body(60_000);
    let rig = rig(&content, false, None);
    rig.transport.fault(FetchFault::Stall { after: 20_000 });
    let (control, receiver) = mpsc::channel(1);
    let run = rig.coordinator.run(rig.job().await, receiver);
    let pause = async {
        // Pause only once the connection took the stall fault; pausing earlier
        // would leave the fault queued for the next session.
        while rig.transport.fetches() == 0 {
            tokio::task::yield_now().await;
        }
        control.send(Control::Pause).await.unwrap();
    };
    let (end, ()) = tokio::join!(run, pause);
    assert_eq!(end, Ok(SessionEnd::Settled(JobState::Paused)));
    rig.command(JobCommand::Resume).await;
    // No validator: existing bytes cannot be trusted, so a new generation starts.
    assert_eq!(rig.run().await, Ok(SessionEnd::Settled(JobState::Queued)));
    assert_eq!(rig.job().await.generation().get(), 2);
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
}

#[tokio::test]
async fn crash_between_rename_and_commit_completes_without_republishing() {
    let content = body(15_000);
    let rig = rig(&content, true, None);
    // The rename happened, then the process died before committing Completed.
    rig.store.place(rig.destination.clone(), content.clone());
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
    assert_eq!(rig.job().await.state(), JobState::Completed);
    assert_eq!(rig.store.published(&rig.destination).unwrap(), content);
}

/// A publication that cannot say what became of the name is not an answer.
///
/// **The one thing the engine must never do with "nobody can say" is file it as "no
/// name was created".** The second permits removing the part; the first forbids it.
/// They arrive through the same `Err`, which is why the answer is carried beside the
/// error rather than read off it -- and why a test has to pin the branch that tells
/// them apart, or the branch can be deleted and every other test stays green.
///
/// **What this measures and what it does not.** The coordinator's branch: given an
/// answer of "nobody can say", the record goes on saying an attempt is unanswered,
/// and the job rests on the reason that blocks a resume without offering to fetch
/// the file again. Where that answer comes from is a question about real files, and
/// it is measured on them -- the storage adapter's
/// `a_failure_after_the_link_says_nobody_can_tell_rather_than_no_name` fails the
/// outcome write with the destination's entry already on disk. What the part store
/// then does about keeping the part is measured on real files too, in the daemon's
/// `delivery_witness.rs`; this double has no `.meta` file to speak for.
#[tokio::test]
async fn a_publication_that_cannot_say_leaves_the_attempt_unanswered() {
    let content = body(15_000);
    let rig = rig(&content, true, None);
    rig.store.set_faults(StoreFaults {
        publish_unknown: true,
        ..StoreFaults::default()
    });
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction))
    );
    let job = rig.job().await;
    assert_eq!(
        job.reason(),
        Some(StopReason::Unconfirmed),
        "a publication with no answer was reported as an ordinary storage failure"
    );
    assert_eq!(
        rig.repo.attempts(rig.id),
        Some((job.generation(), 1, 0)),
        "an answer of \"nobody can say\" was recorded as \"no name was created\""
    );
}

/// A part that may already be the user's file is not replaced, whatever the job is
/// resting on.
///
/// **The domain refuses this for `Unconfirmed`, and that is one record agreeing with
/// another.** Every path that leaves a publication attempt unanswered does come to
/// rest on `Unconfirmed` today -- a security review checked each producer and so did
/// I -- so the refusal holds. What it does not do is *depend* on the witness: a new
/// `RequireAction` reason that forgets to join the list, or a reordering that records
/// the reason before the witness, reopens the route with no test failing. The review
/// said so, and this is the assertion that makes it a rule instead of a coincidence.
///
/// What the route costs: a new generation is a new part, **and the witness row is
/// dropped with it**. So a replacement erases the doubt and the only record of it in
/// one step, after which nothing stands between the old part -- which may be a second
/// name for a delivered file -- and removal.
///
/// The reason here is deliberately *not* `Unconfirmed`: it is `Destination`, which
/// blocks nothing, so the domain would allow the command and only the witness stops
/// it.
#[tokio::test]
async fn an_unanswered_attempt_refuses_a_replacement_whatever_the_reason_says() {
    let content = body(15_000);
    let rig = rig(&content, true, None);
    let stranger = body(4_000);
    rig.store.place(rig.destination.clone(), stranger);
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction))
    );
    let job = rig.job().await;
    assert_eq!(
        job.reason(),
        Some(StopReason::Destination),
        "the premise failed: a reason that blocks a replacement would prove nothing"
    );
    // **The premise, asked without spending it.** A replacement has to be available
    // in this state, or the refusal below would prove nothing -- and an earlier
    // version of this test established that by *performing* one, which moved the job
    // to `Queued` under a new generation. `ReplaceRepresentation` is not a command
    // `Queued` accepts, so the second call was then refused by the state machine and
    // the assertion passed with the guard deleted. The mutation run found it.
    //
    // `decide` answers the same question and commits nothing, on a copy loaded for
    // the purpose and dropped here.
    assert!(
        rig.job()
            .await
            .decide(JobCommand::ReplaceRepresentation)
            .is_ok(),
        "the premise failed: the domain refuses a replacement in this state anyway, \
         so the guard cannot be what refuses it"
    );

    // The state a crash between the two writes leaves.
    rig.repo
        .begin_publish_attempt(rig.id, job.generation())
        .await
        .expect("the attempt is recorded");
    let refused = rig
        .coordinator
        .command(job, JobCommand::ReplaceRepresentation)
        .await;
    assert!(
        refused.is_err(),
        "a part that may be the user's file was replaced, which drops the witness \
         and leaves nothing to stop the part being removed"
    );
    assert!(
        rig.repo
            .unresolved_publish_attempt(rig.id, rig.job().await.generation())
            .await
            .unwrap(),
        "the refused command changed the record anyway"
    );
}

#[tokio::test]
async fn foreign_file_at_the_destination_is_never_overwritten() {
    let content = body(15_000);
    let rig = rig(&content, true, None);
    let stranger = body(4_000);
    rig.store.place(rig.destination.clone(), stranger.clone());
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction))
    );
    let job = rig.job().await;
    assert_eq!(job.reason(), Some(StopReason::Destination));
    assert_eq!(job.state(), JobState::NeedsAction);
    assert_eq!(rig.store.published(&rig.destination).unwrap(), stranger);
}

#[tokio::test]
async fn crash_before_the_rename_republishes_after_reproving_the_bytes() {
    let content = body(25_000);
    let rig = rig(&content, true, None);
    // A blocked destination leaves a durable intent with the job settled.
    rig.store.block(rig.destination.clone());
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction))
    );
    rig.store.free(&rig.destination);
    // Everything is durable, so resuming goes straight to verification.
    rig.command(JobCommand::Resume).await;
    assert_eq!(rig.job().await.state(), JobState::Verifying);
    // Publishing began and the process died before the rename.
    rig.command(JobCommand::VerificationPassed).await;
    assert_eq!(rig.job().await.state(), JobState::Publishing);
    let fetches = rig.transport.fetches();
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
    assert_eq!(rig.job().await.state(), JobState::Completed);
    assert_eq!(rig.store.published(&rig.destination).unwrap(), content);
    assert_eq!(rig.transport.fetches(), fetches, "no bytes fetched again");
}

#[tokio::test]
async fn a_non_file_holding_the_name_blocks_publication() {
    let content = body(12_000);
    let rig = rig(&content, true, None);
    rig.store.block(rig.destination.clone());
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction))
    );
    assert_eq!(rig.job().await.reason(), Some(StopReason::Destination));
}

#[tokio::test]
async fn a_resumed_session_with_nothing_left_to_fetch_still_verifies() {
    let content = body(30_000);
    let rig = rig(&content, true, None);
    // Block publication so the job settles with every byte already durable.
    rig.store.block(rig.destination.clone());
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction))
    );
    rig.store.free(&rig.destination);
    rig.command(JobCommand::Resume).await;
    assert_eq!(rig.job().await.state(), JobState::Verifying);
    let fetches = rig.transport.fetches();
    // This session writes nothing, so only an explicit sync makes verification legal.
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
    assert_eq!(rig.transport.fetches(), fetches);
    assert_eq!(rig.store.published(&rig.destination).unwrap(), content);
}

/// A job interrupted between taking a new generation and creating its part.
///
/// This is the window the end-to-end tests could not reach, and it is recorded
/// in §10 of the publication contract as unimplemented -- so this implements it.
/// A byte counter cannot land here: the resume's own ranged probe satisfies it
/// before the new part exists, which is why the test that claimed this was
/// renamed to what it actually proved.
///
/// The window is a state, not a moment: the record says generation 2 and the
/// disk holds nothing for it. A representation change reaches exactly that, and
/// the fault makes the first attempt to leave it fail as well, so the job is
/// held there across two more runs. Throughout, generation 1's bytes must be
/// untouched -- it is a different object, and the whole point of taking a new
/// generation is that the old one is never written over.
#[tokio::test]
async fn a_failure_between_the_new_generation_and_its_part_leaves_the_old_one_whole() {
    let content = body(40_000);
    let rig = rig(&content, true, None);
    rig.transport.fault(FetchFault::Truncate {
        after: 2000,
        error: TransportError::RepresentationChanged,
    });
    assert_eq!(rig.run().await, Ok(SessionEnd::Settled(JobState::Queued)));

    // The window: the record has moved, and nothing on disk belongs to it.
    let job = rig.job().await;
    assert_eq!(job.generation().get(), 2);
    let first = rig
        .store
        .bytes(job.id(), Generation::new(1).unwrap())
        .expect("the first generation's part is still on disk");
    assert!(
        rig.store
            .bytes(job.id(), Generation::new(2).unwrap())
            .is_none(),
        "the new generation already has a part, so this is not the window"
    );

    // Failing to leave the window is not failing into the old generation.
    rig.store.set_faults(StoreFaults {
        fail_create: true,
        ..Default::default()
    });
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction)),
        "a part that could not be created did not stop the job"
    );
    assert_eq!(
        rig.job().await.reason(),
        Some(StopReason::Storage),
        "a storage failure in the window was reported as something else"
    );
    assert_eq!(
        rig.store.bytes(job.id(), Generation::new(1).unwrap()),
        Some(first.clone()),
        "the old generation was touched while the new one failed to start"
    );
    assert_eq!(
        rig.job().await.generation().get(),
        2,
        "the generation moved again"
    );

    // And the job carries on from the window once storage allows it.
    rig.command(JobCommand::Resume).await;
    assert_eq!(rig.job().await.state(), JobState::Queued);
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
    assert_eq!(
        rig.store.bytes(job.id(), Generation::new(1).unwrap()),
        Some(first),
        "the old generation was written over on the way to publishing"
    );
}

/// **A cancel that arrives after publication is refused, and takes nothing with
/// it.**
///
/// The third thing the cancel race needed settling. Once the file is the user's,
/// "cancel" cannot mean "undo": the job is finished, the bytes are delivered, and
/// the part's name is a second name for a file somebody now owns. So the answer
/// must be a refusal -- and a refusal that touches nothing.
///
/// `confirm_command` is the seam the scheduler now asks when a session ends, so
/// this asks it directly rather than racing a session to reach the same state.
/// What must hold:
///
/// * the command is refused, not silently accepted;
/// * the job stays `Completed` -- it is not walked back to `Cancelling`;
/// * the published file still holds the published bytes.
#[tokio::test]
async fn a_cancel_after_publication_is_refused_and_leaves_the_file_alone() {
    let content = body(15_000);
    let rig = rig(&content, true, None);
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
    assert_eq!(rig.job().await.state(), JobState::Completed);

    let refused = rig
        .coordinator
        .confirm_command(rig.id, JobCommand::Cancel)
        .await;
    assert!(
        refused.is_err(),
        "a cancel was accepted for a job whose file the user already has: {refused:?}"
    );
    assert_eq!(
        rig.job().await.state(),
        JobState::Completed,
        "a refused cancel moved a completed job"
    );
    assert_eq!(
        rig.store.published(&rig.destination).unwrap(),
        content,
        "a refused cancel disturbed the published file"
    );
}

/// **A cancel for a job resting where a session left it is applied, and saying so
/// twice does not double-apply it.**
///
/// The other half of what the scheduler now relies on. When a session ends without
/// having applied a command it was handed, `confirm_command` is what makes the
/// answer true -- so it has to apply the transition to the resting job, and it has
/// to be safe to ask again, because more than one caller can be waiting on the same
/// job and the scheduler answers them in turn.
#[tokio::test]
async fn confirm_command_cancels_a_resting_job_and_is_safe_to_ask_twice() {
    let content = body(15_000);
    let rig = rig(&content, true, None);
    // Stopped for a reason and resting: the state the race left behind.
    rig.transport
        .fail_probe(fhd_app::transport::TransportError::UserAction(
            StopReason::Authentication,
        ));
    let outcome = rig.run().await;
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::NeedsAction))),
        "the job did not come to rest where this test needs it: {outcome:?}"
    );

    let first = rig
        .coordinator
        .confirm_command(rig.id, JobCommand::Cancel)
        .await;
    assert!(first.is_ok(), "a resting job refused a cancel: {first:?}");
    assert_eq!(
        rig.job().await.state(),
        JobState::Cancelled,
        "the cancel was reported as applied and the record disagrees"
    );

    // Asked again, which is what a second waiting caller does. It must not be
    // refused -- the job is where the command was taking it -- and it must not
    // step the job anywhere else.
    let again = rig
        .coordinator
        .confirm_command(rig.id, JobCommand::Cancel)
        .await;
    assert!(
        again.is_ok(),
        "asking twice about the same cancel was refused the second time: {again:?}"
    );
    assert_eq!(
        rig.job().await.state(),
        JobState::Cancelled,
        "asking twice moved the job"
    );
}

/// **A job left at `Cancelling` is finished, not reported as already done.**
///
/// The arm that had no test, and the defect two independent reviews demonstrated
/// with probes. `confirm_command` treated `Cancelling` as settled and answered
/// yes -- so the operator was told the cancel was done while the record said
/// `Cancelling`, the part was still on disk beside their download folder, and
/// nothing in that pass would finish it: only the next engine start heals it.
///
/// The justification for the short-circuit was wrong too. `(Cancelling, Cancel)`
/// is an **accepted no-op** in the domain, not a refusal, so falling through costs
/// nothing and lets `command_resting`'s own `Cancelling` block drop the part and
/// commit `CleanupFinished` -- the same finish `recover` performs after a crash.
///
/// A session can genuinely leave a job there: it commits `Cancelling` when it
/// reads the command and only reaches `CleanupFinished` later, so a commit error,
/// a domain error while draining, or a panicked task ends it in between.
#[tokio::test]
async fn a_job_left_at_cancelling_is_finished_rather_than_called_done() {
    let content = body(15_000);
    let rig = rig(&content, true, None);
    // A real part with real bytes, then stopped where an operator decides.
    rig.transport
        .fail_probe(fhd_app::transport::TransportError::UserAction(
            StopReason::Authentication,
        ));
    let outcome = rig.run().await;
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::NeedsAction))),
        "the job did not come to rest where this test needs it: {outcome:?}"
    );

    // The record a session leaves when it commits the cancel and then dies before
    // finishing it.
    rig.coordinator
        .command(rig.job().await, JobCommand::Cancel)
        .await
        .expect("the domain accepts a cancel from NeedsAction");
    assert_eq!(
        rig.job().await.state(),
        JobState::Cancelling,
        "this test needs the record to say Cancelling"
    );

    let answered = rig
        .coordinator
        .confirm_command(rig.id, JobCommand::Cancel)
        .await
        .expect("confirming a cancel for a job at Cancelling failed");
    let answered = answered.expect("the job was not found in the record");

    // Finished, not merely acknowledged. Before the fix this was `Cancelling`.
    assert_eq!(
        answered.state(),
        JobState::Cancelled,
        "a job left at Cancelling was reported without being finished"
    );
    assert_eq!(
        rig.job().await.state(),
        JobState::Cancelled,
        "the record still says Cancelling after the command was confirmed"
    );
}

/// **The retry after a failed save goes through the domain, so a published file is
/// safe from it.**
///
/// `confirm_command` does not only read the record: where the record does not
/// already show the command taken, it **applies it again**. A review corrected the
/// claim that this path merely re-reads, and that correction raises the question
/// this test answers -- if a cancel is retried, what stops it acting on a job whose
/// file the user already has?
///
/// The domain does. `Completed` has no `Cancel` arm and `Publishing` answers
/// `PublishInProgress`, and the refusal propagates before any part is opened. So
/// the retry is refused, the job stays `Completed`, the published bytes are
/// untouched, and the caller is told the honest thing rather than `Done`.
#[tokio::test]
async fn a_retried_cancel_after_publication_is_refused_and_touches_no_published_file() {
    let content = body(15_000);
    let rig = rig(&content, true, None);
    assert_eq!(
        rig.run().await,
        Ok(SessionEnd::Published(Published::At(
            rig.destination.clone()
        )))
    );
    assert_eq!(rig.job().await.state(), JobState::Completed);

    // Asked twice, which is what the failed-save path does: once to try, once to
    // confirm. Both must refuse.
    for attempt in 1..=2 {
        let refused = rig
            .coordinator
            .confirm_command(rig.id, JobCommand::Cancel)
            .await;
        assert!(
            refused.is_err(),
            "attempt {attempt}: a retried cancel was accepted for a job whose file \
             the user already has: {refused:?}"
        );
        assert_eq!(
            rig.job().await.state(),
            JobState::Completed,
            "attempt {attempt}: a refused cancel moved a completed job"
        );
        assert_eq!(
            rig.store.published(&rig.destination).unwrap(),
            content,
            "attempt {attempt}: a refused cancel disturbed the published file"
        );
    }
}

/// **A record that cannot be read is reported as unknown, not as a refusal.**
///
/// The other half of the failed-save path. When the retry cannot read the record
/// either, nothing is known about what became of the command -- and saying `No`
/// would render as `ENGINE-INVALID-INPUT`, telling the operator their input was
/// wrong about a command that may well have taken effect.
///
/// `confirm_command` returns an error, which the scheduler turns into a dropped
/// reply and the IPC layer into unknown. Asserted here at the seam: an error, and
/// a record that did not move.
#[tokio::test]
async fn a_record_that_cannot_be_read_is_an_error_rather_than_a_refusal() {
    let content = body(15_000);
    let rig = rig(&content, true, None);
    rig.transport
        .fail_probe(fhd_app::transport::TransportError::UserAction(
            StopReason::Authentication,
        ));
    let outcome = rig.run().await;
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::NeedsAction))),
        "the job did not come to rest where this test needs it: {outcome:?}"
    );

    // The next repository operation fails, which is the read `confirm_command`
    // starts with.
    rig.repo.fail_next(1);
    let answered = rig
        .coordinator
        .confirm_command(rig.id, JobCommand::Cancel)
        .await;
    assert!(
        answered.is_err(),
        "a record that could not be read was reported as a definite answer: {answered:?}"
    );
    // And nothing moved on the strength of a read that failed.
    assert_eq!(
        rig.job().await.state(),
        JobState::NeedsAction,
        "the job moved although the record could not be read"
    );
}
