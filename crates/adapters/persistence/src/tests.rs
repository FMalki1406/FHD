use super::*;
use fhd_app::{AddDownload, Authorizer, EntitlementGate, Principal};
use std::sync::atomic::{AtomicU64, Ordering};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let name = format!(
            "fhd-sqlite-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        Self(base.join(name))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if self.0.exists() {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
struct Allow;
impl Authorizer for Allow {
    fn authorize_add(&self, _: Principal, _: &JobSpec) -> std::result::Result<(), AppError> {
        Ok(())
    }
}
impl EntitlementGate for Allow {
    fn authorize_add(&self, _: Principal, _: &JobSpec) -> std::result::Result<(), AppError> {
        Ok(())
    }
}
fn key(n: u8) -> ReceiptKey {
    ReceiptKey::new(Principal::new(u64::MAX).unwrap(), [n; 32])
}
fn spec() -> JobSpec {
    JobSpec::new(
        SourceRef::new(u64::MAX).unwrap(),
        DestinationRef::new(u64::MAX).unwrap(),
        Some([3; 32]),
        Priority::High,
        1000,
    )
    .unwrap()
}
async fn add(repo: &SqliteRepository, n: u8) -> std::result::Result<JobId, AppError> {
    AddDownload::new(repo, &Allow, &Allow)
        .execute(key(n), spec())
        .await
}

#[tokio::test]
async fn lost_ack_reopen_replays_and_reservations_never_reuse() {
    let directory = Directory::new();
    let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
        .await
        .unwrap();
    repo.inner.lock().unwrap().fault = Fault::AfterCommit;
    assert_eq!(add(&repo, 1).await, Err(AppError::PersistenceUnavailable));
    assert_eq!(repo.counts().await.unwrap(), (1, 1));
    let id = add(&repo, 1).await.unwrap();
    let gap = repo.reserve_id().await.unwrap();
    drop(repo);
    let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
        .await
        .unwrap();
    assert_eq!(add(&repo, 1).await.unwrap(), id);
    assert!(repo.reserve_id().await.unwrap().get() > gap.get());
    assert_eq!(
        repo.receipt(key(1)).await.unwrap().unwrap().original(),
        &spec()
    );
}

#[tokio::test]
async fn transaction_failure_rolls_back_job_and_receipt_together() {
    let directory = Directory::new();
    let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
        .await
        .unwrap();
    repo.inner.lock().unwrap().fault = Fault::BeforeCommit;
    assert_eq!(add(&repo, 1).await, Err(AppError::PersistenceUnavailable));
    assert_eq!(repo.counts().await.unwrap(), (0, 0));
    drop(repo);
    let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
        .await
        .unwrap();
    assert!(add(&repo, 1).await.unwrap().get() > 1);
    assert_eq!(repo.counts().await.unwrap(), (1, 1));
}

#[tokio::test]
async fn exclusive_writer_and_real_wal_full_policy() {
    let directory = Directory::new();
    let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
        .await
        .unwrap();
    assert!(matches!(
        SqliteRepository::open(directory.0.clone(), Limits::default()).await,
        Err(PersistenceError::Locked)
    ));
    repo.run(|inner| {
        let mode: String = inner
            .db
            .pragma_query_value(None, "journal_mode", |r| r.get(0))?;
        let sync: i64 = inner
            .db
            .pragma_query_value(None, "synchronous", |r| r.get(0))?;
        assert_eq!(mode, "wal");
        assert_eq!(sync, 2);
        Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn simultaneous_same_command_has_one_durable_job() {
    let directory = Directory::new();
    let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
        .await
        .unwrap();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let repo = repo.clone();
        handles.push(tokio::spawn(async move { add(&repo, 1).await.unwrap() }));
    }
    let mut ids = Vec::new();
    for handle in handles {
        ids.push(handle.await.unwrap());
    }
    assert!(ids.iter().all(|id| *id == ids[0]));
    assert_eq!(repo.counts().await.unwrap(), (1, 1));
    let changed = JobSpec::new(
        SourceRef::new(2).unwrap(),
        spec().destination(),
        None,
        Priority::Normal,
        1000,
    )
    .unwrap();
    assert_eq!(
        AddDownload::new(&repo, &Allow, &Allow)
            .execute(key(1), changed)
            .await,
        Err(AppError::IdempotencyConflict)
    );
}

#[tokio::test]
async fn removal_is_optimistic_tombstoned_and_does_not_evict_at_capacity() {
    let directory = Directory::new();
    let limits = Limits::new(1, 1).unwrap();
    let repo = SqliteRepository::open(directory.0.clone(), limits)
        .await
        .unwrap();
    let id = add(&repo, 1).await.unwrap();
    let user_file = directory.0.join("user-payload");
    fs::write(&user_file, b"preserve").unwrap();
    assert_eq!(add(&repo, 2).await, Err(AppError::Capacity));
    assert_eq!(add(&repo, 1).await.unwrap(), id);
    assert_eq!(
        repo.remove(key(1), 1).await,
        Err(PersistenceError::Conflict)
    );
    assert_eq!(repo.counts().await.unwrap(), (1, 1));
    repo.remove(key(1), 0).await.unwrap();
    drop(repo);
    let repo = SqliteRepository::open(directory.0.clone(), limits)
        .await
        .unwrap();
    assert_eq!(add(&repo, 1).await, Err(AppError::PreviouslyRemoved));
    assert_eq!(add(&repo, 2).await, Err(AppError::Capacity));
    assert_eq!(repo.counts().await.unwrap(), (0, 1));
    assert_eq!(fs::read(user_file).unwrap(), b"preserve");
}

#[tokio::test]
async fn unknown_version_and_unversioned_foreign_database_are_not_migrated() {
    for sql in [
        "PRAGMA user_version=99",
        "CREATE TABLE foreign_data(value TEXT)",
    ] {
        let directory = Directory::new();
        fs::create_dir(&directory.0).unwrap();
        let file = directory.0.join("admission.sqlite");
        let db = Connection::open(&file).unwrap();
        db.execute_batch(sql).unwrap();
        drop(db);
        let original = fs::read(&file).unwrap();
        assert!(matches!(
            SqliteRepository::open(directory.0.clone(), Limits::default()).await,
            Err(PersistenceError::UnsupportedVersion)
        ));
        assert_eq!(fs::read(file).unwrap(), original);
    }
}

#[tokio::test]
async fn corrupt_checksum_and_receipt_pair_fail_closed() {
    let directory = Directory::new();
    let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
        .await
        .unwrap();
    add(&repo, 1).await.unwrap();
    repo.run(|inner| {
        inner.db.execute("UPDATE jobs SET priority=0", [])?;
        Ok(())
    })
    .await
    .unwrap();
    assert!(matches!(
        repo.receipt(key(1)).await,
        Err(AppError::CorruptRepository)
    ));
    repo.run(|inner| {
        inner
            .db
            .execute("UPDATE schema_migrations SET checksum=zeroblob(32)", [])?;
        Ok(())
    })
    .await
    .unwrap();
    drop(repo);
    assert!(matches!(
        SqliteRepository::open(directory.0.clone(), Limits::default()).await,
        Err(PersistenceError::Corrupt)
    ));
}

#[test]
fn limits_and_errors_are_bounded_and_non_sensitive() {
    assert!(Limits::new(0, 1).is_err());
    assert!(Limits::new(2, 1).is_err());
    assert!(Limits::new(1, 100_001).is_err());
    assert_eq!(
        PersistenceError::Unavailable.to_string(),
        "PERSISTENCE-UNAVAILABLE"
    );
    assert_eq!(PersistenceError::Corrupt.code(), "PERSISTENCE-CORRUPT");
    assert_eq!(
        PersistenceError::InvalidPath.to_string(),
        "PERSISTENCE-INVALID-PATH"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_caller_holds_database_credit_until_blocking_work_finishes() {
    let directory = Directory::new();
    let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
        .await
        .unwrap();
    let (started, observed) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let worker_repo = repo.clone();
    let caller = tokio::spawn(async move {
        worker_repo
            .run(move |_| {
                let _ = started.send(());
                wait.recv().unwrap();
                Ok(())
            })
            .await
    });
    observed.await.unwrap();
    caller.abort();
    let _ = caller.await;
    assert_eq!(repo.admission.available_permits(), 0);
    release.send(()).unwrap();
    assert_eq!(repo.counts().await.unwrap(), (0, 0));
    assert_eq!(repo.admission.available_permits(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn redirected_parent_is_allowed_but_private_leaf_symlink_is_rejected() {
    let directory = Directory::new();
    fs::create_dir(&directory.0).unwrap();
    let actual = directory.0.join("actual");
    fs::create_dir(&actual).unwrap();
    let redirected = directory.0.join("redirected");
    std::os::unix::fs::symlink(&actual, &redirected).unwrap();
    let repo = SqliteRepository::open(redirected.join("private"), Limits::default())
        .await
        .unwrap();
    add(&repo, 1).await.unwrap();
    drop(repo);
    assert!(actual.join("private/admission.sqlite").exists());
    let bad = directory.0.join("bad");
    std::os::unix::fs::symlink(actual.join("private"), &bad).unwrap();
    assert!(matches!(
        SqliteRepository::open(bad, Limits::default()).await,
        Err(PersistenceError::InvalidPath)
    ));
}

mod transfer_state {
    use super::*;
    use fhd_app::{DurableExtent, TransferRepository};
    use fhd_domain::{ByteRange, Job, JobCommand, SegmentState, StopReason};

    /// Test digest derived from the range; real digests come from hashing synced bytes.
    fn ext(start: u64, end: u64) -> DurableExtent {
        DurableExtent::new(ByteRange::new(start, end).unwrap(), [start as u8; 32])
    }
    async fn step(repo: &SqliteRepository, job: &mut Job, command: JobCommand) {
        for event in job.decide(command).unwrap() {
            repo.commit_transition(event.clone()).await.unwrap();
            job.apply(&event).unwrap();
        }
    }
    async fn loaded(repo: &SqliteRepository, id: JobId) -> Job {
        repo.load_jobs()
            .await
            .unwrap()
            .into_iter()
            .find(|j| j.id() == id)
            .unwrap()
    }
    /// Admitted job, probed as 10 bytes, with [0,4) committed durable.
    async fn partly_durable(repo: &SqliteRepository) -> Job {
        let id = add(repo, 1).await.unwrap();
        let mut job = loaded(repo, id).await;
        assert_eq!((job.state(), job.version()), (JobState::Queued, 0));
        step(repo, &mut job, JobCommand::Start).await;
        step(
            repo,
            &mut job,
            JobCommand::ProbeSucceeded {
                total: 10,
                max_segments: 4,
                validator: Some([5; 32]),
            },
        )
        .await;
        let first = job.segments().unwrap().segments()[0].id();
        job.split_pending(first, 4).unwrap();
        let lease = job.lease_segment(first, 1).unwrap();
        job.mark_written(lease).unwrap();
        let ticket = job.prepare_sync().unwrap();
        let batch = job.acknowledge_sync(ticket).unwrap();
        let ranges: Vec<_> = batch
            .ranges()
            .iter()
            .map(|r| ext(r.start(), r.end()))
            .collect();
        repo.commit_extents(batch.job(), batch.generation(), ranges.clone())
            .await
            .unwrap();
        // An ambiguous commit is retried with the same ranges.
        repo.commit_extents(batch.job(), batch.generation(), ranges)
            .await
            .unwrap();
        job.acknowledge_commit(batch).unwrap();
        job
    }

    #[tokio::test]
    async fn version_one_database_migrates_forward_once() {
        let directory = Directory::new();
        fs::create_dir(&directory.0).unwrap();
        let db = Connection::open(directory.0.join("admission.sqlite")).unwrap();
        db.execute_batch(MIGRATIONS[0]).unwrap();
        db.execute(
            "INSERT INTO schema_migrations(version,checksum) VALUES(1,?1)",
            [migration_checksum(1).as_slice()],
        )
        .unwrap();
        drop(db);
        for _ in 0..2 {
            let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
                .await
                .unwrap();
            let (version, applied) = repo
                .run(|inner| {
                    let v: i64 = inner
                        .db
                        .pragma_query_value(None, "user_version", |r| r.get(0))?;
                    let n: i64 =
                        inner
                            .db
                            .query_row("SELECT count(*) FROM schema_migrations", [], |r| {
                                r.get(0)
                            })?;
                    Ok((v, n))
                })
                .await
                .unwrap();
            assert_eq!((version, applied), (LATEST, LATEST));
        }
    }

    #[tokio::test]
    async fn durable_progress_survives_reopen_and_nothing_else_does() {
        let directory = Directory::new();
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let mut job = partly_durable(&repo).await;
        // Written but never committed: must not survive.
        let tail = job.segments().unwrap().segments()[1].id();
        let lease = job.lease_segment(tail, 2).unwrap();
        job.mark_written(lease).unwrap();
        let expected = job.projection();
        let id = job.id();
        drop(repo);

        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let mut restored = loaded(&repo, id).await;
        assert_eq!(restored.projection(), expected);
        assert_eq!(restored.version(), 2);
        let states: Vec<_> = restored
            .segments()
            .unwrap()
            .segments()
            .iter()
            .map(|s| (s.range().start(), s.state()))
            .collect();
        assert_eq!(
            states,
            vec![(0, SegmentState::Durable), (4, SegmentState::Pending)]
        );
        step(&repo, &mut restored, JobCommand::Pause).await;
        step(&repo, &mut restored, JobCommand::WorkersDrained).await;
        assert_eq!(loaded(&repo, id).await.state(), JobState::Paused);
    }

    #[tokio::test]
    async fn stale_events_and_foreign_extents_conflict() {
        let directory = Directory::new();
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let mut job = partly_durable(&repo).await;
        let pause = job.decide(JobCommand::Pause).unwrap().remove(0);
        let fail = job
            .decide(JobCommand::Fail {
                reason: StopReason::Policy,
            })
            .unwrap()
            .remove(0);
        repo.commit_transition(pause.clone()).await.unwrap();
        job.apply(&pause).unwrap();
        assert_eq!(
            repo.commit_transition(fail).await,
            Err(CommitError::Conflict)
        );
        let generation = job.generation();
        for ranges in [
            vec![ext(2, 6)],
            vec![ext(6, 8), ext(7, 9)],
            vec![DurableExtent::new(ByteRange::new(0, 4).unwrap(), [9; 32])],
        ] {
            assert_eq!(
                repo.commit_extents(job.id(), generation, ranges).await,
                Err(CommitError::Conflict)
            );
        }
        assert_eq!(
            repo.commit_extents(job.id(), generation.next().unwrap(), vec![ext(4, 6)])
                .await,
            Err(CommitError::Conflict)
        );
        assert_eq!(loaded(&repo, job.id()).await.projection(), job.projection());
    }

    #[tokio::test]
    async fn new_representation_drops_old_extents_and_removal_cascades() {
        let directory = Directory::new();
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let mut job = partly_durable(&repo).await;
        step(&repo, &mut job, JobCommand::RepresentationChanged).await;
        step(&repo, &mut job, JobCommand::WorkersDrained).await;
        assert_eq!((job.state(), job.generation().get()), (JobState::Queued, 2));
        let restored = loaded(&repo, job.id()).await;
        assert_eq!(restored.projection(), job.projection());
        assert!(restored.segments().is_none());
        async fn rows(repo: &SqliteRepository) -> (i64, i64) {
            repo.run(|inner| {
                let e: i64 = inner
                    .db
                    .query_row("SELECT count(*) FROM extents", [], |r| r.get(0))?;
                let s: i64 = inner
                    .db
                    .query_row("SELECT count(*) FROM job_state", [], |r| r.get(0))?;
                Ok((e, s))
            })
            .await
            .unwrap()
        }
        assert_eq!(rows(&repo).await, (0, 1));
        repo.remove(key(1), job.version()).await.unwrap();
        assert_eq!(rows(&repo).await, (0, 0));
        assert!(repo.load_jobs().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn durability_claim_beyond_repository_is_refused() {
        let directory = Directory::new();
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let mut job = partly_durable(&repo).await;
        let tail = job.segments().unwrap().segments()[1].id();
        let lease = job.lease_segment(tail, 2).unwrap();
        job.mark_written(lease).unwrap();
        let ticket = job.prepare_sync().unwrap();
        let batch = job.acknowledge_sync(ticket).unwrap();
        // Skips commit_extents: a buggy coordinator acknowledging in memory only.
        job.acknowledge_commit(batch).unwrap();
        let event = job
            .decide(JobCommand::AllSegmentsDurable)
            .unwrap()
            .remove(0);
        assert_eq!(
            repo.commit_transition(event).await,
            Err(CommitError::Conflict)
        );
        assert_eq!(
            loaded(&repo, job.id()).await.state(),
            JobState::Transferring
        );
    }

    #[tokio::test]
    async fn extents_outside_current_generation_fail_closed_on_open() {
        let directory = Directory::new();
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let job = partly_durable(&repo).await;
        let id = signed_id(job.id()).unwrap();
        repo.run(move |inner| {
            inner.db.execute(
                "INSERT INTO extents(job_id,generation,start,end_excl,digest) VALUES(?1,7,4,6,zeroblob(32))",
                [id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        drop(repo);
        assert!(matches!(
            SqliteRepository::open(directory.0.clone(), Limits::default()).await,
            Err(PersistenceError::Corrupt)
        ));
    }

    #[tokio::test]
    async fn reprobe_keeps_stored_plan_so_reload_still_works() {
        let directory = Directory::new();
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let mut job = partly_durable(&repo).await;
        step(&repo, &mut job, JobCommand::Pause).await;
        step(&repo, &mut job, JobCommand::WorkersDrained).await;
        // Paused: the drain is over, so no more extents may land.
        assert_eq!(
            repo.commit_extents(job.id(), job.generation(), vec![ext(4, 6)])
                .await,
            Err(CommitError::Conflict)
        );
        step(&repo, &mut job, JobCommand::Resume).await;
        step(&repo, &mut job, JobCommand::Start).await;
        step(
            &repo,
            &mut job,
            JobCommand::ProbeSucceeded {
                total: 10,
                max_segments: 2,
                validator: Some([5; 32]),
            },
        )
        .await;
        assert_eq!(job.plan(), Some((10, 4)));
        drop(repo);
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let restored = loaded(&repo, job.id()).await;
        assert_eq!(restored.plan(), Some((10, 4)));
        assert_eq!(restored.projection(), job.projection());
    }

    #[tokio::test]
    async fn extents_that_restore_could_not_rebuild_are_refused() {
        let directory = Directory::new();
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let job = partly_durable(&repo).await;
        let (id, generation) = (job.id(), job.generation());
        // durable [0,4) [6,7) plus gaps [4,6) [7,10): four segments, the maximum.
        repo.commit_extents(id, generation, vec![ext(6, 7)])
            .await
            .unwrap();
        assert_eq!(
            repo.commit_extents(id, generation, vec![ext(8, 9)]).await,
            Err(CommitError::Conflict)
        );
        assert_eq!(
            repo.commit_extents(id, generation, vec![ext(4, 7)]).await,
            Err(CommitError::Conflict),
            "superset of a durable extent"
        );
        assert_eq!(
            loaded(&repo, id).await.segments().unwrap().durable_bytes(),
            5
        );
    }

    #[tokio::test]
    async fn active_job_cannot_be_removed() {
        let directory = Directory::new();
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let mut job = partly_durable(&repo).await;
        assert_eq!(
            repo.remove(key(1), job.version()).await,
            Err(PersistenceError::Conflict)
        );
        step(&repo, &mut job, JobCommand::Pause).await;
        step(&repo, &mut job, JobCommand::WorkersDrained).await;
        repo.remove(key(1), job.version()).await.unwrap();
    }

    #[tokio::test]
    async fn empty_file_commits_and_restores_as_complete() {
        let directory = Directory::new();
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let id = add(&repo, 1).await.unwrap();
        let mut job = loaded(&repo, id).await;
        step(&repo, &mut job, JobCommand::Start).await;
        step(
            &repo,
            &mut job,
            JobCommand::ProbeSucceeded {
                total: 0,
                max_segments: 1,
                validator: Some([5; 32]),
            },
        )
        .await;
        step(&repo, &mut job, JobCommand::AllSegmentsDurable).await;
        step(&repo, &mut job, JobCommand::WorkersDrained).await;
        assert_eq!(job.state(), JobState::Verifying);
        drop(repo);
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        assert_eq!(loaded(&repo, id).await.projection(), job.projection());
    }

    #[tokio::test]
    async fn durable_extents_return_committed_digests_unmerged() {
        let directory = Directory::new();
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let job = partly_durable(&repo).await;
        repo.commit_extents(job.id(), job.generation(), vec![ext(4, 6)])
            .await
            .unwrap();
        assert_eq!(
            repo.durable_extents(job.id()).await.unwrap(),
            vec![ext(0, 4), ext(4, 6)]
        );
        // Touching extents stay separate rows but restore as one durable segment.
        let restored = loaded(&repo, job.id()).await;
        let map = restored.segments().unwrap();
        assert_eq!(map.durable_bytes(), 6);
        assert_eq!(map.segments().len(), 2);
    }

    #[tokio::test]
    async fn validator_survives_reload_and_a_different_one_conflicts() {
        let directory = Directory::new();
        let repo = SqliteRepository::open(directory.0.clone(), Limits::default())
            .await
            .unwrap();
        let mut job = partly_durable(&repo).await;
        step(&repo, &mut job, JobCommand::Pause).await;
        step(&repo, &mut job, JobCommand::WorkersDrained).await;
        step(&repo, &mut job, JobCommand::Resume).await;
        step(&repo, &mut job, JobCommand::Start).await;
        let restored = loaded(&repo, job.id()).await;
        assert_eq!(restored.validator(), Some([5; 32]));
        // A forged re-probe event with another validator must not persist.
        let mut forged = loaded(&repo, job.id()).await;
        forged.handle(JobCommand::RepresentationChanged).unwrap();
        let event = forged.decide(JobCommand::WorkersDrained).unwrap().remove(0);
        assert_eq!(
            repo.commit_transition(event).await,
            Err(CommitError::Conflict),
            "stale version"
        );
        assert_eq!(loaded(&repo, job.id()).await.validator(), Some([5; 32]));
    }
}
