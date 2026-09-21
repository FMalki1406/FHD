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
