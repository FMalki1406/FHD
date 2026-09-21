use fhd_app::{AddDownload, AppError, Principal, ReceiptKey};
use fhd_domain::{DestinationRef, JobSpec, Priority, SourceRef};
use fhd_testkit::{Allow, CommitFault, Deny, MemoryRepository};

fn spec(destination: u64) -> JobSpec {
    JobSpec::new(
        SourceRef::new(1).unwrap(),
        DestinationRef::new(destination).unwrap(),
        Some([3; 32]),
        Priority::Normal,
        1024,
    )
    .unwrap()
}
fn key(principal: u64) -> ReceiptKey {
    ReceiptKey::new(Principal::new(principal).unwrap(), [8; 32])
}

#[tokio::test]
async fn lost_commit_response_replays_without_second_job() {
    let repo = MemoryRepository::new(4);
    let service = AddDownload::new(&repo, &Allow, &Allow);
    repo.fail_next(CommitFault::AfterCommit);
    assert_eq!(
        service.execute(key(1), spec(1)).await,
        Err(AppError::PersistenceUnavailable)
    );
    assert_eq!(repo.job_count(), 1);
    let id = service.execute(key(1), spec(1)).await.unwrap();
    assert_eq!(service.execute(key(1), spec(1)).await.unwrap(), id);
    assert_eq!(repo.commit_calls(), 1);
    assert_eq!(
        service.execute(key(1), spec(2)).await,
        Err(AppError::IdempotencyConflict)
    );
}

#[tokio::test]
async fn failed_commit_does_not_create_and_retry_can_succeed() {
    let repo = MemoryRepository::new(4);
    let service = AddDownload::new(&repo, &Allow, &Allow);
    repo.fail_next(CommitFault::BeforeCommit);
    assert_eq!(
        service.execute(key(1), spec(1)).await,
        Err(AppError::PersistenceUnavailable)
    );
    assert_eq!(repo.job_count(), 0);
    assert!(service.execute(key(1), spec(1)).await.is_ok());
    assert_eq!(repo.job_count(), 1);
}

#[tokio::test]
async fn authorization_precedes_reads_and_expired_entitlement_only_blocks_new_jobs() {
    let repo = MemoryRepository::new(4);
    assert_eq!(
        AddDownload::new(&repo, &Deny, &Allow)
            .execute(key(1), spec(1))
            .await,
        Err(AppError::Forbidden)
    );
    assert_eq!(
        AddDownload::new(&repo, &Allow, &Deny)
            .execute(key(1), spec(1))
            .await,
        Err(AppError::EntitlementDenied)
    );
    assert_eq!(repo.commit_calls(), 0);
    let id = AddDownload::new(&repo, &Allow, &Allow)
        .execute(key(1), spec(1))
        .await
        .unwrap();
    assert_eq!(
        AddDownload::new(&repo, &Deny, &Allow)
            .execute(key(1), spec(1))
            .await,
        Err(AppError::Forbidden)
    );
    assert_eq!(
        AddDownload::new(&repo, &Allow, &Deny)
            .execute(key(1), spec(1))
            .await
            .unwrap(),
        id
    );
    assert_eq!(
        AddDownload::new(&repo, &Allow, &Deny)
            .execute(key(2), spec(1))
            .await,
        Err(AppError::EntitlementDenied)
    );
    assert_eq!(repo.commit_calls(), 1);
}

#[tokio::test]
async fn source_scope_capacity_and_tombstones_are_independent() {
    let repo = MemoryRepository::new(2);
    let service = AddDownload::new(&repo, &Allow, &Allow);
    let first = service.execute(key(1), spec(1)).await.unwrap();
    let second = service.execute(key(2), spec(1)).await.unwrap();
    assert_ne!(first, second);
    assert_eq!(service.execute(key(1), spec(1)).await.unwrap(), first);
    assert_eq!(
        service.execute(key(3), spec(1)).await,
        Err(AppError::Capacity)
    );
    repo.remove(key(1));
    assert_eq!(
        service.execute(key(1), spec(1)).await,
        Err(AppError::PreviouslyRemoved)
    );
    assert_eq!(
        service.execute(key(3), spec(1)).await,
        Err(AppError::Capacity)
    );
    assert_eq!(repo.job_count(), 1);
}

#[tokio::test]
async fn concurrent_first_reads_reconcile_the_atomic_receipt_winner() {
    use fhd_app::{AddUnitOfWork, CommitError, JobRepository, PortFuture, Receipt};
    use fhd_domain::JobId;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct RacingRepository {
        inner: MemoryRepository,
        barrier: tokio::sync::Barrier,
        reads: AtomicUsize,
    }
    impl JobRepository for RacingRepository {
        fn receipt(&self, key: ReceiptKey) -> PortFuture<'_, Result<Option<Receipt>, AppError>> {
            Box::pin(async move {
                let value = self.inner.receipt(key).await?;
                // All eight callers observe absence before any attempts commit.
                if self.reads.fetch_add(1, Ordering::Relaxed) < 8 {
                    self.barrier.wait().await;
                }
                Ok(value)
            })
        }
        fn reserve_id(&self) -> PortFuture<'_, Result<JobId, AppError>> {
            self.inner.reserve_id()
        }
        fn commit_add(&self, unit: AddUnitOfWork) -> PortFuture<'_, Result<(), CommitError>> {
            self.inner.commit_add(unit)
        }
    }
    let repo = Arc::new(RacingRepository {
        inner: MemoryRepository::new(8),
        barrier: tokio::sync::Barrier::new(8),
        reads: AtomicUsize::new(0),
    });
    let mut callers = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let repo = repo.clone();
        callers.spawn(async move {
            AddDownload::new(repo.as_ref(), &Allow, &Allow)
                .execute(key(1), spec(1))
                .await
                .unwrap()
        });
    }
    let mut results = Vec::new();
    while let Some(id) = callers.join_next().await {
        results.push(id.unwrap());
    }
    assert_eq!(results.len(), 8);
    assert!(results.iter().all(|id| *id == results[0]));
    assert_eq!(repo.inner.job_count(), 1);
    assert_eq!(repo.inner.commit_calls(), 8);
}
