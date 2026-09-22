//! Application decisions over ports. No networking, filesystem or database dependency.
#![forbid(unsafe_code)]
pub mod storage;

use fhd_domain::{ByteRange, Generation, Job, JobEvent, JobId, JobSpec};
use std::{future::Future, pin::Pin};

pub type PortFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Assigned by the authenticated gateway; never populated from the command body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Principal(u64);
impl Principal {
    pub fn new(value: u64) -> Result<Self, AppError> {
        if value == 0 {
            Err(AppError::InvalidInput)
        } else {
            Ok(Self(value))
        }
    }
    pub fn get(self) -> u64 {
        self.0
    }
}

/// Fixed-size request identity, scoped by authenticated principal. Not authorization.
/// Gateway hashes the sender's stable request identifier; no raw URL belongs here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReceiptKey {
    principal: Principal,
    digest: [u8; 32],
}
impl ReceiptKey {
    pub fn new(principal: Principal, digest: [u8; 32]) -> Self {
        Self { principal, digest }
    }
    pub fn principal(self) -> Principal {
        self.principal
    }
    pub fn digest(self) -> [u8; 32] {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppError {
    InvalidInput,
    Forbidden,
    EntitlementDenied,
    PersistenceUnavailable,
    IdempotencyConflict,
    PreviouslyRemoved,
    Capacity,
    CorruptRepository,
}
impl AppError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "APP-INVALID-INPUT",
            Self::Forbidden => "AUTH-DENIED",
            Self::EntitlementDenied => "ENTITLEMENT-DENIED",
            Self::PersistenceUnavailable => "PERSISTENCE-UNAVAILABLE",
            Self::IdempotencyConflict => "COMMAND-CONFLICT",
            Self::PreviouslyRemoved => "COMMAND-REMOVED",
            Self::Capacity => "QUEUE-CAPACITY",
            Self::CorruptRepository => "PERSISTENCE-CORRUPT",
        }
    }
}
impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for AppError {}

pub trait Authorizer: Send + Sync {
    fn authorize_add(&self, principal: Principal, spec: &JobSpec) -> Result<(), AppError>;
}
pub trait EntitlementGate: Send + Sync {
    fn authorize_add(&self, principal: Principal, spec: &JobSpec) -> Result<(), AppError>;
}

#[derive(Clone)]
pub struct Receipt {
    key: ReceiptKey,
    original: JobSpec,
    job: JobId,
    removed: bool,
}
impl Receipt {
    pub fn new(key: ReceiptKey, original: JobSpec, job: JobId) -> Self {
        Self {
            key,
            original,
            job,
            removed: false,
        }
    }
    pub fn key(&self) -> ReceiptKey {
        self.key
    }
    pub fn job(&self) -> JobId {
        self.job
    }
    pub fn original(&self) -> &JobSpec {
        &self.original
    }
    pub fn removed(&self) -> bool {
        self.removed
    }
    pub fn tombstone(&self) -> Self {
        let mut r = self.clone();
        r.removed = true;
        r
    }
    fn replay(&self, key: ReceiptKey, spec: &JobSpec) -> Result<JobId, AppError> {
        if self.key != key {
            return Err(AppError::CorruptRepository);
        }
        if &self.original != spec {
            return Err(AppError::IdempotencyConflict);
        }
        if self.removed {
            return Err(AppError::PreviouslyRemoved);
        }
        Ok(self.job)
    }
}

/// An indivisible create transaction. Repository atomically enforces unique receipt
/// and job IDs, capacity, and insert-only semantics. No ACK until commit completes.
pub struct AddUnitOfWork {
    job: Job,
    receipt: Receipt,
}
impl AddUnitOfWork {
    pub fn job(&self) -> &Job {
        &self.job
    }
    pub fn receipt(&self) -> &Receipt {
        &self.receipt
    }
    pub fn into_parts(self) -> (Job, Receipt) {
        (self.job, self.receipt)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitError {
    Conflict,
    Unavailable,
    Capacity,
}

/// A synced range and the SHA-256 of its bytes, hashed after sync. Storage rehashes
/// against this digest before trusting the range again after a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableExtent {
    range: ByteRange,
    digest: [u8; 32],
}
impl DurableExtent {
    pub fn new(range: ByteRange, digest: [u8; 32]) -> Self {
        Self { range, digest }
    }
    pub fn range(self) -> ByteRange {
        self.range
    }
    pub fn digest(self) -> [u8; 32] {
        self.digest
    }
}

/// Durable transfer state. Each call is one transaction; nothing is acknowledged
/// before commit. Callers apply a domain change in memory only after its commit.
pub trait TransferRepository: Send + Sync {
    /// Stores `event.outcome()` only if the stored version, state and generation are
    /// exactly what the event was decided against; otherwise `Conflict`.
    fn commit_transition(&self, event: JobEvent) -> PortFuture<'_, Result<(), CommitError>>;
    /// Records synced extents of the current generation. Re-committing an identical
    /// extent is a no-op, so an ambiguous commit can be retried.
    fn commit_extents(
        &self,
        job: JobId,
        generation: Generation,
        extents: Vec<DurableExtent>,
    ) -> PortFuture<'_, Result<(), CommitError>>;
    /// Every admitted job, rebuilt from durable state only.
    fn load_jobs(&self) -> PortFuture<'_, Result<Vec<Job>, AppError>>;
    /// Durable extents of the job's current generation, ascending, for storage recovery.
    fn durable_extents(&self, job: JobId) -> PortFuture<'_, Result<Vec<DurableExtent>, AppError>>;
}

pub trait JobRepository: Send + Sync {
    fn receipt(&self, key: ReceiptKey) -> PortFuture<'_, Result<Option<Receipt>, AppError>>;
    /// Reservation can leave gaps; IDs must never be reused. The storage adapter
    /// durably reserves across process restarts and concurrent callers.
    fn reserve_id(&self) -> PortFuture<'_, Result<JobId, AppError>>;
    fn commit_add(&self, unit: AddUnitOfWork) -> PortFuture<'_, Result<(), CommitError>>;
}

/// SourceRef and DestinationRef must address immutable, never-reused bindings.
/// Changing URL, credentials, request policy or destination creates a new binding.
/// This service compares the entire original spec, not just its live job settings.
/// Dropping the caller future after a commit does not undo admission: replay key.
pub struct AddDownload<'a> {
    repository: &'a dyn JobRepository,
    authorizer: &'a dyn Authorizer,
    entitlement: &'a dyn EntitlementGate,
}
impl<'a> AddDownload<'a> {
    pub fn new(
        repository: &'a dyn JobRepository,
        authorizer: &'a dyn Authorizer,
        entitlement: &'a dyn EntitlementGate,
    ) -> Self {
        Self {
            repository,
            authorizer,
            entitlement,
        }
    }

    pub async fn execute(&self, key: ReceiptKey, spec: JobSpec) -> Result<JobId, AppError> {
        // Replays require current authorization. A changed entitlement must not
        // prevent reconciliation of a create that was already durably accepted.
        self.authorizer.authorize_add(key.principal, &spec)?;
        if let Some(receipt) = self.repository.receipt(key).await? {
            return receipt.replay(key, &spec);
        }
        self.entitlement.authorize_add(key.principal, &spec)?;
        let id = self.repository.reserve_id().await?;
        let unit = AddUnitOfWork {
            job: Job::new(id, spec.clone()),
            receipt: Receipt::new(key, spec.clone(), id),
        };
        match self.repository.commit_add(unit).await {
            Ok(()) => Ok(id),
            Err(CommitError::Conflict) => self
                .repository
                .receipt(key)
                .await?
                .ok_or(AppError::CorruptRepository)?
                .replay(key, &spec),
            // A commit may have succeeded before the response was lost. Do not
            // manufacture success or compensate by deletion; retry the same key.
            Err(CommitError::Unavailable) => Err(AppError::PersistenceUnavailable),
            Err(CommitError::Capacity) => Err(AppError::Capacity),
        }
    }
}
