//! Durable admission repository, not a vault or a transfer-state repository.
#![forbid(unsafe_code)]

use fhd_app::{
    AddUnitOfWork, AppError, CommitError, JobRepository, PortFuture, Receipt, ReceiptKey,
};
use fhd_domain::{DestinationRef, JobId, JobSpec, JobState, Priority, SourceRef};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

const MIGRATION: &str = include_str!("../migrations/001_admission.sql");
const APPLICATION_ID: i64 = 1_179_141_169;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
fn migration_checksum() -> [u8; 32] {
    Sha256::digest(MIGRATION.replace("\r\n", "\n").as_bytes()).into()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistenceError {
    InvalidPath,
    InvalidLimits,
    Locked,
    Unavailable,
    UnsupportedVersion,
    Corrupt,
    Capacity,
    Conflict,
    Missing,
    Removed,
}
impl PersistenceError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidPath => "PERSISTENCE-INVALID-PATH",
            Self::InvalidLimits => "PERSISTENCE-INVALID-LIMITS",
            Self::Locked => "PERSISTENCE-LOCKED",
            Self::Unavailable => "PERSISTENCE-UNAVAILABLE",
            Self::UnsupportedVersion => "PERSISTENCE-UNSUPPORTED-VERSION",
            Self::Corrupt => "PERSISTENCE-CORRUPT",
            Self::Capacity => "PERSISTENCE-CAPACITY",
            Self::Conflict => "PERSISTENCE-CONFLICT",
            Self::Missing => "PERSISTENCE-MISSING",
            Self::Removed => "PERSISTENCE-REMOVED",
        }
    }
}
impl fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for PersistenceError {}
impl From<rusqlite::Error> for PersistenceError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Unavailable
    }
}
type Result<T> = std::result::Result<T, PersistenceError>;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    jobs: usize,
    receipts: usize,
}
impl Limits {
    pub fn new(jobs: usize, receipts: usize) -> Result<Self> {
        if !(1..=10_000).contains(&jobs) || !(jobs..=100_000).contains(&receipts) {
            return Err(PersistenceError::InvalidLimits);
        }
        Ok(Self { jobs, receipts })
    }
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            jobs: 10_000,
            receipts: 40_000,
        }
    }
}

struct Inner {
    db: Connection,
    limits: Limits,
    #[cfg(test)]
    fault: Fault,
    // Connection must close before releasing the exclusive owner lock.
    _lock: File,
}
#[derive(Clone)]
pub struct SqliteRepository {
    inner: Arc<Mutex<Inner>>,
    admission: Arc<tokio::sync::Semaphore>,
}

fn ordinary(path: &Path, directory: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PersistenceError::InvalidPath)?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(PersistenceError::InvalidPath);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(PersistenceError::InvalidPath);
        }
    }
    Ok(())
}
fn existing_file(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            ordinary(path, false)?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(PersistenceError::InvalidPath),
    }
}
fn validate_schema(db: &Connection, allow_empty: bool) -> Result<()> {
    let version: i64 = db.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version == 0 && allow_empty {
        let tables: i64 = db.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )?;
        if tables == 0 {
            return Ok(());
        }
    }
    if version != 1 {
        return Err(PersistenceError::UnsupportedVersion);
    }
    let app: i64 = db.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if app != APPLICATION_ID {
        return Err(PersistenceError::Corrupt);
    }
    let checksum: Vec<u8> = db
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE version=1",
            [],
            |r| r.get(0),
        )
        .map_err(|_| PersistenceError::Corrupt)?;
    if checksum.as_slice() != migration_checksum().as_slice() {
        return Err(PersistenceError::Corrupt);
    }
    Ok(())
}

impl SqliteRepository {
    /// Directory must be private and caller-owned. No guarantee against hostile
    /// same-user concurrent path swaps; no database or vault migration from legacy.
    pub async fn open(directory: PathBuf, limits: Limits) -> Result<Self> {
        tokio::task::spawn_blocking(move || Self::open_blocking(&directory, limits))
            .await
            .map_err(|_| PersistenceError::Unavailable)?
    }
    fn open_blocking(directory: &Path, limits: Limits) -> Result<Self> {
        if !directory.is_absolute() {
            return Err(PersistenceError::InvalidPath);
        }
        let parent = directory
            .parent()
            .ok_or(PersistenceError::InvalidPath)?
            .canonicalize()
            .map_err(|_| PersistenceError::InvalidPath)?;
        let directory = parent.join(directory.file_name().ok_or(PersistenceError::InvalidPath)?);
        let directory = directory.as_path();
        match fs::create_dir(directory) {
            Ok(()) => {
                #[cfg(unix)]
                File::open(&parent)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| PersistenceError::Unavailable)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(PersistenceError::InvalidPath),
        }
        ordinary(directory, true)?;
        let lock_path = directory.join("owner.lock");
        existing_file(&lock_path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| PersistenceError::Unavailable)?;
        lock.try_lock().map_err(|_| PersistenceError::Locked)?;
        let path = directory.join("admission.sqlite");
        let exists = existing_file(&path)?;
        for name in [
            "admission.sqlite-wal",
            "admission.sqlite-shm",
            "admission.sqlite-journal",
        ] {
            existing_file(&directory.join(name))?;
        }
        // Reject unsupported databases before selecting a journal mode or migrating.
        if exists {
            let reader = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            reader.pragma_update(None, "trusted_schema", "OFF")?;
            validate_schema(&reader, true)?;
        }
        let mut db = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )?;
        let mode: String = db.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        if mode != "wal" {
            return Err(PersistenceError::Unavailable);
        }
        let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version == 0 {
            validate_schema(&db, true)?;
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(MIGRATION)?;
            tx.execute(
                "INSERT INTO schema_migrations(version,checksum) VALUES(1,?1)",
                [migration_checksum().as_slice()],
            )?;
            tx.commit()?;
        }
        validate_schema(&db, false)?;
        let jobs: i64 = db.query_row("SELECT count(*) FROM jobs", [], |r| r.get(0))?;
        let receipts: i64 =
            db.query_row("SELECT count(*) FROM command_receipts", [], |r| r.get(0))?;
        if jobs > limits.jobs as i64 || receipts > limits.receipts as i64 {
            return Err(PersistenceError::Capacity);
        }
        let invalid: i64 = db.query_row("SELECT count(*) FROM command_receipts r LEFT JOIN jobs j ON j.id=r.job_id WHERE (r.removed=0 AND j.id IS NULL) OR (r.removed=1 AND j.id IS NOT NULL) OR r.job_id>(SELECT last_id FROM sequence WHERE singleton=1)", [], |r| r.get(0))?;
        let orphan: i64 = db.query_row("SELECT count(*) FROM jobs j LEFT JOIN command_receipts r ON j.id=r.job_id WHERE r.job_id IS NULL", [], |r| r.get(0))?;
        let sequence: i64 =
            db.query_row("SELECT last_id FROM sequence WHERE singleton=1", [], |r| {
                r.get(0)
            })?;
        if invalid != 0 || orphan != 0 || sequence < 0 {
            return Err(PersistenceError::Corrupt);
        }
        #[cfg(unix)]
        File::open(directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| PersistenceError::Unavailable)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                db,
                limits,
                #[cfg(test)]
                fault: Fault::None,
                _lock: lock,
            })),
            admission: Arc::new(tokio::sync::Semaphore::new(1)),
        })
    }
    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut Inner) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let inner = self.inner.clone();
        let permit = self
            .admission
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| PersistenceError::Unavailable)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut guard = inner.lock().map_err(|_| PersistenceError::Unavailable)?;
            work(&mut guard)
        })
        .await
        .map_err(|_| PersistenceError::Unavailable)?
    }
    /// Trusted application mutation. Caller must authorize this principal/key.
    /// Only the admission row is removed; no transfer files are touched.
    pub async fn remove(&self, key: ReceiptKey, expected_version: u64) -> Result<()> {
        self.run(move |inner| {
            let version = i64::try_from(expected_version).map_err(|_| PersistenceError::Conflict)?;
            let tx = inner.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let receipt = load_receipt(&tx, key)?.ok_or(PersistenceError::Missing)?;
            if receipt.removed() { return Err(PersistenceError::Removed); }
            let id = signed_id(receipt.job())?;
            if tx.execute("DELETE FROM jobs WHERE id=?1 AND version=?2", params![id, version])? != 1 { return Err(PersistenceError::Conflict); }
            if tx.execute("UPDATE command_receipts SET removed=1 WHERE principal=?1 AND key_hash=?2 AND removed=0", params![key.principal().get().to_le_bytes().as_slice(), key.digest().as_slice()])? != 1 { return Err(PersistenceError::Corrupt); }
            tx.commit()?;
            Ok(())
        }).await
    }
    /// Admission counts only; no paths, identifiers, URLs or credential values.
    pub async fn counts(&self) -> Result<(usize, usize)> {
        self.run(|inner| {
            let jobs: i64 = inner
                .db
                .query_row("SELECT count(*) FROM jobs", [], |r| r.get(0))?;
            let receipts: i64 =
                inner
                    .db
                    .query_row("SELECT count(*) FROM command_receipts", [], |r| r.get(0))?;
            Ok((
                usize::try_from(jobs).map_err(|_| PersistenceError::Corrupt)?,
                usize::try_from(receipts).map_err(|_| PersistenceError::Corrupt)?,
            ))
        })
        .await
    }
}

fn signed_id(id: JobId) -> Result<i64> {
    i64::try_from(id.get()).map_err(|_| PersistenceError::Corrupt)
}
fn priority(value: Priority) -> i64 {
    match value {
        Priority::Low => 0,
        Priority::Normal => 1,
        Priority::High => 2,
    }
}
type SpecRow = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, i64, i64);
fn decode_spec(row: SpecRow) -> Result<JobSpec> {
    let (source, destination, expected, importance, max) = row;
    let source = u64::from_le_bytes(source.try_into().map_err(|_| PersistenceError::Corrupt)?);
    let destination = u64::from_le_bytes(
        destination
            .try_into()
            .map_err(|_| PersistenceError::Corrupt)?,
    );
    let importance = match importance {
        0 => Priority::Low,
        1 => Priority::Normal,
        2 => Priority::High,
        _ => return Err(PersistenceError::Corrupt),
    };
    JobSpec::new(
        SourceRef::new(source).map_err(|_| PersistenceError::Corrupt)?,
        DestinationRef::new(destination).map_err(|_| PersistenceError::Corrupt)?,
        expected
            .map(|v| v.try_into().map_err(|_| PersistenceError::Corrupt))
            .transpose()?,
        importance,
        u64::try_from(max).map_err(|_| PersistenceError::Corrupt)?,
    )
    .map_err(|_| PersistenceError::Corrupt)
}
fn load_receipt(db: &Connection, key: ReceiptKey) -> Result<Option<Receipt>> {
    type Row = (i64, i64, SpecRow);
    let found: Option<Row> = db.query_row("SELECT job_id,removed,source,destination,expected,priority,max_bytes FROM command_receipts WHERE principal=?1 AND key_hash=?2",
        params![key.principal().get().to_le_bytes().as_slice(), key.digest().as_slice()], |r| Ok((r.get(0)?,r.get(1)?,(r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)))).optional()?;
    let Some((id, removed, row)) = found else {
        return Ok(None);
    };
    let spec = decode_spec(row)?;
    let id_value = u64::try_from(id).map_err(|_| PersistenceError::Corrupt)?;
    let job = JobId::new(id_value).map_err(|_| PersistenceError::Corrupt)?;
    let saved: Option<SpecRow> = db
        .query_row(
            "SELECT source,destination,expected,priority,max_bytes FROM jobs WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    match (removed, saved) {
        (0, Some(saved)) => {
            if decode_spec(saved)? != spec {
                return Err(PersistenceError::Corrupt);
            }
        }
        (1, None) => {}
        _ => return Err(PersistenceError::Corrupt),
    }
    let receipt = Receipt::new(key, spec, job);
    Ok(Some(if removed == 1 {
        receipt.tombstone()
    } else {
        receipt
    }))
}
fn app_error(error: PersistenceError) -> AppError {
    match error {
        PersistenceError::Capacity => AppError::Capacity,
        PersistenceError::Corrupt | PersistenceError::UnsupportedVersion => {
            AppError::CorruptRepository
        }
        _ => AppError::PersistenceUnavailable,
    }
}
impl JobRepository for SqliteRepository {
    fn receipt(
        &self,
        key: ReceiptKey,
    ) -> PortFuture<'_, std::result::Result<Option<Receipt>, AppError>> {
        Box::pin(async move {
            self.run(move |inner| load_receipt(&inner.db, key))
                .await
                .map_err(app_error)
        })
    }
    fn reserve_id(&self) -> PortFuture<'_, std::result::Result<JobId, AppError>> {
        Box::pin(async move {
            self.run(|inner| {
                let tx = inner
                    .db
                    .transaction_with_behavior(TransactionBehavior::Immediate)?;
                let last: i64 =
                    tx.query_row("SELECT last_id FROM sequence WHERE singleton=1", [], |r| {
                        r.get(0)
                    })?;
                if last < 0 {
                    return Err(PersistenceError::Corrupt);
                }
                let next = last.checked_add(1).ok_or(PersistenceError::Capacity)?;
                if tx.execute(
                    "UPDATE sequence SET last_id=?1 WHERE singleton=1 AND last_id=?2",
                    params![next, last],
                )? != 1
                {
                    return Err(PersistenceError::Conflict);
                }
                tx.commit()?;
                JobId::new(next as u64).map_err(|_| PersistenceError::Corrupt)
            })
            .await
            .map_err(app_error)
        })
    }
    fn commit_add(
        &self,
        unit: AddUnitOfWork,
    ) -> PortFuture<'_, std::result::Result<(), CommitError>> {
        Box::pin(async move {
            self.run(move |inner| {
            let (job, receipt) = unit.into_parts();
            if job.id() != receipt.job() || job.spec() != receipt.original() || receipt.removed()
                || job.version() != 0 || job.state() != JobState::Queued || job.generation().get() != 1 { return Err(PersistenceError::Corrupt); }
            let id = signed_id(job.id())?;
            let key = receipt.key();
            let spec = receipt.original();
            let tx = inner.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM command_receipts WHERE principal=?1 AND key_hash=?2) OR EXISTS(SELECT 1 FROM jobs WHERE id=?3) OR EXISTS(SELECT 1 FROM command_receipts WHERE job_id=?3)", params![key.principal().get().to_le_bytes().as_slice(), key.digest().as_slice(), id], |r| r.get(0))?;
            if exists { return Err(PersistenceError::Conflict); }
            let last: i64 = tx.query_row("SELECT last_id FROM sequence WHERE singleton=1", [], |r| r.get(0))?;
            if id > last { return Err(PersistenceError::Corrupt); }
            let jobs: i64 = tx.query_row("SELECT count(*) FROM jobs", [], |r| r.get(0))?;
            let receipts: i64 = tx.query_row("SELECT count(*) FROM command_receipts", [], |r| r.get(0))?;
            if jobs >= inner.limits.jobs as i64 || receipts >= inner.limits.receipts as i64 { return Err(PersistenceError::Capacity); }
            tx.execute("INSERT INTO jobs(id,source,destination,expected,priority,max_bytes,version) VALUES(?1,?2,?3,?4,?5,?6,0)", params![id, spec.source().get().to_le_bytes().as_slice(), spec.destination().get().to_le_bytes().as_slice(), spec.expected_sha256().as_ref().map(|v|v.as_slice()), priority(spec.priority()), spec.max_bytes() as i64])?;
            #[cfg(test)] if inner.fault == Fault::BeforeCommit { inner.fault = Fault::None; return Err(PersistenceError::Unavailable); }
            tx.execute("INSERT INTO command_receipts(principal,key_hash,job_id,source,destination,expected,priority,max_bytes,removed) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0)", params![key.principal().get().to_le_bytes().as_slice(), key.digest().as_slice(), id, spec.source().get().to_le_bytes().as_slice(), spec.destination().get().to_le_bytes().as_slice(), spec.expected_sha256().as_ref().map(|v|v.as_slice()), priority(spec.priority()), spec.max_bytes() as i64])?;
            tx.commit()?;
            #[cfg(test)] if inner.fault == Fault::AfterCommit { inner.fault = Fault::None; return Err(PersistenceError::Unavailable); }
            Ok(())
        }).await.map_err(|error| match error { PersistenceError::Conflict => CommitError::Conflict, PersistenceError::Capacity => CommitError::Capacity, _ => CommitError::Unavailable })
        })
    }
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    None,
    BeforeCommit,
    AfterCommit,
}

#[cfg(test)]
mod tests;
