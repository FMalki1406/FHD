//! Encrypted singleton queue snapshot; the plaintext never reaches SQLite.
use crate::manager::{Config, JobId, ManagerError, Priority, RetryPolicy, State};
use crate::{Error, Options};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

const MAX_BLOB: usize = 64 * 1024 * 1024;
const MAX_PLAIN: usize = 48 * 1024 * 1024;
pub(crate) struct SavedJob {
    pub id: JobId,
    pub options: Options,
    pub priority: Priority,
    pub state: State,
    pub progress: u64,
    pub attempts: u8,
}
pub(crate) struct Snapshot {
    pub config: Config,
    pub jobs: Vec<SavedJob>,
    pub queue: Vec<JobId>,
}
pub(crate) struct QueueStore {
    db: Connection,
    // Keep the cross-process lock until after the database closes.
    _lock: File,
}

fn failure<T>(_: T) -> ManagerError {
    ManagerError::Persistence
}
fn ordinary(path: &Path, dir: bool) -> Result<(), ManagerError> {
    let metadata = std::fs::symlink_metadata(path).map_err(failure)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(ManagerError::Persistence);
        }
    }
    if metadata.file_type().is_symlink()
        || (dir && !metadata.is_dir())
        || (!dir && !metadata.is_file())
    {
        return Err(ManagerError::Persistence);
    }
    Ok(())
}

fn check_existing(path: &Path) -> Result<bool, ManagerError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            ordinary(path, false)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ManagerError::Persistence),
    }
}

impl QueueStore {
    pub fn open(path: &Path) -> Result<Self, ManagerError> {
        if !path.is_absolute() {
            return Err(ManagerError::InvalidPath);
        }
        // DPAPI availability is checked before creating any storage.
        queue_secrets::protect(b"queue-provider-check").map_err(|_| ManagerError::SecretStorage)?;
        let parent = path.parent().ok_or(ManagerError::InvalidPath)?;
        for ancestor in parent.ancestors() {
            ordinary(ancestor, true)?;
        }
        match std::fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(failure(error)),
        }
        ordinary(path, true)?;
        let lock_path = path.join("owner.lock");
        check_existing(&lock_path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(failure)?;
        lock.try_lock().map_err(|_| ManagerError::QueueLocked)?;
        let db_path = path.join("queue.sqlite");
        if check_existing(&db_path)? {
            ordinary(&db_path, false)?;
            if std::fs::metadata(&db_path).map_err(failure)?.len() > 128 * 1024 * 1024 {
                return Err(ManagerError::Persistence);
            }
        }
        for suffix in [
            "queue.sqlite-journal",
            "queue.sqlite-wal",
            "queue.sqlite-shm",
        ] {
            let sidecar = path.join(suffix);
            check_existing(&sidecar)?;
        }
        let db = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(failure)?;
        db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS queue_snapshot (id INTEGER PRIMARY KEY CHECK(id=1), payload BLOB NOT NULL);").map_err(failure)?;
        Ok(Self { db, _lock: lock })
    }

    pub fn load(&self) -> Result<Option<Snapshot>, ManagerError> {
        use rusqlite::OptionalExtension;
        let size: Option<i64> = self
            .db
            .query_row(
                "SELECT length(payload) FROM queue_snapshot WHERE id=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(failure)?;
        let Some(size) = size else {
            return Ok(None);
        };
        if size <= 0 || size as u64 > MAX_BLOB as u64 {
            return Err(ManagerError::Persistence);
        }
        let bytes: Vec<u8> = self
            .db
            .query_row("SELECT payload FROM queue_snapshot WHERE id=1", [], |row| {
                row.get(0)
            })
            .map_err(failure)?;
        let plain = Zeroizing::new(
            queue_secrets::unprotect(&bytes).map_err(|_| ManagerError::SecretStorage)?,
        );
        decode(&plain).map(Some)
    }

    pub fn save(&mut self, snapshot: &Snapshot) -> Result<(), ManagerError> {
        let bytes = encode(snapshot)?;
        let encrypted = queue_secrets::protect(&bytes).map_err(|_| ManagerError::SecretStorage)?;
        let tx = self.db.transaction().map_err(failure)?;
        tx.execute("INSERT INTO queue_snapshot(id,payload) VALUES(1,?1) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload", [encrypted]).map_err(failure)?;
        tx.commit().map_err(failure)
    }
}

fn put(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
fn string(bytes: &mut Vec<u8>, value: &str) {
    put(bytes, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}
fn option(bytes: &mut Vec<u8>, value: Option<u64>) {
    put(bytes, value.unwrap_or(0));
}

fn encode(snapshot: &Snapshot) -> Result<Zeroizing<Vec<u8>>, ManagerError> {
    let mut bytes = Zeroizing::new(b"FHDQUEUE\x01".to_vec());
    let c = &snapshot.config;
    for value in [
        c.max_active as u64,
        c.max_jobs as u64,
        c.max_per_origin as u64,
        c.retry.max_attempts as u64,
        c.retry.initial_delay_ms,
        c.retry.max_delay_ms,
    ] {
        put(&mut bytes, value);
    }
    option(&mut bytes, c.global_bytes_per_second);
    put(&mut bytes, snapshot.jobs.len() as u64);
    for job in &snapshot.jobs {
        put(&mut bytes, job.id.0);
        string(&mut bytes, &job.options.url);
        string(
            &mut bytes,
            job.options
                .job_dir
                .to_str()
                .ok_or(ManagerError::InvalidPath)?,
        );
        string(&mut bytes, &job.options.output_name);
        bytes.push(u8::from(job.options.expected_sha256.is_some()));
        if let Some(hash) = job.options.expected_sha256 {
            bytes.extend_from_slice(&hash);
        }
        bytes.push(u8::from(job.options.allow_http));
        put(&mut bytes, job.options.checkpoint_bytes);
        put(&mut bytes, job.options.max_download_bytes);
        option(&mut bytes, job.options.bytes_per_second);
        bytes.push(job.options.parallel_connections);
        bytes.push(match job.priority {
            Priority::Low => 0,
            Priority::Normal => 1,
            Priority::High => 2,
        });
        bytes.push(match job.state {
            State::Queued => 0,
            State::Running => 1,
            State::Pausing => 2,
            State::Paused => 3,
            State::Completed => 4,
            State::Failed(_) => 5,
            State::RetryWaiting => 6,
        });
        // Failure categories are intentionally not interpreted as fresh authority.
        // Recovered failures remain failed until an explicit resume.
        put(&mut bytes, job.progress);
        bytes.push(job.attempts);
    }
    put(&mut bytes, snapshot.queue.len() as u64);
    for id in &snapshot.queue {
        put(&mut bytes, id.0);
    }
    if bytes.len() > MAX_PLAIN {
        return Err(ManagerError::Capacity);
    }
    let digest = Sha256::digest(&bytes);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], ManagerError> {
        if count > self.0.len() {
            return Err(ManagerError::Persistence);
        }
        let (front, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(front)
    }
    fn byte(&mut self) -> Result<u8, ManagerError> {
        Ok(self.take(1)?[0])
    }
    fn n(&mut self) -> Result<u64, ManagerError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(failure)?,
        ))
    }
    fn bounded(&mut self, max: u64) -> Result<usize, ManagerError> {
        let n = self.n()?;
        if n > max {
            return Err(ManagerError::Persistence);
        }
        Ok(n as usize)
    }
    fn string(&mut self, max: u64) -> Result<String, ManagerError> {
        let n = self.bounded(max)?;
        String::from_utf8(self.take(n)?.to_vec()).map_err(failure)
    }
    fn option(&mut self) -> Result<Option<u64>, ManagerError> {
        let n = self.n()?;
        Ok((n != 0).then_some(n))
    }
    fn boolean(&mut self) -> Result<bool, ManagerError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ManagerError::Persistence),
        }
    }
}

fn decode(bytes: &[u8]) -> Result<Snapshot, ManagerError> {
    if bytes.len() < 41 || bytes.len() > MAX_PLAIN + 32 {
        return Err(ManagerError::Persistence);
    }
    let (plain, hash) = bytes.split_at(bytes.len() - 32);
    if Sha256::digest(plain).as_slice() != hash {
        return Err(ManagerError::Persistence);
    }
    let mut r = Reader(plain);
    if r.take(9)? != b"FHDQUEUE\x01" {
        return Err(ManagerError::Persistence);
    }
    let config = Config {
        max_active: r.bounded(32)?,
        max_jobs: r.bounded(1024)?,
        max_per_origin: r.bounded(32)?,
        retry: RetryPolicy {
            max_attempts: r.bounded(5)? as u8,
            initial_delay_ms: r.n()?,
            max_delay_ms: r.n()?,
        },
        global_bytes_per_second: r.option()?,
    };
    config.validate()?;
    let count = r.bounded(config.max_jobs as u64)?;
    let mut jobs = Vec::with_capacity(count);
    for _ in 0..count {
        let id = JobId(r.n()?);
        if id.0 == 0 || jobs.iter().any(|job: &SavedJob| job.id == id) {
            return Err(ManagerError::Persistence);
        }
        let url = r.string(16_384)?;
        let job_dir = PathBuf::from(r.string(131_072)?);
        let output_name = r.string(255)?;
        let expected_sha256 = if r.boolean()? {
            Some(r.take(32)?.try_into().map_err(failure)?)
        } else {
            None
        };
        let options = Options {
            url,
            job_dir,
            output_name,
            expected_sha256,
            allow_http: r.boolean()?,
            checkpoint_bytes: r.n()?,
            max_download_bytes: r.n()?,
            bytes_per_second: r.option()?,
            parallel_connections: r.byte()?,
        };
        let priority = match r.byte()? {
            0 => Priority::Low,
            1 => Priority::Normal,
            2 => Priority::High,
            _ => return Err(ManagerError::Persistence),
        };
        let state = match r.byte()? {
            0 => State::Queued,
            1 => State::Running,
            2 => State::Pausing,
            3 => State::Paused,
            4 => State::Completed,
            5 => State::Failed(Error::WorkerFailed),
            6 => State::RetryWaiting,
            _ => return Err(ManagerError::Persistence),
        };
        let progress = r.n()?;
        let attempts = r.byte()?;
        if attempts > 5 || progress > options.max_download_bytes {
            return Err(ManagerError::Persistence);
        }
        jobs.push(SavedJob {
            id,
            options,
            priority,
            state,
            progress,
            attempts,
        });
    }
    let count = r.bounded(jobs.len() as u64)?;
    let mut queue = Vec::with_capacity(count);
    for _ in 0..count {
        let id = JobId(r.n()?);
        if queue.contains(&id) || !jobs.iter().any(|job| job.id == id) {
            return Err(ManagerError::Persistence);
        }
        queue.push(id);
    }
    if !r.0.is_empty() {
        return Err(ManagerError::Persistence);
    }
    Ok(Snapshot {
        config,
        jobs,
        queue,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn envelope_rejects_changes_and_invalid_lengths() {
        let snapshot = Snapshot {
            config: Config::default(),
            jobs: vec![],
            queue: vec![],
        };
        let encoded = encode(&snapshot).unwrap();
        assert!(decode(&encoded).is_ok());
        for index in [0, 10, encoded.len() - 1] {
            let mut bad = encoded.clone();
            bad[index] ^= 1;
            assert!(decode(&bad).is_err());
        }
        assert!(decode(&encoded[..16]).is_err());
    }
}
