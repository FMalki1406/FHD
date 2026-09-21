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
pub(crate) const MAX_RECEIPTS: usize = 4096;
#[derive(Clone)]
pub(crate) struct Receipt {
    pub key_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub job_id: JobId,
    pub removed: bool,
}
pub(crate) struct SavedJob {
    pub id: JobId,
    pub options: Options,
    pub priority: Priority,
    pub state: State,
    pub progress: u64,
    pub attempts: u8,
}
pub(crate) struct Snapshot {
    pub last_id: u64,
    pub receipts: Vec<Receipt>,
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

/// Frozen queue v2/v3 and admission payload v1 layout. A future Options field
/// requires a new versioned encoder/receipt migration, never changing this one.
pub(crate) fn encode_options_v2(
    bytes: &mut Vec<u8>,
    options: &Options,
) -> Result<(), ManagerError> {
    string(bytes, &options.url);
    string(
        bytes,
        options.job_dir.to_str().ok_or(ManagerError::InvalidPath)?,
    );
    string(bytes, &options.output_name);
    bytes.push(u8::from(options.expected_sha256.is_some()));
    if let Some(hash) = options.expected_sha256 {
        bytes.extend_from_slice(&hash);
    }
    bytes.push(u8::from(options.allow_http));
    put(bytes, options.checkpoint_bytes);
    put(bytes, options.max_download_bytes);
    option(bytes, options.bytes_per_second);
    bytes.push(options.parallel_connections);
    string(
        bytes,
        options
            .request_policy
            .authorization
            .as_deref()
            .unwrap_or(""),
    );
    string(
        bytes,
        options.request_policy.cookie.as_deref().unwrap_or(""),
    );
    put(bytes, options.request_policy.redirect_origins.len() as u64);
    for origin in &options.request_policy.redirect_origins {
        string(bytes, origin);
    }
    bytes.push(u8::from(options.refresh_from.is_some()));
    if let Some(hash) = options.refresh_from {
        bytes.extend_from_slice(&hash);
    }
    Ok(())
}

fn encode(snapshot: &Snapshot) -> Result<Zeroizing<Vec<u8>>, ManagerError> {
    let mut bytes = Zeroizing::new(b"FHDQUEUE\x03".to_vec());
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
    put(&mut bytes, snapshot.last_id);
    put(&mut bytes, snapshot.jobs.len() as u64);
    for job in &snapshot.jobs {
        put(&mut bytes, job.id.0);
        encode_options_v2(&mut bytes, &job.options)?;
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
    if snapshot.receipts.len() > MAX_RECEIPTS {
        return Err(ManagerError::ReceiptCapacity);
    }
    put(&mut bytes, snapshot.receipts.len() as u64);
    for receipt in &snapshot.receipts {
        bytes.extend_from_slice(&receipt.key_hash);
        bytes.extend_from_slice(&receipt.payload_hash);
        put(&mut bytes, receipt.job_id.0);
        bytes.push(u8::from(receipt.removed));
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
    let version = r.take(9)?;
    if version != b"FHDQUEUE\x01" && version != b"FHDQUEUE\x02" && version != b"FHDQUEUE\x03" {
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
    let saved_last_id = if version != b"FHDQUEUE\x01" {
        Some(r.n()?)
    } else {
        None
    };
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
        let mut options = Options {
            url,
            job_dir,
            output_name,
            expected_sha256,
            allow_http: r.boolean()?,
            checkpoint_bytes: r.n()?,
            max_download_bytes: r.n()?,
            bytes_per_second: r.option()?,
            parallel_connections: r.byte()?,
            request_policy: Default::default(),
            refresh_from: None,
        };
        if version != b"FHDQUEUE\x01" {
            let auth = r.string(8192)?;
            let cookie = r.string(8192)?;
            let mut origins = Vec::new();
            for _ in 0..r.bounded(8)? {
                origins.push(r.string(16_384)?);
            }
            options.request_policy = crate::RequestPolicy::new(
                (!auth.is_empty()).then_some(auth),
                (!cookie.is_empty()).then_some(cookie),
                origins,
            )
            .map_err(failure)?;
            if r.boolean()? {
                options.refresh_from = Some(r.take(32)?.try_into().map_err(failure)?);
            }
        }
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
    let mut receipts = Vec::new();
    if version == b"FHDQUEUE\x03" {
        let count = r.bounded(MAX_RECEIPTS as u64)?;
        receipts.reserve(count);
        for _ in 0..count {
            let key_hash = r.take(32)?.try_into().map_err(failure)?;
            let payload_hash = r.take(32)?.try_into().map_err(failure)?;
            let job_id = JobId(r.n()?);
            let removed = r.boolean()?;
            if job_id.0 == 0
                || receipts.iter().any(|receipt: &Receipt| {
                    receipt.key_hash == key_hash || receipt.job_id == job_id
                })
                || removed == jobs.iter().any(|job| job.id == job_id)
            {
                return Err(ManagerError::Persistence);
            }
            receipts.push(Receipt {
                key_hash,
                payload_hash,
                job_id,
                removed,
            });
        }
    }
    if !r.0.is_empty() {
        return Err(ManagerError::Persistence);
    }
    let maximum = jobs.iter().map(|j| j.id.0).max().unwrap_or(0);
    let last_id = saved_last_id.unwrap_or(maximum);
    if last_id < maximum || receipts.iter().any(|receipt| receipt.job_id.0 > last_id) {
        return Err(ManagerError::Persistence);
    }
    Ok(Snapshot {
        last_id,
        receipts,
        config,
        jobs,
        queue,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frozen_options_encoding_retains_original_admission_hash() {
        let options = Options {
            url: "https://example.test/file?token=one".into(),
            job_dir: PathBuf::from("/fixed/job"),
            output_name: "file.bin".into(),
            expected_sha256: Some([17; 32]),
            allow_http: false,
            checkpoint_bytes: 65536,
            max_download_bytes: 123456789,
            bytes_per_second: Some(2048),
            parallel_connections: 4,
            request_policy: crate::RequestPolicy::new(
                Some("Bearer example".into()),
                Some("session=example".into()),
                vec!["https://cdn.example.test".into()],
            )
            .unwrap(),
            refresh_from: Some([34; 32]),
        };
        let mut bytes = b"FHD.admission.payload.v1\0".to_vec();
        encode_options_v2(&mut bytes, &options).unwrap();
        bytes.push(2); // High priority
        let expected = [
            0x5a, 0xab, 0xc2, 0xf2, 0x02, 0x1e, 0x54, 0xc7, 0xf9, 0x49, 0x04, 0xf9, 0x89, 0xb4,
            0x1a, 0x50, 0xf1, 0xfc, 0xb1, 0x11, 0x64, 0x3c, 0xa8, 0x57, 0xcf, 0xae, 0x3a, 0xce,
            0xb8, 0xdf, 0x26, 0x3f,
        ];
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), expected);
    }

    #[test]
    fn version_two_queue_migrates_without_receipts_and_keeps_monotonic_id() {
        let snapshot = Snapshot {
            last_id: 37,
            receipts: vec![],
            config: Config::default(),
            jobs: vec![],
            queue: vec![],
        };
        let mut old = encode(&snapshot).unwrap().to_vec();
        old.truncate(old.len() - 40); // Remove v3 empty receipt count and digest.
        old[8] = 2;
        old.extend_from_slice(&Sha256::digest(&old));
        let restored = decode(&old).unwrap();
        assert!(restored.receipts.is_empty());
        assert_eq!(restored.last_id, 37);
        assert!(decode(&encode(&restored).unwrap()).is_ok());
    }

    #[test]
    fn receipt_decoder_rejects_missing_live_jobs_duplicates_and_future_ids() {
        let receipt = Receipt {
            key_hash: [1; 32],
            payload_hash: [2; 32],
            job_id: JobId(1),
            removed: false,
        };
        let mut snapshot = Snapshot {
            last_id: 1,
            receipts: vec![receipt],
            config: Config::default(),
            jobs: vec![],
            queue: vec![],
        };
        assert!(decode(&encode(&snapshot).unwrap()).is_err());
        snapshot.receipts[0].removed = true;
        assert!(decode(&encode(&snapshot).unwrap()).is_ok());
        snapshot.receipts.push(snapshot.receipts[0].clone());
        assert!(decode(&encode(&snapshot).unwrap()).is_err());
        snapshot.receipts.pop();
        snapshot.last_id = 0;
        assert!(decode(&encode(&snapshot).unwrap()).is_err());
    }
    #[test]
    fn version_one_queue_is_read_without_inventing_credentials() {
        let snapshot = Snapshot {
            last_id: 0,
            receipts: vec![],
            config: Config::default(),
            jobs: vec![],
            queue: vec![],
        };
        let mut old = encode(&snapshot).unwrap().to_vec();
        old.truncate(old.len() - 32);
        old.truncate(old.len() - 8); // v3 receipt count is absent in v1.
        old[8] = 1;
        old.drain(65..73);
        old.extend_from_slice(&Sha256::digest(&old));
        let restored = decode(&old).unwrap();
        assert!(restored.jobs.is_empty());
        assert_eq!(restored.last_id, 0);
    }
    #[test]
    fn envelope_rejects_changes_and_invalid_lengths() {
        let snapshot = Snapshot {
            last_id: 0,
            receipts: vec![],
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
