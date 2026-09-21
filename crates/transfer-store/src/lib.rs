#![forbid(unsafe_code)]
//! Blocking sequential download persistence. Call from a dedicated blocking worker.
use rusqlite::{params, Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub struct Identity {
    pub original_url_fingerprint: [u8; 32],
    pub final_url_fingerprint: [u8; 32],
    pub strong_etag: Option<String>,
    pub total: u64,
    pub expected_sha256: Option<[u8; 32]>,
}
/// URL identity only, not encryption or authentication. Caller normalizes first.
pub fn url_fingerprint(normalized_url: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"FHD.url-identity.v2\0");
    hash.update(normalized_url.as_bytes());
    hash.finalize().into()
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Downloading,
    ReadyToPublish,
    Published,
}
#[derive(Debug)]
pub enum StoreError {
    Io(std::io::ErrorKind),
    Database,
    UnsupportedVersion,
    InvalidInput,
    Corrupt,
    Locked,
    Collision,
    Incomplete,
    HashMismatch,
    NotWritable,
}
impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "download storage error: {self:?}")
    }
}
impl std::error::Error for StoreError {}
impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}
impl From<rusqlite::Error> for StoreError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Database
    }
}
type Result<T> = std::result::Result<T, StoreError>;
type SavedRow = (
    i64,
    Vec<u8>,
    Vec<u8>,
    Option<String>,
    i64,
    Option<Vec<u8>>,
    String,
    i64,
    Vec<u8>,
    i64,
);

// Instance-local failure points exist only in unit-test builds. They never read
// environment variables or affect the public storage API.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fault {
    PartialWrite(usize),
    CheckpointSync,
    CheckpointReceiptAcknowledgement,
    PublishLink,
    PublishSync,
    PublishReceiptAcknowledgement,
}

pub struct Store {
    db: Connection,
    part: File,
    dir: PathBuf,
    identity: Identity,
    output: String,
    len: u64,
    committed: u64,
    phase: i64,
    hasher: Sha256,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<Fault>,
    // Fields drop in declaration order: release ownership after DB and part close.
    _lock: File,
}
impl Store {
    pub fn create(dir: &Path, identity: Identity, output_name: &str) -> Result<Self> {
        validate_name(output_name)?;
        validate_identity(&identity)?;
        let dir = std::path::absolute(dir)?;
        check_ancestors(dir.parent().ok_or(StoreError::InvalidInput)?)?;
        fs::create_dir(&dir)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join("owner.lock"))?;
        lock.try_lock().map_err(|_| StoreError::Locked)?;
        let part = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(dir.join("payload.part"))?;
        part.sync_all()?;
        let db = Connection::open(dir.join("state.sqlite"))?;
        configure(&db)?;
        db.execute_batch("CREATE TABLE job (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, original BLOB NOT NULL CHECK(length(original)=32), final BLOB NOT NULL CHECK(length(final)=32), etag TEXT, total INTEGER NOT NULL CHECK(total>=0), expected BLOB, output TEXT NOT NULL, committed INTEGER NOT NULL CHECK(committed>=0 AND committed<=total), digest BLOB NOT NULL CHECK(length(digest)=32), phase INTEGER NOT NULL CHECK(phase BETWEEN 0 AND 3));")?;
        let empty: [u8; 32] = Sha256::digest([]).into();
        db.execute(
            "INSERT INTO job VALUES(1,2,?1,?2,?3,?4,?5,?6,0,?7,0)",
            params![
                identity.original_url_fingerprint.as_slice(),
                identity.final_url_fingerprint.as_slice(),
                identity.strong_etag,
                identity.total as i64,
                identity.expected_sha256.as_ref().map(|v| v.as_slice()),
                output_name,
                empty.as_slice()
            ],
        )?;
        sync_directory(&dir)?;
        Ok(Self {
            _lock: lock,
            db,
            part,
            dir,
            identity,
            output: output_name.into(),
            len: 0,
            committed: 0,
            phase: 0,
            hasher: Sha256::new(),
            poisoned: false,
            #[cfg(test)]
            fault: None,
        })
    }
    pub fn open(dir: &Path) -> Result<Self> {
        let dir = std::path::absolute(dir)?;
        check_ancestors(&dir)?;
        for entry in fs::read_dir(&dir)? {
            reject_link(&entry?.path())?;
        }
        for name in ["owner.lock", "state.sqlite", "payload.part"] {
            if !fs::symlink_metadata(dir.join(name))?.is_file() {
                return Err(StoreError::InvalidInput);
            }
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join("owner.lock"))?;
        lock.try_lock().map_err(|_| StoreError::Locked)?;
        let version_reader = Connection::open_with_flags(
            dir.join("state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        version_reader.pragma_update(None, "trusted_schema", "OFF")?;
        let version: i64 =
            version_reader.query_row("SELECT version FROM job WHERE id=1", [], |row| row.get(0))?;
        if version != 2 {
            return Err(StoreError::UnsupportedVersion);
        }
        drop(version_reader);
        let db = Connection::open_with_flags(
            dir.join("state.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        configure(&db)?;
        let (version, original, final_url, etag, total, expected, output, committed, digest, phase): SavedRow = db.query_row("SELECT version,original,final,etag,total,expected,output,committed,digest,phase FROM job WHERE id=1", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?)))?;
        if version != 2
            || total < 0
            || committed < 0
            || committed > total
            || !(0..=3).contains(&phase)
            || (phase > 0 && committed != total)
        {
            return Err(StoreError::Corrupt);
        }
        let expected_sha256 = expected
            .map(|v| <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt))
            .transpose()?;
        let identity = Identity {
            original_url_fingerprint: original.try_into().map_err(|_| StoreError::Corrupt)?,
            final_url_fingerprint: final_url.try_into().map_err(|_| StoreError::Corrupt)?,
            strong_etag: etag,
            total: total as u64,
            expected_sha256,
        };
        validate_identity(&identity)?;
        validate_name(&output)?;
        let mut part = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join("payload.part"))?;
        let committed = committed as u64;
        if part.metadata()?.len() < committed || (phase > 0 && part.metadata()?.len() != committed)
        {
            return Err(StoreError::Corrupt);
        }
        let hasher = hash_prefix(&mut part, committed)?;
        if hasher.clone().finalize().as_slice() != digest {
            return Err(StoreError::Corrupt);
        }
        // Only bytes absent from the durable receipt may be discarded.
        if part.metadata()?.len() != committed {
            part.set_len(committed)?;
            part.sync_all()?;
        }
        part.seek(SeekFrom::Start(committed))?;
        let store = Self {
            _lock: lock,
            db,
            part,
            dir,
            identity,
            output,
            len: committed,
            committed,
            phase,
            hasher,
            poisoned: false,
            #[cfg(test)]
            fault: None,
        };
        if phase == 3 {
            store.verify_destination()?;
        }
        Ok(store)
    }
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn output_name(&self) -> &str {
        &self.output
    }
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn committed_len(&self) -> u64 {
        self.committed
    }
    pub fn status(&self) -> Status {
        match self.phase {
            0 => Status::Downloading,
            3 => Status::Published,
            _ => Status::ReadyToPublish,
        }
    }
    pub fn append(&mut self, bytes: &[u8]) -> Result<()> {
        if self.poisoned || self.phase != 0 {
            return Err(StoreError::NotWritable);
        }
        let new_len = self
            .len
            .checked_add(bytes.len() as u64)
            .ok_or(StoreError::InvalidInput)?;
        if new_len > self.identity.total {
            return Err(StoreError::InvalidInput);
        }
        // A short write followed by failure requires reopen/reconciliation.
        self.poisoned = true;
        #[cfg(test)]
        if let Some(Fault::PartialWrite(count)) = self.fault {
            self.fault = None;
            self.part.write_all(&bytes[..count.min(bytes.len())])?;
            return Err(StoreError::Io(std::io::ErrorKind::StorageFull));
        }
        self.part.write_all(bytes)?;
        self.hasher.update(bytes);
        self.len = new_len;
        self.poisoned = false;
        Ok(())
    }
    pub fn checkpoint(&mut self) -> Result<()> {
        if self.poisoned || self.phase != 0 {
            return Err(StoreError::NotWritable);
        }
        // A failed durability operation may have an ambiguous on-disk outcome.
        // Reopen and reconcile the receipt before allowing more mutations.
        self.poisoned = true;
        #[cfg(test)]
        self.fail_at(Fault::CheckpointSync)?;
        self.part.sync_all()?;
        let digest: [u8; 32] = self.hasher.clone().finalize().into();
        self.db.execute(
            "UPDATE job SET committed=?1,digest=?2 WHERE id=1",
            params![self.len as i64, digest.as_slice()],
        )?;
        #[cfg(test)]
        self.fail_at(Fault::CheckpointReceiptAcknowledgement)?;
        self.committed = self.len;
        self.poisoned = false;
        Ok(())
    }
    /// Call only after the transport has validated clean body termination.
    pub fn mark_transfer_complete(&mut self) -> Result<()> {
        if self.len != self.identity.total {
            return Err(StoreError::Incomplete);
        }
        self.checkpoint()?;
        self.poisoned = true;
        self.db.execute("UPDATE job SET phase=1 WHERE id=1", [])?;
        self.phase = 1;
        self.poisoned = false;
        Ok(())
    }
    pub fn finalize(&mut self) -> Result<PathBuf> {
        if self.poisoned || self.phase == 0 {
            return Err(StoreError::Incomplete);
        }
        self.poisoned = true;
        let result = self.finalize_inner();
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
    fn finalize_inner(&mut self) -> Result<PathBuf> {
        if self.phase == 1 {
            match fs::symlink_metadata(self.dir.join(&self.output)) {
                Ok(_) => return Err(StoreError::Collision),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            let digest: [u8; 32] = hash_prefix(&mut self.part, self.len)?.finalize().into();
            if digest != <[u8; 32]>::from(self.hasher.clone().finalize()) {
                return Err(StoreError::Corrupt);
            }
            if self
                .identity
                .expected_sha256
                .is_some_and(|expected| expected != digest)
            {
                return Err(StoreError::HashMismatch);
            }
            self.db.execute("UPDATE job SET phase=2 WHERE id=1", [])?;
            self.phase = 2;
        }
        self.publish()?;
        Ok(self.dir.join(&self.output))
    }
    fn publish(&mut self) -> Result<()> {
        if self.part.metadata()?.len() != self.identity.total {
            return Err(StoreError::Corrupt);
        }
        if hash_prefix(&mut self.part, self.len)?.finalize() != self.hasher.clone().finalize() {
            return Err(StoreError::Corrupt);
        }
        let digest: [u8; 32] = self.hasher.clone().finalize().into();
        if self
            .identity
            .expected_sha256
            .is_some_and(|expected| expected != digest)
        {
            return Err(StoreError::HashMismatch);
        }
        let dest = self.dir.join(&self.output);
        match fs::symlink_metadata(&dest) {
            Ok(_) => {
                self.verify_destination()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && self.phase == 2 => {
                #[cfg(test)]
                self.fail_at(Fault::PublishLink)?;
                fs::hard_link(self.dir.join("payload.part"), &dest)?;
            }
            Err(e) => return Err(e.into()),
        }
        #[cfg(test)]
        self.fail_at(Fault::PublishSync)?;
        self.part.sync_all()?;
        sync_directory(&self.dir)?;
        self.db.execute("UPDATE job SET phase=3 WHERE id=1", [])?;
        #[cfg(test)]
        self.fail_at(Fault::PublishReceiptAcknowledgement)?;
        self.phase = 3;
        Ok(())
    }
    #[cfg(test)]
    fn fail_at(&mut self, point: Fault) -> Result<()> {
        if self.fault == Some(point) {
            self.fault = None;
            return Err(StoreError::Io(std::io::ErrorKind::Other));
        }
        Ok(())
    }
    fn verify_destination(&self) -> Result<()> {
        let dest = self.dir.join(&self.output);
        reject_link(&dest)?;
        if !fs::symlink_metadata(&dest)?.is_file() {
            return Err(StoreError::InvalidInput);
        }
        let mut final_file = File::open(&dest)?;
        if final_file.metadata()?.len() != self.identity.total
            || hash_prefix(&mut final_file, self.len)?.finalize() != self.hasher.clone().finalize()
        {
            return Err(StoreError::Collision);
        }
        Ok(())
    }
}
fn configure(db: &Connection) -> Result<()> {
    db.execute_batch(
        "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;",
    )?;
    Ok(())
}
fn hash_prefix(file: &mut File, len: u64) -> Result<Sha256> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut left = len;
    while left > 0 {
        let count =
            usize::try_from(left.min(buffer.len() as u64)).map_err(|_| StoreError::Corrupt)?;
        let read = file.read(&mut buffer[..count])?;
        if read == 0 {
            return Err(StoreError::Corrupt);
        }
        hasher.update(&buffer[..read]);
        left -= read as u64;
    }
    Ok(hasher)
}
fn validate_identity(identity: &Identity) -> Result<()> {
    if identity.total > i64::MAX as u64
        || identity
            .strong_etag
            .as_ref()
            .is_some_and(|s| s.len() > 8192)
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}
fn validate_name(name: &str) -> Result<()> {
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    if name.is_empty()
        || name.len() > 180
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
        || name == "."
        || name == ".."
        || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit())
        || [
            "owner.lock",
            "payload.part",
            "state.sqlite",
            "state.sqlite-journal",
            "state.sqlite-wal",
            "state.sqlite-shm",
        ]
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
    {
        return Err(StoreError::InvalidInput);
    }
    Ok(())
}
fn check_ancestors(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        reject_link(ancestor)?;
        if !fs::symlink_metadata(ancestor)?.is_dir() {
            return Err(StoreError::InvalidInput);
        }
    }
    Ok(())
}
fn reject_link(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(StoreError::InvalidInput);
    }
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(StoreError::InvalidInput);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(StoreError::InvalidInput);
        }
    }
    Ok(())
}
fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "fhd-store-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            if self.0.exists() {
                fs::remove_dir_all(&self.0).unwrap();
            }
        }
    }
    fn identity(total: u64) -> Identity {
        Identity {
            original_url_fingerprint: url_fingerprint("https://example.test/file"),
            final_url_fingerprint: url_fingerprint("https://example.test/file"),
            strong_etag: Some("\"version1\"".into()),
            total,
            expected_sha256: None,
        }
    }
    fn assert_failed_handle_is_closed(store: &mut Store) {
        assert!(matches!(store.append(b""), Err(StoreError::NotWritable)));
        assert!(matches!(store.checkpoint(), Err(StoreError::NotWritable)));
        assert!(store.mark_transfer_complete().is_err());
        assert!(store.finalize().is_err());
    }

    #[test]
    fn partial_disk_full_write_recovers_only_acknowledged_prefix() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(6), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.checkpoint().unwrap();
        store.fault = Some(Fault::PartialWrite(2));
        assert!(matches!(
            store.append(b"def"),
            Err(StoreError::Io(std::io::ErrorKind::StorageFull))
        ));
        assert_eq!(store.committed_len(), 3);
        assert_eq!(fs::read(temp.0.join("payload.part")).unwrap(), b"abcde");
        assert_failed_handle_is_closed(&mut store);
        drop(store);
        let mut recovered = Store::open(&temp.0).unwrap();
        assert_eq!(recovered.len(), 3);
        assert_eq!(fs::read(temp.0.join("payload.part")).unwrap(), b"abc");
        recovered.append(b"def").unwrap();
        recovered.mark_transfer_complete().unwrap();
        assert_eq!(fs::read(recovered.finalize().unwrap()).unwrap(), b"abcdef");
    }

    #[test]
    fn failed_checkpoint_sync_never_advances_receipt() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(6), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.checkpoint().unwrap();
        store.append(b"def").unwrap();
        store.fault = Some(Fault::CheckpointSync);
        assert!(matches!(store.checkpoint(), Err(StoreError::Io(_))));
        assert_eq!(store.committed_len(), 3);
        assert_failed_handle_is_closed(&mut store);
        drop(store);
        let recovered = Store::open(&temp.0).unwrap();
        assert_eq!(recovered.committed_len(), 3);
        assert_eq!(fs::read(temp.0.join("payload.part")).unwrap(), b"abc");
        assert!(!temp.0.join("x.bin").exists());
    }

    #[test]
    fn sqlite_checkpoint_abort_preserves_previous_receipt() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(6), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.checkpoint().unwrap();
        store.append(b"def").unwrap();
        store.db.execute_batch("CREATE TRIGGER fail_receipt BEFORE UPDATE OF committed ON job BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;").unwrap();
        assert!(matches!(store.checkpoint(), Err(StoreError::Database)));
        assert_eq!(store.committed_len(), 3);
        assert_failed_handle_is_closed(&mut store);
        drop(store);
        let mut recovered = Store::open(&temp.0).unwrap();
        assert_eq!(recovered.committed_len(), 3);
        assert_eq!(fs::read(temp.0.join("payload.part")).unwrap(), b"abc");
        recovered
            .db
            .execute_batch("DROP TRIGGER fail_receipt")
            .unwrap();
        recovered.append(b"def").unwrap();
        recovered.mark_transfer_complete().unwrap();
        assert_eq!(fs::read(recovered.finalize().unwrap()).unwrap(), b"abcdef");
    }

    #[test]
    fn ambiguous_checkpoint_result_reopens_actual_committed_receipt() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(6), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.checkpoint().unwrap();
        store.append(b"def").unwrap();
        store.fault = Some(Fault::CheckpointReceiptAcknowledgement);
        assert!(store.checkpoint().is_err());
        assert_eq!(store.committed_len(), 3);
        assert_failed_handle_is_closed(&mut store);
        drop(store);
        let mut recovered = Store::open(&temp.0).unwrap();
        assert_eq!(recovered.committed_len(), 6);
        assert_eq!(fs::read(temp.0.join("payload.part")).unwrap(), b"abcdef");
        assert_eq!(recovered.status(), Status::Downloading);
        assert!(recovered.finalize().is_err());
    }

    #[test]
    fn ambiguous_publication_result_reopens_verified_published_file() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.mark_transfer_complete().unwrap();
        store.fault = Some(Fault::PublishReceiptAcknowledgement);
        assert!(store.finalize().is_err());
        assert_eq!(store.status(), Status::ReadyToPublish);
        assert_failed_handle_is_closed(&mut store);
        drop(store);
        let recovered = Store::open(&temp.0).unwrap();
        assert_eq!(recovered.status(), Status::Published);
        assert_eq!(fs::read(temp.0.join("x.bin")).unwrap(), b"abc");
    }

    #[test]
    fn sqlite_completion_abort_cannot_invent_clean_eof_after_reopen() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.db.execute_batch("CREATE TRIGGER fail_complete BEFORE UPDATE OF phase ON job WHEN NEW.phase=1 BEGIN SELECT RAISE(ABORT, 'injected completion failure'); END;").unwrap();
        assert!(matches!(
            store.mark_transfer_complete(),
            Err(StoreError::Database)
        ));
        assert_failed_handle_is_closed(&mut store);
        drop(store);
        let mut recovered = Store::open(&temp.0).unwrap();
        assert_eq!(recovered.committed_len(), 3);
        assert_eq!(recovered.status(), Status::Downloading);
        assert!(matches!(recovered.finalize(), Err(StoreError::Incomplete)));
        assert!(!temp.0.join("x.bin").exists());
    }

    #[test]
    fn publication_io_failures_reconcile_without_false_success() {
        for fault in [Fault::PublishLink, Fault::PublishSync] {
            let temp = TestDir::new();
            let mut store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
            store.append(b"abc").unwrap();
            store.mark_transfer_complete().unwrap();
            store.fault = Some(fault);
            assert!(matches!(store.finalize(), Err(StoreError::Io(_))));
            assert_eq!(store.status(), Status::ReadyToPublish);
            assert_eq!(temp.0.join("x.bin").exists(), fault == Fault::PublishSync);
            assert_failed_handle_is_closed(&mut store);
            drop(store);
            let mut recovered = Store::open(&temp.0).unwrap();
            assert_eq!(recovered.status(), Status::ReadyToPublish);
            assert_eq!(fs::read(recovered.finalize().unwrap()).unwrap(), b"abc");
            assert_eq!(recovered.status(), Status::Published);
        }
    }

    #[test]
    fn sqlite_publication_aborts_recover_intent_and_existing_link() {
        for rejected_phase in [2, 3] {
            let temp = TestDir::new();
            let mut store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
            store.append(b"abc").unwrap();
            store.mark_transfer_complete().unwrap();
            store.db.execute_batch(&format!("CREATE TRIGGER fail_publish BEFORE UPDATE OF phase ON job WHEN NEW.phase={rejected_phase} BEGIN SELECT RAISE(ABORT, 'injected publication failure'); END;")).unwrap();
            assert!(matches!(store.finalize(), Err(StoreError::Database)));
            assert_eq!(store.status(), Status::ReadyToPublish);
            assert_eq!(temp.0.join("x.bin").exists(), rejected_phase == 3);
            assert_failed_handle_is_closed(&mut store);
            drop(store);
            let mut recovered = Store::open(&temp.0).unwrap();
            assert_eq!(recovered.status(), Status::ReadyToPublish);
            recovered
                .db
                .execute_batch("DROP TRIGGER fail_publish")
                .unwrap();
            assert_eq!(fs::read(recovered.finalize().unwrap()).unwrap(), b"abc");
            drop(recovered);
            assert_eq!(Store::open(&temp.0).unwrap().status(), Status::Published);
        }
    }

    #[test]
    fn collision_after_failed_publication_preserves_both_files() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.mark_transfer_complete().unwrap();
        store.fault = Some(Fault::PublishLink);
        assert!(store.finalize().is_err());
        drop(store);
        fs::write(temp.0.join("x.bin"), b"unrelated user file").unwrap();
        let mut recovered = Store::open(&temp.0).unwrap();
        assert!(matches!(recovered.finalize(), Err(StoreError::Collision)));
        assert_eq!(
            fs::read(temp.0.join("x.bin")).unwrap(),
            b"unrelated user file"
        );
        assert_eq!(fs::read(temp.0.join("payload.part")).unwrap(), b"abc");
    }

    #[test]
    fn url_fields_persist_only_fingerprints() {
        let temp = TestDir::new();
        let secret = "unique-query-secret-58310497";
        let url = format!("https://example.test/private/{secret}?token={secret}");
        let mut id = identity(3);
        id.original_url_fingerprint = url_fingerprint(&url);
        id.final_url_fingerprint = url_fingerprint(&(url.clone() + "&redirect=1"));
        let mut store = Store::create(&temp.0, id, "download.bin").unwrap();
        store.append(b"abc").unwrap();
        store.checkpoint().unwrap();
        drop(store);
        let recovered = Store::open(&temp.0).unwrap();
        assert_eq!(
            recovered.identity().original_url_fingerprint,
            url_fingerprint(&url)
        );
        drop(recovered);
        for entry in fs::read_dir(&temp.0).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes
                .windows(secret.len())
                .any(|part| part == secret.as_bytes()));
        }
    }

    #[test]
    fn legacy_schema_is_rejected_without_rewriting_or_truncating() {
        let temp = TestDir::new();
        fs::create_dir(&temp.0).unwrap();
        fs::write(temp.0.join("owner.lock"), []).unwrap();
        fs::write(temp.0.join("payload.part"), b"keep-uncommitted-tail").unwrap();
        let db = Connection::open(temp.0.join("state.sqlite")).unwrap();
        db.execute_batch("CREATE TABLE job(id INTEGER PRIMARY KEY, version INTEGER, original TEXT); INSERT INTO job VALUES(1,1,'legacy-secret-url');").unwrap();
        drop(db);
        let before = fs::read(temp.0.join("state.sqlite")).unwrap();
        assert!(matches!(
            Store::open(&temp.0),
            Err(StoreError::UnsupportedVersion)
        ));
        assert_eq!(fs::read(temp.0.join("state.sqlite")).unwrap(), before);
        assert_eq!(
            fs::read(temp.0.join("payload.part")).unwrap(),
            b"keep-uncommitted-tail"
        );
        assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 3);
    }

    #[test]
    fn recovery_keeps_checkpoint_and_discards_only_uncommitted_tail() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(6), "download.bin").unwrap();
        store.append(b"abc").unwrap();
        store.checkpoint().unwrap();
        store.append(b"de").unwrap();
        drop(store);
        let mut recovered = Store::open(&temp.0).unwrap();
        assert_eq!(recovered.len(), 3);
        assert_eq!(fs::read(temp.0.join("payload.part")).unwrap(), b"abc");
        recovered.append(b"def").unwrap();
        recovered.mark_transfer_complete().unwrap();
        let path = recovered.finalize().unwrap();
        assert_eq!(fs::read(path).unwrap(), b"abcdef");
        drop(recovered);
        assert_eq!(Store::open(&temp.0).unwrap().status(), Status::Published);
    }
    #[test]
    fn tampered_checkpoint_is_rejected_without_modifying_files() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(6), "download.bin").unwrap();
        store.append(b"abc").unwrap();
        store.checkpoint().unwrap();
        drop(store);
        fs::write(temp.0.join("payload.part"), b"axctail").unwrap();
        assert!(matches!(Store::open(&temp.0), Err(StoreError::Corrupt)));
        assert_eq!(fs::read(temp.0.join("payload.part")).unwrap(), b"axctail");
    }
    #[test]
    fn truncated_checkpoint_is_rejected_without_deletion() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(6), "download.bin").unwrap();
        store.append(b"abc").unwrap();
        store.checkpoint().unwrap();
        drop(store);
        fs::write(temp.0.join("payload.part"), b"a").unwrap();
        assert!(matches!(Store::open(&temp.0), Err(StoreError::Corrupt)));
        assert_eq!(fs::read(temp.0.join("payload.part")).unwrap(), b"a");
    }
    #[test]
    fn os_lock_rejects_second_owner_and_releases_on_drop() {
        let temp = TestDir::new();
        let store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
        assert!(matches!(Store::open(&temp.0), Err(StoreError::Locked)));
        drop(store);
        assert!(Store::open(&temp.0).is_ok());
    }
    #[test]
    fn collision_never_overwrites_even_identical_existing_content() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.mark_transfer_complete().unwrap();
        fs::write(temp.0.join("x.bin"), b"abc").unwrap();
        assert!(matches!(store.finalize(), Err(StoreError::Collision)));
        assert_eq!(fs::read(temp.0.join("x.bin")).unwrap(), b"abc");
    }
    #[test]
    fn recovers_crash_between_link_and_completed_receipt() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.mark_transfer_complete().unwrap();
        store
            .db
            .execute("UPDATE job SET phase=2 WHERE id=1", [])
            .unwrap();
        fs::hard_link(temp.0.join("payload.part"), temp.0.join("x.bin")).unwrap();
        drop(store);
        let mut recovered = Store::open(&temp.0).unwrap();
        assert_eq!(recovered.status(), Status::ReadyToPublish);
        recovered.finalize().unwrap();
        assert_eq!(fs::read(temp.0.join("x.bin")).unwrap(), b"abc");
    }
    #[test]
    fn recovers_crash_after_intent_before_link() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.mark_transfer_complete().unwrap();
        store
            .db
            .execute("UPDATE job SET phase=2 WHERE id=1", [])
            .unwrap();
        drop(store);
        let mut recovered = Store::open(&temp.0).unwrap();
        assert_eq!(recovered.status(), Status::ReadyToPublish);
        recovered.finalize().unwrap();
        assert_eq!(fs::read(temp.0.join("x.bin")).unwrap(), b"abc");
    }
    #[test]
    fn complete_length_without_clean_transport_finish_cannot_publish() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.checkpoint().unwrap();
        drop(store);
        let mut store = Store::open(&temp.0).unwrap();
        assert_eq!(store.status(), Status::Downloading);
        assert!(matches!(store.finalize(), Err(StoreError::Incomplete)));
    }
    #[test]
    fn persisted_expected_digest_cannot_be_forgotten_after_restart() {
        let temp = TestDir::new();
        let mut id = identity(3);
        id.expected_sha256 = Some([0; 32]);
        let mut store = Store::create(&temp.0, id, "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.mark_transfer_complete().unwrap();
        drop(store);
        let mut store = Store::open(&temp.0).unwrap();
        assert!(matches!(store.finalize(), Err(StoreError::HashMismatch)));
        assert!(!temp.0.join("x.bin").exists());
    }
    #[test]
    fn published_file_user_edits_are_preserved_on_reopen() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.mark_transfer_complete().unwrap();
        store.finalize().unwrap();
        drop(store);
        OpenOptions::new()
            .append(true)
            .open(temp.0.join("x.bin"))
            .unwrap()
            .write_all(b"user")
            .unwrap();
        assert!(matches!(Store::open(&temp.0), Err(StoreError::Corrupt)));
        assert_eq!(fs::read(temp.0.join("x.bin")).unwrap(), b"abcuser");
    }
    #[test]
    fn externally_appended_tail_cannot_be_published() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.mark_transfer_complete().unwrap();
        OpenOptions::new()
            .append(true)
            .open(temp.0.join("payload.part"))
            .unwrap()
            .write_all(b"tail")
            .unwrap();
        assert!(matches!(store.finalize(), Err(StoreError::Corrupt)));
        assert!(!temp.0.join("x.bin").exists());
        assert_eq!(fs::read(temp.0.join("payload.part")).unwrap(), b"abctail");
    }
    #[test]
    fn bounds_and_reserved_paths_fail_before_writes() {
        for name in [
            "../oops",
            "state.sqlite",
            "CON.txt",
            "x:stream",
            "x/child",
            "foo.",
        ] {
            let temp = TestDir::new();
            assert!(matches!(
                Store::create(&temp.0, identity(1), name),
                Err(StoreError::InvalidInput)
            ));
            assert!(!temp.0.exists());
        }
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(1), "x.bin").unwrap();
        assert!(matches!(store.append(b"ab"), Err(StoreError::InvalidInput)));
        assert_eq!(store.len(), 0);
    }
    #[test]
    fn recovery_intent_collision_preserves_unrelated_destination() {
        let temp = TestDir::new();
        let mut store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
        store.append(b"abc").unwrap();
        store.mark_transfer_complete().unwrap();
        store
            .db
            .execute("UPDATE job SET phase=2 WHERE id=1", [])
            .unwrap();
        drop(store);
        fs::write(temp.0.join("x.bin"), b"user file").unwrap();
        let mut recovered = Store::open(&temp.0).unwrap();
        assert!(matches!(recovered.finalize(), Err(StoreError::Collision)));
        assert_eq!(fs::read(temp.0.join("x.bin")).unwrap(), b"user file");
        assert_eq!(fs::read(temp.0.join("payload.part")).unwrap(), b"abc");
    }
    #[test]
    fn recovery_rejects_directory_in_place_of_regular_payload() {
        let temp = TestDir::new();
        let store = Store::create(&temp.0, identity(3), "x.bin").unwrap();
        drop(store);
        fs::remove_file(temp.0.join("payload.part")).unwrap();
        fs::create_dir(temp.0.join("payload.part")).unwrap();
        assert!(matches!(
            Store::open(&temp.0),
            Err(StoreError::InvalidInput)
        ));
        assert!(temp.0.join("payload.part").is_dir());
    }
}
