//! Single-owner positional storage. Blocking methods belong on the writer thread.
#![forbid(unsafe_code)]
use fhd_app::storage::{Occupant, PartSpec, SegmentFile, SegmentStore, StorageError};
use fhd_domain::ByteRange;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

const MAGIC: &[u8; 9] = b"FHDPART\0\x01";
const META_LEN: usize = 34;
const MAX_EXTENTS: usize = 262144;
const BUFFER: usize = 64 * 1024;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// One resolution for publishing and for inspecting: the parent is canonicalised
/// and the leaf validated, so both always name the same file.
fn resolve_destination(destination: &Path) -> Result<PathBuf, StorageError> {
    let destination = std::path::absolute(destination).map_err(io)?;
    let parent = destination
        .parent()
        .ok_or(StorageError::InvalidInput)?
        .canonicalize()
        .map_err(io)?;
    let leaf = destination.file_name().ok_or(StorageError::InvalidInput)?;
    validate_leaf(leaf)?;
    Ok(parent.join(leaf))
}
fn io(error: std::io::Error) -> StorageError {
    StorageError::Io(error.kind())
}
fn ordinary(path: &Path, directory: bool) -> Result<(), StorageError> {
    let metadata = fs::symlink_metadata(path).map_err(io)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(StorageError::InvalidInput);
        }
    }
    if metadata.file_type().is_symlink()
        || if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        }
    {
        return Err(StorageError::InvalidInput);
    }
    Ok(())
}
fn check_optional(path: &Path) -> Result<(), StorageError> {
    match fs::symlink_metadata(path) {
        Ok(_) => ordinary(path, false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io(error)),
    }
}
fn directory(path: &Path, create: bool) -> Result<PathBuf, StorageError> {
    let absolute = std::path::absolute(path).map_err(io)?;
    if absolute
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(StorageError::InvalidInput);
    }
    let mut created = false;
    if create {
        match fs::create_dir(&absolute) {
            Ok(()) => created = true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(io(error)),
        }
    }
    // This generated app-owned leaf must not be a link. Redirected ancestor
    // folders are allowed and resolved once; hostile same-user replacement is
    // outside this adapter's current private-directory contract.
    ordinary(&absolute, true)?;
    let resolved = absolute.canonicalize().map_err(io)?;
    if created {
        // Syncing the child persists its contents, not the new entry in its parent.
        sync_directory(resolved.parent().ok_or(StorageError::InvalidInput)?)?;
    }
    Ok(resolved)
}
fn validate_leaf(leaf: &std::ffi::OsStr) -> Result<(), StorageError> {
    let name = leaf.to_str().ok_or(StorageError::InvalidInput)?;
    if name.is_empty()
        || name.len() > 255
        || matches!(name, "." | "..")
        || name.ends_with(['.', ' '])
        || name.chars().any(char::is_control)
        || name.contains(['<', '>', ':', '"', '/', '\\', '|', '?', '*'])
    {
        return Err(StorageError::InvalidInput);
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_lowercase();
    if matches!(
        stem.as_str(),
        "con" | "prn" | "aux" | "nul" | "conin$" | "conout$"
    ) || ["com", "lpt"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|number| {
            matches!(
                number,
                "1" | "2"
                    | "3"
                    | "4"
                    | "5"
                    | "6"
                    | "7"
                    | "8"
                    | "9"
                    | "\u{00B9}"
                    | "\u{00B2}"
                    | "\u{00B3}"
            )
        })
    }) {
        return Err(StorageError::InvalidInput);
    }
    Ok(())
}
fn sync_directory(path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        File::open(path).map_err(io)?.sync_all().map_err(io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
fn identity(spec: PartSpec, sealed: bool) -> [u8; META_LEN] {
    let mut data = [0; META_LEN];
    data[..9].copy_from_slice(MAGIC);
    data[9..17].copy_from_slice(&spec.job().get().to_le_bytes());
    data[17..25].copy_from_slice(&spec.generation().get().to_le_bytes());
    data[25..33].copy_from_slice(&spec.size().to_le_bytes());
    data[33] = u8::from(sealed);
    data
}
/// Holds the part directory against a second engine for as long as it lives, and
/// nothing finer: two jobs in one engine each own their own generation's file, so
/// the directory lock must not be taken again per handle.
#[derive(Default)]
pub struct FileStorage {
    owner: Option<Arc<File>>,
}
impl FileStorage {
    /// Claims `directory` for this process. A second engine pointed at the same
    /// tree is refused here rather than corrupting a part later.
    pub fn own(path: &Path) -> Result<Self, StorageError> {
        // The engine's own tree, created here if this is its first run.
        let directory = directory(path, true)?;
        let lock_path = directory.join("owner.lock");
        check_optional(&lock_path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(io)?;
        lock.try_lock().map_err(|_| StorageError::Locked)?;
        Ok(Self {
            owner: Some(Arc::new(lock)),
        })
    }
}
impl SegmentStore for FileStorage {
    /// Reconciliation only, never the byte path: resolves the destination exactly as
    /// `publish` does, follows no link, and hashes only a file of the expected size.
    fn inspect(
        &self,
        destination: &Path,
        expected_size: u64,
    ) -> Result<Option<Occupant>, StorageError> {
        let destination = resolve_destination(destination)?;
        let metadata = match fs::symlink_metadata(&destination) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io(error)),
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Ok(Some(Occupant::NotAFile));
        }
        if metadata.len() != expected_size {
            return Ok(Some(Occupant::OtherSize));
        }
        let mut file = File::open(&destination).map_err(io)?;
        let mut buffer = [0; BUFFER];
        let mut hash = Sha256::new();
        let mut size = 0u64;
        loop {
            let read = file.read(&mut buffer).map_err(io)?;
            if read == 0 {
                break;
            }
            size = size.checked_add(read as u64).ok_or(StorageError::Bounds)?;
            hash.update(&buffer[..read]);
        }
        if size != expected_size {
            return Ok(Some(Occupant::OtherSize));
        }
        Ok(Some(Occupant::File {
            size,
            digest: hash.finalize().into(),
        }))
    }
    fn create(&self, path: &Path, spec: PartSpec) -> Result<Box<dyn SegmentFile>, StorageError> {
        Ok(Box::new(FilePart::open_inner(
            path,
            spec,
            true,
            self.owner.clone(),
        )?))
    }
    fn open(&self, path: &Path, spec: PartSpec) -> Result<Box<dyn SegmentFile>, StorageError> {
        Ok(Box::new(FilePart::open_inner(
            path,
            spec,
            false,
            self.owner.clone(),
        )?))
    }
}
#[cfg(test)]
#[derive(Clone, Copy)]
enum Fault {
    PartialWrite(usize),
    Sync,
}
struct FilePart {
    file: File,
    metadata: File,
    path: PathBuf,
    directory: PathBuf,
    spec: PartSpec,
    coverage: Vec<ByteRange>,
    protected: Vec<ByteRange>,
    synchronized: bool,
    verified: Option<[u8; 32]>,
    sealed: bool,
    published: bool,
    cancelled: bool,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<Fault>,
    // Released after every open data/metadata handle of this part.
    _lock: Option<Arc<File>>,
}
/// The SHA-256 of a whole file, read through a handle the caller opened.
///
/// Used to check the destination after it has been linked. Publication links a
/// path, and a path is a name rather than the object that was verified: a review
/// renamed a verified part aside, put its own file at the name, and watched
/// those bytes get published. Windows happens to refuse renaming a directory
/// with an open file beneath it, which closed one route there by a property of
/// NTFS this code never asserts; Unix refuses nothing of the sort.
///
/// Reading the destination through one handle, opened once, settles it: if those
/// bytes hash to what was verified, the file the user is about to have is the
/// file we meant. It replaces the re-read that used to happen through our own
/// handle just before linking -- same number of passes over the data, and it
/// answers the question that matters instead of one we already knew the answer
/// to.
fn hash_whole(file: &mut File, length: u64) -> Result<[u8; 32], StorageError> {
    file.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut left = length;
    let mut buffer = [0; BUFFER];
    let mut hash = Sha256::new();
    while left > 0 {
        let take = left.min(BUFFER as u64) as usize;
        file.read_exact(&mut buffer[..take]).map_err(io)?;
        hash.update(&buffer[..take]);
        left -= take as u64;
    }
    Ok(hash.finalize().into())
}

/// The part file's own permissions, not only its directory's.
///
/// A part now lives beside its destination rather than inside the engine's own
/// directory, and on Unix `create_new` leaves the default `0666 & ~umask` --
/// commonly `0644`, readable by everyone. The directory is `0700`, so nothing
/// gets in through it today; a file that protects itself does not depend on
/// that staying true, and a review named the gap.
///
/// Windows takes its access list from the directory it is created in, which the
/// composition root has made private, so there is nothing to set here.
fn owner_only(options: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600)
    }
    #[cfg(not(unix))]
    {
        options
    }
}

impl FilePart {
    fn open_inner(
        path: &Path,
        spec: PartSpec,
        create: bool,
        owner: Option<Arc<File>>,
    ) -> Result<Self, StorageError> {
        let directory = directory(path, create)?;
        let name = format!("{}-{}", spec.job().get(), spec.generation().get());
        let part_path = directory.join(format!("{name}.part"));
        let metadata_path = directory.join(format!("{name}.meta"));
        check_optional(&part_path)?;
        check_optional(&metadata_path)?;
        // Create-new never truncates a surviving generation or unrelated file.
        let mut file = owner_only(OpenOptions::new().read(true).write(true))
            .create_new(create)
            .open(&part_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    StorageError::Conflict
                } else {
                    io(error)
                }
            })?;

        let mut metadata = owner_only(OpenOptions::new().read(true).write(true))
            .create_new(create)
            .open(&metadata_path)
            .map_err(io)?;
        let sealed = if create {
            file.set_len(spec.size()).map_err(io)?;
            file.sync_all().map_err(io)?;
            metadata.write_all(&identity(spec, false)).map_err(io)?;
            metadata.sync_all().map_err(io)?;
            sync_directory(&directory)?;
            false
        } else {
            if metadata.metadata().map_err(io)?.len() != META_LEN as u64
                || file.metadata().map_err(io)?.len() != spec.size()
            {
                return Err(StorageError::Integrity);
            }
            let mut data = [0; META_LEN];
            metadata.read_exact(&mut data).map_err(io)?;
            if data[..33] != identity(spec, false)[..33] || data[33] > 1 {
                return Err(StorageError::Integrity);
            }
            data[33] == 1
        };
        file.seek(SeekFrom::Start(0)).map_err(io)?;
        Ok(Self {
            file,
            metadata,
            path: part_path,
            directory,
            spec,
            coverage: vec![],
            protected: vec![],
            synchronized: create,
            verified: None,
            sealed,
            published: false,
            cancelled: false,
            poisoned: false,
            #[cfg(test)]
            fault: None,
            _lock: owner,
        })
    }
    fn healthy(&self) -> Result<(), StorageError> {
        if self.poisoned {
            Err(StorageError::InvalidState)
        } else {
            Ok(())
        }
    }
    fn range(&self, offset: u64, length: usize) -> Result<ByteRange, StorageError> {
        let end = offset
            .checked_add(length as u64)
            .ok_or(StorageError::Bounds)?;
        if end > self.spec.size() {
            return Err(StorageError::Bounds);
        }
        ByteRange::new(offset, end).map_err(|_| StorageError::Bounds)
    }
    fn coverage_plan(&self, range: ByteRange) -> Result<(usize, usize, ByteRange), StorageError> {
        let first = self
            .coverage
            .partition_point(|entry| entry.end() < range.start());
        let mut last = first;
        let mut start = range.start();
        let mut end = range.end();
        while let Some(entry) = self.coverage.get(last) {
            if entry.start() > end {
                break;
            }
            start = start.min(entry.start());
            end = end.max(entry.end());
            last += 1;
        }
        if self.coverage.len() - (last - first) + 1 > MAX_EXTENTS {
            return Err(StorageError::Bounds);
        }
        Ok((
            first,
            last,
            ByteRange::new(start, end).map_err(|_| StorageError::Bounds)?,
        ))
    }
    fn add_coverage(&mut self, plan: (usize, usize, ByteRange)) {
        let (first, last, range) = plan;
        self.coverage.splice(first..last, [range]);
    }
    fn complete(&self) -> bool {
        self.spec.size() == 0
            || (self.coverage.len() == 1
                && self.coverage[0].start() == 0
                && self.coverage[0].end() == self.spec.size())
    }
    fn hash(&mut self, start: u64, length: u64) -> Result<[u8; 32], StorageError> {
        self.file.seek(SeekFrom::Start(start)).map_err(io)?;
        let mut left = length;
        let mut buffer = [0; BUFFER];
        let mut hash = Sha256::new();
        while left > 0 {
            let length = left.min(BUFFER as u64) as usize;
            self.file.read_exact(&mut buffer[..length]).map_err(io)?;
            hash.update(&buffer[..length]);
            left -= length as u64;
        }
        Ok(hash.finalize().into())
    }
}
impl SegmentFile for FilePart {
    fn spec(&self) -> PartSpec {
        self.spec
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), StorageError> {
        self.healthy()?;
        if self.sealed {
            return Err(StorageError::InvalidState);
        }
        if bytes.is_empty() {
            return if offset <= self.spec.size() {
                Ok(())
            } else {
                Err(StorageError::Bounds)
            };
        }
        let range = self.range(offset, bytes.len())?;
        if self
            .protected
            .iter()
            .any(|entry| entry.start() < range.end() && range.start() < entry.end())
        {
            return Err(StorageError::InvalidState);
        }
        let plan = self.coverage_plan(range)?;
        self.poisoned = true;
        self.synchronized = false;
        self.verified = None;
        self.file.seek(SeekFrom::Start(offset)).map_err(io)?;
        #[cfg(test)]
        if let Some(Fault::PartialWrite(count)) = self.fault.take() {
            self.file
                .write_all(&bytes[..count.min(bytes.len())])
                .map_err(io)?;
            return Err(StorageError::Io(std::io::ErrorKind::StorageFull));
        }
        self.file.write_all(bytes).map_err(io)?;
        self.add_coverage(plan);
        self.poisoned = false;
        Ok(())
    }
    fn sync(&mut self) -> Result<(), StorageError> {
        self.healthy()?;
        self.poisoned = true;
        #[cfg(test)]
        if matches!(self.fault.take(), Some(Fault::Sync)) {
            return Err(StorageError::Io(std::io::ErrorKind::Other));
        }
        self.file.sync_all().map_err(io)?;
        self.synchronized = true;
        self.poisoned = false;
        Ok(())
    }
    fn hash_range(&mut self, range: ByteRange) -> Result<[u8; 32], StorageError> {
        self.healthy()?;
        if range.end() > self.spec.size() {
            return Err(StorageError::Bounds);
        }
        self.hash(range.start(), range.len())
    }
    fn recover_extent(&mut self, range: ByteRange, digest: [u8; 32]) -> Result<(), StorageError> {
        self.healthy()?;
        if range.end() > self.spec.size() {
            return Err(StorageError::Bounds);
        }
        let plan = self.coverage_plan(range)?;
        if self.hash(range.start(), range.len())? != digest {
            return Err(StorageError::Integrity);
        }
        if self.protected.len() >= MAX_EXTENTS {
            return Err(StorageError::Bounds);
        }
        self.protected.push(range);
        self.add_coverage(plan);
        Ok(())
    }
    fn verify(
        &mut self,
        expected: Option<[u8; 32]>,
        record: &[(ByteRange, [u8; 32])],
    ) -> Result<[u8; 32], StorageError> {
        self.healthy()?;
        self.verified = None;
        if !self.complete() || !self.synchronized {
            return Err(StorageError::InvalidState);
        }
        if self.file.metadata().map_err(io)?.len() != self.spec.size() {
            return Err(StorageError::Integrity);
        }

        // Every byte has to sit inside something that was recorded. A range
        // nobody attested is a range nothing here can speak for, so a record
        // with a hole in it fails rather than covering the hole with a digest
        // taken from the file.
        let mut ranges: Vec<ByteRange> = record.iter().map(|(range, _)| *range).collect();
        ranges.sort_by_key(|range| range.start());
        let mut reached = 0u64;
        for range in &ranges {
            if range.start() > reached {
                return Err(StorageError::Integrity);
            }
            reached = reached.max(range.end());
        }
        if reached != self.spec.size() {
            return Err(StorageError::Integrity);
        }

        // And each recorded range is rehashed against what was recorded for it,
        // rather than assumed to be whatever is there now.
        for (range, digest) in record {
            if range.end() > self.spec.size() {
                return Err(StorageError::Bounds);
            }
            if self.hash(range.start(), range.len())? != *digest {
                return Err(StorageError::Integrity);
            }
        }

        let digest = self.hash(0, self.spec.size())?;
        if expected.is_some_and(|expected| expected != digest) {
            return Err(StorageError::Integrity);
        }
        self.verified = Some(digest);
        Ok(digest)
    }
    /// Only after this handle published, so the bytes still exist under their
    /// final name; otherwise the caller must cancel, which is a different decision.
    fn discard(&mut self) -> Result<(), StorageError> {
        if !self.published && !self.cancelled {
            return Err(StorageError::InvalidState);
        }
        // Order matters: the part first, then its sidecar, so no metadata ever
        // claims a generation whose bytes are already gone.
        self.poisoned = true;
        for path in [self.path.clone(), self.path.with_extension("meta")] {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(io(error)),
            }
        }
        sync_directory(&self.directory)
    }
    fn abandon(&mut self) {
        self.cancelled = true;
    }
    fn publish(&mut self, destination: &Path) -> Result<PathBuf, StorageError> {
        self.healthy()?;
        let expected = self.verified.ok_or(StorageError::InvalidState)?;
        if !self.synchronized || !self.complete() {
            return Err(StorageError::InvalidState);
        }
        let destination = resolve_destination(destination)?;
        match fs::symlink_metadata(&destination) {
            Ok(_) => return Err(StorageError::Conflict),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(io(error)),
        }
        ordinary(&self.path, false)?;
        if self.file.metadata().map_err(io)?.len() != self.spec.size() {
            self.verified = None;
            return Err(StorageError::Integrity);
        }
        // Freeze the generation durably BEFORE a second pathname can expose its
        // inode. A reopened part can never modify a published hard-link target.
        self.poisoned = true;
        self.metadata.seek(SeekFrom::Start(33)).map_err(io)?;
        self.metadata.write_all(&[1]).map_err(io)?;
        self.metadata.sync_all().map_err(io)?;
        self.sealed = true;

        // Staged inside our own directory before the final name exists.
        //
        // Checking after linking to the destination closed the substitution but
        // opened two other things: the file carried its final name while it was
        // still being proved, so a user or another program could read bytes
        // nothing had attested yet; and undoing a bad link assumed the name
        // still referred to what we linked, which is the assumption that failed
        // in the first place -- a destination replaced in between would have
        // been deleted on our way out.
        //
        // So the link is made here first, in the directory this engine created
        // with its own access list, where the adversary can neither read it nor
        // put something else at the name. It is proved through a handle on that
        // link, and only then does the destination appear. A failure removes
        // only this staged name, which is ours.
        let staged = self.directory.join(format!(
            "{}-{}.staged",
            self.spec.job().get(),
            self.spec.generation().get()
        ));
        let _ = fs::remove_file(&staged);
        fs::hard_link(&self.path, &staged).map_err(|error| {
            self.poisoned = false;
            self.sealed = false;
            io(error)
        })?;
        let proved = File::open(&staged)
            .map_err(io)
            .and_then(|mut file| hash_whole(&mut file, self.spec.size()));
        if proved.as_ref() != Ok(&expected) {
            let _ = fs::remove_file(&staged);
            self.poisoned = false;
            self.sealed = false;
            self.verified = None;
            return Err(StorageError::Integrity);
        }

        match fs::hard_link(&staged, &destination) {
            Ok(()) => (),
            Err(error) => {
                let _ = fs::remove_file(&staged);
                self.poisoned = false;
                return Err(match error.kind() {
                    std::io::ErrorKind::AlreadyExists => StorageError::Conflict,
                    std::io::ErrorKind::Unsupported | std::io::ErrorKind::CrossesDevices => {
                        StorageError::Unsupported
                    }
                    _ => io(error),
                });
            }
        }
        // The staged name has served its purpose; the destination and the part
        // both name the same inode now.
        let _ = fs::remove_file(&staged);
        self.file.sync_all().map_err(io)?;
        sync_directory(destination.parent().ok_or(StorageError::InvalidInput)?)?;
        sync_directory(&self.directory)?;
        self.published = true;
        self.poisoned = false;
        Ok(destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhd_domain::{Generation, JobId};
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "fhd-positional-{}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }
        fn part(&self) -> PathBuf {
            self.0.join("part")
        }
        fn output(&self) -> PathBuf {
            self.0.join("download.bin")
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn spec(size: u64) -> PartSpec {
        PartSpec::new(JobId::new(1).unwrap(), Generation::initial(), size).unwrap()
    }
    fn hash(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }
    /// A part swapped at its name between verification and publication does not
    /// become the user's file.
    ///
    /// Publication links a path. A review renamed the verified part aside, put
    /// its own file at that name, and watched those bytes get published --
    /// nothing in the suite constrained it. The link is checked against the
    /// verified handle afterwards now, so the question asked is whether the file
    /// that exists is the one we meant.
    #[test]
    fn a_part_swapped_at_its_name_before_publication_never_becomes_the_file() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(6))
            .unwrap();
        part.write_at(0, b"abcdef").unwrap();
        part.sync().unwrap();
        let record = attested(part.as_mut());
        part.verify(None, &record).unwrap();

        // The name is moved aside and another file takes it. The handle survives
        // the rename, which is exactly why the path and the object can differ.
        let name = directory.part().join("1-1.part");
        fs::rename(&name, directory.part().join("moved.bin")).unwrap();
        fs::write(&name, b"EVIL!!").unwrap();

        assert_eq!(
            part.publish(&directory.output()),
            Err(StorageError::Integrity),
            "a file planted at the part's name was published"
        );
        assert!(
            !directory.output().exists(),
            "the planted file was left behind at the destination"
        );
    }

    /// A failed publication never creates the destination, and never removes
    /// anything that is there.
    ///
    /// Proving the link after making it at the destination meant the final name
    /// existed while its bytes were still unproved, and that undoing it assumed
    /// the name still referred to what we had linked -- so a destination
    /// replaced in between would have been deleted on the way out. This asks
    /// both questions directly: with a swapped part, does the name appear, and
    /// is a file already sitting at a nearby name still there afterwards.
    #[test]
    fn a_failed_publication_leaves_the_destination_alone() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(6))
            .unwrap();
        part.write_at(0, b"abcdef").unwrap();
        part.sync().unwrap();
        let record = attested(part.as_mut());
        part.verify(None, &record).unwrap();

        // Somebody else's file, in the folder the destination lives in.
        let bystander = directory.output().with_file_name("theirs.bin");
        fs::write(&bystander, b"not ours").unwrap();

        // The part is swapped at its name after verification.
        let name = directory.part().join("1-1.part");
        fs::rename(&name, directory.part().join("moved.bin")).unwrap();
        fs::write(&name, b"EVIL!!").unwrap();

        assert_eq!(
            part.publish(&directory.output()),
            Err(StorageError::Integrity),
            "a file planted at the part's name was published"
        );
        assert!(
            !directory.output().exists(),
            "the destination name appeared for a publication that failed"
        );
        assert_eq!(
            fs::read(&bystander).unwrap(),
            b"not ours",
            "a failed publication touched a file that was not ours"
        );
        // And nothing of ours is left lying about under its own directory.
        let staged: Vec<_> = fs::read_dir(directory.part())
            .unwrap()
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".staged"))
            .collect();
        assert!(
            staged.is_empty(),
            "a staged link was left behind: {staged:?}"
        );
    }

    /// The store's own lock refuses a second claim on one directory.
    ///
    /// A review measured that the process-level test named for this proves the
    /// *persistence* lock instead: the database claims the state directory
    /// before `FileStorage::own` is ever reached, so deleting `try_lock` here
    /// left that test green. This asks the store directly, with nothing in the
    /// way.
    #[test]
    fn a_second_claim_on_one_directory_is_refused() {
        let directory = Directory::new();
        let held = FileStorage::own(&directory.part()).expect("the first claim succeeds");
        assert!(
            matches!(
                FileStorage::own(&directory.part()),
                Err(StorageError::Locked)
            ),
            "a second claim on a directory already owned was allowed"
        );
        // And it is the holding, not the directory: released, it is claimable
        // again, so this cannot pass against an `own` that always refuses.
        drop(held);
        FileStorage::own(&directory.part()).expect("the directory is claimable once released");
    }

    /// A part file is readable by its owner and nobody else.
    ///
    /// Until now nothing asserted this on any platform: changing `0o600` to
    /// `0o666` passed the whole suite everywhere and no CI step could have
    /// noticed.
    #[cfg(unix)]
    #[test]
    fn a_part_file_carries_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(6))
            .unwrap();
        part.write_at(0, b"abcdef").unwrap();
        part.sync().unwrap();

        for name in ["1-1.part", "1-1.meta"] {
            let mode = fs::metadata(directory.part().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o077,
                0,
                "{name} grants group or other something: {:o}",
                mode & 0o777
            );
            assert_ne!(mode & 0o600, 0, "{name} grants its owner nothing");
        }
    }

    /// Bytes changed after they were recorded do not publish.
    ///
    /// Verification used to hash the file and compare it with that same hash, so
    /// it could not see a change at all. A review overwrote sixteen bytes of a
    /// live part with no digest on the request and watched them become the
    /// user's file. Here the record is taken first and the file is changed
    /// afterwards, which is the order that matters.
    #[test]
    fn a_part_changed_after_it_was_recorded_never_publishes() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(6))
            .unwrap();
        part.write_at(0, b"abcdef").unwrap();
        part.sync().unwrap();
        let record = attested(part.as_mut());

        // Somebody else gets to the bytes. Written through a second handle,
        // because that is how it would happen.
        {
            use std::io::Write;
            let mut other = fs::OpenOptions::new()
                .write(true)
                .open(directory.part().join("1-1.part"))
                .unwrap();
            other.write_all(b"XX").unwrap();
            other.sync_all().unwrap();
        }

        assert_eq!(
            part.verify(None, &record),
            Err(StorageError::Integrity),
            "a part changed after it was recorded verified anyway"
        );
        assert_eq!(
            part.publish(&directory.output()),
            Err(StorageError::InvalidState),
            "an unverified part published"
        );
        assert!(!directory.output().exists());
    }

    /// A record that does not reach every byte is refused.
    ///
    /// An uncovered range is one nothing ever attested, so accepting it would
    /// mean verifying part of the file against evidence and the rest against
    /// nothing.
    #[test]
    fn a_record_with_a_gap_in_it_is_refused() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(6))
            .unwrap();
        part.write_at(0, b"abcdef").unwrap();
        part.sync().unwrap();

        // Everything except the middle two bytes.
        let head = range(0, 2);
        let tail = range(4, 6);
        let gapped = vec![
            (head, part.hash_range(head).unwrap()),
            (tail, part.hash_range(tail).unwrap()),
        ];
        assert_eq!(part.verify(None, &gapped), Err(StorageError::Integrity));

        // A record that stops short is refused too. This is the separate case:
        // the one above is caught by the ranges not meeting, this one only by
        // the record being required to reach the end of the file.
        let prefix = range(0, 4);
        let short = vec![(prefix, part.hash_range(prefix).unwrap())];
        assert_eq!(
            part.verify(None, &short),
            Err(StorageError::Integrity),
            "a record covering four of six bytes was accepted"
        );

        // And the same ranges with the hole filled do verify, so the refusals
        // above are about the coverage and not about the shape of the record.
        let middle = range(2, 4);
        let mut whole = gapped;
        whole.push((middle, part.hash_range(middle).unwrap()));
        part.verify(None, &whole).unwrap();
    }

    /// The whole file, attested as it stands right now.
    ///
    /// Verification takes the repository's committed extents as its prior
    /// evidence. These tests are about other things, so they hand it a record
    /// that matches -- the behaviour the record exists for is proved by
    /// `a_part_changed_after_it_was_recorded_never_publishes`, which builds the
    /// record first and changes the bytes afterwards.
    fn attested(part: &mut dyn SegmentFile) -> Vec<(ByteRange, [u8; 32])> {
        let size = part.spec().size();
        // An empty transfer has nothing to attest, and no byte goes unattested
        // by saying so: the coverage check asks that the record reach the end of
        // the file, and for a file of length zero it already has.
        if size == 0 {
            return Vec::new();
        }
        let whole = ByteRange::new(0, size).unwrap();
        vec![(whole, part.hash_range(whole).unwrap())]
    }

    fn range(start: u64, end: u64) -> ByteRange {
        ByteRange::new(start, end).unwrap()
    }

    #[test]
    fn out_of_order_writes_preserve_holes_until_full_coverage_and_sync() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(6))
            .unwrap();
        part.write_at(3, b"def").unwrap();
        part.sync().unwrap();
        assert_eq!(
            fs::read(directory.part().join("1-1.part")).unwrap(),
            b"\0\0\0def"
        );
        assert_eq!(part.verify(None, &[]), Err(StorageError::InvalidState));
        part.write_at(0, b"abc").unwrap();
        assert_eq!(part.verify(None, &[]), Err(StorageError::InvalidState));
        part.sync().unwrap();
        let record = attested(part.as_mut());
        assert_eq!(
            part.verify(Some(hash(b"abcdef")), &record).unwrap(),
            hash(b"abcdef")
        );
        part.publish(&directory.output()).unwrap();
        assert_eq!(fs::read(directory.output()).unwrap(), b"abcdef");
    }
    #[test]
    fn a_part_is_released_only_after_publication_or_abandonment() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(6))
            .unwrap();
        part.write_at(0, b"abcdef").unwrap();
        part.sync().unwrap();
        let record = attested(part.as_mut());
        part.verify(None, &record).unwrap();
        // Unpublished bytes are never thrown away by mistake.
        assert_eq!(part.discard(), Err(StorageError::InvalidState));
        assert!(directory.part().join("1-1.part").exists());
        part.publish(&directory.output()).unwrap();
        part.discard().unwrap();
        // The published name still holds the bytes; the part and its sidecar are gone.
        assert_eq!(fs::read(directory.output()).unwrap(), b"abcdef");
        assert!(!directory.part().join("1-1.part").exists());
        assert!(!directory.part().join("1-1.meta").exists());
        // The handle is finished for real work, and releasing twice is harmless.
        assert_eq!(part.sync(), Err(StorageError::InvalidState));
        assert_eq!(part.write_at(0, b"x"), Err(StorageError::InvalidState));
        part.discard().unwrap();

        // A cancelled transfer may drop bytes it never published.
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(6))
            .unwrap();
        part.write_at(0, b"abcdef").unwrap();
        part.sync().unwrap();
        part.abandon();
        part.discard().unwrap();
        assert!(!directory.part().join("1-1.part").exists());
    }
    #[test]
    fn file_length_and_zero_hash_never_authorize_unwritten_holes() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(8))
            .unwrap();
        assert_eq!(
            fs::metadata(directory.part().join("1-1.part"))
                .unwrap()
                .len(),
            8
        );
        assert_eq!(
            part.verify(Some(hash(&[0; 8])), &[]),
            Err(StorageError::InvalidState)
        );
        assert_eq!(
            part.publish(&directory.output()),
            Err(StorageError::InvalidState)
        );
    }
    #[test]
    fn reopen_requires_rehashed_repository_extents_and_explicit_sync() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(6))
            .unwrap();
        part.write_at(3, b"def").unwrap();
        part.write_at(0, b"abc").unwrap();
        part.sync().unwrap();
        drop(part);
        let mut reopened = FileStorage::default()
            .open(&directory.part(), spec(6))
            .unwrap();
        assert_eq!(reopened.verify(None, &[]), Err(StorageError::InvalidState));
        reopened.recover_extent(range(3, 6), hash(b"def")).unwrap();
        assert_eq!(
            reopened.recover_extent(range(0, 3), hash(b"bad")),
            Err(StorageError::Integrity)
        );
        reopened.sync().unwrap();
        assert_eq!(reopened.verify(None, &[]), Err(StorageError::InvalidState));
        reopened.recover_extent(range(0, 3), hash(b"abc")).unwrap();
        let record = attested(reopened.as_mut());
        assert_eq!(
            reopened.verify(Some(hash(b"abcdef")), &record).unwrap(),
            hash(b"abcdef")
        );
    }
    #[test]
    fn write_after_verification_invalidates_publication_and_needs_new_sync() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(3))
            .unwrap();
        part.write_at(0, b"abc").unwrap();
        part.sync().unwrap();
        let record = attested(part.as_mut());
        part.verify(None, &record).unwrap();
        part.write_at(1, b"x").unwrap();
        assert_eq!(
            part.publish(&directory.output()),
            Err(StorageError::InvalidState)
        );
        part.sync().unwrap();
        let record = attested(part.as_mut());
        assert_eq!(
            part.verify(Some(hash(b"abc")), &record),
            Err(StorageError::Integrity)
        );
        part.verify(Some(hash(b"axc")), &record).unwrap();
        part.publish(&directory.output()).unwrap();
        assert_eq!(fs::read(directory.output()).unwrap(), b"axc");
    }
    #[test]
    fn destination_collision_never_overwrites_user_file() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(3))
            .unwrap();
        part.write_at(0, b"abc").unwrap();
        part.sync().unwrap();
        let record = attested(part.as_mut());
        part.verify(None, &record).unwrap();
        fs::write(directory.output(), b"USER").unwrap();
        assert_eq!(
            part.publish(&directory.output()),
            Err(StorageError::Conflict)
        );
        assert_eq!(fs::read(directory.output()).unwrap(), b"USER");
    }
    #[test]
    fn seal_survives_reopen_and_prevents_writing_published_inode() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(3))
            .unwrap();
        part.write_at(0, b"abc").unwrap();
        part.sync().unwrap();
        let record = attested(part.as_mut());
        part.verify(None, &record).unwrap();
        part.publish(&directory.output()).unwrap();
        assert_eq!(part.write_at(0, b"xyz"), Err(StorageError::InvalidState));
        drop(part);
        let mut reopened = FileStorage::default()
            .open(&directory.part(), spec(3))
            .unwrap();
        assert_eq!(
            reopened.write_at(0, b"xyz"),
            Err(StorageError::InvalidState)
        );
        drop(reopened);
        assert_eq!(fs::read(directory.output()).unwrap(), b"abc");
        OpenOptions::new()
            .append(true)
            .open(directory.output())
            .unwrap()
            .write_all(b"USER")
            .unwrap();
        assert!(matches!(
            FileStorage::default().open(&directory.part(), spec(3)),
            Err(StorageError::Integrity)
        ));
        assert_eq!(fs::read(directory.output()).unwrap(), b"abcUSER");
    }
    #[test]
    fn lock_identity_bounds_and_existing_generation_are_enforced() {
        let directory = Directory::new();
        let store = FileStorage::own(&directory.part()).unwrap();
        // The tree belongs to one engine: a second one is refused here, not later.
        assert!(matches!(
            FileStorage::own(&directory.part()),
            Err(StorageError::Locked)
        ));
        let mut part = store.create(&directory.part(), spec(3)).unwrap();
        assert_eq!(part.write_at(u64::MAX, b"a"), Err(StorageError::Bounds));
        assert_eq!(part.write_at(2, b"xx"), Err(StorageError::Bounds));
        assert_eq!(part.hash_range(range(2, 4)), Err(StorageError::Bounds));
        drop(part);
        assert!(matches!(
            store.create(&directory.part(), spec(3)),
            Err(StorageError::Conflict)
        ));
        assert!(matches!(
            store.open(&directory.part(), spec(4)),
            Err(StorageError::Integrity)
        ));
        // Two generations of one job, and two jobs, live side by side: the engine
        // runs several at once, so opening one part never excludes another.
        let other = PartSpec::new(JobId::new(1).unwrap(), Generation::new(2).unwrap(), 3).unwrap();
        let _next = store.create(&directory.part(), other).unwrap();
        let elsewhere = PartSpec::new(JobId::new(9).unwrap(), Generation::initial(), 3).unwrap();
        let _other_job = store.create(&directory.part(), elsewhere).unwrap();
        assert!(directory.part().join("9-1.part").exists());
        assert!(directory.part().join("1-1.part").exists());
        assert!(directory.part().join("1-2.part").exists());
    }
    #[test]
    fn partial_write_poisoning_never_credits_full_range() {
        let directory = Directory::new();
        let mut part = FilePart::open_inner(&directory.part(), spec(6), true, None).unwrap();
        part.fault = Some(Fault::PartialWrite(2));
        assert_eq!(
            part.write_at(0, b"abcdef"),
            Err(StorageError::Io(std::io::ErrorKind::StorageFull))
        );
        assert!(part.coverage.is_empty());
        assert_eq!(part.sync(), Err(StorageError::InvalidState));
        assert_eq!(part.write_at(0, b"abcdef"), Err(StorageError::InvalidState));
        drop(part);
        let mut part = FileStorage::default()
            .open(&directory.part(), spec(6))
            .unwrap();
        assert_eq!(
            part.recover_extent(range(0, 6), hash(b"abcdef")),
            Err(StorageError::Integrity)
        );
        part.write_at(0, b"abcdef").unwrap();
        part.sync().unwrap();
        let record = attested(part.as_mut());
        part.verify(Some(hash(b"abcdef")), &record).unwrap();
    }
    #[test]
    fn failed_sync_requires_reopen_and_reconciliation() {
        let directory = Directory::new();
        let mut part = FilePart::open_inner(&directory.part(), spec(3), true, None).unwrap();
        part.write_at(0, b"abc").unwrap();
        part.fault = Some(Fault::Sync);
        assert_eq!(
            part.sync(),
            Err(StorageError::Io(std::io::ErrorKind::Other))
        );
        assert_eq!(part.verify(None, &[]), Err(StorageError::InvalidState));
        assert_eq!(
            part.publish(&directory.output()),
            Err(StorageError::InvalidState)
        );
        drop(part);
        let mut part = FileStorage::default()
            .open(&directory.part(), spec(3))
            .unwrap();
        part.recover_extent(range(0, 3), hash(b"abc")).unwrap();
        part.sync().unwrap();
        let record = attested(part.as_mut());
        part.verify(Some(hash(b"abc")), &record).unwrap();
    }
    #[test]
    fn changed_bytes_after_verification_are_rejected_at_publication() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(3))
            .unwrap();
        part.write_at(0, b"abc").unwrap();
        part.sync().unwrap();
        let record = attested(part.as_mut());
        part.verify(None, &record).unwrap();
        fs::write(directory.part().join("1-1.part"), b"xyz").unwrap();
        assert_eq!(
            part.publish(&directory.output()),
            Err(StorageError::Integrity)
        );
        assert!(!directory.output().exists());
    }
    #[test]
    fn empty_file_is_a_valid_complete_transfer_without_nonempty_extents() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(0))
            .unwrap();
        let record = attested(part.as_mut());
        assert_eq!(part.verify(Some(hash(b"")), &record).unwrap(), hash(b""));
        part.publish(&directory.output()).unwrap();
        assert_eq!(fs::metadata(directory.output()).unwrap().len(), 0);
    }
    #[cfg(unix)]
    #[test]
    fn symlink_generated_part_is_rejected_without_touching_target() {
        let directory = Directory::new();
        fs::create_dir(directory.part()).unwrap();
        fs::write(directory.output(), b"USER").unwrap();
        std::os::unix::fs::symlink(directory.output(), directory.part().join("1-1.part")).unwrap();
        assert!(matches!(
            FileStorage::default().create(&directory.part(), spec(4)),
            Err(StorageError::InvalidInput)
        ));
        assert_eq!(fs::read(directory.output()).unwrap(), b"USER");
    }
    #[test]
    fn recovered_durable_ranges_cannot_be_overwritten() {
        let directory = Directory::new();
        let mut part = FileStorage::default()
            .create(&directory.part(), spec(6))
            .unwrap();
        part.write_at(0, b"abc").unwrap();
        part.sync().unwrap();
        drop(part);
        let mut part = FileStorage::default()
            .open(&directory.part(), spec(6))
            .unwrap();
        part.recover_extent(range(0, 3), hash(b"abc")).unwrap();
        assert_eq!(part.write_at(1, b"XX"), Err(StorageError::InvalidState));
        assert_eq!(part.write_at(2, b"XX"), Err(StorageError::InvalidState));
        part.write_at(3, b"def").unwrap();
        part.sync().unwrap();
        let record = attested(part.as_mut());
        part.verify(Some(hash(b"abcdef")), &record).unwrap();
        assert_eq!(
            fs::read(directory.part().join("1-1.part")).unwrap(),
            b"abcdef"
        );
    }
    #[test]
    fn portable_destination_names_reject_ads_devices_and_controls() {
        for name in [
            "file:stream",
            "NUL.txt",
            "com1.zip",
            "lpt\u{00B2}",
            "file.",
            "file ",
            "a\nb",
            "..",
            "",
        ] {
            assert_eq!(
                validate_leaf(std::ffi::OsStr::new(name)),
                Err(StorageError::InvalidInput)
            );
        }
        assert!(validate_leaf(std::ffi::OsStr::new("report-2026.bin")).is_ok());
    }
}
