//! Blocking storage ports. A writer thread owns each file; network workers never do.
use fhd_domain::{ByteRange, DomainError, Generation, JobId};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartSpec {
    job: JobId,
    generation: Generation,
    size: u64,
}
impl PartSpec {
    pub fn new(job: JobId, generation: Generation, size: u64) -> Result<Self, DomainError> {
        if size > i64::MAX as u64 {
            return Err(DomainError::InvalidInput);
        }
        Ok(Self {
            job,
            generation,
            size,
        })
    }
    pub fn job(self) -> JobId {
        self.job
    }
    pub fn generation(self) -> Generation {
        self.generation
    }
    pub fn size(self) -> u64 {
        self.size
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError {
    InvalidInput,
    InvalidState,
    Bounds,
    Locked,
    Io(ErrorKind),
    Integrity,
    Conflict,
    Unsupported,
}
impl StorageError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "STORAGE-INVALID-INPUT",
            Self::InvalidState => "STORAGE-INVALID-STATE",
            Self::Bounds => "STORAGE-BOUNDS",
            Self::Locked => "STORAGE-LOCKED",
            Self::Integrity => "STORAGE-INTEGRITY",
            Self::Conflict | Self::Io(ErrorKind::AlreadyExists) => "STORAGE-CONFLICT",
            Self::Unsupported | Self::Io(ErrorKind::Unsupported | ErrorKind::CrossesDevices) => {
                "STORAGE-UNSUPPORTED"
            }
            Self::Io(ErrorKind::StorageFull) => "STORAGE-FULL",
            Self::Io(ErrorKind::PermissionDenied) => "STORAGE-ACCESS-DENIED",
            Self::Io(ErrorKind::NotFound) => "STORAGE-NOT-FOUND",
            Self::Io(ErrorKind::TimedOut) => "STORAGE-TIMEOUT",
            Self::Io(ErrorKind::Interrupted) => "STORAGE-INTERRUPTED",
            Self::Io(ErrorKind::WouldBlock) => "STORAGE-BUSY",
            Self::Io(ErrorKind::UnexpectedEof) => "STORAGE-UNEXPECTED-EOF",
            Self::Io(_) => "STORAGE-IO",
        }
    }
}
impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for StorageError {}

/// What already occupies a destination path, for publish reconciliation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Occupant {
    /// A regular file whose digest was computed because its size matched.
    File { size: u64, digest: [u8; 32] },
    /// A regular file of another size: never ours, and not worth hashing.
    OtherSize,
    /// A directory, link or device: never publishable over.
    NotAFile,
}

/// What publication achieved, with the object kept separate from the path.
///
/// Publishing into the adopted folder and being able to say where that folder
/// is are two different claims, and collapsing them is how an operator gets
/// told a file sits at a path that leads nowhere. If the folder is renamed
/// during the transfer the file is still exactly where the contract requires
/// -- inside the object that was adopted -- and the path the operator typed no
/// longer reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Published {
    /// In the adopted folder, and this path reaches it. The ordinary answer.
    At(PathBuf),
    /// In the adopted folder, under `name`, but the path the operator gave no
    /// longer reaches it: the folder was renamed or moved after adoption.
    ///
    /// **Nothing is republished and nothing is removed.** Publishing again
    /// would put a second copy somewhere, and deleting would act on a file this
    /// engine cannot prove is its own. The job is complete and needs the
    /// operator, which is what this state says.
    Moved {
        /// The path that was asked for, which no longer leads to the file.
        requested: PathBuf,
        /// The file's name inside the adopted folder.
        name: std::ffi::OsString,
    },
}

impl std::fmt::Display for Published {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::At(path) => write!(f, "{}", path.display()),
            // Never just the requested path: that is the sentence that tells an
            // operator to look somewhere the file is not.
            Self::Moved { requested, name } => write!(
                f,
                "{} as {} -- in the folder you chose, which was renamed during the transfer",
                requested.display(),
                name.to_string_lossy()
            ),
        }
    }
}

/// Creates a second name for the file a handle already holds, inside a
/// directory another handle already holds.
///
/// Publication is the one place the engine turns bytes it has proved into a
/// file somebody else will open, and the difference between naming a *path* and
/// naming a *handle* is the whole of it: a path is resolved when the call runs,
/// so between proving the bytes and publishing them the name can be made to
/// mean something else. Both ends were measured. The source name was taken over
/// and the other file's bytes were published. The destination folder was moved
/// aside, a new directory took its name, and the file landed in the new one --
/// which is why `directory` is a handle too, and why `name` is a single
/// component rather than a path: the folder the operator approved is fixed as
/// an object before publication begins, and only the leaf is resolved, inside
/// it.
///
/// **A platform without a mechanism says so.** It does not fall back to linking
/// by name: that is the behaviour being replaced, and a fallback that happens
/// quietly would leave the same hole under a new arrangement. Returning
/// `Unsupported` makes publication refuse with a reason instead.
pub trait HandleLinker: Send + Sync {
    fn link(
        &self,
        file: &std::fs::File,
        directory: &std::fs::File,
        name: &std::ffi::OsStr,
    ) -> Result<(), StorageError>;

    /// Whether two open handles are the same file.
    ///
    /// It sits beside `link` for the same reason `link` is a port at all: the
    /// answer needs the platform, and the storage adapter may not depend on it.
    /// Windows exposes it only through `windows_by_handle`, which is unstable,
    /// so the adapter cannot ask the question itself even in safe code.
    ///
    /// Publication uses it once, afterwards, to decide whether the path the
    /// operator gave still reaches what was published. **An error or a `false`
    /// must never become a claim that it does** -- not knowing is reported as
    /// not knowing, and the file stays where it is either way.
    fn same_object(
        &self,
        left: &std::fs::File,
        right: &std::fs::File,
    ) -> Result<bool, StorageError>;
}

pub trait SegmentStore: Send + Sync {
    /// `None` when the destination is free. Hashes only a file of exactly
    /// `expected_size`, so a large stranger is never read. Never follows links.
    fn inspect(
        &self,
        destination: &Path,
        expected_size: u64,
    ) -> Result<Option<Occupant>, StorageError>;
    /// Caller supplies an app-owned directory, never a browser-controlled path.
    fn create(
        &self,
        directory: &Path,
        spec: PartSpec,
    ) -> Result<Box<dyn SegmentFile>, StorageError>;
    fn open(&self, directory: &Path, spec: PartSpec) -> Result<Box<dyn SegmentFile>, StorageError>;
}
/// Single-owner handle. Successful write is not a durable extent receipt.
pub trait SegmentFile: Send {
    fn spec(&self) -> PartSpec;
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), StorageError>;
    fn sync(&mut self) -> Result<(), StorageError>;
    fn hash_range(&mut self, range: ByteRange) -> Result<[u8; 32], StorageError>;
    /// Rehash a receipt recovered from the repository before trusting its extent.
    /// Opening a file alone must not restore coverage based on its size.
    fn recover_extent(&mut self, range: ByteRange, digest: [u8; 32]) -> Result<(), StorageError>;
    /// Proves the file against the record, then optionally against a digest the
    /// request carried.
    ///
    /// `record` is the repository's committed extents: a range and the digest of
    /// its bytes, taken after the bytes were synced. It is the prior evidence
    /// this check is made against. Verifying without it compared the file with a
    /// digest computed from the file a moment earlier, which is a check of this
    /// function against itself -- a review overwrote sixteen bytes of a live part
    /// and watched them publish.
    ///
    /// The implementation must reject a record that does not cover every byte,
    /// because an uncovered range is one nothing ever attested, and it must
    /// rehash each recorded range rather than trusting that it was written.
    ///
    /// **What each of the two shows, exactly.** The record shows the bytes agree
    /// with what was recorded earlier -- consistency, and only as far as the
    /// record itself was protected, since the digests are computed from what
    /// arrived and an attacker able to change the data and the repository
    /// together defeats both halves at once.
    ///
    /// `expected` shows the bytes match the digest the request carried. That
    /// becomes evidence about the source only if the digest itself came from
    /// somewhere trustworthy: one read off the same page that supplied the link
    /// says nothing an attacker who controls the page could not also say. The
    /// check is worth making either way, and what it proves depends on where the
    /// digest came from, which is not something this layer can know.
    ///
    /// Coordinator must first drain workers. File length and zero contents do
    /// not prove coverage. Implementation invalidates any verification on
    /// further writes.
    fn verify(
        &mut self,
        expected: Option<[u8; 32]>,
        record: &[(ByteRange, [u8; 32])],
    ) -> Result<[u8; 32], StorageError>;
    /// Adopts the folder the operator named, as an object rather than a path.
    ///
    /// **This is the moment the destination's identity is decided**, and it is
    /// the only place a destination enters: `publish` takes none, so nothing can
    /// be published into a folder that was never adopted.
    ///
    /// Adoption is called when the session opens the part, before the first
    /// byte, so everything that happens to the folder for the rest of the
    /// transfer is defeated. **What it cannot do** is tell which directory the
    /// operator meant before that moment: they named a path, and a path is all
    /// the engine was given. A folder swapped before adoption is adopted, and
    /// the engine cannot see the difference -- so the window is not closed, it
    /// is moved to before the transfer starts and stated here rather than
    /// implied by the mechanism.
    fn adopt_destination(&mut self, destination: &Path) -> Result<(), StorageError>;
    /// Requires a synchronized, verified file, an adopted destination, and a
    /// durable PublishIntent in the repository. Atomic no-replace is mandatory;
    /// unsupported filesystems fail.
    fn publish(&mut self) -> Result<Published, StorageError>;
    /// Removes this generation's part file. Legitimate only after publication (the
    /// published name holds the bytes) or after `abandon`. The handle is unusable
    /// afterwards, so the caller drops it.
    fn discard(&mut self) -> Result<(), StorageError>;
    /// Declares the transfer abandoned (cancelled), which permits `discard` to
    /// remove bytes that were never published.
    fn abandon(&mut self);
}

#[cfg(test)]
mod error_tests {
    use super::*;

    #[test]
    fn storage_display_uses_stable_allowlisted_codes_only() {
        for (error, code) in [
            (StorageError::InvalidInput, "STORAGE-INVALID-INPUT"),
            (StorageError::Io(ErrorKind::StorageFull), "STORAGE-FULL"),
            (
                StorageError::Io(ErrorKind::PermissionDenied),
                "STORAGE-ACCESS-DENIED",
            ),
            (StorageError::Io(ErrorKind::NotFound), "STORAGE-NOT-FOUND"),
            (
                StorageError::Io(ErrorKind::AlreadyExists),
                "STORAGE-CONFLICT",
            ),
            (StorageError::Io(ErrorKind::TimedOut), "STORAGE-TIMEOUT"),
            (
                StorageError::Io(ErrorKind::CrossesDevices),
                "STORAGE-UNSUPPORTED",
            ),
            (StorageError::Io(ErrorKind::Other), "STORAGE-IO"),
        ] {
            assert_eq!(error.code(), code);
            assert_eq!(error.to_string(), code);
            assert!(code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'-'));
        }
    }
}
