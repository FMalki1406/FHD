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
    /// Something that had to agree does not.
    ///
    /// **Not only the downloaded bytes.** It also covers a record whose
    /// identity does not match the job and generation asked for, and a seal
    /// state no build ever wrote. So it is never on its own a licence to lift a
    /// seal or write over the same part: the thing that is wrong may be the
    /// record that says whether the file was delivered.
    ///
    /// Publication lifts the seal on exactly one integrity failure -- the
    /// bytes it has just re-read through its own verified handle -- and that is
    /// scoped to the check it made, not to this code in general.
    Integrity,
    Conflict,
    Unsupported,
    /// The part on disk was written by a format this build no longer reads.
    ///
    /// Separate from `Integrity` because the answer differs. Corruption means
    /// these bytes are wrong; this means they cannot be interpreted safely --
    /// the older format's record could not say whether the file had been
    /// delivered. The job needs a new generation, which is a new part file and
    /// an object of its own; the old one is left exactly where it is.
    Superseded,
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
            Self::Superseded => "STORAGE-SUPERSEDED",
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

/// How far publication had got, as the metadata records it durably.
///
/// A crash leaves a part behind and the only question that matters is whether
/// the user already has the file. Until now the record answered "sealed" and
/// nothing else, so every crash after the seal was the same unanswerable case
/// and the part was stranded to be safe.
///
/// Three bits of the byte that already carried the seal.
///
/// **A part written by an older format is refused, not read.** This sentence
/// used to say such a byte reads as `Sealed`, "the conservative one", and that
/// was wrong twice over: the older format wrote its seal byte before linking
/// and never again, so its `1` also means a file that was delivered -- and
/// reading it as `Sealed` would permit unsealing the user's own file. The
/// format version carries the difference now, and the claim came back once
/// already when this type moved, which is why it is stated here rather than
/// only where the version is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publication {
    /// Nothing attempted. The ordinary state of a part being written.
    Open,
    /// Sealed, and the link was never begun. **The file cannot exist**, so the
    /// part may be unsealed and the publication retried.
    Sealed,
    /// The link was begun and its outcome was never recorded. The file may or
    /// may not exist, and nothing on this disk can say which. The part is kept
    /// exactly as it is.
    Attempted,
    /// The link returned successfully. The bytes are the user's file now.
    Linked,
}
impl Publication {
    /// Bit 0: the part was sealed.
    pub const SEALED: u8 = 0b001;
    /// Bit 1: the link was begun.
    pub const ATTEMPTED: u8 = 0b010;
    /// Bit 2: the link returned.
    pub const LINKED: u8 = 0b100;

    pub fn from_byte(byte: u8) -> Self {
        if byte & Self::LINKED != 0 {
            Self::Linked
        } else if byte & Self::ATTEMPTED != 0 {
            Self::Attempted
        } else if byte & Self::SEALED != 0 {
            Self::Sealed
        } else {
            Self::Open
        }
    }
    /// The byte this state is written as, so a caller inspecting a part file
    /// can name what it sees instead of comparing numbers.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::Open => 0,
            Self::Sealed => Self::SEALED,
            Self::Attempted => Self::SEALED | Self::ATTEMPTED,
            Self::Linked => Self::SEALED | Self::ATTEMPTED | Self::LINKED,
        }
    }
    /// Whether a part in this state may be written to again.
    pub fn writable(self) -> bool {
        self == Self::Open
    }
}

/// What publication achieved, with the object kept separate from the path, and
/// both kept separate from what could not be established.
///
/// Publishing into the adopted folder and being able to say where that folder
/// is are two different claims, and collapsing them is how an operator gets
/// told a file sits at a path that leads nowhere. There is a third case that
/// must not be folded into either: publication succeeded, and the engine could
/// not find out whether the requested path still reaches it. **Not knowing
/// where the file is is not evidence that it moved**, and reporting it as a
/// move would be an assertion about the filesystem that nothing established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Published {
    /// Published, and the requested path was confirmed to reach it. The only
    /// variant whose path may be shown as somewhere to go and look.
    At(PathBuf),
    /// Published, and the requested path was confirmed **not** to reach it:
    /// either nothing is there, or what is there is a different file. The
    /// folder was renamed or moved after adoption.
    ///
    /// **Nothing is republished and nothing is removed.** Publishing again
    /// would put a second copy somewhere, and deleting would act on a file this
    /// engine cannot prove is its own. The job is complete and needs the
    /// operator, which is what this state says.
    Moved {
        /// The path that was asked for, which was checked and does not lead to
        /// the file. Not a location to show as valid.
        requested: PathBuf,
        /// The file's name inside the adopted folder.
        name: std::ffi::OsString,
    },
    /// Published into the adopted folder, and the check on the requested path
    /// could not be completed -- the path could not be opened for a reason
    /// other than absence, or the platform could not compare the two handles.
    ///
    /// This is ignorance, not a finding. The file may well be exactly where it
    /// was asked for. **No path is offered as valid, and nothing is
    /// republished or removed**, for the same reasons as `Moved` and one more:
    /// acting on a guess here would act on a file whose relationship to this
    /// job was never established.
    LocationUnverified {
        /// The path that was asked for, whose status is unknown.
        requested: PathBuf,
        /// The file's name inside the adopted folder.
        name: std::ffi::OsString,
        /// Why the check could not be completed, for the operator and the log.
        because: StorageError,
    },
}

impl std::fmt::Display for Published {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::At(path) => write!(f, "{}", path.display()),
            // Never just the requested path: that is the sentence that sends an
            // operator to look somewhere the file is not, or somewhere nobody
            // checked.
            Self::Moved { requested, name } => write!(
                f,
                "as {} in the folder you chose -- {} no longer reaches it,                  because the folder was renamed during the transfer",
                name.to_string_lossy(),
                requested.display()
            ),
            Self::LocationUnverified {
                requested,
                name,
                because,
            } => write!(
                f,
                "as {} in the folder you chose -- whether {} still reaches it                  could not be checked ({because})",
                name.to_string_lossy(),
                requested.display()
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
    /// Creates `name` in `directory` for the file `file` holds.
    ///
    /// **An `Err` means no name was created.** Publication writes that to disk
    /// and acts on it: a refused link is recorded as "the attempt is over and
    /// nothing was made", and the part is made writable again on that basis.
    /// An implementation that can fail after creating the name -- a retry
    /// wrapper that resends a request, a filesystem that reports an existing
    /// name for one it just made -- would leave the engine unsealing a file the
    /// user already has.
    ///
    /// The single `NtSetInformationFile` the Windows implementation makes
    /// satisfies this because its failure is atomic. A second implementation
    /// must say how it does. An independent security review asked for this to
    /// be written down, having found the code depending on it and the trait
    /// silent about it.
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

    /// Opens `path` for that comparison: **never blocking**, and only when a
    /// regular file is there.
    ///
    /// `Ok(None)` means the path does not reach a regular file -- nothing is
    /// there, or what is there is a directory, a FIFO, a socket or a device.
    /// Publication reads every one of those as "the path does not reach what was
    /// published", which is true of all of them. `Err` means the question went
    /// unanswered, which is a third outcome and not a file that moved.
    ///
    /// **It is a port for a reason that cost something.** Publication asked this
    /// with `std::fs::File::open`, and on Unix a blocking `O_RDONLY` open of a
    /// FIFO waits for a writer that may never come. The link has already
    /// happened at that point and the part is sealed, so whoever could write the
    /// destination folder could leave a FIFO at the requested name and the call
    /// that should report where the file landed would never return, with nothing
    /// able to cancel it. Avoiding that needs `O_NONBLOCK`, which needs the
    /// platform, and this adapter may not depend on it -- the same reason
    /// `same_object` is here.
    ///
    /// An implementation must read the type from the **open handle**, not from
    /// the path, or a swap between the two answers the wrong question. And it
    /// must not report a regular file it could not open as absent: that is an
    /// `Err`, because "I could not look" and "it is not there" lead to different
    /// claims about the user's file.
    fn open_for_identity(&self, path: &Path) -> Result<Option<std::fs::File>, StorageError>;
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
    /// The last publication state this handle adopted.
    ///
    /// **Not a read of the disk.** A state is adopted only after it has been
    /// made durable, so this is at worst behind what is on disk and never ahead
    /// of it -- but after a failed sync the byte may have reached the disk
    /// anyway while the handle went on without it. A caller that needs to know
    /// what a later run will find must read the part again, not ask this.
    ///
    /// What it is for: deciding what to do with a job. `Attempted` opens
    /// normally and then refuses writing and publishing with `InvalidState`,
    /// which is indistinguishable from several other reasons, so a caller could
    /// only infer the state from which operations failed. Saying it outright is
    /// what lets a recovery tell "nothing was ever linked" from "nobody can
    /// say".
    fn publication(&self) -> Publication;
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
