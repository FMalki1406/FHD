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
    /// Requires a synchronized, verified file and a durable PublishIntent in the
    /// repository. Atomic no-replace is mandatory; unsupported filesystems fail.
    fn publish(&mut self, destination: &Path) -> Result<PathBuf, StorageError>;
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
