//! The publication contract, on the wired path.
//!
//! The storage adapter cannot reach the platform mechanism: it may not depend
//! on `fhd-platform` in any dependency kind, and the architecture gate enforces
//! that. So the contract can only be measured here, where the composition root
//! puts the two together.
//!
//! **No test hook is involved.** An earlier attempt added one to the storage
//! adapter so a test could stand between proving the bytes and naming them.
//! That was unnecessary, and a production build would then have had a place to
//! stop at. The linker call *is* that boundary: it happens after verification
//! and before the destination exists, and it receives the handle that was
//! proved. A linker that takes the source name away and then delegates to the
//! real mechanism reproduces the attack exactly, with no timing in the answer.
mod harness;

use fhd_app::storage::{HandleLinker, PartSpec, SegmentFile, SegmentStore, StorageError};
use fhd_domain::{ByteRange, Generation, JobId};
use fhd_storage::FileStorage;
use harness::Directory;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Takes the source name away, then links through the real mechanism.
///
/// Called after the bytes are proved, before the destination exists, holding
/// the handle that was proved. If publication is bound to that handle the
/// published bytes are the proved ones; if it is bound to a name they are
/// whatever now answers to it.
struct SubstituteThenLink {
    source: PathBuf,
    aside: PathBuf,
    theirs: Vec<u8>,
    reached: Arc<AtomicBool>,
}

impl HandleLinker for SubstituteThenLink {
    fn link(&self, file: &fs::File, destination: &Path) -> Result<(), StorageError> {
        fs::rename(&self.source, &self.aside).expect("the source name is taken");
        fs::write(&self.source, &self.theirs).expect("another file takes that name");
        self.reached.store(true, Ordering::SeqCst);
        let _ = file;
        let _ = destination;
        #[cfg(windows)]
        {
            fhd_platform::link_from_handle(file, destination).map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => StorageError::Conflict,
                other => StorageError::Io(other),
            })
        }
        #[cfg(not(windows))]
        {
            Err(StorageError::Unsupported)
        }
    }
}

fn spec(size: u64) -> PartSpec {
    PartSpec::new(JobId::new(1).unwrap(), Generation::new(1).unwrap(), size).unwrap()
}

fn attested(part: &mut dyn SegmentFile) -> Vec<(ByteRange, [u8; 32])> {
    let size = part.spec().size();
    if size == 0 {
        return Vec::new();
    }
    let whole = ByteRange::new(0, size).unwrap();
    vec![(whole, part.hash_range(whole).unwrap())]
}

/// **The gate.** The source name is taken over at the boundary, and what gets
/// published must still be the bytes that were proved.
///
/// Windows only, because that is the only platform with a mechanism. Elsewhere
/// publication refuses, which is a different property with its own test in the
/// storage adapter, and the support is tracked per platform rather than
/// inferred from this one passing.
#[cfg(windows)]
#[test]
fn publication_carries_the_proved_bytes_though_the_source_name_is_taken() {
    let directory = Directory::new("publish-substitute");
    let parts = directory.0.join("parts");
    fs::create_dir_all(&parts).unwrap();
    let destination = directory.0.join("published.bin");

    let reached = Arc::new(AtomicBool::new(false));
    let store = FileStorage::default().with_linker(Arc::new(SubstituteThenLink {
        source: parts.join("1-1.part"),
        aside: parts.join("aside.bin"),
        theirs: b"ZZZZZZ".to_vec(),
        reached: reached.clone(),
    }));

    let mut part = store.create(&parts, spec(6)).unwrap();
    part.write_at(0, b"AAAAAA").unwrap();
    part.sync().unwrap();
    let record = attested(part.as_mut());
    part.verify(None, &record).unwrap();

    let outcome = part.publish(&destination);
    assert!(
        reached.load(Ordering::SeqCst),
        "the mechanism was never reached, so this run tested nothing"
    );
    // The substitution really happened, or the assertion below would hold for
    // the wrong reason.
    assert_eq!(
        fs::read(parts.join("1-1.part")).unwrap(),
        b"ZZZZZZ",
        "the source name was not taken over"
    );

    match outcome {
        Ok(_) => assert_eq!(
            fs::read(&destination).unwrap(),
            b"AAAAAA",
            "publication delivered bytes the handle never proved"
        ),
        Err(error) => assert!(
            !destination.exists(),
            "a refused publication ({error:?}) left the destination name behind"
        ),
    }
}

/// An occupied destination is refused and its contents are untouched, through
/// the same mechanism.
#[cfg(windows)]
#[test]
fn publication_never_replaces_a_file_that_is_already_there() {
    let directory = Directory::new("publish-occupied");
    let parts = directory.0.join("parts");
    fs::create_dir_all(&parts).unwrap();
    let destination = directory.0.join("published.bin");
    fs::write(&destination, b"somebody else").unwrap();

    struct RealLinker;
    impl HandleLinker for RealLinker {
        fn link(&self, file: &fs::File, destination: &Path) -> Result<(), StorageError> {
            fhd_platform::link_from_handle(file, destination).map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => StorageError::Conflict,
                other => StorageError::Io(other),
            })
        }
    }

    let store = FileStorage::default().with_linker(Arc::new(RealLinker));
    let mut part = store.create(&parts, spec(6)).unwrap();
    part.write_at(0, b"AAAAAA").unwrap();
    part.sync().unwrap();
    let record = attested(part.as_mut());
    part.verify(None, &record).unwrap();

    assert!(
        part.publish(&destination).is_err(),
        "an occupied destination was published over"
    );
    assert_eq!(
        fs::read(&destination).unwrap(),
        b"somebody else",
        "a refused publication changed the file that was there"
    );
}
