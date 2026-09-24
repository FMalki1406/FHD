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

/// **ن٣-أ, honestly.** The window between the last read and the link is real,
/// and this measures it rather than asserting it away.
///
/// Publication re-reads the verified handle immediately before naming it, which
/// catches bytes changed earlier. It cannot catch bytes changed *after* that
/// read: the linker call is the very next thing, and a writer acting there sees
/// its bytes published.
///
/// **Who can act there.** Only somebody holding write access to that inode. The
/// part lives in a directory the engine created with its own access list, and a
/// second local account is denied open, write, delete, rename and creating any
/// name in it -- measured with a restricted token. What remains is a process
/// running as the user, which this design has never claimed to defend against
/// and says so in the customer sentence.
///
/// So this is not a passing test dressed as a guarantee. It records the shape
/// of the window and the identity that fits through it, so that a later change
/// which widens either is visible.
#[cfg(windows)]
#[test]
fn the_window_after_the_last_read_belongs_to_whoever_can_write_the_inode() {
    struct WriteThenLink {
        source: PathBuf,
        wrote: Arc<AtomicBool>,
    }
    impl HandleLinker for WriteThenLink {
        fn link(&self, file: &fs::File, destination: &Path) -> Result<(), StorageError> {
            // Through the name, as a same-account process would.
            if let Ok(mut open) = fs::OpenOptions::new().write(true).open(&self.source) {
                use std::io::Write;
                if open.write_all(b"ZZZZZZ").is_ok() {
                    self.wrote.store(true, Ordering::SeqCst);
                }
            }
            fhd_platform::link_from_handle(file, destination).map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => StorageError::Conflict,
                other => StorageError::Io(other),
            })
        }
    }

    let directory = Directory::new("publish-window");
    let parts = directory.0.join("parts");
    fs::create_dir_all(&parts).unwrap();
    let destination = directory.0.join("published.bin");
    let wrote = Arc::new(AtomicBool::new(false));

    let store = FileStorage::default().with_linker(Arc::new(WriteThenLink {
        source: parts.join("1-1.part"),
        wrote: wrote.clone(),
    }));
    let mut part = store.create(&parts, spec(6)).unwrap();
    part.write_at(0, b"AAAAAA").unwrap();
    part.sync().unwrap();
    let record = attested(part.as_mut());
    part.verify(None, &record).unwrap();

    let outcome = part.publish(&destination);
    assert!(
        wrote.load(Ordering::SeqCst),
        "the write never landed, so this run measured nothing"
    );
    assert!(
        outcome.is_ok(),
        "publication failed for some other reason: {outcome:?}"
    );

    // The window is real: what was published carries the later bytes. If this
    // ever reads AAAAAA, something started preventing the write and the comment
    // above needs rewriting rather than this assertion loosening.
    assert_eq!(
        fs::read(&destination).unwrap(),
        b"ZZZZZZ",
        "the write in the window did not reach the published file, which means \
         the mechanism now prevents it -- a better outcome that this test is not \
         written for"
    );
}

/// **ن٣-ج.** The destination folder is moved at the boundary.
///
/// "No name to resolve" was true of the source and not of the destination: that
/// is still a path, and it is resolved when the link is made. This moves the
/// folder out from under it at exactly that moment.
///
/// What must not happen is a file appearing somewhere nobody asked for, or the
/// operation reporting success while nothing was published.
#[cfg(windows)]
#[test]
fn a_destination_folder_moved_at_the_boundary_does_not_publish_elsewhere() {
    struct MoveThenLink {
        folder: PathBuf,
        aside: PathBuf,
        moved: Arc<AtomicBool>,
    }
    impl HandleLinker for MoveThenLink {
        fn link(&self, file: &fs::File, destination: &Path) -> Result<(), StorageError> {
            if fs::rename(&self.folder, &self.aside).is_ok() {
                // Somebody else's folder now answers to the old name.
                let _ = fs::create_dir(&self.folder);
                self.moved.store(true, Ordering::SeqCst);
            }
            fhd_platform::link_from_handle(file, destination).map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => StorageError::Conflict,
                other => StorageError::Io(other),
            })
        }
    }

    let directory = Directory::new("publish-moved-folder");
    let parts = directory.0.join("parts");
    fs::create_dir_all(&parts).unwrap();
    let folder = directory.0.join("downloads");
    fs::create_dir_all(&folder).unwrap();
    let destination = folder.join("published.bin");
    let moved = Arc::new(AtomicBool::new(false));

    let store = FileStorage::default().with_linker(Arc::new(MoveThenLink {
        folder: folder.clone(),
        aside: directory.0.join("downloads-aside"),
        moved: moved.clone(),
    }));
    let mut part = store.create(&parts, spec(6)).unwrap();
    part.write_at(0, b"AAAAAA").unwrap();
    part.sync().unwrap();
    let record = attested(part.as_mut());
    part.verify(None, &record).unwrap();

    let outcome = part.publish(&destination);
    assert!(
        moved.load(Ordering::SeqCst),
        "the folder was never moved, so this run measured nothing"
    );

    // Whatever the outcome, the bytes must be ours wherever they landed, and
    // the operator must not be told a file exists that does not.
    match outcome {
        Ok(reported) => {
            assert!(
                reported.exists(),
                "publication reported {reported:?}, which is not there"
            );
            assert_eq!(
                fs::read(&reported).unwrap(),
                b"AAAAAA",
                "something other than the proved bytes was published"
            );
        }
        Err(_) => assert!(
            !destination.exists(),
            "a refused publication left a file at the destination"
        ),
    }
}
