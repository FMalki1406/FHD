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
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
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
    fn link(&self, file: &fs::File, folder: &fs::File, name: &OsStr) -> Result<(), StorageError> {
        fs::rename(&self.source, &self.aside).expect("the source name is taken");
        fs::write(&self.source, &self.theirs).expect("another file takes that name");
        self.reached.store(true, Ordering::SeqCst);
        let _ = (file, folder, name);
        #[cfg(windows)]
        {
            fhd_platform::link_into_directory(file, folder, name).map_err(|error| {
                match error.kind() {
                    std::io::ErrorKind::AlreadyExists => StorageError::Conflict,
                    other => StorageError::Io(other),
                }
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
        fn link(
            &self,
            file: &fs::File,
            folder: &fs::File,
            name: &OsStr,
        ) -> Result<(), StorageError> {
            fhd_platform::link_into_directory(file, folder, name).map_err(|error| {
                match error.kind() {
                    std::io::ErrorKind::AlreadyExists => StorageError::Conflict,
                    other => StorageError::Io(other),
                }
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
        fn link(
            &self,
            file: &fs::File,
            folder: &fs::File,
            name: &OsStr,
        ) -> Result<(), StorageError> {
            // Through the name, as a same-account process would.
            if let Ok(mut open) = fs::OpenOptions::new().write(true).open(&self.source) {
                use std::io::Write;
                if open.write_all(b"ZZZZZZ").is_ok() {
                    self.wrote.store(true, Ordering::SeqCst);
                }
            }
            fhd_platform::link_into_directory(file, folder, name).map_err(|error| {
                match error.kind() {
                    std::io::ErrorKind::AlreadyExists => StorageError::Conflict,
                    other => StorageError::Io(other),
                }
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
    // What must hold either way: only bytes that were in the part can reach the
    // file, and publication must not name a file it did not write.
    if !wrote.load(Ordering::SeqCst) {
        // The write was prevented. That is a better outcome than this measures,
        // and the record above should be rewritten rather than this loosened.
        assert!(
            outcome.is_ok(),
            "the write was prevented and publication still failed: {outcome:?}"
        );
        assert_eq!(fs::read(&destination).unwrap(), b"AAAAAA");
        return;
    }

    // Recorded, not required. As the engine stands a write landing in this
    // window reaches the published file; the test states that limit rather than
    // insisting on it, so tightening the protection later makes this pass
    // instead of fail.
    if outcome.is_ok() {
        let published = fs::read(&destination).unwrap();
        assert!(
            published == b"ZZZZZZ" || published == b"AAAAAA",
            "publication delivered bytes that were never in the part: {published:?}"
        );
    } else {
        assert!(
            !destination.exists(),
            "a refused publication left the destination name behind"
        );
    }
}

/// **ن٣-ج.** The destination folder is moved out from under the path at the
/// boundary, and something else takes its name.
///
/// The contract is not "our bytes, wherever they land". It is: the file appears
/// in the folder the operator approved, or publication fails and writes nothing
/// into a folder somebody else put there. An earlier version of this test
/// accepted any location, which would have passed while the engine wrote into a
/// directory an attacker had just created -- so it was weaker than the contract
/// it claimed to check.
///
/// **Who performs the redirect, and with what rights.** Here, the engine's own
/// account: the strongest case for the attacker and the weakest claim for us,
/// because it shows what happens when the swap succeeds rather than that an
/// untrusted account can cause it. Whether one can is a question about the
/// *destination folder's* permissions, which are the operator's: on a data
/// volume here they are `Authenticated Users: Modify`, which carries `DELETE`,
/// so on such a folder the answer is yes. That is the declared ceiling -- a
/// download is protected up to the permissions of the folder chosen for it.
#[cfg(windows)]
#[test]
fn a_destination_folder_swapped_at_the_boundary_publishes_nowhere_else() {
    struct SwapFolderThenLink {
        approved: PathBuf,
        aside: PathBuf,
        swapped: Arc<AtomicBool>,
    }
    impl HandleLinker for SwapFolderThenLink {
        fn link(
            &self,
            file: &fs::File,
            folder: &fs::File,
            name: &OsStr,
        ) -> Result<(), StorageError> {
            if fs::rename(&self.approved, &self.aside).is_ok() {
                fs::create_dir(&self.approved).expect("an impostor takes the name");
                self.swapped.store(true, Ordering::SeqCst);
            }
            fhd_platform::link_into_directory(file, folder, name).map_err(|error| {
                match error.kind() {
                    std::io::ErrorKind::AlreadyExists => StorageError::Conflict,
                    other => StorageError::Io(other),
                }
            })
        }
    }

    let directory = Directory::new("publish-swapped-folder");
    let parts = directory.0.join("parts");
    fs::create_dir_all(&parts).unwrap();
    let approved = directory.0.join("downloads");
    fs::create_dir_all(&approved).unwrap();
    let aside = directory.0.join("downloads-moved-away");
    let destination = approved.join("published.bin");
    let swapped = Arc::new(AtomicBool::new(false));

    let store = FileStorage::default().with_linker(Arc::new(SwapFolderThenLink {
        approved: approved.clone(),
        aside: aside.clone(),
        swapped: swapped.clone(),
    }));
    let mut part = store.create(&parts, spec(6)).unwrap();
    part.write_at(0, b"AAAAAA").unwrap();
    part.sync().unwrap();
    let record = attested(part.as_mut());
    part.verify(None, &record).unwrap();

    let outcome = part.publish(&destination);
    assert!(
        swapped.load(Ordering::SeqCst),
        "the folder was never swapped, so this run measured nothing"
    );

    // Nothing of ours may be sitting in the directory that took the approved
    // folder's name. This is the assertion the earlier version was missing.
    let planted: Vec<_> = fs::read_dir(&approved)
        .expect("the impostor directory is readable")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        planted.is_empty(),
        "publication wrote into a directory that replaced the approved one: {planted:?}"
    );

    match outcome {
        Ok(reported) => {
            // Success is only correct inside the folder the operator approved,
            // which is the directory now answering to `aside`: renaming a folder
            // moves its name, not its identity, and the handle publication holds
            // was taken on that identity.
            let landed = aside.join(destination.file_name().unwrap());
            assert!(
                landed.is_file(),
                "publication reported success but the approved folder has no {:?}",
                destination.file_name().unwrap()
            );
            assert_eq!(
                fs::read(&landed).unwrap(),
                b"AAAAAA",
                "something other than the proved bytes was published"
            );
            // A known limit, recorded rather than hidden: the path handed back
            // is the one the caller asked for, and after the folder is renamed
            // that spelling no longer reaches the file. The file is where the
            // contract requires; only its address is stale.
            assert_eq!(reported, destination);
            assert!(
                !reported.exists(),
                "the spelling stopped being stale -- publication now reports a \
                 reachable path, so this record should be rewritten rather than \
                 the assertion loosened"
            );
        }
        Err(_) => assert!(
            !destination.exists(),
            "a refused publication left a file at the destination name"
        ),
    }
}

/// **ن٤ integrated.** A failed publication leaves a job that can come back,
/// on the same build that publishes from the handle.
///
/// The recovery fix and the handle link were developed on separate branches,
/// and a comment recording the dependency is not evidence that they work
/// together. This composes them: no mechanism, so publication refuses, and the
/// part must still be writable after being reopened from disk -- which is where
/// the seal lives.
#[test]
fn a_refused_publication_leaves_the_part_writable_on_the_next_run() {
    struct NoMechanism;
    impl HandleLinker for NoMechanism {
        fn link(&self, _: &fs::File, _: &fs::File, _: &OsStr) -> Result<(), StorageError> {
            Err(StorageError::Unsupported)
        }
    }

    let directory = Directory::new("publish-recover");
    let parts = directory.0.join("parts");
    fs::create_dir_all(&parts).unwrap();
    let destination = directory.0.join("published.bin");
    let bystander = directory.0.join("theirs.bin");
    fs::write(&bystander, b"not ours").unwrap();

    let store = FileStorage::default().with_linker(Arc::new(NoMechanism));
    let mut part = store.create(&parts, spec(6)).unwrap();
    part.write_at(0, b"AAAAAA").unwrap();
    part.sync().unwrap();
    let record = attested(part.as_mut());
    part.verify(None, &record).unwrap();

    assert_eq!(
        part.publish(&destination),
        Err(StorageError::Unsupported),
        "publication found another way to name the file"
    );
    assert!(
        !destination.exists(),
        "a refused publication named the file"
    );
    assert_eq!(
        fs::read(&bystander).unwrap(),
        b"not ours",
        "a refused publication touched a file that was not ours"
    );
    drop(part);

    // Read the seal byte straight off the disk, so a failure here says whether
    // the seal was lifted or whether reopening is refusing for another reason.
    let meta = fs::read(parts.join("1-1.meta")).unwrap();
    assert_eq!(
        meta.get(33),
        Some(&0u8),
        "the seal is still set on disk after a refused publication"
    );

    // Reopened from disk, which is where the seal lives. Nothing in memory
    // carries over, so this is the assertion the unsealed version fails.
    let mut reopened = FileStorage::default()
        .with_linker(Arc::new(NoMechanism))
        .open(&parts, spec(6))
        .unwrap();
    reopened
        .write_at(0, b"BBBBBB")
        .expect("a part whose publication was refused can be written again");
}
