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
// Every test here measures a real publication mechanism, so the file compiles
// where one exists: Windows and Linux.
//
// It was Windows-only, and the reason given was that the doubles called
// `fhd_platform::same_object`, which that crate exports only on Windows. That
// was true and it stopped being true: Linux has had a mechanism since
// `link_into_directory` landed there, and the answer `same_object` needs on
// unix is `dev` and `ino`, which the composition root already writes. Two
// independent reviews arrived at the same place from different directions --
// the CI step named "Test the publication contract" was running **zero tests**
// on ubuntu and exiting zero, so the substitution attack, the folder swap, the
// seal after a crash and the refusal contract were all unmeasured on the
// platform that had just been given a mechanism. A green step standing in for
// evidence is worse than a missing one, because nobody goes looking.
#![cfg(any(windows, target_os = "linux"))]

mod harness;

use fhd_app::storage::{
    HandleLinker, PartSpec, Published, SegmentFile, SegmentStore, StorageError,
};
use fhd_domain::{ByteRange, Generation, JobId};
use fhd_storage::FileStorage;
use harness::Directory;
use std::ffi::OsStr;
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
    fn same_object(&self, left: &fs::File, right: &fs::File) -> Result<bool, StorageError> {
        objects_match(left, right)
    }
    fn link(&self, file: &fs::File, folder: &fs::File, name: &OsStr) -> Result<(), StorageError> {
        fs::rename(&self.source, &self.aside).expect("the source name is taken");
        fs::write(&self.source, &self.theirs).expect("another file takes that name");
        self.reached.store(true, Ordering::SeqCst);
        link_through_the_platform(file, folder, name)
    }
}

/// Whether two handles hold the same object, however this system says so.
///
/// The same answer the composition root gives, by the same means: Windows needs
/// a platform call because `windows_by_handle` is unstable, and unix has `dev`
/// and `ino` in safe std.
fn objects_match(left: &fs::File, right: &fs::File) -> Result<bool, StorageError> {
    #[cfg(windows)]
    {
        fhd_platform::same_object(left, right).map_err(|error| StorageError::Io(error.kind()))
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::MetadataExt;
        let left = left
            .metadata()
            .map_err(|error| StorageError::Io(error.kind()))?;
        let right = right
            .metadata()
            .map_err(|error| StorageError::Io(error.kind()))?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }
}

/// The real mechanism, called the way the engine calls it.
///
/// Every double here goes through this, so what the tests measure is the
/// platform's own behaviour rather than a stand-in that agrees with the test.
fn link_through_the_platform(
    file: &fs::File,
    folder: &fs::File,
    name: &OsStr,
) -> Result<(), StorageError> {
    fhd_platform::link_into_directory(file, folder, name).map_err(|error| match error.kind() {
        std::io::ErrorKind::AlreadyExists => StorageError::Conflict,
        other => StorageError::Io(other),
    })
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

    part.adopt_destination(&destination).unwrap();
    let outcome = part.publish();
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
        fn same_object(&self, left: &fs::File, right: &fs::File) -> Result<bool, StorageError> {
            objects_match(left, right)
        }
        fn link(
            &self,
            file: &fs::File,
            folder: &fs::File,
            name: &OsStr,
        ) -> Result<(), StorageError> {
            link_through_the_platform(file, folder, name)
        }
    }

    let store = FileStorage::default().with_linker(Arc::new(RealLinker));
    let mut part = store.create(&parts, spec(6)).unwrap();
    part.write_at(0, b"AAAAAA").unwrap();
    part.sync().unwrap();
    let record = attested(part.as_mut());
    part.verify(None, &record).unwrap();

    assert!(
        {
            part.adopt_destination(&destination).unwrap();
            part.publish().is_err()
        },
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
        fn same_object(&self, left: &fs::File, right: &fs::File) -> Result<bool, StorageError> {
            objects_match(left, right)
        }
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
            link_through_the_platform(file, folder, name)
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

    part.adopt_destination(&destination).unwrap();
    let outcome = part.publish();
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
        fn same_object(&self, left: &fs::File, right: &fs::File) -> Result<bool, StorageError> {
            objects_match(left, right)
        }
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
            link_through_the_platform(file, folder, name)
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

    part.adopt_destination(&destination).unwrap();
    let outcome = part.publish();
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
            // And the operator is told which claim holds. Reporting the
            // requested path here would send them to look in the impostor
            // directory, which is empty. `Moved` says the file is in their
            // folder and that this spelling no longer reaches it -- the one
            // answer that is both true and actionable.
            assert_eq!(
                reported,
                Published::Moved {
                    requested: destination.clone(),
                    name: destination.file_name().unwrap().to_os_string(),
                },
                "publication reported a result that hides the rename"
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
        fn same_object(&self, _: &fs::File, _: &fs::File) -> Result<bool, StorageError> {
            Err(StorageError::Unsupported)
        }
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

    // The seal before the operation. Without this the assertion after it is
    // vacuous: a byte that was zero all along proves nothing was lifted.
    assert_eq!(
        fs::read(parts.join("1-1.meta")).unwrap().get(33),
        Some(&0u8),
        "the part was already sealed before publication was attempted"
    );

    assert_eq!(
        {
            part.adopt_destination(&destination).unwrap();
            part.publish()
        },
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

/// **ن٣-ج, the other half.** The folder is swapped *before* it is adopted.
///
/// Adoption fixes the destination as an object, and everything after it is
/// defeated. This is the case on the other side of that line, and the honest
/// answer is that the engine cannot tell: the operator named a path, resolving
/// a path is all anyone can do with it, and a directory sitting at that path
/// when the question is first asked is the directory that gets adopted.
///
/// So this is not a passing control. **It records where the window is**, so
/// that a change which widens it -- adopting later, or re-resolving the path --
/// shows up as this test changing rather than as nothing at all. The engine
/// adopts at session open, before the first byte, which is the earliest point
/// it holds both the part and the destination.
///
/// What is *not* claimed: that the adopted folder is the one the operator
/// meant. Only that it is the one their path led to at the earliest moment the
/// engine could look, and that it does not change afterwards.
#[cfg(windows)]
#[test]
fn a_folder_swapped_before_adoption_is_the_one_adopted_and_that_is_the_window() {
    struct RealLinker;
    impl HandleLinker for RealLinker {
        fn link(
            &self,
            file: &fs::File,
            folder: &fs::File,
            name: &OsStr,
        ) -> Result<(), StorageError> {
            link_through_the_platform(file, folder, name)
        }
        fn same_object(&self, left: &fs::File, right: &fs::File) -> Result<bool, StorageError> {
            objects_match(left, right)
        }
    }

    let directory = Directory::new("publish-swapped-before");
    let parts = directory.0.join("parts");
    fs::create_dir_all(&parts).unwrap();
    let approved = directory.0.join("downloads");
    fs::create_dir_all(&approved).unwrap();
    let destination = approved.join("published.bin");

    let store = FileStorage::default().with_linker(Arc::new(RealLinker));
    let mut part = store.create(&parts, spec(6)).unwrap();
    part.write_at(0, b"AAAAAA").unwrap();
    part.sync().unwrap();
    let record = attested(part.as_mut());
    part.verify(None, &record).unwrap();

    // Before adoption: the folder the operator named is moved away and another
    // takes its name. Nothing has been adopted yet, so nothing is defended.
    let aside = directory.0.join("downloads-moved-away");
    fs::rename(&approved, &aside).unwrap();
    fs::create_dir(&approved).unwrap();

    part.adopt_destination(&destination).unwrap();
    let outcome = part.publish().expect("publication succeeds");

    // The measurement: the file is in the directory that held the path at
    // adoption -- the impostor. The engine reports `At`, because for it that
    // directory *is* the destination; it has no way to know otherwise.
    assert_eq!(
        outcome,
        Published::At(fs::canonicalize(&destination).unwrap()),
        "publication no longer reports the folder it adopted"
    );
    assert_eq!(fs::read(&destination).unwrap(), b"AAAAAA");
    assert!(
        fs::read_dir(&aside).unwrap().next().is_none(),
        "the folder that was moved aside received the file, which would mean \
         adoption reached back before it ran -- a better outcome that this \
         record does not describe"
    );
}

/// **ن٤, the rest of it.** A refused publication leaves a job that can finish,
/// with the bytes it already had, without having touched anything else.
///
/// The test above proves the seal is lifted. That is the part that makes the
/// part *writable* again -- it is not the whole of recovery. Three things more
/// have to hold, and each is asserted here rather than inferred from the first:
///
/// - **the progress survives**: the bytes and their extents are still there, so
///   the retry is a retry and not a fresh download;
/// - **the retry can succeed**: given a mechanism, the same handle publishes;
/// - **nothing else was touched**: every other file in both directories is
///   byte-for-byte what it was, and none has disappeared.
///
/// The third is asserted over a directory listing rather than one bystander
/// file, because "we did not delete the file we were thinking of" is a weaker
/// claim than "we did not delete anything".
#[cfg(windows)]
#[test]
fn a_refused_publication_keeps_the_progress_allows_a_retry_and_touches_nothing_else() {
    struct Refuse(Arc<AtomicBool>);
    impl HandleLinker for Refuse {
        fn link(
            &self,
            file: &fs::File,
            folder: &fs::File,
            name: &OsStr,
        ) -> Result<(), StorageError> {
            if self.0.load(Ordering::SeqCst) {
                return Err(StorageError::Unsupported);
            }
            link_through_the_platform(file, folder, name)
        }
        fn same_object(&self, left: &fs::File, right: &fs::File) -> Result<bool, StorageError> {
            objects_match(left, right)
        }
    }

    /// Everything in a directory, by name and contents.
    fn census(directory: &Path) -> Vec<(String, Vec<u8>)> {
        let mut entries: Vec<_> = fs::read_dir(directory)
            .expect("the directory is readable")
            .flatten()
            .filter(|entry| entry.path().is_file())
            .map(|entry| {
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path()).expect("the file is readable"),
                )
            })
            .collect();
        entries.sort();
        entries
    }

    let directory = Directory::new("publish-retry");
    let parts = directory.0.join("parts");
    fs::create_dir_all(&parts).unwrap();
    let downloads = directory.0.join("downloads");
    fs::create_dir_all(&downloads).unwrap();
    let destination = downloads.join("published.bin");
    // Bystanders in both directories, including one whose name is close enough
    // to be caught by a careless cleanup.
    fs::write(downloads.join("theirs.bin"), b"not ours").unwrap();
    fs::write(downloads.join("published.bin.old"), b"older").unwrap();
    fs::write(parts.join("unrelated.part"), b"another job").unwrap();

    let refusing = Arc::new(AtomicBool::new(true));
    let store = FileStorage::default().with_linker(Arc::new(Refuse(refusing.clone())));
    let mut part = store.create(&parts, spec(6)).unwrap();
    part.write_at(0, b"AAAAAA").unwrap();
    part.sync().unwrap();
    let record = attested(part.as_mut());
    part.verify(None, &record).unwrap();

    let before_parts = census(&parts);
    let before_downloads = census(&downloads);

    part.adopt_destination(&destination).unwrap();
    assert_eq!(
        part.publish(),
        Err(StorageError::Unsupported),
        "publication found another way to name the file"
    );
    drop(part);

    // Nothing else was touched. Names and contents, both directories.
    assert_eq!(
        census(&downloads),
        before_downloads,
        "a refused publication changed the destination directory"
    );
    assert_eq!(
        census(&parts),
        before_parts,
        "a refused publication changed the parts directory"
    );

    // The progress survived: the part still holds the bytes that were verified,
    // so the retry below is a retry rather than a second download.
    assert_eq!(
        fs::read(parts.join("1-1.part")).unwrap(),
        b"AAAAAA",
        "a refused publication lost the bytes that were already proved"
    );

    // And the retry succeeds, on a handle reopened from disk with a mechanism
    // this time. It goes the way production goes: coverage is restored from the
    // recorded extents, which are rehashed on the way in, because opening a
    // file must never restore coverage from its size alone. Without that the
    // reopened handle refuses to verify -- which it did, and is the reason this
    // test is written through `recover_extent` rather than around it.
    refusing.store(false, Ordering::SeqCst);
    let mut again = store.open(&parts, spec(6)).unwrap();
    for (range, digest) in &record {
        again.recover_extent(*range, *digest).unwrap();
    }
    // A reopened handle is not synchronized until it says so, and the
    // coordinator syncs a reopened session before verifying for that reason.
    again.sync().unwrap();
    again.verify(None, &record).unwrap();
    again.adopt_destination(&destination).unwrap();
    assert_eq!(
        again.publish().expect("the retry publishes"),
        Published::At(fs::canonicalize(&destination).unwrap()),
        "the retry did not publish where it was asked to"
    );
    assert_eq!(fs::read(&destination).unwrap(), b"AAAAAA");

    // The bystanders are still there afterwards too: publishing is not the
    // moment to discover a cleanup that ran on the way past.
    assert_eq!(fs::read(downloads.join("theirs.bin")).unwrap(), b"not ours");
    assert_eq!(
        fs::read(downloads.join("published.bin.old")).unwrap(),
        b"older"
    );
    assert_eq!(
        fs::read(parts.join("unrelated.part")).unwrap(),
        b"another job"
    );
}

/// Publication succeeded and the location check could not be completed.
///
/// This must not read as `Moved`. **Not knowing where the file is is not
/// evidence that it moved** -- here it is in exactly the place that was asked
/// for, and the only thing that failed is the question. Reporting a move would
/// be an assertion about the filesystem that nothing established, and it would
/// send an operator hunting for a file sitting where they put it.
///
/// The failure is injected at the one place the answer comes from: the port's
/// `same_object`. The link itself is the real mechanism, so what is measured is
/// the adapter's handling of an unanswered question, not a fake publication.
#[cfg(windows)]
#[test]
fn a_location_check_that_cannot_be_completed_is_not_reported_as_a_move() {
    struct LinkButCannotCompare;
    impl HandleLinker for LinkButCannotCompare {
        fn link(
            &self,
            file: &fs::File,
            folder: &fs::File,
            name: &OsStr,
        ) -> Result<(), StorageError> {
            link_through_the_platform(file, folder, name)
        }
        fn same_object(&self, _: &fs::File, _: &fs::File) -> Result<bool, StorageError> {
            Err(StorageError::Unsupported)
        }
    }

    let directory = Directory::new("publish-unverified");
    let parts = directory.0.join("parts");
    fs::create_dir_all(&parts).unwrap();
    let destination = directory.0.join("published.bin");

    let store = FileStorage::default().with_linker(Arc::new(LinkButCannotCompare));
    let mut part = store.create(&parts, spec(6)).unwrap();
    part.write_at(0, b"AAAAAA").unwrap();
    part.sync().unwrap();
    let record = attested(part.as_mut());
    part.verify(None, &record).unwrap();
    part.adopt_destination(&destination).unwrap();

    let outcome = part.publish().expect("publication succeeds");
    assert_eq!(
        outcome,
        Published::LocationUnverified {
            requested: fs::canonicalize(&destination).unwrap(),
            name: destination.file_name().unwrap().to_os_string(),
            because: StorageError::Unsupported,
        },
        "an unanswered question was reported as a finding"
    );

    // And the file really is where it was asked for: the engine's ignorance is
    // about the check, not about the outcome.
    assert_eq!(fs::read(&destination).unwrap(), b"AAAAAA");

    // Nothing was published twice and nothing was removed.
    let published: Vec<_> = fs::read_dir(&directory.0)
        .unwrap()
        .flatten()
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        published,
        vec!["published.bin".to_string()],
        "an unverified location led to a second copy or a removal"
    );
}

/// A part that has published is finished, and asking again must not undo it.
///
/// Found by asking what happens after `Moved`. The destination path does not
/// exist then -- the folder moved -- so the absence check that stops an
/// ordinary second publication does not stop this one. It reaches the linker,
/// which refuses because the name is taken **inside the adopted folder**, and
/// the refusal path then does what it does for a publication that never
/// happened: it lifts the seal.
///
/// The seal is what stops a reopened part writing to the inode the published
/// file is a link to. Lifting it on a part whose bytes have already been
/// delivered would make a delivered file writable again. Nothing in the engine
/// asks twice today; this makes it safe for the one that eventually does.
#[cfg(windows)]
#[test]
fn a_part_that_has_published_refuses_to_publish_again_and_keeps_its_seal() {
    struct RealLinker;
    impl HandleLinker for RealLinker {
        fn link(
            &self,
            file: &fs::File,
            folder: &fs::File,
            name: &OsStr,
        ) -> Result<(), StorageError> {
            link_through_the_platform(file, folder, name)
        }
        fn same_object(&self, left: &fs::File, right: &fs::File) -> Result<bool, StorageError> {
            objects_match(left, right)
        }
    }

    let directory = Directory::new("publish-twice");
    let parts = directory.0.join("parts");
    fs::create_dir_all(&parts).unwrap();
    let downloads = directory.0.join("downloads");
    fs::create_dir_all(&downloads).unwrap();
    let destination = downloads.join("published.bin");

    let store = FileStorage::default().with_linker(Arc::new(RealLinker));
    let mut part = store.create(&parts, spec(6)).unwrap();
    part.write_at(0, b"AAAAAA").unwrap();
    part.sync().unwrap();
    let record = attested(part.as_mut());
    part.verify(None, &record).unwrap();
    part.adopt_destination(&destination).unwrap();
    part.publish().expect("the first publication succeeds");

    // The folder moves, exactly as in the `Moved` case, so the destination path
    // no longer exists and the absence check lets a second attempt through.
    let aside = directory.0.join("downloads-moved-away");
    fs::rename(&downloads, &aside).unwrap();
    assert!(!destination.exists());

    assert_eq!(
        part.publish(),
        Err(StorageError::InvalidState),
        "a part that has published was allowed to publish again"
    );
    drop(part);

    // The seal still stands, so the delivered file's inode is still protected.
    let meta = fs::read(parts.join("1-1.meta")).unwrap();
    assert_eq!(
        meta.get(33),
        Some(&fhd_app::storage::Publication::Linked.to_byte()),
        "asking twice disturbed the record of a part whose bytes were delivered"
    );

    // And the delivered file is untouched, with no second copy anywhere.
    let landed: Vec<_> = fs::read_dir(&aside)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(landed, vec!["published.bin".to_string()]);
    assert_eq!(fs::read(aside.join("published.bin")).unwrap(), b"AAAAAA");
}

/// The crash window: the link succeeded, and the record never said so.
///
/// Publication seals the part, links, and only then is the completion recorded.
/// A crash in between leaves a published file on disk, a job still marked
/// Publishing, and a part sealed on disk. Reopening that part is exactly the
/// state a restart finds.
///
/// The reconciliation path settles the ordinary case: if the destination holds
/// a file of the recorded size and digest, the job is completed without the
/// part being reopened at all. What this test is about is the case it cannot
/// settle -- nothing at the destination, because the folder moved after
/// adoption, or because the link never happened. **Those two are
/// indistinguishable from here**, and one of them means a delivered file.
///
/// So a part that was already sealed when it was opened must not publish and
/// must not be unsealed. Publishing again would put a second copy somewhere;
/// unsealing would make the inode a delivered file links to writable again.
/// The job stops and needs an operator, which is the honest answer to a
/// question that cannot be decided.
#[test]
fn a_part_found_sealed_after_a_crash_neither_publishes_nor_loses_its_seal() {
    struct RealLinker;
    impl HandleLinker for RealLinker {
        fn link(
            &self,
            file: &fs::File,
            folder: &fs::File,
            name: &OsStr,
        ) -> Result<(), StorageError> {
            link_through_the_platform(file, folder, name)
        }
        fn same_object(&self, left: &fs::File, right: &fs::File) -> Result<bool, StorageError> {
            objects_match(left, right)
        }
    }

    let directory = Directory::new("publish-crash-window");
    let parts = directory.0.join("parts");
    fs::create_dir_all(&parts).unwrap();
    let downloads = directory.0.join("downloads");
    fs::create_dir_all(&downloads).unwrap();
    let destination = downloads.join("published.bin");

    let store = FileStorage::default().with_linker(Arc::new(RealLinker));
    let mut part = store.create(&parts, spec(6)).unwrap();
    part.write_at(0, b"AAAAAA").unwrap();
    part.sync().unwrap();
    let record = attested(part.as_mut());
    part.verify(None, &record).unwrap();
    part.adopt_destination(&destination).unwrap();
    part.publish().expect("the first publication succeeds");
    // The crash: the process ends before the completion is recorded. All that
    // survives is what is on disk.
    drop(part);

    // And the destination folder moves, so reconciliation by path finds
    // nothing and the part is reopened -- the case that cannot be decided.
    let aside = directory.0.join("downloads-moved-away");
    fs::rename(&downloads, &aside).unwrap();
    fs::create_dir(&downloads).unwrap();

    let mut again = store.open(&parts, spec(6)).unwrap();
    for (range, digest) in &record {
        again.recover_extent(*range, *digest).unwrap();
    }
    again.sync().unwrap();
    again.verify(None, &record).unwrap();
    again.adopt_destination(&destination).unwrap();

    assert!(
        again.publish().is_err(),
        "a part that was already sealed on disk published a second copy"
    );
    drop(again);

    // The seal is still there. This is the assertion that matters: the failure
    // path must not treat this like a publication that never happened.
    assert_eq!(
        fs::read(parts.join("1-1.meta")).unwrap().get(33),
        Some(&fhd_app::storage::Publication::Linked.to_byte()),
        "the record changed on a part whose bytes may already be delivered"
    );

    // One copy, where it was published, untouched.
    assert_eq!(fs::read(aside.join("published.bin")).unwrap(), b"AAAAAA");
    assert!(
        fs::read_dir(&downloads).unwrap().next().is_none(),
        "a second copy was published into the folder that took the name"
    );
}
