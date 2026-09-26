//! What macOS actually offers for publication, measured on a real macOS.
//!
//! Nothing in the engine calls the function these exercise. macOS refuses to
//! publish, and will keep refusing until the design question at the end of
//! section 11 of `docs/publication-contract.md` is answered. These exist so
//! that question is answered from a run on the platform rather than from
//! reading Apple's manual pages on a Windows machine.
#![cfg(target_os = "macos")]

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fhd-clonefile-{}-{}-{}",
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
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn written(path: &PathBuf, bytes: &[u8]) -> File {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .read(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    file
}

/// The bytes published are the bytes the descriptor holds, whatever its name
/// has come to mean.
///
/// This is the property that decides whether the mechanism is usable at all.
/// The source's name is taken over by another file after it is opened -- the
/// substitution that makes path-based publication unsafe. If the clone carries
/// the proved bytes, the descriptor is genuinely the source.
#[test]
fn a_clone_carries_the_bytes_of_the_handle_not_of_its_name() {
    let sandbox = Sandbox::new();
    let ours = sandbox.0.join("part");
    let file = written(&ours, b"the proved bytes");
    let folder = File::open(&sandbox.0).unwrap();

    fs::rename(&ours, sandbox.0.join("moved-away")).unwrap();
    written(&ours, b"an impostor");

    fhd_platform::clone_into_directory(&file, &folder, OsStr::new("published")).unwrap();

    assert_eq!(
        fs::read(sandbox.0.join("published")).unwrap(),
        b"the proved bytes",
        "the name was cloned rather than the object the handle holds"
    );
}

/// It is a separate object, which is the fact that decides what adopting it
/// would cost.
///
/// A hard link would answer the same inode, and the engine's claim that a path
/// reaches the file it published is currently asked about the part. A clone is
/// a different inode holding the same bytes, so that question would have to be
/// asked about what was created instead.
#[test]
fn a_clone_is_a_separate_object_from_the_part_it_came_from() {
    let sandbox = Sandbox::new();
    let file = written(&sandbox.0.join("part"), b"the proved bytes");
    let folder = File::open(&sandbox.0).unwrap();

    fhd_platform::clone_into_directory(&file, &folder, OsStr::new("published")).unwrap();

    let part = file.metadata().unwrap();
    let published = fs::metadata(sandbox.0.join("published")).unwrap();
    assert_eq!(
        fs::read(sandbox.0.join("published")).unwrap(),
        b"the proved bytes"
    );
    assert!(
        part.ino() != published.ino(),
        "a clone shares the inode, which would make it a hard link and this note wrong"
    );
}

/// An occupied name is refused, and what is there is left alone.
#[test]
fn a_clone_refuses_an_occupied_name_and_leaves_it_untouched() {
    let sandbox = Sandbox::new();
    let file = written(&sandbox.0.join("part"), b"ours");
    let taken = sandbox.0.join("taken");
    written(&taken, b"someone else's file");
    let folder = File::open(&sandbox.0).unwrap();

    let refused = fhd_platform::clone_into_directory(&file, &folder, OsStr::new("taken"));
    assert_eq!(
        refused.unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists,
        "an occupied name was not refused"
    );
    assert_eq!(fs::read(&taken).unwrap(), b"someone else's file");
}

/// A name that is not one component is refused before any system call.
#[test]
fn a_clone_name_that_is_not_one_component_is_refused() {
    let sandbox = Sandbox::new();
    let file = written(&sandbox.0.join("part"), b"ours");
    fs::create_dir(sandbox.0.join("inner")).unwrap();
    let folder = File::open(&sandbox.0).unwrap();

    for name in ["inner/escaped", "../escaped", "/absolute", ".", ".."] {
        let refused = fhd_platform::clone_into_directory(&file, &folder, OsStr::new(name));
        assert_eq!(
            refused.unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput,
            "{name} was not refused"
        );
    }
    assert!(!sandbox.0.join("inner/escaped").exists());
}

/// The move lands the pinned object in the adopted folder, and it is the same
/// object.
///
/// This is the step that would make the macOS candidate publication rather than
/// a copy nobody can identify. The clone is made in a directory the engine owns
/// and opened there, so the handle is held before the name ever appears in the
/// user's folder; the move then carries *that object*. If identity survives the
/// move, the engine can answer "this path reaches the file I published" about
/// the thing it is holding, which is what the reviews said cloning straight
/// into the destination could not do.
#[test]
fn a_moved_clone_keeps_its_identity_and_lands_in_the_opened_folder() {
    let sandbox = Sandbox::new();
    let ours = sandbox.0.join("part");
    let file = written(&ours, b"the proved bytes");
    let private = sandbox.0.join("private");
    fs::create_dir(&private).unwrap();
    let downloads = sandbox.0.join("downloads");
    fs::create_dir(&downloads).unwrap();
    let private_dir = File::open(&private).unwrap();
    let folder = File::open(&downloads).unwrap();

    fhd_platform::clone_into_directory(&file, &private_dir, OsStr::new("staged")).unwrap();
    let pinned = fhd_platform::open_in_directory(&private_dir, OsStr::new("staged")).unwrap();
    fhd_platform::move_into_directory(
        &private_dir,
        OsStr::new("staged"),
        &folder,
        OsStr::new("wanted.bin"),
    )
    .unwrap();

    let published = downloads.join("wanted.bin");
    assert_eq!(fs::read(&published).unwrap(), b"the proved bytes");
    let held = pinned.metadata().unwrap();
    let landed = fs::metadata(&published).unwrap();
    assert!(
        held.dev() == landed.dev() && held.ino() == landed.ino(),
        "the move did not carry the object that was pinned"
    );
    assert!(
        !private.join("staged").exists(),
        "the staged name outlived the move"
    );
}

/// The move refuses an occupied name and leaves what is there alone.
///
/// `RENAME_EXCL` is what makes this publication rather than replacement, and
/// the default `rename` would silently overwrite -- which is the behaviour this
/// whole design exists to refuse.
#[test]
fn a_moved_clone_refuses_an_occupied_name_and_leaves_it_untouched() {
    let sandbox = Sandbox::new();
    let file = written(&sandbox.0.join("part"), b"ours");
    let private = sandbox.0.join("private");
    fs::create_dir(&private).unwrap();
    let downloads = sandbox.0.join("downloads");
    fs::create_dir(&downloads).unwrap();
    let taken = downloads.join("taken.bin");
    written(&taken, b"someone else's file");
    let private_dir = File::open(&private).unwrap();
    let folder = File::open(&downloads).unwrap();

    fhd_platform::clone_into_directory(&file, &private_dir, OsStr::new("staged")).unwrap();
    let refused = fhd_platform::move_into_directory(
        &private_dir,
        OsStr::new("staged"),
        &folder,
        OsStr::new("taken.bin"),
    );
    assert_eq!(
        refused.unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists,
        "an occupied name was not refused"
    );
    assert_eq!(fs::read(&taken).unwrap(), b"someone else's file");
    assert!(
        private.join("staged").exists(),
        "a refused move consumed the staged clone"
    );
}

/// The destination is the descriptor, not the name it had.
///
/// The adopted folder is moved aside after its descriptor is opened and another
/// directory takes its name. The file must land in the one that was opened.
#[test]
fn a_moved_clone_ignores_a_directory_that_took_the_destination_name() {
    let sandbox = Sandbox::new();
    let file = written(&sandbox.0.join("part"), b"the proved bytes");
    let private = sandbox.0.join("private");
    fs::create_dir(&private).unwrap();
    let adopted = sandbox.0.join("downloads");
    fs::create_dir(&adopted).unwrap();
    let private_dir = File::open(&private).unwrap();
    let folder = File::open(&adopted).unwrap();

    fs::rename(&adopted, sandbox.0.join("moved-away")).unwrap();
    fs::create_dir(&adopted).unwrap();

    fhd_platform::clone_into_directory(&file, &private_dir, OsStr::new("staged")).unwrap();
    fhd_platform::move_into_directory(
        &private_dir,
        OsStr::new("staged"),
        &folder,
        OsStr::new("wanted.bin"),
    )
    .unwrap();

    assert!(
        !adopted.join("wanted.bin").exists(),
        "the file landed in the directory that replaced the adopted one"
    );
    assert_eq!(
        fs::read(sandbox.0.join("moved-away").join("wanted.bin")).unwrap(),
        b"the proved bytes"
    );
}

/// Neither end takes a name that is more than one component.
#[test]
fn a_moved_clone_refuses_names_that_are_not_one_component() {
    let sandbox = Sandbox::new();
    let file = written(&sandbox.0.join("part"), b"ours");
    let private = sandbox.0.join("private");
    fs::create_dir(&private).unwrap();
    let downloads = sandbox.0.join("downloads");
    fs::create_dir(&downloads).unwrap();
    fs::create_dir(downloads.join("inner")).unwrap();
    let private_dir = File::open(&private).unwrap();
    let folder = File::open(&downloads).unwrap();
    fhd_platform::clone_into_directory(&file, &private_dir, OsStr::new("staged")).unwrap();

    for name in ["inner/escaped", "../escaped", "/absolute", ".", "..", "x/."] {
        let refused = fhd_platform::move_into_directory(
            &private_dir,
            OsStr::new("staged"),
            &folder,
            OsStr::new(name),
        );
        assert_eq!(
            refused.unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput,
            "{name} was not refused as a destination"
        );
        let refused = fhd_platform::move_into_directory(
            &private_dir,
            OsStr::new(name),
            &folder,
            OsStr::new("wanted.bin"),
        );
        assert_eq!(
            refused.unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput,
            "{name} was not refused as a source"
        );
    }
    assert!(!downloads.join("inner/escaped").exists());
    assert!(!downloads.join("wanted.bin").exists());
}

/// **The measurement that decides against the candidate.**
///
/// The three steps were proposed because `fclonefileat` hands back no descriptor
/// for the clone it makes, so opening the new name to learn what was published
/// lets the name be substituted first. Staging the clone somewhere private, then
/// pinning it, then moving it was meant to close that.
///
/// It does not, and this measures it rather than arguing it. The staged name is
/// replaced after the pin, and the move carries **the replacement**: it looks
/// `staged` up again, because `renameatx_np` takes a name and the pinned
/// descriptor is not one. So an engine that trusted the pinned handle would
/// report success about bytes it never verified. That is the false reporting the
/// whole design exists to prevent, which is why nothing calls these three.
///
/// If macOS ever grows a descriptor-sourced link or rename, this test is the one
/// that should start failing.
#[test]
fn a_moved_clone_carries_the_staged_name_not_the_pinned_object() {
    let sandbox = Sandbox::new();
    let file = written(&sandbox.0.join("part"), b"the proved bytes");
    let private = sandbox.0.join("private");
    fs::create_dir(&private).unwrap();
    let downloads = sandbox.0.join("downloads");
    fs::create_dir(&downloads).unwrap();
    let private_dir = File::open(&private).unwrap();
    let folder = File::open(&downloads).unwrap();

    fhd_platform::clone_into_directory(&file, &private_dir, OsStr::new("staged")).unwrap();
    let pinned = fhd_platform::open_in_directory(&private_dir, OsStr::new("staged")).unwrap();

    // Whatever can write the staging directory, between the pin and the move.
    fs::remove_file(private.join("staged")).unwrap();
    written(&private.join("staged"), b"bytes nobody verified");

    fhd_platform::move_into_directory(
        &private_dir,
        OsStr::new("staged"),
        &folder,
        OsStr::new("wanted.bin"),
    )
    .unwrap();

    let published = downloads.join("wanted.bin");
    assert_eq!(
        fs::read(&published).unwrap(),
        b"bytes nobody verified",
        "the move carried the pinned object, so macOS has a descriptor-sourced \
         rename after all and section 11 of the publication contract is wrong"
    );
    let held = pinned.metadata().unwrap();
    let landed = fs::metadata(&published).unwrap();
    assert!(
        held.ino() != landed.ino(),
        "the published object is the pinned one, which would contradict the line above"
    );
}

/// The pin refuses a symlink at that name rather than following it.
///
/// `O_NOFOLLOW`'s property, which had no test: every one of the four move
/// properties passed with the flag deleted, so an engineering review pointed out
/// that step two was constrained by nothing at all.
#[test]
fn a_pin_refuses_a_symlink_and_does_not_follow_it() {
    let sandbox = Sandbox::new();
    let private = sandbox.0.join("private");
    fs::create_dir(&private).unwrap();
    let secret = sandbox.0.join("secret");
    written(&secret, b"not ours to publish");
    std::os::unix::fs::symlink(&secret, private.join("staged")).unwrap();
    let private_dir = File::open(&private).unwrap();

    let refused = fhd_platform::open_in_directory(&private_dir, OsStr::new("staged"));
    assert!(
        refused.is_err(),
        "a symlink at the staged name was followed instead of refused"
    );
}

/// The pin refuses anything that is not a regular file.
///
/// A FIFO is the one that matters: a blocking `O_RDONLY` open on it waits for a
/// writer that may never come, which would hang publication with nothing able to
/// cancel it. A directory opens quite happily and would then be moved into the
/// user's folder as though it were the download. Both came from review.
#[test]
fn a_pin_refuses_what_is_not_a_regular_file() {
    let sandbox = Sandbox::new();
    let private = sandbox.0.join("private");
    fs::create_dir(&private).unwrap();
    let private_dir = File::open(&private).unwrap();

    fs::create_dir(private.join("a-directory")).unwrap();
    let refused = fhd_platform::open_in_directory(&private_dir, OsStr::new("a-directory"));
    assert_eq!(
        refused.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput,
        "a directory was pinned as though it were the download"
    );

    // `mkfifo(1)` rather than the libc call, so the test needs no unsafe of its
    // own. If the tool is missing the assertion is skipped, not silently passed
    // off as met -- the panic below says which.
    let made = std::process::Command::new("mkfifo")
        .arg(private.join("a-pipe"))
        .status()
        .expect("mkfifo(1) is needed to measure that a FIFO cannot hang the pin");
    assert!(
        made.success(),
        "mkfifo(1) failed, so the FIFO case is unmeasured"
    );

    // The point is that this returns at all: without `O_NONBLOCK` it would block
    // here forever and the test would time out rather than fail.
    let refused = fhd_platform::open_in_directory(&private_dir, OsStr::new("a-pipe"));
    assert_eq!(
        refused.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput,
        "a FIFO was pinned as though it were the download"
    );
}

/// The pin resolves inside the descriptor it was given, not inside a path.
///
/// The staging directory is moved aside after its descriptor is opened and
/// another directory takes its name, holding a different file under the same
/// staged name. The pin must find the one in the directory that was opened.
#[test]
fn a_pin_looks_only_inside_the_directory_that_was_opened() {
    let sandbox = Sandbox::new();
    let private = sandbox.0.join("private");
    fs::create_dir(&private).unwrap();
    written(&private.join("staged"), b"the proved bytes");
    let private_dir = File::open(&private).unwrap();

    fs::rename(&private, sandbox.0.join("moved-away")).unwrap();
    fs::create_dir(&private).unwrap();
    written(&private.join("staged"), b"an impostor");

    let pinned = fhd_platform::open_in_directory(&private_dir, OsStr::new("staged")).unwrap();
    let held = pinned.metadata().unwrap();
    let ours = fs::metadata(sandbox.0.join("moved-away").join("staged")).unwrap();
    assert!(
        held.dev() == ours.dev() && held.ino() == ours.ino(),
        "the pin resolved the directory by name and found the impostor"
    );
}

/// The pin refuses a name that is not one component, before any system call.
#[test]
fn a_pin_refuses_names_that_are_not_one_component() {
    let sandbox = Sandbox::new();
    let private = sandbox.0.join("private");
    fs::create_dir(&private).unwrap();
    fs::create_dir(private.join("inner")).unwrap();
    written(&private.join("inner").join("escaped"), b"not ours");
    let private_dir = File::open(&private).unwrap();

    for name in [
        "inner/escaped",
        "../escaped",
        "/absolute",
        ".",
        "..",
        "inner/.",
    ] {
        let refused = fhd_platform::open_in_directory(&private_dir, OsStr::new(name));
        assert_eq!(
            refused.unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput,
            "{name} was not refused"
        );
    }
}
