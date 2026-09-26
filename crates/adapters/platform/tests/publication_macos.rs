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
