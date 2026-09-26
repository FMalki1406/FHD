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
