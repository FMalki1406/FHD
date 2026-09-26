//! What the Linux publication mechanism does, measured rather than assumed.
//!
//! These run only where the mechanism exists. The platform without one is not
//! tested into looking as though it has one: it refuses, and
//! `docs/publication-contract.md` says what was measured there and why.
#![cfg(target_os = "linux")]

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
            "fhd-linkat-{}-{}-{}",
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

fn same(left: &File, right: &std::fs::Metadata) -> bool {
    let left = left.metadata().unwrap();
    left.dev() == right.dev() && left.ino() == right.ino()
}

/// The object published is the object the handle holds, whatever its name says.
///
/// This is the whole reason the port takes handles. The source's name is taken
/// over by another file between opening it and publishing -- which is the
/// substitution that was measured against `hard_link` and found to publish the
/// other file's bytes. Through the descriptor there is no name to take over.
#[test]
fn a_source_name_taken_over_does_not_change_what_is_published() {
    let sandbox = Sandbox::new();
    let ours = sandbox.0.join("part");
    let file = written(&ours, b"the proved bytes");
    let folder = File::open(&sandbox.0).unwrap();

    // The name now means something else entirely.
    fs::rename(&ours, sandbox.0.join("moved-away")).unwrap();
    written(&ours, b"an impostor").sync_all().unwrap();

    fhd_platform::link_into_directory(&file, &folder, OsStr::new("published")).unwrap();

    let published = sandbox.0.join("published");
    assert_eq!(fs::read(&published).unwrap(), b"the proved bytes");
    assert!(
        same(&file, &fs::metadata(&published).unwrap()),
        "the name was published rather than the object"
    );
}

/// An occupied name is refused, never replaced.
#[test]
fn an_occupied_name_is_refused_and_the_file_there_is_untouched() {
    let sandbox = Sandbox::new();
    let file = written(&sandbox.0.join("part"), b"ours");
    let taken = sandbox.0.join("taken");
    written(&taken, b"someone else's file");
    let folder = File::open(&sandbox.0).unwrap();

    let refused = fhd_platform::link_into_directory(&file, &folder, OsStr::new("taken"));
    assert_eq!(
        refused.unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists,
        "an occupied name was not refused"
    );
    assert_eq!(fs::read(&taken).unwrap(), b"someone else's file");
}

/// A name that is not one component is refused before any system call.
///
/// Anything with a separator would resolve a path inside the directory, which
/// is the resolution this call exists to avoid.
///
/// The last three spellings are the reason the check reads the bytes *before*
/// parsing, and an engineering and a security review both found that this list
/// did not contain them. `Path::components` normalises: it reports `x/`, `x//`
/// and `x/.` as the single component `x`, so the parse alone accepts all three.
/// The first five here are refused by the parse, which meant deleting the byte
/// check left this whole suite green -- on the platform where publication
/// actually ships. `a_symlinked_directory_is_not_walked_by_a_trailing_dot` below
/// is the half of it that has teeth.
#[test]
fn a_name_that_is_not_one_component_is_refused() {
    let sandbox = Sandbox::new();
    let file = written(&sandbox.0.join("part"), b"ours");
    fs::create_dir(sandbox.0.join("inner")).unwrap();
    let folder = File::open(&sandbox.0).unwrap();

    for name in [
        "inner/escaped",
        "../escaped",
        "/absolute",
        ".",
        "..",
        "inner/",
        "inner//",
        "inner/.",
        "",
    ] {
        let refused = fhd_platform::link_into_directory(&file, &folder, OsStr::new(name));
        assert_eq!(
            refused.unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput,
            "{name:?} was not refused"
        );
    }
    assert!(!sandbox.0.join("inner/escaped").exists());
}

/// The spelling the byte check exists for, with the symlink that makes it matter.
///
/// `x/.` parses as the single component `x`. Where `x` is a symlink to a
/// directory, the kernel walks it -- `AT_SYMLINK_FOLLOW` is set on the source, but
/// this is the *destination* end, and a trailing `/.` forces the last component to
/// be resolved as a directory. So a name the parse calls "one component" would
/// have published into somewhere else entirely. Nothing in the tree measured this
/// before; both reviews of the shared `one_component` asked for it by name.
#[test]
fn a_symlinked_directory_is_not_walked_by_a_trailing_dot() {
    let sandbox = Sandbox::new();
    let file = written(&sandbox.0.join("part"), b"ours");
    let elsewhere = sandbox.0.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, sandbox.0.join("link")).unwrap();
    let folder = File::open(&sandbox.0).unwrap();

    let refused = fhd_platform::link_into_directory(&file, &folder, OsStr::new("link/."));
    assert_eq!(
        refused.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput,
        "a trailing /. on a symlink to a directory was not refused"
    );
    assert_eq!(
        fs::read_dir(&elsewhere).unwrap().count(),
        0,
        "the link was followed and something was published through it"
    );
}

/// The destination is the directory handle, not a path that can be swapped.
///
/// The folder is moved aside after it is opened and another directory takes its
/// name. The file must land in the one that was opened -- the folder the engine
/// adopted -- and not in whatever now answers to that name.
#[test]
fn a_destination_folder_swapped_after_it_was_opened_is_not_the_one_published_into() {
    let sandbox = Sandbox::new();
    let file = written(&sandbox.0.join("part"), b"the proved bytes");
    let adopted = sandbox.0.join("downloads");
    fs::create_dir(&adopted).unwrap();
    let folder = File::open(&adopted).unwrap();

    // Moved aside, and an impostor directory takes the name.
    fs::rename(&adopted, sandbox.0.join("moved-away")).unwrap();
    fs::create_dir(&adopted).unwrap();

    fhd_platform::link_into_directory(&file, &folder, OsStr::new("wanted.bin")).unwrap();

    assert!(
        !adopted.join("wanted.bin").exists(),
        "publication landed in the directory that replaced the adopted one"
    );
    let landed = sandbox.0.join("moved-away").join("wanted.bin");
    assert_eq!(fs::read(&landed).unwrap(), b"the proved bytes");
}
