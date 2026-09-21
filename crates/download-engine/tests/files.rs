use download_engine::{
    files::{check_space, export_completed, validate_name, Conflict, ExportResult},
    Error,
};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use transfer_store::{url_fingerprint, Identity, Store};
struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "fhd-export-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("destination")).unwrap();
        Self { root }
    }
    fn store(&self, publish: bool) {
        let id = Identity {
            original_url_fingerprint: url_fingerprint("https://example.com/file"),
            final_url_fingerprint: url_fingerprint("https://example.com/file"),
            strong_etag: Some("\"v1\"".into()),
            total: 7,
            expected_sha256: None,
        };
        let mut s = Store::create(&self.root.join("job"), id, "file.bin").unwrap();
        s.append(b"payload").unwrap();
        s.checkpoint().unwrap();
        if publish {
            s.mark_transfer_complete().unwrap();
            s.finalize().unwrap();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn export_rejects_skips_or_renames_without_touching_existing_data() {
    let f = Fixture::new();
    f.store(true);
    let dest = f.root.join("destination").canonicalize().unwrap();
    fs::write(dest.join("file.bin"), b"personal").unwrap();
    assert_eq!(
        export_completed(&f.root.join("job"), &dest, "file.bin", Conflict::Reject),
        Err(Error::DestinationConflict)
    );
    assert_eq!(
        export_completed(&f.root.join("job"), &dest, "file.bin", Conflict::Skip).unwrap(),
        ExportResult::Skipped(dest.join("file.bin"))
    );
    assert_eq!(
        export_completed(&f.root.join("job"), &dest, "file.bin", Conflict::Rename).unwrap(),
        ExportResult::Published(dest.join("file (1).bin"))
    );
    assert_eq!(fs::read(dest.join("file.bin")).unwrap(), b"personal");
    assert_eq!(fs::read(dest.join("file (1).bin")).unwrap(), b"payload");
    assert_eq!(fs::read_dir(&dest).unwrap().count(), 2);
    assert_eq!(Store::open(&f.root.join("job")).unwrap().committed_len(), 7);
}
#[test]
fn incomplete_or_corrupt_sources_are_never_exported() {
    let f = Fixture::new();
    f.store(false);
    let dest = f.root.join("destination").canonicalize().unwrap();
    assert_eq!(
        export_completed(&f.root.join("job"), &dest, "file.bin", Conflict::Reject),
        Err(Error::InvalidTransition)
    );
    fs::write(f.root.join("job/payload.part"), b"changed").unwrap();
    assert_eq!(
        export_completed(&f.root.join("job"), &dest, "file.bin", Conflict::Reject),
        Err(Error::StoredDataCorrupt)
    );
    assert_eq!(fs::read_dir(dest).unwrap().count(), 0);
}
#[test]
fn destination_admission_rejects_unsafe_names_and_impossible_space() {
    let f = Fixture::new();
    for name in [
        "../x", "a/b", "a\\b", "NUL", "COM1.txt", "x.", "x ", "x:stream", "",
    ] {
        assert!(validate_name(name).is_err(), "{name}");
    }
    assert_eq!(
        check_space(&f.root.join("destination"), u64::MAX, 1),
        Err(Error::SizeLimit)
    );
    assert_eq!(
        check_space(&f.root.join("destination"), u64::MAX, 0),
        Err(Error::InsufficientSpace)
    );
    assert!(check_space(&f.root.join("destination"), 1, 0).is_ok());
}
