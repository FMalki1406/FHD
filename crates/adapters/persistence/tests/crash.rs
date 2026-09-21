//! Committed admission survives process termination without repository Drop.
//! This is not a power-loss or torn-write test.
use fhd_app::{AddDownload, AppError, Authorizer, EntitlementGate, Principal, ReceiptKey};
use fhd_domain::{DestinationRef, JobSpec, Priority, SourceRef};
use fhd_persistence::{Limits, SqliteRepository};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const CHILD_DIRECTORY: &str = "FHD_ADMISSION_CRASH_TEST_DIRECTORY";
struct Allow;
impl Authorizer for Allow {
    fn authorize_add(&self, _: Principal, _: &JobSpec) -> Result<(), AppError> {
        Ok(())
    }
}
impl EntitlementGate for Allow {
    fn authorize_add(&self, _: Principal, _: &JobSpec) -> Result<(), AppError> {
        Ok(())
    }
}
fn key() -> ReceiptKey {
    ReceiptKey::new(Principal::new(7).unwrap(), [19; 32])
}
fn spec(destination: u64) -> JobSpec {
    JobSpec::new(
        SourceRef::new(41).unwrap(),
        DestinationRef::new(destination).unwrap(),
        Some([27; 32]),
        Priority::High,
        8 * 1024 * 1024,
    )
    .unwrap()
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = fs::canonicalize(std::env::temp_dir()).unwrap();
        let path = parent.join(format!(
            "fhd-admission-crash-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct ChildGuard(Option<Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn wait_for_commit(child: &mut Child, directory: &Path) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(text) = fs::read_to_string(directory.join("ready")) {
            return text.parse().expect("child published a complete job ID");
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("child exited before readiness: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "child did not commit within timeout"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn process_child() {
    let Some(directory) = std::env::var_os(CHILD_DIRECTORY) else {
        return;
    };
    let directory = PathBuf::from(directory);
    runtime().block_on(async {
        let repository = SqliteRepository::open(directory.join("repository"), Limits::default())
            .await
            .unwrap();
        let id = AddDownload::new(&repository, &Allow, &Allow)
            .execute(key(), spec(42))
            .await
            .unwrap();
        assert_eq!(repository.counts().await.unwrap(), (1, 1));
        fs::write(directory.join("ready.tmp"), id.get().to_string()).unwrap();
        fs::rename(directory.join("ready.tmp"), directory.join("ready")).unwrap();
        // Keep the repository and its SQLite WAL connection alive. The parent
        // terminates this process; no graceful shutdown or Rust Drop executes.
        loop {
            std::thread::park_timeout(Duration::from_secs(1));
        }
    });
}

#[test]
fn killed_process_retains_committed_job_and_replays_same_receipt() {
    let directory = Directory::new();
    let executable = std::env::current_exe().unwrap();
    let mut child = ChildGuard(Some(
        Command::new(executable)
            .args(["--exact", "process_child", "--nocapture"])
            .env(CHILD_DIRECTORY, &directory.0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    ));
    let process = child.0.as_mut().unwrap();
    let committed_id = wait_for_commit(process, &directory.0);
    assert!(process.try_wait().unwrap().is_none());
    process.kill().unwrap();
    let status = process.wait().unwrap();
    assert!(
        !status.success(),
        "child must be terminated, not exit normally"
    );
    child.0.take();

    runtime().block_on(async {
        let repository = SqliteRepository::open(directory.0.join("repository"), Limits::default())
            .await
            .unwrap();
        assert_eq!(repository.counts().await.unwrap(), (1, 1));
        let service = AddDownload::new(&repository, &Allow, &Allow);
        let replayed = service.execute(key(), spec(42)).await.unwrap();
        assert_eq!(replayed.get(), committed_id);
        assert_eq!(
            service.execute(key(), spec(43)).await,
            Err(AppError::IdempotencyConflict)
        );
        assert_eq!(repository.counts().await.unwrap(), (1, 1));
    });
}
