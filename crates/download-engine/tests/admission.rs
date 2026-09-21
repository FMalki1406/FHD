#![cfg(windows)]

use download_engine::{
    manager::{Config, JobId, JobSnapshot, Manager, ManagerError, Priority, RetryPolicy, State},
    Options, RequestPolicy,
};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

static NEXT: AtomicUsize = AtomicUsize::new(0);
const KEY: &str = "admission-request-00000001";
const PAYLOAD: &[u8] = b"exactly one accepted transfer";
struct Fixture {
    root: PathBuf,
    url: String,
    count: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fhd-admission-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "http://{}/file?token=private",
            listener.local_addr().unwrap()
        );
        let count = Arc::new(AtomicUsize::new(0));
        let requests = count.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                let mut socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = vec![];
                while !request.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    if socket.read_exact(&mut byte).is_err() {
                        break;
                    }
                    request.push(byte[0]);
                    assert!(request.len() < 16384);
                }
                requests.fetch_add(1, Ordering::AcqRel);
                let _ = write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"admission-v1\"\r\nConnection: close\r\n\r\n", PAYLOAD.len());
                let _ = socket.write_all(PAYLOAD);
            }
        });
        Self {
            root,
            url,
            count,
            stop,
            worker: Some(worker),
        }
    }
    fn options(&self) -> Options {
        Options {
            url: self.url.clone(),
            job_dir: self.root.join("job"),
            output_name: "result.bin".into(),
            expected_sha256: Some(Sha256::digest(PAYLOAD).into()),
            allow_http: true,
            checkpoint_bytes: 8,
            max_download_bytes: 1024,
            bytes_per_second: None,
            parallel_connections: 1,
            request_policy: RequestPolicy::new(
                Some("Bearer SECRET".into()),
                Some("session=SECRET".into()),
                vec![],
            )
            .unwrap(),
            refresh_from: None,
        }
    }
    fn count(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let result = self.worker.take().unwrap().join();
        if !thread::panicking() {
            result.unwrap();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn config() -> Config {
    Config {
        retry: RetryPolicy::disabled(),
        ..Config::default()
    }
}
async fn completed(updates: &mut watch::Receiver<Vec<JobSnapshot>>, id: JobId) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if updates
                .borrow()
                .iter()
                .any(|job| job.id == id && job.state == State::Completed)
            {
                return;
            }
            updates.changed().await.unwrap();
        }
    })
    .await
    .expect("accepted transfer completion deadline");
}

#[tokio::test]
async fn eight_concurrent_replays_and_restart_produce_one_transfer_and_one_receipt() {
    let fixture = Fixture::new();
    let queue = fixture.root.join("queue");
    let manager = Arc::new(Manager::open(queue.clone(), config()).await.unwrap());
    let mut updates = manager.subscribe();
    let mut callers = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let manager = manager.clone();
        let options = fixture.options();
        callers.spawn(async move {
            manager
                .enqueue_once(KEY.into(), options, Priority::Normal)
                .await
                .unwrap()
        });
    }
    let mut ids = vec![];
    while let Some(result) = callers.join_next().await {
        ids.push(result.unwrap());
    }
    assert_eq!(ids.len(), 8);
    assert!(ids.iter().all(|id| *id == ids[0]));
    let id = ids[0];
    completed(&mut updates, id).await;
    manager.set_job_rate(id, Some(4096)).await.unwrap();
    let manager = Arc::try_unwrap(manager).unwrap_or_else(|_| panic!("caller retained manager"));
    manager.shutdown().await.unwrap();
    assert_eq!(fixture.count(), 1);
    assert_eq!(
        std::fs::read(fixture.root.join("job/result.bin")).unwrap(),
        PAYLOAD
    );

    let reopened = Manager::open(queue, Config::default()).await.unwrap();
    assert_eq!(
        reopened
            .enqueue_once(KEY.into(), fixture.options(), Priority::Normal)
            .await
            .unwrap(),
        id
    );
    assert_eq!(reopened.subscribe().borrow().len(), 1);
    assert_eq!(
        reopened.subscribe().borrow()[0].bytes_per_second,
        Some(4096)
    );
    reopened.shutdown().await.unwrap();
    assert_eq!(
        fixture.count(),
        1,
        "replayed durable receipt must not restart HTTP"
    );
}

#[tokio::test]
async fn reusing_key_with_changed_immutable_input_is_rejected_without_second_transfer() {
    let fixture = Fixture::new();
    let manager = Manager::open(fixture.root.join("queue"), config())
        .await
        .unwrap();
    let mut updates = manager.subscribe();
    let base = fixture.options();
    let id = manager
        .enqueue_once(KEY.into(), base.clone(), Priority::Normal)
        .await
        .unwrap();
    completed(&mut updates, id).await;
    let mut variants = vec![];
    let mut value = base.clone();
    value.url.push_str("-different");
    variants.push(value);
    let mut value = base.clone();
    value.output_name = "other.bin".into();
    variants.push(value);
    let mut value = base.clone();
    value.expected_sha256 = Some([9; 32]);
    variants.push(value);
    let mut value = base.clone();
    value.bytes_per_second = Some(4096);
    variants.push(value);
    let mut value = base.clone();
    value.job_dir = fixture.root.join("other");
    variants.push(value);
    let mut value = base.clone();
    value.parallel_connections = 2;
    variants.push(value);
    let mut value = base.clone();
    value.checkpoint_bytes = 16;
    variants.push(value);
    let mut value = base.clone();
    value.max_download_bytes = 2048;
    variants.push(value);
    let mut value = base.clone();
    value.request_policy = RequestPolicy::new(
        Some("Bearer OTHER".into()),
        Some("session=SECRET".into()),
        vec![],
    )
    .unwrap();
    variants.push(value);
    let mut value = base.clone();
    value.request_policy = RequestPolicy::new(
        Some("Bearer SECRET".into()),
        Some("session=OTHER".into()),
        vec![],
    )
    .unwrap();
    variants.push(value);
    for options in variants {
        assert_eq!(
            manager
                .enqueue_once(KEY.into(), options, Priority::Normal)
                .await,
            Err(ManagerError::IdempotencyConflict)
        );
    }
    assert_eq!(
        manager.enqueue_once(KEY.into(), base, Priority::High).await,
        Err(ManagerError::IdempotencyConflict)
    );
    manager.shutdown().await.unwrap();
    assert_eq!(fixture.count(), 1);
}

#[tokio::test]
async fn forgotten_receipt_survives_restart_without_recreating_job_or_deleting_file() {
    let fixture = Fixture::new();
    let queue = fixture.root.join("queue");
    let manager = Manager::open(queue.clone(), config()).await.unwrap();
    let mut updates = manager.subscribe();
    let id = manager
        .enqueue_once(KEY.into(), fixture.options(), Priority::Normal)
        .await
        .unwrap();
    completed(&mut updates, id).await;
    manager.forget(id).await.unwrap();
    manager.shutdown().await.unwrap();
    let reopened = Manager::open(queue, config()).await.unwrap();
    assert!(reopened.subscribe().borrow().is_empty());
    assert_eq!(
        reopened
            .enqueue_once(KEY.into(), fixture.options(), Priority::Normal)
            .await,
        Err(ManagerError::PreviouslyRemoved)
    );
    reopened.shutdown().await.unwrap();
    assert_eq!(fixture.count(), 1);
    assert_eq!(
        std::fs::read(fixture.root.join("job/result.bin")).unwrap(),
        PAYLOAD
    );
}

#[tokio::test]
async fn admission_fails_closed_without_durable_storage() {
    let fixture = Fixture::new();
    let manager = Manager::start_configured(config()).unwrap();
    assert_eq!(
        manager
            .enqueue_once(KEY.into(), fixture.options(), Priority::Normal)
            .await,
        Err(ManagerError::NotDurable)
    );
    manager.shutdown().await.unwrap();
    assert_eq!(fixture.count(), 0);
    assert!(!fixture.root.join("job").exists());
}

#[tokio::test]
async fn failed_receipt_transaction_never_acknowledges_or_starts_transfer() {
    let fixture = Fixture::new();
    let queue = fixture.root.join("queue");
    let manager = Manager::open(queue.clone(), config()).await.unwrap();
    // Wait for the actor's initial snapshot commit before injecting failure.
    manager.set_global_rate(None).await.unwrap();
    let db = rusqlite::Connection::open(queue.join("queue.sqlite")).unwrap();
    db.execute("DROP TABLE queue_snapshot", []).unwrap();
    drop(db);
    assert_eq!(
        manager
            .enqueue_once(KEY.into(), fixture.options(), Priority::Normal)
            .await,
        Err(ManagerError::Persistence)
    );
    assert_eq!(manager.shutdown().await, Err(ManagerError::Persistence));
    assert_eq!(fixture.count(), 0);
    assert!(!fixture.root.join("job").exists());
}
