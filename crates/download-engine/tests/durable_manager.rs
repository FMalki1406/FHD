#![cfg(windows)]

use download_engine::{
    manager::{Config, JobSnapshot, Manager, ManagerError, Priority, RetryPolicy, State},
    Error, Options,
};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const PREFIX: usize = 4096;
const TOTAL: usize = 16384;
fn body() -> Vec<u8> {
    (0..TOTAL).map(|i| (i % 251) as u8).collect()
}
struct Lab {
    root: PathBuf,
    url: String,
    stop: Arc<AtomicBool>,
    counts: Arc<Mutex<HashMap<String, usize>>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Lab {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "fhd-durable-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let counts = Arc::new(Mutex::new(HashMap::new()));
        let flag = stop.clone();
        let requests = counts.clone();
        let worker = thread::spawn(move || {
            let mut connections = vec![];
            while !flag.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let flag = flag.clone();
                        let requests = requests.clone();
                        connections.push(thread::spawn(move || serve(socket, flag, requests)));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
            for connection in connections {
                connection.join().unwrap();
            }
        });
        Self {
            root,
            url,
            stop,
            counts,
            worker: Some(worker),
        }
    }
    fn options(&self, name: &str) -> Options {
        Options {
            url: format!("{}/{name}?token=PRIVATE_QUEUE_SECRET", self.url),
            job_dir: self.root.join(name),
            output_name: "private-filename.bin".into(),
            expected_sha256: None,
            allow_http: true,
            checkpoint_bytes: PREFIX as u64,
            max_download_bytes: TOTAL as u64,
            bytes_per_second: None,
            parallel_connections: 1,
            request_policy: Default::default(),
            refresh_from: None,
        }
    }
    fn count(&self, name: &str) -> usize {
        *self.counts.lock().unwrap().get(name).unwrap_or(&0)
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let result = self.worker.take().unwrap().join();
        if !thread::panicking() {
            result.unwrap();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn serve(mut socket: TcpStream, stop: Arc<AtomicBool>, counts: Arc<Mutex<HashMap<String, usize>>>) {
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = vec![];
    while !request.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        match socket.read(&mut byte) {
            Ok(0) => return,
            Ok(_) => request.push(byte[0]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                if stop.load(Ordering::Acquire) {
                    return;
                }
            }
            Err(_) => return,
        }
        assert!(request.len() < 16384);
    }
    let text = String::from_utf8(request).unwrap();
    assert!(text.contains("token=PRIVATE_QUEUE_SECRET"));
    let name = text
        .split_whitespace()
        .nth(1)
        .unwrap()
        .trim_start_matches('/')
        .split('?')
        .next()
        .unwrap()
        .to_owned();
    let number = {
        let mut counts = counts.lock().unwrap();
        let value = counts.entry(name.clone()).or_insert(0);
        *value += 1;
        *value
    };
    if name == "fail" || name == "permanent" || name == "backoff" {
        let status = if name == "permanent" { 404 } else { 503 };
        let extra = if name == "backoff" {
            "Retry-After: 60\r\n"
        } else {
            ""
        };
        let _ = write!(
            socket,
            "HTTP/1.1 {status} Failure\r\nContent-Length: 0\r\n{extra}Connection: close\r\n\r\n"
        );
        return;
    }
    let lower = text.to_ascii_lowercase();
    if name == "second" {
        assert!(lower.contains("authorization: bearer queue_auth_canary"));
        assert!(lower.contains("cookie: session=queue_cookie_canary"));
    }
    let data = body();
    if lower.contains("range: bytes=") {
        assert!(lower.contains("range: bytes=4096-16383"));
        assert!(lower.contains("if-range: \"queue-v1\""));
        let _ = write!(socket, "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {PREFIX}-{}/{TOTAL}\r\nETag: \"queue-v1\"\r\nConnection: close\r\n\r\n", TOTAL-PREFIX, TOTAL-1);
        let _ = socket.write_all(&data[PREFIX..]);
        return;
    }
    let _ = write!(socket, "HTTP/1.1 200 OK\r\nContent-Length: {TOTAL}\r\nETag: \"queue-v1\"\r\nConnection: close\r\n\r\n");
    if name == "hold" || (name == "drop" && number == 1) {
        let _ = socket.write_all(&data[..PREFIX]);
        if name == "drop" {
            return;
        }
        while !stop.load(Ordering::Acquire) {
            let mut byte = [0];
            match socket.read(&mut byte) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(_) => break,
            }
        }
    } else {
        let _ = socket.write_all(&data);
    }
}
async fn wait_for(
    receiver: &mut tokio::sync::watch::Receiver<Vec<JobSnapshot>>,
    predicate: impl Fn(&[JobSnapshot]) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if predicate(&receiver.borrow()) {
                return;
            }
            receiver.changed().await.expect("manager stopped");
        }
    })
    .await
    .expect("state deadline");
}
fn config() -> Config {
    Config {
        max_active: 1,
        max_jobs: 16,
        max_per_origin: 1,
        retry: RetryPolicy {
            max_attempts: 3,
            initial_delay_ms: 100,
            max_delay_ms: 400,
        },
        global_bytes_per_second: None,
    }
}

#[cfg(windows)]
#[tokio::test]
async fn encrypted_queue_reopens_without_urls_and_preserves_settings_and_partial_bytes() {
    let lab = Lab::new();
    let path = lab.root.join("queue");
    let manager = Manager::open(path.clone(), config()).await.unwrap();
    assert!(matches!(
        Manager::open(path.clone(), config()).await,
        Err(ManagerError::QueueLocked)
    ));
    let mut updates = manager.subscribe();
    let a = manager.enqueue(lab.options("hold")).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == a && j.committed_bytes == PREFIX as u64)
    })
    .await;
    let mut authenticated = lab.options("second");
    authenticated.request_policy = download_engine::RequestPolicy::new(
        Some("Bearer QUEUE_AUTH_CANARY".into()),
        Some("session=QUEUE_COOKIE_CANARY".into()),
        vec![],
    )
    .unwrap();
    let b = manager
        .enqueue_with_priority(authenticated, Priority::High)
        .await
        .unwrap();
    manager.set_job_rate(b, Some(65536)).await.unwrap();
    manager.set_global_rate(Some(131072)).await.unwrap();
    manager.shutdown().await.unwrap();
    let data = std::fs::read(path.join("queue.sqlite")).unwrap();
    for secret in [
        b"PRIVATE_QUEUE_SECRET".as_slice(),
        b"private-filename.bin",
        b"127.0.0.1",
        b"QUEUE_AUTH_CANARY",
        b"QUEUE_COOKIE_CANARY",
    ] {
        assert!(!data.windows(secret.len()).any(|part| part == secret));
    }
    // The caller supplies neither prior URLs nor prior per-job settings.
    let reopened = Manager::open(path, Config::default()).await.unwrap();
    let mut updates = reopened.subscribe();
    assert!(updates
        .borrow()
        .iter()
        .all(|job| job.state == State::Paused));
    assert!(updates.borrow().iter().any(|job| job.id == b
        && job.priority == Priority::High
        && job.bytes_per_second == Some(65536)));
    reopened.resume_all().await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.len() == 2 && jobs.iter().all(|j| j.state == State::Completed)
    })
    .await;
    reopened.shutdown().await.unwrap();
    for name in ["hold", "second"] {
        assert_eq!(
            std::fs::read(lab.root.join(name).join("private-filename.bin")).unwrap(),
            body()
        );
    }
    assert_eq!(lab.count("hold"), 2);
    assert_eq!(lab.count("second"), 1);
}

#[cfg(windows)]
#[tokio::test]
async fn tampered_ciphertext_is_rejected_without_plaintext_fallback() {
    let lab = Lab::new();
    let path = lab.root.join("queue");
    Manager::open(path.clone(), config())
        .await
        .unwrap()
        .shutdown()
        .await
        .unwrap();
    let db = rusqlite::Connection::open(path.join("queue.sqlite")).unwrap();
    let mut payload: Vec<u8> = db
        .query_row("SELECT payload FROM queue_snapshot", [], |row| row.get(0))
        .unwrap();
    let end = payload.len() - 1;
    payload[end] ^= 1;
    db.execute("UPDATE queue_snapshot SET payload=?1", [payload])
        .unwrap();
    drop(db);
    assert!(matches!(
        Manager::open(path, config()).await,
        Err(ManagerError::SecretStorage | ManagerError::Persistence)
    ));
}

#[cfg(windows)]
#[tokio::test]
async fn persistence_failure_rejects_admission_and_does_not_start_worker() {
    let lab = Lab::new();
    let path = lab.root.join("queue");
    let manager = Manager::open(path.clone(), config()).await.unwrap();
    manager.set_global_rate(None).await.unwrap();
    // Alter the owned test database to force the next commit path to fail.
    let db = rusqlite::Connection::open(path.join("queue.sqlite")).unwrap();
    db.execute("DROP TABLE queue_snapshot", []).unwrap();
    drop(db);
    assert_eq!(
        manager.enqueue(lab.options("never")).await,
        Err(ManagerError::Persistence)
    );
    assert_eq!(manager.shutdown().await, Err(ManagerError::Persistence));
    assert_eq!(lab.count("never"), 0);
}

#[tokio::test]
async fn transient_disconnect_resumes_and_attempt_count_is_bounded() {
    let lab = Lab::new();
    let manager = Manager::start_configured(config()).unwrap();
    let mut updates = manager.subscribe();
    let drop = manager.enqueue(lab.options("drop")).await.unwrap();
    let failure = manager.enqueue(lab.options("fail")).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == drop && j.state == State::Completed)
            && jobs
                .iter()
                .any(|j| j.id == failure && matches!(j.state, State::Failed(_)))
    })
    .await;
    assert!(updates
        .borrow()
        .iter()
        .any(|j| j.id == drop && j.attempts == 2));
    assert!(updates.borrow().iter().any(|j| j.id == failure
        && j.attempts == 3
        && j.state == State::Failed(Error::HttpStatus(503))));
    manager.shutdown().await.unwrap();
    assert_eq!(lab.count("drop"), 2);
    assert_eq!(lab.count("fail"), 3);
    assert_eq!(
        std::fs::read(lab.root.join("drop/private-filename.bin")).unwrap(),
        body()
    );
}

#[tokio::test]
async fn permanent_status_and_explicit_server_backoff_are_not_retried() {
    let lab = Lab::new();
    let manager = Manager::start_configured(config()).unwrap();
    let mut updates = manager.subscribe();
    manager.enqueue(lab.options("permanent")).await.unwrap();
    manager.enqueue(lab.options("backoff")).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.len() == 2 && jobs.iter().all(|j| matches!(j.state, State::Failed(_)))
    })
    .await;
    assert!(updates.borrow().iter().all(|j| j.attempts == 1));
    manager.shutdown().await.unwrap();
    assert_eq!(lab.count("permanent"), 1);
    assert_eq!(lab.count("backoff"), 1);
}

#[tokio::test]
async fn retry_wait_releases_slot_and_pause_cancels_scheduled_attempt() {
    let lab = Lab::new();
    let mut settings = config();
    settings.retry.initial_delay_ms = 1000;
    settings.retry.max_delay_ms = 1000;
    let manager = Manager::start_configured(settings).unwrap();
    let mut updates = manager.subscribe();
    let failed = manager.enqueue(lab.options("fail")).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == failed && j.state == State::RetryWaiting)
    })
    .await;
    let success = manager.enqueue(lab.options("success")).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == success && j.state == State::Completed)
    })
    .await;
    manager.pause(failed).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(lab.count("fail"), 1);
    manager.shutdown().await.unwrap();
}
