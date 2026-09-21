use download_engine::{
    manager::{Config, JobId, JobSnapshot, Manager, ManagerError, RetryPolicy, State},
    Error, Options, RequestPolicy,
};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
use transfer_store::{url_fingerprint, Store};
static NEXT: AtomicUsize = AtomicUsize::new(0);
const PREFIX: usize = 4096;
const TOTAL: usize = 16384;
struct Fixture {
    root: PathBuf,
    url: String,
    bytes: Vec<u8>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "fhd-refresh-{}-{}-{}",
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
        let url = format!("http://{}/file", listener.local_addr().unwrap());
        let bytes: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();
        let data = bytes.clone();
        let requests = Arc::new(Mutex::new(vec![]));
        let seen = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                let mut socket = match listener.accept() {
                    Ok((s, _)) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("accept {e}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut bytes = vec![];
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut b = [0];
                    if socket.read_exact(&mut b).is_err() {
                        break;
                    }
                    bytes.push(b[0]);
                    assert!(bytes.len() < 16384);
                }
                let request = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
                let target = request.split_whitespace().nth(1).unwrap().to_owned();
                seen.lock().unwrap().push(target.clone());
                let range = request.lines().find_map(|line| {
                    line.strip_prefix("range: bytes=")
                        .map(|v| v.split('-').next().unwrap().parse::<usize>().unwrap())
                });
                let start = range.unwrap_or(0);
                let tag = if target.contains("token=changed") {
                    "changed-v2"
                } else {
                    "refresh-v1"
                };
                if range.is_some() {
                    assert!(request.contains("if-range: \"refresh-v1\""));
                    let _=write!(socket,"HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nETag: \"{}\"\r\nConnection: close\r\n\r\n",TOTAL-start,start,TOTAL-1,TOTAL,tag);
                } else {
                    let _=write!(socket,"HTTP/1.1 200 OK\r\nContent-Length: {TOTAL}\r\nETag: \"{tag}\"\r\nConnection: close\r\n\r\n");
                }
                let end = if target.contains("token=one") || target.contains("token=two") {
                    (start + PREFIX).min(TOTAL)
                } else {
                    TOTAL
                };
                if target.contains("token=forged") {
                    let mut forged = data[start..end].to_vec();
                    forged[0] ^= 0xff;
                    let _ = socket.write_all(&forged);
                } else {
                    let _ = socket.write_all(&data[start..end]);
                }
                let _ = socket.flush();
                // Ensure the valid prefix is consumed before deliberately breaking framing.
                if end < TOTAL {
                    thread::sleep(Duration::from_millis(50));
                }
            }
        });
        Self {
            root,
            url,
            bytes,
            requests,
            stop,
            worker: Some(worker),
        }
    }
    fn url(&self, token: &str) -> String {
        format!("{}?token={token}", self.url)
    }
    fn options(&self) -> Options {
        Options {
            url: self.url("one"),
            job_dir: self.root.join("job"),
            output_name: "result.bin".into(),
            expected_sha256: Some(Sha256::digest(&self.bytes).into()),
            allow_http: true,
            checkpoint_bytes: PREFIX as u64,
            max_download_bytes: TOTAL as u64,
            bytes_per_second: None,
            parallel_connections: 1,
            request_policy: RequestPolicy::default(),
            refresh_from: None,
        }
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
async fn wait_for(
    updates: &mut watch::Receiver<Vec<JobSnapshot>>,
    id: JobId,
    condition: impl Fn(&State) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if updates
                .borrow()
                .iter()
                .any(|job| job.id == id && condition(&job.state))
            {
                return;
            }
            updates.changed().await.unwrap();
        }
    })
    .await
    .expect("manager state deadline");
}

#[tokio::test]
async fn two_signed_query_refreshes_reconcile_current_binding_and_resume_exact_bytes() {
    let f = Fixture::new();
    let manager = Manager::start_configured(config()).unwrap();
    let mut updates = manager.subscribe();
    let id = manager.enqueue(f.options()).await.unwrap();
    wait_for(&mut updates, id, |s| {
        matches!(s, State::Failed(Error::Network))
    })
    .await;
    {
        let store = Store::open(&f.root.join("job")).unwrap();
        assert_eq!(store.committed_len(), PREFIX as u64);
    }
    manager.refresh_url(id, f.url("two")).await.unwrap();
    manager.resume(id).await.unwrap();
    wait_for(&mut updates, id, |s| {
        f.requests.lock().unwrap().len() >= 2 && matches!(s, State::Failed(Error::Network))
    })
    .await;
    {
        let store = Store::open(&f.root.join("job")).unwrap();
        assert_eq!(store.committed_len(), (2 * PREFIX) as u64);
        assert_eq!(
            store.identity().original_url_fingerprint,
            url_fingerprint(&f.url("two"))
        );
    }
    manager.refresh_url(id, f.url("three")).await.unwrap();
    manager.resume(id).await.unwrap();
    wait_for(&mut updates, id, |s| *s == State::Completed).await;
    manager.shutdown().await.unwrap();
    assert_eq!(
        std::fs::read(f.root.join("job/result.bin")).unwrap(),
        f.bytes
    );
    assert_eq!(
        *f.requests.lock().unwrap(),
        vec!["/file?token=one", "/file?token=two", "/file?token=three"]
    );
}
#[tokio::test]
async fn refresh_rejects_origin_path_and_missing_trusted_digest() {
    let f = Fixture::new();
    let manager = Manager::start_configured(config()).unwrap();
    let mut updates = manager.subscribe();
    let id = manager.enqueue(f.options()).await.unwrap();
    wait_for(&mut updates, id, |s| matches!(s, State::Failed(_))).await;
    for url in [
        format!("{}-other?token=two", f.url),
        "https://different.invalid/file?token=two".into(),
    ] {
        assert_eq!(
            manager.refresh_url(id, url).await,
            Err(ManagerError::InvalidOptions)
        );
    }
    let mut unsigned = f.options();
    unsigned.job_dir = f.root.join("unsigned");
    unsigned.expected_sha256 = None;
    let other = manager.enqueue(unsigned).await.unwrap();
    wait_for(&mut updates, other, |s| matches!(s, State::Failed(_))).await;
    assert_eq!(
        manager.refresh_url(other, f.url("three")).await,
        Err(ManagerError::InvalidOptions)
    );
    manager.shutdown().await.unwrap();
    assert_eq!(f.requests.lock().unwrap().len(), 2);
}
#[tokio::test]
async fn refreshed_url_with_changed_etag_never_appends_or_publishes() {
    let f = Fixture::new();
    let manager = Manager::start_configured(config()).unwrap();
    let mut updates = manager.subscribe();
    let id = manager.enqueue(f.options()).await.unwrap();
    wait_for(&mut updates, id, |s| matches!(s, State::Failed(_))).await;
    manager.refresh_url(id, f.url("changed")).await.unwrap();
    manager.resume(id).await.unwrap();
    wait_for(&mut updates, id, |s| {
        f.requests.lock().unwrap().len() >= 2 && matches!(s, State::Failed(Error::ResumeRejected))
    })
    .await;
    manager.shutdown().await.unwrap();
    let store = Store::open(&f.root.join("job")).unwrap();
    assert_eq!(store.committed_len(), PREFIX as u64);
    assert_eq!(
        store.identity().original_url_fingerprint,
        url_fingerprint(&f.url("one"))
    );
    assert!(!f.root.join("job/result.bin").exists());
    assert_eq!(
        std::fs::read(f.root.join("job/payload.part")).unwrap(),
        f.bytes[..PREFIX]
    );
}
#[cfg(windows)]
#[tokio::test]
async fn forgetting_inactive_job_preserves_partial_and_persists_monotonic_ids() {
    let f = Fixture::new();
    let queue = f.root.join("queue");
    let manager = Manager::open(queue.clone(), config()).await.unwrap();
    let mut updates = manager.subscribe();
    let old = manager.enqueue(f.options()).await.unwrap();
    wait_for(&mut updates, old, |s| matches!(s, State::Failed(_))).await;
    manager.forget(old).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !updates.borrow().is_empty() {
            updates.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    manager.shutdown().await.unwrap();
    assert_eq!(
        std::fs::read(f.root.join("job/payload.part")).unwrap(),
        f.bytes[..PREFIX]
    );
    let reopened = Manager::open(queue, Config::default()).await.unwrap();
    let mut updates = reopened.subscribe();
    assert!(updates.borrow().is_empty());
    let mut options = f.options();
    options.url = f.url("three");
    options.job_dir = f.root.join("second");
    let new = reopened.enqueue(options).await.unwrap();
    assert!(new.0 > old.0);
    wait_for(&mut updates, new, |s| *s == State::Completed).await;
    reopened.shutdown().await.unwrap();
    assert_eq!(
        std::fs::read(f.root.join("second/result.bin")).unwrap(),
        f.bytes
    );
    assert!(f.root.join("job/payload.part").exists());
}

#[tokio::test]
async fn refreshed_body_with_same_etag_and_length_fails_trusted_checksum() {
    let f = Fixture::new();
    let manager = Manager::start_configured(config()).unwrap();
    let mut updates = manager.subscribe();
    let id = manager.enqueue(f.options()).await.unwrap();
    wait_for(&mut updates, id, |state| {
        matches!(state, State::Failed(Error::Network))
    })
    .await;
    manager.refresh_url(id, f.url("forged")).await.unwrap();
    manager.resume(id).await.unwrap();
    wait_for(&mut updates, id, |state| {
        matches!(state, State::Failed(Error::ChecksumMismatch))
    })
    .await;
    manager.shutdown().await.unwrap();
    assert_eq!(f.requests.lock().unwrap().len(), 2);
    assert!(!f.root.join("job/result.bin").exists());
    let partial = std::fs::read(f.root.join("job/payload.part")).unwrap();
    assert_eq!(partial.len(), TOTAL);
    assert_eq!(&partial[..PREFIX], &f.bytes[..PREFIX]);
    assert_ne!(partial, f.bytes);
}
