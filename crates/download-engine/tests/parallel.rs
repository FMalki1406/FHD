use download_engine::{download, Error, Options};
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
use transfer_store::Store;

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    url: String,
    stop: Arc<AtomicBool>,
    mode: Arc<AtomicUsize>,
    ranges: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
    bytes: Vec<u8>,
}
impl Fixture {
    fn new(mode: usize) -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "fhd-parallel-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/file", listener.local_addr().unwrap());
        let bytes: Vec<u8> = (0..1_400_013).map(|i| (i % 251) as u8).collect();
        let stop = Arc::new(AtomicBool::new(false));
        let mode = Arc::new(AtomicUsize::new(mode));
        let ranges = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let (flag, behavior, count, maximum, data) = (
            stop.clone(),
            mode.clone(),
            ranges.clone(),
            peak.clone(),
            Arc::new(bytes.clone()),
        );
        let worker = thread::spawn(move || {
            let mut workers = vec![];
            let active = Arc::new(AtomicUsize::new(0));
            let deadline = Instant::now() + Duration::from_secs(60);
            while !flag.load(Ordering::Acquire) {
                let (mut socket, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline);
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("accept {e}"),
                };
                let (behavior, count, maximum, data, active) = (
                    behavior.clone(),
                    count.clone(),
                    maximum.clone(),
                    data.clone(),
                    active.clone(),
                );
                workers.push(thread::spawn(move|| {
     socket.set_nonblocking(false).unwrap(); socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();socket.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
     let mut request=vec![];
     while !request.ends_with(b"\r\n\r\n") {let mut b=[0];if socket.read_exact(&mut b).is_err(){return;}request.push(b[0]);assert!(request.len()<16384);}
     let request=String::from_utf8(request).unwrap().to_ascii_lowercase();
     let range=request.lines().find_map(|line|line.strip_prefix("range: bytes=").map(|v|{let(a,b)=v.split_once('-').unwrap();(a.parse::<usize>().unwrap(),b.parse::<usize>().unwrap()+1)}));
     let mode=behavior.load(Ordering::Acquire);
     if let Some((start,end))=range {
      count.fetch_add(1,Ordering::AcqRel);
      let n=active.fetch_add(1,Ordering::AcqRel)+1;maximum.fetch_max(n,Ordering::AcqRel);
      thread::sleep(Duration::from_millis(if mode==4 && start>0 {350}else{(4-(start/(256*1024))%4)as u64*30}));
      if mode==6 && start>0 {
       let _=write!(socket,"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 30\r\nConnection: close\r\n\r\n");
      } else if mode==5 && start>0 {
       let _=write!(socket,"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
      } else if mode==1 {
       let _=write!(socket,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"parallel-v1\"\r\nConnection: close\r\n\r\n",data.len());let _=socket.write_all(&data);
      } else {
       let tag=if mode==2 && start>0 {"parallel-changed"}else{"parallel-v1"};
       let declared_start=if mode==3 && start>0 {start+1}else{start};
       let _=write!(socket,"HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nETag: \"{}\"\r\nConnection: close\r\n\r\n",end-start,declared_start,end-1,data.len(),tag);
       let _=socket.write_all(&data[start..end]);
      }
      active.fetch_sub(1,Ordering::AcqRel);
     } else {
      let _=write!(socket,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"parallel-v1\"\r\nConnection: close\r\n\r\n",data.len());let _=socket.write_all(&data);
     }
    }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            root,
            url,
            stop,
            mode,
            ranges,
            peak,
            worker: Some(worker),
            bytes,
        }
    }
    fn options(&self) -> Options {
        Options {
            url: self.url.clone(),
            job_dir: self.root.join("job"),
            output_name: "result.bin".into(),
            expected_sha256: None,
            allow_http: true,
            checkpoint_bytes: 64 * 1024,
            max_download_bytes: 2 * 1024 * 1024,
            bytes_per_second: None,
            parallel_connections: 3,
            request_policy: Default::default(),
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

#[tokio::test]
async fn concurrent_ranges_are_bounded_and_publish_exact_bytes() {
    let f = Fixture::new(0);
    let (_owner, cancel) = watch::channel(false);
    let outcome = download(f.options(), cancel, |_| {}).await.unwrap();
    assert_eq!(std::fs::read(outcome.path).unwrap(), f.bytes);
    assert!(f.ranges.load(Ordering::Acquire) >= 6);
    assert!((2..=3).contains(&f.peak.load(Ordering::Acquire)));
}
#[tokio::test]
async fn ignoring_ranges_falls_back_without_duplicate_bytes() {
    let f = Fixture::new(1);
    let (_owner, cancel) = watch::channel(false);
    let outcome = download(f.options(), cancel, |_| {}).await.unwrap();
    assert_eq!(std::fs::read(outcome.path).unwrap(), f.bytes);
    assert_eq!(f.ranges.load(Ordering::Acquire), 1);
}
#[tokio::test]
async fn changed_range_identity_never_appends_mixed_representation() {
    let f = Fixture::new(2);
    let (_owner, cancel) = watch::channel(false);
    assert_eq!(
        download(f.options(), cancel.clone(), |_| {})
            .await
            .unwrap_err(),
        Error::RepresentationChanged
    );
    assert!(!f.root.join("job/result.bin").exists());
    let store = Store::open(&f.root.join("job")).unwrap();
    assert_eq!(store.committed_len(), 256 * 1024);
    drop(store);
    f.mode.store(0, Ordering::Release);
    let outcome = download(f.options(), cancel, |_| {}).await.unwrap();
    assert_eq!(outcome.resumed_from, 256 * 1024);
    assert_eq!(std::fs::read(outcome.path).unwrap(), f.bytes);
}
#[tokio::test]
async fn incorrect_range_bounds_fail_without_publication() {
    let f = Fixture::new(3);
    let (_owner, cancel) = watch::channel(false);
    assert_eq!(
        download(f.options(), cancel, |_| {}).await.unwrap_err(),
        Error::ResumeRejected
    );
    assert!(!f.root.join("job/result.bin").exists());
    let store = Store::open(&f.root.join("job")).unwrap();
    assert_eq!(store.committed_len(), 256 * 1024);
}
#[tokio::test]
async fn cancellation_drains_ranges_then_allows_safe_resume() {
    let f = Fixture::new(4);
    let (owner, cancel) = watch::channel(false);
    let signal = owner.clone();
    let seen = f.ranges.clone();
    let result = download(f.options(), cancel, move |bytes| {
        if bytes == 256 * 1024 {
            let signal = signal.clone();
            let seen = seen.clone();
            tokio::spawn(async move {
                let until = tokio::time::Instant::now() + Duration::from_secs(2);
                while seen.load(Ordering::Acquire) < 3 && tokio::time::Instant::now() < until {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let _ = signal.send(true);
            });
        }
    })
    .await;
    assert_eq!(result.unwrap_err(), Error::Cancelled);
    assert!(
        f.ranges.load(Ordering::Acquire) >= 3,
        "cancellation must reach active parallel requests"
    );
    let store = Store::open(&f.root.join("job")).unwrap();
    assert_eq!(store.committed_len(), 256 * 1024);
    drop(store);
    f.mode.store(0, Ordering::Release);
    let (_owner, cancel) = watch::channel(false);
    let outcome = download(f.options(), cancel, |_| {}).await.unwrap();
    assert_eq!(std::fs::read(outcome.path).unwrap(), f.bytes);
}

#[tokio::test]
async fn transient_status_without_etag_remains_retryable_status() {
    let f = Fixture::new(5);
    let (_owner, cancel) = watch::channel(false);
    assert_eq!(
        download(f.options(), cancel, |_| {}).await.unwrap_err(),
        Error::HttpStatus(503)
    );
    assert!(!f.root.join("job/result.bin").exists());
    let store = Store::open(&f.root.join("job")).unwrap();
    assert_eq!(store.committed_len(), 256 * 1024);
}
#[tokio::test]
async fn parallel_workers_share_one_job_rate_budget() {
    let f = Fixture::new(0);
    let (_owner, cancel) = watch::channel(false);
    let mut options = f.options();
    options.bytes_per_second = Some(1024 * 1024);
    let started = Instant::now();
    let outcome = download(options, cancel, |_| {}).await.unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(1300),
        "workers multiplied the per-job rate"
    );
    assert_eq!(std::fs::read(outcome.path).unwrap(), f.bytes);
}

#[tokio::test]
async fn retry_after_is_preserved_as_explicit_server_cooldown() {
    let f = Fixture::new(6);
    let (_owner, cancel) = watch::channel(false);
    assert_eq!(
        download(f.options(), cancel, |_| {}).await.unwrap_err(),
        Error::ServerBackoff(503)
    );
    assert!(!f.root.join("job/result.bin").exists());
}

#[cfg(windows)]
#[tokio::test]
async fn durable_parallel_retry_and_bandwidth_survive_manager_reopen() {
    use download_engine::manager::{Config, Manager, RetryPolicy, State};
    let fixture = Fixture::new(5);
    let queue = fixture.root.join("queue");
    let config = Config {
        max_active: 1,
        max_jobs: 8,
        max_per_origin: 1,
        retry: RetryPolicy {
            max_attempts: 3,
            initial_delay_ms: 400,
            max_delay_ms: 400,
        },
        global_bytes_per_second: Some(512 * 1024),
    };
    let manager = Manager::open(queue.clone(), config).await.unwrap();
    let mut updates = manager.subscribe();
    let mut options = fixture.options();
    options.parallel_connections = 4;
    options.bytes_per_second = Some(1024 * 1024);
    let id = manager.enqueue(options).await.unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if updates
                .borrow()
                .iter()
                .any(|job| job.id == id && job.state == State::RetryWaiting)
            {
                break;
            }
            updates.changed().await.unwrap();
        }
    })
    .await
    .expect("first range failure must enter retry waiting");
    fixture.mode.store(0, Ordering::Release);
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if updates
                .borrow()
                .iter()
                .any(|job| job.id == id && job.state == State::Completed)
            {
                break;
            }
            updates.changed().await.unwrap();
        }
    })
    .await
    .expect("retried parallel transfer must complete");
    assert!(updates
        .borrow()
        .iter()
        .any(|job| job.id == id && job.attempts == 2));
    manager.shutdown().await.unwrap();
    assert_eq!(
        std::fs::read(fixture.root.join("job/result.bin")).unwrap(),
        fixture.bytes
    );

    let reopened = Manager::open(queue, Config::default()).await.unwrap();
    let mut updates = reopened.subscribe();
    assert!(updates.borrow().iter().any(|job| job.id == id
        && job.state == State::Completed
        && job.attempts == 2
        && job.bytes_per_second == Some(1024 * 1024)));
    // The new job has no local rate: only the global rate recovered from disk
    // can enforce this bound after reopening with the unlimited default config.
    let mut second = fixture.options();
    second.job_dir = fixture.root.join("second");
    second.parallel_connections = 4;
    let started = Instant::now();
    let second_id = reopened.enqueue(second).await.unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if updates
                .borrow()
                .iter()
                .any(|job| job.id == second_id && job.state == State::Completed)
            {
                break;
            }
            updates.changed().await.unwrap();
        }
    })
    .await
    .expect("second transfer must complete with recovered global cap");
    assert!(
        started.elapsed() >= Duration::from_millis(2600),
        "persisted global cap was lost"
    );
    reopened.shutdown().await.unwrap();
    assert_eq!(
        std::fs::read(fixture.root.join("second/result.bin")).unwrap(),
        fixture.bytes
    );
}
