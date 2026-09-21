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

struct Fixture {
    directory: PathBuf,
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(bytes: Vec<u8>) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let directory = std::env::temp_dir().join(format!(
            "fhd-rate-{}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/file", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            while !flag.load(Ordering::Acquire) {
                let mut socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline);
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut b = [0];
                    socket.read_exact(&mut b).unwrap();
                    request.push(b[0]);
                    assert!(request.len() < 16384);
                }
                let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
                let start = request.lines().find_map(|line| {
                    line.strip_prefix("range: bytes=")
                        .map(|value| value.split('-').next().unwrap().parse::<usize>().unwrap())
                });
                if let Some(start) = start {
                    assert!(request.contains("if-range: \"rate-v1\""));
                    write!(socket,"HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{}/{}\r\nETag: \"rate-v1\"\r\nConnection: close\r\n\r\n",bytes.len()-start,bytes.len()-1,bytes.len()).unwrap();
                } else {
                    write!(socket,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"rate-v1\"\r\nConnection: close\r\n\r\n",bytes.len()).unwrap();
                }
                let _ = socket.write_all(&bytes[start.unwrap_or(0)..]);
            }
        });
        Self {
            directory,
            url,
            stop,
            worker: Some(worker),
        }
    }
    fn options(&self, rate: u64, checkpoint: u64) -> Options {
        Options {
            url: self.url.clone(),
            job_dir: self.directory.join("job"),
            output_name: "file.bin".into(),
            expected_sha256: None,
            allow_http: true,
            checkpoint_bytes: checkpoint,
            max_download_bytes: 1024 * 1024,
            bytes_per_second: Some(rate),
            parallel_connections: 1,
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
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

#[tokio::test]
async fn rate_limit_paces_complete_body_and_preserves_bytes() {
    let bytes: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
    let fixture = Fixture::new(bytes.clone());
    let (owner, cancel) = watch::channel(false);
    let started = Instant::now();
    let result = download(fixture.options(8192, 1024), cancel, |_| {})
        .await
        .unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(950),
        "body was accepted faster than configured rate"
    );
    assert_eq!(std::fs::read(result.path).unwrap(), bytes);
    drop(owner);
}

#[tokio::test]
async fn cancellation_interrupts_long_rate_wait_and_keeps_durable_prefix() {
    let fixture = Fixture::new(b"abcdefghij".to_vec());
    let (owner, cancel) = watch::channel(false);
    let scheduled = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let result = download(fixture.options(1, 1), cancel, |count| {
        if count > 0 && !scheduled.swap(true, Ordering::AcqRel) {
            let owner = owner.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                owner.send_replace(true);
            });
        }
    })
    .await;
    assert_eq!(result.unwrap_err(), Error::Cancelled);
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "cancellation did not interrupt pacing wait"
    );
    let store = Store::open(&fixture.directory.join("job")).unwrap();
    assert_eq!(store.committed_len(), 1);
    assert_eq!(
        std::fs::read(fixture.directory.join("job/payload.part")).unwrap(),
        b"a"
    );
    assert!(!fixture.directory.join("job/file.bin").exists());
    drop(store);
    let (owner, cancel) = watch::channel(false);
    let mut options = fixture.options(1, 1);
    options.bytes_per_second = None;
    let resumed = download(options, cancel, |_| {}).await.unwrap();
    assert_eq!(resumed.resumed_from, 1);
    assert_eq!(std::fs::read(resumed.path).unwrap(), b"abcdefghij");
    drop(owner);
}

#[tokio::test]
async fn intentional_pacing_longer_than_network_timeout_still_completes() {
    let bytes = vec![b'x'; 33];
    let fixture = Fixture::new(bytes.clone());
    let (owner, cancel) = watch::channel(false);
    let started = Instant::now();
    let result = download(fixture.options(1, 1), cancel, |_| {})
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(32));
    assert_eq!(std::fs::read(result.path).unwrap(), bytes);
    drop(owner);
}

#[tokio::test]
async fn aggregate_limit_covers_two_real_downloads() {
    use download_engine::{download_controlled, Bandwidth, TrafficControl};
    let bytes = vec![b'g'; 8192];
    let a = Fixture::new(bytes.clone());
    let b = Fixture::new(bytes.clone());
    let budget = Bandwidth::new(Some(8192)).unwrap();
    let ca = TrafficControl::with_global(budget.clone(), None).unwrap();
    let cb = TrafficControl::with_global(budget, None).unwrap();
    let (owner, cancel) = watch::channel(false);
    let start = Instant::now();
    let (ra, rb) = tokio::join!(
        download_controlled(a.options(8192, 1024), cancel.clone(), ca, |_| {}),
        download_controlled(b.options(8192, 1024), cancel, cb, |_| {})
    );
    assert!(start.elapsed() >= Duration::from_millis(1900));
    assert_eq!(std::fs::read(ra.unwrap().path).unwrap(), bytes);
    assert_eq!(std::fs::read(rb.unwrap().path).unwrap(), bytes);
    drop(owner);
}

#[tokio::test]
async fn active_download_observes_live_job_and_global_changes() {
    use download_engine::{download_controlled, Bandwidth, TrafficControl};
    for global_slow in [false, true] {
        let fixture = Fixture::new(b"live-rate".to_vec());
        let budget = Bandwidth::new(if global_slow { Some(1) } else { None }).unwrap();
        let control =
            TrafficControl::with_global(budget.clone(), if global_slow { None } else { Some(1) })
                .unwrap();
        let update = control.clone();
        let changer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            update.set_job_rate(None).unwrap();
            budget.set_limit(None).unwrap();
        });
        let (owner, cancel) = watch::channel(false);
        let start = Instant::now();
        let result = download_controlled(fixture.options(1, 1), cancel, control, |_| {})
            .await
            .unwrap();
        assert!(start.elapsed() < Duration::from_secs(3));
        assert_eq!(std::fs::read(result.path).unwrap(), b"live-rate");
        changer.await.unwrap();
        drop(owner);
    }
}
