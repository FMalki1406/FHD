use download_engine::{download, Error, Options, Outcome};
use std::{
    future::Future,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
use transfer_store::{Status, Store};

const PREFIX: usize = 16 * 1024;
const TOTAL: usize = 64 * 1024;
type Owner = Arc<Mutex<Option<watch::Sender<bool>>>>;

fn payload() -> Vec<u8> {
    (0..TOTAL).map(|index| (index % 251) as u8).collect()
}

struct Directory(PathBuf);

impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "fhd-cancellation-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn job(&self) -> PathBuf {
        self.0.join("job")
    }
}

impl Drop for Directory {
    fn drop(&mut self) {
        let result = std::fs::remove_dir_all(&self.0);
        if !thread::panicking() {
            result.unwrap();
        }
    }
}

struct Server {
    url: String,
    stop: Arc<AtomicBool>,
    release_first: Arc<AtomicBool>,
    ranges: Arc<Mutex<Vec<u64>>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/file", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let release_first = Arc::new(AtomicBool::new(false));
        let ranges = Arc::new(Mutex::new(Vec::new()));
        let worker_stop = stop.clone();
        let worker_release = release_first.clone();
        let worker_ranges = ranges.clone();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut first = true;
            while !worker_stop.load(Ordering::Acquire) {
                assert!(Instant::now() < deadline, "fixture exceeded its deadline");
                match listener.accept() {
                    Ok((stream, _)) => {
                        serve(stream, first, &worker_stop, &worker_release, &worker_ranges);
                        first = false;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                }
            }
        });
        Self {
            url,
            stop,
            release_first,
            ranges,
            worker: Some(worker),
        }
    }

    fn options(&self, directory: &Directory) -> Options {
        Options {
            url: self.url.clone(),
            job_dir: directory.job(),
            output_name: "complete.bin".into(),
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
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let result = self.worker.take().unwrap().join();
        if !thread::panicking() {
            result.unwrap();
        }
    }
}

fn serve(
    mut stream: TcpStream,
    first: bool,
    stop: &AtomicBool,
    release: &AtomicBool,
    ranges: &Mutex<Vec<u64>>,
) {
    // Windows accepted sockets inherit the nonblocking listener's mode.
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        request.push(byte[0]);
        assert!(request.len() <= 16 * 1024, "fixture request too large");
    }
    let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
    let start = request.lines().find_map(|line| {
        line.strip_prefix("range: bytes=")
            .map(|value| value.split_once('-').unwrap().0.parse::<usize>().unwrap())
    });
    let data = payload();
    if first {
        assert_eq!(start, None);
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {TOTAL}\r\nETag: \"fixture-v1\"\r\nConnection: close\r\n\r\n").unwrap();
        stream.write_all(&data[..PREFIX]).unwrap();
        stream.flush().unwrap();
        // Keep the response unfinished. Cancellation must finish without EOF,
        // a network error, or the server releasing the remainder of the body.
        let deadline = Instant::now() + Duration::from_secs(20);
        while !stop.load(Ordering::Acquire) && !release.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "first response was never released"
            );
            thread::sleep(Duration::from_millis(5));
        }
    } else {
        let start = start.expect("second request must resume the durable prefix");
        assert_eq!(start, PREFIX);
        assert!(request
            .lines()
            .any(|line| line == "if-range: \"fixture-v1\""));
        ranges.lock().unwrap().push(start as u64);
        write!(stream, "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{}/{TOTAL}\r\nETag: \"fixture-v1\"\r\nConnection: close\r\n\r\n", TOTAL - start, TOTAL - 1).unwrap();
        stream.write_all(&data[start..]).unwrap();
    }
}

async fn bounded(
    future: impl Future<Output = Result<Outcome, Error>>,
    owner: &Owner,
) -> Result<Outcome, Error> {
    tokio::pin!(future);
    match tokio::time::timeout(Duration::from_secs(10), &mut future).await {
        Ok(result) => result,
        Err(_) => {
            // Preserve and await the download future: dropping it could leave
            // spawn_blocking writes alive while the fixture directory is removed.
            owner.lock().unwrap().take();
            let result = future.await;
            panic!("transfer deadline exceeded; drained result: {result:?}");
        }
    }
}

#[tokio::test]
async fn cancellation_preserves_checkpoint_and_resumes_exact_bytes() {
    let directory = Directory::new();
    let server = Server::new();
    let (sender, receiver) = watch::channel(false);
    let owner: Owner = Arc::new(Mutex::new(Some(sender)));
    let result = bounded(
        download(server.options(&directory), receiver, |bytes| {
            assert_eq!(bytes, PREFIX as u64);
            owner.lock().unwrap().as_ref().unwrap().send(true).unwrap();
        }),
        &owner,
    )
    .await;
    assert_eq!(result.unwrap_err(), Error::Cancelled);
    assert!(!directory.job().join("complete.bin").exists());
    {
        // Reopening immediately also proves cancellation awaited release of the lock.
        let store = Store::open(&directory.job()).unwrap();
        assert_eq!(store.committed_len(), PREFIX as u64);
        assert_eq!(store.status(), Status::Downloading);
        assert_eq!(
            std::fs::read(directory.job().join("payload.part")).unwrap(),
            payload()[..PREFIX]
        );
    }
    server.release_first.store(true, Ordering::Release);
    let (sender, receiver) = watch::channel(false);
    let owner: Owner = Arc::new(Mutex::new(Some(sender)));
    let outcome = bounded(
        download(server.options(&directory), receiver, |_| {}),
        &owner,
    )
    .await
    .unwrap();
    assert_eq!(outcome.resumed_from, PREFIX as u64);
    assert_eq!(outcome.bytes, TOTAL as u64);
    assert_eq!(std::fs::read(outcome.path).unwrap(), payload());
    assert_eq!(*server.ranges.lock().unwrap(), vec![PREFIX as u64]);
}

#[tokio::test]
async fn losing_owner_during_transfer_cancels_without_publication() {
    let directory = Directory::new();
    let server = Server::new();
    let (sender, receiver) = watch::channel(false);
    let owner: Owner = Arc::new(Mutex::new(Some(sender)));
    let result = bounded(
        download(server.options(&directory), receiver, |bytes| {
            assert_eq!(bytes, PREFIX as u64);
            owner.lock().unwrap().take();
        }),
        &owner,
    )
    .await;
    assert_eq!(result.unwrap_err(), Error::Cancelled);
    assert!(!directory.job().join("complete.bin").exists());
    let store = Store::open(&directory.job()).unwrap();
    assert_eq!(store.committed_len(), PREFIX as u64);
    assert_eq!(store.status(), Status::Downloading);
    assert_eq!(
        std::fs::read(directory.job().join("payload.part")).unwrap(),
        payload()[..PREFIX]
    );
}
