use download_engine::{download, Error, Options, RequestPolicy};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;
use transfer_store::{Status, Store};

const PREFIX: usize = 4096;
const TOTAL: usize = 16384;
fn body() -> Vec<u8> {
    (0..TOTAL).map(|i| (i % 251) as u8).collect()
}
struct Lab {
    root: PathBuf,
    url: String,
    stop: Arc<AtomicBool>,
    count: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Lab {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "fhd-unknown-{}-{}-{}",
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
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicUsize::new(0));
        let flag = stop.clone();
        let requests = count.clone();
        let worker = thread::spawn(move || {
            while !flag.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        requests.fetch_add(1, Ordering::Relaxed);
                        serve(socket, &flag);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
        });
        Self {
            root,
            url,
            stop,
            count,
            worker: Some(worker),
        }
    }
    fn options(&self, name: &str) -> Options {
        Options {
            url: format!("{}/{name}", self.url),
            job_dir: self.root.join(name),
            output_name: "file.bin".into(),
            expected_sha256: None,
            allow_http: true,
            checkpoint_bytes: PREFIX as u64,
            max_download_bytes: TOTAL as u64,
            bytes_per_second: None,
            parallel_connections: 4,
            request_policy: RequestPolicy::default(),
            refresh_from: None,
        }
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let joined = self.worker.take().unwrap().join();
        if !thread::panicking() {
            joined.unwrap();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
fn serve(mut socket: TcpStream, stop: &AtomicBool) {
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
    let request = String::from_utf8(request).unwrap();
    assert!(!request.to_ascii_lowercase().contains("range:"));
    let name = request.split_whitespace().nth(1).unwrap();
    if name == "/close" {
        let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nsilent truncation");
        return;
    }
    let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nETag: \"unknown-v1\"\r\nConnection: close\r\n\r\n");
    if name == "/empty" {
        let _ = socket.write_all(b"0\r\n\r\n");
        return;
    }
    let data = body();
    if name == "/soak" {
        // Generate 64 MiB from a reusable 16 KiB block; opt-in workload only.
        for _ in 0..4096 {
            if stop.load(Ordering::Acquire) {
                return;
            }
            if write!(socket, "{:X}\r\n", data.len())
                .and_then(|()| socket.write_all(&data))
                .and_then(|()| socket.write_all(b"\r\n"))
                .is_err()
            {
                return;
            }
        }
        let _ = socket.write_all(b"0\r\n\r\n");
        return;
    }
    for (index, bytes) in data.chunks(PREFIX).enumerate() {
        if write!(socket, "{:X}\r\n", bytes.len())
            .and_then(|()| socket.write_all(bytes))
            .and_then(|()| socket.write_all(b"\r\n"))
            .is_err()
        {
            return;
        }
        if index == 0 && name == "/hold" {
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
            return;
        }
    }
    if name == "/cut" {
        return;
    }
    if name == "/over" {
        let _ = socket.write_all(b"1\r\nx\r\n");
    }
    let _ = socket.write_all(b"0\r\n\r\n");
}

#[tokio::test]
async fn chunked_stream_finishes_with_actual_length_and_expected_digest() {
    let lab = Lab::new();
    let mut options = lab.options("good");
    options.expected_sha256 = Some(Sha256::digest(body()).into());
    let (owner, cancel) = watch::channel(false);
    let result = download(options.clone(), cancel, |_| {}).await.unwrap();
    assert_eq!(result.bytes, TOTAL as u64);
    assert_eq!(std::fs::read(&result.path).unwrap(), body());
    let store = Store::open(&options.job_dir).unwrap();
    assert_eq!(store.status(), Status::Published);
    assert!(!store.is_unknown_length());
    assert_eq!(store.identity().total, TOTAL as u64);
    drop(store);
    let again = download(options, owner.subscribe(), |_| {}).await.unwrap();
    assert_eq!(again.bytes, TOTAL as u64);
    assert_eq!(lab.count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn missing_chunk_terminator_never_publishes_even_after_full_expected_bytes() {
    let lab = Lab::new();
    let options = lab.options("cut");
    let (owner, cancel) = watch::channel(false);
    assert!(matches!(
        download(options.clone(), cancel, |_| {}).await,
        Err(Error::Network)
    ));
    assert!(!options.job_dir.join("file.bin").exists());
    let store = Store::open(&options.job_dir).unwrap();
    assert!(store.is_unknown_length());
    assert_eq!(store.status(), Status::Downloading);
    drop(store);
    assert!(matches!(
        download(options, owner.subscribe(), |_| {}).await,
        Err(Error::ResumeUnsupported)
    ));
    assert_eq!(lab.count.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn close_delimited_body_is_rejected_before_creating_storage() {
    let lab = Lab::new();
    let options = lab.options("close");
    let (_owner, cancel) = watch::channel(false);
    assert!(matches!(
        download(options.clone(), cancel, |_| {}).await,
        Err(Error::InvalidHeaders)
    ));
    assert!(!options.job_dir.exists());
}

#[tokio::test]
async fn empty_framed_body_completes_as_an_empty_file() {
    let lab = Lab::new();
    let options = lab.options("empty");
    let (_owner, cancel) = watch::channel(false);
    let result = download(options, cancel, |_| {}).await.unwrap();
    assert_eq!(result.bytes, 0);
    assert_eq!(std::fs::metadata(result.path).unwrap().len(), 0);
}

#[tokio::test]
async fn actual_body_cap_is_enforced_and_partial_is_not_published() {
    let lab = Lab::new();
    let options = lab.options("over");
    let (_owner, cancel) = watch::channel(false);
    assert!(matches!(
        download(options.clone(), cancel, |_| {}).await,
        Err(Error::SizeLimit)
    ));
    assert!(!options.job_dir.join("file.bin").exists());
    let store = Store::open(&options.job_dir).unwrap();
    assert!(store.is_unknown_length());
    assert!(store.committed_len() <= TOTAL as u64);
}

#[tokio::test]
async fn cancellation_keeps_durable_prefix_but_reopening_cannot_append_unknown_data() {
    let lab = Lab::new();
    let options = lab.options("hold");
    let (owner, cancel) = watch::channel(false);
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        download(options.clone(), cancel, |bytes| {
            if bytes >= PREFIX as u64 {
                owner.send_replace(true);
            }
        }),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(Error::Cancelled)));
    assert_eq!(
        std::fs::read(options.job_dir.join("payload.part")).unwrap(),
        body()[..PREFIX]
    );
    let (fresh, receiver) = watch::channel(false);
    assert!(matches!(
        download(options.clone(), receiver, |_| {}).await,
        Err(Error::ResumeUnsupported)
    ));
    assert_eq!(lab.count.load(Ordering::Relaxed), 1);
    assert!(!options.job_dir.join("file.bin").exists());
    drop(fresh);
}

#[tokio::test]
#[ignore = "Optional 64 MiB bounded streaming workload; not a long-duration qualification"]
async fn bounded_64_mib_chunked_workload() {
    let lab = Lab::new();
    let mut options = lab.options("soak");
    options.max_download_bytes = 64 * 1024 * 1024;
    options.checkpoint_bytes = 1024 * 1024;
    let block = body();
    let mut expected = Sha256::new();
    for _ in 0..4096 {
        expected.update(&block);
    }
    let digest: [u8; 32] = expected.finalize().into();
    options.expected_sha256 = Some(digest);
    let (_owner, cancel) = watch::channel(false);
    let result = tokio::time::timeout(Duration::from_secs(180), download(options, cancel, |_| {}))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.bytes, 64 * 1024 * 1024);
    let mut file = std::fs::File::open(result.path).unwrap();
    let mut buffer = [0u8; 64 * 1024];
    let mut actual = Sha256::new();
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        actual.update(&buffer[..read]);
    }
    assert_eq!(<[u8; 32]>::from(actual.finalize()), digest);
}
