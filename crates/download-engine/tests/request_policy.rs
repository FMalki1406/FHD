use download_engine::{download, Error, Options, RequestPolicy};
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
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Server {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn new(redirect: Option<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
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
                    assert!(bytes.len() < 20000);
                }
                let text = String::from_utf8(bytes).unwrap().to_ascii_lowercase();
                let start = text.starts_with("get /start ");
                seen.lock().unwrap().push(text);
                if let (true, Some(location)) = (start, redirect.as_ref()) {
                    let _=write!(socket,"HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nSet-Cookie: injected=SERVER\r\nConnection: close\r\n\r\n",location);
                } else {
                    let _=write!(socket,"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nETag: \"request-v1\"\r\nConnection: close\r\n\r\nabc");
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
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
struct Job(PathBuf);
impl Job {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "fhd-request-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn options(&self, url: String, origins: Vec<String>) -> Options {
        Options {
            url,
            job_dir: self.0.join("job"),
            output_name: "result.bin".into(),
            expected_sha256: None,
            allow_http: true,
            checkpoint_bytes: 1,
            max_download_bytes: 1024,
            bytes_per_second: None,
            parallel_connections: 1,
            request_policy: RequestPolicy::new(
                Some("Bearer PRIVATE".into()),
                Some("session=SECRET".into()),
                origins,
            )
            .unwrap(),
            refresh_from: None,
        }
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[tokio::test]
async fn explicit_credentials_are_sent_to_initial_origin() {
    let server = Server::new(None);
    let job = Job::new();
    let (_owner, cancel) = watch::channel(false);
    let result = download(
        job.options(format!("{}/file", server.url), vec![]),
        cancel,
        |_| {},
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(result.path).unwrap(), b"abc");
    let seen = server.requests.lock().unwrap();
    assert!(seen[0].contains("authorization: bearer private\r\n"));
    assert!(seen[0].contains("cookie: session=secret\r\n"));
}
#[tokio::test]
async fn same_origin_redirect_keeps_explicit_credentials_but_ignores_set_cookie() {
    let server = Server::new(Some("/file".into()));
    let job = Job::new();
    let (_owner, cancel) = watch::channel(false);
    download(
        job.options(format!("{}/start", server.url), vec![]),
        cancel,
        |_| {},
    )
    .await
    .unwrap();
    let seen = server.requests.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(seen[1].contains("authorization: bearer private\r\n"));
    assert!(seen[1].contains("cookie: session=secret\r\n"));
    assert!(!seen[1].contains("injected="));
}
#[tokio::test]
async fn explicitly_allowed_cross_origin_redirect_strips_credentials() {
    let destination = Server::new(None);
    let source = Server::new(Some(format!("{}/file", destination.url)));
    let job = Job::new();
    let (_owner, cancel) = watch::channel(false);
    download(
        job.options(
            format!("{}/start", source.url),
            vec![destination.url.clone()],
        ),
        cancel,
        |_| {},
    )
    .await
    .unwrap();
    let origin = source.requests.lock().unwrap();
    assert!(origin[0].contains("authorization:"));
    drop(origin);
    let seen = destination.requests.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(!seen[0].contains("authorization:"));
    assert!(!seen[0].contains("cookie:"));
    assert!(!seen[0].contains("referer:"));
}
#[tokio::test]
async fn unapproved_cross_origin_redirect_never_contacts_destination() {
    let destination = Server::new(None);
    let source = Server::new(Some(format!("{}/file", destination.url)));
    let job = Job::new();
    let (_owner, cancel) = watch::channel(false);
    assert_eq!(
        download(
            job.options(format!("{}/start", source.url), vec![]),
            cancel,
            |_| {}
        )
        .await
        .unwrap_err(),
        Error::RedirectOriginChange
    );
    assert!(destination.requests.lock().unwrap().is_empty());
    assert!(!job.0.join("job").exists());
}
