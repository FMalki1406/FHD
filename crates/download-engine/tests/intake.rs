#![cfg(windows)]
use download_engine::{
    intake::Inbox,
    manager::{Config, Manager, ManagerError, State},
    Options,
};
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
struct Lab {
    root: PathBuf,
    url: String,
    stop: Arc<AtomicBool>,
    count: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Lab {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "fhd-intake-{}-{}-{}",
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
        let seen = count.clone();
        let worker = thread::spawn(move || {
            let mut handlers = vec![];
            while !flag.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        seen.fetch_add(1, Ordering::AcqRel);
                        let end = flag.clone();
                        handlers.push(thread::spawn(move||{socket.set_nonblocking(false).unwrap();socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();socket.set_write_timeout(Some(Duration::from_secs(2))).unwrap();let mut request=vec![];while !request.ends_with(b"\r\n\r\n")&&!end.load(Ordering::Acquire){let mut byte=[0];match socket.read(&mut byte){Ok(1)=>request.push(byte[0]),_=>return}if request.len()>20000{return;}}let _=socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nETag: \"hold\"\r\nConnection: close\r\n\r\nx");while !end.load(Ordering::Acquire){thread::sleep(Duration::from_millis(10));}}));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("accept {e}"),
                }
            }
            for h in handlers {
                h.join().unwrap();
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
    fn hold(&self) -> Options {
        Options {
            url: format!("{}/hold", self.url),
            job_dir: self.root.join("hold"),
            output_name: "hold.bin".into(),
            expected_sha256: None,
            allow_http: true,
            checkpoint_bytes: 1,
            max_download_bytes: 8192,
            bytes_per_second: None,
            parallel_connections: 1,
            request_policy: Default::default(),
            refresh_from: None,
        }
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.worker.take().unwrap().join();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
#[tokio::test]
async fn approved_proposal_replays_after_restart_without_another_transfer() {
    let lab = Lab::new();
    let queue = lab.root.join("queue");
    let settings = Config {
        max_active: 1,
        max_per_origin: 1,
        ..Config::default()
    };
    let manager = Manager::open(queue.clone(), settings).await.unwrap();
    let mut changes = manager.subscribe();
    let blocker = manager.enqueue(lab.hold()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if changes
                .borrow()
                .iter()
                .any(|j| j.id == blocker && j.state == State::Running)
                && lab.count.load(Ordering::Acquire) == 1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let url = lab.url.replacen("http:", "https:", 1) + "/proposed?token=private";
    let mut inbox = Inbox::for_source("chrome-profile-A".into()).unwrap();
    let proposal = inbox.propose("request-1".into(), url.clone()).unwrap();
    let job_dir = lab.root.join("approved");
    let accepted = inbox
        .approve(&manager, proposal, job_dir.clone(), "file.bin".into())
        .await
        .unwrap();
    assert!(inbox.preview_url(proposal).is_none());
    assert_eq!(lab.count.load(Ordering::Acquire), 1);
    manager.shutdown().await.unwrap();
    let reopened = Manager::open(queue, Config::default()).await.unwrap();
    changes = reopened.subscribe();
    let mut inbox = Inbox::for_source("chrome-profile-A".into()).unwrap();
    let proposal = inbox.propose("request-1".into(), url.clone()).unwrap();
    assert_eq!(
        inbox
            .approve(&reopened, proposal, job_dir.clone(), "file.bin".into())
            .await
            .unwrap(),
        accepted
    );
    assert_eq!(changes.borrow().len(), 2);
    assert!(changes.borrow().iter().all(|j| j.state == State::Paused));
    assert_eq!(lab.count.load(Ordering::Acquire), 1);
    let changed = inbox.propose("request-1".into(), url).unwrap();
    assert_eq!(
        inbox
            .approve(&reopened, changed, job_dir.clone(), "different.bin".into())
            .await,
        Err(ManagerError::IdempotencyConflict)
    );
    assert!(inbox.preview_url(changed).is_some());
    reopened.forget(accepted).await.unwrap();
    assert_eq!(
        inbox
            .approve(&reopened, changed, job_dir, "file.bin".into())
            .await,
        Err(ManagerError::PreviouslyRemoved)
    );
    reopened.shutdown().await.unwrap();
}
#[tokio::test]
async fn nondurable_manager_cannot_issue_a_handoff_acknowledgement() {
    let lab = Lab::new();
    let manager = Manager::start(1, 4).unwrap();
    let mut inbox = Inbox::default();
    let proposal = inbox
        .propose("request-1".into(), lab.url.replacen("http:", "https:", 1))
        .unwrap();
    assert_eq!(
        inbox
            .approve(
                &manager,
                proposal,
                lab.root.join("never"),
                "file.bin".into()
            )
            .await,
        Err(ManagerError::NotDurable)
    );
    assert!(inbox.preview_url(proposal).is_some());
    assert!(!lab.root.join("never").exists());
    assert_eq!(lab.count.load(Ordering::Acquire), 0);
    manager.shutdown().await.unwrap();
}
