use download_engine::{
    manager::{Manager, State},
    Options,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use transfer_store::Store;

const PREFIX: usize = 4096;
const TOTAL: usize = 16384;
fn body() -> Vec<u8> {
    (0..TOTAL).map(|i| (i % 251) as u8).collect()
}
struct Lab {
    root: PathBuf,
    url: String,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Lab {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fhd-manager-{}-{}",
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
        let requests = Arc::new(AtomicUsize::new(0));
        let flag = stop.clone();
        let count = requests.clone();
        let worker = thread::spawn(move || {
            let mut connections = Vec::new();
            while !flag.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let flag = flag.clone();
                        let count = count.clone();
                        connections.push(thread::spawn(move || serve(socket, flag, count)));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("fixture accept: {e}"),
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
            requests,
            worker: Some(worker),
        }
    }
    fn options(&self, name: &str) -> Options {
        Options {
            url: format!("{}/{}", self.url, name),
            job_dir: self.root.join(name),
            output_name: "file.bin".into(),
            expected_sha256: None,
            allow_http: true,
            checkpoint_bytes: PREFIX as u64,
            max_download_bytes: TOTAL as u64,
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
fn serve(mut socket: TcpStream, stop: Arc<AtomicBool>, requests: Arc<AtomicUsize>) {
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = Vec::new();
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
    requests.fetch_add(1, Ordering::AcqRel);
    let text = String::from_utf8(request).unwrap().to_ascii_lowercase();
    let data = body();
    if text.contains("range: bytes=") {
        assert!(text.contains("range: bytes=4096-16383"));
        assert!(text.contains("if-range: \"manager-v1\""));
        write!(socket,"HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {PREFIX}-{}/{TOTAL}\r\nETag: \"manager-v1\"\r\nConnection: close\r\n\r\n",TOTAL-PREFIX,TOTAL-1).unwrap();
        let _ = socket.write_all(&data[PREFIX..]);
    } else {
        write!(socket,"HTTP/1.1 200 OK\r\nContent-Length: {TOTAL}\r\nETag: \"manager-v1\"\r\nConnection: close\r\n\r\n").unwrap();
        let _ = socket.write_all(&data[..PREFIX]);
        // Never finish first response: only cancellation can release the worker.
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
    }
}
async fn wait_for(
    receiver: &mut tokio::sync::watch::Receiver<Vec<download_engine::manager::JobSnapshot>>,
    predicate: impl Fn(&[download_engine::manager::JobSnapshot]) -> bool,
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if predicate(&receiver.borrow()) {
                return;
            }
            receiver
                .changed()
                .await
                .expect("manager unexpectedly stopped");
        }
    })
    .await
    .expect("manager state deadline");
}

#[tokio::test]
async fn fifo_pause_releases_slot_and_resume_preserves_bytes() {
    let lab = Lab::new();
    let manager = Manager::start(1, 8).unwrap();
    let mut updates = manager.subscribe();
    let a = manager.enqueue(lab.options("a")).await.unwrap();
    let b = manager.enqueue(lab.options("b")).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == a && j.committed_bytes == PREFIX as u64)
    })
    .await;
    assert_eq!(lab.requests.load(Ordering::Acquire), 1);
    assert!(updates
        .borrow()
        .iter()
        .any(|j| j.id == b && j.state == State::Queued));
    manager.pause(a).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter().any(|j| j.id == a && j.state == State::Paused)
            && jobs
                .iter()
                .any(|j| j.id == b && j.committed_bytes == PREFIX as u64)
    })
    .await;
    assert_eq!(
        Store::open(&lab.root.join("a")).unwrap().committed_len(),
        PREFIX as u64
    );
    assert!(!lab.root.join("a/file.bin").exists());
    manager.pause(b).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter().any(|j| j.id == b && j.state == State::Paused)
    })
    .await;
    manager.resume(a).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == a && j.state == State::Completed)
    })
    .await;
    assert!(updates
        .borrow()
        .iter()
        .any(|j| j.id == b && j.state == State::Paused));
    assert_eq!(std::fs::read(lab.root.join("a/file.bin")).unwrap(), body());
    manager.resume(b).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter().all(|j| j.state == State::Completed)
    })
    .await;
    manager.shutdown().await.unwrap();
    assert_eq!(std::fs::read(lab.root.join("b/file.bin")).unwrap(), body());
}

#[tokio::test]
async fn shutdown_drains_workers_and_never_starts_queued_job() {
    let lab = Lab::new();
    let manager = Manager::start(1, 2).unwrap();
    let mut updates = manager.subscribe();
    let a = manager.enqueue(lab.options("a")).await.unwrap();
    manager.enqueue(lab.options("b")).await.unwrap();
    assert!(manager.enqueue(lab.options("c")).await.is_err());
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == a && j.committed_bytes == PREFIX as u64)
    })
    .await;
    manager.shutdown().await.unwrap();
    assert_eq!(lab.requests.load(Ordering::Acquire), 1);
    assert!(!lab.root.join("b").exists());
    assert_eq!(
        Store::open(&lab.root.join("a")).unwrap().committed_len(),
        PREFIX as u64
    );
}

#[tokio::test]
async fn dropping_owner_drains_and_releases_store_lock() {
    let lab = Lab::new();
    let manager = Manager::start(1, 2).unwrap();
    let mut updates = manager.subscribe();
    let a = manager.enqueue(lab.options("a")).await.unwrap();
    assert!(manager.enqueue(lab.options("a")).await.is_err());
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == a && j.committed_bytes == PREFIX as u64)
    })
    .await;
    drop(manager);
    tokio::time::timeout(Duration::from_secs(10), async {
        while updates.changed().await.is_ok() {}
    })
    .await
    .unwrap();
    assert_eq!(
        Store::open(&lab.root.join("a")).unwrap().committed_len(),
        PREFIX as u64
    );
    assert!(!lab.root.join("a/file.bin").exists());
}

#[tokio::test]
async fn two_slots_run_two_jobs_while_third_stays_queued() {
    let lab = Lab::new();
    let manager = Manager::start(2, 3).unwrap();
    let mut updates = manager.subscribe();
    let a = manager.enqueue(lab.options("a")).await.unwrap();
    let b = manager.enqueue(lab.options("b")).await.unwrap();
    let c = manager.enqueue(lab.options("c")).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .filter(|j| (j.id == a || j.id == b) && j.committed_bytes == PREFIX as u64)
            .count()
            == 2
    })
    .await;
    assert_eq!(lab.requests.load(Ordering::Acquire), 2);
    assert!(updates
        .borrow()
        .iter()
        .any(|j| j.id == c && j.state == State::Queued));
    manager.shutdown().await.unwrap();
    assert!(!lab.root.join("c").exists());
    assert_eq!(
        Store::open(&lab.root.join("a")).unwrap().committed_len(),
        PREFIX as u64
    );
    assert_eq!(
        Store::open(&lab.root.join("b")).unwrap().committed_len(),
        PREFIX as u64
    );
}

#[tokio::test]
async fn pausing_queued_job_prevents_network_until_explicit_resume() {
    let lab = Lab::new();
    let manager = Manager::start(1, 3).unwrap();
    let mut updates = manager.subscribe();
    let a = manager.enqueue(lab.options("a")).await.unwrap();
    let b = manager.enqueue(lab.options("b")).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == a && j.committed_bytes == PREFIX as u64)
    })
    .await;
    manager.pause(b).await.unwrap();
    manager.pause(a).await.unwrap();
    assert_eq!(lab.requests.load(Ordering::Acquire), 1);
    assert!(!lab.root.join("b").exists());
    manager.resume(b).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == b && j.committed_bytes == PREFIX as u64)
    })
    .await;
    assert_eq!(lab.requests.load(Ordering::Acquire), 2);
    manager.shutdown().await.unwrap();
}

#[tokio::test]
async fn saturated_origin_does_not_block_other_origin_and_keeps_its_limit() {
    let first = Lab::new();
    let second = Lab::new();
    let manager = Manager::start_with_limits(3, 8, 1).unwrap();
    let mut updates = manager.subscribe();
    let a = manager.enqueue(first.options("a")).await.unwrap();
    let b = manager
        .enqueue_with_priority(first.options("b"), download_engine::manager::Priority::High)
        .await
        .unwrap();
    let c = manager
        .enqueue_with_priority(second.options("c"), download_engine::manager::Priority::Low)
        .await
        .unwrap();
    let d = manager.enqueue(second.options("d")).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .filter(|j| (j.id == a || j.id == c) && j.committed_bytes == PREFIX as u64)
            .count()
            == 2
    })
    .await;
    assert_eq!(first.requests.load(Ordering::Acquire), 1);
    assert_eq!(second.requests.load(Ordering::Acquire), 1);
    assert!(updates
        .borrow()
        .iter()
        .any(|j| j.id == b && j.state == State::Queued));
    assert!(updates
        .borrow()
        .iter()
        .any(|j| j.id == d && j.state == State::Queued));
    manager.pause(a).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == b && j.committed_bytes == PREFIX as u64)
    })
    .await;
    assert_eq!(first.requests.load(Ordering::Acquire), 2);
    assert_eq!(second.requests.load(Ordering::Acquire), 1);
    assert_eq!(
        Store::open(&first.root.join("a")).unwrap().committed_len(),
        PREFIX as u64
    );
    manager.shutdown().await.unwrap();
}

#[tokio::test]
async fn priorities_pick_highest_waiting_without_interrupting_running_job() {
    use download_engine::manager::Priority;
    let lab = Lab::new();
    let manager = Manager::start_with_limits(1, 5, 1).unwrap();
    let mut updates = manager.subscribe();
    let gate = manager.enqueue(lab.options("gate")).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == gate && j.committed_bytes == PREFIX as u64)
    })
    .await;
    let low = manager
        .enqueue_with_priority(lab.options("low"), Priority::Low)
        .await
        .unwrap();
    let normal = manager.enqueue(lab.options("normal")).await.unwrap();
    let high = manager
        .enqueue_with_priority(lab.options("high"), Priority::High)
        .await
        .unwrap();
    assert_eq!(lab.requests.load(Ordering::Acquire), 1);
    assert!(updates
        .borrow()
        .iter()
        .any(|j| j.id == gate && j.state == State::Running));
    manager.pause(gate).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == high && j.committed_bytes == PREFIX as u64)
    })
    .await;
    assert!(updates
        .borrow()
        .iter()
        .any(|j| j.id == normal && j.state == State::Queued));
    assert!(updates
        .borrow()
        .iter()
        .any(|j| j.id == low && j.state == State::Queued));
    manager.pause(high).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == normal && j.committed_bytes == PREFIX as u64)
    })
    .await;
    manager.pause(normal).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == low && j.committed_bytes == PREFIX as u64)
    })
    .await;
    manager.shutdown().await.unwrap();
}

#[tokio::test]
async fn changing_queued_priority_keeps_equal_priority_fifo_and_rejects_running_change() {
    use download_engine::manager::Priority;
    let lab = Lab::new();
    let manager = Manager::start_with_limits(1, 4, 1).unwrap();
    let mut updates = manager.subscribe();
    let gate = manager.enqueue(lab.options("gate")).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == gate && j.committed_bytes == PREFIX as u64)
    })
    .await;
    let first = manager
        .enqueue_with_priority(lab.options("first"), Priority::Low)
        .await
        .unwrap();
    let second = manager
        .enqueue_with_priority(lab.options("second"), Priority::High)
        .await
        .unwrap();
    manager.set_priority(first, Priority::High).await.unwrap();
    assert!(manager.set_priority(gate, Priority::Low).await.is_err());
    assert!(updates
        .borrow()
        .iter()
        .any(|j| j.id == first && j.priority == Priority::High));
    manager.pause(gate).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == first && j.committed_bytes == PREFIX as u64)
    })
    .await;
    assert!(updates
        .borrow()
        .iter()
        .any(|j| j.id == second && j.state == State::Queued));
    manager.pause(first).await.unwrap();
    wait_for(&mut updates, |jobs| {
        jobs.iter()
            .any(|j| j.id == second && j.committed_bytes == PREFIX as u64)
    })
    .await;
    manager.shutdown().await.unwrap();
}
