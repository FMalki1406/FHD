//! The whole engine over real adapters: a local HTTP server, SQLite on disk and
//! real part files. No fakes anywhere in this path.
use fhd_daemon::{Engine, EngineConfig, EngineError, Intent, JobOutcome, Request};
use fhd_domain::{JobState, StopReason};
use fhd_runtime::coordinator::{Control, SessionEnd};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::mpsc;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Self {
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = base.join(format!(
            "fhd-e2e-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn content(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 253) as u8).collect()
}

/// Serves ranges of `body` with a strong validator. `cut_after` closes the connection
/// mid-body for the first `failures` range requests, to force retries and resumes.
fn serve(body: Vec<u8>, failures: usize) -> (u16, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = Arc::new(AtomicU64::new(0));
    let counter = served.clone();
    let body = Arc::new(body);
    let failures = Arc::new(AtomicU64::new(failures as u64));
    std::thread::spawn(move || {
        // A thread per connection: an idle keep-alive must not block the next request.
        while let Ok((mut stream, _)) = listener.accept() {
            let (body, failures, counter) = (body.clone(), failures.clone(), counter.clone());
            std::thread::spawn(move || {
                let request = read_request(&mut stream);
                counter.fetch_add(1, Ordering::Relaxed);
                let range = request
                    .lines()
                    .find_map(|line| line.strip_prefix("range: bytes="))
                    .map(|value| {
                        let value = value.trim();
                        let (start, end) = value.split_once('-').unwrap_or((value, ""));
                        let start: u64 = start.parse().unwrap_or(0);
                        let end: u64 = end.parse().unwrap_or(body.len() as u64 - 1);
                        (start, end.min(body.len() as u64 - 1))
                    });
                let (start, end) = range.unwrap_or((0, body.len() as u64 - 1));
                let slice = &body[start as usize..=end as usize];
                let head = format!(
                    "HTTP/1.1 206 Partial Content\r\nETag: \"v1\"\r\nAccept-Ranges: bytes\r\n\
                 Content-Range: bytes {start}-{end}/{}\r\nContent-Length: {}\r\n\r\n",
                    body.len(),
                    slice.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let failing = failures
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_ok();
                if failing && slice.len() > 8 {
                    // Half a body, then the connection dies.
                    let _ = stream.write_all(&slice[..slice.len() / 2]);
                    let _ = stream.flush();
                    return;
                }
                let _ = stream.write_all(slice);
                let _ = stream.flush();
            });
        }
    });
    (port, served)
}
fn read_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => request.push(byte[0]),
        }
    }
    String::from_utf8_lossy(&request).to_ascii_lowercase()
}

fn config(state: &Directory, destination: PathBuf, connections: usize) -> EngineConfig {
    EngineConfig {
        state_directory: state.0.clone(),
        destination,
        connections,
        engine_connections: connections.max(2),
        max_active: 2,
        expected_sha256: None,
        max_bytes: 64 * 1024 * 1024,
        allow_http: true,
        intent: Intent::Start,
    }
}
fn resuming(state: &Directory, destination: PathBuf, connections: usize) -> EngineConfig {
    EngineConfig {
        intent: Intent::Resume,
        ..config(state, destination, connections)
    }
}
/// Total size of everything still under the engine's parts directory.
fn part_bytes(state: &Directory) -> u64 {
    fn walk(path: &std::path::Path) -> u64 {
        let Ok(entries) = std::fs::read_dir(path) else {
            return 0;
        };
        entries
            .flatten()
            .map(|entry| match entry.metadata() {
                Ok(metadata) if metadata.is_dir() => walk(&entry.path()),
                // owner.lock and similar bookkeeping are not payload.
                Ok(metadata) if metadata.len() > 4096 => metadata.len(),
                _ => 0,
            })
            .sum()
    }
    walk(&state.0.join("parts"))
}
fn expected_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downloads_verifies_and_publishes_over_real_adapters() {
    let body = content(3 * 1024 * 1024 + 517);
    let (port, served) = serve(body.clone(), 0);
    let state = Directory::new("happy");
    let destination = state.0.join("result.bin");
    let url = format!("http://127.0.0.1:{port}/file");
    let mut settings = config(&state, destination.clone(), 4);
    settings.expected_sha256 = Some(expected_digest(&body));

    let engine = Engine::open(settings, &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert_eq!(
        engine.run(receiver).await.unwrap(),
        SessionEnd::Published(destination.clone())
    );
    assert_eq!(std::fs::read(&destination).unwrap(), body);
    assert_eq!(engine.state().await.unwrap(), JobState::Completed);
    // The part is released: its bytes live under the final name now.
    assert_eq!(part_bytes(&state), 0, "part file left behind");
    assert!(served.load(Ordering::Relaxed) > 1, "used several requests");

    // One owner at a time: release the state directory before reopening it.
    drop(engine);
    // The identical request replays to the same job; a different one would conflict.
    let mut same = config(&state, destination.clone(), 4);
    same.expected_sha256 = Some(expected_digest(&body));
    let (_control, receiver) = mpsc::channel(1);
    let engine = Engine::open(same, &url).await.unwrap();
    assert_eq!(
        engine.run(receiver).await.unwrap(),
        SessionEnd::Settled(JobState::Completed)
    );
    drop(engine);

    // A changed request is a different request: its own job, not a replay and not a
    // conflict. This one asks for a digest the file does not have.
    let mut different = config(&state, destination.clone(), 4);
    different.expected_sha256 = Some([9; 32]);
    let engine = Engine::open(different, &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert_eq!(
        engine.run(receiver).await.unwrap(),
        SessionEnd::Settled(JobState::NeedsAction)
    );
    assert_eq!(engine.reason().await.unwrap(), Some(StopReason::Integrity));
    // The file published by the first request is untouched.
    assert_eq!(std::fs::read(&destination).unwrap(), body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_connection_resumes_from_committed_bytes() {
    let body = content(6 * 1024 * 1024 + 41);
    // The first two range requests die half way through.
    let (port, _) = serve(body.clone(), 2);
    let state = Directory::new("resume");
    let destination = state.0.join("resumed.bin");
    let url = format!("http://127.0.0.1:{port}/file");

    // Each run settles once; a transient failure parks the job in RetryWait until
    // its deadline passes. Nothing here shortens that wait.
    let mut published = None;
    for _ in 0..12 {
        let engine = Engine::open(config(&state, destination.clone(), 2), &url)
            .await
            .unwrap();
        let (_control, receiver) = mpsc::channel(1);
        let outcome = engine.run(receiver).await.unwrap();
        drop(engine);
        match outcome {
            SessionEnd::Published(path) => {
                published = Some(path);
                break;
            }
            SessionEnd::Settled(state) => {
                assert!(
                    matches!(state, JobState::RetryWait | JobState::Queued),
                    "unexpected rest state {state:?}"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert_eq!(published, Some(destination.clone()));
    assert_eq!(std::fs::read(&destination).unwrap(), body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_expected_digest_never_publishes() {
    let body = content(512 * 1024);
    let (port, _) = serve(body.clone(), 0);
    let state = Directory::new("digest");
    let destination = state.0.join("never.bin");
    let url = format!("http://127.0.0.1:{port}/file");
    let mut settings = config(&state, destination.clone(), 2);
    settings.expected_sha256 = Some([0x5A; 32]);

    let engine = Engine::open(settings, &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert_eq!(
        engine.run(receiver).await.unwrap(),
        SessionEnd::Settled(JobState::NeedsAction)
    );
    assert!(!destination.exists(), "nothing is published unverified");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_occupied_destination_is_never_overwritten() {
    let body = content(256 * 1024);
    let (port, _) = serve(body.clone(), 0);
    let state = Directory::new("occupied");
    let destination = state.0.join("taken.bin");
    std::fs::write(&destination, b"someone else's file").unwrap();
    let url = format!("http://127.0.0.1:{port}/file");

    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert_eq!(
        engine.run(receiver).await.unwrap(),
        SessionEnd::Settled(JobState::NeedsAction)
    );
    assert_eq!(std::fs::read(&destination).unwrap(), b"someone else's file");
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(StopReason::Destination)
    );
    drop(engine);

    // Running again changes nothing by itself.
    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert!(engine.run(receiver).await.is_err(), "no automatic resume");
    drop(engine);

    // Once the operator frees the name, a resume publishes without refetching.
    std::fs::remove_file(&destination).unwrap();
    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert_eq!(
        engine.run(receiver).await.unwrap(),
        SessionEnd::Published(destination.clone())
    );
    assert_eq!(std::fs::read(&destination).unwrap(), body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pause_keeps_durable_progress_and_a_later_run_finishes() {
    let body = content(8 * 1024 * 1024);
    let (port, served) = serve(body.clone(), 0);
    let state = Directory::new("pause");
    let destination = state.0.join("paused.bin");
    let url = format!("http://127.0.0.1:{port}/file");

    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (control, receiver) = mpsc::channel(1);
    let run = engine.run(receiver);
    let pause = async {
        while served.load(Ordering::Relaxed) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        control.send(Control::Pause).await.unwrap();
    };
    let (outcome, ()) = tokio::join!(run, pause);
    // Pausing may lose a race with completion; both outcomes are legitimate.
    match outcome.unwrap() {
        SessionEnd::Published(path) => assert_eq!(path, destination),
        SessionEnd::Settled(state) => assert_eq!(state, JobState::Paused),
    }
    drop(engine);
    if !destination.exists() {
        // A stopped job stays stopped until the operator asks for it.
        let idle = Engine::open(config(&state, destination.clone(), 2), &url)
            .await
            .unwrap();
        let (_control, receiver) = mpsc::channel(1);
        assert!(idle.run(receiver).await.is_err(), "no automatic resume");
        drop(idle);
        let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
            .await
            .unwrap();
        let (_control, receiver) = mpsc::channel(1);
        let outcome = engine.run(receiver).await.unwrap();
        assert_eq!(
            outcome,
            SessionEnd::Published(destination.clone()),
            "reason: {:?}",
            engine.reason().await.unwrap()
        );
    }
    assert_eq!(std::fs::read(&destination).unwrap(), body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_destination_on_another_volume_is_refused_before_downloading() {
    let state = Directory::new("volume");
    let other = if cfg!(windows) {
        "Z:/elsewhere.bin"
    } else {
        "/proc/elsewhere.bin"
    };
    let settings = EngineConfig {
        destination: PathBuf::from(other),
        ..config(&state, state.0.join("unused.bin"), 2)
    };
    // Publication renames within one volume, so this is refused up front.
    assert!(Engine::open(settings, "http://127.0.0.1:1/file")
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_job_leaves_no_part_behind() {
    let body = content(4 * 1024 * 1024);
    let (port, served) = serve(body, 0);
    let state = Directory::new("cancel");
    let destination = state.0.join("cancelled.bin");
    let url = format!("http://127.0.0.1:{port}/file");
    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (control, receiver) = mpsc::channel(1);
    let run = engine.run(receiver);
    let cancel = async {
        while served.load(Ordering::Relaxed) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        control.send(Control::Cancel).await.unwrap();
    };
    let (outcome, ()) = tokio::join!(run, cancel);
    match outcome.unwrap() {
        SessionEnd::Settled(JobState::Cancelled) => {}
        // Publication can win the race; then the part is released the other way.
        SessionEnd::Published(_) => {}
        other => panic!("unexpected outcome {other:?}"),
    }
    assert_eq!(part_bytes(&state), 0, "cancelled work keeps nothing");
    assert!(!destination.exists() || std::fs::metadata(&destination).unwrap().len() > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_publish_reconciled_after_a_crash_leaves_no_part() {
    let body = content(2 * 1024 * 1024);
    let (port, _) = serve(body.clone(), 0);
    let state = Directory::new("reconcile");
    let destination = state.0.join("done.bin");
    let url = format!("http://127.0.0.1:{port}/file");

    // First run publishes and releases its part.
    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert_eq!(
        engine.run(receiver).await.unwrap(),
        SessionEnd::Published(destination.clone())
    );
    drop(engine);

    // A second request for the same bytes to the same name finds them already
    // there: it reconciles instead of republishing, and keeps no part either.
    let mut second = config(&state, destination.clone(), 2);
    second.max_bytes = 63 * 1024 * 1024;
    let engine = Engine::open(second, &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert_eq!(
        engine.run(receiver).await.unwrap(),
        SessionEnd::Published(destination.clone())
    );
    assert_eq!(std::fs::read(&destination).unwrap(), body);
    assert_eq!(part_bytes(&state), 0, "reconciled publish left a part");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn several_requests_share_one_engine_and_each_lands_in_its_own_file() {
    let first = content(2 * 1024 * 1024 + 11);
    let second = content(1024 * 1024 + 7);
    let (one, _) = serve(first.clone(), 0);
    let (two, _) = serve(second.clone(), 0);
    let state = Directory::new("several");
    let requests = vec![
        Request {
            url: format!("http://127.0.0.1:{one}/file"),
            destination: state.0.join("first.bin"),
            expected_sha256: Some(expected_digest(&first)),
            sensitive: false,
        },
        Request {
            url: format!("http://127.0.0.1:{two}/file"),
            destination: state.0.join("second.bin"),
            expected_sha256: Some(expected_digest(&second)),
            sensitive: false,
        },
    ];
    // One connection each and room for both: the two jobs genuinely overlap, each
    // writing its own part in the one directory the engine owns.
    let mut settings = config(&state, state.0.join("unused.bin"), 1);
    settings.engine_connections = 2;
    settings.max_active = 2;

    let engine = Engine::open_many(settings, requests.clone()).await.unwrap();
    let (_keep, commands) = mpsc::channel(4);
    let outcomes = engine.run_all(commands).await.unwrap();

    assert_eq!(outcomes.len(), 2);
    for ((index, outcome), request) in outcomes.into_iter().zip(&requests) {
        match outcome {
            JobOutcome::Published(path) => assert_eq!(path, request.destination, "job {index}"),
            JobOutcome::Settled(state, reason) => {
                panic!("job {index} stopped in {state:?} because {reason:?}")
            }
            other => panic!("job {index} ended as {other:?}"),
        }
    }
    assert_eq!(std::fs::read(state.0.join("first.bin")).unwrap(), first);
    assert_eq!(std::fs::read(state.0.join("second.bin")).unwrap(), second);
    // Both parts were released once their bytes reached their final names.
    assert_eq!(part_bytes(&state), 0, "part files left behind");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_later_run_continues_what_it_remembers_without_being_told_the_link() {
    let body = content(2 * 1024 * 1024 + 33);
    let (port, _) = serve(body.clone(), 0);
    let state = Directory::new("continue");
    let destination = state.0.join("remembered.bin");
    let url = format!("http://127.0.0.1:{port}/file");

    // First run: pause it, so there is unfinished work worth continuing.
    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (control, receiver) = mpsc::channel(1);
    let pause = async {
        tokio::time::sleep(Duration::from_millis(15)).await;
        control.send(Control::Pause).await.unwrap();
    };
    // Pausing may lose the race with a fast local server; either way the second run
    // is the one under test, and it is told nothing.
    let (outcome, ()) = tokio::join!(engine.run(receiver), pause);
    outcome.unwrap();
    drop(engine);

    // Second run knows nothing but the directory: no URL, no destination given.
    let mut settings = config(&state, state.0.clone(), 2);
    settings.intent = Intent::Resume;
    let engine = Engine::reopen(settings).await.unwrap();
    let (_keep, commands) = mpsc::channel(4);
    let outcomes = engine.run_all(commands).await.unwrap();
    assert_eq!(outcomes.len(), 1);
    match &outcomes[0].1 {
        JobOutcome::Published(path) => assert_eq!(path, &destination),
        // Already finished before the pause landed: the remembered job was still
        // found and settled, which is what continuing has to prove.
        JobOutcome::Settled(JobState::Completed, _) => {}
        other => panic!("continuing ended as {other:?}"),
    }
    assert_eq!(std::fs::read(&destination).unwrap(), body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sensitive_link_is_not_remembered_so_it_cannot_be_continued() {
    let body = content(64 * 1024);
    let (port, _) = serve(body, 0);
    let state = Directory::new("sensitive");
    let destination = state.0.join("secret.bin");
    let request = Request {
        url: format!("http://127.0.0.1:{port}/file"),
        destination,
        expected_sha256: None,
        sensitive: true,
    };
    let engine = Engine::open_many(config(&state, state.0.join("unused.bin"), 1), vec![request])
        .await
        .unwrap();
    let (_keep, commands) = mpsc::channel(4);
    engine.run_all(commands).await.unwrap();
    drop(engine);

    // The link was never written, so there is nothing here to continue with.
    let settings = config(&state, state.0.clone(), 1);
    assert!(
        matches!(
            Engine::reopen(settings).await,
            Err(EngineError::NothingToContinue)
        ),
        "a sensitive link must not survive the run that used it"
    );
}
