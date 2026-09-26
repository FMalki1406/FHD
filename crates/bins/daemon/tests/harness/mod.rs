//! Shared test scaffolding: a local HTTP server, a temporary state directory, and
//! the small helpers both end-to-end suites need. Not a fake of anything -- every
//! test that uses it runs the real adapters.
#![allow(dead_code)]
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

/// Whether this build can publish on this platform.
///
/// Windows and Linux: an NT call there, `linkat` through the descriptor's
/// procfs entry here. macOS has no measured mechanism and refuses, rather than
/// falling back to linking by path, which is the behaviour being replaced.
///
/// **Green tests are not a support claim.** What keeps this constant honest is
/// the suites that read it: set it true where publication does not work and
/// `published_as_declared` fails for want of a published file; set it false
/// where it does and the refusal branch fails instead. So a wrong value is a
/// red run either way.
///
/// It used to credit that guarantee to a test named
/// `publication_support_on_this_platform_is_declared`, **which has never
/// existed in this repository** -- a comment describing a control that was
/// never written, which an independent review found by grepping for it. The
/// guarantee is real; the attribution was not.
pub const PUBLISHES: bool = cfg!(any(windows, target_os = "linux"));

/// Whether a part beside `destination` holds exactly `body`.
///
/// The part lives in `.fhd-parts` next to the destination rather than under
/// the state directory, which is what lets a download land on a volume the
/// engine does not live on. Contents rather than length, because a part is
/// created at its full size before anything is fetched.
pub fn kept_beside_matches(destination: &Path, body: &[u8]) -> bool {
    fn walk(path: &Path, body: &[u8]) -> bool {
        let Ok(entries) = std::fs::read_dir(path) else {
            return false;
        };
        entries.flatten().any(|entry| {
            let path = entry.path();
            match entry.metadata() {
                Ok(metadata) if metadata.is_dir() => walk(&path, body),
                Ok(metadata) if metadata.len() == body.len() as u64 => std::fs::read(&path)
                    .map(|held| held == body)
                    .unwrap_or(false),
                _ => false,
            }
        })
    }
    destination
        .parent()
        .is_some_and(|folder| walk(&folder.join(".fhd-parts"), body))
}

/// The declared outcome of a *program* run that fetched everything.
///
/// Returns `true` where this platform publishes, after asserting the run exited
/// zero and left the destination holding `body`. Where it does not publish, it
/// asserts the contract the program actually offers -- the run reached
/// publication and stopped there, nothing was published, and the bytes are
/// still on disk beside the destination -- and returns `false`, so the caller
/// stops before looking at a file this platform never creates.
///
/// This is not a way of switching a test off: both branches assert, and neither
/// accepts "something went wrong". The exit code is pinned to 1, which is what
/// a job settling short of `Completed` produces; a binary that could not parse
/// its arguments or open its state directory exits 2 and would fail here.
#[track_caller]
pub fn program_published(
    code: Option<i32>,
    destination: &Path,
    body: &[u8],
    out: &str,
    err: &str,
) -> bool {
    if PUBLISHES {
        assert_eq!(code, Some(0), "stdout: {out}\nstderr: {err}");
        let published = std::fs::read(destination).expect("the file is where it was asked for");
        assert_eq!(published, body, "the published bytes are the served bytes");
        return true;
    }
    assert_eq!(
        code,
        Some(1),
        "a refused publication must stop the job, not fail the program some other \
         way.\nstdout: {out}\nstderr: {err}"
    );
    // The state the engine declares for it, printed by the program itself. "Not
    // zero" alone is satisfied by a run that never reached the transport.
    assert!(
        out.contains("stopped in NeedsAction"),
        "the run did not stop the way a refused publication stops.\nstdout: \
         {out}\nstderr: {err}"
    );
    assert!(
        !destination.exists(),
        "a refused publication created the destination"
    );
    // Contents rather than length: a part is created at its full size before a
    // byte arrives, so only the bytes prove the transfer finished and that what
    // stopped it was publication.
    assert!(
        kept_beside_matches(destination, body),
        "no part beside the destination holds the bytes that were downloaded"
    );
    false
}

/// A job's line from a `list` answer -- `<job> <state> <durable>/<total>
/// <reason>` -- read as its state and reason once the job is at rest.
///
/// `None` while the job is still moving. Any resting state is an answer, so a
/// caller polling this fails on a wrong state at once instead of waiting out
/// its deadline, and never has to accept "whatever turned up".
pub fn resting(line: &str) -> Option<(&str, Option<&str>)> {
    let mut fields = line.split_whitespace();
    let (_job, state, _progress) = (fields.next()?, fields.next()?, fields.next());
    matches!(state, "Completed" | "NeedsAction" | "Failed" | "Cancelled")
        .then(|| (state, fields.next()))
}

/// Assert a session that did not publish settled in one of the states the
/// engine declares for it, rather than merely failing somehow.
///
/// F2 in the re-review of 11dd794: "not published" plus "no destination" is
/// satisfied by any error at all, including a transport failure that fetched
/// nothing. A test that accepts those is not measuring a publication refusal.
///
/// `allowed` is the set of resting states the caller's race can legitimately
/// produce. When the state is `NeedsAction`, the reason must be the storage one
/// -- that is what a refused publication looks like, and it is what separates
/// it from a job that stopped for some other cause.
#[track_caller]
pub fn settled_without_publishing(
    outcome: &Result<fhd_runtime::coordinator::SessionEnd, fhd_daemon::EngineError>,
    reason: Option<fhd_domain::StopReason>,
    allowed: &[fhd_domain::JobState],
) {
    use fhd_runtime::coordinator::SessionEnd;
    let Ok(SessionEnd::Settled(state)) = outcome else {
        panic!("expected a settled session without publication, got {outcome:?}");
    };
    assert!(
        allowed.contains(state),
        "settled in {state:?}, which is not one of the declared outcomes {allowed:?}"
    );
    if *state == fhd_domain::JobState::NeedsAction {
        assert_eq!(
            reason,
            Some(fhd_domain::StopReason::Storage),
            "the job needs action for some reason other than publication being refused"
        );
    }
}

pub struct Directory(pub PathBuf);
impl Directory {
    /// The engine's own tree. Downloads land beside it, never inside it.
    pub fn engine(&self) -> PathBuf {
        self.0.join("engine")
    }
}
impl Directory {
    /// A base directory nobody outside this account can rename.
    ///
    /// The shared temporary directory will not do. Measured on Windows 11, it is
    /// renameable by packaged-application principals, and on a data volume every
    /// ancestor grants Authenticated Users enough to move a directory aside -- so
    /// the engine refuses to put its database and part files there, which is the
    /// point. A real installation makes a directory of its own under the user's
    /// local application data, and so does this.
    fn base() -> PathBuf {
        #[cfg(windows)]
        let root = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        #[cfg(not(windows))]
        let root = std::env::temp_dir();
        let base = root.join("fhd-tests");
        // Created with its permissions rather than given them afterwards, as an
        // installer would. `create_dir_all` followed by a repair is what this
        // used to do, and on Unix the repair did nothing at all -- so under a
        // umask of 002 the base came out group-writable and a macOS runner
        // refused its own test directory, correctly. A repair would also leave
        // the window it was meant to close.
        //
        // A directory left over from an earlier run is not touched: this reports
        // that it already existed and says nothing about its permissions, which
        // is the same treatment the engine gives a directory it finds.
        let _ = fhd_platform::create_protected_directory(&base);
        std::fs::canonicalize(&base).unwrap_or(base)
    }

    pub fn new(label: &str) -> Self {
        let base = Self::base();
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

pub fn content(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 253) as u8).collect()
}

/// Serves ranges of `body` with a strong validator. `cut_after` closes the connection
/// mid-body for the first `failures` range requests, to force retries and resumes.
pub fn serve(body: Vec<u8>, failures: usize) -> (u16, Arc<AtomicU64>) {
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
/// A server that delivers the body slowly, and counts the bytes it delivered.
///
/// The pause test needs two things the ordinary server cannot give. It needs
/// the pause to land while the transfer is genuinely part-way -- the request
/// counter rises before a byte is sent, so triggering on it can pause before
/// any progress exists, or after the whole file has already gone out, and then
/// the test measures a race rather than a resume. And it needs to know how many
/// bytes were actually sent, which is the only way to tell a resume that used
/// the saved progress from one that fetched the file again.
///
/// Slow rather than blocking: an earlier version held the body open until the
/// test released it, and hung. A server that always makes progress cannot
/// deadlock with the client no matter how the pause lands.
/// Decrements the in-flight count however its handler leaves -- returning
/// early on a broken pipe included, since a count that only falls on the happy
/// path is worse than none.
struct Leaving(Arc<AtomicU64>);
impl Drop for Leaving {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct Slow {
    pub port: u16,
    pub requests: Arc<AtomicU64>,
    pub delivered: Arc<AtomicU64>,
    /// Responses this server could not finish writing.
    ///
    /// CI read as "the resume fetched 147461 of 2097152 bytes" and as a job
    /// stopped for a `Network` reason, with nothing to say whether the client
    /// gave up or the server did. A test server that fails silently turns its
    /// own faults into the engine's.
    pub broken: Arc<AtomicU64>,
    /// Responses being written right now.
    ///
    /// `delivered` counts every byte this server ever sent, across every run of
    /// the engine that used it. A caller measuring one run has to know when the
    /// previous one's connections have actually finished, or their last chunks
    /// are charged to the run being measured -- which is what happened: a
    /// resume was billed 32769 bytes more than the file, two chunks and a probe
    /// left over from before a pause. `quiet` is how a caller waits for that.
    pub in_flight: Arc<AtomicU64>,
}

impl Slow {
    /// Waits, bounded, until nothing is being written and nothing more arrives.
    ///
    /// The bound is the point: an unbounded wait would hide a server that never
    /// settles, and raising a byte allowance to cover the overlap would hide
    /// the overlap. This makes the measurement that follows belong to one run.
    pub async fn quiet(&self, within: std::time::Duration) {
        let deadline = std::time::Instant::now() + within;
        loop {
            let idle = self.in_flight.load(Ordering::Relaxed) == 0;
            let seen = self.delivered.load(Ordering::Relaxed);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            // Asked again at the moment of deciding, not only before waiting.
            // A connection accepted during the wait left the first reading
            // stale, and the barrier returned on it with one live after all --
            // demonstrated in the review of 2f5cb33. Quiet before and quiet
            // after, with nothing delivered in between.
            if idle
                && self.in_flight.load(Ordering::Relaxed) == 0
                && self.delivered.load(Ordering::Relaxed) == seen
            {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the server never went quiet: {} responses still being written, \
                 {} bytes delivered",
                self.in_flight.load(Ordering::Relaxed),
                self.delivered.load(Ordering::Relaxed)
            );
        }
    }
}

pub fn serve_slowly(body: Vec<u8>, chunk: usize, pause: std::time::Duration) -> Slow {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(AtomicU64::new(0));
    let delivered = Arc::new(AtomicU64::new(0));
    let broken = Arc::new(AtomicU64::new(0));
    let in_flight = Arc::new(AtomicU64::new(0));
    let body = Arc::new(body);
    let (counter, bytes, faults, busy) = (
        requests.clone(),
        delivered.clone(),
        broken.clone(),
        in_flight.clone(),
    );
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let (body, counter, bytes, faults, busy) = (
                body.clone(),
                counter.clone(),
                bytes.clone(),
                faults.clone(),
                busy.clone(),
            );
            // Counted from acceptance, not from the request being complete.
            //
            // It used to rise after `read_request` returned, which left a
            // connection that had been accepted but had not finished sending
            // its headers invisible: `quiet` could return while one was
            // pending, and the bytes it went on to deliver were charged to
            // whatever the caller measured next. Review of 7dc810a demonstrated
            // exactly that. The guard is made here and moved into the handler,
            // so the count falls however the handler leaves -- and also if the
            // thread never starts.
            busy.fetch_add(1, Ordering::Relaxed);
            let leaving = Leaving(busy.clone());
            std::thread::spawn(move || {
                let _leaving = leaving;
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
                    // `Connection: close`, because this server answers one
                    // request per connection and its thread then ends. Without
                    // it the response is HTTP/1.1 with a content length, which
                    // invites the client to keep the connection and send its
                    // next request on a socket that is about to close -- a
                    // truncated transfer the engine can only report as a
                    // network fault, which is what CI reported. Delivering
                    // slowly holds the connection open far longer than `serve`
                    // does, which is why the window opened here and not there.
                    "HTTP/1.1 206 Partial Content\r\nETag: \"v1\"\r\nAccept-Ranges: bytes\r\n\
                 Connection: close\r\nContent-Range: bytes {start}-{end}/{}\r\n\
                 Content-Length: {}\r\n\r\n",
                    body.len(),
                    slice.len()
                );
                if stream.write_all(head.as_bytes()).is_err() {
                    faults.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                for piece in slice.chunks(chunk.max(1)) {
                    if stream.write_all(piece).is_err() || stream.flush().is_err() {
                        faults.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    bytes.fetch_add(piece.len() as u64, Ordering::Relaxed);
                    std::thread::sleep(pause);
                }
            });
        }
    });
    Slow {
        port,
        requests,
        delivered,
        broken,
        in_flight,
    }
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

pub fn part_bytes(state: &Directory) -> u64 {
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
    walk(&state.engine().join("parts"))
}
pub fn expected_digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}
