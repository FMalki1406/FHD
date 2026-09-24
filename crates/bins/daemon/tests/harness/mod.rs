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
/// Windows only today: the mechanism is an NT call, and no measured equivalent
/// exists yet for Linux or macOS. Publication refuses there rather than falling
/// back to linking by path, which is the behaviour being replaced.
///
/// **Green tests are not a support claim.** This constant is what the tests
/// below assert against, and `publication_support_on_this_platform_is_declared`
/// is what ties it to the engine's actual behaviour, so the two cannot drift
/// into a suite that passes while nothing works.
pub const PUBLISHES: bool = cfg!(windows);

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
