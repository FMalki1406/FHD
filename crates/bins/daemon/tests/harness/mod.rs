//! Shared test scaffolding: a local HTTP server, a temporary state directory, and
//! the small helpers both end-to-end suites need. Not a fake of anything -- every
//! test that uses it runs the real adapters.
#![allow(dead_code)]
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

pub struct Directory(pub PathBuf);
impl Directory {
    /// The engine's own tree. Downloads land beside it, never inside it.
    pub fn engine(&self) -> PathBuf {
        self.0.join("engine")
    }
}
impl Directory {
    pub fn new(label: &str) -> Self {
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
