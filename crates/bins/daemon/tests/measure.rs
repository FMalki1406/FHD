//! Measurements, not assertions. Every test here is `#[ignore]`d: it is run on
//! purpose, on a named machine, and its numbers are recorded in
//! `docs/engine-measurements.md`. A number from a loaded laptop is not a
//! qualification, and none of these prove §1's targets -- they say where the
//! engine stands and what it costs, which is what the record currently lacks.
//!
//! Run one with:
//!   cargo test -p fhd-daemon --test measure -- --ignored --nocapture <name>
mod harness;

use fhd_daemon::{Engine, EngineConfig, Intent};
use harness::Directory;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    time::Instant,
};

/// A server that is not the thing being measured: threaded, serving a body held
/// in memory, answering byte ranges. If it were the bottleneck the numbers would
/// be about it rather than about the engine.
fn serve_fast(body: Arc<Vec<u8>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let body = body.clone();
            std::thread::spawn(move || answer(stream, &body));
        }
    });
    port
}

fn answer(mut stream: TcpStream, body: &[u8]) {
    let _ = stream.set_nodelay(true);
    loop {
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(0) | Err(_) => return,
                Ok(_) => request.push(byte[0]),
            }
        }
        let text = String::from_utf8_lossy(&request).to_ascii_lowercase();
        let (start, end) = match text
            .split("range: bytes=")
            .nth(1)
            .and_then(|rest| rest.split("\r\n").next())
        {
            Some(range) => {
                let mut parts = range.trim().split('-');
                let start: usize = parts.next().unwrap_or("0").parse().unwrap_or(0);
                let end = parts
                    .next()
                    .and_then(|value| value.parse::<usize>().ok())
                    .map_or(body.len() - 1, |end| end.min(body.len() - 1));
                (start, end)
            }
            None => (0, body.len() - 1),
        };
        let slice = &body[start..=end];
        let head = format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/{}\r\nETag: \"m1\"\r\nAccept-Ranges: bytes\r\nContent-Length: {}\r\n\r\n",
            body.len(),
            slice.len()
        );
        if stream.write_all(head.as_bytes()).is_err() || stream.write_all(slice).is_err() {
            return;
        }
        let _ = stream.flush();
    }
}

fn settings(state: &Directory, connections: usize) -> EngineConfig {
    EngineConfig {
        state_directory: state.engine(),
        destination: state.0.join("measured.bin"),
        connections,
        engine_connections: connections.max(2),
        max_active: 1,
        expected_sha256: None,
        max_bytes: 8 * 1024 * 1024 * 1024,
        allow_http: true,
        download_root: None,
        intent: Intent::Start,
    }
}

/// What one file costs end to end: fetch, checkpoint, verify, publish. The
/// transport here is loopback, so this is the engine's own overhead and not a
/// claim about a 1 Gbps link.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "measurement: run deliberately and record the numbers"]
async fn one_file_end_to_end() {
    let megabytes: usize = std::env::var("FHD_MEASURE_MB")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256);
    let connections: usize = std::env::var("FHD_MEASURE_CONNECTIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8);
    let body = Arc::new(
        (0..megabytes * 1024 * 1024)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>(),
    );
    let size = body.len() as f64;
    let port = serve_fast(body);
    let state = Directory::new("measure");
    let url = format!("http://127.0.0.1:{port}/file");

    let engine = Engine::open(settings(&state, connections), &url)
        .await
        .unwrap();
    let (_keep, control) = tokio::sync::mpsc::channel(1);
    let started = Instant::now();
    let outcome = engine.run(control).await.unwrap();
    let elapsed = started.elapsed().as_secs_f64();

    let rate = size / elapsed / (1024.0 * 1024.0);
    println!("MEASURE one_file_end_to_end");
    println!("  size_mib        {megabytes}");
    println!("  connections     {connections}");
    println!("  seconds         {elapsed:.3}");
    println!("  mib_per_second  {rate:.1}");
    println!("  megabits        {:.0}", rate * 8.0);
    println!("  outcome         {outcome:?}");
}

/// §1 asks for ten thousand jobs in the record. This measures the record
/// itself -- admission and the read-back every start performs -- rather than a
/// single `open_many`, which refuses more than 256 requests at once. That limit
/// is itself worth knowing: the composition root cannot admit a queue of this
/// size in one call, so a client or an import would have to batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement: run deliberately and record the numbers"]
async fn ten_thousand_jobs_in_the_record() {
    use fhd_app::{
        AddDownload, Authorizer, EntitlementGate, Principal, ReceiptKey, TransferRepository,
    };
    use fhd_domain::{DestinationRef, JobSpec, Priority, SourceRef};
    use fhd_persistence::{Limits, SqliteRepository};

    struct Allow;
    impl Authorizer for Allow {
        fn authorize_add(&self, _: Principal, _: &JobSpec) -> Result<(), fhd_app::AppError> {
            Ok(())
        }
    }
    impl EntitlementGate for Allow {
        fn authorize_add(&self, _: Principal, _: &JobSpec) -> Result<(), fhd_app::AppError> {
            Ok(())
        }
    }

    let count: u64 = std::env::var("FHD_MEASURE_JOBS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000);
    let directory = Directory::new("measure-scale");
    let repository = SqliteRepository::open(directory.engine(), Limits::default())
        .await
        .unwrap();

    let started = Instant::now();
    for index in 1..=count {
        let spec = JobSpec::new(
            SourceRef::new(index).unwrap(),
            DestinationRef::new(index).unwrap(),
            None,
            Priority::Normal,
            1 << 30,
        )
        .unwrap();
        // A distinct key per request: a repeating byte would collide every 256
        // and the repository would rightly call it a replay of another request.
        let mut digest = [0u8; 32];
        digest[..8].copy_from_slice(&index.to_le_bytes());
        let key = ReceiptKey::new(Principal::new(1).unwrap(), digest);
        AddDownload::new(&repository, &Allow, &Allow)
            .execute(key, spec)
            .await
            .unwrap();
    }
    let admitting = started.elapsed().as_secs_f64();

    let started = Instant::now();
    let loaded = repository.load_jobs().await.unwrap();
    let reading = started.elapsed().as_secs_f64();
    assert_eq!(loaded.len() as u64, count);

    let database = std::fs::metadata(directory.engine().join("admission.sqlite"))
        .map(|meta| meta.len())
        .unwrap_or(0);
    println!("MEASURE ten_thousand_jobs_in_the_record");
    println!("  jobs                {count}");
    println!(
        "  admit_seconds       {admitting:.3}  ({:.0} per second)",
        count as f64 / admitting
    );
    println!("  load_all_seconds    {reading:.3}");
    println!("  database_bytes      {database}");
}

/// Where the time in `one_file_end_to_end` goes. The engine writes every byte
/// once, hashes it once at each checkpoint, and hashes it again to verify before
/// publishing -- so the floor is one write and two passes of SHA-256 over the
/// file, whatever the network does. Knowing that floor is the difference between
/// "the engine is slow" and "this is what the design costs".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement: run deliberately and record the numbers"]
async fn cost_of_the_parts() {
    use sha2::{Digest, Sha256};
    let megabytes: usize = std::env::var("FHD_MEASURE_MB")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256);
    let bytes = megabytes * 1024 * 1024;
    let body: Vec<u8> = (0..bytes).map(|i| (i % 251) as u8).collect();
    let mib = bytes as f64 / (1024.0 * 1024.0);

    let started = Instant::now();
    let mut hash = Sha256::new();
    hash.update(&body);
    let digest: [u8; 32] = hash.finalize().into();
    let hashing = started.elapsed().as_secs_f64();

    let directory = Directory::new("measure-parts");
    let path = directory.0.join("written.bin");
    let started = Instant::now();
    {
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(&body).unwrap();
        file.sync_all().unwrap();
    }
    let writing = started.elapsed().as_secs_f64();

    let started = Instant::now();
    let read = std::fs::read(&path).unwrap();
    let mut hash = Sha256::new();
    hash.update(&read);
    let verify: [u8; 32] = hash.finalize().into();
    let rereading = started.elapsed().as_secs_f64();
    assert_eq!(digest, verify);

    println!("MEASURE cost_of_the_parts");
    println!("  size_mib          {megabytes}");
    println!(
        "  hash_seconds      {hashing:.3}  ({:.0} MiB/s)",
        mib / hashing
    );
    println!(
        "  write_seconds     {writing:.3}  ({:.0} MiB/s)",
        mib / writing
    );
    println!(
        "  read_hash_seconds {rereading:.3}  ({:.0} MiB/s)",
        mib / rereading
    );
    println!(
        "  floor_seconds     {:.3}  (one write plus two hashes)",
        writing + hashing + rereading
    );
}
