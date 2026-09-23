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
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::Instant,
};

/// When each engine event happened, so a run can be split into the part that
/// moves bytes and the part that makes the file usable. The engine already
/// reports both; this only timestamps what it says.
type Marks = Arc<Mutex<Vec<(String, Instant)>>>;
static MARKS: OnceLock<Marks> = OnceLock::new();

fn marks() -> Marks {
    MARKS
        .get_or_init(|| Arc::new(Mutex::new(Vec::new())))
        .clone()
}

/// Records the code of every engine event with the moment it arrived.
struct Stopwatch;
struct CodeOnly(Option<String>);
impl tracing::field::Visit for CodeOnly {
    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "code" {
            self.0 = Some(value.to_owned());
        }
    }
}
impl tracing::Subscriber for Stopwatch {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "fhd"
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut code = CodeOnly(None);
        event.record(&mut code);
        if let Some(code) = code.0 {
            marks().lock().unwrap().push((code, Instant::now()));
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Starts the clock for one run and forgets any earlier one.
fn watch() -> Instant {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = tracing::subscriber::set_global_default(Stopwatch);
    });
    marks().lock().unwrap().clear();
    Instant::now()
}

/// The last moment the engine said bytes became durable: the end of moving
/// bytes, before anything is read back to prove them.
fn last(code: &str, start: Instant) -> Option<f64> {
    marks()
        .lock()
        .unwrap()
        .iter()
        .filter(|(seen, _)| seen == code)
        .map(|(_, at)| at.duration_since(start).as_secs_f64())
        .next_back()
}

/// A server that is not the thing being measured: threaded, serving a body held
/// in memory, answering byte ranges. If it were the bottleneck the numbers would
/// be about it rather than about the engine. It also counts what it sent, which
/// is how a resumed run shows what it had to fetch again.
fn serve_fast(body: Arc<Vec<u8>>) -> u16 {
    serve_counted(body).0
}

fn serve_counted(body: Arc<Vec<u8>>) -> (u16, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let served = Arc::new(AtomicU64::new(0));
    let counter = served.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let body = body.clone();
            let counter = counter.clone();
            std::thread::spawn(move || answer(stream, &body, &counter));
        }
    });
    (port, served)
}

fn answer(mut stream: TcpStream, body: &[u8], served: &AtomicU64) {
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
        served.fetch_add(slice.len() as u64, Ordering::Relaxed);
        let _ = stream.flush();
    }
}

fn settings(state: &Directory, connections: usize) -> EngineConfig {
    EngineConfig {
        state_directory: state.engine(),
        destination: state.0.join("measured.bin"),
        connections,
        // The buffer budget is sized from this, so it is separated here: a pool
        // exactly as large as the connections leaves a worker nothing to take
        // while the writer holds a block, which is worth measuring on purpose.
        engine_connections: std::env::var("FHD_MEASURE_POOL")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(connections.max(2)),
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
    let cpu_before = fhd_platform::process_cpu()
        .unwrap_or_default()
        .as_secs_f64();
    let started = watch();
    let outcome = engine.run(control).await.unwrap();
    let elapsed = started.elapsed().as_secs_f64();
    let cpu = fhd_platform::process_cpu()
        .unwrap_or_default()
        .as_secs_f64()
        - cpu_before;
    // The last commit is the moment every byte was durable: the transfer is over
    // and nothing has been read back yet.
    let transfer = last("STORE-COMMITTED", started).unwrap_or(elapsed);

    let mib = size / (1024.0 * 1024.0);
    println!("MEASURE one_file_end_to_end");
    println!("  size_mib          {megabytes}");
    println!("  connections       {connections}");
    println!("  transfer_seconds  {transfer:.3}");
    println!(
        "  transfer_mib_s    {:.1}   ({:.0} Mbps)",
        mib / transfer,
        mib / transfer * 8.0
    );
    println!("  ready_seconds     {elapsed:.3}   (usable file)");
    println!(
        "  ready_mib_s       {:.1}   ({:.0} Mbps)",
        mib / elapsed,
        mib / elapsed * 8.0
    );
    println!("  verify_publish    {:.3}", elapsed - transfer);
    // The server runs in this process too, so this is an upper bound on the
    // engine's own share; the attribution test separates them.
    println!(
        "  cpu_core_s_gib    {:.1}",
        cpu / (size / (1024.0 * 1024.0 * 1024.0))
    );
    println!("  outcome           {outcome:?}");
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

/// The ceiling §19 declares: thirty-two jobs at once over sixty-four
/// connections. What it costs in wall time and what the engine gets through,
/// measured together rather than one job at a time.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "measurement: run deliberately and record the numbers"]
async fn thirty_two_jobs_at_once() {
    let jobs: usize = std::env::var("FHD_MEASURE_ACTIVE")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(32);
    let each: usize = std::env::var("FHD_MEASURE_MB")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(16);
    let body = Arc::new(
        (0..each * 1024 * 1024)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>(),
    );
    let port = serve_fast(body);
    let state = Directory::new("measure-many");
    let mut requests = Vec::with_capacity(jobs);
    for index in 0..jobs {
        requests.push(fhd_daemon::Request {
            url: format!("http://127.0.0.1:{port}/file-{index}"),
            destination: state.0.join(format!("many-{index}.bin")),
            expected_sha256: None,
            sensitive: false,
        });
    }
    let mut config = settings(&state, 2);
    config.engine_connections = 64;
    config.max_active = jobs;
    let engine = fhd_daemon::Engine::open_many(config, requests)
        .await
        .unwrap();

    let (_keep, commands) = tokio::sync::mpsc::channel(4);
    let started = Instant::now();
    let outcomes = engine.run_all(commands).await.unwrap();
    let elapsed = started.elapsed().as_secs_f64();
    let published = outcomes
        .iter()
        .filter(|(_, outcome)| matches!(outcome, fhd_daemon::JobOutcome::Published(_)))
        .count();
    let total = (jobs * each) as f64;

    println!("MEASURE thirty_two_jobs_at_once");
    println!("  jobs              {jobs}");
    println!("  each_mib          {each}");
    println!("  published         {published}");
    println!("  seconds           {elapsed:.3}");
    println!("  aggregate_mib_s   {:.1}", total / elapsed);
    assert_eq!(published, jobs, "a job did not finish");
}

/// What a crash costs. The run is cut off with bytes in flight, then continued:
/// the difference between what the server sent in total and the size of the file
/// is what had to be fetched a second time, which is the price of the checkpoint
/// interval. Cancelling the run drops workers without draining them, so the
/// uncommitted bytes are lost exactly as they would be in a crash; the part file
/// is closed cleanly, which a power cut would not do.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "measurement: run deliberately and record the numbers"]
async fn what_a_crash_costs() {
    let megabytes: usize = std::env::var("FHD_MEASURE_MB")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256);
    let cut: f64 = std::env::var("FHD_MEASURE_CUT_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(900.0);
    let body = Arc::new(
        (0..megabytes * 1024 * 1024)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>(),
    );
    let size = body.len() as u64;
    let (port, served) = serve_counted(body);
    let state = Directory::new("measure-crash");
    let url = format!("http://127.0.0.1:{port}/file");

    // Cut off mid-transfer.
    {
        let engine = Engine::open(settings(&state, 1), &url).await.unwrap();
        let (_keep, control) = tokio::sync::mpsc::channel(1);
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs_f64(cut / 1000.0),
            engine.run(control),
        )
        .await;
    }
    let before = served.load(Ordering::Relaxed);

    // Continue. Anything fetched now beyond what was missing is the cost.
    let mut resumed = settings(&state, 1);
    resumed.intent = Intent::Resume;
    // The cut engine's background work lets go of the directory shortly after it
    // stops; waiting for that is part of what a restart costs in practice.
    let waited = Instant::now();
    let engine = loop {
        match Engine::open(resumed.clone(), &url).await {
            Ok(engine) => break engine,
            Err(error) if waited.elapsed().as_secs() < 30 => {
                assert!(
                    format!("{error:?}").contains("Locked")
                        || matches!(error, fhd_daemon::EngineError::StateBusy),
                    "reopening failed for another reason: {error:?}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            Err(error) => panic!("the directory never became available: {error:?}"),
        }
    };
    let unlock = waited.elapsed().as_secs_f64();
    let (_keep, control) = tokio::sync::mpsc::channel(1);
    let started = Instant::now();
    let outcome = engine.run(control).await.unwrap();
    let recovery = started.elapsed().as_secs_f64();
    let total = served.load(Ordering::Relaxed);

    println!("MEASURE what_a_crash_costs");
    println!("  size_mib          {megabytes}");
    println!("  cut_after_ms      {cut:.0}");
    println!(
        "  sent_before_mib   {:.1}",
        before as f64 / (1024.0 * 1024.0)
    );
    println!(
        "  sent_total_mib    {:.1}",
        total as f64 / (1024.0 * 1024.0)
    );
    println!(
        "  refetched_mib     {:.1}",
        (total.saturating_sub(size)) as f64 / (1024.0 * 1024.0)
    );
    println!("  unlock_seconds    {unlock:.3}   (waiting for the cut engine to let go)");
    println!("  resume_seconds    {recovery:.3}");
    println!("  outcome           {outcome:?}");
}

/// What admitting a job costs, and what it would cost if the engine committed a
/// batch of them together. The guarantee is not in question either way: a job is
/// acknowledged only after its transaction is durable. This measures the ceiling
/// group commit would buy, so the decision to build it rests on a number.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement: run deliberately and record the numbers"]
async fn what_group_commit_would_buy() {
    let count: usize = std::env::var("FHD_MEASURE_JOBS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000);
    let directory = Directory::new("measure-commit");
    std::fs::create_dir_all(directory.engine()).unwrap();
    for batch in [1usize, 16, 64, 256] {
        let path = directory.engine().join(format!("batch-{batch}.sqlite"));
        let database = rusqlite::Connection::open(&path).unwrap();
        // The same durability the repository uses: a write-ahead log that is
        // flushed to the disk on every commit.
        database.pragma_update(None, "journal_mode", "WAL").unwrap();
        database.pragma_update(None, "synchronous", "FULL").unwrap();
        database
            .execute(
                "CREATE TABLE rows(id INTEGER PRIMARY KEY, payload BLOB NOT NULL)",
                [],
            )
            .unwrap();
        let payload = vec![0u8; 96];
        let started = Instant::now();
        let mut written = 0usize;
        while written < count {
            let size = batch.min(count - written);
            let transaction = database.unchecked_transaction().unwrap();
            for index in 0..size {
                transaction
                    .execute(
                        "INSERT INTO rows(id,payload) VALUES(?1,?2)",
                        rusqlite::params![(written + index) as i64 + 1, payload.as_slice()],
                    )
                    .unwrap();
            }
            // One flush per batch, and nothing is acknowledged before it returns.
            transaction.commit().unwrap();
            written += size;
        }
        let elapsed = started.elapsed().as_secs_f64();
        println!(
            "MEASURE group_commit batch={batch:>3}  {:.3}s  {:.0} rows/second",
            elapsed,
            count as f64 / elapsed
        );
    }
}

/// Processor time, attributed. The engine's total is known; this measures the
/// same bytes through each layer under it, so the difference says where the
/// cost actually is rather than where it seems to be.
///
/// Every step moves the same 256 MiB over the same loopback server:
///   1. a bare socket read, which is the floor for touching the bytes at all
///   2. the HTTP client the engine uses, discarding the body
///   3. the HTTP client plus hashing, as a checkpoint does
///   4. the engine itself, end to end
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "measurement: run deliberately and record the numbers"]
async fn where_the_processor_time_goes() {
    use sha2::{Digest, Sha256};
    let Some(_) = fhd_platform::process_cpu() else {
        println!("MEASURE where_the_processor_time_goes: unavailable on this platform");
        return;
    };
    let megabytes: usize = std::env::var("FHD_MEASURE_MB")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256);
    let body = Arc::new(
        (0..megabytes * 1024 * 1024)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<u8>>(),
    );
    let gib = (megabytes as f64) / 1024.0;
    let port = serve_fast(body.clone());
    let url = format!("http://127.0.0.1:{port}/file");

    let cpu = || {
        fhd_platform::process_cpu()
            .unwrap_or_default()
            .as_secs_f64()
    };
    let report = |label: &str, seconds: f64, wall: f64| {
        println!(
            "  {label:<22} cpu={seconds:6.2}s  ({:5.1} core-s/GiB)  wall={wall:5.2}s",
            seconds / gib
        );
    };
    println!("MEASURE where_the_processor_time_goes  ({megabytes} MiB)");

    // 1. The floor: read the bytes off a socket and count them.
    let before = cpu();
    let clock = Instant::now();
    {
        use std::io::Read as _;
        let mut socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
        socket
            .write_all(b"GET /file HTTP/1.1\r\nHost: x\r\nRange: bytes=0-\r\n\r\n")
            .unwrap();
        let mut buffer = vec![0u8; 256 * 1024];
        let mut total = 0usize;
        while total < body.len() {
            match socket.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => total += read,
            }
        }
    }
    report("bare socket", cpu() - before, clock.elapsed().as_secs_f64());

    // 2. The HTTP client the engine uses, throwing the body away.
    let before = cpu();
    let clock = Instant::now();
    {
        let client = reqwest::Client::builder().build().unwrap();
        let mut response = client.get(&url).send().await.unwrap();
        let mut total = 0usize;
        while let Some(chunk) = response.chunk().await.unwrap() {
            total += chunk.len();
        }
        assert!(total > 0);
    }
    report("http client", cpu() - before, clock.elapsed().as_secs_f64());

    // 3. The same, hashing as it goes: what a checkpoint costs on top.
    let before = cpu();
    let clock = Instant::now();
    {
        let client = reqwest::Client::builder().build().unwrap();
        let mut response = client.get(&url).send().await.unwrap();
        let mut hash = Sha256::new();
        while let Some(chunk) = response.chunk().await.unwrap() {
            hash.update(&chunk);
        }
        let _: [u8; 32] = hash.finalize().into();
    }
    report(
        "http client + hash",
        cpu() - before,
        clock.elapsed().as_secs_f64(),
    );

    // 4. The engine, end to end.
    let state = Directory::new("measure-cpu");
    let engine = Engine::open(settings(&state, 1), &url).await.unwrap();
    let (_keep, control) = tokio::sync::mpsc::channel(1);
    let before = cpu();
    let clock = Instant::now();
    engine.run(control).await.unwrap();
    report(
        "engine end to end",
        cpu() - before,
        clock.elapsed().as_secs_f64(),
    );
}

/// What the engine pays for its internal digests, and what a different function
/// would cost for the same work. The file the user receives is verified with
/// SHA-256 and that cannot change -- it is the digest a caller supplies and the
/// one published. But the per-extent digest at each checkpoint is internal: its
/// only job is to prove, after a crash, that a saved range still holds the same
/// bytes. This measures whether that internal choice is worth revisiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement: run deliberately and record the numbers"]
async fn what_the_digest_costs() {
    use sha2::{Digest, Sha256};
    let megabytes: usize = std::env::var("FHD_MEASURE_MB")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256);
    let body: Vec<u8> = (0..megabytes * 1024 * 1024)
        .map(|i| (i % 251) as u8)
        .collect();
    let mib = body.len() as f64 / (1024.0 * 1024.0);
    let gib = mib / 1024.0;
    let cpu = || {
        fhd_platform::process_cpu()
            .unwrap_or_default()
            .as_secs_f64()
    };

    println!("MEASURE what_the_digest_costs  ({megabytes} MiB)");
    for (name, run) in [("sha2 (today)", 0usize), ("blake3", 1)] {
        let before_cpu = cpu();
        let clock = Instant::now();
        match run {
            0 => {
                let mut hash = Sha256::new();
                hash.update(&body);
                let _: [u8; 32] = hash.finalize().into();
            }
            _ => {
                let mut hash = blake3::Hasher::new();
                hash.update(&body);
                let _ = hash.finalize();
            }
        }
        let wall = clock.elapsed().as_secs_f64();
        println!(
            "  {name:<20} wall={wall:5.2}s  {:6.0} MiB/s  cpu={:5.1} core-s/GiB",
            mib / wall,
            (cpu() - before_cpu) / gib
        );
    }
}
