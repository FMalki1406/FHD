//! What a storage failure may and may not cost, on the destination's own disk.
//!
//! **The binding criterion of م٥, measured as one unit.** `docs/feature-download-to-a-different-disk.md`
//! states it plainly: no error path may delete committed extents or a valid part
//! file, and the evidence must be a test that injects the error and shows the
//! durable bytes still there. The coordinator suite measures that against doubles;
//! this measures it against the things the claim is about -- SQLite on disk, a real
//! part file beside the destination, a real HTTP server -- and across an **engine
//! reopen**, because "the record kept it" and "the record still has it after the
//! process is gone" are different statements and only the second one matters to a
//! user who lost power.
//!
//! **Where the fault is injected, and why there.** The real store's own fault hooks
//! are `#[cfg(test)]` inside its crate, so they cannot be reached from here. What is
//! wrapped instead is the port: the store is the production `FileStorage`, creating
//! and opening real files, and the decorator refuses one write or one sync with
//! exactly the error the adapter itself would return. The refusal is total -- no
//! bytes are forwarded for the write that fails -- which is the conservative half of
//! a real `ENOSPC`. The other half, a partial write that must not be credited, is
//! measured inside the adapter by `partial_write_poisoning_never_credits_full_range`,
//! where the poison flag it turns on can be seen.
//!
//! **Removable media are deliberately not here.** The document puts reconnecting a
//! disconnected disk in a follow-up item, and this file does not make it a condition
//! of closing the feature. What does apply to it is the rule these tests measure:
//! whatever the I/O error was, it does not delete saved progress.
#![cfg(any(windows, target_os = "linux"))]

mod harness;

use fhd_app::{
    storage::{
        HandleLinker, LinkRefused, Occupant, PartSpec, PublishRefused, Published, SegmentFile,
        SegmentStore, StorageError,
    },
    AddDownload, AppError, Authorizer, Destinations, EntitlementGate, Principal, ReceiptKey,
    ReferenceStore, SourceReference, TransferRepository,
};
use fhd_domain::{
    ByteRange, DestinationRef, Generation, Job, JobCommand, JobId, JobSpec, JobState, Priority,
    RetryPolicy, SourceRef, StopReason,
};
use fhd_http::{HttpConfig, HttpTransport, SourceBinding};
use fhd_persistence::{Limits, SqliteRepository};
use fhd_runtime::{
    buffers::BufferPool,
    coordinator::{Clock, Coordinator, CoordinatorConfig, Ports, SessionEnd},
};
use fhd_storage::FileStorage;
use harness::{content, expected_digest, serve, Directory};
use std::{
    path::{Path, PathBuf},
    sync::{atomic::Ordering, Arc, Mutex},
};
use tokio::sync::mpsc;

/// One write or one sync refuses, once, with the error the adapter would give.
#[derive(Clone, Copy, Debug, Default)]
struct Faults {
    /// The next write covering this offset fails with `StorageFull`, and clears.
    fail_write_at: Option<u64>,
    /// The next sync fails, and clears.
    ///
    /// One failure rather than a standing one, because a run whose every sync fails
    /// never makes anything durable and so has nothing to lose -- and a test of what
    /// survives a failure needs something to have survived it.
    fail_sync_once: bool,
}

/// The production store, with one refusal in front of it.
struct Faulty {
    inner: FileStorage,
    faults: Arc<Mutex<Faults>>,
}
impl SegmentStore for Faulty {
    fn inspect(
        &self,
        destination: &Path,
        expected_size: u64,
    ) -> Result<Option<Occupant>, StorageError> {
        self.inner.inspect(destination, expected_size)
    }
    fn create(
        &self,
        directory: &Path,
        spec: PartSpec,
    ) -> Result<Box<dyn SegmentFile>, StorageError> {
        Ok(Box::new(FaultyFile {
            inner: self.inner.create(directory, spec)?,
            faults: self.faults.clone(),
        }))
    }
    fn open(&self, directory: &Path, spec: PartSpec) -> Result<Box<dyn SegmentFile>, StorageError> {
        Ok(Box::new(FaultyFile {
            inner: self.inner.open(directory, spec)?,
            faults: self.faults.clone(),
        }))
    }
}

struct FaultyFile {
    inner: Box<dyn SegmentFile>,
    faults: Arc<Mutex<Faults>>,
}
impl SegmentFile for FaultyFile {
    fn spec(&self) -> PartSpec {
        self.inner.spec()
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), StorageError> {
        let refuse = {
            let mut faults = self.faults.lock().expect("the faults are readable");
            match faults.fail_write_at {
                Some(at) if offset <= at && at < offset + bytes.len() as u64 => {
                    faults.fail_write_at = None;
                    true
                }
                _ => false,
            }
        };
        if refuse {
            // Nothing is forwarded: the file keeps the hole, exactly as it would had
            // the write never reached the disk.
            return Err(StorageError::Io(std::io::ErrorKind::StorageFull));
        }
        self.inner.write_at(offset, bytes)
    }
    fn sync(&mut self) -> Result<(), StorageError> {
        let refuse = {
            let mut faults = self.faults.lock().expect("the faults are readable");
            std::mem::take(&mut faults.fail_sync_once)
        };
        if refuse {
            return Err(StorageError::Io(std::io::ErrorKind::Other));
        }
        self.inner.sync()
    }
    fn hash_range(&mut self, range: ByteRange) -> Result<[u8; 32], StorageError> {
        self.inner.hash_range(range)
    }
    fn recover_extent(&mut self, range: ByteRange, digest: [u8; 32]) -> Result<(), StorageError> {
        self.inner.recover_extent(range, digest)
    }
    fn verify(
        &mut self,
        expected: Option<[u8; 32]>,
        record: &[(ByteRange, [u8; 32])],
    ) -> Result<[u8; 32], StorageError> {
        self.inner.verify(expected, record)
    }
    fn publication(&self) -> fhd_app::storage::Publication {
        self.inner.publication()
    }
    fn adopt_destination(&mut self, destination: &Path) -> Result<(), StorageError> {
        self.inner.adopt_destination(destination)
    }
    fn publish(&mut self) -> Result<Published, PublishRefused> {
        self.inner.publish()
    }
    fn discard(&mut self) -> Result<(), StorageError> {
        self.inner.discard()
    }
    fn abandon(&mut self) {
        self.inner.abandon()
    }
}

/// The platform's own linking mechanism, as the composition root wires it.
///
/// **Publication needs a mechanism, and a test that leaves it out measures nothing.**
/// The first version of this file omitted the linker: every run reached verification
/// and then refused to publish with `Unsupported` -- the answer a platform with no
/// mechanism gives -- and the resume looked like a storage failure that had not
/// cleared. The composition root's linker is private to the daemon, so this is the
/// same translation over the same `fhd-platform` calls.
struct Linker;
impl HandleLinker for Linker {
    fn open_for_identity(&self, path: &Path) -> Result<Option<std::fs::File>, StorageError> {
        fhd_platform::open_regular_without_blocking(path)
            .map_err(|error| StorageError::Io(error.kind()))
    }
    fn link(
        &self,
        file: &std::fs::File,
        folder: &std::fs::File,
        name: &std::ffi::OsStr,
    ) -> Result<(), LinkRefused> {
        fhd_platform::link_into_directory(file, folder, name).map_err(|failure| {
            let called = failure.called();
            let error = match failure.error().kind() {
                std::io::ErrorKind::AlreadyExists => StorageError::Conflict,
                std::io::ErrorKind::Unsupported | std::io::ErrorKind::CrossesDevices => {
                    StorageError::Unsupported
                }
                other => StorageError::Io(other),
            };
            if called {
                LinkRefused::after_the_call(error)
            } else {
                LinkRefused::before_the_call(error)
            }
        })
    }
    fn same_object(
        &self,
        left: &std::fs::File,
        right: &std::fs::File,
    ) -> Result<bool, StorageError> {
        #[cfg(windows)]
        {
            fhd_platform::same_object(left, right).map_err(|error| StorageError::Io(error.kind()))
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::MetadataExt;
            let left = left
                .metadata()
                .map_err(|error| StorageError::Io(error.kind()))?;
            let right = right
                .metadata()
                .map_err(|error| StorageError::Io(error.kind()))?;
            Ok(left.dev() == right.dev() && left.ino() == right.ino())
        }
    }
}

struct RealClock;
impl Clock for RealClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
    fn jitter(&self) -> u64 {
        0
    }
}

/// Everything is permitted; these tests are not about admission.
struct Operator;
impl Authorizer for Operator {
    fn authorize_add(&self, _: Principal, _: &JobSpec) -> Result<(), AppError> {
        Ok(())
    }
}
impl EntitlementGate for Operator {
    fn authorize_add(&self, _: Principal, _: &JobSpec) -> Result<(), AppError> {
        Ok(())
    }
}

/// One destination, with its part beside it on the same disk.
struct Beside {
    reference: DestinationRef,
    destination: PathBuf,
    parts: PathBuf,
}
impl Destinations for Beside {
    fn resolve(&self, destination: DestinationRef) -> Result<PathBuf, AppError> {
        if destination == self.reference {
            return Ok(self.destination.clone());
        }
        Err(AppError::InvalidInput)
    }
    fn parts_for(&self, destination: DestinationRef) -> Result<PathBuf, AppError> {
        if destination == self.reference {
            return Ok(self.parts.clone());
        }
        Err(AppError::InvalidInput)
    }
}

/// The production adapters, wired as the composition root wires them.
struct Wired {
    coordinator: Arc<Coordinator>,
    repository: Arc<SqliteRepository>,
    job: JobId,
    destination: PathBuf,
    parts: PathBuf,
    faults: Arc<Mutex<Faults>>,
}

impl Wired {
    /// Wires the state directory. Called again -- after the previous one is dropped
    /// -- this is a restart: the same database, the same parts, the same job.
    async fn open(state: &Directory, body: &[u8], port: u16) -> Self {
        let url = format!("http://127.0.0.1:{port}/file");
        let engine = state.engine();
        let downloads = state.0.join("downloads");
        std::fs::create_dir_all(&engine).expect("the engine directory is usable");
        std::fs::create_dir_all(&downloads).expect("the downloads directory is usable");
        std::fs::create_dir_all(engine.join("parts")).expect("the parts claim is usable");
        let destination = downloads.join("file.bin");
        let parts = downloads.join(".fhd-parts-storage-failure");
        std::fs::create_dir_all(&parts).expect("the part directory is usable");

        let sqlite = Arc::new(
            SqliteRepository::open(engine.join("state"), Limits::default())
                .await
                .expect("the repository opens"),
        );
        let source = SourceRef::new(7).expect("a source reference");
        let reference = DestinationRef::new(11).expect("a destination reference");
        let transport = HttpTransport::new(HttpConfig::default()).expect("the transport binds");
        transport
            .bind(
                source,
                SourceBinding::new(&url, None, None, true, vec![]).expect("the binding is valid"),
            )
            .expect("the source binds");
        let spec = JobSpec::new(
            source,
            reference,
            Some(expected_digest(body)),
            Priority::Normal,
            64 * 1024 * 1024,
        )
        .expect("the spec is valid");
        let job = AddDownload::new(sqlite.as_ref(), &Operator, &Operator)
            .execute(
                ReceiptKey::new(Principal::new(1).expect("a principal"), [9u8; 32]),
                spec,
            )
            .await
            .expect("the job is admitted");
        ReferenceStore::record(
            sqlite.as_ref(),
            source,
            SourceReference::new(url.clone(), true).expect("a source reference"),
            reference,
            destination.clone(),
        )
        .await
        .expect("the reference is recorded");

        let faults = Arc::new(Mutex::new(Faults::default()));
        let ports = Ports {
            repository: sqlite.clone(),
            store: Arc::new(Faulty {
                inner: FileStorage::own(&engine.join("parts"))
                    .expect("the part store is claimed")
                    .with_linker(Arc::new(Linker)),
                faults: faults.clone(),
            }),
            transport: Arc::new(transport),
            destinations: Arc::new(Beside {
                reference,
                destination: destination.clone(),
                parts: parts.clone(),
            }),
        };
        let coordinator = Arc::new(
            Coordinator::new(
                ports,
                BufferPool::new(4 * 256 * 1024).expect("the buffer pool is valid"),
                Arc::new(RealClock),
                CoordinatorConfig {
                    connections: 2,
                    max_segments: 1024,
                    min_segment: 256 * 1024,
                    checkpoint_bytes: 512 * 1024,
                    writer_capacity: 16,
                    retry: RetryPolicy::new(2, 10, 100).expect("the retry policy is valid"),
                },
            )
            .expect("the coordinator is valid"),
        );
        Self {
            coordinator,
            repository: sqlite,
            job,
            destination,
            parts,
            faults,
        }
    }

    fn arm(&self, faults: Faults) {
        *self.faults.lock().expect("the faults are writable") = faults;
    }

    async fn run(&self) -> Result<SessionEnd, String> {
        let (_control, receiver) = mpsc::channel(1);
        let job = self.reload().await;
        self.coordinator
            .run(job, receiver)
            .await
            .map_err(|error| format!("{error:?}"))
    }

    async fn reload(&self) -> Job {
        self.repository
            .load_jobs()
            .await
            .expect("the record is readable")
            .into_iter()
            .find(|job| job.id() == self.job)
            .expect("the job is in the record")
    }

    async fn resume(&self) {
        self.coordinator
            .command_resting(self.job, JobCommand::Resume)
            .await
            .expect("the resume is accepted");
    }

    /// The committed extents, as ranges and digests, read out of SQLite.
    async fn extents(&self) -> Vec<(ByteRange, [u8; 32])> {
        let mut extents: Vec<(ByteRange, [u8; 32])> = self
            .repository
            .durable_extents(self.job)
            .await
            .expect("the record is readable")
            .into_iter()
            .map(|extent| (extent.range(), extent.digest()))
            .collect();
        extents.sort_by_key(|(range, _)| range.start());
        extents
    }

    /// The part file's bytes, read from the disk the destination is on.
    fn part(&self, generation: Generation) -> Option<Vec<u8>> {
        let name = format!("{}-{}.part", self.job.get(), generation.get());
        std::fs::read(self.parts.join(name)).ok()
    }
}

/// Every recorded extent is backed by the bytes it claims, in the file on disk.
fn record_matches_disk(extents: &[(ByteRange, [u8; 32])], part: &[u8], body: &[u8]) {
    for (range, digest) in extents {
        let (start, end) = (range.start() as usize, range.end() as usize);
        assert!(
            end <= part.len(),
            "the record claims {start}..{end} of a part that is only {} long",
            part.len()
        );
        assert_eq!(
            &part[start..end],
            &body[start..end],
            "the part no longer holds the bytes the record credits at {start}..{end}"
        );
        assert_eq!(
            *digest,
            expected_digest(&body[start..end]),
            "a recorded extent's digest is not the digest of its bytes"
        );
    }
}

/// A disk that fills up, then an engine that is closed and opened again.
///
/// The three claims of م٥ in one run, because they are one claim: the record must
/// credit nothing the disk refused, the part must still be there afterwards, and the
/// work already done must be continued rather than fetched a second time -- **on the
/// same generation**, since a storage error is not a reason to start a new object.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_destination_disk_keeps_the_record_honest_and_the_part_resumable() {
    let body = content(3 * 1024 * 1024);
    let state = Directory::new("storage-failure-full");
    let (port, served) = serve(body.clone(), 0);

    let engine = Wired::open(&state, &body, port).await;
    engine.arm(Faults {
        fail_write_at: Some(2 * 1024 * 1024),
        ..Default::default()
    });
    assert_eq!(
        engine.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction)),
        "a full disk must stop the job, not end it"
    );
    let job = engine.reload().await;
    assert_eq!(job.reason(), Some(StopReason::Storage));
    let generation = job.generation();

    // What the record credits, and what the disk holds for it.
    let before = engine.extents().await;
    let durable: u64 = before.iter().map(|(range, _)| range.len()).sum();
    assert!(
        durable > 0,
        "the premise failed: nothing had been made durable when the disk filled"
    );
    assert!(
        durable < body.len() as u64,
        "the premise failed: the whole file was already durable"
    );
    let part = engine
        .part(generation)
        .expect("the part file was removed by a storage error");
    record_matches_disk(&before, &part, &body);
    // And nothing the failed write would have covered is credited.
    assert!(
        before
            .iter()
            .all(|(range, _)| !(range.start()..range.end()).contains(&(2 * 1024 * 1024))),
        "the record credits the range the disk refused"
    );

    // The engine goes away entirely -- database lock, part store claim and all --
    // and comes back to what is on disk. This is the half a double cannot measure.
    drop(engine);
    let engine = Wired::open(&state, &body, port).await;
    let after = engine.extents().await;
    assert_eq!(
        after, before,
        "reopening the engine changed what the record credits"
    );
    let part = engine
        .part(generation)
        .expect("the part file did not survive the restart");
    record_matches_disk(&after, &part, &body);

    // Room again, and the job is continued: same generation, and the durable bytes
    // are not asked for a second time.
    let served_before = served.load(Ordering::SeqCst);
    engine.resume().await;
    assert_eq!(
        engine.run().await,
        Ok(SessionEnd::Published(Published::At(
            engine.destination.clone()
        ))),
        "the job did not finish after the disk had room again"
    );
    let finished = engine.reload().await;
    assert_eq!(finished.state(), JobState::Completed);
    assert_eq!(
        finished.generation(),
        generation,
        "a storage error must not start a new representation"
    );
    assert_eq!(
        std::fs::read(&engine.destination).expect("the file is at the destination"),
        body
    );
    let missing = body.len() as u64 - durable;
    let refetched = served.load(Ordering::SeqCst) - served_before;
    assert!(
        refetched <= missing,
        "the resume fetched {refetched} bytes with only {missing} missing: progress was lost"
    );
}

/// A sync that fails, then an engine that is closed and opened again.
///
/// The other half of the same criterion. A failed sync is the case where the record
/// is most tempted to be wrong: the bytes are in the file, and only the sync says
/// they will still be there after a power cut. So what must survive here is not the
/// part alone but the **honesty of the record** -- it may credit only what a sync
/// returned for, and that is what the reopened engine is asked about.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_sync_leaves_the_record_crediting_only_what_survived_it() {
    let body = content(3 * 1024 * 1024);
    let state = Directory::new("storage-failure-sync");
    let (port, served) = serve(body.clone(), 0);

    let engine = Wired::open(&state, &body, port).await;
    engine.arm(Faults {
        fail_sync_once: true,
        ..Default::default()
    });
    assert_eq!(
        engine.run().await,
        Ok(SessionEnd::Settled(JobState::NeedsAction)),
        "a failed sync must stop the job"
    );
    let job = engine.reload().await;
    assert_eq!(job.reason(), Some(StopReason::Storage));
    let generation = job.generation();
    let before = engine.extents().await;
    let durable: u64 = before.iter().map(|(range, _)| range.len()).sum();
    assert!(
        durable < body.len() as u64,
        "the premise failed: the whole file was credited although a sync failed"
    );

    drop(engine);
    let engine = Wired::open(&state, &body, port).await;
    assert_eq!(
        engine.extents().await,
        before,
        "reopening the engine changed what the record credits"
    );
    if let Some(part) = engine.part(generation) {
        record_matches_disk(&before, &part, &body);
    } else {
        assert!(
            before.is_empty(),
            "the part file is gone while the record still credits {} extents",
            before.len()
        );
    }

    let served_before = served.load(Ordering::SeqCst);
    engine.resume().await;
    assert_eq!(
        engine.run().await,
        Ok(SessionEnd::Published(Published::At(
            engine.destination.clone()
        ))),
        "the job did not finish after the sync stopped failing"
    );
    assert_eq!(engine.reload().await.generation(), generation);
    assert_eq!(
        std::fs::read(&engine.destination).expect("the file is at the destination"),
        body
    );
    let missing = body.len() as u64 - durable;
    let refetched = served.load(Ordering::SeqCst) - served_before;
    assert!(
        refetched <= missing,
        "the resume fetched {refetched} bytes with only {missing} missing: progress was lost"
    );
}
