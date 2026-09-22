//! In-memory transfer ports with the same acceptance rules as the real adapters,
//! plus fault injection. Deterministic and test-only.
use fhd_app::{
    storage::{Occupant, PartSpec, SegmentFile, SegmentStore, StorageError},
    transport::{ByteStream, Probe, Transport, TransportError},
    AppError, CommitError, Destinations, DurableExtent, PortFuture, PublishIntent,
    TransferRepository,
};
use fhd_domain::{
    ByteRange, DestinationRef, Generation, Job, JobCommand, JobEvent, JobId, JobRecord, JobState,
    SourceRef,
};
use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

/// Toy 32-byte digest for fakes; not cryptographic.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (lane, chunk) in out.chunks_mut(8).enumerate() {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ lane as u64;
        for byte in bytes {
            h = (h ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
        h ^= bytes.len() as u64;
        chunk.copy_from_slice(&h.to_le_bytes());
    }
    out
}

fn overlaps(a: ByteRange, b: ByteRange) -> bool {
    a.start() < b.end() && b.start() < a.end()
}

struct Stored {
    record: JobRecord,
    extents: Vec<DurableExtent>,
    intent: Option<PublishIntent>,
}
#[derive(Default)]
pub struct MemoryTransfers {
    jobs: Mutex<HashMap<JobId, Stored>>,
    unavailable: AtomicUsize,
}
impl MemoryTransfers {
    /// Stores a freshly admitted job, as the admission repository would.
    pub fn admit(&self, job: &Job) {
        let record = JobRecord {
            id: job.id(),
            spec: job.spec().clone(),
            version: 0,
            state: JobState::Queued,
            generation: Generation::initial(),
            reason: None,
            retry_at: None,
            stop: None,
            replace_on_drain: false,
            attempts: 0,
            plan: None,
            validator: None,
            durable: vec![],
        };
        self.jobs.lock().unwrap().insert(
            job.id(),
            Stored {
                record,
                extents: vec![],
                intent: None,
            },
        );
    }
    /// The next `n` commits fail as Unavailable without changing anything.
    pub fn fail_next(&self, n: usize) {
        self.unavailable.store(n, Ordering::SeqCst);
    }
    fn outage(&self) -> bool {
        self.unavailable
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
    }
    pub fn state(&self, job: JobId) -> Option<JobState> {
        self.jobs.lock().unwrap().get(&job).map(|s| s.record.state)
    }
}
impl TransferRepository for MemoryTransfers {
    fn commit_transition(&self, event: JobEvent) -> PortFuture<'_, Result<(), CommitError>> {
        Box::pin(async move {
            if self.outage() {
                return Err(CommitError::Unavailable);
            }
            let mut jobs = self.jobs.lock().unwrap();
            let stored = jobs.get_mut(&event.job()).ok_or(CommitError::Conflict)?;
            let r = &mut stored.record;
            if r.version + 1 != event.version()
                || r.state != event.from()
                || r.generation != event.generation()
            {
                return Err(CommitError::Conflict);
            }
            let o = event.outcome();
            let replaced = o.generation != r.generation;
            let plan = match (event.command(), r.plan) {
                _ if replaced => None,
                (JobCommand::ProbeSucceeded { total, .. }, Some(plan)) => {
                    if plan.0 != total {
                        return Err(CommitError::Conflict);
                    }
                    Some(plan)
                }
                (
                    JobCommand::ProbeSucceeded {
                        total,
                        max_segments,
                        ..
                    },
                    None,
                ) => Some((total, max_segments)),
                (_, plan) => plan,
            };
            let validator = match event.command() {
                _ if replaced => None,
                JobCommand::ProbeSucceeded { validator, .. } if r.plan.is_none() => validator,
                JobCommand::ProbeSucceeded { validator, .. } => {
                    if validator.is_none() || validator != r.validator {
                        return Err(CommitError::Conflict);
                    }
                    r.validator
                }
                _ => r.validator,
            };
            if validator != o.validator {
                return Err(CommitError::Conflict);
            }
            let durable: u64 = if replaced {
                0
            } else {
                stored.extents.iter().map(|e| e.range().len()).sum()
            };
            if o.durable_bytes > durable {
                return Err(CommitError::Conflict);
            }
            if replaced {
                stored.extents.clear();
                stored.intent = None;
            }
            let r = &mut stored.record;
            r.version = event.version();
            r.state = o.state;
            r.generation = o.generation;
            r.reason = o.reason;
            r.retry_at = o.retry_at;
            r.stop = o.stop;
            r.replace_on_drain = o.replace_on_drain;
            r.attempts = o.attempts;
            if event.command() == JobCommand::PublishCommitted {
                stored.intent = None;
            }
            let r = &mut stored.record;
            r.plan = plan;
            r.validator = validator;
            Ok(())
        })
    }
    fn commit_extents(
        &self,
        job: JobId,
        generation: Generation,
        extents: Vec<DurableExtent>,
    ) -> PortFuture<'_, Result<(), CommitError>> {
        Box::pin(async move {
            if self.outage() {
                return Err(CommitError::Unavailable);
            }
            let mut jobs = self.jobs.lock().unwrap();
            let stored = jobs.get_mut(&job).ok_or(CommitError::Conflict)?;
            let (total, _) = stored.record.plan.ok_or(CommitError::Conflict)?;
            if stored.record.generation != generation
                || !matches!(
                    stored.record.state,
                    JobState::Transferring | JobState::Stopping | JobState::Cancelling
                )
                || extents.iter().any(|e| e.range().end() > total)
            {
                return Err(CommitError::Conflict);
            }
            let mut fresh: Vec<DurableExtent> = vec![];
            for extent in extents {
                if stored.extents.contains(&extent) || fresh.contains(&extent) {
                    continue;
                }
                if stored
                    .extents
                    .iter()
                    .chain(fresh.iter())
                    .any(|e| overlaps(e.range(), extent.range()))
                {
                    return Err(CommitError::Conflict);
                }
                fresh.push(extent);
            }
            stored.extents.extend(fresh);
            stored.extents.sort_by_key(|e| e.range().start());
            Ok(())
        })
    }
    fn load_jobs(&self) -> PortFuture<'_, Result<Vec<Job>, AppError>> {
        Box::pin(async move {
            let jobs = self.jobs.lock().unwrap();
            let mut out = Vec::with_capacity(jobs.len());
            for stored in jobs.values() {
                let mut record = stored.record.clone();
                record.durable = stored.extents.iter().map(|e| e.range()).collect();
                out.push(Job::restore(record).map_err(|_| AppError::CorruptRepository)?);
            }
            out.sort_by_key(|j| j.id());
            Ok(out)
        })
    }
    fn record_publish_intent(
        &self,
        intent: PublishIntent,
    ) -> PortFuture<'_, Result<(), CommitError>> {
        Box::pin(async move {
            let mut jobs = self.jobs.lock().unwrap();
            let stored = jobs.get_mut(&intent.job()).ok_or(CommitError::Conflict)?;
            if stored.record.state != JobState::Verifying
                || stored.record.generation != intent.generation()
                || stored
                    .record
                    .plan
                    .is_none_or(|(total, _)| total != intent.size())
            {
                return Err(CommitError::Conflict);
            }
            stored.intent = Some(intent);
            Ok(())
        })
    }
    fn publish_intent(
        &self,
        job: JobId,
    ) -> PortFuture<'_, Result<Option<PublishIntent>, AppError>> {
        Box::pin(async move { Ok(self.jobs.lock().unwrap().get(&job).and_then(|s| s.intent)) })
    }
    fn durable_extents(&self, job: JobId) -> PortFuture<'_, Result<Vec<DurableExtent>, AppError>> {
        Box::pin(async move {
            Ok(self
                .jobs
                .lock()
                .unwrap()
                .get(&job)
                .map(|s| s.extents.clone())
                .unwrap_or_default())
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StoreFaults {
    pub fail_sync: bool,
    /// Writes touching this offset fail with StorageFull.
    pub fail_write_at: Option<u64>,
}
/// `live` is what reads see; `durable` is what survives `MemoryStore::crash`.
#[derive(Default)]
struct FileData {
    live: Vec<u8>,
    durable: Vec<u8>,
}
type Files = HashMap<(JobId, Generation), Arc<Mutex<FileData>>>;
type Published = HashMap<PathBuf, Vec<u8>>;
/// Files outlive handles, like a disk across process restarts.
#[derive(Clone, Default)]
pub struct MemoryStore {
    files: Arc<Mutex<Files>>,
    published: Arc<Mutex<Published>>,
    blocked: Arc<Mutex<Vec<PathBuf>>>,
    faults: Arc<Mutex<StoreFaults>>,
}
impl MemoryStore {
    pub fn set_faults(&self, faults: StoreFaults) {
        *self.faults.lock().unwrap() = faults;
    }
    pub fn bytes(&self, job: JobId, generation: Generation) -> Option<Vec<u8>> {
        let files = self.files.lock().unwrap();
        let file = files.get(&(job, generation))?;
        let bytes = file.lock().unwrap().live.clone();
        Some(bytes)
    }
    /// Simulates corruption at rest.
    pub fn corrupt(&self, job: JobId, generation: Generation, offset: usize) {
        let files = self.files.lock().unwrap();
        let mut file = files[&(job, generation)].lock().unwrap();
        file.live[offset] ^= 0xff;
        file.durable[offset] ^= 0xff;
    }
    /// Power loss: every byte written since its file's last sync is gone.
    pub fn crash(&self) {
        for file in self.files.lock().unwrap().values() {
            let mut file = file.lock().unwrap();
            file.live = file.durable.clone();
        }
    }
    /// Bytes already at a destination path.
    pub fn published(&self, path: &Path) -> Option<Vec<u8>> {
        self.published.lock().unwrap().get(path).cloned()
    }
    /// Places foreign (or identical) content at a destination before a publish.
    pub fn place(&self, path: PathBuf, bytes: Vec<u8>) {
        self.published.lock().unwrap().insert(path, bytes);
    }
    /// Occupies a destination with something that is not a regular file.
    pub fn block(&self, path: PathBuf) {
        self.blocked.lock().unwrap().push(path);
    }
    /// Frees a destination previously blocked or occupied.
    pub fn free(&self, path: &Path) {
        self.blocked.lock().unwrap().retain(|p| p != path);
        self.published.lock().unwrap().remove(path);
    }
    fn handle(&self, spec: PartSpec, data: Arc<Mutex<FileData>>) -> Box<dyn SegmentFile> {
        Box::new(MemoryFile {
            spec,
            data,
            coverage: vec![],
            synced: false,
            verified: false,
            faults: self.faults.clone(),
            published: self.published.clone(),
            blocked: self.blocked.clone(),
            files: self.files.clone(),
            published_once: false,
            abandoned: false,
            discarded: false,
        })
    }
}
impl SegmentStore for MemoryStore {
    fn inspect(
        &self,
        destination: &Path,
        expected_size: u64,
    ) -> Result<Option<Occupant>, StorageError> {
        if self
            .blocked
            .lock()
            .unwrap()
            .iter()
            .any(|p| p == destination)
        {
            return Ok(Some(Occupant::NotAFile));
        }
        Ok(self
            .published
            .lock()
            .unwrap()
            .get(destination)
            .map(|bytes| {
                if bytes.len() as u64 != expected_size {
                    return Occupant::OtherSize;
                }
                Occupant::File {
                    size: bytes.len() as u64,
                    digest: digest(bytes),
                }
            }))
    }
    fn create(&self, _: &Path, spec: PartSpec) -> Result<Box<dyn SegmentFile>, StorageError> {
        let mut files = self.files.lock().unwrap();
        let key = (spec.job(), spec.generation());
        if files.contains_key(&key) {
            return Err(StorageError::Conflict);
        }
        let zeros = vec![0; spec.size() as usize];
        let data = Arc::new(Mutex::new(FileData {
            live: zeros.clone(),
            durable: zeros,
        }));
        files.insert(key, data.clone());
        drop(files);
        Ok(self.handle(spec, data))
    }
    fn open(&self, _: &Path, spec: PartSpec) -> Result<Box<dyn SegmentFile>, StorageError> {
        let data = self
            .files
            .lock()
            .unwrap()
            .get(&(spec.job(), spec.generation()))
            .cloned()
            .ok_or(StorageError::Io(std::io::ErrorKind::NotFound))?;
        Ok(self.handle(spec, data))
    }
}
struct MemoryFile {
    spec: PartSpec,
    data: Arc<Mutex<FileData>>,
    coverage: Vec<(u64, u64)>,
    synced: bool,
    verified: bool,
    faults: Arc<Mutex<StoreFaults>>,
    published: Arc<Mutex<Published>>,
    blocked: Arc<Mutex<Vec<PathBuf>>>,
    files: Arc<Mutex<Files>>,
    published_once: bool,
    abandoned: bool,
    discarded: bool,
}
impl MemoryFile {
    /// Like the real adapter, a discarded handle refers to a file that is gone.
    fn usable(&self) -> Result<(), StorageError> {
        if self.discarded {
            return Err(StorageError::InvalidState);
        }
        Ok(())
    }
    fn cover(&mut self, start: u64, end: u64) {
        self.coverage.push((start, end));
        self.coverage.sort_unstable();
        let mut merged: Vec<(u64, u64)> = vec![];
        for (s, e) in self.coverage.drain(..) {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.coverage = merged;
    }
    fn complete(&self) -> bool {
        self.spec.size() == 0 || self.coverage == [(0, self.spec.size())]
    }
    fn slice_digest(&self, range: ByteRange) -> [u8; 32] {
        let data = self.data.lock().unwrap();
        digest(&data.live[range.start() as usize..range.end() as usize])
    }
}
impl SegmentFile for MemoryFile {
    fn spec(&self) -> PartSpec {
        self.spec
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), StorageError> {
        self.usable()?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(StorageError::Bounds)?;
        if end > self.spec.size() {
            return Err(StorageError::Bounds);
        }
        if self
            .faults
            .lock()
            .unwrap()
            .fail_write_at
            .is_some_and(|at| offset <= at && at < end)
        {
            return Err(StorageError::Io(std::io::ErrorKind::StorageFull));
        }
        self.data.lock().unwrap().live[offset as usize..end as usize].copy_from_slice(bytes);
        self.cover(offset, end);
        self.synced = false;
        self.verified = false;
        Ok(())
    }
    fn sync(&mut self) -> Result<(), StorageError> {
        self.usable()?;
        if self.faults.lock().unwrap().fail_sync {
            return Err(StorageError::Io(std::io::ErrorKind::Other));
        }
        let mut data = self.data.lock().unwrap();
        data.durable = data.live.clone();
        self.synced = true;
        Ok(())
    }
    fn hash_range(&mut self, range: ByteRange) -> Result<[u8; 32], StorageError> {
        if range.end() > self.spec.size() {
            return Err(StorageError::Bounds);
        }
        Ok(self.slice_digest(range))
    }
    fn recover_extent(&mut self, range: ByteRange, expected: [u8; 32]) -> Result<(), StorageError> {
        if range.end() > self.spec.size() {
            return Err(StorageError::Bounds);
        }
        if self.slice_digest(range) != expected {
            return Err(StorageError::Integrity);
        }
        self.cover(range.start(), range.end());
        // Like the real adapter: a reopened handle has not synced anything yet.
        Ok(())
    }
    fn verify(&mut self, expected: Option<[u8; 32]>) -> Result<[u8; 32], StorageError> {
        if !self.complete() || !self.synced {
            return Err(StorageError::InvalidState);
        }
        let actual = digest(&self.data.lock().unwrap().live);
        if expected.is_some_and(|e| e != actual) {
            return Err(StorageError::Integrity);
        }
        self.verified = true;
        Ok(actual)
    }
    /// Same rule as the real adapter: nothing is removed unless it was published
    /// or explicitly abandoned.
    fn discard(&mut self) -> Result<(), StorageError> {
        self.usable()?;
        if !self.published_once && !self.abandoned {
            return Err(StorageError::InvalidState);
        }
        self.discarded = true;
        self.files
            .lock()
            .unwrap()
            .remove(&(self.spec.job(), self.spec.generation()));
        Ok(())
    }
    fn abandon(&mut self) {
        self.abandoned = true;
    }
    /// Atomic no-replace: an occupied destination is a conflict, never an overwrite.
    /// Like the real adapter, only a verified, synced, complete file may be published.
    fn publish(&mut self, destination: &Path) -> Result<PathBuf, StorageError> {
        self.usable()?;
        if !self.complete() || !self.synced || !self.verified {
            return Err(StorageError::InvalidState);
        }
        if self
            .blocked
            .lock()
            .unwrap()
            .contains(&destination.to_path_buf())
        {
            return Err(StorageError::Conflict);
        }
        let mut published = self.published.lock().unwrap();
        if published.contains_key(destination) {
            return Err(StorageError::Conflict);
        }
        published.insert(
            destination.to_path_buf(),
            self.data.lock().unwrap().live.clone(),
        );
        self.published_once = true;
        Ok(destination.to_path_buf())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum FetchFault {
    Fail(TransportError),
    /// Deliver `after` bytes, then fail.
    Truncate {
        after: usize,
        error: TransportError,
    },
    /// Deliver `after` bytes, then never complete (a stalled connection).
    Stall {
        after: usize,
    },
}
pub struct ScriptedTransport {
    body: Mutex<Arc<Vec<u8>>>,
    ranges: bool,
    chunk: usize,
    probe_faults: Mutex<VecDeque<TransportError>>,
    faults: Mutex<VecDeque<FetchFault>>,
    changed: Mutex<bool>,
    fetches: AtomicUsize,
}
impl ScriptedTransport {
    pub fn new(body: Vec<u8>, ranges: bool, chunk: usize) -> Self {
        Self {
            body: Mutex::new(Arc::new(body)),
            ranges,
            chunk: chunk.max(1),
            probe_faults: Mutex::default(),
            faults: Mutex::default(),
            changed: Mutex::new(false),
            fetches: AtomicUsize::new(0),
        }
    }
    pub fn fail_probe(&self, error: TransportError) {
        self.probe_faults.lock().unwrap().push_back(error);
    }
    /// Faults apply to subsequent fetches in order.
    pub fn fault(&self, fault: FetchFault) {
        self.faults.lock().unwrap().push_back(fault);
    }
    /// Later fetches report RepresentationChanged until the next probe.
    pub fn change_representation(&self) {
        *self.changed.lock().unwrap() = true;
    }
    /// The server now serves different content (possibly the same size): a new
    /// validator. Fetches bound to the old one report RepresentationChanged.
    pub fn replace_body(&self, body: Vec<u8>) {
        *self.body.lock().unwrap() = Arc::new(body);
        *self.changed.lock().unwrap() = true;
    }
    fn validator(&self, body: &[u8]) -> Option<[u8; 32]> {
        self.ranges.then(|| digest(body))
    }
    pub fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}
impl Transport for ScriptedTransport {
    fn probe(&self, _: SourceRef) -> PortFuture<'_, Result<Probe, TransportError>> {
        Box::pin(async move {
            if let Some(error) = self.probe_faults.lock().unwrap().pop_front() {
                return Err(error);
            }
            *self.changed.lock().unwrap() = false;
            let body = self.body.lock().unwrap().clone();
            Ok(Probe::new(body.len() as u64, self.validator(&body)))
        })
    }
    fn fetch(
        &self,
        _: SourceRef,
        range: ByteRange,
        validator: Option<[u8; 32]>,
    ) -> PortFuture<'_, Result<Box<dyn ByteStream>, TransportError>> {
        Box::pin(async move {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            let body = self.body.lock().unwrap().clone();
            if *self.changed.lock().unwrap() || validator != self.validator(&body) {
                return Err(TransportError::RepresentationChanged);
            }
            if range.end() > body.len() as u64
                || (!self.ranges && (range.start() != 0 || range.end() != body.len() as u64))
            {
                return Err(TransportError::Fatal(fhd_domain::StopReason::Unknown));
            }
            let fault = self.faults.lock().unwrap().pop_front();
            if let Some(FetchFault::Fail(error)) = fault {
                return Err(error);
            }
            Ok(Box::new(ScriptedStream {
                body,
                at: range.start() as usize,
                end: range.end() as usize,
                chunk: self.chunk,
                delivered: 0,
                fault,
            }) as Box<dyn ByteStream>)
        })
    }
}
struct ScriptedStream {
    body: Arc<Vec<u8>>,
    at: usize,
    end: usize,
    chunk: usize,
    delivered: usize,
    fault: Option<FetchFault>,
}
impl ByteStream for ScriptedStream {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, TransportError>> {
        Box::pin(async move {
            let mut limit = self.chunk.min(buf.len()).min(self.end - self.at);
            match self.fault {
                Some(FetchFault::Truncate { after, error }) if self.delivered >= after => {
                    return Err(error)
                }
                Some(FetchFault::Stall { after }) if self.delivered >= after => {
                    std::future::pending::<()>().await;
                }
                Some(FetchFault::Truncate { after, .. } | FetchFault::Stall { after }) => {
                    limit = limit.min(after - self.delivered);
                }
                _ => {}
            }
            buf[..limit].copy_from_slice(&self.body[self.at..self.at + limit]);
            self.at += limit;
            self.delivered += limit;
            Ok(limit)
        })
    }
}

/// Maps every destination reference to one path under a test directory.
pub struct FixedDestination(pub PathBuf);
impl Destinations for FixedDestination {
    fn resolve(&self, _: DestinationRef) -> Result<PathBuf, AppError> {
        Ok(self.0.clone())
    }
}
