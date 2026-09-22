//! Runs one job session. The coordinator alone owns the `Job`: every transition is
//! decide → commit → apply. Workers only fetch and hand buffers to the writer lane.
//! A checkpoint is prepare_sync → sync → hash each range → commit extents → ack.
use crate::{
    buffers::{BufferPool, MAX_BUFFER},
    writer::{Writer, WriterError},
    CancellationToken,
};
use fhd_app::{
    storage::{PartSpec, SegmentFile, SegmentStore, StorageError},
    transport::{Transport, TransportError},
    CommitError, DurableExtent, TransferRepository,
};
use fhd_domain::{
    ByteRange, DomainError, ErrorClass, Job, JobCommand, JobState, Lease, RetryDecision,
    RetryPolicy, SegmentState, SourceRef, StopReason,
};
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::{
    sync::mpsc,
    task::{Id, JoinSet},
};

/// Wall-clock milliseconds (persisted retry deadlines) and caller-supplied jitter.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
    fn jitter(&self) -> u64;
}

#[derive(Clone, Copy, Debug)]
pub struct CoordinatorConfig {
    pub connections: usize,
    pub max_segments: usize,
    /// Split granularity; initial and stolen splits align to it.
    pub min_segment: u64,
    /// Written-but-unsynced bytes that trigger a checkpoint.
    pub checkpoint_bytes: u64,
    pub writer_capacity: usize,
    pub retry: RetryPolicy,
}
impl CoordinatorConfig {
    fn valid(&self) -> bool {
        (1..=16).contains(&self.connections)
            && (self.connections..=262_144).contains(&self.max_segments)
            && self.min_segment > 0
            && self.checkpoint_bytes > 0
            && (1..=256).contains(&self.writer_capacity)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Pause,
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// The job rests in this state; the scheduler decides what happens next.
    Settled(JobState),
    /// Every byte durable and the whole file verified; the job stays in Verifying
    /// until publication (which needs a durable PublishIntent) is implemented.
    Verified([u8; 32]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunError {
    InvalidConfig,
    NotRunnable(JobState),
    Domain(DomainError),
    /// The repository refused or could not confirm a commit. The session aborted;
    /// reload the job from the repository before any further decision.
    Commit(CommitError),
    Repository,
    Writer(WriterError),
    Storage(StorageError),
    /// Internal bookkeeping disagreed with itself; a bug, never an input problem.
    Invariant,
}

enum Failure {
    Cancelled,
    Transport(TransportError),
    Writer(WriterError),
    Panicked,
}

pub struct Coordinator {
    repository: Arc<dyn TransferRepository>,
    store: Arc<dyn SegmentStore>,
    transport: Arc<dyn Transport>,
    buffers: BufferPool,
    clock: Arc<dyn Clock>,
    config: CoordinatorConfig,
    directory: PathBuf,
}

async fn step(
    repository: &dyn TransferRepository,
    job: &mut Job,
    command: JobCommand,
) -> Result<(), RunError> {
    for event in job.decide(command).map_err(RunError::Domain)? {
        repository
            .commit_transition(event.clone())
            .await
            .map_err(RunError::Commit)?;
        job.apply(&event).map_err(RunError::Domain)?;
    }
    Ok(())
}

impl Coordinator {
    pub fn new(
        repository: Arc<dyn TransferRepository>,
        store: Arc<dyn SegmentStore>,
        transport: Arc<dyn Transport>,
        buffers: BufferPool,
        clock: Arc<dyn Clock>,
        config: CoordinatorConfig,
        directory: PathBuf,
    ) -> Result<Self, RunError> {
        let block = MAX_BUFFER.min(buffers.capacity());
        if !config.valid() || buffers.capacity() < config.connections * block {
            return Err(RunError::InvalidConfig);
        }
        Ok(Self {
            repository,
            store,
            transport,
            buffers,
            clock,
            config,
            directory,
        })
    }

    /// Settles a job restored after a crash (§5.2): nothing is resumed implicitly.
    /// Part-file cleanup for Cancelling is not implemented yet; the record completes.
    pub async fn recover(&self, mut job: Job) -> Result<Job, RunError> {
        let repository = self.repository.as_ref();
        match job.state() {
            JobState::Probing | JobState::Transferring | JobState::Verifying => {
                step(repository, &mut job, JobCommand::Pause).await?;
                if job.state() == JobState::Stopping {
                    step(repository, &mut job, JobCommand::WorkersDrained).await?;
                }
            }
            JobState::Stopping => step(repository, &mut job, JobCommand::WorkersDrained).await?,
            JobState::Cancelling => step(repository, &mut job, JobCommand::CleanupFinished).await?,
            _ => {}
        }
        Ok(job)
    }

    /// Runs a Queued job (or re-verifies a Verifying one) until it settles.
    /// Drive the future to completion: dropping it aborts workers without draining
    /// the writer lane; use `Control::Pause` or `Control::Cancel` to stop instead.
    pub async fn run(
        &self,
        job: Job,
        control: mpsc::Receiver<Control>,
    ) -> Result<SessionEnd, RunError> {
        if !matches!(job.state(), JobState::Queued | JobState::Verifying) {
            return Err(RunError::NotRunnable(job.state()));
        }
        let mut session = Session {
            c: self,
            source: job.spec().source(),
            job,
            control,
            control_open: true,
            writer: None,
            workers: JoinSet::new(),
            leases: HashMap::new(),
            stop_workers: CancellationToken::new(),
            io: CancellationToken::new(),
            unsynced: 0,
            storage_failed: false,
            connections: self.config.connections,
            next_worker: 0,
        };
        let result = session.drive().await;
        session.close().await;
        result
    }
}

struct Session<'c> {
    c: &'c Coordinator,
    source: SourceRef,
    job: Job,
    control: mpsc::Receiver<Control>,
    control_open: bool,
    writer: Option<Arc<Writer>>,
    workers: JoinSet<Result<(), Failure>>,
    leases: HashMap<Id, Lease>,
    /// Cancels network workers; never used for the coordinator's own writer calls.
    stop_workers: CancellationToken,
    io: CancellationToken,
    unsynced: u64,
    storage_failed: bool,
    connections: usize,
    next_worker: u64,
}

impl Session<'_> {
    async fn step(&mut self, command: JobCommand) -> Result<(), RunError> {
        step(self.c.repository.as_ref(), &mut self.job, command).await
    }

    async fn drive(&mut self) -> Result<SessionEnd, RunError> {
        if self.job.state() == JobState::Verifying {
            self.open_part().await?;
            return self.verify().await;
        }
        self.step(JobCommand::Start).await?;
        let probe = loop {
            tokio::select! { biased;
                control = self.control.recv(), if self.control_open => {
                    if control.is_none() {
                        self.control_open = false;
                        continue;
                    }
                    self.on_control(control).await?;
                    return self.finish().await;
                }
                probe = self.c.transport.probe(self.source) => break probe,
            }
        };
        let probe = match probe {
            Ok(probe) => probe,
            Err(error) => {
                self.on_transport_error(error).await?;
                return self.finish().await;
            }
        };
        let durable = self.job.projection().durable_bytes;
        let changed = self
            .job
            .plan()
            .is_some_and(|(total, _)| total != probe.total())
            || (!probe.ranges() && durable > 0);
        if changed {
            self.step(JobCommand::RepresentationChanged).await?;
            return self.finish().await;
        }
        if !probe.ranges() {
            self.connections = 1;
        }
        let max_segments = if probe.ranges() {
            self.c.config.max_segments
        } else {
            1
        };
        self.step(JobCommand::ProbeSucceeded {
            total: probe.total(),
            max_segments,
        })
        .await?;
        self.open_part().await?;
        if self.job.state() != JobState::Transferring {
            return self.finish().await;
        }
        self.initial_split()?;
        self.transfer().await?;
        self.finish().await
    }

    /// Creates the part, or reopens it and re-proves every durable extent by digest.
    async fn open_part(&mut self) -> Result<(), RunError> {
        let (total, _) = self
            .job
            .plan()
            .ok_or(RunError::NotRunnable(self.job.state()))?;
        let spec =
            PartSpec::new(self.job.id(), self.job.generation(), total).map_err(RunError::Domain)?;
        let extents = self
            .c
            .repository
            .durable_extents(self.job.id())
            .await
            .map_err(|_| RunError::Repository)?;
        let store = self.c.store.clone();
        let directory = self.c.directory.clone();
        let opened =
            tokio::task::spawn_blocking(move || -> Result<Box<dyn SegmentFile>, StorageError> {
                if extents.is_empty() {
                    return match store.create(&directory, spec) {
                        Err(StorageError::Conflict) => store.open(&directory, spec),
                        other => other,
                    };
                }
                let mut file = store.open(&directory, spec)?;
                for extent in extents {
                    file.recover_extent(extent.range(), extent.digest())?;
                }
                Ok(file)
            })
            .await
            .map_err(|_| RunError::Writer(WriterError::WorkerFailed))?;
        let file = match opened {
            Ok(file) => file,
            Err(error) => {
                self.storage_failed = true;
                let reason = if error == StorageError::Integrity {
                    StopReason::Integrity
                } else {
                    StopReason::Storage
                };
                let command = JobCommand::RequireAction { reason };
                if self.job.state() == JobState::Verifying {
                    self.step(command).await?;
                } else {
                    self.stop_with(command).await?;
                }
                return Ok(());
            }
        };
        let writer =
            Writer::start(file, self.c.config.writer_capacity).map_err(RunError::Writer)?;
        self.writer = Some(Arc::new(writer));
        Ok(())
    }

    /// A fresh single-segment plan is cut into aligned pieces, one per connection.
    fn initial_split(&mut self) -> Result<(), RunError> {
        let Some(map) = self.job.segments() else {
            return Ok(());
        };
        let [only] = map.segments() else {
            return Ok(());
        };
        if only.state() != SegmentState::Pending || only.range().start() != 0 {
            return Ok(());
        }
        let (mut current, total) = (only.id(), only.range().end());
        let unit = self.c.config.min_segment;
        let pieces = (total / unit).min(self.connections as u64);
        if pieces < 2 {
            return Ok(());
        }
        let size = total.div_ceil(pieces).div_ceil(unit) * unit;
        let mut at = size;
        while at < total {
            current = match self.job.split_pending(current, at) {
                Ok(right) => right,
                Err(DomainError::Capacity) => break,
                Err(error) => return Err(RunError::Domain(error)),
            };
            at += size;
        }
        Ok(())
    }

    /// Next pending segment to lease. While idle connections outnumber pending
    /// pieces, the largest pending piece is halved (aligned) instead of waiting.
    fn next_pending(&mut self) -> Result<Option<fhd_domain::SegmentId>, RunError> {
        let Some(map) = self.job.segments() else {
            return Ok(None);
        };
        let pending: Vec<_> = map
            .segments()
            .iter()
            .filter(|s| s.state() == SegmentState::Pending)
            .map(|s| (s.id(), s.range()))
            .collect();
        let Some(&(first, _)) = pending.first() else {
            return Ok(None);
        };
        let idle = self.connections - self.workers.len();
        let unit = self.c.config.min_segment;
        if let Some(&(id, range)) = pending.iter().max_by_key(|(_, r)| r.len()) {
            let mid = range.start() + (range.len() / 2).div_ceil(unit) * unit;
            if pending.len() < idle && range.len() >= 2 * unit && mid < range.end() {
                match self.job.split_pending(id, mid) {
                    Ok(right) => return Ok(Some(right)),
                    Err(DomainError::Capacity) => {}
                    Err(error) => return Err(RunError::Domain(error)),
                }
            }
        }
        Ok(Some(self.cap_lease(first)?))
    }

    /// Leases at most `max(min_segment, checkpoint_bytes)` (aligned): a cancelled or
    /// failed connection then loses at most one bounded piece, not a whole share.
    fn cap_lease(&mut self, id: fhd_domain::SegmentId) -> Result<fhd_domain::SegmentId, RunError> {
        let unit = self.c.config.min_segment;
        let cap = self.c.config.checkpoint_bytes.max(unit).div_ceil(unit) * unit;
        let Some(range) = self
            .job
            .segments()
            .and_then(|m| m.segments().iter().find(|s| s.id() == id))
            .map(|s| s.range())
        else {
            return Ok(id);
        };
        if range.len() > cap {
            match self.job.split_pending(id, range.start() + cap) {
                Ok(_) | Err(DomainError::Capacity) => {}
                Err(error) => return Err(RunError::Domain(error)),
            }
        }
        Ok(id)
    }

    fn spawn_workers(&mut self) -> Result<(), RunError> {
        while self.job.state() == JobState::Transferring && self.workers.len() < self.connections {
            let Some(id) = self.next_pending()? else {
                break;
            };
            self.next_worker += 1;
            let lease = self
                .job
                .lease_segment(id, self.next_worker)
                .map_err(RunError::Domain)?;
            let writer = self
                .writer
                .clone()
                .ok_or(RunError::Writer(WriterError::Closed))?;
            let task = fetch(
                self.c.transport.clone(),
                self.source,
                writer,
                self.c.buffers.clone(),
                lease,
                self.stop_workers.clone(),
            );
            let handle = self.workers.spawn(task);
            self.leases.insert(handle.id(), lease);
        }
        Ok(())
    }

    fn has_unsynced(&self) -> bool {
        self.job.segments().is_some_and(|m| m.has_unsynced())
    }

    async fn transfer(&mut self) -> Result<(), RunError> {
        loop {
            self.spawn_workers()?;
            let state = self.job.state();
            if self.workers.is_empty() {
                match state {
                    JobState::Transferring => {
                        if self.has_unsynced() {
                            self.checkpoint().await?;
                            continue;
                        }
                        if self.job.segments().is_some_and(|m| m.all_durable()) {
                            self.step(JobCommand::AllSegmentsDurable).await?;
                            continue;
                        }
                        // Nothing leasable and nothing running: cannot progress.
                        return Err(RunError::Invariant);
                    }
                    _ => return Ok(()),
                }
            }
            if state == JobState::Transferring && self.unsynced >= self.c.config.checkpoint_bytes {
                self.checkpoint().await?;
            }
            tokio::select! {
                Some(done) = self.workers.join_next_with_id() => self.on_worker(done).await?,
                control = self.control.recv(), if self.control_open => self.on_control(control).await?,
            }
        }
    }

    async fn on_worker(
        &mut self,
        done: Result<(Id, Result<(), Failure>), tokio::task::JoinError>,
    ) -> Result<(), RunError> {
        let (id, outcome) = match done {
            Ok((id, outcome)) => (id, outcome),
            Err(error) => (error.id(), Err(Failure::Panicked)),
        };
        let lease = self.leases.remove(&id).ok_or(RunError::Invariant)?;
        match outcome {
            Ok(()) => {
                self.job.mark_written(lease).map_err(RunError::Domain)?;
                self.unsynced += lease.range().len();
            }
            Err(failure) => {
                self.job.release(lease).map_err(RunError::Domain)?;
                match failure {
                    Failure::Cancelled => {}
                    Failure::Transport(error) => self.on_transport_error(error).await?,
                    Failure::Writer(WriterError::Cancelled) => {}
                    Failure::Writer(_) => self.on_storage_failure().await?,
                    Failure::Panicked => {
                        self.stop_with(JobCommand::Fail {
                            reason: StopReason::Unknown,
                        })
                        .await?
                    }
                }
            }
        }
        Ok(())
    }

    async fn on_control(&mut self, control: Option<Control>) -> Result<(), RunError> {
        match control {
            None => self.control_open = false,
            Some(Control::Pause) => self.stop_with(JobCommand::Pause).await?,
            Some(Control::Cancel) => {
                self.step(JobCommand::Cancel).await?;
                self.stop_workers.cancel();
            }
        }
        Ok(())
    }

    /// Enters or raises Stopping and stops the network workers.
    async fn stop_with(&mut self, command: JobCommand) -> Result<(), RunError> {
        if matches!(
            self.job.state(),
            JobState::Probing | JobState::Transferring | JobState::Stopping
        ) {
            self.step(command).await?;
        }
        self.stop_workers.cancel();
        Ok(())
    }

    async fn on_transport_error(&mut self, error: TransportError) -> Result<(), RunError> {
        let command = match error {
            TransportError::RepresentationChanged => JobCommand::RepresentationChanged,
            TransportError::UserAction(reason) => JobCommand::RequireAction { reason },
            TransportError::Fatal(reason) => JobCommand::Fail { reason },
            TransportError::Transient | TransportError::Throttled { .. } => {
                let now = self.c.clock.now_ms();
                let (class, deadline) = match error {
                    TransportError::Throttled { retry_after_ms } => (
                        ErrorClass::Throttled,
                        retry_after_ms.map(|ms| now.saturating_add(ms)),
                    ),
                    _ => (ErrorClass::Transient, None),
                };
                match self.c.config.retry.decide(
                    class,
                    self.job.attempts().max(1),
                    now,
                    deadline,
                    self.c.clock.jitter(),
                ) {
                    Ok(RetryDecision::RetryAt(at_tick)) => JobCommand::Retry { at_tick },
                    _ => JobCommand::RequireAction {
                        reason: StopReason::Network,
                    },
                }
            }
        };
        self.stop_with(command).await
    }

    async fn on_storage_failure(&mut self) -> Result<(), RunError> {
        self.storage_failed = true;
        self.stop_with(JobCommand::RequireAction {
            reason: StopReason::Storage,
        })
        .await
    }

    async fn checkpoint(&mut self) -> Result<(), RunError> {
        if !self.has_unsynced() || self.storage_failed {
            return Ok(());
        }
        let writer = self
            .writer
            .clone()
            .ok_or(RunError::Writer(WriterError::Closed))?;
        let ticket = self.job.prepare_sync().map_err(RunError::Domain)?;
        if writer.sync(&self.io).await.is_err() {
            self.job.abandon_checkpoint().map_err(RunError::Domain)?;
            return self.on_storage_failure().await;
        }
        let batch = self
            .job
            .acknowledge_sync(ticket)
            .map_err(RunError::Domain)?;
        let mut extents = Vec::with_capacity(batch.ranges().len());
        for range in batch.ranges() {
            match writer.hash(*range, &self.io).await {
                Ok(digest) => extents.push(DurableExtent::new(*range, digest)),
                Err(_) => {
                    self.job.abandon_checkpoint().map_err(RunError::Domain)?;
                    return self.on_storage_failure().await;
                }
            }
        }
        // Idempotent: an ambiguous failure is retried with identical extents.
        let mut attempt = 0;
        loop {
            match self
                .c
                .repository
                .commit_extents(batch.job(), batch.generation(), extents.clone())
                .await
            {
                Ok(()) => break,
                Err(CommitError::Unavailable) if attempt < 2 => {
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(50 * attempt)).await;
                }
                Err(error) => {
                    self.job.abandon_checkpoint().map_err(RunError::Domain)?;
                    return Err(RunError::Commit(error));
                }
            }
        }
        self.job
            .acknowledge_commit(batch)
            .map_err(RunError::Domain)?;
        self.unsynced = 0;
        Ok(())
    }

    /// Drains the stop: final checkpoint (or discard if storage failed), then settle.
    async fn finish(&mut self) -> Result<SessionEnd, RunError> {
        while let Some(done) = self.workers.join_next_with_id().await {
            self.on_worker(done).await?;
        }
        while self.control_open {
            match self.control.try_recv() {
                Ok(Control::Cancel)
                    if matches!(self.job.state(), JobState::Stopping | JobState::Paused) =>
                {
                    self.step(JobCommand::Cancel).await?
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        match self.job.state() {
            JobState::Stopping => {
                if self.has_unsynced() && !self.job.representation_change_pending() {
                    if self.storage_failed {
                        self.job.discard_unsynced().map_err(RunError::Domain)?;
                    } else {
                        self.checkpoint().await?;
                        if self.storage_failed {
                            self.job.discard_unsynced().map_err(RunError::Domain)?;
                        }
                    }
                }
                self.step(JobCommand::WorkersDrained).await?;
            }
            JobState::Cancelling => self.step(JobCommand::CleanupFinished).await?,
            _ => {}
        }
        if self.job.state() == JobState::Verifying {
            return self.verify().await;
        }
        Ok(SessionEnd::Settled(self.job.state()))
    }

    async fn verify(&mut self) -> Result<SessionEnd, RunError> {
        let Some(writer) = self.writer.clone() else {
            return Ok(SessionEnd::Settled(self.job.state()));
        };
        match writer
            .verify(self.job.spec().expected_sha256(), &self.io)
            .await
        {
            Ok(digest) => Ok(SessionEnd::Verified(digest)),
            Err(error) => {
                let reason = if error == WriterError::Storage(StorageError::Integrity) {
                    StopReason::Integrity
                } else {
                    StopReason::Storage
                };
                self.step(JobCommand::RequireAction { reason }).await?;
                Ok(SessionEnd::Settled(self.job.state()))
            }
        }
    }

    /// Stops workers and waits for the writer thread; accepted writes finish first.
    async fn close(&mut self) {
        self.stop_workers.cancel();
        while self.workers.join_next().await.is_some() {}
        self.leases.clear();
        if let Some(writer) = self.writer.take() {
            match Arc::try_unwrap(writer) {
                Ok(writer) => {
                    let _ = writer.shutdown().await;
                }
                // Every worker is joined, so no clone can remain.
                Err(_) => debug_assert!(false, "writer still shared after workers joined"),
            }
        }
    }
}

/// One connection: fetch the leased range and hand full buffers to the writer lane.
async fn fetch(
    transport: Arc<dyn Transport>,
    source: SourceRef,
    writer: Arc<Writer>,
    buffers: BufferPool,
    lease: Lease,
    cancel: CancellationToken,
) -> Result<(), Failure> {
    let range: ByteRange = lease.range();
    let spec = writer.spec();
    let mut stream = tokio::select! { biased;
        _ = cancel.cancelled() => return Err(Failure::Cancelled),
        stream = transport.fetch(source, range) => stream.map_err(Failure::Transport)?,
    };
    let block = MAX_BUFFER.min(buffers.capacity()) as u64;
    let mut offset = range.start();
    while offset < range.end() {
        let len = block.min(range.end() - offset) as usize;
        let mut buffer = buffers
            .acquire(len, &cancel)
            .await
            .map_err(|_| Failure::Cancelled)?;
        let mut filled = 0;
        while filled < len {
            let read = tokio::select! { biased;
                _ = cancel.cancelled() => return Err(Failure::Cancelled),
                read = stream.read(&mut buffer.as_mut_slice()[filled..]) => read.map_err(Failure::Transport)?,
            };
            if read == 0 {
                return Err(Failure::Transport(TransportError::Transient));
            }
            filled += read;
        }
        writer
            .write(spec, offset, buffer, &cancel)
            .await
            .map_err(Failure::Writer)?;
        offset += len as u64;
    }
    let mut probe = [0u8; 1];
    let tail = tokio::select! { biased;
        _ = cancel.cancelled() => return Err(Failure::Cancelled),
        read = stream.read(&mut probe) => read.map_err(Failure::Transport)?,
    };
    if tail != 0 {
        return Err(Failure::Transport(TransportError::Transient));
    }
    Ok(())
}
