//! Bounded, process-local ownership of transfers. Call `shutdown` before stopping
//! the Tokio runtime; dropping the handle requests cancellation but cannot await it.

use crate::queue_store::{
    encode_options_v2, QueueStore, Receipt, SavedJob, Snapshot, MAX_RECEIPTS,
};
use crate::{download_controlled, Bandwidth, Error, Options, Outcome, TrafficControl};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    path::{Component, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::{Id, JoinHandle, JoinSet},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct JobId(pub u64);

/// Non-preemptive scheduling priority. Equal priorities retain queue order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Low,
    #[default]
    Normal,
    High,
}

// A normalized origin, never included in public snapshots or diagnostics.
#[derive(Clone, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

fn origin(options: &Options) -> Result<Origin, ManagerError> {
    let url = crate::parse_url(&options.url, options.allow_http)
        .map_err(|_| ManagerError::InvalidOptions)?;
    Ok(Origin {
        scheme: url.scheme().to_owned(),
        host: url
            .host_str()
            .ok_or(ManagerError::InvalidOptions)?
            .to_owned(),
        port: url
            .port_or_known_default()
            .ok_or(ManagerError::InvalidOptions)?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Queued,
    Running,
    Pausing,
    Paused,
    Completed,
    Failed(Error),
    RetryWaiting,
}

/// Deliberately excludes URLs, filenames, paths and response headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSnapshot {
    pub id: JobId,
    pub priority: Priority,
    pub state: State,
    pub committed_bytes: u64,
    pub attempts: u8,
    pub bytes_per_second: Option<u64>,
    pub parallel_connections: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagerError {
    InvalidLimits,
    NoRuntime,
    Closed,
    Capacity,
    InvalidOptions,
    InvalidPath,
    DuplicateJob,
    UnknownJob,
    InvalidTransition,
    WorkerFailed,
    Persistence,
    SecretStorage,
    QueueLocked,
    NotDurable,
    InvalidIdempotencyKey,
    IdempotencyConflict,
    PreviouslyRemoved,
    ReceiptCapacity,
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ManagerError {}

/// The first request counts as an attempt; retry delays release worker slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    pub max_attempts: u8,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
}
impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 1000,
            max_delay_ms: 30_000,
        }
    }
}
impl RetryPolicy {
    pub fn disabled() -> Self {
        Self {
            max_attempts: 1,
            ..Self::default()
        }
    }
    fn delay(self, attempts: u8) -> Duration {
        Duration::from_millis(
            self.initial_delay_ms
                .saturating_mul(1u64 << attempts.saturating_sub(1).min(4))
                .min(self.max_delay_ms),
        )
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub max_active: usize,
    pub max_jobs: usize,
    pub max_per_origin: usize,
    pub retry: RetryPolicy,
    pub global_bytes_per_second: Option<u64>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            max_active: 3,
            max_jobs: 1024,
            max_per_origin: 2,
            retry: RetryPolicy::default(),
            global_bytes_per_second: None,
        }
    }
}
impl Config {
    pub(crate) fn validate(&self) -> Result<(), ManagerError> {
        if !(1..=32).contains(&self.max_active)
            || !(1..=1024).contains(&self.max_jobs)
            || self.max_active > self.max_jobs
            || !(1..=self.max_active).contains(&self.max_per_origin)
            || !(1..=5).contains(&self.retry.max_attempts)
            || !(100..=60_000).contains(&self.retry.initial_delay_ms)
            || !(self.retry.initial_delay_ms..=300_000).contains(&self.retry.max_delay_ms)
            || !crate::rate::valid_limit(self.global_bytes_per_second)
        {
            return Err(ManagerError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Default)]
struct AdmissionLedger {
    last_id: u64,
    receipts: Vec<Receipt>,
}
struct AdmissionHashes {
    key: [u8; 32],
    payload: [u8; 32],
}
fn admission_hashes(
    key: &str,
    options: &Options,
    priority: Priority,
) -> Result<AdmissionHashes, ManagerError> {
    if key.is_empty() || key.len() > 128 || !key.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Err(ManagerError::InvalidIdempotencyKey);
    }
    validate_options(options)?;
    if !options.job_dir.is_absolute()
        || options
            .job_dir
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(ManagerError::InvalidPath);
    }
    let mut canonical = options.clone();
    canonical.url = crate::parse_url(&options.url, options.allow_http)
        .map_err(|_| ManagerError::InvalidOptions)?
        .to_string();
    // Stable lexical normalization without querying a path that may have moved
    // since acceptance. Preserve case, including case-sensitive Windows dirs.
    canonical.job_dir = options.job_dir.components().collect();
    let mut bytes = Zeroizing::new(b"FHD.admission.payload.v1\0".to_vec());
    encode_options_v2(&mut bytes, &canonical)?;
    bytes.push(match priority {
        Priority::Low => 0,
        Priority::Normal => 1,
        Priority::High => 2,
    });
    let payload = Sha256::digest(&bytes).into();
    let mut hash = Sha256::new();
    hash.update(b"FHD.admission.key.v1\0");
    hash.update((key.len() as u64).to_le_bytes());
    hash.update(key.as_bytes());
    Ok(AdmissionHashes {
        key: hash.finalize().into(),
        payload,
    })
}

type Reply<T> = oneshot::Sender<Result<T, ManagerError>>;
enum Command {
    Enqueue(
        Box<Options>,
        Priority,
        Option<AdmissionHashes>,
        Reply<JobId>,
    ),
    SetPriority(JobId, Priority, Reply<()>),
    Pause(JobId, Reply<()>),
    Resume(JobId, Reply<()>),
    GlobalRate(Option<u64>, Reply<()>),
    JobRate(JobId, Option<u64>, Reply<()>),
    ResumeAll(Reply<()>),
    Refresh(JobId, String, Reply<()>),
    Forget(JobId, Reply<()>),
}

/// One owner; command methods may be used concurrently through shared references.
/// Successful command submission may take effect even if its caller stops waiting.
pub struct Manager {
    commands: Option<mpsc::Sender<Command>>,
    snapshots: watch::Receiver<Vec<JobSnapshot>>,
    actor: Option<JoinHandle<Result<(), ManagerError>>>,
    durable: bool,
}

impl Manager {
    pub fn start(max_active: usize, max_jobs: usize) -> Result<Self, ManagerError> {
        Self::start_with_limits(max_active, max_jobs, max_active)
    }

    /// Limits concurrent transfers by normalized scheme, host and effective port.
    /// Running and pausing workers hold their slots until they have joined.
    pub fn start_with_limits(
        max_active: usize,
        max_jobs: usize,
        max_per_origin: usize,
    ) -> Result<Self, ManagerError> {
        Self::start_configured(Config {
            max_active,
            max_jobs,
            max_per_origin,
            retry: RetryPolicy::disabled(),
            global_bytes_per_second: None,
        })
    }

    pub fn start_configured(config: Config) -> Result<Self, ManagerError> {
        config.validate()?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| ManagerError::NoRuntime)?;
        Self::launch(runtime, config, Vec::new(), None)
    }

    /// Opens an encrypted Windows user-scoped queue. Existing settings prevail;
    /// nonterminal jobs recover paused and require explicit resume.
    pub async fn open(path: PathBuf, config: Config) -> Result<Self, ManagerError> {
        config.validate()?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| ManagerError::NoRuntime)?;
        let (store, saved) = tokio::task::spawn_blocking(move || {
            let mut store = QueueStore::open(&path)?;
            let saved = match store.load()? {
                Some(saved) => saved,
                None => {
                    let saved = Snapshot {
                        config,
                        jobs: vec![],
                        queue: vec![],
                        last_id: 0,
                        receipts: vec![],
                    };
                    store.save(&saved)?;
                    saved
                }
            };
            Ok::<_, ManagerError>((store, saved))
        })
        .await
        .map_err(|_| ManagerError::WorkerFailed)??;
        let config = saved.config;
        let global = Bandwidth::new(config.global_bytes_per_second)
            .map_err(|_| ManagerError::InvalidLimits)?;
        let mut jobs: Vec<(JobId, Job)> = Vec::new();
        for saved in saved.jobs {
            validate_options(&saved.options)?;
            let path = saved.options.job_dir.clone();
            let key = tokio::task::spawn_blocking(move || path_key(path))
                .await
                .map_err(|_| ManagerError::WorkerFailed)??;
            if jobs.iter().any(|(_, job)| job.key == key) {
                return Err(ManagerError::DuplicateJob);
            }
            let control =
                TrafficControl::with_global(global.clone(), saved.options.bytes_per_second)
                    .map_err(|_| ManagerError::InvalidOptions)?;
            let state = match saved.state {
                State::Completed | State::Failed(_) | State::Paused => saved.state,
                _ => State::Paused,
            };
            jobs.push((
                saved.id,
                Job {
                    origin: origin(&saved.options)?,
                    options: saved.options,
                    priority: saved.priority,
                    key,
                    state,
                    progress: Arc::new(AtomicU64::new(saved.progress)),
                    cancel: None,
                    pause_reply: None,
                    attempts: saved.attempts,
                    retry_at: None,
                    control,
                },
            ));
        }
        // Queue rank is retained even though recovery requires explicit resume.
        jobs.sort_by_key(|(id, _)| {
            saved
                .queue
                .iter()
                .position(|queued| queued == id)
                .unwrap_or(usize::MAX)
        });
        Self::launch_with_global(
            runtime,
            config,
            jobs,
            Some(store),
            global,
            AdmissionLedger {
                last_id: saved.last_id,
                receipts: saved.receipts,
            },
        )
    }

    fn launch(
        runtime: tokio::runtime::Handle,
        config: Config,
        jobs: Vec<(JobId, Job)>,
        store: Option<QueueStore>,
    ) -> Result<Self, ManagerError> {
        let global = Bandwidth::new(config.global_bytes_per_second)
            .map_err(|_| ManagerError::InvalidLimits)?;
        Self::launch_with_global(
            runtime,
            config,
            jobs,
            store,
            global,
            AdmissionLedger::default(),
        )
    }

    fn launch_with_global(
        runtime: tokio::runtime::Handle,
        config: Config,
        jobs: Vec<(JobId, Job)>,
        store: Option<QueueStore>,
        global: Bandwidth,
        ledger: AdmissionLedger,
    ) -> Result<Self, ManagerError> {
        let (commands, receiver) = mpsc::channel(64);
        let (updates, snapshots) = watch::channel(Vec::new());
        publish(&jobs, &updates);
        let durable = store.is_some();
        let actor = runtime.spawn(run(receiver, updates, config, jobs, store, global, ledger));
        Ok(Self {
            commands: Some(commands),
            snapshots,
            actor: Some(actor),
            durable,
        })
    }

    pub async fn set_global_rate(&self, rate: Option<u64>) -> Result<(), ManagerError> {
        if !crate::rate::valid_limit(rate) {
            return Err(ManagerError::InvalidOptions);
        }
        let (reply, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or(ManagerError::Closed)?
            .send(Command::GlobalRate(rate, reply))
            .await
            .map_err(|_| ManagerError::Closed)?;
        result.await.map_err(|_| ManagerError::Closed)?
    }

    pub async fn set_job_rate(&self, id: JobId, rate: Option<u64>) -> Result<(), ManagerError> {
        if !crate::rate::valid_limit(rate) {
            return Err(ManagerError::InvalidOptions);
        }
        let (reply, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or(ManagerError::Closed)?
            .send(Command::JobRate(id, rate, reply))
            .await
            .map_err(|_| ManagerError::Closed)?;
        result.await.map_err(|_| ManagerError::Closed)?
    }

    /// Resumes all paused/failed jobs atomically, retaining recovered queue order.
    pub async fn resume_all(&self) -> Result<(), ManagerError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or(ManagerError::Closed)?
            .send(Command::ResumeAll(reply))
            .await
            .map_err(|_| ManagerError::Closed)?;
        result.await.map_err(|_| ManagerError::Closed)?
    }

    pub fn subscribe(&self) -> watch::Receiver<Vec<JobSnapshot>> {
        self.snapshots.clone()
    }

    pub async fn enqueue(&self, options: Options) -> Result<JobId, ManagerError> {
        self.enqueue_with_priority(options, Priority::Normal).await
    }

    pub async fn enqueue_with_priority(
        &self,
        options: Options,
        priority: Priority,
    ) -> Result<JobId, ManagerError> {
        validate_options(&options)?;
        let (reply, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or(ManagerError::Closed)?
            .send(Command::Enqueue(Box::new(options), priority, None, reply))
            .await
            .map_err(|_| ManagerError::Closed)?;
        result.await.map_err(|_| ManagerError::Closed)?
    }

    /// Durably admits one immutable caller request. Replay returns its original
    /// job, conflicts reject changes, and forgotten jobs retain a tombstone.
    /// The caller must namespace keys by its authenticated source before calling.
    pub async fn enqueue_once(
        &self,
        key: String,
        options: Options,
        priority: Priority,
    ) -> Result<JobId, ManagerError> {
        if !self.durable {
            return Err(ManagerError::NotDurable);
        }
        let key = Zeroizing::new(key);
        let hashes = admission_hashes(&key, &options, priority)?;
        let (reply, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or(ManagerError::Closed)?
            .send(Command::Enqueue(
                Box::new(options),
                priority,
                Some(hashes),
                reply,
            ))
            .await
            .map_err(|_| ManagerError::Closed)?;
        result.await.map_err(|_| ManagerError::Closed)?
    }

    /// Updates queued, paused or failed jobs without preempting an active transfer.
    pub async fn set_priority(&self, id: JobId, priority: Priority) -> Result<(), ManagerError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or(ManagerError::Closed)?
            .send(Command::SetPriority(id, priority, reply))
            .await
            .map_err(|_| ManagerError::Closed)?;
        result.await.map_err(|_| ManagerError::Closed)?
    }

    /// Returns only after the active worker has finished its durable cancellation.
    /// Final publication may win a late pause; inspect the resulting snapshot.
    /// A worker failure returns `WorkerFailed`; its controlled cause is in the snapshot.
    pub async fn pause(&self, id: JobId) -> Result<(), ManagerError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or(ManagerError::Closed)?
            .send(Command::Pause(id, reply))
            .await
            .map_err(|_| ManagerError::Closed)?;
        result.await.map_err(|_| ManagerError::Closed)?
    }

    pub async fn resume(&self, id: JobId) -> Result<(), ManagerError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or(ManagerError::Closed)?
            .send(Command::Resume(id, reply))
            .await
            .map_err(|_| ManagerError::Closed)?;
        result.await.map_err(|_| ManagerError::Closed)?
    }

    /// Updates only the query of a paused/failed resource; resumption remains explicit.
    pub async fn refresh_url(&self, id: JobId, url: String) -> Result<(), ManagerError> {
        crate::parse_url(&url, true).map_err(|_| ManagerError::InvalidOptions)?;
        let (reply, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or(ManagerError::Closed)?
            .send(Command::Refresh(id, url, reply))
            .await
            .map_err(|_| ManagerError::Closed)?;
        result.await.map_err(|_| ManagerError::Closed)?
    }

    /// Removes inactive queue metadata only. User files and partial data are retained.
    pub async fn forget(&self, id: JobId) -> Result<(), ManagerError> {
        let (reply, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or(ManagerError::Closed)?
            .send(Command::Forget(id, reply))
            .await
            .map_err(|_| ManagerError::Closed)?;
        result.await.map_err(|_| ManagerError::Closed)?
    }

    /// Stops admission, cancels active jobs, and awaits every worker without aborting.
    /// Success means workers drained, not that every job paused successfully; retain
    /// a snapshot subscription to inspect failures after shutdown.
    pub async fn shutdown(mut self) -> Result<(), ManagerError> {
        self.commands.take();
        if let Some(actor) = self.actor.take() {
            actor.await.map_err(|_| ManagerError::WorkerFailed)??;
        }
        Ok(())
    }
}

struct Job {
    options: Options,
    origin: Origin,
    priority: Priority,
    key: PathBuf,
    state: State,
    progress: Arc<AtomicU64>,
    cancel: Option<watch::Sender<bool>>,
    pause_reply: Option<Reply<()>>,
    attempts: u8,
    retry_at: Option<tokio::time::Instant>,
    control: TrafficControl,
}

fn validate_options(options: &Options) -> Result<(), ManagerError> {
    options
        .request_policy
        .validate()
        .map_err(|_| ManagerError::InvalidOptions)?;
    crate::files::validate_name(&options.output_name).map_err(|_| ManagerError::InvalidOptions)?;
    if options.url.len() > 16_384
        || options.output_name.is_empty()
        || options.output_name.len() > 255
        || options.job_dir.as_os_str().len() > 32_768
        || options.checkpoint_bytes == 0
        || options.checkpoint_bytes > 64 * 1024 * 1024
        || options.max_download_bytes == 0
        || options.max_download_bytes > i64::MAX as u64
        || !(1..=8).contains(&options.parallel_connections)
        || !crate::rate::valid_limit(options.bytes_per_second)
        || crate::parse_url(&options.url, options.allow_http).is_err()
    {
        return Err(ManagerError::InvalidOptions);
    }
    Ok(())
}

fn path_key(path: PathBuf) -> Result<PathBuf, ManagerError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(ManagerError::InvalidPath);
    }
    let leaf = path.file_name().ok_or(ManagerError::InvalidPath)?;
    #[cfg(windows)]
    {
        let leaf = leaf.to_str().ok_or(ManagerError::InvalidPath)?;
        let stem = leaf.split('.').next().unwrap_or("").to_ascii_lowercase();
        let device = matches!(
            stem.as_str(),
            "con" | "prn" | "aux" | "nul" | "conin$" | "conout$"
        ) || ["com", "lpt"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        });
        if leaf.ends_with(['.', ' '])
            || leaf.contains([':', '<', '>', '"', '|', '?', '*'])
            || leaf.chars().any(char::is_control)
            || device
        {
            return Err(ManagerError::InvalidPath);
        }
    }
    let parent = path.parent().ok_or(ManagerError::InvalidPath)?;
    let parent = parent
        .canonicalize()
        .map_err(|_| ManagerError::InvalidPath)?;
    let key = parent.join(leaf);
    // Existing aliases (including links) share a key; Store still independently
    // rejects unsafe filesystem objects and acquires its operating-system lock.
    let key = match key.try_exists() {
        Ok(true) => key.canonicalize().map_err(|_| ManagerError::InvalidPath)?,
        Ok(false) => key,
        Err(_) => return Err(ManagerError::InvalidPath),
    };
    #[cfg(windows)]
    let key = PathBuf::from(
        key.to_str()
            .ok_or(ManagerError::InvalidPath)?
            .to_lowercase(),
    );
    Ok(key)
}

fn publish(jobs: &[(JobId, Job)], updates: &watch::Sender<Vec<JobSnapshot>>) {
    let next: Vec<_> = jobs
        .iter()
        .map(|(id, job)| JobSnapshot {
            id: *id,
            priority: job.priority,
            state: job.state.clone(),
            committed_bytes: job.progress.load(Ordering::Relaxed),
            attempts: job.attempts,
            bytes_per_second: job.options.bytes_per_second,
            parallel_connections: job.options.parallel_connections,
        })
        .collect();
    updates.send_if_modified(|current| {
        if *current == next {
            false
        } else {
            *current = next;
            true
        }
    });
}

fn stop(jobs: &mut [(JobId, Job)], queue: &mut VecDeque<JobId>) {
    // Retain queued ordering for an explicit resume-all after reopening.
    let _ = queue;
    for (_, job) in jobs {
        match job.state {
            State::Queued | State::RetryWaiting => {
                job.state = State::Paused;
                job.retry_at = None;
            }
            State::Running => {
                job.state = State::Pausing;
                if let Some(cancel) = &job.cancel {
                    cancel.send_replace(true);
                }
            }
            _ => {}
        }
    }
}

fn finish(job: &mut Job, result: Result<Outcome, Error>) {
    job.cancel = None;
    job.state = match result {
        Ok(outcome) => {
            job.progress.store(outcome.bytes, Ordering::Relaxed);
            State::Completed
        }
        Err(Error::Cancelled) if job.state == State::Pausing => State::Paused,
        Err(error) => State::Failed(error),
    };
}

fn next_eligible(
    jobs: &[(JobId, Job)],
    queue: &VecDeque<JobId>,
    max_per_origin: usize,
) -> Option<usize> {
    let mut selected = None;
    let mut selected_priority = Priority::Low;
    for (index, id) in queue.iter().enumerate() {
        let Some((_, candidate)) = jobs.iter().find(|(key, _)| key == id) else {
            continue;
        };
        if candidate.state != State::Queued {
            continue;
        }
        let active = jobs
            .iter()
            .filter(|(_, job)| {
                job.origin == candidate.origin
                    && matches!(job.state, State::Running | State::Pausing)
            })
            .count();
        if active >= max_per_origin {
            continue;
        }
        if selected.is_none() || candidate.priority > selected_priority {
            selected = Some(index);
            selected_priority = candidate.priority;
        }
    }
    selected
}

fn retryable(error: &Error) -> bool {
    matches!(
        error,
        Error::Network | Error::HttpStatus(408 | 500 | 502 | 503 | 504)
    )
}

async fn save_state(
    store: &mut Option<QueueStore>,
    jobs: &[(JobId, Job)],
    queue: &VecDeque<JobId>,
    config: &Config,
    ledger: &AdmissionLedger,
) -> Result<(), ManagerError> {
    let Some(mut owned) = store.take() else {
        return Ok(());
    };
    let snapshot = Snapshot {
        config: config.clone(),
        last_id: ledger.last_id,
        receipts: ledger.receipts.clone(),
        jobs: jobs
            .iter()
            .map(|(id, job)| SavedJob {
                id: *id,
                options: job.options.clone(),
                priority: job.priority,
                state: job.state.clone(),
                progress: job.progress.load(Ordering::Relaxed),
                attempts: job.attempts,
            })
            .collect(),
        queue: queue.iter().copied().collect(),
    };
    let (owned, result) = tokio::task::spawn_blocking(move || {
        let result = owned.save(&snapshot);
        (owned, result)
    })
    .await
    .map_err(|_| ManagerError::WorkerFailed)?;
    *store = Some(owned);
    result
}

enum Acknowledge {
    Unit(Reply<()>),
    Enqueued(Reply<JobId>, JobId),
}
impl Acknowledge {
    fn send(self, result: Result<(), ManagerError>) {
        match self {
            Self::Unit(reply) => {
                let _ = reply.send(result);
            }
            Self::Enqueued(reply, id) => {
                let _ = reply.send(result.map(|()| id));
            }
        }
    }
}

async fn run(
    mut commands: mpsc::Receiver<Command>,
    updates: watch::Sender<Vec<JobSnapshot>>,
    mut config: Config,
    mut jobs: Vec<(JobId, Job)>,
    mut store: Option<QueueStore>,
    global: Bandwidth,
    mut ledger: AdmissionLedger,
) -> Result<(), ManagerError> {
    let mut queue: VecDeque<_> = jobs.iter().map(|(id, _)| *id).collect();
    let mut workers: JoinSet<Result<Outcome, Error>> = JoinSet::new();
    let mut owners: HashMap<Id, JobId> = HashMap::new();
    let mut closing = false;
    let mut failure = None;
    let mut dirty = true;
    let mut acknowledgements = Vec::<Acknowledge>::new();
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if commands.is_closed() && !closing {
            closing = true;
            commands.close();
            stop(&mut jobs, &mut queue);
            dirty = true;
        }
        if !closing {
            for (id, job) in &mut jobs {
                if job.state == State::RetryWaiting
                    && job
                        .retry_at
                        .is_some_and(|at| at <= tokio::time::Instant::now())
                {
                    job.state = State::Queued;
                    job.retry_at = None;
                    queue.push_back(*id);
                    dirty = true;
                }
            }
        }
        if dirty && failure.is_none() {
            if let Err(error) = save_state(&mut store, &jobs, &queue, &config, &ledger).await {
                failure = Some(error);
                closing = true;
                commands.close();
                stop(&mut jobs, &mut queue);
            } else {
                // Settings become live only after the durable commit.
                let _ = global.set_limit(config.global_bytes_per_second);
                for (_, job) in &jobs {
                    let _ = job.control.set_job_rate(job.options.bytes_per_second);
                }
            }
            dirty = false;
        }
        for ack in acknowledgements.drain(..) {
            ack.send(failure.map_or(Ok(()), Err));
        }
        while !closing && workers.len() < config.max_active {
            let Some(index) = next_eligible(&jobs, &queue, config.max_per_origin) else {
                break;
            };
            let Some(id) = queue.remove(index) else {
                break;
            };
            let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) else {
                continue;
            };
            if job.state != State::Queued {
                continue;
            }
            job.state = State::Running;
            job.attempts = job.attempts.saturating_add(1);
            if let Err(error) = save_state(&mut store, &jobs, &queue, &config, &ledger).await {
                failure = Some(error);
                closing = true;
                commands.close();
                stop(&mut jobs, &mut queue);
                // No worker exists for this just-prepared task.
                if let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) {
                    job.state = State::Paused;
                }
                break;
            }
            if commands.is_closed() {
                closing = true;
                stop(&mut jobs, &mut queue);
                dirty = true;
                if let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) {
                    job.state = State::Paused;
                }
                break;
            }
            let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) else {
                continue;
            };
            let options = job.options.clone();
            let progress = Arc::clone(&job.progress);
            let control = job.control.clone();
            let (cancel, receiver) = watch::channel(false);
            job.cancel = Some(cancel);
            let handle = workers.spawn(async move {
                download_controlled(options, receiver, control, |bytes| {
                    progress.store(bytes, Ordering::Relaxed);
                })
                .await
            });
            owners.insert(handle.id(), id);
        }
        publish(&jobs, &updates);
        if closing && workers.is_empty() {
            if dirty && failure.is_none() {
                if let Err(error) = save_state(&mut store, &jobs, &queue, &config, &ledger).await {
                    failure = Some(error);
                }
            }
            break;
        }
        tokio::select! {
            result = workers.join_next_with_id(), if !workers.is_empty() => {
                let Some(result) = result else { continue; };
                let (task, result) = match result {
                    Ok((task, result)) => (task, result),
                    Err(error) => (error.id(), Err(Error::WorkerFailed)),
                };
                if let Some(id) = owners.remove(&task) {
                    if let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) {
                        let retry = !closing && job.state == State::Running && job.attempts < config.retry.max_attempts && result.as_ref().is_err_and(retryable);
                        finish(job, result);
                        if retry {
                            job.state = State::RetryWaiting;
                            job.retry_at = Some(tokio::time::Instant::now() + config.retry.delay(job.attempts));
                        }
                        if let Some(reply) = job.pause_reply.take() {
                            if matches!(job.state, State::Failed(_)) { let _ = reply.send(Err(ManagerError::WorkerFailed)); }
                            else { acknowledgements.push(Acknowledge::Unit(reply)); }
                        }
                        dirty = true;
                    }
                }
            }
            command = commands.recv(), if !closing => {
                match command {
                    Some(Command::Refresh(id,url,reply)) => {
                        let Some((_,job))=jobs.iter_mut().find(|(key,_)|*key==id) else {let _=reply.send(Err(ManagerError::UnknownJob));continue;};
                        if !matches!(job.state,State::Paused|State::Failed(_)){let _=reply.send(Err(ManagerError::InvalidTransition));continue;}
                        if job.options.expected_sha256.is_none(){let _=reply.send(Err(ManagerError::InvalidOptions));continue;}
                        let old=crate::parse_url(&job.options.url,job.options.allow_http);
                        let new=crate::parse_url(&url,job.options.allow_http);
                        let (Ok(old),Ok(new))=(old,new) else {let _=reply.send(Err(ManagerError::InvalidOptions));continue;};
                        if old.origin()!=new.origin() || old.path()!=new.path(){let _=reply.send(Err(ManagerError::InvalidOptions));continue;}
                                                let directory=job.options.job_dir.clone();
                        let expected=job.options.expected_sha256;
                        let current=transfer_store::url_fingerprint(old.as_str());
                        let previous=job.options.refresh_from;
                        let binding=tokio::task::spawn_blocking(move || {
                            match std::fs::symlink_metadata(&directory) {
                                Err(e) if e.kind()==std::io::ErrorKind::NotFound => Ok(None),
                                Err(_) => Err(ManagerError::InvalidPath),
                                Ok(_) => {
                                    let store=transfer_store::Store::open(&directory).map_err(|_|ManagerError::WorkerFailed)?;
                                    let identity=store.identity();
                                    if store.status()!=transfer_store::Status::Downloading || store.is_unknown_length() || identity.strong_etag.is_none() || identity.expected_sha256!=expected || (identity.original_url_fingerprint!=current && Some(identity.original_url_fingerprint)!=previous) {return Err(ManagerError::InvalidOptions);}
                                    Ok(Some(identity.original_url_fingerprint))
                                }
                            }
                        }).await;
                        job.options.refresh_from=match binding{Ok(Ok(value))=>value,Ok(Err(error))=>{let _=reply.send(Err(error));continue;},Err(_)=>{let _=reply.send(Err(ManagerError::WorkerFailed));continue;}};
                        job.options.url=new.to_string();
                        job.state=State::Paused;
                        dirty=true;acknowledgements.push(Acknowledge::Unit(reply));
                    }
                    Some(Command::Forget(id,reply)) => {
                        let Some(index)=jobs.iter().position(|(key,_)|*key==id)else{let _=reply.send(Err(ManagerError::UnknownJob));continue;};
                        if matches!(jobs[index].1.state,State::Running|State::Pausing){let _=reply.send(Err(ManagerError::InvalidTransition));continue;}
                        jobs.remove(index);queue.retain(|key|*key!=id);
                        for receipt in &mut ledger.receipts { if receipt.job_id == id { receipt.removed = true; } }
                        dirty=true;acknowledgements.push(Acknowledge::Unit(reply));
                    }
                    None => { closing = true; stop(&mut jobs, &mut queue); dirty = true; }
                    Some(Command::Enqueue(options, priority, admission, reply)) => {
                        let options = *options;
                        if let Some(hashes) = &admission {
                            if store.is_none() { let _ = reply.send(Err(ManagerError::NotDurable)); continue; }
                            if let Some(receipt) = ledger.receipts.iter().find(|receipt| receipt.key_hash == hashes.key) {
                                let result = if receipt.payload_hash != hashes.payload { Err(ManagerError::IdempotencyConflict) }
                                    else if receipt.removed { Err(ManagerError::PreviouslyRemoved) }
                                    else { Ok(receipt.job_id) };
                                let _ = reply.send(result); continue;
                            }
                            if ledger.receipts.len() >= MAX_RECEIPTS { let _ = reply.send(Err(ManagerError::ReceiptCapacity)); continue; }
                        }
                        if jobs.len() >= config.max_jobs { let _ = reply.send(Err(ManagerError::Capacity)); continue; }
                        let origin = match origin(&options) { Ok(origin) => origin, Err(error) => { let _ = reply.send(Err(error)); continue; } };
                        let path = options.job_dir.clone();
                        let key = match tokio::task::spawn_blocking(move || path_key(path)).await {
                            Ok(Ok(key)) => key,
                            Ok(Err(error)) => { let _ = reply.send(Err(error)); continue; }
                            Err(_) => { let _ = reply.send(Err(ManagerError::WorkerFailed)); continue; }
                        };
                        if jobs.iter().any(|(_, job)| job.key == key) { let _ = reply.send(Err(ManagerError::DuplicateJob)); continue; }
                        let Some(next) = ledger.last_id.checked_add(1) else { let _ = reply.send(Err(ManagerError::Capacity)); continue; };
                        ledger.last_id = next;
                        let id = JobId(next);
                        let control = match TrafficControl::with_global(global.clone(), options.bytes_per_second) { Ok(control) => control, Err(_) => { let _ = reply.send(Err(ManagerError::InvalidOptions)); continue; } };
                        jobs.push((id, Job { options, origin, priority, key, state: State::Queued, progress: Arc::new(AtomicU64::new(0)), cancel: None, pause_reply: None, attempts: 0, retry_at: None, control }));
                        queue.push_back(id);
                        if let Some(hashes) = admission { ledger.receipts.push(Receipt { key_hash: hashes.key, payload_hash: hashes.payload, job_id: id, removed: false }); }
                        acknowledgements.push(Acknowledge::Enqueued(reply, id));
                        dirty = true;
                    }
                    Some(Command::SetPriority(id, priority, reply)) => {
                        let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) else { let _ = reply.send(Err(ManagerError::UnknownJob)); continue; };
                        if matches!(job.state, State::Queued | State::Paused | State::Failed(_) | State::RetryWaiting) {
                            job.priority = priority;
                            acknowledgements.push(Acknowledge::Unit(reply)); dirty = true;
                        } else { let _ = reply.send(Err(ManagerError::InvalidTransition)); }
                    }
                    Some(Command::Pause(id, reply)) => {
                        let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) else { let _ = reply.send(Err(ManagerError::UnknownJob)); continue; };
                        match job.state {
                            State::Queued | State::RetryWaiting => {
                                queue.retain(|key| *key != id); job.state = State::Paused; job.retry_at = None;
                                acknowledgements.push(Acknowledge::Unit(reply)); dirty = true;
                            }
                            State::Running => {
                                job.state = State::Pausing; job.pause_reply = Some(reply);
                                if let Some(cancel) = &job.cancel { cancel.send_replace(true); }
                                dirty = true;
                            }
                            State::Paused => { acknowledgements.push(Acknowledge::Unit(reply)); dirty = true; }
                            _ => { let _ = reply.send(Err(ManagerError::InvalidTransition)); }
                        }
                    }
                    Some(Command::Resume(id, reply)) => {
                        let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) else { let _ = reply.send(Err(ManagerError::UnknownJob)); continue; };
                        if matches!(job.state, State::Paused | State::Failed(_)) {
                            job.state = State::Queued; job.attempts = 0; job.retry_at = None;
                            queue.retain(|key| *key != id);
                            queue.push_back(id);
                            acknowledgements.push(Acknowledge::Unit(reply)); dirty = true;
                        } else { let _ = reply.send(Err(ManagerError::InvalidTransition)); }
                    }
                    Some(Command::ResumeAll(reply)) => {
                        let mut ordered: Vec<JobId> = queue.iter().copied().collect();
                        for (id, _) in &jobs { if !ordered.contains(id) { ordered.push(*id); } }
                        for id in ordered {
                            if let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) {
                                if matches!(job.state, State::Paused | State::Failed(_)) {
                                    job.state = State::Queued; job.attempts = 0; job.retry_at = None;
                                    if !queue.contains(&id) { queue.push_back(id); }
                                }
                            }
                        }
                        acknowledgements.push(Acknowledge::Unit(reply)); dirty = true;
                    }
                    Some(Command::GlobalRate(rate, reply)) => {
                        config.global_bytes_per_second = rate;
                        acknowledgements.push(Acknowledge::Unit(reply)); dirty = true;
                    }
                    Some(Command::JobRate(id, rate, reply)) => {
                        let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) else { let _ = reply.send(Err(ManagerError::UnknownJob)); continue; };
                        job.options.bytes_per_second = rate;
                        acknowledgements.push(Acknowledge::Unit(reply)); dirty = true;
                    }
                }
            }
            _ = tick.tick() => {}
        }
    }
    // If a persistence failure occurred, callers get an error and every existing
    // worker has still drained; the last successful snapshot remains authoritative.
    publish(&jobs, &updates);
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_fingerprint_covers_every_option_and_uses_separate_key_domain() {
        let base = options();
        let original = admission_hashes("source:request-1", &base, Priority::Normal).unwrap();
        let mut variants = Vec::new();
        macro_rules! changed {
            ($field:ident, $value:expr) => {{
                let mut value = base.clone();
                value.$field = $value;
                variants.push(value);
            }};
        }
        changed!(url, "https://example.com/other".into());
        changed!(job_dir, base.job_dir.with_file_name("other-job"));
        changed!(output_name, "other.bin".into());
        changed!(expected_sha256, Some([7; 32]));
        changed!(allow_http, true);
        changed!(checkpoint_bytes, 2048);
        changed!(max_download_bytes, 2048);
        changed!(bytes_per_second, Some(512));
        changed!(parallel_connections, 2);
        changed!(refresh_from, Some([9; 32]));
        for policy in [
            crate::RequestPolicy::new(Some("Bearer one".into()), None, vec![]).unwrap(),
            crate::RequestPolicy::new(None, Some("session=one".into()), vec![]).unwrap(),
            crate::RequestPolicy::new(None, None, vec!["https://other.example".into()]).unwrap(),
        ] {
            changed!(request_policy, policy);
        }
        for variant in variants {
            assert_ne!(
                original.payload,
                admission_hashes("source:request-1", &variant, Priority::Normal)
                    .unwrap()
                    .payload
            );
        }
        assert_ne!(
            original.payload,
            admission_hashes("source:request-1", &base, Priority::High)
                .unwrap()
                .payload
        );
        let other_key = admission_hashes("source:request-2", &base, Priority::Normal).unwrap();
        assert_ne!(original.key, other_key.key);
        assert_eq!(original.payload, other_key.payload);
        assert_ne!(original.key, original.payload);
        let mut same_url = base.clone();
        same_url.url = "https://EXAMPLE.com:443/private?secret=DO_NOT_DISCLOSE".into();
        assert_eq!(
            original.payload,
            admission_hashes("source:request-1", &same_url, Priority::Normal)
                .unwrap()
                .payload
        );
        for invalid in [
            "".to_owned(),
            "x".repeat(129),
            "has space".into(),
            "has\nnewline".into(),
            "غيرascii".into(),
        ] {
            assert!(matches!(
                admission_hashes(&invalid, &base, Priority::Normal),
                Err(ManagerError::InvalidIdempotencyKey)
            ));
        }
    }

    #[cfg(windows)]
    fn admission_directory(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "fhd-admission-unit-{label}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        root
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn lost_reply_still_commits_one_durable_receipt() {
        let root = admission_directory("lost-reply");
        let mut input = options();
        input.url = "http://127.0.0.1:1/unreachable".into();
        input.allow_http = true;
        input.job_dir = root.join("job");
        let manager = Manager::open(root.join("queue"), Config::default())
            .await
            .unwrap();
        let hashes = admission_hashes("source:lost-ack", &input, Priority::Normal).unwrap();
        let (reply, abandoned) = oneshot::channel();
        drop(abandoned); // The caller is gone before the actor sees this command.
        assert!(manager
            .commands
            .as_ref()
            .unwrap()
            .send(Command::Enqueue(
                Box::new(input.clone()),
                Priority::Normal,
                Some(hashes),
                reply
            ))
            .await
            .is_ok());
        manager.set_global_rate(None).await.unwrap(); // FIFO barrier after commit.
        let id = manager
            .enqueue_once("source:lost-ack".into(), input.clone(), Priority::Normal)
            .await
            .unwrap();
        assert_eq!(id, JobId(1));
        manager.shutdown().await.unwrap();
        let reopened = Manager::open(root.join("queue"), Config::default())
            .await
            .unwrap();
        assert_eq!(
            reopened
                .enqueue_once("source:lost-ack".into(), input, Priority::Normal)
                .await
                .unwrap(),
            id
        );
        assert_eq!(reopened.subscribe().borrow().len(), 1);
        reopened.shutdown().await.unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn full_receipt_ledger_rejects_new_keys_without_evicting_tombstones() {
        let root = admission_directory("full-ledger");
        let mut input = options();
        input.job_dir = root.join("job");
        let mut receipts = Vec::new();
        for index in 0..MAX_RECEIPTS {
            let hashes =
                admission_hashes(&format!("source:old-{index}"), &input, Priority::Normal).unwrap();
            receipts.push(Receipt {
                key_hash: hashes.key,
                payload_hash: hashes.payload,
                job_id: JobId(index as u64 + 1),
                removed: true,
            });
        }
        let path = root.join("queue");
        let saved_path = path.clone();
        tokio::task::spawn_blocking(move || {
            let mut store = QueueStore::open(&saved_path).unwrap();
            store
                .save(&Snapshot {
                    last_id: MAX_RECEIPTS as u64,
                    receipts,
                    config: Config::default(),
                    jobs: vec![],
                    queue: vec![],
                })
                .unwrap();
        })
        .await
        .unwrap();
        let manager = Manager::open(path, Config::default()).await.unwrap();
        assert_eq!(
            manager
                .enqueue_once("source:new".into(), input.clone(), Priority::Normal)
                .await,
            Err(ManagerError::ReceiptCapacity)
        );
        assert_eq!(
            manager
                .enqueue_once("source:old-0".into(), input, Priority::Normal)
                .await,
            Err(ManagerError::PreviouslyRemoved)
        );
        assert!(manager.subscribe().borrow().is_empty());
        manager.shutdown().await.unwrap();
        let store = QueueStore::open(&root.join("queue")).unwrap();
        assert_eq!(store.load().unwrap().unwrap().receipts.len(), MAX_RECEIPTS);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn options() -> Options {
        Options {
            url: "https://example.com/private?secret=DO_NOT_DISCLOSE".into(),
            job_dir: std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join("private-job"),
            output_name: "private-filename.bin".into(),
            expected_sha256: None,
            allow_http: false,
            checkpoint_bytes: 1024,
            max_download_bytes: 1024,
            bytes_per_second: None,
            parallel_connections: 1,
            request_policy: Default::default(),
            refresh_from: None,
        }
    }

    fn pausing_job() -> Job {
        Job {
            options: options(),
            origin: origin(&options()).unwrap(),
            priority: Priority::Normal,
            key: PathBuf::new(),
            state: State::Pausing,
            progress: Arc::new(AtomicU64::new(0)),
            cancel: None,
            pause_reply: None,
            attempts: 0,
            retry_at: None,
            control: TrafficControl::new(None).unwrap(),
        }
    }

    #[test]
    fn publication_wins_late_pause_and_storage_failure_is_not_paused() {
        let mut job = pausing_job();
        finish(
            &mut job,
            Ok(Outcome {
                bytes: 1024,
                resumed_from: 512,
                path: PathBuf::from("private-filename.bin"),
            }),
        );
        assert_eq!(job.state, State::Completed);
        assert_eq!(job.progress.load(Ordering::Relaxed), 1024);
        let mut job = pausing_job();
        finish(
            &mut job,
            Err(Error::StorageIo(std::io::ErrorKind::StorageFull)),
        );
        assert_eq!(
            job.state,
            State::Failed(Error::StorageIo(std::io::ErrorKind::StorageFull))
        );
        let mut job = pausing_job();
        finish(&mut job, Err(Error::Cancelled));
        assert_eq!(job.state, State::Paused);
    }

    #[test]
    fn admission_rejects_large_inputs_and_invalid_limits_without_runtime() {
        for limits in [(0, 1), (33, 100), (1, 0), (1, 1025), (2, 1)] {
            assert!(matches!(
                Manager::start(limits.0, limits.1),
                Err(ManagerError::InvalidLimits)
            ));
        }
        assert!(matches!(Manager::start(1, 1), Err(ManagerError::NoRuntime)));
        for limits in [(2, 8, 0), (2, 8, 3), (0, 8, 1), (33, 64, 1)] {
            assert!(matches!(
                Manager::start_with_limits(limits.0, limits.1, limits.2),
                Err(ManagerError::InvalidLimits)
            ));
        }
        assert!(matches!(
            Manager::start_with_limits(2, 8, 1),
            Err(ManagerError::NoRuntime)
        ));
        let mut opts = options();
        opts.url = "x".repeat(16_385);
        assert_eq!(validate_options(&opts), Err(ManagerError::InvalidOptions));
        let mut opts = options();
        opts.output_name = "x".repeat(256);
        assert_eq!(validate_options(&opts), Err(ManagerError::InvalidOptions));
        for rate in [0, crate::rate::MAX_BYTES_PER_SECOND + 1, u64::MAX] {
            let mut opts = options();
            opts.bytes_per_second = Some(rate);
            assert_eq!(validate_options(&opts), Err(ManagerError::InvalidOptions));
        }
        for rate in [None, Some(1), Some(crate::rate::MAX_BYTES_PER_SECOND)] {
            let mut opts = options();
            opts.bytes_per_second = rate;
            assert_eq!(validate_options(&opts), Ok(()));
        }
        assert_eq!(
            path_key(PathBuf::from("relative/job")),
            Err(ManagerError::InvalidPath)
        );
    }

    #[test]
    fn origins_normalize_hosts_and_default_ports_without_merging_other_ports() {
        let key = |url: &str| {
            let mut opts = options();
            opts.url = url.into();
            opts.allow_http = true;
            origin(&opts).unwrap()
        };
        assert!(key("https://EXAMPLE.com:443/a?token=one") == key("https://example.com/b"));
        assert!(key("http://example.com:80/a") == key("http://example.com/b"));
        assert!(key("https://example.com:444/a") != key("https://example.com/a"));
        assert!(key("http://example.com:443/a") != key("https://example.com/a"));
        assert!(key("https://[0:0:0:0:0:0:0:1]:443/a") == key("https://[::1]/b"));
    }

    fn queued_job(url: &str, priority: Priority) -> Job {
        let mut job = pausing_job();
        job.options.url = url.into();
        job.origin = origin(&job.options).unwrap();
        job.priority = priority;
        job.state = State::Queued;
        job
    }

    #[test]
    fn scheduler_bypasses_saturated_origin_and_keeps_slots_until_pausing_joins() {
        let mut active = queued_job("https://a.example/file", Priority::Low);
        active.state = State::Pausing;
        let mut jobs = vec![
            (JobId(1), active),
            (
                JobId(2),
                queued_job("https://a.example/next", Priority::High),
            ),
            (
                JobId(3),
                queued_job("https://b.example/next", Priority::Low),
            ),
        ];
        let queue = VecDeque::from([JobId(2), JobId(3)]);
        assert_eq!(next_eligible(&jobs, &queue, 1), Some(1));
        jobs[2].1.state = State::Running;
        assert_eq!(next_eligible(&jobs, &queue, 1), None);
        // Only completion/join releases the previous origin slot.
        finish(&mut jobs[0].1, Err(Error::Cancelled));
        assert_eq!(next_eligible(&jobs, &queue, 1), Some(0));
    }

    #[test]
    fn scheduler_selects_highest_priority_then_fifo_without_reordering_queue() {
        let mut jobs = vec![
            (JobId(1), queued_job("https://a.example/1", Priority::Low)),
            (JobId(2), queued_job("https://a.example/2", Priority::High)),
            (JobId(3), queued_job("https://a.example/3", Priority::High)),
            (
                JobId(4),
                queued_job("https://a.example/4", Priority::Normal),
            ),
        ];
        let mut queue = VecDeque::from([JobId(1), JobId(2), JobId(3), JobId(4)]);
        assert_eq!(next_eligible(&jobs, &queue, 2), Some(1));
        queue.remove(1);
        jobs[1].1.state = State::Running;
        assert_eq!(next_eligible(&jobs, &queue, 2), Some(1));
        // Priority changes retain the original FIFO position within the queue.
        jobs[0].1.priority = Priority::High;
        assert_eq!(next_eligible(&jobs, &queue, 2), Some(0));
        jobs[0].1.state = State::Running;
        assert_eq!(next_eligible(&jobs, &queue, 2), None);
    }

    #[test]
    fn snapshots_do_not_expose_job_inputs() {
        let job = pausing_job();
        let (updates, receiver) = watch::channel(Vec::new());
        publish(&[(JobId(1), job)], &updates);
        let text = format!("{:?}", receiver.borrow());
        for secret in [
            "DO_NOT_DISCLOSE",
            "example.com",
            "private-job",
            "private-filename",
        ] {
            assert!(!text.contains(secret));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_ambiguous_leaf_names_are_rejected() {
        for leaf in [
            "job.",
            "job ",
            "NUL",
            "nul.txt",
            "COM1",
            "LPT2.dat",
            "job:stream",
            "COM¹",
        ] {
            assert_eq!(
                path_key(std::env::temp_dir().canonicalize().unwrap().join(leaf)),
                Err(ManagerError::InvalidPath)
            );
        }
    }
}
