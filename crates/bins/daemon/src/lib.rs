//! Composition root: the only place that wires ports to adapters. It owns no
//! protocol, storage or state rules of its own.
#![forbid(unsafe_code)]

mod service;
pub use service::Resident;

use fhd_app::{
    AddDownload, AppError, Authorizer, Destinations, EntitlementGate, Principal, ReceiptKey,
    ReferenceStore, SourceReference, TransferRepository,
};
use fhd_domain::{
    DestinationRef, Job, JobCommand, JobSpec, JobState, Priority, RetryPolicy, SourceRef,
    StopReason,
};
use fhd_http::{BindingError, HttpConfig, HttpTransport, SourceBinding};
use fhd_persistence::{Limits, PersistenceError, SqliteRepository};
use fhd_runtime::{
    buffers::BufferPool,
    coordinator::{Clock, Control, Coordinator, CoordinatorConfig, Ports, RunError, SessionEnd},
    origin::{OriginGovernor, OriginLimits},
    scheduler::{Command, Scheduler, SchedulerConfig},
};
use fhd_storage::FileStorage;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum EngineError {
    InvalidInput,
    /// The control surface could not be claimed for this user.
    EndpointUnavailable,
    /// Nothing this run could continue: no recorded job with a usable link.
    NothingToContinue,
    /// Publication renames within a volume; this destination is on another one.
    CrossVolume,
    /// The job is waiting for a decision; run again with Intent::Resume.
    NeedsDecision(Option<StopReason>),
    Persistence(PersistenceError),
    Binding(BindingError),
    Admission(AppError),
    Run(RunError),
}

/// Wall clock in milliseconds plus jitter derived from it; no RNG dependency.
struct SystemClock;
impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
    fn jitter(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|since| since.subsec_nanos())
            .unwrap_or(0);
        u64::from(now)
    }
}

/// One destination per reference, fixed when the job was accepted. A reference
/// this run never admitted resolves to nothing: the map is the whole authority.
struct FixedDestinations(HashMap<DestinationRef, PathBuf>);
impl Destinations for FixedDestinations {
    fn resolve(&self, destination: DestinationRef) -> Result<PathBuf, AppError> {
        self.0
            .get(&destination)
            .cloned()
            .ok_or(AppError::InvalidInput)
    }
}

/// This build accepts requests only from the local operator.
struct LocalOperator;
impl Authorizer for LocalOperator {
    fn authorize_add(&self, _: Principal, _: &JobSpec) -> Result<(), AppError> {
        Ok(())
    }
}
impl EntitlementGate for LocalOperator {
    fn authorize_add(&self, _: Principal, _: &JobSpec) -> Result<(), AppError> {
        Ok(())
    }
}

/// What the operator asked for, beyond starting the transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intent {
    /// Only start or continue what is already running; a stopped job stays stopped.
    Start,
    /// Release a stopped job: the operator has looked at the reason.
    Resume,
}

#[derive(Clone, Debug)]
pub struct EngineConfig {
    /// Application-owned directory for the database and the part files.
    pub state_directory: PathBuf,
    pub destination: PathBuf,
    /// Connections one job may use.
    pub connections: usize,
    /// Connections across every job, and how many jobs run at once. The defaults
    /// make a single-request run behave exactly as it did before there was a queue.
    pub engine_connections: usize,
    pub max_active: usize,
    pub expected_sha256: Option<[u8; 32]>,
    pub max_bytes: u64,
    pub allow_http: bool,
    pub intent: Intent,
}

/// One thing to fetch and where it lands. The operator names every destination:
/// nothing is derived from a URL, so no server can choose a path.
#[derive(Clone, Debug)]
pub struct Request {
    pub url: String,
    pub destination: PathBuf,
    pub expected_sha256: Option<[u8; 32]>,
    /// A link that must not be written to disk, such as a signed one. The job is
    /// remembered without it, so a later run stops for a person rather than
    /// fetching from a credential left behind.
    pub sensitive: bool,
}

/// How one request ended. A job needing a decision does not fail its neighbours.
#[derive(Debug)]
pub enum JobOutcome {
    Published(PathBuf),
    /// Where the job came to rest, and why when it says so: a state alone does not
    /// tell an operator whether to retry, free space, or fix the link.
    Settled(JobState, Option<StopReason>),
    NeedsDecision(Option<StopReason>),
    Failed(RunError),
}

/// Enough engine to download, verify and publish end to end, for one request or
/// several under one set of caps. No IPC and no reference store yet: the caller
/// supplies each URL again on every run, so no URL or credential is written to disk.
pub struct Engine {
    repository: Arc<SqliteRepository>,
    coordinator: Arc<Coordinator>,
    scheduler: Scheduler,
    requests: Vec<Admitted>,
    intent: Intent,
    id: std::sync::Mutex<Option<fhd_domain::JobId>>,
}

/// What one request became once it had an identity.
struct Admitted {
    key: ReceiptKey,
    spec: JobSpec,
}

fn digest(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(label);
    for part in parts {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}
/// A stable reference, so re-running the same request reaches the same job. It
/// covers everything that changes what would be fetched or where it lands.
fn reference(label: &[u8], parts: &[&[u8]]) -> u64 {
    let digest = digest(label, parts);
    u64::from_le_bytes(digest[..8].try_into().unwrap_or([1; 8])).max(1)
}

/// Creates the engine's own tree: no link may stand in for a directory, and on
/// Unix only the owner may read it. The destination stays the user's business.
fn own_directory(path: &Path) -> Result<(), EngineError> {
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(EngineError::InvalidInput),
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| EngineError::InvalidInput)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(EngineError::InvalidInput);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(EngineError::InvalidInput);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| EngineError::InvalidInput)?;
    }
    Ok(())
}

/// Publication renames within one volume; a destination elsewhere is refused up
/// front instead of after the whole file has been downloaded.
fn same_volume(state: &Path, destination: &Path) -> Result<bool, EngineError> {
    let target = destination.parent().ok_or(EngineError::InvalidInput)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let state = std::fs::metadata(state).map_err(|_| EngineError::InvalidInput)?;
        let target = std::fs::metadata(target).map_err(|_| EngineError::InvalidInput)?;
        Ok(state.dev() == target.dev())
    }
    #[cfg(not(unix))]
    {
        let volume = |path: &Path| {
            path.components()
                .next()
                .map(|component| component.as_os_str().to_ascii_lowercase())
        };
        let target = std::path::absolute(target).map_err(|_| EngineError::InvalidInput)?;
        Ok(volume(state) == volume(&target) && volume(state).is_some())
    }
}

impl Engine {
    /// One request, the common case: the caller keeps the old shape.
    pub async fn open(config: EngineConfig, url: &str) -> Result<Self, EngineError> {
        let request = Request {
            url: url.to_owned(),
            destination: config.destination.clone(),
            expected_sha256: config.expected_sha256,
            sensitive: false,
        };
        Self::open_many(config, vec![request]).await
    }

    /// Several requests under one set of caps: one database, one connection budget,
    /// one governor. Each request keeps its own destination and its own checksum.
    pub async fn open_many(
        config: EngineConfig,
        requests: Vec<Request>,
    ) -> Result<Self, EngineError> {
        if !config.state_directory.is_absolute()
            || !(1..=16).contains(&config.connections)
            || !(1..=64).contains(&config.engine_connections)
            || config.connections > config.engine_connections
            || !(1..=64).contains(&config.max_active)
            || requests.is_empty()
            || requests.len() > 256
        {
            return Err(EngineError::InvalidInput);
        }
        // The engine owns this tree and creates it; the destinations are the user's.
        own_directory(&config.state_directory)?;
        own_directory(&config.state_directory.join("parts"))?;
        let repository = Arc::new(
            SqliteRepository::open(config.state_directory.join("state"), Limits::default())
                .await
                .map_err(EngineError::Persistence)?,
        );
        let transport = HttpTransport::new(HttpConfig::default()).map_err(EngineError::Binding)?;
        let mut destinations = HashMap::new();
        let mut admitted = Vec::with_capacity(requests.len());
        let mut references = Vec::with_capacity(requests.len());
        for request in &requests {
            if !request.destination.is_absolute() {
                return Err(EngineError::InvalidInput);
            }
            if !same_volume(&config.state_directory, &request.destination)? {
                return Err(EngineError::CrossVolume);
            }
            // The binding, not just the URL: an http permission changes what may be sent.
            let source = SourceRef::new(reference(
                b"FHD.source.v1\0",
                &[request.url.as_bytes(), &[u8::from(config.allow_http)]],
            ))
            .map_err(|_| EngineError::InvalidInput)?;
            let destination = DestinationRef::new(reference(
                b"FHD.destination.v1\0",
                &[request.destination.to_string_lossy().as_bytes()],
            ))
            .map_err(|_| EngineError::InvalidInput)?;
            // Two requests landing on one name would race for it; refuse up front.
            if destinations
                .insert(destination, request.destination.clone())
                .is_some()
            {
                return Err(EngineError::InvalidInput);
            }
            transport
                .bind(
                    source,
                    SourceBinding::new(&request.url, None, None, config.allow_http, vec![])
                        .map_err(EngineError::Binding)?,
                )
                .map_err(EngineError::Binding)?;
            // What this job points at, so a later run can continue it unaided.
            let reference = if request.sensitive {
                SourceReference::sensitive(config.allow_http)
            } else {
                SourceReference::new(request.url.clone(), config.allow_http)
                    .map_err(EngineError::Admission)?
            };
            references.push((source, reference, destination, request.destination.clone()));
            admitted.push(Admitted {
                key: ReceiptKey::new(
                    Principal::new(1).map_err(EngineError::Admission)?,
                    // The whole request: the same URL elsewhere is another job.
                    digest(
                        b"FHD.request.v1\0",
                        &[
                            request.url.as_bytes(),
                            request.destination.to_string_lossy().as_bytes(),
                            &request.expected_sha256.unwrap_or_default(),
                            &config.max_bytes.to_le_bytes(),
                            &[u8::from(config.allow_http)],
                        ],
                    ),
                ),
                spec: JobSpec::new(
                    source,
                    destination,
                    request.expected_sha256,
                    Priority::Normal,
                    config.max_bytes,
                )
                .map_err(|_| EngineError::InvalidInput)?,
            });
        }
        let buffers = BufferPool::new(config.engine_connections * 256 * 1024)
            .map_err(|_| EngineError::InvalidInput)?;
        let governor = Arc::new(
            OriginGovernor::new(OriginLimits {
                connections: config.engine_connections,
                ..OriginLimits::default()
            })
            .map_err(|_| EngineError::InvalidInput)?,
        );
        let coordinator = Arc::new(
            Coordinator::new(
                Ports {
                    repository: repository.clone(),
                    store: Arc::new(
                        FileStorage::own(&config.state_directory.join("parts"))
                            .map_err(|_| EngineError::InvalidInput)?,
                    ),
                    transport: Arc::new(transport),
                    destinations: Arc::new(FixedDestinations(destinations)),
                },
                buffers,
                Arc::new(SystemClock),
                CoordinatorConfig {
                    connections: config.connections,
                    max_segments: 1024,
                    min_segment: 1024 * 1024,
                    checkpoint_bytes: 8 * 1024 * 1024,
                    writer_capacity: 16,
                    retry: RetryPolicy::new(5, 1000, 60_000)
                        .map_err(|_| EngineError::InvalidInput)?,
                },
                config.state_directory.join("parts"),
            )
            .map_err(EngineError::Run)?
            .with_governor(governor.clone()),
        );
        let scheduler = Scheduler::new(
            coordinator.clone(),
            governor,
            SchedulerConfig {
                max_active: config.max_active,
                connections: config.engine_connections,
                per_job: config.connections,
                resident: false,
            },
        )
        .map_err(EngineError::Run)?;
        for (source, reference, destination, path) in references {
            ReferenceStore::record(repository.as_ref(), source, reference, destination, path)
                .await
                .map_err(|_| EngineError::Admission(AppError::PersistenceUnavailable))?;
        }
        Ok(Self {
            repository,
            coordinator,
            scheduler,
            requests: admitted,
            intent: config.intent,
            id: std::sync::Mutex::new(None),
        })
    }

    /// Reopens what an earlier run recorded: every job in the state directory,
    /// fetched through the links it was given then. A job whose link was marked
    /// sensitive is not resumed here -- nothing on disk can say where it came from,
    /// so it waits for a person to supply the link again.
    pub async fn reopen(config: EngineConfig) -> Result<Self, EngineError> {
        if !config.state_directory.is_absolute() {
            return Err(EngineError::InvalidInput);
        }
        let repository = Arc::new(
            SqliteRepository::open(config.state_directory.join("state"), Limits::default())
                .await
                .map_err(EngineError::Persistence)?,
        );
        let store: &dyn ReferenceStore = repository.as_ref();
        let sources: HashMap<_, _> = store
            .sources()
            .await
            .map_err(EngineError::Admission)?
            .into_iter()
            .collect();
        let destinations: HashMap<_, _> = store
            .destinations()
            .await
            .map_err(EngineError::Admission)?
            .into_iter()
            .collect();
        let mut requests = Vec::new();
        for job in repository
            .load_jobs()
            .await
            .map_err(EngineError::Admission)?
        {
            let (Some(reference), Some(path)) = (
                sources.get(&job.spec().source()),
                destinations.get(&job.spec().destination()),
            ) else {
                continue;
            };
            let Some(url) = reference.url() else {
                continue;
            };
            requests.push(Request {
                url: url.to_owned(),
                destination: path.clone(),
                expected_sha256: job.spec().expected_sha256(),
                sensitive: false,
            });
        }
        drop(repository);
        if requests.is_empty() {
            return Err(EngineError::NothingToContinue);
        }
        Self::open_many(config, requests).await
    }

    /// Admits the request (replaying an earlier one with the same key) and settles
    /// whatever state it is in: recovery first, then one session under the queue.
    pub async fn run(
        &self,
        mut control: mpsc::Receiver<Control>,
    ) -> Result<SessionEnd, EngineError> {
        let ids = self.admit().await?;
        let (id, _) = *ids.first().ok_or(EngineError::InvalidInput)?;
        *self.id.lock().map_err(|_| EngineError::InvalidInput)? = Some(id);
        // The job has an identity now, so a control has something to name.
        let (commands, receiver) = mpsc::channel(4);
        tokio::spawn(async move {
            while let Some(control) = control.recv().await {
                let command = match control {
                    Control::Pause => Command::Pause(id),
                    Control::Cancel => Command::Cancel(id),
                };
                if commands.send(command).await.is_err() {
                    return;
                }
            }
        });
        let mut outcomes = self.drive(ids, receiver).await?;
        match outcomes.pop().map(|(_, outcome)| outcome) {
            Some(JobOutcome::Published(path)) => Ok(SessionEnd::Published(path)),
            Some(JobOutcome::Settled(state, _)) => Ok(SessionEnd::Settled(state)),
            Some(JobOutcome::NeedsDecision(reason)) => Err(EngineError::NeedsDecision(reason)),
            Some(JobOutcome::Failed(error)) => Err(EngineError::Run(error)),
            None => Err(EngineError::InvalidInput),
        }
    }

    /// Every request, under the engine's caps. Results come back in request order.
    pub async fn run_all(
        &self,
        commands: mpsc::Receiver<Command>,
    ) -> Result<Vec<(usize, JobOutcome)>, EngineError> {
        let ids = self.admit().await?;
        self.drive(ids, commands).await
    }

    /// Accepts every request, replaying any admitted by an earlier run.
    async fn admit(&self) -> Result<Vec<(fhd_domain::JobId, usize)>, EngineError> {
        let mut ids = Vec::with_capacity(self.requests.len());
        for (index, request) in self.requests.iter().enumerate() {
            let id = AddDownload::new(self.repository.as_ref(), &LocalOperator, &LocalOperator)
                .execute(request.key, request.spec.clone())
                .await
                .map_err(EngineError::Admission)?;
            ids.push((id, index));
        }
        Ok(ids)
    }

    /// Settles each job's starting state, then hands what may run to the scheduler.
    async fn drive(
        &self,
        ids: Vec<(fhd_domain::JobId, usize)>,
        commands: mpsc::Receiver<Command>,
    ) -> Result<Vec<(usize, JobOutcome)>, EngineError> {
        let mut outcomes = Vec::with_capacity(ids.len());
        let mut runnable = Vec::new();
        let mut owners = HashMap::new();
        for (id, index) in ids {
            owners.insert(id, index);
            match self.prepare(self.load(id).await?).await? {
                Ok(job) => runnable.push(job),
                Err(outcome) => outcomes.push((index, outcome)),
            }
        }
        for outcome in self.scheduler.run(runnable, commands).await {
            let index = *owners.get(&outcome.id).ok_or(EngineError::InvalidInput)?;
            let rest = outcome.job.as_ref().map(|job| (job.state(), job.reason()));
            outcomes.push((
                index,
                match (outcome.result, rest) {
                    (Some(Ok(SessionEnd::Published(path))), _) => JobOutcome::Published(path),
                    (Some(Err(error)), _) => JobOutcome::Failed(error),
                    (_, Some((state, reason))) => JobOutcome::Settled(state, reason),
                    // Nothing came back but a job: a session that ended without one
                    // proves nothing, and the repository is the authority anyway.
                    (_, None) => JobOutcome::Failed(RunError::Invariant),
                },
            ));
        }
        outcomes.sort_by_key(|(index, _)| *index);
        Ok(outcomes)
    }

    /// Recovery, then the operator's intent. A stopped job stays stopped unless the
    /// operator has looked at the reason and asked for it to go on.
    async fn prepare(&self, job: Job) -> Result<Result<Job, JobOutcome>, EngineError> {
        let job = self
            .coordinator
            .recover(job)
            .await
            .map_err(EngineError::Run)?;
        if matches!(job.state(), JobState::Completed | JobState::Cancelled) {
            return Ok(Err(JobOutcome::Settled(job.state(), job.reason())));
        }
        let job = match (job.state(), self.intent) {
            (JobState::Queued | JobState::Probing | JobState::Transferring, _) => job,
            // A waiting retry is released by its own deadline: the scheduler waits
            // it out rather than the operator clearing it.
            (JobState::RetryWait, _) => job,
            // Stopped jobs stay stopped until the operator says otherwise.
            (_, Intent::Start) => return Ok(Err(JobOutcome::NeedsDecision(job.reason()))),
            (JobState::NeedsAction, Intent::Resume)
                if matches!(
                    job.reason(),
                    Some(StopReason::SourceChanged | StopReason::Integrity)
                ) =>
            {
                // These bytes cannot be trusted: start a new representation.
                self.command(job, JobCommand::ReplaceRepresentation).await?
            }
            (_, Intent::Resume) => self.command(job, JobCommand::Resume).await?,
        };
        Ok(Ok(job))
    }

    /// Why this job is waiting for a person, when it is.
    pub async fn reason(&self) -> Result<Option<StopReason>, EngineError> {
        Ok(self.current().await?.reason())
    }
    pub async fn state(&self) -> Result<JobState, EngineError> {
        Ok(self.current().await?.state())
    }
    async fn current(&self) -> Result<Job, EngineError> {
        let known = *self.id.lock().map_err(|_| EngineError::InvalidInput)?;
        let jobs = self
            .repository
            .load_jobs()
            .await
            .map_err(EngineError::Admission)?;
        jobs.into_iter()
            .find(|job| match known {
                Some(id) => job.id() == id,
                None => self
                    .requests
                    .first()
                    .is_some_and(|request| job.spec() == &request.spec),
            })
            .ok_or(EngineError::InvalidInput)
    }

    async fn load(&self, id: fhd_domain::JobId) -> Result<Job, EngineError> {
        self.repository
            .load_jobs()
            .await
            .map_err(EngineError::Admission)?
            .into_iter()
            .find(|job| job.id() == id)
            .ok_or(EngineError::InvalidInput)
    }

    async fn command(&self, job: Job, command: JobCommand) -> Result<Job, EngineError> {
        self.coordinator
            .command(job, command)
            .await
            .map_err(EngineError::Run)
    }
}

/// Prints the engine's allowlisted events to standard error. They carry only
/// codes and numbers, so there is nothing to redact; anything else in the process
/// would need its own review before being logged.
pub struct StderrEvents;
/// The engine's event shape. Anything else in the process is not printed here,
/// whatever target it claims.
const ALLOWED: [&str; 5] = ["code", "job_id", "generation", "value", "elapsed_ms"];
struct Fields(String);
impl Fields {
    fn put(&mut self, field: &tracing::field::Field, value: std::fmt::Arguments<'_>) {
        use std::fmt::Write;
        if !ALLOWED.contains(&field.name()) {
            return;
        }
        let text: String = value
            .to_string()
            .chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect();
        let _ = write!(self.0, " {}={text}", field.name());
    }
}
impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.put(field, format_args!("{value:?}"));
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.put(field, format_args!("{value}"));
    }
}
impl tracing::Subscriber for StderrEvents {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        metadata.target() == "fhd"
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        eprintln!("event{}", fields.0);
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Reads a URL from standard input so signed links never appear in a process list.
pub fn read_url(input: impl std::io::Read) -> Result<String, EngineError> {
    let mut lines = read_lines(input)?;
    match (lines.pop(), lines.is_empty()) {
        (Some(url), true) => Ok(url),
        _ => Err(EngineError::InvalidInput),
    }
}

/// One request per line: a URL, or a URL and the file it lands in separated by a
/// tab. The operator names every destination; nothing is taken from a URL, so no
/// server can steer where its own bytes are written. A line without one uses the
/// destination given on the command line, which only one line may do.
pub fn read_requests(
    input: impl std::io::Read,
    default_destination: &Path,
) -> Result<Vec<Request>, EngineError> {
    let mut requests = Vec::new();
    let mut defaulted = false;
    for line in read_lines(input)? {
        let (url, destination) = match line.split_once('\t') {
            Some((url, destination)) => (url, absolute(Path::new(destination.trim()))?),
            None => {
                if defaulted {
                    // Two URLs cannot share one name; the second must say where.
                    return Err(EngineError::InvalidInput);
                }
                defaulted = true;
                (line.as_str(), default_destination.to_path_buf())
            }
        };
        let url = url.trim();
        if url.is_empty() {
            return Err(EngineError::InvalidInput);
        }
        requests.push(Request {
            url: url.to_owned(),
            destination,
            expected_sha256: None,
            sensitive: false,
        });
    }
    if requests.is_empty() {
        return Err(EngineError::InvalidInput);
    }
    Ok(requests)
}

fn read_lines(mut input: impl std::io::Read) -> Result<Vec<String>, EngineError> {
    use std::io::Read;
    let mut buffer = Vec::new();
    input
        .by_ref()
        .take(1 << 20)
        .read_to_end(&mut buffer)
        .map_err(|_| EngineError::InvalidInput)?;
    let text = String::from_utf8(buffer).map_err(|_| EngineError::InvalidInput)?;
    let lines: Vec<String> = text
        .lines()
        .map(|line| line.trim_end_matches('\r').to_owned())
        .filter(|line| !line.is_empty())
        .collect();
    if lines.is_empty() || lines.iter().any(|line| line.len() > 16_384) {
        return Err(EngineError::InvalidInput);
    }
    Ok(lines)
}

pub fn absolute(path: &Path) -> Result<PathBuf, EngineError> {
    std::path::absolute(path).map_err(|_| EngineError::InvalidInput)
}

/// Only controlled categories reach the operator: never a URL or server text.
pub fn code(error: &EngineError) -> String {
    match error {
        EngineError::InvalidInput => "ENGINE-INVALID-INPUT".into(),
        EngineError::EndpointUnavailable => "IPC-ENDPOINT-UNAVAILABLE".into(),
        EngineError::NothingToContinue => "NOTHING-TO-CONTINUE".into(),
        EngineError::CrossVolume => "DESTINATION-OTHER-VOLUME".into(),
        EngineError::NeedsDecision(reason) => match reason {
            Some(reason) => format!("STOPPED-{reason:?}-RERUN-WITH-RESUME").to_uppercase(),
            None => "STOPPED-RERUN-WITH-RESUME".into(),
        },
        EngineError::Persistence(error) => error.code().into(),
        EngineError::Binding(error) => format!("SOURCE-{error:?}").to_uppercase(),
        EngineError::Admission(error) => error.code().into(),
        EngineError::Run(error) => format!("RUN-{error:?}").to_uppercase(),
    }
}
