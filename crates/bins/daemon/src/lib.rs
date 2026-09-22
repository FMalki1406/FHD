//! Composition root: the only place that wires ports to adapters. It owns no
//! protocol, storage or state rules of its own.
#![forbid(unsafe_code)]

use fhd_app::{
    AddDownload, AppError, Authorizer, Destinations, EntitlementGate, Principal, ReceiptKey,
    TransferRepository,
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
};
use fhd_storage::FileStorage;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;

#[derive(Debug)]
pub enum EngineError {
    InvalidInput,
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

/// One destination per reference, fixed when the job was accepted.
struct FixedDestinations {
    reference: DestinationRef,
    path: PathBuf,
}
impl Destinations for FixedDestinations {
    fn resolve(&self, destination: DestinationRef) -> Result<PathBuf, AppError> {
        if destination != self.reference {
            return Err(AppError::InvalidInput);
        }
        Ok(self.path.clone())
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
    pub connections: usize,
    pub expected_sha256: Option<[u8; 32]>,
    pub max_bytes: u64,
    pub allow_http: bool,
    pub intent: Intent,
}

/// A single-job engine: enough to download, verify and publish end to end.
/// No scheduler, no IPC, and no reference store yet: the caller supplies the URL
/// again on every run, so no URL or credential is written to disk.
pub struct Engine {
    repository: Arc<SqliteRepository>,
    coordinator: Coordinator,
    key: ReceiptKey,
    spec: JobSpec,
    intent: Intent,
    id: std::sync::Mutex<Option<fhd_domain::JobId>>,
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
    pub async fn open(config: EngineConfig, url: &str) -> Result<Self, EngineError> {
        if !config.state_directory.is_absolute()
            || !config.destination.is_absolute()
            || !(1..=16).contains(&config.connections)
        {
            return Err(EngineError::InvalidInput);
        }
        // The engine owns this tree and creates it; the destination is the user's.
        own_directory(&config.state_directory)?;
        own_directory(&config.state_directory.join("parts"))?;
        if !same_volume(&config.state_directory, &config.destination)? {
            return Err(EngineError::CrossVolume);
        }
        let repository = Arc::new(
            SqliteRepository::open(config.state_directory.join("state"), Limits::default())
                .await
                .map_err(EngineError::Persistence)?,
        );
        let transport = HttpTransport::new(HttpConfig::default()).map_err(EngineError::Binding)?;
        // The binding, not just the URL: an http permission changes what may be sent.
        let source = SourceRef::new(reference(
            b"FHD.source.v1\0",
            &[url.as_bytes(), &[u8::from(config.allow_http)]],
        ))
        .map_err(|_| EngineError::InvalidInput)?;
        let destination = DestinationRef::new(reference(
            b"FHD.destination.v1\0",
            &[config.destination.to_string_lossy().as_bytes()],
        ))
        .map_err(|_| EngineError::InvalidInput)?;
        transport
            .bind(
                source,
                SourceBinding::new(url, None, None, config.allow_http, vec![])
                    .map_err(EngineError::Binding)?,
            )
            .map_err(EngineError::Binding)?;
        let spec = JobSpec::new(
            source,
            destination,
            config.expected_sha256,
            Priority::Normal,
            config.max_bytes,
        )
        .map_err(|_| EngineError::InvalidInput)?;
        let buffers = BufferPool::new(config.connections * 256 * 1024)
            .map_err(|_| EngineError::InvalidInput)?;
        let coordinator = Coordinator::new(
            Ports {
                repository: repository.clone(),
                store: Arc::new(FileStorage),
                transport: Arc::new(transport),
                destinations: Arc::new(FixedDestinations {
                    reference: destination,
                    path: config.destination.clone(),
                }),
            },
            buffers,
            Arc::new(SystemClock),
            CoordinatorConfig {
                connections: config.connections,
                max_segments: 1024,
                min_segment: 1024 * 1024,
                checkpoint_bytes: 8 * 1024 * 1024,
                writer_capacity: 16,
                retry: RetryPolicy::new(5, 1000, 60_000).map_err(|_| EngineError::InvalidInput)?,
            },
            config.state_directory.join("parts"),
        )
        .map_err(EngineError::Run)?;
        Ok(Self {
            repository,
            coordinator,
            key: ReceiptKey::new(
                Principal::new(1).map_err(EngineError::Admission)?,
                // The whole request: the same URL to another destination is another job.
                digest(
                    b"FHD.request.v1\0",
                    &[
                        url.as_bytes(),
                        config.destination.to_string_lossy().as_bytes(),
                        &config.expected_sha256.unwrap_or_default(),
                        &config.max_bytes.to_le_bytes(),
                        &[u8::from(config.allow_http)],
                    ],
                ),
            ),
            spec,
            intent: config.intent,
            id: std::sync::Mutex::new(None),
        })
    }

    /// Admits the request (replaying an earlier one with the same key) and settles
    /// whatever state it is in: recovery first, then one session.
    pub async fn run(&self, control: mpsc::Receiver<Control>) -> Result<SessionEnd, EngineError> {
        let id = AddDownload::new(self.repository.as_ref(), &LocalOperator, &LocalOperator)
            .execute(self.key, self.spec.clone())
            .await
            .map_err(EngineError::Admission)?;
        *self.id.lock().map_err(|_| EngineError::InvalidInput)? = Some(id);
        let job = self.load(id).await?;
        let job = self
            .coordinator
            .recover(job)
            .await
            .map_err(EngineError::Run)?;
        if matches!(job.state(), JobState::Completed | JobState::Cancelled) {
            return Ok(SessionEnd::Settled(job.state()));
        }
        let job = match (job.state(), self.intent) {
            (JobState::Queued | JobState::Probing | JobState::Transferring, _) => job,
            // A waiting retry is released by its own deadline, never by clearing it.
            (JobState::RetryWait, _) => {
                let due = job.retry_at().is_some_and(|at| at <= SystemClock.now_ms());
                if !due {
                    return Ok(SessionEnd::Settled(JobState::RetryWait));
                }
                self.command(
                    job,
                    JobCommand::RetryDue {
                        now_tick: SystemClock.now_ms(),
                    },
                )
                .await?
            }
            // Stopped jobs stay stopped until the operator says otherwise.
            (_, Intent::Start) => {
                return Err(EngineError::NeedsDecision(job.reason()));
            }
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
        self.coordinator
            .run(job, control)
            .await
            .map_err(EngineError::Run)
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
                None => job.spec() == &self.spec,
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

/// Reads a URL from standard input so signed links never appear in a process list.
pub fn read_url(mut input: impl std::io::Read) -> Result<String, EngineError> {
    use std::io::Read;
    let mut buffer = Vec::new();
    input
        .by_ref()
        .take(16_386)
        .read_to_end(&mut buffer)
        .map_err(|_| EngineError::InvalidInput)?;
    let url = String::from_utf8(buffer).map_err(|_| EngineError::InvalidInput)?;
    let url = url.trim_end_matches(['\r', '\n']).to_owned();
    if url.is_empty() || url.len() > 16_384 {
        return Err(EngineError::InvalidInput);
    }
    Ok(url)
}

pub fn absolute(path: &Path) -> Result<PathBuf, EngineError> {
    std::path::absolute(path).map_err(|_| EngineError::InvalidInput)
}
