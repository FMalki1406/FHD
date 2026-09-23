//! The resident engine: it takes work over the control surface for as long as it
//! runs, instead of being handed a list at startup. It owns the mapping from a
//! request to a job; the socket layer only carries frames, and the scheduler only
//! decides who runs.
use crate::{
    digest, reference, same_volume, EngineConfig, EngineError, LocalOperator, SystemClock,
};
use fhd_app::{
    AddDownload, AppError, Destinations, ReferenceStore, SourceReference, TransferRepository,
};
use fhd_domain::{DestinationRef, Job, JobId, JobSpec, JobState, Priority, SourceRef};
use fhd_http::{HttpConfig, HttpTransport, SourceBinding};
use fhd_ipc::{Endpoint, Handler, Server};
use fhd_persistence::{Limits, SqliteRepository};
use fhd_protocol::{AddRequest, JobSummary, Request, Response, MAX_JOBS_PER_PAGE};
use fhd_runtime::{
    buffers::BufferPool,
    coordinator::{Coordinator, CoordinatorConfig, Ports},
    origin::{OriginGovernor, OriginLimits},
    scheduler::{Command, Scheduler, SchedulerConfig},
};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc;

/// Destinations learned as jobs are admitted, rather than fixed at startup.
#[derive(Default)]
struct Registry(Mutex<HashMap<DestinationRef, PathBuf>>);
impl Registry {
    fn insert(&self, destination: DestinationRef, path: PathBuf) {
        if let Ok(mut map) = self.0.lock() {
            map.insert(destination, path);
        }
    }
    /// True when this name is already spoken for by a different reference.
    fn claimed_by_other(&self, destination: DestinationRef, path: &std::path::Path) -> bool {
        self.0.lock().is_ok_and(|map| {
            map.iter()
                .any(|(other, taken)| *other != destination && taken.as_path() == path)
        })
    }
}
impl Destinations for Registry {
    fn resolve(&self, destination: DestinationRef) -> Result<PathBuf, AppError> {
        self.0
            .lock()
            .map_err(|_| AppError::PersistenceUnavailable)?
            .get(&destination)
            .cloned()
            .ok_or(AppError::InvalidInput)
    }
}

/// Everything a request needs to become a job, and the channel that carries it to
/// the scheduler.
pub struct Service {
    repository: Arc<SqliteRepository>,
    transport: Arc<HttpTransport>,
    destinations: Arc<Registry>,
    commands: mpsc::Sender<Command>,
    config: EngineConfig,
    /// The engine's own tree and the allowed root, as the filesystem itself names
    /// them: a destination cannot be admitted by spelling one of them differently.
    canonical_state: PathBuf,
    canonical_root: Option<PathBuf>,
}

/// A running engine: its control surface and the scheduler behind it.
pub struct Resident {
    service: Arc<Service>,
    scheduler: Scheduler,
    incoming: mpsc::Receiver<Command>,
    restored: Vec<Job>,
}

impl Resident {
    /// Builds the engine and restores what the state directory remembers. Nothing
    /// is fetched until `serve` runs.
    pub async fn open(config: EngineConfig) -> Result<Self, EngineError> {
        if !config.state_directory.is_absolute()
            || !(1..=16).contains(&config.connections)
            || !(1..=64).contains(&config.engine_connections)
            || config.connections > config.engine_connections
            || !(1..=64).contains(&config.max_active)
        {
            return Err(EngineError::InvalidInput);
        }
        crate::own_directory(&config.state_directory)?;
        crate::own_directory(&config.state_directory.join("parts"))?;
        let repository = Arc::new(
            SqliteRepository::open(config.state_directory.join("state"), Limits::default())
                .await
                .map_err(EngineError::Persistence)?,
        );
        let transport =
            Arc::new(HttpTransport::new(HttpConfig::default()).map_err(EngineError::Binding)?);
        let destinations = Arc::new(Registry::default());
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
                    store: Arc::new(crate::own_parts(&config.state_directory)?),
                    transport: transport.clone(),
                    destinations: destinations.clone(),
                },
                BufferPool::new(config.engine_connections * 256 * 1024)
                    .map_err(|_| EngineError::InvalidInput)?,
                Arc::new(SystemClock),
                CoordinatorConfig {
                    connections: config.connections,
                    max_segments: 1024,
                    min_segment: 1024 * 1024,
                    checkpoint_bytes: 8 * 1024 * 1024,
                    writer_capacity: 16,
                    retry: fhd_domain::RetryPolicy::new(5, 1000, 60_000)
                        .map_err(|_| EngineError::InvalidInput)?,
                },
                config.state_directory.join("parts"),
            )
            .map_err(EngineError::Run)?
            .with_governor(governor.clone()),
        );
        let scheduler = Scheduler::new(
            coordinator,
            governor,
            SchedulerConfig {
                max_active: config.max_active,
                connections: config.engine_connections,
                per_job: config.connections,
                // It waits for work rather than finishing when the queue empties.
                resident: true,
            },
        )
        .map_err(EngineError::Run)?;
        let (commands, incoming) = mpsc::channel(64);
        let state = config.state_directory.clone();
        // Both exist by now: the engine made its own tree above, and a download
        // root that does not exist is a configuration error, not a surprise.
        let canonical_state = state
            .canonicalize()
            .map_err(|_| EngineError::InvalidInput)?;
        let canonical_root = match &config.download_root {
            Some(root) => Some(
                root.canonicalize()
                    .map_err(|_| EngineError::DestinationRefused)?,
            ),
            None => None,
        };
        let service = Arc::new(Service {
            repository: repository.clone(),
            transport: transport.clone(),
            destinations: destinations.clone(),
            commands,
            config,
            canonical_state,
            canonical_root,
        });
        let restored = service.restore().await?;
        Ok(Self {
            service,
            scheduler,
            incoming,
            restored,
        })
    }

    /// Claims the control surface. Binding is separate from serving so a caller
    /// knows the endpoint is live before it tells anyone to use it.
    pub fn bind(self, endpoint: Endpoint) -> Result<Serving, EngineError> {
        let Self {
            service,
            scheduler,
            incoming,
            restored,
        } = self;
        let server = Server::bind(endpoint).map_err(|_| EngineError::EndpointUnavailable)?;
        Ok(Serving {
            server,
            service,
            scheduler,
            incoming,
            restored,
        })
    }
}

/// A bound engine: the endpoint is live and the queue is ready to run.
pub struct Serving {
    server: Server,
    service: Arc<Service>,
    scheduler: Scheduler,
    incoming: mpsc::Receiver<Command>,
    restored: Vec<Job>,
}

impl Serving {
    pub fn endpoint(&self) -> &Endpoint {
        self.server.endpoint()
    }

    /// Answers clients and runs the scheduler until one asks it to stop or `stop`
    /// resolves. Jobs the directory remembered start straight away.
    pub async fn serve(
        self,
        stop: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<(), EngineError> {
        let Self {
            server,
            service,
            scheduler,
            incoming,
            restored,
        } = self;
        let commands = service.commands.clone();
        // Two ways to end: a client's Shutdown, or the caller's own signal. Either
        // stops the listener and lets running jobs come to rest durably.
        let (done, ended) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            stop.await;
            let _ = commands.send(Command::Shutdown).await;
            let _ = done.send(());
        });
        let serving = tokio::spawn({
            let service = service.clone();
            async move {
                server
                    .serve(service, async {
                        let _ = ended.await;
                    })
                    .await;
            }
        });
        let outcomes = scheduler.run(restored, incoming).await;
        // The repository keeps every job; these are only what this run touched.
        drop(outcomes);
        // Let go of the endpoint and the database before returning, so a caller
        // that opens this directory next does not meet our own lock.
        serving.abort();
        let _ = serving.await;
        drop(service);
        Ok(())
    }
}

impl Service {
    /// Jobs this directory remembers, bound so they can be fetched again.
    async fn restore(&self) -> Result<Vec<Job>, EngineError> {
        let store: &dyn ReferenceStore = self.repository.as_ref();
        let sources: HashMap<_, _> = store
            .sources()
            .await
            .map_err(EngineError::Admission)?
            .into_iter()
            .collect();
        for (destination, path) in store.destinations().await.map_err(EngineError::Admission)? {
            self.destinations.insert(destination, path);
        }
        let mut restored = Vec::new();
        for job in self
            .repository
            .load_jobs()
            .await
            .map_err(EngineError::Admission)?
        {
            let Some(reference) = sources.get(&job.spec().source()) else {
                continue;
            };
            // A link kept out of the database cannot be fetched again unattended.
            let Some(url) = reference.url() else {
                continue;
            };
            // Policy is what this run was started with, not what an earlier run
            // was allowed: a job recorded with cleartext permitted stays parked
            // until an operator starts the engine that way again.
            if reference.allow_http() && !self.config.allow_http {
                continue;
            }
            if self
                .bind(job.spec().source(), url, reference.allow_http())
                .is_err()
            {
                continue;
            }
            if matches!(job.state(), JobState::Queued | JobState::RetryWait) {
                restored.push(job);
            }
        }
        Ok(restored)
    }

    fn bind(&self, source: SourceRef, url: &str, allow_http: bool) -> Result<(), EngineError> {
        self.transport
            .bind(
                source,
                SourceBinding::new(url, None, None, allow_http, vec![])
                    .map_err(EngineError::Binding)?,
            )
            .map_err(EngineError::Binding)
    }

    /// Admits one request: checks it, records what it points at, and hands the job
    /// to the scheduler. Anything refused is refused before a byte is fetched.
    async fn add(&self, request: AddRequest) -> Result<JobId, EngineError> {
        // The client proposes; this decides. A destination is refused here rather
        // than after a whole file has been fetched.
        let destination_path = self.allowed_destination(&request.destination)?;
        // Both sides resolved the same way: comparing a canonical path with a
        // configured one would compare a verbatim prefix against a drive letter
        // and call two places on one disk different volumes.
        if !same_volume(&self.canonical_state, &destination_path)? {
            return Err(EngineError::CrossVolume);
        }
        let expected = match &request.expected_sha256 {
            Some(hex) => Some(decode_digest(hex)?),
            None => None,
        };
        let allow_http = request.allow_http && self.config.allow_http;
        let source = SourceRef::new(reference(
            b"FHD.source.v1\0",
            &[request.url.as_bytes(), &[u8::from(allow_http)]],
        ))
        .map_err(|_| EngineError::InvalidInput)?;
        let destination = DestinationRef::new(reference(
            b"FHD.destination.v1\0",
            &[request.destination.as_bytes()],
        ))
        .map_err(|_| EngineError::InvalidInput)?;
        // Two jobs aiming at one name would race for it; the second is refused.
        if self
            .destinations
            .claimed_by_other(destination, &destination_path)
        {
            return Err(EngineError::InvalidInput);
        }
        self.bind(source, &request.url, allow_http)?;
        let spec = JobSpec::new(
            source,
            destination,
            expected,
            Priority::Normal,
            request.max_bytes.min(self.config.max_bytes),
        )
        .map_err(|_| EngineError::InvalidInput)?;
        let key = fhd_app::ReceiptKey::new(
            fhd_app::Principal::new(1).map_err(EngineError::Admission)?,
            digest(
                b"FHD.request.v1\0",
                &[
                    request.url.as_bytes(),
                    request.destination.as_bytes(),
                    &expected.unwrap_or_default(),
                    &request.max_bytes.to_le_bytes(),
                    &[u8::from(allow_http)],
                ],
            ),
        );
        let id = AddDownload::new(self.repository.as_ref(), &LocalOperator, &LocalOperator)
            .execute(key, spec)
            .await
            .map_err(EngineError::Admission)?;
        let stored = if request.sensitive {
            SourceReference::sensitive(allow_http)
        } else {
            SourceReference::new(request.url.clone(), allow_http).map_err(EngineError::Admission)?
        };
        ReferenceStore::record(
            self.repository.as_ref(),
            source,
            stored,
            destination,
            destination_path.clone(),
        )
        .await
        .map_err(|_| EngineError::Admission(AppError::PersistenceUnavailable))?;
        // Only now, once the database holds both: the map is a cache of what was
        // accepted, never a claim staked before anything was.
        self.destinations
            .insert(destination, destination_path.clone());
        let job = self.job(id).await?;
        // Already finished or resting: admitted, but nothing for the queue.
        if matches!(job.state(), JobState::Queued) {
            let _ = self.commands.send(Command::Admit(Box::new(job))).await;
        }
        Ok(id)
    }

    /// Where a client's bytes may land. A local peer is the same user, so this is
    /// not a wall against that user -- it is a wall against a request choosing a
    /// name that the engine itself, or the system, gives meaning to.
    fn allowed_destination(&self, proposed: &str) -> Result<PathBuf, EngineError> {
        let path = PathBuf::from(proposed);
        if !path.is_absolute() {
            return Err(EngineError::DestinationRefused);
        }
        // `..` never reaches the filesystem: it is resolved here, so a path that
        // climbs out of an allowed place cannot be admitted by spelling.
        let mut resolved = PathBuf::new();
        for part in path.components() {
            match part {
                std::path::Component::ParentDir => {
                    if !resolved.pop() {
                        return Err(EngineError::DestinationRefused);
                    }
                }
                std::path::Component::CurDir => {}
                other => resolved.push(other.as_os_str()),
            }
        }
        let leaf = resolved
            .file_name()
            .and_then(|leaf| leaf.to_str())
            .ok_or(EngineError::DestinationRefused)?;
        if !crate::publishable_name(leaf) {
            return Err(EngineError::DestinationRefused);
        }
        // Comparing the paths as written answers only the spelling in front of
        // us: on Windows a different case, an 8.3 alias or a junction all name
        // the same directory while comparing unequal. The parent must exist to
        // publish into anyway, so it is resolved by the filesystem, and every
        // comparison below is between answers from the filesystem itself.
        let parent = resolved.parent().ok_or(EngineError::DestinationRefused)?;
        let parent = parent
            .canonicalize()
            .map_err(|_| EngineError::DestinationRefused)?;
        // The engine's own tree holds the database, its journals and the part
        // files. A download landing in there would be handing a remote server a
        // say in the engine's own state.
        if parent.starts_with(&self.canonical_state) {
            return Err(EngineError::DestinationRefused);
        }
        match &self.canonical_root {
            Some(root) if !parent.starts_with(root) => return Err(EngineError::DestinationRefused),
            _ => {}
        }
        Ok(parent.join(leaf))
    }

    async fn job(&self, id: JobId) -> Result<Job, EngineError> {
        self.repository
            .load_jobs()
            .await
            .map_err(EngineError::Admission)?
            .into_iter()
            .find(|job| job.id() == id)
            .ok_or(EngineError::InvalidInput)
    }

    /// One page of jobs, oldest identifier first.
    async fn list(&self, after: Option<u64>) -> Result<Response, EngineError> {
        let mut jobs: Vec<Job> = self
            .repository
            .load_jobs()
            .await
            .map_err(EngineError::Admission)?
            .into_iter()
            .filter(|job| job.id().get() > after.unwrap_or(0))
            .collect();
        jobs.sort_by_key(|job| job.id().get());
        let next = jobs
            .get(MAX_JOBS_PER_PAGE)
            .map(|_| jobs[MAX_JOBS_PER_PAGE - 1].id().get());
        jobs.truncate(MAX_JOBS_PER_PAGE);
        Ok(Response::Jobs {
            jobs: jobs.iter().map(summarize).collect(),
            next,
        })
    }
}

fn summarize(job: &Job) -> JobSummary {
    let projection = job.projection();
    JobSummary {
        job: job.id().get(),
        // Closed names, for the same reason the error codes are closed: a future
        // variant carrying a path must not put it on the wire by being printed.
        state: crate::job_state(job.state()).to_owned(),
        reason: job
            .reason()
            .map(|reason| crate::stop_reason(&reason).to_owned()),
        durable_bytes: projection.durable_bytes,
        total: job.plan().map(|(total, _)| total),
    }
}

fn decode_digest(hex: &str) -> Result<[u8; 32], EngineError> {
    if hex.len() != 64 {
        return Err(EngineError::InvalidInput);
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16)
            .map_err(|_| EngineError::InvalidInput)?;
    }
    Ok(digest)
}

impl Handler for Service {
    async fn handle(&self, request: Request) -> Response {
        match request {
            Request::Add(add) => match self.add(add).await {
                Ok(id) => Response::Accepted { job: id.get() },
                Err(error) => Response::Failed {
                    code: crate::code(&error),
                },
            },
            Request::List { after } => match self.list(after).await {
                Ok(response) => response,
                Err(error) => Response::Failed {
                    code: crate::code(&error),
                },
            },
            Request::Pause { job } | Request::Resume { job } | Request::Cancel { job } => {
                let Ok(id) = JobId::new(job) else {
                    return Response::Failed {
                        code: "ENGINE-INVALID-INPUT".into(),
                    };
                };
                let command = match request {
                    Request::Cancel { .. } => Command::Cancel(id),
                    // Resume is not a scheduler command: a stopped job is released
                    // by the operator, which this build does not do over IPC yet.
                    Request::Resume { .. } => {
                        return Response::Failed {
                            code: "ENGINE-UNSUPPORTED".into(),
                        }
                    }
                    _ => Command::Pause(id),
                };
                match self.commands.send(command).await {
                    Ok(()) => Response::Done,
                    Err(_) => Response::Failed {
                        code: "ENGINE-STOPPING".into(),
                    },
                }
            }
            Request::Shutdown => match self.commands.send(Command::Shutdown).await {
                Ok(()) => Response::Done,
                Err(_) => Response::Done,
            },
        }
    }
}
