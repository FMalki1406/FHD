//! Bounded, process-local ownership of transfers. Call `shutdown` before stopping
//! the Tokio runtime; dropping the handle requests cancellation but cannot await it.

use crate::{download, Error, Options, Outcome};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct JobId(pub u64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Queued,
    Running,
    Pausing,
    Paused,
    Completed,
    Failed(Error),
}

/// Deliberately excludes URLs, filenames, paths and response headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSnapshot {
    pub id: JobId,
    pub state: State,
    pub committed_bytes: u64,
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
}

impl std::fmt::Display for ManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ManagerError {}

type Reply<T> = oneshot::Sender<Result<T, ManagerError>>;
enum Command {
    Enqueue(Options, Reply<JobId>),
    Pause(JobId, Reply<()>),
    Resume(JobId, Reply<()>),
}

/// One owner; command methods may be used concurrently through shared references.
/// Successful command submission may take effect even if its caller stops waiting.
pub struct Manager {
    commands: Option<mpsc::Sender<Command>>,
    snapshots: watch::Receiver<Vec<JobSnapshot>>,
    actor: Option<JoinHandle<()>>,
}

impl Manager {
    pub fn start(max_active: usize, max_jobs: usize) -> Result<Self, ManagerError> {
        if !(1..=32).contains(&max_active)
            || !(1..=1024).contains(&max_jobs)
            || max_active > max_jobs
        {
            return Err(ManagerError::InvalidLimits);
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| ManagerError::NoRuntime)?;
        let (commands, receiver) = mpsc::channel(64);
        let (updates, snapshots) = watch::channel(Vec::new());
        let actor = runtime.spawn(run(receiver, updates, max_active, max_jobs));
        Ok(Self {
            commands: Some(commands),
            snapshots,
            actor: Some(actor),
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<Vec<JobSnapshot>> {
        self.snapshots.clone()
    }

    pub async fn enqueue(&self, options: Options) -> Result<JobId, ManagerError> {
        validate_options(&options)?;
        let (reply, result) = oneshot::channel();
        self.commands
            .as_ref()
            .ok_or(ManagerError::Closed)?
            .send(Command::Enqueue(options, reply))
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

    /// Stops admission, cancels active jobs, and awaits every worker without aborting.
    /// Success means workers drained, not that every job paused successfully; retain
    /// a snapshot subscription to inspect failures after shutdown.
    pub async fn shutdown(mut self) -> Result<(), ManagerError> {
        self.commands.take();
        if let Some(actor) = self.actor.take() {
            actor.await.map_err(|_| ManagerError::WorkerFailed)?;
        }
        Ok(())
    }
}

struct Job {
    options: Options,
    key: PathBuf,
    state: State,
    progress: Arc<AtomicU64>,
    cancel: Option<watch::Sender<bool>>,
    pause_reply: Option<Reply<()>>,
}

fn validate_options(options: &Options) -> Result<(), ManagerError> {
    if options.url.len() > 16_384
        || options.output_name.is_empty()
        || options.output_name.len() > 255
        || options.job_dir.as_os_str().len() > 32_768
        || options.checkpoint_bytes == 0
        || options.checkpoint_bytes > 64 * 1024 * 1024
        || options.max_download_bytes == 0
        || options.max_download_bytes > i64::MAX as u64
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
            state: job.state.clone(),
            committed_bytes: job.progress.load(Ordering::Relaxed),
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
    queue.clear();
    for (_, job) in jobs {
        match job.state {
            State::Queued => job.state = State::Paused,
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

async fn run(
    mut commands: mpsc::Receiver<Command>,
    updates: watch::Sender<Vec<JobSnapshot>>,
    max_active: usize,
    max_jobs: usize,
) {
    let mut jobs: Vec<(JobId, Job)> = Vec::new();
    let mut queue = VecDeque::new();
    let mut workers: JoinSet<Result<Outcome, Error>> = JoinSet::new();
    let mut owners: HashMap<Id, JobId> = HashMap::new();
    let mut closing = false;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        // Detect dropped ownership before scheduling another queued job.
        if commands.is_closed() && !closing {
            closing = true;
            commands.close();
            stop(&mut jobs, &mut queue);
        }
        while !closing && workers.len() < max_active {
            let Some(id) = queue.pop_front() else {
                break;
            };
            let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) else {
                continue;
            };
            if job.state != State::Queued {
                continue;
            }
            let options = job.options.clone();
            let progress = Arc::clone(&job.progress);
            let (cancel, receiver) = watch::channel(false);
            job.cancel = Some(cancel);
            job.state = State::Running;
            let handle = workers.spawn(async move {
                download(options, receiver, |bytes| {
                    progress.store(bytes, Ordering::Relaxed);
                })
                .await
            });
            owners.insert(handle.id(), id);
        }
        publish(&jobs, &updates);
        if closing && workers.is_empty() {
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
                        finish(job, result);
                        publish(&jobs, &updates);
                        if let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) {
                            if let Some(reply) = job.pause_reply.take() {
                                let result = if matches!(job.state, State::Failed(_)) { Err(ManagerError::WorkerFailed) } else { Ok(()) };
                                let _ = reply.send(result);
                            }
                        }
                    }
                }
            }
            command = commands.recv(), if !closing => {
                match command {
                    None => { closing = true; stop(&mut jobs, &mut queue); }
                    Some(Command::Enqueue(options, reply)) => {
                        if jobs.len() >= max_jobs { let _ = reply.send(Err(ManagerError::Capacity)); continue; }
                        let path = options.job_dir.clone();
                        let key = tokio::task::spawn_blocking(move || path_key(path)).await;
                        let key = match key {
                            Ok(Ok(key)) => key,
                            Ok(Err(error)) => { let _ = reply.send(Err(error)); continue; }
                            Err(_) => { let _ = reply.send(Err(ManagerError::WorkerFailed)); continue; }
                        };
                        if jobs.iter().any(|(_, job)| job.key == key) {
                            let _ = reply.send(Err(ManagerError::DuplicateJob)); continue;
                        }
                        let id = JobId(jobs.len() as u64 + 1);
                        jobs.push((id, Job { options, key, state: State::Queued, progress: Arc::new(AtomicU64::new(0)), cancel: None, pause_reply: None }));
                        queue.push_back(id);
                        publish(&jobs, &updates);
                        let _ = reply.send(Ok(id));
                    }
                    Some(Command::Pause(id, reply)) => {
                        let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) else { let _ = reply.send(Err(ManagerError::UnknownJob)); continue; };
                        match job.state {
                            State::Queued => {
                                queue.retain(|key| *key != id);
                                job.state = State::Paused;
                                publish(&jobs, &updates);
                                let _ = reply.send(Ok(()));
                            }
                            State::Running => {
                                job.state = State::Pausing;
                                job.pause_reply = Some(reply);
                                if let Some(cancel) = &job.cancel { cancel.send_replace(true); }
                            }
                            State::Paused => { let _ = reply.send(Ok(())); }
                            _ => { let _ = reply.send(Err(ManagerError::InvalidTransition)); }
                        }
                    }
                    Some(Command::Resume(id, reply)) => {
                        let Some((_, job)) = jobs.iter_mut().find(|(key, _)| *key == id) else { let _ = reply.send(Err(ManagerError::UnknownJob)); continue; };
                        if matches!(job.state, State::Paused | State::Failed(_)) {
                            job.state = State::Queued;
                            queue.push_back(id);
                            publish(&jobs, &updates);
                            let _ = reply.send(Ok(()));
                        } else { let _ = reply.send(Err(ManagerError::InvalidTransition)); }
                    }
                }
            }
            _ = tick.tick() => {}
        }
    }
    publish(&jobs, &updates);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> Options {
        Options {
            url: "https://example.com/private?secret=DO_NOT_DISCLOSE".into(),
            job_dir: std::env::temp_dir().join("private-job"),
            output_name: "private-filename.bin".into(),
            expected_sha256: None,
            allow_http: false,
            checkpoint_bytes: 1024,
            max_download_bytes: 1024,
        }
    }

    fn pausing_job() -> Job {
        Job {
            options: options(),
            key: PathBuf::new(),
            state: State::Pausing,
            progress: Arc::new(AtomicU64::new(0)),
            cancel: None,
            pause_reply: None,
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
        let mut opts = options();
        opts.url = "x".repeat(16_385);
        assert_eq!(validate_options(&opts), Err(ManagerError::InvalidOptions));
        let mut opts = options();
        opts.output_name = "x".repeat(256);
        assert_eq!(validate_options(&opts), Err(ManagerError::InvalidOptions));
        assert_eq!(
            path_key(PathBuf::from("relative/job")),
            Err(ManagerError::InvalidPath)
        );
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
                path_key(std::env::temp_dir().join(leaf)),
                Err(ManagerError::InvalidPath)
            );
        }
    }
}
