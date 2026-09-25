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
    /// Another engine still owns this state directory. Its own shutdown releases
    /// it, which can take a moment after it has returned.
    StateBusy,
    /// The destination is not somewhere this engine will write: outside the
    /// allowed root, inside its own state tree, or a name the system reads as an
    /// instruction rather than a file.
    DestinationRefused,
    /// Nothing this run could continue: no recorded job with a usable link.
    NothingToContinue,
    /// The job is waiting for a decision; run again with Intent::Resume.
    NeedsDecision(Option<StopReason>),
    /// The state directory's own access list lets accounts other than this one,
    /// the system and the administrators write into it. It holds the job record
    /// and the receipts, so the engine will not adopt it. The count is how
    /// many such principals were found; the SIDs stay out of the code, which is
    /// carried across layers and logged.
    ExposedStateDirectory(u32),
    /// Some component of the path to the state directory could be renamed by an
    /// account outside the trusted set, so the directory checked is not
    /// guaranteed to be the directory opened. The count is how many components,
    /// not which: the code crosses layers and is logged.
    SwappableStatePath(u32),
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
struct FixedDestinations(HashMap<DestinationRef, PathBuf>, String);
impl Destinations for FixedDestinations {
    fn resolve(&self, destination: DestinationRef) -> Result<PathBuf, AppError> {
        self.0
            .get(&destination)
            .cloned()
            .ok_or(AppError::InvalidInput)
    }

    fn parts_for(&self, destination: DestinationRef) -> Result<PathBuf, AppError> {
        private_parts_directory(&self.resolve(destination)?, &self.1)
    }
}

/// A name for this engine's parts, taken from the directory that holds its job
/// record.
///
/// Two engines are two job records, and each numbers its jobs from one. Sharing
/// a download folder they would both claim `1-1.part`: a review ran that, and
/// the second engine took the first one's file over, re-downloaded into it from
/// zero and published its own content correctly -- while the first engine's
/// progress was destroyed with nothing said. Published bytes were never wrong;
/// the loss was silent, which is the part that makes it a defect rather than a
/// race worth tolerating.
///
/// The state directory is the identity because it is what a job record belongs
/// to: the same engine restarting resolves to the same name and finds its own
/// part to resume, and a different one cannot collide with it. Hashed rather
/// than spelled out, because the path is the operator's business and this name
/// is written inside the user's download folder.
pub(crate) fn engine_tag(state_directory: &Path) -> String {
    let canonical =
        std::fs::canonicalize(state_directory).unwrap_or_else(|_| state_directory.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(b"FHD.parts.owner.v1\x00");
    hasher.update(canonical.to_string_lossy().to_lowercase().as_bytes());
    let digest = hasher.finalize();
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The private directory a destination's part file is written in.
///
/// Parts moved next to their destination so that publication stays a link
/// within one directory, which is what lets a download land on a disk the
/// engine does not live on. Inside the engine's own directory they were covered
/// by an access list it had set; the user's download folder is not ours, and on
/// a data volume here it grants `Authenticated Users` write. Writing the part
/// straight into it would hand every account on the machine the bytes of a
/// download in progress.
///
/// So the part goes in a directory beside the destination that this engine
/// creates with its own list -- this account, the system, the administrators,
/// inheritance closed -- and the part inherits that. Same volume as the
/// destination, so the link is unaffected.
///
/// **What this does not reach**, measured rather than assumed -- an earlier
/// version of this comment said two things a review disproved.
///
/// It said `Authenticated Users: Modify` on the download folder leaves the
/// holder able to rename or remove this directory. It does not: that mask is
/// `0x1301BF` and `FILE_DELETE_CHILD` (`0x40`) is clear. Measured against a
/// live part file, an Authenticated-Users principal was denied read, write,
/// create, delete and rename. The residual applies to a folder that grants Full
/// Control or delete-child explicitly, not to the ordinary data-volume default.
///
/// And it said a substituted part can never be published because the file is
/// verified against its digest. That holds only when the caller supplied one.
/// With no `--sha256`, verification computes the digest from the file itself
/// and compares it with itself, so tampering is invisible to it; a review
/// overwrote sixteen bytes of a live part and the engine published them. What
/// stops substitution here is this directory's access list, not verification --
/// so the list is the control, and it is the thing that has to be right.
///
/// The ceiling is still the folder the user chose, and we do not raise it.
pub(crate) fn private_parts_directory(
    destination: &Path,
    engine: &str,
) -> Result<PathBuf, AppError> {
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(AppError::InvalidInput)?;
    // The shared outer directory first, then this engine's own inside it. Both
    // are created with our list; the outer one is what another engine also
    // opens, and the inner one is what makes "another engine" a different
    // directory rather than a fight over one file name.
    let outer = parent.join(".fhd-parts");
    let created_outer =
        fhd_platform::create_protected_directory(&outer).map_err(|_| AppError::InvalidInput)?;
    if !created_outer {
        inspect_found_directory(&outer)?;
    }
    let directory = outer.join(engine);
    let created =
        fhd_platform::create_protected_directory(&directory).map_err(|_| AppError::InvalidInput)?;
    if created {
        return Ok(directory);
    }
    inspect_found_directory(&directory)?;
    Ok(directory)
}

/// A directory we found rather than made.
///
/// A download folder that grants write lets any account on the machine make it
/// first, and whoever makes it owns it. Replacing its access list is not taking
/// it back, because an owner holds WRITE_DAC whatever the list says: ours goes
/// on, theirs goes back, and the part file inherits theirs. A review did exactly
/// that and read and wrote a live part file through it.
///
/// So it is inspected the way the state directory is, and refused rather than
/// adopted. `foreign_writers` reads the owner too, which is the part that
/// matters here -- on Windows through the descriptor, on Unix through the mode
/// and the owning uid.
fn inspect_found_directory(directory: &Path) -> Result<(), AppError> {
    let metadata = std::fs::symlink_metadata(directory).map_err(|_| AppError::InvalidInput)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AppError::InvalidInput);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(AppError::InvalidInput);
        }
    }
    let exposed = fhd_platform::foreign_writers(directory).map_err(|_| AppError::InvalidInput)?;
    if !exposed.is_empty() {
        return Err(AppError::InvalidInput);
    }
    Ok(())
}

/// Why the parts path is not refused for being swappable, though the state
/// directory is.
///
/// A review measured `swappable_components` reporting the download folder on the
/// ordinary data-volume default: `Authenticated Users` holds `DELETE` on the
/// folder and `FILE_ADD_SUBDIRECTORY` on the volume root, which is both halves
/// of a rename. Its recommendation was to refuse here as `own_directory`
/// refuses there.
///
/// Refusing would end the feature. That default is what `D:\Downloads` looks
/// like on a stock machine, so the refusal would fall on every download to a
/// data volume -- which is the case this whole change exists to support. The
/// state directory can be refused because the engine chooses where it goes; the
/// destination is the user's choice and we do not get to veto it.
///
/// What the swap costs, stated without leaning on a control that may move.
///
/// The adversary can read a partial file and destroy progress. **Whether they
/// can substitute the result is a separate question and it is open** -- see
/// `docs/feature-download-to-a-different-disk.md` §5 ب٣. An earlier version of
/// this comment said they could not, because publication hashed the destination
/// after linking it. That check has since been replaced, and the justification
/// for *this* decision was left pointing at it. That is the failure this project
/// keeps repeating: the compensating control moves and the argument that rested
/// on it stays behind, so a reader finds a reason that was true once.
///
/// So the reason given here is the one that does not depend on how publication
/// works: the finished file lands in the folder the user chose regardless, and
/// a folder other accounts can write cannot be made safer by anything we do
/// after delivering into it. The ceiling was never higher than that folder, and
/// refusing would not raise it -- it would only refuse the download.
///
/// So it is declared rather than enforced, and declared in the customer-facing
/// sentence rather than only here: **a download is protected up to the
/// permissions of the folder you chose for it.** Raising that needs the user to
/// choose somewhere else, which is advice, not a control.
/// How this platform turns a proved handle into a published name.
///
/// Publication asks for a link from the handle it verified rather than from the
/// path that handle happens to sit at, because a path is resolved when the call
/// runs -- so between proving the bytes and naming them, the name can be made
/// to mean another file. Measured, and it published the other file's bytes.
///
/// **Windows has a mechanism and Unix does not yet.** `linkat` through
/// `/proc/self/fd` on Linux and `/dev/fd` on macOS are candidates and neither is
/// measured, so neither is claimed here. Until one is, publication on those
/// platforms refuses with `Unsupported` rather than linking by name: the
/// fallback is the behaviour being replaced, and taking it quietly would leave
/// the same hole under a new arrangement.
struct PlatformLinker;

impl fhd_app::storage::HandleLinker for PlatformLinker {
    fn same_object(
        &self,
        left: &std::fs::File,
        right: &std::fs::File,
    ) -> Result<bool, fhd_app::storage::StorageError> {
        #[cfg(windows)]
        {
            fhd_platform::same_object(left, right)
                .map_err(|error| fhd_app::storage::StorageError::Io(error.kind()))
        }
        #[cfg(not(windows))]
        {
            use std::os::unix::fs::MetadataExt;
            let (left, right) = (
                left.metadata()
                    .map_err(|error| fhd_app::storage::StorageError::Io(error.kind()))?,
                right
                    .metadata()
                    .map_err(|error| fhd_app::storage::StorageError::Io(error.kind()))?,
            );
            Ok(left.dev() == right.dev() && left.ino() == right.ino())
        }
    }

    fn link(
        &self,
        file: &std::fs::File,
        directory: &std::fs::File,
        name: &std::ffi::OsStr,
    ) -> Result<(), fhd_app::storage::StorageError> {
        #[cfg(windows)]
        {
            fhd_platform::link_into_directory(file, directory, name).map_err(|error| {
                match error.kind() {
                    std::io::ErrorKind::AlreadyExists => fhd_app::storage::StorageError::Conflict,
                    std::io::ErrorKind::Unsupported | std::io::ErrorKind::CrossesDevices => {
                        fhd_app::storage::StorageError::Unsupported
                    }
                    std::io::ErrorKind::InvalidInput => {
                        fhd_app::storage::StorageError::InvalidInput
                    }
                    other => fhd_app::storage::StorageError::Io(other),
                }
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (file, directory, name);
            Err(fhd_app::storage::StorageError::Unsupported)
        }
    }
}

/// Stable codes for what an operator should know about a destination folder.
///
/// The decision lives here, in the composition root, because both entry points
/// need it and only one of them had it. The direct path printed a warning after
/// reading its requests from stdin; a download added through the service got
/// nothing, which was R4 in the review of 2026-09-24. A warning that only one
/// caller can see is not a warning the product gives.
///
/// Codes rather than sentences: the protocol carries these to a client, and a
/// message built from a request is a message an attacker helps write. The
/// folder is the caller's own input, so the code is enough to say which.
///
/// **A warning is not a protection.** The folder's permissions are the
/// operator's, and the finished file is protected only as far as they go.
pub fn shared_destination_warnings(folder: &Path) -> Vec<String> {
    let swappable = fhd_platform::swappable_components(folder).unwrap_or_default();
    let exposed = fhd_platform::foreign_writers(folder)
        .map(|writers| !writers.is_empty())
        .unwrap_or(false);
    if swappable.is_empty() && !exposed {
        return Vec::new();
    }
    vec!["DESTINATION-SHARED".to_string()]
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
    /// Application-owned directory for the job record, the receipts and the
    /// engine's own bookkeeping. Part files go in a private directory beside
    /// each destination instead, so publication stays a link within one
    /// directory and the destination may be on another disk.
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
    /// Where downloads may land. `None` allows anywhere on the engine's volume
    /// outside its own tree; a resident engine should be given one, so a client
    /// cannot choose a system location.
    pub download_root: Option<PathBuf>,
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
    /// Published into the folder that was adopted. Carries `Published` rather
    /// than a path so the caller can tell "it is at this path" from "it is in
    /// your folder, which has since been renamed".
    Published(fhd_app::storage::Published),
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

/// Claims the part directory for this engine, telling a caller that is merely
/// too early apart from one that asked for something impossible.
fn own_parts(state: &Path) -> Result<FileStorage, EngineError> {
    FileStorage::own(&state.join("parts"))
        .map(|store| store.with_linker(Arc::new(PlatformLinker)))
        .map_err(|error| match error {
            fhd_app::storage::StorageError::Locked => EngineError::StateBusy,
            _ => EngineError::InvalidInput,
        })
}

/// Creates the engine's own tree: no link may stand in for a directory, and on
/// Unix only the owner may read it. The destination stays the user's business.
fn own_directory(path: &Path) -> Result<(), EngineError> {
    // Whether this run made the directory decides what may be done to it: one we
    // created gets permissions of our own, one we found gets inspected.
    //
    // Created *with* its access list rather than created and then repaired.
    // Creating first leaves a window in which the directory carries whatever it
    // inherited -- on a data volume that is write access for every account on the
    // machine -- and Windows decides access when a handle is opened, so a handle
    // taken in that window outlives the repair.
    let created =
        fhd_platform::create_protected_directory(path).map_err(|_| EngineError::InvalidInput)?;
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
        // Only a directory we made. `create_protected_directory` passes the mode
        // to `mkdir(2)`, so ours already carries it and this is a no-op for them;
        // running it unconditionally narrowed an operator's existing directory to
        // 0700 without asking, which is the surprise the paragraph below says we
        // decline to cause. Left in for the case where the mode did not take.
        if created {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| EngineError::InvalidInput)?;
        }
    }
    // Unix states the permissions it wants above. Windows inherits instead, and
    // what it inherits depends entirely on where the operator put this directory:
    // a child of %LOCALAPPDATA%\Temp picks up entries for packaged applications,
    // and one on a data volume or at a drive root picks up Authenticated Users
    // with Modify -- every account on the machine. Since this directory holds the
    // job record and every partial file, inheriting either would mean something
    // other than this engine can rewrite what a download has already saved.
    //
    // So a directory we just made carries permissions of its own from the moment
    // it exists, and one that was already there is inspected and refused if it is
    // open to anyone else. We do not rewrite what we did not create: the operator
    // may have pointed at something shared or redirected, and changing its
    // permissions silently is a worse surprise than declining to use it.
    //
    // The inspection runs either way. A directory we created should have nothing
    // to report, and checking it anyway is what would catch a creation that
    // silently did not carry its list.
    let _ = created;
    let foreign = fhd_platform::foreign_writers(path).map_err(|_| EngineError::InvalidInput)?;
    if !foreign.is_empty() {
        return Err(EngineError::ExposedStateDirectory(
            foreign.sids().len() as u32
        ));
    }
    // And who could move it aside. Giving the directory a list of its own settles
    // who may write into it; it settles nothing about who may replace it, because
    // renaming needs DELETE on the component or FILE_DELETE_CHILD on its parent
    // and neither is granted by the directory's own list. If any component of the
    // path can be swapped, every check above describes a directory that may not
    // be the one the database and the part files are opened in a moment later --
    // measured on this machine: on a data volume every ancestor grants
    // Authenticated Users enough to do it.
    let swappable =
        fhd_platform::swappable_components(path).map_err(|_| EngineError::InvalidInput)?;
    if !swappable.is_empty() {
        return Err(EngineError::SwappableStatePath(swappable.len() as u32));
    }
    Ok(())
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
                    // What to fetch and where it lands: the same URL elsewhere is
                    // another job. The expected digest is deliberately NOT here.
                    // It changes neither of those, and folding it in made the same
                    // command line before and after `--sha256` started being
                    // applied resolve to two different jobs aiming at one name --
                    // which `open_many` then refuses outright, leaving `--continue`
                    // permanently broken for that directory. Out of the key, a
                    // changed digest meets `Receipt::replay` instead and is
                    // refused loudly as a conflict.
                    digest(
                        b"FHD.request.v1\0",
                        &[
                            request.url.as_bytes(),
                            request.destination.to_string_lossy().as_bytes(),
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
                    store: Arc::new(own_parts(&config.state_directory)?),
                    transport: Arc::new(transport),
                    destinations: Arc::new(FixedDestinations(
                        destinations,
                        engine_tag(&config.state_directory),
                    )),
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
            // Two remembered jobs may name one file. `open_many` refuses a batch
            // that does, which is right for requests an operator just typed --
            // but here the batch is everything the directory remembers, so
            // refusing it would make one duplicated destination lock every other
            // job out of being continued, with no way back except deleting the
            // directory and its progress. The later one is left behind instead,
            // said out loud, and the rest of the directory keeps working.
            if requests
                .iter()
                .any(|earlier: &Request| earlier.destination == *path)
            {
                tracing::event!(
                    target: "fhd",
                    tracing::Level::WARN,
                    code = "CONTINUE-DESTINATION-TAKEN",
                    job_id = job.id().get(),
                );
                continue;
            }
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
                    // No reply channel: this mapper forwards a local control
                    // signal, and there is no client waiting to be told.
                    Control::Pause => Command::Pause(id, None),
                    Control::Cancel => Command::Cancel(id, None),
                };
                if commands.send(command).await.is_err() {
                    return;
                }
            }
        });
        let mut outcomes = self.drive(ids, receiver).await?;
        match outcomes.pop().map(|(_, outcome)| outcome) {
            Some(JobOutcome::Published(outcome)) => Ok(SessionEnd::Published(outcome)),
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
                    (Some(Ok(SessionEnd::Published(outcome))), _) => JobOutcome::Published(outcome),
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
                if job
                    .reason()
                    .is_some_and(|reason| reason.needs_new_representation()) =>
            {
                // These bytes cannot be used: start a new representation. A new
                // generation is a new part file, so the part that cannot be
                // trusted or cannot be read is left exactly where it is rather
                // than written over.
                //
                // Which reasons those are is the domain's to say, not this
                // module's. Spelling the list out here is what let it drift from
                // the transition's own list, which an independent review found.
                self.command(job, JobCommand::ReplaceRepresentation).await?
            }
            // A reason that blocks a resume and has no replacement to offer.
            // `Unconfirmed` is the one: the part may already be the user's file,
            // so there is nothing for "go on" to mean, and the transition would
            // refuse it anyway. Reported as a decision the operator still owns
            // rather than attempted and refused, which would cost the origin a
            // probe to arrive back at this same answer.
            (JobState::NeedsAction, Intent::Resume)
                if job.reason().is_some_and(|reason| reason.blocks_resume()) =>
            {
                return Ok(Err(JobOutcome::NeedsDecision(job.reason())))
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
    /// Bytes this job has committed durably, as the repository records them.
    ///
    /// A test that wants to know whether progress survived a pause cannot ask
    /// the part file: it is created at its full length before anything is
    /// fetched, so its size says nothing. This is the record, which is what
    /// "durable progress" means.
    pub async fn durable_bytes(&self) -> Result<u64, EngineError> {
        Ok(self.current().await?.projection().durable_bytes)
    }
    /// Which representation of the source this job is working on.
    ///
    /// Part files carry it in their name, but a published part is removed from
    /// disk before the run returns, so the files cannot answer whether a resume
    /// continued the old representation or took a new one. The record can, and
    /// it is the record that decides.
    pub async fn generation(&self) -> Result<u64, EngineError> {
        Ok(self.current().await?.generation().get())
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

/// A closed set of names for what stopped a job. Formatting the enum would put
/// whatever a future variant carries -- a path, a server's words -- on the wire.
fn stop_reason(reason: &StopReason) -> &'static str {
    match reason {
        StopReason::SourceChanged => "SOURCE-CHANGED",
        StopReason::Authentication => "AUTHENTICATION",
        StopReason::Storage => "STORAGE",
        StopReason::Integrity => "INTEGRITY",
        StopReason::Network => "NETWORK",
        StopReason::Policy => "POLICY",
        StopReason::Unknown => "UNKNOWN",
        StopReason::Destination => "DESTINATION",
        StopReason::Unreadable => "UNREADABLE",
        StopReason::Unconfirmed => "UNCONFIRMED",
    }
}

fn binding_code(error: &BindingError) -> &'static str {
    match error {
        BindingError::AlreadyBound => "SOURCE-ALREADY-BOUND",
        BindingError::InvalidUrl => "SOURCE-INVALID-URL",
        BindingError::InsecureHttp => "SOURCE-INSECURE-HTTP",
        BindingError::InvalidCredential => "SOURCE-INVALID-CREDENTIAL",
        BindingError::TooManyOrigins => "SOURCE-TOO-MANY-ORIGINS",
    }
}

fn run_code(error: &RunError) -> &'static str {
    match error {
        RunError::InvalidConfig => "RUN-INVALID-CONFIG",
        RunError::NotRunnable(_) => "RUN-NOT-RUNNABLE",
        RunError::Domain(_) => "RUN-DOMAIN",
        RunError::Commit(_) => "RUN-COMMIT",
        RunError::Repository => "RUN-REPOSITORY",
        RunError::Writer(_) => "RUN-WRITER",
        RunError::Storage(_) => "RUN-STORAGE",
        RunError::Invariant => "RUN-INVARIANT",
    }
}

/// Closed names for a job's state, so a wire value never comes from printing a
/// domain type that may one day carry a payload.
pub fn job_state(state: fhd_domain::JobState) -> &'static str {
    use fhd_domain::JobState as S;
    match state {
        S::Queued => "Queued",
        S::Probing => "Probing",
        S::Transferring => "Transferring",
        S::Stopping => "Stopping",
        S::Paused => "Paused",
        S::RetryWait => "RetryWait",
        S::NeedsAction => "NeedsAction",
        S::Verifying => "Verifying",
        S::Publishing => "Publishing",
        S::Cancelling => "Cancelling",
        S::Failed => "Failed",
        S::Completed => "Completed",
        S::Cancelled => "Cancelled",
    }
}

/// Names the system reads as an instruction rather than as a file, names that
/// read as something they are not, and names the filesystem will quietly turn
/// into one of those (§16.4). Refused at admission, so such a request never
/// costs a download first.
pub fn publishable_name(leaf: &str) -> bool {
    /// Extensions whose file is an instruction to the system, wherever they
    /// appear in the name: `Invoice.pdf.lnk` is a shortcut, not a document.
    const REFUSED: [&str; 14] = [
        "lnk",
        "url",
        "scf",
        "library-ms",
        "search-ms",
        "searchconnector-ms",
        "appref-ms",
        "theme",
        "themepack",
        "desktop",
        "inf",
        "hta",
        "msc",
        "reg",
    ];
    /// Reserved by the operating system: opening one of these names talks to a
    /// device, whatever extension follows.
    const DEVICES: [&str; 22] = [
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    if leaf.is_empty() || leaf.len() > 255 || leaf == "." || leaf == ".." {
        return false;
    }
    // Windows drops a trailing dot or space, so `x.lnk.` becomes `x.lnk` on
    // disk. Checking the name as written would be checking the wrong name.
    if leaf.ends_with('.') || leaf.ends_with(' ') || leaf.starts_with(' ') {
        return false;
    }
    // A name carrying a stream separator names a stream inside another file.
    if leaf.contains(':') || leaf.contains('/') || leaf.contains('\\') {
        return false;
    }
    let lower = leaf.to_ascii_lowercase();
    if matches!(lower.as_str(), "autorun.inf" | "desktop.ini" | ".htaccess") {
        return false;
    }
    let mut parts = lower.split('.');
    let stem = parts.next().unwrap_or_default();
    if DEVICES.contains(&stem) {
        return false;
    }
    // Every extension, not only the last: the last one is what the shell reads,
    // and a trailing dot or a second extension is how that gets hidden.
    for part in parts {
        if REFUSED.contains(&part) {
            return false;
        }
    }
    // Direction overrides and isolates make a name read as something it is not.
    !leaf.chars().any(|c| {
        c.is_control()
            || ('\u{202a}'..='\u{202e}').contains(&c)
            || ('\u{2066}'..='\u{2069}').contains(&c)
            || c == '\u{200e}'
            || c == '\u{200f}'
    })
}

/// Only controlled categories reach the operator: never a URL or server text.
pub fn code(error: &EngineError) -> String {
    match error {
        EngineError::InvalidInput => "ENGINE-INVALID-INPUT".into(),
        EngineError::EndpointUnavailable => "IPC-ENDPOINT-UNAVAILABLE".into(),
        EngineError::StateBusy => "STATE-DIRECTORY-BUSY".into(),
        EngineError::DestinationRefused => "DESTINATION-REFUSED".into(),
        EngineError::NothingToContinue => "NOTHING-TO-CONTINUE".into(),
        EngineError::NeedsDecision(reason) => match reason {
            // A resume is refused for this one, by design: the part may already
            // be the user's file. Telling the operator to rerun with `--resume`
            // -- which is what every other stop says, and what this used to say
            // -- advises the one action that cannot be taken, and they would get
            // this same code back for their trouble. What it needs instead is
            // the question only a person can answer: is the file there?
            Some(StopReason::Unconfirmed) => "STOPPED-UNCONFIRMED-CHECK-DESTINATION".into(),
            Some(reason) => format!("STOPPED-{}-RERUN-WITH-RESUME", stop_reason(reason)),
            None => "STOPPED-RERUN-WITH-RESUME".into(),
        },
        EngineError::ExposedStateDirectory(_) => "STATE-DIRECTORY-EXPOSED".into(),
        EngineError::SwappableStatePath(_) => "STATE-PATH-SWAPPABLE".into(),
        EngineError::Persistence(error) => error.code().into(),
        EngineError::Binding(error) => binding_code(error).into(),
        EngineError::Admission(error) => error.code().into(),
        EngineError::Run(error) => run_code(error).into(),
    }
}

#[cfg(test)]
mod names {
    /// Each of these is a way a name gets past a check that reads it literally.
    #[test]
    fn a_name_the_system_would_act_on_is_refused_however_it_is_spelled() {
        for refused in [
            "payload.lnk",
            // Windows drops the trailing dot: this lands as payload.lnk.
            "payload.lnk.",
            "payload.lnk ",
            "Invoice.pdf.lnk",
            "INVOICE.PDF.LNK",
            "autorun.inf",
            "desktop.ini",
            "setup.hta",
            "policy.msc",
            "keys.reg",
            "pack.themepack",
            "find.searchConnector-ms",
            // Device names, with or without an extension.
            "NUL",
            "con.txt",
            "COM1",
            // A stream inside another file, and separators that are not ours.
            "safe.txt:hidden.exe",
            "a/b.bin",
            "a\\b.bin",
            // Made to read backwards.
            "photo\u{202e}gnp.exe",
            "photo\u{2069}gnp.exe",
            "",
            ".",
            "..",
        ] {
            assert!(
                !super::publishable_name(refused),
                "accepted {refused:?}, which the system would act on"
            );
        }
    }

    #[test]
    fn ordinary_names_are_still_accepted() {
        for accepted in [
            "film.mkv",
            "archive.tar.gz",
            "installer.exe",
            "notes.txt",
            "تقرير.pdf",
            "data.2026-09-23.csv",
        ] {
            assert!(super::publishable_name(accepted), "refused {accepted:?}");
        }
    }
}

/// What the operator is told when a job stops, which is the whole of what they
/// have to act on.
#[cfg(test)]
mod told {
    use super::{code, EngineError};
    use fhd_domain::StopReason;

    /// The one reason that must not advise a resume, and every other one that
    /// must still advise it.
    ///
    /// A review found this saying `STOPPED-UNCONFIRMED-RERUN-WITH-RESUME`: for
    /// the single state where resuming is refused by design, the engine was
    /// telling the operator to resume. Following that advice returns this same
    /// code, so the only thing it could produce is a loop.
    #[test]
    fn the_one_reason_that_cannot_be_resumed_does_not_advise_resuming() {
        let unconfirmed = code(&EngineError::NeedsDecision(Some(StopReason::Unconfirmed)));
        assert_eq!(unconfirmed, "STOPPED-UNCONFIRMED-CHECK-DESTINATION");
        assert!(
            !unconfirmed.contains("RESUME"),
            "the engine advised the one action it refuses: {unconfirmed}"
        );

        for reason in [
            StopReason::Network,
            StopReason::Storage,
            StopReason::Authentication,
            StopReason::Destination,
            StopReason::Policy,
            StopReason::Unknown,
            StopReason::SourceChanged,
            StopReason::Integrity,
            StopReason::Unreadable,
        ] {
            let told = code(&EngineError::NeedsDecision(Some(reason)));
            assert!(
                told.ends_with("-RERUN-WITH-RESUME"),
                "{reason:?} stopped telling the operator what to do: {told}"
            );
            assert!(told.contains(super::stop_reason(&reason)), "{reason:?}");
        }
        assert_eq!(
            code(&EngineError::NeedsDecision(None)),
            "STOPPED-RERUN-WITH-RESUME"
        );
    }

    /// Every reason this engine can report is one the protocol declares, and
    /// every reason the protocol declares is one this engine can report.
    ///
    /// Warnings crossing the socket were enumerated in `fhd_protocol`; reasons
    /// were not, so a reason was a free string on a versioned answer and a
    /// decoder had nothing to check it against. A review named that as the gap.
    /// The two lists live in different crates -- the protocol cannot see
    /// `StopReason`, and should not -- so this is what holds them together.
    #[test]
    fn every_reason_the_engine_reports_is_one_the_protocol_declares() {
        let reported: Vec<&str> = REASONS_HERE.iter().map(super::stop_reason).collect();
        for reason in &reported {
            assert!(
                fhd_protocol::REASONS.contains(reason),
                "the engine reports {reason}, which the protocol does not declare"
            );
        }
        for declared in fhd_protocol::REASONS {
            assert!(
                reported.contains(&declared),
                "the protocol declares {declared}, which no reason produces"
            );
        }
        assert_eq!(
            reported.len(),
            fhd_protocol::REASONS.len(),
            "one of the two lists has a duplicate"
        );
    }

    /// Every variant, listed once. Adding one to the domain without adding it
    /// here leaves the count wrong and the test above says so.
    const REASONS_HERE: [StopReason; 10] = [
        StopReason::SourceChanged,
        StopReason::Authentication,
        StopReason::Storage,
        StopReason::Integrity,
        StopReason::Network,
        StopReason::Policy,
        StopReason::Unknown,
        StopReason::Destination,
        StopReason::Unreadable,
        StopReason::Unconfirmed,
    ];
}
