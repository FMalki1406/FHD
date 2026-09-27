//! The delivery witness: what a part may be used for, and when it may be removed.
//!
//! **On SQLite and real part files, because that is what the claims are about.** The
//! in-memory repository and the in-memory segment store cannot carry any of these:
//! one of the four turns on a byte inside a `.meta` file on disk, and the other three
//! turn on what survives closing the database and opening it again. A review named
//! that limit for an earlier attempt measured against doubles, and it was right --
//! the doubles agreed with the code because they were written from it.
//!
//! **What the witness is.** A publication attempt has three possible ends and only
//! two of them are answers: the file was linked, the linking call refused and said
//! so, or nothing can say -- a crash between recording the attempt and recording its
//! outcome, or a refusal whose answer could not be saved. The record counts attempts
//! begun and attempts shown to have created no name, and `started > resolved` is
//! exactly "an attempt of the third kind exists". While that holds, the part may not
//! be written, may not be linked again, and may not be removed: it may be a second
//! name for a file the user already has.
//!
//! **Why publication needs a mechanism here.** Every test drives a real publication
//! attempt, so the file compiles where one exists.
#![cfg(any(windows, target_os = "linux"))]

mod harness;

use fhd_app::{
    storage::{HandleLinker, StorageError},
    AddDownload, AppError, Authorizer, CommitError, Destinations, DurableExtent, EntitlementGate,
    PortFuture, Principal, PublishIntent, ReceiptKey, ReferenceStore, SourceReference,
    TransferRepository,
};
use fhd_domain::{
    DestinationRef, Generation, Job, JobCommand, JobEvent, JobId, JobSpec, JobState, Priority,
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
use rusqlite::OptionalExtension;
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::sync::mpsc;

/// The platform's real mechanism, with a switch that makes the linking call refuse.
///
/// **Why a refusal has to come from here.** A publication attempt is only *begun*
/// once the destination has been found free -- the coordinator reconciles against
/// whatever is at the path first, and anything there stops the job before an attempt
/// is recorded. So a file or a directory in the way cannot produce the case these
/// tests are about: an attempt that was begun and then definitively refused. The
/// linking call refusing is that case, and it is also where the answer "no name was
/// created" is allowed to come from at all.
///
/// **And the switch is what makes the guards testable.** With it off the mechanism
/// links for real, so a run that reaches the link publishes a file -- which is how
/// "publication did not link again" becomes an assertion with something behind it
/// rather than a linker that was never going to succeed.
///
/// The three forwards are the ones `publication.rs` makes, for the reason given
/// there: the composition root's own binding is private to the crate, and a double
/// that linked by name would publish differently from production.
struct Linker {
    refuse: Arc<AtomicBool>,
}
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
    ) -> Result<(), StorageError> {
        if self.refuse.load(Ordering::SeqCst) {
            // The one answer that establishes no directory entry was created: the
            // call that would have created it, refusing.
            return Err(StorageError::Conflict);
        }
        fhd_platform::link_into_directory(file, folder, name).map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => StorageError::Conflict,
            other => StorageError::Io(other),
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

/// Wall-clock time, which is what the retry waits are measured against.
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

/// One destination, with its parts in a directory the test can name.
///
/// The engine hashes the state directory into that name so two engines cannot
/// collide; a test wants a path it can read a `.meta` file out of, and there is only
/// one engine here. What matters for these tests is what the production layout also
/// guarantees: the part sits beside the destination, on the same volume, so a
/// publication never crosses one.
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

/// The real repository, with one of the witness's two operations made to fail.
///
/// **Everything else goes to SQLite**, so the durable state under test is the real
/// one. What is simulated is a repository that will not do one thing, and the two
/// things worth simulating are different failures with the same required outcome:
///
/// - it will not accept the write that clears a doubt. The answer existed and was
///   never saved, and nothing may act on an answer only this process ever knew.
/// - it will not answer the question at all. Not being able to ask whether a file
///   may already be the user's is not permission to remove the evidence that it
///   might be.
///
/// Neither is reachable by driving the real repository: a full disk and a locked
/// database are real, and they do not happen on request.
struct Interfering {
    inner: Arc<SqliteRepository>,
    /// How many saves of a refusal's answer to fail. `0` fails none; `usize::MAX`
    /// fails every one. A count rather than a flag because the coordinator retries
    /// this write: a fault that clears itself measures the retry, and one that never
    /// clears measures what happens when the answer is never saved at all. They are
    /// different claims and both are required.
    refuse_to_save: AtomicUsize,
    /// Reads counted, so a test can fail the *n*th one. The witness is read at more
    /// than one point in a session, and which one fails changes what has to happen:
    /// failing the read before the part is opened has to stop the job, and so does
    /// failing the one before the link, and they are different lines.
    reads: AtomicUsize,
    /// The read index from which reads fail. `usize::MAX` never fails.
    refuse_from: AtomicUsize,
}
impl Interfering {
    fn new(inner: Arc<SqliteRepository>, refuse_to_save: usize) -> Self {
        Self {
            inner,
            refuse_to_save: AtomicUsize::new(refuse_to_save),
            reads: AtomicUsize::new(0),
            refuse_from: AtomicUsize::new(usize::MAX),
        }
    }
    /// Every read from now on fails.
    fn stop_answering(&self) {
        self.refuse_from.store(0, Ordering::SeqCst);
    }
    /// The next `allowed` reads succeed and every read after them fails.
    fn stop_answering_after(&self, allowed: usize) {
        self.refuse_from.store(
            self.reads.load(Ordering::SeqCst) + allowed,
            Ordering::SeqCst,
        );
    }
}
impl TransferRepository for Interfering {
    fn commit_transition(&self, event: JobEvent) -> PortFuture<'_, Result<(), CommitError>> {
        self.inner.commit_transition(event)
    }
    fn commit_extents(
        &self,
        job: JobId,
        generation: Generation,
        extents: Vec<DurableExtent>,
    ) -> PortFuture<'_, Result<(), CommitError>> {
        self.inner.commit_extents(job, generation, extents)
    }
    fn load_jobs(&self) -> PortFuture<'_, Result<Vec<Job>, AppError>> {
        self.inner.load_jobs()
    }
    fn durable_extents(&self, job: JobId) -> PortFuture<'_, Result<Vec<DurableExtent>, AppError>> {
        self.inner.durable_extents(job)
    }
    fn record_publish_intent(
        &self,
        intent: PublishIntent,
    ) -> PortFuture<'_, Result<(), CommitError>> {
        self.inner.record_publish_intent(intent)
    }
    fn publish_intent(
        &self,
        job: JobId,
    ) -> PortFuture<'_, Result<Option<PublishIntent>, AppError>> {
        self.inner.publish_intent(job)
    }
    fn begin_publish_attempt(
        &self,
        job: JobId,
        generation: Generation,
    ) -> PortFuture<'_, Result<(), CommitError>> {
        self.inner.begin_publish_attempt(job, generation)
    }
    fn resolve_publish_attempt(
        &self,
        job: JobId,
        generation: Generation,
    ) -> PortFuture<'_, Result<bool, CommitError>> {
        if self
            .refuse_to_save
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            return Box::pin(async { Err(CommitError::Unavailable) });
        }
        self.inner.resolve_publish_attempt(job, generation)
    }
    fn unresolved_publish_attempt(
        &self,
        job: JobId,
        generation: Generation,
    ) -> PortFuture<'_, Result<bool, AppError>> {
        if self.reads.fetch_add(1, Ordering::SeqCst) >= self.refuse_from.load(Ordering::SeqCst) {
            return Box::pin(async { Err(AppError::PersistenceUnavailable) });
        }
        self.inner.unresolved_publish_attempt(job, generation)
    }
}

/// One job over the four real adapters, assembled here so a port can be wrapped.
///
/// **Not a second composition root.** The adapters are the production ones -- SQLite
/// on disk, the part store with the platform's linker, the HTTP transport -- and the
/// fully wired assembly is measured by `end_to_end.rs` and `publication.rs`. What
/// this adds is a handle on the repository, which `Engine` deliberately does not
/// offer: a test hook in the composition root would be a place a production build
/// could stop at.
struct Wired {
    coordinator: Arc<Coordinator>,
    repository: Arc<SqliteRepository>,
    job: JobId,
    destination: PathBuf,
    parts: PathBuf,
    /// The engine's own tree, which holds the database this test also reads.
    state: PathBuf,
    /// The repository the coordinator sees, so a test can arm a fault mid-run.
    interference: Arc<Interfering>,
    /// While set, the linking call refuses; clearing it lets a link succeed.
    refuse: Arc<AtomicBool>,
}

impl Wired {
    async fn open(state: &Directory, body: &[u8], repository: Repository) -> Self {
        let (port, _) = serve(body.to_vec(), 0);
        let url = format!("http://127.0.0.1:{port}/file");
        let engine = state.engine();
        let downloads = state.0.join("downloads");
        std::fs::create_dir_all(&engine).expect("the engine directory is usable");
        std::fs::create_dir_all(&downloads).expect("the downloads directory is usable");
        std::fs::create_dir_all(engine.join("parts")).expect("the parts claim is usable");
        let destination = downloads.join("file.bin");
        let parts = downloads.join(".fhd-parts-witness");
        std::fs::create_dir_all(&parts).expect("the part directory is usable");

        let refuse = Arc::new(AtomicBool::new(true));
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
                ReceiptKey::new(Principal::new(1).expect("a principal"), [7u8; 32]),
                spec,
            )
            .await
            .expect("the job is admitted");
        // What the source says it points at, so a later run of the same record can
        // continue it. Recorded through the same port the engine uses.
        ReferenceStore::record(
            sqlite.as_ref(),
            source,
            SourceReference::new(url.clone(), true).expect("a source reference"),
            reference,
            destination.clone(),
        )
        .await
        .expect("the reference is recorded");

        // Always through the decorator, faults or none: one path for every test, so a
        // test that arms nothing is running the same code as one that does.
        let interference = Arc::new(Interfering::new(
            sqlite.clone(),
            match repository {
                Repository::Real => 0,
                Repository::FailsToSaveTheAnswerOnce => 1,
                Repository::FailsToSaveTheAnswer => usize::MAX,
            },
        ));
        let ports = Ports {
            repository: interference.clone(),
            store: Arc::new(
                FileStorage::own(&engine.join("parts"))
                    .expect("the part store is claimed")
                    .with_linker(Arc::new(Linker {
                        refuse: refuse.clone(),
                    })),
            ),
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
                    min_segment: 1024 * 1024,
                    checkpoint_bytes: 8 * 1024 * 1024,
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
            state: engine,
            interference,
            refuse,
        }
    }

    /// Lets the linking call succeed from here on.
    fn allow_linking(&self) {
        self.refuse.store(false, Ordering::SeqCst);
    }

    /// Takes a job resting on a reason that does not block a resume back to the
    /// queue, so it can be run again.
    async fn resume(&self) {
        self.coordinator
            .command_resting(self.job, JobCommand::Resume)
            .await
            .expect("the resume is accepted");
    }

    /// The witness's two counters, for saying which answer the record is giving.
    async fn begin_attempt(&self) {
        let generation = self.reload().await.generation();
        self.repository
            .begin_publish_attempt(self.job, generation)
            .await
            .expect("the attempt is recorded");
    }

    /// Which attempt the record says was last intended to publish.
    ///
    /// **This is what tells the two refusals apart.** The witness is consulted when
    /// the session opens its part and again before the link, and either refusal on
    /// its own stops the job with the same reason -- so a test that only looks at the
    /// reason cannot say which one acted. A job stopped at the first never reaches
    /// verification, so it never records another intent; one stopped at the second
    /// has already been taken through verification and into `Publishing`. The attempt
    /// number says which happened.
    async fn intended_attempt(&self) -> Option<u32> {
        self.repository
            .publish_intent(self.job)
            .await
            .expect("the record is readable")
            .map(|intent| intent.attempt())
    }

    /// The two counters, read out of the database rather than through the port.
    ///
    /// The port answers one question -- is an attempt unanswered -- because that is
    /// the only question the engine has any business asking. A test needs more than
    /// the answer: it needs to know the record was in the state the answer is
    /// supposed to come from, or an assertion about "the doubt stands" passes just as
    /// well when no attempt was ever recorded. So this reads the row.
    ///
    /// A second read-only connection, which WAL allows alongside the repository's own.
    async fn counters(&self) -> Option<(i64, i64)> {
        let path = self.state.join("state").join("admission.sqlite");
        let db =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("the database opens for reading");
        db.query_row(
            "SELECT started,resolved FROM publish_attempts WHERE job_id=?1",
            [i64::try_from(self.job.get()).expect("the job id fits")],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .expect("the witness is readable")
    }

    /// Records a definite refusal, and answers whether the record now accounts for
    /// every attempt begun.
    async fn resolve_attempt(&self) -> bool {
        let generation = self.reload().await.generation();
        self.repository
            .resolve_publish_attempt(self.job, generation)
            .await
            .expect("the answer is accepted")
    }

    /// Runs the job from whatever the record says it is, with no control channel.
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

    async fn state(&self) -> JobState {
        self.reload().await.state()
    }

    async fn reason(&self) -> Option<StopReason> {
        self.reload().await.reason()
    }

    async fn unresolved(&self) -> bool {
        self.repository
            .unresolved_publish_attempt(self.job, self.reload().await.generation())
            .await
            .expect("the witness is readable")
    }

    /// Cancels a resting job through the path a client's cancel takes, and drives the
    /// cleanup to its end.
    async fn cancel(&self) {
        self.coordinator
            .command_resting(self.job, JobCommand::Cancel)
            .await
            .expect("the cancel is accepted");
        // A cancel of a resting job settles through `confirm_command`, which is what
        // the scheduler calls and what actually reaches the cleanup.
        self.coordinator
            .confirm_command(self.job, JobCommand::Cancel)
            .await
            .expect("the cancel is confirmed");
    }

    fn part(&self) -> PathBuf {
        self.parts.join(format!("{}-1.part", self.job.get()))
    }
    fn meta(&self) -> PathBuf {
        self.parts.join(format!("{}-1.meta", self.job.get()))
    }

    /// The publication byte of the part's record, which is the witness this design
    /// deliberately does not rely on alone.
    fn publication_byte(&self) -> u8 {
        *std::fs::read(self.meta())
            .expect("the part record is readable")
            .get(33)
            .expect("the part record has a publication byte")
    }

    fn set_publication_byte(&self, value: u8) {
        let mut data = std::fs::read(self.meta()).expect("the part record is readable");
        data[33] = value;
        std::fs::write(self.meta(), data).expect("the part record is writable");
    }
}

enum Repository {
    Real,
    /// The save fails once and then works, which is what a busy database looks like.
    FailsToSaveTheAnswerOnce,
    /// The save never works.
    FailsToSaveTheAnswer,
}

/// A publication refused where no name could have been made lets the part go.
///
/// The linking call refused and said so, the answer was saved, and the record then
/// accounts for every attempt begun. A cancelled job keeps nothing it downloaded, and
/// with no doubt outstanding that applies here.
///
/// **This is the test that stops the guard from being a leak.** A witness that kept
/// the part whenever *any* attempt had been made would strand one after every
/// ordinary refusal, which is what two earlier designs did:
/// `a_stopped_job_can_be_cancelled_and_an_unknown_one_is_refused` measures the same
/// thing over the in-memory doubles, and this measures it where the files are real.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_that_proves_no_name_was_made_lets_the_part_go() {
    let state = Directory::new("witness-clean");
    let body = content(512 * 1024 + 3);
    let wired = Wired::open(&state, &body, Repository::Real).await;

    let outcome = wired.run().await;
    assert_eq!(
        wired.state().await,
        JobState::NeedsAction,
        "the refused link did not stop the job: {outcome:?}"
    );
    assert!(
        !wired.destination.exists(),
        "the refused link created the file anyway"
    );
    // The premise: an attempt really was begun and really was answered. Without the
    // first the cleanup below would be permitted by there being nothing to doubt.
    assert_eq!(
        wired.counters().await,
        Some((1, 1)),
        "the attempt was not recorded, or its answer was not"
    );
    assert!(
        !wired.unresolved().await,
        "a refusal that reached a definite answer left a doubt standing"
    );
    assert!(wired.part().exists(), "the bytes were dropped on a refusal");

    wired.cancel().await;
    assert_eq!(wired.state().await, JobState::Cancelled);
    assert!(
        !wired.part().exists() && !wired.meta().exists(),
        "a cancelled job with no unanswered attempt left its part behind"
    );
}

/// An attempt that was never answered keeps the part, and a later refusal does not
/// speak for it.
///
/// The record is put where a crash between the two writes leaves it: an attempt
/// begun, and nothing saying how it ended. Two things then have to hold.
///
/// **The engine must not act.** It must not write to the part, because the part may
/// be a second name for a file the user already has and writing to it would change
/// that file; it must not link again, because that would leave a second copy
/// somewhere; and it must not remove the part, because that destroys the only local
/// evidence that publication may have happened. The linking call is allowed to
/// succeed for this run, so a missing guard would publish a file and the assertion
/// would see it.
///
/// **And the record must not be talked over.** Answering the *later* attempt does not
/// account for the earlier one: the answer advances the count only when every attempt
/// before it is already answered, so the doubt survives. That rule is asserted here
/// directly, against SQLite, because the engine now refuses to begin a second attempt
/// at all -- which is the stronger behaviour, and which would otherwise leave the
/// durable rule underneath it unmeasured.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unanswered_attempt_keeps_the_part_and_is_not_answered_by_a_later_refusal() {
    let state = Directory::new("witness-unknown");
    let body = content(512 * 1024 + 3);
    let wired = Wired::open(&state, &body, Repository::Real).await;

    // A first run that downloads everything and is refused, so a complete part is on
    // disk with a record that matches it.
    let _ = wired.run().await;
    assert_eq!(wired.state().await, JobState::NeedsAction);
    assert_eq!(wired.counters().await, Some((1, 1)));

    // Now the state a crash leaves: attempt 2 begun, and nothing saying how it ended.
    // Written through the port the engine writes it through, because what a crash
    // leaves is a committed row rather than a half-finished call.
    wired.begin_attempt().await;
    assert_eq!(wired.counters().await, Some((2, 1)));
    assert!(
        wired.unresolved().await,
        "an attempt with no saved outcome was not counted as unanswered"
    );

    // And a third attempt, which is definitively refused. **This is the case the
    // whole design turns on**: the refusal is about attempt 3 and says nothing about
    // attempt 2, so it must not account for it. The count advances only when every
    // attempt before the one being answered is already answered.
    //
    // An earlier version of this test answered the *latest* attempt and expected the
    // doubt to survive, which was wrong -- answering the latest attempt when it is
    // the only unanswered one is exactly what clears a doubt, and the assertion
    // caught the mistake in the test rather than in the code.
    wired.begin_attempt().await;
    assert_eq!(wired.counters().await, Some((3, 1)));
    assert!(
        !wired.resolve_attempt().await,
        "the record claimed to account for an attempt it says nothing about"
    );
    assert_eq!(
        wired.counters().await,
        Some((3, 1)),
        "answering the later attempt accounted for the earlier one as well"
    );
    assert!(
        wired.unresolved().await,
        "a later attempt's refusal cleared a doubt it says nothing about"
    );

    // From here a link would succeed, so what stops one is the witness and nothing
    // else.
    wired.allow_linking();
    let before = std::fs::read(wired.part()).expect("the part is readable");
    wired.resume().await;
    let outcome = wired.run().await;

    assert_eq!(
        wired.reason().await,
        Some(StopReason::Unconfirmed),
        "an unanswered attempt did not stop the job as unconfirmed: {outcome:?}"
    );
    assert!(
        !wired.destination.exists(),
        "publication linked again although an earlier attempt may have delivered the file"
    );
    assert_eq!(
        std::fs::read(wired.part()).expect("the part is readable"),
        before,
        "the part was written to although it may be a name for the user's file"
    );

    wired.cancel().await;
    assert_eq!(wired.state().await, JobState::Cancelled);
    assert!(
        wired.part().exists() && wired.meta().exists(),
        "a cancel removed the only local evidence that publication may have happened"
    );
}

/// An answer that could not be saved is not an answer.
///
/// The linking call refused and said so, and the write that would have recorded it
/// failed. Nothing may act on an answer only this process ever knew -- and this
/// process is about to stop -- so the record goes on saying an attempt is unanswered,
/// and the part stays.
///
/// **The refusal itself is real**, on real files and against SQLite: only the one
/// write is made to fail. That is the difference between this and the case above,
/// where the answer was saved and simply could not account for an older attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_that_could_not_be_saved_leaves_the_doubt_standing() {
    let state = Directory::new("witness-unsaved");
    let body = content(512 * 1024 + 3);
    let wired = Wired::open(&state, &body, Repository::FailsToSaveTheAnswer).await;

    let outcome = wired.run().await;
    assert_eq!(
        wired.state().await,
        JobState::NeedsAction,
        "the refused link did not stop the job: {outcome:?}"
    );
    assert_eq!(
        wired.counters().await,
        Some((1, 0)),
        "the answer was saved after all, so this measures nothing"
    );
    assert!(
        wired.unresolved().await,
        "the refusal's answer was never saved, and the record claims it was"
    );
    // **And the job rests on the reason the record justifies, not on the one this
    // refusal suggests.** The linker refused because the name was taken, which reads
    // as `Destination` -- an operator moves the file, resumes, and meets a job that
    // still refuses to move, because the record holds a doubt. Reporting the doubt is
    // what makes the state and the reason agree.
    assert_eq!(
        wired.reason().await,
        Some(StopReason::Unconfirmed),
        "a job whose record holds an unanswered attempt was reported as something an \
         operator can fix at the destination"
    );

    wired.cancel().await;
    assert_eq!(wired.state().await, JobState::Cancelled);
    assert!(
        wired.part().exists() && wired.meta().exists(),
        "a cancel removed a part whose attempt has no saved answer"
    );
}

/// A part record that says an attempt was begun is refused on that record alone.
///
/// **This is the other half of the corrupted-byte claim.** The test above shows that
/// a record reading `Open` is refused by the witness; without this one, nothing said
/// that a record reading `Attempted` is refused at all -- so "a flip from 3 to 0
/// hands over permission" would have been an assertion about the code rather than a
/// measurement. Here the witness is deliberately *clear*, and the byte is the only
/// thing that refuses.
///
/// The byte is written directly, the way `crashed_at` writes it in the storage
/// adapter's own tests: what a restart sees is the bytes, and these are the bytes.
/// Interrupting a real attempt would need a hook in the code under test, and a hook
/// is a place a production build can stop at.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_part_that_says_an_attempt_was_begun_is_refused_on_its_own_record() {
    let state = Directory::new("witness-byte");
    let body = content(512 * 1024 + 3);
    let wired = Wired::open(&state, &body, Repository::Real).await;

    let _ = wired.run().await;
    assert_eq!(wired.state().await, JobState::NeedsAction);
    // The witness says there is nothing outstanding, and stays saying it.
    assert_eq!(wired.counters().await, Some((1, 1)));
    assert!(!wired.unresolved().await);

    // The record a crash between the two writes leaves.
    wired.set_publication_byte(3);
    wired.allow_linking();
    let before = std::fs::read(wired.part()).expect("the part is readable");

    wired.resume().await;
    let outcome = wired.run().await;
    assert_eq!(
        wired.reason().await,
        Some(StopReason::Unconfirmed),
        "a part whose record says an attempt was begun was run on anyway: {outcome:?}"
    );
    assert!(
        !wired.destination.exists(),
        "publication linked again over a record that says an attempt was begun"
    );
    assert_eq!(
        std::fs::read(wired.part()).expect("the part is readable"),
        before,
        "the part was written to although its own record says an attempt was begun"
    );
    assert_eq!(
        wired.publication_byte(),
        3,
        "opening the part rewrote the record that was refusing"
    );

    wired.cancel().await;
    assert_eq!(wired.state().await, JobState::Cancelled);
    assert!(
        wired.part().exists() && wired.meta().exists(),
        "a cancel removed a part whose own record says an attempt was begun"
    );
}

/// A witness that cannot be read stops the job; it does not fail the session.
///
/// **The difference is whether an operator has anything left to do.** A session that
/// returns an error leaves the job durably `Transferring`, `Verifying` or
/// `Publishing` with no session behind it -- and the domain refuses `Pause` and
/// `Cancel` while a publication is in progress, so nothing can move it until the
/// daemon restarts. A busy database on one job start would have been enough. An
/// engineering review traced it through the scheduler's failure arm, and this is the
/// assertion that the conservative answer is the one taken.
///
/// Both reads in a session are covered, because they are two lines and a fix for one
/// is not a fix for the other: the one before the part is opened, and the one before
/// the link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_witness_that_cannot_be_read_stops_the_job_rather_than_the_session() {
    for allowed in [0, 1] {
        let state = Directory::new(&format!("witness-unaskable-{allowed}"));
        let body = content(512 * 1024 + 3);
        let wired = Wired::open(&state, &body, Repository::Real).await;
        wired.interference.stop_answering_after(allowed);

        let outcome = wired.run().await;
        assert!(
            outcome.is_ok(),
            "read {allowed}: the session failed instead of stopping the job, which \
             leaves it running with nothing behind it: {outcome:?}"
        );
        assert_eq!(
            wired.state().await,
            JobState::NeedsAction,
            "read {allowed}: the job was left in a running state"
        );
        assert_eq!(
            wired.reason().await,
            Some(StopReason::Unconfirmed),
            "read {allowed}: a question that went unanswered was reported as something \
             an operator can retry"
        );
    }
}

/// A witness that cannot be read is not a `false`.
///
/// The record here says every attempt is accounted for, so the part may go -- and the
/// previous tests show that it does. Then the repository stops answering. The
/// difference between this and them is one question that gets no reply, and the part
/// must stay: not being able to ask whether a file may already be the user's is not
/// permission to remove the evidence that it might be.
///
/// **It is the failure direction that matters.** A guard that reads the witness and
/// treats "could not ask" as "nothing to doubt" looks correct in every test where the
/// database works, which is all of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_witness_that_cannot_be_read_keeps_the_part() {
    let state = Directory::new("witness-unreadable");
    let body = content(512 * 1024 + 3);
    let wired = Wired::open(&state, &body, Repository::Real).await;

    let outcome = wired.run().await;
    assert_eq!(
        wired.state().await,
        JobState::NeedsAction,
        "the refused link did not stop the job: {outcome:?}"
    );
    // The premise: with the record readable, this part would be removed.
    assert_eq!(
        wired.counters().await,
        Some((1, 1)),
        "the attempt was not recorded and answered, so nothing here is being kept back"
    );

    wired.interference.stop_answering();
    wired.cancel().await;
    assert_eq!(
        wired.state().await,
        JobState::Cancelled,
        "an unreadable witness stopped the job from being cancelled, which it must not"
    );
    assert!(
        wired.part().exists() && wired.meta().exists(),
        "a part was removed although nothing could say whether it may be the user's file"
    );
}

/// A save that fails once is retried, and the doubt does not survive it.
///
/// **Without the retry a transient error is a permanent one.** One busy database on
/// the write that records an ordinary refusal would leave the doubt standing for
/// ever: the part is kept for ever, and both ways out are closed -- reconciliation
/// cannot succeed because nothing was linked, and a replacement is refused while a
/// doubt stands. An engineering review traced that, and pointed at the extent commit
/// on the same path, which has retried an unavailable repository for as long as it
/// has existed.
///
/// The companion test above is the case where the save never works, and the doubt
/// then stands by design. This is the case where it works on the second try, and the
/// job must end up exactly where it would have without the failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_save_that_fails_once_is_retried_and_settles_the_attempt() {
    let state = Directory::new("witness-retried");
    let body = content(512 * 1024 + 3);
    let wired = Wired::open(&state, &body, Repository::FailsToSaveTheAnswerOnce).await;

    let outcome = wired.run().await;
    assert_eq!(
        wired.state().await,
        JobState::NeedsAction,
        "the refused link did not stop the job: {outcome:?}"
    );
    assert_eq!(
        wired.counters().await,
        Some((1, 1)),
        "the retry did not save the answer, so one busy database is permanent"
    );
    assert!(!wired.unresolved().await);
    assert_eq!(
        wired.reason().await,
        Some(StopReason::Destination),
        "the record accounts for every attempt, so the reason should be the one the \
         refusal actually carried"
    );

    wired.cancel().await;
    assert_eq!(wired.state().await, JobState::Cancelled);
    assert!(
        !wired.part().exists() && !wired.meta().exists(),
        "a transient failure to save an answer kept the part anyway"
    );
}

/// A part whose own record says nothing was begun is still refused by the witness.
///
/// **This is the corrupted byte, and the pair below it is what makes that claim
/// mean something.** `Sealed | Attempted` is 3; flipping it to 0 gives `Open`, a
/// value every build accepts, and the part then reads as one nothing was ever tried
/// on. The companion test shows that a record reading 3 is refused on that record
/// alone -- so the flip really does hand over permission, and what is left standing
/// here is the witness and nothing else.
///
/// **The premise is the byte, read before anything touches it.** An earlier version
/// of this test wrote 3, asserted it had written 3, and wrote 0 back: a no-op on
/// disk, and an assertion about its own write that could not fail. An engineering
/// review found that, and found that the suite therefore never held a part whose
/// record said `Attempted` while the witness decided -- which is what the companion
/// test is for.
///
/// Writing, linking again and removing are all asserted, because they are three
/// refusals in three different places and a fix for one is not a fix for the others.
/// The linking call is allowed to succeed, so the middle one is a real opportunity to
/// publish.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_part_that_says_nothing_was_begun_is_still_refused_by_the_witness() {
    let state = Directory::new("witness-corrupt");
    let body = content(512 * 1024 + 3);
    let wired = Wired::open(&state, &body, Repository::Real).await;

    let _ = wired.run().await;
    assert_eq!(wired.state().await, JobState::NeedsAction);
    wired.begin_attempt().await;

    // **The premise, read off the disk rather than written there.** The refused
    // publication left the part unsealed, so its record says `Open` -- the same value
    // a 3 corrupted to 0 reads as, and the value the companion test shows is the
    // difference between refusing and proceeding. Nothing below writes this byte: the
    // part's own record gives permission, and only the witness refuses.
    assert_eq!(
        wired.publication_byte(),
        0,
        "the part's own record already refuses, so the witness is not what is being \
         measured here"
    );
    wired.allow_linking();
    let before = std::fs::read(wired.part()).expect("the part is readable");

    wired.resume().await;
    let outcome = wired.run().await;
    assert_eq!(
        wired.reason().await,
        Some(StopReason::Unconfirmed),
        "a corrupted publication byte let the job run on: {outcome:?}"
    );
    // Writing -- and the session did not even get as far as being able to. A job
    // stopped where the part is opened records no further intent; one that reached
    // the guard before the link would have been verified and moved to `Publishing`
    // first, and its intent would say attempt two.
    assert_eq!(
        wired.intended_attempt().await,
        Some(1),
        "the session opened the part and ran on, and was stopped only at the link"
    );
    assert_eq!(
        std::fs::read(wired.part()).expect("the part is readable"),
        before,
        "the part was written to on the strength of a corrupted byte"
    );
    // Linking again.
    assert!(
        !wired.destination.exists(),
        "a second name was created on the strength of a corrupted byte"
    );
    // And removing.
    wired.cancel().await;
    assert_eq!(wired.state().await, JobState::Cancelled);
    assert!(
        wired.part().exists() && wired.meta().exists(),
        "a corrupted byte authorised removing the evidence of a possible delivery"
    );
}
