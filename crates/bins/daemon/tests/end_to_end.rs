//! The whole engine over real adapters: a local HTTP server, SQLite on disk and
//! real part files. No fakes anywhere in this path.
mod harness;

use fhd_app::{storage::Published, AppError};
use fhd_daemon::{Engine, EngineConfig, EngineError, Intent, JobOutcome, Request};
use fhd_domain::{JobState, StopReason};
use fhd_runtime::coordinator::{Control, SessionEnd};
use harness::{
    content, expected_digest, kept_beside_matches, part_bytes, serve, settled_without_publishing,
    Directory, PUBLISHES,
};
use std::{
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::Duration,
};
use tokio::sync::mpsc;

/// The declared outcome of a run that fetched and verified everything.
///
/// Returns the published path where publication is supported, and `None` where
/// it is not -- after asserting, in that case, the contract the engine actually
/// offers: no published file, no completed job, and the downloaded bytes still
/// on disk so the transfer can finish the day a mechanism exists.
///
/// This is not a way of switching tests off. Every test still runs on every
/// platform and still asserts something the engine must do; what changes is
/// which contract it is held to. A caller that gets `None` stops, because what
/// follows is about a file this platform does not create.
#[track_caller]
fn published_as_declared(
    outcome: Result<SessionEnd, fhd_daemon::EngineError>,
    reason: Option<StopReason>,
    destination: &Path,
    body: &[u8],
) -> Option<PathBuf> {
    if PUBLISHES {
        match outcome {
            Ok(SessionEnd::Published(Published::At(path))) => {
                assert_eq!(&path, destination, "published somewhere else");
                return Some(path);
            }
            other => panic!("expected a published file, got {other:?}"),
        }
    }
    // The exact settlement, not merely "not published". F2 in the re-review of
    // 11dd794: anything short of this would let a transport failure, a storage
    // failure, or a run that stopped early satisfy the same assertion, and the
    // test would report success for a download that never happened.
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::NeedsAction))),
        "a refused publication did not settle the way the engine declares: {outcome:?}"
    );
    assert_eq!(
        reason,
        Some(StopReason::Storage),
        "the job stopped for some reason other than publication being refused"
    );
    assert!(
        !destination.exists(),
        "a refused publication created the destination"
    );
    // The bytes, not the size. `create` sets the part's length before a single
    // byte arrives, so a positive file size proves only that a file was
    // allocated -- which is what the re-review objected to. Comparing contents
    // proves the transfer finished and that what stopped it was publication.
    assert!(
        kept_beside_matches(destination, body),
        "no part beside the destination holds the bytes that were downloaded"
    );
    None
}

/// Bytes still held in the parts directory beside a destination.
///
/// `part_bytes` reads the state directory, which is where parts stopped living
/// when they moved next to the file they become -- so on its own it answers
/// zero for a transfer whose work is perfectly intact.
fn kept_beside(destination: &Path) -> u64 {
    fn walk(path: &Path) -> u64 {
        let Ok(entries) = std::fs::read_dir(path) else {
            return 0;
        };
        entries
            .flatten()
            .map(|entry| match entry.metadata() {
                Ok(metadata) if metadata.is_dir() => walk(&entry.path()),
                // owner.lock and similar bookkeeping are not payload.
                Ok(metadata) if metadata.len() > 4096 => metadata.len(),
                _ => 0,
            })
            .sum()
    }
    match destination.parent() {
        Some(parent) => walk(&parent.join(".fhd-parts")),
        None => 0,
    }
}

fn config(state: &Directory, destination: PathBuf, connections: usize) -> EngineConfig {
    EngineConfig {
        state_directory: state.engine(),
        destination,
        connections,
        engine_connections: connections.max(2),
        max_active: 2,
        expected_sha256: None,
        max_bytes: 64 * 1024 * 1024,
        allow_http: true,
        download_root: None,
        intent: Intent::Start,
    }
}
fn resuming(state: &Directory, destination: PathBuf, connections: usize) -> EngineConfig {
    EngineConfig {
        intent: Intent::Resume,
        ..config(state, destination, connections)
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downloads_verifies_and_publishes_over_real_adapters() {
    let body = content(3 * 1024 * 1024 + 517);
    let (port, served) = serve(body.clone(), 0);
    let state = Directory::new("happy");
    let destination = state.0.join("result.bin");
    let url = format!("http://127.0.0.1:{port}/file");
    let mut settings = config(&state, destination.clone(), 4);
    settings.expected_sha256 = Some(expected_digest(&body));

    let engine = Engine::open(settings, &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = engine.run(receiver).await;
    let Some(_) =
        published_as_declared(outcome, engine.reason().await.unwrap(), &destination, &body)
    else {
        return;
    };
    assert_eq!(std::fs::read(&destination).unwrap(), body);
    assert_eq!(engine.state().await.unwrap(), JobState::Completed);
    // The part is released: its bytes live under the final name now.
    assert_eq!(part_bytes(&state), 0, "part file left behind");
    assert!(served.load(Ordering::Relaxed) > 1, "used several requests");

    // One owner at a time: release the state directory before reopening it.
    drop(engine);
    // The identical request replays to the same job; a different one would conflict.
    let mut same = config(&state, destination.clone(), 4);
    same.expected_sha256 = Some(expected_digest(&body));
    let (_control, receiver) = mpsc::channel(1);
    let engine = Engine::open(same, &url).await.unwrap();
    assert_eq!(
        engine.run(receiver).await.unwrap(),
        SessionEnd::Settled(JobState::Completed)
    );
    drop(engine);

    // The same URL and the same destination, asking for a digest the file does not
    // have, is a conflict -- not a second job.
    //
    // This used to open its own job, because the expected digest was folded into
    // the idempotency receipt. That made two jobs aim at one name, which
    // `open_many` then refuses outright, so a directory in that state could never
    // be continued again and every other job in it was lost with it. The digest is
    // out of the receipt key now: it changes neither what is fetched nor where it
    // lands, so a changed one meets `Receipt::replay` and is refused where the
    // operator can see it.
    let mut different = config(&state, destination.clone(), 4);
    different.expected_sha256 = Some([9; 32]);
    // Admission happens when the engine runs, not when it opens, so the conflict
    // surfaces there.
    let engine = Engine::open(different, &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = engine.run(receiver).await;
    assert!(
        matches!(
            outcome,
            Err(EngineError::Admission(AppError::IdempotencyConflict))
        ),
        "a changed digest on the same request must conflict, not fork the job: {outcome:?}"
    );
    drop(engine);
    // The file published by the first request is untouched.
    assert_eq!(std::fs::read(&destination).unwrap(), body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_connection_resumes_from_committed_bytes() {
    let body = content(6 * 1024 * 1024 + 41);
    // The first two range requests die half way through.
    let (port, _) = serve(body.clone(), 2);
    let state = Directory::new("resume");
    let destination = state.0.join("resumed.bin");
    let url = format!("http://127.0.0.1:{port}/file");

    // Each run settles once; a transient failure parks the job in RetryWait until
    // its deadline passes. Nothing here shortens that wait.
    let mut published = None;
    for _ in 0..12 {
        let engine = Engine::open(config(&state, destination.clone(), 2), &url)
            .await
            .unwrap();
        let (_control, receiver) = mpsc::channel(1);
        let outcome = engine.run(receiver).await;
        // Read before the engine is dropped: the stop reason is part of the
        // refusal contract, and after the drop there is nothing left to ask.
        let reason = engine.reason().await.unwrap();
        drop(engine);
        if !PUBLISHES {
            // Publication is unsupported here, so no run in this loop can
            // finish. The retries are still waited out -- that is what this test
            // is about -- and the run that gets past them is held to the refusal
            // contract: nothing published, no destination, and the bytes
            // committed before the server dropped the connection still on disk.
            if matches!(
                outcome,
                Ok(SessionEnd::Settled(JobState::RetryWait | JobState::Queued))
            ) {
                tokio::time::sleep(Duration::from_millis(400)).await;
                continue;
            }
            published_as_declared(outcome, reason, &destination, &body);
            return;
        }
        match outcome.unwrap() {
            SessionEnd::Published(path) => {
                published = Some(path);
                break;
            }
            SessionEnd::Settled(state) => {
                assert!(
                    matches!(state, JobState::RetryWait | JobState::Queued),
                    "unexpected rest state {state:?}"
                );
            }
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert_eq!(published, Some(Published::At(destination.clone())));
    assert_eq!(std::fs::read(&destination).unwrap(), body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_expected_digest_never_publishes() {
    let body = content(512 * 1024);
    let (port, _) = serve(body.clone(), 0);
    let state = Directory::new("digest");
    let destination = state.0.join("never.bin");
    let url = format!("http://127.0.0.1:{port}/file");
    let mut settings = config(&state, destination.clone(), 2);
    settings.expected_sha256 = Some([0x5A; 32]);

    let engine = Engine::open(settings, &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert_eq!(
        engine.run(receiver).await.unwrap(),
        SessionEnd::Settled(JobState::NeedsAction)
    );
    assert!(!destination.exists(), "nothing is published unverified");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_occupied_destination_is_never_overwritten() {
    let body = content(256 * 1024);
    let (port, _) = serve(body.clone(), 0);
    let state = Directory::new("occupied");
    let destination = state.0.join("taken.bin");
    std::fs::write(&destination, b"someone else's file").unwrap();
    let url = format!("http://127.0.0.1:{port}/file");

    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert_eq!(
        engine.run(receiver).await.unwrap(),
        SessionEnd::Settled(JobState::NeedsAction)
    );
    assert_eq!(std::fs::read(&destination).unwrap(), b"someone else's file");
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(StopReason::Destination)
    );
    drop(engine);

    // Running again changes nothing by itself.
    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert!(engine.run(receiver).await.is_err(), "no automatic resume");
    drop(engine);

    // Once the operator frees the name, a resume publishes without refetching.
    std::fs::remove_file(&destination).unwrap();
    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = engine.run(receiver).await;
    // Publication is unsupported here. What this test set out to prove is
    // already proved above -- the occupied name was left alone and a rerun did
    // not resume by itself -- and the resume that follows the operator freeing
    // the name is held to the refusal contract instead of to a published file.
    let Some(_) =
        published_as_declared(outcome, engine.reason().await.unwrap(), &destination, &body)
    else {
        return;
    };
    assert_eq!(std::fs::read(&destination).unwrap(), body);
}

/// Pausing stops the run, the job stays stopped, and a later run finishes it.
///
/// **What this does not claim, and why.** The review of 9f4127d objected that
/// `kept_beside > 0` proved nothing, because a part is created at its full
/// length before a byte arrives. Replacing it with the repository's own
/// `durable_bytes` found something better than a stronger assertion: measured
/// here, 491 KiB of a 1 MiB file had been delivered and the record still said
/// **zero**. An extent is committed when a segment completes, not as bytes
/// arrive, and `initial_split` cuts a transfer into at most one segment per
/// connection, all fetched at once. So the record goes from nothing to
/// everything, and a pause part-way through keeps nothing.
///
/// That is a property of the engine, not of this test, and it is worth writing
/// down: **this build does not preserve partial progress across a pause taken
/// mid-segment.** A test that manufactured a window to assert otherwise would
/// be describing an engine we do not have.
///
/// What is asserted instead is what the pause is actually for: the run stops,
/// it does not restart by itself, an explicit resume finishes it, and the
/// record is the same after the state directory is closed and reopened. The
/// claim that a resume reuses committed work belongs to
/// `a_dropped_connection_resumes_from_committed_bytes`, where a segment has
/// completed and there is something to reuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pause_stops_the_run_and_a_later_run_finishes_it() {
    // Delivered slowly so the pause lands mid-transfer rather than racing the
    // end of it, and counted so the resume can be compared against it.
    let body = content(2 * 1024 * 1024);
    let server = harness::serve_slowly(body.clone(), 16 * 1024, Duration::from_millis(2));
    let state = Directory::new("pause");
    let destination = state.0.join("paused.bin");
    let url = format!("http://127.0.0.1:{}/file", server.port);

    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (control, receiver) = mpsc::channel(1);
    let run = engine.run(receiver);
    let delivered = server.delivered.clone();
    let faults = server.broken.clone();
    let quarter = body.len() as u64 / 4;
    let pause = async {
        // Bounded. An unbounded wait here is how a test stops being a test:
        // both Unix runners sat in this suite until the job timed out, with
        // nothing to say for it, while Windows passed. Whatever the cause, a
        // wait that cannot end is the wrong instrument -- this one gives up
        // and says what it saw.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while delivered.load(Ordering::Relaxed) < quarter {
            assert!(
                std::time::Instant::now() < deadline,
                "only {} of {quarter} bytes arrived in 60s, so the pause never had                  a part-way transfer to land in; the server failed to finish {}                  responses",
                delivered.load(Ordering::Relaxed),
                faults.load(Ordering::Relaxed)
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // The run may already have settled, in which case the receiver is gone
        // and there is nothing to pause. That is a legitimate outcome and the
        // assertions below judge it; failing to send is not itself a failure.
        let _ = control.send(Control::Pause).await;
    };
    let (outcome, ()) = tokio::join!(run, pause);

    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::Paused))),
        "the run did not pause: {outcome:?}"
    );
    // Whatever the record holds, it is the record that decides -- and it has to
    // survive the state directory being closed and reopened, which is what
    // makes it durable rather than remembered.
    let kept = engine.durable_bytes().await.unwrap();
    assert!(kept <= body.len() as u64);
    drop(engine);

    let idle = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert!(idle.run(receiver).await.is_err(), "no automatic resume");
    assert_eq!(
        idle.durable_bytes().await.unwrap(),
        kept,
        "the committed progress did not survive reopening the state directory"
    );
    drop(idle);

    let resumed = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    // A bounded barrier before the measurement. `delivered` counts every byte
    // this server ever sent, and connections from before the pause are still
    // draining when the resume starts -- CI billed the resume 32769 bytes more
    // than the whole file, which is two chunks and a probe left over from the
    // first run. Waiting for the server to go quiet makes what follows belong
    // to this run; widening the allowance would only have hidden the overlap.
    server.quiet(Duration::from_secs(30)).await;
    let before = server.delivered.load(Ordering::Relaxed);
    let broken_before = server.broken.load(Ordering::Relaxed);
    let (_control, receiver) = mpsc::channel(1);
    let outcome = tokio::time::timeout(Duration::from_secs(120), resumed.run(receiver))
        .await
        .expect("the resumed run did not come back");
    let reason = resumed.reason().await.unwrap();

    // The run's own verdict first. Asserting on the byte count ahead of it hid
    // the answer: CI reported "the resume fetched 147461 bytes of 2097152" and
    // said nothing about why the run ended, when the run had in fact stopped
    // for a network fault. A count cannot explain a run that ended for another
    // reason, so the reason is established before the count is read.
    let landed = published_as_declared(outcome, reason, &destination, &body);

    // Then how much it had to fetch: what was missing, and no more than the
    // file. With nothing committed that is the whole of it, which is the honest
    // number here rather than a saving this engine does not make at this
    // granularity. The upper bound allows for the probe, a one-byte ranged
    // request the server counts like any other delivery.
    server.quiet(Duration::from_secs(30)).await;
    let refetched = server.delivered.load(Ordering::Relaxed) - before;
    // The resume's own broken responses, not the whole run's. Pausing abandons
    // connections on purpose, so the first run's count is expected to be
    // non-zero and says nothing about this one.
    let broken = server.broken.load(Ordering::Relaxed) - broken_before;
    assert!(
        refetched >= body.len() as u64 - kept && refetched <= body.len() as u64 + 1024,
        "the resume fetched {refetched} bytes with {kept} committed, out of {}; \
         the server failed to finish {broken} responses during the resume",
        body.len()
    );

    if landed.is_none() {
        return;
    }
    assert_eq!(std::fs::read(&destination).unwrap(), body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_destination_away_from_the_state_directory_downloads_and_publishes() {
    // Publication is a hard link, which cannot cross a volume, and every part
    // used to live under the engine's own directory -- so that directory decided
    // which disk the user could download to, and a destination anywhere else was
    // refused before a byte was fetched. The part goes beside its destination
    // now, so the link stays inside one directory and the question stops
    // arising.
    //
    // Two unrelated trees rather than two volumes, because a second volume is
    // not present on every machine this runs on. What this proves is the
    // mechanism: nothing under the state directory, the bytes written next to
    // the file they become. The claim about a genuinely different disk is
    // proved by `a_destination_on_a_second_volume_downloads_and_publishes`,
    // which needs one and says so.
    let body = content(2 * 1024 * 1024 + 11);
    let (port, served) = serve(body.clone(), 0);
    let state = Directory::new("elsewhere-state");
    let downloads = Directory::new("elsewhere-target");
    let destination = downloads.0.join("result.bin");
    let url = format!("http://127.0.0.1:{port}/file");
    let mut settings = config(&state, destination.clone(), 4);
    settings.expected_sha256 = Some(expected_digest(&body));

    let engine = Engine::open(settings, &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = engine.run(receiver).await;
    let published =
        published_as_declared(outcome, engine.reason().await.unwrap(), &destination, &body);
    if published.is_none() {
        // Publication is unsupported here: the run was held to the refusal
        // contract above, which includes the fetched bytes surviving in the
        // download folder. The state directory is still measured, because
        // keeping the part out of it is the claim this test exists for and it
        // holds whether or not the file can be published.
        assert_eq!(
            part_bytes(&state),
            0,
            "the part was written under the state directory after all"
        );
        assert!(served.load(Ordering::Relaxed) > 1, "used several requests");
        return;
    }
    assert_eq!(std::fs::read(&destination).unwrap(), body);
    assert_eq!(engine.state().await.unwrap(), JobState::Completed);
    assert!(served.load(Ordering::Relaxed) > 1, "used several requests");
    // And the part never went near the state directory, which is the whole
    // reason the volumes no longer have to match.
    assert_eq!(
        part_bytes(&state),
        0,
        "the part was written under the state directory after all"
    );
}

/// The claim itself, on a genuinely different disk.
///
/// Ignored by default because a second writable volume is not present on every
/// machine or every CI runner, and a test that quietly passes where it cannot
/// run is worse than one that is not run at all. This is recorded as coverage
/// that is not carried by the default suite -- see the support matrix in
/// `docs/feature-download-to-a-different-disk.md`.
///
/// Give it a directory on another volume and run it:
///
/// ```text
/// FHD_SECOND_VOLUME=D:hd-test cargo test -p fhd-daemon --test end_to_end -- --ignored
/// ```
#[ignore = "needs a writable directory on a second volume in FHD_SECOND_VOLUME"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_destination_on_a_second_volume_downloads_and_publishes() {
    let elsewhere = std::env::var_os("FHD_SECOND_VOLUME").map(PathBuf::from).expect(
        "this test needs FHD_SECOND_VOLUME to name a writable directory on another volume;          without it the cross-volume claim is uncovered rather than covered",
    );
    std::fs::create_dir_all(&elsewhere).expect("the second-volume directory is usable");

    let body = content(3 * 1024 * 1024 + 7);
    let (port, served) = serve(body.clone(), 0);
    let state = Directory::new("second-volume");
    let destination = elsewhere.join(format!("fhd-{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&destination);
    let url = format!("http://127.0.0.1:{port}/file");
    let mut settings = config(&state, destination.clone(), 4);
    settings.expected_sha256 = Some(expected_digest(&body));

    // The volumes really are different, or this test proves nothing.
    let volume = |path: &std::path::Path| {
        path.components()
            .next()
            .map(|component| component.as_os_str().to_ascii_lowercase())
    };
    assert_ne!(
        volume(&state.engine()),
        volume(&destination),
        "FHD_SECOND_VOLUME is on the same volume as the state directory, so this          would pass without crossing anything"
    );

    // Ignored by default, so CI never reaches this. Run by hand on a platform
    // that cannot publish, it would fail at a destination that was never going
    // to exist and blame the second volume for it. Whether a download can land
    // on another volume is a question about publication, so where there is no
    // publication there is no question to ask.
    if !PUBLISHES {
        eprintln!("skipped: this build does not publish on this platform");
        return;
    }

    let engine = Engine::open(settings, &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = engine.run(receiver).await.unwrap();
    // Compared after resolving, because the engine reports the path it opened
    // and Windows spells that one `\?\D:\...` where the caller wrote `D:\...`.
    let published = match &outcome {
        // The path only exists on `At`; a `Moved` result here would mean the
        // download folder was renamed mid-test, which it is not.
        SessionEnd::Published(Published::At(path)) => path.clone(),
        other => panic!(
            "not published: {other:?}, reason: {:?}",
            engine.reason().await.unwrap()
        ),
    };
    assert_eq!(
        std::fs::canonicalize(&published).unwrap(),
        std::fs::canonicalize(&destination).unwrap()
    );
    assert_eq!(std::fs::read(&destination).unwrap(), body);
    assert_eq!(part_bytes(&state), 0, "the part went to the state volume");
    assert!(served.load(Ordering::Relaxed) > 1, "used several requests");
    let _ = std::fs::remove_file(&destination);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_job_leaves_no_part_behind() {
    let body = content(4 * 1024 * 1024);
    let (port, served) = serve(body, 0);
    let state = Directory::new("cancel");
    let destination = state.0.join("cancelled.bin");
    let url = format!("http://127.0.0.1:{port}/file");
    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (control, receiver) = mpsc::channel(1);
    let run = engine.run(receiver);
    let cancel = async {
        while served.load(Ordering::Relaxed) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        control.send(Control::Cancel).await.unwrap();
    };
    let (outcome, ()) = tokio::join!(run, cancel);
    if !PUBLISHES {
        // Publication is unsupported here, so a run that outran the cancel stops
        // at publication instead of finishing. Cancelling still has to leave the
        // destination uncreated, which is asserted; whether the part survives is
        // decided by which of the two won the race, so it is not asserted here.
        // Cancelled, or stopped at a publication this platform refuses, and
        // nothing else: "not published" alone would have been satisfied by a
        // transport failure that fetched nothing.
        settled_without_publishing(
            &outcome,
            engine.reason().await.unwrap(),
            &[JobState::Cancelled, JobState::NeedsAction],
        );
        assert!(
            !destination.exists(),
            "a cancelled job that never published created the destination"
        );
        return;
    }
    match outcome.unwrap() {
        SessionEnd::Settled(JobState::Cancelled) => {}
        // Publication can win the race; then the part is released the other way.
        SessionEnd::Published(_) => {}
        other => panic!("unexpected outcome {other:?}"),
    }
    assert_eq!(part_bytes(&state), 0, "cancelled work keeps nothing");
    assert!(!destination.exists() || std::fs::metadata(&destination).unwrap().len() > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_publish_reconciled_after_a_crash_leaves_no_part() {
    let body = content(2 * 1024 * 1024);
    let (port, _) = serve(body.clone(), 0);
    let state = Directory::new("reconcile");
    let destination = state.0.join("done.bin");
    let url = format!("http://127.0.0.1:{port}/file");

    // First run publishes and releases its part.
    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = engine.run(receiver).await;
    // Publication is unsupported here: the first run is held to the refusal
    // contract instead, and with nothing published there is no file for a second
    // request to reconcile against.
    let Some(_) =
        published_as_declared(outcome, engine.reason().await.unwrap(), &destination, &body)
    else {
        return;
    };
    drop(engine);

    // A second request for the same bytes to the same name finds them already
    // there: it reconciles instead of republishing, and keeps no part either.
    let mut second = config(&state, destination.clone(), 2);
    second.max_bytes = 63 * 1024 * 1024;
    let engine = Engine::open(second, &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    assert_eq!(
        engine.run(receiver).await.unwrap(),
        SessionEnd::Published(Published::At(destination.clone()))
    );
    assert_eq!(std::fs::read(&destination).unwrap(), body);
    // Beside the destination, which is where parts live. This assertion used to
    // read the state directory -- `part_bytes(&state)` -- and parts moved out of
    // there when publication became a link within one folder, so it was
    // answering zero for a directory nothing writes to. It measured nothing, and
    // a review found the leak it should have caught: a part kept back after a
    // publication this run confirmed.
    assert_eq!(
        kept_beside(&destination),
        0,
        "a reconciled publish left a part beside the file"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn several_requests_share_one_engine_and_each_lands_in_its_own_file() {
    let first = content(2 * 1024 * 1024 + 11);
    let second = content(1024 * 1024 + 7);
    let (one, _) = serve(first.clone(), 0);
    let (two, _) = serve(second.clone(), 0);
    let state = Directory::new("several");
    let requests = vec![
        Request {
            url: format!("http://127.0.0.1:{one}/file"),
            destination: state.0.join("first.bin"),
            expected_sha256: Some(expected_digest(&first)),
            sensitive: false,
        },
        Request {
            url: format!("http://127.0.0.1:{two}/file"),
            destination: state.0.join("second.bin"),
            expected_sha256: Some(expected_digest(&second)),
            sensitive: false,
        },
    ];
    // One connection each and room for both: the two jobs genuinely overlap, each
    // writing its own part in the one directory the engine owns.
    let mut settings = config(&state, state.0.join("unused.bin"), 1);
    settings.engine_connections = 2;
    settings.max_active = 2;

    let engine = Engine::open_many(settings, requests.clone()).await.unwrap();
    let (_keep, commands) = mpsc::channel(4);
    let outcomes = engine.run_all(commands).await.unwrap();

    assert_eq!(outcomes.len(), 2);
    if !PUBLISHES {
        // Publication is unsupported here, so neither job can land in its file.
        // Both jobs still ran side by side in the one directory the engine owns,
        // and what is asserted is that each stopped at publication with its own
        // name untouched and its own bytes kept.
        for ((index, outcome), request) in outcomes.into_iter().zip(&requests) {
            // Each job reached publication and was refused there. Accepting any
            // non-published outcome would have passed for two jobs that never
            // fetched a byte.
            match outcome {
                JobOutcome::Settled(JobState::NeedsAction, reason) => assert_eq!(
                    reason,
                    Some(StopReason::Storage),
                    "job {index} stopped for something other than publication"
                ),
                other => panic!("job {index} settled in a state nothing declares: {other:?}"),
            }
            assert!(
                !request.destination.exists(),
                "job {index} created its destination without publishing"
            );
        }
        // The two parts share one folder, so this is measured once for both.
        assert!(
            kept_beside(&state.0.join("first.bin")) > 0,
            "the downloaded bytes were discarded when publication was refused"
        );
        return;
    }
    for ((index, outcome), request) in outcomes.into_iter().zip(&requests) {
        match outcome {
            JobOutcome::Published(outcome) => {
                assert_eq!(
                    outcome,
                    Published::At(request.destination.clone()),
                    "job {index}"
                )
            }
            JobOutcome::Settled(state, reason) => {
                panic!("job {index} stopped in {state:?} because {reason:?}")
            }
            other => panic!("job {index} ended as {other:?}"),
        }
    }
    assert_eq!(std::fs::read(state.0.join("first.bin")).unwrap(), first);
    assert_eq!(std::fs::read(state.0.join("second.bin")).unwrap(), second);
    // Both parts were released once their bytes reached their final names.
    assert_eq!(part_bytes(&state), 0, "part files left behind");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_later_run_continues_what_it_remembers_without_being_told_the_link() {
    let body = content(2 * 1024 * 1024 + 33);
    // Delivered slowly and paused on the bytes that actually arrived, not on a
    // timer. The timer was a race the test could lose: on a fast runner the
    // transfer finished inside the 15 ms, and then there was no unfinished work
    // for the second run to continue -- which is the whole subject. Where
    // publication is refused that also left the job needing action rather than
    // paused, so the run under test had nothing to pick up.
    let server = harness::serve_slowly(body.clone(), 16 * 1024, Duration::from_millis(2));
    let state = Directory::new("continue");
    let destination = state.0.join("remembered.bin");
    let url = format!("http://127.0.0.1:{}/file", server.port);

    // First run: pause it, so there is unfinished work worth continuing.
    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (control, receiver) = mpsc::channel(1);
    let delivered = server.delivered.clone();
    let faults = server.broken.clone();
    let quarter = body.len() as u64 / 4;
    let pause = async {
        // Bounded. An unbounded wait here is how a test stops being a test:
        // both Unix runners sat in this suite until the job timed out, with
        // nothing to say for it, while Windows passed. Whatever the cause, a
        // wait that cannot end is the wrong instrument -- this one gives up
        // and says what it saw.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while delivered.load(Ordering::Relaxed) < quarter {
            assert!(
                std::time::Instant::now() < deadline,
                "only {} of {quarter} bytes arrived in 60s, so the pause never had                  a part-way transfer to land in; the server failed to finish {}                  responses",
                delivered.load(Ordering::Relaxed),
                faults.load(Ordering::Relaxed)
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        // The run may already have settled, in which case the receiver is gone
        // and there is nothing to pause. That is a legitimate outcome and the
        // assertions below judge it; failing to send is not itself a failure.
        let _ = control.send(Control::Pause).await;
    };
    let (outcome, ()) = tokio::join!(engine.run(receiver), pause);
    // Paused, or stopped at a publication this platform refuses, and nothing
    // else. The first run is scaffolding either way -- the second is the one
    // under test, and it runs on every platform.
    //
    // F3 in the review of 9f4127d: this used to return here where publication
    // is unsupported, so on Linux and macOS it never reached the reopen it is
    // named after. Not being able to name the finished bytes has nothing to do
    // with whether a later run can find a job it was never told about, which is
    // what is being tested.
    // Paused on every platform now, because the pause is bound to the transfer
    // rather than to a clock. That is what leaves work for the second run.
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::Paused))),
        "the first run did not pause, so there is nothing to continue: {outcome:?}"
    );
    assert!(
        !destination.exists(),
        "a paused run created the destination"
    );
    drop(engine);

    // Second run knows nothing but the directory: no URL, no destination given.
    let mut settings = config(&state, state.0.clone(), 2);
    settings.intent = Intent::Resume;
    let engine = Engine::reopen(settings).await.unwrap();
    let (_keep, commands) = mpsc::channel(4);
    // Bounded, because this is a path Unix only started taking when the early
    // return went: where publication is refused the job settles needing action
    // rather than completing, and a scheduler that waited for something else
    // would hang here with nothing to show for it. A timeout says which call
    // did not come back.
    let outcomes = tokio::time::timeout(Duration::from_secs(120), engine.run_all(commands))
        .await
        .expect("continuing did not come back")
        .unwrap();
    assert_eq!(outcomes.len(), 1);
    // The job was found and carried to its end, and what "its end" is depends
    // on the platform. That it was found at all is the claim.
    match &outcomes[0].1 {
        JobOutcome::Published(outcome) if PUBLISHES => {
            assert_eq!(outcome, &Published::At(destination.clone()));
        }
        // Already finished before the pause landed: the remembered job was still
        // found and settled, which is what continuing has to prove.
        JobOutcome::Settled(JobState::Completed, _) if PUBLISHES => {}
        // Found, continued, and stopped where this platform stops -- at
        // publication, for the storage reason.
        JobOutcome::Settled(JobState::NeedsAction, reason) if !PUBLISHES => {
            // CI saw `Network` here. That is not a publication being refused,
            // it is a transfer that broke, and accepting it would have turned a
            // test-server fault into a passing test. The server's own failure
            // count is printed beside it so the next reading does not have to
            // guess which end gave up.
            assert_eq!(
                *reason,
                Some(StopReason::Storage),
                "continuing stopped for the wrong reason; the server failed to                  finish {} responses",
                server.broken.load(Ordering::Relaxed)
            );
            assert!(
                !destination.exists(),
                "a refused publication created the destination"
            );
            assert!(
                kept_beside_matches(&destination, &body),
                "continuing did not leave the downloaded bytes on disk"
            );
        }
        other => panic!("continuing ended as {other:?}"),
    }
    // The published file, where there is one. The non-publishing arm above has
    // already made its own two assertions -- no destination, and the bytes
    // still beside it -- and this line contradicted the first of them: it read
    // a file the same test had just required not to exist, and CI said so with
    // a NotFound at this line.
    if PUBLISHES {
        assert_eq!(std::fs::read(&destination).unwrap(), body);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sensitive_link_is_not_remembered_so_it_cannot_be_continued() {
    let body = content(64 * 1024);
    let (port, _) = serve(body, 0);
    let state = Directory::new("sensitive");
    let destination = state.0.join("secret.bin");
    let request = Request {
        url: format!("http://127.0.0.1:{port}/file"),
        destination,
        expected_sha256: None,
        sensitive: true,
    };
    let engine = Engine::open_many(config(&state, state.0.join("unused.bin"), 1), vec![request])
        .await
        .unwrap();
    let (_keep, commands) = mpsc::channel(4);
    let outcomes = engine.run_all(commands).await.unwrap();
    if !PUBLISHES {
        // Publication is unsupported here, so the run stops at publication
        // rather than finishing. That is asserted and the test goes on: what it
        // is really about is what was written down, and a link that was never
        // recorded is not recorded on this platform either.
        assert!(
            !outcomes
                .iter()
                .any(|(_, outcome)| matches!(outcome, JobOutcome::Published(_))),
            "publication succeeded on a platform with no mechanism: {outcomes:?}"
        );
    }
    drop(engine);

    // The link was never written, so there is nothing here to continue with.
    let settings = config(&state, state.0.clone(), 1);
    assert!(
        matches!(
            Engine::reopen(settings).await,
            Err(EngineError::NothingToContinue)
        ),
        "a sensitive link must not survive the run that used it"
    );
}

/// The access list on a **part file**, while one exists, in a download folder
/// that lets everybody write.
///
/// Parts moved next to their destination so a download could land on a disk the
/// engine does not live on. Inside the engine's directory they were covered by
/// a list it had set; a download folder belongs to the user, and on a data
/// volume here it grants `Authenticated Users` write -- so the move took a
/// protection away and this is what holds it back.
///
/// The job is paused rather than finished, because a completed one discards its
/// part and an earlier version of this test read an empty directory and called
/// the part protected. The folder is granted Modify on purpose, the list is read
/// back with `icacls`, which knows nothing about our code, and the assertion is
/// on the file, not on the directory that holds it.
///
/// **Coverage this does not carry.** It reads the permissions rather than
/// attempting a read as another principal, which is what criterion م٣ asks for.
/// Doing that needs a second local account or a restricted token, and this test
/// process has neither; an independent review did it with a restricted token and
/// measured the denials. Recorded here as a missing environment requirement
/// rather than left to look covered.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_part_file_does_not_inherit_what_the_download_folder_grants() {
    let body = content(8 * 1024 * 1024);
    let (port, served) = serve(body.clone(), 0);
    let state = Directory::new("part-acl-state");
    let downloads = Directory::new("part-acl-folder");
    let folder = downloads.0.join("Downloads");
    std::fs::create_dir_all(&folder).expect("the download folder is created");

    let granted = std::process::Command::new("icacls")
        .arg(&folder)
        .args(["/grant", "*S-1-5-11:(OI)(CI)M"])
        .output()
        .expect("icacls runs");
    assert!(
        granted.status.success(),
        "this test needs icacls to grant Modify to S-1-5-11; without it the \
         protection is uncovered rather than covered: {}",
        String::from_utf8_lossy(&granted.stderr)
    );

    // A control written straight into the folder: it must pick the grant up, or
    // the folder is not the hostile place this test assumes and nothing below
    // proves anything.
    let control = folder.join("control.bin");
    std::fs::write(&control, b"control").expect("the control file is written");
    let control_acl = String::from_utf8_lossy(
        &std::process::Command::new("icacls")
            .arg(&control)
            .output()
            .expect("icacls runs")
            .stdout,
    )
    .to_string();
    assert!(
        control_acl.contains("Authenticated Users"),
        "a file in this folder did not inherit the grant, so the folder is not \
         hostile and the part below proves nothing:\n{control_acl}"
    );

    let destination = folder.join("result.bin");
    let url = format!("http://127.0.0.1:{port}/file");
    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (paused, receiver) = mpsc::channel(1);
    let run = engine.run(receiver);
    let pause = async {
        while served.load(Ordering::Relaxed) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        paused.send(Control::Pause).await.unwrap();
    };
    let (outcome, ()) = tokio::join!(run, pause);
    outcome.expect("the run settles");
    drop(engine);

    // A finished job discards its part, and a discarded part cannot be asked
    // anything. If the pause lost the race there is nothing here to measure, and
    // that is reported rather than passed over.
    // Under `.fhd-parts/<engine>/`, so the walk is recursive: each engine owns
    // its own directory there so two of them cannot claim one part name.
    let parts = folder.join(".fhd-parts");
    fn collect(path: &std::path::Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect(&path, found);
            } else if path.extension().is_some_and(|kind| kind == "part") {
                found.push(path);
            }
        }
    }
    let mut found = Vec::new();
    collect(&parts, &mut found);
    assert!(
        !found.is_empty(),
        "no part file survived the pause, so nothing here was measured: {parts:?}"
    );

    for part in found {
        let acl = String::from_utf8_lossy(
            &std::process::Command::new("icacls")
                .arg(&part)
                .output()
                .expect("icacls runs")
                .stdout,
        )
        .to_string();
        assert!(
            !acl.contains("Authenticated Users") && !acl.contains("S-1-5-11"),
            "a part file carries the grant the download folder hands out:\n{acl}"
        );
        assert!(
            acl.contains("(F)"),
            "a part file grants this account nothing:\n{acl}"
        );
    }
}

/// A parts directory this engine did not create is refused, not adopted.
///
/// A download folder that lets everybody write lets everybody create
/// `.fhd-parts` first -- and whoever creates it owns it. An owner holds
/// WRITE_DAC whatever list we write afterwards, so replacing the list is not
/// taking the directory back: theirs goes on again whenever they like, and the
/// part file inherits it. A review pre-created it, re-granted itself while the
/// engine ran, and read and wrote a live part file.
///
/// So the boolean saying whether this call created the directory is the
/// decision, and one we found is inspected the way the state directory is.
///
/// The directory here is made by this test process rather than a second
/// account, so what is measured is that a foreign grant on a directory we did
/// not create is refused. **Not covered:** foreign *ownership* with a clean
/// list, which needs a second account. Recorded rather than implied.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_parts_directory_we_did_not_create_is_refused() {
    let body = content(512 * 1024);
    let (port, _served) = serve(body.clone(), 0);
    let state = Directory::new("squat-state");
    let downloads = Directory::new("squat-folder");
    let folder = downloads.0.join("Downloads");
    std::fs::create_dir_all(&folder).expect("the download folder is created");

    // Somebody got there first, and left it open.
    let planted = folder.join(".fhd-parts");
    std::fs::create_dir(&planted).expect("the parts directory is planted");
    let granted = std::process::Command::new("icacls")
        .arg(&planted)
        .args(["/grant", "*S-1-5-11:(OI)(CI)M"])
        .output()
        .expect("icacls runs");
    assert!(
        granted.status.success(),
        "this test needs icacls to grant Modify to S-1-5-11 on the planted \
         directory; without it the case is uncovered rather than covered: {}",
        String::from_utf8_lossy(&granted.stderr)
    );

    let destination = folder.join("result.bin");
    let url = format!("http://127.0.0.1:{port}/file");
    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = engine.run(receiver).await;

    assert!(
        !matches!(outcome, Ok(SessionEnd::Published(_))),
        "a download published through a parts directory somebody else made"
    );
    assert!(
        !destination.exists(),
        "the destination was written through a parts directory somebody else made"
    );
    // And the engine did not quietly rewrite what it found: the grant is still
    // there, which is what makes refusing the right answer rather than a
    // silent repair that ownership would undo anyway.
    let acl = String::from_utf8_lossy(
        &std::process::Command::new("icacls")
            .arg(&planted)
            .output()
            .expect("icacls runs")
            .stdout,
    )
    .to_string();
    assert!(
        acl.contains("Authenticated Users") || acl.contains("S-1-5-11"),
        "the planted directory was taken over instead of refused:\n{acl}"
    );
}

/// Two engines downloading into one folder do not fight over a part file.
///
/// Each engine has its own job record and each numbers its jobs from one, so
/// sharing a download folder they both wanted `1-1.part`. A review ran that: the
/// second engine took the first one's file over, re-downloaded into it from
/// zero, and published its own content correctly -- while the first engine's
/// progress was destroyed with nothing said. The bytes published were never
/// wrong; the loss was silent, which is what makes it a defect rather than a
/// race worth tolerating.
///
/// So each engine's parts live under a directory named for the state directory
/// that holds its job record: stable across a restart, so the same engine finds
/// its own part and resumes, and distinct between engines, so neither can reach
/// the other's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_engines_sharing_a_download_folder_keep_their_own_parts() {
    let first_body = content(6 * 1024 * 1024);
    let second_body = content(3 * 1024 * 1024 + 5);
    let (first_port, first_served) = serve(first_body.clone(), 0);
    let (second_port, _) = serve(second_body.clone(), 0);

    let shared = Directory::new("two-engines-folder");
    let folder = shared.0.join("Downloads");
    std::fs::create_dir_all(&folder).expect("the download folder is created");
    let first_state = Directory::new("two-engines-a");
    let second_state = Directory::new("two-engines-b");
    let first_destination = folder.join("first.bin");
    let second_destination = folder.join("second.bin");

    // Engine A starts and is paused with progress on disk.
    let first_url = format!("http://127.0.0.1:{first_port}/file");
    let engine = Engine::open(
        config(&first_state, first_destination.clone(), 2),
        &first_url,
    )
    .await
    .unwrap();
    let (paused, receiver) = mpsc::channel(1);
    let run = engine.run(receiver);
    let pause = async {
        while first_served.load(Ordering::Relaxed) < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        paused.send(Control::Pause).await.unwrap();
    };
    let (outcome, ()) = tokio::join!(run, pause);
    if PUBLISHES {
        outcome.expect("the first run settles");
    } else {
        // Publication is unsupported here, so engine A stops at its pause or at
        // publication -- either way with its bytes in the shared folder, which
        // is what engine B must not touch. Engine B still runs below.
        assert!(
            !matches!(outcome, Ok(SessionEnd::Published(_))),
            "publication succeeded on a platform with no mechanism: {outcome:?}"
        );
    }
    drop(engine);

    // Engine B runs a different download to completion in the same folder.
    let second_url = format!("http://127.0.0.1:{second_port}/file");
    let mut settings = config(&second_state, second_destination.clone(), 2);
    settings.expected_sha256 = Some(expected_digest(&second_body));
    let other = Engine::open(settings, &second_url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = other.run(receiver).await;
    if !PUBLISHES {
        // Publication is unsupported here, so engine B cannot finish either.
        // Both engines still wrote their parts into the one shared folder, which
        // is where they used to collide: what is asserted is that neither
        // published, neither destination was created, and bytes are still held
        // there -- engine A's among them, since it never got to release them.
        assert!(
            !matches!(outcome, Ok(SessionEnd::Published(_))),
            "publication succeeded on a platform with no mechanism: {outcome:?}"
        );
        assert!(
            !second_destination.exists() && !first_destination.exists(),
            "a refused publication created a destination"
        );
        assert!(
            kept_beside(&first_destination) > 0,
            "the downloaded bytes were discarded when publication was refused"
        );
        return;
    }
    assert_eq!(
        outcome.unwrap(),
        SessionEnd::Published(Published::At(second_destination.clone())),
        "reason: {:?}",
        other.reason().await.unwrap()
    );
    drop(other);
    assert_eq!(std::fs::read(&second_destination).unwrap(), second_body);

    // Engine A resumes. Its progress must have survived engine B entirely, and
    // its file must be its own content.
    if !first_destination.exists() {
        let resumed = Engine::open(
            resuming(&first_state, first_destination.clone(), 2),
            &first_url,
        )
        .await
        .unwrap();
        let (_control, receiver) = mpsc::channel(1);
        let outcome = resumed.run(receiver).await.unwrap();
        assert_eq!(
            outcome,
            SessionEnd::Published(Published::At(first_destination.clone())),
            "reason: {:?}",
            resumed.reason().await.unwrap()
        );
    }
    assert_eq!(
        std::fs::read(&first_destination).unwrap(),
        first_body,
        "the first engine's file did not survive the second engine"
    );
}

/// What a platform with no publication mechanism actually does, end to end.
///
/// **macOS does not finish downloads on this branch**. It refuses publication
/// because linking by a recovered source path would reintroduce the
/// substitution the handle contract prevents. Linux has a mechanism and its
/// end-to-end tests require a published file with matching bytes.
///
/// A prose statement of that is not evidence. This measures it, so the record
/// says what the engine does rather than what was intended:
///
/// - the bytes arrive and are verified, so the refusal is at publication and
///   nothing earlier;
/// - the destination is never created;
/// - the job stops needing a decision rather than reporting completion;
/// - the downloaded bytes are still on disk, so the day a mechanism exists the
///   transfer finishes rather than starting again.
///
/// This test is for platforms still lacking a mechanism. Linux now publishes
/// and is covered by the shared end-to-end tests above; macOS still refuses.
#[cfg(not(any(windows, target_os = "linux")))]
#[tokio::test]
async fn a_platform_without_a_mechanism_refuses_to_publish_and_keeps_the_bytes() {
    let body = content(64 * 1024 + 17);
    let (port, _served) = serve(body.clone(), 0);
    let state = Directory::new("no-mechanism");
    let destination = state.0.join("result.bin");
    let url = format!("http://127.0.0.1:{port}/file");
    let mut settings = config(&state, destination.clone(), 2);
    settings.expected_sha256 = Some(expected_digest(&body));

    let engine = Engine::open(settings, &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = engine.run(receiver).await;

    assert!(
        !matches!(outcome, Ok(SessionEnd::Published(_))),
        "publication succeeded on a platform with no mechanism: {outcome:?}"
    );
    assert!(
        !destination.exists(),
        "a refused publication created the destination"
    );
    assert_ne!(
        engine.state().await.unwrap(),
        JobState::Completed,
        "a job that never published reported completion"
    );
    // The transfer's work survives: this is a job waiting for a mechanism, not
    // one that has to be downloaded again.
    //
    // Measured where the parts actually are. `part_bytes` walks the state
    // directory, but a part lives in `.fhd-parts` beside its destination --
    // that is what lets a download land on a volume the engine does not live
    // on -- so `part_bytes` answers zero for a transfer whose work is
    // completely intact. Written against it alone, this assertion could never
    // have held, and would have failed here for a reason that has nothing to
    // do with what it is checking.
    assert!(
        part_bytes(&state) + kept_beside(&destination) > 0,
        "the downloaded bytes were discarded when publication was refused"
    );
}

/// A connection that has been accepted but has not finished asking must hold
/// the barrier shut.
///
/// The review of 7dc810a found `quiet` returning while such a connection was
/// pending, and demonstrated that it then delivered bytes -- which the next
/// measurement was charged for. The count rose only once the request had been
/// read, so a client still sending its headers was invisible.
///
/// No engine here: this is the harness measuring itself, because a barrier that
/// reports quiet while work is inbound makes every byte count downstream of it
/// untrustworthy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_half_sent_request_keeps_the_barrier_shut() {
    use std::io::Write;

    let body = content(256 * 1024);
    let server = harness::serve_slowly(body.clone(), 16 * 1024, Duration::from_millis(2));
    let address = format!("127.0.0.1:{}", server.port);

    // Nothing has connected: the barrier passes at once.
    server.quiet(Duration::from_secs(10)).await;

    // Connect and send a request that is deliberately incomplete -- no blank
    // line, so `read_request` is still waiting.
    let mut half = std::net::TcpStream::connect(&address).expect("the server accepts");
    half.write_all(b"GET /file HTTP/1.1\r\nHost: localhost\r\n")
        .expect("the header goes out");
    half.flush().unwrap();

    // Accepted, so it counts -- even though the server cannot know yet what it
    // wants. This is the assertion the old counter could not make.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while server.in_flight.load(Ordering::Relaxed) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the server never counted a connection it had accepted"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // And the barrier refuses to call this quiet. A short bound, because what
    // is being checked is that it does not return, not how long it waits.
    let waited = tokio::time::timeout(
        Duration::from_secs(2),
        server.quiet(Duration::from_secs(30)),
    )
    .await;
    assert!(
        waited.is_err(),
        "the barrier reported quiet while a request was still arriving"
    );

    // Finish the request, and read the answer. Reading matters: this server
    // delivers slowly, and a client that never drains fills the socket and
    // blocks the handler -- which is a stuck test, not a measurement.
    half.write_all(b"\r\n").expect("the request completes");
    half.flush().unwrap();
    let drained = std::thread::spawn(move || {
        use std::io::Read;
        let mut sink = Vec::new();
        let _ = half.read_to_end(&mut sink);
        sink.len()
    });

    server.quiet(Duration::from_secs(30)).await;
    assert_eq!(
        server.in_flight.load(Ordering::Relaxed),
        0,
        "the barrier returned with a response still being written"
    );
    let read_back = drained.join().expect("the reader finishes");
    assert!(
        read_back > body.len(),
        "the connection was counted but never served, so this proved nothing"
    );
}

/// A part this build cannot read stops the job by name, and is left alone.
///
/// The whole point of separating this from corruption is that the answer
/// differs: corrupt bytes are fetched again, a record that cannot be
/// interpreted is not touched at all and the job continues under a new
/// representation. A stop reason nobody can tell apart from the others cannot
/// carry that difference to whoever acts on it.
///
/// The old record is written by hand rather than produced by an older build,
/// because the point is what a restart finds on disk, and that is bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_part_this_build_cannot_read_stops_the_job_and_is_left_untouched() {
    let body = content(512 * 1024);
    let state = Directory::new("unreadable");
    let downloads = state.0.join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    let destination = downloads.join("wanted.bin");
    // One source for both runs: a different link is a different job, and the
    // second run would never open the part the first one left.
    let server = harness::serve_slowly(body.clone(), 16 * 1024, Duration::from_millis(2));
    let url = format!("http://127.0.0.1:{}/file", server.port);

    // A pause leaves a part on disk with work in it.
    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (control, receiver) = mpsc::channel(1);
    let delivered = server.delivered.clone();
    let quarter = body.len() as u64 / 4;
    let pause = async {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while delivered.load(Ordering::Relaxed) < quarter {
            assert!(
                std::time::Instant::now() < deadline,
                "the transfer never started"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let _ = control.send(Control::Pause).await;
    };
    let (outcome, ()) = tokio::join!(engine.run(receiver), pause);
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::Paused))),
        "the run did not pause: {outcome:?}"
    );
    drop(engine);

    // The record is rewritten as an older format would have left it, and a
    // bystander sits beside it so "left alone" is asserted rather than assumed.
    let parts = destination.parent().unwrap().join(".fhd-parts");
    let meta = find(&parts, "1-1.meta").expect("the part's record is on disk");
    let part = find(&parts, "1-1.part").expect("the part is on disk");
    let before_record = std::fs::read(&meta).unwrap();
    let before_bytes = std::fs::read(&part).unwrap();
    let mut planted = before_record.clone();
    planted[8] = 1;
    std::fs::write(&meta, &planted).unwrap();
    let bystander = downloads.join("theirs.bin");
    std::fs::write(&bystander, b"not ours").unwrap();

    // A later run finds it and stops, naming the one thing that is true.
    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = engine.run(receiver).await;
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::NeedsAction))),
        "an unreadable part did not stop the job: {outcome:?}"
    );
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(StopReason::Unreadable),
        "an unreadable part was reported as something else"
    );
    drop(engine);

    // Nothing was retried on it, rewritten, or removed -- and no file that was
    // never ours was touched.
    assert_eq!(
        std::fs::read(&meta).unwrap(),
        planted,
        "the record was rewritten"
    );
    assert_eq!(
        std::fs::read(&part).unwrap(),
        before_bytes,
        "the part was written to"
    );
    assert_eq!(std::fs::read(&bystander).unwrap(), b"not ours");
    assert!(!destination.exists(), "an unreadable part published");
}

/// The first file of this name anywhere under `root`.
fn find(root: &Path, name: &str) -> Option<PathBuf> {
    for entry in std::fs::read_dir(root).ok()?.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find(&path, name) {
                return Some(found);
            }
        } else if path.file_name().is_some_and(|it| it == name) {
            return Some(path);
        }
    }
    None
}

/// Runs a transfer part-way, pauses it, and hands back the part it left.
///
/// Every recovery test below starts from a real part with real work in it,
/// because what a restart finds on disk is bytes, and a part built by hand
/// would only prove the test's own idea of the format.
///
/// The `1-1` names assume the first job of a fresh state directory on its first
/// representation. That holds for these callers -- each opens its own directory
/// and nothing has changed generation before the pause -- and the `expect` says
/// so rather than searching for whatever part happens to be there, which would
/// quietly pass on the wrong file if either assumption ever broke.
async fn paused_part(
    state: &Directory,
    destination: &Path,
    server: &harness::Slow,
    total: u64,
) -> (PathBuf, PathBuf) {
    let url = format!("http://127.0.0.1:{}/file", server.port);
    let engine = Engine::open(config(state, destination.to_path_buf(), 2), &url)
        .await
        .unwrap();
    let (control, receiver) = mpsc::channel(1);
    let delivered = server.delivered.clone();
    let quarter = total / 4;
    let pause = async {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while delivered.load(Ordering::Relaxed) < quarter {
            assert!(
                std::time::Instant::now() < deadline,
                "the transfer never started"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let _ = control.send(Control::Pause).await;
    };
    let (outcome, ()) = tokio::join!(engine.run(receiver), pause);
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::Paused))),
        "the run did not pause: {outcome:?}"
    );
    drop(engine);

    let parts = destination.parent().unwrap().join(".fhd-parts");
    (
        find(&parts, "1-1.meta").expect("the part's record is on disk"),
        find(&parts, "1-1.part").expect("the part is on disk"),
    )
}

/// A part this build cannot read is continued as a new object, never over the
/// old one.
///
/// Stopping was the previous step; this is what the operator's resume does
/// about it. The job takes a new generation and fetches into a part of its own.
/// The part that could not be read keeps every byte it had, the destination is
/// created rather than replaced, and a file that was never ours is untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_part_is_continued_under_a_new_generation() {
    let body = content(256 * 1024);
    let state = Directory::new("replace-unreadable");
    let downloads = state.0.join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    let destination = downloads.join("wanted.bin");
    let server = harness::serve_slowly(body.clone(), 16 * 1024, Duration::from_millis(2));

    let (meta, part) = paused_part(&state, &destination, &server, body.len() as u64).await;
    let bystander = downloads.join("theirs.bin");
    std::fs::write(&bystander, b"not ours").unwrap();
    let mut planted = std::fs::read(&meta).unwrap();
    planted[8] = 1; // The format version an older build wrote.
    std::fs::write(&meta, &planted).unwrap();
    let held = std::fs::read(&part).unwrap();

    let url = format!("http://127.0.0.1:{}/file", server.port);
    // One run to find it and stop, then the resume that acts on the reason.
    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let _ = engine.run(receiver).await;
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(StopReason::Unreadable),
        "the first run did not reach the state this test is about"
    );
    drop(engine);

    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the resumed run did not come back");
    let reason = engine.reason().await.unwrap();
    // The record, read before the engine is closed: a published part is removed
    // from disk, so the part files cannot say which representation ran.
    let generation = engine.generation().await.unwrap();
    let landed = published_as_declared(outcome, reason, &destination, &body);
    drop(engine);

    // A new object, not the old one written over.
    assert_eq!(
        generation, 2,
        "the resume did not take a representation of its own"
    );
    assert_eq!(
        std::fs::read(&meta).unwrap(),
        planted,
        "the old record was rewritten"
    );
    assert_eq!(
        std::fs::read(&part).unwrap(),
        held,
        "the old part was written to"
    );
    assert_eq!(std::fs::read(&bystander).unwrap(), b"not ours");
    if landed.is_some() {
        assert_eq!(std::fs::read(&destination).unwrap(), body);
    }
}

/// A part that may already have been delivered is never fetched again.
///
/// This is the case the reason exists to keep apart. The record says the link
/// was begun and nothing says how it ended. The destination not holding the
/// file is not evidence it never did -- a folder can be renamed, and the file
/// may be in the user's hands. So a resume stops again, with the same reason,
/// instead of quietly fetching a second copy or reopening the part for writing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_part_that_may_be_delivered_is_not_fetched_again() {
    let body = content(256 * 1024);
    let state = Directory::new("unconfirmed");
    let downloads = state.0.join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    let destination = downloads.join("wanted.bin");
    let server = harness::serve_slowly(body.clone(), 16 * 1024, Duration::from_millis(2));

    let (meta, part) = paused_part(&state, &destination, &server, body.len() as u64).await;
    let held = std::fs::read(&part).unwrap();
    // Sealed and the link attempted: the record a crash inside publication
    // leaves, and the one state that says nothing about how it ended.
    let mut planted = std::fs::read(&meta).unwrap();
    planted[33] = 0b011;
    std::fs::write(&meta, &planted).unwrap();

    let url = format!("http://127.0.0.1:{}/file", server.port);
    server.quiet(Duration::from_secs(30)).await;
    let before = server.delivered.load(Ordering::Relaxed);
    // The run that discovers it: the part is opened, the state is read, and the
    // job stops without publishing.
    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the run did not come back");
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::NeedsAction))),
        "an unconfirmed part did not stop the job: {outcome:?}"
    );
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(StopReason::Unconfirmed),
        "the job stopped for some other reason"
    );
    drop(engine);

    // And asking again is refused before anything is opened or asked of the
    // origin. This is where a replacement path would have fired; instead the
    // operator is handed back the decision, which is the only honest answer
    // while nothing can establish how the publication ended. Two further asks,
    // because a refusal that holds once and not twice is not a refusal.
    for attempt in 0..2 {
        let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
            .await
            .unwrap();
        let (_control, receiver) = mpsc::channel(1);
        let outcome = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
            .await
            .expect("the run did not come back");
        assert!(
            matches!(
                outcome,
                Err(EngineError::NeedsDecision(Some(StopReason::Unconfirmed)))
            ),
            "attempt {attempt}: a resume of an unconfirmed part was not refused: {outcome:?}"
        );
        assert_eq!(
            engine.reason().await.unwrap(),
            Some(StopReason::Unconfirmed),
            "attempt {attempt}: the refusal did not leave the reason in place"
        );
        drop(engine);
    }

    // Nothing was fetched. The allowance is for the probe -- a `bytes=0-1`
    // ranged request, two bytes, which the server counts like any other
    // delivery rather than the one byte earlier comments claimed; anything approaching
    // the file would be a second copy of what the user may already have.
    server.quiet(Duration::from_secs(30)).await;
    let fetched = server.delivered.load(Ordering::Relaxed) - before;
    assert!(
        fetched <= 1024,
        "a part that may already be delivered was fetched again: {fetched} bytes"
    );
    let parts = destination.parent().unwrap().join(".fhd-parts");
    assert!(
        find(&parts, "1-2.part").is_none(),
        "an unconfirmed part was replaced by a new generation"
    );
    assert_eq!(
        std::fs::read(&meta).unwrap(),
        planted,
        "the record was rewritten"
    );
    assert_eq!(
        std::fs::read(&part).unwrap(),
        held,
        "the part was written to"
    );
    assert!(!destination.exists(), "an unconfirmed part published");
}

/// A record this build cannot make sense of is replaced, not repaired.
///
/// `Integrity` is the other reason that takes a new generation, and §10 of the
/// publication contract claimed it on the strength of the code alone -- an
/// independent review pointed out that no test anywhere exercised it end to end.
/// It is a different refusal from `Unreadable`: the format is ours, the contents
/// are not usable. The answer is the same, and now it is measured rather than
/// asserted in prose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_corrupt_record_is_replaced_by_a_new_generation() {
    let body = content(256 * 1024);
    let state = Directory::new("corrupt-record");
    let downloads = state.0.join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    let destination = downloads.join("wanted.bin");
    let server = harness::serve_slowly(body.clone(), 16 * 1024, Duration::from_millis(2));

    let (meta, part) = paused_part(&state, &destination, &server, body.len() as u64).await;
    let mut planted = std::fs::read(&meta).unwrap();
    // Inside the magic, not the version byte: the same bytes with the version
    // changed are a format we refuse as superseded, which is the other reason.
    planted[0] ^= 0xff;
    std::fs::write(&meta, &planted).unwrap();
    let held = std::fs::read(&part).unwrap();

    let url = format!("http://127.0.0.1:{}/file", server.port);
    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = engine.run(receiver).await;
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::NeedsAction))),
        "a corrupt record did not stop the job: {outcome:?}"
    );
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(StopReason::Integrity),
        "a corrupt record was reported as something else"
    );
    drop(engine);

    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the resumed run did not come back");
    let reason = engine.reason().await.unwrap();
    let generation = engine.generation().await.unwrap();
    let landed = published_as_declared(outcome, reason, &destination, &body);
    drop(engine);

    assert_eq!(generation, 2, "a corrupt record was not given a new object");
    assert_eq!(
        std::fs::read(&meta).unwrap(),
        planted,
        "the corrupt record was rewritten rather than left for inspection"
    );
    assert_eq!(
        std::fs::read(&part).unwrap(),
        held,
        "the old part was written to"
    );
    if landed.is_some() {
        assert_eq!(std::fs::read(&destination).unwrap(), body);
    }
}

/// The new generation exists beside the old part, and a restart keeps both.
///
/// The replacement moves the record to a new generation and then fetches into a
/// part file of its own. This waits until that file is **on disk**, closes the
/// state directory with both generations present, reopens from disk and carries
/// the job to the end -- with the part that could not be read never written to.
///
/// **What it does not do**, stated because an earlier version of this test
/// claimed it: it does not land inside the window between the committed
/// generation bump and the new part's creation. It first waited on the delivered
/// byte counter, which an independent review showed is satisfied by the resume's
/// ranged probe -- two bytes, counted like any other delivery -- strictly before
/// the generation-2 file exists. So the trigger fired before the transition, the
/// assertions held with no interruption at all, and the name promised a crash
/// that a graceful pause never performed. Reaching the real window needs a fault
/// injected between the bump and `create`, which is not implemented; what is
/// asserted here is the boundary this test can actually observe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_new_generation_stands_beside_the_old_part_across_a_restart() {
    let body = content(256 * 1024);
    let state = Directory::new("mid-generation");
    let downloads = state.0.join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    let destination = downloads.join("wanted.bin");
    let server = harness::serve_slowly(body.clone(), 16 * 1024, Duration::from_millis(2));

    let (meta, part) = paused_part(&state, &destination, &server, body.len() as u64).await;
    let mut planted = std::fs::read(&meta).unwrap();
    planted[8] = 1;
    std::fs::write(&meta, &planted).unwrap();
    let held = std::fs::read(&part).unwrap();

    let url = format!("http://127.0.0.1:{}/file", server.port);
    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let _ = engine.run(receiver).await;
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(StopReason::Unreadable),
        "the first run did not reach the state this test is about"
    );
    drop(engine);

    // The resume, stopped once the new generation's part file is on disk -- the
    // transition observed directly, rather than inferred from a byte counter
    // that the probe satisfies before the transition happens.
    let parts = destination.parent().unwrap().join(".fhd-parts");
    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (control, receiver) = mpsc::channel(1);
    let watch = parts.clone();
    let stop = async {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while find(&watch, "1-2.part").is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "the new generation's part file never appeared on disk"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let _ = control.send(Control::Pause).await;
    };
    let (_outcome, ()) = tokio::join!(engine.run(receiver), stop);
    drop(engine);

    // Both generations are on disk at once: the new one exists without the old
    // one having been reused, renamed or removed to make room for it.
    assert!(
        find(&parts, "1-2.part").is_some(),
        "the new generation's part file did not survive the restart"
    );
    // And the old part is as it was.
    assert_eq!(
        std::fs::read(&meta).unwrap(),
        planted,
        "the old record was rewritten while the generation changed"
    );
    assert_eq!(
        std::fs::read(&part).unwrap(),
        held,
        "the old part was written to while the generation changed"
    );

    // And the job can still be carried to the end this platform allows.
    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the run after the restart did not come back");
    let reason = engine.reason().await.unwrap();
    let landed = published_as_declared(outcome, reason, &destination, &body);
    drop(engine);
    if landed.is_some() {
        assert_eq!(std::fs::read(&destination).unwrap(), body);
    }
    assert_eq!(
        std::fs::read(&meta).unwrap(),
        planted,
        "the old record was rewritten"
    );
    assert_eq!(
        std::fs::read(&part).unwrap(),
        held,
        "the old part was written to"
    );
}

/// A part whose record cannot be read is not replaced when the job record says
/// a publication was begun for it.
///
/// This is the defect an independent security review found in the first version
/// of the recovery path, and it is the one that matters most, because it undoes
/// a fix this project already paid for. The format version is checked before the
/// publication byte, so a record this build cannot read says **nothing** about
/// whether the file was delivered. Answering that with "fetch it all again and
/// publish" is exactly what the version bump to `\x02` was made to stop: the
/// review that forced the bump had reproduced a file delivered by an older build
/// being published a second time under another name.
///
/// One byte written at offset 8 of the part's record was enough to ask for it.
/// The witness that survives is the publish intent: recorded before the seal and
/// before the link, held in the job record rather than in the user's download
/// folder, and dropped when the generation changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_record_is_not_replaced_when_a_publication_was_begun() {
    let body = content(256 * 1024);
    let state = Directory::new("unreadable-with-intent");
    let downloads = state.0.join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    let destination = downloads.join("wanted.bin");
    // Occupied, so publication is attempted and refused: the intent is recorded
    // and the part survives. This is the cheapest way to reach a job that has
    // begun publishing without finishing it.
    std::fs::write(&destination, b"someone else's file").unwrap();
    let server = harness::serve_slowly(body.clone(), 64 * 1024, Duration::from_millis(1));
    let url = format!("http://127.0.0.1:{}/file", server.port);

    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the first run did not come back");
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::NeedsAction))),
        "the transfer did not reach publication: {outcome:?}"
    );
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(StopReason::Destination),
        "the run stopped before it could record an intent to publish"
    );
    drop(engine);

    // The operator frees the name -- so nothing at the destination can answer the
    // question either, which is the renamed-folder case in miniature.
    std::fs::remove_file(&destination).unwrap();
    let parts = downloads.join(".fhd-parts");
    let meta = find(&parts, "1-1.meta").expect("the part's record is on disk");
    let part = find(&parts, "1-1.part").expect("the part is on disk");
    let mut planted = std::fs::read(&meta).unwrap();
    planted[8] = 1; // The format version an older build wrote.
    std::fs::write(&meta, &planted).unwrap();
    let held = std::fs::read(&part).unwrap();

    let before = server.delivered.load(Ordering::Relaxed);
    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the run did not come back");
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::NeedsAction))),
        "an unreadable record with a publication begun did not stop the job: {outcome:?}"
    );
    // Not `Unreadable`: that reason is answered by fetching the file again, and
    // this part may already be the user's.
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(StopReason::Unconfirmed),
        "a part that may already have been published was reported as replaceable"
    );
    let generation = engine.generation().await.unwrap();
    drop(engine);

    // And asking again is refused, so nothing is fetched and nothing published.
    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the second ask did not come back");
    assert!(
        matches!(
            outcome,
            Err(EngineError::NeedsDecision(Some(StopReason::Unconfirmed)))
        ),
        "a second ask was not refused: {outcome:?}"
    );
    drop(engine);

    assert_eq!(
        generation, 1,
        "a possibly published part took a new generation"
    );
    server.quiet(Duration::from_secs(30)).await;
    let fetched = server.delivered.load(Ordering::Relaxed) - before;
    assert!(
        fetched <= 1024,
        "a possibly published part was fetched again: {fetched} bytes"
    );
    assert!(
        find(&parts, "1-2.part").is_none(),
        "a possibly published part was replaced by a new generation"
    );
    assert_eq!(
        std::fs::read(&meta).unwrap(),
        planted,
        "the record was rewritten"
    );
    assert_eq!(
        std::fs::read(&part).unwrap(),
        held,
        "the part was written to"
    );
    assert!(!destination.exists(), "a second copy was published");
}

/// Corrupt bytes on a part that may already be delivered are still not replaced.
///
/// The other half of the same guard, and it was not covered: a re-review proved
/// it by moving the `Integrity` error ahead of the publication check, at which
/// point **the entire suite still passed** while a part whose record says the
/// link was begun became replaceable -- fetched again and published a second
/// time. Re-proving the durable extents hashes the bytes, so a part that reached
/// publication and then suffered a bad sector arrives exactly here.
///
/// `Integrity` is the right answer when the link never began, which
/// `a_corrupt_record_is_replaced_by_a_new_generation` covers. It is the wrong
/// answer once the record says a publication was begun, and this is that case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn corrupt_bytes_on_a_part_that_may_be_delivered_are_not_replaced() {
    let body = content(256 * 1024);
    let state = Directory::new("unconfirmed-corrupt");
    let downloads = state.0.join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    let destination = downloads.join("wanted.bin");
    let server = harness::serve_slowly(body.clone(), 16 * 1024, Duration::from_millis(2));

    // A completed transfer whose publication was refused: every byte is durable
    // and committed with a digest, which is what makes re-proving the extents
    // run at all. A pause does not do -- it may commit nothing, and then the
    // corruption below is never looked at. That is not a hypothetical: the first
    // version of this test was built on a pause, passed under the very mutation
    // it was written to catch, and was measuring the plain `Attempted` path that
    // another test already covers.
    let url = format!("http://127.0.0.1:{}/file", server.port);
    std::fs::write(&destination, b"someone else's file").unwrap();
    let engine = Engine::open(config(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the first run did not come back");
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::NeedsAction))),
        "the transfer did not reach publication: {outcome:?}"
    );
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(StopReason::Destination),
        "the run stopped before every byte was durable"
    );
    assert_eq!(
        engine.durable_bytes().await.unwrap(),
        body.len() as u64,
        "not every byte was committed, so no extent would be re-proved"
    );
    drop(engine);
    std::fs::remove_file(&destination).unwrap();

    let parts = downloads.join(".fhd-parts");
    let meta = find(&parts, "1-1.meta").expect("the part's record is on disk");
    let part = find(&parts, "1-1.part").expect("the part is on disk");
    // Sealed and the link begun, as a crash inside publication leaves it.
    let mut planted = std::fs::read(&meta).unwrap();
    planted[33] = 0b011;
    std::fs::write(&meta, &planted).unwrap();
    // And the bytes no longer match the digest committed for them, so re-proving
    // the extents fails before the destination is ever adopted.
    let mut bytes = std::fs::read(&part).unwrap();
    bytes[32] ^= 0xff;
    std::fs::write(&part, &bytes).unwrap();

    server.quiet(Duration::from_secs(30)).await;
    let before = server.delivered.load(Ordering::Relaxed);

    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        // A regression here does not return a wrong reason -- it takes a new
        // generation and fetches the whole file again, so it shows up as this
        // run not coming back rather than as the assertion below.
        .expect("the run did not come back; a replacement path would refetch here");
    assert!(
        matches!(outcome, Ok(SessionEnd::Settled(JobState::NeedsAction))),
        "the job did not stop: {outcome:?}"
    );
    // Not `Integrity`: that reason is answered by fetching the file again.
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(StopReason::Unconfirmed),
        "corrupt bytes on a possibly delivered part were reported as replaceable"
    );
    let generation = engine.generation().await.unwrap();
    drop(engine);

    // And a further ask is refused rather than answered with a second copy.
    let engine = Engine::open(resuming(&state, destination.clone(), 2), &url)
        .await
        .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the second ask did not come back");
    assert!(
        matches!(
            outcome,
            Err(EngineError::NeedsDecision(Some(StopReason::Unconfirmed)))
        ),
        "a second ask was not refused: {outcome:?}"
    );
    drop(engine);

    assert_eq!(
        generation, 1,
        "a possibly delivered part took a new generation"
    );
    server.quiet(Duration::from_secs(30)).await;
    let fetched = server.delivered.load(Ordering::Relaxed) - before;
    assert!(
        fetched <= 1024,
        "a possibly delivered part was fetched again: {fetched} bytes"
    );
    let parts = destination.parent().unwrap().join(".fhd-parts");
    assert!(
        find(&parts, "1-2.part").is_none(),
        "a possibly delivered part was replaced by a new generation"
    );
    assert_eq!(
        std::fs::read(&meta).unwrap(),
        planted,
        "the record was rewritten"
    );
    assert_eq!(
        std::fs::read(&part).unwrap(),
        bytes,
        "the part was written to"
    );
    assert!(!destination.exists(), "a second copy was published");
}
