//! The engine as a service: work arrives over the control surface while it runs,
//! and what it was told survives it going away.
mod harness;

use fhd_daemon::{Engine, EngineConfig, EngineError, Intent, Resident};
use fhd_ipc::{ask, connect, Endpoint};
use fhd_protocol::{AddRequest, Request, Response};
use harness::{
    content, expected_digest, kept_beside_matches, serve as serve_file, Directory, PUBLISHES,
};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::sync::mpsc;

fn settings(state: &Directory) -> EngineConfig {
    EngineConfig {
        state_directory: state.engine(),
        destination: state.0.clone(),
        connections: 2,
        engine_connections: 4,
        max_active: 2,
        expected_sha256: None,
        max_bytes: 64 * 1024 * 1024,
        allow_http: true,
        // The tests write beside the state directory, which is where their
        // temporary tree lives; a real engine is given the user's downloads.
        download_root: Some(state.0.clone()),
        intent: Intent::Start,
    }
}

fn endpoint(label: &str) -> Endpoint {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    Endpoint::for_user(&format!(
        "resident-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Opens the directory again, allowing for the moment it takes the previous
/// engine's background work to let go of the database after it has returned.
async fn reopen(state: &Directory) -> Resident {
    // A guard against waiting forever, not a claim about how fast a loaded machine
    // lets go: the previous engine's background work releases the locks shortly
    // after it returns.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let busy = match Resident::open(settings(state)).await {
            Ok(resident) => return resident,
            Err(error) => error,
        };
        assert!(
            matches!(busy, EngineError::StateBusy) || format!("{busy:?}").contains("Locked"),
            "reopening failed for another reason: {busy:?}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "the directory never became available: {busy:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn add(url: String, destination: &std::path::Path, digest: [u8; 32]) -> Request {
    Request::Add(AddRequest {
        url,
        destination: destination.to_string_lossy().into_owned(),
        sensitive: false,
        expected_sha256: Some(digest.iter().map(|byte| format!("{byte:02x}")).collect()),
        max_bytes: 64 * 1024 * 1024,
        allow_http: true,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn work_given_over_the_socket_is_fetched_published_and_remembered() {
    let body = content(2 * 1024 * 1024 + 91);
    let (port, _) = serve_file(body.clone(), 0);
    let state = Directory::new("resident");
    // The download lands in its own folder, and that folder is opened to other
    // accounts on purpose, so the answer carries a warning and the assertion
    // below is about delivery rather than two empty lists agreeing.
    //
    // Its own folder, not the test root: sharing the root made an ancestor of
    // the engine's state directory renameable by others and the engine refused
    // to open at all, with SwappableStatePath -- correctly. The warning is
    // about where a download lands; refusing to keep a job record under a path
    // strangers can move is a different rule, and this test is not about it.
    let downloads = state.0.join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    let destination = downloads.join("over-ipc.bin");
    assert!(
        open_to_others(&downloads),
        "the folder could not be shared, so the warning would have nothing to say"
    );
    let address = endpoint("add");

    let serving = Resident::open(settings(&state))
        .await
        .unwrap()
        .bind(address.clone())
        .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let engine = tokio::spawn(async move {
        serving
            .serve(async {
                let _ = stopped.await;
            })
            .await
    });

    let mut client = connect(&address).await.unwrap();
    let url = format!("http://127.0.0.1:{port}/file");
    let accepted = ask(
        &mut client,
        1,
        &add(url.clone(), &destination, expected_digest(&body)),
    )
    .await
    .unwrap();
    let Response::Accepted { job, warnings } = accepted else {
        panic!("the engine refused the request: {accepted:?}");
    };

    // R4 from the review of 2026-09-24: the shared-destination warning existed
    // only on the path that reads requests from stdin, so a download added
    // through the service was never warned about. It travels on the response
    // now, and this is the assertion that it reaches a client at all.
    //
    // Which way it goes depends on the folder the test runs in, and both
    // answers are legitimate -- what is not legitimate is a field nobody fills.
    // So the codes are checked for shape, and the decision is compared against
    // the one the direct path would make for the same folder, which is what
    //  is.
    let folder = destination.parent().expect("the destination has a folder");
    // Non-empty, because the folder was opened to other accounts above. The
    // earlier version of this compared the service's verdict with the direct
    // path's, and on a private folder both are empty -- which proves the two
    // agree and nothing about a warning reaching anyone. This is the delivery.
    assert_eq!(
        warnings,
        vec!["DESTINATION-SHARED".to_string()],
        "the warning for a shared folder did not reach the client"
    );
    // And it is still the same verdict the direct path would reach, so the two
    // cannot drift apart.
    assert_eq!(
        warnings,
        fhd_daemon::shared_destination_warnings(folder),
        "the service reached a different verdict than the direct path"
    );

    // The state this job settles in, which is not the same on every platform.
    //
    // This is what failed CI on Linux and macOS at 11dd794: the test waited two
    // minutes for "Completed" while publication is unsupported there, so the
    // wait could only ever time out. Raising the timeout would have been a way
    // of not noticing; deleting the test would have hidden the missing support.
    // It now waits for the state the engine declares for this platform, and a
    // wrong one fails immediately instead of after the deadline.
    let wanted = if PUBLISHES {
        "Completed"
    } else {
        "NeedsAction"
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let mut settled = None;
    while std::time::Instant::now() < deadline {
        let Response::Jobs { jobs, .. } = ask(&mut client, 2, &Request::List { after: None })
            .await
            .unwrap()
        else {
            panic!("listing failed")
        };
        let ours = jobs.iter().find(|summary| summary.job == job).unwrap();
        // Any resting state is an answer; only the moving ones are worth waiting
        // out. Accepting "whatever turns up" is how a wrong state passes.
        if matches!(
            ours.state.as_str(),
            "Completed" | "NeedsAction" | "Failed" | "Cancelled"
        ) {
            settled = Some(ours.clone());
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let settled = settled.expect("the job never came to rest over the socket");
    assert_eq!(
        settled.state, wanted,
        "the job settled in a state this platform does not declare"
    );

    if PUBLISHES {
        assert_eq!(std::fs::read(&destination).unwrap(), body);
    } else {
        // The declared refusal, over the socket rather than in-process: nothing
        // published, and the work kept so the transfer can finish the day a
        // mechanism exists. Contents, not size -- a part is created at its full
        // length before a byte arrives.
        assert!(
            !destination.exists(),
            "a refused publication created the destination"
        );
        assert!(
            kept_beside_matches(&destination, &body),
            "no part beside the destination holds the bytes that were downloaded"
        );
    }

    // Asking it to stop ends the engine; the client's answer comes first.
    assert_eq!(
        ask(&mut client, 3, &Request::Shutdown).await.unwrap(),
        Response::Done
    );
    let _ = stop.send(());
    // The engine must actually finish: a timeout here would be a hang, not a pass.
    tokio::time::timeout(Duration::from_secs(60), engine)
        .await
        .expect("the engine did not stop")
        .unwrap()
        .unwrap();

    // A later engine on the same directory remembers the job it never was told.
    let address = endpoint("restored");
    let serving = reopen(&state).await.bind(address.clone()).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let engine = tokio::spawn(async move {
        serving
            .serve(async {
                let _ = stopped.await;
            })
            .await
    });
    let mut client = connect(&address).await.unwrap();
    let Response::Jobs { jobs, .. } = ask(&mut client, 1, &Request::List { after: None })
        .await
        .unwrap()
    else {
        panic!("listing failed")
    };
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].job, job);
    // Restored to the same state it settled in, whichever that was: the point
    // of this half is that a later engine remembers a job it was never told
    // about, and that holds whether the job completed or is waiting for a
    // mechanism.
    assert_eq!(jobs[0].state, wanted);
    let _ = stop.send(());
    let _ = tokio::time::timeout(Duration::from_secs(60), engine).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_request_the_engine_refuses_is_answered_with_a_code_not_a_message() {
    let state = Directory::new("refused");
    let address = endpoint("refused");
    let serving = Resident::open(settings(&state))
        .await
        .unwrap()
        .bind(address.clone())
        .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let engine = tokio::spawn(async move {
        serving
            .serve(async {
                let _ = stopped.await;
            })
            .await
    });

    let mut client = connect(&address).await.unwrap();
    // A destination on another volume cannot be published to by renaming.
    let elsewhere = if cfg!(windows) {
        r"Z:\somewhere\x.bin"
    } else {
        "/proc/x.bin"
    };
    let answer = ask(
        &mut client,
        1,
        &Request::Add(AddRequest {
            url: "http://127.0.0.1:1/file".into(),
            destination: elsewhere.into(),
            sensitive: false,
            expected_sha256: None,
            max_bytes: 1024,
            allow_http: true,
        }),
    )
    .await
    .unwrap();
    match answer {
        Response::Failed { code } => {
            assert!(
                !code.contains('/') && !code.contains('\\'),
                "{code} carries a path"
            );
            assert!(code.len() <= 64);
        }
        other => panic!("the engine accepted a destination it cannot publish to: {other:?}"),
    }
    let _ = stop.send(());
    let _ = tokio::time::timeout(Duration::from_secs(60), engine).await;
}

/// The client proposes a destination; the engine decides. These are the ones it
/// must not accept, each refused before a single byte is fetched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn destinations_the_engine_will_not_write_to_are_refused_at_admission() {
    let state = Directory::new("destinations");
    let address = endpoint("destinations");
    let serving = Resident::open(settings(&state))
        .await
        .unwrap()
        .bind(address.clone())
        .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let engine = tokio::spawn(async move {
        serving
            .serve(async {
                let _ = stopped.await;
            })
            .await
    });
    let mut client = connect(&address).await.unwrap();

    let refused = [
        // Inside the engine's own tree: a remote server would get a say in the
        // engine's database, its journals or its part files.
        state.engine().join("state-wal").display().to_string(),
        state
            .engine()
            .join("parts")
            .join("1-1.part")
            .display()
            .to_string(),
        // Climbing out of the allowed root by spelling.
        state
            .0
            .join("..")
            .join("elsewhere.bin")
            .display()
            .to_string(),
        // Names the system reads as an instruction rather than as a file.
        state.0.join("x.desktop").display().to_string(),
        state.0.join("autorun.inf").display().to_string(),
        state.0.join("shortcut.lnk").display().to_string(),
        // Relative: nothing says where it lands.
        "downloads/x.bin".to_string(),
    ];
    for (index, destination) in refused.into_iter().enumerate() {
        let answer = ask(
            &mut client,
            index as u64 + 1,
            &Request::Add(AddRequest {
                url: "http://127.0.0.1:1/file".into(),
                destination: destination.clone(),
                sensitive: false,
                expected_sha256: None,
                max_bytes: 1024,
                allow_http: true,
            }),
        )
        .await
        .unwrap();
        match answer {
            Response::Failed { code } => assert!(
                !code.contains('/') && !code.contains('\\'),
                "{code} carries a path"
            ),
            other => panic!("accepted {destination}: {other:?}"),
        }
    }
    // Nothing was created for any of them.
    assert!(!state.engine().join("state-wal").exists());
    let _ = stop.send(());
    let _ = tokio::time::timeout(Duration::from_secs(60), engine).await;
}

/// A folder other accounts can write produces the warning; a private one does
/// not.
///
/// The review of 7dc810a: the delivery test compared the service's verdict with
/// the direct path's, and on a private folder both are empty -- so it proved
/// the two agree, not that a warning ever reaches anyone. This makes a folder
/// that is genuinely shared and checks the decision on it, so the delivery test
/// below has something to deliver.
///
/// Shared means what each platform means by it: mode bits on Unix, an access
/// list entry for Authenticated Users on Windows. Both are what an operator
/// would actually have on a data volume, not a contrivance.
#[test]
fn a_folder_others_can_write_is_the_one_that_warns() {
    let directory = Directory::new("warned");
    let private = directory.0.join("private");
    std::fs::create_dir(&private).unwrap();
    assert_eq!(
        fhd_daemon::shared_destination_warnings(&private),
        Vec::<String>::new(),
        "a folder this account made alone was reported as shared"
    );

    let shared = directory.0.join("shared");
    std::fs::create_dir(&shared).unwrap();
    assert!(
        open_to_others(&shared),
        "the folder could not be shared, so this test would prove nothing"
    );
    assert_eq!(
        fhd_daemon::shared_destination_warnings(&shared),
        vec!["DESTINATION-SHARED".to_string()],
        "a folder other accounts can write was not reported"
    );
}

/// Grants every account on the machine write access to `folder`.
///
/// Returns false when the platform would not do it, so a caller can say the
/// test proved nothing rather than pass on a folder that was never shared.
fn open_to_others(folder: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o777)).is_ok()
    }
    #[cfg(windows)]
    {
        // S-1-5-11 is Authenticated Users, which is what a data volume grants
        // by default; (M) is Modify.
        std::process::Command::new("icacls")
            .arg(folder)
            .args(["/grant", "*S-1-5-11:(OI)(CI)(M)"])
            .output()
            .map(|done| done.status.success())
            .unwrap_or(false)
    }
}

/// A job that stopped for a reason can still be cancelled, and a job that does
/// not exist is refused rather than reported as done.
///
/// Both halves were broken, and an independent review found them while looking
/// at something else. The scheduler owns what it is running and what waits in
/// its queue; a stopped job is in neither, so its command was dropped with
/// `CommandIgnored` -- while the client was told `Done`, because the reply was
/// sent on the strength of the channel send rather than the execution. So every
/// `Pause`/`Cancel` for a stopped job did nothing and said it had worked.
///
/// That is also what made `Unconfirmed` a state with no way out: resume is
/// refused by design, replacement is refused by design, and cancel -- the exit
/// the contract named -- never arrived. `NeedsAction` is the state all of those
/// rest in, and this reaches it the cheapest way there is, by occupying the
/// destination name. What it proves is the path, which `Unconfirmed` shares.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stopped_job_can_be_cancelled_and_an_unknown_one_is_refused() {
    let body = content(256 * 1024);
    let (port, _) = serve_file(body.clone(), 0);
    let state = Directory::new("cancel-resting");
    let downloads = state.0.join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    let destination = downloads.join("taken.bin");
    // Something else already holds the name, so the transfer finishes and the
    // publication is refused: the job comes to rest in `NeedsAction`.
    std::fs::write(&destination, b"someone else's file").unwrap();
    let address = endpoint("cancel");

    let serving = Resident::open(settings(&state))
        .await
        .unwrap()
        .bind(address.clone())
        .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let engine = tokio::spawn(async move {
        serving
            .serve(async {
                let _ = stopped.await;
            })
            .await
    });

    let mut client = connect(&address).await.unwrap();
    let url = format!("http://127.0.0.1:{port}/file");
    let accepted = ask(
        &mut client,
        1,
        &add(url.clone(), &destination, expected_digest(&body)),
    )
    .await
    .unwrap();
    let Response::Accepted { job, .. } = accepted else {
        panic!("the engine refused the request: {accepted:?}");
    };

    // Wait for it to come to rest, bounded: an unbounded wait here would turn a
    // job that never stopped into a test that never ends.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let resting = loop {
        let listed = ask(&mut client, 2, &Request::List { after: None })
            .await
            .unwrap();
        let Response::Jobs { jobs, .. } = listed else {
            panic!("the engine refused to list: {listed:?}");
        };
        let found = jobs
            .iter()
            .find(|summary| summary.job == job)
            .expect("the job it just accepted is not in the list")
            .clone();
        if found.state == "NeedsAction" {
            break found;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the job never came to rest: {found:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!(
        resting.reason.as_deref(),
        Some("DESTINATION"),
        "the job rested for some other reason"
    );

    // A job nobody has: refused, not reported as done.
    let unknown = ask(&mut client, 3, &Request::Cancel { job: job + 4242 })
        .await
        .unwrap();
    assert!(
        matches!(&unknown, Response::Failed { code } if code == "ENGINE-INVALID-INPUT"),
        "a command for a job that does not exist was not refused: {unknown:?}"
    );

    // And the stopped job takes the command.
    let cancelled = ask(&mut client, 4, &Request::Cancel { job }).await.unwrap();
    assert!(
        matches!(cancelled, Response::Done),
        "the engine refused to cancel a stopped job: {cancelled:?}"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let listed = ask(&mut client, 5, &Request::List { after: None })
            .await
            .unwrap();
        let Response::Jobs { jobs, .. } = listed else {
            panic!("the engine refused to list: {listed:?}");
        };
        let found = jobs
            .iter()
            .find(|summary| summary.job == job)
            .expect("the job disappeared from the list")
            .clone();
        if found.state == "Cancelled" {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the cancel was accepted and never carried out: {found:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let _ = stop.send(());
    let _ = engine.await;

    // The file that was never ours is still exactly what it was, and the
    // cancelled job kept nothing.
    assert_eq!(std::fs::read(&destination).unwrap(), b"someone else's file");
    let parts = downloads.join(".fhd-parts");
    let mut left = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&parts) {
        for entry in entries.flatten() {
            if let Ok(inner) = std::fs::read_dir(entry.path()) {
                left.extend(inner.flatten().map(|it| it.file_name()));
            }
        }
    }
    assert!(
        left.is_empty(),
        "a cancelled job left parts behind: {left:?}"
    );
}

/// The first file of this name anywhere under `root`.
fn find(root: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
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

/// A job stopped as `Unconfirmed` is cancelled over the socket, the answer says
/// what happened, it survives a restart -- and the part it may have delivered is
/// kept, not deleted.
///
/// This is the acceptance criterion as the review wrote it, and each clause is a
/// separate assertion: the command is applied to the stored job and its
/// transition recorded; the reply is not `Done` until the scheduler has answered;
/// the job store is compared after reopening; and a sealed part that may belong
/// to a delivered file is not touched.
///
/// `Unconfirmed` is reached the way a crash inside publication leaves it: every
/// byte durable, the link recorded as begun, and the destination name free again
/// -- which is the renamed-folder case, where the destination cannot answer
/// whether the file was ever delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unconfirmed_job_is_cancelled_over_the_socket_and_keeps_its_part() {
    let body = content(256 * 1024);
    let (port, _) = serve_file(body.clone(), 0);
    let state = Directory::new("cancel-unconfirmed");
    let downloads = state.0.join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    let destination = downloads.join("wanted.bin");
    std::fs::write(&destination, b"someone else's file").unwrap();
    let url = format!("http://127.0.0.1:{port}/file");

    // Transfer everything, then have publication refused: all bytes durable and
    // an intent recorded, which is the state a publication crash starts from.
    let one_shot = EngineConfig {
        destination: destination.clone(),
        ..settings(&state)
    };
    let engine = Engine::open(one_shot.clone(), &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let outcome = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the first run did not come back");
    assert!(outcome.is_ok(), "the transfer failed: {outcome:?}");
    assert_eq!(engine.durable_bytes().await.unwrap(), body.len() as u64);
    drop(engine);

    // The link recorded as begun, and the name free again.
    let parts = downloads.join(".fhd-parts");
    let meta = find(&parts, "1-1.meta").expect("the part's record is on disk");
    let part = find(&parts, "1-1.part").expect("the part is on disk");
    let mut planted = std::fs::read(&meta).unwrap();
    planted[33] = 0b011;
    std::fs::write(&meta, &planted).unwrap();
    let held = std::fs::read(&part).unwrap();
    std::fs::remove_file(&destination).unwrap();

    // One run to reach the state itself, so the record says `Unconfirmed`
    // rather than the test asserting it into existence.
    let engine = Engine::open(
        EngineConfig {
            intent: Intent::Resume,
            ..one_shot.clone()
        },
        &url,
    )
    .await
    .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let _ = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the run did not come back");
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(fhd_domain::StopReason::Unconfirmed),
        "the job did not reach the state this test is about"
    );
    drop(engine);

    // Now the service, on the same state directory.
    let address = endpoint("unconfirmed");
    let serving = reopen(&state).await.bind(address.clone()).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(async move {
        serving
            .serve(async {
                let _ = stopped.await;
            })
            .await
    });
    let mut client = connect(&address).await.unwrap();

    let listed = ask(&mut client, 1, &Request::List { after: None })
        .await
        .unwrap();
    let Response::Jobs { jobs, .. } = listed else {
        panic!("the engine refused to list: {listed:?}");
    };
    let before = jobs.first().expect("the job is in the record").clone();
    assert_eq!(before.state, "NeedsAction");
    assert_eq!(
        before.reason.as_deref(),
        Some("UNCONFIRMED"),
        "the service reports the state differently from the engine"
    );

    let cancelled = ask(&mut client, 2, &Request::Cancel { job: before.job })
        .await
        .unwrap();
    assert!(
        matches!(cancelled, Response::Done),
        "cancelling a job stopped as unconfirmed was refused: {cancelled:?}"
    );

    let _ = stop.send(());
    let _ = running.await;

    // The record after a restart, which is what "recorded" has to mean.
    let address = endpoint("unconfirmed-again");
    let serving = reopen(&state).await.bind(address.clone()).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(async move {
        serving
            .serve(async {
                let _ = stopped.await;
            })
            .await
    });
    let mut client = connect(&address).await.unwrap();
    let listed = ask(&mut client, 1, &Request::List { after: None })
        .await
        .unwrap();
    let Response::Jobs { jobs, .. } = listed else {
        panic!("the engine refused to list: {listed:?}");
    };
    let after = jobs
        .first()
        .expect("the job is still in the record")
        .clone();
    assert_eq!(
        after.state, "Cancelled",
        "the cancel was answered and did not survive the restart"
    );
    let _ = stop.send(());
    let _ = running.await;

    // And the part is still there, whole. A cancelled job keeps nothing it
    // downloaded -- but this part's record says a link was begun, so it may be a
    // second name for a file the user already has, and removing it would destroy
    // the only local evidence of that. It is kept on purpose, and that is the
    // outcome the review asked to see stated plainly rather than assumed.
    assert_eq!(
        std::fs::read(&part).unwrap(),
        held,
        "a part that may have been delivered was written to"
    );
    assert_eq!(
        std::fs::read(&meta).unwrap(),
        planted,
        "the record of a part that may have been delivered was rewritten"
    );
    assert!(
        !destination.exists(),
        "cancelling created the destination it was unsure about"
    );
}

/// Evidence at the destination resolves an unconfirmed job; its absence does not.
///
/// This is the procedure Â§10 recorded as missing -- the one thing that could end
/// that state, leaving cancel as the only exit. The engine cannot decide it
/// alone in both directions, and does not pretend to: a destination holding a
/// file whose size and digest are the ones recorded is proof the publication
/// happened, while a destination holding nothing proves nothing at all, because
/// a folder can be renamed.
///
/// So both directions are asserted here, and the second matters more: asking
/// with the file absent must leave the job exactly as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_file_at_the_destination_resolves_an_unconfirmed_job_and_nothing_else_does() {
    let body = content(256 * 1024);
    let (port, _) = serve_file(body.clone(), 0);
    let state = Directory::new("confirm");
    let downloads = state.0.join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    let destination = downloads.join("wanted.bin");
    std::fs::write(&destination, b"someone else's file").unwrap();
    let url = format!("http://127.0.0.1:{port}/file");

    // Every byte durable and an intent recorded, then the link recorded as begun
    // and the name freed: a crash inside publication, with the destination
    // unable to answer for it.
    let one_shot = EngineConfig {
        destination: destination.clone(),
        ..settings(&state)
    };
    let engine = Engine::open(one_shot.clone(), &url).await.unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let _ = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the first run did not come back");
    assert_eq!(engine.durable_bytes().await.unwrap(), body.len() as u64);
    drop(engine);

    let parts = downloads.join(".fhd-parts");
    let meta = find(&parts, "1-1.meta").expect("the part's record is on disk");
    let part = find(&parts, "1-1.part").expect("the part is on disk");
    let mut planted = std::fs::read(&meta).unwrap();
    planted[33] = 0b011;
    std::fs::write(&meta, &planted).unwrap();
    std::fs::remove_file(&destination).unwrap();

    let engine = Engine::open(
        EngineConfig {
            intent: Intent::Resume,
            ..one_shot.clone()
        },
        &url,
    )
    .await
    .unwrap();
    let (_control, receiver) = mpsc::channel(1);
    let _ = tokio::time::timeout(Duration::from_secs(120), engine.run(receiver))
        .await
        .expect("the run did not come back");
    assert_eq!(
        engine.reason().await.unwrap(),
        Some(fhd_domain::StopReason::Unconfirmed)
    );
    drop(engine);

    let address = endpoint("confirm");
    let serving = reopen(&state).await.bind(address.clone()).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(async move {
        serving
            .serve(async {
                let _ = stopped.await;
            })
            .await
    });
    let mut client = connect(&address).await.unwrap();
    let listed = ask(&mut client, 1, &Request::List { after: None })
        .await
        .unwrap();
    let Response::Jobs { jobs, .. } = listed else {
        panic!("the engine refused to list: {listed:?}");
    };
    let job = jobs.first().expect("the job is in the record").job;

    // Nothing is at the destination, so nothing is resolved -- and the job is
    // left exactly as it was rather than being declared either way.
    let absent = ask(&mut client, 2, &Request::Confirm { job })
        .await
        .unwrap();
    assert!(
        matches!(&absent, Response::Failed { code } if code == "UNCONFIRMED-NOT-AT-DESTINATION"),
        "an absent file was treated as an answer: {absent:?}"
    );
    let listed = ask(&mut client, 3, &Request::List { after: None })
        .await
        .unwrap();
    let Response::Jobs { jobs, .. } = listed else {
        panic!("the engine refused to list");
    };
    let unchanged = jobs.first().expect("the job is still there").clone();
    assert_eq!(unchanged.state, "NeedsAction");
    assert_eq!(unchanged.reason.as_deref(), Some("UNCONFIRMED"));
    assert!(
        part.exists(),
        "a question that resolved nothing removed the part"
    );

    // A file of another size is not an answer.
    std::fs::write(&destination, b"not the download").unwrap();
    let wrong = ask(&mut client, 4, &Request::Confirm { job })
        .await
        .unwrap();
    assert!(
        matches!(&wrong, Response::Failed { code } if code == "UNCONFIRMED-NOT-AT-DESTINATION"),
        "a different file was treated as ours: {wrong:?}"
    );

    // Nor is a file of exactly the right size holding the wrong bytes -- the
    // case the digest exists for, and the only one that makes it do any work.
    //
    // The line above cannot reach it: `inspect` refuses to hash a file whose
    // size is not the recorded size, so a sixteen-byte stand-in is rejected on
    // size and the digest is never compared. A security review demonstrated
    // that by relaxing the digest check to `|| true` and watching the whole
    // suite pass. One flipped byte is the difference between a test of "size
    // and digest" and a test of size.
    let mut flipped = body.clone();
    flipped[body.len() / 2] ^= 0xff;
    std::fs::write(&destination, &flipped).unwrap();
    let wrong_bytes = ask(&mut client, 5, &Request::Confirm { job })
        .await
        .unwrap();
    assert!(
        matches!(&wrong_bytes, Response::Failed { code } if code == "UNCONFIRMED-NOT-AT-DESTINATION"),
        "a file of the right size holding the wrong bytes was treated as ours: {wrong_bytes:?}"
    );

    // And the file itself, which is the evidence the state was waiting for.
    std::fs::write(&destination, &body).unwrap();
    let confirmed = ask(&mut client, 5, &Request::Confirm { job })
        .await
        .unwrap();
    assert!(
        matches!(confirmed, Response::Done),
        "the file at the destination did not resolve the job: {confirmed:?}"
    );

    let _ = stop.send(());
    let _ = running.await;

    // The record says so after a restart, and the part is gone: with the outcome
    // established it was a name, not evidence.
    let address = endpoint("confirm-again");
    let serving = reopen(&state).await.bind(address.clone()).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(async move {
        serving
            .serve(async {
                let _ = stopped.await;
            })
            .await
    });
    let mut client = connect(&address).await.unwrap();
    let listed = ask(&mut client, 1, &Request::List { after: None })
        .await
        .unwrap();
    let Response::Jobs { jobs, .. } = listed else {
        panic!("the engine refused to list");
    };
    let after = jobs
        .first()
        .expect("the job is still in the record")
        .clone();
    assert_eq!(
        after.state, "Completed",
        "the resolution did not survive the restart"
    );
    assert_eq!(after.reason, None, "a completed job kept a reason");
    let _ = stop.send(());
    let _ = running.await;

    assert_eq!(
        std::fs::read(&destination).unwrap(),
        body,
        "the file was touched by the question about it"
    );
    assert!(!part.exists(), "a resolved job kept its part");
}

/// Asking about a job this question cannot resolve says so, rather than making
/// a claim about a destination nobody looked at.
///
/// One code used to answer five situations, four of which never touched the
/// filesystem -- including a job that does not exist, which every other command
/// answers as such. A review named it as the one place this surface said more
/// than it had checked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_job_this_question_cannot_resolve_is_told_apart_from_an_absent_file() {
    let body = content(64 * 1024);
    let (port, _) = serve_file(body.clone(), 0);
    let state = Directory::new("confirm-other");
    let downloads = state.0.join("downloads");
    std::fs::create_dir(&downloads).unwrap();
    let destination = downloads.join("wanted.bin");
    let address = endpoint("confirm-other");

    let serving = Resident::open(settings(&state))
        .await
        .unwrap()
        .bind(address.clone())
        .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let running = tokio::spawn(async move {
        serving
            .serve(async {
                let _ = stopped.await;
            })
            .await
    });
    let mut client = connect(&address).await.unwrap();

    // A job nobody has.
    let unknown = ask(&mut client, 1, &Request::Confirm { job: 4242 })
        .await
        .unwrap();
    assert!(
        matches!(&unknown, Response::Failed { code } if code == "ENGINE-INVALID-INPUT"),
        "a job that does not exist was answered with a fact about a destination: {unknown:?}"
    );

    // And one that exists but is not in this state: the answer is the same, and
    // it is not the one that talks about the destination.
    let url = format!("http://127.0.0.1:{port}/file");
    let accepted = ask(
        &mut client,
        2,
        &add(url, &destination, expected_digest(&body)),
    )
    .await
    .unwrap();
    let Response::Accepted { job, .. } = accepted else {
        panic!("the engine refused the request: {accepted:?}");
    };
    let running_job = ask(&mut client, 3, &Request::Confirm { job })
        .await
        .unwrap();
    assert!(
        matches!(&running_job, Response::Failed { code } if code == "ENGINE-INVALID-INPUT"),
        "a job in another state was answered with a fact about a destination: {running_job:?}"
    );

    let _ = stop.send(());
    let _ = running.await;
}
