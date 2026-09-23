//! The engine as a service: work arrives over the control surface while it runs,
//! and what it was told survives it going away.
mod harness;

use fhd_daemon::{EngineConfig, EngineError, Intent, Resident};
use fhd_ipc::{ask, connect, Endpoint};
use fhd_protocol::{AddRequest, Request, Response};
use harness::{content, expected_digest, serve as serve_file, Directory};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

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
    let destination = state.0.join("over-ipc.bin");
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
    let Response::Accepted { job } = accepted else {
        panic!("the engine refused the request: {accepted:?}");
    };

    // The job is real work, so it takes a moment; the socket stays answerable.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let mut published = false;
    while std::time::Instant::now() < deadline {
        let Response::Jobs { jobs, .. } = ask(&mut client, 2, &Request::List { after: None })
            .await
            .unwrap()
        else {
            panic!("listing failed")
        };
        let ours = jobs.iter().find(|summary| summary.job == job).unwrap();
        if ours.state == "Completed" {
            published = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(published, "the job never completed over the socket");
    assert_eq!(std::fs::read(&destination).unwrap(), body);

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
    assert_eq!(jobs[0].state, "Completed");
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
