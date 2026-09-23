//! The engine as a service: work arrives over the control surface while it runs,
//! and what it was told survives it going away.
mod harness;

use fhd_daemon::{EngineConfig, Intent, Resident};
use fhd_ipc::{ask, connect, Endpoint};
use fhd_protocol::{AddRequest, Request, Response};
use harness::{content, expected_digest, serve as serve_file, Directory};
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

fn settings(state: &Directory) -> EngineConfig {
    EngineConfig {
        state_directory: state.0.clone(),
        destination: state.0.clone(),
        connections: 2,
        engine_connections: 4,
        max_active: 2,
        expected_sha256: None,
        max_bytes: 64 * 1024 * 1024,
        allow_http: true,
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
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match Resident::open(settings(state)).await {
            Ok(resident) => return resident,
            Err(error) if std::time::Instant::now() < deadline => {
                assert!(
                    format!("{error:?}").contains("Locked"),
                    "reopening failed for another reason: {error:?}"
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => panic!("the directory never became available: {error:?}"),
        }
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
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
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
    tokio::time::timeout(Duration::from_secs(10), engine)
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
    let _ = tokio::time::timeout(Duration::from_secs(10), engine).await;
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
    let _ = tokio::time::timeout(Duration::from_secs(10), engine).await;
}
