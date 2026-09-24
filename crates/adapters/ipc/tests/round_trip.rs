//! What the control surface guarantees over a real endpoint: frames in order, a
//! named fault for a whole frame that is not the contract, and no way for a peer
//! to make the engine hold memory or give up serving everyone else.
use fhd_ipc::{ask, connect, Endpoint, Handler, Server};
use fhd_protocol::{decode_response, Request, Response, MAX_FRAME};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Counting {
    seen: AtomicU64,
}
impl Handler for Counting {
    async fn handle(&self, request: Request) -> Response {
        self.seen.fetch_add(1, Ordering::SeqCst);
        match request {
            Request::Pause { job } => Response::Accepted {
                job,
                warnings: Vec::new(),
            },
            Request::Shutdown => Response::Done,
            _ => Response::Failed {
                code: "ENGINE-INVALID-INPUT".into(),
            },
        }
    }
}

fn endpoint(label: &str) -> Endpoint {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    Endpoint::for_user(&format!(
        "test-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Serves in the background until the returned sender is used.
fn serve(server: Server, handler: Arc<Counting>) -> tokio::sync::oneshot::Sender<()> {
    let (stop, stopped) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        server
            .serve(handler, async {
                let _ = stopped.await;
            })
            .await;
    });
    stop
}

fn counting() -> Arc<Counting> {
    Arc::new(Counting {
        seen: AtomicU64::new(0),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_are_answered_in_order_over_a_real_endpoint() {
    let server = Server::bind(endpoint("order")).unwrap();
    let address = server.endpoint().clone();
    let handler = counting();
    let stop = serve(server, handler.clone());

    let mut client = connect(&address).await.unwrap();
    for job in 1..=3 {
        assert_eq!(
            ask(&mut client, job, &Request::Pause { job })
                .await
                .unwrap(),
            Response::Accepted {
                job,
                warnings: Vec::new()
            }
        );
    }
    assert_eq!(
        ask(&mut client, 9, &Request::Shutdown).await.unwrap(),
        Response::Done
    );
    assert_eq!(handler.seen.load(Ordering::SeqCst), 4);
    let _ = stop.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_frame_the_contract_refuses_is_answered_with_its_code() {
    let server = Server::bind(endpoint("bad-frame")).unwrap();
    let address = server.endpoint().clone();
    let handler = counting();
    let stop = serve(server, handler.clone());

    let mut client = connect(&address).await.unwrap();
    // A whole frame carrying a field this build does not know: a newer client
    // meaning something, so it is told, not guessed at and not hung up on.
    let body = br#"{"v":1,"id":1,"body":{"kind":"pause","job":1,"force":true}}"#;
    let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    frame.extend_from_slice(body);
    client.write_all(&frame).await.unwrap();

    let mut buffer = vec![0u8; 4096];
    let read = client.read(&mut buffer).await.unwrap();
    let (_, response) = decode_response(&buffer[4..read]).unwrap();
    assert_eq!(
        response,
        Response::Failed {
            code: "IPC-MALFORMED".into()
        }
    );
    // The engine never handed that frame to the engine's own logic.
    assert_eq!(handler.seen.load(Ordering::SeqCst), 0);
    let _ = stop.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_announcing_an_enormous_frame_is_dropped_and_others_keep_working() {
    let server = Server::bind(endpoint("too-large")).unwrap();
    let address = server.endpoint().clone();
    let stop = serve(server, counting());

    let mut shouting = connect(&address).await.unwrap();
    let header = u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes();
    let _ = shouting.write_all(&header).await;

    // Nothing is held for that announcement, and the next client is served.
    let mut honest = connect(&address).await.unwrap();
    assert_eq!(
        ask(&mut honest, 1, &Request::Pause { job: 1 })
            .await
            .unwrap(),
        Response::Accepted {
            job: 1,
            warnings: Vec::new()
        }
    );
    let _ = stop.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_engine_cannot_take_an_endpoint_that_is_already_served() {
    let server = Server::bind(endpoint("taken")).unwrap();
    let address = server.endpoint().clone();
    let stop = serve(server, counting());
    // Let the listener become reachable before trying to take its name.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let second = Server::bind(address.clone());
    assert!(second.is_err(), "a second engine took a live endpoint");
    // And the first is still the one answering.
    let mut client = connect(&address).await.unwrap();
    assert_eq!(
        ask(&mut client, 1, &Request::Shutdown).await.unwrap(),
        Response::Done
    );
    let _ = stop.send(());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_silent_client_does_not_stop_the_engine_answering_another() {
    let server = Server::bind(endpoint("silent")).unwrap();
    let address = server.endpoint().clone();
    let stop = serve(server, counting());

    // Connected, framed halfway, and then nothing: a stall, not a disconnect.
    let mut silent = connect(&address).await.unwrap();
    silent.write_all(&[0, 0, 0, 32]).await.unwrap();

    let mut busy = connect(&address).await.unwrap();
    for job in 1..=5 {
        assert_eq!(
            ask(&mut busy, job, &Request::Pause { job }).await.unwrap(),
            Response::Accepted {
                job,
                warnings: Vec::new()
            }
        );
    }
    let _ = stop.send(());
}
