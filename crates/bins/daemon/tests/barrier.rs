//! The measurement barrier itself, measured.
//!
//! No engine in this file. `quiet` is what makes a byte count belong to one run
//! rather than two, so a barrier that reports quiet while work is inbound makes
//! every count downstream of it untrustworthy. Twice now it has been right
//! about its number and wrong about the span it covered, and both times the
//! fault was invisible to the tests that used it.
mod harness;

use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// Sends a complete request and reads the whole answer, so the handler is never
/// left blocked on a socket nobody drains.
fn finish(mut stream: std::net::TcpStream) -> std::thread::JoinHandle<usize> {
    std::thread::spawn(move || {
        let _ = stream.write_all(b"\r\n");
        let _ = stream.flush();
        let mut sink = Vec::new();
        let _ = stream.read_to_end(&mut sink);
        sink.len()
    })
}

/// A connection accepted while the barrier is waiting must keep it shut.
///
/// The review of 2f5cb33: `quiet` read the busy count, waited 50ms, and then
/// decided on the reading it had taken before the wait. A connection accepted
/// in between left that reading stale, so the barrier returned with one live --
/// and it went on to deliver bytes that the next measurement was charged for.
///
/// **The property, not the timing.** Trying to land a connection inside one
/// 50ms window would be a race, and a test that depends on winning one is
/// worse than no test. This asserts what must hold however the interleaving
/// falls: whenever the barrier returns, nothing is in flight. Many attempts,
/// each with a different delay, so the interesting interleaving is reached
/// often -- and every attempt is a real check rather than a lottery ticket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_barrier_never_returns_while_a_connection_is_live() {
    let body = harness::content(64 * 1024);
    let server = Arc::new(harness::serve_slowly(
        body.clone(),
        8 * 1024,
        Duration::from_millis(2),
    ));
    let address = format!("127.0.0.1:{}", server.port);

    let mut arrived_during_a_wait = 0;
    for attempt in 0..24 {
        server.quiet(Duration::from_secs(30)).await;

        let watching = tokio::spawn({
            let server = server.clone();
            async move {
                server.quiet(Duration::from_secs(30)).await;
                server.in_flight.load(Ordering::Relaxed)
            }
        });

        // Spread across the barrier's window, so some attempts connect while it
        // is waiting and some after it has already returned. Both are fine;
        // what must never happen is a return with one live.
        tokio::time::sleep(Duration::from_millis(attempt * 4 % 60)).await;
        let mut half = std::net::TcpStream::connect(&address).expect("the server accepts");
        half.write_all(b"GET /file HTTP/1.1\r\nHost: localhost\r\n")
            .expect("the header goes out");
        half.flush().unwrap();

        // If the barrier is still shut, this connection reached it in time.
        let settled = tokio::time::timeout(Duration::from_millis(200), watching).await;
        match settled {
            Ok(joined) => assert_eq!(
                joined.expect("the barrier task finishes"),
                0,
                "the barrier returned while a connection was live"
            ),
            Err(_) => arrived_during_a_wait += 1,
        }

        let drained = finish(half);
        server.quiet(Duration::from_secs(30)).await;
        assert!(
            drained.join().expect("the reader finishes") > body.len(),
            "the connection was counted but never answered, so this attempt \
             proved nothing"
        );
    }

    // Without this the test could pass having never once exercised the case it
    // is named for -- every attempt landing after the barrier had returned.
    assert!(
        arrived_during_a_wait > 0,
        "no attempt connected while the barrier was waiting, so the case under \
         test was never reached"
    );
}
