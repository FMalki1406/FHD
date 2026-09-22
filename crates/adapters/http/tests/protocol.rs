//! Protocol behaviour against a scripted in-process server: no network, no lab.
use fhd_app::transport::{Transport, TransportError};
use fhd_domain::{ByteRange, SourceRef, StopReason};
use fhd_http::{HttpConfig, HttpTransport, SourceBinding};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    time::Duration,
};

/// Answers each connection with the next scripted response and records the request.
struct Server {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}
fn serve(responses: Vec<Vec<u8>>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = seen.clone();
    std::thread::spawn(move || {
        for response in responses {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let request = read_request(&mut stream);
            recorder.lock().unwrap().push(request);
            let _ = stream.write_all(&response);
            let _ = stream.flush();
        }
    });
    Server { port, seen }
}
fn read_request(stream: &mut TcpStream) -> String {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) | Err(_) => break,
            Ok(_) => request.push(byte[0]),
        }
    }
    String::from_utf8_lossy(&request).into_owned()
}
fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n").into_bytes();
    for (name, value) in headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

fn new_transport() -> HttpTransport {
    HttpTransport::new(HttpConfig {
        read_idle_timeout: Duration::from_millis(300),
        response_timeout: Duration::from_millis(500),
        ..HttpConfig::default()
    })
    .unwrap()
}
/// Header names arrive lowercase from the client.
fn sent(server: &Server, index: usize) -> String {
    server.seen.lock().unwrap()[index].clone()
}
fn source() -> SourceRef {
    SourceRef::new(1).unwrap()
}
fn bind(transport: &HttpTransport, port: u16, origins: Vec<String>) {
    transport
        .bind(
            source(),
            SourceBinding::new(
                &format!("http://127.0.0.1:{port}/file"),
                Some("Bearer SECRET".into()),
                None,
                true,
                origins,
            )
            .unwrap(),
        )
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probe_reports_size_and_a_validator_only_with_ranges_and_a_strong_etag() {
    // 206 with a strong ETag: resumable.
    let server = serve(vec![response(
        "206 Partial Content",
        &[
            ("Content-Range", "bytes 0-9/10"),
            ("ETag", "\"v1\""),
            ("Accept-Ranges", "bytes"),
        ],
        b"0123456789",
    )]);
    let transport = new_transport();
    bind(&transport, server.port, vec![]);
    let probe = transport.probe(source()).await.unwrap();
    assert_eq!(probe.total(), 10);
    assert!(probe.ranges() && probe.validator().is_some());
    assert!(sent(&server, 0).contains("range: bytes=0-"));

    // A weak validator is no validator: no ranges, no resume.
    let server = serve(vec![response(
        "206 Partial Content",
        &[("Content-Range", "bytes 0-9/10"), ("ETag", "W/\"v1\"")],
        b"0123456789",
    )]);
    let transport = new_transport();
    bind(&transport, server.port, vec![]);
    let probe = transport.probe(source()).await.unwrap();
    assert_eq!((probe.total(), probe.validator()), (10, None));

    // A server ignoring Range answers 200: size only.
    let server = serve(vec![response(
        "200 OK",
        &[("ETag", "\"v1\"")],
        b"0123456789",
    )]);
    let transport = new_transport();
    bind(&transport, server.port, vec![]);
    let probe = transport.probe(source()).await.unwrap();
    assert_eq!((probe.total(), probe.validator()), (10, None));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_range_is_bound_to_the_probed_representation() {
    let ok = || {
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 0-9/10"), ("ETag", "\"v1\"")],
            b"0123456789",
        )
    };
    let server = serve(vec![
        ok(),
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 2-5/10"), ("ETag", "\"v1\"")],
            b"2345",
        ),
    ]);
    let transport = new_transport();
    bind(&transport, server.port, vec![]);
    let probe = transport.probe(source()).await.unwrap();
    let mut stream = transport
        .fetch(source(), ByteRange::new(2, 6).unwrap(), probe.validator())
        .await
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 3];
    loop {
        let read = stream.read(&mut buf).await.unwrap();
        if read == 0 {
            break;
        }
        got.extend_from_slice(&buf[..read]);
    }
    assert_eq!(got, b"2345");
    let seen = server.seen.lock().unwrap();
    assert!(seen[1].contains("range: bytes=2-5"));
    assert!(seen[1].contains("if-range: \"v1\""));
    assert!(seen[1].contains("authorization: Bearer SECRET"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_representation_is_never_appended() {
    let probe = || {
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 0-9/10"), ("ETag", "\"v1\"")],
            b"0123456789",
        )
    };
    for answer in [
        // The whole file instead of the range.
        response("200 OK", &[("ETag", "\"v1\"")], b"0123456789"),
        // A different validator.
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 2-5/10"), ("ETag", "\"v2\"")],
            b"2345",
        ),
        // Someone else's range.
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 3-6/10"), ("ETag", "\"v1\"")],
            b"3456",
        ),
        // A different total.
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 2-5/11"), ("ETag", "\"v1\"")],
            b"2345",
        ),
    ] {
        let server = serve(vec![probe(), answer]);
        let transport = new_transport();
        bind(&transport, server.port, vec![]);
        let probe = transport.probe(source()).await.unwrap();
        assert_eq!(
            transport
                .fetch(source(), ByteRange::new(2, 6).unwrap(), probe.validator())
                .await
                .err(),
            Some(TransportError::RepresentationChanged)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn statuses_and_codings_map_to_outcomes() {
    for (status, headers, expected) in [
        (
            "429 Too Many Requests",
            vec![("Retry-After", "7")],
            TransportError::Throttled {
                retry_after_ms: Some(7000),
            },
        ),
        (
            "503 Service Unavailable",
            vec![],
            TransportError::Throttled {
                retry_after_ms: None,
            },
        ),
        (
            "500 Internal Server Error",
            vec![],
            TransportError::Transient,
        ),
        (
            "401 Unauthorized",
            vec![],
            TransportError::UserAction(StopReason::Authentication),
        ),
        (
            "404 Not Found",
            vec![],
            TransportError::UserAction(StopReason::SourceChanged),
        ),
        (
            "200 OK",
            vec![("Content-Encoding", "gzip")],
            TransportError::Fatal(StopReason::Policy),
        ),
    ] {
        let server = serve(vec![response(status, &headers, b"body")]);
        let transport = new_transport();
        bind(&transport, server.port, vec![]);
        assert_eq!(
            transport.probe(source()).await.err(),
            Some(expected),
            "{status}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_range_answer_longer_than_asked_is_refused() {
    let server = serve(vec![
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 0-9/10"), ("ETag", "\"v1\"")],
            b"0123456789",
        ),
        // Claims the right range but announces six bytes for a four-byte window.
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 2-5/10"), ("ETag", "\"v1\"")],
            b"234567",
        ),
    ]);
    let transport = new_transport();
    bind(&transport, server.port, vec![]);
    let probe = transport.probe(source()).await.unwrap();
    assert_eq!(
        transport
            .fetch(source(), ByteRange::new(2, 6).unwrap(), probe.validator())
            .await
            .err(),
        Some(TransportError::RepresentationChanged)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirects_need_permission_and_never_carry_credentials_away() {
    let elsewhere = serve(vec![response(
        "206 Partial Content",
        &[("Content-Range", "bytes 0-9/10"), ("ETag", "\"v1\"")],
        b"0123456789",
    )]);
    let redirect = |port: u16| {
        response(
            "302 Found",
            &[("Location", &format!("http://127.0.0.1:{port}/moved"))],
            b"",
        )
    };
    // Unlisted origin: refused.
    let server = serve(vec![redirect(elsewhere.port)]);
    let transport = new_transport();
    bind(&transport, server.port, vec![]);
    assert_eq!(
        transport.probe(source()).await.err(),
        Some(TransportError::Fatal(StopReason::Policy))
    );

    // Allowed origin: followed, and the credential stays behind.
    let server = serve(vec![redirect(elsewhere.port)]);
    let transport = new_transport();
    bind(
        &transport,
        server.port,
        vec![format!("http://127.0.0.1:{}", elsewhere.port)],
    );
    let probe = transport.probe(source()).await.unwrap();
    assert_eq!(probe.total(), 10);
    let followed = &elsewhere.seen.lock().unwrap()[0];
    assert!(!followed.contains("authorization"), "credential leaked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_body_times_out_as_transient() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        // One thread per connection: a stalled body must not block the next request.
        while let Ok((mut stream, _)) = listener.accept() {
            std::thread::spawn(move || {
                read_request(&mut stream);
                let _ = stream.write_all(
                    b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-9/10\r\nETag: \"v1\"\r\nContent-Length: 10\r\n\r\n01234",
                );
                let _ = stream.flush();
                // Never sends the rest, and never closes.
                std::thread::sleep(Duration::from_secs(5));
            });
        }
    });
    let transport = new_transport();
    bind(&transport, port, vec![]);
    let probe = transport.probe(source()).await.unwrap();
    assert_eq!(probe.total(), 10);
    let mut stream = transport
        .fetch(source(), ByteRange::new(0, 10).unwrap(), probe.validator())
        .await
        .unwrap();
    let mut buf = [0u8; 16];
    let mut outcome = Ok(0);
    for _ in 0..4 {
        outcome = stream.read(&mut buf).await;
        if outcome.is_err() {
            break;
        }
    }
    assert_eq!(outcome, Err(TransportError::Transient));
}

#[test]
fn bindings_reject_unsafe_sources_and_hide_their_contents() {
    for url in [
        "file:///etc/passwd",
        "https://user:pass@example.test/a",
        "https://example.test/a#part",
        "https://example.test/\na",
    ] {
        assert!(
            SourceBinding::new(url, None, None, false, vec![]).is_err(),
            "{url}"
        );
    }
    assert!(SourceBinding::new("http://example.test/a", None, None, false, vec![]).is_err());
    assert!(SourceBinding::new(
        "https://example.test/a",
        Some("Bearer x\r\nHost: evil".into()),
        None,
        false,
        vec![]
    )
    .is_err());
    let binding = SourceBinding::new(
        "https://example.test/private?token=SECRET",
        Some("Bearer SECRET".into()),
        None,
        false,
        vec![],
    )
    .unwrap();
    let shown = format!("{binding:?}");
    assert!(!shown.contains("SECRET") && !shown.contains("example.test"));
}

/// Reads until the stream ends or errors.
async fn drain(
    stream: &mut Box<dyn fhd_app::transport::ByteStream>,
) -> Result<Vec<u8>, TransportError> {
    let mut got = Vec::new();
    let mut buf = [0u8; 8];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => return Ok(got),
            Ok(read) => got.extend_from_slice(&buf[..read]),
            Err(error) => return Err(error),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_chunks_are_not_an_ending_and_extra_bytes_are_refused() {
    // Chunked framing lets the server send an empty chunk mid-body, then overrun.
    let probe = response(
        "206 Partial Content",
        &[("Content-Range", "bytes 0-9/10"), ("ETag", "\"v1\"")],
        b"0123456789",
    );
    let chunked = |body: &str| {
        format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 2-5/10\r\nETag: \"v1\"\r\nTransfer-Encoding: chunked\r\n\r\n{body}"
        )
        .into_bytes()
    };
    // "23" then an empty chunk then "45": four bytes, exactly the range.
    let server = serve(vec![probe.clone(), chunked("2\r\n23\r\n0\r\n\r\n")]);
    let transport = new_transport();
    bind(&transport, server.port, vec![]);
    let validator = transport.probe(source()).await.unwrap().validator();
    let mut stream = transport
        .fetch(source(), ByteRange::new(2, 6).unwrap(), validator)
        .await
        .unwrap();
    // The body ended two bytes early: never reported as a clean end.
    assert_eq!(drain(&mut stream).await, Err(TransportError::Transient));

    // More bytes than the window were asked for.
    let server = serve(vec![probe, chunked("6\r\n234567\r\n0\r\n\r\n")]);
    let transport = new_transport();
    bind(&transport, server.port, vec![]);
    let validator = transport.probe(source()).await.unwrap().validator();
    let mut stream = transport
        .fetch(source(), ByteRange::new(2, 6).unwrap(), validator)
        .await
        .unwrap();
    assert_eq!(drain(&mut stream).await, Err(TransportError::Transient));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fetch_belongs_to_the_representation_the_caller_holds() {
    let server = serve(vec![
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 0-9/10"), ("ETag", "\"v1\"")],
            b"0123456789",
        ),
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 0-9/10"), ("ETag", "\"v2\"")],
            b"abcdefghij",
        ),
    ]);
    let transport = new_transport();
    bind(&transport, server.port, vec![]);
    let first = transport.probe(source()).await.unwrap().validator();
    // A newer probe replaced the representation; the old job must not be served.
    let second = transport.probe(source()).await.unwrap().validator();
    assert_ne!(first, second);
    assert_eq!(
        transport
            .fetch(source(), ByteRange::new(2, 6).unwrap(), first)
            .await
            .err(),
        Some(TransportError::RepresentationChanged)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_validator_only_the_whole_file_may_be_fetched() {
    let whole = || response("200 OK", &[], b"0123456789");
    let server = serve(vec![whole(), whole()]);
    let transport = new_transport();
    bind(&transport, server.port, vec![]);
    let probe = transport.probe(source()).await.unwrap();
    assert_eq!(probe.validator(), None);
    // A resumed range cannot be proven to match anything: refused before any request.
    assert_eq!(
        transport
            .fetch(source(), ByteRange::new(4, 10).unwrap(), None)
            .await
            .err(),
        Some(TransportError::RepresentationChanged)
    );
    let mut stream = transport
        .fetch(source(), ByteRange::new(0, 10).unwrap(), None)
        .await
        .unwrap();
    assert_eq!(drain(&mut stream).await.unwrap(), b"0123456789");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_ranges_and_unsatisfiable_requests_are_refused() {
    let probe = || {
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 0-9/10"), ("ETag", "\"v1\"")],
            b"0123456789",
        )
    };
    for answer in [
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 2-5"), ("ETag", "\"v1\"")],
            b"2345",
        ),
        response(
            "206 Partial Content",
            &[("Content-Range", "items 2-5/10"), ("ETag", "\"v1\"")],
            b"2345",
        ),
        response(
            "206 Partial Content",
            &[("Content-Range", "bytes 2-5/*"), ("ETag", "\"v1\"")],
            b"2345",
        ),
        response("416 Range Not Satisfiable", &[], b""),
    ] {
        let server = serve(vec![probe(), answer]);
        let transport = new_transport();
        bind(&transport, server.port, vec![]);
        let validator = transport.probe(source()).await.unwrap().validator();
        assert_eq!(
            transport
                .fetch(source(), ByteRange::new(2, 6).unwrap(), validator)
                .await
                .err(),
            Some(TransportError::RepresentationChanged)
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reference_is_bound_once_and_can_be_forgotten() {
    let transport = new_transport();
    let binding =
        || SourceBinding::new("https://example.test/a", None, None, false, vec![]).unwrap();
    transport.bind(source(), binding()).unwrap();
    assert!(transport.bind(source(), binding()).is_err());
    transport.unbind(source());
    transport.bind(source(), binding()).unwrap();
}
