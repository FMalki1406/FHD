//! The engine as a program, not as a library.
//!
//! Every other suite here calls `Engine::open` or drives `Resident` in-process,
//! so nothing exercises what an operator actually touches: argument parsing, the
//! dispatch between one-shot and `--serve` and `--client`, standard input as the
//! only channel for a link, exit codes, and the control surface between two real
//! processes. A regression in any of those would have left the whole suite green.
mod harness;

use harness::{content, expected_digest, serve, Directory};
use std::{
    io::Write,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// The binary under test, resolved by Cargo for this crate's `[[bin]]`.
fn engine() -> &'static str {
    env!("CARGO_BIN_EXE_fhd-engine")
}

/// Runs the engine to completion with `stdin` piped in, and returns
/// (exit code, stdout, stderr). A test that unwraps the status alone would not
/// say why a failure happened, and these runs fail in ways worth reading.
fn run(arguments: &[&str], stdin: &str) -> (Option<i32>, String, String) {
    let mut child = Command::new(engine())
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the engine binary is built and runnable");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(stdin.as_bytes())
        .expect("write the link");
    let output = child.wait_with_output().expect("the engine exits");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// One file, fetched and published by the program itself.
///
/// This is the path an operator runs. It proves the argument parser accepts what
/// the usage text promises, that a link read from standard input reaches the
/// transport, and that a successful run leaves a correct file and exits zero.
#[test]
fn the_program_downloads_and_publishes_a_file() {
    let state = Directory::new("process-oneshot");
    let body = content(64 * 1024);
    let (port, _) = serve(body.clone(), 0);
    let destination = state.0.join("downloaded.bin");
    let digest = expected_digest(&body);

    let (code, out, err) = run(
        &[
            &state.engine().to_string_lossy(),
            &destination.to_string_lossy(),
            "--allow-http",
            "--sha256",
            &hex(&digest),
        ],
        &format!("http://127.0.0.1:{port}/file\n"),
    );

    assert_eq!(code, Some(0), "stdout: {out}\nstderr: {err}");
    let published = std::fs::read(&destination).expect("the file is where it was asked for");
    assert_eq!(published, body, "the published bytes are the served bytes");
}

/// The digest the operator supplies is honoured, not decorative.
///
/// Without this, `--sha256` could be parsed and dropped and every other test
/// would still pass, because the bytes would be right anyway.
#[test]
fn a_wrong_digest_on_the_command_line_fails_the_run() {
    let state = Directory::new("process-digest");
    let body = content(32 * 1024);
    let (port, _) = serve(body, 0);
    let destination = state.0.join("downloaded.bin");

    let (code, _, err) = run(
        &[
            &state.engine().to_string_lossy(),
            &destination.to_string_lossy(),
            "--allow-http",
            "--sha256",
            &hex(&[0x11; 32]),
        ],
        &format!("http://127.0.0.1:{port}/file\n"),
    );

    assert_ne!(code, Some(0), "a mismatched digest must not exit zero");
    assert!(!destination.exists(), "nothing is published: {err}");
}

/// Plain HTTP without `--allow-http` is refused before anything is fetched.
///
/// The flag is a policy decision the engine makes, so asking for a cleartext
/// link without it has to fail rather than quietly succeed.
#[test]
fn cleartext_is_refused_unless_the_operator_asks_for_it() {
    let state = Directory::new("process-cleartext");
    let body = content(8 * 1024);
    let (port, served) = serve(body, 0);
    let destination = state.0.join("downloaded.bin");

    let (code, _, _) = run(
        &[
            &state.engine().to_string_lossy(),
            &destination.to_string_lossy(),
        ],
        &format!("http://127.0.0.1:{port}/file\n"),
    );

    assert_ne!(code, Some(0), "cleartext without the flag must fail");
    assert!(!destination.exists());
    assert_eq!(
        served.load(std::sync::atomic::Ordering::Relaxed),
        0,
        "the refusal happens before any request is sent"
    );
}

/// An unknown sub-command prints the usage and exits 2, rather than being
/// mistaken for a destination path and creating a file named after it.
#[test]
fn an_unknown_client_command_is_refused_with_usage() {
    let state = Directory::new("process-usage");
    let (code, _, err) = run(
        &[&state.engine().to_string_lossy(), "--client", "frobnicate"],
        "",
    );
    assert_eq!(code, Some(2));
    assert!(err.contains("usage:"), "stderr was: {err}");
}

/// Two processes over the real control surface: one serving, one commanding.
///
/// This is the only test anywhere that opens the pipe or socket between separate
/// processes. In-process tests share a runtime and never cross that boundary, so
/// peer identity, framing and the client's own refusal path are untested without
/// it.
#[test]
fn a_client_process_commands_a_serving_process() {
    let state = Directory::new("process-serve");
    let root = state.0.join("downloads");
    std::fs::create_dir_all(&root).unwrap();
    let body = content(48 * 1024);
    let (port, _) = serve(body.clone(), 0);

    let mut resident = Command::new(engine())
        .args([
            &state.engine().to_string_lossy() as &str,
            "--serve",
            "--download-root",
            &root.to_string_lossy(),
            "--allow-http",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the resident starts");

    // The surface appears when the resident is ready; polling it is the signal,
    // and a fixed sleep would be either flaky or slow.
    let destination = root.join("over-ipc.bin");
    let deadline = Instant::now() + Duration::from_secs(30);
    let accepted = loop {
        let (code, out, _) = run(
            &[
                &state.engine().to_string_lossy(),
                "--client",
                "add",
                &destination.to_string_lossy(),
                "--allow-http",
            ],
            &format!("http://127.0.0.1:{port}/file\n"),
        );
        if code == Some(0) {
            break out;
        }
        assert!(
            Instant::now() < deadline,
            "the control surface never accepted a client"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(accepted.starts_with("accepted "), "got: {accepted}");

    // The job is visible to a second, separate client process.
    let (code, listed, _) = run(&[&state.engine().to_string_lossy(), "--client", "list"], "");
    assert_eq!(code, Some(0));
    assert!(!listed.trim().is_empty(), "list returned nothing");

    let deadline = Instant::now() + Duration::from_secs(60);
    while !destination.exists() {
        assert!(Instant::now() < deadline, "the download never published");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(std::fs::read(&destination).unwrap(), body);

    // Shutdown travels over the same surface, and the process actually leaves.
    let (code, _, _) = run(&[&state.engine().to_string_lossy(), "--client", "stop"], "");
    assert_eq!(code, Some(0));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match resident.try_wait().expect("wait on the resident") {
            Some(status) => {
                assert!(status.success(), "the resident exited with {status}");
                break;
            }
            None => {
                assert!(
                    Instant::now() < deadline,
                    "the resident ignored a shutdown over the control surface"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// A client with no engine behind the directory reports it and exits non-zero,
/// instead of hanging or pretending the command was taken.
#[test]
fn a_client_without_an_engine_fails_promptly() {
    let state = Directory::new("process-noengine");
    std::fs::create_dir_all(state.engine()).unwrap();
    let started = Instant::now();
    let (code, _, err) = run(&[&state.engine().to_string_lossy(), "--client", "list"], "");
    assert_ne!(code, Some(0));
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "it should not hang: {err}"
    );
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
