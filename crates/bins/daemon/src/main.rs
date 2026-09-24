//! Operator entry point for the new engine: one job, driven to rest.
//! Ctrl+C pauses durably rather than killing the transfer.
#![forbid(unsafe_code)]

use fhd_daemon::{
    absolute, code, read_requests, read_url, Engine, EngineConfig, EngineError, Intent, JobOutcome,
    Resident, StderrEvents,
};
use fhd_protocol::{AddRequest, Request, Response};
use fhd_runtime::coordinator::{Control, SessionEnd};
use std::path::PathBuf;
use tokio::sync::mpsc;

fn usage() -> &'static str {
    "usage: fhd-engine <state-directory> <destination-file> [--connections N] \
     [--engine-connections N] [--max-active N] [--max-bytes N] [--sha256 HEX] \
     [--allow-http] [--resume] [--sensitive-link]   (one URL per line on stdin, \
     each optionally followed by a tab and its own destination file)\n\
     or:    fhd-engine <state-directory> --continue [--resume]   (no stdin: every \
     job this directory remembers)\n\
     or:    fhd-engine <state-directory> --serve --download-root DIR \
     [--allow-http]   (resident: takes work over this user's control surface; \
     downloads may land only under DIR)\n\
     or:    fhd-engine <state-directory> --client <command>   where command is \
     add <destination-file> [--sensitive] [--allow-http] (URL on stdin), list,      pause <job>, \
     cancel <job>, or stop"
}

/// What the command line asked for: the engine's settings, whether links are to be
/// kept out of the database, and whether this run was told anything at all.
struct Invocation {
    config: EngineConfig,
    sensitive: bool,
    cont: bool,
    serve: bool,
}

fn parse() -> Result<Invocation, &'static str> {
    let mut args = std::env::args().skip(1);
    let state_directory = PathBuf::from(args.next().ok_or(usage())?);
    let second = args.next().ok_or(usage())?;
    if second == "--client" {
        return Err("client");
    }
    let cont = second == "--continue";
    let serve = second == "--serve";
    // Neither continuing nor serving needs a destination: each job carries its own.
    let destination = if cont || serve {
        state_directory.clone()
    } else {
        PathBuf::from(second)
    };
    let mut sensitive = false;
    let mut config = EngineConfig {
        state_directory: absolute(&state_directory).map_err(|_| "invalid state directory")?,
        destination: absolute(&destination).map_err(|_| "invalid destination")?,
        connections: 4,
        engine_connections: 8,
        max_active: 4,
        expected_sha256: None,
        max_bytes: 100 * 1024 * 1024 * 1024,
        allow_http: false,
        download_root: None,
        intent: Intent::Start,
    };
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--connections" => {
                config.connections = args
                    .next()
                    .ok_or("missing connection count")?
                    .parse()
                    .map_err(|_| "invalid connection count")?
            }
            "--max-bytes" => {
                config.max_bytes = args
                    .next()
                    .ok_or("missing maximum size")?
                    .parse()
                    .map_err(|_| "invalid maximum size")?
            }
            "--sha256" => {
                let hex = args.next().ok_or("missing checksum")?;
                if hex.len() != 64 || !hex.is_ascii() {
                    return Err("invalid checksum");
                }
                let mut digest = [0u8; 32];
                for (index, byte) in digest.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16)
                        .map_err(|_| "invalid checksum")?;
                }
                config.expected_sha256 = Some(digest);
            }
            "--engine-connections" => {
                config.engine_connections = args
                    .next()
                    .ok_or("missing engine connection count")?
                    .parse()
                    .map_err(|_| "invalid engine connection count")?
            }
            "--max-active" => {
                config.max_active = args
                    .next()
                    .ok_or("missing active job count")?
                    .parse()
                    .map_err(|_| "invalid active job count")?
            }
            "--allow-http" => config.allow_http = true,
            // Policy for a resident engine: clients may land files here and
            // nowhere else, whatever they ask for.
            "--download-root" => {
                let root = PathBuf::from(args.next().ok_or("missing download root")?);
                config.download_root = Some(absolute(&root).map_err(|_| "invalid download root")?);
            }
            // A signed link is a credential: remember the job, not the link.
            "--sensitive-link" => sensitive = true,
            // Releasing a stopped job is the operator's decision, never automatic.
            "--resume" => config.intent = Intent::Resume,
            _ => return Err(usage()),
        }
    }
    // Flags only one mode reads are refused in the others. Accepting one where
    // nothing looks at it is the same silent drop that let `--sha256` be parsed,
    // validated and then ignored: the operator asks for something, is told
    // nothing, and does not get it.
    //
    // A checksum belongs to one request the operator named. `--continue` is every
    // job the directory remembers and `--serve` is whatever a client asks for
    // later, so neither has a request to attach it to.
    if (cont || serve) && config.expected_sha256.is_some() {
        return Err("--sha256 belongs to a single request");
    }
    // The download root confines where a *client* may land files, so only a
    // resident engine acts on it. Elsewhere it reads like a confinement that is
    // not there, which is worse than not offering it.
    if !serve && config.download_root.is_some() {
        return Err("--download-root belongs to --serve");
    }
    // A link is kept off the disk for the request being made now. `--continue`
    // replays what is already recorded and `--serve` takes each request over the
    // wire with its own flag, so neither reads this one.
    if (cont || serve) && sensitive {
        return Err("--sensitive-link belongs to a single request");
    }
    // Releasing a stopped job is decided per run of the engine itself; a resident
    // takes that decision from a client instead, and never reads this.
    if serve && config.intent == Intent::Resume {
        return Err("--resume belongs to a run that drives jobs itself");
    }
    Ok(Invocation {
        config,
        sensitive,
        cont,
        serve,
    })
}

/// Speaks to a resident engine on this user's control surface. One request, one
/// answer, then it leaves: a client holds nothing open.
async fn client_run(state: PathBuf, mut args: impl Iterator<Item = String>) -> ! {
    let command = args.next().unwrap_or_default();
    let request = match command.as_str() {
        "add" => {
            let destination = match args.next() {
                Some(destination) => match absolute(&PathBuf::from(destination)) {
                    Ok(path) => path,
                    Err(_) => fail("ENGINE-INVALID-INPUT"),
                },
                None => fail("ENGINE-INVALID-INPUT"),
            };
            // Refused rather than ignored, exactly as the engine's own parser
            // does. Swallowing the rest meant a one-character typo in
            // `--sensitive` wrote the link to disk in cleartext and still
            // reported success -- the flag exists precisely to keep a signed URL
            // off the disk, and the operator had no way to tell it had not
            // applied.
            let mut sensitive = false;
            let mut allow_http = false;
            for argument in args {
                match argument.as_str() {
                    "--sensitive" => sensitive = true,
                    // A client may ask for cleartext; the engine still decides
                    // whether it is allowed, so asking is not the same as getting.
                    "--allow-http" => allow_http = true,
                    _ => {
                        eprintln!("{}", usage());
                        std::process::exit(2);
                    }
                }
            }
            // The link comes on standard input, never as an argument: arguments
            // are visible to every process on the machine.
            let Ok(url) = read_url(std::io::stdin()) else {
                fail("ENGINE-INVALID-INPUT")
            };
            Request::Add(AddRequest {
                url,
                destination: destination.to_string_lossy().into_owned(),
                sensitive,
                expected_sha256: None,
                max_bytes: 100 * 1024 * 1024 * 1024,
                allow_http,
            })
        }
        "list" => {
            refuse_extra(args);
            Request::List { after: None }
        }
        "pause" | "cancel" => {
            let Some(job) = args.next().and_then(|job| job.parse::<u64>().ok()) else {
                fail("ENGINE-INVALID-INPUT")
            };
            // One command names one job. `cancel 3 7` used to cancel 3, print
            // "done" and exit zero, leaving the operator believing both were
            // cancelled -- and this refusal happens before anything is sent.
            refuse_extra(args);
            if command == "pause" {
                Request::Pause { job }
            } else {
                Request::Cancel { job }
            }
        }
        "stop" => {
            refuse_extra(args);
            Request::Shutdown
        }
        _ => {
            eprintln!("{}", usage());
            std::process::exit(2);
        }
    };
    let Ok(state) = absolute(&state) else {
        fail("ENGINE-INVALID-INPUT")
    };
    let endpoint = fhd_ipc::Endpoint::for_user(&endpoint_name(&state));
    let mut connection = match fhd_ipc::connect(&endpoint).await {
        Ok(connection) => connection,
        // Nothing is listening for this directory, or it is not ours.
        Err(error) => fail(error.code()),
    };
    match fhd_ipc::ask(&mut connection, 1, &request).await {
        Ok(Response::Accepted { job, warnings }) => {
            for warning in &warnings {
                // The service decided this; the client says it, so adding a
                // download through the service warns like adding one directly.
                eprintln!("{warning}");
                if warning == "DESTINATION-SHARED" {
                    eprintln!(
                        "  other accounts on this machine can change files in this folder. \n                         the download is protected while it runs; the finished file is not."
                    );
                }
            }
            println!("accepted {job}");
            std::process::exit(0)
        }
        Ok(Response::Done) => {
            println!("done");
            std::process::exit(0)
        }
        Ok(Response::Jobs { jobs, next }) => {
            for job in jobs {
                let reason = job.reason.unwrap_or_default();
                println!(
                    "{} {} {}/{} {}",
                    job.job,
                    printable(&job.state),
                    job.durable_bytes,
                    job.total.map_or("?".to_owned(), |total| total.to_string()),
                    printable(&reason)
                );
            }
            if let Some(next) = next {
                println!("more after {next}");
            }
            std::process::exit(0)
        }
        Ok(Response::Failed { code }) => fail(&code),
        Err(error) => fail(error.code()),
    }
}

/// Refuses anything left over after a client command has taken what it needs.
///
/// Silence here is the defect this closes: an argument that is collected and
/// never looked at tells the operator their instruction was accepted.
fn refuse_extra(rest: impl Iterator<Item = String>) {
    if rest.count() > 0 {
        eprintln!("{}", usage());
        std::process::exit(2);
    }
}

/// The engine's answer to an operator is a code, never a sentence assembled from
/// whatever went wrong.
fn fail(code: &str) -> ! {
    eprintln!("{}", printable(code));
    std::process::exit(1)
}

/// What a peer sent is data, and this is a terminal. An answer carrying escape
/// sequences could retitle the window or paste into the shell, and an engine is
/// not the only thing that can answer on a socket.
fn printable(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).take(64).collect()
}

#[tokio::main]
async fn main() {
    // Engine events go to standard error; the published path goes to standard output.
    let _ = tracing::subscriber::set_global_default(StderrEvents);
    let Invocation {
        config,
        sensitive,
        cont,
        serve,
    } = match parse() {
        Ok(invocation) => invocation,
        // The client path shares only the state directory with the engine's own
        // settings, so it is parsed where it is used.
        Err("client") => {
            let mut args = std::env::args().skip(1);
            let state = PathBuf::from(args.next().unwrap_or_default());
            let _ = args.next();
            client_run(state, args).await
        }
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    if serve {
        serve_run(config).await;
    }
    if cont {
        continue_run(config).await;
    }
    let mut requests = match read_requests(std::io::stdin(), &config.destination) {
        Ok(mut requests) => {
            for request in &mut requests {
                request.sensitive = sensitive;
            }
            requests
        }
        Err(_) => {
            eprintln!("expected one URL per line on stdin");
            std::process::exit(2);
        }
    };
    // A checksum on the command line belongs to a single request; several requests
    // would each need their own, which this entry point does not take yet.
    if requests.len() > 1 && config.expected_sha256.is_some() {
        eprintln!("ENGINE-INVALID-INPUT");
        std::process::exit(2);
    }
    // And it has to reach that request. `read_requests` cannot know about a flag
    // parsed from the command line, so it leaves the field empty; applying it here
    // is what makes `--sha256` mean anything. Without this the engine verified the
    // bytes against its own record, published the file and exited zero while the
    // digest the operator gave it was never compared to anything.
    if let Some(expected) = config.expected_sha256 {
        // Total on purpose: `if let ... {}` with no else would re-encode "a digest
        // with nowhere to go is discarded quietly", which is the defect this
        // exists to close. `read_requests` cannot return an empty list today, and
        // this stays correct if that ever changes.
        match requests.first_mut() {
            Some(request) => request.expected_sha256 = Some(expected),
            None => {
                eprintln!("ENGINE-INVALID-INPUT");
                std::process::exit(2);
            }
        }
    }
    warn_about_shared_destinations(&requests);
    let several = requests.len() > 1;
    let engine = match Engine::open_many(config, requests).await {
        Ok(engine) => engine,
        Err(error) => {
            eprintln!("{}", code(&error));
            std::process::exit(2);
        }
    };
    let (control, receiver) = mpsc::channel(1);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            // Durable pause: progress already committed is kept.
            let _ = control.send(Control::Pause).await;
        }
        // A second interrupt leaves immediately; committed progress is already safe.
        if tokio::signal::ctrl_c().await.is_ok() {
            std::process::exit(130);
        }
        std::future::pending::<()>().await;
    });
    if several {
        let (_keep, commands) = mpsc::channel(4);
        match engine.run_all(commands).await {
            Ok(outcomes) => std::process::exit(report(outcomes)),
            Err(error) => {
                eprintln!("{}", code(&error));
                std::process::exit(2);
            }
        }
    }
    match engine.run(receiver).await {
        Ok(SessionEnd::Published(outcome)) => println!("published {outcome}"),
        Ok(SessionEnd::Settled(state)) => {
            println!("stopped in {state:?}");
            std::process::exit(if state == fhd_domain::JobState::Completed {
                0
            } else {
                1
            });
        }
        Err(error) => {
            eprintln!("{}", code(&error));
            std::process::exit(2);
        }
    }
}

/// Runs as a resident engine: takes work over this user's control surface until a
/// client asks it to stop or the operator interrupts.
async fn serve_run(config: EngineConfig) -> ! {
    // A resident engine takes destinations from whoever connects, so where those
    // may land is policy, not an option. Without it the engine would accept any
    // path on its volume, which is a fail-open default; it refuses to start.
    if config.download_root.is_none() {
        eprintln!("--serve requires --download-root");
        std::process::exit(2);
    }
    let name = endpoint_name(&config.state_directory);
    let resident = match Resident::open(config).await {
        Ok(resident) => resident,
        Err(error) => {
            eprintln!("{}", code(&error));
            std::process::exit(2);
        }
    };
    let serving = match resident.bind(fhd_ipc::Endpoint::for_user(&name)) {
        Ok(serving) => serving,
        Err(error) => {
            eprintln!("{}", code(&error));
            std::process::exit(2);
        }
    };
    // Printed only once the endpoint is live, so a caller may use it at once.
    println!("listening {}", serving.endpoint().0);
    // Interrupting a resident engine stops the listener; running jobs come to rest
    // durably rather than being killed.
    let stop = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    match serving.serve(stop).await {
        Ok(()) => std::process::exit(0),
        Err(error) => {
            eprintln!("{}", code(&error));
            std::process::exit(2);
        }
    }
}

/// One endpoint per state directory, named by a digest of its path: two engines on
/// one machine never collide, and the name itself carries no path.
fn endpoint_name(state: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"FHD.endpoint.v1");
    hash.update(state.to_string_lossy().as_bytes());
    let digest: [u8; 32] = hash.finalize().into();
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Continues every job this state directory remembers, with no link supplied now.
async fn continue_run(config: EngineConfig) -> ! {
    let engine = match Engine::reopen(config).await {
        Ok(engine) => engine,
        Err(error) => {
            eprintln!("{}", code(&error));
            std::process::exit(2);
        }
    };
    let (_keep, commands) = mpsc::channel(4);
    match engine.run_all(commands).await {
        Ok(outcomes) => std::process::exit(report(outcomes)),
        Err(error) => {
            eprintln!("{}", code(&error));
            std::process::exit(2);
        }
    }
}

/// Prints one line per request and says whether anything is still unfinished.
fn report(outcomes: Vec<(usize, JobOutcome)>) -> i32 {
    let mut failed = false;
    for (index, outcome) in outcomes {
        match outcome {
            JobOutcome::Published(outcome) => println!("{index} published {outcome}"),
            JobOutcome::Settled(state, reason) => {
                failed |= state != fhd_domain::JobState::Completed;
                match reason {
                    Some(reason) => println!("{index} stopped in {state:?} ({reason:?})"),
                    None => println!("{index} stopped in {state:?}"),
                }
            }
            JobOutcome::NeedsDecision(reason) => {
                failed = true;
                println!("{index} {}", code(&EngineError::NeedsDecision(reason)));
            }
            JobOutcome::Failed(error) => {
                failed = true;
                println!("{index} {}", code(&EngineError::Run(error)));
            }
        }
    }
    i32::from(failed)
}

/// Says once, for each folder, that other accounts on this machine can change
/// what lands in it.
///
/// The engine protects a download while it is in progress: the part file lives
/// in a directory it created with its own access list, and a second account is
/// denied everything in it. Once the finished file is delivered into a folder
/// others can write, that protection ends -- and nothing the engine does
/// afterwards can extend it, because the file is theirs to reach.
///
/// Not a refusal. A folder every account can write is the stock arrangement on
/// a data volume, so refusing would refuse most downloads to a second disk,
/// which is what this engine exists to allow. Not per download either: it is a
/// property of the folder, and repeating it per file trains people to skip it.
///
/// Until there is an interface to say it in, it is said here, because a limit
/// that lives only in a source comment is not a declared limit.
fn warn_about_shared_destinations(requests: &[fhd_daemon::Request]) {
    let mut told: Vec<std::path::PathBuf> = Vec::new();
    for request in requests {
        let Some(folder) = request.destination.parent() else {
            continue;
        };
        if told.iter().any(|seen| seen == folder) {
            continue;
        }
        // The same decision the service path uses, so the two cannot drift.
        if fhd_daemon::shared_destination_warnings(folder).is_empty() {
            continue;
        }
        told.push(folder.to_path_buf());
        eprintln!("DESTINATION-SHARED {}", folder.display());
        eprintln!(
            "  other accounts on this machine can change files in this folder.              the download is protected while it runs; the finished file is not."
        );
    }
}
