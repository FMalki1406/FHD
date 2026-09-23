//! Operator entry point for the new engine: one job, driven to rest.
//! Ctrl+C pauses durably rather than killing the transfer.
#![forbid(unsafe_code)]

use fhd_daemon::{
    absolute, read_requests, Engine, EngineConfig, EngineError, Intent, JobOutcome, StderrEvents,
};
use fhd_runtime::coordinator::{Control, SessionEnd};
use std::path::PathBuf;
use tokio::sync::mpsc;

fn usage() -> &'static str {
    "usage: fhd-engine <state-directory> <destination-file> [--connections N] \
     [--engine-connections N] [--max-active N] [--max-bytes N] [--sha256 HEX] \
     [--allow-http] [--resume] [--sensitive-link]   (one URL per line on stdin, \
     each optionally followed by a tab and its own destination file)\n\
     or:    fhd-engine <state-directory> --continue [--resume]   (no stdin: every \
     job this directory remembers)"
}

/// What the command line asked for: the engine's settings, whether links are to be
/// kept out of the database, and whether this run was told anything at all.
struct Invocation {
    config: EngineConfig,
    sensitive: bool,
    cont: bool,
}

fn parse() -> Result<Invocation, &'static str> {
    let mut args = std::env::args().skip(1);
    let state_directory = PathBuf::from(args.next().ok_or(usage())?);
    let second = args.next().ok_or(usage())?;
    let cont = second == "--continue";
    // Continuing needs no destination: every job kept its own.
    let destination = if cont {
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
            // A signed link is a credential: remember the job, not the link.
            "--sensitive-link" => sensitive = true,
            // Releasing a stopped job is the operator's decision, never automatic.
            "--resume" => config.intent = Intent::Resume,
            _ => return Err(usage()),
        }
    }
    Ok(Invocation {
        config,
        sensitive,
        cont,
    })
}

#[tokio::main]
async fn main() {
    // Engine events go to standard error; the published path goes to standard output.
    let _ = tracing::subscriber::set_global_default(StderrEvents);
    let Invocation {
        config,
        sensitive,
        cont,
    } = match parse() {
        Ok(invocation) => invocation,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    if cont {
        continue_run(config).await;
    }
    let requests = match read_requests(std::io::stdin(), &config.destination) {
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
        Ok(SessionEnd::Published(path)) => println!("published {}", path.display()),
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
            JobOutcome::Published(path) => println!("{index} published {}", path.display()),
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

/// Only controlled categories reach the operator: never a URL or server text.
fn code(error: &EngineError) -> String {
    match error {
        EngineError::InvalidInput => "ENGINE-INVALID-INPUT".into(),
        EngineError::NothingToContinue => "NOTHING-TO-CONTINUE".into(),
        EngineError::CrossVolume => "DESTINATION-OTHER-VOLUME".into(),
        EngineError::NeedsDecision(reason) => match reason {
            Some(reason) => format!("STOPPED-{reason:?}-RERUN-WITH-RESUME").to_uppercase(),
            None => "STOPPED-RERUN-WITH-RESUME".into(),
        },
        EngineError::Persistence(error) => error.code().into(),
        EngineError::Binding(error) => format!("SOURCE-{error:?}").to_uppercase(),
        EngineError::Admission(error) => error.code().into(),
        EngineError::Run(error) => format!("RUN-{error:?}").to_uppercase(),
    }
}
