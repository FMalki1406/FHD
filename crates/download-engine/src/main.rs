#![forbid(unsafe_code)]
use download_engine::{download, Error, Options};
use std::{
    io::{self, Read, Write},
    path::PathBuf,
};

fn arguments() -> Result<Options, &'static str> {
    let mut args = std::env::args().skip(1);
    let job_dir = PathBuf::from(args.next().ok_or("missing job directory")?);
    let output_name = args.next().ok_or("missing output name")?;
    let mut allow_http = false;
    let mut checkpoint_bytes = 1024 * 1024;
    let mut expected_sha256 = None;
    let mut max_download_bytes = 100 * 1024 * 1024 * 1024;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--allow-http" => allow_http = true,
            "--checkpoint-bytes" => {
                checkpoint_bytes = args
                    .next()
                    .ok_or("missing checkpoint size")?
                    .parse()
                    .map_err(|_| "invalid checkpoint size")?
            }
            "--max-bytes" => {
                max_download_bytes = args
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
                let mut bytes = [0; 32];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                        .map_err(|_| "invalid checksum")?;
                }
                expected_sha256 = Some(bytes);
            }
            _ => return Err("unknown option"),
        }
    }
    // URL via stdin so signed URLs are not exposed in process command lines.
    let mut input = Vec::new();
    io::stdin()
        .take(16_386)
        .read_to_end(&mut input)
        .map_err(|_| "cannot read URL")?;
    let url = String::from_utf8(input).map_err(|_| "invalid URL encoding")?;
    let url = url.trim_end_matches(['\r', '\n']).to_owned();
    if url.len() > 16_384 {
        return Err("URL too long");
    }
    Ok(Options {
        url,
        job_dir,
        output_name,
        expected_sha256,
        allow_http,
        checkpoint_bytes,
        max_download_bytes,
    })
}

#[tokio::main]
async fn main() {
    let options = match arguments() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(2);
        }
    };
    let (sender, cancel) = tokio::sync::watch::channel(false);
    let signal = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = sender.send(true);
        }
        std::future::pending::<()>().await;
    });
    let result = download(options, cancel, |bytes| {
        println!("checkpoint={bytes}");
        let _ = io::stdout().flush();
    })
    .await;
    signal.abort();
    match result {
        Ok(outcome) => println!(
            "completed bytes={} resumed_from={}",
            outcome.bytes, outcome.resumed_from
        ),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(if error == Error::Cancelled { 130 } else { 2 });
        }
    }
}
