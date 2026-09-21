//! Single-owner, single-connection transfer. No browser/IPC-facing API yet.
#![forbid(unsafe_code)]

use download_core::state::{Command, Download, DownloadId, Event};
use reqwest::{
    header::{self, HeaderMap, HeaderName},
    Client, Response, Url,
};
use resume_policy::{Decision, Field, ResponseHeaders, ResumeRequest, StrongEtag};
use std::{path::PathBuf, time::Duration};
use tokio::sync::watch;
use transfer_store::{Identity, Status, Store, StoreError};

pub struct Options {
    pub url: String,
    pub job_dir: PathBuf,
    pub output_name: String,
    pub expected_sha256: Option<[u8; 32]>,
    /// Explicit permission from a trusted local caller; never infer it from a web page.
    pub allow_http: bool,
    pub checkpoint_bytes: u64,
    pub max_download_bytes: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidOptions,
    InvalidUrl,
    InsecureHttp,
    RedirectLimit,
    RedirectOriginChange,
    Network,
    HttpStatus(u16),
    InvalidHeaders,
    RepresentationChanged,
    ResumeUnsupported,
    ResumeRejected,
    LocalStateMismatch,
    Storage,
    WorkerFailed,
    Cancelled,
    InvalidTransition,
    BodyLength,
    SizeLimit,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Only controlled categories. reqwest errors may embed signed URLs.
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Debug)]
pub struct Outcome {
    pub bytes: u64,
    pub resumed_from: u64,
    pub path: PathBuf,
}

fn parse_url(raw: &str, allow_http: bool) -> Result<Url, Error> {
    if raw.len() > 16_384 || raw.chars().any(char::is_control) {
        return Err(Error::InvalidUrl);
    }
    let url = Url::parse(raw).map_err(|_| Error::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::InvalidUrl);
    }
    if url.scheme() == "http" && !allow_http {
        return Err(Error::InsecureHttp);
    }
    Ok(url)
}

fn field<'a>(headers: &'a HeaderMap, name: HeaderName) -> Field<'a> {
    let all = headers.get_all(name);
    let mut values = all.iter();
    match (values.next(), values.next()) {
        (None, _) => Field::Missing,
        (Some(value), None) => Field::Single(value.as_bytes()),
        _ => Field::Repeated,
    }
}

fn length(headers: &HeaderMap) -> Result<u64, Error> {
    let Field::Single(value) = field(headers, header::CONTENT_LENGTH) else {
        return Err(Error::InvalidHeaders);
    };
    if value.is_empty() || value.len() > 20 {
        return Err(Error::InvalidHeaders);
    }
    value
        .iter()
        .try_fold(0u64, |n, b| {
            if !b.is_ascii_digit() {
                return Err(Error::InvalidHeaders);
            }
            n.checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(b - b'0')))
                .ok_or(Error::InvalidHeaders)
        })
        .and_then(|n| {
            if n <= i64::MAX as u64 {
                Ok(n)
            } else {
                Err(Error::InvalidHeaders)
            }
        })
}

fn validate_representation(headers: &HeaderMap) -> Result<(), Error> {
    match field(headers, header::CONTENT_ENCODING) {
        Field::Missing => {}
        Field::Single(value) if value.eq_ignore_ascii_case(b"identity") => {}
        _ => return Err(Error::InvalidHeaders),
    }
    if headers.contains_key(header::TRANSFER_ENCODING)
        && headers.contains_key(header::CONTENT_LENGTH)
    {
        return Err(Error::InvalidHeaders);
    }
    match field(headers, header::CONTENT_TYPE) {
        Field::Repeated => return Err(Error::InvalidHeaders),
        Field::Single(value)
            if value.len() > resume_policy::MAX_FIELD_BYTES
                || value
                    .trim_ascii()
                    .get(..10)
                    .is_some_and(|s| s.eq_ignore_ascii_case(b"multipart/")) =>
        {
            return Err(Error::InvalidHeaders);
        }
        _ => {}
    }
    Ok(())
}

fn is_cancelled(cancel: &watch::Receiver<bool>) -> bool {
    *cancel.borrow() || cancel.has_changed().is_err()
}

async fn cancelled(cancel: &mut watch::Receiver<bool>) {
    loop {
        if *cancel.borrow() {
            return;
        }
        if cancel.changed().await.is_err() {
            return;
        }
    }
}

async fn disk<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
) -> Result<T, Error> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| Error::WorkerFailed)?
        .map_err(|_| Error::Storage)
}

fn event(job: &mut Download, event: Event) -> Result<(), Error> {
    job.event(job.attempt(), event)
        .map(|_| ())
        .map_err(|_| Error::InvalidTransition)
}

async fn request(
    client: &Client,
    mut url: Url,
    range: Option<(u64, u64, &str)>,
    allow_http: bool,
    cancel: &mut watch::Receiver<bool>,
) -> Result<Response, Error> {
    for redirects in 0..=5 {
        let mut builder = client
            .get(url.clone())
            .header(header::ACCEPT_ENCODING, "identity");
        if let Some((start, total, etag)) = range {
            builder = builder
                .header(header::RANGE, format!("bytes={start}-{}", total - 1))
                .header(header::IF_RANGE, etag);
        }
        let response = tokio::select! {
            biased;
            _ = cancelled(cancel) => return Err(Error::Cancelled),
            result = builder.send() => result.map_err(|_| Error::Network)?,
        };
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            if redirects == 5 {
                return Err(Error::RedirectLimit);
            }
            let Field::Single(location) = field(response.headers(), header::LOCATION) else {
                return Err(Error::InvalidHeaders);
            };
            if location.len() > 16_384 {
                return Err(Error::InvalidHeaders);
            }
            let location = std::str::from_utf8(location).map_err(|_| Error::InvalidHeaders)?;
            let next = url.join(location).map_err(|_| Error::InvalidUrl)?;
            let next = parse_url(next.as_str(), allow_http)?;
            // A conservative first transport: explicit cross-origin redirect consent is not implemented.
            if next.origin() != url.origin() {
                return Err(Error::RedirectOriginChange);
            }
            url = next;
        } else {
            return Ok(response);
        }
    }
    Err(Error::RedirectLimit)
}

/// The caller serializes one task per job directory; Store enforces a process lock.
/// Checkpoint callbacks carry byte counts only, never paths, request URLs or headers.
/// Do not abort/drop this future: disk workers cannot be interrupted that way.
/// Request cancellation through the watch channel and await the result. Final
/// verification/publication is a non-cancellable commit once its worker starts.
pub async fn download(
    options: Options,
    mut cancel: watch::Receiver<bool>,
    on_checkpoint: impl Fn(u64),
) -> Result<Outcome, Error> {
    if options.checkpoint_bytes == 0
        || options.checkpoint_bytes > 64 * 1024 * 1024
        || options.max_download_bytes == 0
        || options.max_download_bytes > i64::MAX as u64
    {
        return Err(Error::InvalidOptions);
    }
    let original = parse_url(&options.url, options.allow_http)?;
    if is_cancelled(&cancel) {
        return Err(Error::Cancelled);
    }
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(30))
        .user_agent("FHD-development/0.1")
        .build()
        .map_err(|_| Error::Network)?;

    let directory = options.job_dir.clone();
    let mut existing = if directory.try_exists().map_err(|_| Error::Storage)? {
        Some(disk(move || Store::open(&directory)).await?)
    } else {
        None
    };
    if is_cancelled(&cancel) {
        return Err(Error::Cancelled);
    }
    if let Some(store) = &existing {
        if store.identity().original_url != original.as_str()
            || store.identity().expected_sha256 != options.expected_sha256
            || store.output_name() != options.output_name
        {
            return Err(Error::LocalStateMismatch);
        }
        if store.identity().total > options.max_download_bytes {
            return Err(Error::SizeLimit);
        }
    }
    let start = existing.as_ref().map_or(0, Store::committed_len);
    if existing
        .as_ref()
        .is_some_and(|s| matches!(s.status(), Status::ReadyToPublish | Status::Published))
    {
        let mut store = existing.take().ok_or(Error::Storage)?;
        let total = store.identity().total;
        if is_cancelled(&cancel) {
            return Err(Error::Cancelled);
        }
        let path = disk(move || store.finalize()).await?;
        return Ok(Outcome {
            bytes: total,
            resumed_from: start,
            path,
        });
    }
    // A full prefix without the clean framing marker must not be promoted to success.
    if existing
        .as_ref()
        .is_some_and(|s| start == s.identity().total && start > 0)
    {
        return Err(Error::ResumeRejected);
    }

    let etag = existing
        .as_ref()
        .and_then(|s| s.identity().strong_etag.as_deref());
    let range = if start > 0 {
        let etag = etag.ok_or(Error::ResumeUnsupported)?;
        StrongEtag::parse(etag.as_bytes()).map_err(|_| Error::ResumeUnsupported)?;
        Some((
            start,
            existing.as_ref().ok_or(Error::Storage)?.identity().total,
            etag,
        ))
    } else {
        None
    };
    let mut response = request(
        &client,
        original.clone(),
        range,
        options.allow_http,
        &mut cancel,
    )
    .await?;
    validate_representation(response.headers())?;
    let final_url = response.url().as_str().to_owned();
    let mut job = Download::new(DownloadId(1)); // Owned locally; no cross-task event channel exists here.
    job.command(Command::Start)
        .map_err(|_| Error::InvalidTransition)?;
    let total;
    if let Some(store) = &existing {
        let identity = store.identity();
        if final_url != identity.final_url {
            return Err(Error::RepresentationChanged);
        }
        total = identity.total;
        if start > 0 {
            let tag = StrongEtag::parse(
                identity
                    .strong_etag
                    .as_deref()
                    .ok_or(Error::ResumeUnsupported)?
                    .as_bytes(),
            )
            .map_err(|_| Error::ResumeUnsupported)?;
            let expected =
                ResumeRequest::new(start, total, total, tag).map_err(|_| Error::ResumeRejected)?;
            let headers = ResponseHeaders {
                content_range: field(response.headers(), header::CONTENT_RANGE),
                content_length: field(response.headers(), header::CONTENT_LENGTH),
                etag: field(response.headers(), header::ETAG),
                content_encoding: field(response.headers(), header::CONTENT_ENCODING),
            };
            if !matches!(
                resume_policy::evaluate(expected, response.status().as_u16(), headers),
                Decision::ReadRange(_)
            ) {
                return Err(Error::ResumeRejected);
            }
        } else {
            if response.status().as_u16() != 200 {
                return Err(Error::HttpStatus(response.status().as_u16()));
            }
            if response.headers().contains_key(header::CONTENT_RANGE) {
                return Err(Error::InvalidHeaders);
            }
            if length(response.headers())? != total {
                return Err(Error::RepresentationChanged);
            }
            if let Some(tag) = &identity.strong_etag {
                if !matches!(field(response.headers(), header::ETAG), Field::Single(v) if v == tag.as_bytes())
                {
                    return Err(Error::RepresentationChanged);
                }
            }
        }
    } else {
        if response.status().as_u16() != 200 {
            return Err(Error::HttpStatus(response.status().as_u16()));
        }
        if response.headers().contains_key(header::CONTENT_RANGE) {
            return Err(Error::InvalidHeaders);
        }
        total = length(response.headers())?;
        if total > options.max_download_bytes {
            return Err(Error::SizeLimit);
        }
        let strong_etag = match field(response.headers(), header::ETAG) {
            Field::Missing => None,
            Field::Repeated => return Err(Error::InvalidHeaders),
            Field::Single(v) => {
                if v.len() > resume_policy::MAX_FIELD_BYTES {
                    return Err(Error::InvalidHeaders);
                }
                if StrongEtag::parse(v).is_ok() {
                    Some(
                        std::str::from_utf8(v)
                            .map_err(|_| Error::InvalidHeaders)?
                            .to_owned(),
                    )
                } else {
                    None
                }
            }
        };
        let identity = Identity {
            original_url: original.to_string(),
            final_url,
            strong_etag,
            total,
            expected_sha256: options.expected_sha256,
        };
        let name = options.output_name;
        let directory = options.job_dir;
        existing = Some(disk(move || Store::create(&directory, identity, &name)).await?);
    }
    event(&mut job, Event::ProbeSucceeded)?;
    let mut store = existing.take().ok_or(Error::Storage)?;
    let mut received = start;
    loop {
        let next = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => Err(Error::Cancelled),
            next = response.chunk() => next.map_err(|_| Error::Network),
        };
        let chunk = match next {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => {
                disk(move || {
                    store.checkpoint()?;
                    Ok(())
                })
                .await?;
                return Err(error);
            }
        };
        received = received
            .checked_add(chunk.len() as u64)
            .ok_or(Error::BodyLength)?;
        if received > total {
            return Err(Error::BodyLength);
        }
        // Bound each disk operation and copied buffer; no whole-file accumulation.
        for bytes in chunk.chunks(64 * 1024) {
            if is_cancelled(&cancel) {
                disk(move || store.checkpoint()).await?;
                return Err(Error::Cancelled);
            }
            let owned = bytes.to_vec();
            let threshold = options.checkpoint_bytes;
            store = disk(move || {
                store.append(&owned)?;
                if store.len() - store.committed_len() >= threshold {
                    store.checkpoint()?;
                }
                Ok(store)
            })
            .await?;
            if store.len() == store.committed_len() {
                on_checkpoint(store.committed_len());
            }
        }
    }
    if received != total {
        return Err(Error::BodyLength);
    }
    if is_cancelled(&cancel) {
        disk(move || {
            store.checkpoint()?;
            Ok(())
        })
        .await?;
        return Err(Error::Cancelled);
    }
    event(&mut job, Event::TransferFinished)?;
    let path = disk(move || {
        store.mark_transfer_complete()?;
        store.finalize()
    })
    .await?;
    event(&mut job, Event::Verified)?;
    event(&mut job, Event::PublishSucceeded)?;
    Ok(Outcome {
        bytes: total,
        resumed_from: start,
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn recovery_checks_owner_and_identity_before_publication() {
        let dir = std::env::temp_dir().join(format!(
            "fhd-engine-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let url = "https://example.com/file";
        let mut store = Store::create(
            &dir,
            Identity {
                original_url: url.into(),
                final_url: url.into(),
                strong_etag: None,
                total: 3,
                expected_sha256: None,
            },
            "final.bin",
        )
        .unwrap();
        store.append(b"abc").unwrap();
        store.mark_transfer_complete().unwrap();
        drop(store);
        let options = |url: &str, name: &str| Options {
            url: url.into(),
            job_dir: dir.clone(),
            output_name: name.into(),
            expected_sha256: None,
            allow_http: false,
            checkpoint_bytes: 1024,
            max_download_bytes: 1024,
        };
        let (sender, cancel) = watch::channel(false);
        for opts in [
            options("https://example.com/other", "final.bin"),
            options(url, "other.bin"),
        ] {
            assert_eq!(
                download(opts, cancel.clone(), |_| {}).await.unwrap_err(),
                Error::LocalStateMismatch
            );
            assert!(!dir.join("final.bin").exists());
        }
        drop(sender);
        assert_eq!(
            download(options(url, "final.bin"), cancel, |_| {})
                .await
                .unwrap_err(),
            Error::Cancelled
        );
        assert!(!dir.join("final.bin").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn url_admission_rejects_credentials_fragments_and_unsafe_schemes() {
        for url in [
            "file:///tmp/a",
            "https://user:password@example.com/a",
            "https://example.com/a#part",
            "https://example.com/a\n",
        ] {
            assert_eq!(parse_url(url, true), Err(Error::InvalidUrl));
        }
        assert_eq!(
            parse_url("http://127.0.0.1/a", false),
            Err(Error::InsecureHttp)
        );
        assert!(parse_url("http://127.0.0.1/a", true).is_ok());
    }
    #[test]
    fn header_length_and_codings_are_strict() {
        let mut h = HeaderMap::new();
        h.insert(header::CONTENT_LENGTH, "12".parse().unwrap());
        assert_eq!(length(&h), Ok(12));
        h.append(header::CONTENT_LENGTH, "12".parse().unwrap());
        assert_eq!(length(&h), Err(Error::InvalidHeaders));
        h.remove(header::CONTENT_LENGTH);
        h.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
        assert_eq!(validate_representation(&h), Err(Error::InvalidHeaders));
        h.remove(header::CONTENT_ENCODING);
        h.insert(
            header::CONTENT_TYPE,
            "multipart/byteranges; boundary=x".parse().unwrap(),
        );
        assert_eq!(validate_representation(&h), Err(Error::InvalidHeaders));
    }
}
