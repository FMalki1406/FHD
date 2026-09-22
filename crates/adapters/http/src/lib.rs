//! HTTP transport adapter. It owns every protocol decision (validators, If-Range,
//! 206 bounds, identity coding, redirects, credential scope) and reports only typed
//! outcomes: no URL, header or server text crosses the port boundary.
#![forbid(unsafe_code)]

use fhd_app::{
    transport::{ByteStream, Probe, Transport, TransportError},
    PortFuture,
};
use fhd_domain::{resume::StrongEtag, ByteRange, SourceRef, StopReason};
use reqwest::{
    header::{self, HeaderMap, HeaderName, HeaderValue},
    Client, Response, StatusCode, Url,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use zeroize::Zeroizing;

const MAX_URL: usize = 16_384;
const MAX_FIELD: usize = 8192;
/// Domain label so a validator digest is never confused with any other digest.
const VALIDATOR_LABEL: &[u8] = b"FHD.representation.validator.v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingError {
    AlreadyBound,
    InvalidUrl,
    InsecureHttp,
    InvalidCredential,
    TooManyOrigins,
}

/// Where a source reference points and what may be sent with it. Constructed by the
/// trusted controller; never from page-supplied data. Debug and Display never reveal it.
pub struct SourceBinding {
    url: Url,
    authorization: Option<Zeroizing<String>>,
    cookie: Option<Zeroizing<String>>,
    allow_http: bool,
    redirect_origins: Vec<String>,
}
impl std::fmt::Debug for SourceBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceBinding")
            .field("url", &"[redacted]")
            .field(
                "credentials",
                &(self.authorization.is_some() || self.cookie.is_some()),
            )
            .field("redirect_origins", &self.redirect_origins.len())
            .finish()
    }
}
impl SourceBinding {
    pub fn new(
        url: &str,
        authorization: Option<String>,
        cookie: Option<String>,
        allow_http: bool,
        redirect_origins: Vec<String>,
    ) -> Result<Self, BindingError> {
        let url = parse_url(url, allow_http)?;
        for value in [authorization.as_deref(), cookie.as_deref()]
            .into_iter()
            .flatten()
        {
            if value.is_empty()
                || value.len() > MAX_FIELD
                || !value.is_ascii()
                || value.bytes().any(|b| b.is_ascii_control())
                || HeaderValue::from_str(value).is_err()
            {
                return Err(BindingError::InvalidCredential);
            }
        }
        if redirect_origins.len() > 8 {
            return Err(BindingError::TooManyOrigins);
        }
        let mut origins = Vec::with_capacity(redirect_origins.len());
        for origin in &redirect_origins {
            let parsed = parse_url(origin, true)?;
            if parsed.path() != "/" || parsed.query().is_some() {
                return Err(BindingError::InvalidUrl);
            }
            origins.push(parsed.origin().ascii_serialization());
        }
        origins.sort();
        origins.dedup();
        Ok(Self {
            url,
            authorization: authorization.map(Zeroizing::new),
            cookie: cookie.map(Zeroizing::new),
            allow_http,
            redirect_origins: origins,
        })
    }
}

fn parse_url(raw: &str, allow_http: bool) -> Result<Url, BindingError> {
    if raw.len() > MAX_URL || raw.chars().any(char::is_control) {
        return Err(BindingError::InvalidUrl);
    }
    let url = Url::parse(raw).map_err(|_| BindingError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(BindingError::InvalidUrl);
    }
    if url.scheme() == "http" && !allow_http {
        return Err(BindingError::InsecureHttp);
    }
    Ok(url)
}

#[derive(Clone, Copy, Debug)]
pub struct HttpConfig {
    pub connect_timeout: Duration,
    /// Maximum wait for the next body bytes; exceeded is a transient failure.
    pub read_idle_timeout: Duration,
    pub response_timeout: Duration,
    pub max_redirects: u8,
    pub user_agent: &'static str,
}
impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            read_idle_timeout: Duration::from_secs(30),
            response_timeout: Duration::from_secs(30),
            max_redirects: 10,
            user_agent: "FHD/0.1",
        }
    }
}

/// The representation a probe proved, so later ranges are bound to it.
#[derive(Clone)]
struct Representation {
    etag: String,
    total: u64,
    url: Url,
}

#[derive(Default)]
struct Registry {
    bindings: HashMap<SourceRef, Arc<SourceBinding>>,
    probed: HashMap<SourceRef, Representation>,
}

pub struct HttpTransport {
    client: Client,
    config: HttpConfig,
    registry: Mutex<Registry>,
}

impl HttpTransport {
    pub fn new(config: HttpConfig) -> Result<Self, BindingError> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            // No proxy profile exists yet, so no ambient environment proxy either.
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(config.connect_timeout)
            .user_agent(config.user_agent)
            .build()
            .map_err(|_| BindingError::InvalidUrl)?;
        Ok(Self {
            client,
            config,
            registry: Mutex::new(Registry::default()),
        })
    }
    /// Binds a reference to an immutable source. A reference is bound once: changing
    /// the URL, credentials or policy is a new reference, never a rebind.
    pub fn bind(&self, source: SourceRef, binding: SourceBinding) -> Result<(), BindingError> {
        let mut registry = self.registry.lock().unwrap();
        if registry.bindings.contains_key(&source) {
            return Err(BindingError::AlreadyBound);
        }
        registry.bindings.insert(source, Arc::new(binding));
        Ok(())
    }
    /// Forgets a binding and what it probed, dropping (and zeroing) its credentials.
    pub fn unbind(&self, source: SourceRef) {
        let mut registry = self.registry.lock().unwrap();
        registry.bindings.remove(&source);
        registry.probed.remove(&source);
    }
    fn binding(&self, source: SourceRef) -> Option<Arc<SourceBinding>> {
        self.registry.lock().unwrap().bindings.get(&source).cloned()
    }

    /// Follows redirects by hand: never downgrades to http, and only to an origin the
    /// binding allows. Credentials go to the initial origin only.
    async fn send(
        &self,
        binding: &SourceBinding,
        start: &Url,
        range: Option<(u64, u64)>,
        if_range: Option<&str>,
    ) -> Result<Response, TransportError> {
        let mut url = start.clone();
        // Sticky: once a hop leaves the binding's origin, credentials are gone for good.
        let mut credentials = url.origin() == binding.url.origin();
        for _ in 0..=self.config.max_redirects {
            let mut request = self
                .client
                .get(url.clone())
                .header(header::ACCEPT_ENCODING, "identity");
            if credentials {
                for (name, value) in [
                    (header::AUTHORIZATION, binding.authorization.as_deref()),
                    (header::COOKIE, binding.cookie.as_deref()),
                ] {
                    if let Some(value) = value {
                        let mut value = HeaderValue::from_str(value)
                            .map_err(|_| TransportError::Fatal(StopReason::Policy))?;
                        value.set_sensitive(true);
                        request = request.header(name, value);
                    }
                }
            }
            if let Some((start, end)) = range {
                request = request.header(header::RANGE, format!("bytes={start}-{}", end - 1));
                if let Some(validator) = if_range {
                    request = request.header(header::IF_RANGE, validator);
                }
            }
            let response = tokio::time::timeout(self.config.response_timeout, request.send())
                .await
                .map_err(|_| TransportError::Transient)?
                .map_err(connection_error)?;
            if !matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
                return Ok(response);
            }
            let location = single(response.headers(), header::LOCATION)
                .ok_or(TransportError::Fatal(StopReason::Unknown))?;
            let location = std::str::from_utf8(location)
                .map_err(|_| TransportError::Fatal(StopReason::Unknown))?;
            let next = url
                .join(location)
                .map_err(|_| TransportError::Fatal(StopReason::Unknown))?;
            let next = parse_url(next.as_str(), binding.allow_http)
                .map_err(|_| TransportError::Fatal(StopReason::Policy))?;
            if url.scheme() == "https" && next.scheme() != "https" {
                return Err(TransportError::Fatal(StopReason::Policy));
            }
            if next.origin() != url.origin()
                && !binding
                    .redirect_origins
                    .iter()
                    .any(|origin| *origin == next.origin().ascii_serialization())
            {
                return Err(TransportError::Fatal(StopReason::Policy));
            }
            credentials &= next.origin() == binding.url.origin();
            url = next;
        }
        Err(TransportError::Fatal(StopReason::Policy))
    }
}

/// A refused certificate, TLS handshake or name lookup needs a person, not a retry.
/// Heuristic over the error chain: reqwest does not expose these as typed variants.
fn connection_error(error: reqwest::Error) -> TransportError {
    let mut text = String::new();
    let mut source: Option<&dyn std::error::Error> = Some(&error);
    while let Some(current) = source {
        text.push_str(&current.to_string().to_ascii_lowercase());
        text.push(' ');
        source = current.source();
    }
    let unactionable = [
        "certificate",
        "tls",
        "handshake",
        "dns error",
        "lookup address",
    ];
    if unactionable.iter().any(|needle| text.contains(needle)) {
        return TransportError::UserAction(StopReason::Policy);
    }
    TransportError::Transient
}

fn single(headers: &HeaderMap, name: HeaderName) -> Option<&[u8]> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) if value.len() <= MAX_FIELD => Some(value.as_bytes()),
        _ => None,
    }
}

fn digits(value: &[u8]) -> Option<u64> {
    if value.is_empty() || value.len() > 20 {
        return None;
    }
    value.iter().try_fold(0u64, |n, b| {
        if !b.is_ascii_digit() {
            return None;
        }
        n.checked_mul(10)?.checked_add(u64::from(b - b'0'))
    })
}

/// Rejects anything but a single, unencoded, non-multipart representation.
fn representation_is_plain(headers: &HeaderMap) -> bool {
    let encoding = match headers.get_all(header::CONTENT_ENCODING).iter().count() {
        0 => true,
        1 => single(headers, header::CONTENT_ENCODING)
            .is_some_and(|value| value.eq_ignore_ascii_case(b"identity")),
        _ => false,
    };
    let framing = !(headers.contains_key(header::TRANSFER_ENCODING)
        && headers.contains_key(header::CONTENT_LENGTH));
    let kind = match headers.get_all(header::CONTENT_TYPE).iter().count() {
        0 => true,
        1 => single(headers, header::CONTENT_TYPE).is_some_and(|value| {
            !value
                .trim_ascii()
                .get(..10)
                .is_some_and(|s| s.eq_ignore_ascii_case(b"multipart/"))
        }),
        _ => false,
    };
    encoding && framing && kind
}

/// `bytes start-end/total` of exactly the requested range.
fn content_range(headers: &HeaderMap, expected: ByteRange) -> Option<u64> {
    let value = single(headers, header::CONTENT_RANGE)?;
    let rest = value.strip_prefix(b"bytes ")?;
    let (range, total) = rest.split_at(rest.iter().position(|b| *b == b'/')?);
    let total = digits(&total[1..])?;
    let (start, end) = range.split_at(range.iter().position(|b| *b == b'-')?);
    let (start, end) = (digits(start)?, digits(&end[1..])?);
    if start != expected.start() || end.checked_add(1)? != expected.end() || end >= total {
        return None;
    }
    Some(total)
}

fn strong_validator(headers: &HeaderMap) -> Option<String> {
    let value = single(headers, header::ETAG)?;
    StrongEtag::parse(value).ok()?;
    std::str::from_utf8(value).ok().map(str::to_owned)
}

fn validator_digest(etag: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(VALIDATOR_LABEL);
    hash.update((etag.len() as u64).to_le_bytes());
    hash.update(etag.as_bytes());
    hash.finalize().into()
}

/// Status to outcome. Retry-After in seconds becomes a throttle delay.
fn status_error(status: StatusCode, headers: &HeaderMap) -> TransportError {
    let retry_after_ms = single(headers, header::RETRY_AFTER)
        .and_then(digits)
        .and_then(|seconds| seconds.checked_mul(1000));
    match status.as_u16() {
        408 | 425 | 500 | 502 | 504 => TransportError::Transient,
        429 | 503 => TransportError::Throttled { retry_after_ms },
        401 | 407 => TransportError::UserAction(StopReason::Authentication),
        403 | 451 => TransportError::UserAction(StopReason::Policy),
        404 | 410 => TransportError::UserAction(StopReason::SourceChanged),
        416 => TransportError::RepresentationChanged,
        _ => TransportError::Fatal(StopReason::Unknown),
    }
}

impl Transport for HttpTransport {
    fn probe(&self, source: SourceRef) -> PortFuture<'_, Result<Probe, TransportError>> {
        Box::pin(async move {
            let binding = self
                .binding(source)
                .ok_or(TransportError::Fatal(StopReason::Policy))?;
            // One byte proves range support and reports the total; nothing is wasted.
            let response = self
                .send(&binding, &binding.url, Some((0, 1)), None)
                .await?;
            let status = response.status();
            if !matches!(status.as_u16(), 200 | 206) {
                return Err(status_error(status, response.headers()));
            }
            let headers = response.headers().clone();
            let url = response.url().clone();
            drop(response);
            if !representation_is_plain(&headers) {
                return Err(TransportError::Fatal(StopReason::Policy));
            }
            let etag = strong_validator(&headers);
            let total = if status == StatusCode::PARTIAL_CONTENT {
                single(&headers, header::CONTENT_RANGE)
                    .and_then(|value| {
                        let rest = value.strip_prefix(b"bytes ")?;
                        let slash = rest.iter().position(|b| *b == b'/')?;
                        digits(&rest[slash + 1..])
                    })
                    .ok_or(TransportError::Fatal(StopReason::Unknown))?
            } else {
                single(&headers, header::CONTENT_LENGTH)
                    .and_then(digits)
                    .ok_or(TransportError::Fatal(StopReason::Policy))?
            };
            if total > i64::MAX as u64 {
                return Err(TransportError::Fatal(StopReason::Policy));
            }
            // Ranges are offered only with a strong validator to bind them to.
            let validator = match (status == StatusCode::PARTIAL_CONTENT, etag) {
                (true, Some(etag)) => {
                    let digest = validator_digest(&etag);
                    self.registry.lock().unwrap().probed.insert(
                        source,
                        Representation {
                            etag,
                            total,
                            url: url.clone(),
                        },
                    );
                    Some(digest)
                }
                _ => {
                    self.registry.lock().unwrap().probed.remove(&source);
                    None
                }
            };
            Ok(Probe::new(total, validator))
        })
    }

    fn fetch(
        &self,
        source: SourceRef,
        range: ByteRange,
        validator: Option<[u8; 32]>,
    ) -> PortFuture<'_, Result<Box<dyn ByteStream>, TransportError>> {
        Box::pin(async move {
            let binding = self
                .binding(source)
                .ok_or(TransportError::Fatal(StopReason::Policy))?;
            let probed = self.registry.lock().unwrap().probed.get(&source).cloned();
            // A newer probe must never serve bytes to a job bound to an older one.
            if validator != probed.as_ref().map(|p| validator_digest(&p.etag)) {
                return Err(TransportError::RepresentationChanged);
            }
            let (url, if_range, total) = match &probed {
                // Whole-file fetch of a source without ranges: the probe proved the size.
                None => (binding.url.clone(), None, None),
                Some(probed) => (
                    probed.url.clone(),
                    Some(probed.etag.clone()),
                    Some(probed.total),
                ),
            };
            let request = if if_range.is_some() {
                Some((range.start(), range.end()))
            } else if range.start() == 0 {
                None
            } else {
                // No validator: a resumed range cannot be proven to match.
                return Err(TransportError::RepresentationChanged);
            };
            let response = self
                .send(&binding, &url, request, if_range.as_deref())
                .await?;
            let status = response.status();
            if !matches!(status.as_u16(), 200 | 206) {
                return Err(status_error(status, response.headers()));
            }
            if !representation_is_plain(response.headers()) {
                return Err(TransportError::Fatal(StopReason::Policy));
            }
            if let Some(expected) = if_range.as_deref() {
                // 200 answers an If-Range only when the representation changed.
                let declared = single(response.headers(), header::CONTENT_LENGTH).and_then(digits);
                if status != StatusCode::PARTIAL_CONTENT
                    || strong_validator(response.headers()).as_deref() != Some(expected)
                    || content_range(response.headers(), range) != total
                    || declared.is_some_and(|length| length != range.len())
                {
                    return Err(TransportError::RepresentationChanged);
                }
            } else if status == StatusCode::PARTIAL_CONTENT
                || single(response.headers(), header::CONTENT_LENGTH).and_then(digits)
                    != Some(range.len())
            {
                return Err(TransportError::RepresentationChanged);
            }
            Ok(Box::new(HttpStream {
                response,
                pending: bytes::Bytes::new(),
                at: 0,
                remaining: range.len(),
                idle: self.config.read_idle_timeout,
            }) as Box<dyn ByteStream>)
        })
    }
}

struct HttpStream {
    response: Response,
    pending: bytes::Bytes,
    at: usize,
    remaining: u64,
    idle: Duration,
}
impl ByteStream for HttpStream {
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, TransportError>> {
        Box::pin(async move {
            if buf.is_empty() {
                return Err(TransportError::Fatal(StopReason::Policy));
            }
            // Empty chunks are legal (HTTP/2 DATA frames); they are never an ending.
            while self.at == self.pending.len() {
                let chunk = tokio::time::timeout(self.idle, self.response.chunk())
                    .await
                    .map_err(|_| TransportError::Transient)?
                    .map_err(connection_error)?;
                match chunk {
                    // The body outran the range, or ended before it.
                    Some(chunk) if chunk.len() as u64 > self.remaining => {
                        return Err(TransportError::Transient)
                    }
                    Some(chunk) => {
                        self.pending = chunk;
                        self.at = 0;
                    }
                    None if self.remaining == 0 => return Ok(0),
                    None => return Err(TransportError::Transient),
                }
            }
            let take = buf.len().min(self.pending.len() - self.at);
            buf[..take].copy_from_slice(&self.pending[self.at..self.at + take]);
            self.at += take;
            self.remaining -= take as u64;
            Ok(take)
        })
    }
}
