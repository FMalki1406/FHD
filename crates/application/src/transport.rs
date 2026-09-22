//! Network port. The adapter enforces HTTP semantics (validators, If-Range, 206 bounds,
//! identity encoding, redirects, credentials) and reports typed outcomes only: no URL,
//! header or response text crosses this boundary.
use crate::PortFuture;
use fhd_domain::{ByteRange, SourceRef, StopReason};

/// Opaque grouping key for a source's origin (scheme, host, port). The runtime
/// governs per-origin limits by comparing these; it can never read a host from one.
///
/// Adapter contract: derive it by a domain-separated hash keyed with a secret the
/// process makes at startup. The origin space is small enough to enumerate, so an
/// unsalted digest would be invertible by anyone holding a log of it. Keyed, a value
/// is comparable inside one process and meaningless outside it — which is all the
/// governor needs. It is not an anonymity guarantee against whoever holds the key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct OriginId([u8; 16]);
impl OriginId {
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub fn get(self) -> [u8; 16] {
        self.0
    }
}
impl std::fmt::Debug for OriginId {
    /// Short and opaque: enough to tell two origins apart in a log, never a host.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "origin:{:02x}{:02x}{:02x}{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    total: u64,
    validator: Option<[u8; 32]>,
}
impl Probe {
    /// `validator`: an opaque digest of the representation's strong validator, which
    /// the adapter binds every range request to (If-Range). Without one there is no
    /// range support and no resume: the representation cannot be proven unchanged.
    ///
    /// Adapter contract: derive it only from a strong ETag (the exact bytes including
    /// quotes; never a weak `W/` tag, never Last-Modified), hashed with a fixed domain
    /// label. A 200 answer to an If-Range request, or a 206 whose ETag differs, is
    /// `TransportError::RepresentationChanged`, never bytes.
    pub fn new(total: u64, validator: Option<[u8; 32]>) -> Self {
        Self { total, validator }
    }
    pub fn total(self) -> u64 {
        self.total
    }
    pub fn validator(self) -> Option<[u8; 32]> {
        self.validator
    }
    pub fn ranges(self) -> bool {
        self.validator.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// Reset, timeout, truncated body, 5xx: retry with backoff.
    Transient,
    /// 429/503; the server's delay in milliseconds when it gave one.
    Throttled {
        retry_after_ms: Option<u64>,
    },
    /// Validators or status prove a different representation than the one probed.
    RepresentationChanged,
    /// Needs the user: expired link, authentication, forbidden, unsupported, policy.
    UserAction(StopReason),
    Fatal(StopReason),
}

/// The adapter enforces a read idle timeout (reported as `Transient`): a stalled
/// connection must not hold its buffer forever.
pub trait ByteStream: Send {
    /// Reads into `buf`. `Ok(0)` only at the exact end of the requested range; a body
    /// that ends early or runs long is an error, never silently short or extra bytes.
    /// Callers read once more after the range and require `Ok(0)`.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> PortFuture<'a, Result<usize, TransportError>>;
}

/// Dropping a returned future or stream cancels the request.
pub trait Transport: Send + Sync {
    /// The origin this source belongs to, for per-origin limits. Must be stable for
    /// the life of the source binding and equal only for the same scheme, host and
    /// port; an unknown source gets a key of its own, never a shared bucket.
    fn origin(&self, source: SourceRef) -> OriginId;
    fn probe(&self, source: SourceRef) -> PortFuture<'_, Result<Probe, TransportError>>;
    /// `validator` is the representation the caller's bytes belong to, as reported by
    /// the probe. The adapter must refuse (`RepresentationChanged`) if what it would
    /// fetch is anything else, so a later probe cannot swap it under a running job.
    fn fetch(
        &self,
        source: SourceRef,
        range: ByteRange,
        validator: Option<[u8; 32]>,
    ) -> PortFuture<'_, Result<Box<dyn ByteStream>, TransportError>>;
}
