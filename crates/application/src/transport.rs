//! Network port. The adapter enforces HTTP semantics (validators, If-Range, 206 bounds,
//! identity encoding, redirects, credentials) and reports typed outcomes only: no URL,
//! header or response text crosses this boundary.
use crate::PortFuture;
use fhd_domain::{ByteRange, SourceRef, StopReason};

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
