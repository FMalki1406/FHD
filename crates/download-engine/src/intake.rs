//! In-process approval boundary. No listening socket or ambient browser authority.
use crate::{
    manager::{JobId, Manager, ManagerError, Priority},
    Options, RequestPolicy,
};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    path::PathBuf,
    time::{Duration, Instant},
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposalId(u64);
struct Proposal {
    id: ProposalId,
    source: String,
    url: String,
    created: Instant,
}
/// Owned by the trusted desktop controller, never handed to web content.
pub struct Inbox {
    pending: VecDeque<Proposal>,
    source_namespace: String,
    next: u64,
}
impl Default for Inbox {
    fn default() -> Self {
        Self {
            pending: VecDeque::new(),
            source_namespace: "local-ui".into(),
            next: 1,
        }
    }
}
impl Inbox {
    /// Namespace assigned by the trusted controller, not by page-supplied payload.
    /// Browser adapters must bind it to their authenticated extension/profile.
    pub fn for_source(source: String) -> Result<Self, ManagerError> {
        if source.is_empty()
            || source.len() > 128
            || !source
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return Err(ManagerError::InvalidOptions);
        }
        Ok(Self {
            source_namespace: source,
            ..Self::default()
        })
    }

    fn receipt_key(&self, request_id: &str) -> String {
        let mut hash = Sha256::new();
        hash.update(b"FHD.intake.admission.v1\0");
        for part in [self.source_namespace.as_str(), request_id] {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part.as_bytes());
        }
        use std::fmt::Write;
        let mut key = String::with_capacity(70);
        key.push_str("inbox-");
        for byte in hash.finalize() {
            let _ = write!(key, "{byte:02x}");
        }
        key
    }
    /// Only stages a request. Does not touch disk, DNS or network, or cancel a browser download.
    /// This does not implement authenticated browser transport or SSRF protection.
    pub fn propose(&mut self, request_id: String, url: String) -> Result<ProposalId, ManagerError> {
        self.pending
            .retain(|p| p.created.elapsed() < Duration::from_secs(900));
        if request_id.is_empty()
            || request_id.len() > 128
            || !request_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(ManagerError::InvalidOptions);
        }
        if let Some(p) = self.pending.iter().find(|p| p.source == request_id) {
            return if p.url == url {
                Ok(p.id)
            } else {
                Err(ManagerError::DuplicateJob)
            };
        }
        crate::parse_url(&url, false).map_err(|_| ManagerError::InvalidOptions)?;
        if self.pending.len() >= 64 {
            return Err(ManagerError::Capacity);
        }
        let id = ProposalId(self.next);
        self.next = self.next.checked_add(1).ok_or(ManagerError::Capacity)?;
        self.pending.push_back(Proposal {
            id,
            source: request_id,
            url,
            created: Instant::now(),
        });
        Ok(id)
    }
    /// Trusted UI-only preview. Sensitive signed URL must not be logged or exported.
    pub fn preview_url(&self, id: ProposalId) -> Option<&str> {
        self.pending
            .iter()
            .find(|p| p.id == id && p.created.elapsed() < Duration::from_secs(900))
            .map(|p| p.url.as_str())
    }
    pub fn reject(&mut self, id: ProposalId) {
        self.pending.retain(|p| p.id != id);
    }
    /// Only call after explicit trusted UI approval, including the destination.
    /// No credentials, HTTP permission, redirect permission or arbitrary path comes from the proposal.
    /// Requires a durable manager. Replay must use the original approved settings.
    /// Acceptance does not authorize cancellation of an existing browser transfer.
    pub async fn approve(
        &mut self,
        manager: &Manager,
        id: ProposalId,
        job_dir: PathBuf,
        name: String,
    ) -> Result<JobId, ManagerError> {
        crate::files::validate_name(&name).map_err(|_| ManagerError::InvalidOptions)?;
        let index = self
            .pending
            .iter()
            .position(|p| p.id == id && p.created.elapsed() < Duration::from_secs(900))
            .ok_or(ManagerError::UnknownJob)?;
        let proposal = &self.pending[index];
        let options = Options {
            url: proposal.url.clone(),
            job_dir,
            output_name: name,
            expected_sha256: None,
            allow_http: false,
            checkpoint_bytes: 1024 * 1024,
            max_download_bytes: 100 * 1024 * 1024 * 1024,
            bytes_per_second: None,
            parallel_connections: 1,
            request_policy: RequestPolicy::default(),
            refresh_from: None,
        };
        let receipt_key = self.receipt_key(&proposal.source);
        let accepted = manager
            .enqueue_once(receipt_key, options, Priority::Normal)
            .await?;
        self.pending.remove(index).ok_or(ManagerError::UnknownJob)?;
        Ok(accepted)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn namespace_is_bounded_and_hashes_each_identifier_separately() {
        for invalid in ["", "page\norigin", "../source"] {
            assert!(Inbox::for_source(invalid.into()).is_err());
        }
        assert!(Inbox::for_source("a".repeat(129)).is_err());
        let first = Inbox::for_source("profile-A".into()).unwrap();
        let again = Inbox::for_source("profile-A".into()).unwrap();
        let other = Inbox::for_source("profile-B".into()).unwrap();
        assert_eq!(
            first.receipt_key("request-1"),
            again.receipt_key("request-1")
        );
        assert_ne!(
            first.receipt_key("request-1"),
            other.receipt_key("request-1")
        );
        assert_ne!(
            first.receipt_key("request-1"),
            first.receipt_key("request-2")
        );
        assert_eq!(first.receipt_key("request-1").len(), 70);
    }
    #[test]
    fn proposal_is_bounded_deduplicated_and_grants_no_request_permissions() {
        let mut inbox = Inbox::default();
        assert!(inbox
            .propose("1".into(), "http://example.com/file".into())
            .is_err());
        let id = inbox
            .propose("2".into(), "https://example.com/?token=private".into())
            .unwrap();
        assert_eq!(
            inbox
                .propose("2".into(), "https://example.com/?token=private".into())
                .unwrap(),
            id
        );
        assert!(inbox
            .propose("2".into(), "https://other.example/".into())
            .is_err());
        for n in 3..66 {
            inbox
                .propose(n.to_string(), "https://example.com/".into())
                .unwrap();
        }
        assert_eq!(
            inbox.propose("66".into(), "https://example.com/".into()),
            Err(ManagerError::Capacity)
        );
        inbox.reject(id);
        assert!(inbox.preview_url(id).is_none());
    }
}
