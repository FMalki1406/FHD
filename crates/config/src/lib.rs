//! Validated, immutable effective settings. No environment, registry or file IO.
#![forbid(unsafe_code)]

use std::fmt;
use url::Url;

const MIB: u64 = 1024 * 1024;
const COUNT: usize = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Setting {
    ActiveJobs,
    ConnectionsPerJob,
    ConnectionsPerOrigin,
    BufferBytes,
    Redirects,
    ConnectTimeoutMs,
    TlsTimeoutMs,
    FirstByteTimeoutMs,
    ReadIdleTimeoutMs,
    PoolIdleTtlMs,
    ProposalTtlMs,
}

impl Setting {
    fn bounds(self) -> (u64, u64) {
        match self {
            Self::ActiveJobs => (1, 32),
            Self::ConnectionsPerJob => (1, 16),
            Self::ConnectionsPerOrigin => (1, 32),
            Self::BufferBytes => (MIB, 512 * MIB),
            Self::Redirects => (0, 20),
            Self::ConnectTimeoutMs | Self::TlsTimeoutMs => (100, 120_000),
            Self::FirstByteTimeoutMs | Self::ReadIdleTimeoutMs => (100, 600_000),
            Self::PoolIdleTtlMs => (1_000, 3_600_000),
            Self::ProposalTtlMs => (1_000, 86_400_000),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    OutOfRange(Setting),
    InvalidProxy,
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configuration error: {self:?}")
    }
}
impl std::error::Error for ConfigError {}

/// Parsed endpoint only. Proxy credentials must be supplied through a vault port.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyEndpoint(Url);
impl ProxyEndpoint {
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        if raw.len() > 4096 || raw.chars().any(char::is_control) {
            return Err(ConfigError::InvalidProxy);
        }
        let url = Url::parse(raw).map_err(|_| ConfigError::InvalidProxy)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.port() == Some(0)
        {
            return Err(ConfigError::InvalidProxy);
        }
        Ok(Self(url))
    }

    /// Explicit transport access. Never place this value in diagnostics.
    pub fn expose_endpoint(&self) -> &str {
        self.0.as_str()
    }
}
impl fmt::Debug for ProxyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyEndpoint([redacted])")
    }
}
impl fmt::Display for ProxyEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted proxy endpoint]")
    }
}

/// Selection intent; an HTTP adapter must implement it or fail explicitly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum NetworkPolicy {
    #[default]
    Direct,
    System,
    Proxy(ProxyEndpoint),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Default,
    User,
    Enforced,
}

/// A patch can only be constructed with valid individual values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigPatch {
    numbers: [Option<u64>; COUNT],
    network: Option<NetworkPolicy>,
    telemetry: Option<bool>,
    allow_http: Option<bool>,
}
impl ConfigPatch {
    pub fn set(mut self, setting: Setting, value: u64) -> Result<Self, ConfigError> {
        let (min, max) = setting.bounds();
        if !(min..=max).contains(&value) {
            return Err(ConfigError::OutOfRange(setting));
        }
        self.numbers[setting as usize] = Some(value);
        Ok(self)
    }
    pub fn with_network(mut self, value: NetworkPolicy) -> Self {
        self.network = Some(value);
        self
    }
    /// Controls local observability only; never implies permission for upload.
    pub fn with_telemetry(mut self, value: bool) -> Self {
        self.telemetry = Some(value);
        self
    }
    pub fn with_http(mut self, value: bool) -> Self {
        self.allow_http = Some(value);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveConfig {
    numbers: [u64; COUNT],
    sources: [Source; COUNT],
    network: NetworkPolicy,
    network_source: Source,
    telemetry: bool,
    telemetry_source: Source,
    allow_http: bool,
    http_source: Source,
}
impl Default for EffectiveConfig {
    fn default() -> Self {
        Self {
            numbers: [
                4,
                8,
                8,
                64 * MIB,
                10,
                15_000,
                15_000,
                30_000,
                30_000,
                90_000,
                900_000,
            ],
            sources: [Source::Default; COUNT],
            network: NetworkPolicy::Direct,
            network_source: Source::Default,
            telemetry: true,
            telemetry_source: Source::Default,
            allow_http: false,
            http_source: Source::Default,
        }
    }
}
impl EffectiveConfig {
    /// Returns a complete replacement snapshot. No live state is partially changed.
    /// Trusted code supplies the enforced layer; a user file cannot label itself policy.
    pub fn resolve(user: &ConfigPatch, enforced: &ConfigPatch) -> Self {
        let mut result = Self::default();
        for (patch, source) in [(user, Source::User), (enforced, Source::Enforced)] {
            for (index, value) in patch.numbers.iter().enumerate() {
                if let Some(value) = value {
                    result.numbers[index] = *value;
                    result.sources[index] = source;
                }
            }
            if let Some(value) = &patch.network {
                result.network = value.clone();
                result.network_source = source;
            }
            if let Some(value) = patch.telemetry {
                result.telemetry = value;
                result.telemetry_source = source;
            }
            if let Some(value) = patch.allow_http {
                result.allow_http = value;
                result.http_source = source;
            }
        }
        result
    }
    pub fn value(&self, setting: Setting) -> u64 {
        self.numbers[setting as usize]
    }
    pub fn source(&self, setting: Setting) -> Source {
        self.sources[setting as usize]
    }
    pub fn network(&self) -> &NetworkPolicy {
        &self.network
    }
    pub fn network_source(&self) -> Source {
        self.network_source
    }
    pub fn telemetry_enabled(&self) -> bool {
        self.telemetry
    }
    pub fn telemetry_source(&self) -> Source {
        self.telemetry_source
    }
    pub fn http_allowed(&self) -> bool {
        self.allow_http
    }
    pub fn http_source(&self) -> Source {
        self.http_source
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enforced_values_override_only_their_fields_and_report_provenance() {
        let user = ConfigPatch::default()
            .set(Setting::ActiveJobs, 16)
            .unwrap()
            .set(Setting::ConnectionsPerJob, 12)
            .unwrap()
            .with_http(true)
            .with_network(NetworkPolicy::System);
        let policy = ConfigPatch::default()
            .set(Setting::ActiveJobs, 2)
            .unwrap()
            .with_http(false)
            .with_telemetry(false);
        let result = EffectiveConfig::resolve(&user, &policy);
        assert_eq!(result.value(Setting::ActiveJobs), 2);
        assert_eq!(result.source(Setting::ActiveJobs), Source::Enforced);
        assert_eq!(result.value(Setting::ConnectionsPerJob), 12);
        assert_eq!(result.source(Setting::ConnectionsPerJob), Source::User);
        assert_eq!(result.value(Setting::BufferBytes), 64 * MIB);
        assert_eq!(result.source(Setting::BufferBytes), Source::Default);
        assert_eq!(result.network(), &NetworkPolicy::System);
        assert!(!result.http_allowed());
        assert_eq!(result.http_source(), Source::Enforced);
        assert!(!result.telemetry_enabled());
    }
    #[test]
    fn rejected_patch_never_changes_a_previously_resolved_snapshot() {
        let prior = EffectiveConfig::default();
        let candidate = ConfigPatch::default()
            .set(Setting::ActiveJobs, 8)
            .unwrap()
            .set(Setting::BufferBytes, 513 * MIB);
        assert_eq!(
            candidate,
            Err(ConfigError::OutOfRange(Setting::BufferBytes))
        );
        assert_eq!(prior.value(Setting::ActiveJobs), 4);
        for setting in [
            Setting::ActiveJobs,
            Setting::ConnectionsPerJob,
            Setting::ConnectionsPerOrigin,
            Setting::BufferBytes,
            Setting::Redirects,
            Setting::ConnectTimeoutMs,
            Setting::TlsTimeoutMs,
            Setting::FirstByteTimeoutMs,
            Setting::ReadIdleTimeoutMs,
            Setting::PoolIdleTtlMs,
            Setting::ProposalTtlMs,
        ] {
            let (min, max) = setting.bounds();
            assert!(ConfigPatch::default().set(setting, min).is_ok());
            assert!(ConfigPatch::default().set(setting, max).is_ok());
            assert!(ConfigPatch::default().set(setting, max + 1).is_err());
            if min > 0 {
                assert!(ConfigPatch::default().set(setting, min - 1).is_err());
            }
        }
    }
    #[test]
    fn proxy_is_parsed_redacted_and_never_contains_inline_credentials() {
        for invalid in [
            "https://user:SECRET@proxy.test",
            "https://proxy.test/?token=SECRET",
            "https://proxy.test/path",
            "https://proxy.test/#secret",
            "socks5://proxy.test",
            "http://proxy.test:0",
            "https://proxy.test\n",
        ] {
            assert_eq!(
                ProxyEndpoint::parse(invalid),
                Err(ConfigError::InvalidProxy)
            );
        }
        let proxy = ProxyEndpoint::parse("https://PRIVATE-PROXY.test:8443").unwrap();
        assert_eq!(proxy.expose_endpoint(), "https://private-proxy.test:8443/");
        let config = EffectiveConfig::resolve(
            &ConfigPatch::default(),
            &ConfigPatch::default().with_network(NetworkPolicy::Proxy(proxy.clone())),
        );
        assert!(!format!("{config:?} {proxy}").contains("private-proxy"));
        assert_eq!(config.network_source(), Source::Enforced);
    }
}
