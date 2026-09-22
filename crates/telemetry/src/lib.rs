//! Allowlisted local events. No file, network, URL or arbitrary message field.
#![forbid(unsafe_code)]

use std::{collections::VecDeque, fmt, time::Duration};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TelemetryError {
    InvalidCapacity,
    SensitiveValueTooLarge,
    SequenceExhausted,
}
impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "telemetry error: {self:?}")
    }
}
impl std::error::Error for TelemetryError {}

macro_rules! sensitive {
    ($name:ident, $limit:expr) => {
        /// Debug and Display never reveal the contents. Exposing is explicit.
        pub struct $name(Zeroizing<String>);
        impl $name {
            pub fn new(value: String) -> Result<Self, TelemetryError> {
                let value = Zeroizing::new(value);
                if value.len() > $limit {
                    return Err(TelemetryError::SensitiveValueTooLarge);
                }
                Ok(Self(value))
            }
            /// Only for a trusted adapter, never for diagnostics.
            pub fn expose(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("[redacted]")
            }
        }
    };
}
sensitive!(SecretUrl, 16_384);
sensitive!(Credential, 8_192);
sensitive!(UserPath, 131_072);

/// Fixed cardinality codes. Adding one requires extending its count/name table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Code {
    JobAccepted,
    JobPaused,
    JobCompleted,
    DnsFailed,
    ConnectTimeout,
    TlsRejected,
    ReadTimeout,
    RequestThrottled,
    SourceChanged,
    DiskFull,
    StorageFailed,
    CheckpointCommitted,
    BufferPressure,
    PolicyRejected,
    /// A command arrived for a job nobody here owns; it changed nothing.
    CommandIgnored,
}
const CODE_COUNT: usize = 15;
impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::JobAccepted => "JOB-ACCEPTED",
            Self::JobPaused => "JOB-PAUSED",
            Self::JobCompleted => "JOB-COMPLETED",
            Self::DnsFailed => "NET-DNS",
            Self::ConnectTimeout => "NET-TIMEOUT-CONNECT",
            Self::TlsRejected => "NET-TLS-REJECTED",
            Self::ReadTimeout => "NET-TIMEOUT-READ",
            Self::RequestThrottled => "NET-THROTTLED",
            Self::SourceChanged => "SRC-CHANGED",
            Self::DiskFull => "DISK-FULL",
            Self::StorageFailed => "DISK-IO",
            Self::CheckpointCommitted => "STORE-COMMITTED",
            Self::BufferPressure => "BUFFER-PRESSURE",
            Self::PolicyRejected => "POLICY-REJECTED",
            Self::CommandIgnored => "CMD-IGNORED",
        }
    }
}

/// Construct only from trusted numeric context; never encode input strings in IDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    code: Code,
    job_id: Option<u64>,
    generation: Option<u64>,
    value: u64,
    elapsed_ms: u64,
}
impl Event {
    pub fn new(code: Code) -> Self {
        Self {
            code,
            job_id: None,
            generation: None,
            value: 0,
            elapsed_ms: 0,
        }
    }
    pub fn for_job(mut self, job_id: u64, generation: u64) -> Self {
        self.job_id = Some(job_id);
        self.generation = Some(generation);
        self
    }
    pub fn with_measurement(mut self, value: u64, elapsed: Duration) -> Self {
        self.value = value;
        self.elapsed_ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        self
    }
    pub fn code(&self) -> Code {
        self.code
    }
    pub fn job_id(&self) -> Option<u64> {
        self.job_id
    }
    pub fn generation(&self) -> Option<u64> {
        self.generation
    }
    pub fn value(&self) -> u64 {
        self.value
    }
    pub fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    sequence: u64,
    event: Event,
}
impl Record {
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn event(&self) -> &Event {
        &self.event
    }
}

/// Counters have no dynamic labels. Individual job IDs are never metric labels.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    counts: [u64; CODE_COUNT],
    overwritten: u64,
}
impl Metrics {
    pub fn count(&self, code: Code) -> u64 {
        self.counts[code as usize]
    }
    pub fn overwritten_records(&self) -> u64 {
        self.overwritten
    }
}

/// Single-owner bounded in-memory diagnostics, with an optional tracing sink.
/// The caller installs a trusted subscriber and applies persistence/retention policy.
pub struct Recorder {
    records: VecDeque<Record>,
    capacity: usize,
    sequence: u64,
    metrics: Metrics,
    enabled: bool,
}
impl Recorder {
    pub fn new(capacity: usize) -> Result<Self, TelemetryError> {
        if !(1..=4096).contains(&capacity) {
            return Err(TelemetryError::InvalidCapacity);
        }
        Ok(Self {
            records: VecDeque::with_capacity(capacity),
            capacity,
            sequence: 0,
            metrics: Metrics::default(),
            enabled: true,
        })
    }
    /// Stops future events at this facade. Existing records remain until cleared.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
    pub fn clear_records(&mut self) {
        self.records.clear();
    }
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.iter()
    }
    pub fn record(&mut self, event: Event) -> Result<Option<u64>, TelemetryError> {
        if !self.enabled {
            return Ok(None);
        }
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(TelemetryError::SequenceExhausted)?;
        if self.records.len() == self.capacity {
            self.records.pop_front();
            self.metrics.overwritten = self.metrics.overwritten.saturating_add(1);
        }
        self.sequence = sequence;
        self.metrics.counts[event.code as usize] =
            self.metrics.counts[event.code as usize].saturating_add(1);
        self.records.push_back(Record { sequence, event });
        tracing::event!(target: "fhd", tracing::Level::INFO,
            code = event.code.as_str(), sequence,
            job_id = event.job_id, generation = event.generation,
            value = event.value, elapsed_ms = event.elapsed_ms);
        Ok(Some(sequence))
    }
}

/// Emits one allowlisted event without keeping a record of it. For components
/// that report but do not own diagnostics storage.
pub fn emit(event: Event) {
    tracing::event!(target: "fhd", tracing::Level::INFO,
        code = event.code.as_str(),
        job_id = event.job_id, generation = event.generation,
        value = event.value, elapsed_ms = event.elapsed_ms);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    // Tests emitting through the recorder callsite run one at a time; see the capture test.
    static CALLSITE: Mutex<()> = Mutex::new(());

    #[test]
    fn redaction_applies_to_display_debug_and_rejects_oversized_values() {
        let url =
            SecretUrl::new("https://private.test/PATH_SECRET?token=TOKEN_SECRET".into()).unwrap();
        let credential = Credential::new("Bearer CREDENTIAL_SECRET".into()).unwrap();
        let path = UserPath::new("C:/PRIVATE_PATH/customer.bin".into()).unwrap();
        let output = format!("{url:?} {url} {credential:?} {credential} {path:?} {path}");
        for canary in [
            "private.test",
            "PATH_SECRET",
            "TOKEN_SECRET",
            "CREDENTIAL_SECRET",
            "PRIVATE_PATH",
        ] {
            assert!(!output.contains(canary));
        }
        assert!(url.expose().contains("TOKEN_SECRET"));
        assert!(Credential::new("x".repeat(8193)).is_err());
    }
    #[test]
    fn record_storage_and_metric_cardinality_are_bounded() {
        let _serial = CALLSITE.lock().unwrap_or_else(|e| e.into_inner());
        assert!(Recorder::new(0).is_err());
        assert!(Recorder::new(4097).is_err());
        let mut recorder = Recorder::new(2).unwrap();
        for id in 1..=100 {
            recorder
                .record(Event::new(Code::ReadTimeout).for_job(id, 1))
                .unwrap();
        }
        assert_eq!(recorder.records().count(), 2);
        assert_eq!(recorder.records().next().unwrap().sequence(), 99);
        assert_eq!(recorder.metrics().count(Code::ReadTimeout), 100);
        assert_eq!(recorder.metrics().overwritten_records(), 98);
        recorder.set_enabled(false);
        assert_eq!(recorder.record(Event::new(Code::TlsRejected)), Ok(None));
        assert_eq!(recorder.metrics().count(Code::TlsRejected), 0);
        recorder.clear_records();
        assert_eq!(recorder.records().count(), 0);
    }
    #[test]
    fn sequence_exhaustion_does_not_evict_or_mutate_metrics() {
        let _serial = CALLSITE.lock().unwrap_or_else(|e| e.into_inner());
        let mut recorder = Recorder::new(1).unwrap();
        recorder.record(Event::new(Code::JobAccepted)).unwrap();
        recorder.sequence = u64::MAX;
        assert_eq!(
            recorder.record(Event::new(Code::JobCompleted)),
            Err(TelemetryError::SequenceExhausted)
        );
        assert_eq!(recorder.records().count(), 1);
        assert_eq!(recorder.metrics().count(Code::JobCompleted), 0);
    }

    struct Capture(Arc<Mutex<String>>);
    struct Fields<'a>(&'a mut String);
    impl tracing::field::Visit for Fields<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
            use fmt::Write;
            write!(self.0, "{}={value:?};", field.name()).unwrap();
        }
    }
    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            event.record(&mut Fields(&mut self.0.lock().unwrap()));
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }
    #[test]
    fn actual_tracing_subscriber_receives_safe_codes_and_redacted_wrappers() {
        // A concurrent first registration can cache "never" from a pre-subscriber
        // snapshot; exclude it, then rebuild with this subscriber installed.
        let _serial = CALLSITE.lock().unwrap_or_else(|e| e.into_inner());
        let captured = Arc::new(Mutex::new(String::new()));
        let subscriber = Capture(captured.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            let credential = Credential::new("DO_NOT_LOG_ME".into()).unwrap();
            tracing::event!(tracing::Level::INFO, credential = ?credential);
            let mut recorder = Recorder::new(2).unwrap();
            recorder
                .record(
                    Event::new(Code::CheckpointCommitted)
                        .for_job(7, 2)
                        .with_measurement(4096, Duration::from_millis(5)),
                )
                .unwrap();
            recorder.set_enabled(false);
            recorder.record(Event::new(Code::TlsRejected)).unwrap();
        });
        let text = captured.lock().unwrap();
        assert!(text.contains("redacted"));
        assert!(text.contains("STORE-COMMITTED"));
        assert!(!text.contains("DO_NOT_LOG_ME"));
        assert!(!text.contains("NET-TLS-REJECTED"));
    }
}
