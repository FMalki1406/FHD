//! Pure domain decisions: no clock reads, filesystem, network or asynchronous work.
#![forbid(unsafe_code)]
mod job;
mod retry;
mod segments;
pub use job::*;
pub use resume_policy as resume;
pub use retry::*;
pub use segments::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainError {
    InvalidInput,
    Overflow,
    Capacity,
    UnknownSegment,
    InvalidTransition,
    StaleToken,
    CheckpointPending,
    Incomplete,
    StaleEvent,
    PublishInProgress,
}
impl std::fmt::Display for DomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DomainError {}
macro_rules! identifier {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);
        impl $name {
            pub fn new(value: u64) -> Result<Self, DomainError> {
                if value == 0 {
                    Err(DomainError::InvalidInput)
                } else {
                    Ok(Self(value))
                }
            }
            pub fn get(self) -> u64 {
                self.0
            }
        }
    };
}
identifier!(JobId);
identifier!(Generation);
identifier!(SourceRef);
identifier!(DestinationRef);
impl Generation {
    pub fn initial() -> Self {
        Self(1)
    }
    pub fn next(self) -> Result<Self, DomainError> {
        self.0.checked_add(1).map(Self).ok_or(DomainError::Overflow)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    start: u64,
    end: u64,
}
impl ByteRange {
    pub fn new(start: u64, end: u64) -> Result<Self, DomainError> {
        if start >= end || end > i64::MAX as u64 {
            Err(DomainError::InvalidInput)
        } else {
            Ok(Self { start, end })
        }
    }
    pub fn start(self) -> u64 {
        self.start
    }
    pub fn end(self) -> u64 {
        self.end
    }
    pub fn len(self) -> u64 {
        self.end - self.start
    }
    pub fn is_empty(self) -> bool {
        false
    }
    pub fn contains(self, other: Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }
    pub fn split(self, at: u64) -> Result<(Self, Self), DomainError> {
        Ok((Self::new(self.start, at)?, Self::new(at, self.end)?))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    Low,
    Normal,
    High,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobSpec {
    source: SourceRef,
    destination: DestinationRef,
    expected_sha256: Option<[u8; 32]>,
    priority: Priority,
    max_bytes: u64,
}
impl JobSpec {
    pub fn new(
        source: SourceRef,
        destination: DestinationRef,
        expected_sha256: Option<[u8; 32]>,
        priority: Priority,
        max_bytes: u64,
    ) -> Result<Self, DomainError> {
        if max_bytes == 0 || max_bytes > i64::MAX as u64 {
            return Err(DomainError::InvalidInput);
        }
        Ok(Self {
            source,
            destination,
            expected_sha256,
            priority,
            max_bytes,
        })
    }
    pub fn source(&self) -> SourceRef {
        self.source
    }
    pub fn destination(&self) -> DestinationRef {
        self.destination
    }
    pub fn expected_sha256(&self) -> Option<[u8; 32]> {
        self.expected_sha256
    }
    pub fn priority(&self) -> Priority {
        self.priority
    }
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}
