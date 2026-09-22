//! Bounded data-path building blocks. No HTTP or database adapters are linked here.
#![forbid(unsafe_code)]
pub mod buffers;
pub mod coordinator;
pub mod writer;
pub use tokio_util::sync::CancellationToken;
