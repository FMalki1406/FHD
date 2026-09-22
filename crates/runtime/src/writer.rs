use crate::{buffers::Buffer, CancellationToken};
use fhd_app::storage::{PartSpec, SegmentFile, StorageError};
use fhd_domain::ByteRange;
use tokio::sync::{mpsc, oneshot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriterError {
    InvalidCapacity,
    WrongGeneration,
    Bounds,
    Cancelled,
    Closed,
    WorkerFailed,
    Storage(StorageError),
}
type Reply<T> = oneshot::Sender<Result<T, WriterError>>;
enum Command {
    Write {
        offset: u64,
        buffer: Buffer,
        reply: Reply<()>,
    },
    Sync(Reply<()>),
    Hash(ByteRange, Reply<[u8; 32]>),
    Verify(Option<[u8; 32]>, Reply<[u8; 32]>),
}

/// One dedicated OS writer for a part; workers only send owned bounded buffers.
/// This is a lane, not yet the shared multi-job WriterPool supervisor.
pub struct Writer {
    spec: PartSpec,
    sender: Option<mpsc::Sender<Command>>,
    thread: Option<std::thread::JoinHandle<Result<(), WriterError>>>,
}
impl Writer {
    pub fn start(mut file: Box<dyn SegmentFile>, capacity: usize) -> Result<Self, WriterError> {
        if !(1..=256).contains(&capacity) {
            return Err(WriterError::InvalidCapacity);
        }
        let spec = file.spec();
        let (sender, mut receiver) = mpsc::channel(capacity);
        let thread = std::thread::Builder::new()
            .name("fhd-writer".into())
            .spawn(move || {
                let mut failure = None;
                let mut pending = None;
                while let Some(command) = pending.take().or_else(|| receiver.blocking_recv()) {
                    match command {
                        Command::Write {
                            offset,
                            mut buffer,
                            reply,
                        } => {
                            let mut replies = vec![reply];
                            // Coalesce only already queued adjacent writes. A sync/hash
                            // barrier or a gap stays pending, preserving FIFO ordering.
                            // Bound each batch even when producers refill the queue.
                            for _ in 1..capacity {
                                let Ok(next) = receiver.try_recv() else {
                                    break;
                                };
                                match next {
                                    Command::Write {
                                        offset: next_offset,
                                        buffer: next_buffer,
                                        reply: next_reply,
                                    } if offset.checked_add(buffer.len() as u64)
                                        == Some(next_offset)
                                        && buffer.append(&next_buffer) =>
                                    {
                                        replies.push(next_reply);
                                    }
                                    other => {
                                        pending = Some(other);
                                        break;
                                    }
                                }
                            }
                            let result = match failure {
                                Some(error) => Err(error),
                                None => file
                                    .write_at(offset, buffer.as_slice())
                                    .map_err(WriterError::Storage),
                            };
                            if let Err(error) = result {
                                failure = Some(error);
                            }
                            // Release credit before notifying the next producer.
                            drop(buffer);
                            for reply in replies {
                                let _ = reply.send(result);
                            }
                        }
                        Command::Sync(reply) => {
                            let result = match failure {
                                Some(error) => Err(error),
                                None => file.sync().map_err(WriterError::Storage),
                            };
                            if let Err(error) = result {
                                failure = Some(error);
                            }
                            let _ = reply.send(result);
                        }
                        Command::Hash(range, reply) => {
                            let result = match failure {
                                Some(error) => Err(error),
                                None => file.hash_range(range).map_err(WriterError::Storage),
                            };
                            if let Err(error) = result {
                                failure = Some(error);
                            }
                            let _ = reply.send(result);
                        }
                        // A digest mismatch is a verdict, not a broken lane: no poisoning.
                        Command::Verify(expected, reply) => {
                            let result = match failure {
                                Some(error) => Err(error),
                                None => file.verify(expected).map_err(WriterError::Storage),
                            };
                            if let Err(error) = result {
                                if error != WriterError::Storage(StorageError::Integrity) {
                                    failure = Some(error);
                                }
                            }
                            let _ = reply.send(result);
                        }
                    }
                }
                failure.map_or(Ok(()), Err)
            })
            .map_err(|_| WriterError::WorkerFailed)?;
        Ok(Self {
            spec,
            sender: Some(sender),
            thread: Some(thread),
        })
    }
    pub fn spec(&self) -> PartSpec {
        self.spec
    }
    async fn send(&self, command: Command, cancel: &CancellationToken) -> Result<(), WriterError> {
        let sender = self.sender.as_ref().ok_or(WriterError::Closed)?;
        let permit = tokio::select! { biased;
            _ = cancel.cancelled() => return Err(WriterError::Cancelled),
            p = sender.reserve() => p.map_err(|_| WriterError::Closed)?,
        };
        // Accepted commands run to completion, even if the caller drops its reply.
        // The coordinator drains the lane before releasing its generation/lock.
        permit.send(command);
        Ok(())
    }
    pub async fn write(
        &self,
        spec: PartSpec,
        offset: u64,
        buffer: Buffer,
        cancel: &CancellationToken,
    ) -> Result<(), WriterError> {
        if spec != self.spec {
            return Err(WriterError::WrongGeneration);
        }
        if offset
            .checked_add(buffer.len() as u64)
            .is_none_or(|end| end > self.spec.size())
        {
            return Err(WriterError::Bounds);
        }
        let (reply, result) = oneshot::channel();
        self.send(
            Command::Write {
                offset,
                buffer,
                reply,
            },
            cancel,
        )
        .await?;
        result.await.map_err(|_| WriterError::WorkerFailed)?
    }
    /// FIFO barrier: all preceding accepted writes finish before file sync.
    /// Only the repository commit can turn this acknowledgment into durability.
    pub async fn sync(&self, cancel: &CancellationToken) -> Result<(), WriterError> {
        let (reply, result) = oneshot::channel();
        self.send(Command::Sync(reply), cancel).await?;
        result.await.map_err(|_| WriterError::WorkerFailed)?
    }
    pub async fn hash(
        &self,
        range: ByteRange,
        cancel: &CancellationToken,
    ) -> Result<[u8; 32], WriterError> {
        if range.end() > self.spec.size() {
            return Err(WriterError::Bounds);
        }
        let (reply, result) = oneshot::channel();
        self.send(Command::Hash(range, reply), cancel).await?;
        result.await.map_err(|_| WriterError::WorkerFailed)?
    }
    /// Whole-file verification after every range is durable; FIFO after prior writes.
    pub async fn verify(
        &self,
        expected: Option<[u8; 32]>,
        cancel: &CancellationToken,
    ) -> Result<[u8; 32], WriterError> {
        let (reply, result) = oneshot::channel();
        self.send(Command::Verify(expected, reply), cancel).await?;
        result.await.map_err(|_| WriterError::WorkerFailed)?
    }
    pub async fn shutdown(mut self) -> Result<(), WriterError> {
        self.sender.take();
        let thread = self.thread.take().ok_or(WriterError::Closed)?;
        tokio::task::spawn_blocking(move || thread.join().map_err(|_| WriterError::WorkerFailed)?)
            .await
            .map_err(|_| WriterError::WorkerFailed)?
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        // Dropping closes admission; accepted commands drain on the owned thread.
        // Explicit shutdown is required to await physical completion.
        self.sender.take();
    }
}
