use crate::{buffers::Buffer, CancellationToken};
use fhd_app::storage::{NameEvidence, PartSpec, SegmentFile, StorageError};
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
/// A refused publication as the lane reports it: why, and whether a name was
/// created at the destination.
///
/// The lane has answers of its own to add to the adapter's. Failing to hand the
/// command over means the linker was never reached. **Losing the reply does not**:
/// an accepted command runs to completion, so a reply that never arrives means the
/// lane died while publishing, and whether the link was made is then exactly what
/// nobody can say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishFailure {
    error: WriterError,
    name: NameEvidence,
}
impl PublishFailure {
    pub fn none_created(error: WriterError) -> Self {
        Self {
            error,
            name: NameEvidence::NoneCreated,
        }
    }
    pub fn unknown(error: WriterError) -> Self {
        Self {
            error,
            name: NameEvidence::Unknown,
        }
    }
    pub fn error(self) -> WriterError {
        self.error
    }
    pub fn name(self) -> NameEvidence {
        self.name
    }
}
impl From<PublishFailure> for WriterError {
    fn from(failure: PublishFailure) -> Self {
        failure.error
    }
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
    Verify(
        Option<[u8; 32]>,
        Vec<(ByteRange, [u8; 32])>,
        Reply<[u8; 32]>,
    ),
    Publish(oneshot::Sender<Result<fhd_app::storage::Published, PublishFailure>>),
    Discard {
        abandon: bool,
        reply: Reply<()>,
    },
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
                // Set when a publication could not say whether it linked. It
                // outlives that command, because every later answer this lane
                // gives about a name has to stay ignorant too.
                let mut published_unknown = false;
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
                        // Terminal: the part is gone and the lane is finished with it.
                        Command::Discard { abandon, reply } => {
                            let result = match failure {
                                Some(error) => Err(error),
                                None => {
                                    if abandon {
                                        file.abandon();
                                    }
                                    file.discard().map_err(WriterError::Storage)
                                }
                            };
                            // The file is gone either way: the lane is finished with it.
                            failure = Some(result.err().unwrap_or(WriterError::Closed));
                            let _ = reply.send(result);
                        }
                        // A destination conflict is a verdict, not a broken lane.
                        Command::Publish(reply) => {
                            let result = match failure {
                                // This command never reached the file, so this
                                // attempt made no name -- and the poison it is
                                // refusing on did not either, unless it came from
                                // a publication that could not say. Remembered
                                // rather than assumed: a caller must not be told
                                // "nothing was created" because an earlier
                                // unanswerable publication left the lane broken.
                                Some(error) if published_unknown => {
                                    Err(PublishFailure::unknown(error))
                                }
                                Some(error) => Err(PublishFailure::none_created(error)),
                                None => file.publish().map_err(|refused| PublishFailure {
                                    error: WriterError::Storage(refused.error()),
                                    name: refused.name(),
                                }),
                            };
                            if let Err(failed) = result.as_ref() {
                                if failed.error != WriterError::Storage(StorageError::Conflict) {
                                    failure = Some(failed.error);
                                }
                                published_unknown |= failed.name == NameEvidence::Unknown;
                            }
                            let _ = reply.send(result);
                        }
                        // A digest mismatch is a verdict, not a broken lane: no poisoning.
                        Command::Verify(expected, record, reply) => {
                            let result = match failure {
                                Some(error) => Err(error),
                                None => {
                                    file.verify(expected, &record).map_err(WriterError::Storage)
                                }
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
        record: Vec<(ByteRange, [u8; 32])>,
        cancel: &CancellationToken,
    ) -> Result<[u8; 32], WriterError> {
        let (reply, result) = oneshot::channel();
        self.send(Command::Verify(expected, record, reply), cancel)
            .await?;
        result.await.map_err(|_| WriterError::WorkerFailed)?
    }
    /// Atomic no-replace publication, after every write and the verification.
    ///
    /// No destination is passed. The folder was adopted before this writer
    /// existed -- by the session that opened the part -- so there is no command
    /// on this lane that can introduce one, and nothing can be published
    /// anywhere the session did not fix in advance.
    /// Refusing says whether a name was created; see `PublishFailure`.
    pub async fn publish(
        &self,
        cancel: &CancellationToken,
    ) -> Result<fhd_app::storage::Published, PublishFailure> {
        let (reply, result) = oneshot::channel();
        // Nothing has been handed over yet, so nothing can have been linked: a
        // closed lane or a cancelled send is a refusal before the attempt.
        self.send(Command::Publish(reply), cancel)
            .await
            .map_err(PublishFailure::none_created)?;
        // And here the command was accepted, so a lost reply is the one case
        // nobody can answer rather than a refusal.
        result
            .await
            .map_err(|_| PublishFailure::unknown(WriterError::WorkerFailed))?
    }
    /// Removes the part file: after publication, or with `abandon` for a cancelled job.
    pub async fn discard(
        &self,
        abandon: bool,
        cancel: &CancellationToken,
    ) -> Result<(), WriterError> {
        let (reply, result) = oneshot::channel();
        self.send(Command::Discard { abandon, reply }, cancel)
            .await?;
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
