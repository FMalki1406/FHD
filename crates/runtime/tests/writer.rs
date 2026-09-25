use fhd_app::storage::{PartSpec, SegmentFile, StorageError};
use fhd_domain::{ByteRange, Generation, JobId};
use fhd_runtime::{
    buffers::{BufferPool, MAX_BUFFER},
    writer::{Writer, WriterError},
    CancellationToken,
};
use std::{
    future::{poll_fn, Future},
    io::ErrorKind,
    path::Path,
    pin::Pin,
    sync::{Arc, Condvar, Mutex},
    task::Poll,
    thread::{self, ThreadId},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation {
    Write(u64, usize),
    Sync,
    Hash,
    Discard,
    Drop,
}
#[derive(Clone, Copy)]
enum Fault {
    None,
    Write,
    Sync,
    Panic,
}
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    ready: Condvar,
}
impl Gate {
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.ready.notify_all();
    }
    fn wait(&self) {
        let guard = self.open.lock().unwrap();
        drop(self.ready.wait_while(guard, |open| !*open).unwrap());
    }
}
type Log = Arc<Mutex<Vec<(Operation, ThreadId)>>>;
struct FakeFile {
    spec: PartSpec,
    log: Log,
    fault: Fault,
    data: Option<Arc<Mutex<Vec<u8>>>>,
    gate: Option<Arc<Gate>>,
    entered: Option<tokio::sync::oneshot::Sender<()>>,
    abandoned: bool,
    discarded: bool,
}
impl FakeFile {
    fn observe(&self, operation: Operation) {
        self.log
            .lock()
            .unwrap()
            .push((operation, thread::current().id()));
    }
}
impl Drop for FakeFile {
    fn drop(&mut self) {
        self.observe(Operation::Drop);
    }
}
impl SegmentFile for FakeFile {
    fn spec(&self) -> PartSpec {
        self.spec
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<(), StorageError> {
        self.observe(Operation::Write(offset, bytes.len()));
        if let Some(entered) = self.entered.take() {
            let _ = entered.send(());
        }
        if let Some(gate) = self.gate.take() {
            gate.wait();
        }
        match self.fault {
            Fault::Write => return Err(StorageError::Io(ErrorKind::StorageFull)),
            Fault::Panic => panic!("injected writer panic"),
            _ => (),
        }
        if let Some(data) = &self.data {
            data.lock().unwrap()[offset as usize..offset as usize + bytes.len()]
                .copy_from_slice(bytes);
        }
        Ok(())
    }
    fn sync(&mut self) -> Result<(), StorageError> {
        self.observe(Operation::Sync);
        if matches!(self.fault, Fault::Sync) {
            Err(StorageError::Io(ErrorKind::Other))
        } else {
            Ok(())
        }
    }
    fn hash_range(&mut self, _: ByteRange) -> Result<[u8; 32], StorageError> {
        self.observe(Operation::Hash);
        Ok([9; 32])
    }
    fn recover_extent(&mut self, _: ByteRange, _: [u8; 32]) -> Result<(), StorageError> {
        Err(StorageError::Unsupported)
    }
    fn verify(
        &mut self,
        _: Option<[u8; 32]>,
        _: &[(fhd_domain::ByteRange, [u8; 32])],
    ) -> Result<[u8; 32], StorageError> {
        Err(StorageError::Unsupported)
    }
    fn publication(&self) -> fhd_app::storage::Publication {
        fhd_app::storage::Publication::Open
    }
    fn adopt_destination(&mut self, _: &Path) -> Result<(), StorageError> {
        Ok(())
    }
    fn publish(&mut self) -> Result<fhd_app::storage::Published, StorageError> {
        Err(StorageError::Unsupported)
    }
    fn discard(&mut self) -> Result<(), StorageError> {
        self.observe(Operation::Discard);
        if !self.abandoned {
            return Err(StorageError::InvalidState);
        }
        self.discarded = true;
        Ok(())
    }
    fn abandon(&mut self) {
        self.abandoned = true;
    }
}
fn spec() -> PartSpec {
    PartSpec::new(JobId::new(1).unwrap(), Generation::initial(), 1024).unwrap()
}
fn fixture(fault: Fault) -> (FakeFile, Log) {
    let log = Arc::new(Mutex::new(Vec::new()));
    (
        FakeFile {
            spec: spec(),
            log: log.clone(),
            fault,
            data: None,
            gate: None,
            entered: None,
            abandoned: false,
            discarded: false,
        },
        log,
    )
}
async fn require_pending<T>(mut future: Pin<&mut impl Future<Output = T>>) {
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await
}

#[tokio::test]
async fn accepted_commands_drain_fifo_on_one_thread_after_callers_drop_replies() {
    let (mut file, log) = fixture(Fault::None);
    let gate = Arc::new(Gate::default());
    let (entered, waiting) = tokio::sync::oneshot::channel();
    file.gate = Some(gate.clone());
    file.entered = Some(entered);
    let writer = Writer::start(Box::new(file), 4).unwrap();
    let pool = BufferPool::new(2 * MAX_BUFFER).unwrap();
    let cancel = CancellationToken::new();
    let first = pool.acquire(8, &cancel).await.unwrap();
    let second = pool.acquire(8, &cancel).await.unwrap();
    {
        let mut first_write = Box::pin(writer.write(spec(), 0, first, &cancel));
        require_pending(first_write.as_mut()).await;
        waiting.await.unwrap(); // Physical first write is blocked; admission is known.
        let mut second_write = Box::pin(writer.write(spec(), 8, second, &cancel));
        require_pending(second_write.as_mut()).await;
        let mut sync = Box::pin(writer.sync(&cancel));
        require_pending(sync.as_mut()).await;
        let mut hash = Box::pin(writer.hash(ByteRange::new(0, 16).unwrap(), &cancel));
        require_pending(hash.as_mut()).await;
        assert_eq!(pool.in_use(), 2 * MAX_BUFFER);
        // Dropping reply futures must not undo accepted writes or the sync barrier.
    }
    cancel.cancel(); // Cancellation closes future admission, not already accepted IO.
    gate.release();
    writer.shutdown().await.unwrap();
    assert_eq!(pool.in_use(), 0);
    let entries = log.lock().unwrap();
    let operations: Vec<_> = entries.iter().map(|entry| entry.0).collect();
    assert_eq!(
        operations,
        [
            Operation::Write(0, 8),
            Operation::Write(8, 8),
            Operation::Sync,
            Operation::Hash,
            Operation::Drop
        ]
    );
    let worker_thread = entries[0].1;
    assert_ne!(worker_thread, thread::current().id());
    assert!(entries.iter().all(|entry| entry.1 == worker_thread));
}

#[tokio::test]
async fn abandoned_discard_removes_the_part_and_finishes_the_lane() {
    let (file, log) = fixture(Fault::None);
    let writer = Writer::start(Box::new(file), 1).unwrap();
    let pool = BufferPool::new(8).unwrap();
    let cancel = CancellationToken::new();
    let buffer = pool.acquire(8, &cancel).await.unwrap();
    writer.write(spec(), 0, buffer, &cancel).await.unwrap();
    writer.discard(true, &cancel).await.unwrap();
    // The file is gone, so nothing may be written or synced to it afterwards.
    let buffer = pool.acquire(8, &cancel).await.unwrap();
    assert_eq!(
        writer.write(spec(), 8, buffer, &cancel).await,
        Err(WriterError::Closed)
    );
    assert_eq!(pool.in_use(), 0);
    assert_eq!(writer.sync(&cancel).await, Err(WriterError::Closed));
    assert_eq!(writer.shutdown().await, Err(WriterError::Closed));
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .map(|entry| entry.0)
            .collect::<Vec<_>>(),
        [Operation::Write(0, 8), Operation::Discard, Operation::Drop]
    );
}

#[tokio::test]
async fn discarding_unpublished_bytes_is_refused_and_leaves_no_second_attempt() {
    let (file, log) = fixture(Fault::None);
    let writer = Writer::start(Box::new(file), 1).unwrap();
    let cancel = CancellationToken::new();
    let refusal = WriterError::Storage(StorageError::InvalidState);
    // The storage port decides; the lane only carries the verdict back.
    assert_eq!(writer.discard(false, &cancel).await, Err(refusal));
    assert_eq!(writer.discard(true, &cancel).await, Err(refusal));
    assert_eq!(writer.shutdown().await, Err(refusal));
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .map(|entry| entry.0)
            .collect::<Vec<_>>(),
        [Operation::Discard, Operation::Drop]
    );
}

#[tokio::test]
async fn storage_write_failure_poisons_lane_without_more_io_and_returns_credits() {
    let (file, log) = fixture(Fault::Write);
    let writer = Writer::start(Box::new(file), 1).unwrap();
    let pool = BufferPool::new(8).unwrap();
    let cancel = CancellationToken::new();
    let failure = WriterError::Storage(StorageError::Io(ErrorKind::StorageFull));
    for offset in [0, 8] {
        let buffer = pool.acquire(8, &cancel).await.unwrap();
        assert_eq!(
            writer.write(spec(), offset, buffer, &cancel).await,
            Err(failure)
        );
        assert_eq!(pool.in_use(), 0);
    }
    assert_eq!(writer.sync(&cancel).await, Err(failure));
    assert_eq!(
        writer.hash(ByteRange::new(0, 8).unwrap(), &cancel).await,
        Err(failure)
    );
    assert_eq!(writer.shutdown().await, Err(failure));
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .map(|entry| entry.0)
            .collect::<Vec<_>>(),
        [Operation::Write(0, 8), Operation::Drop]
    );
}

#[tokio::test]
async fn failed_sync_is_not_acknowledged_or_followed_by_more_storage_operations() {
    let (file, log) = fixture(Fault::Sync);
    let writer = Writer::start(Box::new(file), 1).unwrap();
    let pool = BufferPool::new(8).unwrap();
    let cancel = CancellationToken::new();
    writer
        .write(spec(), 0, pool.acquire(8, &cancel).await.unwrap(), &cancel)
        .await
        .unwrap();
    let failure = WriterError::Storage(StorageError::Io(ErrorKind::Other));
    assert_eq!(writer.sync(&cancel).await, Err(failure));
    assert_eq!(
        writer
            .write(spec(), 8, pool.acquire(8, &cancel).await.unwrap(), &cancel)
            .await,
        Err(failure)
    );
    assert_eq!(pool.in_use(), 0);
    assert_eq!(writer.shutdown().await, Err(failure));
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .map(|entry| entry.0)
            .collect::<Vec<_>>(),
        [Operation::Write(0, 8), Operation::Sync, Operation::Drop]
    );
}

#[tokio::test]
async fn rejected_generation_bounds_and_cancelled_admission_never_reach_file() {
    let (file, log) = fixture(Fault::None);
    let writer = Writer::start(Box::new(file), 1).unwrap();
    let pool = BufferPool::new(8).unwrap();
    let cancel = CancellationToken::new();
    let stale = PartSpec::new(JobId::new(1).unwrap(), Generation::new(2).unwrap(), 1024).unwrap();
    assert_eq!(
        writer
            .write(stale, 0, pool.acquire(8, &cancel).await.unwrap(), &cancel)
            .await,
        Err(WriterError::WrongGeneration)
    );
    assert_eq!(
        writer
            .write(
                spec(),
                u64::MAX,
                pool.acquire(8, &cancel).await.unwrap(),
                &cancel
            )
            .await,
        Err(WriterError::Bounds)
    );
    let buffer = pool.acquire(8, &cancel).await.unwrap();
    cancel.cancel();
    assert_eq!(
        writer.write(spec(), 0, buffer, &cancel).await,
        Err(WriterError::Cancelled)
    );
    assert_eq!(pool.in_use(), 0);
    writer.shutdown().await.unwrap();
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .map(|entry| entry.0)
            .collect::<Vec<_>>(),
        [Operation::Drop]
    );
}

#[tokio::test]
async fn worker_panic_is_reported_and_unwinding_releases_buffer_budget() {
    let (file, log) = fixture(Fault::Panic);
    let writer = Writer::start(Box::new(file), 1).unwrap();
    let pool = BufferPool::new(8).unwrap();
    let cancel = CancellationToken::new();
    assert_eq!(
        writer
            .write(spec(), 0, pool.acquire(8, &cancel).await.unwrap(), &cancel)
            .await,
        Err(WriterError::WorkerFailed)
    );
    assert_eq!(writer.shutdown().await, Err(WriterError::WorkerFailed));
    assert_eq!(pool.in_use(), 0);
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .map(|entry| entry.0)
            .collect::<Vec<_>>(),
        [Operation::Write(0, 8), Operation::Drop]
    );
}

#[tokio::test]
async fn queued_adjacent_writes_coalesce_without_crossing_sync_barrier() {
    let (mut file, log) = fixture(Fault::None);
    let gate = Arc::new(Gate::default());
    let data = Arc::new(Mutex::new(vec![0; spec().size() as usize]));
    let (entered, waiting) = tokio::sync::oneshot::channel();
    file.gate = Some(gate.clone());
    file.entered = Some(entered);
    file.data = Some(data.clone());
    let writer = Writer::start(Box::new(file), 8).unwrap();
    let pool = BufferPool::new(5 * MAX_BUFFER).unwrap();
    let cancel = CancellationToken::new();
    let mut first = pool.acquire(8, &cancel).await.unwrap();
    first.as_mut_slice().fill(1);
    let mut second = pool.acquire(2, &cancel).await.unwrap();
    second.as_mut_slice().fill(2);
    let mut third = pool.acquire(3, &cancel).await.unwrap();
    third.as_mut_slice().fill(3);
    let mut fourth = pool.acquire(4, &cancel).await.unwrap();
    fourth.as_mut_slice().fill(4);
    let mut last = pool.acquire(5, &cancel).await.unwrap();
    last.as_mut_slice().fill(5);
    {
        let mut first_write = Box::pin(writer.write(spec(), 0, first, &cancel));
        require_pending(first_write.as_mut()).await;
        waiting.await.unwrap(); // First physical IO already started and is blocked.
        let mut second_write = Box::pin(writer.write(spec(), 8, second, &cancel));
        require_pending(second_write.as_mut()).await;
        let mut third_write = Box::pin(writer.write(spec(), 10, third, &cancel));
        require_pending(third_write.as_mut()).await;
        let mut fourth_write = Box::pin(writer.write(spec(), 13, fourth, &cancel));
        require_pending(fourth_write.as_mut()).await;
        let mut sync = Box::pin(writer.sync(&cancel));
        require_pending(sync.as_mut()).await;
        let mut last_write = Box::pin(writer.write(spec(), 17, last, &cancel));
        require_pending(last_write.as_mut()).await;
        assert_eq!(pool.in_use(), 5 * MAX_BUFFER);
        assert_eq!(
            log.lock()
                .unwrap()
                .iter()
                .map(|entry| entry.0)
                .collect::<Vec<_>>(),
            [Operation::Write(0, 8)]
        );
        // All later commands are admitted before release; no sleeps or races are
        // needed to decide which writes are available for the coalescing batch.
        gate.release();
        first_write.await.unwrap();
        second_write.await.unwrap();
        third_write.await.unwrap();
        fourth_write.await.unwrap();
        sync.await.unwrap();
        last_write.await.unwrap();
    }
    writer.shutdown().await.unwrap();
    assert_eq!(pool.in_use(), 0);
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .map(|entry| entry.0)
            .collect::<Vec<_>>(),
        [
            Operation::Write(0, 8),
            Operation::Write(8, 9),
            Operation::Sync,
            Operation::Write(17, 5),
            Operation::Drop,
        ]
    );
    let expected = [vec![1; 8], vec![2; 2], vec![3; 3], vec![4; 4], vec![5; 5]].concat();
    let bytes = data.lock().unwrap();
    assert_eq!(&bytes[..expected.len()], expected.as_slice());
    assert!(bytes[expected.len()..].iter().all(|byte| *byte == 0));
}
