use crate::CancellationToken;
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const MAX_BUFFER: usize = 256 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BufferError {
    InvalidBudget,
    InvalidLength,
    Cancelled,
    Closed,
}
struct Pool {
    permits: Arc<Semaphore>,
    block: usize,
    blocks: usize,
    free: Mutex<Vec<Vec<u8>>>,
}
#[derive(Clone)]
pub struct BufferPool {
    pool: Arc<Pool>,
}
impl BufferPool {
    pub fn new(budget: usize) -> Result<Self, BufferError> {
        if !(1..=512 * 1024 * 1024).contains(&budget) {
            return Err(BufferError::InvalidBudget);
        }
        let block = budget.min(MAX_BUFFER);
        let blocks = budget / block;
        Ok(Self {
            pool: Arc::new(Pool {
                permits: Arc::new(Semaphore::new(blocks)),
                block,
                blocks,
                free: Mutex::new(Vec::new()),
            }),
        })
    }
    pub fn capacity(&self) -> usize {
        self.pool.block * self.pool.blocks
    }
    pub fn in_use(&self) -> usize {
        (self.pool.blocks - self.pool.permits.available_permits()) * self.pool.block
    }
    pub fn close(&self) {
        self.pool.permits.close();
    }
    /// Credit is acquired before allocation and held until the writer drops it.
    /// This covers these application buffers, not HTTP/TLS/kernel allocations.
    pub async fn acquire(
        &self,
        len: usize,
        cancel: &CancellationToken,
    ) -> Result<Buffer, BufferError> {
        if len == 0 || len > self.pool.block {
            return Err(BufferError::InvalidLength);
        }
        let permit = tokio::select! { biased;
            _ = cancel.cancelled() => return Err(BufferError::Cancelled),
            p = self.pool.permits.clone().acquire_owned() => p.map_err(|_| BufferError::Closed)?,
        };
        let mut bytes = self
            .pool
            .free
            .lock()
            .map_err(|_| BufferError::Closed)?
            .pop()
            .unwrap_or_else(|| vec![0; self.pool.block]);
        // Reused buffers cannot expose the previous job's bytes through this API.
        bytes[..len].fill(0);
        Ok(Buffer {
            bytes,
            len,
            pool: self.pool.clone(),
            _permit: permit,
        })
    }
}
/// Not Clone and cannot resize. Moving into the writer transfers the byte budget.
pub struct Buffer {
    bytes: Vec<u8>,
    len: usize,
    pool: Arc<Pool>,
    _permit: OwnedSemaphorePermit,
}
impl Buffer {
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }
    pub(crate) fn append(&mut self, other: &Self) -> bool {
        let Some(end) = self.len.checked_add(other.len) else {
            return false;
        };
        if end > self.bytes.len() {
            return false;
        }
        self.bytes[self.len..end].copy_from_slice(other.as_slice());
        self.len = end;
        true
    }
}
impl Drop for Buffer {
    fn drop(&mut self) {
        if let Ok(mut free) = self.pool.free.lock() {
            free.push(std::mem::take(&mut self.bytes));
        }
        // The permit drops after the buffer is reusable: no unbudgeted allocation gap.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn storage_is_reused_and_previous_job_bytes_are_not_exposed() {
        let pool = BufferPool::new(16).unwrap();
        let token = CancellationToken::new();
        let mut first = pool.acquire(16, &token).await.unwrap();
        first.as_mut_slice().fill(42);
        let address = first.as_slice().as_ptr() as usize;
        drop(first);
        let second = pool.acquire(8, &token).await.unwrap();
        assert_eq!(second.as_slice().as_ptr() as usize, address);
        assert_eq!(second.as_slice(), &[0; 8]);
        assert_eq!(pool.in_use(), 16); // whole physical block remains charged
        drop(second);
        let third = pool.acquire(16, &token).await.unwrap();
        assert_eq!(third.as_slice(), &[0; 16]);
        assert_eq!(pool.capacity(), 16);
    }
    #[tokio::test]
    async fn credits_follow_buffers_across_clones_and_cancel_waits_without_allocation() {
        let pool = BufferPool::new(16).unwrap();
        let child = pool.clone();
        let token = CancellationToken::new();
        let first = pool.acquire(16, &token).await.unwrap();
        assert_eq!(child.in_use(), 16);
        let waiting = token.child_token();
        waiting.cancel();
        assert!(matches!(
            child.acquire(1, &waiting).await,
            Err(BufferError::Cancelled)
        ));
        assert_eq!(pool.in_use(), 16);
        drop(first);
        let second = child.acquire(16, &token).await.unwrap();
        assert_eq!(pool.in_use(), 16);
        drop(second);
        assert_eq!(pool.in_use(), 0);
        pool.close();
        assert!(matches!(
            pool.acquire(1, &token).await,
            Err(BufferError::Closed)
        ));
    }
    #[tokio::test]
    async fn cancelled_parent_releases_waiting_child() {
        let pool = BufferPool::new(1).unwrap();
        let parent = CancellationToken::new();
        let held = pool.acquire(1, &parent).await.unwrap();
        let child = parent.child_token();
        let waiter_pool = pool.clone();
        let waiter = tokio::spawn(async move { waiter_pool.acquire(1, &child).await });
        tokio::task::yield_now().await;
        parent.cancel();
        assert!(matches!(waiter.await.unwrap(), Err(BufferError::Cancelled)));
        assert_eq!(pool.in_use(), 1);
        drop(held);
        assert_eq!(pool.in_use(), 0);
    }
}
