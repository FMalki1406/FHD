//! Cancellation-aware shared pacing of body bytes, not a wire traffic meter.
use crate::Error;
use std::{sync::Arc, time::Duration};
use tokio::sync::{watch, Mutex};

pub(super) const MAX_BYTES_PER_SECOND: u64 = 1024 * 1024 * 1024;
const MAX_SLICE: usize = 64 * 1024;
pub(super) fn valid_limit(value: Option<u64>) -> bool {
    value.is_none_or(|n| (1..=MAX_BYTES_PER_SECOND).contains(&n))
}

struct Budget {
    limit: watch::Sender<Option<u64>>,
    gate: Mutex<()>,
}
/// Cloneable budget shared by every transfer owned by one manager.
#[derive(Clone)]
pub struct Bandwidth {
    inner: Arc<Budget>,
}
impl Bandwidth {
    pub fn new(limit: Option<u64>) -> Result<Self, Error> {
        if !valid_limit(limit) {
            return Err(Error::InvalidOptions);
        }
        let (limit, _) = watch::channel(limit);
        Ok(Self {
            inner: Arc::new(Budget {
                limit,
                gate: Mutex::new(()),
            }),
        })
    }
    pub fn set_limit(&self, limit: Option<u64>) -> Result<(), Error> {
        if !valid_limit(limit) {
            return Err(Error::InvalidOptions);
        }
        self.inner.limit.send_if_modified(|current| {
            if *current == limit {
                false
            } else {
                *current = limit;
                true
            }
        });
        Ok(())
    }
    pub fn limit(&self) -> Option<u64> {
        *self.inner.limit.borrow()
    }
    async fn charge(&self, bytes: u32, cancel: &mut watch::Receiver<bool>) -> Result<(), Error> {
        // Serialize charges; a cancelled waiter cannot reserve future bandwidth.
        let _guard = tokio::select! {biased; _=crate::cancelled(cancel)=>return Err(Error::Cancelled), guard=self.inner.gate.lock()=>guard};
        let mut changes = self.inner.limit.subscribe();
        loop {
            let current = *changes.borrow_and_update();
            if crate::is_cancelled(cancel) {
                return Err(Error::Cancelled);
            }
            let Some(rate) = current else {
                return Ok(());
            };
            let delay = Duration::from_nanos((u64::from(bytes) * 1_000_000_000).div_ceil(rate));
            tokio::select! {
                biased;
                _=crate::cancelled(cancel)=>return Err(Error::Cancelled),
                changed=changes.changed()=>{if changed.is_err(){return Err(Error::Cancelled);} /* Re-pay under new policy; no stale credit. */}
                _=tokio::time::sleep(delay)=>return Ok(()),
            }
        }
    }
}

/// One job's mutable budget plus an optional shared manager budget.
#[derive(Clone)]
pub struct TrafficControl {
    job: Bandwidth,
    global: Bandwidth,
    gate: Arc<Mutex<()>>,
}
impl TrafficControl {
    pub fn new(job_rate: Option<u64>) -> Result<Self, Error> {
        Self::with_global(Bandwidth::new(None)?, job_rate)
    }
    pub fn with_global(global: Bandwidth, job_rate: Option<u64>) -> Result<Self, Error> {
        Ok(Self {
            job: Bandwidth::new(job_rate)?,
            global,
            gate: Arc::new(Mutex::new(())),
        })
    }
    pub fn set_job_rate(&self, limit: Option<u64>) -> Result<(), Error> {
        self.job.set_limit(limit)
    }
    pub fn job_rate(&self) -> Option<u64> {
        self.job.limit()
    }
    pub fn slice_bytes(&self) -> usize {
        [self.job.limit(), self.global.limit()]
            .into_iter()
            .flatten()
            .map(|n| (n / 10).clamp(1, MAX_SLICE as u64) as usize)
            .min()
            .unwrap_or(MAX_SLICE)
    }
    pub async fn consume(
        &self,
        bytes: u32,
        cancel: &mut watch::Receiver<bool>,
    ) -> Result<(), Error> {
        if bytes as usize > MAX_SLICE {
            return Err(Error::InvalidOptions);
        }
        if bytes == 0 {
            return Ok(());
        }
        let _guard = tokio::select! {biased; _=crate::cancelled(cancel)=>return Err(Error::Cancelled),guard=self.gate.lock()=>guard};
        // Job is charged first. Global charge ends immediately before acceptance,
        // preventing queued job delays from bunching already-paid global slices.
        self.job.charge(bytes, cancel).await?;
        self.global.charge(bytes, cancel).await?;
        if crate::is_cancelled(cancel) {
            return Err(Error::Cancelled);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn lowering_live_limit_invalidates_old_faster_wait() {
        for job in [true, false] {
            let global = Bandwidth::new(if job { None } else { Some(1000) }).unwrap();
            let control =
                TrafficControl::with_global(global.clone(), if job { Some(1000) } else { None })
                    .unwrap();
            let worker_control = control.clone();
            let (owner, mut cancel) = watch::channel(false);
            let worker =
                tokio::spawn(async move { worker_control.consume(100, &mut cancel).await });
            tokio::time::sleep(Duration::from_millis(40)).await;
            if job {
                control.set_job_rate(Some(1)).unwrap();
            } else {
                global.set_limit(Some(1)).unwrap();
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert!(
                !worker.is_finished(),
                "old faster policy must not finish the pending wait"
            );
            control.set_job_rate(None).unwrap();
            global.set_limit(None).unwrap();
            worker.await.unwrap().unwrap();
            drop(owner);
        }
    }
    #[test]
    fn bounded_configuration_and_slices() {
        for rate in [0, MAX_BYTES_PER_SECOND + 1, u64::MAX] {
            assert!(TrafficControl::new(Some(rate)).is_err());
        }
        let control = TrafficControl::new(None).unwrap();
        assert_eq!(control.slice_bytes(), 65536);
        control.set_job_rate(Some(1)).unwrap();
        assert_eq!(control.slice_bytes(), 1);
        assert!(control.set_job_rate(Some(0)).is_err());
        assert_eq!(control.job_rate(), Some(1));
    }
    #[tokio::test]
    async fn aggregate_budget_is_shared_between_jobs() {
        let global = Bandwidth::new(Some(2048)).unwrap();
        let a = TrafficControl::with_global(global.clone(), None).unwrap();
        let b = TrafficControl::with_global(global, None).unwrap();
        let (owner, cancel) = watch::channel(false);
        let mut ca = cancel.clone();
        let mut cb = cancel;
        let start = std::time::Instant::now();
        let (ra, rb) = tokio::join!(a.consume(1024, &mut ca), b.consume(1024, &mut cb));
        ra.unwrap();
        rb.unwrap();
        assert!(start.elapsed() >= Duration::from_millis(950));
        drop(owner);
    }
    #[tokio::test]
    async fn unchanged_updates_do_not_restart_the_wait() {
        let global = Bandwidth::new(Some(1000)).unwrap();
        let control = TrafficControl::with_global(global.clone(), None).unwrap();
        let writer = tokio::spawn(async move {
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                global.set_limit(Some(1000)).unwrap();
            }
        });
        let (owner, mut cancel) = watch::channel(false);
        tokio::time::timeout(
            Duration::from_millis(350),
            control.consume(100, &mut cancel),
        )
        .await
        .unwrap()
        .unwrap();
        writer.await.unwrap();
        drop(owner);
    }
    #[tokio::test]
    async fn live_change_wakes_global_wait_and_job_wait() {
        for job in [true, false] {
            let global = Bandwidth::new(if job { None } else { Some(1) }).unwrap();
            let control =
                TrafficControl::with_global(global.clone(), if job { Some(1) } else { None })
                    .unwrap();
            let updater = control.clone();
            let update = tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                if job {
                    updater.set_job_rate(None).unwrap();
                } else {
                    global.set_limit(None).unwrap();
                }
            });
            let (owner, mut cancel) = watch::channel(false);
            tokio::time::timeout(Duration::from_secs(2), control.consume(10, &mut cancel))
                .await
                .unwrap()
                .unwrap();
            update.await.unwrap();
            drop(owner);
        }
    }
    #[tokio::test]
    async fn cancellation_interrupts_wait_without_allocating_credit() {
        use std::{
            future::{poll_fn, Future},
            task::Poll,
        };
        for job in [true, false] {
            let global = Bandwidth::new(if job { None } else { Some(1) }).unwrap();
            let control =
                TrafficControl::with_global(global, if job { Some(1) } else { None }).unwrap();
            let (owner, mut cancel) = watch::channel(false);
            let mut waiting = Box::pin(control.consume(10, &mut cancel));
            poll_fn(|cx| {
                assert!(waiting.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            owner.send_replace(true);
            // The very next poll must complete; no timer advance or real-time
            // deadline can accidentally make an uncancellable wait pass.
            poll_fn(|cx| {
                assert_eq!(
                    waiting.as_mut().poll(cx),
                    Poll::Ready(Err(Error::Cancelled))
                );
                Poll::Ready(())
            })
            .await;
            drop(waiting);
            assert!(control.gate.try_lock().is_ok());
            assert!(control.job.inner.gate.try_lock().is_ok());
            assert!(control.global.inner.gate.try_lock().is_ok());
        }
    }
}
