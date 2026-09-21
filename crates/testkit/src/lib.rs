//! Deterministic in-memory ports for application tests. Never a production store.
#![forbid(unsafe_code)]
use fhd_app::{
    AddUnitOfWork, AppError, Authorizer, CommitError, EntitlementGate, JobRepository, PortFuture,
    Principal, Receipt, ReceiptKey,
};
use fhd_domain::{Job, JobId, JobSpec};
use std::{collections::HashMap, sync::Mutex};

#[derive(Clone, Copy, Debug, Default)]
pub enum CommitFault {
    #[default]
    None,
    BeforeCommit,
    AfterCommit,
}
struct State {
    next: u64,
    jobs: HashMap<JobId, Job>,
    receipts: HashMap<ReceiptKey, Receipt>,
    fault: CommitFault,
    calls: usize,
}
pub struct MemoryRepository {
    state: Mutex<State>,
    capacity: usize,
}
impl MemoryRepository {
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(State {
                next: 0,
                jobs: HashMap::new(),
                receipts: HashMap::new(),
                fault: CommitFault::None,
                calls: 0,
            }),
            capacity,
        }
    }
    pub fn fail_next(&self, fault: CommitFault) {
        self.state.lock().unwrap().fault = fault;
    }
    pub fn job_count(&self) -> usize {
        self.state.lock().unwrap().jobs.len()
    }
    pub fn commit_calls(&self) -> usize {
        self.state.lock().unwrap().calls
    }
    pub fn remove(&self, key: ReceiptKey) {
        let mut state = self.state.lock().unwrap();
        if let Some(receipt) = state.receipts.get(&key).cloned() {
            state.jobs.remove(&receipt.job());
            state.receipts.insert(key, receipt.tombstone());
        }
    }
}
impl JobRepository for MemoryRepository {
    fn receipt(&self, key: ReceiptKey) -> PortFuture<'_, Result<Option<Receipt>, AppError>> {
        Box::pin(async move {
            Ok(self
                .state
                .lock()
                .map_err(|_| AppError::PersistenceUnavailable)?
                .receipts
                .get(&key)
                .cloned())
        })
    }
    fn reserve_id(&self) -> PortFuture<'_, Result<JobId, AppError>> {
        Box::pin(async move {
            let mut state = self
                .state
                .lock()
                .map_err(|_| AppError::PersistenceUnavailable)?;
            state.next = state.next.checked_add(1).ok_or(AppError::Capacity)?;
            JobId::new(state.next).map_err(|_| AppError::Capacity)
        })
    }
    fn commit_add(&self, unit: AddUnitOfWork) -> PortFuture<'_, Result<(), CommitError>> {
        Box::pin(async move {
            let mut state = self.state.lock().map_err(|_| CommitError::Unavailable)?;
            state.calls += 1;
            let fault = std::mem::take(&mut state.fault);
            if matches!(fault, CommitFault::BeforeCommit) {
                return Err(CommitError::Unavailable);
            }
            if state.receipts.contains_key(&unit.receipt().key())
                || state.jobs.contains_key(&unit.receipt().job())
            {
                return Err(CommitError::Conflict);
            }
            if state.jobs.len() >= self.capacity || state.receipts.len() >= self.capacity {
                return Err(CommitError::Capacity);
            }
            let (job, receipt) = unit.into_parts();
            state.jobs.insert(receipt.job(), job);
            state.receipts.insert(receipt.key(), receipt);
            if matches!(fault, CommitFault::AfterCommit) {
                return Err(CommitError::Unavailable);
            }
            Ok(())
        })
    }
}

pub struct Allow;
impl Authorizer for Allow {
    fn authorize_add(&self, _: Principal, _: &JobSpec) -> Result<(), AppError> {
        Ok(())
    }
}
impl EntitlementGate for Allow {
    fn authorize_add(&self, _: Principal, _: &JobSpec) -> Result<(), AppError> {
        Ok(())
    }
}
pub struct Deny;
impl Authorizer for Deny {
    fn authorize_add(&self, _: Principal, _: &JobSpec) -> Result<(), AppError> {
        Err(AppError::Forbidden)
    }
}
impl EntitlementGate for Deny {
    fn authorize_add(&self, _: Principal, _: &JobSpec) -> Result<(), AppError> {
        Err(AppError::EntitlementDenied)
    }
}
