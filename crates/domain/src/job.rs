use crate::{
    CommitBatch, DomainError, Generation, JobId, JobSpec, Lease, SegmentId, SegmentMap, SyncTicket,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Probing,
    Transferring,
    Pausing,
    Paused,
    RetryWait,
    NeedsAction,
    Verifying,
    Publishing,
    Completed,
    Cancelling,
    Cancelled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    SourceChanged,
    Authentication,
    Storage,
    Integrity,
    Network,
    Policy,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobCommand {
    Start,
    ProbeSucceeded { total: u64, max_segments: usize },
    Pause,
    WorkersDrained,
    Resume,
    Retry { at_tick: u64 },
    RetryDue { now_tick: u64 },
    RequireAction { reason: StopReason },
    RetryApproved,
    AllSegmentsDurable,
    VerificationPassed,
    PublishCommitted,
    Cancel,
    ReplaceRepresentation,
}
#[derive(Clone, Debug)]
pub struct JobEvent {
    job: JobId,
    version: u64,
    from: JobState,
    to: JobState,
    generation: Generation,
    command: JobCommand,
}
impl JobEvent {
    pub fn job(&self) -> JobId {
        self.job
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn from(&self) -> JobState {
        self.from
    }
    pub fn to(&self) -> JobState {
        self.to
    }
    pub fn generation(&self) -> Generation {
        self.generation
    }
}
#[derive(Debug)]
pub struct Job {
    id: JobId,
    spec: JobSpec,
    state: JobState,
    generation: Generation,
    version: u64,
    reason: Option<StopReason>,
    retry_at: Option<u64>,
    segments: Option<SegmentMap>,
}
impl Job {
    fn snapshot(&self) -> Self {
        Self {
            id: self.id,
            spec: self.spec.clone(),
            state: self.state,
            generation: self.generation,
            version: self.version,
            reason: self.reason,
            retry_at: self.retry_at,
            segments: self.segments.as_ref().map(SegmentMap::snapshot),
        }
    }

    pub fn new(id: JobId, spec: JobSpec) -> Self {
        Self {
            id,
            spec,
            state: JobState::Queued,
            generation: Generation::initial(),
            version: 0,
            reason: None,
            retry_at: None,
            segments: None,
        }
    }
    pub fn id(&self) -> JobId {
        self.id
    }
    pub fn spec(&self) -> &JobSpec {
        &self.spec
    }
    pub fn state(&self) -> JobState {
        self.state
    }
    pub fn generation(&self) -> Generation {
        self.generation
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn reason(&self) -> Option<StopReason> {
        self.reason
    }
    pub fn segments(&self) -> Option<&SegmentMap> {
        self.segments.as_ref()
    }
    pub fn retry_at(&self) -> Option<u64> {
        self.retry_at
    }
    /// Plan an event without mutation. Persist the event and related extents before apply.
    pub fn decide(&self, command: JobCommand) -> Result<Vec<JobEvent>, DomainError> {
        let mut next = self.snapshot();
        next.execute(command)?;
        let version = self.version.checked_add(1).ok_or(DomainError::Overflow)?;
        Ok(vec![JobEvent {
            job: self.id,
            version,
            from: self.state,
            to: next.state,
            generation: self.generation,
            command,
        }])
    }
    /// Checked replay. Duplicate/out-of-order events never mutate the aggregate.
    pub fn apply(&mut self, event: &JobEvent) -> Result<(), DomainError> {
        if event.job != self.id
            || event.from != self.state
            || event.generation != self.generation
            || self.version.checked_add(1) != Some(event.version)
        {
            return Err(DomainError::StaleEvent);
        }
        let mut next = self.snapshot();
        next.execute(event.command)?;
        if next.state != event.to {
            return Err(DomainError::StaleEvent);
        }
        next.version = event.version;
        *self = next;
        Ok(())
    }
    /// Convenience for simulations; applications must decide, commit, then apply.
    pub fn handle(&mut self, command: JobCommand) -> Result<Vec<JobEvent>, DomainError> {
        let events = self.decide(command)?;
        for event in &events {
            self.apply(event)?;
        }
        Ok(events)
    }
    fn execute(&mut self, command: JobCommand) -> Result<(), DomainError> {
        use JobCommand as C;
        use JobState as S;
        let next = match (self.state, command) {
            (S::Queued, C::Start) => S::Probing,
            (
                S::Probing,
                C::ProbeSucceeded {
                    total,
                    max_segments,
                },
            ) => {
                if total > self.spec.max_bytes() || !(1..=262144).contains(&max_segments) {
                    return Err(DomainError::InvalidInput);
                }
                if let Some(map) = &self.segments {
                    if map.total() != total || map.generation() != self.generation {
                        return Err(DomainError::InvalidInput);
                    }
                } else {
                    self.segments = Some(SegmentMap::new(
                        self.id,
                        self.generation,
                        total,
                        max_segments,
                    )?);
                }
                S::Transferring
            }
            (S::Queued, C::Pause) => S::Paused,
            (S::Probing | S::Transferring, C::Pause) => S::Pausing,
            (S::Pausing, C::WorkersDrained) => {
                if self.has_active_leases()
                    || self
                        .segments
                        .as_ref()
                        .is_some_and(SegmentMap::has_pending_checkpoint)
                {
                    return Err(DomainError::Incomplete);
                }
                S::Paused
            }
            (S::Paused, C::Resume) => S::Queued,
            (S::Probing | S::Transferring, C::Retry { at_tick }) => {
                if self.has_active_leases()
                    || self
                        .segments
                        .as_ref()
                        .is_some_and(SegmentMap::has_pending_checkpoint)
                {
                    return Err(DomainError::Incomplete);
                }
                self.retry_at = Some(at_tick);
                S::RetryWait
            }
            (S::RetryWait, C::RetryDue { now_tick }) => {
                if self.retry_at.is_none_or(|at| now_tick < at) {
                    return Err(DomainError::InvalidTransition);
                }
                self.retry_at = None;
                S::Queued
            }
            (
                S::Probing | S::Transferring | S::Verifying | S::Publishing | S::Pausing,
                C::RequireAction { reason },
            ) => {
                if self.has_active_leases()
                    || self
                        .segments
                        .as_ref()
                        .is_some_and(SegmentMap::has_pending_checkpoint)
                {
                    return Err(DomainError::Incomplete);
                }
                self.reason = Some(reason);
                S::NeedsAction
            }
            (S::NeedsAction, C::RetryApproved) => {
                if matches!(
                    self.reason,
                    Some(StopReason::SourceChanged | StopReason::Integrity)
                ) {
                    return Err(DomainError::InvalidTransition);
                }
                self.reason = None;
                S::Queued
            }
            (S::Transferring, C::AllSegmentsDurable) => {
                if !self.segments.as_ref().is_some_and(SegmentMap::all_durable) {
                    return Err(DomainError::Incomplete);
                }
                S::Verifying
            }
            (S::Verifying, C::VerificationPassed) => S::Publishing,
            (S::Publishing, C::PublishCommitted) => S::Completed,
            (S::Queued | S::Paused | S::RetryWait | S::NeedsAction, C::Cancel) => {
                self.retry_at = None;
                S::Cancelled
            }
            (S::Probing | S::Transferring | S::Pausing | S::Verifying, C::Cancel) => S::Cancelling,
            (S::Cancelling, C::WorkersDrained) => {
                if self.has_active_leases()
                    || self
                        .segments
                        .as_ref()
                        .is_some_and(SegmentMap::has_pending_checkpoint)
                {
                    return Err(DomainError::Incomplete);
                }
                S::Cancelled
            }
            (S::NeedsAction | S::Paused, C::ReplaceRepresentation) => {
                self.generation = self.generation.next()?;
                self.segments = None;
                self.reason = None;
                self.retry_at = None;
                S::Queued
            }
            _ => return Err(DomainError::InvalidTransition),
        };
        self.state = next;
        Ok(())
    }
    fn has_active_leases(&self) -> bool {
        self.segments.as_ref().is_some_and(|map| {
            map.segments()
                .iter()
                .any(|s| matches!(s.state(), crate::SegmentState::InFlight { .. }))
        })
    }
    fn map_mut(&mut self) -> Result<&mut SegmentMap, DomainError> {
        if !matches!(
            self.state,
            JobState::Transferring | JobState::Pausing | JobState::Cancelling
        ) {
            return Err(DomainError::InvalidTransition);
        }
        self.segments.as_mut().ok_or(DomainError::Incomplete)
    }
    pub fn lease_segment(&mut self, id: SegmentId, worker: u64) -> Result<Lease, DomainError> {
        if self.state != JobState::Transferring {
            return Err(DomainError::InvalidTransition);
        }
        self.map_mut()?.lease(id, worker)
    }
    pub fn split_pending(&mut self, id: SegmentId, at: u64) -> Result<SegmentId, DomainError> {
        if self.state != JobState::Transferring {
            return Err(DomainError::InvalidTransition);
        }
        self.map_mut()?.split_pending(id, at)
    }
    pub fn mark_written(&mut self, lease: Lease) -> Result<(), DomainError> {
        self.map_mut()?.mark_written(lease)
    }
    pub fn release(&mut self, lease: Lease) -> Result<(), DomainError> {
        self.map_mut()?.release(lease)
    }
    /// Call only after the adapter stops using the old ticket and reconciles uncertain IO.
    pub fn abandon_checkpoint(&mut self) -> Result<(), DomainError> {
        self.map_mut()?.discard_checkpoint();
        Ok(())
    }
    pub fn prepare_sync(&mut self) -> Result<SyncTicket, DomainError> {
        self.map_mut()?.prepare_sync()
    }
    pub fn acknowledge_sync(&mut self, ticket: SyncTicket) -> Result<CommitBatch, DomainError> {
        self.map_mut()?.acknowledge_sync(ticket)
    }
    pub fn acknowledge_commit(&mut self, batch: CommitBatch) -> Result<(), DomainError> {
        self.map_mut()?.acknowledge_commit(batch)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DestinationRef, Priority, SourceRef};
    fn job() -> Job {
        Job::new(
            JobId::new(1).unwrap(),
            JobSpec::new(
                SourceRef::new(1).unwrap(),
                DestinationRef::new(1).unwrap(),
                None,
                Priority::Normal,
                1024,
            )
            .unwrap(),
        )
    }
    #[test]
    fn every_state_command_pair_matches_explicit_transition_table() {
        use JobCommand as C;
        use JobState::*;
        let states = [
            Queued,
            Probing,
            Transferring,
            Pausing,
            Paused,
            RetryWait,
            NeedsAction,
            Verifying,
            Publishing,
            Completed,
            Cancelling,
            Cancelled,
        ];
        let commands = [
            C::Start,
            C::ProbeSucceeded {
                total: 0,
                max_segments: 16,
            },
            C::Pause,
            C::WorkersDrained,
            C::Resume,
            C::Retry { at_tick: 10 },
            C::RetryDue { now_tick: 10 },
            C::RequireAction {
                reason: StopReason::Network,
            },
            C::RetryApproved,
            C::AllSegmentsDurable,
            C::VerificationPassed,
            C::PublishCommitted,
            C::Cancel,
            C::ReplaceRepresentation,
        ];
        // Rows are states; columns are the explicit commands above. Guards use a drained empty map.
        let rows: [&[(usize, JobState)]; 12] = [
            &[(0, Probing), (2, Paused), (12, Cancelled)],
            &[
                (1, Transferring),
                (2, Pausing),
                (5, RetryWait),
                (7, NeedsAction),
                (12, Cancelling),
            ],
            &[
                (2, Pausing),
                (5, RetryWait),
                (7, NeedsAction),
                (9, Verifying),
                (12, Cancelling),
            ],
            &[(3, Paused), (7, NeedsAction), (12, Cancelling)],
            &[(4, Queued), (12, Cancelled), (13, Queued)],
            &[(6, Queued), (12, Cancelled)],
            &[(8, Queued), (12, Cancelled), (13, Queued)],
            &[(7, NeedsAction), (10, Publishing), (12, Cancelling)],
            &[(7, NeedsAction), (11, Completed)],
            &[],
            &[(3, Cancelled)],
            &[],
        ];
        for (row, state) in states.into_iter().enumerate() {
            for (column, command) in commands.into_iter().enumerate() {
                let mut value = job();
                value.state = state;
                value.retry_at = Some(10);
                value.segments = Some(SegmentMap::new(value.id, value.generation, 0, 16).unwrap());
                let before = value.snapshot();
                let result = value.handle(command);
                match rows[row].iter().find(|(index, _)| *index == column) {
                    Some((_, target)) => {
                        assert!(result.is_ok(), "{state:?} {command:?}");
                        assert_eq!(value.state, *target);
                    }
                    None => {
                        assert_eq!(
                            result.unwrap_err(),
                            DomainError::InvalidTransition,
                            "{state:?} {command:?}"
                        );
                        assert_eq!(value.state, before.state);
                        assert_eq!(value.version, before.version);
                    }
                }
            }
        }
    }
    #[test]
    fn only_committed_ranges_allow_verification_and_event_replay_is_ordered() {
        let mut value = job();
        let events = value.decide(JobCommand::Start).unwrap();
        assert_eq!(value.state, JobState::Queued);
        value.apply(&events[0]).unwrap();
        assert_eq!(value.apply(&events[0]), Err(DomainError::StaleEvent));
        value
            .handle(JobCommand::ProbeSucceeded {
                total: 10,
                max_segments: 4,
            })
            .unwrap();
        let id = value.segments().unwrap().segments()[0].id();
        let lease = value.lease_segment(id, 1).unwrap();
        value.mark_written(lease).unwrap();
        assert_eq!(
            value.handle(JobCommand::AllSegmentsDurable).unwrap_err(),
            DomainError::Incomplete
        );
        let ticket = value.prepare_sync().unwrap();
        let batch = value.acknowledge_sync(ticket).unwrap();
        assert_eq!(
            value.handle(JobCommand::AllSegmentsDurable).unwrap_err(),
            DomainError::Incomplete
        );
        value.acknowledge_commit(batch).unwrap();
        value.handle(JobCommand::AllSegmentsDurable).unwrap();
        value.handle(JobCommand::VerificationPassed).unwrap();
        assert_eq!(
            value.handle(JobCommand::Cancel).unwrap_err(),
            DomainError::InvalidTransition
        );
        value.handle(JobCommand::PublishCommitted).unwrap();
        assert_eq!(value.state, JobState::Completed);
    }
    #[test]
    fn pause_waits_for_workers_and_retry_obeys_injected_tick() {
        let mut value = job();
        value.handle(JobCommand::Start).unwrap();
        value
            .handle(JobCommand::ProbeSucceeded {
                total: 10,
                max_segments: 4,
            })
            .unwrap();
        let id = value.segments().unwrap().segments()[0].id();
        let lease = value.lease_segment(id, 1).unwrap();
        value.handle(JobCommand::Pause).unwrap();
        assert_eq!(
            value.handle(JobCommand::WorkersDrained).unwrap_err(),
            DomainError::Incomplete
        );
        value.release(lease).unwrap();
        value.handle(JobCommand::WorkersDrained).unwrap();
        value.handle(JobCommand::Resume).unwrap();
        value.handle(JobCommand::Start).unwrap();
        value.handle(JobCommand::Retry { at_tick: 100 }).unwrap();
        assert_eq!(
            value
                .handle(JobCommand::RetryDue { now_tick: 99 })
                .unwrap_err(),
            DomainError::InvalidTransition
        );
        value
            .handle(JobCommand::RetryDue { now_tick: 100 })
            .unwrap();
    }
    #[test]
    fn pause_drains_pending_checkpoint_and_failed_sync_can_be_retried() {
        let mut value = job();
        value.handle(JobCommand::Start).unwrap();
        value
            .handle(JobCommand::ProbeSucceeded {
                total: 10,
                max_segments: 4,
            })
            .unwrap();
        let lease = value
            .lease_segment(value.segments().unwrap().segments()[0].id(), 1)
            .unwrap();
        value.mark_written(lease).unwrap();
        let ticket = value.prepare_sync().unwrap();
        value.handle(JobCommand::Pause).unwrap();
        assert_eq!(
            value.handle(JobCommand::WorkersDrained).unwrap_err(),
            DomainError::Incomplete
        );
        value.abandon_checkpoint().unwrap();
        assert_eq!(
            value.acknowledge_sync(ticket).unwrap_err(),
            DomainError::StaleToken
        );
        let ticket = value.prepare_sync().unwrap();
        let batch = value.acknowledge_sync(ticket).unwrap();
        value.acknowledge_commit(batch).unwrap();
        value.handle(JobCommand::WorkersDrained).unwrap();
        assert_eq!(value.state(), JobState::Paused);
    }
    #[test]
    fn retry_and_needs_action_cannot_orphan_checkpoint() {
        let mut value = job();
        value.handle(JobCommand::Start).unwrap();
        value
            .handle(JobCommand::ProbeSucceeded {
                total: 10,
                max_segments: 4,
            })
            .unwrap();
        let id = value.segments().unwrap().segments()[0].id();
        let lease = value.lease_segment(id, 1).unwrap();
        value.mark_written(lease).unwrap();
        let ticket = value.prepare_sync().unwrap();
        for command in [
            JobCommand::Retry { at_tick: 10 },
            JobCommand::RequireAction {
                reason: StopReason::Storage,
            },
        ] {
            assert_eq!(value.handle(command).unwrap_err(), DomainError::Incomplete);
            assert_eq!(value.state(), JobState::Transferring);
        }
        let batch = value.acknowledge_sync(ticket).unwrap();
        value.acknowledge_commit(batch).unwrap();
        value
            .handle(JobCommand::RequireAction {
                reason: StopReason::SourceChanged,
            })
            .unwrap();
        assert_eq!(
            value.handle(JobCommand::RetryApproved).unwrap_err(),
            DomainError::InvalidTransition
        );
        value.handle(JobCommand::ReplaceRepresentation).unwrap();
        assert_eq!(value.generation().get(), 2);
        assert!(value.segments().is_none());
    }
}
