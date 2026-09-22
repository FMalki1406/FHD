use crate::{
    ByteRange, CommitBatch, DomainError, Generation, JobId, JobSpec, Lease, SegmentId, SegmentMap,
    SyncTicket,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Probing,
    Transferring,
    /// Sole exit from Probing/Transferring other than completion; see `Job::stop_target`.
    Stopping,
    Paused,
    RetryWait,
    NeedsAction,
    Verifying,
    Publishing,
    Cancelling,
    /// Non-terminal: Resume starts a fresh attempt.
    Failed,
    Completed,
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
/// Where a stopping job lands once workers, writer lanes and checkpoints drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopTarget {
    Verifying,
    Queued,
    Paused,
    RetryWait { at_tick: u64 },
    NeedsAction { reason: StopReason },
    Failed { reason: StopReason },
}
impl StopTarget {
    fn rank(self) -> u8 {
        match self {
            Self::Verifying => 0,
            Self::Queued => 1,
            Self::Paused => 2,
            Self::RetryWait { .. } => 3,
            Self::NeedsAction { .. } => 4,
            Self::Failed { .. } => 5,
        }
    }
    /// Concurrent causes never lower severity; the first reason of a rank wins.
    fn raise(self, other: Self) -> Self {
        match (self, other) {
            (Self::RetryWait { at_tick: a }, Self::RetryWait { at_tick: b }) => {
                Self::RetryWait { at_tick: a.max(b) }
            }
            _ if other.rank() > self.rank() => other,
            _ => self,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobCommand {
    Start,
    ProbeSucceeded {
        total: u64,
        max_segments: usize,
    },
    Pause,
    Resume,
    Cancel,
    /// Scheduler reclaims the slot for higher-priority work.
    Preempt,
    AllSegmentsDurable,
    Retry {
        at_tick: u64,
    },
    RequireAction {
        reason: StopReason,
    },
    Fail {
        reason: StopReason,
    },
    /// Validators or status proved a new representation; drain, then restart under generation+1.
    RepresentationChanged,
    WorkersDrained,
    RetryDue {
        now_tick: u64,
    },
    VerificationPassed,
    PublishCommitted,
    /// Part cleanup ran; orphans it could not remove are recorded by the storage adapter.
    CleanupFinished,
    ReplaceRepresentation,
}
/// Everything an event decides, so a repository persists it and `apply` can reject drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobProjection {
    pub state: JobState,
    pub generation: Generation,
    pub reason: Option<StopReason>,
    pub retry_at: Option<u64>,
    pub stop: Option<StopTarget>,
    pub replace_on_drain: bool,
    pub attempts: u8,
    pub durable_bytes: u64,
}
#[derive(Clone, Debug)]
pub struct JobEvent {
    job: JobId,
    version: u64,
    from: JobState,
    to: JobState,
    generation: Generation,
    command: JobCommand,
    outcome: JobProjection,
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
    pub fn command(&self) -> JobCommand {
        self.command
    }
    pub fn outcome(&self) -> JobProjection {
        self.outcome
    }
}
/// A job as a repository persists it. Only durable ranges survive; `Job::restore` validates.
#[derive(Clone, Debug)]
pub struct JobRecord {
    pub id: JobId,
    pub spec: JobSpec,
    pub version: u64,
    pub state: JobState,
    pub generation: Generation,
    pub reason: Option<StopReason>,
    pub retry_at: Option<u64>,
    pub stop: Option<StopTarget>,
    pub replace_on_drain: bool,
    pub attempts: u8,
    /// `(total, max_segments)` from this generation's ProbeSucceeded.
    pub plan: Option<(u64, usize)>,
    pub durable: Vec<ByteRange>,
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
    stop: Option<StopTarget>,
    replace_on_drain: bool,
    attempts: u8,
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
            stop: self.stop,
            replace_on_drain: self.replace_on_drain,
            attempts: self.attempts,
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
            stop: None,
            replace_on_drain: false,
            attempts: 0,
            segments: None,
        }
    }
    /// Rebuilds a persisted job exactly, without leases or uncommitted bytes. Recovery
    /// then uses ordinary commands (e.g. Pause, WorkersDrained); there is no restart path.
    pub fn restore(record: JobRecord) -> Result<Self, DomainError> {
        use JobState as S;
        let r = &record;
        let consistent = r.stop.is_some() == (r.state == S::Stopping)
            && (!r.replace_on_drain || r.state == S::Stopping)
            && r.retry_at.is_some() == (r.state == S::RetryWait)
            && (r.reason.is_some() || !matches!(r.state, S::NeedsAction | S::Failed))
            && (r.plan.is_some()
                || !matches!(
                    r.state,
                    S::Transferring | S::Verifying | S::Publishing | S::Completed
                ))
            && (r.plan.is_some() || r.durable.is_empty())
            && r.plan.is_none_or(|(total, _)| total <= r.spec.max_bytes());
        if !consistent {
            return Err(DomainError::InvalidInput);
        }
        let segments = r
            .plan
            .map(|(total, maximum)| {
                SegmentMap::restore(r.id, r.generation, total, maximum, &r.durable)
            })
            .transpose()?;
        if matches!(r.state, S::Verifying | S::Publishing | S::Completed)
            && !segments.as_ref().is_some_and(SegmentMap::all_durable)
        {
            return Err(DomainError::InvalidInput);
        }
        Ok(Self {
            id: record.id,
            spec: record.spec,
            state: record.state,
            generation: record.generation,
            version: record.version,
            reason: record.reason,
            retry_at: record.retry_at,
            stop: record.stop,
            replace_on_drain: record.replace_on_drain,
            attempts: record.attempts,
            segments,
        })
    }
    /// `(total, max_segments)` a repository needs to rebuild the segment map.
    pub fn plan(&self) -> Option<(u64, usize)> {
        self.segments.as_ref().map(|m| (m.total(), m.maximum()))
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
    pub fn stop_target(&self) -> Option<StopTarget> {
        self.stop
    }
    pub fn representation_change_pending(&self) -> bool {
        self.replace_on_drain
    }
    /// Transfer attempts since the last user Resume or new representation.
    pub fn attempts(&self) -> u8 {
        self.attempts
    }
    pub fn projection(&self) -> JobProjection {
        JobProjection {
            state: self.state,
            generation: self.generation,
            reason: self.reason,
            retry_at: self.retry_at,
            stop: self.stop,
            replace_on_drain: self.replace_on_drain,
            attempts: self.attempts,
            durable_bytes: self.segments.as_ref().map_or(0, SegmentMap::durable_bytes),
        }
    }
    /// The storage adapter may delete part files only once this holds.
    pub fn cleanup_ready(&self) -> bool {
        self.state == JobState::Cancelling && self.quiescent()
    }
    /// States from which the repository may delete the job record.
    pub fn removable(&self) -> bool {
        matches!(
            self.state,
            JobState::Queued
                | JobState::Paused
                | JobState::RetryWait
                | JobState::NeedsAction
                | JobState::Failed
                | JobState::Completed
                | JobState::Cancelled
        )
    }
    /// Plan without mutation. An empty result means the command is an accepted no-op.
    /// Persist events and related extents before apply.
    pub fn decide(&self, command: JobCommand) -> Result<Vec<JobEvent>, DomainError> {
        let mut next = self.snapshot();
        if !next.execute(command)? {
            return Ok(vec![]);
        }
        let version = self.version.checked_add(1).ok_or(DomainError::Overflow)?;
        Ok(vec![JobEvent {
            job: self.id,
            version,
            from: self.state,
            to: next.state,
            generation: self.generation,
            command,
            outcome: next.projection(),
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
        // Segment progress between decide and apply changes guard results; the whole
        // projection must match what was persisted, not only the state name.
        let mut next = self.snapshot();
        if !next.execute(event.command)?
            || next.state != event.to
            || next.projection() != event.outcome
        {
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
    fn quiescent(&self) -> bool {
        !self.has_active_leases()
            && !self
                .segments
                .as_ref()
                .is_some_and(SegmentMap::has_pending_checkpoint)
    }
    /// Quiescent and every written byte committed, unless the generation is being replaced.
    fn settled(&self) -> bool {
        self.quiescent()
            && (self.replace_on_drain
                || !self.segments.as_ref().is_some_and(SegmentMap::has_unsynced))
    }
    fn all_durable(&self) -> bool {
        self.segments.as_ref().is_some_and(SegmentMap::all_durable)
    }
    fn begin_stop(&mut self, target: StopTarget) -> JobState {
        self.stop = Some(target);
        JobState::Stopping
    }
    /// `Ok(false)` is an accepted no-op; the aggregate is unchanged.
    fn execute(&mut self, command: JobCommand) -> Result<bool, DomainError> {
        use JobCommand as C;
        use JobState as S;
        let next = match (self.state, command) {
            (S::Queued, C::Start) => {
                self.attempts = self.attempts.saturating_add(1);
                S::Probing
            }
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

            (S::Probing | S::Transferring, C::Pause) => self.begin_stop(StopTarget::Paused),
            (S::Probing | S::Transferring, C::Preempt) => self.begin_stop(StopTarget::Queued),
            (S::Probing | S::Transferring, C::Retry { at_tick }) => {
                self.begin_stop(StopTarget::RetryWait { at_tick })
            }
            (S::Probing | S::Transferring, C::RequireAction { reason }) => {
                self.begin_stop(StopTarget::NeedsAction { reason })
            }
            (S::Probing | S::Transferring, C::Fail { reason }) => {
                self.begin_stop(StopTarget::Failed { reason })
            }
            (S::Probing | S::Transferring, C::RepresentationChanged) => {
                self.replace_on_drain = true;
                self.begin_stop(StopTarget::Queued)
            }
            (S::Transferring, C::AllSegmentsDurable) => {
                if !self.all_durable() {
                    return Err(DomainError::Incomplete);
                }
                self.begin_stop(StopTarget::Verifying)
            }

            (S::Stopping, C::Resume) => {
                if self.stop != Some(StopTarget::Paused) {
                    return Ok(false);
                }
                self.stop = Some(if self.all_durable() && !self.replace_on_drain {
                    StopTarget::Verifying
                } else {
                    StopTarget::Queued
                });
                self.attempts = 0;
                S::Stopping
            }
            (S::Stopping, C::RepresentationChanged) => {
                if self.replace_on_drain {
                    return Ok(false);
                }
                let current = self.stop.ok_or(DomainError::InvalidTransition)?;
                self.replace_on_drain = true;
                self.stop = Some(current.raise(StopTarget::Queued));
                S::Stopping
            }
            (
                S::Stopping,
                C::Pause | C::Preempt | C::Retry { .. } | C::RequireAction { .. } | C::Fail { .. },
            ) => {
                let cause = match command {
                    C::Pause => StopTarget::Paused,
                    C::Preempt => StopTarget::Queued,
                    C::Retry { at_tick } => StopTarget::RetryWait { at_tick },
                    C::RequireAction { reason } => StopTarget::NeedsAction { reason },
                    C::Fail { reason } => StopTarget::Failed { reason },
                    _ => return Err(DomainError::InvalidTransition),
                };
                let current = self.stop.ok_or(DomainError::InvalidTransition)?;
                let raised = current.raise(cause);
                if raised == current {
                    return Ok(false);
                }
                self.stop = Some(raised);
                S::Stopping
            }
            (S::Stopping, C::WorkersDrained) => {
                if !self.settled() {
                    return Err(DomainError::Incomplete);
                }
                let target = self.stop.take().ok_or(DomainError::InvalidTransition)?;
                if self.replace_on_drain {
                    self.replace_on_drain = false;
                    self.generation = self.generation.next()?;
                    self.segments = None;
                }
                match target {
                    StopTarget::Verifying if self.all_durable() => S::Verifying,
                    StopTarget::Verifying | StopTarget::Paused => S::Paused,
                    StopTarget::Queued => S::Queued,
                    StopTarget::RetryWait { at_tick } => {
                        self.retry_at = Some(at_tick);
                        S::RetryWait
                    }
                    StopTarget::NeedsAction { reason } => {
                        self.reason = Some(reason);
                        S::NeedsAction
                    }
                    StopTarget::Failed { reason } => {
                        self.reason = Some(reason);
                        S::Failed
                    }
                }
            }

            (S::Queued | S::Verifying, C::Pause) => S::Paused,
            (S::RetryWait, C::Pause) => {
                self.retry_at = None;
                S::Paused
            }
            (S::Paused | S::NeedsAction | S::Failed | S::Cancelling, C::Pause) => return Ok(false),

            (S::Paused, C::Resume) => {
                self.attempts = 0;
                if self.all_durable() {
                    S::Verifying
                } else {
                    S::Queued
                }
            }
            (S::RetryWait, C::Resume) => {
                self.retry_at = None;
                self.attempts = 0;
                S::Queued
            }
            (S::NeedsAction, C::Resume) => {
                if matches!(
                    self.reason,
                    Some(StopReason::SourceChanged | StopReason::Integrity)
                ) {
                    return Err(DomainError::InvalidTransition);
                }
                self.reason = None;
                self.attempts = 0;
                S::Queued
            }
            (S::Failed, C::Resume) => {
                self.reason = None;
                self.attempts = 0;
                S::Queued
            }
            (
                S::Queued | S::Probing | S::Transferring | S::Verifying | S::Publishing,
                C::Resume,
            ) => return Ok(false),

            (S::RetryWait, C::RetryDue { now_tick }) => {
                if self.retry_at.is_none_or(|at| now_tick < at) {
                    return Err(DomainError::InvalidTransition);
                }
                self.retry_at = None;
                S::Queued
            }

            (S::Verifying | S::Publishing, C::RequireAction { reason }) => {
                self.reason = Some(reason);
                S::NeedsAction
            }
            (S::Verifying, C::Fail { reason }) => {
                self.reason = Some(reason);
                S::Failed
            }
            (S::Verifying, C::VerificationPassed) => S::Publishing,
            (S::Publishing, C::PublishCommitted) => S::Completed,

            (
                S::Queued
                | S::Probing
                | S::Transferring
                | S::Stopping
                | S::Paused
                | S::RetryWait
                | S::NeedsAction
                | S::Verifying
                | S::Failed,
                C::Cancel,
            ) => {
                self.stop = None;
                self.replace_on_drain = false;
                self.retry_at = None;
                S::Cancelling
            }
            (S::Cancelling, C::Cancel) => return Ok(false),
            (S::Publishing, C::Pause | C::Cancel) => return Err(DomainError::PublishInProgress),
            (S::Cancelling, C::CleanupFinished) => {
                if !self.quiescent() {
                    return Err(DomainError::Incomplete);
                }
                S::Cancelled
            }

            (S::NeedsAction | S::Paused | S::Failed, C::ReplaceRepresentation) => {
                self.generation = self.generation.next()?;
                self.segments = None;
                self.reason = None;
                self.retry_at = None;
                self.attempts = 0;
                S::Queued
            }
            _ => return Err(DomainError::InvalidTransition),
        };
        self.state = next;
        Ok(true)
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
            JobState::Transferring | JobState::Stopping | JobState::Cancelling
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
    /// For a stop that cannot sync (e.g. failed storage): uncommitted bytes return to
    /// Pending and are downloaded again. Durable progress is untouched.
    pub fn discard_unsynced(&mut self) -> Result<(), DomainError> {
        if self.state != JobState::Stopping {
            return Err(DomainError::InvalidTransition);
        }
        self.map_mut()?.discard_unsynced()
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
    fn transferring(total: u64) -> Job {
        let mut value = job();
        value.handle(JobCommand::Start).unwrap();
        value
            .handle(JobCommand::ProbeSucceeded {
                total,
                max_segments: 4,
            })
            .unwrap();
        value
    }
    fn first_lease(value: &mut Job) -> Lease {
        let id = value.segments().unwrap().segments()[0].id();
        value.lease_segment(id, 1).unwrap()
    }

    #[test]
    fn every_state_command_pair_matches_explicit_transition_table() {
        use JobCommand as C;
        use JobState::*;
        let states = [
            Queued,
            Probing,
            Transferring,
            Stopping,
            Paused,
            RetryWait,
            NeedsAction,
            Verifying,
            Publishing,
            Cancelling,
            Failed,
            Completed,
            Cancelled,
        ];
        let commands = [
            C::Start,
            C::ProbeSucceeded {
                total: 0,
                max_segments: 16,
            },
            C::Pause,
            C::Resume,
            C::Cancel,
            C::Preempt,
            C::AllSegmentsDurable,
            C::Retry { at_tick: 10 },
            C::RequireAction {
                reason: StopReason::Network,
            },
            C::Fail {
                reason: StopReason::Network,
            },
            C::RepresentationChanged,
            C::WorkersDrained,
            C::RetryDue { now_tick: 10 },
            C::VerificationPassed,
            C::PublishCommitted,
            C::CleanupFinished,
            C::ReplaceRepresentation,
        ];
        // One row per state, one column per command above.
        // '.' rejected, 'x' rejected as PublishInProgress, '=' accepted no-op, otherwise the state:
        // Q P T S p(aused) R N V B(publishing) C(ancelling) F D(completed) X(cancelled).
        // Fixture: drained empty map (all durable), Stopping{Paused}, reason Network.
        let rows = [
            "P.p=C............",
            ".TS=CS.SSSS......",
            "..S=CSSSSSS......",
            "..=SC=.SSSSp.....",
            "..=VC...........Q",
            "..pQC.......Q....",
            "..=QC...........Q",
            "..p=C...NF...B...",
            "..x=x...N.....D..",
            "..=.=..........X.",
            "..=QC...........Q",
            ".................",
            ".................",
        ];
        let decode = |code: char| match code {
            'Q' => Queued,
            'P' => Probing,
            'T' => Transferring,
            'S' => Stopping,
            'p' => Paused,
            'R' => RetryWait,
            'N' => NeedsAction,
            'V' => Verifying,
            'B' => Publishing,
            'C' => Cancelling,
            'F' => Failed,
            'D' => Completed,
            'X' => Cancelled,
            other => panic!("unknown code {other}"),
        };
        for (row, state) in states.into_iter().enumerate() {
            let expected: Vec<char> = rows[row].chars().collect();
            assert_eq!(expected.len(), commands.len(), "row {state:?}");
            for (column, command) in commands.into_iter().enumerate() {
                let mut value = job();
                value.state = state;
                value.retry_at = Some(10);
                value.reason = Some(StopReason::Network);
                if state == Stopping {
                    value.stop = Some(StopTarget::Paused);
                }
                value.segments = Some(SegmentMap::new(value.id, value.generation, 0, 16).unwrap());
                let result = value.handle(command);
                match expected[column] {
                    '.' => {
                        assert_eq!(
                            result.unwrap_err(),
                            DomainError::InvalidTransition,
                            "{state:?} {command:?}"
                        );
                        assert_eq!((value.state, value.version), (state, 0));
                    }
                    'x' => {
                        assert_eq!(result.unwrap_err(), DomainError::PublishInProgress);
                        assert_eq!((value.state, value.version), (state, 0));
                    }
                    '=' => {
                        assert!(result.unwrap().is_empty(), "{state:?} {command:?}");
                        assert_eq!((value.state, value.version), (state, 0));
                    }
                    code => {
                        assert_eq!(result.unwrap().len(), 1, "{state:?} {command:?}");
                        assert_eq!(value.state, decode(code), "{state:?} {command:?}");
                        assert_eq!(value.version, 1);
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
        let lease = first_lease(&mut value);
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
        assert_eq!(value.stop_target(), Some(StopTarget::Verifying));
        value.handle(JobCommand::WorkersDrained).unwrap();
        value.handle(JobCommand::VerificationPassed).unwrap();
        assert_eq!(
            value.handle(JobCommand::Cancel).unwrap_err(),
            DomainError::PublishInProgress
        );
        value.handle(JobCommand::PublishCommitted).unwrap();
        assert_eq!(value.state, JobState::Completed);
    }

    #[test]
    fn every_error_exit_waits_for_workers_and_checkpoint() {
        let exits = [
            (JobCommand::Pause, JobState::Paused),
            (JobCommand::Preempt, JobState::Queued),
            (JobCommand::Retry { at_tick: 100 }, JobState::RetryWait),
            (
                JobCommand::RequireAction {
                    reason: StopReason::Storage,
                },
                JobState::NeedsAction,
            ),
            (
                JobCommand::Fail {
                    reason: StopReason::Policy,
                },
                JobState::Failed,
            ),
            (JobCommand::RepresentationChanged, JobState::Queued),
        ];
        for (command, landing) in exits {
            let mut value = transferring(10);
            let lease = first_lease(&mut value);
            value.handle(command).unwrap();
            assert_eq!(value.state(), JobState::Stopping, "{command:?}");
            assert_eq!(
                value.handle(JobCommand::WorkersDrained).unwrap_err(),
                DomainError::Incomplete
            );
            // A stopping job hands out no new work.
            let pending = value.segments().unwrap().segments()[0].id();
            assert_eq!(
                value.lease_segment(pending, 2).unwrap_err(),
                DomainError::InvalidTransition
            );
            value.mark_written(lease).unwrap();
            let ticket = value.prepare_sync().unwrap();
            assert_eq!(
                value.handle(JobCommand::WorkersDrained).unwrap_err(),
                DomainError::Incomplete
            );
            let batch = value.acknowledge_sync(ticket).unwrap();
            value.acknowledge_commit(batch).unwrap();
            value.handle(JobCommand::WorkersDrained).unwrap();
            assert_eq!(value.state(), landing, "{command:?}");
            assert_eq!(value.stop_target(), None);
        }
    }

    #[test]
    fn concurrent_causes_only_raise_severity() {
        let mut value = transferring(10);
        let _lease = first_lease(&mut value);
        value.handle(JobCommand::Preempt).unwrap();
        assert!(value.handle(JobCommand::Preempt).unwrap().is_empty());
        value.handle(JobCommand::Retry { at_tick: 50 }).unwrap();
        value.handle(JobCommand::Retry { at_tick: 70 }).unwrap();
        assert!(value
            .handle(JobCommand::Retry { at_tick: 60 })
            .unwrap()
            .is_empty());
        assert_eq!(
            value.stop_target(),
            Some(StopTarget::RetryWait { at_tick: 70 })
        );
        assert!(value.handle(JobCommand::Pause).unwrap().is_empty());
        value
            .handle(JobCommand::RequireAction {
                reason: StopReason::Authentication,
            })
            .unwrap();
        assert!(value
            .handle(JobCommand::RequireAction {
                reason: StopReason::Storage,
            })
            .unwrap()
            .is_empty());
        value
            .handle(JobCommand::Fail {
                reason: StopReason::Policy,
            })
            .unwrap();
        assert!(value.handle(JobCommand::Resume).unwrap().is_empty());
        assert_eq!(
            value.stop_target(),
            Some(StopTarget::Failed {
                reason: StopReason::Policy
            })
        );
    }

    #[test]
    fn resume_during_pause_lands_on_queue_or_verification() {
        let mut value = transferring(10);
        let lease = first_lease(&mut value);
        value.handle(JobCommand::Pause).unwrap();
        value.handle(JobCommand::Resume).unwrap();
        assert_eq!(value.stop_target(), Some(StopTarget::Queued));
        value.release(lease).unwrap();
        value.handle(JobCommand::WorkersDrained).unwrap();
        assert_eq!(value.state(), JobState::Queued);

        let mut value = transferring(10);
        let lease = first_lease(&mut value);
        value.mark_written(lease).unwrap();
        let ticket = value.prepare_sync().unwrap();
        let batch = value.acknowledge_sync(ticket).unwrap();
        value.acknowledge_commit(batch).unwrap();
        value.handle(JobCommand::Pause).unwrap();
        value.handle(JobCommand::Resume).unwrap();
        assert_eq!(value.stop_target(), Some(StopTarget::Verifying));
        value.handle(JobCommand::WorkersDrained).unwrap();
        assert_eq!(value.state(), JobState::Verifying);
    }

    #[test]
    fn representation_change_replaces_generation_only_after_drain() {
        let mut value = transferring(10);
        let lease = first_lease(&mut value);
        value.handle(JobCommand::Pause).unwrap();
        value.handle(JobCommand::RepresentationChanged).unwrap();
        assert!(value.representation_change_pending());
        assert_eq!(value.generation().get(), 1);
        // Resume cannot short-circuit to verifying bytes of the old representation.
        value.handle(JobCommand::Resume).unwrap();
        assert_eq!(value.stop_target(), Some(StopTarget::Queued));
        value.release(lease).unwrap();
        value.handle(JobCommand::WorkersDrained).unwrap();
        assert_eq!(value.state(), JobState::Queued);
        assert_eq!(value.generation().get(), 2);
        assert!(value.segments().is_none());
        assert!(!value.representation_change_pending());
    }

    #[test]
    fn retry_wait_obeys_injected_tick_and_failed_is_resumable() {
        let mut value = transferring(10);
        value.handle(JobCommand::Retry { at_tick: 100 }).unwrap();
        value.handle(JobCommand::WorkersDrained).unwrap();
        assert_eq!(value.retry_at(), Some(100));
        assert_eq!(
            value
                .handle(JobCommand::RetryDue { now_tick: 99 })
                .unwrap_err(),
            DomainError::InvalidTransition
        );
        value
            .handle(JobCommand::RetryDue { now_tick: 100 })
            .unwrap();
        value.handle(JobCommand::Start).unwrap();
        value
            .handle(JobCommand::Fail {
                reason: StopReason::Policy,
            })
            .unwrap();
        value.handle(JobCommand::WorkersDrained).unwrap();
        assert_eq!(
            (value.state(), value.reason()),
            (JobState::Failed, Some(StopReason::Policy))
        );
        assert!(value.removable());
        value.handle(JobCommand::Resume).unwrap();
        assert_eq!((value.state(), value.reason()), (JobState::Queued, None));
    }

    #[test]
    fn every_cancel_passes_through_cleanup() {
        for setup in [
            JobCommand::Pause,
            JobCommand::Retry { at_tick: 5 },
            JobCommand::RequireAction {
                reason: StopReason::Network,
            },
        ] {
            let mut value = transferring(10);
            value.handle(setup).unwrap();
            value.handle(JobCommand::WorkersDrained).unwrap();
            value.handle(JobCommand::Cancel).unwrap();
            assert_eq!(value.state(), JobState::Cancelling);
            assert!(!value.removable());
            value.handle(JobCommand::CleanupFinished).unwrap();
            assert_eq!(value.state(), JobState::Cancelled);
        }
        let mut value = transferring(10);
        let lease = first_lease(&mut value);
        value.handle(JobCommand::Cancel).unwrap();
        assert_eq!(
            value.handle(JobCommand::CleanupFinished).unwrap_err(),
            DomainError::Incomplete
        );
        value.release(lease).unwrap();
        value.handle(JobCommand::CleanupFinished).unwrap();
    }

    #[test]
    fn integrity_failures_require_new_representation() {
        let mut value = transferring(10);
        let lease = first_lease(&mut value);
        value.mark_written(lease).unwrap();
        let ticket = value.prepare_sync().unwrap();
        value
            .handle(JobCommand::RequireAction {
                reason: StopReason::SourceChanged,
            })
            .unwrap();
        value.abandon_checkpoint().unwrap();
        assert_eq!(
            value.acknowledge_sync(ticket).unwrap_err(),
            DomainError::StaleToken
        );
        let ticket = value.prepare_sync().unwrap();
        let batch = value.acknowledge_sync(ticket).unwrap();
        value.acknowledge_commit(batch).unwrap();
        value.handle(JobCommand::WorkersDrained).unwrap();
        assert_eq!(
            value.handle(JobCommand::Resume).unwrap_err(),
            DomainError::InvalidTransition
        );
        value.handle(JobCommand::ReplaceRepresentation).unwrap();
        assert_eq!(value.generation().get(), 2);
        assert!(value.segments().is_none());
    }

    #[test]
    fn drain_waits_for_final_commit_or_explicit_discard() {
        let mut value = transferring(10);
        let lease = first_lease(&mut value);
        value.mark_written(lease).unwrap();
        value
            .handle(JobCommand::RequireAction {
                reason: StopReason::Storage,
            })
            .unwrap();
        assert_eq!(
            value.handle(JobCommand::WorkersDrained).unwrap_err(),
            DomainError::Incomplete
        );
        // Storage cannot sync: give the bytes back instead of stalling forever.
        value.discard_unsynced().unwrap();
        value.handle(JobCommand::WorkersDrained).unwrap();
        assert_eq!(value.state(), JobState::NeedsAction);
        assert_eq!(value.projection().durable_bytes, 0);
        assert_eq!(
            value.segments().unwrap().segments()[0].state(),
            crate::SegmentState::Pending
        );
    }

    #[test]
    fn apply_rejects_event_whose_projection_drifted() {
        let mut value = transferring(10);
        let lease = first_lease(&mut value);
        value.mark_written(lease).unwrap();
        let ticket = value.prepare_sync().unwrap();
        let batch = value.acknowledge_sync(ticket).unwrap();
        value.handle(JobCommand::Pause).unwrap();
        let events = value.decide(JobCommand::Resume).unwrap();
        assert_eq!(events[0].outcome().stop, Some(StopTarget::Queued));
        // The commit lands between decide and apply; Resume would now choose Verifying.
        value.acknowledge_commit(batch).unwrap();
        assert_eq!(value.apply(&events[0]), Err(DomainError::StaleEvent));
        assert_eq!(value.stop_target(), Some(StopTarget::Paused));
        value.handle(JobCommand::Resume).unwrap();
        assert_eq!(value.stop_target(), Some(StopTarget::Verifying));
    }

    #[test]
    fn cancel_during_stop_defers_cleanup_until_quiescent() {
        let mut value = transferring(10);
        let lease = first_lease(&mut value);
        value.mark_written(lease).unwrap();
        let ticket = value.prepare_sync().unwrap();
        value.handle(JobCommand::Pause).unwrap();
        value.handle(JobCommand::Cancel).unwrap();
        assert_eq!(value.state(), JobState::Cancelling);
        assert!(!value.cleanup_ready());
        let batch = value.acknowledge_sync(ticket).unwrap();
        value.acknowledge_commit(batch).unwrap();
        assert!(value.cleanup_ready());
        value.handle(JobCommand::CleanupFinished).unwrap();
        assert_eq!(value.state(), JobState::Cancelled);
    }

    #[test]
    fn verification_pause_resumes_into_verification() {
        let mut value = transferring(10);
        let lease = first_lease(&mut value);
        value.mark_written(lease).unwrap();
        let ticket = value.prepare_sync().unwrap();
        let batch = value.acknowledge_sync(ticket).unwrap();
        value.acknowledge_commit(batch).unwrap();
        value.handle(JobCommand::AllSegmentsDurable).unwrap();
        value.handle(JobCommand::WorkersDrained).unwrap();
        value.handle(JobCommand::Pause).unwrap();
        assert_eq!(value.state(), JobState::Paused);
        value.handle(JobCommand::Resume).unwrap();
        assert_eq!(value.state(), JobState::Verifying);
    }

    #[test]
    fn representation_change_keeps_a_more_severe_target() {
        let mut value = transferring(10);
        value
            .handle(JobCommand::Fail {
                reason: StopReason::Policy,
            })
            .unwrap();
        value.handle(JobCommand::RepresentationChanged).unwrap();
        assert!(value
            .handle(JobCommand::RepresentationChanged)
            .unwrap()
            .is_empty());
        value.handle(JobCommand::WorkersDrained).unwrap();
        assert_eq!(value.state(), JobState::Failed);
        assert_eq!(value.generation().get(), 2);
    }

    #[test]
    fn probe_rejects_out_of_bounds_inputs() {
        for (total, max_segments) in [(1025, 4), (10, 0), (10, 262145)] {
            let mut value = job();
            value.handle(JobCommand::Start).unwrap();
            assert_eq!(
                value
                    .handle(JobCommand::ProbeSucceeded {
                        total,
                        max_segments
                    })
                    .unwrap_err(),
                DomainError::InvalidInput
            );
            assert_eq!(value.state(), JobState::Probing);
        }
        let mut value = transferring(10);
        value.handle(JobCommand::Pause).unwrap();
        value.handle(JobCommand::WorkersDrained).unwrap();
        value.handle(JobCommand::Resume).unwrap();
        value.handle(JobCommand::Start).unwrap();
        assert_eq!(
            value
                .handle(JobCommand::ProbeSucceeded {
                    total: 11,
                    max_segments: 4
                })
                .unwrap_err(),
            DomainError::InvalidInput
        );
    }

    #[test]
    fn stop_target_raise_is_monotone() {
        let reasons = [StopReason::Network, StopReason::Storage];
        let mut targets = vec![
            StopTarget::Verifying,
            StopTarget::Queued,
            StopTarget::Paused,
            StopTarget::RetryWait { at_tick: 1 },
            StopTarget::RetryWait { at_tick: 9 },
        ];
        for reason in reasons {
            targets.push(StopTarget::NeedsAction { reason });
            targets.push(StopTarget::Failed { reason });
        }
        for a in &targets {
            for b in &targets {
                let raised = a.raise(*b);
                assert!(raised.rank() >= a.rank().max(b.rank()), "{a:?} {b:?}");
                assert!(raised == *a || raised == *b || raised.rank() == 3);
            }
        }
    }

    #[test]
    fn random_command_sequences_keep_invariants() {
        use JobCommand as C;
        let commands = [
            C::Start,
            C::ProbeSucceeded {
                total: 64,
                max_segments: 8,
            },
            C::Pause,
            C::Resume,
            C::Cancel,
            C::Preempt,
            C::AllSegmentsDurable,
            C::Retry { at_tick: 5 },
            C::RequireAction {
                reason: StopReason::Network,
            },
            C::Fail {
                reason: StopReason::Policy,
            },
            C::RepresentationChanged,
            C::WorkersDrained,
            C::RetryDue { now_tick: 5 },
            C::VerificationPassed,
            C::PublishCommitted,
            C::CleanupFinished,
            C::ReplaceRepresentation,
        ];
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..400 {
            let mut value = job();
            let mut leases: Vec<Lease> = vec![];
            let mut ticket: Option<SyncTicket> = None;
            for _ in 0..60 {
                let roll = next();
                match roll % 5 {
                    0 => {
                        let pending = value.segments().and_then(|m| {
                            m.segments()
                                .iter()
                                .find(|s| s.state() == crate::SegmentState::Pending)
                                .map(|s| s.id())
                        });
                        if let Some(id) = pending {
                            if let Ok(lease) = value.lease_segment(id, 1 + roll % 3) {
                                leases.push(lease);
                            }
                        }
                    }
                    1 => {
                        if let Some(lease) = leases.pop() {
                            let _ = if roll % 2 == 0 {
                                value.mark_written(lease)
                            } else {
                                value.release(lease)
                            };
                        }
                    }
                    2 => match ticket.take() {
                        Some(t) => {
                            if let Ok(batch) = value.acknowledge_sync(t) {
                                let _ = value.acknowledge_commit(batch);
                            }
                        }
                        None => ticket = value.prepare_sync().ok(),
                    },
                    _ => {
                        let command = commands[(roll >> 8) as usize % commands.len()];
                        let before = value.projection();
                        let version = value.version();
                        let planned = value.decide(command);
                        assert_eq!(value.projection(), before, "decide mutated");
                        match planned {
                            Ok(events) => {
                                for event in &events {
                                    value.apply(event).unwrap();
                                    assert_eq!(value.projection(), event.outcome());
                                }
                                assert_eq!(value.version(), version + events.len() as u64);
                            }
                            Err(_) => assert_eq!(value.projection(), before),
                        }
                    }
                }
                let p = value.projection();
                assert_eq!(p.stop.is_some(), p.state == JobState::Stopping);
                assert!(!p.replace_on_drain || p.state == JobState::Stopping);
                if let Some(map) = value.segments() {
                    assert!(p.durable_bytes <= map.total());
                    // Settled states never hold live work or uncommitted bytes.
                    if matches!(
                        p.state,
                        JobState::Paused
                            | JobState::RetryWait
                            | JobState::NeedsAction
                            | JobState::Failed
                            | JobState::Verifying
                    ) {
                        assert!(!map.has_pending_checkpoint(), "{:?}", p.state);
                        assert!(!map.has_unsynced(), "{:?}", p.state);
                        assert!(!map
                            .segments()
                            .iter()
                            .any(|s| matches!(s.state(), crate::SegmentState::InFlight { .. })));
                    }
                }
            }
        }
    }

    fn record_of(value: &Job) -> JobRecord {
        let p = value.projection();
        JobRecord {
            id: value.id(),
            spec: value.spec().clone(),
            version: value.version(),
            state: p.state,
            generation: p.generation,
            reason: p.reason,
            retry_at: p.retry_at,
            stop: p.stop,
            replace_on_drain: p.replace_on_drain,
            attempts: p.attempts,
            plan: value.plan(),
            durable: value
                .segments()
                .map(|m| {
                    m.segments()
                        .iter()
                        .filter(|s| s.state() == crate::SegmentState::Durable)
                        .map(|s| s.range())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    #[test]
    fn restore_keeps_only_durable_progress_and_recovers_with_ordinary_commands() {
        let mut value = transferring(10);
        let first = value.segments().unwrap().segments()[0].id();
        value.split_pending(first, 4).unwrap();
        let lease = value.lease_segment(first, 1).unwrap();
        value.mark_written(lease).unwrap();
        let ticket = value.prepare_sync().unwrap();
        let batch = value.acknowledge_sync(ticket).unwrap();
        value.acknowledge_commit(batch).unwrap();
        // Uncommitted work at crash time: a live lease on the tail.
        let tail = value.segments().unwrap().segments()[1].id();
        value.lease_segment(tail, 2).unwrap();

        let mut restored = Job::restore(record_of(&value)).unwrap();
        assert_eq!(restored.projection(), value.projection());
        assert_eq!(restored.version(), value.version());
        let map = restored.segments().unwrap();
        assert_eq!(map.durable_bytes(), 4);
        assert_eq!(
            map.segments()[1].state(),
            crate::SegmentState::Pending,
            "leases do not survive"
        );
        restored.handle(JobCommand::Pause).unwrap();
        restored.handle(JobCommand::WorkersDrained).unwrap();
        assert_eq!(restored.state(), JobState::Paused);
        restored.handle(JobCommand::Resume).unwrap();
        assert_eq!(restored.state(), JobState::Queued);
    }

    #[test]
    fn restore_rejects_inconsistent_records() {
        let value = transferring(10);
        let good = record_of(&value);
        let mut cases = Vec::new();
        let mut r = good.clone();
        r.state = JobState::Stopping;
        cases.push(r);
        let mut r = good.clone();
        r.stop = Some(StopTarget::Paused);
        cases.push(r);
        let mut r = good.clone();
        r.state = JobState::Verifying;
        cases.push(r);
        let mut r = good.clone();
        r.state = JobState::RetryWait;
        cases.push(r);
        let mut r = good.clone();
        r.state = JobState::NeedsAction;
        cases.push(r);
        let mut r = good.clone();
        r.plan = None;
        cases.push(r);
        let mut r = good.clone();
        r.plan = Some((2048, 4));
        cases.push(r);
        let mut r = good.clone();
        r.durable = vec![ByteRange::new(0, 6).unwrap(), ByteRange::new(5, 8).unwrap()];
        cases.push(r);
        let mut r = good.clone();
        r.durable = vec![ByteRange::new(8, 11).unwrap()];
        cases.push(r);
        for case in cases {
            assert!(Job::restore(case.clone()).is_err(), "{case:?}");
        }
        let mut touching = good.clone();
        touching.durable = vec![ByteRange::new(0, 3).unwrap(), ByteRange::new(3, 6).unwrap()];
        let restored = Job::restore(touching).unwrap();
        assert_eq!(restored.segments().unwrap().segments().len(), 2);
        let mut fragmented = good;
        fragmented.plan = Some((10, 2));
        fragmented.durable = vec![ByteRange::new(2, 4).unwrap()];
        assert_eq!(Job::restore(fragmented).unwrap_err(), DomainError::Capacity);
    }
}
