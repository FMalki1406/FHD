use crate::{ByteRange, DomainError, Generation, JobId};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SegmentId(u64);
impl SegmentId {
    pub fn get(self) -> u64 {
        self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SegmentState {
    Pending,
    InFlight { worker: u64, attempt: u64 },
    Written { attempt: u64 },
    Durable,
}
#[derive(Clone, Debug)]
pub struct Segment {
    id: SegmentId,
    range: ByteRange,
    state: SegmentState,
}
impl Segment {
    pub fn id(&self) -> SegmentId {
        self.id
    }
    pub fn range(&self) -> ByteRange {
        self.range
    }
    pub fn state(&self) -> SegmentState {
        self.state
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    job: JobId,
    generation: Generation,
    id: SegmentId,
    attempt: u64,
    worker: u64,
    range: ByteRange,
}
impl Lease {
    pub fn job(self) -> JobId {
        self.job
    }
    pub fn generation(self) -> Generation {
        self.generation
    }
    pub fn segment(self) -> SegmentId {
        self.id
    }
    pub fn attempt(self) -> u64 {
        self.attempt
    }
    pub fn range(self) -> ByteRange {
        self.range
    }
}
#[derive(Clone, Debug)]
struct Checkpoint {
    sequence: u64,
    ids: Vec<SegmentId>,
    selection: Vec<(SegmentId, ByteRange, u64)>,
    synced: bool,
}
/// An issued request for a physical sync, not evidence that IO occurred.
#[derive(Debug)]
pub struct SyncTicket {
    job: JobId,
    generation: Generation,
    sequence: u64,
    ranges: Vec<ByteRange>,
    selection: Vec<(SegmentId, ByteRange, u64)>,
}
impl SyncTicket {
    pub fn ranges(&self) -> &[ByteRange] {
        &self.ranges
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}
/// The trusted adapter reports sync success before this commit request is issued.
#[derive(Debug)]
pub struct CommitBatch {
    job: JobId,
    generation: Generation,
    sequence: u64,
    ranges: Vec<ByteRange>,
    selection: Vec<(SegmentId, ByteRange, u64)>,
}
impl CommitBatch {
    pub fn ranges(&self) -> &[ByteRange] {
        &self.ranges
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}
#[derive(Debug)]
pub struct SegmentMap {
    job: JobId,
    generation: Generation,
    total: u64,
    maximum: usize,
    segments: Vec<Segment>,
    next_id: u64,
    next_attempt: u64,
    next_checkpoint: u64,
    checkpoint: Option<Checkpoint>,
}
impl SegmentMap {
    pub(crate) fn snapshot(&self) -> Self {
        Self {
            job: self.job,
            generation: self.generation,
            total: self.total,
            maximum: self.maximum,
            segments: self.segments.clone(),
            next_id: self.next_id,
            next_attempt: self.next_attempt,
            next_checkpoint: self.next_checkpoint,
            checkpoint: self.checkpoint.clone(),
        }
    }
    pub fn has_pending_checkpoint(&self) -> bool {
        self.checkpoint.is_some()
    }
    pub fn has_unsynced(&self) -> bool {
        self.segments
            .iter()
            .any(|s| matches!(s.state, SegmentState::Written { .. }))
    }
    /// Gives up written-but-uncommitted bytes so they are fetched again. Only for a
    /// drain that cannot sync (failed storage); never while a checkpoint is pending.
    pub fn discard_unsynced(&mut self) -> Result<(), DomainError> {
        if self.checkpoint.is_some() {
            return Err(DomainError::CheckpointPending);
        }
        for segment in &mut self.segments {
            if matches!(segment.state, SegmentState::Written { .. }) {
                segment.state = SegmentState::Pending;
            }
        }
        Ok(())
    }

    pub fn new(
        job: JobId,
        generation: Generation,
        total: u64,
        maximum: usize,
    ) -> Result<Self, DomainError> {
        if total > i64::MAX as u64 || !(1..=262144).contains(&maximum) {
            return Err(DomainError::InvalidInput);
        }
        let segments = if total == 0 {
            vec![]
        } else {
            vec![Segment {
                id: SegmentId(1),
                range: ByteRange::new(0, total)?,
                state: SegmentState::Pending,
            }]
        };
        Ok(Self {
            job,
            generation,
            total,
            maximum,
            segments,
            next_id: 2,
            next_attempt: 1,
            next_checkpoint: 1,
            checkpoint: None,
        })
    }
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }
    pub fn total(&self) -> u64 {
        self.total
    }
    pub fn generation(&self) -> Generation {
        self.generation
    }
    pub fn durable_bytes(&self) -> u64 {
        self.segments
            .iter()
            .filter(|s| s.state == SegmentState::Durable)
            .map(|s| s.range.len())
            .sum()
    }
    pub fn all_durable(&self) -> bool {
        self.segments
            .iter()
            .all(|s| s.state == SegmentState::Durable)
    }
    fn index(&self, id: SegmentId) -> Result<usize, DomainError> {
        self.segments
            .iter()
            .position(|s| s.id == id)
            .ok_or(DomainError::UnknownSegment)
    }
    pub fn split_pending(&mut self, id: SegmentId, at: u64) -> Result<SegmentId, DomainError> {
        let index = self.index(id)?;
        if self.segments[index].state != SegmentState::Pending {
            return Err(DomainError::InvalidTransition);
        }
        if self.segments.len() == self.maximum {
            return Err(DomainError::Capacity);
        }
        let (left, right) = self.segments[index].range.split(at)?;
        let next = self.next_id.checked_add(1).ok_or(DomainError::Overflow)?;
        let right_id = SegmentId(self.next_id);
        self.segments[index].range = left;
        self.segments.insert(
            index + 1,
            Segment {
                id: right_id,
                range: right,
                state: SegmentState::Pending,
            },
        );
        self.next_id = next;
        Ok(right_id)
    }
    /// Only pending work can be stolen. Cancel/drain and release active leases first.
    pub fn steal_largest_pending(
        &mut self,
        minimum: u64,
    ) -> Result<Option<SegmentId>, DomainError> {
        if minimum == 0 {
            return Err(DomainError::InvalidInput);
        }
        let threshold = minimum.checked_mul(2).ok_or(DomainError::Overflow)?;
        let candidate = self
            .segments
            .iter()
            .filter(|s| s.state == SegmentState::Pending && s.range.len() >= threshold)
            .max_by_key(|s| s.range.len())
            .map(|s| (s.id, s.range.start() + s.range.len() / 2));
        candidate
            .map(|(id, at)| self.split_pending(id, at))
            .transpose()
    }
    pub fn lease(&mut self, id: SegmentId, worker: u64) -> Result<Lease, DomainError> {
        if worker == 0 {
            return Err(DomainError::InvalidInput);
        }
        let index = self.index(id)?;
        if self.segments[index].state != SegmentState::Pending {
            return Err(DomainError::InvalidTransition);
        }
        let next = self
            .next_attempt
            .checked_add(1)
            .ok_or(DomainError::Overflow)?;
        let attempt = self.next_attempt;
        self.next_attempt = next;
        let segment = &mut self.segments[index];
        segment.state = SegmentState::InFlight { worker, attempt };
        Ok(Lease {
            job: self.job,
            generation: self.generation,
            id,
            attempt,
            worker,
            range: segment.range,
        })
    }
    fn lease_index(&self, lease: Lease) -> Result<usize, DomainError> {
        if lease.job != self.job || lease.generation != self.generation {
            return Err(DomainError::StaleToken);
        }
        let index = self.index(lease.id).map_err(|_| DomainError::StaleToken)?;
        let s = &self.segments[index];
        if s.range != lease.range
            || s.state
                != (SegmentState::InFlight {
                    worker: lease.worker,
                    attempt: lease.attempt,
                })
        {
            return Err(DomainError::StaleToken);
        }
        Ok(index)
    }
    pub fn mark_written(&mut self, lease: Lease) -> Result<(), DomainError> {
        let index = self.lease_index(lease)?;
        self.segments[index].state = SegmentState::Written {
            attempt: lease.attempt,
        };
        Ok(())
    }
    pub fn release(&mut self, lease: Lease) -> Result<(), DomainError> {
        let index = self.lease_index(lease)?;
        self.segments[index].state = SegmentState::Pending;
        Ok(())
    }
    pub fn prepare_sync(&mut self) -> Result<SyncTicket, DomainError> {
        if self.checkpoint.is_some() {
            return Err(DomainError::CheckpointPending);
        }
        let selected: Vec<_> = self
            .segments
            .iter()
            .filter(|s| matches!(s.state, SegmentState::Written { .. }))
            .collect();
        if selected.is_empty() {
            return Err(DomainError::Incomplete);
        }
        let selection = selected
            .iter()
            .map(|s| {
                (
                    s.id,
                    s.range,
                    match s.state {
                        SegmentState::Written { attempt } => attempt,
                        _ => 0,
                    },
                )
            })
            .collect::<Vec<_>>();
        let ids = selected.iter().map(|s| s.id).collect();
        let ranges = selected.iter().map(|s| s.range).collect();
        let sequence = self.next_checkpoint;
        self.next_checkpoint = self
            .next_checkpoint
            .checked_add(1)
            .ok_or(DomainError::Overflow)?;
        self.checkpoint = Some(Checkpoint {
            sequence,
            ids,
            selection: selection.clone(),
            synced: false,
        });
        Ok(SyncTicket {
            job: self.job,
            generation: self.generation,
            sequence,
            ranges,
            selection,
        })
    }
    pub fn acknowledge_sync(&mut self, ticket: SyncTicket) -> Result<CommitBatch, DomainError> {
        let checkpoint = self.checkpoint.as_mut().ok_or(DomainError::StaleToken)?;
        if ticket.job != self.job
            || ticket.generation != self.generation
            || checkpoint.sequence != ticket.sequence
            || checkpoint.selection != ticket.selection
            || checkpoint.synced
        {
            return Err(DomainError::StaleToken);
        }
        checkpoint.synced = true;
        Ok(CommitBatch {
            job: ticket.job,
            generation: ticket.generation,
            sequence: ticket.sequence,
            ranges: ticket.ranges,
            selection: ticket.selection,
        })
    }
    pub fn acknowledge_commit(&mut self, batch: CommitBatch) -> Result<(), DomainError> {
        let checkpoint = self.checkpoint.as_ref().ok_or(DomainError::StaleToken)?;
        if batch.job != self.job
            || batch.generation != self.generation
            || checkpoint.sequence != batch.sequence
            || checkpoint.selection != batch.selection
            || !checkpoint.synced
        {
            return Err(DomainError::StaleToken);
        }
        // Check all entries before changing any, so rejection is atomic.
        let indices: Vec<_> = checkpoint
            .ids
            .iter()
            .map(|id| self.index(*id))
            .collect::<Result<_, _>>()?;
        if indices
            .iter()
            .any(|i| !matches!(self.segments[*i].state, SegmentState::Written { .. }))
        {
            return Err(DomainError::InvalidTransition);
        }
        for index in indices {
            self.segments[index].state = SegmentState::Durable;
        }
        self.checkpoint = None;
        Ok(())
    }
    /// A failed/ambiguous adapter transaction must be reconciled from storage before continuing.
    pub fn discard_checkpoint(&mut self) {
        self.checkpoint = None;
    }
    pub fn replace_generation(&mut self, total: u64) -> Result<(), DomainError> {
        if self.checkpoint.is_some()
            || self
                .segments
                .iter()
                .any(|segment| matches!(segment.state, SegmentState::InFlight { .. }))
        {
            return Err(DomainError::InvalidTransition);
        }
        let next = self.generation.next()?;
        *self = Self::new(self.job, next, total, self.maximum)?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn map(total: u64) -> SegmentMap {
        SegmentMap::new(JobId::new(1).unwrap(), Generation::initial(), total, 128).unwrap()
    }
    fn invariant(map: &SegmentMap) {
        let mut end = 0;
        let mut sum = 0;
        for s in map.segments() {
            assert_eq!(s.range.start(), end);
            end = s.range.end();
            sum += s.range.len();
        }
        assert_eq!(end, map.total);
        assert_eq!(sum, map.total);
        assert!(map.durable_bytes() <= map.total);
    }
    #[test]
    fn partitions_survive_many_orders_and_sizes() {
        for total in 1..=96 {
            let mut m = map(total);
            while m.steal_largest_pending(1).unwrap().is_some() {
                invariant(&m);
            }
            let ids: Vec<_> = m.segments().iter().rev().map(|s| s.id()).collect();
            for id in ids {
                let lease = m.lease(id, 1).unwrap();
                m.mark_written(lease).unwrap();
                let ticket = m.prepare_sync().unwrap();
                let batch = m.acknowledge_sync(ticket).unwrap();
                m.acknowledge_commit(batch).unwrap();
                invariant(&m);
            }
            assert!(m.all_durable());
            assert_eq!(m.durable_bytes(), total);
        }
    }
    #[test]
    fn stale_attempt_generation_and_active_split_cannot_mutate() {
        let mut m = map(100);
        let id = m.segments()[0].id();
        let first = m.lease(id, 1).unwrap();
        assert_eq!(m.split_pending(id, 50), Err(DomainError::InvalidTransition));
        m.release(first).unwrap();
        let second = m.lease(id, 2).unwrap();
        assert_eq!(m.mark_written(first), Err(DomainError::StaleToken));
        m.mark_written(second).unwrap();
        let ticket = m.prepare_sync().unwrap();
        m.discard_checkpoint();
        m.replace_generation(100).unwrap();
        assert_eq!(
            m.acknowledge_sync(ticket).unwrap_err(),
            DomainError::StaleToken
        );
        assert_eq!(m.mark_written(second), Err(DomainError::StaleToken));
        assert_eq!(m.durable_bytes(), 0);
        invariant(&m);
    }
    #[test]
    fn written_and_synced_do_not_imply_durable() {
        let mut m = map(10);
        let lease = m.lease(m.segments()[0].id(), 1).unwrap();
        m.mark_written(lease).unwrap();
        assert_eq!(m.durable_bytes(), 0);
        let ticket = m.prepare_sync().unwrap();
        let batch = m.acknowledge_sync(ticket).unwrap();
        assert_eq!(m.durable_bytes(), 0);
        m.discard_checkpoint();
        assert_eq!(m.acknowledge_commit(batch), Err(DomainError::StaleToken));
        let ticket = m.prepare_sync().unwrap();
        let batch = m.acknowledge_sync(ticket).unwrap();
        m.acknowledge_commit(batch).unwrap();
        assert_eq!(m.durable_bytes(), 10);
    }
    #[test]
    fn completed_later_range_does_not_wait_for_earlier_worker() {
        let mut m = map(100);
        let right = m.split_pending(m.segments()[0].id(), 50).unwrap();
        let left = m.lease(m.segments()[0].id(), 1).unwrap();
        let fast = m.lease(right, 2).unwrap();
        m.mark_written(fast).unwrap();
        let ticket = m.prepare_sync().unwrap();
        assert_eq!(ticket.ranges(), &[ByteRange::new(50, 100).unwrap()]);
        let batch = m.acknowledge_sync(ticket).unwrap();
        m.acknowledge_commit(batch).unwrap();
        assert_eq!(m.durable_bytes(), 50);
        assert!(!m.all_durable());
        m.release(left).unwrap();
    }
    #[test]
    fn foreign_checkpoint_with_same_job_generation_sequence_is_rejected() {
        let mut a = map(100);
        let mut b = map(100);
        let ar = a.split_pending(a.segments()[0].id(), 50).unwrap();
        b.split_pending(b.segments()[0].id(), 50).unwrap();
        let lease = a.lease(ar, 1).unwrap();
        a.mark_written(lease).unwrap();
        let lease = b.lease(b.segments()[0].id(), 1).unwrap();
        b.mark_written(lease).unwrap();
        let ticket_a = a.prepare_sync().unwrap();
        let ticket_b = b.prepare_sync().unwrap();
        assert_eq!(
            b.acknowledge_sync(ticket_a).unwrap_err(),
            DomainError::StaleToken
        );
        let batch_b = b.acknowledge_sync(ticket_b).unwrap();
        assert_eq!(a.acknowledge_commit(batch_b), Err(DomainError::StaleToken));
        assert_eq!(a.durable_bytes(), 0);
        assert_eq!(b.durable_bytes(), 0);
    }
    #[test]
    fn generation_replacement_waits_for_leases_and_checkpoints() {
        let mut value = map(100);
        let lease = value.lease(value.segments()[0].id(), 1).unwrap();
        assert_eq!(
            value.replace_generation(100),
            Err(DomainError::InvalidTransition)
        );
        value.mark_written(lease).unwrap();
        let ticket = value.prepare_sync().unwrap();
        assert_eq!(
            value.replace_generation(100),
            Err(DomainError::InvalidTransition)
        );
        let batch = value.acknowledge_sync(ticket).unwrap();
        value.acknowledge_commit(batch).unwrap();
        value.replace_generation(100).unwrap();
        assert_eq!(value.generation().get(), 2);
        assert_eq!(value.durable_bytes(), 0);
    }
    #[test]
    fn foreign_commit_batch_cannot_attest_different_synced_selection() {
        let mut a = map(100);
        let mut b = map(100);
        let right = a.split_pending(a.segments()[0].id(), 50).unwrap();
        b.split_pending(b.segments()[0].id(), 50).unwrap();
        let lease = a.lease(right, 1).unwrap();
        a.mark_written(lease).unwrap();
        let lease = b.lease(b.segments()[0].id(), 1).unwrap();
        b.mark_written(lease).unwrap();
        let ticket = a.prepare_sync().unwrap();
        let batch_a = a.acknowledge_sync(ticket).unwrap();
        let ticket = b.prepare_sync().unwrap();
        let batch_b = b.acknowledge_sync(ticket).unwrap();
        assert_eq!(a.acknowledge_commit(batch_b), Err(DomainError::StaleToken));
        assert_eq!(b.acknowledge_commit(batch_a), Err(DomainError::StaleToken));
        assert_eq!(a.durable_bytes(), 0);
        assert_eq!(b.durable_bytes(), 0);
    }
}
