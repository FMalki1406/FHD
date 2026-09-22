//! Transfer-state transactions: one row of projection per job plus its durable extents.
use super::{app_error, decode_spec, signed_id, PersistenceError, Result, SqliteRepository};
use fhd_app::{
    AppError, CommitError, DurableExtent, PortFuture, PublishIntent, TransferRepository,
};
use fhd_domain::{
    ByteRange, Generation, Job, JobCommand, JobEvent, JobId, JobRecord, JobState, StopReason,
    StopTarget,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

const STATES: [JobState; 13] = [
    JobState::Queued,
    JobState::Probing,
    JobState::Transferring,
    JobState::Stopping,
    JobState::Paused,
    JobState::RetryWait,
    JobState::NeedsAction,
    JobState::Verifying,
    JobState::Publishing,
    JobState::Cancelling,
    JobState::Failed,
    JobState::Completed,
    JobState::Cancelled,
];
const REASONS: [StopReason; 8] = [
    StopReason::SourceChanged,
    StopReason::Authentication,
    StopReason::Storage,
    StopReason::Integrity,
    StopReason::Network,
    StopReason::Policy,
    StopReason::Unknown,
    StopReason::Destination,
];
fn state_code(state: JobState) -> i64 {
    match state {
        JobState::Queued => 0,
        JobState::Probing => 1,
        JobState::Transferring => 2,
        JobState::Stopping => 3,
        JobState::Paused => 4,
        JobState::RetryWait => 5,
        JobState::NeedsAction => 6,
        JobState::Verifying => 7,
        JobState::Publishing => 8,
        JobState::Cancelling => 9,
        JobState::Failed => 10,
        JobState::Completed => 11,
        JobState::Cancelled => 12,
    }
}
/// Codes of states from which `remove` may delete a job; see `Job::removable`.
pub(super) const REMOVABLE_CODES: &str = "0,4,5,6,10,11,12";
fn state_of(code: i64) -> Result<JobState> {
    usize::try_from(code)
        .ok()
        .and_then(|i| STATES.get(i).copied())
        .ok_or(PersistenceError::Corrupt)
}
fn reason_code(reason: StopReason) -> i64 {
    match reason {
        StopReason::SourceChanged => 0,
        StopReason::Authentication => 1,
        StopReason::Storage => 2,
        StopReason::Integrity => 3,
        StopReason::Network => 4,
        StopReason::Policy => 5,
        StopReason::Unknown => 6,
        StopReason::Destination => 7,
    }
}
fn reason_of(code: i64) -> Result<StopReason> {
    usize::try_from(code)
        .ok()
        .and_then(|i| REASONS.get(i).copied())
        .ok_or(PersistenceError::Corrupt)
}
fn stored(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| PersistenceError::Corrupt)
}
fn loaded(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| PersistenceError::Corrupt)
}
fn stop_columns(stop: Option<StopTarget>) -> Result<(Option<i64>, Option<i64>)> {
    Ok(match stop {
        None => (None, None),
        Some(StopTarget::Verifying) => (Some(0), None),
        Some(StopTarget::Queued) => (Some(1), None),
        Some(StopTarget::Paused) => (Some(2), None),
        Some(StopTarget::RetryWait { at_tick }) => (Some(3), Some(stored(at_tick)?)),
        Some(StopTarget::NeedsAction { reason }) => (Some(4), Some(reason_code(reason))),
        Some(StopTarget::Failed { reason }) => (Some(5), Some(reason_code(reason))),
    })
}
fn stop_of(kind: Option<i64>, value: Option<i64>) -> Result<Option<StopTarget>> {
    Ok(match (kind, value) {
        (None, None) => None,
        (Some(0), None) => Some(StopTarget::Verifying),
        (Some(1), None) => Some(StopTarget::Queued),
        (Some(2), None) => Some(StopTarget::Paused),
        (Some(3), Some(v)) => Some(StopTarget::RetryWait {
            at_tick: loaded(v)?,
        }),
        (Some(4), Some(v)) => Some(StopTarget::NeedsAction {
            reason: reason_of(v)?,
        }),
        (Some(5), Some(v)) => Some(StopTarget::Failed {
            reason: reason_of(v)?,
        }),
        _ => return Err(PersistenceError::Corrupt),
    })
}

/// State of a job the transfer tables do not mention yet: freshly admitted.
struct Current {
    state: JobState,
    generation: i64,
    plan: Option<(i64, i64)>,
    validator: Option<Vec<u8>>,
}
fn current(tx: &Transaction<'_>, id: i64) -> Result<Current> {
    type Row = (i64, i64, Option<i64>, Option<i64>, Option<Vec<u8>>);
    let row: Option<Row> = tx
        .query_row(
            "SELECT state,generation,total,max_segments,validator FROM job_state WHERE job_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    Ok(match row {
        None => Current {
            state: JobState::Queued,
            generation: 1,
            plan: None,
            validator: None,
        },
        Some((state, generation, total, maximum, validator)) => Current {
            state: state_of(state)?,
            generation,
            plan: total.zip(maximum),
            validator,
        },
    })
}
fn extents(db: &Connection, id: i64, generation: i64) -> Result<Vec<DurableExtent>> {
    let mut statement = db.prepare_cached(
        "SELECT start,end_excl,digest FROM extents WHERE job_id=?1 AND generation=?2 ORDER BY start",
    )?;
    let rows = statement.query_map(params![id, generation], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (start, end, digest) = row?;
        let range =
            ByteRange::new(loaded(start)?, loaded(end)?).map_err(|_| PersistenceError::Corrupt)?;
        let digest = digest.try_into().map_err(|_| PersistenceError::Corrupt)?;
        out.push(DurableExtent::new(range, digest));
    }
    Ok(out)
}
fn ranges(extents: &[DurableExtent]) -> Vec<ByteRange> {
    extents.iter().map(|e| e.range()).collect()
}
/// Extents to insert. Each committed extent keeps its own digest (a union has no
/// derivable digest), so rows are never merged. An identical extent is a no-op retry;
/// any other overlap, with durable rows or within the batch, is `None`.
fn admit(existing: &[DurableExtent], incoming: &[DurableExtent]) -> Option<Vec<DurableExtent>> {
    let overlaps = |a: ByteRange, b: ByteRange| a.start() < b.end() && b.start() < a.end();
    let mut fresh: Vec<DurableExtent> = Vec::with_capacity(incoming.len());
    for extent in incoming {
        if existing.contains(extent) || fresh.contains(extent) {
            continue;
        }
        if existing
            .iter()
            .chain(fresh.iter())
            .any(|e| overlaps(e.range(), extent.range()))
        {
            return None;
        }
        fresh.push(*extent);
    }
    Some(fresh)
}
/// Segments `SegmentMap::restore` would build: touching durable ranges merge, plus gaps.
fn restored_segments(mut durable: Vec<ByteRange>, total: u64) -> usize {
    durable.sort_by_key(|r| r.start());
    let mut count = 0;
    let mut cursor = 0;
    for range in durable {
        if count > 0 && range.start() == cursor {
            cursor = range.end();
            continue;
        }
        count += usize::from(range.start() > cursor) + 1;
        cursor = range.end();
    }
    count + usize::from(cursor < total)
}

/// Open-time check: extents belong to the job's current, planned generation.
pub(super) fn consistent(db: &Connection) -> Result<bool> {
    let bad: i64 = db.query_row(
        "SELECT count(*) FROM extents e LEFT JOIN job_state s ON s.job_id=e.job_id \
         WHERE s.job_id IS NULL OR e.generation!=s.generation OR s.total IS NULL OR e.end_excl>s.total",
        [],
        |r| r.get(0),
    )?;
    Ok(bad == 0)
}

impl SqliteRepository {
    async fn transition(&self, event: JobEvent) -> Result<()> {
        self.run(move |inner| {
            let id = signed_id(event.job())?;
            let tx = inner
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let version: Option<i64> = tx
                .query_row("SELECT version FROM jobs WHERE id=?1", [id], |r| r.get(0))
                .optional()?;
            let version = version.ok_or(PersistenceError::Conflict)?;
            let now = current(&tx, id)?;
            if loaded(version)?.checked_add(1) != Some(event.version())
                || now.state != event.from()
                || now.generation != stored(event.generation().get())?
            {
                return Err(PersistenceError::Conflict);
            }
            let outcome = event.outcome();
            let generation = stored(outcome.generation.get())?;
            let replaced = generation != now.generation;
            // A re-probe keeps the existing map (the domain ignores its new maximum),
            // so the stored plan must not change either.
            let plan = match (event.command(), now.plan) {
                _ if replaced => None,
                (JobCommand::ProbeSucceeded { total, .. }, Some(plan)) => {
                    if plan.0 != stored(total)? {
                        return Err(PersistenceError::Conflict);
                    }
                    Some(plan)
                }
                (
                    JobCommand::ProbeSucceeded {
                        total,
                        max_segments,
                        ..
                    },
                    None,
                ) => Some((stored(total)?, stored(max_segments as u64)?)),
                (_, plan) => plan,
            };
            // The representation identity follows the plan: set once, compared on
            // re-probe, forgotten with the generation.
            let validator = match (event.command(), &now.validator) {
                _ if replaced => None,
                (JobCommand::ProbeSucceeded { validator, .. }, _) if now.plan.is_none() => {
                    validator.map(|v| v.to_vec())
                }
                (JobCommand::ProbeSucceeded { validator, .. }, stored) => {
                    // Resuming existing bytes needs a validator, as in the domain.
                    if validator.is_none() || validator.map(|v| v.to_vec()) != *stored {
                        return Err(PersistenceError::Conflict);
                    }
                    stored.clone()
                }
                (_, stored) => stored.clone(),
            };
            if validator.as_deref() != outcome.validator.as_ref().map(|v| v.as_slice()) {
                return Err(PersistenceError::Conflict);
            }
            if replaced {
                tx.execute("DELETE FROM extents WHERE job_id=?1", [id])?;
                tx.execute("DELETE FROM publish_intents WHERE job_id=?1", [id])?;
            }
            // A published job needs no intent; the record itself says Completed.
            if event.command() == JobCommand::PublishCommitted {
                tx.execute("DELETE FROM publish_intents WHERE job_id=?1", [id])?;
            }
            let durable: u64 = extents(&tx, id, generation)?
                .iter()
                .map(|e| e.range().len())
                .sum();
            // Memory only marks bytes durable after this repository committed them.
            // Retrying cannot fix a caller whose view diverged: Conflict, not Unavailable.
            if outcome.durable_bytes > durable {
                return Err(PersistenceError::Conflict);
            }
            let (stop_kind, stop_value) = stop_columns(outcome.stop)?;
            tx.execute(
                "INSERT INTO job_state(job_id,state,generation,reason,retry_at,stop_kind,stop_value,\
                 replace_on_drain,attempts,total,max_segments,validator) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) \
                 ON CONFLICT(job_id) DO UPDATE SET state=excluded.state,generation=excluded.generation,\
                 reason=excluded.reason,retry_at=excluded.retry_at,stop_kind=excluded.stop_kind,\
                 stop_value=excluded.stop_value,replace_on_drain=excluded.replace_on_drain,\
                 attempts=excluded.attempts,total=excluded.total,max_segments=excluded.max_segments,\
                 validator=excluded.validator",
                params![
                    id,
                    state_code(outcome.state),
                    generation,
                    outcome.reason.map(reason_code),
                    outcome.retry_at.map(stored).transpose()?,
                    stop_kind,
                    stop_value,
                    i64::from(outcome.replace_on_drain),
                    i64::from(outcome.attempts),
                    plan.map(|p| p.0),
                    plan.map(|p| p.1),
                    validator,
                ],
            )?;
            if tx.execute(
                "UPDATE jobs SET version=?1 WHERE id=?2 AND version=?3",
                params![stored(event.version())?, id, version],
            )? != 1
            {
                return Err(PersistenceError::Conflict);
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    async fn durable(
        &self,
        job: JobId,
        generation: Generation,
        incoming: Vec<DurableExtent>,
    ) -> Result<()> {
        self.run(move |inner| {
            let id = signed_id(job)?;
            let tx = inner
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let exists: bool =
                tx.query_row("SELECT EXISTS(SELECT 1 FROM jobs WHERE id=?1)", [id], |r| {
                    r.get(0)
                })?;
            if !exists {
                return Err(PersistenceError::Conflict);
            }
            let now = current(&tx, id)?;
            let generation = stored(generation.get())?;
            let (total, maximum) = now.plan.ok_or(PersistenceError::Conflict)?;
            if generation != now.generation
                || !matches!(
                    now.state,
                    JobState::Transferring | JobState::Stopping | JobState::Cancelling
                )
            {
                return Err(PersistenceError::Conflict);
            }
            let total = loaded(total)?;
            if incoming.iter().any(|e| e.range().end() > total) {
                return Err(PersistenceError::Corrupt);
            }
            let existing = extents(&tx, id, generation)?;
            let fresh = admit(&existing, &incoming).ok_or(PersistenceError::Conflict)?;
            let mut all = ranges(&existing);
            all.extend(ranges(&fresh));
            // Never write a state that load_jobs could not rebuild.
            if restored_segments(all, total)
                > usize::try_from(maximum).map_err(|_| PersistenceError::Corrupt)?
            {
                return Err(PersistenceError::Conflict);
            }
            for extent in &fresh {
                tx.execute(
                    "INSERT INTO extents(job_id,generation,start,end_excl,digest) VALUES(?1,?2,?3,?4,?5)",
                    params![
                        id,
                        generation,
                        stored(extent.range().start())?,
                        stored(extent.range().end())?,
                        extent.digest().as_slice()
                    ],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
    }

    async fn intent(&self, job: JobId) -> Result<Option<PublishIntent>> {
        self.run(move |inner| {
            let id = signed_id(job)?;
            let row: Option<(i64, i64, i64, Vec<u8>)> = inner
                .db
                .query_row(
                    "SELECT generation,attempt,size,digest FROM publish_intents WHERE job_id=?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let Some((generation, attempt, size, digest)) = row else {
                return Ok(None);
            };
            Ok(Some(PublishIntent::new(
                job,
                Generation::new(loaded(generation)?).map_err(|_| PersistenceError::Corrupt)?,
                u32::try_from(attempt).map_err(|_| PersistenceError::Corrupt)?,
                loaded(size)?,
                digest.try_into().map_err(|_| PersistenceError::Corrupt)?,
            )))
        })
        .await
    }

    async fn intend_publish(&self, intent: PublishIntent) -> Result<()> {
        self.run(move |intent_inner| {
            let inner = intent_inner;
            let id = signed_id(intent.job())?;
            let tx = inner
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let now = current(&tx, id)?;
            // Only a verified job of this generation may be published.
            if now.state != JobState::Verifying
                || now.generation != stored(intent.generation().get())?
                || now
                    .plan
                    .is_none_or(|(total, _)| loaded(total) != Ok(intent.size()))
            {
                return Err(PersistenceError::Conflict);
            }
            tx.execute(
                "INSERT INTO publish_intents(job_id,generation,attempt,size,digest) \
                 VALUES(?1,?2,?3,?4,?5) ON CONFLICT(job_id) DO UPDATE SET \
                 generation=excluded.generation,attempt=excluded.attempt,\
                 size=excluded.size,digest=excluded.digest",
                params![
                    id,
                    stored(intent.generation().get())?,
                    i64::from(intent.attempt()),
                    stored(intent.size())?,
                    intent.digest().as_slice()
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    async fn current_extents(&self, job: JobId) -> Result<Vec<DurableExtent>> {
        self.run(move |inner| {
            let id = signed_id(job)?;
            let generation: Option<i64> = inner
                .db
                .query_row(
                    "SELECT generation FROM job_state WHERE job_id=?1",
                    [id],
                    |r| r.get(0),
                )
                .optional()?;
            extents(&inner.db, id, generation.unwrap_or(1))
        })
        .await
    }

    async fn jobs(&self) -> Result<Vec<Job>> {
        self.run(|inner| {
            type Row = (
                i64,
                i64,
                super::SpecRow,
                Option<(i64, i64, Option<i64>, Option<i64>, Option<i64>, Option<i64>, i64, i64)>,
                Option<(i64, i64)>,
                Option<Vec<u8>>,
            );
            let mut statement = inner.db.prepare(
                "SELECT j.id,j.version,j.source,j.destination,j.expected,j.priority,j.max_bytes,\
                 s.state,s.generation,s.reason,s.retry_at,s.stop_kind,s.stop_value,s.replace_on_drain,\
                 s.attempts,s.total,s.max_segments,s.validator FROM jobs j LEFT JOIN job_state s ON s.job_id=j.id \
                 ORDER BY j.id",
            )?;
            let rows: Vec<Row> = statement
                .query_map([], |r| {
                    let state: Option<i64> = r.get(7)?;
                    let total: Option<i64> = r.get(15)?;
                    let maximum: Option<i64> = r.get(16)?;
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        (r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?),
                        match state {
                            None => None,
                            Some(state) => Some((
                                state,
                                r.get(8)?,
                                r.get(9)?,
                                r.get(10)?,
                                r.get(11)?,
                                r.get(12)?,
                                r.get(13)?,
                                r.get(14)?,
                            )),
                        },
                        total.zip(maximum),
                        r.get(17)?,
                    ))
                })?
                .collect::<std::result::Result<_, _>>()?;
            let mut jobs = Vec::with_capacity(rows.len());
            for (id, version, spec, state, plan, validator) in rows {
                let validator = validator
                    .map(|v| <[u8; 32]>::try_from(v).map_err(|_| PersistenceError::Corrupt))
                    .transpose()?;
                let job_id = JobId::new(loaded(id)?).map_err(|_| PersistenceError::Corrupt)?;
                let spec = decode_spec(spec)?;
                let version = loaded(version)?;
                let record = match state {
                    None => JobRecord {
                        id: job_id,
                        spec,
                        version,
                        state: JobState::Queued,
                        generation: Generation::initial(),
                        reason: None,
                        retry_at: None,
                        stop: None,
                        replace_on_drain: false,
                        attempts: 0,
                        plan: None,
                        validator: None,
                        durable: vec![],
                    },
                    Some((state, generation, reason, retry_at, kind, value, replace, attempts)) => {
                        let plan = plan
                            .map(|(t, m)| {
                                Ok::<_, PersistenceError>((
                                    loaded(t)?,
                                    usize::try_from(m).map_err(|_| PersistenceError::Corrupt)?,
                                ))
                            })
                            .transpose()?;
                        JobRecord {
                            id: job_id,
                            spec,
                            version,
                            state: state_of(state)?,
                            generation: Generation::new(loaded(generation)?)
                                .map_err(|_| PersistenceError::Corrupt)?,
                            reason: reason.map(reason_of).transpose()?,
                            retry_at: retry_at.map(loaded).transpose()?,
                            stop: stop_of(kind, value)?,
                            replace_on_drain: replace == 1,
                            attempts: u8::try_from(attempts)
                                .map_err(|_| PersistenceError::Corrupt)?,
                            plan,
                            validator,
                            durable: ranges(&extents(&inner.db, id, generation)?),
                        }
                    }
                };
                jobs.push(Job::restore(record).map_err(|_| PersistenceError::Corrupt)?);
            }
            Ok(jobs)
        })
        .await
    }
}

fn commit_error(error: PersistenceError) -> CommitError {
    match error {
        PersistenceError::Conflict => CommitError::Conflict,
        PersistenceError::Capacity => CommitError::Capacity,
        _ => CommitError::Unavailable,
    }
}

impl TransferRepository for SqliteRepository {
    fn commit_transition(
        &self,
        event: JobEvent,
    ) -> PortFuture<'_, std::result::Result<(), CommitError>> {
        Box::pin(async move { self.transition(event).await.map_err(commit_error) })
    }
    fn commit_extents(
        &self,
        job: JobId,
        generation: Generation,
        extents: Vec<DurableExtent>,
    ) -> PortFuture<'_, std::result::Result<(), CommitError>> {
        Box::pin(async move {
            self.durable(job, generation, extents)
                .await
                .map_err(commit_error)
        })
    }
    fn durable_extents(
        &self,
        job: JobId,
    ) -> PortFuture<'_, std::result::Result<Vec<DurableExtent>, AppError>> {
        Box::pin(async move { self.current_extents(job).await.map_err(app_error) })
    }
    fn record_publish_intent(
        &self,
        intent: PublishIntent,
    ) -> PortFuture<'_, std::result::Result<(), CommitError>> {
        Box::pin(async move { self.intend_publish(intent).await.map_err(commit_error) })
    }
    fn publish_intent(
        &self,
        job: JobId,
    ) -> PortFuture<'_, std::result::Result<Option<PublishIntent>, AppError>> {
        Box::pin(async move { self.intent(job).await.map_err(app_error) })
    }
    fn load_jobs(&self) -> PortFuture<'_, std::result::Result<Vec<Job>, AppError>> {
        Box::pin(async move { self.jobs().await.map_err(app_error) })
    }
}
