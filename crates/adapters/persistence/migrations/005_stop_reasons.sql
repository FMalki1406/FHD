-- The stop-reason check had gone stale, and a reason the engine can produce
-- could not be written.
--
-- Widens the stop-reason check for `Unreadable` and `Unconfirmed`, 8 and 9.
--
-- Two earlier versions of this comment claimed more than that, and both were
-- wrong. The first said the old check `BETWEEN 0 AND 6` had always prevented
-- storing `StopReason::Destination` (7), so such a job came back
-- `PERSISTENCE-UNAVAILABLE` instead of its reason. The second, after an
-- engineering review, narrowed that to databases created before commit 5799bab.
-- A security review disputed it, and checking settles it:
--
--   * 5799bab added `Destination` and widened 003 to `BETWEEN 0 AND 7` in the
--     same commit, so no build ever had that reason with a narrower check of its
--     own making.
--   * A database carrying the pre-5799bab 003 does not quietly keep the narrow
--     check either: `validate_schema` compares every applied migration against
--     its recorded checksum, so such a database is refused as `Corrupt` on open
--     rather than opened with the old CHECK in place.
--
-- So no database ever refused to store a reason the engine produced. The only
-- real defect was the two new codes, and this file is the whole of it.
--
-- And the "lesson" the second version of this comment kept was itself false, in
-- the same way, one level down. It said 5799bab had edited an applied migration
-- in place. `git show --name-status 5799bab` says `A` -- it *added* 003, a new
-- file that rebuilt `job_state` to widen the CHECK, which is exactly the
-- practice this comment goes on to prescribe. The narrow `BETWEEN 0 AND 6` was
-- 002's, superseded by 003 the moment `Destination` existed.
--
-- So nothing survives that objection except the shape this file already has:
-- widen a CHECK with a new migration, never by editing one that has shipped.
-- Three wrong versions of a five-line comment is the actual lesson -- a claim
-- about history is worth exactly the command that checks it.
--
-- SQLite cannot widen a CHECK in place, so the table is rebuilt. Everything
-- else about it is carried across unchanged.
CREATE TABLE job_state_next (
    job_id INTEGER PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 12),
    generation INTEGER NOT NULL CHECK(generation > 0),
    reason INTEGER CHECK(reason IS NULL OR reason BETWEEN 0 AND 9),
    retry_at INTEGER CHECK(retry_at IS NULL OR retry_at >= 0),
    stop_kind INTEGER CHECK(stop_kind IS NULL OR stop_kind BETWEEN 0 AND 5),
    stop_value INTEGER CHECK(stop_value IS NULL OR stop_value >= 0),
    replace_on_drain INTEGER NOT NULL CHECK(replace_on_drain IN (0, 1)),
    attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 255),
    total INTEGER CHECK(total IS NULL OR total >= 0),
    max_segments INTEGER CHECK(max_segments IS NULL OR max_segments BETWEEN 1 AND 262144),
    validator BLOB CHECK(validator IS NULL OR length(validator) = 32),
    CHECK((total IS NULL) = (max_segments IS NULL)),
    CHECK(validator IS NULL OR total IS NOT NULL)
);
INSERT INTO job_state_next
    SELECT job_id, state, generation, reason, retry_at, stop_kind, stop_value,
           replace_on_drain, attempts, total, max_segments, validator
    FROM job_state;
DROP TABLE job_state;
ALTER TABLE job_state_next RENAME TO job_state;
PRAGMA user_version = 5;
