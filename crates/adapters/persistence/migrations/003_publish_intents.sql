CREATE TABLE publish_intents (
    job_id INTEGER PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK(generation > 0),
    attempt INTEGER NOT NULL CHECK(attempt > 0),
    size INTEGER NOT NULL CHECK(size >= 0),
    digest BLOB NOT NULL CHECK(length(digest) = 32)
);
CREATE TABLE job_state_next (
    job_id INTEGER PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 12),
    generation INTEGER NOT NULL CHECK(generation > 0),
    reason INTEGER CHECK(reason IS NULL OR reason BETWEEN 0 AND 7),
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
INSERT INTO job_state_next(job_id, state, generation, reason, retry_at, stop_kind,
    stop_value, replace_on_drain, attempts, total, max_segments, validator)
    SELECT job_id, state, generation, reason, retry_at, stop_kind, stop_value,
    replace_on_drain, attempts, total, max_segments, validator FROM job_state;
DROP TABLE job_state;
ALTER TABLE job_state_next RENAME TO job_state;
PRAGMA user_version = 3;
