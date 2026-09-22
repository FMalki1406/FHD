CREATE TABLE schema_migrations_next (
    version INTEGER PRIMARY KEY CHECK(version >= 1),
    checksum BLOB NOT NULL CHECK(length(checksum) = 32)
);
INSERT INTO schema_migrations_next(version, checksum)
    SELECT version, checksum FROM schema_migrations;
DROP TABLE schema_migrations;
ALTER TABLE schema_migrations_next RENAME TO schema_migrations;
CREATE TABLE job_state (
    job_id INTEGER PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 12),
    generation INTEGER NOT NULL CHECK(generation > 0),
    reason INTEGER CHECK(reason IS NULL OR reason BETWEEN 0 AND 6),
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
CREATE TABLE extents (
    job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK(generation > 0),
    start INTEGER NOT NULL CHECK(start >= 0),
    end_excl INTEGER NOT NULL CHECK(end_excl > start),
    digest BLOB NOT NULL CHECK(length(digest) = 32),
    PRIMARY KEY(job_id, generation, start)
) WITHOUT ROWID;
PRAGMA user_version = 2;
