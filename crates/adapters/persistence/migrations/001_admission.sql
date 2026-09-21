CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK(version = 1),
    checksum BLOB NOT NULL CHECK(length(checksum) = 32)
);
CREATE TABLE sequence (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    last_id INTEGER NOT NULL CHECK(last_id >= 0)
);
INSERT INTO sequence VALUES(1, 0);
CREATE TABLE jobs (
    id INTEGER PRIMARY KEY CHECK(id > 0),
    source BLOB NOT NULL CHECK(length(source) = 8),
    destination BLOB NOT NULL CHECK(length(destination) = 8),
    expected BLOB CHECK(expected IS NULL OR length(expected) = 32),
    priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 2),
    max_bytes INTEGER NOT NULL CHECK(max_bytes > 0),
    version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0)
);
CREATE TABLE command_receipts (
    principal BLOB NOT NULL CHECK(length(principal) = 8),
    key_hash BLOB NOT NULL CHECK(length(key_hash) = 32),
    job_id INTEGER NOT NULL UNIQUE CHECK(job_id > 0),
    source BLOB NOT NULL CHECK(length(source) = 8),
    destination BLOB NOT NULL CHECK(length(destination) = 8),
    expected BLOB CHECK(expected IS NULL OR length(expected) = 32),
    priority INTEGER NOT NULL CHECK(priority BETWEEN 0 AND 2),
    max_bytes INTEGER NOT NULL CHECK(max_bytes > 0),
    removed INTEGER NOT NULL CHECK(removed IN (0, 1)),
    PRIMARY KEY(principal, key_hash)
);
PRAGMA user_version = 1;
PRAGMA application_id = 1179141169;
