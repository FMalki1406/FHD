-- What a job points at, so a later run can continue it without being told again.
-- A sensitive link (a signed URL is a credential) is never written here: the row
-- records that the source exists and stays without a link, so the job stops for a
-- person after a restart instead of silently losing what it was fetching.
CREATE TABLE sources (
    source_id INTEGER PRIMARY KEY,
    url TEXT CHECK(url IS NULL OR (length(url) BETWEEN 1 AND 16384)),
    allow_http INTEGER NOT NULL CHECK(allow_http IN (0, 1)),
    sensitive INTEGER NOT NULL CHECK(sensitive IN (0, 1)),
    CHECK(sensitive = 0 OR url IS NULL)
);
CREATE TABLE destinations (
    destination_id INTEGER PRIMARY KEY,
    path TEXT NOT NULL CHECK(length(path) BETWEEN 1 AND 32768)
);
PRAGMA user_version = 4;
