-- The delivery witness: how many publication attempts began for this generation,
-- and how many were shown to have created no name at the destination.
--
-- Two counters rather than one flag. A publication attempt has three possible
-- ends and only two of them are answers: the file was linked, the linker refused
-- and said so, or nothing can say -- a crash between the two writes, or a refusal
-- whose record could not be saved. `started > resolved` is precisely "an attempt
-- of the third kind exists", and it stays true no matter what later attempts do,
-- which is what the earlier single flag could not express: a refusal of the
-- current attempt is not evidence about an earlier one.
--
-- `resolved <= started` is enforced here as well as in the update, because the
-- constraint is what makes the comparison meaningful.
CREATE TABLE publish_attempts (
    job_id INTEGER PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    generation INTEGER NOT NULL CHECK(generation > 0),
    started INTEGER NOT NULL CHECK(started > 0),
    resolved INTEGER NOT NULL CHECK(resolved >= 0),
    CHECK(resolved <= started)
);
PRAGMA user_version = 6;
