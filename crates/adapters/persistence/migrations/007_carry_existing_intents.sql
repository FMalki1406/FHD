-- Every publication attempt an older build recorded becomes an unanswered one.
--
-- Migration 006 created the witness empty, which said "no attempt was ever begun"
-- about databases where one had been. That is the answer that permits removing a
-- part -- and a part from an older build may be a second name for a file the user
-- already has, with its own record one unauthenticated byte that a flip to `Open`
-- makes look untouched. An independent review found this before the upgrade shipped.
--
-- **Why every intent, and not the ones that look refused.** An intent is written
-- before the link and is not cleared when a publication is definitively refused, so
-- it is present both for attempts that were answered and for attempts that were
-- interrupted. The build that wrote these rows did not record which -- that is the
-- whole reason the witness exists -- so the only honest reading of a legacy intent is
-- "an attempt was begun and nothing here says how it ended". Reading the job's stop
-- reason instead would be guessing from a field that was never kept for this purpose.
--
-- The cost is stated rather than traded away: a job holding an intent at upgrade time
-- comes to rest on `Unconfirmed` and keeps its part until the destination reconciles
-- it or an operator cancels. That is the conservative side of a question about a file
-- the user may already have.
--
-- `attempt` carries over as the count begun, and `0` as the count answered, so the
-- record says exactly that none of them was. Intents of a generation the job has moved
-- past come across with their own generation, where the reader ignores them -- the
-- part they belonged to is not the part on disk.
INSERT INTO publish_attempts(job_id, generation, started, resolved)
    SELECT job_id, generation, attempt, 0 FROM publish_intents
    WHERE job_id NOT IN (SELECT job_id FROM publish_attempts);
PRAGMA user_version = 7;
