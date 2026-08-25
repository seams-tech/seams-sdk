-- Refactor 103 Phase 8: let a link-session CAS abort someone else's batch.
--
-- Finalizing Device 2's owner credential and advancing its link session are two
-- writes that must not be separable. Finalize is irreversible — one transaction
-- registers the passkey, the custody envelope, and the owner binding — so if a
-- cancel or an expiry won the session between the two, the wallet was left with
-- a live owner credential belonging to a session that had already terminated.
--
-- Both live in this database, so the two become one D1 batch. What a batch does
-- not give us is failure on a CAS miss: `UPDATE ... WHERE revision = ?` that
-- matches no row is a successful statement affecting zero rows, and the
-- credential would still commit.
--
-- This table is how the batch is made to fail. The session CAS is followed by
-- an insert that only runs when the update changed nothing, and that insert
-- always collides with the seeded row — so a lost CAS raises a constraint
-- violation and takes the whole batch, credential included, down with it.
--
-- The same shape as `lane_cas_guard` and `registration_ceremony_cas_guard`;
-- separate from them so the R103 lane teardown cannot remove a table the
-- linked-device finalize depends on.
CREATE TABLE IF NOT EXISTS linked_device_session_cas_guard (
  guard_id INTEGER PRIMARY KEY CHECK (guard_id = 1)
);

INSERT OR IGNORE INTO linked_device_session_cas_guard (guard_id) VALUES (1);

-- The guard is load-bearing, so it must not be emptied into uselessness: an
-- absent row would make the guarded insert succeed and silently restore the
-- split-brain window this migration exists to close.
CREATE TRIGGER IF NOT EXISTS linked_device_session_cas_guard_no_delete
BEFORE DELETE ON linked_device_session_cas_guard
BEGIN
  SELECT RAISE(ABORT, 'linked_device_session_cas_guard row is required');
END;
