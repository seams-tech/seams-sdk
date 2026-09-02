-- Refactor 130A: remove the retired DKIM/Outlayer recovery state.
-- Historical migrations remain immutable; this forward migration removes only
-- tables that no supported runtime path reads or writes.
DROP INDEX IF EXISTS email_recovery_preparations_account_idx;
DROP INDEX IF EXISTS email_recovery_preparations_expires_idx;
DROP TABLE IF EXISTS email_recovery_preparations;

DROP INDEX IF EXISTS recovery_executions_session_idx;
DROP INDEX IF EXISTS recovery_executions_status_idx;
DROP TABLE IF EXISTS recovery_executions;

DROP INDEX IF EXISTS recovery_sessions_expiry_idx;
DROP INDEX IF EXISTS recovery_sessions_near_account_idx;
DROP TABLE IF EXISTS recovery_sessions;
