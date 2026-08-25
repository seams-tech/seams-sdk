-- Refactor 103 Phase 8: which wallet auth method issued each Wallet Session.
--
-- The session already stores `authority_digest`, which proves what the
-- authority was. Proving is not addressing: pausing or revoking one credential
-- has to select every session that credential issued, and a digest can only be
-- recomputed and compared one candidate auth method at a time.
--
-- Carrying the binding id makes that selection an indexed lookup, which is what
-- lets a linked device be fenced through its own canonical credential instead
-- of through a separate per-device signing lane.
--
-- Nullable because sessions minted before this migration have no recorded
-- issuer. They are read back as unattributed and cannot be fenced by binding —
-- they expire on their own clock. Every session minted from here on has one.
ALTER TABLE reusable_wallet_sessions ADD COLUMN wallet_auth_method_id TEXT;

CREATE INDEX idx_reusable_wallet_sessions_auth_method
  ON reusable_wallet_sessions(namespace, tenant_id, wallet_id, wallet_auth_method_id);
