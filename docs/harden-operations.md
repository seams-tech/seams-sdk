# Operations Hardening Plan

Operational hardening work that should happen before production custody. This plan covers deployment, storage, and maintenance controls that are separate from the SDK/domain refactors.

## Phase 1: Signing Root Secret Share Custody

Status: Planned

### Current State

`signing_root_secret_shares` lives in the relay Postgres schema and stores sealed signing-root secret shares:

- `signing_root_id`
- `signing_root_version`
- `share_id`
- `sealed_share_b64u`
- `storage_id`
- `kek_id`

The row payload is expected to be ciphertext. The KEK/decrypt path must stay outside the general relay Postgres database.

### Target State

Move signing-root share custody behind a dedicated secret-storage boundary:

- Preferred: KMS/HSM-backed secret store with audit logging.
- Acceptable interim: separate Postgres database or schema with a restricted DB role.
- Platform-specific: Cloudflare Durable Object or another deployment adapter when the KEK path is isolated.

The general relay database should keep only public metadata or opaque references when needed. Runtime access should go through `SigningRootSecretStore` and `SigningRootShareResolver`.

### Tasks

- [ ] Define a production `SigningRootSecretStore` adapter backed by KMS/HSM or an equivalent secret store.
- [ ] Decide whether Postgres keeps a metadata/reference table for signing roots.
- [ ] Move `sealed_share_b64u` storage out of the general relay Postgres schema.
- [ ] Restrict the normal relay DB role from reading or writing sealed signing-root shares directly.
- [ ] Add audit events for signing-root share reads, writes, deletes, and decrypt failures.
- [ ] Add an operator runbook for signing-root import, rotation, backup, restore, and retirement.
- [ ] Add a recovery drill that verifies imported shares derive the expected ECDSA owner address and Ed25519 public key.
- [ ] Document backup rules: encrypted backups, separate KEK custody, and tested restore.

### Acceptance Criteria

- The app cannot read signing-root shares by querying the general relay schema.
- The decrypt path is isolated from the general relay Postgres credentials.
- Reads and writes of signing-root shares are audit-visible.
- Signing-root deletion is explicit and scoped by `signingRootId` plus `signingRootVersion`.
- A documented restore drill can recreate the expected threshold signing identities from sealed shares.

## Phase 2: Expired Session Pruning

Status: Planned

### Current State

Threshold session tables use `expires_at_ms` for read filtering, but expired rows can accumulate without a broad maintenance sweep.

Relevant tables:

- `threshold_ed25519_sessions`
- `threshold_ed25519_auth_consumptions`
- `threshold_ecdsa_signing_sessions`
- `threshold_ecdsa_presign_sessions`

### Tasks

- [ ] Add an operator-safe pruning command for expired threshold session rows.
- [ ] Add a low-frequency scheduled cleanup path for hosted deployments.
- [ ] Keep pruning scoped to `expires_at_ms <= now`.
- [ ] Add metrics for rows deleted per table and cleanup duration.
- [ ] Document manual SQL cleanup for emergency maintenance.

### Acceptance Criteria

- Expired session rows are pruned without touching active sessions.
- Cleanup can run repeatedly without changing active signing behavior.
- Operators can see when cleanup last ran and how many rows it removed.
