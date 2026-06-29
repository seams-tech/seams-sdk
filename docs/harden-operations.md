# Operations Hardening Plan

Operational hardening work that should happen before production custody. This plan covers deployment, storage, and maintenance controls that are separate from the SDK/domain refactors.

## Phase 1: Signing Root Secret Share Custody

Status: Planned

### Current State

`signer_signing_root_secret_shares` lives in the signer D1 database and stores sealed signing-root secret shares:

- `signing_root_id`
- `signing_root_version`
- `share_id`
- `sealed_share_b64u`
- `storage_id`
- `kek_id`

The row payload is ciphertext. The KEK/decrypt path stays outside D1 and outside the general relay database credentials.

### Target State

Move signing-root share custody behind a dedicated secret-storage boundary:

- Preferred: D1 ciphertext rows with KMS/HSM-backed KEK resolution and audit logging.
- Acceptable interim: Cloudflare secrets or another deployment adapter when the KEK path is isolated.
- Postgres escape hatch: full signer-family Postgres backend with a restricted secret-read role.

The general relay database should keep only public metadata or opaque references when needed. Runtime access should go through `SigningRootSecretStore` and `SigningRootShareResolver`.

### Tasks

- [ ] Define a production `SigningRootSecretStore` adapter backed by KMS/HSM or an equivalent secret store.
- [ ] Decide whether Postgres keeps a metadata/reference table for signing roots.
- [x] Move `sealed_share_b64u` storage out of the general relay Postgres schema.
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

Relevant state:

- Durable Object threshold ECDSA presign sessions

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
