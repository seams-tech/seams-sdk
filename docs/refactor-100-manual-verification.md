# Refactor 100 Manual Verification And Merge Readiness

Status: implementation complete; runtime verification pending.

Branch: `refactor-100-passkey-custody`

Worktree: `/private/tmp/seams-sdk-r100`

The final integration pass intentionally ran no tests, typechecks, proofs, or
live-stack checks. This document is the required verification handoff before
merge.

## Recovery Semantics

Recovery codes are wallet-scoped and portable across devices. A valid code
opens the wallet custody seed and the recovery ceremony restores every key set
in the exact manifest before credential promotion.

Recovery codes do not reconstruct authentication-factor secrets. They do not
recover an old passkey's PRF/private material or an Email OTP device secret.
The current recovery operation registers one replacement passkey envelope and
retires the previously active custody envelopes. Treat recovery as a custody
factor reset. Re-enrol any additional authentication methods after recovery.

## Source Audit

| Operating path | Source evidence | Source status |
| --- | --- | --- |
| Fresh-device recovery | `RecoveryCapability` exposes bootstrap challenge, verify, prepare, and complete; `WalletRecoveryCoordinator` retains the resumable operation; direct and iframe handlers are wired | Implemented |
| Passkey-authorized `addPasskey` | Existing credential assertion opens the active custody envelope, creates a new PRF credential, reseals the same seed, and atomically finalizes credential plus envelope | Implemented |
| Email-OTP-authorized `addPasskey` | Explicit authorization union; OTP unlock stays in the Email OTP worker; a bounded two-minute opaque WASM handle crosses prepare/complete; factor bytes are zeroized; direct and iframe handlers are wired | Implemented |
| Passkey cold unlock | Ordinary login rejoins missing Ed25519 and ECDSA custody material and restores canonical Refactor-90 continuity | Implemented |
| Email OTP cold unlock | Server-authored capability selection; worker-held factor opens/rejoins custody; Ed25519 cache material and ECDSA continuity are restored | Implemented |
| Credential management | Public/direct/iframe list, rename, and revoke; activity metadata is separate from envelope AAD; revocation atomically updates auth and custody with a last-active-envelope guard | Implemented |
| Cross-device wallet recovery | Email OTP bootstrap requires no local wallet session; caller selects the credential being replaced; code opens the wallet seed; every manifest entry is recovered; replacement credential promotion is atomic | Implemented |
| Recovery-code rotation | Passkey and Email OTP authorization both regenerate exactly ten codes and a fresh manifest KEK; the server replaces the full recovery set with CAS and re-arms backup acknowledgement | Implemented |
| Legacy deletion | Separate Email OTP device-escrow routes, services, stores, client calls, root vault, sealed recovery, raw custody-seed registration APIs, deterministic passkey-PRF root API, and stale fixtures are removed | Implemented |

## Manual Test Matrix

Record the browser, authenticator, wallet ID, key-set shape, and server log
correlation ID for every row.

### A. Registration And Initial Backup

1. Register a passkey wallet for each shape: Ed25519-only, ECDSA-only, mixed.
2. Register an Email OTP wallet for each shape.
3. Confirm exactly ten wallet recovery codes are shown before completion.
4. Confirm dismissing the acknowledgement prevents registration completion.
5. Confirm successful completion reports backup acknowledged and stores one
   active custody envelope for the selected factor.
6. Confirm no recovery code, seed, PRF output, Email OTP secret, or signing
   share appears in application logs, iframe messages, or IndexedDB records.

### B. Cold Unlock

For every wallet shape and authorization method:

1. Clear the wallet-origin browser storage while retaining the authenticator or
   Email OTP identity.
2. Log in from the clean browser.
3. Perform one operation with every recovered key family.
4. Reload and repeat the operation using persisted canonical continuity.
5. Confirm registered public keys, EVM addresses, material activation IDs, and
   server generation remain unchanged.
6. For ordinary Ed25519 signing, confirm no Deriver/Yao recovery call occurs
   after local custody material is active.

### C. Add Passkey

Run once with `existing_passkey` authorization and once with `email_otp`:

1. Start from a wallet with one active custody envelope.
2. Confirm the public request requires an explicit authorization branch.
3. Cancel credential creation and confirm no credential or envelope is added.
4. Complete creation and confirm the server registration options are used
   exactly, including RP ID, user handle, challenge, algorithms, exclusions,
   authenticator selection, and PRF salts.
5. Confirm the new credential opens the same wallet and signs with the same
   public key/address identities.
6. For Email OTP authorization, wait beyond two minutes before completion and
   confirm the opaque worker continuation expires and is freed.
7. Confirm replaying a consumed continuation fails.

### D. Credential Management

1. List credentials and confirm IDs, labels, backup observations, and activity
   belong only to the requested wallet.
2. Rename one credential and confirm the envelope ciphertext/AAD is unchanged.
3. Use the credential and confirm last-used time and use count advance.
4. Revoke one of two credentials and confirm its auth record and matching
   envelopes are revoked atomically.
5. Confirm the revoked credential is removed from local WebAuthn selection.
6. Attempt to revoke the final active envelope and confirm the operation is
   refused.
7. Race two revocations and confirm the database guard preserves one active
   envelope.

### E. Fresh-Device Recovery

Run for Ed25519-only, ECDSA-only, and mixed wallets from a browser with no local
wallet state:

1. Request the recovery bootstrap challenge.
2. Verify Email OTP and confirm the response lists credential IDs and labels
   without disclosing secrets.
3. Select the exact credential to replace.
4. Prepare with one valid wallet recovery code.
5. Complete from the wallet-origin foreground surface and create the replacement
   passkey with PRF support.
6. Confirm every manifest key set is recovered before finalization.
7. Confirm one replacement passkey envelope is active and prior active custody
   envelopes are retired.
8. Sign with every recovered key family and compare public identities with the
   pre-recovery wallet.
9. Reuse the consumed code and confirm rejection.
10. Retry the identical finalize payload after a simulated lost response and
    confirm the committed result replays without a second activation.
11. Cancel after prepare, retry with the same in-memory operation, and confirm
    the reservation remains usable until expiry.

### F. Full Ten-Code Rotation

Run once with passkey authorization and once with Email OTP authorization:

1. Read the current recovery-set version.
2. Rotate and confirm exactly ten new, unique, non-decimal Crockford Base32
   codes are returned only after the server CAS succeeds.
3. Confirm backup status becomes outstanding for the new issuance.
4. Confirm every old code fails.
5. Recover with one new code and confirm the same wallet public identities.
6. Confirm that code becomes consumed while the other nine remain usable.
7. Submit rotation with a stale store version and confirm no recovery state
   changes.
8. Acknowledge the new backup and confirm status clears.

### G. Boundary And Failure Checks

1. Use a mismatched wallet ID, organization, RP ID, credential ID, enrollment
   ID, seal-key version, or authority reference and confirm fail-closed behavior.
2. Attempt direct parent-frame injection of relay URL, session JWT, OTP secret,
   factor bytes, or opaque worker handle and confirm the iframe boundary rejects
   it.
3. Confirm worker termination frees pending custody handles.
4. Confirm network failure before CAS returns no new codes.
5. Confirm network failure after recovery promotion can resolve through exact
   committed-state replay.

## Merge Readiness

The branch is ready for review, not yet ready to merge.

Required before merge:

1. Complete the manual matrix above and record evidence.
2. Run the repository's intended-behaviour contracts and the narrow crypto,
   type-fixture, server-store, iframe, and credential-management checks after
   the verification freeze is lifted.
3. Run `git diff --check` and the repository-wide check on the final reviewed
   commit.
4. Reconcile the two commits currently present on `dev` but absent from this
   branch, then repeat the affected checks.
5. Review the recovery factor-reset behavior explicitly. If preservation of
   additional active auth methods is desired, specify and implement a separate
   re-enrolment policy before merge.
6. Merge only after the worktree is clean and all required evidence is attached.

Already-landed Refactor-101/102 commits remain in branch history per direction;
this closeout did not add further Refactor-101, Refactor-102, or Refactor-103
work.
