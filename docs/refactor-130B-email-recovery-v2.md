# Refactor 130B — Email Recovery V2

Status: deferred.

## Goal

Define a possible centralized recovery-contact system for a future project.
This plan records the current product and security direction. It does not
authorize implementation, schema work, compatibility scaffolding, or preparatory
abstractions.

The legacy inbound-email, DKIM, Outlayer, and on-chain EmailRecoverer pipeline is
removed independently by [Refactor 130A](./refactor-130A-email-recovery-cleanup.md).
Completion of 130A creates no delivery commitment or runtime foundation for this
plan.

The existing 10 one-time recovery codes remain the primary offline recovery
factor. The new email system is an independent fallback for users who lose
their authenticators and every saved recovery code.

Social recovery authorizes a new wallet authenticator and rotates the recovery
code set. It never reveals or decrypts the old plaintext recovery codes.

## Deferral Rule

Do not begin this plan as part of Refactor 130A. Re-evaluate the product model,
threat model, account-replacement lifecycle, notification channel, abuse
controls, and operational ownership before changing this status from deferred.

Any future implementation starts from the post-130A codebase. Do not restore
legacy request shapes, storage, routes, contracts, configuration, or local email
mappings.

All phases and checkboxes below are inactive while this plan remains deferred.

## Working Product Decisions

1. A logged-in user enrolls up to three recovery email addresses by approving
   one exact policy with a passkey assertion.
2. Every address must complete an outbound verification challenge before the
   policy becomes active.
3. Three contacts use a 2-of-3 threshold.
4. Two contacts use a 2-of-2 threshold.
5. One contact must be combined with a saved recovery code or a surviving
   authenticator. A single inbox cannot independently replace a wallet key.
6. Recovery begins in a browser session that creates the proposed new passkey
   or wallet keypair. Contact approvals are bound to that public key.
7. Each contact receives an independent, single-use approval link. Response
   order has no security meaning, and no code is routed to the last responder.
8. Quorum starts a 24-hour cancellation period. Existing wallet devices and all
   recovery contacts receive notifications at initiation, quorum, cancellation,
   and completion.
9. Finalization installs the new authenticator, invalidates the recovery
   attempt, revokes the old recovery-code set, and invokes the existing recovery
   code rotation path to issue 10 fresh codes.
10. The new recovery codes are displayed once inside the wallet-owned UI. The
    existing wrapped-escrow records remain the server-side recovery material;
    plaintext recovery codes never enter server persistence, logs, analytics,
    or email.

## Non-Goals

- Preserve the DKIM/Outlayer recovery protocol or its request shapes.
- Migrate old on-chain recovery-email hashes into the centralized system.
- Retrieve an existing plaintext recovery-code set.
- Email recovery codes to the user or to recovery contacts.
- Treat multiple aliases for one mailbox as independent security factors.
- Add support-agent overrides in this refactor.
- Create a second recovery-code generator, wrapper, storage model, or rotation
  workflow.

## Working Security Invariants

- The server accepts a recovery contact only after a wallet-bound passkey
  assertion and an outbound email verification.
- The signed enrollment intent contains the wallet ID, complete contact set,
  threshold policy, policy version, server nonce, and expiration.
- Adding, removing, or replacing a contact creates a new passkey-signed policy.
- The previous active policy remains authoritative until the replacement is
  verified and its cooling period completes.
- Every verification and approval token is cryptographically random, stored as
  a hash, scoped to one purpose, single-use, and time-limited.
- A recovery approval identifies one wallet, policy version, recovery attempt,
  and proposed public-key fingerprint.
- Inbound email headers never prove control of a recovery address. The service
  sends challenges to addresses stored in the active policy.
- A policy change invalidates open attempts under the superseded policy.
- Concurrent finalization is idempotent. Exactly one attempt can install a new
  authenticator and rotate a recovery-code set.
- Recovery responses do not disclose whether a wallet or email address exists.
- Rate limits apply per wallet, contact, attempt, IP address, and device.
- Recovery events are auditable without storing plaintext tokens, codes, email
  bodies, or key material.

## Phase 1 — Define the Central Recovery Domain

Create new domain names from the post-130A codebase. Avoid reusing ambiguous
legacy types such as `EmailRecoveryRequest` or `setRecoveryEmails`.

### 1.1 Contact policy

Model contact cardinality and approval policy as a closed union:

```ts
type RecoveryContactPolicyShape =
  | {
      kind: 'one_contact_plus_factor';
      contacts: readonly [VerifiedRecoveryContact];
      requiredEmailApprovals: 1;
      requiredAdditionalFactor: 'recovery_code_or_authenticator';
    }
  | {
      kind: 'two_of_two';
      contacts: readonly [VerifiedRecoveryContact, VerifiedRecoveryContact];
      requiredEmailApprovals: 2;
      requiredAdditionalFactor: 'none';
    }
  | {
      kind: 'two_of_three';
      contacts: readonly [
        VerifiedRecoveryContact,
        VerifiedRecoveryContact,
        VerifiedRecoveryContact,
      ];
      requiredEmailApprovals: 2;
      requiredAdditionalFactor: 'none';
    };
```

Represent policy lifecycle with separate `pending_verification`, `active`,
`superseded`, and `expired` branches. Each branch has required timestamps and
`never` fields for invalid combinations. Use branch-specific builders and an
exhaustive switch for every transition.

### 1.2 Recovery attempt

Use an immutable attempt identity and a lifecycle union:

```text
pending_approvals
    -> quorum_reached
    -> cooling_off
    -> finalized

pending_approvals | quorum_reached | cooling_off
    -> cancelled | expired
```

Every attempt requires:

- attempt ID;
- wallet ID;
- active policy ID and version;
- proposed authenticator kind;
- canonical new public key and fingerprint;
- required approval count;
- created and expiration timestamps;
- current lifecycle branch.

Diagnostics and notification delivery records cannot influence authorization.
Authorization reads only parsed policy, attempt, approval, and factor state.

### 1.3 Persistence

Add new D1 tables for:

- recovery contact policies;
- encrypted contact addresses and deterministic address digests;
- contact verification challenges;
- recovery attempts;
- per-contact approvals;
- recovery notifications and audit events.

Normalize raw D1 rows once at the repository boundary. Core services accept
only parsed domain records. Store contact email ciphertext under a dedicated
KMS-managed envelope key; keep lookup digests, token hashes, and audit metadata
separate.

### Phase 1 exit criteria

- Invalid contact counts, thresholds, and lifecycle combinations fail static
  type fixtures.
- Raw request and D1 shapes cannot reach core recovery functions.
- Schema tests prove uniqueness for policy versions, one approval per contact,
  and one successful finalization per wallet recovery attempt.

## Phase 2 — Passkey-Signed Contact Enrollment

- [ ] Add a server endpoint that issues a short-lived enrollment challenge for
      the authenticated wallet.
- [ ] Canonicalize and validate one to three addresses at the request boundary.
- [ ] Build one canonical enrollment intent containing the complete proposed
      policy.
- [ ] Require a WebAuthn assertion with user verification. Verify challenge,
      origin, RP ID, wallet binding, policy digest, nonce, and expiration.
- [ ] Persist the policy as `pending_verification`.
- [ ] Send each contact a distinct verification link through the centralized
      email sender.
- [ ] Activate the policy only after every address in the proposed policy is
      verified.
- [ ] Notify the previous policy contacts and existing wallet devices when a
      replacement is proposed and activated.
- [ ] Apply a 24-hour cooling period to contact removal, threshold reduction,
      and complete policy replacement.

Existing on-chain hashes and local recovery-email mappings are not migrated.
Users enroll again through this flow.

## Phase 3 — Social Recovery Approval

- [ ] Start recovery from a wallet-owned browser surface with a newly created
      passkey or wallet keypair.
- [ ] Create an attempt bound to the new public-key fingerprint and active
      policy version.
- [ ] Return the same public response for known and unknown wallets.
- [ ] Send one independent approval link to each active contact.
- [ ] Show the wallet label, recovery initiation time, proposed key fingerprint,
      expiration, and a clear deny action in the contact UI.
- [ ] Accept each approval once and record the verified contact identity
      server-side.
- [ ] Reject approvals for a different attempt, key fingerprint, policy version,
      expired token, or already-used token.
- [ ] Enter `quorum_reached` only when the policy's exact threshold is satisfied.
- [ ] For `one_contact_plus_factor`, require a reserved recovery code or a fresh
      surviving authenticator before quorum can complete.
- [ ] Start the 24-hour cancellation period and notify all contacts and existing
      wallet devices.

The recovering browser holds an opaque attempt secret used only to resume the
attempt. Email response ordering never selects a recipient or grants additional
authority.

## Phase 4 — Atomic Finalization and Recovery-Code Rotation

- [ ] Re-read the active policy, attempt, approvals, additional factor, and
      cancellation state in one finalization transaction.
- [ ] Install the exact authenticator/public key committed by the attempt.
- [ ] Revoke superseded wallet sessions and credentials according to the current
      account-replacement lifecycle.
- [ ] Mark the attempt finalized and consume every approval token.
- [ ] Invoke the existing recovery-code rotation service.
- [ ] Revoke all records belonging to the previous recovery-code set.
- [ ] Persist the fresh recovery-wrapped escrow records through the existing
      recovery-code repository.
- [ ] Return the fresh plaintext codes only to the wallet-owned recovery UI and
      immediately clear transient server/worker memory.
- [ ] Send completion notifications with a repudiation path to all contacts and
      previously active devices.

Finalization must be idempotent. A retry returns the completed result metadata
without installing another key or generating another code set.

## Phase 5 — Product UI

### Recovery settings

- Show one to three contacts with `pending`, `verified`, or `active` status.
- Explain the active threshold in plain language.
- Require a passkey confirmation for every policy change.
- Warn when multiple contacts appear to be aliases or forwarding destinations
  under the user's control; do not claim they are independent guardians.
- Show the activation delay and notify users that the previous policy remains
  active until activation.

### Recovery flow

- Create the replacement passkey before sending contact approvals.
- Show approval progress without revealing full contact addresses.
- Provide cancel and restart actions.
- Show the cooling-period deadline and finalization state.
- After completion, display the existing recovery-code modal with the newly
  rotated set and the current download action.

Use the existing accessible form, modal, focus, error, and loading patterns.
Recovery errors must identify the next safe action without disclosing registered
addresses to unauthenticated users.

## Phase 6 — Verification and Delivery

### Static guarantees

- Invalid one-contact policies without an additional factor fail to compile.
- Duplicate contacts, invalid thresholds, and illegal lifecycle timestamp
  combinations are rejected at their boundaries.
- Public APIs cannot accept approval counts, verified flags, or caller-supplied
  recovery codes.
- Finalization accepts only a `cooling_off` attempt whose deadline has elapsed.

### Behavioral coverage

- Passkey assertion binds the complete enrollment policy.
- Address verification activates one policy version exactly once.
- Old policy links stop working after replacement.
- Two approvals complete 2-of-3; one approval cannot.
- Both approvals are required for 2-of-2.
- One contact requires the declared additional factor.
- Approval replay, token swapping, public-key substitution, concurrent
  finalization, cancellation races, and expired attempts fail safely.
- Recovery rotates the existing code set and invalidates every old code.
- Plaintext codes and email addresses do not appear in logs, analytics, route
  responses, or audit payloads.

### Intended-behavior contract

Add one authoritative browser contract:

1. Register a wallet and save the initial recovery-code set.
2. Enroll three contacts with a passkey assertion and verify them.
3. Simulate loss of local credentials and recovery codes.
4. Create a new passkey and recovery attempt.
5. Approve with two contacts.
6. Complete the cancellation delay through the test clock.
7. Finalize recovery.
8. Sign through NEAR and one EVM-family target with the recovered wallet.
9. Confirm the old codes fail and the new 10-code set is available once.

Prefer this contract, focused repository tests, and type fixtures over new
source-text guards.

### Delivery order

1. Complete a fresh product and security review and change this plan's status
   through an explicit decision.
2. Land the new schema and centralized backend domain.
3. Land enrollment, approval, finalization, and UI as one supported path.
4. Require all users who want email fallback to enroll new recovery contacts.

Rollback of the replacement does not restore the deleted legacy system. Users
retain their existing recovery codes throughout the rollout.

## Completion Criteria

- A passkey-authenticated user can enroll and verify up to three centralized
  recovery contacts.
- The exact configured threshold authorizes only the public key committed by
  the recovery attempt.
- Recovery installs a new authenticator and rotates the existing recovery-code
  set without exposing the old codes.
- Policy changes, recovery attempts, approvals, cancellations, and completion
  are notified and auditable.
- Focused tests, static fixtures, the intended recovery contract,
  `pnpm test:source-guards`, `pnpm check`, and `git diff --check` pass.
