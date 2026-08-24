# Intended Behaviours

Date created: 2026-05-30

Status: source-of-truth behavioural contract.

This document defines expected wallet behaviour across passkey and Email OTP
accounts. Refactor plans and tests should point back here when deciding whether
new code is correct.

E2E enforcement plan: [Refactor 88: Intended Behaviour E2E Contract](./refactor-88-intended-behaviour-e2e.md).

## Terms

| Term                 | Meaning                                                                                                                              |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `walletId`           | Durable wallet identity. For current NEAR-backed wallets this is often the NEAR account id, but code must treat it as the wallet id. |
| `providerSubject`    | External identity-provider subject, such as a Google subject used by Email OTP registration.                                         |
| `challengeSubjectId` | Subject stored on an Email OTP challenge. For Google Email OTP it must match `providerSubject`.                                      |
| `walletSessionId`    | Reusable authenticated Wallet Session identity.                                                                                      |
| `quotaId`            | Server-authoritative remaining-use and expiry quota for a Wallet Session.                                                            |
| `capabilityGrantId`  | Exact one-operation authority bound to an operation, capability, and material activation.                                            |
| `thresholdSessionId` | Cryptographic signing-session id for Ed25519 or ECDSA material.                                                                      |
| `chainTarget`        | Concrete ECDSA signing target, such as Tempo testnet or Arc EVM testnet.                                                             |
| `warm session`       | Short-lived reusable signing session created by registration or unlock.                                                              |
| `step-up auth`       | Same-method fresh authorization scoped to one privileged operation.                                                                  |
| `owner proof`        | Server-internal passkey or Email OTP verification result consumed once to mint a Wallet Session or authorize one exact operation.    |
| `opaque token`       | Random Wallet Session bearer whose identity, budget, expiry, and revocation state are resolved by the server.                        |
| `walletAuthorityId`  | Opaque identity of one permissioned wallet authority and its exact signer activations.                                                |
| `walletAuthMethodId` | Opaque identity of one Passkey or Email OTP method attached to a wallet authority.                                                     |
| `deviceId`           | Installation identity for one wallet authority on one browser or device; it is not a hardware fingerprint.                           |

## Global Invariants

- Passkey and Email OTP are separate auth methods. A flow selected as
  `email_otp` must not call passkey/WebAuthn credential lookup. A flow selected
  as `passkey` must not call Email OTP verification.
- Registration must persist the configured signer inventory and establish a
  reusable Wallet Session for the authenticated registration authority. Default
  wallet unlock hydrates that durable inventory; explicit partial unlock
  hydrates only the requested lane subset.
- Transaction signing uses warm-session budget. It should not ask for step-up
  while a valid warm session has enough signature uses for the requested
  operation.
- Step-up authorizes one exact operation. It does not create, renew, or add
  budget to a reusable Wallet Session.
- Key export always requires fresh operation-specific authorization. A normal
  transaction-signing warm session is not sufficient authority for export.
- ECDSA lanes are target-specific. Tempo and Arc/EVM may share key facts and
  source material, but readiness, budget lookup, and persistence must carry the
  concrete `chainTarget`.
- Page refresh must not create new authority by itself. It may rehydrate valid
  persisted/sealed session state. If rehydration fails or a session is expired
  or exhausted, the next operation must use normal unlock or step-up auth.
- Application authentication is outside the wallet SDK. An application token,
  cookie, user id, or provider session never proves wallet ownership.
- Owner Wallet Session tokens are opaque. Client code must not decode identity,
  budget, expiry, authority, or signing claims from them.

## Hosted Auth Menu Entry Point

When hosted wallet-iframe mode is configured, mounting `SeamsAuthMenu` opens one
`modal_auth_menu` surface in the wallet-origin iframe. The app document contains
only an inert lifecycle marker; auth inputs, progress, OTP prompts, and the final
CTA belong to the wallet origin.

- Login and registration prepare their asynchronous prerequisites before enabling
  the single wallet-origin CTA. The CTA starts the selected passkey ceremony from
  that wallet-origin activation.
- Registration uses the configured account-input policy and completes through the
  same prepared surface; it does not open a second registration-confirmation modal.
- The wallet host owns passkey and Email OTP validation, OTP state,
  registration continuation, and unlock continuation.
- A hosted-wallet handoff is single-use and bound to the application and wallet
  origins. The outer application never receives the wallet host's opaque Wallet
  Session token.
- The adapter emits exactly one terminal `HostedAuthMenuOutcome` for the session.
  Unmounting or closing cancels only that session and leaves direct
  `registerWallet()`, `addWalletSigner()`, and `unlock()` confirmation surfaces
  unchanged.

## Registration

### Passkey Account

Expected behaviour:

- Registration prompts for one passkey credential creation.
- The newly created passkey credential is bound to the wallet and stored as a
  passkey auth method.
- Registration returns after the wallet, auth method, configured ECDSA signer
  inventory, and reusable Wallet Session are durable. Tempo and Arc/EVM signing
  may begin immediately.
- For a mixed signer set, Ed25519/NEAR provisioning continues under the same
  authenticated ceremony and publishes one of `near_pending`,
  `near_provisioning`, `near_ready`, or `near_failed_retryable`.
- NEAR signing becomes available at `near_ready` without a second passkey prompt.
  A retryable provisioning failure remains visible to the caller.
- ECDSA key export remains available while NEAR is pending and requires fresh
  export authorization.
- Passkey registration must not send or verify an Email OTP challenge.

Failure behaviour:

- If local persistence postconditions fail, registration must not report local
  success.
- If blockchain account creation has already happened, immutable chain-state
  rollback messaging must be separate from local persistence rollback/repair
  messaging.

### Email OTP Account

Expected behaviour:

- Registration sends one Email OTP code for the active registration attempt.
- The user may reroll the wallet name without sending another OTP code.
- The final wallet id may differ from the wallet id shown when the OTP was sent.
- The OTP remains valid for registration reroll only when the provider subject,
  challenged email, challenge id, org, owner-proof binding, and allowed
  registration purpose match.
- Registration stores the Email OTP auth method and binds it to the final
  wallet id.
- Registration returns after the wallet, Email OTP auth method, configured ECDSA
  signer inventory, and reusable Wallet Session are durable. Tempo and Arc/EVM
  signing may begin immediately.
- For a mixed signer set, Ed25519/NEAR provisioning continues with the live
  registration factor and publishes one of `near_pending`,
  `near_provisioning`, `near_ready`, or `near_failed_retryable`.
- NEAR signing becomes available at `near_ready` without a second OTP
  verification. A retryable provisioning failure remains visible to the caller.
- ECDSA key export remains available while NEAR is pending and requires fresh
  export authorization.
- Email OTP registration must not create passkey-owned runtime material.
- Email OTP registration must not call passkey PRF/touch-confirm sealed restore.

Failure behaviour:

- A wallet-unlock OTP challenge must not satisfy registration verification
  unless the request carries an explicit registration reroll proof whose
  provider subject, challenged email, challenge id, org, and owner-proof binding
  match.
- A registration OTP challenge must not satisfy wallet-unlock verification.
- Reroll must fail with a precise challenge/proof mismatch code when the
  provider subject or challenged email differs.

### Page Refresh During Registration

Expected behaviour:

- Refreshing before registration finalize may restore UI progress from durable
  registration attempt state when available.
- Refreshing must not send a second OTP solely because the wallet name changed.
- Refreshing must not finalize registration without the same required
  operation-bound owner proof.
- After completed registration, a refresh follows the session-refresh behaviour
  below.

## Wallet Unlock

### Passkey Account

Expected behaviour:

- Unlock prompts for the wallet's registered passkey.
- If the credential id is known, WebAuthn should request that credential
  directly so the browser does not show an unnecessary account picker.
- By default, unlock warms NEAR Ed25519 and configured ECDSA signing lanes.
- Callers may request an explicit subset, such as NEAR-only, ECDSA-only, or
  specific ECDSA targets, to avoid unnecessary unlock latency.
- Unlock creates a multi-use transaction-signing session according to the
  current environment policy.
- Unlock should not require Email OTP.
- Unlock should not delete durable sealed/session records that are needed for
  future refresh or recovery unless the user explicitly removes the wallet,
  device, auth method, or account.

Failure behaviour:

- If no passkey auth method or credential can be found for the wallet, unlock
  fails before reporting success.
- If requested signing lanes cannot be hydrated, unlock fails or reports a
  typed partial-hydration error before normal signing begins.

### Email OTP Account

Expected behaviour:

- Unlock sends one wallet-unlock OTP challenge.
- By default, verifying the OTP warms NEAR Ed25519 and configured ECDSA signing
  lanes.
- Callers may request an explicit subset, such as NEAR-only, ECDSA-only, or
  specific ECDSA targets, to avoid unnecessary unlock latency.
- Unlock creates a multi-use transaction-signing session according to the
  current environment policy.
- Unlock should not require passkey/WebAuthn.
- Unlock should not call passkey PRF/touch-confirm sealed restore.
- Default unlock should hydrate the same lane inventory as successful Email OTP
  registration for the same wallet and auth method. Explicit partial unlock
  should hydrate the requested lane subset only.

Failure behaviour:

- A registration OTP challenge must not unlock the wallet.
- A step-up/export OTP challenge must not unlock the wallet.
- Unlock must fail before reporting success if no usable Email OTP auth method
  exists for the wallet.

### Page Refresh After Unlock

Expected behaviour:

- Refresh may restore valid warm-session state from durable/sealed records
  without a user prompt.
- Refresh must preserve exact auth method, curve, chain target, session ids, and
  budget identity.
- If restored warm sessions are still valid, NEAR, Tempo, and EVM transaction
  signing should proceed without unlock or step-up prompts.
- If restored warm sessions are expired, exhausted, invalid, or missing, the
  wallet should require unlock or operation-specific step-up on the next
  privileged operation.
- Refresh must not silently switch an Email OTP wallet to passkey paths or a
  passkey wallet to Email OTP paths.

## Account Recovery

### Single-Passkey Wallet

Expected behaviour:

- The hosted login menu accepts one unused recovery code, resolves its wallet,
  then creates a replacement Passkey from a separate user activation.
- The recovery code is the sole recovery authorization. The flow does not ask
  for Email OTP, Google identity, an assertion from the source Passkey, or a
  client-selected source credential.
- Recovery is available only when the wallet has exactly one active owner auth
  method, that method is a Passkey, and it is bound to the requested RP.
- Finalization verifies the complete stored key manifest and preserves the
  registered NEAR, Tempo, and Arc/EVM public identities.
- Replacement installation, recovery-code consumption, source auth-method and
  envelope retirement, and source Wallet Session revocation occur atomically.
- Recovery completion proceeds through normal login with the replacement
  Passkey. That login creates the fresh Wallet Session.
- A consumed code cannot authorize a second replacement.

Failure behaviour:

- Unknown wallets, malformed or spent codes, RP mismatches, unsupported auth
  shapes, and conflicting attempts receive the same generic hosted refusal.
- Precommit cancellation and definite failure leave the recovery code
  unconsumed.
- Recovery material, server diagnostics, and code values never enter hosted
  outcomes, parent-window messages, or logs.

## Transaction Signing

### Passkey Account

Expected behaviour:

- NEAR, Tempo, and EVM signing select an exact passkey lane for the requested
  curve and chain target.
- If the selected warm session has enough signature uses, signing proceeds
  without another prompt.
- The server resolves the opaque Wallet Session and chooses reusable admission,
  same-method step-up, or hard denial.
- NEAR action batching consumes one signature use per NEAR transaction, not one
  use per action.
- Multiple independent transactions in one signing request consume one
  signature use per transaction digest.
- Tempo and EVM each consume one signature use per transaction request unless a
  future batch API explicitly declares more.
- After successful signing, the signing grant budget is finalized
  exactly once.

Failure behaviour:

- If no exact lane exists, signing fails with a typed lane-selection error.
- If the exact lane exists but budget is exhausted or expired, signing plans
  same-method step-up.
- Passkey signing must not ask for Email OTP unless the user explicitly selected
  an Email OTP auth method for a wallet that supports it.

### Email OTP Account

Expected behaviour:

- NEAR, Tempo, and EVM signing select an exact Email OTP lane for the requested
  curve and chain target.
- If the selected warm session has enough signature uses, signing proceeds
  without another OTP.
- The server resolves the opaque Wallet Session and chooses reusable admission,
  same-method step-up, or hard denial.
- NEAR action batching consumes one signature use per NEAR transaction, not one
  use per action.
- Multiple independent transactions in one signing request consume one
  signature use per transaction digest.
- Tempo and EVM each consume one signature use per transaction request unless a
  future batch API explicitly declares more.
- ECDSA shared-key material may be sourced from another EVM-family target, but
  signing readiness and budget checks must remain exact to the requested
  `chainTarget`.
- After successful signing, the signing grant budget is finalized
  exactly once.

Failure behaviour:

- If no exact lane exists, signing fails with a typed lane-selection error.
- If the exact lane exists but budget is exhausted or expired, signing plans
  Email OTP step-up.
- Email OTP signing must not call WebAuthn credential lookup, passkey PRF, or
  passkey/touch-confirm sealed restore.

### Page Refresh Before Signing

Expected behaviour:

- A refreshed page may use restored warm sessions if they are exact, valid, and
  have enough budget.
- A refreshed page must re-read lane inventory before signing.
- A refreshed page must not rely on stale in-memory diagnostics or stale
  candidates from before refresh.
- If restoration cannot prove exact readiness, the signing flow must request
  unlock or same-method step-up.

## Step-Up Auth

### Passkey Account

Expected behaviour:

- Step-up uses the selected wallet's passkey auth method.
- If the credential id is known, WebAuthn should request that credential
  directly.
- Step-up is operation-specific and claims one quota-neutral authorized
  operation.
- Step-up preserves the existing key, lane, material activation, Wallet
  Session, and budget identity.
- Step-up for NEAR must not refresh ECDSA-only lanes unless the approved
  operation requires them.
- Step-up for Tempo/EVM must be exact to the requested ECDSA chain target.

Failure behaviour:

- A cancelled passkey prompt cancels the operation and must not spend budget.
- A passkey step-up result cannot authorize an Email OTP lane.

### Email OTP Account

Expected behaviour:

- Step-up sends an operation-specific Email OTP challenge.
- Verifying the OTP claims one quota-neutral authorized operation.
- Step-up preserves the existing key, lane, material activation, Wallet
  Session, and budget identity.
- Step-up for NEAR must authorize the selected Ed25519 lane.
- Step-up for Tempo/EVM must authorize the selected ECDSA lane and exact chain
  target.
- Step-up should show one OTP prompt per approved operation.

Failure behaviour:

- A cancelled or failed OTP prompt cancels the operation and must not spend
  budget.
- An Email OTP step-up result cannot authorize a passkey lane.
- A step-up OTP challenge cannot be reused for wallet unlock, registration, or
  key export.

### Page Refresh During Step-Up

Expected behaviour:

- Refreshing during an incomplete step-up cancels or resumes only through an
  explicit operation-state path.
- A stale step-up challenge must not authorize a different operation after
  refresh.
- A completed step-up may be restored only if the restored lane is exact to the
  same wallet, auth method, operation, curve, chain target, and session ids.

## Key Export

### Passkey Account

Expected behaviour:

- Key export requires fresh export-scoped passkey authorization.
- A normal transaction-signing warm session is not enough to export keys.
- Ed25519 export selects an exact Ed25519 export lane.
- ECDSA export selects an exact ECDSA export lane for the requested chain target
  or shared EVM-family key, with source material explicitly resolved.
- Export opens the export viewer only after authorization and material
  preparation succeed.
- Export authorization is one-time or export-scoped according to policy.

Failure behaviour:

- Transaction step-up authorization must not be accepted for key export.
- If export material is unavailable, export fails with an exact export-lane or
  material error.
- Passkey export must not call Email OTP verification unless the user selected
  an Email OTP auth method for a wallet that supports it.

### Email OTP Account

Expected behaviour:

- Key export requires fresh export-scoped Email OTP authorization.
- A wallet-unlock OTP or transaction step-up OTP is not enough to export keys.
- Ed25519 export selects an exact Email OTP Ed25519 export lane.
- ECDSA export selects an exact Email OTP ECDSA export lane for the requested
  chain target or shared EVM-family key, with source material explicitly
  resolved.
- Export opens the export viewer only after authorization and material
  preparation succeed.
- Export must not call WebAuthn credential lookup, passkey PRF, or
  passkey/touch-confirm sealed restore.

Failure behaviour:

- Transaction step-up authorization must not be accepted for key export.
- Wallet-unlock authorization must not be accepted for key export.
- If export material is unavailable, export fails with an exact export-lane or
  material error.

### Page Refresh During Export

Expected behaviour:

- Refreshing during export must not leak key material or leave an export viewer
  authorized without fresh operation state.
- If export resumes after refresh, it must revalidate export-scoped
  authorization and exact lane/material identity.
- A transaction-signing session restored after refresh must not become export
  authority.

## Account Recovery

Until Refactor 109A defines multi-auth recovery, code recovery accepts only a
wallet with exactly one active Passkey owner method for the requested RP.

Expected behaviour:

- The hosted wallet-iframe menu accepts one unused recovery code. The server
  resolves the wallet from the code locator. It does not request Email OTP, Google authentication, an
  existing Passkey assertion, or an old credential ID.
- Preparation reserves the code and returns replacement Passkey registration
  options. A separate **Create new passkey** activation starts WebAuthn.
- Finalization preserves every public wallet identity and atomically installs
  the replacement authenticator, auth method, binding, and custody envelope;
  consumes one code; revokes the source method and its Wallet Sessions; and
  retires the source envelope.
- Recovery restores local continuity against the replacement Passkey authority.
- The menu reports `authenticated/passkey` only after normal login with the
  replacement Passkey creates a fresh Wallet Session.
- The remaining recovery codes stay active. Reusing the consumed code receives
  the same generic refusal as every other invalid recovery attempt.

Failure behaviour:

- Cancellation before finalization leaves the code usable after its reservation
  expires and clears client-held recovery material.
- A failed atomic finalization leaves the source method active and the code
  unconsumed. Transport uncertainty may replay the same finalization.
- Unknown wallets, unusable codes, RP mismatch, and unsupported auth-method
  shapes expose no distinguishing recovery detail.

## Linked Devices

Expected behaviour:

- Linking creates a fresh `deviceId`, `walletAuthorityId`,
  `walletAuthMethodId`, and signer activation for every signer family present
  on the source authority. The wallet's public signer identities remain
  unchanged, and Device 1's authority, methods, material, sessions, and
  revocation epoch remain unchanged.
- Device 2 never receives the wallet custody seed. An Ed25519 installation
  with `export_keys` receives only the one-use encrypted Yao Client export
  root and seals it under the verified target method.
- Device 2 uses ordinary Wallet Session, signing, export, reload, lock,
  unlock, inventory, and revocation paths after activation. Those operations
  do not read the completed link session or repair missing material.
- Device inventory is derived from active wallet authorities with
  device-link provenance and their exact auth methods. A completed link
  session is temporary workflow state and is deleted after acknowledgement.
- A Passkey card displays server-derived authenticator metadata when it is
  available. An Email OTP card displays `Email OTP` and makes no browser,
  operating-system, provider, transport, sync, or hardware claim.
- Every card displays a stable shortened `deviceId`. Creation-order labels
  such as `Device 2` are not durable identity, and metadata must not imply an
  exact physical machine or exclusive possession of a synced Passkey.
- Device metadata is display and audit context only. Authorization, signing,
  export, unlock, and revocation never branch on labels, browser or operating-
  system names, providers, transports, or sync state.
- Raw User-Agent strings, attestation objects, PRF output, factor secrets, and
  Email OTP addresses do not enter the management response.
- User revocation targets one exact `walletAuthMethodId` and requires fresh
  proof from a different active method under a full-owner authority. Removing
  the wallet's final active method is refused without changing durable state.
- Revoking the final method attached to an authority retires that authority,
  invalidates its sessions, and disables its exact signer activations while
  leaving other methods, authorities, and devices operational.

Failure behaviour:

- Missing, duplicate, cross-wallet, wrong-kind, revoked, or digest-mismatched
  authority and auth-method records fail closed. Runtime operations do not
  select a sibling device or infer identity from timestamps or display data.
- An incomplete migrated enrollment returns `relink_required` at its boundary.
  Linking does not hydrate, recover, rotate, promote, or synthesize missing
  signer or export material.
- Retrying after the pending-authority commit reuses the exact authority,
  method, activation, package, and digest identities. It must not create a
  duplicate authority or signer activation.

## Test Matrix

Every release touching registration, auth methods, signing sessions, budget,
lane selection, worker material, or export should validate this matrix.

| Account type | Registration                            | Unlock                    | NEAR tx                   | Tempo tx                     | EVM tx                       | Step-up NEAR     | Step-up Tempo    | Step-up EVM      | Ed25519 export                | ECDSA export                | Page refresh                                       |
| ------------ | --------------------------------------- | ------------------------- | ------------------------- | ---------------------------- | ---------------------------- | ---------------- | ---------------- | ---------------- | ----------------------------- | --------------------------- | -------------------------------------------------- |
| Passkey      | ECDSA-ready; NEAR readiness is explicit | warms exact present lanes | available at `near_ready` | no prompt while budget valid | no prompt while budget valid | passkey prompt   | passkey prompt   | passkey prompt   | fresh auth after `near_ready` | fresh passkey export auth   | restores durable readiness and exact present lanes |
| Email OTP    | one OTP; reroll allowed; ECDSA-ready    | warms exact present lanes | available at `near_ready` | no OTP while budget valid    | no OTP while budget valid    | Email OTP prompt | Email OTP prompt | Email OTP prompt | fresh auth after `near_ready` | fresh Email OTP export auth | restores durable readiness and exact present lanes |

## Validation Mapping

Each row needs either an automated test or an explicit manual verification note
when a change touches registration, unlock, signing, step-up, export, session
restore, lane selection, or budget handling.

| Behaviour                                                                | Evidence                                                   |
| ------------------------------------------------------------------------ | ---------------------------------------------------------- |
| Email OTP registration with zero rerolls uses one OTP code               | Relayer route/auth-service test                            |
| Email OTP registration with one reroll uses the original OTP code        | `tests/unit/authService.hostedAccountPrivacy.unit.test.ts` |
| Email OTP registration with multiple rerolls uses the original OTP code  | Relayer route test or manual registration reroll note      |
| Wrong Email OTP provider subject is rejected                             | `tests/unit/authService.hostedAccountPrivacy.unit.test.ts` |
| Wrong Email OTP challenged email is rejected                             | `tests/unit/authService.hostedAccountPrivacy.unit.test.ts` |
| Registration and unlock produce equivalent runtime lanes                 | Client runtime-postcondition test                          |
| Passkey registration signs Tempo/Arc immediately and NEAR at readiness   | Intended-behaviour registration contract                   |
| Email OTP registration signs Tempo/Arc immediately and NEAR at readiness | Intended-behaviour registration contract                   |
| Passkey step-up signs NEAR, Tempo, and Arc/EVM                           | Client signing test or manual browser note                 |
| Email OTP step-up signs NEAR, Tempo, and Arc/EVM                         | Client signing test or manual browser note                 |
| Passkey Ed25519 and ECDSA export require fresh export auth               | Client export test or manual browser note                  |
| Email OTP Ed25519 and ECDSA export require fresh export auth             | Client export test or manual browser note                  |
| Page refresh restores only exact valid lanes                             | Page-refresh session test or manual browser note           |
| Code recovery replaces one Passkey and preserves all public identities   | Intended-behaviour recovery contract                       |
| Code recovery revokes source sessions and consumes exactly one code      | Intended-behaviour recovery contract                       |
| Email OTP paths never call passkey credential lookup or PRF restore      | `tests/unit/refactor46d.guard.unit.test.ts`                |
| ECDSA budget checks are exact to chain target                            | `tests/unit/refactor46d.guard.unit.test.ts`                |

## Non-Goals

- Do not use passkey fallback paths to repair Email OTP state.
- Do not use Email OTP fallback paths to repair passkey state.
- Do not hide registration failures by relying on a later wallet unlock to fix
  local runtime state.
- Do not treat public ECDSA identity as signing material.
- Do not use session ids alone to identify ECDSA readiness or budget.
- Do not send extra OTP codes during registration reroll.
