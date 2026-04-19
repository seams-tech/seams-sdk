# EVM Device Linking and Recovery Plan

## Implementation Status

Completed foundations:

- [x] server-side canonical `account_signer` store
- [x] server-side canonical `smart_account_recovery_subject` store
- [x] registration persists the initial threshold-ECDSA smart-account signer set seed
- [x] registration persists recovery-subject bindings for smart-account targets
- [x] canonical `recovery_session` store for multichain email recovery
- [x] `email-recovery/prepare` persists multichain recovery session state
- [x] `email-recovery/prepare` can bootstrap optional threshold-ECDSA recovery material
- [x] canonical `recovery_execution` store for per-chain/account recovery tracking
- [x] `/recover-email` records NEAR recovery submission state when the email maps to a pending recovery session
- [x] `/recover-email` advances canonical `recovery_session` status to `near_recovered` / `evm_recovering` / `failed`
- [x] `link-device/prepare` can bootstrap optional threshold-ECDSA device-link material
- [x] `link-device/prepare` persists pending canonical signer rows for linked smart accounts
- [x] client `linkDevice` persists threshold-ECDSA bootstrap state and pending linked-account signer rows
- [x] the authorizing device can execute deployed EVM `addOwner(...)` / `removeOwner(...)` signer mutations from queued canonical signer ops
- [x] deployment observation materializes canonical pending signer rows for undeployed smart accounts
- [x] successful NEAR recovery submission seeds pending per-account EVM `recovery_execution` rows for linked smart accounts
- [x] canonical `recovery_execution` state can enumerate pending `recover_add_owner` work for future executor pickup
- [x] canonical `recovery_session` state can be reconciled from per-account EVM `recovery_execution` rows
- [x] `recoveryAuthority` core executor can consume queued `recover_add_owner` rows and finalize undeployed recovery canonically
- [x] `recoveryAuthority` can resume submitted deployed recovery executions and finalize canonical signer/session state after receipt confirmation
- [x] canonical recovery execution metadata now carries server-side deployed vs undeployed target mode
- [x] later smart-account deployments refresh canonical recovery-subject deployment state through an authenticated relay observation path
- [x] deployed EVM recovery now runs through the shared sponsorship runtime with policy, spend/prepaid settlement, ledger linkage, and receipt confirmation
- [x] canonical undeployed smart-account deployment manifests are materialized from server-side signer state and consumed by relay/client deployment flows
- [x] background recovery continuation now monitors failed and stale per-account `recovery_execution` rows
- [x] sponsored recovery monitoring now emits console observability incidents when recovery rows carry sponsorship scope metadata
- [x] sponsored recovery observability incidents use deterministic scope/window dedupe keys so background recovery ticks do not spam duplicate alerts
- [x] retryable failed EVM recovery executions now requeue automatically back into the recoveryAuthority worker loop
- [x] repeated EVM recovery attempts now carry explicit per-account retry metadata instead of silently overwriting prior failure context
- [x] canonical recovery email payload now binds `new_near_key`, `new_evm_key`, `recoverySessionId`, and `deadline` inside the verified email artifact
- [x] `email-recovery/prepare` now creates recovery sessions bound to the new EVM owner, recovery deadline, and canonical payload hash
- [x] `/recover-email` now rejects mismatched recovery emails before NEAR execution and marks the canonical recovery session `verified`
- [x] EVM recovery continuation now requires a verified recovery session plus an explicit NEAR-success gate before queuing linked smart-account recovery
- [x] deployed recovery sponsorship now builds spec-facing `verifyAndRecover` / `recoverAddOwner` authorization payloads with session binding, nonce, and deadline
- [x] off-chain recovery authorization now uses selector-independent digest and nonce derivation so deployed replay semantics match the smart-account spec
- [x] deployed recovery and deployed `addOwner(...)` owner-mutation execution now derive canonical selectors from the in-repo smart-account spec metadata
- [x] a reusable relay-side EVM deploy adapter now executes deterministic factory deployment from the canonical `evmDeploymentPlan`
- [x] canonical deployment-manifest sync now persists derived EVM deployment-plan metadata on recovery subjects and clears stale non-EVM plan metadata
- [x] sponsored recovery execution rows now persist canonical smart-account call and authorization metadata needed for receipt tracking and observability
- [x] sponsored recovery verification now covers submission, retry requeue, and receipt confirmation while preserving canonical smart-account metadata
- [x] in-repo `/contracts/evm-smart-account` package now implements the canonical smart-account surface with forge tests plus generated ABI and metadata artifacts
- [x] end-to-end relayer verification now covers undeployed recovery continuation from `/recover-email`
- [x] end-to-end relayer verification now covers deployed recovery submission and confirmation while preserving canonical smart-account metadata
- [x] end-to-end relayer verification now covers deterministic EVM deployment from canonical deployment-plan metadata
- [x] source-backed verification now covers deployed owner-mutation and replay paths against current client modules plus the in-repo smart-account spec package
- [x] canonical deployment-manifest ordering now preserves owner order into EVM init data exactly
- [x] spec-package deployment tests now cover undeployed-to-deployed continuity after canonical link-device or recovery owner mutations
- [x] operational runbooks now cover replay incidents, failed sponsorship, and partial completion

Broader multichain follow-ons remain in the phased checklist below, but the active V1 EVM smart-account track above is complete.

## Goal

Extend `linkDevice` and `email recovery` to EVM chains without re-implementing DKIM verification on every EVM chain.

This plan adopts one recovery architecture only:

- a verified recovery email binds both `new_near_key` and `new_evm_key`
- the same recovery proof drives NEAR account recovery and EVM smart-account recovery
- EVM recovery is executed and sponsored by one global `recoveryAuthority`

Target product shape:

- one smart account per user per EVM chain
- multiple authorized device signers per smart account
- `linkDevice` adds a new signer to that same smart account
- `email recovery` restores NEAR and EVM access in one flow

## Chosen architecture

### 1. EVM needs smart accounts

For EVM, a new passkey / new threshold-ECDSA client share produces a new threshold owner identity. A plain EOA cannot absorb that as "the same account". The stable user-facing account must therefore be a smart account with mutable signer state.

This remains consistent with [smart-accounts-evm.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/smart-accounts-evm.md):

- registration may provision an undeployed counterfactual smart account
- deployment can stay deferred until first EVM use or recovery

### 2. One verified recovery email binds both keys

The recovery root for EVM should not be "a NEAR key signed another message after recovery".

Instead, the recovery email itself should carry a recovery payload that binds:

- the canonical NEAR account, e.g. `bob.near`
- `new_near_key`
- `new_evm_key`
- a recovery session identifier / nonce
- a deadline
- optional recovery scope metadata

Outlayer verifies DKIM inside the TEE and returns a compact verification result over that payload.

That one verified email result is then consumed in two places:

- NEAR `EmailRecoverer` adds `new_near_key`
- EVM `recoveryAuthority` adds `new_evm_key` to linked smart accounts

This is the core design. There is no separate "Solution 1" or "Solution 2" in this plan.

### 3. `recoveryAuthority` is the EVM recovery authority

EVM recovery should trust one global `recoveryAuthority`:

- the threshold MPC signer / relayer we control
- responsible for sponsoring and dispatching deployed EVM recovery mutations
- responsible for consuming the verified email recovery result and turning it into EVM recovery actions

The EVM contract should not verify DKIM, DNS, raw email blobs, or live NEAR account state.

The contract should verify only an EVM-friendly recovery authorization from `recoveryAuthority`.

`verifyAndRecover()` should remain callable by anyone, but in practice V1 recovery is executed by `recoveryAuthority`.

Important distinction:

- caller / executor is not the trust root
- `recoveryAuthority` authorization is the trust root

### 4. NEAR remains the canonical identity anchor

The canonical recovery subject is still the NEAR account, e.g. `near:bob.near`.

But the authorization artifact for EVM recovery is the verified recovery email payload, not a post-recovery NEAR signature.

That keeps the flow simpler:

- no extra NEAR signing step after recovery
- no need to prove a newly-added NEAR key signed anything after recovery
- both chains are restored from the same verified email event

### 5. `linkDevice` and `email recovery` remain separate paths

They should not share the same authority path.

- `linkDevice` is normal owner-management authorized by an existing active EVM owner
- `email recovery` is a privileged recovery path authorized by `recoveryAuthority` after verified email recovery

### 6. Undeployed smart accounts still mutate off-chain

Deployment is not required just to update the intended signer set.

- deployed smart accounts mutate on-chain immediately
- undeployed smart accounts update canonical off-chain signer state
- later deployment uses the latest signer set as initializer state

### 7. Recovery is sponsored

Deployed EVM recovery mutations are sponsored.

The user should not need:

- an already-working EVM signer on the target chain
- gas on the target chain
- a second recovery approval step after the email recovery succeeded

The repo now has a concrete sponsorship runtime. Recovery sponsorship should use that shared path rather than a custom "relayer pays gas" branch.

## Final Recovery Pipeline

The V1 recovery pipeline is now:

1. `email-recovery/prepare` creates a canonical recovery session bound to `nearAccountId`, `new_near_key`, `new_evm_key`, `recoverySessionId`, `deadline`, and the DKIM-bound payload hash.
2. `/recover-email` verifies the email payload against that canonical session and records the NEAR recovery submission.
3. Successful NEAR recovery gates EVM continuation; the relayer will not queue linked smart-account recovery before that gate is satisfied.
4. For each linked EVM smart account, the relayer records a canonical `recovery_execution` row with deployed vs undeployed target metadata.
5. Undeployed accounts mutate canonical signer state off-chain only; later deployment materializes the latest canonical owner set into `evmDeploymentPlan.initData`.
6. Deployed accounts execute `verifyAndRecover(...)` through the shared sponsorship runtime using the canonical EIP-712 recovery authorization.
7. Receipt confirmation activates the recovered signer canonically, updates deployment/recovery metadata, and reconciles the parent `recovery_session`.
8. Background continuation handles retryable failures, submitted confirmations, and observability for stuck or failed recovery rows.

## Operational Runbook

### Replay Rejection

- Symptom: a deployed recovery row fails with `tx_reverted` and the preserved `recoverySpec.authorization.payload.nonce` already appears consumed for that smart account.
- Confirm the failure is a true replay by checking the recovery row metadata, the smart-account event or receipt, and `isRecoveryNonceUsed(...)` on the target account.
- Do not requeue the same authorization. Recovery nonces are single-use per account, and the worker already treats `tx_reverted` as non-retryable.
- If recovery still needs to proceed, generate a fresh canonical recovery authorization from the current recovery session and submit a new sponsored execution.

### Failed Sponsorship

- Symptom: deployed recovery remains `pending`, `submitted`, or `failed` with sponsorship metadata but no successful settlement.
- Confirm sponsorship scope, policy resolution, spend-cap reservation, prepaid-balance state, and relayer RPC health before retrying.
- If the failure is retryable, let the background recovery loop requeue it; if the failure is non-retryable, fix the billing or policy condition first and then issue a fresh recovery execution.
- Preserve the existing `recoverySpec` and sponsorship metadata for incident review; do not overwrite prior failure context manually.

### Partial Completion

- Symptom: NEAR recovery succeeded but one or more linked EVM recovery rows are still `pending`, `submitted`, or `failed`.
- Use the canonical `recovery_execution` rows as the source of truth. The parent `recovery_session` should be reconciled from those per-account rows, not guessed from client state.
- If the account is undeployed, confirm the recovered signer appears in canonical signer state and in the current deployment manifest before any later deploy.
- If the account is deployed, confirm receipt status, signer activation, and updated recovery-subject deployment metadata before marking the session fully complete.

## Recovery proof model

### Email recovery payload

The recovery email should embed a structured payload that includes:

- `nearAccountId`
- `newNearKey`
- `newEvmKey`
- `recoverySessionId`
- `deadline`
- optional scope metadata if recovery should target a subset of linked EVM accounts

This payload must be inside the DKIM-verified portion of the email.

If we cannot guarantee that a field is inside the verified portion, it must not be trusted for recovery.

### Verified email result

Outlayer should return a compact verification result that binds the verified recovery payload to the recovered NEAR account.

At minimum the verified result should identify:

- `nearAccountId`
- `newNearKey`
- `newEvmKey`
- `recoverySessionId`
- verification success
- verification timestamp / expiry metadata

This result is not meant to be parsed by EVM contracts directly in V1. It is consumed off-chain by the relayer / `recoveryAuthority`.

### Why this is better than a post-recovery NEAR intent signature

The older idea was:

- recover NEAR first
- ask the new NEAR key to sign a second recovery intent for EVM

This plan replaces that with:

- one verified email payload binds both new keys
- the verified email event is enough to recover both NEAR and EVM

Benefits:

- better UX
- fewer moving parts
- no second wallet action after recovery
- tighter binding between `new_near_key` and `new_evm_key`

## NEAR-side model

### Existing recovery pipeline

We already have the NEAR recovery shape:

- an `EmailRecoverer` contract is configured for the account
- the recovery email is sent to a Cloudflare Worker relayer
- the relayer encrypts the raw email for an Outlayer worker running in a TEE
- the NEAR account / recovery contract forwards the encrypted email to Outlayer
- Outlayer decrypts the email, verifies DKIM, and returns a compact verification result

Concrete TEE implementation reference:

- [email-dkim-verifier](https://github.com/web3-authn/email-dkim-verifier)

### Required extension

The recovery email payload must now carry both:

- `new_near_key`
- `new_evm_key`

The verified result must therefore be sufficient for:

- `EmailRecoverer` to add `new_near_key`
- `recoveryAuthority` to recover linked EVM smart accounts with `new_evm_key`

### NEAR success as a gating signal

Operationally, EVM recovery should not race ahead of NEAR recovery.

`recoveryAuthority` should execute EVM recovery only after:

- the email verification result is valid
- the recovery session matches the expected pending state
- the NEAR-side `addKey(new_near_key)` recovery step succeeded

That gives one consistent recovery event across both ecosystems.

## EVM-side model

### Smart account shape

Each EVM chain gets one smart account instance for the user. State and deployment remain chain-local.

The smart account should support:

- standard owner add/remove for active signers
- a dedicated recovery method for email-driven recovery
- replay protection for recovery operations
- explicit separation between normal owner-management and recovery-management

Suggested naming:

- normal path: `addOwner`, `removeOwner`
- recovery path: `verifyAndRecover` or `recoverAddOwner`

Avoid naming EVM methods `addKey` / `deleteKey`. On EVM these are owners or signers, not protocol-native account keys.

### Trusted recovery authority

V1 should use one global `recoveryAuthority`.

Do not model:

- per-account attestor sets
- multiple recovery backends inside the smart-account contract
- direct TEE proof verification inside the smart-account contract

The contract only needs to know:

- which NEAR account this smart account is associated with
- which EVM owner set is active
- which recovery nonce values have already been used
- how to verify a recovery authorization from `recoveryAuthority`

### Recovery payload

The EVM recovery authorization should use an EIP-712 typed payload.

Recommended struct:

```solidity
RecoverAddOwner(
  bytes32 nearAccountIdHash,
  bytes32 newNearKeyHash,
  address newOwner,
  bytes32 recoverySessionHash,
  uint256 nonce,
  uint256 deadline
)
```

Recommended domain:

- `name = <smart account recovery domain>`
- `version = 1`
- `chainId = block.chainid`
- `verifyingContract = smartAccount`

Notes:

- `nearAccountIdHash` keeps the recovered account identifier explicit
- `newNearKeyHash` makes the exact recovered NEAR key auditable
- `newOwner` is the new EVM signer being installed
- `recoverySessionHash` binds the authorization to the verified email recovery session
- `nonce` and `deadline` provide replay protection and expiry

The smart account verifies:

- signature is from `recoveryAuthority`
- payload is for this chain and this smart account via the EIP-712 domain
- nonce is unused
- deadline has not expired

The smart account does not verify:

- DKIM signatures
- DNS TXT records
- Outlayer attestation format
- live NEAR account state

### Executor model

`verifyAndRecover()` should be callable by anyone.

That keeps execution flexible:

- V1: `recoveryAuthority` submits the transaction and sponsors gas
- later: another relayer or external executor could submit the same recovery authorization

But V1 product behavior remains:

- `recoveryAuthority` is the practical executor
- recovery is sponsored

### Sponsorship runtime integration

The repo now has a shared sponsorship runtime for EVM execution, including:

- sponsorship policy matching
- spend-cap reservation
- prepaid balance reservation when configured
- exact spend settlement
- sponsored execution history
- billing and observability linkage

Relevant implementation references:

- [docs/gas-and-signing-policies.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/gas-and-signing-policies.md)
- [docs/gas-sponsorship-prepaid-balances.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/gas-sponsorship-prepaid-balances.md)
- [server/src/router/relaySponsoredEvmCall.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relaySponsoredEvmCall.ts)
- [server/src/router/sponsorshipExecution.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/sponsorshipExecution.ts)
- [server/src/sponsorship/evmRelay.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/sponsorship/evmRelay.ts)

Implication for recovery:

- do not invent a bespoke recovery-only gas payment path
- deployed EVM recovery should reuse the shared sponsorship runtime or an internal adapter over the same settlement primitives
- if recovery is tenant-billed, it should be subject to the same sponsorship policy, spend-cap, prepaid-balance, and atomic-settlement rules as other sponsored EVM execution
- if recovery is platform-funded, that should be an explicit sponsorship mode, but the execution record should still flow through the same sponsored-execution history and observability path

### Deployed vs undeployed behavior

#### Deployed smart account

- `linkDevice` submits a normal owner-management action on-chain
- `email recovery` submits a sponsored recovery action on-chain

#### Undeployed counterfactual smart account

- update canonical off-chain signer state
- mark the recovered EVM owner as active in the undeployed signer set
- deploy later with the latest signer set as initializer state

This keeps recovery possible even before first EVM deployment.

### Recovery scope across EVM accounts

The default recovery scope should be:

- all linked EVM smart accounts for the recovered profile

The recovery session can later support narrower scopes if needed, but V1 should optimize for automatic continuity.

That means one verified recovery email can recover:

- the NEAR account
- all linked deployed EVM smart accounts
- all linked undeployed EVM smart accounts by updating off-chain signer state

## Data model changes

### Canonical model

The canonical model should be:

- profile / user identity
- chain accounts
- account signers
- recovery subject metadata
- recovery sessions

The client already has a good chain-agnostic direction with `accountSigners` in [passkeyClientDB.types.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyClientDB.types.ts). Reuse that direction instead of inventing EVM-specific parallel storage and NEAR-specific special cases.

### Required refactor

The current server-side WebAuthn credential binding shape is still NEAR-oriented. It should not keep absorbing EVM-specific meaning.

Plan:

- introduce a chain-agnostic server-side account-signer store
- keep credential binding focused on authenticator identity
- introduce a recovery-session store for email-driven multichain recovery
- remove any design assumption that EVM recovery state lives in NEAR-specific binding records

Suggested server-side records:

- `credential_binding`
  - `credentialId`
  - `rpId`
  - `userId`
  - `signerSlot`
- `account_signer`
  - `userId`
  - `chainIdKey`
  - `accountAddress`
  - `signerType`
  - `signerId`
  - `status`
  - metadata including threshold-ECDSA owner info
- `smart_account_recovery_subject`
  - `userId`
  - `chainIdKey`
  - `accountAddress`
  - `nearAccountId`
- `recovery_session`
  - `sessionId`
  - `userId`
  - `nearAccountId`
  - `newNearKey`
  - `newEvmKey`
  - `scope`
  - `status`
  - `expiresAt`
  - `verifiedEmailProofHash`
  - audit metadata

Optional but useful:

- `recovery_execution`
  - `sessionId`
  - `chainIdKey`
  - `accountAddress`
  - `action`
  - `status`
  - `transactionHash`

Implementation note:

- `account_signer` and `smart_account_recovery_subject` are now implemented on the server side
- `recovery_session` and `recovery_execution` are now canonical server-side stores
- current execution tracking covers the NEAR submission path; EVM continuation is still pending

### Canonical signer set

The signer set should be canonical off-chain and materialized on-chain.

For each smart account:

- active device signers
- pending signers
- revoked signers
- recovery subject metadata

There is no separate per-account recovery-attestor set in this plan.

Deployed chains apply mutations immediately.
Undeployed chains inherit the latest signer set when deployed.

### Undeployed source of truth

The canonical source of truth for undeployed smart accounts should be the server-side `account_signer` state.

Any deployment manifest must be derived from that canonical state, not treated as a separate authority.

This avoids drift between:

- undeployed recovery mutations
- deployed smart-account initialization
- client-side local state restoration

## API and flow changes

### 1. Registration

Registration should continue to:

- provision threshold ECDSA
- persist the chain account as `erc4337`
- allow deployment to remain deferred

Registration must additionally:

- persist the first EVM owner signer record
- persist the recovery subject for each smart account
- ensure linked EVM accounts can later be resolved from the recovered profile

### 2. `linkDevice`

The EVM `linkDevice` flow should be:

1. New device performs WebAuthn registration.
2. New device derives a new threshold-ECDSA owner identity.
3. Existing active device authorizes adding that owner to the smart account.
4. Server persists the new signer record.
5. If the smart account is deployed, submit on-chain owner addition.
6. If undeployed, update the off-chain desired signer set only.
7. New device restores local signer state and becomes usable immediately.

Important:

- use the standard owner-management path
- do not route this through the email-recovery path

### 3. `email recovery`

The EVM `email recovery` flow should be:

1. New device begins recovery and generates:
   - `new_near_key`
   - `new_evm_key`
2. Server creates a pending `recovery_session` that binds:
   - `nearAccountId`
   - `new_near_key`
   - `new_evm_key`
   - recovery scope
   - expiry
3. The recovery email embeds that recovery payload in DKIM-covered content.
4. The Cloudflare Worker relayer encrypts and forwards the raw email into the existing NEAR / Outlayer recovery pipeline.
5. Outlayer verifies DKIM and returns a verified recovery result for the session.
6. `EmailRecoverer` adds `new_near_key` to the NEAR account.
7. After NEAR recovery succeeds, `recoveryAuthority` resolves all linked EVM smart accounts in scope.
8. For each linked EVM smart account:
   - if deployed, sponsor and submit `verifyAndRecover` / `recoverAddOwner`
   - if undeployed, update the canonical off-chain signer set
9. Server records execution results and finalizes the recovery session.
10. New device finalizes local state and can use the recovered smart accounts.

Important:

- no extra user signature is required after email recovery
- `new_evm_key` must already be bound by the recovery session
- EVM recovery is automatic once the verified email recovery succeeds

V1 recommendation:

- recovery adds a new owner first
- normal owner-management can remove stale owners afterward

Open risk:

- if old owners are compromised rather than merely lost, "add new owner first" may be insufficient
- a later phase may need `recoverRotateOwners` or a timelocked full-rotation path

### 4. `syncAccount`

`syncAccount` is not part of the smart-account mutation layer.

It remains useful as a local rehydration primitive for:

- same-passkey multi-device restore
- iCloud / Google passkey-sync restore

It should be treated as a later follow-on task, not as a prerequisite for EVM `linkDevice` or EVM `email recovery`.

### Internal relayer hooks

Keep these internal-only. Do not introduce public generic mutation routes unless there is a strong product reason.

Needed internal capabilities:

- `recoverySessionStart`
- `processVerifiedEmailRecovery`
- `smartAccountDeploy`
- `smartAccountAddOwner`
- `smartAccountRemoveOwner`
- `smartAccountRecoverOwner`

Or, preferably, one generic internal mutation executor:

- `smartAccountExecuteMutation`

That executor can handle:

- deployed vs undeployed branching
- sponsorship
- chain-specific bundler integration
- audit logging

The NEAR / email recovery pipeline should feed one canonical recovery session outcome into that mutation executor.

## Details to lock before implementation

The architecture is settled, but a few implementation details should be made explicit before coding starts:

- exact recovery payload schema inside the email, including encoding and placement inside DKIM-covered content
- exact verified-result schema returned by the Outlayer pipeline and persisted by the relayer
- recovery-session state machine, including status transitions, expiry, and retry behavior
- how recovery-session creation proves or binds control of `new_evm_key` to the recovering device
- how linked EVM accounts are resolved for the default "recover all linked EVM accounts" scope
- which concrete NEAR success signal gates EVM recovery execution
- how partial per-chain EVM recovery failures are retried without double-applying successful recoveries
- whether recovery sponsorship is tenant-billed, platform-funded, or supports both modes
- whether recovery calls go through the public sponsored EVM route contract or an internal adapter using the same sponsorship settlement path

These are implementation details, not alternative architectures. They should be locked early so the rest of the work does not churn.

## Phased to-do list

### Phase 0: Lock schemas and state transitions

- [x] Define the exact email-embedded recovery payload schema.
- [x] Define where that payload lives in DKIM-covered email content.
- [x] Define the canonical verified-result schema produced by the Outlayer pipeline.
- [x] Define the `recovery_session` status model and allowed transitions.
- [ ] Define the default recovery scope resolution rule for linked EVM accounts.
- [x] Define how `new_evm_key` ownership or control is bound at recovery-session creation time.
- [x] Define the exact NEAR-side success signal that unblocks EVM recovery execution.
- [ ] Decide whether recovery sponsorship is tenant-billed, platform-funded, or dual-mode.
- [x] Decide whether deployed recovery uses the public sponsorship route shape or an internal adapter over the same sponsorship runtime.

### Phase 1: Data and session refactor

- [x] Add a chain-agnostic server-side account-signer store.
- [x] Stop extending NEAR-specific binding records for EVM signer state.
- [x] Add a `recovery_session` store for email-driven multichain recovery.
- [x] Persist canonical EVM signer metadata at registration.
- [x] Persist recovery subject metadata per smart account.
- [x] Define client/server representation for undeployed smart-account signer sets.
- [x] Remove any per-account recovery-attestor-set design from the model.

### Phase 2: NEAR / Outlayer recovery integration

- [x] Extend the recovery email payload to include both `new_near_key` and `new_evm_key`.
- [x] Ensure those fields are inside DKIM-covered content.
- [x] Extend the relayer / Outlayer pipeline to return a canonical verified recovery result for that payload.
- [x] Ensure NEAR `EmailRecoverer` can consume that verified result and add `new_near_key`.
- [x] Emit or persist enough recovery-session metadata for `recoveryAuthority` to continue into EVM recovery.
- [x] Gate EVM recovery on successful NEAR-side recovery completion.

### Phase 3: EVM smart-account spec and relayer support

- [x] Implement smart-account owner-management methods for normal device linking.
- [x] Implement `verifyAndRecover` / `recoverAddOwner` authorized by `recoveryAuthority`.
- [x] Use an EIP-712 recovery payload with session binding, nonce, and deadline.
- [x] Add replay protection and expiry checks for recovery payloads.
- [x] Add internal relayer mutation hooks for add/remove/recover owner flows.
- [x] Configure one global `recoveryAuthority`.
- [x] Integrate deployed recovery mutations with the shared sponsorship runtime instead of ad hoc relayer gas handling.
- [x] Require sponsored execution support for deployed recovery mutations.
- [x] Reserve and settle sponsored recovery spend through the shared billing / prepaid / sponsored-call path when enabled.
- [x] Record sponsored recovery executions with route, policy, and billing linkage compatible with sponsored-call history.
- [x] Keep `verifyAndRecover()` callable by anyone even though V1 execution is relayer-driven.

### Phase 4: Client flows

- [x] Implement EVM `linkDevice` using normal owner-management.
- [x] Extend `link-device/prepare` to return chain-aware threshold-ECDSA bootstrap and linked smart-account metadata.
- [x] Persist returned threshold-ECDSA bootstrap and pending linked-account signer state on the new device.
- [x] Remove the legacy local signer auto-activation shortcut so pending linked-account signers stay pending until canonical owner management finishes.
- [x] Publish prepared threshold-ECDSA owner metadata back through the device-link relay session so the authorizing device can seed canonical pending signer mutations.
- [x] Execute deployed EVM linked-account signer additions through queued owner-management mutations and activate only after on-chain success.
- [x] Implement recovery-session creation that binds `new_near_key` and `new_evm_key`.
- [x] Implement EVM `email recovery` as automatic continuation after NEAR email recovery succeeds.
- [x] Queue linked smart-account recovery execution rows after successful NEAR recovery submission.
- [x] Advance canonical recovery-session state during recover-email submission handling.
- [x] Consume queued `recover_add_owner` rows through a core `recoveryAuthority` executor with deployed/undeployed branching hooks.
- [x] Resolve deployed vs undeployed recovery mode from canonical server metadata instead of caller-supplied execution hooks.
- [x] Ensure undeployed accounts mutate off-chain signer state without forcing deploy.
- [x] Ensure deployed accounts mutate on-chain signer state and reconcile local storage.
- [ ] Later: extend `syncAccount` to restore threshold-ECDSA continuity for same-passkey multi-device login.

### Phase 5: Hardening and retry handling

- [x] Add recovery-session retry handling for partial multi-chain failures.
- [x] Add idempotent per-account execution tracking for repeated recovery attempts.
- [x] Add canonical EVM recovery execution summary reconciliation over queued per-account rows.
- [x] Confirm and finalize previously submitted deployed recovery executions from canonical `recovery_execution` state.
- [x] Dispatch `recoveryAuthority` pending/submitted passes automatically from `/recover-email`, while leaving deployed rows queued when sponsorship execution is unavailable.
- [x] Add a Cloudflare cron recovery-continuation job so queued/submitted recovery work can advance outside the request path.
- [x] Add a non-Cloudflare interval recovery-continuation runner for Node/Express deployments.
- [x] Refresh canonical smart-account deployment state after later client-driven deployments so recovery mode stays accurate after undeployed -> deployed transitions.
- [x] Add monitoring and alerting around failed and stuck per-account recovery executions in background continuation.
- [x] Add operational runbooks for replay incidents, failed sponsorship, and partial completion.
- [x] Add observability and reconciliation coverage for sponsored recovery executions.
- [x] Deduplicate sponsored recovery observability incidents across repeated background ticks with deterministic scope/window alert keys.

### Phase 6: Cleanup and convergence

- [x] Materialize canonical undeployed deployment manifests from server-side signer state and reuse them for later deployment.
- [x] Remove older recovery designs that depended on post-recovery NEAR intent signatures.
- [x] Remove legacy assumptions that EVM recovery needs separate backend variants in the smart-account spec.
- [x] Refactor NEAR-only recovery flow types into chain-aware recovery domain types.
- [x] Consolidate multichain account continuity under one profile + signer-set model.
- [x] Document the final recovery pipeline next to [smart-accounts-evm.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/smart-accounts-evm.md).

## Security requirements

- recovery payload fields used for EVM recovery must be inside DKIM-covered email content
- recovery sessions must be single-use and short-lived
- `new_evm_key` must be bound exactly at recovery-session creation time
- recovery payload must be domain-separated with EIP-712
- recovery payload must include nonce and deadline
- replay protection must be stored on-chain
- normal owner-management and recovery-management must remain distinct
- V1 recovery must be add-only
- `recoveryAuthority` should execute EVM recovery only after NEAR recovery succeeded
- audit logs must record recovery-session creation, verification, and per-chain execution
- contract verification must stay EVM-friendly; do not require parsing DKIM artifacts, raw email blobs, or TEE transport envelopes on-chain

Implementation note:

- if `new_evm_key` is not deterministic, recovery-session creation must still prove or strongly bind control of that key to the recovering device

## Testing plan

### Unit

- [x] recovery session persists `nearAccountId`, `new_near_key`, and `new_evm_key` together
- [x] verified email result maps back to exactly one pending recovery session
- [x] `verifyAndRecover` payload includes `nearAccountId`, `new_near_key`, and `recoverySession`
- [x] rejecting replayed recovery payloads
- [x] rejecting expired recovery payloads
- [x] rejecting wrong-chain and wrong-wallet recovery payloads
- [x] persisting canonical signer sets across client/server state transitions

### Integration

- [x] registration provisions undeployed smart account plus first signer
- [x] `linkDevice` adds a second EVM owner and new device can sign
- [x] one verified recovery email adds `new_near_key` on NEAR and `new_evm_key` on deployed EVM smart accounts
- [x] undeployed smart account later deploys with the recovered signer set
- [x] recovery is sponsored for deployed EVM accounts

### Adversarial

- [x] tampered recovery email payload outside DKIM-covered content is rejected
- [x] mismatched `new_evm_key` between recovery session and verified email result is rejected
- [x] replay of one recovery session across chains or different smart accounts is rejected
- [x] stale or expired recovery sessions are rejected
- [x] compromised old owner races newly recovered owner
- [x] partial failure where NEAR recovery succeeds but some EVM recovery mutations fail
- [ ] stale signer metadata after owner removal

## Billing and sponsorship

Account recovery supports sponsorship.

This applies to deployed recovery mutations such as:

- `verifyAndRecover`
- `recoverAddOwner`
- later recovery-side owner rotation if introduced

Recommended behavior:

- recovery mutations are executed through the shared sponsorship runtime, not a custom billing path
- user-facing recovery does not depend on the user already having spendable gas on the target EVM chain
- sponsorship is enforced inside the recovery executor / sponsorship runtime, not pushed into the client flow
- if recovery is tenant-billed, sponsorship admission should obey the same policy, spend-cap, prepaid-balance, and atomic-settlement rules as other sponsored execution
- if recovery is platform-funded, that mode should still record sponsored execution history and billing/observability metadata through the shared sponsored-execution path

This decision does not require all normal owner-management operations to be sponsored.

## Out of scope for V1

- post-recovery NEAR intent signatures for EVM recovery
- direct DKIM or TEE proof verification inside EVM smart-account contracts
- per-account recovery-attestor sets
- DKIM verification on EVM chains
- recovery-side owner removal / full rotation

## Recommended V1 scope

Keep V1 narrow:

- smart account per user per chain
- normal `linkDevice` via active owner add
- one global `recoveryAuthority`
- one verified recovery email binds `new_near_key` and `new_evm_key`
- NEAR and EVM recovery run off the same verified recovery session
- automatic sponsored `recoverAddOwner` for deployed EVM accounts through the shared sponsorship runtime
- undeployed accounts mutate off-chain signer set only
- no extra user signature after email recovery
- no direct DKIM, DNS, or TEE proof verification on EVM

This gets NEAR-rooted EVM continuity working with the cleanest current UX and the least on-chain complexity.
