# Multchain Account Recovery Plan

Last updated: 2026-02-18

## Goal

Extend the existing NEAR email-recovery flow into a multichain recovery control plane where NEAR authority can rotate owners/keys on EVM and Tempo smart accounts.

## Product Model

- Keep auth and wallet as separate concepts:
  - Auth: SSO, email/password, passkey (app/session access)
  - Wallet: passkey-only authorization for signing
- Keep threshold signing key derivation passkey-based.
- Use recovery only for account regain + key rotation, never as a normal transaction signing path.

## Current State

- Implemented for NEAR:
  1. User submits recovery email + new recovery public key.
  2. Server verifies DKIM (sender + date/freshness).
  3. Recovery flow adds/rotates NEAR access key.
- Not yet implemented for EVM/Tempo smart accounts.

## Target Architecture

### Control Plane

- NEAR recovery authority is the source of truth for user recovery intent.
- EVM/Tempo smart accounts trust a dedicated `ed25519Verifier` module path for recovery-only actions.

### Execution Plane

- `ed25519Verifier` verifies a signed recovery intent using the configured NEAR recovery public key.
- If valid, it calls smart-account recovery entrypoints (`recover`, `setOwner`, `rotateKey`, etc.).

### Account Model

- Works for smart/contract accounts on EVM/Tempo.
- Does not apply to plain EOAs.

## Onchain State Requirements

Use one of these patterns:

1. Smart account stores recovery authority directly:
- `recoveryPublicKey` (or hash)
- replay state (`nonce` and/or consumed `requestId`)
- trusted verifier address

2. Preferred for reuse:
- smart account stores `recoveryAuthorityId` + trusted verifier
- verifier stores `recoveryAuthorityId -> recoveryPublicKey` mapping

Pattern 2 simplifies multichain authority management and coordinated key rotation.

## Canonical Recovery Intent

All recovery signatures must cover the full intent payload:

```json
{
  "version": "recovery_intent_v1",
  "action": "set_owner",
  "targetChainId": "11155111",
  "targetSmartAccount": "0xabc...",
  "newOwner": "0xdef...",
  "recoveryAuthorityId": "near:alice.testnet",
  "nonce": "42",
  "requestId": "uuid-or-random-128b",
  "deadlineMs": 1760000000000
}
```

Required invariants:

- Domain separation: chain + target account + action must be signed.
- Replay protection: `nonce` monotonic and/or `requestId` one-time-use.
- Expiry: reject when `now > deadlineMs`.
- Deterministic encoding: canonical JSON or fixed binary struct before hashing/signing.

## End-to-End Recovery Flow

1. User initiates email recovery and passes DKIM checks (existing flow).
2. Recovery flow restores/rotates NEAR recovery key material.
3. User (or wallet-origin flow) signs a multichain `RecoveryIntent` with NEAR recovery key.
4. Relayer submits `(intent, signature)` to `ed25519Verifier` on target chain.
5. `ed25519Verifier` validates:
- signature matches configured recovery key/authority
- domain fields match call target
- nonce/requestId not replayed
- deadline still valid
6. Verifier calls target smart account recovery method.
7. Backend invalidates old sessions/keyrefs and rotates local signer metadata.

## Smart Account Contract Requirements

- Recovery methods are callable only by trusted verifier/guardian path.
- Recovery path emits explicit events (`RecoveryExecuted`, `OwnerRotated`, etc.).
- Optional timelock/cancel path for high-value accounts.
- Explicit function separation:
  - `setOwner` / `rotateOwner`
  - `rotateRecoveryAuthority` (separate governance path)

## Security Requirements

- Passkey remains required for normal transaction signing.
- Recovery path cannot authorize arbitrary transaction execution.
- No wildcard verifier calls: enforce action allowlist and target checks.
- Include chainId and target account in signed payload to prevent cross-chain replay.
- Enforce short recovery deadlines.
- Alerting:
  - notify user on recovery request/start/success
  - provide revoke/freeze path if recovery is disputed

## Integration Points

### Existing Components

- Reuse DKIM verification service for recovery eligibility.
- Reuse NEAR recovery state machine for restoring NEAR authority.

### New Components

- `RecoveryIntent` builder + canonical serializer in wallet origin.
- Relayer endpoint to submit signed intent to verifier contract.
- EVM/Tempo verifier bindings and smart-account recovery adapters.
- Session/keyref invalidation hooks after successful owner rotation.

## Rollout Plan

### Phase 0: Spec Lock

- Finalize `RecoveryIntent` schema and canonical encoding.
- Finalize onchain replay model (`nonce`, `requestId`, or both).
- Finalize trusted verifier wiring model (direct key vs authority id).

### Phase 1: EVM Recovery MVP

- Implement `ed25519Verifier` interface for `setOwner`.
- Add relayer route to submit signed recovery intent.
- Add smart-account recovery call guardrails and eventing.

### Phase 2: Tempo Recovery MVP

- Reuse same intent schema.
- Implement Tempo-specific smart-account adapter.
- Ensure identical replay/expiry semantics.

### Phase 3: Operations Hardening

- Add user notifications and recovery audit log.
- Add kill-switch/freeze for compromised authority scenarios.
- Add rotation flow for recovery authority public key.

## Testing Plan

### Contract Tests

- Valid signature + valid nonce/deadline rotates owner.
- Wrong chain/target/action rejects.
- Replayed nonce/requestId rejects.
- Expired deadline rejects.
- Non-verifier caller cannot rotate owner.

### Integration Tests

- NEAR recovery -> signed intent -> EVM owner rotation.
- NEAR recovery -> signed intent -> Tempo owner rotation.
- Old wallet sessions invalidated post-rotation.

### Negative Tests

- Signature from non-authorized key rejects.
- Cross-chain replay of same payload rejects.
- Target-account mismatch between payload and call rejects.

## Open Decisions

- Should replay protection use nonce only, requestId only, or both?
- Do we require a timelock for owner rotation in MVP?
- Should recovery authority rotation require current authority signature, app governance action, or both?

