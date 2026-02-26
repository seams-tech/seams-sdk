# Delegation Grant Plan

Date updated: February 26, 2026

## Objective

Add a first-class delegated server-execution feature where a user can approve bounded wallet operations once, then let a developer backend execute those operations under strict policy constraints.

Core outcomes:

1. Delegation is explicit user consent, separate from app auth.
2. Delegation is bounded by TTL, remaining uses, and intent policy.
3. Server execution is scoped per wallet via dedicated API credentials.
4. No legacy login semantics or duplicate authorization codepaths.

## Product Contract (Locked)

1. Delegation is modeled as a `DelegationGrant` object, not as app login.
2. Grant issuance requires step-up user presence (`passkey`/wallet unlock path).
3. Grants are least-privilege by default:

- explicit intent allowlist
- explicit constraints (amount, recipient, contract/method, chain)
- explicit expiry and usage limits

4. Existing warm session and threshold signing contracts remain canonical; delegation composes on top.
5. Breaking changes are allowed; legacy aliases and duplicate pathways are removed during rollout.

## Why This Fits Current Architecture

Current session model already has the right primitives:

1. Separate `app_session_v1` and `threshold_*_session_v1` domains.
2. Explicit threshold session policy (`ttlMs`, `remainingUses`).
3. Canonical warm-session readiness checks via shared planner logic.
4. Wallet lock/unlock semantics already separated from app auth direction.

Delegation grants should reuse these primitives instead of adding parallel auth/session logic.

## Non-Goals

1. Unbounded server signing authority.
2. Chain-specific only design (for example NEAR-only contracts in core model).
3. Transaction-time implicit session minting.
4. Legacy compatibility layer for old login/delegate naming.

## Terminology

1. `DelegationGrant`: user-approved capability object for delegated operations.
2. `Wallet API Key`: scoped credential bound to `walletId + grantId + tenantId`.
3. `Delegation Material`: encrypted grant payload or key envelope that backend can present to delegation endpoints.
4. `Intent`: typed action request (`transfer`, `swap`, `stake`, `delegate_action`, and others).

## DelegationGrant Model (Proposed)

```json
{
  "id": "dg_123",
  "walletId": "wallet_123",
  "tenantId": "org_123",
  "delegateId": "svc_payments_v1",
  "status": "active",
  "allowedIntents": ["transfer", "delegate_action"],
  "constraints": {
    "chainAllowlist": ["near-mainnet"],
    "receiverAllowlist": ["merchant.near"],
    "methodAllowlist": ["ft_transfer_call"],
    "maxAmountPerUse": "50.00",
    "maxAmountTotal": "500.00",
    "rateLimit": {
      "windowSeconds": 3600,
      "maxUses": 20
    }
  },
  "expiresAt": "2026-02-27T00:00:00.000Z",
  "remainingUses": 50,
  "stepUpRules": {
    "requireFreshUserPresenceOverAmount": "100.00",
    "requireFreshUserPresenceForNewReceiver": true
  },
  "createdAt": "2026-02-26T20:00:00.000Z"
}
```

## API Plan (Breaking, No Legacy)

### Grant Issuance

1. `POST /delegation-grants/options`

- Returns challenge + policy template for user confirmation UX.

2. `POST /delegation-grants/create`

- Requires authenticated app session and wallet unlock step-up.
- Creates `DelegationGrant`.
- Mints scoped `walletApiKey`.
- Returns encrypted `delegationMaterial`.

### Grant Management

1. `GET /delegation-grants/:grantId`
2. `GET /wallets/:walletId/delegation-grants`
3. `POST /delegation-grants/:grantId/revoke`
4. `POST /delegation-grants/:grantId/rotate-key`

### Delegated Execution

1. `POST /delegation-grants/:grantId/execute`

- Auth: `walletApiKey` + signed request nonce.
- Input: typed `intent`.
- Server validates grant constraints before any signing path.
- On success, decrements remaining uses and writes audit events.

2. `POST /delegation-grants/:grantId/simulate`

- Same policy checks as `execute`, no signing side effect.

## Wallet API Key and Delegation Material

### Wallet API Key

1. Bound to one `walletId`, one `grantId`, one tenant/project scope.
2. Can only call delegation endpoints.
3. Has independent expiry, revocation, and rotation.
4. Supports short-lifetime access token + optional refresh token flow for backend agents.

### Delegation Material

1. Returned as encrypted envelope (JWE-like shape or KMS envelope format).
2. Encrypted to customer backend public key or server-side KMS recipient.
3. Includes `grantId`, `walletId`, policy hash, and key version binding.
4. Never returned in plaintext after creation endpoint response.

## Intent Model (Chain-Agnostic Core)

Define canonical intent families:

1. `transfer`
2. `contract_call`
3. `swap`
4. `stake`
5. `delegate_action` (for NEAR-specific delegated bundles)

Each intent must carry:

1. `chainId`
2. normalized amount/value fields
3. target receiver/contract
4. optional calldata/method
5. idempotency key and expiry

Policy engine validates intent against grant constraints before threshold signing orchestration.

## NEAR Delegate Action Integration

Use NEAR delegate actions as an adapter, not as the core abstraction:

1. Map `delegate_action` intents to NEAR delegate action payload generation and validation.
2. Keep core grant model chain-neutral so EVM/Tempo can reuse the same flow.
3. Preserve one policy evaluator and one audit model across chains.
4. Add NEAR-specific constraint fields only in adapter extensions.

## Session and Signing Architecture Compatibility

1. Grant creation requires active app session (`app_session_v1`) plus wallet unlock confirmation path.
2. Delegated execute path reuses threshold session policy enforcement:

- grant TTL and remaining uses
- threshold session readiness checks
- fail-closed behavior on expired/exhausted states

3. No transaction-time implicit session creation.
4. Existing shared session planner remains the single readiness gate.

## Security Controls

1. Strict least-privilege defaults on `allowedIntents` and constraints.
2. Nonce + timestamp + idempotency enforcement on execute requests.
3. HMAC/request-signature verification for backend-to-wallet-server calls.
4. Replay prevention and sequence tracking per `grantId`.
5. Risk hooks:

- force lock wallet
- force revoke grant
- require step-up on anomaly

6. Complete audit trail for grant create/use/revoke/fail decisions.

## Webhooks and Observability

Emit signed lifecycle events:

1. `delegation.grant.created`
2. `delegation.grant.used`
3. `delegation.grant.exhausted`
4. `delegation.grant.expired`
5. `delegation.grant.revoked`
6. `delegation.execution.denied`

Delivery requirements:

1. HMAC signature + timestamp.
2. Idempotent event IDs.
3. Retry/backoff and dead-letter visibility.
4. Tenant/project scoping in payload.

## Rollout Plan

### Phase 0: Spec Lock

1. Freeze `DelegationGrant` schema.
2. Freeze intent taxonomy and constraint model.
3. Freeze wallet API key scope rules and lifecycle.

### Phase 1: Data and Policy Engine

1. Add storage models for grants, grant usage counters, and key material references.
2. Implement grant policy evaluation module with deterministic decision logs.
3. Add migration and indexing for `walletId`, `grantId`, `expiresAt`, `status`.

### Phase 2: Grant Issuance APIs

1. Implement `/delegation-grants/options` and `/delegation-grants/create`.
2. Wire passkey/user-presence step-up into creation flow.
3. Mint scoped wallet API keys and encrypted delegation material.

### Phase 3: Execute and Simulate APIs

1. Implement `/execute` and `/simulate`.
2. Integrate with shared session planner and threshold signing orchestrators.
3. Enforce atomic `remainingUses` decrement and fail-closed semantics.

### Phase 4: NEAR Adapter

1. Add `delegate_action` intent adapter to NEAR delegate action API.
2. Add chain-specific validation and normalization tests.
3. Keep core chain-agnostic policy surface unchanged.

### Phase 5: SDK and Docs

1. Add SDK methods:

- `createDelegationGrant`
- `listDelegationGrants`
- `revokeDelegationGrant`
- `executeDelegatedIntent`

2. Add backend quickstarts for recurring payments, subscription billing, and bot automation.
3. Remove deprecated or duplicate session/delegate naming in docs and SDK.

## Testing Plan

### Unit

1. Policy evaluator: allow/deny matrix for every intent and constraint type.
2. Key scope checks (`walletId`, `grantId`, tenant isolation).
3. Nonce/replay/idempotency protections.

### Integration

1. Grant create with user presence -> delegated execute happy path.
2. Expiry, exhaustion, and revoke behavior on execute.
3. Step-up requirement for threshold/risk boundaries.
4. Webhook delivery/signature/retry behavior.

### Regression

1. Existing non-delegated threshold sign flows remain unchanged.
2. Existing warm session lifecycle endpoints remain unchanged.
3. No hidden fallback to removed legacy route names or symbols.

## Primary Use Cases Unlocked

1. Recurring payments/subscriptions with hard spend caps.
2. DCA/rebalancing bots without prompting every trade.
3. Marketplace actions (list/cancel/update) from backend jobs.
4. Webhook-driven ops (release escrow, claim rewards, settle invoices).
5. Gas sponsorship/relayer flows with strict method + value limits.
6. Session-based gaming/social actions (many low-risk txs quickly).
7. Team/agent automations (CI, cron, AI agents) under bounded permissions.
8. Enterprise policies (allowlist-only counterparties, daily notional limits).

## Acceptance Criteria

1. Developers can create bounded delegation grants with explicit user approval.
2. Backend can execute only policy-allowed intents via scoped wallet API key.
3. Grant TTL and remaining-uses limits are enforced consistently and atomically.
4. Delegated execution integrates with current threshold signing session architecture without introducing duplicate auth/session paths.
5. NEAR delegate actions are supported via adapter while core grant model remains chain-agnostic.
6. No legacy login/delegate aliasing remains after rollout.
