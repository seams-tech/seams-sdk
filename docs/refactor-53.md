# Signer-Bound Step-Up Budget Plan

Date updated: June 1, 2026

Status: Complete

## Goal

Fix the step-up budget stealing issue where one signer can consume a wallet
signing budget minted for another signer.

The target invariant is:

- a step-up budget minted for one threshold signer stays bound to that signer
- NEAR Ed25519, Tempo ECDSA, and EVM ECDSA cannot satisfy or spend each
  other's step-up budget
- wallet-level UX can still reuse a single `walletSigningSessionId` as the
  shared wallet session identifier
- server authorization remains the source of truth for budget ownership and
  consumption

## Failure Mode

Observed sequence:

1. User step-up authenticates a NEAR transaction.
2. Before the NEAR transaction completes, user sends a Tempo transaction.
3. Tempo observes the existing wallet signing budget and signs without its own
   step-up prompt.
4. NEAR then fails with a budget exhausted error.

This means the wallet budget was keyed too broadly. The shared
`walletSigningSessionId` identified the wallet session, while the actual
spendable authority lacked a binding to the threshold signer that created it.

## Root Cause

The budget record was effectively scoped by `walletSigningSessionId` alone.
That allowed three unsafe behaviors:

- budget status lookup could project a wallet budget onto the caller's
  requested curve
- budget status validation did not require the budget's threshold session id to
  match the caller's threshold session id
- budget consumption could spend the wallet budget without checking that it was
  minted for the same signer session

The fix is to make the spendable budget identity the tuple:

```ts
type WalletSigningBudgetIdentity = {
  walletSigningSessionId: string;
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionId: string;
};
```

`walletSigningSessionId` remains the durable wallet-session handle. The
`curve + thresholdSessionId` binding decides which signer may observe and spend
the budget.

## Target Model

Persist every wallet signing budget with a required binding:

```ts
type WalletSigningBudgetBinding = {
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionId: string;
};

type WalletSigningBudgetRecord = {
  walletSigningSessionId: string;
  walletBudgetBinding: WalletSigningBudgetBinding;
  userId: string;
  rpId: string;
  participantIds: number[];
  expiresAtMs: number;
};
```

Boundary parsers should normalize old or malformed records into an unavailable
budget. Core authorization and signing paths should only handle records with a
valid binding.

## Completion Summary

Implemented:

- spendable budget records are stored under the signer-bound tuple
  `walletSigningSessionId + curve + thresholdSessionId`
- wallet budget records carry a signer binding containing `curve` and
  `thresholdSessionId`
- wallet budget mint paths provide the signer binding explicitly
- wallet budget status only reports budgets for the bound signer
- wallet budget consume rejects missing or mismatched bindings before spending a
  use
- stale unbound records are treated as unavailable budget

Validated with:

- `pnpm -C tests exec playwright test ./unit/signingSessionSeal.sessionPolicy.unit.test.ts ./unit/signingBudgetStatus.parser.unit.test.ts --reporter=line`
- `pnpm -C tests exec playwright test -c playwright.relayer.config.ts ./relayer/express-router.test.ts ./relayer/cloudflare-router.test.ts -g "signing-budget/status" --reporter=line`
- `pnpm -C examples/seams-site typecheck`
- `pnpm -C sdk build:prepare`
- `git diff --check`

## Completed Phase 0: Inventory

Map every path that creates, checks, or consumes wallet signing budget.

Required inventory:

- Ed25519 passkey step-up mint
- Ed25519 session connect and refresh paths
- ECDSA passkey step-up mint
- ECDSA registration-bootstrap reauth
- ECDSA threshold-session-authorized bootstrap
- `/signing-budget/status` parser and policy lookup
- Ed25519 authorize/signing consume path
- ECDSA authorize/signing consume path
- key export paths if they inspect wallet budget readiness

Deliverable:

- one list of budget mint call sites
- one list of budget consume call sites
- one list of budget status call sites
- note which signer identity each call site already knows

## Completed Phase 1: Persistence Boundary

Add a wallet budget binding to the auth session record stored for wallet
signing budgets.

Work:

- add `WalletSigningBudgetBinding`
- store `walletBudgetBinding` on wallet budget records
- parse `walletBudgetBinding` at the session-store boundary
- treat records without a valid binding as unavailable wallet budgets
- keep any compatibility behavior isolated to parsing and status normalization

Acceptance:

- core code never needs to infer `curve` or `thresholdSessionId` from a bare
  `walletSigningSessionId`
- malformed or missing binding does not become a spendable budget

## Completed Phase 2: Mint Path Binding

Require every wallet budget mint path to pass the signer binding explicitly.

Work:

- change wallet budget mint helper input to require:

```ts
{
  walletSigningSessionId: string;
  binding: {
    curve: 'ed25519' | 'ecdsa';
    thresholdSessionId: string;
  };
}
```

- Ed25519 mint paths pass `{ curve: 'ed25519', thresholdSessionId: sessionId }`
- ECDSA mint paths pass `{ curve: 'ecdsa', thresholdSessionId: sessionId }`
- reject attempts to reuse an existing `walletSigningSessionId` for a different
  binding unless a fresh-auth refresh path is deliberately replacing the record
- make refresh paths write the new binding atomically with the refreshed budget

Acceptance:

- minting a NEAR budget cannot leave an ECDSA-spendable budget record
- minting an ECDSA budget cannot leave an Ed25519-spendable budget record
- conflicting reuse returns an authorization failure instead of mutating the
  existing record

## Completed Phase 3: Consume Enforcement

Make server-side budget consumption enforce the binding before decrementing use
count.

Work:

- when a request includes `walletSigningSessionId`, load the wallet budget
  record before consume
- require `walletBudgetBinding.thresholdSessionId === curveSessionId`
- require the expected curve to match the route's curve
- consume with the existing idempotency key only after binding checks pass
- return an authorization failure for missing or mismatched bindings

Acceptance:

- a Tempo/EVM request cannot spend a NEAR budget
- a NEAR request cannot spend a Tempo/EVM budget
- concurrent requests race only on the budget they are authorized to use

## Completed Phase 4: Status Enforcement

Make readiness and status checks report wallet budget only for the bound signer.

Work:

- status policy reads `walletBudgetBinding` from the stored record
- status lookup returns `null` when the stored binding curve differs from the
  requested curve
- status lookup returns the stored `thresholdSessionId`, never a caller-stamped
  session id
- `/signing-budget/status` validates:
  - status curve equals auth curve
  - status wallet signing session id equals auth wallet signing session id
  - status threshold session id equals auth threshold session id
  - user, RP ID, relayer key, and participant ids match

Acceptance:

- Tempo/EVM readiness does not become ready from a NEAR budget
- NEAR readiness does not become ready from a Tempo/EVM budget
- clients see a reauth-required state for mismatched or missing bindings

## Completed Phase 5: Client Reauth Behavior

Keep client behavior simple: if the server cannot prove a bound wallet budget
for the requested signer, the signer needs step-up auth.

Work:

- map bound-budget `not_found`, `unavailable`, and mismatch-style authorization
  failures to signer-local reauth
- avoid using diagnostics from one signer to mark another signer ready
- keep NEAR, Tempo, and EVM readiness lanes independently represented

Acceptance:

- after NEAR step-up, a Tempo/EVM transaction still prompts for Tempo/EVM
  step-up unless it already has its own bound budget
- after Tempo/EVM step-up, a NEAR transaction still prompts for NEAR step-up
  unless it already has its own bound budget
- a failed consume in one lane does not clear or spend another lane's budget

## Completed Phase 6: Tests

Add targeted tests around the security boundary.

Unit tests:

- wallet budget status ignores a record with missing binding
- wallet budget status ignores a record bound to another curve
- wallet budget status ignores a record bound to another threshold session
- wallet budget status accepts a record bound to the authenticated threshold
  session
- consume rejects missing binding
- consume rejects mismatched threshold session id
- consume rejects mismatched curve
- consume spends exactly once for the matching binding and idempotency key

Relayer tests:

- Ed25519 step-up budget cannot satisfy ECDSA signing-budget status
- ECDSA step-up budget cannot satisfy Ed25519 signing-budget status
- ECDSA Tempo and EVM requests cannot consume an Ed25519 budget
- Ed25519 requests cannot consume an ECDSA budget

Client tests:

- NEAR step-up leaves Tempo/EVM readiness requiring reauth
- Tempo/EVM step-up leaves NEAR readiness requiring reauth
- later retries after a mismatch prompt once and then sign with the newly bound
  budget

Manual regression:

1. Step-up auth a NEAR transaction.
2. Immediately send a Tempo transaction.
3. Confirm Tempo requests its own step-up auth.
4. Confirm NEAR completes or fails for its own reason without `budget exhausted`
   caused by Tempo.
5. Repeat with EVM after Tempo and with NEAR after EVM.

## Data Reset

Existing wallet budget records without `walletBudgetBinding` should be treated
as invalid and allowed to expire. During local development, clear active
threshold auth session storage after deploying this change to avoid confusing
manual tests with stale unbound budget records.

No long-lived compatibility path is needed. This project is still in
development, and unbound wallet budgets are unsafe current-state data.

## Acceptance Criteria

This work is complete:

- every wallet budget record has a signer binding at creation time
- status lookup cannot synthesize signer identity from the request
- consume cannot decrement a budget unless the signer binding matches
- NEAR, Tempo, and EVM step-up budgets are isolated from each other
- targeted unit and relayer tests cover cross-signer status and consume denial
- manual NEAR-to-Tempo and Tempo-to-NEAR step-up sequences no longer reproduce
  budget stealing
