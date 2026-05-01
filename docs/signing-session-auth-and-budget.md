# Signing Session Auth And Budget

Status: active spec for auth planes, wallet signing-session budget, and
transaction signing-session semantics.

## Authority

This document defines stable concepts used by
[signing-session-refactor-2.md](signing-session-refactor-2.md). It replaces the
deleted warm-session and Email OTP session migration notes. Do not reintroduce
their old fallback proposals without revalidating them against the deterministic
transaction state machine.

## Auth Planes

### App Session

An app session proves the user is logged in and may request user-level
operations, such as Email OTP challenge issuance.

An app session is not signing authority. It must not authorize threshold signing,
threshold key export, or threshold continuation routes by itself.

### Threshold Session

A threshold session proves active signing capability for one curve-specific
threshold session.

Use threshold-session auth for:

1. Ed25519 threshold signing and HSS continuation routes.
2. ECDSA threshold signing, presign, and HSS continuation routes.
3. Threshold export routes after the operation has obtained the required fresh
   user authorization.

Do not reuse threshold-session auth as generic app/session authority.

### Wallet Signing Session

`walletSigningSessionId` is the wallet-level signing-session budget id. It ties
curve-specific threshold sessions to one server-authoritative TTL and
`remainingUses` counter.

`thresholdSessionId` identifies the concrete curve-specific threshold session.

Both are required for transaction signing. The wallet id alone is not enough, and
the threshold session id alone is not enough.

## Budget Terms

1. `remainingUses`: trusted server remaining budget for the wallet signing
   session.
2. `operationUsesNeeded`: cost of the current signing operation, normally `1`.
3. `sessionBudgetUses`: capacity minted by step-up or reusable-session creation.
4. `projectionVersion`: opaque causal token for the trusted server budget status.
5. `availableUses`: local admission hint after same-projection in-flight holds.
6. `inFlightReservedUses`: local holds against the same projection.

`remainingUses` is never a local projection. UI and status surfaces should not
subtract local holds from it.

## Operation Cost

One user-approved transaction signing request is one wallet signing-session use
unless product policy explicitly changes that definition.

Examples:

1. One NEAR batched signing request is one use, even if it contains multiple
   transactions or actions.
2. One EVM/Tempo/ARC transaction signing request is one use.
3. Key export is not transaction signing and must use its own exact operation-auth
   policy. It must not use broad maintenance restore.

Transaction and action counts are display and risk-policy inputs, not budget
cost by default.

## Step-Up Policy

After budget exhaustion:

1. Email OTP accounts show Email OTP.
2. Passkey accounts show passkey/TouchID.
3. Mixed/linked accounts follow explicit account policy before lane selection.
4. After one concrete lane is selected, the auth method cannot change.

Transaction step-up mints a single-operation session by default:

```ts
sessionBudgetUses = operationUsesNeeded;
```

Reusable signing sessions require an explicit reusable-session command.

## Refresh Policy

Refresh is not exhaustion.

If worker memory is missing but server budget is valid, transaction signing should
restore the exact selected lane from durable sealed state and continue without
prompting.

If server budget is exhausted, transaction signing should perform same-method
step-up.

## Mixed Auth Accounts

Linked OTP/passkey accounts are allowed, but transaction signing must be
deterministic:

1. Hard account policy may exclude lanes before selection.
2. Account preference and primary-auth metadata cannot hide or override a
   concrete current runtime lane.
3. Runtime records anchor selection when their exact concrete identity is present.
4. Durable records are candidates, not authority.
5. A selected OTP lane can never become passkey reauth.
6. A selected passkey lane can never become OTP reauth.
7. Missing hot material for the selected lane is a readiness state, not permission
   to choose another auth method.

## Budget Timing

1. Warm-session budget identity is captured before signing.
2. Reauth-created budget identity is captured immediately after mint/reconnect and
   before signing.
3. Ed25519 signing may consume authoritative server budget during the signing
   ceremony, so finalization must reconcile an already-consumed selected lane.
4. Finalization must not prepare budget identity after signing.

## Related Specs

1. Product intent:
   [signing-session-refresh-intent.md](signing-session-refresh-intent.md).
2. Deterministic state-machine plan:
   [signing-session-refactor-2.md](signing-session-refactor-2.md).
3. Email OTP secret and restore model:
   [email-otp-secret-restore.md](email-otp-secret-restore.md).
4. Linked account policy:
   [addkey-otp-passkey-accounts.md](addkey-otp-passkey-accounts.md).
