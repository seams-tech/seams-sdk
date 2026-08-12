---
title: Results and recoverable errors
description: Handle Seams registration, login, signing, recovery, and device outcomes as exhaustive discriminated unions.
---

# Results and recoverable errors

Public operations return state, not a generic success flag. Switch on the
outer discriminator, then on the branch-specific discriminator such as `kind`,
`status`, or `code`.

## Registration

`RegistrationResult` separates failure from successful wallet creation. A
successful result then identifies its capability branch or pending provisioning
state. `walletId` is the stable wallet identity; chain-specific account data
belongs to the relevant capability or provisioning branch.

Do not read retired flat fields or assume that a successful registration means
every requested signer is ready. When NEAR provisioning is pending, observe the
provisioning state and continue only from its ready branch.

## Login and sessions

`LoginResult` and `LoginAndCreateSessionResult` distinguish cancelled,
recoverable, and ready outcomes. A ready wallet session carries capability
readiness and use limits. Pass its exact reference into signing.

## Signing and actions

`ActionResult`, `SignNEP413MessageResult`, and EVM-family results preserve user
cancellation, policy denial, transport failure, broadcast acceptance, and
finalization as separate outcomes where the operation exposes them. Show the
user the recovery action associated with the current branch.

## Error handling rule

1. Exhaust the union.
2. Log the stable code and operation identity, excluding secrets.
3. Retry only branches documented as retryable.
4. Request fresh user presence when the session or policy branch requires it.
5. Reconcile chain status before replaying an operation whose broadcast state
   is uncertain.

Use [events and progress](/reference/events-and-progress) for user-facing
progress and [troubleshooting](/deploy-and-operate/troubleshooting) for common
recovery paths.
