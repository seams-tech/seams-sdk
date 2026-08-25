# Defect: one shared row holds every wallet's recovery capability

Date recorded: August 25, 2026. Found while running the Refactor 109C signer
profile matrix; not caused by it and not fixed by it.

## What happens

Every wallet stops provisioning NEAR at once, with:

    D1_ERROR: string or blob too big: SQLITE_TOOBIG

It is not gradual and not confined to new wallets. Contracts that passed minutes
earlier fail identically, because the failure is in a record they all share.

## Why

`router_ab_yao_versioned_json_records` holds a single row keyed
`router-ab-yao:router-ab-ed25519-yao:shared`. Its
`state.state.recovery.capabilities.entries` is a list of `[walletKey, value]`
pairs - one entry per wallet that has provisioned recovery, at roughly 19KB
each. On the local gateway database it reached 122 entries and 2.18MB, which is
past what D1 accepts for one value.

Nothing prunes it, and every wallet appends to it, so the row only grows. The
limit is a property of the shared record rather than of any wallet's own state:
one row reaching the ceiling takes NEAR provisioning down for every wallet in
the environment.

## Why this is not local test debris

The local stack reaches 122 wallets quickly because tests register freely, but
nothing about the growth is test-specific. A production environment accumulates
the same entries more slowly and hits the same ceiling, and it fails for
everyone simultaneously rather than degrading. Recovering needs an operator to
edit a shared record.

## What was done, and what was not

Clearing that record's `entries` restored provisioning immediately and without a
restart, which was the right move to unblock a test run. It is not the fix: it
discards recovery capability for every wallet already in the environment, and
the row starts growing again from the next registration.

The fix belongs where the record is written - partitioning per wallet, or
bounding and pruning what the shared record retains. Both are outside Refactor
109C.
