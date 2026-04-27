# Org And Project Extension Notes

## Question

When would a customer want more than one project inside a single org?

## Short answer

Use multiple projects inside one org when it is still the same customer account, the same top-level team, and the same billing owner, but there are multiple app or workload boundaries inside that customer.

Use multiple orgs when team membership, billing, or ownership should be truly separate.

## Why keep the hierarchy

The current product keeps the simpler UX default of `1 org -> 1 project`, which is good for most users.

That does not mean the `project` layer is useless. It gives us room for:

- multiple apps under one customer account
- separate app resources within one company
- per-project settings, keys, wallets, environments, and reporting
- shared org billing and shared org admins without forcing everything into one undifferentiated workspace

The right model is:

- `org` = customer, billing, top-level team, account boundary
- `project` = app or workload boundary inside that customer
- `environment` = deployment stage inside the project

## When 2+ projects in one org make sense

Real cases:

- one company has multiple apps or products
- one company has a customer-facing app and a separate internal admin app
- one team wants separate wallets or policies for different workloads
- one org wants different API keys, webhooks, or runtime settings per app
- one customer wants shared billing and shared admins, but separate app domains

Example patterns:

- checkout app + treasury app
- consumer app + admin console
- marketplace app + rewards or loyalty app
- production product + separate sandbox/demo product under the same customer account

## When it should be a separate org instead

Use a separate org when the separation is actually about customer/account boundaries, not app boundaries.

That includes:

- different team rosters
- different billing accounts
- different owners
- different legal or customer entities
- strict isolation where users should not share the same top-level account context

If the teams, billing, and ownership are truly separate, that should be `2 orgs`, not `2 projects`.

## Why not flatten to org-only

Flattening everything into one top-level object would look simpler at first, but it would force customers with multiple apps to create multiple top-level accounts just to separate workloads.

That would create avoidable friction:

- duplicate team-member management
- duplicate billing accounts when one payer is desired
- duplicate account switching for one company
- no clean place for “one company, many apps”

So the better choice is:

- keep the hierarchical model
- hide the extra layer in the UX by default
- create one default project during onboarding
- only expose multi-project workflows when a customer actually needs them

## Product stance

For now, the UX should continue to bias toward `1 org -> 1 project`.

That gives us:

- simple onboarding
- simple team and billing mental model
- room to grow into multi-project customers later without redesigning the core tenancy model

This is the right tradeoff:

- simple default UX
- richer underlying model
- clear separation between `org` problems and `project` problems
