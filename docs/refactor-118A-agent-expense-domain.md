# Refactor 118A — Expense domain and direct stablecoin rail

Date created: August 29, 2026

Status: scaffolded implementation plan. Domain decisions and the first operating
path remain unimplemented.

Product context:

- [Seams product vision](vision.md)
- [Expense management for agents](product-vision.md)
- [R104 agent spend scaffolding](refactor-104-agent-id-spending.md)

Child plans:

- [R118B — Airwallex card rail](refactor-118B-airwallex-card-rail.md)
- [R118C — Agent expense Console](refactor-118C-agent-expense-console.md)
- [R118D — Agent connections](refactor-118D-agent-connections.md)

## Goal

Introduce the authoritative expense domain and demonstrate one complete,
policy-bound stablecoin purchase from a customer's existing Seams wallet.

```text
authenticated agent actor
  -> active Agent Grant
  -> canonical purchase intent
  -> allow, block, or request approval
  -> atomic budget reservation
  -> exact direct stablecoin execution
  -> durable outcome and audit evidence
```

R118A owns the product state consumed by every later payment and connection
adapter. R118B–D cannot redefine its agent, grant, purchase, budget, approval,
or audit semantics.

## Dependencies and authority

R118A consumes:

- R104 for a clean repository boundary without dormant delegated-agent domain
  types;
- Refactor 90 for exact authorization resources, operation identity, replay,
  effect ordering, and audit;
- R101/R102 for stable wallet-key identity and validated execution-lane
  activation, rotation, and fencing;
- R103F for exact owner administration and fresh verified owner approval;
- existing wallet custody, signing, and stablecoin transaction builders.

R118A owns:

- agent identity and public authorship keys;
- the rail-neutral Agent Connection reference consumed at admission;
- Agent Grants and versioned spending mandates;
- canonical purchase intents and digests;
- policy decisions, exact purchase approvals, and denial evidence;
- expense budgets, reservations, replay, and reconciliation identity;
- the prepared payment-execution boundary;
- the direct stablecoin execution branch;
- revocation and the cross-domain audit chain.

R118A does not own connection transport, Console presentation, or provider card
state.

## Product model

```text
Seams funding account
  -> Agent Connection reference
  -> Agent Grant
  -> Spending Mandate
  -> Purchase Intent
  -> Spend Decision
  -> Budget Reservation
  -> Prepared Payment Execution
  -> Payment Outcome
```

Use the existing wallet identity as the stablecoin funding source when its
meaning is exact. Add no parallel `SeamsAccountId` solely to rename `WalletId`.
If the expense product requires an organization-level account above wallets,
model that separately and keep the funding wallet explicit.

## Domain branches

### Agent identity

An agent identity uses key material independent from wallet ownership,
recovery, and execution material. Each signed request names one exact active
agent key.

Connection adapters in R118D authenticate callers and resolve an exact Agent
Connection reference. They cannot create or widen spending authority.

### Agent Grant

An Agent Grant binds:

- one funding account and exact funding source;
- one agent identity or connection reference;
- one reviewed spending mandate;
- one budget policy;
- one purchase-approval policy;
- one validity interval;
- one revocation epoch; and
- a nonempty set of supported execution rails.

An agent cannot change its grant, create another grant, export owner keys, or
perform recovery, membership, linking, and account-administration operations.

### Spending mandate

The first mandate vocabulary covers:

- aggregate and per-purchase limits;
- merchant and merchant-category rules;
- item, quantity, and substitution constraints;
- currency and geography;
- shipping, tax, fee, and final-price ceilings;
- delivery destination;
- one-time versus recurring payment;
- validity and expiry; and
- human-approval thresholds.

Natural language may propose a mandate. Admission consumes the reviewed typed
record.

### Purchase intent

The canonical purchase intent describes the commercial action independently of
its payment rail:

- merchant;
- items and quantities;
- currency;
- subtotal, shipping, tax, fees, and total;
- delivery terms and destination; and
- recurring-payment status.

Chain transaction bytes, wallet lanes, Airwallex cards, provider transaction
IDs, and MCP tool arguments are execution or transport evidence. They are not
fields in the rail-neutral intent.

### Spend decision

Every policy evaluation returns one exhaustive branch:

```text
allowed
blocked
approval_required
```

An approval request binds the exact Agent Grant, purchase-intent digest, amount,
merchant, execution constraints, approver, issue time, and expiry. Approval is
single-purpose and cannot widen the grant.

### Budget and reconciliation

Budget claims are server-canonical and atomic. The first lifecycle supports:

```text
reserved
committed
released
outcome_unknown
```

Payment-rail events later project authorization, settlement, reversal, refund,
and dispute state without creating a second budget authority. Refund credit
policy must be explicit; observing incoming funds alone does not restore agent
spending authority.

### Prepared execution boundary

Only an allowed or exactly approved purchase can construct prepared execution.
The trusted record carries:

- Agent Grant identity and revocation epoch;
- canonical purchase-intent digest;
- exact approval evidence when required;
- budget reservation;
- stable operation and idempotency identity; and
- selected payment-rail branch.

R118B and the direct-wallet adapter consume this state. They cannot evaluate a
raw prompt or broaden policy.

## Direct stablecoin rail

The first implementation pays one supported stablecoin on one supported chain
from the owner's existing wallet.

The adapter must:

1. bind the canonical purchase to an exact merchant quote or destination;
2. construct and decode the final unsigned transaction independently;
3. prove amount, asset, destination, fees, chain, and transaction bytes match
   the approved spend;
4. resolve exact active wallet execution material after policy admission;
5. sign and submit once under stable replay identity;
6. commit budget only after authoritative success;
7. release on definitive pre-execution failure; and
8. retain ambiguous outcomes for reconciliation.

The agent receives no wallet custody seed, owner signing root, owner recovery
authority, complete signing key, or account-administration capability.

## Required invariants

1. Agent identity, owner authorization, and payment execution are distinct
   proofs.
2. Every spend names one active Agent Grant and exact agent actor.
3. Every grant has a budget, validity interval, approval policy, and revocation
   epoch.
4. Policy validates the canonical purchase and the selected rail's final
   execution data.
5. Concurrent requests cannot exceed aggregate or per-purchase limits.
6. Policy denial and pending approval perform no irreversible payment work.
7. Revocation fails before wallet share, presignature, or execution work.
8. A connection diagnostic or UI projection cannot influence admission.
9. Raw tool, quote, transaction, persistence, and provider shapes are parsed
   once at their boundaries.
10. Every terminal and ambiguous outcome remains linked to the originating
    purchase, reservation, request, approval, and grant.

## Implementation sequence

### Phase 1: Domain and static guarantees

- [ ] Add branded identities and exhaustive lifecycle unions.
- [ ] Add Agent Grant, mandate, purchase intent, decision, approval, budget,
      prepared-execution, outcome, and audit records.
- [ ] Add strict boundary parsers and branch-specific builders.
- [ ] Add type fixtures rejecting invalid owner, agent, connection, grant,
      approval, budget, and payment-rail combinations.

### Phase 2: Stores and policy admission

- [ ] Add server-canonical agent, grant, budget, replay, purchase, approval,
      and audit stores.
- [ ] Implement exact owner grant creation, replacement, suspension, and
      revocation through the existing owner-operation boundary.
- [ ] Implement the first typed mandate evaluator.
- [ ] Atomically claim replay and reserve budget before dispatch.

### Phase 3: Direct stablecoin adapter

- [ ] Bind one purchase intent to one exact stablecoin transaction.
- [ ] Reuse R101/R102 execution machinery only after R118A admission.
- [ ] Submit once and reconcile confirmed, rejected, and unknown outcomes.
- [ ] Preserve the complete owner, agent, policy, budget, wallet, and chain
      evidence chain.

### Phase 4: First operating proof

- [ ] Exercise one real agent actor through a temporary test boundary.
- [ ] Create one grant and one purchase intent.
- [ ] Demonstrate allowed, blocked, and approval-required decisions.
- [ ] Execute one allowed stablecoin purchase.
- [ ] Revoke the grant and prove subsequent admission fails.
- [ ] Read one durable audit projection from instruction through outcome.

## Exit criteria

R118A is complete when one supported agent can execute a bounded stablecoin
purchase from the owner's wallet, concurrent overspending and substitution fail,
approval and revocation are exact, and every outcome is durably auditable.

## Non-goals

- Airwallex cards and provider webhooks
- Console and dashboard presentation
- OAuth, MCP, API credential, or CLI transport
- merchant discovery and agent orchestration
- broad cross-asset fiat valuation
- swaps, bridges, allowances, subscriptions, or arbitrary contract calls
- a separately funded agent wallet
