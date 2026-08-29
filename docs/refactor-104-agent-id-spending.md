# Refactor 104 — Agent spend scaffolding

Date created: July 22, 2026

Last revised: August 29, 2026

Status: implemented August 29, 2026. This revision replaces the earlier R104
agent-runtime, delegated-lane, and direct-spending implementation plan.

Successor plans:

- [R118A — Expense domain and direct stablecoin rail](refactor-118A-agent-expense-domain.md)
- [R118B — Airwallex card rail](refactor-118B-airwallex-card-rail.md)
- [R118C — Agent expense Console](refactor-118C-agent-expense-console.md)
- [R118D — Agent connections](refactor-118D-agent-connections.md)

## Goal

Prepare the repository for the agent-expense product without introducing a
second temporary domain model.

R104 removes dormant lane-owned agent policy, intent, custody, and principal
scaffolds; retains the exact R101/R102 execution contracts that R118A can
consume; and establishes clean module and type boundaries for the successor
plans.

R104 delivers no user-facing agent spending. R118A owns the first complete
operating path.

```text
R104
  -> delete obsolete delegated-agent scaffolds
  -> retain reusable wallet execution primitives
  -> establish exact neutral identities and boundaries
  -> leave one clean starting point

R118A
  -> introduce the authoritative expense domain
  -> prove direct stablecoin spending
```

## Authority and handoff

R104 owns repository preparation only. It does not own final Agent Grant,
purchase, budget, approval, payment, or connection records.

R118A becomes authoritative for:

- agent identity and agent authorship
- Agent Grants and spending mandates
- typed purchase intents
- policy decisions and purchase approvals
- expense budget reservations and replay
- direct stablecoin execution
- revocation, reconciliation, and audit

R101 and R102 remain authoritative for wallet-key identity, execution lanes,
share epochs, activation, rotation, and fencing. References in those plans to
R104 delegated admission describe the successor seam now owned by R118A.

## Current scaffold classification

Classify each existing delegated-agent surface before changing it:

| Surface | R104 action | Final owner |
| --- | --- | --- |
| `DelegatedExecutionSigningLaneRecord` and exact parser | Retain unchanged; its IDs are execution bindings, not authority evidence | R101/R102 execution machinery |
| Lane participant, epoch, activation, rotation, and fencing records | Retain | R101/R102 |
| `PreparedDelegatedWalletExecution` and reserved-claim interface | Retain as the R101 prepared-execution contract | R118A supplies the admitted expense claim |
| Lane-owned mandate or policy records | Delete | R118A |
| Lane-owned budget stores or replay records | Delete when present | R118A |
| Unsigned or lane-derived agent spending requests | Delete | R118A |
| Broad optional agent-custody bags | Delete | R118D connection-specific branches |
| Agent identity aliases whose names describe share holders | Replace only when the exact identity meaning is proven | R118A |
| Asset, amount, address, and counterparty value objects | Retain only when already exact and product-neutral | Shared value modules or R118A |
| Dormant public SDK and wallet re-exports | Delete | R118A–D add supported surfaces later |
| Source guards and fixtures for retired shapes | Delete | Successor behavioral and type tests |

## Required invariants

1. A wallet execution lane cannot establish agent identity, spending authority,
   budget, replay rights, or purchase approval.
2. No retained scaffold treats an execution share holder as the canonical
   agent principal.
3. No retained type combines owner, linked-device, and agent lifecycle branches
   through optional fields.
4. Wallet roots, wallet custody seed material, recovery sets, and owner signing
   authority remain outside agent-spend scaffolding.
5. Retained lane records continue to require exact wallet key, participants,
   share epoch, activation, and revocation state.
6. R104 adds no placeholder Airwallex, MCP, OAuth, Console, or CLI branch.
7. R104 adds no generic `PaymentProvider`, `AgentRuntime`, `Policy`, or
   `Connection` string union in anticipation of successor work.
8. Raw legacy records, compatibility aliases, and obsolete re-exports do not
   enter the R118A implementation boundary.
9. Existing persisted or request compatibility logic remains isolated at its
   current boundary and is deleted when no supported record requires it.
10. Static fixtures reject attempts to construct authority or budget state from
    retained lane records.

## Implementation sequence

### Phase 1: Inventory the dormant surfaces

- [x] Locate every delegated-agent policy, intent, budget, request, audit,
      custody, identifier, parser, re-export, fixture, and source guard.
- [x] Classify each hit as reusable execution machinery, exact neutral value
      object, obsolete scaffold, or active supported behavior.
- [x] Confirm whether any persisted or public request shape is deployed before
      deleting it. Keep required compatibility at that boundary only.
- [x] Record the narrow modules that R118A must consume from R101/R102 and
      Refactor 90.

### Phase 2: Delete obsolete domain ownership

- [x] Delete lane-owned mandate, policy, request, and audit types. Retain the
      R101 prepared-execution reserved-claim interface.
- [x] Delete broad agent-custody runtime branches. No dormant CLI assumptions
      were present.
- [x] Delete wallet and SDK re-exports for unsupported agent-spend APIs.
- [x] Delete tests, fixtures, mocks, and source guards that exist solely for
      the retired shapes.
- [x] Remove duplicate value objects when an existing exact shared type already
      represents the same concept.

### Phase 3: Preserve exact execution seams

- [x] Keep delegated execution-lane records as inert execution material.
- [x] Keep participant binding, material activation, share epoch, rotation,
      receipt, and fencing behavior unchanged.
- [x] Confirm hydration and execution helpers do not accept lane data alone as
      authorization evidence.
- [x] Expose only the already validated execution inputs that R118A will need
      after it has admitted an approved spend.

### Phase 4: Close type escape hatches

- [x] Confirm type fixtures prove that lane data cannot construct agent
      identity, Agent Grant, budget, replay, approval, or owner-operation state.
- [x] Reject broad object spreads and invalid owner, linked-device, and delegated
      branch combinations.
- [x] Keep boundary parsers beside raw persistence, request, worker, and UI
      inputs. Core execution modules accept exact internal types only.
- [x] Remove obsolete exports so R118A starts from one definition per retained
      concept.

### Phase 5: Verify the handoff

- [x] Run the narrow type fixtures and focused lane tests affected by deletion.
- [x] Run repository typecheck and architecture checks for changed shared
      modules.
- [x] Search for every retired symbol and classify the remaining hits.
- [x] Confirm R118A can add its domain without importing a lane-owned policy,
      budget, or agent identity.

## Implementation result

The inventory found a real execution-lane substrate and an unused product-shaped
shell introduced alongside it. No production module consumed the shell's mandate,
intent, custody-runtime, or agent-principal types. Earlier server route and
budget-store placeholders had already been deleted.

R104 therefore:

- removed the unused mandate, intent, audit, custody-runtime, agent-principal,
  idempotency, and digest definitions;
- removed their wallet and shared-module re-exports;
- retained the R101 `DelegatedExecutionSigningLaneRecord` authorization-binding
  references and exact parser unchanged;
- retained `PreparedDelegatedWalletExecution` and its reserved-claim interface
  as the prepared-execution seam R118A must satisfy; and
- kept `delegated_execution` unchanged across TypeScript, Rust protocols, D1
  schemas, activation, rotation, revocation, and fencing.

No compatibility shape was retained for the removed product records because they
had no production writer or consumer. The durable execution-lane and prepared
execution contracts remain intact.

## Exit criteria

R104 is complete when:

- obsolete delegated-agent domain scaffolds are gone;
- retained lane records represent execution material only;
- no unsupported agent-spend public API remains exported;
- exact type fixtures guard the execution and authority boundary;
- the repository has one clean seam for R118A prepared execution; and
- R104 owns no product behavior that R118A must later replace.

## Non-goals

- defining the final agent identity or Agent Connection model
- defining Agent Grants, mandates, purchases, approvals, or expense ledgers
- executing a stablecoin or card payment
- provisioning an agent runtime or delivering holder shares
- adding OAuth, MCP, API credentials, or CLI commands
- adding Console pages or management APIs
- adding Airwallex configuration, cards, webhooks, or provider records
- preserving dormant scaffolds for compatibility
