# Refactor 118D — OAuth, MCP, API, and CLI agent connections

Date created: August 29, 2026

Status: scaffolded implementation plan. Begin after R118A freezes agent actor,
connection reference, signed request, and revocation boundaries.

Parent plan:

- [R118A — Expense domain and direct stablecoin rail](refactor-118A-agent-expense-domain.md)

Related plan:

- [R118C — Agent expense Console](refactor-118C-agent-expense-console.md)

External reference:

- [Official OpenAI MCP documentation](https://learn.chatgpt.com/docs/extend/mcp)

## Goal

Let hosted and local agents authenticate to Seams through one of four exact
connection branches while keeping connection access separate from spending
authority.

```text
OAuth hosted agent
remote MCP client
scoped API client
local Seams CLI
  -> exact Agent Connection
  -> authenticated agent actor
  -> R118A Agent Grant admission
```

Creating a connection grants access to the Seams agent API surface. Only an
active R118A Agent Grant permits spending.

## Connection model

Use one discriminated lifecycle union with branch-specific required fields:

```text
oauth
remote_mcp
api_credential
local_cli
```

Do not construct a single optional record containing redirect URIs, MCP server
metadata, API-key hashes, CLI public keys, and local-custody fields together.

Every active connection resolves:

- one exact Seams customer or organization scope;
- one agent identity;
- one connection ID and kind;
- one authenticated credential or key binding;
- one issue and expiry policy;
- one revocation epoch; and
- one bounded set of API operations.

Connection scope cannot express merchant, amount, budget, payment-rail, or
purchase policy. Those belong to the Agent Grant.

## Adapter ownership

### OAuth

Owns:

- authorization request and callback state;
- exact redirect and client identity validation;
- authorization-code replay prevention;
- access and refresh credential lifecycle;
- user-visible connection consent; and
- disconnect and credential revocation.

OAuth proves which hosted integration the customer connected. It does not
replace R118A owner approval for a spending grant.

### Remote MCP

Owns:

- one streamable HTTP MCP server;
- OAuth or bearer-token authentication supported by the selected client;
- server instructions describing spend workflows and constraints;
- exact tool schemas and annotations;
- approval-compatible mutating tool behavior;
- rate limits and idempotency; and
- connection and tool-call audit evidence.

Official OpenAI documentation currently describes Streamable HTTP MCP with
bearer and OAuth authentication for Codex, with remote MCP-backed tools exposed
to ChatGPT through plugins. Treat client-side tool approval as an additional
checkpoint. R118A remains the spending security boundary.

### Scoped API credentials

Owns:

- one-time credential display;
- hashed or sealed server representation;
- exact operation scope;
- expiry, rotation, and revocation;
- tenant and environment binding; and
- request authentication and replay controls.

An API credential cannot carry an embedded Agent Grant or broad wallet signing
authority.

### Local CLI

Owns:

- local agent identity-key generation and proof of possession;
- secure storage through supported operating-system facilities;
- enrollment and connection approval;
- status, request, and revocation commands;
- machine-readable output containing public state only; and
- explicit loss and replacement behavior.

The first CLI path should avoid delegated MPC holder-package delivery unless the
R118A direct-wallet adapter proves that local participation is necessary. A
connection key can authenticate agent authorship without becoming wallet
execution material.

## Agent tool surface

The normal connection surface exposes intent-oriented operations:

```text
get_spending_authority
propose_purchase
request_purchase_approval
execute_approved_purchase
get_purchase_status
cancel_purchase
get_remaining_budget
```

There is no default generic `sign`, `send_money`, `export_key`, `create_grant`,
or `change_policy` agent tool. Owner administration uses the exact customer
surface and R118A owner-operation boundary.

Tool inputs contain raw request data only. The server parses them into R118A
boundary requests and returns explicit recoverable result unions.

## Required invariants

1. Connection identity and Agent Grant authority are separate records and
   lifecycles.
2. Revoking a connection denies new requests without changing wallet ownership.
3. Revoking a grant denies spend while leaving the underlying connection
   available for status and recovery-safe operations.
4. No connection can widen its own scopes, grant, budget, policy, or expiry.
5. Every mutating request carries stable idempotency and authenticated actor
   identity.
6. OAuth tokens, API credentials, CLI private keys, and provider secrets never
   enter logs or public projections.
7. MCP or client approval never substitutes for R118A policy admission.
8. Raw tool arguments and credential claims are normalized once at transport
   boundaries.
9. Cross-tenant, cross-environment, stale-epoch, expired, and revoked
   credentials fail before purchase or payment work.
10. Connection adapters share domain services and do not duplicate policy or
    payment orchestration.

## Implementation sequence

### Phase 1: Shared connection boundary

- [ ] Add exact connection IDs, lifecycle union, authenticated actor, and audit
      projection.
- [ ] Add create, list, inspect, rotate where applicable, and revoke services.
- [ ] Add narrow R118A resolution from authenticated actor to active Agent
      Grant.
- [ ] Add static fixtures rejecting mixed adapter branches and embedded policy.

### Phase 2: One first connection

- [ ] Choose either local CLI or remote MCP as the first operating adapter.
- [ ] Complete its authentication, revocation, and request-signing path.
- [ ] Demonstrate one R118A purchase through that adapter.
- [ ] Keep the other adapters unavailable until the shared boundary is proven.

### Phase 3: Remote MCP and OAuth

- [ ] Implement the streamable HTTP MCP endpoint.
- [ ] Implement the selected OAuth flow and exact connection consent.
- [ ] Publish the narrow tool set with correct read and mutation annotations.
- [ ] Test expired authentication, revoked connection, duplicate tool calls,
      client approval, server denial, and ambiguous execution.

### Phase 4: API and CLI parity

- [ ] Add scoped API credentials through the same authenticated actor boundary.
- [ ] Add CLI enrollment and secure local key handling.
- [ ] Prove equivalent R118A results across supported adapters.
- [ ] Keep adapter-specific metadata out of the expense domain.

## Exit criteria

R118D is complete when at least one hosted and one local agent connection can be
created, revoked, and used to propose the same R118A purchase without receiving
wallet ownership, unrestricted signing, or policy-administration authority.

## Non-goals

- defining Agent Grants, budgets, purchases, approvals, or payment state
- implementing wallet or card execution
- storing provider card credentials
- general agent orchestration, memory, scheduling, or tool hosting
- using OAuth scopes as spending policy
- relying on client-side approval as the sole financial control
