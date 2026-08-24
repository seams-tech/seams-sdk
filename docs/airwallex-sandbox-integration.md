# Airwallex Sandbox Integration Plan

Date created: August 22, 2026

Status: planned; sandbox credentials and environment placeholders exist, and no
runtime integration has been implemented.

Parent plan:

- [Stablecoin-linked virtual card](stablecoin-linked-virtual-card.md)

## Outcome

Build one server-side Airwallex sandbox adaptor that proves the card-provider
side of the stablecoin-linked virtual card flow:

```text
Seams test runtime
  -> authenticate to Airwallex sandbox
  -> create one sandbox cardholder
  -> issue one sandbox virtual card
  -> simulate authorization and capture
  -> receive and reconcile Airwallex events
  -> simulate reversal and refund
```

The first operating path uses one Airwallex organisation and one account. It
does not use Connected Accounts, customer stablecoin, real fiat, production
cards, or live card-network transactions.

## Provider Constraints

Airwallex sandbox is separate from production and provides simulated Wallet
funds and Issuing transaction APIs. The self-service sandbox excludes Connected
Account APIs. Issuing, Remote Authorization, and PAN delegation may still need
Airwallex enablement.

The implementation therefore has two explicit provider states:

```ts
type AirwallexSandboxAvailability =
  | {
      kind: "airwallex_sandbox_available";
      configuration: AirwallexSandboxConfiguration;
    }
  | {
      kind: "airwallex_sandbox_capability_missing";
      capability: "issuing" | "remote_authorization" | "pan_delegation";
    };
```

Core card logic receives the available branch for Airwallex calls. Capability
failure does not activate a permissive provider path. Tests that do not require
Airwallex use a separate fake adaptor selected during runtime composition.

## Environment Contract

The checked-in template is `apps/web-server/.env.example`:

| Variable | Purpose |
| --- | --- |
| `AIRWALLEX_BASE_URL` | Must equal the Airwallex sandbox API origin during this plan. |
| `AIRWALLEX_CLIENT_ID` | Sandbox API client identifier. |
| `AIRWALLEX_API_KEY` | Sandbox API secret; local or hosted secret storage only. |
| `AIRWALLEX_ACCOUNT_ID` | Single Airwallex sandbox account used for the first slice. |
| `AIRWALLEX_ORGANISATION_ID` | Owning sandbox organisation identifier. |

Remote Authorization and webhook delivery will add these secrets when those
capabilities are configured:

- `AIRWALLEX_REMOTE_AUTH_SHARED_SECRET`
- `AIRWALLEX_WEBHOOK_SECRET`

The boundary parser must:

- require all identity and credential fields for an enabled adaptor
- accept only `https://api.sandbox.airwallex.com/api/v1`
- reject the production API origin and every other host
- return a precise configured or unconfigured result
- avoid logging API keys, bearer tokens, shared secrets, or raw card data

## Package Boundary

Keep the first slice within the existing server and test workspaces:

| Area | Responsibility |
| --- | --- |
| `packages/wallet-server/src/stablecoinCards` | Provider-neutral card lifecycle, adaptor port, normalized results, and authorization service. |
| `packages/wallet-server/src/stablecoinCards/airwallex` | Airwallex configuration parser, HTTP client, raw response parsers, signature verification, and adaptor implementation. |
| `apps/web-server/src` | Runtime composition, Remote Authorization route, webhook route, and secret injection. |
| `tests/unit` | Configuration, client, parser, signature, idempotency, and lifecycle tests. |
| `tests/e2e/intended-behaviours` | Opt-in Airwallex sandbox operating-path contract. |

Reuse the existing Stripe provider pattern for bounded HTTP calls, injected
`fetch`, configuration parsing, and provider-error normalization. Reuse the
existing router raw-body capture for webhook signature verification.

Airwallex response objects stay inside the Airwallex boundary. Provider-neutral
services receive branded identifiers, integer minor-unit amounts, normalized
currencies, and discriminated lifecycle events.

## Implementation Sequence

### Milestone 1: Configuration And Authentication Probe

Implement the smallest read-only provider client:

1. Parse the five Airwallex environment variables once at server startup.
2. Reject any non-sandbox API origin.
3. Call `POST /authentication/login` with the Client ID and API key.
4. Parse the access token and expiry into a private token-cache record.
5. Call `GET /balances/current` to prove authenticated sandbox access.
6. Return normalized success, credential failure, capability failure, timeout,
   rate-limit, or provider-unavailable results.

Cache an access token only until its provider expiry. A concurrent refresh uses
one in-flight request. Provider responses and thrown errors must never include
credential headers in application logs.

Milestone acceptance:

- the server starts with no Airwallex configuration and leaves the adaptor
  unconfigured
- a complete sandbox configuration produces one successful balance query
- a production or malformed origin prevents server startup for the enabled
  adaptor
- authentication failures are normalized without exposing secrets

### Milestone 2: Sandbox Cardholder And Virtual Card

Add only the endpoints required for one card:

1. Create an Airwallex sandbox cardholder with a stable Seams request ID.
2. Retrieve the cardholder after ambiguous failures before retrying creation.
3. Create one virtual card associated with that cardholder.
4. Persist Airwallex cardholder ID, card ID, status, nickname, masked number,
   and request ID.
5. Implement retrieve, freeze, unfreeze, and close operations.

Use branch-specific request builders for the selected sandbox cardholder type.
Do not accept a broad object with optional individual, delegate, or business
fields.

Seams application code must not call the sensitive card-details endpoint or
receive PAN or CVV. Card display remains unavailable until Airwallex enables
PAN delegation. When enabled, the browser receives a short-lived secure-iframe
token and Airwallex renders the sensitive fields.

Milestone acceptance:

- one request ID creates at most one cardholder and one card
- a repeated request converges on the existing provider records
- freeze, unfreeze, and close produce valid lifecycle transitions
- logs and persisted records contain no PAN, CVV, or bearer token

### Milestone 3: Transaction Simulation And Reconciliation

Wrap the sandbox-only simulation endpoints:

- `POST /simulation/issuing/create`
- `POST /simulation/issuing/{transaction_id}/capture`
- `POST /simulation/issuing/{transaction_id}/reverse`
- `POST /simulation/issuing/refund`

Prove these paths in order:

1. successful authorization followed by full capture
2. authorization followed by partial capture
3. authorization followed by full and partial reversal
4. failed authorization
5. incremental authorization
6. single-message authorization and capture
7. linked refund

Normalize every provider transaction into one card lifecycle event. Amounts use
integer minor units at the Seams boundary. Provider decimal amounts are parsed
once and rejected when precision exceeds the currency definition.

Add reconciliation reads for a single card and transaction. A reconciliation
run compares provider state with Seams state and emits a discrepancy record; it
does not silently mutate an unexplained mismatch.

### Milestone 4: Signed Webhook Ingestion

Add a dedicated Issuing webhook endpoint:

1. Capture the exact raw request body.
2. Read `x-timestamp` and `x-signature`.
3. Compute HMAC-SHA-256 over the timestamp followed by the raw body.
4. Compare signatures in constant time and enforce a bounded timestamp skew.
5. Parse the verified payload into an Airwallex boundary type.
6. Store the provider event ID before applying its normalized transition.
7. Return `200` for an already-applied event.

Airwallex retries failed deliveries and does not guarantee event order. State
application must be idempotent and reconcile older or reordered events against
the authoritative transaction record.

Milestone acceptance:

- invalid signatures and stale timestamps are rejected
- duplicate delivery produces one transition
- reordered delivery converges through reconciliation
- processing failure leaves the event retryable
- the endpoint acknowledges a durable event before slow follow-up work

### Milestone 5: Remote Authorization

Start this milestone only when Airwallex enables Remote Authorization for the
sandbox account.

Add a dedicated synchronous endpoint that:

1. verifies the Airwallex nonce signature before parsing provider data
2. rejects replayed nonces
3. resolves the card to exactly one active Seams reserve allocation
4. converts the requested merchant amount into a bounded reserve obligation
5. atomically creates one authorization hold
6. responds approve or decline within Airwallex's 2.5-second window
7. declines on timeout, unavailable state, unknown card, invalid currency,
   stale price, insufficient reserve, or storage failure

The endpoint performs no onchain transaction, stablecoin conversion, Wallet
funding, or network call on the critical authorization path. Those operations
run asynchronously after durable authorization evidence exists.

Begin with a fake reserve ledger so this milestone can be tested independently
of the escrow contract. Replace the fake only after the complete Airwallex
authorization lifecycle works.

### Milestone 6: Escrow Connection

Connect the proven Airwallex adaptor to the testnet reserve system:

1. reconcile a confirmed mock-stablecoin escrow allocation
2. set the card hard limit no higher than the allocation
3. create a reserve hold for an approved Airwallex authorization
4. release or adjust the hold for reversal, expiry, or incremental auth
5. move settled test reserve into the testnet settlement multisig
6. simulate redemption, USD receipt, and Airwallex Wallet replenishment
7. credit a simulated refund back to testnet escrow

The Airwallex adaptor remains unaware of chain RPCs, escrow contracts, MPC,
redemption venues, bank accounts, and treasury keys.

## Verification Strategy

Use three levels of verification:

1. Unit tests with injected `fetch` own environment parsing, authentication,
   response parsing, timeout handling, signatures, and error normalization.
2. Provider-contract tests with the fake adaptor own card and transaction
   lifecycle behavior without external services.
3. One opt-in sandbox contract uses locally supplied Airwallex credentials to
   create a card and simulate authorization, capture, reversal, and refund.

The sandbox contract must use a unique run prefix, clean up or close its card,
and print provider request IDs without printing secrets or sensitive card data.
It skips with a precise missing-capability result when Issuing or Remote
Authorization has not been enabled.

## Completion Criteria

The Airwallex sandbox integration is technically ready when:

- sandbox authentication and token refresh work
- one cardholder and virtual card can be created idempotently
- card freeze, unfreeze, and close work
- authorization, capture, reversal, refund, incremental auth, and failure
  simulations reconcile correctly
- signed webhook retries and reordering cannot duplicate value
- Remote Authorization creates one atomic hold and declines safely on failure,
  when the capability is available
- Seams never handles or persists PAN or CVV
- the configured provider host cannot be changed to production
- no path moves mainnet assets, real fiat, or live card-network funds

Completion provides testnet engineering evidence. Production activation still
requires the regulatory, issuer, banking, capital, security, and operational
gate in the parent plan.

## References

- [Airwallex sandbox environment](https://www.airwallex.com/docs/developer-tools/sandbox-environment)
- [Airwallex Issuing sandbox simulations](https://www.airwallex.com/docs/developer-tools/sandbox-environment/issuing/simulate-transactions-on-issued-cards)
- [Airwallex Issuing cards API](https://www.airwallex.com/docs/api/issuing/cards/create)
- [Airwallex Remote Authorization testing](https://www.airwallex.com/docs/issuing/card-controls/remote-authorization/test-remote-authorization)
- [Airwallex webhook verification](https://www.airwallex.com/docs/developer-tools/webhooks/listen-for-webhook-events)
- [Airwallex secure card-detail iframes](https://www.airwallex.com/docs/issuing/manage-cards/retrieve-sensitive-card-details/secure-iframes)
