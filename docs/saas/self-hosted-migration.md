# Customer-Owned Wallet Domain Plan

Date updated: March 10, 2026

## Objective

Support a customer-owned wallet origin such as `https://wallet.dev1.com` from day 0, while keeping the first deployment vendor-hosted and preserving a clean path to later customer self-hosting.

This plan intentionally optimizes for:

- stable `rpId` and wallet origin from the user's point of view,
- low-touch infrastructure cutover later,
- explicit tradeoffs versus shared-network wallet composability.

## Recommended Model

Use a customer-owned wallet hostname from the start:

- wallet origin: `https://wallet.dev1.com`
- app origin: `https://app.dev1.com` (or another customer-controlled host)
- `rpId`: either `dev1.com` or `wallet.dev1.com`

The browser-visible wallet origin must remain `https://wallet.dev1.com` during both phases:

1. vendor-hosted initial rollout,
2. customer-hosted later rollout.

Do not rely on redirects to a vendor domain. The customer hostname must stay visible in the browser so passkeys and wallet-origin IndexedDB stay bound to the customer domain.

## Why This Model

This avoids the two hard migration problems:

- passkeys do not need a new domain migration because `rpId` stays stable,
- wallet-origin local state does not need an origin migration because the visible wallet host stays stable.

Threshold backend cutover remains an infrastructure problem, not a passkey re-enrollment problem.

## Customer Prerequisites

The customer must provide:

1. A domain they already control.
2. A dedicated wallet subdomain, for example `wallet.dev1.com`.
3. DNS control for that subdomain so they can add `CNAME` and `TXT` records.
4. A willingness to point that subdomain at vendor infrastructure first with a `CNAME`.
5. A willingness to complete ownership / TLS validation with vendor-provided `TXT` records when required.

Recommended complementary app setup:

- app hostname: `app.dev1.com`
- wallet hostname: `wallet.dev1.com`
- shared base-domain `rpId`: `dev1.com`

## Customer Setup Instructions

### 1. Choose the wallet hostname

Pick a stable wallet hostname that will not change later:

- recommended: `wallet.dev1.com`

Do not start on a vendor hostname if the customer may later require self-hosting.

### 2. Add DNS records for hosted rollout

Use a browser-transparent `CNAME + TXT` setup:

- `CNAME wallet.dev1.com -> customer-wallet-edge.tatchi.xyz`
- `TXT _tatchi-verify.wallet.dev1.com -> <vendor-generated-verification-token>`
- optional: `TXT _acme-challenge.wallet.dev1.com -> <vendor-generated-acme-token>` when DNS-based certificate validation is required

Requirements:

- the browser must keep showing `https://wallet.dev1.com`,
- passkey ceremonies must execute under that hostname,
- wallet assets and `/wallet-service` must be served from that hostname.

Non-goal:

- HTTP redirects from `wallet.dev1.com` to `wallet.tatchi.xyz`
- NS delegation of the customer subdomain for the default onboarding flow

Operational note:

- the customer keeps DNS control in their own provider and only copies vendor-provided records,
- vendor activates the hostname after the `CNAME` and verification `TXT` records resolve.

### 3. Configure app integration

The customer app must point the SDK at the customer-owned wallet origin:

```ts
iframeWallet: {
  walletOrigin: 'https://wallet.dev1.com',
  walletServicePath: '/wallet-service',
}
```

The app must also delegate WebAuthn to the wallet origin via `Permissions-Policy` and iframe `allow` attributes.

### 4. Freeze the RP boundary

Choose the `rpId` policy once and keep it stable:

- `rpId = dev1.com` for app-scoped credentials across customer subdomains, or
- `rpId = wallet.dev1.com` for wallet-host-scoped credentials

Changing this later turns the project into a passkey migration.

## Vendor Implementation Plan

### Phase 1. Hosting and routing

1. Add `CNAME`-based custom-domain support on vendor edge for customer wallet domains.
2. Generate per-customer DNS onboarding instructions:
   - `CNAME` target for wallet traffic,
   - ownership verification `TXT` record,
   - temporary ACME / certificate-validation `TXT` records when required.
3. Support browser-transparent serving of:
   - `/wallet-service`
   - `/sdk/*` assets
   - wallet CSP and WebAuthn delegation headers
4. Add TLS issuance/renewal support for customer wallet hostnames after DNS verification succeeds.

### Phase 2. Tenant configuration

1. Persist per-customer wallet origin and `rpId` settings.
2. Validate that configured app origins are allowed to embed the wallet.
3. Expose onboarding instructions for DNS and app integration.
4. Track hostname activation state:
   - pending DNS,
   - pending verification / TLS,
   - active.

### Phase 3. Runtime support

1. Ensure relay/session flows use the customer-configured `rpId`.
2. Ensure `/.well-known/webauthn` and related-origin configuration stay aligned with the customer wallet hostname and allowed app origins.
3. Keep vendor-hosted runtime behavior identical to later self-hosted expectations:
   - same wallet paths,
   - same headers,
   - same origin,
   - same `rpId`.

### Phase 4. Self-host cutover

When the customer is ready to self-host:

1. Customer deploys the wallet service under the same hostname and path contract.
2. Customer deploys the same wallet asset/runtime bundle or a supported equivalent.
3. Customer preserves:
   - `https://wallet.dev1.com`
   - the same `rpId`
   - the same WebAuthn delegation and wallet CSP behavior
4. Customer updates the `CNAME` target or equivalent edge routing from vendor infrastructure to customer infrastructure.
5. Vendor and customer perform a short validation window for:
   - registration,
   - login,
   - transaction signing,
   - Safari related-origin behavior,
   - wallet local-state continuity.

## Threshold Backend Migration Notes

The wallet-domain plan removes the passkey-domain migration problem, but the customer still needs compatible signing backend state.

Preferred shape:

- use derived relayer-share modes where available,
- migrate master-secret material and environment config rather than exporting per-user plaintext key material,
- treat in-flight sessions and presign caches as disposable cutover state.

Operationally, the self-host cutover should preserve:

- relay API compatibility,
- session minting behavior,
- threshold master-secret configuration,
- audit and observability paths expected by the customer deployment.

## Tradeoffs With Wallet Composability

Moving from a shared vendor wallet domain to customer-owned wallet domains changes the wallet composability model.

### Shared vendor wallet domain

Example:

- wallet origin: `https://wallet.tatchi.xyz`

Properties:

- wallets can be reused across unrelated apps that integrate the same shared wallet domain,
- stronger cross-customer network composability,
- weaker portability for customers who later want their own domain boundary.

### Customer-owned wallet domain

Example:

- wallet origin: `https://wallet.dev1.com`

Properties:

- wallets can be reused across apps that integrate the same customer-owned wallet origin,
- clean path to vendor-hosted first and customer-hosted later,
- no cross-customer wallet composability.

This means:

- `wallet.dev1.com` and `wallet.dev2.com` are separate passkey and wallet ecosystems,
- composability is preserved within one customer's product family, not across the whole network.

## Product Recommendation

Support two explicit modes rather than trying to make one mode satisfy conflicting goals:

1. Shared network wallet mode
   - vendor-owned wallet origin
   - optimized for cross-app composability
2. Customer-owned wallet mode
   - customer-owned wallet origin from day 0
   - optimized for future self-hosting and white-label portability

Do not promise seamless migration from a vendor-owned wallet domain to a customer-owned wallet domain after launch. That is a true passkey-domain migration and should be treated as a separate product with explicit user migration steps.

For the default customer-owned wallet flow, prefer `CNAME + TXT` onboarding over delegated subdomain DNS or full registrar transfer.
