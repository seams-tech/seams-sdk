# Auth Gating For Current Routes

Date updated: 2026-08-30

## Scope

This document describes the current route-auth model after the Router A/B
signing cleanup. Router A/B is the only public signing architecture for
Ed25519 and ECDSA product signing. Old public threshold signing route
families are intentionally absent from the current route surface.

## Auth Planes

Every server route should belong to exactly one primary auth plane.

| Plane | Used for | Credential |
| --- | --- | --- |
| Console session + RBAC | Human operator console routes | Console session claims plus role checks |
| API credential | Machine/browser relay access outside wallet-user sessions | Publishable key or secret key |
| Wallet Session | Product signing and signing-budget routes | `WalletSessionOperationCredentialV1` or `HostedWalletSessionOperationCredentialV1` |
| Router A/B private service | Cross-worker Router A/B internals | Worker binding plus private service/auth guard |
| Explicit public | Health and readiness | None |

Console auth, API credentials, and Wallet Sessions are separate auth planes. A
route must not silently accept credentials from another plane.

## Router A/B Public Signing

Public Ed25519 and ECDSA signing uses the current Router A/B route families:

- `POST /router-ab/ed25519/sign/prepare`
- `POST /router-ab/ed25519/sign`
- `POST /router-ab/ecdsa-derivation/sign/prepare`
- `POST /router-ab/ecdsa-derivation/sign`

Router A/B public signing requirements:

- `Authorization` header carrying the exact Wallet Session operation credential
- browser `credentials: 'omit'`
- exact origin CORS behavior for configured origins
- strict request-body parsing at the Router boundary
- policy, quota, replay, expiry, and abuse checks before private worker fanout
- no cookie Wallet Session auth until credentialed CORS requirements are
  specified and covered by deployed browser evidence

## Router A/B Private Worker Routes

Router A/B private worker routes are internal cross-worker protocol routes. They
remain versioned as part of the durable Router A/B protocol and are not public
SDK routes.

Requirements:

- reachable only through Worker bindings or the approved private service
  boundary
- no public browser CORS exposure
- no Wallet Session parsing in SigningWorker private route handlers
- strict boundary parsers and unknown-field rejection
- one-use nonce or presignature storage for signing material

## Wallet Session Routes

Wallet Session issuance, status, exchange, unlock, and signing-budget routes
resolve the exact V2 authorization represented by the operation credential and
its fully scoped identity.

Current session route shapes are:

- `POST /wallet/session/exchange/issue` authenticates with the primary
  operation credential and creates an origin-bound hosted child exchange.
- `POST /wallet/session/exchange/redeem` consumes the exchange and returns a
  `HostedWalletSessionOperationCredentialV1` for the same parent authorization.
- `POST /wallet/session/status` requires the exact `walletSessionId` and
  `quotaId` in the request and checks them against the credential's resolved
  authorization.
- `POST /wallet/unlock/challenge` and `POST /wallet/unlock/verify` bind the
  selected exact authority and `walletAuthMethodId` before direct V2 issuance.
- `POST /wallet/email-otp/challenge` requires the selected exact
  `walletAuthMethodId`; `/wallet/email-otp/factor-release` binds either the
  exact Wallet Session credential or the exact method on an OTP grant.

Rules:

- raw request bodies are parsed once at the route boundary
- current persisted records are normalized before core logic sees them
- removed legacy shapes are rejected at the request boundary
- signing budget consumption must bind wallet id, authority id,
  `walletAuthMethodId`, Wallet Session id, quota id, account id, scope, expiry,
  and operation fingerprint

## Deleted Signing Route Families

The old public threshold signing route families are no longer current auth
planes. Active docs should not describe them as callable product signing APIs.
Historical refactor notes may still mention them as removed implementation
history.

The zero-tolerance source guards in the Router A/B cleanup plan cover deleted
public route literals, deleted SDK helper names, and retired signing-auth fields
in active SDK signing modules.

## Billing And Metering

Routes that can spend relayer funds or consume signing budget must state their
metering policy in the owning route module or product plan.

Current signing budget enforcement lives behind Wallet Session/Router A/B
admission. Deployed release evidence must confirm no private Deriver invocation
or SigningWorker signing happens for rejected public Router A/B requests.
