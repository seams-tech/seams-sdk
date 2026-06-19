# Auth Gating For Current Routes

Date updated: 2026-06-17

## Scope

This document describes the current route-auth model after the Router A/B
signing cleanup. Router A/B is the only public signing architecture for
Ed25519 and ECDSA-HSS product signing. Old public threshold signing route
families are intentionally absent from the current route surface.

## Auth Planes

Every server route should belong to exactly one primary auth plane.

| Plane | Used for | Credential |
| --- | --- | --- |
| Console session + RBAC | Human operator console routes | Console session claims plus role checks |
| API credential | Machine/browser relay access outside wallet-user sessions | Publishable key, secret key, or bootstrap token |
| App session | User wallet management routes | `app_session_v1` |
| Wallet Session | Product signing and signing-budget routes | Wallet Session JWT or current request-boundary token |
| Router A/B private service | Cross-worker Router A/B internals | Worker binding plus private service/auth guard |
| Explicit public | Health and readiness | None |

Console auth, API credentials, app sessions, and Wallet Sessions are separate
auth planes. A route must not silently accept credentials from another plane.

## Router A/B Public Signing

Public Ed25519 and ECDSA-HSS signing uses:

- `POST /v2/router-ab/ed25519/sign/prepare`
- `POST /v2/router-ab/ed25519/sign`

Router A/B public signing requirements:

- bearer Wallet Session JWT
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

Wallet Session mint, budget, and restore routes may still use request-boundary
discriminants named around threshold sessions where those values are current
stored/request protocol names. Core signing logic should normalize those inputs
to Wallet Session domain state immediately.

Rules:

- raw request bodies are parsed once at the route boundary
- current persisted records are normalized before core logic sees them
- stale compatibility branches need a deletion condition and focused rejection
  coverage
- signing budget consumption must bind wallet id, threshold session id, account
  id, scope, expiry, and operation fingerprint

## Deleted Signing Route Families

The old public threshold signing route families are no longer current auth
planes. Active docs should not describe them as callable product signing APIs.
Historical refactor notes may still mention them as removed implementation
history.

The zero-tolerance source guards in the Router A/B cleanup plan cover deleted
public route literals, deleted SDK helper names, and old threshold-session
signing-auth fields in active SDK signing modules.

## Billing And Metering

Routes that can spend relayer funds or consume signing budget must state their
metering policy in the owning route module or product plan.

Current signing budget enforcement lives behind Wallet Session/Router A/B
admission. Deployed release evidence must confirm no private Deriver invocation
or SigningWorker signing happens for rejected public Router A/B requests.
