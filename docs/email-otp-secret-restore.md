# Email OTP Secret And Restore

Status: active spec for Email OTP secret ownership, sealed restore, and
transaction signing boundaries.

## Authority

This document replaces the deleted Email OTP migration logs. Do not reintroduce
the old phase plans or fallback proposals without revalidating them against the
current deterministic signing-session design.

## Core Invariants

1. Email OTP secrets are distinct from passkey PRF material.
2. Email OTP fallback must not wrap or store passkey PRF output.
3. Secret-bearing material stays worker-owned or encrypted at rest.
4. Durable sealed records are restore sources, not current signing authority by
   themselves.
5. Status and snapshot reads do not unseal, restore, consume, delete, or prompt.
6. Transaction signing restores only the exact selected lane.
7. Key export is not a transaction signing-session lifecycle operation.

## Secret Model

Email OTP derives signing capability from Email OTP-specific secret material.

The stable model is:

1. Enrollment creates or binds Email OTP-specific secret material.
2. Login or step-up verifies a fresh Email OTP challenge.
3. The worker reconstructs the required signing material.
4. Transaction signing uses a threshold session tied to a
   `walletSigningSessionId`.
5. Durable sealed refresh records allow exact restore after page refresh while
   server budget remains valid.

## Storage Ownership

| Store | Owns |
| --- | --- |
| Email OTP worker memory | unsealed Email OTP secret material and hot signing material |
| IndexedDB sealed records | encrypted restore material plus non-secret lane identity |
| server | Email OTP enrollment identity, challenge verification, session validity, and wallet budget |
| runtime record store | concrete current threshold-session records |

No transaction flow may treat a durable companion record as the current selected
lane unless the state machine selected that exact lane.

## Transaction Signing

Email OTP transaction signing has two modes:

1. Session-retained signing: use the existing selected Email OTP lane while
   server budget is valid.
2. Per-operation step-up: prompt for Email OTP and mint a single-operation
   replacement lane.

In both modes, the transaction state machine owns lane selection. Email OTP
helpers may verify challenges, mint sessions, and restore exact material, but
they may not choose another auth method or publish another curve as the current
transaction lane.

## Sealed Refresh

Sealed refresh exists so page refresh does not force Email OTP again when the
server says the wallet signing-session budget is still valid.

Rules:

1. Restore is exact by selected lane identity.
2. Restore failure becomes readiness for that lane or a typed restore failure.
3. Restore does not probe OTP then passkey, or passkey then OTP.
4. Restore does not change curve or chain.
5. Restore does not consume budget by itself unless the explicit restore protocol
   requires an authoritative server-side one-use transition.

## Curve Boundaries

1. NEAR transaction signing uses Ed25519.
2. Tempo/ARC/EVM transaction signing uses ECDSA.
3. One curve may persist durable companion material for another curve only as
   durable restorable state.
4. One curve may not publish the other curve as the current transaction lane.
5. ECDSA step-up cannot make the next Ed25519 transaction skip Email OTP unless
   the Ed25519 transaction state machine selected and validated that exact lane.

## Key Export

Key export requires operation-specific fresh authorization. It must not:

1. mint or renew transaction signing sessions
2. consume transaction signing budget
3. clear transaction signing material
4. overwrite current transaction records
5. reuse transaction challenge helpers

Export may use restored signing-session authority only to request the export
challenge route when policy allows it. The export itself still requires fresh
operation authorization.

## Related Specs

1. Product intent:
   [signing-session-refresh-intent.md](signing-session-refresh-intent.md).
2. Transaction state machine:
   [signing-session-refactor-2.md](signing-session-refactor-2.md).
3. Auth and budget:
   [signing-session-auth-and-budget.md](signing-session-auth-and-budget.md).
4. Route auth planes:
   [auth-gating-routes.md](auth-gating-routes.md).
