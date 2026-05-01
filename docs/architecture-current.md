# Architecture Current

Status: active documentation map. The older architecture snapshot was deleted
because it described stale implementation assumptions.

## Current Authority

1. Signing-session product intent:
   [signing-session-refresh-intent.md](signing-session-refresh-intent.md).
2. Signing-session implementation plan:
   [signing-session-refactor-2.md](signing-session-refactor-2.md).
3. Signing-session architecture summary:
   [signing-session-architecture.md](signing-session-architecture.md).
4. Auth and budget model:
   [signing-session-auth-and-budget.md](signing-session-auth-and-budget.md).
5. Email OTP secret/restore model:
   [email-otp-secret-restore.md](email-otp-secret-restore.md).
6. Ed25519 model:
   [stateless-shared-root-ed25519.md](stateless-shared-root-ed25519.md).
7. ECDSA model:
   [ecdsa_threshold_signing.md](ecdsa_threshold_signing.md).
8. Route auth planes:
   [auth-gating-routes.md](auth-gating-routes.md).

## Cleanup Rule

Older docs are treated as historical until revalidated. If a doc contains stale
phase logs, compatibility proposals, or migration TODOs, move stable material into
an active spec and archive the rest.
