# Refactor 90 merge decisions

## Merge of local `dev` at `e95887fdc`

Merge commit: `43b9c83f0`.

The merge brought the current `dev` animation, iframe, and test updates into
`codex/refactor-90-implementation`. The ECDSA activation-response conflict was
resolved in favor of the Refactor 90 branch shape:

- `threshold_session_id`, `wallet_session_id`, and `quota_id` remain distinct
  response identities.
- `signing_grant_id` remains at this boundary until Unit 3c migrates every
  consumer and replaces the JWT/session binding atomically.
- `bootstrapSession` continues to receive the existing response identity set.
- The deleted `postRegistrationSessionActivation` test remains deleted; its
  old response shape is obsolete.

This deliberately does not accept `e95887fdc`'s partial TypeScript-only
removal. That commit removed fields without migrating the live Email OTP,
bootstrap, and activation consumers, and it omitted the Wallet Session/quota
identities required by the current Refactor 90 model. The full removal remains
owned by Unit 3c's coordinated Rust/TypeScript claim-verifier cutover.

Validation after resolution:

- `pnpm -C packages/shared-ts exec tsc --noEmit`
- `pnpm -C packages/sdk-server-ts type-check`
- `pnpm -C tests run type-check:unit`
- `git diff --check`

All passed. The focused activation test remains outside this merge gate and is
tracked separately because its role-local fixture is stale before the wire
call.
