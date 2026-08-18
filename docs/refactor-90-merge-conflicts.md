# Refactor 90 merge decisions

## Merge of local `dev` at `e95887fdc`

Merge commit: `43b9c83f0`.

The merge brought the current `dev` animation, iframe, and test updates into
`codex/refactor-90-implementation`. The ECDSA activation-response conflict was
resolved in favor of the Refactor 90 branch shape:

- `threshold_session_id`, `wallet_session_id`, and `quota_id` remain distinct
  response identities.
- Unit 3c subsequently removed the retired grant field after migrating every
  consumer and replacing the JWT/session binding atomically.
- `bootstrapSession` continues to receive the existing response identity set.
- The deleted `postRegistrationSessionActivation` test remains deleted; its
  old response shape is obsolete.

This deliberately does not accept `e95887fdc`'s partial TypeScript-only
removal. That commit removed fields without migrating the live Email OTP,
bootstrap, and activation consumers, and it omitted the Wallet Session/quota
identities required by the current Refactor 90 model. Unit 3c later completed
the coordinated Rust/TypeScript claim-verifier cutover.

Validation after resolution:

- `pnpm -C packages/shared-ts exec tsc --noEmit`
- `pnpm -C packages/wallet-server type-check`
- `pnpm -C tests run type-check:unit`
- `git diff --check`

All passed. The focused activation test remains outside this merge gate and is
tracked separately because its role-local fixture is stale before the wire
call.
