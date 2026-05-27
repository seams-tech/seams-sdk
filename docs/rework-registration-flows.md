# Completed Registration Flow Rework

Status: completed historical note. Active follow-up work now lives in
`docs/rework-registration-flows-2.md`.

The original registration-flow rework replaced the split legacy registration
path with wallet-subject registration ceremonies. The completed work includes:

- Passkey wallet registration through `/wallets/register/intent`,
  `/wallets/register/start`, `/wallets/register/hss/respond`, and
  `/wallets/register/finalize`.
- First-class signer selection for Ed25519-only, ECDSA-only, and combined
  Ed25519 plus ECDSA passkey registration.
- Add-signer ceremonies through `/wallets/:walletSubjectId/signers/*`.
- Deletion of production registration-continuation token generation and
  continuation-token ECDSA bootstrap authorization.
- Deletion of the legacy `/registration/bootstrap` and
  `/registration/threshold-ed25519/hss/*` route surface.
- Cleanup guards for deleted registration continuation paths, deleted
  `walletAuth/`, and deleted signing-engine layout paths.

The old implementation plan and checklist are intentionally collapsed here
because their remaining unchecked items were either completed, obsolete, or
moved to the auth-method follow-up.

Use `docs/rework-registration-flows-2.md` as the active plan for refactor-43
style work. That follow-up owns first-class registration auth methods, explicit
`authMethod` inputs, Email OTP wallet registration, multiple auth methods per
wallet, auth-method revocation, and related type/test coverage.
