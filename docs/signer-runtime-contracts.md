# Signer Runtime Contracts

Canonical signer runtime contracts are enforced by architecture checks and typed worker APIs in:

- `client/src/core/signingEngine/workers/*`
- `client/src/core/signingEngine/workers/signerWorkerManager/backends/*`
- `sdk/scripts/checks/check-signing-api-cycles.mjs`
- `sdk/scripts/checks/check-stable-experimental-export-boundaries.mjs`
- `sdk/scripts/checks/check-worker-runtime-boundaries.mjs`

Use `docs/next-steps-for-signers.md` and `docs/refactor2.md` for active migration work.
