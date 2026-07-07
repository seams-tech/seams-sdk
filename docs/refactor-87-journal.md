# Refactor 87 Journal

## July 8, 2026

- Started Phase 0 with the accepted console package target:
  `packages/console-server-ts` / `@seams-internal/console-server`.
- Added `check-signer-console-module-boundaries` to `test:source-guards`.
  The guard rejects console/sponsorship imports from signer-core roots and
  keeps current signer-router coupling on an exact allowlist for later burn
  down.
- Completed Phase 1 B8 by repointing the Cloudflare ECDSA route from
  `sponsorship/evmWorkerSignerWasm` to
  `core/ThresholdService/ethSignerWasm`.
- Completed Phase 1 B1 by moving `src/sponsorship` to
  `src/console/sponsorship`. Router, console-service, tests, and docs now
  import sponsorship through the console-owned path, with no compatibility
  folder left behind.
- Completed the first Phase 2 auth-port inversion slice. Signer-owned Router
  API credential, bootstrap-token verifier, usage-meter, and project
  environment resolver ports now live in `router/apiCredentialPorts.ts`.
  Console-backed API-key auth, publishable-key auth, billing usage metering,
  bootstrap-token verification, and bootstrap-grant brokerage now live under
  `src/console/router`.
- Burned down the B3 signer-console import guard exceptions for
  `routerApiKeyAuth`, `routerApiCredentialAuth`, `bootstrapGrantBroker`, and
  related scope/bootstrap imports. `commonRouterUtils`,
  `walletRegistrationRoutes`, and `routeAuthPolicy` now use signer-owned port
  types or constants for this slice.
- Validation:
  - `pnpm -C tests run check:signer-console-module-boundaries`
  - `pnpm -C packages/sdk-server-ts run build`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/sponsorship.staticPricing.unit.test.ts unit/sponsorship.realPricing.unit.test.ts unit/sponsorship.evmRelayConfig.unit.test.ts unit/cloudflareD1ConsoleServices.unit.test.ts relayer/console-d1-adapters.test.ts`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/cloudflareD1ConsoleServices.unit.test.ts unit/relayWalletRegistration.boundary.unit.test.ts unit/router.sponsoredEvmCallCloudflare.unit.test.ts unit/router.routerApiRouteSurface.unit.test.ts`
