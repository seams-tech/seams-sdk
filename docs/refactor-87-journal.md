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
- Started Phase 3 by moving managed bootstrap-grant and API-wallet read route
  ownership into `console/router/routeExtensions.ts`. The core Cloudflare
  router no longer statically imports `routes/bootstrapGrants` or
  `routes/apiWallets`, and `RouterApiOptions` no longer carries
  `bootstrapGrantBroker` or `wallets`; the D1 composition closes over those
  services inside the console route extension.
- Continued Phase 3 by moving sponsored EVM route ownership into the same
  console route extension. The core Cloudflare router no longer imports
  `routes/sponsoredEvmCall`, `RouterApiOptions` no longer carries
  `sponsoredEvmCall`, and the D1/local/staging composition closes over the
  sponsored EVM services and worker execution adapter at extension creation.
- Burned down the signer-console guard exception for
  `router/routerApiSponsoredEvmCall.ts`; the handler now lives at
  `console/router/routerApiSponsoredEvmCall.ts`.
- Moved the shared sponsorship execution, billing-event, runtime, and
  spend-cap observability helpers from `router/` to `console/router/`. The
  guard no longer treats those helpers as signer-router files; the remaining
  signed-delegate coupling is now concentrated in `routerApiSignedDelegate.ts`.
- Moved `routerApiSignedDelegate.ts` into `console/router`. The hosted
  Cloudflare route wrapper still owns the route mount, but the console
  sponsorship implementation and helper imports are now outside signer-router
  guard scope.
- Moved signed-delegate route ownership into
  `console/router/routeExtensions.ts`. The core Cloudflare router no longer
  imports `routes/signedDelegate`, `RouterApiOptions` no longer carries
  `signedDelegate`, and route surfaces derive `signedDelegatePath` from
  declared extension routes.
- Finished the Phase 2 `RouterApiOptions` split for the signer Router API.
  Removed dead top-level sponsorship and observability-ingestion options,
  replaced the console webhook service type with the signer-owned
  `RouterApiWebhookEmitter` port, and burned down the `routerApi.ts`
  signer-console import guard allowlist entries.
- Validation:
  - `pnpm -C tests run check:signer-console-module-boundaries`
  - `pnpm -C packages/sdk-server-ts run build`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/sponsorship.staticPricing.unit.test.ts unit/sponsorship.realPricing.unit.test.ts unit/sponsorship.evmRelayConfig.unit.test.ts unit/cloudflareD1ConsoleServices.unit.test.ts relayer/console-d1-adapters.test.ts`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/cloudflareD1ConsoleServices.unit.test.ts unit/relayWalletRegistration.boundary.unit.test.ts unit/router.sponsoredEvmCallCloudflare.unit.test.ts unit/router.routerApiRouteSurface.unit.test.ts`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/router.routeDefinitions.unit.test.ts unit/router.routerApiRouteSurface.unit.test.ts unit/cloudflareD1ConsoleServices.unit.test.ts unit/cloudflareSelfHostedSigningWorker.script.unit.test.ts`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/router.routeDefinitions.unit.test.ts unit/router.routerApiRouteSurface.unit.test.ts unit/router.sponsoredEvmCallCloudflare.unit.test.ts unit/cloudflareD1ConsoleServices.unit.test.ts unit/cloudflareSelfHostedSigningWorker.script.unit.test.ts`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/router.routerApiRouteSurface.unit.test.ts unit/router.sponsoredEvmCallCloudflare.unit.test.ts unit/cloudflareD1ConsoleServices.unit.test.ts relayer/console-d1-adapters.test.ts`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/router.routerApiRouteSurface.unit.test.ts unit/router.routeDefinitions.unit.test.ts unit/cloudflareSelfHostedSigningWorker.script.unit.test.ts`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/router.routeDefinitions.unit.test.ts unit/router.routerApiRouteSurface.unit.test.ts unit/cloudflareSelfHostedSigningWorker.script.unit.test.ts unit/router.sponsoredEvmCallCloudflare.unit.test.ts unit/cloudflareD1ConsoleServices.unit.test.ts`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/router.routerApiRouteSurface.unit.test.ts`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/cloudflareD1ConsoleServices.unit.test.ts unit/router.routerApiRouteSurface.unit.test.ts`
