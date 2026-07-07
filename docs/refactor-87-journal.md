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
- Completed the Phase 4 B6 entrypoint split slice. The root package barrel no
  longer exports console modules, the console barrel is isolated from the root
  export surface, and Phase 6 moved it to
  `packages/console-server-ts/src/index.ts`.
- Completed the Phase 4 B7 env-type split. Cloudflare Worker env types now
  separate signer variables, console variables, signer D1/DO bindings, console
  D1 bindings, and the composition intersections.
- Completed the Phase 5 B9 console-constant split. Console-owned shared
  constants now live in `packages/console-shared-ts` as
  `@seams-internal/console-shared`; `@seams-internal/shared-ts` no longer
  exports or contains a `console` subtree.
- Updated server, site, and test imports to consume console constants from the
  new console-owned shared package.
- Added package export contracts for the new console shared package and for
  removal of the old `shared-ts` console export surface.
- Completed Phase 6 by creating `packages/console-server-ts` as
  `@seams-internal/console-server` and moving console services, console router
  assembly, console route extensions, Cloudflare console workers, B10
  composition harnesses, `CONSOLE_DB` migrations, Wrangler configs, D1 scripts,
  and console dev vars into the package.
- Removed the interim `@seams/sdk-server/console` export and trimmed signer
  router adapters back to signer-only exports. The console package now owns
  `router/express-adaptor`, `router/cloudflare-adaptor`, and console
  Cloudflare env/composition types.
- Added the private `@seams/sdk-server/internal/*` subpath so the closed
  console package can consume signer internals needed for composition without
  restoring console code to the signer package.
- Updated D1 operational docs, web-server imports, source guards, package
  export contracts, staging script fixtures, and package install smoke tests
  for the new console package home.
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
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/packageExports.contract.unit.test.ts unit/sdkPackageInstallSmoke.unit.test.ts`
  - `pnpm install --ignore-scripts`
  - `pnpm -C packages/console-shared-ts run type-check`
  - `pnpm -C packages/shared-ts run type-check`
  - `pnpm -C packages/sdk-server-ts run build`
  - `pnpm -C packages/sdk-server-ts run type-check`
  - `pnpm -C packages/console-server-ts run type-check`
  - `pnpm -C packages/console-server-ts run build`
  - `pnpm -C apps/web-server run build`
  - `pnpm -C tests run check:signer-console-module-boundaries`
  - `pnpm -C tests run check:workspace-package-boundaries`
  - `pnpm -C tests run check:cloudflare-d1-runtime-boundaries`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/packageExports.contract.unit.test.ts unit/sdkPackageInstallSmoke.unit.test.ts`
  - `pnpm -C apps/seams-site typecheck`
  - `pnpm -C tests exec playwright test -c playwright.unit.config.ts --reporter=line unit/packageExports.contract.unit.test.ts unit/sdkPackageInstallSmoke.unit.test.ts unit/sponsorship.staticPricing.unit.test.ts unit/sponsorship.realPricing.unit.test.ts`
  - `VITE_CACHE_DIR=/tmp/seams-vite-cache-ref87-phase5-e2e W3A_TEST_FRONTEND_URL=http://127.0.0.1:5197 pnpm -C tests exec playwright test --reporter=line e2e/dashboard.webhooks.apiWiring.test.ts e2e/dashboard.consoleConfigPages.apiWiring.test.ts -g "dashboard webhooks|gas sponsorship page wires create|credentials page supports"`
