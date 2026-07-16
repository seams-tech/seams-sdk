#!/usr/bin/env node

import assert from 'node:assert/strict';

function test(_name, fn) {
  fn();
}

function expect(actual, message) {
  return {
    toEqual(expected) {
      assert.deepEqual(actual, expected, message);
    },
    toContain(expected) {
      assert.ok(
        actual.includes(expected),
        message ?? `expected value to contain ${String(expected)}`,
      );
    },
    not: {
      toContain(expected) {
        assert.ok(
          !actual.includes(expected),
          message ?? `expected value not to contain ${String(expected)}`,
        );
      },
    },
  };
}

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ts from 'typescript';
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const standaloneCheckerPath = 'tests/scripts/check-cloudflare-d1-runtime-boundaries.mjs';
const cloudflareRuntimeRoots = [
    'packages/sdk-server-ts/src/router/cloudflare-adaptor.ts',
    ...listTypeScriptFiles('packages/sdk-server-ts/src/router/cloudflare'),
].filter(isRuntimeSourceFile);
const routerAbLocalDevScriptRoot = 'crates/router-ab-dev/scripts';
const ciWorkflowPath = '.github/workflows/ci.yml';
const gitignorePath = '.gitignore';
const refactor82PlanPath = 'docs/refactor-82-cloudflare-D1-migration.md';
const sdkServerReadmePath = 'packages/console-server-ts/README.md';
const sdkServerTsconfigPath = 'packages/sdk-server-ts/tsconfig.json';
const webServerPackagePath = 'apps/web-server/package.json';
const accountSettingsDocPath = 'docs/saas/account-settings.md';
const apiKeysDocPath = 'docs/saas/api-keys.md';
const billingCleanupDocPath = 'docs/saas/billing-cleanup.md';
const consoleOnboardingDocPath = 'docs/saas/console-onboarding.md';
const currentBillingDocPaths = ['docs/saas/billing-2.md', 'docs/saas/prepaid-billing.md'];
const dbSchemaDocPath = 'docs/saas/db-schema.md';
const dashboardBackendImplementationDocPath = 'docs/saas/dashboard-backend-implementation-plan.md';
const policyIdDocPath = 'docs/saas/policyId.md';
const generalizedGasSponsorshipDocPath = 'docs/saas/generalized-gas-sponsorship.md';
const gasSponsorshipPrepaidDocPath = 'docs/saas/gas-sponsorship-prepaid-balances.md';
const gasAndSigningPoliciesDocPath = 'docs/saas/gas-and-signing-policies.md';
const policyEngineDocPath = 'docs/saas/policy-engine.md';
const policyDraftsDocPath = 'docs/saas/policy-drafts.md';
const professionalizeDocPath = 'docs/saas/professionalize.md';
const sponsorshipPolicyDocPath = 'docs/sponsorship-policy.md';
const observabilityDocPaths = [
    'docs/saas/observability-events-3.md',
    'docs/saas/observability-events-4.md',
];
const authServicePath = 'packages/sdk-server-ts/src/core/AuthService.ts';
const walletRegistrationRoutesPath = 'packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts';
const syncAccountRequestValidationPath = 'packages/sdk-server-ts/src/router/syncAccountRequestValidation.ts';
const authServicePortPath = 'packages/sdk-server-ts/src/router/authServicePort.ts';
const authServiceWebAuthnPath = 'packages/sdk-server-ts/src/core/authService/webauthn.ts';
const d1WebAuthnAuthServicePath = 'packages/sdk-server-ts/src/router/cloudflare/d1WebAuthnAuthService.ts';
const sdkWebSyncAccountPath = 'packages/sdk-web/src/SeamsWeb/operations/recovery/syncAccount.ts';
const sdkServerCoreTypesPath = 'packages/sdk-server-ts/src/core/types.ts';
const routeDefinitionsPath = 'packages/sdk-server-ts/src/router/routeDefinitions.ts';
const routeExecutionContextPath = 'packages/sdk-server-ts/src/router/routeExecutionContext.ts';
const d1RegistrationIntentServicePath = 'packages/sdk-server-ts/src/router/cloudflare/d1RegistrationIntentService.ts';
const d1WalletRegistrationServicePath = 'packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts';
const d1RegistrationCeremonyRecordsPath = 'packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords.ts';
const d1RegistrationCeremonyStorePath = 'packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyStore.ts';
const d1RegistrationCeremonyDoPath = 'packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyDo.ts';
const forbiddenCloudflarePostgresEnvTokens = [
    'POSTGRES_URL',
    'CONSOLE_POSTGRES_URL',
    'POSTGRES_MIGRATION_URL',
    'CONSOLE_POSTGRES_MIGRATION_URL',
    'BILLING_POSTGRES_URL',
    'RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL',
    'WEBHOOK_RETRY_POSTGRES_URL',
];
const forbiddenCloudflareD1EnvPricingPatterns = [
    {
        pattern: /\bSPONSORED_EXECUTION_(?:STATIC|REAL)_PRICING_JSON\b/,
        message: 'reads sponsored execution pricing from Worker env instead of Console D1',
    },
    {
        pattern: /\bresolve(?:Static|CoinGecko|Sponsored)SponsoredExecutionPricingFromEnv\b/,
        message: 'constructs sponsored execution pricing from Worker env instead of Console D1',
    },
];
const legacyRouteCapabilityFlagPatterns = [
    {
        pattern: /\bemailRecovery\s*:\s*\{\s*enabled\b/,
        message: 'uses the old emailRecovery enabled flag instead of structural route services',
    },
    {
        pattern: /\bed25519RegistrationPrepare\b/,
        message: 'uses the old separate Ed25519 registration prepare route capability',
    },
    {
        pattern: /\bsigningSessionSeal\s*:\s*\{[^}]*\benabled\b/s,
        message: 'uses the old signingSessionSeal enabled flag instead of structural route services',
    },
];
const forbiddenRouterAbLocalPostgresPatterns = [
    {
        pattern: /\bPOSTGRES_URL\b/,
        message: 'uses POSTGRES_URL instead of current SQLite/D1/DO local seed tooling',
    },
    {
        pattern: /\bthreshold_ed25519_keys\b/,
        message: 'writes the removed partial Postgres Ed25519 key-store table',
    },
    {
        pattern: /\bthreshold_wallet_session_(?:budget_reservations|consumptions)\b/,
        message: 'writes the removed partial Postgres wallet-session tables',
    },
];
const forbiddenCiPostgresPatterns = [
    {
        pattern: /\brelay-server-postgres-split-smoke\b/,
        message: 'defines the removed split-domain Postgres smoke job',
    },
    {
        pattern: /\bpostgres:setup:split\b/,
        message: 'runs the removed web-server Postgres setup script',
    },
    {
        pattern: /\bpostgres:down\b/,
        message: 'runs the removed web-server Postgres teardown script',
    },
    {
        pattern: /\bPOSTGRES_URL\b/,
        message: 'exports Postgres env for current CI jobs',
    },
    {
        pattern: /\bCONSOLE_POSTGRES_URL\b/,
        message: 'exports console Postgres env for current CI jobs',
    },
    {
        pattern: /\bpostgres:\s*\n\s*image:\s*postgres:/,
        message: 'starts a Postgres service for current CI jobs',
    },
];
const deletedWebServerPostgresToolingPaths = [
    'apps/web-server/docker-compose.postgres.yml',
    'apps/web-server/scripts/postgres-bootstrap-split-domains.mjs',
    'apps/web-server/scripts/postgres-down.mjs',
    'apps/web-server/scripts/postgres-migrate-console.mjs',
    'apps/web-server/scripts/postgres-migrate-monolith-to-split.mjs',
    'apps/web-server/scripts/postgres-migrate-signer.mjs',
    'apps/web-server/scripts/postgres-up.mjs',
    'apps/web-server/scripts/postgres-verify-split-domains.mjs',
];
const forbiddenSdkServerTsconfigPostgresPatterns = [
    {
        pattern: /"pg"/,
        message: 'adds pg to sdk-server TypeScript ambient types or path aliases',
    },
    {
        pattern: /@types\/pg/,
        message: 'resolves the removed pg type package from sdk-server TypeScript config',
    },
];
const staleBillingCleanupValidationPatterns = [
    {
        pattern: /\bserver\/src\b/,
        message: 'references the old server/src tree instead of packages/sdk-server-ts/src',
    },
    {
        pattern: /\bexamples\/seams-site\b/,
        message: 'references the old examples/seams-site tree instead of apps/seams-site',
    },
    {
        pattern: /\bconsole-billing\.postgres\.test\.ts\b/,
        message: 'references the deleted live-Postgres console billing relayer suite',
    },
    {
        pattern: /\bconsole-tenant-isolation\.postgres\.test\.ts\b/,
        message: 'references the deleted live-Postgres tenant isolation relayer suite',
    },
    {
        pattern: /\bconsole-config-modules\.postgres\.test\.ts\b/,
        message: 'references the deleted live-Postgres console config relayer suite',
    },
    {
        pattern: /\brelay-api-keys\.test\.ts\b/,
        message: 'references the old Router API key test filename',
    },
    {
        pattern: /\bPostgres tests no longer clean up\b/,
        message: 'describes current billing cleanup validation as Postgres tests',
    },
];
const staleAccountSettingsDocPatterns = [
    {
        pattern: /\bserver\/src\/console\/account\b/,
        message: 'references the old server account module path',
    },
    {
        pattern: /\bpostgres\.ts\b/,
        message: 'references the deleted account Postgres adapter',
    },
    {
        pattern: /\baccount Postgres slice\b/,
        message: 'describes the current account adapter as Postgres-backed',
    },
    {
        pattern: /\bconsole_(?:organizations|user_profiles|user_backup_emails)\b/,
        message: 'uses old console-prefixed account D1 table names',
    },
    {
        pattern: /\bconsole_org_user_index\b/,
        message: 'uses an old console-prefixed account organization index name',
    },
];
const staleD1SchemaDocPatterns = [
    {
        pattern: /\bconsole_(?:organizations|user_profiles|user_backup_emails)\b/,
        message: 'uses old console-prefixed account D1 table names',
    },
    {
        pattern: /\bconsole_(?:team_members|approvals|audit_events|audit_evidence|runtime_snapshot_outbox)\b/,
        message: 'uses old console-prefixed D1 table names for current dashboard storage',
    },
    {
        pattern: /\bapp\.console_(?:namespace|org_id)\b/,
        message: 'describes removed Postgres tenant context primitives',
    },
    {
        pattern: /\bUse the same Postgres cluster\/instance\b/,
        message: 'keeps the pre-Refactor 82 Postgres topology as the current default',
    },
    {
        pattern: /\btransaction-scoped Postgres\b/,
        message: 'describes tenant scoping as Postgres-client wiring',
    },
    {
        pattern: /\bRLS\b/,
        message: 'describes current D1 tenant isolation as Postgres RLS',
    },
    {
        pattern: /\bRLS policy enforcement\b/,
        message: 'describes current tenant isolation as Postgres RLS',
    },
    {
        pattern: /\bDB-level tenant context variables\b/,
        message: 'describes current D1 tenant isolation as DB-level Postgres context',
    },
    {
        pattern: /\bFORCE-RLS\b/,
        message: 'describes current billing finalization as Force-RLS compatibility',
    },
    {
        pattern: /\bPostgres org isolation\b/,
        message: 'describes current dashboard route isolation as Postgres-backed',
    },
    {
        pattern: /\bPostgres billing services\b/,
        message: 'describes current billing coverage as Postgres-backed',
    },
    {
        pattern: /\bpostgresUrl\b/,
        message: 'describes current D1 cron job config as Postgres URL based',
    },
    {
        pattern: /\bin-memory \+ postgres service \+ router wiring\b/,
        message: 'describes current dashboard route services as Postgres-backed',
    },
    {
        pattern: /\brelay-server demo\b/,
        message: 'describes current local dashboard seed wiring with the old relay-server name',
    },
    {
        pattern: /\bactive relay-server Postgres automation\b/,
        message: 'describes removed web-server Postgres automation with the old relay-server name',
    },
    {
        pattern: /\badvisory-lock execution\b/,
        message: 'describes current D1 outbox dispatch as Postgres advisory locking',
    },
    {
        pattern: /\bDB-level policy tests\b/,
        message: 'describes current tenant-isolation coverage as DB-level Postgres policy tests',
    },
];
const staleD1ApiKeyDocPatterns = [
    {
        pattern: /\bconsole_api_keys\b/,
        message: 'uses the old console-prefixed api_keys table name',
    },
    {
        pattern: /\bconsole_api_key_auth_events\b/,
        message: 'describes an unimplemented console-prefixed API-key auth-event table',
    },
    {
        pattern: /\bconsole_bootstrap_tokens\b/,
        message: 'uses the old console-prefixed bootstrap_tokens table name',
    },
    {
        pattern: /\bconsole_onboarding_runs\b/,
        message: 'describes an unimplemented console-prefixed onboarding table',
    },
    {
        pattern: /\btenant-scoped with RLS\b/,
        message: 'describes D1 API-key tenant isolation as Postgres RLS',
    },
    {
        pattern: /\bPostgres persistence tests\b/,
        message: 'describes current API-key persistence coverage as Postgres-backed',
    },
    {
        pattern: /\bPostgres tests:\b/,
        message: 'describes current API-key persistence tests as Postgres tests',
    },
];
const staleConsoleOnboardingDocPatterns = [
    {
        pattern: /\bRLS\b/,
        message: 'describes current onboarding tenant isolation as Postgres RLS',
    },
    {
        pattern: /\bPostgres service\b/,
        message: 'describes current onboarding service coverage as Postgres-backed',
    },
];
const staleD1PolicyTableDocPatterns = [
    {
        pattern: /\bconsole_policies\b/,
        message: 'uses the old console-prefixed policies table name',
    },
    {
        pattern: /\bconsole_policy_versions\b/,
        message: 'uses the old console-prefixed policy_versions table name',
    },
    {
        pattern: /\bconsole_policy_assignments\b/,
        message: 'uses the old console-prefixed policy_assignments table name',
    },
    {
        pattern: /\bconsole_gas_sponsorship_configs\b/,
        message: 'references the removed standalone gas sponsorship config table',
    },
];
const staleCurrentBillingDocPatterns = [
    {
        pattern: /\/Users\/pta\/Dev\/rust\/simple-threshold-signer/,
        message: 'references the old simple-threshold-signer absolute workspace path',
    },
    {
        pattern: /\bPostgres billing\b/,
        message: 'describes the current billing path as Postgres billing',
    },
    {
        pattern: /\bPostgres validation and cleanup\b/,
        message: 'describes current billing validation as Postgres-specific',
    },
    {
        pattern: /\bPostgres org balance sync\b/,
        message: 'describes current org balance sync as Postgres-specific',
    },
    {
        pattern: /\bPostgres receipt\b/,
        message: 'describes current receipt projections as Postgres-specific',
    },
    {
        pattern: /\bPostgres invoice\b/,
        message: 'describes current invoice reads as Postgres-specific',
    },
    {
        pattern: /\bin the Postgres billing path\b/,
        message: 'describes current billing behavior as Postgres-specific',
    },
    {
        pattern: /\bThe Postgres billing path\b/,
        message: 'describes current billing behavior as Postgres-specific',
    },
    {
        pattern: /\bconsole_billing_ledger_accounts\b/,
        message: 'uses the old console-prefixed billing_accounts table name',
    },
    {
        pattern: /\bconsole_billing_ledger_entries\b/,
        message: 'uses the old console-prefixed billing_ledger_entries table name',
    },
    {
        pattern: /\bconsole_billing_ledger_postings\b/,
        message: 'uses the old console-prefixed billing_ledger_postings table name',
    },
    {
        pattern: /\bconsole_billing_account_balances\b/,
        message: 'uses the old console-prefixed billing_accounts projection name',
    },
    {
        pattern: /\bconsole_billing_documents\b/,
        message: 'uses the old console-prefixed invoices table name',
    },
    {
        pattern: /\bconsole_billing_document_line_items\b/,
        message: 'uses the old console-prefixed invoice_line_items table name',
    },
    {
        pattern: /\bconsole_billing_activity_projection\b/,
        message: 'uses the old standalone billing activity projection table name',
    },
];
const staleGasSponsorshipPrepaidDocPatterns = [
    {
        pattern: /\/Users\/pta\/Dev\/rust\/simple-threshold-signer/,
        message: 'references the old simple-threshold-signer absolute workspace path',
    },
    {
        pattern: /\bserver\/src\/console\/(?:billing|billingPrepaidReservations|sponsoredCalls)\/postgres\.ts\b/,
        message: 'references removed server Postgres sponsorship or billing adapters',
    },
    {
        pattern: /\bshared Postgres billing\/prepaid\/sponsored-call services\b/,
        message: 'describes sponsored settlement as backed by shared Postgres services',
    },
    {
        pattern: /\bshared Postgres runtime for settlement\b/,
        message: 'describes sponsored settlement as requiring a shared Postgres runtime',
    },
    {
        pattern: /\bsupporting Postgres indexes\b/,
        message: 'describes current sponsorship history indexes as Postgres indexes',
    },
    {
        pattern: /\batomic Postgres settlement contract\b/,
        message: 'describes current sponsorship tests as aligned to Postgres settlement',
    },
    {
        pattern: /\bconsole_sponsored_call_records\b/,
        message: 'uses the old console-prefixed sponsored_call_records table name',
    },
];
const staleGeneralizedGasSponsorshipDocPatterns = [
    {
        pattern: /\/Users\/pta\/Dev\/rust\/simple-threshold-signer/,
        message: 'references the old simple-threshold-signer absolute workspace path',
    },
    {
        pattern: /(^|[\s([`])server\/src\b/,
        message: 'references the old server/src tree instead of packages/sdk-server-ts/src',
    },
    {
        pattern: /\bexamples\/seams-site\b/,
        message: 'references the old examples/seams-site tree instead of apps/seams-site',
    },
    {
        pattern: /\bexamples\/relay-server\b/,
        message: 'references the old examples/relay-server tree instead of apps/web-server',
    },
    {
        pattern: /\brelaySponsoredEvmCall\.ts\b/,
        message: 'references the deleted sponsored EVM relay route filename',
    },
    {
        pattern: /\brelaySignedDelegate\.ts\b/,
        message: 'references the deleted signed delegate relay route filename',
    },
    {
        pattern: /\b(?:web|relay)-packages\/sdk-server-ts\b/,
        message: 'contains a bad chained path replacement from the old relay-server path',
    },
    {
        pattern: /\bpostgres\.ts\b/,
        message: 'references deleted Postgres sponsorship adapter files',
    },
];
const staleGasAndSigningPoliciesDocPatterns = [
    {
        pattern: /\/Users\/pta\/Dev\/rust\/simple-threshold-signer/,
        message: 'references the old simple-threshold-signer absolute workspace path',
    },
    {
        pattern: /\]\(.*\bserver\/src\//,
        message: 'links to the old server/src tree instead of packages/sdk-server-ts/src',
    },
    {
        pattern: /\]\(.*\bexamples\/seams-site\//,
        message: 'links to the old examples/seams-site tree instead of apps/seams-site',
    },
];
const stalePolicyEngineDocPatterns = [
    {
        pattern: /\/Users\/pta\/Dev\/rust\/simple-threshold-signer/,
        message: 'references the old simple-threshold-signer absolute workspace path',
    },
    {
        pattern: /\]\(.*\bserver\/src\//,
        message: 'links to the old server/src tree instead of packages/sdk-server-ts/src',
    },
    {
        pattern: /\]\(.*\bexamples\/seams-site\//,
        message: 'links to the old examples/seams-site tree instead of apps/seams-site',
    },
    {
        pattern: /\bPostgres storage for policies\b/,
        message: 'describes current policy storage as Postgres-backed',
    },
    {
        pattern: /\bPostgres policy services\b/,
        message: 'describes current policy service parity as Postgres-backed',
    },
    {
        pattern: /\bPostgres namespace split\b/,
        message: 'describes current example policy stack as Postgres-backed',
    },
    {
        pattern: /\bin-memory and Postgres services\b/,
        message: 'describes current policy service sharing as Postgres-backed',
    },
    {
        pattern: /\bmemory versus Postgres services\b/,
        message: 'describes current policy evaluator duplication as Postgres-backed',
    },
    {
        pattern: /\bexample relay\b/,
        message: 'describes current local Router API wiring with the old example-relay name',
    },
    {
        pattern: /\bserver\/src\/console\/(?:policies|gasSponsorship)\/postgres\.ts\b/,
        message: 'references deleted policy or gas-sponsorship Postgres adapters',
    },
];
const staleSponsorshipPolicyDocPatterns = [
    {
        pattern: /\/Users\/pta\/Dev\/rust\/simple-threshold-signer/,
        message: 'references the old simple-threshold-signer absolute workspace path',
    },
    {
        pattern: /\]\(.*\bserver\/src\//,
        message: 'links to the old server/src tree instead of packages/sdk-server-ts/src',
    },
    {
        pattern: /\]\(.*\bexamples\/seams-site\//,
        message: 'links to the old examples/seams-site tree instead of apps/seams-site',
    },
];
const staleObservabilityDocPatterns = [
    {
        pattern: /\bserver\/src\b/,
        message: 'references the old server/src tree instead of packages/sdk-server-ts/src',
    },
    {
        pattern: /\bexamples\/seams-site\b/,
        message: 'references the old examples/seams-site tree instead of apps/seams-site',
    },
    {
        pattern: /\bpostgres\.ts\b/,
        message: 'references deleted Postgres observability adapter files',
    },
    {
        pattern: /\bconsole_observability_(?:events|event_dedup|ingest_windows|request_rollups_minute)\b/,
        message: 'uses old console-prefixed observability table names instead of D1 names',
    },
];
const staleSaasFrontendDocPatterns = [
    {
        pattern: /\bexamples\/seams-site\b/,
        message: 'references the old examples/seams-site tree instead of apps/seams-site',
    },
    {
        pattern: /\bsrc\/\.vitepress\/config\.ts\b/,
        message: 'references the removed VitePress site config instead of the React app router',
    },
];
const sharedD1HelperPath = 'packages/sdk-server-ts/src/storage/d1Sql.ts';
const sharedSqliteD1TestHelperPath = 'tests/helpers/sqliteD1.ts';
const cloudflareD1ConsoleServicesPath = 'packages/console-server-ts/src/router/cloudflare/d1ConsoleServices.ts';
const cloudflareD1ConsoleStagingWorkerPath = 'packages/console-server-ts/src/router/cloudflare/d1ConsoleStagingWorker.ts';
const cloudflareD1LocalDevWorkerPath = 'packages/console-server-ts/src/router/cloudflare/d1LocalDevWorker.ts';
const cloudflareD1RouterApiStagingWorkerPath = 'packages/console-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts';
const cloudflareD1RouterApiAuthServicePath = 'packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService.ts';
const cloudflareD1EmailOtpRecoveryServicePath = 'packages/sdk-server-ts/src/router/cloudflare/d1EmailOtpRecoveryService.ts';
const authServiceEmailOtpGrantPath = 'packages/sdk-server-ts/src/core/authService/emailOtpGrant.ts';
const authServiceEmailOtpRecoveryKeysPath = 'packages/sdk-server-ts/src/core/authService/emailOtpRecoveryKeys.ts';
const oldCloudflareD1RelayStagingWorkerPath = 'packages/sdk-server-ts/src/router/cloudflare/d1RelayStagingWorker.ts';
const oldRelayApiKeysTestPath = 'tests/relayer/relay-api-keys.test.ts';
const oldRouterApiHarnessScriptPaths = [
    'tests/scripts/provision-relay-server.mjs',
    'tests/scripts/test-relay-server.mjs',
];
const oldWebServerTestPaths = [
    'tests/unit/relayServer.consoleConfig.unit.test.ts',
    'tests/unit/relayServer.stripeBillingProvider.unit.test.ts',
];
const oldEmailEncryptionOutlayerCompatTestPath = 'tests/unit/emailEncryptionOutlayerCompat.test.ts';
const oldExpressTypeShimPath = 'packages/sdk-server-ts/src/router/express-shim.d.ts';
const deletedDuplicateTestSetupMockPaths = [
    'tests/setup/route-mocks.ts',
    'tests/setup/intercepts.ts',
];
const routerApiProxyShimTextPaths = [
    'tests/setup/cross-origin-headers.ts',
    'tests/setup/bootstrap.ts',
];
const activeRouterApiTextPaths = [
    'apps/web-server/.env.example',
    'apps/web-server/README.md',
    'apps/web-server/package.json',
    'apps/web-server/src/jwtSession.ts',
    'apps/web-server/scripts/ensure-bun.mjs',
    'docs/chats/chat-6-voiceId.md',
    'docs/deployment/infra.md',
    'docs/registrations-top-up.md',
    'docs/refactor-90-modular-auth-capabilities-SPEC.md',
    'docs/auth-provider-integrations/auth0.md',
    'docs/auth-provider-integrations/better-auth.md',
    'docs/auth-provider-integrations/google-oidc.md',
    'docs/auth-provider-integrations/okta.md',
    'docs/auth-provider-integrations/quickstarts-clerk-supabase-firebase.md',
    'packages/sdk-server-ts/src/README.md',
    'packages/console-server-ts/README.md',
    'packages/sdk-web/README.md',
    'tests/README.md',
    'packages/sdk-server-ts/src/core/routerAbSigning/createCloudflareDurableObjectRouterAbSigningRuntimes.ts',
    'packages/sdk-server-ts/src/core/defaultConfigsServer.ts',
    'packages/console-server-ts/src/router/cloudflare/d1ConsoleServices.ts',
    'packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyStore.ts',
    'packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthConfig.ts',
    'packages/sdk-server-ts/src/router/cloudflare/d1RouterAbSigningRuntime.ts',
    'docs/saas/bring-you-own-auth.md',
    'tests/unit/cloudflareD1ConsoleServices.unit.test.ts',
    'tests/unit/cloudflareD1RouterApiEmailOtp.unit.test.ts',
    'tests/unit/cloudflareD1RouterApiOidc.unit.test.ts',
    'tests/unit/cloudflareD1RouterApiRegistrationCeremony.unit.test.ts',
    'tests/unit/cloudflareD1RouterApiServiceSurface.unit.test.ts',
    'tests/unit/cloudflareD1RouterApiWalletAuthMethods.unit.test.ts',
    'tests/unit/helpers/cloudflareD1RouterApiAuthService.fixtures.ts',
    'voiceId/README.md',
    'voiceId/docs/voiceId-mvp-1-tasks.md',
    'packages/console-server-ts/wrangler.d1-staging-console.toml.example',
    'packages/console-server-ts/wrangler.d1-staging-router-api.toml.example',
    'wasm/near_signer/src/types/signing.rs',
    apiKeysDocPath,
    'tests/package.json',
];
const staleRouterApiRenameTokens = [
    'RelayRouterOptions',
    'RelayApiKey',
    'RelayPublishableKey',
    'RelayBootstrapGrant',
    'RelayRouteSurface',
    'RelayRouteExtension',
    'RelayRouterModule',
    'CloudflareRelayContext',
    'ExpressRelayContext',
    'CloudflareRelayAuthService',
    'createRelayRouter',
    'createRelayApiKeyAuthAdapter',
    'createRelayBootstrapGrantBroker',
    'd1RelayStagingWorker',
    'sdkRelayExtension',
    'Cloudflare D1 relay auth service',
    'Cloudflare D1 relay registration intents',
    'Cloudflare D1 relay thresholdStore',
    'D1 relay bootstrapGrantTokenTtlMs',
    'D1 relay storage options',
    'relay API-key',
    'relay API key',
    'Relay API-key',
    'Relay API key',
    'relay-server.example.com',
    'relay-server.localhost',
    'relay_worker_deployment_status',
    'relay_worker',
    'relay deployments status',
    'relay-worker',
    'relay.example.com',
    'JWT_ISSUER=relay-server',
    'JWT_ISSUER=relay',
    "issuer: process.env.JWT_ISSUER || 'relay'",
    'dev-relay-jwt-secret',
    'Local relay process',
    'compatible adapter',
    "SDK's legacy prefix defaults",
    'not legacy `code_source`',
    "compatible with the SDK's threshold store protocol",
    'Outlayer compat tests',
    'emailEncryptionOutlayerCompat',
    'Email encryption compatibility with Outlayer worker seed',
    'email encryption Outlayer compat test unavailable',
    'gmail_reset_full.eml encryption compat test unavailable',
    'allowed by the relay',
    'served by the relay',
    'relay validates token audience',
    'on the relay',
    'multi-process relay fleet',
    'The relay prints',
    'The relay uses this secret',
    'The relay executes',
    'relay uses deterministic',
    'The relay verifies',
    'relayConfigPath',
    '--relay-config',
    'relayOrigin',
    '--relay-origin',
    'relayWorker',
    'relay_readyz',
    'relay_healthz',
    'relaySmokeCheckIds',
    'relayOriginFromSmoke',
    'defaultD1StagingRelayConfigPath',
    'd1StagingRelayManifestArgDefaults',
    'normalizeConsoleRelayD1StagingConfig',
    'normalizeRelayD1StagingConfig',
    'normalizeConsoleRelayD1StagingOptions',
    'validD1RelayStagingConfig',
    'D1_STAGING_RELAY_ORIGIN',
    'wrangler.d1-staging-relay.toml',
    'wrangler.d1-staging-relay.toml.example',
    'wrangler.other-relay',
    'relayer server',
    'relay-worker-demo',
    'createRelaySession',
    'RELAY_BASE_URL',
    'RELAY_API_KEY_AUTH_ENABLED',
    'relay app sessions',
    '[relay][bootstrap-grants]',
    '[relay][webhooks]',
    '[relay][signed-delegate]',
    'relay][signed-delegate',
    'relay usage-meter',
    'relay-issued sessions',
    'relayer app session',
    'relayer expects',
    'relayer for a challenge',
    'relayer validates',
    'relay registration',
    'prepared on the relay',
    'prepared relay state',
    'relay metadata',
    'relay verification',
    'relay publishable key auth',
    'relay ceremony step',
    'relay app session mint',
    'sent to the relay',
    'override relay URL',
    'must use relay surface',
    'VoiceIdRelayRouteDefinition',
    'voiceIdCapabilityRouteToRelayRouteDefinition',
    'voiceIdRelayRouteMetering',
    'RelayServerConsoleConfig',
    'resolveRelayServerConsoleConfig',
    'relayServerDir',
    'relayDotenvPath',
    '"name": "relay-server"',
    'imported from relay-server types',
    '[relay-server]',
    'relay-server console config',
    'relay-server stripe billing provider config',
    'relayServer.consoleConfig',
    'relayServer.stripeBillingProvider',
    'installRelayServerProxyShim',
    'relay proxy shim installed',
    'relay-proxy',
    'setupRelayServerTest',
    'setupRelayServerMock',
    'relay-server mocks',
    'relay-server (atomic)',
    'atomic relay-server flow',
    'Relay server / worker env',
    'Relay server failure injected',
    'relay-server (mock)',
    'real relay-server harness',
];
const staleRouterApiProxyShimTokens = [
    'installRelayServerProxyShim',
    'relayUrl?:',
    'relayBase',
    'relay mock',
    'Router server mock',
    "scope: 'relay'",
    'relayOrigin:',
    'relayUpstream:',
    'relay proxy shim installed',
    'relay-proxy',
];
const staleRouterApiHarnessTokens = [
    'provision-relay-server',
    'test-relay-server',
    'test:unit:relay-server-scripts',
    'examples/relay-server',
    'example relay server',
    'relay-server .env',
    'Start both relay-server',
    'Relay server not healthy',
    '[test-relay]',
];
const d1LocalBackupRestoreDrillScript = 'packages/console-server-ts/scripts/d1-local-backup-restore-drill.mjs';
const d1StagingManifestWriterScripts = [
    d1LocalBackupRestoreDrillScript,
    'packages/console-server-ts/scripts/d1-staging-fixture-import.mjs',
    'packages/console-server-ts/scripts/d1-staging-kek-check.mjs',
    'packages/console-server-ts/scripts/d1-staging-migrate.mjs',
    'packages/console-server-ts/scripts/d1-staging-r2-restore-drill.mjs',
    'packages/console-server-ts/scripts/d1-staging-reconciliation.mjs',
    'packages/console-server-ts/scripts/d1-staging-resource-inventory.mjs',
    'packages/console-server-ts/scripts/d1-staging-signer-custody.mjs',
    'packages/console-server-ts/scripts/d1-staging-smoke.mjs',
    'packages/console-server-ts/scripts/d1-staging-time-travel-bookmark.mjs',
];
const d1StagingSharedHelperPath = 'packages/console-server-ts/scripts/d1-staging-config.mjs';
const d1StagingCliHelperScripts = listJavaScriptFiles('packages/console-server-ts/scripts').filter((relativePath) => relativePath === d1LocalBackupRestoreDrillScript ||
    (path.basename(relativePath).startsWith('d1-staging-') &&
        relativePath !== d1StagingSharedHelperPath));
const publicRegistrationRequestConstructionFiles = [
    ...listTypeScriptLikeFiles('apps/seams-site/src'),
    'packages/sdk-web/src/SeamsWeb/SeamsWeb.ts',
    'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts',
    'packages/sdk-web/src/SeamsWeb/operations/evm/index.ts',
    'packages/sdk-web/src/SeamsWeb/operations/near/index.ts',
    'packages/sdk-web/src/SeamsWeb/operations/registration/registrationSignerSet.ts',
    'packages/sdk-web/src/SeamsWeb/publicInputs.typecheck.ts',
    'packages/sdk-web/src/SeamsWeb/walletIframe/SeamsWebIframe.ts',
];
const publicRegistrationTypeSurfaceFiles = [
    'packages/sdk-web/src/index.ts',
    'packages/sdk-web/src/react/index.ts',
    'packages/sdk-web/src/SeamsWeb/publicApi/types.ts',
    'packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts',
];
const removedRegistrationSignerSelectionFileBasename = `registrationSigner${'Selection'}`;
const registrationSignerFilenameScanRoots = [
    'packages/sdk-web/src/SeamsWeb/operations/registration',
    'tests/unit',
];
const forbiddenPublicRegistrationLegacySelectionTokens = [
    {
        token: "mode: 'ed25519_and_ecdsa'",
        message: 'constructs legacy combined registration signer selection',
    },
    {
        token: "mode: 'ed25519_only'",
        message: 'constructs legacy Ed25519-only registration signer selection',
    },
    {
        token: "mode: 'ecdsa_only'",
        message: 'constructs legacy ECDSA-only registration signer selection',
    },
    {
        token: 'combined_registration',
        message: 'constructs legacy combined-registration ceremony state',
    },
    {
        token: 'buildNearWalletRegistrationSignerSelection',
        message: 'uses the removed legacy registration signer-selection builder',
    },
    {
        token: 'registrationSignerSelectionForInternalState',
        message: 'converts signer-set registration requests back to legacy internal mode state',
    },
];
const forbiddenCloudflareRuntimeLegacyRegistrationTokens = [
    {
        pattern: /\bmode\s*(?::|={2,3})\s*['"]ed25519_and_ecdsa['"]/,
        message: 'uses legacy combined registration mode instead of signer-set branches',
    },
    {
        pattern: /\bmode\s*(?::|={2,3})\s*['"]ed25519_only['"]/,
        message: 'uses legacy Ed25519-only registration mode instead of signer-set branches',
    },
    {
        pattern: /\bmode\s*(?::|={2,3})\s*['"]ecdsa_only['"]/,
        message: 'uses legacy ECDSA-only registration mode instead of signer-set branches',
    },
    {
        token: 'combined_registration',
        message: 'uses removed combined-registration ceremony state',
    },
    {
        token: 'd1RegistrationIntentPasskeyRpId',
        message: 'revives passkey-only RP ID authority for generic Ed25519 registration',
    },
    {
        token: 'D1 registration intent rpId requires a passkey auth method',
        message: 'revives passkey-only RP ID validation for generic Ed25519 registration',
    },
    {
        token: 'for (const expectedKeyHandle of expectedKeyHandles)',
        message: 'revives all-equal ECDSA key-handle checking instead of allowlist matching',
    },
    {
        token: 'expectedKeyHandles.some((keyHandle) => keyHandle !==',
        message: 'revives all-equal ECDSA key-handle checking instead of allowlist matching',
    },
    {
        token: 'currently supports implicit NEAR accounts',
        message: 'revives the D1 finalize block against sponsored named NEAR accounts',
    },
];
const forbiddenAuthServiceLegacyRegistrationModeTokens = [
    {
        pattern: /\bmode\s*(?::|={2,3})\s*['"]ed25519_and_ecdsa['"]/,
        message: 'branches on legacy combined wallet-registration mode',
    },
    {
        pattern: /\bmode\s*(?::|={2,3})\s*['"]ed25519_only['"]/,
        message: 'branches on legacy Ed25519-only wallet-registration mode',
    },
    {
        pattern: /\bmode\s*(?::|={2,3})\s*['"]ecdsa_only['"]/,
        message: 'branches on legacy ECDSA-only wallet-registration mode',
    },
    {
        token: 'registrationIntentRpId(',
        message: 'revives passkey-only RP ID helper for generic Ed25519 registration',
    },
    {
        token: 'rpId: this.registrationIntentRpId',
        message: 'passes passkey-only RP ID into generic Ed25519 registration',
    },
    {
        token: 'expectedKeyHandles.some((keyHandle) => keyHandle !==',
        message: 'revives all-equal ECDSA key-handle checking instead of allowlist matching',
    },
];
const forbiddenRouterApiAuthServiceCouplingPatterns = [
    {
        pattern: /\bPick<AuthService\b/,
        message: 'derives Router API service ports from AuthService',
    },
    {
        pattern: /\bimport\s+type\s+\{\s*AuthService\s*\}\s+from\b/,
        message: 'imports AuthService into Router API source',
    },
    {
        pattern: /\bfrom ['"][^'"]*core\/AuthService['"]/,
        message: 'imports AuthService into Router API source',
    },
    {
        pattern: /\bCloudflareRouterApiAuthService\b/,
        message: 'uses the old Cloudflare-specific Router API port name',
    },
    {
        pattern: /\bRouterApiMethod(?:Input|Result|Handler)\b/,
        message: 'reintroduces generic Router API method helper aliases',
    },
];
const forbiddenRouterApiAuthServiceMountPatterns = [
    {
        pattern: /\bcreateRouterApiRouter\s*\(\s*authService\b/,
        message: 'mounts Router API routes with AuthService',
    },
    {
        pattern: /\bcreateCloudflareRouter\s*\(\s*authService\b/,
        message: 'mounts Cloudflare Router API routes with an AuthService variable',
    },
];
const deletedAuthServiceRouterApiHarnessPaths = [
    'tests/relayer/bootstrap-grants.test.ts',
    'tests/relayer/cloudflare-router.test.ts',
    'tests/relayer/console-api-key-kinds.test.ts',
    'tests/relayer/email-otp.authservice.test.ts',
    'tests/relayer/email-recovery.prepare.test.ts',
    'tests/relayer/email-otp.routes.test.ts',
    'tests/relayer/email-otp.bootstrap-integration.test.ts',
    'tests/relayer/health-wellknown.test.ts',
    'tests/relayer/login.challengeReplay.test.ts',
    'tests/relayer/router-ab-keyset-routes.test.ts',
    'tests/relayer/router-ab-normal-signing-auth-boundary.test.ts',
    'tests/relayer/router-api-keys.test.ts',
    'tests/relayer/signing-session-seal-router.test.ts',
    'tests/relayer/threshold-ecdsa.signature-harness.test.ts',
    'tests/relayer/threshold-ed25519.scheme-dispatch.test.ts',
];
const allowedAuthServiceConstructorPaths = new Set([
    'apps/web-server/src/index.ts',
    'tests/relayer/email-otp.shamir3pass.test.ts',
    'tests/relayer/oidc-exchange.authservice.test.ts',
    'tests/unit/authService.hostedAccountPrivacy.unit.test.ts',
]);
const forbiddenD1RouterApiAuthFacadePatterns = [
    {
        pattern: /\bCloudflareD1RouterApiAuthMetadataService\b/,
        message: 'revives the deleted monolithic D1 Router API auth implementation class',
    },
    {
        pattern: /\bclass\s+CloudflareD1RouterApiAuth\b/,
        message: 'implements the D1 Router API service bag through a monolithic class',
    },
    {
        pattern: /\bRouterApiMethod(?:Input|Result)\b/,
        message: 'uses generic Router API method aliases instead of concrete route/domain types',
    },
    {
        pattern: /^\s*async\s+(?:createRegistrationIntent|startWalletRegistration|prepareWalletRegistration|respondWalletRegistrationHss|finalizeWalletRegistration|createAddSignerIntent|startWalletAddSigner|respondWalletAddSignerHss|finalizeWalletAddSigner|createAddAuthMethodIntent|startWalletAddAuthMethod|finalizeWalletAddAuthMethod|createEmailOtpChallenge|verifyEmailOtpChallenge|createWebAuthnLoginOptions|verifyWebAuthnLogin)\s*\(/m,
        message: 'implements route-family methods as flat async facade methods',
    },
];
const forbiddenAuthServiceRouterApiLifecycleMethodPatterns = [
    /\basync\s+createRegistrationIntent\s*\(/,
    /\basync\s+createAddSignerIntent\s*\(/,
    /\basync\s+createAddAuthMethodIntent\s*\(/,
    /\basync\s+prepareWalletRegistration\s*\(/,
    /\basync\s+startWalletRegistration\s*\(/,
    /\basync\s+respondWalletRegistrationHss\s*\(/,
    /\basync\s+finalizeWalletRegistration\s*\(/,
    /\basync\s+startWalletAddSigner\s*\(/,
    /\basync\s+startWalletAddAuthMethod\s*\(/,
    /\basync\s+finalizeWalletAddAuthMethod\s*\(/,
    /\basync\s+finalizeWalletAddSigner\s*\(/,
];
const forbiddenProductionCombinedRegistrationTokens = [
    {
        token: 'combined_registration',
        message: 'revives the removed combined-registration ceremony state',
    },
];
const forbiddenLocalD1HelperPatterns = [
    {
        pattern: /\bfunction\s+parseD1RecordJson\b/,
        message: 'defines a local D1 JSON record parser instead of parseD1JsonColumn',
    },
    {
        pattern: /\bfunction\s+(?:d1Changes|toD1Changes|runChanges|changedRows)\b/,
        message: 'defines a local D1 mutation-count helper instead of d1ChangedRows',
    },
    {
        pattern: /\bfunction\s+(?:isD1DatabaseLike|resolveD1DatabaseFromConfig)\b/,
        message: 'defines a local D1 database resolver instead of the shared d1Sql helper',
    },
];
const forbiddenSqliteD1HarnessDuplicationPatterns = [
    {
        pattern: /\bclass\s+SqliteCliD1Database\b/,
        message: 'defines a local SQLite-D1 database harness instead of tests/helpers/sqliteD1',
    },
    {
        pattern: /\bclass\s+SqliteCliD1PreparedStatement\b/,
        message: 'defines a local SQLite-D1 statement harness instead of tests/helpers/sqliteD1',
    },
    {
        pattern: /\bfunction\s+createTemporaryD1Database\b/,
        message: 'defines a local temporary D1 database helper instead of tests/helpers/sqliteD1',
    },
    {
        pattern: /\bfunction\s+cleanupTemporaryD1Database\b/,
        message: 'defines a local temporary D1 cleanup helper instead of tests/helpers/sqliteD1',
    },
    {
        pattern: /\bfunction\s+interpolateSql\b/,
        message: 'defines local D1 SQL interpolation instead of tests/helpers/sqliteD1',
    },
    {
        pattern: /\bspawnSync\(\s*['"]sqlite3['"]/,
        message: 'shells out to sqlite3 instead of using tests/helpers/sqliteD1',
    },
    {
        pattern: /\bfunction\s+applyMigrations\b/,
        message: 'defines a local D1 migration applicator instead of tests/helpers/sqliteD1',
    },
    {
        pattern: /packages\/sdk-server-ts\/migrations\/d1-/,
        message: 'hard-codes D1 migration paths instead of using tests/helpers/sqliteD1',
    },
];
const forbiddenD1StagingCliHelperPatterns = [
    {
        pattern: /\bfunction\s+requireNextArg\b/,
        message: 'defines local argument parsing instead of d1-staging-config',
    },
    {
        pattern: /\bspawnSync\s*\(/,
        message: 'defines local command execution instead of d1-staging-config',
    },
    {
        pattern: /\bfor\s*\(\s*let\s+index\s*=\s*0;\s*index\s*<\s*args\.length\b/,
        message: 'defines a local D1 script CLI parse loop instead of parseFlagArgs',
    },
    {
        pattern: /\bfunction\s+(?:resolvePackagePath|resolveRepoPath)\b/,
        message: 'defines local path resolution instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+(?:requirePackagePath|resolveRequiredPackagePath|requirePath|normalizePath)\b/,
        message: 'defines local required path resolution instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+relativeToPackage\b/,
        message: 'defines local package-relative formatting instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+resolveManifestPath\b/,
        message: 'defines local manifest-output resolution instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+normalizeMode\b/,
        message: 'defines local staging mode parsing instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+readinessFailureMessage\b/,
        message: 'defines local readiness error formatting instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+isDirectInvocation\b/,
        message: 'defines local direct-invocation detection instead of d1-staging-config',
    },
    {
        pattern: /\bfileURLToPath\b/,
        message: 'imports fileURLToPath only for local direct-invocation detection',
    },
    {
        pattern: /\bfunction\s+normalizeIso\b/,
        message: 'defines local ISO timestamp parsing instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+normalizeGeneratedAtIso\b/,
        message: 'defines local generated-at parsing instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+(?:stampFromIso|compactIsoStamp)\b/,
        message: 'defines local ISO stamp formatting instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+wranglerCommand\b/,
        message: 'defines local Wrangler command formatting instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+(?:r2Command|wranglerR2Command)\b/,
        message: 'defines local Wrangler R2 command formatting instead of d1-staging-config',
    },
    {
        pattern: /pnpm --dir packages\/sdk-server-ts exec wrangler/,
        message: 'formats Wrangler package commands outside d1-staging-config',
    },
    {
        pattern: /\bfunction\s+(?:collectReadinessChecks|collectReadinessErrors|runReadinessCheck)\b/,
        message: 'defines local staging readiness collection instead of d1-staging-readiness-check',
    },
    {
        pattern: /\bfunction\s+print[A-Za-z]+Result\b/,
        message: 'defines local staging result printing instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+(?:executeSmokeEndpoint|executeJsonEndpoint|fetchWithTimeout|abortFetch|readJsonBody|assertJsonEndpointResponse|assertSmokeResponse|assertJsonField|isJsonRecord)\b/,
        message: 'defines local staging JSON endpoint plumbing instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+(?:normalizeOrigin|normalizeHttpsOrigin|normalizeTimeoutMs)\b/,
        message: 'defines local staging origin or timeout validation instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+normalizeR2Bucket\b/,
        message: 'defines local R2 bucket validation instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+sha256(?:String|File)\b/,
        message: 'defines local SHA-256 helpers instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+sqlString(?:List)?\b/,
        message: 'defines local SQL quoting helpers instead of d1-staging-config',
    },
    {
        pattern: /\bfunction\s+isRecord\b/,
        message: 'defines local JSON record detection instead of d1-staging-config',
    },
    {
        pattern: /\bconst\s+default(?:Console|RouterApi)ConfigPath\s*=\s*path\.join\(\s*packageRoot,\s*['"]wrangler\.d1-staging-(?:console|router-api)\.toml['"]\s*\)/,
        message: 'defines local staging Wrangler config defaults instead of d1-staging-config',
    },
    {
        pattern: /\bresolvePackagePath\(\s*input\.(?:console|routerApi)ConfigPath\b/,
        message: 'normalizes console/Router API config paths outside d1-staging-config',
    },
    {
        pattern: /console\.error\(error instanceof Error \? error\.message : String\(error\)\)/,
        message: 'formats CLI exceptions outside d1-staging-config',
    },
    {
        pattern: /parseFlagArgs\(\s*args,\s*\{\s*consoleConfigPath:\s*'',\s*environmentName:\s*'staging',\s*generatedAtIso:\s*'',\s*manifestPath:\s*'',\s*mode:\s*'dry-run',\s*routerApiConfigPath:\s*''/s,
        message: 'duplicates console/router-api manifest CLI defaults outside d1-staging-config',
    },
    {
        pattern: /parseFlagArgs\(\s*args,\s*\{\s*environmentName:\s*'staging',\s*generatedAtIso:\s*'',\s*manifestPath:\s*'',\s*mode:\s*'dry-run',\s*routerApiConfigPath:\s*''/s,
        message: 'duplicates router-api manifest CLI defaults outside d1-staging-config',
    },
    {
        pattern: /\bresolveManifestOutputPath\s*\(/,
        message: 'assembles stamped staging manifest output paths outside d1-staging-config',
    },
    {
        pattern: /\bmanifestStamp\(\s*options\.generatedAtIso\s*\)/,
        message: 'formats generated-at manifest filenames outside d1-staging-config',
    },
];
const forbiddenSdkServerPostgresRuntimePatterns = [
    {
        pattern: /\bfrom\s+['"]pg['"]/,
        message: 'imports pg at runtime',
    },
    {
        pattern: /\bimport\s*\(\s*['"]pg['"]\s*\)/,
        message: 'imports pg dynamically at runtime',
    },
    {
        pattern: /\bnew\s+Pool\b/,
        message: 'constructs a Postgres pool',
    },
    {
        pattern: /\bgetPostgresPool\b/,
        message: 'uses the removed Postgres pool helper',
    },
    {
        pattern: /\bcreatePostgres[A-Za-z0-9_]*Service\b/,
        message: 'exposes a live partial Postgres service factory',
    },
    {
        pattern: /\bpostgresRecords\b/,
        message: 'uses removed Postgres record helpers',
    },
];
const coreOrchestrationPortOnlyFiles = [
    'packages/sdk-server-ts/src/core/AuthService.ts',
    'packages/sdk-server-ts/src/core/SessionService.ts',
    'packages/sdk-server-ts/src/core/routerAbSigning/RouterAbNormalSigningRuntime.ts',
    'packages/sdk-server-ts/src/core/routerAbSigning/RouterAbEcdsaBootstrapExportRuntime.ts',
    'packages/sdk-server-ts/src/core/routerAbSigning/RouterAbEcdsaPresignRuntime.ts',
    'packages/sdk-server-ts/src/core/routerAbSigning/createRouterAbSigningRuntimes.ts',
    'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers.ts',
    'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPresignBridge.ts',
];
const forbiddenCoreOrchestrationPersistencePatterns = [
    {
        pattern: /\bfrom\s+['"](?:\.\.\/)+storage\//,
        message: 'imports storage-layer modules instead of domain-store ports',
    },
    {
        pattern: /\bD1(?:Database|PreparedStatement|Result)Like\b/,
        message: 'mentions raw D1 binding or statement types',
    },
    {
        pattern: /\bCloudflareDurableObject(?:Namespace|Stub)Like\b/,
        message: 'mentions raw Durable Object binding or stub types',
    },
    {
        pattern: /\bTenantStorageRoute\b/,
        message: 'depends on tenant-route resolution instead of injected domain stores',
    },
    {
        pattern: /\bresolveD1DatabaseFromConfig\b/,
        message: 'resolves D1 databases inside core orchestration',
    },
    {
        pattern: /\b(?:CONSOLE_DB|SIGNER_DB|THRESHOLD_STORE)\b/,
        message: 'mentions Cloudflare binding names inside core orchestration',
    },
    {
        pattern: /\.\s*(?:prepare|batch|exec)\s*\(/,
        message: 'calls raw database methods inside core orchestration',
    },
];
function isRuntimeSourceFile(relativePath) {
    return !relativePath.endsWith('.typecheck.ts');
}
function toRepoPath(absolutePath) {
    return path.relative(repoRoot, absolutePath).split(path.sep).join('/');
}
function toAbsolutePath(relativePath) {
    return path.join(repoRoot, relativePath);
}
function listTypeScriptFiles(relativeDir) {
    const absoluteDir = toAbsolutePath(relativeDir);
    const files = [];
    for (const entry of fs.readdirSync(absoluteDir, { withFileTypes: true })) {
        const relativePath = `${relativeDir}/${entry.name}`;
        if (entry.isDirectory()) {
            files.push(...listTypeScriptFiles(relativePath));
            continue;
        }
        if (entry.isFile() && entry.name.endsWith('.ts'))
            files.push(relativePath);
    }
    return files.sort();
}
function listTypeScriptLikeFiles(relativeDir) {
    const absoluteDir = toAbsolutePath(relativeDir);
    const files = [];
    for (const entry of fs.readdirSync(absoluteDir, { withFileTypes: true })) {
        const relativePath = `${relativeDir}/${entry.name}`;
        if (entry.isDirectory()) {
            files.push(...listTypeScriptLikeFiles(relativePath));
            continue;
        }
        if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx'))) {
            files.push(relativePath);
        }
    }
    return files.sort();
}
function listJavaScriptFiles(relativeDir) {
    const absoluteDir = toAbsolutePath(relativeDir);
    const files = [];
    for (const entry of fs.readdirSync(absoluteDir, { withFileTypes: true })) {
        const relativePath = `${relativeDir}/${entry.name}`;
        if (entry.isDirectory()) {
            files.push(...listJavaScriptFiles(relativePath));
            continue;
        }
        if (entry.isFile() && entry.name.endsWith('.mjs'))
            files.push(relativePath);
    }
    return files.sort();
}
function listRouterRuntimeFiles() {
    return listTypeScriptFiles('packages/sdk-server-ts/src/router').filter(isRuntimeSourceFile);
}
function readSource(relativePath) {
    return fs.readFileSync(toAbsolutePath(relativePath), 'utf8');
}
function parseSource(relativePath) {
    return ts.createSourceFile(relativePath, readSource(relativePath), ts.ScriptTarget.Latest, true);
}
function lineNumber(sourceFile, node) {
    return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
}
function importHasRuntimeBinding(node) {
    const clause = node.importClause;
    if (!clause)
        return true;
    if (clause.isTypeOnly)
        return false;
    if (clause.name)
        return true;
    const namedBindings = clause.namedBindings;
    if (!namedBindings)
        return true;
    if (ts.isNamespaceImport(namedBindings))
        return true;
    for (const element of namedBindings.elements) {
        if (!element.isTypeOnly)
            return true;
    }
    return false;
}
function exportHasRuntimeBinding(node) {
    if (node.isTypeOnly)
        return false;
    const clause = node.exportClause;
    if (!clause)
        return true;
    if (ts.isNamespaceExport(clause))
        return true;
    for (const element of clause.elements) {
        if (!element.isTypeOnly)
            return true;
    }
    return false;
}
function moduleSpecifierText(node) {
    const specifier = node.moduleSpecifier;
    if (!specifier || !ts.isStringLiteral(specifier))
        return null;
    return specifier.text;
}
function dynamicImportSpecifierText(node) {
    if (!ts.isCallExpression(node))
        return null;
    if (node.expression.kind !== ts.SyntaxKind.ImportKeyword)
        return null;
    const [specifier] = node.arguments;
    if (!specifier || !ts.isStringLiteral(specifier))
        return null;
    return specifier.text;
}
function runtimeDependencies(relativePath) {
    const sourceFile = parseSource(relativePath);
    const deps = [];
    for (const statement of sourceFile.statements) {
        if (ts.isImportDeclaration(statement)) {
            if (!importHasRuntimeBinding(statement))
                continue;
            const specifier = moduleSpecifierText(statement);
            if (!specifier)
                continue;
            deps.push({
                importer: relativePath,
                line: lineNumber(sourceFile, statement),
                specifier,
                resolved: resolveRelativeModule(relativePath, specifier),
            });
            continue;
        }
        if (ts.isExportDeclaration(statement)) {
            if (!exportHasRuntimeBinding(statement))
                continue;
            const specifier = moduleSpecifierText(statement);
            if (!specifier)
                continue;
            deps.push({
                importer: relativePath,
                line: lineNumber(sourceFile, statement),
                specifier,
                resolved: resolveRelativeModule(relativePath, specifier),
            });
        }
    }
    deps.push(...dynamicImportDependencies(sourceFile, relativePath));
    return deps;
}
function dynamicImportDependencies(sourceFile, relativePath) {
    const deps = [];
    const stack = [sourceFile];
    while (stack.length > 0) {
        const node = stack.pop();
        if (!node)
            continue;
        const specifier = dynamicImportSpecifierText(node);
        if (specifier) {
            deps.push({
                importer: relativePath,
                line: lineNumber(sourceFile, node),
                specifier,
                resolved: resolveRelativeModule(relativePath, specifier),
            });
        }
        const children = node.getChildren(sourceFile);
        for (let i = children.length - 1; i >= 0; i -= 1) {
            stack.push(children[i]);
        }
    }
    return deps;
}
function resolveRelativeModule(importer, specifier) {
    if (!specifier.startsWith('.'))
        return null;
    const importerDir = path.dirname(toAbsolutePath(importer));
    const basePath = path.resolve(importerDir, specifier);
    const candidates = [
        `${basePath}.ts`,
        `${basePath}.tsx`,
        path.join(basePath, 'index.ts'),
        path.join(basePath, 'index.tsx'),
    ];
    for (const candidate of candidates) {
        if (fs.existsSync(candidate))
            return toRepoPath(candidate);
    }
    return null;
}
function forbiddenRuntimeReason(resolvedPath) {
    if (resolvedPath === 'packages/sdk-server-ts/src/storage/postgres.ts') {
        return 'imports the Postgres storage driver';
    }
    if (/^packages\/sdk-server-ts\/src\/console\/shared\/postgres.*\.ts$/.test(resolvedPath)) {
        return 'imports a console Postgres shared helper';
    }
    if (resolvedPath === 'packages/sdk-server-ts/src/threshold/session/signingSessionSeal/index.ts') {
        return 'imports the mixed session-seal barrel instead of Cloudflare runtime leaf modules';
    }
    if (/^packages\/sdk-server-ts\/src\/console\/[^/]+\/index\.ts$/.test(resolvedPath)) {
        return 'imports a mixed console barrel instead of leaf modules';
    }
    if (/^packages\/sdk-server-ts\/src\/console\/.*\/postgres\.ts$/.test(resolvedPath)) {
        return 'imports a console Postgres adapter';
    }
    return null;
}
function cloudflareRuntimeDependencyViolations() {
    const pending = [...cloudflareRuntimeRoots];
    const seen = new Set();
    const violations = [];
    while (pending.length > 0) {
        const current = pending.pop();
        if (!current || seen.has(current))
            continue;
        seen.add(current);
        for (const dependency of runtimeDependencies(current)) {
            const resolved = dependency.resolved;
            if (!resolved)
                continue;
            const reason = forbiddenRuntimeReason(resolved);
            if (reason) {
                violations.push(`${dependency.importer}:${dependency.line} ${dependency.specifier} -> ${resolved}: ${reason}`);
            }
            if (resolved.startsWith('packages/sdk-server-ts/src/'))
                pending.push(resolved);
        }
    }
    return violations.sort();
}
function cloudflarePostgresEnvTokenViolations() {
    const violations = [];
    for (const relativePath of cloudflareRuntimeRoots) {
        const source = readSource(relativePath);
        for (const token of forbiddenCloudflarePostgresEnvTokens) {
            if (source.includes(token))
                violations.push(`${relativePath} contains ${token}`);
        }
    }
    return violations.sort();
}
function legacyRouteCapabilityFlagViolations() {
    const violations = [];
    for (const relativePath of listRouterRuntimeFiles()) {
        const source = readSource(relativePath);
        for (const { pattern, message } of legacyRouteCapabilityFlagPatterns) {
            if (pattern.test(source))
                violations.push(`${relativePath}: ${message}`);
        }
    }
    return violations.sort();
}
function routerAbLocalPostgresToolingViolations() {
    const violations = [];
    for (const relativePath of listJavaScriptFiles(routerAbLocalDevScriptRoot)) {
        const source = readSource(relativePath);
        for (const { pattern, message } of forbiddenRouterAbLocalPostgresPatterns) {
            if (pattern.test(source))
                violations.push(`${relativePath}: ${message}`);
        }
    }
    return violations.sort();
}
function ciWorkflowPostgresSmokeViolations() {
    const violations = [];
    const source = readSource(ciWorkflowPath);
    for (const { pattern, message } of forbiddenCiPostgresPatterns) {
        if (pattern.test(source))
            violations.push(`${ciWorkflowPath}: ${message}`);
    }
    return violations.sort();
}
function webServerPostgresToolingViolations() {
    const violations = [];
    for (const relativePath of deletedWebServerPostgresToolingPaths) {
        if (fs.existsSync(toAbsolutePath(relativePath))) {
            violations.push(`${relativePath}: deleted web-server Postgres tooling path exists`);
        }
    }
    const packageJson = JSON.parse(readSource(webServerPackagePath));
    for (const [name, command] of Object.entries(packageJson.scripts || {})) {
        if (/postgres|POSTGRES|docker-compose\.postgres/.test(`${name} ${command}`)) {
            violations.push(`${webServerPackagePath}: script ${name} revives Postgres tooling`);
        }
    }
    return violations.sort();
}
function sdkServerTsconfigPostgresScaffoldingViolations() {
    const violations = [];
    const source = readSource(sdkServerTsconfigPath);
    for (const { pattern, message } of forbiddenSdkServerTsconfigPostgresPatterns) {
        if (pattern.test(source))
            violations.push(`${sdkServerTsconfigPath}: ${message}`);
    }
    return violations.sort();
}
function sourcePatternViolations(relativePath, patterns) {
    const violations = [];
    const source = readSource(relativePath);
    for (const { pattern, message } of patterns) {
        if (pattern.test(source))
            violations.push(`${relativePath}: ${message}`);
    }
    return violations.sort();
}
function sourcePatternViolationsForFiles(relativePaths, patterns) {
    const violations = [];
    for (const relativePath of relativePaths) {
        violations.push(...sourcePatternViolations(relativePath, patterns));
    }
    return violations.sort();
}
function cloudflareD1EnvPricingViolations() {
    return sourcePatternViolationsForFiles(cloudflareRuntimeRoots, forbiddenCloudflareD1EnvPricingPatterns);
}
function staleRefactor82NameViolations() {
    const violations = [];
    if (fs.existsSync(toAbsolutePath(oldCloudflareD1RelayStagingWorkerPath))) {
        violations.push(`${oldCloudflareD1RelayStagingWorkerPath}: old relay staging Worker filename exists`);
    }
    if (fs.existsSync(toAbsolutePath(oldRelayApiKeysTestPath))) {
        violations.push(`${oldRelayApiKeysTestPath}: old Relay API key test filename exists`);
    }
    for (const relativePath of oldRouterApiHarnessScriptPaths) {
        if (fs.existsSync(toAbsolutePath(relativePath))) {
            violations.push(`${relativePath}: old Router API harness script filename exists`);
        }
    }
    for (const relativePath of oldWebServerTestPaths) {
        if (fs.existsSync(toAbsolutePath(relativePath))) {
            violations.push(`${relativePath}: old web-server test filename exists`);
        }
    }
    if (fs.existsSync(toAbsolutePath(oldEmailEncryptionOutlayerCompatTestPath))) {
        violations.push(`${oldEmailEncryptionOutlayerCompatTestPath}: old Outlayer email encryption test filename exists`);
    }
    if (fs.existsSync(toAbsolutePath(oldExpressTypeShimPath))) {
        violations.push(`${oldExpressTypeShimPath}: old ambient Express type shim exists`);
    }
    for (const relativePath of deletedDuplicateTestSetupMockPaths) {
        if (fs.existsSync(toAbsolutePath(relativePath))) {
            violations.push(`${relativePath}: duplicate dead test setup mock file exists`);
        }
    }
    for (const relativePath of [
        ...listTypeScriptFiles('apps/web-server/src'),
        ...listTypeScriptFiles('packages/sdk-server-ts/src'),
        ...listTypeScriptFiles('packages/sdk-web/src'),
        ...listTypeScriptFiles('tests'),
        ...listJavaScriptFiles('apps/web-server/scripts'),
        ...listJavaScriptFiles('packages/sdk-server-ts/scripts'),
        ...listJavaScriptFiles('packages/console-server-ts/scripts'),
        ...activeRouterApiTextPaths,
    ]) {
        if (relativePath === 'tests/unit/cloudflareD1RuntimeBoundaries.guard.unit.test.ts') {
            continue;
        }
        const source = readSource(relativePath);
        if (source.includes('routerApier')) {
            violations.push(`${relativePath}: references old routerApier typo path`);
        }
        for (const token of staleRouterApiRenameTokens) {
            if (source.includes(token)) {
                violations.push(`${relativePath}: references old ${token} name`);
            }
        }
    }
    for (const relativePath of [...listJavaScriptFiles('tests/scripts'), 'tests/package.json']) {
        if (relativePath === standaloneCheckerPath) {
            continue;
        }
        const source = readSource(relativePath);
        for (const token of staleRouterApiHarnessTokens) {
            if (source.includes(token)) {
                violations.push(`${relativePath}: references old ${token} harness name`);
            }
        }
    }
    for (const relativePath of routerApiProxyShimTextPaths) {
        const source = readSource(relativePath);
        for (const token of staleRouterApiProxyShimTokens) {
            if (source.includes(token)) {
                violations.push(`${relativePath}: references old ${token} Router API proxy name`);
            }
        }
    }
    return violations.sort();
}
function staleRefactor82ScaffoldingViolations() {
    const violations = [];
    for (const relativePath of listTypeScriptFiles('packages/sdk-server-ts/src')) {
        const source = readSource(relativePath);
        if (source.includes('scaffolding')) {
            violations.push(`${relativePath}: describes current production code as scaffolding`);
        }
    }
    return violations.sort();
}
function duplicatedD1StagingManifestWriterViolations() {
    const violations = [];
    for (const relativePath of d1StagingManifestWriterScripts) {
        const source = readSource(relativePath);
        if (source.includes('writeFileSync(manifestPath')) {
            violations.push(`${relativePath}: writes staging JSON manifest directly`);
        }
        if (source.includes('mkdirSync(path.dirname(manifestPath)')) {
            violations.push(`${relativePath}: creates staging manifest directories directly`);
        }
        if (/JSON\.stringify\(manifest,\s*null,\s*2\)/.test(source)) {
            violations.push(`${relativePath}: duplicates staging manifest JSON formatting`);
        }
    }
    return violations.sort();
}
function duplicatedD1StagingCliHelperViolations() {
    const violations = [];
    for (const relativePath of d1StagingCliHelperScripts) {
        const source = readSource(relativePath);
        for (const { pattern, message } of forbiddenD1StagingCliHelperPatterns) {
            if (pattern.test(source))
                violations.push(`${relativePath}: ${message}`);
        }
    }
    return violations.sort();
}
function localD1HelperDuplicationViolations() {
    const violations = [];
    for (const relativePath of listTypeScriptFiles('packages/sdk-server-ts/src')) {
        if (!isRuntimeSourceFile(relativePath) || relativePath === sharedD1HelperPath)
            continue;
        const source = readSource(relativePath);
        for (const { pattern, message } of forbiddenLocalD1HelperPatterns) {
            if (pattern.test(source))
                violations.push(`${relativePath}: ${message}`);
        }
    }
    return violations.sort();
}
function sqliteD1HarnessDuplicationViolations() {
    const violations = [];
    for (const relativePath of listTypeScriptFiles('tests')) {
        if (relativePath === sharedSqliteD1TestHelperPath)
            continue;
        const source = readSource(relativePath);
        for (const { pattern, message } of forbiddenSqliteD1HarnessDuplicationPatterns) {
            if (pattern.test(source))
                violations.push(`${relativePath}: ${message}`);
        }
    }
    return violations.sort();
}
function sdkServerRuntimePostgresImplementationViolations() {
    const violations = [];
    for (const relativePath of listTypeScriptFiles('packages/sdk-server-ts/src')) {
        if (!isRuntimeSourceFile(relativePath))
            continue;
        if (path.basename(relativePath).toLowerCase().includes('postgres')) {
            violations.push(`${relativePath}: Postgres runtime implementation file exists`);
            continue;
        }
        const source = readSource(relativePath);
        for (const { pattern, message } of forbiddenSdkServerPostgresRuntimePatterns) {
            if (pattern.test(source))
                violations.push(`${relativePath}: ${message}`);
        }
    }
    return violations.sort();
}
function coreOrchestrationPersistenceBoundaryViolations() {
    const violations = [];
    for (const relativePath of coreOrchestrationPortOnlyFiles) {
        const source = readSource(relativePath);
        for (const { pattern, message } of forbiddenCoreOrchestrationPersistencePatterns) {
            if (pattern.test(source))
                violations.push(`${relativePath}: ${message}`);
        }
    }
    return violations.sort();
}
function sourceFunctionBody(relativePath, functionName) {
    const source = readSource(relativePath);
    const startPattern = new RegExp(`export\\s+async\\s+function\\s+${functionName}\\s*\\(`);
    const startMatch = startPattern.exec(source);
    if (!startMatch)
        return null;
    const startIndex = startMatch.index;
    let braceIndex = source.indexOf('{', startIndex);
    if (braceIndex < 0)
        return null;
    let depth = 0;
    for (let index = braceIndex; index < source.length; index += 1) {
        const char = source[index];
        if (char === '{')
            depth += 1;
        if (char === '}') {
            depth -= 1;
            if (depth === 0)
                return source.slice(startIndex, index + 1);
        }
    }
    return null;
}
function consoleOnlyStagingSignerCustodyViolations() {
    const functionName = 'createCloudflareD1ConsoleOnlyServiceBundle';
    const body = sourceFunctionBody(cloudflareD1ConsoleServicesPath, functionName);
    if (!body)
        return [`${cloudflareD1ConsoleServicesPath}: missing ${functionName}`];
    const forbidden = [
        'kekProvider',
        'signerMetadataDatabase',
        'thresholdStore',
        'createCloudflareD1TenantRouteResolver',
        'createCloudflareD1SigningRootSecretAdapters',
    ];
    const violations = [];
    for (const token of forbidden) {
        if (body.includes(token)) {
            violations.push(`${cloudflareD1ConsoleServicesPath}: ${functionName} references ${token}`);
        }
    }
    return violations.sort();
}
function consoleStagingWorkerSignerCustodyViolations() {
    const source = readSource(cloudflareD1ConsoleStagingWorkerPath);
    const forbidden = [
        'SIGNER_DB',
        'THRESHOLD_STORE',
        'kekProvider',
        'createCloudflareD1ConsoleServiceBundle',
        'createCloudflareSecretsStoreKekProviderFromEnv',
    ];
    const violations = [];
    for (const token of forbidden) {
        if (source.includes(token)) {
            violations.push(`${cloudflareD1ConsoleStagingWorkerPath}: references ${token}`);
        }
    }
    return violations.sort();
}
function routerApiStagingWorkerSignerCustodyViolations() {
    const source = readSource(cloudflareD1RouterApiStagingWorkerPath);
    const required = [
        'SIGNER_DB',
        'THRESHOLD_STORE',
        'createCloudflareSecretsStoreKekProviderFromEnv',
        'resolveSponsoredEvmWorkerExecutionAdapter',
    ];
    const violations = [];
    for (const token of required) {
        if (!source.includes(token)) {
            violations.push(`${cloudflareD1RouterApiStagingWorkerPath}: missing ${token}`);
        }
    }
    return violations.sort();
}
function d1WorkerRouterApiHandlerLifetimeViolations() {
    const violations = [];
    for (const relativePath of [
        cloudflareD1LocalDevWorkerPath,
        cloudflareD1RouterApiStagingWorkerPath,
        cloudflareD1ConsoleStagingWorkerPath,
    ]) {
        const source = readSource(relativePath);
        if (/WeakMap<[^>]*FetchHandler/.test(source) || /new WeakMap<[^>]*FetchHandler/.test(source)) {
            violations.push(`${relativePath}: caches FetchHandler instances that can retain request-scoped Worker I/O bindings`);
        }
        if (/HandlerCacheEntry/.test(source) || /HandlerCache/.test(source)) {
            violations.push(`${relativePath}: caches Router API handlers instead of request-independent live session stores`);
        }
    }
    const localWorker = readSource(cloudflareD1LocalDevWorkerPath);
    const stagingWorker = readSource(cloudflareD1RouterApiStagingWorkerPath);
    const ecdsaPoolFill = readSource('packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers.ts');
    const thresholdStore = readSource('packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore.ts');
    const thresholdStoreClient = readSource('packages/sdk-server-ts/src/core/ThresholdService/stores/CloudflareDurableObjectStore.ts');
    if (localWorker.includes('localRouterApiEcdsaPoolFillLiveSessions')) {
        violations.push(`${cloudflareD1LocalDevWorkerPath}: owns ECDSA pool-fill live sessions outside the Durable Object`);
    }
    if (stagingWorker.includes('routerApiStagingEcdsaPoolFillLiveSessions')) {
        violations.push(`${cloudflareD1RouterApiStagingWorkerPath}: owns ECDSA pool-fill live sessions outside the Durable Object`);
    }
    if (localWorker.includes('createRouterAbEcdsaDerivationPoolFillLiveSessionStore') ||
        stagingWorker.includes('createRouterAbEcdsaDerivationPoolFillLiveSessionStore')) {
        violations.push('D1 Router API Worker constructs ECDSA pool-fill live-session stores directly');
    }
    for (const [relativePath, source] of [
        [cloudflareD1LocalDevWorkerPath, localWorker],
        [cloudflareD1RouterApiStagingWorkerPath, stagingWorker],
    ]) {
        if (source.includes('SigningWorkerPresignSession')) {
            violations.push(`${relativePath}: references live Router A/B ECDSA derivation WASM presign sessions outside the Durable Object`);
        }
        if (source.includes('presignSession') && source.includes('JSON.stringify')) {
            violations.push(`${relativePath}: may serialize Router A/B ECDSA derivation live presign session state outside the Durable Object`);
        }
    }
    if (ecdsaPoolFill.includes('fetch.bind(globalThis)')) {
        violations.push('packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaDerivationPoolFillHandlers.ts: caches a request-context fetch binding');
    }
    for (const token of [
        'routerAbEcdsaDerivationPoolFillLiveSessionCreate',
        'routerAbEcdsaDerivationPoolFillLiveSessionStep',
        'routerAbEcdsaDerivationPoolFillLiveSessionDelete',
        'InMemoryRouterAbEcdsaDerivationPoolFillLiveSessionOwner',
    ]) {
        if (!thresholdStore.includes(token)) {
            violations.push(`packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore.ts: missing ${token}`);
        }
    }
    if (!thresholdStoreClient.includes('CloudflareDurableObjectRouterAbEcdsaDerivationPoolFillLiveSessionOwner')) {
        violations.push('packages/sdk-server-ts/src/core/ThresholdService/stores/CloudflareDurableObjectStore.ts: missing DO-backed ECDSA pool-fill live-session owner');
    }
    if (!thresholdStoreClient.includes(':ecdsa-pool-fill:${id}')) {
        violations.push('packages/sdk-server-ts/src/core/ThresholdService/stores/CloudflareDurableObjectStore.ts: ECDSA pool-fill live-session owner must route live WASM state by presignSessionId');
    }
    return violations.sort();
}
function cloudflareRuntimeLegacyRegistrationModeViolations() {
    const violations = [];
    for (const relativePath of cloudflareRuntimeRoots) {
        const source = readSource(relativePath);
        for (const rule of forbiddenCloudflareRuntimeLegacyRegistrationTokens) {
            const found = 'pattern' in rule ? rule.pattern.test(source) : source.includes(rule.token);
            if (found) {
                violations.push(`${relativePath}: ${rule.message}`);
            }
        }
    }
    return violations.sort();
}
function authServiceLegacyRegistrationModeViolations() {
    const violations = [];
    const source = readSource(authServicePath);
    for (const rule of forbiddenAuthServiceLegacyRegistrationModeTokens) {
        const found = 'pattern' in rule ? rule.pattern.test(source) : source.includes(rule.token);
        if (found)
            violations.push(`${authServicePath}: ${rule.message}`);
    }
    return violations.sort();
}
function routerApiAuthServiceCouplingViolations() {
    const violations = [];
    for (const relativePath of listTypeScriptFiles('packages/sdk-server-ts/src/router')) {
        const source = readSource(relativePath);
        for (const { pattern, message } of forbiddenRouterApiAuthServiceCouplingPatterns) {
            if (pattern.test(source))
                violations.push(`${relativePath}: ${message}`);
        }
    }
    return violations.sort();
}
function routerApiAuthServiceMountViolations() {
    const violations = [];
    for (const relativePath of [
        ...listTypeScriptFiles('apps/web-server/src'),
        ...listTypeScriptFiles('packages/sdk-server-ts/src/router'),
    ]) {
        const source = readSource(relativePath);
        for (const { pattern, message } of forbiddenRouterApiAuthServiceMountPatterns) {
            if (pattern.test(source))
                violations.push(`${relativePath}: ${message}`);
        }
    }
    return violations.sort();
}
function routerApiRouteServiceMetadataViolations() {
    const violations = [];
    const routeDefinitions = readSource(routeDefinitionsPath);
    const routeExecutionContext = readSource(routeExecutionContextPath);
    const forbiddenServiceKeys = [
        {
            key: 'authService',
            message: 'uses monolithic AuthService as a route service key',
        },
        {
            key: 'threshold',
            message: 'uses stale threshold route service key instead of thresholdRuntime',
        },
    ];
    for (const { key, message } of forbiddenServiceKeys) {
        const exactString = new RegExp(`['"]${key}['"]`);
        if (exactString.test(routeDefinitions)) {
            violations.push(`${routeDefinitionsPath}: ${message}`);
        }
        if (exactString.test(routeExecutionContext)) {
            violations.push(`${routeExecutionContextPath}: ${message}`);
        }
    }
    return violations.sort();
}
function authServiceRouterApiHarnessViolations() {
    const violations = [];
    for (const relativePath of deletedAuthServiceRouterApiHarnessPaths) {
        if (fs.existsSync(toAbsolutePath(relativePath))) {
            violations.push(`${relativePath}: obsolete AuthService-backed Router API route harness exists`);
        }
    }
    const scannedRoots = [
        'apps',
        'packages/sdk-server-ts/src',
        'tests/relayer',
        'tests/unit',
    ];
    for (const root of scannedRoots) {
        for (const relativePath of listTypeScriptLikeFiles(root)) {
            const source = readSource(relativePath);
            if (!/\bnew\s+AuthService\s*\(/.test(source))
                continue;
            if (!allowedAuthServiceConstructorPaths.has(relativePath)) {
                violations.push(`${relativePath}: constructs AuthService outside an explicitly non-Router owner`);
            }
        }
    }
    return violations.sort();
}
function d1RouterApiAuthServiceFacadeViolations() {
    const source = readSource(cloudflareD1RouterApiAuthServicePath);
    const violations = [];
    for (const { pattern, message } of forbiddenD1RouterApiAuthFacadePatterns) {
        if (pattern.test(source))
            violations.push(`${cloudflareD1RouterApiAuthServicePath}: ${message}`);
    }
    return violations.sort();
}
function d1EmailOtpRecoveryGrantBindingViolations() {
    const source = readSource(cloudflareD1EmailOtpRecoveryServicePath);
    const functionMatch = source.match(/function emailOtpRecoveryGrantBindingMismatch\([\s\S]*?\n}\n/);
    if (!functionMatch) {
        return [
            `${cloudflareD1EmailOtpRecoveryServicePath}: missing Email OTP recovery grant binding parser`,
        ];
    }
    const bindingFunction = functionMatch[0];
    const violations = [];
    for (const token of ['sessionHash', 'appSessionVersion']) {
        if (bindingFunction.includes(token)) {
            violations.push(`${cloudflareD1EmailOtpRecoveryServicePath}: recovery grant binding reads ${token}`);
        }
    }
    for (const token of [
        'record.userId !== input.userId',
        'record.walletId !== input.walletId',
        'record.otpChannel !== EMAIL_OTP_CHANNEL',
        'record.orgId !== input.orgId',
    ]) {
        if (!bindingFunction.includes(token)) {
            violations.push(`${cloudflareD1EmailOtpRecoveryServicePath}: recovery grant binding missing ${token}`);
        }
    }
    if (source.includes('Recovery grant is not valid for the current app session')) {
        violations.push(`${cloudflareD1EmailOtpRecoveryServicePath}: uses obsolete app-session recovery grant error`);
    }
    return violations.sort();
}
function authServiceEmailOtpGrantBindingViolations() {
    const checkedFunctions = [
        {
            path: authServiceEmailOtpGrantPath,
            name: 'consumeEmailOtpGrantWithStore',
            match: /export async function consumeEmailOtpGrantWithStore\([\s\S]*?\n}\n/,
        },
        {
            path: authServiceEmailOtpRecoveryKeysPath,
            name: 'recoveryGrantBindingMatches',
            match: /function recoveryGrantBindingMatches\([\s\S]*?\n}\n/,
        },
    ];
    const violations = [];
    for (const checkedFunction of checkedFunctions) {
        const source = readSource(checkedFunction.path);
        const functionMatch = source.match(checkedFunction.match);
        if (!functionMatch) {
            violations.push(`${checkedFunction.path}: missing ${checkedFunction.name}`);
            continue;
        }
        const functionSource = functionMatch[0];
        for (const token of ['sessionHash', 'appSessionVersion']) {
            if (functionSource.includes(token)) {
                violations.push(`${checkedFunction.path}: ${checkedFunction.name} reads ${token}`);
            }
        }
        if (source.includes('Recovery grant is not valid for the current app session')) {
            violations.push(`${checkedFunction.path}: uses obsolete app-session recovery grant error`);
        }
    }
    return violations.sort();
}
function authServiceRouterApiLifecycleMethodViolations() {
    const source = readSource(authServicePath);
    const violations = [];
    for (const pattern of forbiddenAuthServiceRouterApiLifecycleMethodPatterns) {
        if (pattern.test(source)) {
            violations.push(`${authServicePath}: contains removed Router API lifecycle method ${pattern}`);
        }
    }
    return violations.sort();
}
function durableRegistrationIntentLegacySelectionConversionViolations() {
    const violations = [];
    for (const relativePath of [
        authServicePath,
        walletRegistrationRoutesPath,
        d1RegistrationIntentServicePath,
        d1RegistrationCeremonyRecordsPath,
    ]) {
        const source = readSource(relativePath);
        if (source.includes('legacyRegistrationSignerSelectionFromPlan')) {
            violations.push(`${relativePath}: converts normalized signer plans back to legacy durable intent state`);
        }
    }
    return violations.sort();
}
function productionCombinedRegistrationStateViolations() {
    const violations = [];
    for (const relativePath of [
        ...listTypeScriptLikeFiles('apps/seams-site/src'),
        ...listTypeScriptFiles('packages/shared-ts/src'),
        ...listTypeScriptFiles('packages/sdk-server-ts/src'),
        ...listTypeScriptFiles('packages/sdk-web/src'),
    ]) {
        if (!isRuntimeSourceFile(relativePath))
            continue;
        const source = readSource(relativePath);
        for (const { token, message } of forbiddenProductionCombinedRegistrationTokens) {
            if (source.includes(token))
                violations.push(`${relativePath}: ${message}`);
        }
    }
    return violations.sort();
}
function publicRegistrationLegacyModeConstructionViolations() {
    const violations = [];
    const scanned = new Set();
    for (const relativePath of publicRegistrationRequestConstructionFiles) {
        if (scanned.has(relativePath))
            continue;
        scanned.add(relativePath);
        const source = readSource(relativePath);
        for (const { token, message } of forbiddenPublicRegistrationLegacySelectionTokens) {
            if (source.includes(token)) {
                violations.push(`${relativePath}: ${message}`);
            }
        }
    }
    return violations.sort();
}
function publicRegistrationLegacyModeTypeSurfaceViolations() {
    const violations = [];
    for (const relativePath of publicRegistrationTypeSurfaceFiles) {
        const source = readSource(relativePath);
        if (source.includes('RegistrationSignerSelection')) {
            violations.push(`${relativePath}: exposes legacy registration mode types on the public signer-set surface`);
        }
    }
    return violations.sort();
}
function removedRegistrationSignerSelectionFilenameViolations() {
    const violations = [];
    for (const relativeDir of registrationSignerFilenameScanRoots) {
        for (const relativePath of listTypeScriptLikeFiles(relativeDir)) {
            if (!path.basename(relativePath).includes(removedRegistrationSignerSelectionFileBasename)) {
                continue;
            }
            violations.push(`${relativePath}: uses removed registration signer-selection filename`);
        }
    }
    return violations.sort();
}

function d1LocalDevRouterApiRoutePrefixViolations() {
    const source = readSource(cloudflareD1LocalDevWorkerPath);
    const violations = [];
    if (!source.includes("pathname.startsWith('/near/')")) {
        violations.push(`${cloudflareD1LocalDevWorkerPath}: does not forward /near/* Router API routes`);
    }
    if (source.includes("pathname.startsWith('-internal/shared-ts/near/')")) {
        violations.push(`${cloudflareD1LocalDevWorkerPath}: forwards malformed shared-ts route prefix instead of /near/*`);
    }
    return violations.sort();
}

function syncAccountSessionPolicyInputViolations() {
    const violations = [];
    for (const relativePath of [
        syncAccountRequestValidationPath,
        authServicePortPath,
        authServiceWebAuthnPath,
        d1WebAuthnAuthServicePath,
        sdkWebSyncAccountPath,
    ]) {
        if (readSource(relativePath).includes('threshold_ed25519')) {
            violations.push(`${relativePath}: exposes the removed sync-account threshold session-policy input`);
        }
    }
    return violations.sort();
}
test('Cloudflare router runtime graph stays D1/DO-only at persistence boundaries', () => {
    const violations = cloudflareRuntimeDependencyViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('Cloudflare Worker env shape does not expose Postgres cron fallbacks', () => {
    const violations = cloudflarePostgresEnvTokenViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('Cloudflare D1 runtime reads sponsored pricing from Console D1, not Worker env', () => {
    const violations = cloudflareD1EnvPricingViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('Router API route capabilities are selected by structural services, not enabled flags', () => {
    const violations = legacyRouteCapabilityFlagViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('router-ab local dev scripts do not revive partial Postgres seed tooling', () => {
    const violations = routerAbLocalPostgresToolingViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('CI does not revive removed Postgres staging smoke jobs', () => {
    const violations = ciWorkflowPostgresSmokeViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('concrete D1 staging Wrangler configs stay untracked', () => {
    const source = readSource(gitignorePath);
    expect(source).toContain('packages/console-server-ts/wrangler.d1-staging-console.toml');
    expect(source).toContain('packages/console-server-ts/wrangler.d1-staging-router-api.toml');
});
test('D1 staging README documents missing-KEK signer custody evidence', () => {
    const source = readSource(sdkServerReadmePath);
    expect(source).toContain('--wallet-session-jwt-env SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT');
    expect(source).toContain('--missing-kek-fixture ./staging/fixtures/ecdsa-export-share-missing-kek.json');
    expect(source).toContain('--missing-kek-wallet-session-jwt-env SEAMS_STAGING_MISSING_KEK_WALLET_SESSION_JWT');
    expect(source).toContain('--missing-kek-expected-status 503');
    expect(source).toContain('--missing-kek-expected-code missing_signing_root_kek');
    expect(source).toContain('ecdsa_export_share_missing_kek_fail_closed');
    expect(source).toContain('--output .wrangler/d1-staging-evidence/verification.json');
});
test('D1 staging README shows dry-run before remote mutating commands', () => {
    const source = readSource(sdkServerReadmePath);
    expect(source).toContain(`pnpm run d1:staging:bookmark -- \\
  --mode dry-run \\
  --purpose before_fixture_import`);
    expect(source).toContain(`pnpm run d1:staging:bookmark -- \\
  --mode dry-run \\
  --purpose before_route_switch`);
    expect(source).toContain(`pnpm run d1:staging:import-fixtures -- \\
  --mode dry-run`);
    expect(source).toContain(`pnpm run d1:staging:import-fixtures -- \\
  --mode remote`);
    expect(source).toContain(`pnpm run d1:staging:smoke -- \\
  --mode dry-run`);
    expect(source).toContain(`pnpm run d1:staging:smoke -- \\
  --mode remote`);
});
test('Refactor 82 fixture-import plan describes migration-derived table allowlists', () => {
    const source = readSource(refactor82PlanPath);
    expect(source).toContain('derived from the checked-in D1 migrations');
    expect(source).toContain('migrations/d1-console');
    expect(source).toContain('migrations/d1-signer');
    expect(source).not.toContain('Console fixtures may touch only `console_` tables');
    expect(source).not.toContain('signer fixtures may touch only `signer_` tables');
});
test('web-server package does not revive deleted Postgres helper tooling', () => {
    const violations = webServerPostgresToolingViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('sdk-server TypeScript config does not revive pg compiler scaffolding', () => {
    const violations = sdkServerTsconfigPostgresScaffoldingViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('account settings docs describe the current D1 account adapter', () => {
    const violations = sourcePatternViolations(accountSettingsDocPath, staleAccountSettingsDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('schema and dashboard backend docs describe D1 tenant-scoped tables', () => {
    const violations = sourcePatternViolationsForFiles([dbSchemaDocPath, dashboardBackendImplementationDocPath], staleD1SchemaDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('API-key docs describe current D1 credential and bootstrap-token tables', () => {
    const violations = sourcePatternViolations(apiKeysDocPath, staleD1ApiKeyDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('console onboarding docs describe current D1-era tenant isolation', () => {
    const violations = sourcePatternViolations(consoleOnboardingDocPath, staleConsoleOnboardingDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('policy docs describe D1 policy table names', () => {
    const violations = sourcePatternViolationsForFiles([policyIdDocPath, dashboardBackendImplementationDocPath], staleD1PolicyTableDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('billing cleanup docs do not point at deleted Refactor 82 relayer suites', () => {
    const violations = sourcePatternViolations(billingCleanupDocPath, staleBillingCleanupValidationPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('current billing docs describe D1-era billing instead of active Postgres billing', () => {
    const violations = sourcePatternViolationsForFiles(currentBillingDocPaths, staleCurrentBillingDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('gas sponsorship prepaid docs describe the current D1 settlement path', () => {
    const violations = sourcePatternViolations(gasSponsorshipPrepaidDocPath, staleGasSponsorshipPrepaidDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('generalized gas sponsorship docs link to current sponsorship modules', () => {
    const violations = sourcePatternViolations(generalizedGasSponsorshipDocPath, staleGeneralizedGasSponsorshipDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('gas and signing policy docs link to the current package layout', () => {
    const violations = sourcePatternViolations(gasAndSigningPoliciesDocPath, staleGasAndSigningPoliciesDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('policy engine docs describe D1-era policy storage and current package paths', () => {
    const violations = sourcePatternViolations(policyEngineDocPath, stalePolicyEngineDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('sponsorship policy docs link to the current package layout', () => {
    const violations = sourcePatternViolations(sponsorshipPolicyDocPath, staleSponsorshipPolicyDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('observability docs describe D1-era storage and current package paths', () => {
    const violations = sourcePatternViolationsForFiles(observabilityDocPaths, staleObservabilityDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('SaaS frontend docs point at the current app layout', () => {
    const violations = sourcePatternViolationsForFiles([policyDraftsDocPath, professionalizeDocPath], staleSaasFrontendDocPatterns);
    expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 82 stale staging and relayer names stay deleted', () => {
    const violations = staleRefactor82NameViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('Refactor 82 production source no longer describes current runtime as scaffolding', () => {
    const violations = staleRefactor82ScaffoldingViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('D1 staging scripts share JSON manifest writing', () => {
    const violations = duplicatedD1StagingManifestWriterViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('D1 staging scripts share common helpers', () => {
    const violations = duplicatedD1StagingCliHelperViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('D1 persistence helpers stay centralized at the storage boundary', () => {
    const violations = localD1HelperDuplicationViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('SQLite-backed D1 test harness stays centralized', () => {
    const violations = sqliteD1HarnessDuplicationViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('Postgres escape hatch remains a typed contract without sdk-server runtime adapters', () => {
    const violations = sdkServerRuntimePostgresImplementationViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('core orchestration receives domain-store ports instead of raw persistence bindings', () => {
    const violations = coreOrchestrationPersistenceBoundaryViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('console-only Cloudflare D1 staging factory does not receive signer custody bindings', () => {
    const violations = consoleOnlyStagingSignerCustodyViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('console staging Worker stays isolated from signer custody bindings', () => {
    const violations = consoleStagingWorkerSignerCustodyViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('Router API staging Worker owns signer custody and sponsored EVM bindings', () => {
    const violations = routerApiStagingWorkerSignerCustodyViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('D1 Worker ECDSA pool-fill live sessions stay request-independent', () => {
    const violations = d1WorkerRouterApiHandlerLifetimeViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('local D1 Worker forwards Router API route prefixes', () => {
    const violations = d1LocalDevRouterApiRoutePrefixViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('Cloudflare D1 runtime does not revive legacy registration modes', () => {
    const violations = cloudflareRuntimeLegacyRegistrationModeViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('AuthService wallet registration does not revive legacy registration modes', () => {
    const violations = authServiceLegacyRegistrationModeViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('Router API service ports stay backend-neutral and explicit', () => {
    const violations = routerApiAuthServiceCouplingViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('Router API routes are not mounted with AuthService', () => {
    const violations = routerApiAuthServiceMountViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('Router API route metadata uses explicit facade service keys', () => {
    const violations = routerApiRouteServiceMetadataViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('AuthService-backed Router API route harnesses stay deleted', () => {
    const violations = authServiceRouterApiHarnessViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('D1 Router API service factory does not revive a flat AuthService-shaped facade', () => {
    const violations = d1RouterApiAuthServiceFacadeViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('D1 Email OTP recovery grants bind to stable authority fields', () => {
    const violations = d1EmailOtpRecoveryGrantBindingViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('AuthService Email OTP grants bind to stable authority fields', () => {
    const violations = authServiceEmailOtpGrantBindingViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('AuthService does not own Router API wallet lifecycle methods', () => {
    const violations = authServiceRouterApiLifecycleMethodViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('durable registration intent writers keep signer-set state', () => {
    const violations = durableRegistrationIntentLegacySelectionConversionViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('production source does not revive combined registration state', () => {
    const violations = productionCombinedRegistrationStateViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('public/demo registration request construction stays on signer-set terminology', () => {
    const violations = publicRegistrationLegacyModeConstructionViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('public registration type surfaces stay signer-set only', () => {
    const violations = publicRegistrationLegacyModeTypeSurfaceViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('SDK registration helper files use signer-set filenames', () => {
    const violations = removedRegistrationSignerSelectionFilenameViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});
test('sync-account exposes only verified identity and Yao recovery inputs', () => {
    const violations = syncAccountSessionPolicyInputViolations();
    expect(violations, violations.join('\n')).toEqual([]);
});

console.log('[cloudflare-d1-runtime-boundaries] ok');
