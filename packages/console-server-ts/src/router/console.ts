import type { RouterLogger } from '@seams/sdk-server/internal/router/logger';
import type { ConsoleBillingService } from '@seams-internal/console-server/billing';
import type { ConsoleBillingPrepaidReservationService } from '@seams-internal/console-server/billingPrepaidReservations';
import type { ConsoleSponsoredCallService } from '@seams-internal/console-server/sponsoredCalls';
import type { ConsoleApiKeyService } from '@seams-internal/console-server/apiKeys';
import type { ConsoleOrgProjectEnvService } from '@seams-internal/console-server/orgProjectEnv';
import type { ConsolePolicyService } from '@seams-internal/console-server/policies';
import type { ConsoleWalletService } from '@seams-internal/console-server/wallets';
import type { ConsoleWebhookService } from '@seams-internal/console-server/webhooks';
import type { ConsoleKeyExportService } from '@seams-internal/console-server/keyExports';
import type { ConsoleRuntimeSnapshotService } from '@seams-internal/console-server/runtimeSnapshots';
import type { ConsoleTeamRbacService } from '@seams-internal/console-server/teamRbac';
import type { ConsoleApprovalService } from '@seams-internal/console-server/approvals';
import type { ConsoleAuditService } from '@seams-internal/console-server/audit';
import type { ConsoleAuditExportsService } from '@seams-internal/console-server/auditExports';
import type { ConsoleEnterpriseIsolationService } from '@seams-internal/console-server/enterpriseIsolation';
import type { ConsoleOnboardingService } from '@seams-internal/console-server/onboarding';
import type { ConsoleAccountService } from '@seams-internal/console-server/account';
import type {
  ConsoleObservabilityIngestionService,
  ConsoleObservabilityService,
} from '@seams-internal/console-server/observability';
import type { SessionAdapter } from '@seams/sdk-server/internal/router/routerApi';
import type { TenantStorageRouteResolver } from '@seams/sdk-server/internal/storage/tenantRoute';
import type { ConsoleAuthAdapter } from '@seams/sdk-server/internal/router/consoleAuth';

export type {
  ConsoleAuthAdapter,
  ConsoleAuthAdapterResult,
  ConsoleAuthClaims,
  ConsoleAuthResult,
  ConsoleRole,
  HeaderRecord,
} from '@seams/sdk-server/internal/router/consoleAuth';
export { authenticateConsoleRequest, hasConsoleRole } from '@seams/sdk-server/internal/router/consoleAuth';

export type ConsoleTenantStorageRoutingOptions =
  | {
      tenantStorageRouteResolver?: null | undefined;
      tenantStorageNamespace?: never;
    }
  | {
      tenantStorageRouteResolver: TenantStorageRouteResolver;
      tenantStorageNamespace: string;
    };

export type ConsoleRouterOptions = ConsoleRouterBaseOptions & ConsoleTenantStorageRoutingOptions;

export interface ConsoleRouterBaseOptions {
  healthz?: boolean;
  readyz?: boolean;
  /**
   * Optional list(s) of CORS origins (CSV strings or literal origins).
   * Pass raw strings; the router normalizes/merges internally.
   */
  corsOrigins?: Array<string | undefined>;
  // Optional auth adapter for console/admin endpoints.
  auth?: ConsoleAuthAdapter | null;
  // Optional readiness probe hook for console infra dependencies.
  readyCheck?: (() => Promise<void> | void) | null;
  // Optional billing adapter for console billing endpoints.
  billing?: ConsoleBillingService | null;
  // Optional prepaid sponsorship reservation adapter for balance/reservation reporting endpoints.
  prepaidReservations?: ConsoleBillingPrepaidReservationService | null;
  // Optional sponsored-execution history adapter for console billing/reporting endpoints.
  sponsoredCalls?: ConsoleSponsoredCallService | null;
  // Optional org/project/environment metadata adapter for console routes.
  orgProjectEnv?: ConsoleOrgProjectEnvService | null;
  // Optional policy adapter for console policy lifecycle routes.
  policies?: ConsolePolicyService | null;
  // Optional wallet adapter for console wallet list/search/detail routes.
  wallets?: ConsoleWalletService | null;
  // Optional API key adapter for console API key management endpoints.
  apiKeys?: ConsoleApiKeyService | null;
  // Optional webhook adapter for console webhook management endpoints.
  webhooks?: ConsoleWebhookService | null;
  // Optional key export adapter for export request and approval endpoints.
  keyExports?: ConsoleKeyExportService | null;
  // Optional runtime snapshot adapter for versioned per-environment config snapshots.
  runtimeSnapshots?: ConsoleRuntimeSnapshotService | null;
  // Optional team/membership adapter for org member and role-scope management endpoints.
  teamRbac?: ConsoleTeamRbacService | null;
  // Optional unified approval queue adapter for policy/export approvals.
  approvals?: ConsoleApprovalService | null;
  // Optional audit/evidence adapter for investigation timeline and export metadata endpoints.
  audit?: ConsoleAuditService | null;
  // Optional audit export adapter for evidence export materialization workflow.
  auditExports?: ConsoleAuditExportsService | null;
  // Optional enterprise isolation adapter for shared->dedicated isolation controls.
  enterpriseIsolation?: ConsoleEnterpriseIsolationService | null;
  // Optional onboarding adapter for first-run setup and onboarding state endpoints.
  onboarding?: ConsoleOnboardingService | null;
  // Optional account settings adapter for profile and multi-org operations.
  account?: ConsoleAccountService | null;
  // Optional observability adapter for logs/metrics/health read APIs.
  observability?: ConsoleObservabilityService | null;
  // Optional observability ingestion adapter for telemetry event writes.
  observabilityIngestion?: ConsoleObservabilityIngestionService | null;
  // Optional app session adapter used when console routes need to rotate session scope.
  session?: SessionAdapter | null;
  // Optional shared secret required by Stripe webhook ingestion endpoint.
  billingStripeWebhookSecret?: string;
  // Optional local/dev escape hatch: allows live environment provisioning without billing readiness.
  // Keep disabled in production and only enable intentionally.
  allowLiveEnvironmentBillingBypass?: boolean;
  // Optional logger; defaults to silent.
  logger?: RouterLogger | null;
}
