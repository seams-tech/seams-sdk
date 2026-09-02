import type { RouterLogger } from '@seams-internal/console-server/boundary/index';
import type { ConsoleBillingService } from '@seams-internal/console-server/billing/index';
import type { ConsoleBillingPrepaidReservationService } from '@seams-internal/wallet-console-server/billingPrepaidReservations/index';
import type { ConsoleSponsoredCallService } from '@seams-internal/wallet-console-server/sponsoredCalls/index';
import type { ConsoleApiKeyService } from '@seams-internal/console-server/apiKeys/index';
import type { ConsoleOrgProjectEnvService } from '@seams-internal/console-server/orgProjectEnv/index';
import type { ConsolePolicyService } from '@seams-internal/wallet-console-server/policies/index';
import type { ConsoleWalletService } from '@seams-internal/wallet-console-server/wallets/index';
import type { ConsoleWebhookService } from '@seams-internal/console-server/webhooks/index';
import type { ConsoleKeyExportService } from '@seams-internal/wallet-console-server/keyExports/index';
import type { ConsoleRuntimeSnapshotService } from '@seams-internal/wallet-console-server/runtimeSnapshots/index';
import type { ConsoleOrganizationAccessService } from '@seams-internal/console-server/teamRbac/index';
import type { ConsoleApprovalService } from '@seams-internal/wallet-console-server/approvals/index';
import type { ConsoleAuditService } from '@seams-internal/console-server/audit/index';
import type { ConsoleAuditExportsService } from '@seams-internal/console-server/auditExports/index';
import type { ConsoleEnterpriseIsolationService } from '@seams-internal/console-server/enterpriseIsolation/index';
import type { ConsoleOnboardingService } from '@seams-internal/console-server/onboarding/index';
import type { ConsoleAccountService } from '@seams-internal/console-server/account/index';
import type {
  ConsoleObservabilityIngestionService,
  ConsoleObservabilityService,
} from '@seams-internal/console-server/observability/index';
import type { SessionAdapter } from '@seams-internal/console-server/boundary/index';
import type { ConsoleAuthAdapter } from '@seams-internal/console-server/router/consoleAuth';
import type { TenantStorageRouteResolver } from './cloudflare/tenantStorageRoute';

export type {
  ConsoleAuthAdapter,
  ConsoleAuthAdapterResult,
  ConsoleAuthClaims,
  ConsoleAuthResult,
  HeaderRecord,
} from '@seams-internal/console-server/router/consoleAuth';
export { authenticateConsoleRequest } from '@seams-internal/console-server/router/consoleAuth';

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
  // Optional organization membership, invitation, permission, and project-access adapter.
  organizationAccess?: ConsoleOrganizationAccessService | null;
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
  // Stripe endpoint signing secret used to verify the raw Stripe-Signature payload.
  billingStripeWebhookSigningSecret?: string;
  // Optional local/dev escape hatch: allows live environment provisioning without billing readiness.
  // Keep disabled in production and only enable intentionally.
  allowLiveEnvironmentBillingBypass?: boolean;
  // Optional logger; defaults to silent.
  logger?: RouterLogger | null;
}
