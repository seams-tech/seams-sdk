import type { ConsoleAccountService } from '@seams-internal/console-server/account/index';
import type { ConsoleApiKeyService } from '@seams-internal/console-server/apiKeys/index';
import type { ConsoleApprovalService } from '@seams-internal/wallet-console-server/approvals/index';
import type { ConsoleAuditService } from '@seams-internal/console-server/audit/index';
import type { ConsoleBillingService } from '@seams-internal/console-server/billing/index';
import type { ConsoleBillingPrepaidReservationService } from '@seams-internal/wallet-console-server/billingPrepaidReservations/index';
import type {
  ConsoleObservabilityIngestionService,
  ConsoleObservabilityService,
} from '@seams-internal/console-server/observability/index';
import type { ConsoleOnboardingService } from '@seams-internal/console-server/onboarding/index';
import type { ConsoleOrgProjectEnvService } from '@seams-internal/console-server/orgProjectEnv/index';
import type { ConsolePolicyService } from '@seams-internal/wallet-console-server/policies/index';
import type { ConsoleKeyExportService } from '@seams-internal/wallet-console-server/keyExports/index';
import type { ConsoleRuntimeSnapshotService } from '@seams-internal/wallet-console-server/runtimeSnapshots/index';
import type { ConsoleSponsoredCallService } from '@seams-internal/wallet-console-server/sponsoredCalls/index';
import type { ConsoleOrganizationAccessService } from '@seams-internal/console-server/teamRbac/index';
import type { ConsoleWalletService } from '@seams-internal/wallet-console-server/wallets/index';
import type { ConsoleWebhookService } from '@seams-internal/console-server/webhooks/index';
import type { SessionAdapter } from '@seams-internal/console-server/boundary/index';
import type { ConsoleRouterOptions } from './console';
import type { ConsoleAuthAdapter } from '@seams-internal/console-server/router/consoleAuth';
import { createCloudflareConsoleRouter } from './cloudflare/createCloudflareConsoleRouter';
import type { TenantStorageRouteResolver } from './cloudflare/tenantStorageRoute';

// Exact branch compositions for the production Console router. Every service a
// branch serves is a required input here; the broad optional ConsoleRouterOptions
// bag remains only as the internal assembly format these builders produce.
// The core/walletConsole grouping is the R105 Phase 2 package split.

export interface ConsoleCoreRouterServices {
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly organizationAccess: ConsoleOrganizationAccessService;
  readonly account: ConsoleAccountService;
  readonly apiKeys: ConsoleApiKeyService;
  readonly audit: ConsoleAuditService;
  readonly billing: ConsoleBillingService;
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService;
  readonly webhooks: ConsoleWebhookService | null;
  readonly observability: ConsoleObservabilityService;
  readonly observabilityIngestion: ConsoleObservabilityIngestionService;
  readonly onboarding: ConsoleOnboardingService;
}

export interface WalletConsoleRouterServices {
  readonly policies: ConsolePolicyService;
  readonly wallets: ConsoleWalletService;
  readonly approvals: ConsoleApprovalService;
  readonly keyExports: ConsoleKeyExportService;
  readonly sponsoredCalls: ConsoleSponsoredCallService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
}

export interface ConsoleOnlyRouterComposition {
  readonly core: ConsoleCoreRouterServices;
  readonly walletConsole: WalletConsoleRouterServices;
  readonly auth: ConsoleAuthAdapter;
  readonly readyCheck: () => Promise<void> | void;
  readonly billingStripeWebhookSigningSecret: string;
}

export interface HostedConsoleRouterComposition {
  readonly core: ConsoleCoreRouterServices;
  readonly walletConsole: WalletConsoleRouterServices;
  readonly tenantStorage: {
    readonly resolver: TenantStorageRouteResolver;
    readonly namespace: string;
  };
  readonly auth: ConsoleAuthAdapter;
  readonly session: SessionAdapter;
  readonly corsOrigins: Array<string | undefined>;
  readonly readyCheck: () => Promise<void> | void;
  readonly billingStripeWebhookSigningSecret: string | undefined;
}

function spreadBranchServices(
  core: ConsoleCoreRouterServices,
  walletConsole: WalletConsoleRouterServices,
) {
  return {
    orgProjectEnv: core.orgProjectEnv,
    organizationAccess: core.organizationAccess,
    account: core.account,
    apiKeys: core.apiKeys,
    audit: core.audit,
    billing: core.billing,
    prepaidReservations: core.prepaidReservations,
    webhooks: core.webhooks,
    observability: core.observability,
    observabilityIngestion: core.observabilityIngestion,
    onboarding: core.onboarding,
    policies: walletConsole.policies,
    wallets: walletConsole.wallets,
    approvals: walletConsole.approvals,
    keyExports: walletConsole.keyExports,
    sponsoredCalls: walletConsole.sponsoredCalls,
    runtimeSnapshots: walletConsole.runtimeSnapshots,
  };
}

/**
 * The Wallet Console router: Console core plus the Wallet Console service set,
 * every input required. This is the only production mount point; the optional
 * ConsoleRouterOptions bag stays internal to the route assembly.
 */
export function createWalletConsoleRouter(
  input: ConsoleOnlyRouterComposition,
): ReturnType<typeof createCloudflareConsoleRouter> {
  return createCloudflareConsoleRouter(composeConsoleOnlyRouterOptions(input));
}

export function createHostedWalletConsoleRouter(
  input: HostedConsoleRouterComposition,
): ReturnType<typeof createCloudflareConsoleRouter> {
  return createCloudflareConsoleRouter(composeHostedConsoleRouterOptions(input));
}

export function composeConsoleOnlyRouterOptions(
  input: ConsoleOnlyRouterComposition,
): ConsoleRouterOptions {
  return {
    ...spreadBranchServices(input.core, input.walletConsole),
    healthz: true,
    readyz: true,
    auth: input.auth,
    readyCheck: input.readyCheck,
    billingStripeWebhookSigningSecret: input.billingStripeWebhookSigningSecret,
  };
}

export function composeHostedConsoleRouterOptions(
  input: HostedConsoleRouterComposition,
): ConsoleRouterOptions {
  return {
    ...spreadBranchServices(input.core, input.walletConsole),
    tenantStorageRouteResolver: input.tenantStorage.resolver,
    tenantStorageNamespace: input.tenantStorage.namespace,
    healthz: true,
    readyz: true,
    corsOrigins: input.corsOrigins,
    auth: input.auth,
    session: input.session,
    readyCheck: input.readyCheck,
    billingStripeWebhookSigningSecret: input.billingStripeWebhookSigningSecret,
  };
}
