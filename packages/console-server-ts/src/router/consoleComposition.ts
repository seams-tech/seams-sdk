import type { ConsoleAccountService } from '@seams-internal/console-server/account';
import type { ConsoleApiKeyService } from '@seams-internal/console-server/apiKeys';
import type { ConsoleApprovalService } from '@seams-internal/console-server/approvals';
import type { ConsoleAuditService } from '@seams-internal/console-server/audit';
import type { ConsoleBillingService } from '@seams-internal/console-server/billing';
import type { ConsoleBillingPrepaidReservationService } from '@seams-internal/console-server/billingPrepaidReservations';
import type {
  ConsoleObservabilityIngestionService,
  ConsoleObservabilityService,
} from '@seams-internal/console-server/observability';
import type { ConsoleOnboardingService } from '@seams-internal/console-server/onboarding';
import type { ConsoleOrgProjectEnvService } from '@seams-internal/console-server/orgProjectEnv';
import type { ConsolePolicyService } from '@seams-internal/console-server/policies';
import type { ConsoleKeyExportService } from '@seams-internal/console-server/keyExports';
import type { ConsoleRuntimeSnapshotService } from '@seams-internal/console-server/runtimeSnapshots';
import type { ConsoleSponsoredCallService } from '@seams-internal/console-server/sponsoredCalls';
import type { ConsoleOrganizationAccessService } from '@seams-internal/console-server/teamRbac';
import type { ConsoleWalletService } from '@seams-internal/console-server/wallets';
import type { ConsoleWebhookService } from '@seams-internal/console-server/webhooks';
import type { SessionAdapter } from '../boundary';
import type { ConsoleRouterOptions } from './console';
import type { ConsoleAuthAdapter } from './consoleAuth';
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
