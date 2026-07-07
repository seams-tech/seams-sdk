import { toOptionalTrimmedString } from '@shared/utils/validation';
import { normalizeLogger, type Logger } from '../../core/logger';
import type { CloudflareDurableObjectNamespaceLike } from '../../core/types';
import {
  createSigningRootSecretShareKekResolver,
  type SigningRootKekProvider,
} from '../../core/ThresholdService/signingRootKekProvider';
import { openSigningRootSecretShareWireV1 } from '../../core/ThresholdService/signingRootSecretSealing';
import {
  type CreateHostedSigningRootShareResolverInput,
  type SealedSigningRootShare,
  type SigningRootShareDecryptAdapter,
  type SigningRootShareSource,
  type ThresholdPrfPolicy,
} from '../../core/ThresholdService/signingRootShareResolver';
import { D1SigningRootSecretStore } from '../../core/ThresholdService/stores/SigningRootSecretStore.d1';
import type { SigningRootSecretShareSource } from '../../core/ThresholdService/stores/SigningRootSecretStore.shared';
import {
  normalizeSigningRootSecretShareId,
  type SealedSigningRootSecretShare,
} from '../../core/ThresholdService/signingRootSecretShareWires';
import { createD1ConsoleAccountService } from '../../console/account/d1';
import type { ConsoleAccountService } from '../../console/account/service';
import { createD1ConsoleApiKeyService } from '../../console/apiKeys/d1';
import type {
  ConsoleApiKeysContext,
  ConsoleApiKeyService,
} from '../../console/apiKeys/service';
import type {
  CreateConsoleApiKeyRequest,
  CreateConsoleApiKeyResult,
} from '../../console/apiKeys/types';
import { createD1ConsoleApprovalService } from '../../console/approvals/d1';
import type { ConsoleApprovalService } from '../../console/approvals/service';
import { createD1ConsoleAuditService } from '../../console/audit/d1';
import type { ConsoleAuditService } from '../../console/audit/service';
import { createD1ConsoleBootstrapTokenService } from '../../console/bootstrapTokens/d1';
import type { ConsoleBootstrapTokenService } from '../../console/bootstrapTokens/service';
import { createD1ConsoleBillingService } from '../../console/billing/d1';
import type { BillingProviderAdapters } from '../../console/billing/providers';
import type { ConsoleBillingService } from '../../console/billing/service';
import { createD1ConsoleBillingPrepaidReservationService } from '../../console/billingPrepaidReservations/d1';
import type { ConsoleBillingPrepaidReservationService } from '../../console/billingPrepaidReservations/service';
import { createD1ConsoleKeyExportService } from '../../console/keyExports/d1';
import type { ConsoleKeyExportService } from '../../console/keyExports/service';
import {
  createD1ConsoleWebhookService,
  type ConsoleWebhookSecretCipher,
} from '../../console/webhooks/d1';
import type {
  ConsoleWebhookService,
  WebhookDispatchAdapter,
} from '../../console/webhooks/service';
import { createD1ConsoleOrgProjectEnvService } from '../../console/orgProjectEnv/d1';
import type { ConsoleOrgProjectEnvService } from '../../console/orgProjectEnv/service';
import {
  createD1ConsoleObservabilityIngestionService,
  createD1ConsoleObservabilityService,
} from '../../console/observability/d1';
import type { ConsoleObservabilityIngestionService } from '../../console/observability/ingestionService';
import type { ConsoleObservabilityService } from '../../console/observability/service';
import type { ConsoleObservabilityMetadataRedactionPolicy } from '../../console/observability/types';
import {
  createInMemoryConsoleOnboardingService,
  type ConsoleOnboardingService,
} from '../../console/onboarding/service';
import { createD1ConsolePolicyService } from '../../console/policies/d1';
import type { ConsolePolicyService } from '../../console/policies/service';
import { createD1ConsoleSponsoredCallService } from '../../console/sponsoredCalls/d1';
import type { ConsoleSponsoredCallService } from '../../console/sponsoredCalls/service';
import {
  createD1ConsoleSponsorshipPricingService,
  ensureConsoleSponsorshipPricingD1Schema,
  seedD1ConsoleStaticEvmSponsorshipPricingRule,
} from '../../console/sponsorshipPricing/d1';
import { createD1ConsoleSponsorshipSpendCapService } from '../../console/sponsorshipSpendCaps/d1';
import type { ConsoleSponsorshipSpendCapService } from '../../console/sponsorshipSpendCaps/service';
import { createD1ConsoleTeamRbacService } from '../../console/teamRbac/d1';
import type { ConsoleTeamRbacService } from '../../console/teamRbac/service';
import { createD1ConsoleWalletService } from '../../console/wallets/d1';
import type { ConsoleWalletService } from '../../console/wallets/service';
import { createD1ConsoleRuntimeSnapshotService } from '../../console/runtimeSnapshots/d1';
import type { ConsoleRuntimeSnapshotService } from '../../console/runtimeSnapshots/service';
import {
  DEFAULT_TEMPO_ONBOARDING_CONTRACT,
  TEMPO_TESTNET_CHAIN_ID,
} from '../../console/gasSponsorship/onboarding';
import { ensureTempoOnboardingSponsorshipForExistingEnvironments } from '../../console/gasSponsorship/seeding';
import type { ConsoleGasSponsorshipPolicyProjection } from '../../console/gasSponsorship/types';
import type {
  RouterApiKeyAuthAdapter,
  RouterApiBootstrapTokenVerifier,
  RouterApiPublishableKeyAuthAdapter,
  RouterApiOptions,
  RouterApiUsageMeterAdapter,
} from '../routerApi';
import type { ConsoleRouterOptions } from '../console';
import {
  createRouterApiKeyAuthAdapter,
  createRouterApiBillingUsageMeterAdapter,
  createRouterApiPublishableKeyAuthAdapter,
} from '../../console/router/routerApiKeyAuth';
import { createRouterApiBootstrapGrantBroker } from '../../console/router/bootstrapGrantBroker';
import { createRouterApiBootstrapTokenVerifier } from '../../console/router/bootstrapTokenVerifier';
import { createConsoleRouterApiRouteExtensions } from '../../console/router/routeExtensions';
import type { RouterAbNormalSigningAdmissionAdapter } from '../routerAbPrivateSigningWorker';
import {
  createCloudflareDurableObjectRouterAbNormalSigningAdmissionStore,
  createRouterAbNormalSigningAdmissionAdapter,
} from '../routerAbNormalSigningAdmissionCore';
import type {
  SponsoredEvmCallExecutorConfig,
  SponsoredEvmExecutionAdapterResolver,
} from '../../console/sponsorship/evmExecutorTypes';
import type { SponsorshipSpendPricingService } from '../../console/sponsorship/spendCaps';
import {
  createStaticCloudflareTenantStorageRouteResolverFromBindings,
  type CloudflareTenantStorageRoute,
  type CloudflareTenantTopology,
  type D1BindingName,
  type D1DatabaseLike,
  type D1DatabaseName,
  type DurableObjectBindingName,
  type TenantDataJurisdiction,
  type TenantStorageRouteResolver,
} from '../../storage/tenantRoute';

const DEFAULT_CONSOLE_D1_BINDING_NAME = 'CONSOLE_DB';
const DEFAULT_CONSOLE_D1_DATABASE_NAME = 'seams-console';
const DEFAULT_SIGNER_D1_BINDING_NAME = 'SIGNER_DB';
const DEFAULT_SIGNER_D1_DATABASE_NAME = 'seams-signer';
const DEFAULT_THRESHOLD_STORE_BINDING_NAME = 'THRESHOLD_STORE';
const DEFAULT_ROUTE_VERSION = 1;
const DEFAULT_TOPOLOGY: CloudflareTenantTopology = 'shared';
const DEFAULT_JURISDICTION: TenantDataJurisdiction = 'automatic';
const DEFAULT_BOOTSTRAP_GRANT_TOKEN_TTL_MS = 60_000;

export interface CloudflareD1ConsoleStorageBindings {
  readonly consoleDatabase: D1DatabaseLike;
  readonly signerMetadataDatabase: D1DatabaseLike;
  readonly thresholdStore: CloudflareDurableObjectNamespaceLike;
  readonly kekProvider: SigningRootKekProvider;
}

export interface CloudflareD1ConsoleOnlyStorageBindings {
  readonly consoleDatabase: D1DatabaseLike;
}

export interface CloudflareD1ConsoleStorageBindingNames {
  readonly consoleBindingName?: D1BindingName;
  readonly consoleDatabaseName?: D1DatabaseName;
  readonly signerMetadataBindingName?: D1BindingName;
  readonly signerMetadataDatabaseName?: D1DatabaseName;
  readonly thresholdStoreBindingName?: DurableObjectBindingName;
}

export interface CloudflareD1ConsoleRouteOptions {
  readonly namespace: string;
  readonly routeVersion?: number;
  readonly topology?: CloudflareTenantTopology;
  readonly jurisdiction?: TenantDataJurisdiction;
}

export interface CloudflareD1ConsoleAdapterOptions {
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
  readonly logger?: Logger | null;
  readonly billingProviders?: Partial<BillingProviderAdapters>;
  readonly defaultPrepaidReservationTtlMs?: number;
  readonly webhookSecretCipher?: ConsoleWebhookSecretCipher;
  readonly webhookDispatcher?: WebhookDispatchAdapter;
  readonly webhookEndpointDegradedThreshold?: number;
  readonly observabilityRedactionPolicy?: ConsoleObservabilityMetadataRedactionPolicy;
  readonly observabilityMaxBatchSize?: number;
  readonly observabilityMaxEventsPerMinute?: number;
  readonly observabilityQueryMaxWindowMs?: number;
  readonly runtimeSnapshotRetentionTtlMs?: number;
  readonly runtimeSnapshotRetentionPruneIntervalMs?: number;
  readonly runtimeSnapshotRetentionBatchSize?: number;
  readonly bootstrapGrantTokenTtlMs?: number;
  readonly sponsorshipPricing?: SponsorshipSpendPricingService | null;
  readonly sponsoredEvmCallConfig?: SponsoredEvmCallExecutorConfig | null;
  readonly resolveSponsoredEvmExecutionAdapter?: SponsoredEvmExecutionAdapterResolver | null;
}

export interface CloudflareD1ConsoleServiceBundleOptions {
  readonly bindings: CloudflareD1ConsoleStorageBindings;
  readonly route: CloudflareD1ConsoleRouteOptions;
  readonly bindingNames?: CloudflareD1ConsoleStorageBindingNames;
  readonly adapters?: CloudflareD1ConsoleAdapterOptions;
}

export interface CloudflareD1ConsoleOnlyServiceBundleOptions {
  readonly bindings: CloudflareD1ConsoleOnlyStorageBindings;
  readonly route: Pick<CloudflareD1ConsoleRouteOptions, 'namespace'>;
  readonly adapters?: Omit<
    CloudflareD1ConsoleAdapterOptions,
    | 'bootstrapGrantTokenTtlMs'
    | 'sponsorshipPricing'
    | 'sponsoredEvmCallConfig'
    | 'resolveSponsoredEvmExecutionAdapter'
  >;
}

export interface CloudflareD1ConsoleRouterStorageOptions {
  readonly tenantStorageRouteResolver: TenantStorageRouteResolver;
  readonly tenantStorageNamespace: string;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly teamRbac: ConsoleTeamRbacService;
  readonly account: ConsoleAccountService;
  readonly policies: ConsolePolicyService;
  readonly wallets: ConsoleWalletService;
  readonly apiKeys: ConsoleApiKeyService;
  readonly approvals: ConsoleApprovalService;
  readonly keyExports: ConsoleKeyExportService;
  readonly webhooks?: ConsoleWebhookService | null;
  readonly observability: ConsoleObservabilityService;
  readonly observabilityIngestion: ConsoleObservabilityIngestionService;
  readonly onboarding: ConsoleOnboardingService;
  readonly audit: ConsoleAuditService;
  readonly billing: ConsoleBillingService;
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService;
  readonly sponsoredCalls: ConsoleSponsoredCallService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
}

export interface CloudflareD1RouterApiStorageOptions {
  readonly sponsorship: NonNullable<RouterApiOptions['sponsorship']>;
  readonly observabilityIngestion: ConsoleObservabilityIngestionService;
  readonly apiKeyAuth: RouterApiKeyAuthAdapter;
  readonly publishableKeyAuth: RouterApiPublishableKeyAuthAdapter;
  readonly apiKeyUsageMeter: RouterApiUsageMeterAdapter;
  readonly bootstrapTokenVerifier: RouterApiBootstrapTokenVerifier;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly routeExtensions: NonNullable<RouterApiOptions['routeExtensions']>;
  readonly routerAbNormalSigningAdmission: RouterAbNormalSigningAdmissionAdapter;
}

export interface CloudflareD1ConsoleServiceBundle {
  readonly tenantStorageRouteResolver: TenantStorageRouteResolver;
  readonly tenantStorageNamespace: string;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly teamRbac: ConsoleTeamRbacService;
  readonly account: ConsoleAccountService;
  readonly policies: ConsolePolicyService;
  readonly wallets: ConsoleWalletService;
  readonly apiKeys: ConsoleApiKeyService;
  readonly approvals: ConsoleApprovalService;
  readonly keyExports: ConsoleKeyExportService;
  readonly webhooks: ConsoleWebhookService | null;
  readonly observability: ConsoleObservabilityService;
  readonly observabilityIngestion: ConsoleObservabilityIngestionService;
  readonly onboarding: ConsoleOnboardingService;
  readonly bootstrapTokens: ConsoleBootstrapTokenService;
  readonly audit: ConsoleAuditService;
  readonly billing: ConsoleBillingService;
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService;
  readonly spendCaps: ConsoleSponsorshipSpendCapService;
  readonly sponsoredCalls: ConsoleSponsoredCallService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
  readonly consoleRouterOptions: CloudflareD1ConsoleRouterStorageOptions;
  readonly routerApiRouterOptions: CloudflareD1RouterApiStorageOptions;
}

export type CloudflareD1ConsoleOnlyServiceBundle = Omit<
  CloudflareD1ConsoleServiceBundle,
  | 'tenantStorageRouteResolver'
  | 'bootstrapTokens'
  | 'spendCaps'
  | 'routerApiRouterOptions'
  | 'consoleRouterOptions'
> & {
  readonly consoleRouterOptions: ConsoleRouterOptions;
};

export interface CloudflareD1SigningRootSecretAdapterOptions {
  readonly route: CloudflareTenantStorageRoute;
  readonly projectId: string;
  readonly envId: string;
  readonly envelopeVersion: string;
  readonly lastAuditEventId: string;
  readonly policy: ThresholdPrfPolicy;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

export interface CloudflareD1SigningRootSecretAdapters {
  readonly signingRootSecretStore: D1SigningRootSecretStore;
  readonly signingRootShareStore: SigningRootShareSource;
  readonly signingRootShareDecryptAdapter: SigningRootShareDecryptAdapter;
  readonly signingRootSharePolicy: ThresholdPrfPolicy;
  readonly signingRootShareResolverAdapters: CreateHostedSigningRootShareResolverInput;
}

interface NormalizedCloudflareD1ConsoleCommonOptions {
  readonly consoleDatabase: D1DatabaseLike;
  readonly namespace: string;
  readonly ensureSchema: boolean;
  readonly now?: () => Date;
  readonly logger?: Logger | null;
  readonly billingProviders?: Partial<BillingProviderAdapters>;
  readonly defaultPrepaidReservationTtlMs?: number;
  readonly webhookSecretCipher?: ConsoleWebhookSecretCipher;
  readonly webhookDispatcher?: WebhookDispatchAdapter;
  readonly webhookEndpointDegradedThreshold?: number;
  readonly observabilityRedactionPolicy?: ConsoleObservabilityMetadataRedactionPolicy;
  readonly observabilityMaxBatchSize?: number;
  readonly observabilityMaxEventsPerMinute?: number;
  readonly observabilityQueryMaxWindowMs?: number;
  readonly runtimeSnapshotRetentionTtlMs?: number;
  readonly runtimeSnapshotRetentionPruneIntervalMs?: number;
  readonly runtimeSnapshotRetentionBatchSize?: number;
}

interface NormalizedCloudflareD1ConsoleServiceBundleOptions
  extends NormalizedCloudflareD1ConsoleCommonOptions {
  readonly signerMetadataDatabase: D1DatabaseLike;
  readonly thresholdStore: CloudflareDurableObjectNamespaceLike;
  readonly kekProvider: SigningRootKekProvider;
  readonly routeVersion: number;
  readonly topology: CloudflareTenantTopology;
  readonly jurisdiction: TenantDataJurisdiction;
  readonly consoleBindingName: D1BindingName;
  readonly consoleDatabaseName: D1DatabaseName;
  readonly signerMetadataBindingName: D1BindingName;
  readonly signerMetadataDatabaseName: D1DatabaseName;
  readonly thresholdStoreBindingName: DurableObjectBindingName;
  readonly bootstrapGrantTokenTtlMs: number;
  readonly sponsorshipPricing?: SponsorshipSpendPricingService | null;
  readonly sponsoredEvmCallConfig?: SponsoredEvmCallExecutorConfig | null;
  readonly resolveSponsoredEvmExecutionAdapter?: SponsoredEvmExecutionAdapterResolver | null;
}

interface CloudflareD1ConsoleCommonServices {
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly teamRbac: ConsoleTeamRbacService;
  readonly account: ConsoleAccountService;
  readonly policies: ConsolePolicyService;
  readonly wallets: ConsoleWalletService;
  readonly apiKeys: ConsoleApiKeyService;
  readonly approvals: ConsoleApprovalService;
  readonly keyExports: ConsoleKeyExportService;
  readonly webhooks: ConsoleWebhookService | null;
  readonly observability: ConsoleObservabilityService;
  readonly observabilityIngestion: ConsoleObservabilityIngestionService;
  readonly onboarding: ConsoleOnboardingService;
  readonly audit: ConsoleAuditService;
  readonly billing: ConsoleBillingService;
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService;
  readonly sponsoredCalls: ConsoleSponsoredCallService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
}

type TempoStaticSponsorshipPricingSeed = {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now?: () => Date;
};

const TEMPO_STATIC_SPONSORSHIP_PRICING_VERSION_PREFIX = 'tempo-testnet-static-v1';
const TEMPO_STATIC_SPONSORSHIP_ESTIMATE_FEE_PER_GAS_WEI = 40_000_000_000n;
const TEMPO_STATIC_SPONSORSHIP_MINOR_PER_WEI_NUMERATOR = 1n;
const TEMPO_STATIC_SPONSORSHIP_MINOR_PER_WEI_DENOMINATOR = 1_000_000_000_000_000n;

class TempoOnboardingApiKeyService implements ConsoleApiKeyService {
  constructor(
    private readonly base: ConsoleApiKeyService,
    private readonly orgProjectEnv: ConsoleOrgProjectEnvService,
    private readonly policies: ConsolePolicyService,
    private readonly runtimeSnapshots: ConsoleRuntimeSnapshotService,
    private readonly pricingSeed: TempoStaticSponsorshipPricingSeed | null,
  ) {}

  async listApiKeys(ctx: ConsoleApiKeysContext) {
    return await this.base.listApiKeys(ctx);
  }

  async createApiKey(
    ctx: ConsoleApiKeysContext,
    request: CreateConsoleApiKeyRequest,
  ): Promise<CreateConsoleApiKeyResult> {
    if (request.kind === 'publishable_key') {
      await this.ensureTempoSnapshot(ctx, request.environmentId);
    }
    return await this.base.createApiKey(ctx, request);
  }

  async revokeApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
    request?: Parameters<ConsoleApiKeyService['revokeApiKey']>[2],
  ) {
    return await this.base.revokeApiKey(ctx, apiKeyId, request);
  }

  async deleteApiKey(ctx: ConsoleApiKeysContext, apiKeyId: string) {
    return await this.base.deleteApiKey(ctx, apiKeyId);
  }

  async rotateApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
    request?: Parameters<ConsoleApiKeyService['rotateApiKey']>[2],
  ) {
    return await this.base.rotateApiKey(ctx, apiKeyId, request);
  }

  async updateApiKey(
    ctx: ConsoleApiKeysContext,
    apiKeyId: string,
    request: Parameters<ConsoleApiKeyService['updateApiKey']>[2],
  ) {
    return await this.base.updateApiKey(ctx, apiKeyId, request);
  }

  async authenticatePublishableKey(
    request: Parameters<NonNullable<ConsoleApiKeyService['authenticatePublishableKey']>>[0],
  ) {
    return await this.base.authenticatePublishableKey?.(request) ?? {
      ok: false,
      status: 401,
      code: 'publishable_key_invalid',
      message: 'Publishable key auth is not configured',
    };
  }

  async authenticateApiKey(
    request: Parameters<NonNullable<ConsoleApiKeyService['authenticateApiKey']>>[0],
  ) {
    return await this.base.authenticateApiKey?.(request) ?? {
      ok: false,
      status: 401,
      code: 'secret_key_invalid',
      message: 'Secret key auth is not configured',
    };
  }

  private async ensureTempoSnapshot(
    ctx: ConsoleApiKeysContext,
    environmentId: string,
  ): Promise<void> {
    const orgProjectEnvCtx = {
      orgId: ctx.orgId,
      actorUserId: ctx.actorUserId,
      roles: [...ctx.roles],
    };
    const environments = await this.orgProjectEnv.listEnvironments(orgProjectEnvCtx);
    const environment = environments.find((entry) => entry.id === environmentId);
    if (!environment) return;
    const seededPolicies = await ensureTempoOnboardingSponsorshipForExistingEnvironments({
      orgProjectEnv: this.orgProjectEnv,
      policies: this.policies,
      runtimeSnapshots: this.runtimeSnapshots,
      ctx: orgProjectEnvCtx,
      faucetContractAddress: DEFAULT_TEMPO_ONBOARDING_CONTRACT,
      projectId: environment.projectId,
    });
    for (const policy of seededPolicies) {
      await this.seedTempoPricingForPolicy(ctx, environment, policy);
    }
  }

  private async seedTempoPricingForPolicy(
    ctx: ConsoleApiKeysContext,
    environment: { readonly id: string; readonly projectId: string },
    policy: ConsoleGasSponsorshipPolicyProjection,
  ): Promise<void> {
    if (!this.pricingSeed || policy.kind !== 'evm_call') return;
    await seedD1ConsoleStaticEvmSponsorshipPricingRule({
      database: this.pricingSeed.database,
      namespace: this.pricingSeed.namespace,
      orgId: ctx.orgId,
      projectId: environment.projectId,
      environmentId: environment.id,
      policyId: policy.id,
      chainId: TEMPO_TESTNET_CHAIN_ID,
      pricingVersion: `${TEMPO_STATIC_SPONSORSHIP_PRICING_VERSION_PREFIX}:${policy.id}`,
      estimateFeePerGasWei: TEMPO_STATIC_SPONSORSHIP_ESTIMATE_FEE_PER_GAS_WEI,
      minorPerWeiNumerator: TEMPO_STATIC_SPONSORSHIP_MINOR_PER_WEI_NUMERATOR,
      minorPerWeiDenominator: TEMPO_STATIC_SPONSORSHIP_MINOR_PER_WEI_DENOMINATOR,
      minSpendMinor: 1,
      createdBy: ctx.actorUserId,
      now: this.pricingSeed.now,
    });
  }
}

function createTempoOnboardingApiKeyService(input: {
  readonly apiKeys: ConsoleApiKeyService;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly policies: ConsolePolicyService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
  readonly pricingSeed: TempoStaticSponsorshipPricingSeed | null;
}): ConsoleApiKeyService {
  return new TempoOnboardingApiKeyService(
    input.apiKeys,
    input.orgProjectEnv,
    input.policies,
    input.runtimeSnapshots,
    input.pricingSeed,
  );
}

function normalizeRequiredString(input: string | undefined, fallback: string, field: string): string {
  const value = String(input || fallback).trim();
  if (!value) {
    throw new Error(`${field} is required`);
  }
  return value;
}

function normalizeNamespace(input: string): string {
  const namespace = String(input || '').trim();
  if (!namespace) {
    throw new Error('D1 console storage namespace is required');
  }
  return namespace;
}

function normalizeBootstrapGrantTokenTtlMs(input: number | undefined): number {
  const ttlMs = Number(input || DEFAULT_BOOTSTRAP_GRANT_TOKEN_TTL_MS);
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000) {
    throw new Error('D1 Router API bootstrapGrantTokenTtlMs must be at least 1000');
  }
  return ttlMs;
}

function requireSigningRootAdapterString(input: unknown, field: string): string {
  const value = toOptionalTrimmedString(input);
  if (!value) throw new Error(`${field} is required for D1 signing-root adapters`);
  return value;
}

function normalizeSecretShareDecryptRecord(
  record: SealedSigningRootShare,
): SealedSigningRootSecretShare {
  const signingRootId = requireSigningRootAdapterString(record.signingRootId, 'signingRootId');
  const shareId = normalizeSigningRootSecretShareId(record.shareId);
  const kekId = requireSigningRootAdapterString(record.kekId, 'kekId');
  if (!shareId) throw new Error('sealed signing-root share record has invalid shareId');
  if (!(record.sealedShare instanceof Uint8Array) || record.sealedShare.byteLength === 0) {
    throw new Error('sealed signing-root share record requires sealedShare bytes');
  }
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const storageId = toOptionalTrimmedString(record.storageId);
  return {
    signingRootId,
    shareId,
    sealedShare: record.sealedShare,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(storageId ? { storageId } : {}),
    kekId,
  };
}

class SigningRootSecretShareSourceBridge implements SigningRootShareSource {
  private readonly source: SigningRootSecretShareSource;

  constructor(source: SigningRootSecretShareSource) {
    this.source = source;
  }

  async listSealedSigningRootShares(
    input: Parameters<SigningRootShareSource['listSealedSigningRootShares']>[0],
  ): Promise<readonly SealedSigningRootShare[]> {
    return await this.source.listSealedSigningRootSecretShares(input);
  }
}

class SigningRootKekProviderDecryptAdapter implements SigningRootShareDecryptAdapter {
  private readonly resolveKek: ReturnType<typeof createSigningRootSecretShareKekResolver>;

  constructor(kekProvider: SigningRootKekProvider) {
    this.resolveKek = createSigningRootSecretShareKekResolver(kekProvider);
  }

  async decryptSigningRootShare(record: SealedSigningRootShare): Promise<Uint8Array> {
    return await openSigningRootSecretShareWireV1({
      record: normalizeSecretShareDecryptRecord(record),
      resolveKek: this.resolveKek,
    });
  }
}

function createCloudflareD1SigningRootSecretShareStore(
  store: D1SigningRootSecretStore,
): SigningRootShareSource {
  return new SigningRootSecretShareSourceBridge(store);
}

export function createCloudflareD1SigningRootShareDecryptAdapter(
  kekProvider: SigningRootKekProvider,
): SigningRootShareDecryptAdapter {
  return new SigningRootKekProviderDecryptAdapter(kekProvider);
}

function normalizeRouteVersion(input: number | undefined): number {
  const routeVersion = Number(input || DEFAULT_ROUTE_VERSION);
  if (!Number.isInteger(routeVersion) || routeVersion < 1) {
    throw new Error('D1 console storage routeVersion must be a positive integer');
  }
  return routeVersion;
}

function normalizeTopology(input: CloudflareTenantTopology | undefined): CloudflareTenantTopology {
  return input || DEFAULT_TOPOLOGY;
}

function normalizeJurisdiction(
  input: TenantDataJurisdiction | undefined,
): TenantDataJurisdiction {
  return input || DEFAULT_JURISDICTION;
}

function normalizeCloudflareD1ConsoleServiceBundleOptions(
  options: CloudflareD1ConsoleServiceBundleOptions,
): NormalizedCloudflareD1ConsoleServiceBundleOptions {
  return {
    consoleDatabase: options.bindings.consoleDatabase,
    signerMetadataDatabase: options.bindings.signerMetadataDatabase,
    thresholdStore: options.bindings.thresholdStore,
    kekProvider: options.bindings.kekProvider,
    namespace: normalizeNamespace(options.route.namespace),
    routeVersion: normalizeRouteVersion(options.route.routeVersion),
    topology: normalizeTopology(options.route.topology),
    jurisdiction: normalizeJurisdiction(options.route.jurisdiction),
    consoleBindingName: normalizeRequiredString(
      options.bindingNames?.consoleBindingName,
      DEFAULT_CONSOLE_D1_BINDING_NAME,
      'consoleBindingName',
    ),
    consoleDatabaseName: normalizeRequiredString(
      options.bindingNames?.consoleDatabaseName,
      DEFAULT_CONSOLE_D1_DATABASE_NAME,
      'consoleDatabaseName',
    ),
    signerMetadataBindingName: normalizeRequiredString(
      options.bindingNames?.signerMetadataBindingName,
      DEFAULT_SIGNER_D1_BINDING_NAME,
      'signerMetadataBindingName',
    ),
    signerMetadataDatabaseName: normalizeRequiredString(
      options.bindingNames?.signerMetadataDatabaseName,
      DEFAULT_SIGNER_D1_DATABASE_NAME,
      'signerMetadataDatabaseName',
    ),
    thresholdStoreBindingName: normalizeRequiredString(
      options.bindingNames?.thresholdStoreBindingName,
      DEFAULT_THRESHOLD_STORE_BINDING_NAME,
      'thresholdStoreBindingName',
    ),
    ensureSchema: options.adapters?.ensureSchema !== false,
    now: options.adapters?.now,
    logger: options.adapters?.logger,
    billingProviders: options.adapters?.billingProviders,
    defaultPrepaidReservationTtlMs: options.adapters?.defaultPrepaidReservationTtlMs,
    webhookSecretCipher: options.adapters?.webhookSecretCipher,
    webhookDispatcher: options.adapters?.webhookDispatcher,
    webhookEndpointDegradedThreshold: options.adapters?.webhookEndpointDegradedThreshold,
    observabilityRedactionPolicy: options.adapters?.observabilityRedactionPolicy,
    observabilityMaxBatchSize: options.adapters?.observabilityMaxBatchSize,
    observabilityMaxEventsPerMinute: options.adapters?.observabilityMaxEventsPerMinute,
    observabilityQueryMaxWindowMs: options.adapters?.observabilityQueryMaxWindowMs,
    runtimeSnapshotRetentionTtlMs: options.adapters?.runtimeSnapshotRetentionTtlMs,
    runtimeSnapshotRetentionPruneIntervalMs:
      options.adapters?.runtimeSnapshotRetentionPruneIntervalMs,
    runtimeSnapshotRetentionBatchSize: options.adapters?.runtimeSnapshotRetentionBatchSize,
    bootstrapGrantTokenTtlMs: normalizeBootstrapGrantTokenTtlMs(
      options.adapters?.bootstrapGrantTokenTtlMs,
    ),
    sponsorshipPricing: options.adapters?.sponsorshipPricing,
    sponsoredEvmCallConfig: options.adapters?.sponsoredEvmCallConfig,
    resolveSponsoredEvmExecutionAdapter: options.adapters?.resolveSponsoredEvmExecutionAdapter,
  };
}

function normalizeCloudflareD1ConsoleOnlyServiceBundleOptions(
  options: CloudflareD1ConsoleOnlyServiceBundleOptions,
): NormalizedCloudflareD1ConsoleCommonOptions {
  return {
    consoleDatabase: options.bindings.consoleDatabase,
    namespace: normalizeNamespace(options.route.namespace),
    ensureSchema: options.adapters?.ensureSchema !== false,
    now: options.adapters?.now,
    logger: options.adapters?.logger,
    billingProviders: options.adapters?.billingProviders,
    defaultPrepaidReservationTtlMs: options.adapters?.defaultPrepaidReservationTtlMs,
    webhookSecretCipher: options.adapters?.webhookSecretCipher,
    webhookDispatcher: options.adapters?.webhookDispatcher,
    webhookEndpointDegradedThreshold: options.adapters?.webhookEndpointDegradedThreshold,
    observabilityRedactionPolicy: options.adapters?.observabilityRedactionPolicy,
    observabilityMaxBatchSize: options.adapters?.observabilityMaxBatchSize,
    observabilityMaxEventsPerMinute: options.adapters?.observabilityMaxEventsPerMinute,
    observabilityQueryMaxWindowMs: options.adapters?.observabilityQueryMaxWindowMs,
    runtimeSnapshotRetentionTtlMs: options.adapters?.runtimeSnapshotRetentionTtlMs,
    runtimeSnapshotRetentionPruneIntervalMs:
      options.adapters?.runtimeSnapshotRetentionPruneIntervalMs,
    runtimeSnapshotRetentionBatchSize: options.adapters?.runtimeSnapshotRetentionBatchSize,
  };
}

function createCloudflareD1TenantRouteResolver(
  options: NormalizedCloudflareD1ConsoleServiceBundleOptions,
): TenantStorageRouteResolver {
  return createStaticCloudflareTenantStorageRouteResolverFromBindings({
    routeVersion: options.routeVersion,
    topology: options.topology,
    jurisdiction: options.jurisdiction,
    consoleBindingName: options.consoleBindingName,
    consoleDatabaseName: options.consoleDatabaseName,
    consoleDatabase: options.consoleDatabase,
    signerMetadataBindingName: options.signerMetadataBindingName,
    signerMetadataDatabaseName: options.signerMetadataDatabaseName,
    signerMetadataDatabase: options.signerMetadataDatabase,
    thresholdStoreBindingName: options.thresholdStoreBindingName,
    thresholdStore: options.thresholdStore,
    kekProvider: options.kekProvider,
  });
}

async function createCloudflareD1PrepaidReservations(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleBillingPrepaidReservationService> {
  return await createD1ConsoleBillingPrepaidReservationService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    now: options.now,
    defaultReservationTtlMs: options.defaultPrepaidReservationTtlMs,
  });
}

async function createCloudflareD1Billing(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleBillingService> {
  return await createD1ConsoleBillingService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    now: options.now,
    providers: options.billingProviders,
  });
}

async function createCloudflareD1OrgProjectEnv(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleOrgProjectEnvService> {
  return await createD1ConsoleOrgProjectEnvService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1TeamRbac(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleTeamRbacService> {
  return await createD1ConsoleTeamRbacService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1Account(input: {
  readonly options: NormalizedCloudflareD1ConsoleCommonOptions;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly teamRbac: ConsoleTeamRbacService;
  readonly onboarding: ConsoleOnboardingService;
}): Promise<ConsoleAccountService> {
  return await createD1ConsoleAccountService({
    database: input.options.consoleDatabase,
    namespace: input.options.namespace,
    ensureSchema: input.options.ensureSchema,
    now: input.options.now,
    orgProjectEnv: input.orgProjectEnv,
    teamRbac: input.teamRbac,
    onboarding: input.onboarding,
  });
}

async function createCloudflareD1Policies(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsolePolicyService> {
  return await createD1ConsolePolicyService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1Wallets(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleWalletService> {
  return await createD1ConsoleWalletService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1ApiKeys(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleApiKeyService> {
  return await createD1ConsoleApiKeyService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1Approvals(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleApprovalService> {
  return await createD1ConsoleApprovalService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1KeyExports(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleKeyExportService> {
  return await createD1ConsoleKeyExportService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1Observability(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleObservabilityService> {
  return await createD1ConsoleObservabilityService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
    queryMaxWindowMs: options.observabilityQueryMaxWindowMs,
  });
}

async function createCloudflareD1ObservabilityIngestion(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleObservabilityIngestionService> {
  return await createD1ConsoleObservabilityIngestionService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
    redactionPolicy: options.observabilityRedactionPolicy,
    maxBatchSize: options.observabilityMaxBatchSize,
    maxEventsPerMinute: options.observabilityMaxEventsPerMinute,
  });
}

async function createCloudflareD1Webhooks(input: {
  readonly options: NormalizedCloudflareD1ConsoleCommonOptions;
  readonly observabilityIngestion: ConsoleObservabilityIngestionService;
}): Promise<ConsoleWebhookService | null> {
  const options = input.options;
  if (!options.webhookSecretCipher) return null;
  const logger = normalizeLogger(options.logger);
  return await createD1ConsoleWebhookService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
    dispatcher: options.webhookDispatcher,
    secretCipher: options.webhookSecretCipher,
    observabilityIngestion: input.observabilityIngestion,
    observabilityLogger: logger,
    endpointDegradedThreshold: options.webhookEndpointDegradedThreshold,
  });
}

function createCloudflareD1Onboarding(input: {
  readonly options: NormalizedCloudflareD1ConsoleCommonOptions;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly apiKeys: ConsoleApiKeyService;
  readonly billing: ConsoleBillingService;
  readonly teamRbac: ConsoleTeamRbacService;
}): ConsoleOnboardingService {
  return createInMemoryConsoleOnboardingService({
    orgProjectEnv: input.orgProjectEnv,
    apiKeys: input.apiKeys,
    billing: input.billing,
    teamRbac: input.teamRbac,
    logger: input.options.logger,
  });
}

async function createCloudflareD1Audit(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleAuditService> {
  return await createD1ConsoleAuditService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1BootstrapTokens(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleBootstrapTokenService> {
  return await createD1ConsoleBootstrapTokenService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1SponsoredCalls(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleSponsoredCallService> {
  return await createD1ConsoleSponsoredCallService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    now: options.now,
  });
}

async function ensureCloudflareD1SponsorshipPricingSchema(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<void> {
  if (!options.ensureSchema) return;
  await ensureConsoleSponsorshipPricingD1Schema({
    database: options.consoleDatabase,
  });
}

async function createCloudflareD1SpendCaps(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleSponsorshipSpendCapService> {
  return await createD1ConsoleSponsorshipSpendCapService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1RuntimeSnapshots(
  options: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<ConsoleRuntimeSnapshotService> {
  return await createD1ConsoleRuntimeSnapshotService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
    logger: options.logger,
    retentionTtlMs: options.runtimeSnapshotRetentionTtlMs,
    retentionPruneIntervalMs: options.runtimeSnapshotRetentionPruneIntervalMs,
    retentionBatchSize: options.runtimeSnapshotRetentionBatchSize,
  });
}

async function createCloudflareD1ConsoleCommonServices(
  normalized: NormalizedCloudflareD1ConsoleCommonOptions,
): Promise<CloudflareD1ConsoleCommonServices> {
  const orgProjectEnv = await createCloudflareD1OrgProjectEnv(normalized);
  const teamRbac = await createCloudflareD1TeamRbac(normalized);
  const policies = await createCloudflareD1Policies(normalized);
  const wallets = await createCloudflareD1Wallets(normalized);
  const apiKeys = await createCloudflareD1ApiKeys(normalized);
  const approvals = await createCloudflareD1Approvals(normalized);
  const keyExports = await createCloudflareD1KeyExports(normalized);
  const observability = await createCloudflareD1Observability(normalized);
  const observabilityIngestion = await createCloudflareD1ObservabilityIngestion(normalized);
  const webhooks = await createCloudflareD1Webhooks({
    options: normalized,
    observabilityIngestion,
  });
  const audit = await createCloudflareD1Audit(normalized);
  const billing = await createCloudflareD1Billing(normalized);
  const prepaidReservations = await createCloudflareD1PrepaidReservations(normalized);
  const sponsoredCalls = await createCloudflareD1SponsoredCalls(normalized);
  await ensureCloudflareD1SponsorshipPricingSchema(normalized);
  const runtimeSnapshots = await createCloudflareD1RuntimeSnapshots(normalized);
  const onboarding = createCloudflareD1Onboarding({
    options: normalized,
    orgProjectEnv,
    apiKeys,
    billing,
    teamRbac,
  });
  const account = await createCloudflareD1Account({
    options: normalized,
    orgProjectEnv,
    teamRbac,
    onboarding,
  });
  return {
    orgProjectEnv,
    teamRbac,
    account,
    policies,
    wallets,
    apiKeys,
    approvals,
    keyExports,
    webhooks,
    observability,
    observabilityIngestion,
    onboarding,
    audit,
    billing,
    prepaidReservations,
    sponsoredCalls,
    runtimeSnapshots,
  };
}

export function createCloudflareD1SigningRootSecretAdapters(
  options: CloudflareD1SigningRootSecretAdapterOptions,
): CloudflareD1SigningRootSecretAdapters {
  const signingRootSecretStore = new D1SigningRootSecretStore({
    database: options.route.signer.metadataDatabase,
    namespace: options.route.namespace,
    orgId: options.route.orgId,
    projectId: requireSigningRootAdapterString(options.projectId, 'projectId'),
    envId: requireSigningRootAdapterString(options.envId, 'envId'),
    envelopeVersion: requireSigningRootAdapterString(
      options.envelopeVersion,
      'envelopeVersion',
    ),
    lastAuditEventId: requireSigningRootAdapterString(
      options.lastAuditEventId,
      'lastAuditEventId',
    ),
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
  const signingRootShareStore =
    createCloudflareD1SigningRootSecretShareStore(signingRootSecretStore);
  const signingRootShareDecryptAdapter =
    createCloudflareD1SigningRootShareDecryptAdapter(options.route.signer.kekProvider);
  return {
    signingRootSecretStore,
    signingRootShareStore,
    signingRootShareDecryptAdapter,
    signingRootSharePolicy: options.policy,
    signingRootShareResolverAdapters: {
      policy: options.policy,
      storageAdapter: signingRootShareStore,
      decryptAdapter: signingRootShareDecryptAdapter,
    },
  };
}

function createCloudflareD1ConsoleRouterStorageOptions(input: {
  readonly tenantStorageRouteResolver: TenantStorageRouteResolver;
  readonly tenantStorageNamespace: string;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly teamRbac: ConsoleTeamRbacService;
  readonly account: ConsoleAccountService;
  readonly policies: ConsolePolicyService;
  readonly wallets: ConsoleWalletService;
  readonly apiKeys: ConsoleApiKeyService;
  readonly approvals: ConsoleApprovalService;
  readonly keyExports: ConsoleKeyExportService;
  readonly webhooks: ConsoleWebhookService | null;
  readonly observability: ConsoleObservabilityService;
  readonly observabilityIngestion: ConsoleObservabilityIngestionService;
  readonly onboarding: ConsoleOnboardingService;
  readonly audit: ConsoleAuditService;
  readonly billing: ConsoleBillingService;
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService;
  readonly sponsoredCalls: ConsoleSponsoredCallService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
}): CloudflareD1ConsoleRouterStorageOptions {
  return {
    tenantStorageRouteResolver: input.tenantStorageRouteResolver,
    tenantStorageNamespace: input.tenantStorageNamespace,
    orgProjectEnv: input.orgProjectEnv,
    teamRbac: input.teamRbac,
    account: input.account,
    policies: input.policies,
    wallets: input.wallets,
    apiKeys: input.apiKeys,
    approvals: input.approvals,
    keyExports: input.keyExports,
    webhooks: input.webhooks,
    observability: input.observability,
    observabilityIngestion: input.observabilityIngestion,
    onboarding: input.onboarding,
    audit: input.audit,
    billing: input.billing,
    prepaidReservations: input.prepaidReservations,
    sponsoredCalls: input.sponsoredCalls,
    runtimeSnapshots: input.runtimeSnapshots,
  };
}

function createCloudflareD1RouterApiStorageOptions(input: {
  readonly options: NormalizedCloudflareD1ConsoleServiceBundleOptions;
  readonly sponsorshipPricing: SponsorshipSpendPricingService | null;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly wallets: ConsoleWalletService;
  readonly apiKeys: ConsoleApiKeyService;
  readonly bootstrapTokens: ConsoleBootstrapTokenService;
  readonly billing: ConsoleBillingService;
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService;
  readonly spendCaps: ConsoleSponsorshipSpendCapService;
  readonly sponsoredCalls: ConsoleSponsoredCallService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
  readonly observabilityIngestion: ConsoleObservabilityIngestionService;
  readonly webhooks: ConsoleWebhookService | null;
}): CloudflareD1RouterApiStorageOptions {
  const { options } = input;
  const admissionStore = createCloudflareDurableObjectRouterAbNormalSigningAdmissionStore({
    namespace: options.thresholdStore,
    storageNamespace: options.namespace,
  });
  const sponsoredEvmCallConfig = options.sponsoredEvmCallConfig || null;
  const apiKeyAuth = createRouterApiKeyAuthAdapter(input.apiKeys);
  const publishableKeyAuth = createRouterApiPublishableKeyAuthAdapter(input.apiKeys);
  const bootstrapGrantBroker = createRouterApiBootstrapGrantBroker({
    apiKeys: input.apiKeys,
    tokenStore: input.bootstrapTokens,
    orgProjectEnv: input.orgProjectEnv,
    tokenTtlMs: options.bootstrapGrantTokenTtlMs,
    rateLimitsByBucket: {
      default: { windowMs: 60_000, maxIssued: 60 },
      default_web_v1: { windowMs: 60_000, maxIssued: 60 },
    },
    quotasByBucket: {
      default: { maxIssued: 1_000 },
      free_registrations_v1: { maxIssued: 100_000 },
    },
  });
  const bootstrapTokenVerifier = createRouterApiBootstrapTokenVerifier(input.bootstrapTokens);
  return {
    sponsorship: {
      spendCaps: input.spendCaps,
      pricing: input.sponsorshipPricing,
      prepaidReservations: input.prepaidReservations,
    },
    observabilityIngestion: input.observabilityIngestion,
    apiKeyAuth,
    publishableKeyAuth,
    apiKeyUsageMeter: createRouterApiBillingUsageMeterAdapter(input.billing, {
      orgProjectEnv: input.orgProjectEnv,
      wallets: input.wallets,
    }),
    bootstrapTokenVerifier,
    orgProjectEnv: input.orgProjectEnv,
    routeExtensions: createConsoleRouterApiRouteExtensions({
      apiKeyAuth,
      bootstrapGrantBroker,
      ...(sponsoredEvmCallConfig
        ? {
            sponsoredEvmCall: {
              publishableKeyAuth,
              billing: input.billing,
              ledger: input.sponsoredCalls,
              runtimeSnapshots: input.runtimeSnapshots,
              config: sponsoredEvmCallConfig,
              resolveExecutionAdapter: options.resolveSponsoredEvmExecutionAdapter || null,
              observabilityIngestion: input.observabilityIngestion,
              prepaidReservations: input.prepaidReservations,
              pricing: input.sponsorshipPricing,
              spendCaps: input.spendCaps,
              webhooks: input.webhooks,
            },
          }
        : {}),
      wallets: input.wallets,
    }),
    routerAbNormalSigningAdmission:
      createRouterAbNormalSigningAdmissionAdapter(admissionStore),
  };
}

async function createCloudflareD1RouterApiSponsorshipPricing(
  options: NormalizedCloudflareD1ConsoleServiceBundleOptions,
): Promise<SponsorshipSpendPricingService | null> {
  if (options.sponsorshipPricing !== undefined) return options.sponsorshipPricing;
  if (!options.sponsoredEvmCallConfig) return null;
  return await createD1ConsoleSponsorshipPricingService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: false,
    now: options.now,
  });
}

export async function createCloudflareD1ConsoleServiceBundle(
  options: CloudflareD1ConsoleServiceBundleOptions,
): Promise<CloudflareD1ConsoleServiceBundle> {
  const normalized = normalizeCloudflareD1ConsoleServiceBundleOptions(options);
  const tenantStorageRouteResolver = createCloudflareD1TenantRouteResolver(normalized);
  const services = await createCloudflareD1ConsoleCommonServices(normalized);
  const apiKeys = normalized.sponsoredEvmCallConfig
      ? createTempoOnboardingApiKeyService({
          apiKeys: services.apiKeys,
          orgProjectEnv: services.orgProjectEnv,
          policies: services.policies,
          runtimeSnapshots: services.runtimeSnapshots,
          pricingSeed: {
            database: normalized.consoleDatabase,
            namespace: normalized.namespace,
            now: normalized.now,
          },
        })
    : services.apiKeys;
  const servicesWithApiKeys = {
    ...services,
    apiKeys,
  };
  const bootstrapTokens = await createCloudflareD1BootstrapTokens(normalized);
  const spendCaps = await createCloudflareD1SpendCaps(normalized);
  const sponsorshipPricing = await createCloudflareD1RouterApiSponsorshipPricing(normalized);
  const consoleRouterOptions = createCloudflareD1ConsoleRouterStorageOptions({
    tenantStorageRouteResolver,
    tenantStorageNamespace: normalized.namespace,
    ...servicesWithApiKeys,
  });
  const routerApiRouterOptions = createCloudflareD1RouterApiStorageOptions({
    options: normalized,
    sponsorshipPricing,
    orgProjectEnv: servicesWithApiKeys.orgProjectEnv,
    wallets: servicesWithApiKeys.wallets,
    apiKeys: servicesWithApiKeys.apiKeys,
    bootstrapTokens,
    billing: servicesWithApiKeys.billing,
    prepaidReservations: servicesWithApiKeys.prepaidReservations,
    spendCaps,
    sponsoredCalls: servicesWithApiKeys.sponsoredCalls,
    runtimeSnapshots: servicesWithApiKeys.runtimeSnapshots,
    observabilityIngestion: servicesWithApiKeys.observabilityIngestion,
    webhooks: servicesWithApiKeys.webhooks,
  });
  return {
    tenantStorageRouteResolver,
    tenantStorageNamespace: normalized.namespace,
    ...servicesWithApiKeys,
    bootstrapTokens,
    spendCaps,
    consoleRouterOptions,
    routerApiRouterOptions,
  };
}

export async function createCloudflareD1ConsoleOnlyServiceBundle(
  options: CloudflareD1ConsoleOnlyServiceBundleOptions,
): Promise<CloudflareD1ConsoleOnlyServiceBundle> {
  const normalized = normalizeCloudflareD1ConsoleOnlyServiceBundleOptions(options);
  const services = await createCloudflareD1ConsoleCommonServices(normalized);
  return {
    tenantStorageNamespace: normalized.namespace,
    ...services,
    consoleRouterOptions: {
      ...services,
    },
  };
}

export function asConsoleRouterOptions(
  input: CloudflareD1ConsoleRouterStorageOptions,
): CloudflareD1ConsoleRouterStorageOptions {
  return input;
}

export function asRouterApiOptions(
  input: CloudflareD1RouterApiStorageOptions,
): CloudflareD1RouterApiStorageOptions {
  return input;
}
