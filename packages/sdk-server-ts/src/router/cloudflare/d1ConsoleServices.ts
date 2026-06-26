import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { Logger } from '../../core/logger';
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
import {
  D1SigningRootSecretStore,
  type SigningRootSecretShareSource,
} from '../../core/ThresholdService/stores/SigningRootSecretStore';
import {
  normalizeSigningRootSecretShareId,
  type SealedSigningRootSecretShare,
} from '../../core/ThresholdService/signingRootSecretShareWires';
import {
  createD1ConsoleAccountService,
  type ConsoleAccountService,
} from '../../console/account';
import {
  createD1ConsoleBillingPrepaidReservationService,
  type ConsoleBillingPrepaidReservationService,
} from '../../console/billingPrepaidReservations';
import {
  createD1ConsoleOrgProjectEnvService,
  type ConsoleOrgProjectEnvService,
} from '../../console/orgProjectEnv';
import {
  createD1ConsoleSponsoredCallService,
  type ConsoleSponsoredCallService,
} from '../../console/sponsoredCalls';
import {
  createD1ConsoleTeamRbacService,
  type ConsoleTeamRbacService,
} from '../../console/teamRbac';
import {
  createD1ConsoleRuntimeSnapshotService,
  type ConsoleRuntimeSnapshotService,
} from '../../console/runtimeSnapshots';
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

export interface CloudflareD1ConsoleStorageBindings {
  readonly consoleDatabase: D1DatabaseLike;
  readonly signerMetadataDatabase: D1DatabaseLike;
  readonly thresholdStore: CloudflareDurableObjectNamespaceLike;
  readonly kekProvider: SigningRootKekProvider;
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
  readonly defaultPrepaidReservationTtlMs?: number;
  readonly runtimeSnapshotRetentionTtlMs?: number;
  readonly runtimeSnapshotRetentionPruneIntervalMs?: number;
  readonly runtimeSnapshotRetentionBatchSize?: number;
}

export interface CloudflareD1ConsoleServiceBundleOptions {
  readonly bindings: CloudflareD1ConsoleStorageBindings;
  readonly route: CloudflareD1ConsoleRouteOptions;
  readonly bindingNames?: CloudflareD1ConsoleStorageBindingNames;
  readonly adapters?: CloudflareD1ConsoleAdapterOptions;
}

export interface CloudflareD1ConsoleRouterStorageOptions {
  readonly tenantStorageRouteResolver: TenantStorageRouteResolver;
  readonly tenantStorageNamespace: string;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly teamRbac: ConsoleTeamRbacService;
  readonly account: ConsoleAccountService;
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService;
  readonly sponsoredCalls: ConsoleSponsoredCallService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
}

export interface CloudflareD1ConsoleServiceBundle {
  readonly tenantStorageRouteResolver: TenantStorageRouteResolver;
  readonly tenantStorageNamespace: string;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly teamRbac: ConsoleTeamRbacService;
  readonly account: ConsoleAccountService;
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService;
  readonly sponsoredCalls: ConsoleSponsoredCallService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
  readonly consoleRouterOptions: CloudflareD1ConsoleRouterStorageOptions;
}

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

interface NormalizedCloudflareD1ConsoleServiceBundleOptions {
  readonly consoleDatabase: D1DatabaseLike;
  readonly signerMetadataDatabase: D1DatabaseLike;
  readonly thresholdStore: CloudflareDurableObjectNamespaceLike;
  readonly kekProvider: SigningRootKekProvider;
  readonly namespace: string;
  readonly routeVersion: number;
  readonly topology: CloudflareTenantTopology;
  readonly jurisdiction: TenantDataJurisdiction;
  readonly consoleBindingName: D1BindingName;
  readonly consoleDatabaseName: D1DatabaseName;
  readonly signerMetadataBindingName: D1BindingName;
  readonly signerMetadataDatabaseName: D1DatabaseName;
  readonly thresholdStoreBindingName: DurableObjectBindingName;
  readonly ensureSchema: boolean;
  readonly now?: () => Date;
  readonly logger?: Logger | null;
  readonly defaultPrepaidReservationTtlMs?: number;
  readonly runtimeSnapshotRetentionTtlMs?: number;
  readonly runtimeSnapshotRetentionPruneIntervalMs?: number;
  readonly runtimeSnapshotRetentionBatchSize?: number;
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

function createCloudflareD1SigningRootShareDecryptAdapter(
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
    defaultPrepaidReservationTtlMs: options.adapters?.defaultPrepaidReservationTtlMs,
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
  options: NormalizedCloudflareD1ConsoleServiceBundleOptions,
): Promise<ConsoleBillingPrepaidReservationService> {
  return await createD1ConsoleBillingPrepaidReservationService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
    defaultReservationTtlMs: options.defaultPrepaidReservationTtlMs,
  });
}

async function createCloudflareD1OrgProjectEnv(
  options: NormalizedCloudflareD1ConsoleServiceBundleOptions,
): Promise<ConsoleOrgProjectEnvService> {
  return await createD1ConsoleOrgProjectEnvService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1TeamRbac(
  options: NormalizedCloudflareD1ConsoleServiceBundleOptions,
): Promise<ConsoleTeamRbacService> {
  return await createD1ConsoleTeamRbacService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1Account(input: {
  readonly options: NormalizedCloudflareD1ConsoleServiceBundleOptions;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly teamRbac: ConsoleTeamRbacService;
}): Promise<ConsoleAccountService> {
  return await createD1ConsoleAccountService({
    database: input.options.consoleDatabase,
    namespace: input.options.namespace,
    ensureSchema: input.options.ensureSchema,
    now: input.options.now,
    orgProjectEnv: input.orgProjectEnv,
    teamRbac: input.teamRbac,
  });
}

async function createCloudflareD1SponsoredCalls(
  options: NormalizedCloudflareD1ConsoleServiceBundleOptions,
): Promise<ConsoleSponsoredCallService> {
  return await createD1ConsoleSponsoredCallService({
    database: options.consoleDatabase,
    namespace: options.namespace,
    ensureSchema: options.ensureSchema,
    now: options.now,
  });
}

async function createCloudflareD1RuntimeSnapshots(
  options: NormalizedCloudflareD1ConsoleServiceBundleOptions,
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
    prepaidReservations: input.prepaidReservations,
    sponsoredCalls: input.sponsoredCalls,
    runtimeSnapshots: input.runtimeSnapshots,
  };
}

export async function createCloudflareD1ConsoleServiceBundle(
  options: CloudflareD1ConsoleServiceBundleOptions,
): Promise<CloudflareD1ConsoleServiceBundle> {
  const normalized = normalizeCloudflareD1ConsoleServiceBundleOptions(options);
  const tenantStorageRouteResolver = createCloudflareD1TenantRouteResolver(normalized);
  const orgProjectEnv = await createCloudflareD1OrgProjectEnv(normalized);
  const teamRbac = await createCloudflareD1TeamRbac(normalized);
  const account = await createCloudflareD1Account({
    options: normalized,
    orgProjectEnv,
    teamRbac,
  });
  const prepaidReservations = await createCloudflareD1PrepaidReservations(normalized);
  const sponsoredCalls = await createCloudflareD1SponsoredCalls(normalized);
  const runtimeSnapshots = await createCloudflareD1RuntimeSnapshots(normalized);
  const consoleRouterOptions = createCloudflareD1ConsoleRouterStorageOptions({
    tenantStorageRouteResolver,
    tenantStorageNamespace: normalized.namespace,
    orgProjectEnv,
    teamRbac,
    account,
    prepaidReservations,
    sponsoredCalls,
    runtimeSnapshots,
  });
  return {
    tenantStorageRouteResolver,
    tenantStorageNamespace: normalized.namespace,
    orgProjectEnv,
    teamRbac,
    account,
    prepaidReservations,
    sponsoredCalls,
    runtimeSnapshots,
    consoleRouterOptions,
  };
}

export function asConsoleRouterOptions(
  input: CloudflareD1ConsoleRouterStorageOptions,
): CloudflareD1ConsoleRouterStorageOptions {
  return input;
}
