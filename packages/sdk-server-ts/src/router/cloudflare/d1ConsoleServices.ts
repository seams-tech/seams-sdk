import type { Logger } from '../../core/logger';
import type { CloudflareDurableObjectNamespaceLike } from '../../core/types';
import type { SigningRootKekProvider } from '../../core/ThresholdService/signingRootKekProvider';
import {
  createD1ConsoleBillingPrepaidReservationService,
  type ConsoleBillingPrepaidReservationService,
} from '../../console/billingPrepaidReservations';
import {
  createD1ConsoleSponsoredCallService,
  type ConsoleSponsoredCallService,
} from '../../console/sponsoredCalls';
import {
  createD1ConsoleRuntimeSnapshotService,
  type ConsoleRuntimeSnapshotService,
} from '../../console/runtimeSnapshots';
import {
  createStaticCloudflareTenantStorageRouteResolverFromBindings,
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
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService;
  readonly sponsoredCalls: ConsoleSponsoredCallService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
}

export interface CloudflareD1ConsoleServiceBundle {
  readonly tenantStorageRouteResolver: TenantStorageRouteResolver;
  readonly tenantStorageNamespace: string;
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService;
  readonly sponsoredCalls: ConsoleSponsoredCallService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
  readonly consoleRouterOptions: CloudflareD1ConsoleRouterStorageOptions;
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

function createCloudflareD1ConsoleRouterStorageOptions(input: {
  readonly tenantStorageRouteResolver: TenantStorageRouteResolver;
  readonly tenantStorageNamespace: string;
  readonly prepaidReservations: ConsoleBillingPrepaidReservationService;
  readonly sponsoredCalls: ConsoleSponsoredCallService;
  readonly runtimeSnapshots: ConsoleRuntimeSnapshotService;
}): CloudflareD1ConsoleRouterStorageOptions {
  return {
    tenantStorageRouteResolver: input.tenantStorageRouteResolver,
    tenantStorageNamespace: input.tenantStorageNamespace,
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
  const prepaidReservations = await createCloudflareD1PrepaidReservations(normalized);
  const sponsoredCalls = await createCloudflareD1SponsoredCalls(normalized);
  const runtimeSnapshots = await createCloudflareD1RuntimeSnapshots(normalized);
  const consoleRouterOptions = createCloudflareD1ConsoleRouterStorageOptions({
    tenantStorageRouteResolver,
    tenantStorageNamespace: normalized.namespace,
    prepaidReservations,
    sponsoredCalls,
    runtimeSnapshots,
  });
  return {
    tenantStorageRouteResolver,
    tenantStorageNamespace: normalized.namespace,
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
