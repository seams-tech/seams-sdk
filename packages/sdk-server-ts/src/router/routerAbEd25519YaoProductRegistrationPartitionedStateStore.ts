import type {
  CloudflareVersionedJsonObject,
  CloudflareVersionedJsonRecordReadResult,
} from './cloudflare/versionedJsonRecordStore';
import {
  createCloudflareD1VersionedJsonRecordStore,
  type CloudflareD1VersionedJsonRecordStoreOptions,
} from './cloudflare/d1VersionedJsonRecordStore';
import { createRouterAbEd25519YaoProductRegistrationStateV1 } from './routerAbEd25519YaoProductRegistration';
import type { RouterAbEd25519YaoProductRegistrationStateV1 } from './routerAbEd25519YaoProductRegistration';
import {
  encodeRouterAbEd25519YaoProductRegistrationStateV1,
  parseRouterAbEd25519YaoProductRegistrationStateJsonV1,
} from './routerAbEd25519YaoProductRegistrationPersistence';
import {
  mergeRouterAbEd25519YaoProductRegistrationStatePartitionV1,
  partitionRouterAbEd25519YaoProductRegistrationStateV1,
  type RouterAbEd25519YaoProductRegistrationCeremonyStateV1,
  type RouterAbEd25519YaoProductRegistrationSharedStateV1,
} from './routerAbEd25519YaoProductRegistrationPartitioning';

export const ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1 = 'router-ab-ed25519-yao:shared';
const PARTITION_RECORD_CODEC_KIND =
  'router_ab_ed25519_yao_product_registration_partition_record_json_v1';
const SHARED_RECORD_KIND = 'router_ab_ed25519_yao_product_registration_shared_record_v1';
const CEREMONY_RECORD_KIND = 'router_ab_ed25519_yao_product_registration_ceremony_record_v1';

type EncodedPartitionRecord = {
  readonly kind: typeof PARTITION_RECORD_CODEC_KIND;
  readonly recordKind: typeof SHARED_RECORD_KIND | typeof CEREMONY_RECORD_KIND;
  readonly lifecycleId: string;
  readonly state: CloudflareVersionedJsonObject;
};

export type RouterAbEd25519YaoProductRegistrationPartitionRecordV1 =
  | {
      readonly kind: typeof SHARED_RECORD_KIND;
      readonly value: RouterAbEd25519YaoProductRegistrationSharedStateV1;
    }
  | {
      readonly kind: typeof CEREMONY_RECORD_KIND;
      readonly lifecycleId: string;
      readonly value: RouterAbEd25519YaoProductRegistrationCeremonyStateV1;
    };

export type RouterAbEd25519YaoProductRegistrationPartitionMutationV1 = {
  readonly key: string;
  readonly value: RouterAbEd25519YaoProductRegistrationPartitionRecordV1;
  readonly expectedVersion: string | null;
};

export type RouterAbEd25519YaoProductRegistrationPartitionBatchResultV1 =
  | {
      readonly kind: 'stored';
      readonly versions: readonly {
        readonly key: string;
        readonly version: string;
      }[];
    }
  | { readonly kind: 'version_mismatch'; readonly key: string };

export type RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1 = {
  readonly readMany: (
    keys: readonly string[],
  ) => Promise<
    readonly {
      readonly key: string;
      readonly result: CloudflareVersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>;
    }[]
  >;
  readonly putMany: (
    mutations: readonly RouterAbEd25519YaoProductRegistrationPartitionMutationV1[],
  ) => Promise<RouterAbEd25519YaoProductRegistrationPartitionBatchResultV1>;
};

export type RouterAbEd25519YaoProductRegistrationPartitionedStateV1 = {
  readonly kind: 'router_ab_ed25519_yao_product_registration_partitioned_state_v1';
  readonly state: RouterAbEd25519YaoProductRegistrationStateV1;
  readonly sharedState: RouterAbEd25519YaoProductRegistrationSharedStateV1;
  readonly sharedVersion: string | null;
  readonly ceremonyVersion: string | null;
};

export type RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1 = {
  readonly lifecycleId: string;
  readonly state: RouterAbEd25519YaoProductRegistrationStateV1;
  readonly sharedState: RouterAbEd25519YaoProductRegistrationSharedStateV1;
  readonly sharedVersion: string | null;
  readonly ceremonyVersion: string | null;
};

export type RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1 =
  | {
      readonly kind: 'stored';
      readonly sharedVersion: string | null;
      readonly ceremonyVersion: string;
    }
  | { readonly kind: 'version_mismatch'; readonly key: 'shared' | 'ceremony' };

export interface RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  load(lifecycleId: string): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateV1>;
  commit(
    input: RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1>;
}

export function createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1(
  store: RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1,
): RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  return new RouterAbEd25519YaoProductRegistrationPartitionedStateStore(store);
}

export type RouterAbEd25519YaoProductRegistrationPartitionedStateD1OptionsV1 = Omit<
  CloudflareD1VersionedJsonRecordStoreOptions<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>,
  'encode' | 'parse'
>;

export function createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1(
  options: RouterAbEd25519YaoProductRegistrationPartitionedStateD1OptionsV1,
): RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  const records = createCloudflareD1VersionedJsonRecordStore({
    ...options,
    encode: encodeRouterAbEd25519YaoProductRegistrationPartitionRecordV1,
    parse: parseRouterAbEd25519YaoProductRegistrationPartitionRecordV1,
  });
  return createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1({
    readMany: records.readMany.bind(records),
    putMany: records.putMany.bind(records),
  });
}

export function encodeRouterAbEd25519YaoProductRegistrationPartitionRecordV1(
  record: RouterAbEd25519YaoProductRegistrationPartitionRecordV1,
): CloudflareVersionedJsonObject {
  const lifecycleId = record.kind === SHARED_RECORD_KIND ? 'shared' : record.lifecycleId;
  const state = createRouterAbEd25519YaoProductRegistrationStateV1();
  const empty = partitionRouterAbEd25519YaoProductRegistrationStateV1(state, lifecycleId);
  const materialized = mergeRouterAbEd25519YaoProductRegistrationStatePartitionV1(state, {
    kind: 'router_ab_ed25519_yao_product_registration_state_partition_v1',
    lifecycleId,
    shared: record.kind === SHARED_RECORD_KIND ? record.value : empty.shared,
    ceremony: record.kind === CEREMONY_RECORD_KIND ? record.value : empty.ceremony,
  });
  return {
    kind: PARTITION_RECORD_CODEC_KIND,
    recordKind: record.kind,
    lifecycleId,
    state: encodeRouterAbEd25519YaoProductRegistrationStateV1(materialized),
  } satisfies EncodedPartitionRecord;
}

export function parseRouterAbEd25519YaoProductRegistrationPartitionRecordV1(
  input: unknown,
): RouterAbEd25519YaoProductRegistrationPartitionRecordV1 | null {
  if (!isRecord(input) || input.kind !== PARTITION_RECORD_CODEC_KIND) return null;
  if (input.recordKind !== SHARED_RECORD_KIND && input.recordKind !== CEREMONY_RECORD_KIND) {
    return null;
  }
  const lifecycleId = readLifecycleId(input.lifecycleId);
  if (lifecycleId === null) return null;
  const state = parseRouterAbEd25519YaoProductRegistrationStateJsonV1(input.state);
  if (state === null) return null;
  const partition = partitionRouterAbEd25519YaoProductRegistrationStateV1(state, lifecycleId);
  if (
    stateFingerprint(state) !==
    stateFingerprint(materializeState(partition.shared, partition.ceremony))
  ) {
    return null;
  }
  if (input.recordKind === SHARED_RECORD_KIND) {
    if (lifecycleId !== 'shared') return null;
    return { kind: SHARED_RECORD_KIND, value: partition.shared };
  }
  if (partition.ceremony.lifecycleId !== lifecycleId) return null;
  return { kind: CEREMONY_RECORD_KIND, lifecycleId, value: partition.ceremony };
}

class RouterAbEd25519YaoProductRegistrationPartitionedStateStore implements RouterAbEd25519YaoProductRegistrationPartitionedStateStoreV1 {
  constructor(
    private readonly store: RouterAbEd25519YaoProductRegistrationPartitionRecordStoreV1,
  ) {}

  async load(
    lifecycleId: string,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateV1> {
    const normalizedLifecycleId = requireLifecycleId(lifecycleId);
    const entries = await this.store.readMany([
      ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1,
      normalizedLifecycleId,
    ]);
    const sharedResult = readManyEntry(
      entries,
      ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1,
    );
    const ceremonyResult = readManyEntry(entries, normalizedLifecycleId);
    const shared = readSharedRecord(sharedResult);
    const ceremony = readCeremonyRecord(ceremonyResult, normalizedLifecycleId);
    return {
      kind: 'router_ab_ed25519_yao_product_registration_partitioned_state_v1',
      state: materializeState(shared.value, ceremony.value),
      sharedState: shared.value,
      sharedVersion: shared.version,
      ceremonyVersion: ceremony.version,
    };
  }

  async commit(
    input: RouterAbEd25519YaoProductRegistrationPartitionedStateCommitInputV1,
  ): Promise<RouterAbEd25519YaoProductRegistrationPartitionedStateCommitResultV1> {
    const lifecycleId = requireLifecycleId(input.lifecycleId);
    const partition = partitionRouterAbEd25519YaoProductRegistrationStateV1(
      input.state,
      lifecycleId,
    );
    const mutations: RouterAbEd25519YaoProductRegistrationPartitionMutationV1[] = [];
    if (stateFingerprint(partition.shared) !== stateFingerprint(input.sharedState)) {
      mutations.push({
        key: ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1,
        value: {
          kind: 'router_ab_ed25519_yao_product_registration_shared_record_v1',
          value: partition.shared,
        },
        expectedVersion: input.sharedVersion,
      });
    }
    mutations.push({
      key: lifecycleId,
      value: {
        kind: 'router_ab_ed25519_yao_product_registration_ceremony_record_v1',
        lifecycleId,
        value: partition.ceremony,
      },
      expectedVersion: input.ceremonyVersion,
    });
    const result = await this.store.putMany(mutations);
    if (result.kind === 'version_mismatch') {
      return {
        kind: 'version_mismatch',
        key:
          result.key === ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1 ? 'shared' : 'ceremony',
      };
    }
    const sharedVersion =
      mutations[0]?.key === ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1
        ? findStoredVersion(result.versions, ROUTER_AB_ED25519_YAO_SHARED_STATE_RECORD_KEY_V1)
        : input.sharedVersion;
    const ceremonyVersion = findStoredVersion(result.versions, lifecycleId);
    return { kind: 'stored', sharedVersion, ceremonyVersion };
  }
}

type ReadPartitionRecordResult = {
  readonly value: RouterAbEd25519YaoProductRegistrationSharedStateV1;
  readonly version: string | null;
};

function readManyEntry<T>(
  entries: readonly { readonly key: string; readonly result: T }[],
  key: string,
): T {
  const entry = entries.find((candidate) => candidate.key === key);
  if (!entry) throw new Error(`Router A/B batch read omitted ${key}`);
  return entry.result;
}

type ReadCeremonyRecordResult = {
  readonly value: RouterAbEd25519YaoProductRegistrationCeremonyStateV1;
  readonly version: string | null;
};

function readSharedRecord(
  result: CloudflareVersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>,
): ReadPartitionRecordResult {
  if (result.kind === 'missing') {
    const empty = partitionRouterAbEd25519YaoProductRegistrationStateV1(
      createRouterAbEd25519YaoProductRegistrationStateV1(),
      'initial',
    );
    return { value: empty.shared, version: null };
  }
  if (result.value.kind !== 'router_ab_ed25519_yao_product_registration_shared_record_v1') {
    throw new Error('Router A/B shared state record has an invalid kind');
  }
  return { value: structuredClone(result.value.value), version: result.version };
}

function readCeremonyRecord(
  result: CloudflareVersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationPartitionRecordV1>,
  lifecycleId: string,
): ReadCeremonyRecordResult {
  if (result.kind === 'missing') {
    const empty = partitionRouterAbEd25519YaoProductRegistrationStateV1(
      createRouterAbEd25519YaoProductRegistrationStateV1(),
      lifecycleId,
    );
    return { value: empty.ceremony, version: null };
  }
  if (
    result.value.kind !== 'router_ab_ed25519_yao_product_registration_ceremony_record_v1' ||
    result.value.lifecycleId !== lifecycleId ||
    result.value.value.lifecycleId !== lifecycleId
  ) {
    throw new Error('Router A/B ceremony state record does not match its lifecycle key');
  }
  return { value: structuredClone(result.value.value), version: result.version };
}

function materializeState(
  shared: RouterAbEd25519YaoProductRegistrationSharedStateV1,
  ceremony: RouterAbEd25519YaoProductRegistrationCeremonyStateV1,
): RouterAbEd25519YaoProductRegistrationStateV1 {
  const state = createRouterAbEd25519YaoProductRegistrationStateV1();
  return mergeRouterAbEd25519YaoProductRegistrationStatePartitionV1(state, {
    kind: 'router_ab_ed25519_yao_product_registration_state_partition_v1',
    lifecycleId: ceremony.lifecycleId,
    shared,
    ceremony,
  });
}

function findStoredVersion(
  versions: readonly { readonly key: string; readonly version: string }[],
  key: string,
): string {
  const entry = versions.find((candidate) => candidate.key === key);
  if (!entry) throw new Error(`Router A/B batch result omitted ${key}`);
  return entry.version;
}

function requireLifecycleId(value: string): string {
  if (!isVisibleLifecycleId(value)) throw new Error('Router A/B lifecycle ID is invalid');
  return value;
}

function isVisibleLifecycleId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 256 &&
    /^[\x21-\x7e]+$/u.test(value)
  );
}

function readLifecycleId(value: unknown): string | null {
  return isVisibleLifecycleId(value) ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stateFingerprint(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'string') return `string:${JSON.stringify(value)}`;
  if (typeof value === 'boolean') return `boolean:${value ? '1' : '0'}`;
  if (typeof value === 'number') return `number:${String(value)}`;
  if (value instanceof Uint8Array) return `bytes:${Array.from(value).join(',')}`;
  if (value instanceof Map) {
    return `map:${Array.from(value.entries())
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${stateFingerprint(key)}=${stateFingerprint(entry)}`)
      .join('|')}`;
  }
  if (value instanceof Set) {
    return `set:${Array.from(value, stateFingerprint).sort().join('|')}`;
  }
  if (Array.isArray(value)) return `array:${value.map(stateFingerprint).join('|')}`;
  if (typeof value === 'object') {
    return `object:${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${key}:${stateFingerprint(entry)}`)
      .join('|')}`;
  }
  throw new Error('Router A/B shared state contains an unsupported value');
}
