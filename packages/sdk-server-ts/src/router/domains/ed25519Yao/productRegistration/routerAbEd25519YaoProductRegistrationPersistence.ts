import {
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
} from '@shared/utils/routerAbEd25519Yao';
import type {
  VersionedJsonObject,
  VersionedJsonRecordPutResult,
  VersionedJsonRecordReadResult,
  VersionedJsonValue,
} from '../../../framework/versionedJsonRecordStore';
import {
  parseRouterAbEd25519YaoProductRegistrationStateV1,
  type RouterAbEd25519YaoProductRegistrationStateV1,
} from './routerAbEd25519YaoProductRegistration';

/**
 * A request-boundary key. It is intentionally limited to the opaque lifecycle
 * identifier already present in a validated Yao request; no wallet or account
 * value is accepted as a persistence partition key.
 */
export type RouterAbEd25519YaoCeremonyKeyV1 = {
  readonly kind: 'router_ab_ed25519_yao_ceremony_key_v1';
  readonly lifecycleId: string;
};

export type RouterAbEd25519YaoCeremonyKeyResolutionV1 =
  | { readonly kind: 'ceremony'; readonly value: RouterAbEd25519YaoCeremonyKeyV1 }
  | { readonly kind: 'none' }
  | { readonly kind: 'invalid'; readonly message: string };

/**
 * The persistence adapter used by a future request-scoped composition. The
 * adapter owns one record per ceremony and must implement an atomic version
 * check for every update. The generic Cloudflare JSON adapter can satisfy this
 * contract without exposing raw Durable Object storage to lifecycle code.
 */
export interface RouterAbEd25519YaoCeremonyStateStoreV1 {
  read(
    key: RouterAbEd25519YaoCeremonyKeyV1,
  ): Promise<VersionedJsonRecordReadResult<RouterAbEd25519YaoProductRegistrationStateV1>>;
  put(
    key: RouterAbEd25519YaoCeremonyKeyV1,
    value: RouterAbEd25519YaoProductRegistrationStateV1,
    expectedVersion: string | null,
  ): Promise<VersionedJsonRecordPutResult>;
}

type VersionedJsonStoreLike<T> = {
  read(key: string): Promise<VersionedJsonRecordReadResult<T>>;
  put(
    key: string,
    value: T,
    expectedVersion: string | null,
  ): Promise<VersionedJsonRecordPutResult>;
};

/** Bind the generic JSON adapter to the validated opaque ceremony key. */
export function createRouterAbEd25519YaoCeremonyStateStoreV1(
  store: VersionedJsonStoreLike<RouterAbEd25519YaoProductRegistrationStateV1>,
): RouterAbEd25519YaoCeremonyStateStoreV1 {
  return {
    read: async (key) => await store.read(key.lifecycleId),
    put: async (key, value, expectedVersion) =>
      await store.put(key.lifecycleId, value, expectedVersion),
  };
}

type EncodedStateValue = VersionedJsonValue;

const CODEC_KIND = 'router_ab_ed25519_yao_product_registration_state_json_v1';
const MAP_KIND = 'map_v1';
const SET_KIND = 'set_v1';
const BYTES_KIND = 'bytes_v1';

type EncodedMap = {
  readonly __seamsType: typeof MAP_KIND;
  readonly entries: readonly (readonly [string, EncodedStateValue])[];
};

type EncodedSet = {
  readonly __seamsType: typeof SET_KIND;
  readonly values: readonly EncodedStateValue[];
};

type EncodedBytes = {
  readonly __seamsType: typeof BYTES_KIND;
  readonly values: readonly number[];
};

type EncodedStateObject = {
  readonly [key: string]: EncodedStateValue;
};

type EncodedStateRecord = {
  readonly kind: typeof CODEC_KIND;
  readonly state: EncodedStateObject;
};

export function encodeRouterAbEd25519YaoProductRegistrationStateV1(
  state: RouterAbEd25519YaoProductRegistrationStateV1,
): VersionedJsonObject {
  const encoded = encodeStateValue(state);
  if (!isEncodedStateObject(encoded)) {
    throw new Error('Ed25519 Yao product state must encode to a JSON object');
  }
  return {
    kind: CODEC_KIND,
    state: encoded,
  } satisfies EncodedStateRecord;
}

export function parseRouterAbEd25519YaoProductRegistrationStateJsonV1(
  input: unknown,
): RouterAbEd25519YaoProductRegistrationStateV1 | null {
  if (!isRecord(input) || input.kind !== CODEC_KIND || !isRecord(input.state)) return null;
  const decoded = decodeStateValue(input.state);
  if (decoded === null || !isRecord(decoded)) return null;
  const parsed = parseRouterAbEd25519YaoProductRegistrationStateV1(decoded);
  return parsed.ok ? parsed.value : null;
}

export function parseRouterAbEd25519YaoCeremonyKeyV1(
  input: unknown,
): RouterAbEd25519YaoCeremonyKeyV1 | null {
  if (!isRecord(input)) return null;
  const lifecycleId = input.lifecycleId;
  if (!isVisibleLifecycleId(lifecycleId)) return null;
  return {
    kind: 'router_ab_ed25519_yao_ceremony_key_v1',
    lifecycleId,
  };
}

/**
 * Resolve only fields owned by the route's wire contract. This function does
 * not recursively search arbitrary JSON, which prevents unrelated identifiers
 * from silently becoming persistence keys.
 */
export async function resolveRouterAbEd25519YaoCeremonyKeyFromRequestV1(
  request: Request,
): Promise<RouterAbEd25519YaoCeremonyKeyResolutionV1> {
  const pathname = new URL(request.url).pathname;
  const source = ceremonyFieldSource(pathname);
  if (source.kind === 'none') return source;

  let body: unknown;
  try {
    body = await request.clone().json();
  } catch {
    return { kind: 'invalid', message: 'Yao ceremony request body must be valid JSON' };
  }
  const lifecycleId = readLifecycleId(body, source.field);
  if (lifecycleId === null) {
    return { kind: 'invalid', message: 'Yao ceremony lifecycle_id is required' };
  }
  if (!isVisibleLifecycleId(lifecycleId)) {
    return { kind: 'invalid', message: 'Yao ceremony lifecycle_id is invalid' };
  }
  return {
    kind: 'ceremony',
    value: {
      kind: 'router_ab_ed25519_yao_ceremony_key_v1',
      lifecycleId,
    },
  };
}

type CeremonyField =
  | 'scope.lifecycle_id'
  | 'binding.lifecycle.lifecycle_id'
  | 'binding.ceremony.lifecycle.lifecycle_id'
  | 'ed25519.activationReference.lifecycle_id';

type CeremonyFieldSource =
  | { readonly kind: 'none' }
  | { readonly kind: 'field'; readonly field: CeremonyField };

function ceremonyFieldSource(pathname: string): CeremonyFieldSource {
  switch (pathname) {
    case ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1:
    case ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1:
    case ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1:
      return { kind: 'field', field: 'scope.lifecycle_id' };
    case ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1:
    case ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1:
    case ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1:
      return { kind: 'field', field: 'binding.lifecycle.lifecycle_id' };
    case ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1:
      return { kind: 'field', field: 'binding.ceremony.lifecycle.lifecycle_id' };
    default:
      return /^\/wallets\/[^/]+\/signers\/finalize$/u.test(pathname)
        ? { kind: 'field', field: 'ed25519.activationReference.lifecycle_id' }
        : { kind: 'none' };
  }
}

function readLifecycleId(input: unknown, field: CeremonyField): string | null {
  if (!isRecord(input)) return null;
  switch (field) {
    case 'scope.lifecycle_id':
      return readString(input.scope, 'lifecycle_id');
    case 'binding.lifecycle.lifecycle_id':
      return readString(isRecord(input.binding) ? input.binding.lifecycle : null, 'lifecycle_id');
    case 'binding.ceremony.lifecycle.lifecycle_id': {
      const binding = isRecord(input.binding) ? input.binding : null;
      const ceremony = isRecord(binding?.ceremony) ? binding.ceremony : null;
      return readString(isRecord(ceremony?.lifecycle) ? ceremony.lifecycle : null, 'lifecycle_id');
    }
    case 'ed25519.activationReference.lifecycle_id': {
      const ed25519 = isRecord(input.ed25519) ? input.ed25519 : null;
      return readString(
        isRecord(ed25519?.activationReference) ? ed25519.activationReference : null,
        'lifecycle_id',
      );
    }
    default:
      return assertNever(field);
  }
}

function readString(input: unknown, key: string): string | null {
  if (!isRecord(input) || typeof input[key] !== 'string') return null;
  return input[key];
}

function isVisibleLifecycleId(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value.length > 0 &&
    value.length <= 256 &&
    /^[\x21-\x7e]+$/u.test(value)
  );
}

function encodeStateValue(value: unknown): EncodedStateValue {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Ed25519 Yao state contains a non-finite number');
    return value;
  }
  if (value instanceof Uint8Array) {
    return {
      __seamsType: BYTES_KIND,
      values: Array.from(value),
    } satisfies EncodedBytes;
  }
  if (value instanceof Map) {
    const entries: [string, EncodedStateValue][] = [];
    for (const [key, entry] of value) {
      if (typeof key !== 'string') throw new Error('Ed25519 Yao state Map keys must be strings');
      entries.push([key, encodeStateValue(entry)]);
    }
    return { __seamsType: MAP_KIND, entries } satisfies EncodedMap;
  }
  if (value instanceof Set) {
    return {
      __seamsType: SET_KIND,
      values: Array.from(value, encodeStateValue),
    } satisfies EncodedSet;
  }
  if (Array.isArray(value)) return value.map(encodeStateValue);
  if (isRecord(value)) {
    const object: Record<string, EncodedStateValue> = {};
    for (const [key, entry] of Object.entries(value)) object[key] = encodeStateValue(entry);
    return object;
  }
  throw new Error(`Ed25519 Yao state contains unsupported value: ${typeof value}`);
}

function decodeStateValue(value: unknown): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (Array.isArray(value)) return value.map(decodeStateValue);
  if (!isRecord(value)) return null;
  if (value.__seamsType === BYTES_KIND) {
    return decodeBytes(value.values);
  }
  if (value.__seamsType === MAP_KIND) {
    return decodeMap(value.entries);
  }
  if (value.__seamsType === SET_KIND) {
    return decodeSet(value.values);
  }
  const object: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    const decoded = decodeStateValue(entry);
    if (decoded === null && entry !== null) return null;
    object[key] = decoded;
  }
  return object;
}

function decodeBytes(value: unknown): Uint8Array | null {
  if (!Array.isArray(value)) return null;
  const bytes = value.map((entry) => (typeof entry === 'number' ? entry : NaN));
  if (bytes.some((entry) => !Number.isSafeInteger(entry) || entry < 0 || entry > 255)) {
    return null;
  }
  return Uint8Array.from(bytes);
}

function decodeMap(value: unknown): Map<string, unknown> | null {
  if (!Array.isArray(value)) return null;
  const map = new Map<string, unknown>();
  for (const entry of value) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string') return null;
    const decoded = decodeStateValue(entry[1]);
    if (decoded === null && entry[1] !== null) return null;
    map.set(entry[0], decoded);
  }
  return map;
}

function decodeSet(value: unknown): Set<unknown> | null {
  if (!Array.isArray(value)) return null;
  const set = new Set<unknown>();
  for (const entry of value) {
    const decoded = decodeStateValue(entry);
    if (decoded === null && entry !== null) return null;
    set.add(decoded);
  }
  return set;
}

function isEncodedStateObject(value: EncodedStateValue): value is EncodedStateObject {
  return isRecord(value) && !('__seamsType' in value);
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return typeof input === 'object' && input !== null && !Array.isArray(input);
}

function assertNever(value: never): never {
  throw new Error(`Unsupported Ed25519 Yao ceremony field: ${String(value)}`);
}
