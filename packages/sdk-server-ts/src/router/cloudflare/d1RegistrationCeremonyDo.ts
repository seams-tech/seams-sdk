import { toOptionalTrimmedString } from '@shared/utils/validation';
import { THRESHOLD_DO_OBJECT_NAME_DEFAULT } from '../../core/defaultConfigsServer';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
  ThresholdStoreConfigInput,
} from '../../core/types';
import { isRecordValue, toRecordValue } from './d1RouterApiAuthBoundary';

type CloudflareDoResponse<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly code?: string; readonly message?: string };

type CloudflareDoSetRequest = {
  readonly op: 'set';
  readonly key: string;
  readonly value: unknown;
  readonly ttlMs?: number;
};

type CloudflareDoReserveReplayGuardRequest = {
  readonly op: 'authReserveReplayGuard';
  readonly key: string;
  readonly expiresAtMs: number;
};

type CloudflareDoGetRequest = {
  readonly op: 'get';
  readonly key: string;
};

type CloudflareDoGetDelRequest = {
  readonly op: 'getdel';
  readonly key: string;
};

type CloudflareRegistrationIntentDoRequest =
  | CloudflareDoSetRequest
  | CloudflareDoReserveReplayGuardRequest
  | CloudflareDoGetRequest
  | CloudflareDoGetDelRequest;

export type RegistrationCeremonyDoConfig = {
  readonly namespace: CloudflareDurableObjectNamespaceLike;
  readonly objectName: string;
  readonly prefix: string;
};

export function resolveRegistrationCeremonyDoConfig(
  input: ThresholdStoreConfigInput | null | undefined,
): RegistrationCeremonyDoConfig | null {
  const config = toRecordValue(input);
  if (!config) return null;
  if (toOptionalTrimmedString(config.kind) !== 'cloudflare-do') return null;
  const namespace = config.namespace;
  if (!isCloudflareDurableObjectNamespaceLike(namespace)) return null;
  return {
    namespace,
    objectName: resolveRegistrationCeremonyDoObjectName(config),
    prefix: resolveRegistrationCeremonyDoPrefix(config),
  };
}

export async function callRegistrationCeremonyDo<T>(
  stub: CloudflareDurableObjectStubLike,
  request: CloudflareRegistrationIntentDoRequest,
): Promise<CloudflareDoResponse<T>> {
  const response = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  const body = await readDoJsonResponse(response);
  return parseDoResponse<T>(body);
}

export function resolveRegistrationCeremonyDoStub(
  input: RegistrationCeremonyDoConfig,
): CloudflareDurableObjectStubLike {
  const id = input.namespace.idFromName(input.objectName);
  return input.namespace.get(id);
}

function resolveRegistrationCeremonyDoObjectName(config: Record<string, unknown>): string {
  return (
    toOptionalTrimmedString(config.name) ||
    toOptionalTrimmedString(config.objectName) ||
    THRESHOLD_DO_OBJECT_NAME_DEFAULT
  );
}

function resolveRegistrationCeremonyDoPrefix(config: Record<string, unknown>): string {
  const explicit =
    toOptionalTrimmedString(config.WALLET_REGISTRATION_PREFIX) ||
    toOptionalTrimmedString(config.walletRegistrationPrefix);
  const base =
    explicit ||
    toOptionalTrimmedString(config.keyPrefix) ||
    toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  if (!base) return 'wallet-registration:';
  return base.endsWith(':') ? `${base}wallet-registration:` : `${base}:wallet-registration:`;
}

async function readDoJsonResponse(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function parseDoResponse<T>(body: unknown): CloudflareDoResponse<T> {
  if (!isRecordValue(body)) {
    return { ok: false, code: 'invalid_response', message: 'Durable Object returned invalid JSON' };
  }
  if (body.ok === true) return { ok: true, value: body.value as T };
  return {
    ok: false,
    code: toOptionalTrimmedString(body.code) || 'do_error',
    message: toOptionalTrimmedString(body.message) || 'Durable Object request failed',
  };
}

function isCloudflareDurableObjectNamespaceLike(
  value: unknown,
): value is CloudflareDurableObjectNamespaceLike {
  return (
    isRecordValue(value) &&
    typeof value.idFromName === 'function' &&
    typeof value.get === 'function'
  );
}
