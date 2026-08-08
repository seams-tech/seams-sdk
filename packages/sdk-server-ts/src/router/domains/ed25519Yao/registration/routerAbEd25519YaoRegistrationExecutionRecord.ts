import {
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationResultV1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import type {
  VersionedJsonObject,
  VersionedJsonValue,
} from '../../../framework/versionedJsonRecordStore';
import type {
  RouterAbEd25519YaoRegistrationFailure,
  RouterAbEd25519YaoRegistrationFailureCode,
} from './routerAbEd25519YaoRegistration';

export const ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTION_RECORD_KIND_V1 =
  'router_ab_ed25519_yao_registration_execution_record_v1';

type AdmissionReceipt = RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
type ExecuteRequest = RouterAbEd25519YaoActivationExecuteRequestV1<'registration'>;
type ActivationResult = RouterAbEd25519YaoActivationResultV1<'registration'>;

type RegistrationExecutionAuthority = {
  readonly lifecycleId: string;
  readonly admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  readonly admissionReceipt: AdmissionReceipt;
  readonly admissionBindingJson: string;
  readonly credentialDigestSha256Hex: string;
  readonly expiresAtMs: number;
};

export type RouterAbEd25519YaoRegistrationExecutionRecordV1 =
  | (RegistrationExecutionAuthority & {
      readonly kind: 'ready';
      readonly requestDigestSha256Hex?: never;
      readonly request?: never;
      readonly result?: never;
      readonly failure?: never;
      readonly consumerBinding?: never;
    })
  | (RegistrationExecutionAuthority & {
      readonly kind: 'claimed';
      readonly requestDigestSha256Hex: string;
      readonly request: ExecuteRequest;
      readonly claimedAtMs: number;
      readonly reconcileAfterMs: number;
      readonly result?: never;
      readonly failure?: never;
      readonly consumerBinding?: never;
    })
  | (RegistrationExecutionAuthority & {
      readonly kind: 'completed';
      readonly requestDigestSha256Hex: string;
      readonly request: ExecuteRequest;
      readonly claimedAtMs: number;
      readonly reconcileAfterMs: number;
      readonly result: ActivationResult;
      readonly consumerBinding: string | null;
      readonly failure?: never;
    })
  | (RegistrationExecutionAuthority & {
      readonly kind: 'failed';
      readonly requestDigestSha256Hex: string;
      readonly request: ExecuteRequest;
      readonly claimedAtMs: number;
      readonly reconcileAfterMs: number;
      readonly failure: RouterAbEd25519YaoRegistrationFailure;
      readonly result?: never;
      readonly consumerBinding?: never;
    });

export function routerAbEd25519YaoRegistrationExecutionRecordKeyV1(lifecycleId: string): string {
  return `registration-execution:${requireVisibleString(lifecycleId, 'lifecycleId', 256)}`;
}

export function encodeRouterAbEd25519YaoRegistrationExecutionRecordV1(
  record: RouterAbEd25519YaoRegistrationExecutionRecordV1,
): VersionedJsonObject {
  return toJsonObject({
    recordKind: ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTION_RECORD_KIND_V1,
    ...record,
  });
}

export function parseRouterAbEd25519YaoRegistrationExecutionRecordV1(
  input: unknown,
): RouterAbEd25519YaoRegistrationExecutionRecordV1 | null {
  if (
    !isRecord(input) ||
    input.recordKind !== ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTION_RECORD_KIND_V1
  ) {
    return null;
  }
  const lifecycleId = readVisibleString(input.lifecycleId, 256);
  const admissionRequest = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
    input.admissionRequest,
  );
  const admissionReceipt = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(
    input.admissionReceipt,
  );
  const admissionBindingJson = readVisibleString(input.admissionBindingJson, 65_536);
  const credentialDigestSha256Hex = readSha256Hex(input.credentialDigestSha256Hex);
  const expiresAtMs = readPositiveSafeInteger(input.expiresAtMs);
  if (
    lifecycleId === null ||
    !admissionRequest.ok ||
    !admissionReceipt.ok ||
    admissionBindingJson === null ||
    credentialDigestSha256Hex === null ||
    expiresAtMs === null ||
    admissionRequest.value.scope.lifecycle_id !== lifecycleId ||
    admissionReceipt.value.binding.lifecycle.lifecycle_id !== lifecycleId
  ) {
    return null;
  }
  const authority: RegistrationExecutionAuthority = {
    lifecycleId,
    admissionRequest: admissionRequest.value,
    admissionReceipt: admissionReceipt.value,
    admissionBindingJson,
    credentialDigestSha256Hex,
    expiresAtMs,
  };
  if (input.kind === 'ready') return authorityReady(authority);
  const requestDigestSha256Hex = readSha256Hex(input.requestDigestSha256Hex);
  const request = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1(input.request);
  const claimedAtMs = readPositiveSafeInteger(input.claimedAtMs);
  const reconcileAfterMs = readPositiveSafeInteger(input.reconcileAfterMs);
  if (
    requestDigestSha256Hex === null ||
    !request.ok ||
    claimedAtMs === null ||
    reconcileAfterMs === null ||
    reconcileAfterMs <= claimedAtMs ||
    request.value.binding.lifecycle.lifecycle_id !== lifecycleId
  ) {
    return null;
  }
  if (input.kind === 'claimed') {
    return {
      kind: 'claimed',
      ...authority,
      requestDigestSha256Hex,
      request: request.value,
      claimedAtMs,
      reconcileAfterMs,
    };
  }
  if (input.kind === 'completed') {
    const result = parseRouterAbEd25519YaoRegistrationActivationResultV1(input.result);
    const consumerBinding =
      input.consumerBinding === null ? null : readVisibleString(input.consumerBinding, 512);
    if (!result.ok || (consumerBinding === null && input.consumerBinding !== null)) return null;
    return {
      kind: 'completed',
      ...authority,
      requestDigestSha256Hex,
      request: request.value,
      claimedAtMs,
      reconcileAfterMs,
      result: result.value,
      consumerBinding,
    };
  }
  if (input.kind === 'failed') {
    const failure = parseFailure(input.failure);
    if (failure === null) return null;
    return {
      kind: 'failed',
      ...authority,
      requestDigestSha256Hex,
      request: request.value,
      claimedAtMs,
      reconcileAfterMs,
      failure,
    };
  }
  return null;
}

export function routerAbEd25519YaoRegistrationExecutionRequestDigestV1(
  request: ExecuteRequest,
): Promise<string> {
  return sha256Hex(JSON.stringify(request));
}

export function routerAbEd25519YaoRegistrationAdmissionBindingJsonV1(
  receipt: AdmissionReceipt,
): string {
  return JSON.stringify(receipt.binding);
}

function authorityReady(
  authority: RegistrationExecutionAuthority,
): RouterAbEd25519YaoRegistrationExecutionRecordV1 {
  return { kind: 'ready', ...authority };
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  try {
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
    let encoded = '';
    for (const byte of digest) encoded += byte.toString(16).padStart(2, '0');
    digest.fill(0);
    return encoded;
  } finally {
    bytes.fill(0);
  }
}

function parseFailure(input: unknown): RouterAbEd25519YaoRegistrationFailure | null {
  if (
    !isRecord(input) ||
    input.ok !== false ||
    !Number.isSafeInteger(input.status) ||
    typeof input.code !== 'string' ||
    typeof input.message !== 'string'
  ) {
    return null;
  }
  if (
    input.status !== 400 &&
    input.status !== 401 &&
    input.status !== 403 &&
    input.status !== 404 &&
    input.status !== 408 &&
    input.status !== 409 &&
    input.status !== 429 &&
    input.status !== 500 &&
    input.status !== 502 &&
    input.status !== 503
  ) {
    return null;
  }
  if (!isFailureCode(input.code)) return null;
  return {
    ok: false,
    status: input.status,
    code: input.code,
    message: input.message,
  };
}

function isFailureCode(input: string): input is RouterAbEd25519YaoRegistrationFailureCode {
  return (
    input === 'invalid_backend_response' ||
    input === 'admission_failed' ||
    input === 'admission_in_progress' ||
    input === 'admission_uncertain' ||
    input === 'unknown_registration' ||
    input === 'binding_mismatch' ||
    input === 'execution_in_progress' ||
    input === 'execution_failed' ||
    input === 'ceremony_expired'
  );
}

function readSha256Hex(input: unknown): string | null {
  return typeof input === 'string' && /^[0-9a-f]{64}$/u.test(input) ? input : null;
}

function readPositiveSafeInteger(input: unknown): number | null {
  return typeof input === 'number' && Number.isSafeInteger(input) && input > 0 ? input : null;
}

function requireVisibleString(input: unknown, field: string, maxLength: number): string {
  const value = readVisibleString(input, maxLength);
  if (value === null) throw new Error(`Yao registration execution ${field} is invalid`);
  return value;
}

function readVisibleString(input: unknown, maxLength: number): string | null {
  return typeof input === 'string' &&
    input.length > 0 &&
    input.length <= maxLength &&
    /^[\x20-\x7e]+$/u.test(input)
    ? input
    : null;
}

function toJsonObject(input: unknown): VersionedJsonObject {
  const value = JSON.parse(JSON.stringify(input));
  if (!isJsonObject(value)) {
    throw new Error('Yao registration execution record is not canonical JSON');
  }
  return value;
}

function isJsonObject(input: unknown): input is VersionedJsonObject {
  return isRecord(input) && Object.values(input).every(isJsonValue);
}

function isJsonValue(input: unknown): input is VersionedJsonValue {
  if (
    input === null ||
    typeof input === 'string' ||
    typeof input === 'boolean' ||
    typeof input === 'number'
  ) {
    return typeof input !== 'number' || Number.isFinite(input);
  }
  if (Array.isArray(input)) return input.every(isJsonValue);
  return isJsonObject(input);
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return typeof input === 'object' && input !== null && !Array.isArray(input);
}
