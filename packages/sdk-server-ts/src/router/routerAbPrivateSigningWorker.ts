import type {
  RouterAbNormalSigningBudgetFinalizeInput,
  RouterAbSigningWorkerPrivateTransport,
} from '../core/routerAbSigning/RouterAbNormalSigningRuntime';
import type { RouterAbNormalSigningRuntime } from '../core/routerAbSigning/RouterAbNormalSigningRuntime';
import type { ThresholdEd25519AuthorityScope } from '../core/types';
import { postRouterAbInternalServiceJson } from '../core/ThresholdService/routerAb/internalServiceHttp';
import { thresholdEcdsaStatusCode } from '../threshold/statusCodes';
import type {
  RouterAbEcdsaDerivationWalletSessionClaims,
  RouterAbEd25519WalletSessionClaims,
} from '../core/ThresholdService/validation';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../core/ThresholdService/validation';
import type {
  VerifiedEcdsaWalletSessionAuth,
  VerifiedEd25519WalletSessionAuth,
} from './verifiedWalletSessionAuth';
import {
  validateRouterAbEcdsaDerivationWalletSessionInputs,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from './commonRouterUtils';
import { parseSessionKind, type SessionAdapter } from './routerApi';
import {
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  parseRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  routerAbEcdsaDerivationActiveStateSessionId,
  routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1,
  routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestFromBudgetedV1,
  routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1,
  routerAbEcdsaDerivationNormalSigningScopeCanonicalBytesV1,
  sameRouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbPublicDigest32V1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';

const ED25519_SIGNING_PAYLOAD_VERSION_V2 = 'router-ab-protocol/ed25519-normal-signing/payload/v2';

const PRIVATE_ED25519_SIGNING_PREPARE_PATH = '/router-ab/signing-worker/sign/prepare';
const PRIVATE_ED25519_SIGNING_FINALIZE_PATH = '/router-ab/signing-worker/sign';
const PRIVATE_ECDSA_DERIVATION_SIGNING_PREPARE_PATH = '/router-ab/signing-worker/ecdsa-derivation/sign/prepare';
const PRIVATE_ECDSA_DERIVATION_SIGNING_FINALIZE_PATH = '/router-ab/signing-worker/ecdsa-derivation/sign';

export type RouterAbEd25519PrivateSigningPath =
  | typeof PRIVATE_ED25519_SIGNING_PREPARE_PATH
  | typeof PRIVATE_ED25519_SIGNING_FINALIZE_PATH;

export const ROUTER_AB_ED25519_PRIVATE_SIGNING_PATHS = {
  prepare: PRIVATE_ED25519_SIGNING_PREPARE_PATH,
  finalize: PRIVATE_ED25519_SIGNING_FINALIZE_PATH,
} as const;

export type RouterAbEcdsaDerivationPrivateSigningPath =
  | typeof PRIVATE_ECDSA_DERIVATION_SIGNING_PREPARE_PATH
  | typeof PRIVATE_ECDSA_DERIVATION_SIGNING_FINALIZE_PATH;

export const ROUTER_AB_ECDSA_DERIVATION_PRIVATE_SIGNING_PATHS = {
  prepare: PRIVATE_ECDSA_DERIVATION_SIGNING_PREPARE_PATH,
  finalize: PRIVATE_ECDSA_DERIVATION_SIGNING_FINALIZE_PATH,
} as const;

export type RouterAbSigningWorkerJsonResult =
  | { ok: true; body: unknown }
  | {
      ok: false;
      status: number;
      body: { ok: false; code: string; message: string };
    };
type RouterAbSigningWorkerJsonError = Extract<RouterAbSigningWorkerJsonResult, { ok: false }>;

function resolveRouterAbSigningWorkerFetch(input?: typeof fetch): typeof fetch | null {
  if (input) return input;
  return typeof globalThis.fetch === 'function'
    ? (globalThis.fetch.bind(globalThis) as typeof fetch)
    : null;
}

export type RouterAbEd25519NormalSigningRoutePhase = 'prepare' | 'finalize';

export type RouterAbJsonRouteResult = {
  status: number;
  body: unknown;
};

type RouterAbConfiguredSigningWorkerPrivateTransport = Extract<
  RouterAbSigningWorkerPrivateTransport,
  { readonly kind: 'configured' }
>;

export type RouterAbNormalSigningRouteRuntime = Pick<
  RouterAbNormalSigningRuntime,
  | 'getSigningWorkerPrivateTransport'
  | 'reservePrepareReplay'
  | 'reserveBudget'
  | 'commitBudget'
  | 'validateBudget'
  | 'releaseBudget'
  | 'releaseBudgetForIdentity'
>;

export type RouterAbNormalSigningRouteAdmission =
  | {
      ok: true;
      thresholdSessionId: string;
      requestId: string;
      expiresAtMs: number;
    }
  | {
      ok: false;
      error: RouterAbSigningWorkerJsonError;
    };

export type RouterAbNormalSigningAdmissionFailureCode =
  | 'project_policy_rejected'
  | 'quota_saturated'
  | 'abuse_rejected'
  | 'rate_limited'
  | 'unauthorized'
  | 'invalid_body'
  | 'not_configured'
  | 'internal';

export type RouterAbNormalSigningAdmissionFailure = {
  ok: false;
  status: 400 | 401 | 403 | 408 | 409 | 429 | 500 | 501 | 503;
  code: RouterAbNormalSigningAdmissionFailureCode;
  message: string;
};

export type RouterAbNormalSigningAdmissionResult =
  | { ok: true }
  | RouterAbNormalSigningAdmissionFailure;

export type RouterAbNormalSigningAdmissionInput =
  | {
      curve: 'ed25519';
      phase: 'prepare' | 'finalize';
      walletId: string;
      authorityScope: ThresholdEd25519AuthorityScope;
      thresholdSessionId: string;
      signingGrantId: string;
      requestId: string;
      expiresAtMs: number;
      signingWorkerId: string;
      runtimePolicyScope: RuntimePolicyScope;
    }
  | {
      curve: 'ecdsa';
      phase: 'prepare' | 'finalize';
      walletId: string;
      evmFamilySigningKeySlotId: string;
      thresholdSessionId: string;
      signingGrantId: string;
      requestId: string;
      expiresAtMs: number;
      signingWorkerId: string;
      keyHandle: string;
      runtimePolicyScope: RuntimePolicyScope;
    };

export interface RouterAbNormalSigningAdmissionAdapter {
  evaluate(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningAdmissionResult>;
}

type AcceptedRouteAdmission = Extract<RouterAbNormalSigningRouteAdmission, { ok: true }>;

export type RouterAbNormalSigningAdmissionEvaluationInput =
  | {
      adapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
      curve: 'ed25519';
      phase: 'prepare' | 'finalize';
      claims: RouterAbEd25519WalletSessionClaims;
      walletSessionAuth: VerifiedEd25519WalletSessionAuth;
      admission: AcceptedRouteAdmission;
    }
  | {
      adapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
      curve: 'ecdsa';
      phase: 'prepare' | 'finalize';
      claims: RouterAbEcdsaDerivationWalletSessionClaims;
      walletSessionAuth: VerifiedEcdsaWalletSessionAuth;
      admission: AcceptedRouteAdmission;
    };

export async function evaluateRouterAbNormalSigningAdmission(
  input: RouterAbNormalSigningAdmissionEvaluationInput,
): Promise<RouterAbNormalSigningAdmissionResult> {
  if (!input.adapter) {
    return {
      ok: false,
      status: 501,
      code: 'not_configured',
      message: 'Router A/B normal-signing admission adapter is not configured',
    };
  }

  if (input.curve === 'ed25519') {
    return await input.adapter.evaluate({
      curve: 'ed25519',
      phase: input.phase,
      walletId: input.walletSessionAuth.userId,
      authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(
        input.walletSessionAuth.authority,
      ),
      thresholdSessionId: input.walletSessionAuth.thresholdSessionId,
      signingGrantId: input.walletSessionAuth.signingGrantId,
      requestId: input.admission.requestId,
      expiresAtMs: input.admission.expiresAtMs,
      signingWorkerId: input.claims.routerAbNormalSigning.signingWorkerId,
      runtimePolicyScope: input.claims.runtimePolicyScope,
    });
  }

  if (!input.claims.runtimePolicyScope) {
    return {
      ok: false,
      status: 403,
      code: 'project_policy_rejected',
      message: 'Router A/B ECDSA derivation normal-signing runtime policy scope is required',
    };
  }

  return await input.adapter.evaluate({
    curve: 'ecdsa',
    phase: input.phase,
    walletId: input.walletSessionAuth.userId,
    evmFamilySigningKeySlotId: input.walletSessionAuth.evmFamilySigningKeySlotId,
    thresholdSessionId: input.walletSessionAuth.thresholdSessionId,
    signingGrantId: input.walletSessionAuth.signingGrantId,
    requestId: input.admission.requestId,
    expiresAtMs: input.admission.expiresAtMs,
    signingWorkerId: input.claims.routerAbEcdsaDerivationNormalSigning.scope.signing_worker.server_id,
    keyHandle: input.walletSessionAuth.keyHandle,
    runtimePolicyScope: input.claims.runtimePolicyScope,
  });
}

export type RouterAbEd25519PrivateSigningWorkerBody = {
  kind: 'router_ab_ed25519_signing_worker_active_state_request_v1';
  request: Record<string, unknown>;
};

type RouterAbEcdsaDerivationTrustedAdmissionV1 = {
  account_id: string;
  session_id: string;
  request_digest: RouterAbPublicDigest32V1Wire;
  signing_digest: RouterAbPublicDigest32V1Wire;
  admitted_at_ms: number;
  expires_at_ms: number;
};

type RouterAbEcdsaDerivationPrivatePrepareSigningWorkerBody = {
  request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire;
  trusted_admission: RouterAbEcdsaDerivationTrustedAdmissionV1;
};

type RouterAbEcdsaDerivationPrivateFinalizeSigningWorkerBody = {
  request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire;
  trusted_admission: RouterAbEcdsaDerivationTrustedAdmissionV1;
};

export type RouterAbEcdsaDerivationPrivateSigningWorkerBody =
  | RouterAbEcdsaDerivationPrivatePrepareSigningWorkerBody
  | RouterAbEcdsaDerivationPrivateFinalizeSigningWorkerBody;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function nonEmptyString(value: unknown): string {
  return String(value || '').trim();
}

function pushU32Be(out: number[], value: number): void {
  out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function textBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function pushLen32(out: number[], bytes: Uint8Array): void {
  pushU32Be(out, bytes.length);
  for (const byte of bytes) out.push(byte);
}

async function sha256B64u(bytes: Uint8Array): Promise<string> {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', buffer);
  return base64UrlEncode(new Uint8Array(digest));
}

function signingPayloadDigestFromWire(value: unknown): string {
  const record = isPlainObject(value) ? value : null;
  const bytes = Array.isArray(record?.bytes) ? record.bytes.map((entry) => Number(entry)) : [];
  if (
    bytes.length !== 32 ||
    !bytes.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)
  ) {
    return '';
  }
  return base64UrlEncode(Uint8Array.from(bytes));
}

const ED25519_BUDGET_REQUEST_DIGEST_VERSION_V1 = 'router_ab_ed25519_budget_request_digest_v1';
const ECDSA_DERIVATION_BUDGET_OPERATION_ID_VERSION_V1 = 'router_ab_ecdsa_derivation_budget_operation_id_v1';
const ECDSA_DERIVATION_BUDGET_REQUEST_DIGEST_VERSION_V1 = 'router_ab_ecdsa_derivation_budget_request_digest_v1';

async function ed25519SigningPayloadDigestB64u(value: unknown): Promise<string> {
  const payload = isPlainObject(value) ? value : null;
  if (!payload) return '';
  const out: number[] = [];
  pushLen32(out, textBytes(ED25519_SIGNING_PAYLOAD_VERSION_V2));
  const kind = nonEmptyString(payload.kind);
  switch (kind) {
    case 'near_unsigned_transaction_borsh_v1':
      pushLen32(out, textBytes(kind));
      pushLen32(out, textBytes(nonEmptyString(payload.unsigned_transaction_borsh_b64u)));
      pushLen32(out, textBytes(nonEmptyString(payload.expected_signing_digest_b64u)));
      return sha256B64u(Uint8Array.from(out));
    case 'nep413_message_v1':
      pushLen32(out, textBytes(kind));
      pushLen32(out, textBytes(nonEmptyString(payload.canonical_message_b64u)));
      pushLen32(out, textBytes(nonEmptyString(payload.expected_signing_digest_b64u)));
      return sha256B64u(Uint8Array.from(out));
    case 'near_delegate_action_v1':
      pushLen32(out, textBytes(kind));
      pushLen32(out, textBytes(nonEmptyString(payload.canonical_delegate_borsh_b64u)));
      pushLen32(out, textBytes(nonEmptyString(payload.expected_signing_digest_b64u)));
      return sha256B64u(Uint8Array.from(out));
    default:
      return '';
  }
}

function routerAbScopeField(body: Record<string, unknown>, key: string): string {
  const scope = isPlainObject(body.scope) ? body.scope : null;
  return nonEmptyString(scope?.[key]);
}

function expiresAtMsField(body: Record<string, unknown>): string {
  const value = Number(body.expires_at_ms);
  if (!Number.isFinite(value) || value <= 0) return '';
  return String(Math.floor(value));
}

function pushBudgetDigestField(out: number[], name: string, value: string): void {
  pushLen32(out, textBytes(name));
  pushLen32(out, textBytes(value));
}

type BudgetDigestField = readonly [name: string, value: string];
type BudgetDigestBytesField = readonly [name: string, value: Uint8Array];

async function hashBudgetFields(input: {
  version: string;
  fields: readonly BudgetDigestField[];
  bytesFields?: readonly BudgetDigestBytesField[];
  prefix?: string;
}): Promise<string> {
  if (input.fields.some(([, value]) => !nonEmptyString(value))) return '';
  const out: number[] = [];
  pushLen32(out, textBytes(input.version));
  for (const [name, value] of input.bytesFields || []) {
    pushLen32(out, textBytes(name));
    pushLen32(out, value);
  }
  for (const [name, value] of input.fields) {
    pushBudgetDigestField(out, name, value);
  }
  const digest = await sha256B64u(Uint8Array.from(out));
  return input.prefix ? `${input.prefix}:${digest}` : digest;
}

async function ed25519BudgetSigningPayloadDigestB64u(
  body: Record<string, unknown>,
): Promise<string> {
  const prepareBinding = isPlainObject(body.prepare_binding) ? body.prepare_binding : null;
  const finalizePayloadDigest = signingPayloadDigestFromWire(
    prepareBinding?.signing_payload_digest,
  );
  if (finalizePayloadDigest) return finalizePayloadDigest;
  return ed25519SigningPayloadDigestB64u(body.signing_payload);
}

async function ed25519BudgetRequestDigestB64u(input: {
  body: Record<string, unknown>;
  operationId: string;
  signingWorkerId: string;
}): Promise<string> {
  const requestId = routerAbScopeField(input.body, 'request_id');
  const accountId = routerAbScopeField(input.body, 'account_id');
  const sessionId = routerAbScopeField(input.body, 'session_id');
  const scopeSigningWorkerId = routerAbScopeField(input.body, 'signing_worker_id');
  const expiresAtMs = expiresAtMsField(input.body);
  const payloadDigest = await ed25519BudgetSigningPayloadDigestB64u(input.body);
  if (
    !requestId ||
    !accountId ||
    !sessionId ||
    !scopeSigningWorkerId ||
    !input.signingWorkerId ||
    !input.operationId ||
    !expiresAtMs ||
    !payloadDigest
  ) {
    return '';
  }
  return hashBudgetFields({
    version: ED25519_BUDGET_REQUEST_DIGEST_VERSION_V1,
    fields: [
      ['request_id', requestId],
      ['account_id', accountId],
      ['session_id', sessionId],
      ['scope_signing_worker_id', scopeSigningWorkerId],
      ['claims_signing_worker_id', input.signingWorkerId],
      ['operation_id', input.operationId],
      ['expires_at_ms', expiresAtMs],
      ['signing_payload_digest', payloadDigest],
    ],
  });
}

function ed25519PrepareOperationId(body: Record<string, unknown>): string {
  const intent = isPlainObject(body.intent) ? body.intent : null;
  return nonEmptyString(intent?.operation_id);
}

function ed25519FinalizeOperationId(body: Record<string, unknown>): string {
  return nonEmptyString(body.budget_operation_id);
}

export async function deriveRouterAbEcdsaDerivationBudgetOperationId(input: {
  body:
    | RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire
    | RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire;
  signingWorkerId: string;
  thresholdSessionId: string;
}): Promise<string> {
  const publicIdentity = input.body.scope.public_identity;
  const presignatureId =
    'client_presignature_id' in input.body
      ? input.body.client_presignature_id
      : input.body.server_presignature_id;
  const fields = [
    ['threshold_session_id', input.thresholdSessionId],
    ['wallet_id', input.body.scope.wallet_id],
    ['wallet_key_id', input.body.scope.wallet_key_id],
    ['ecdsa_threshold_key_id', input.body.scope.ecdsa_threshold_key_id],
    ['signing_root_id', input.body.scope.signing_root_id],
    ['signing_root_version', input.body.scope.signing_root_version],
    ['activation_epoch', input.body.scope.activation_epoch],
    ['signing_worker_id', input.signingWorkerId],
    ['scope_signing_worker_id', input.body.scope.signing_worker.server_id],
    ['context_binding_b64u', publicIdentity.context_binding_b64u],
    ['threshold_public_key33_b64u', publicIdentity.threshold_public_key33_b64u],
    ['presignature_id', presignatureId],
    ['expires_at_ms', String(input.body.expires_at_ms)],
    ['signing_digest_b64u', input.body.signing_digest_b64u],
  ] as const;
  return hashBudgetFields({
    version: ECDSA_DERIVATION_BUDGET_OPERATION_ID_VERSION_V1,
    fields,
    prefix: 'router-ab-ecdsa-derivation',
  });
}

export async function deriveRouterAbEcdsaDerivationBudgetRequestDigest(input: {
  body:
    | RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire
    | RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire;
  signingWorkerId: string;
  thresholdSessionId: string;
}): Promise<string> {
  const presignatureId =
    'client_presignature_id' in input.body
      ? input.body.client_presignature_id
      : input.body.server_presignature_id;
  const fields = [
    ['threshold_session_id', input.thresholdSessionId],
    ['signing_worker_id', input.signingWorkerId],
    ['scope_signing_worker_id', input.body.scope.signing_worker.server_id],
    ['presignature_id', presignatureId],
    ['expires_at_ms', String(input.body.expires_at_ms)],
    ['signing_digest_b64u', input.body.signing_digest_b64u],
  ] as const;
  return hashBudgetFields({
    version: ECDSA_DERIVATION_BUDGET_REQUEST_DIGEST_VERSION_V1,
    bytesFields: [['scope', routerAbEcdsaDerivationNormalSigningScopeCanonicalBytesV1(input.body.scope)]],
    fields,
  });
}

function ed25519BudgetSigningWorkerId(claims: RouterAbEd25519WalletSessionClaims): string {
  return nonEmptyString(claims.routerAbNormalSigning.signingWorkerId);
}

function ecdsaDerivationBudgetSigningWorkerId(claims: RouterAbEcdsaDerivationWalletSessionClaims): string {
  return nonEmptyString(claims.routerAbEcdsaDerivationNormalSigning.scope.signing_worker.server_id);
}

function budgetReservationId(body: Record<string, unknown>): string {
  return nonEmptyString(body.budget_reservation_id);
}

function budgetOperationId(body: Record<string, unknown>): string {
  return nonEmptyString(body.budget_operation_id);
}

async function forwardThenCommitBudgetedSigning(input: {
  runtime: RouterAbNormalSigningRouteRuntime;
  signingWorker: RouterAbConfiguredSigningWorkerPrivateTransport;
  path: RouterAbEd25519PrivateSigningPath | RouterAbEcdsaDerivationPrivateSigningPath;
  body: unknown;
  budget: RouterAbNormalSigningBudgetFinalizeInput;
}): Promise<RouterAbJsonRouteResult> {
  const forwarded = await postRouterAbSigningWorkerJson({
    config: input.signingWorker,
    path: input.path,
    body: input.body,
  });
  if (!forwarded.ok) {
    await input.runtime.releaseBudget({
      curve: input.budget.curve,
      phase: 'finalize',
      thresholdSessionId: input.budget.thresholdSessionId,
      signingGrantId: input.budget.signingGrantId,
      reservationId: input.budget.reservationId,
    });
    return { status: forwarded.status, body: forwarded.body };
  }
  const budget = await input.runtime.commitBudget(input.budget);
  if (!budget.ok) {
    return {
      status: budget.status,
      body: { ok: false, code: budget.code, message: budget.message },
    };
  }
  return { status: 200, body: forwarded.body };
}

function stripRouterAbBudgetMetadata(body: Record<string, unknown>): Record<string, unknown> {
  const {
    budget_reservation_id: _budgetReservationId,
    budget_operation_id: _budgetOperationId,
    ...rest
  } = body;
  return rest;
}

function withBudgetReservationMetadata(
  body: unknown,
  input: {
    reservationId: string;
    operationId?: string;
    remainingUses: number;
    reservedUses: number;
    availableUses: number;
  },
): unknown {
  if (!isPlainObject(body)) return body;
  return {
    ...body,
    budget_reservation_id: input.reservationId,
    ...(input.operationId ? { budget_operation_id: input.operationId } : {}),
    budget_status: {
      committed_remaining_uses: input.remainingUses,
      reserved_uses: input.reservedUses,
      available_uses: input.availableUses,
    },
  };
}

function routerAbSigningError(
  status: number,
  code: string,
  message: string,
): RouterAbSigningWorkerJsonError {
  return { ok: false, status, body: { ok: false, code, message } };
}

function rejectRouterAbCookieSessionKind(
  rawBody: unknown,
  message: string,
): RouterAbJsonRouteResult | null {
  if (parseSessionKind(rawBody) !== 'cookie') return null;
  return {
    status: 400,
    body: {
      ok: false,
      code: 'invalid_body',
      message,
    },
  };
}

function privateSigningWorkerUrl(
  config: RouterAbConfiguredSigningWorkerPrivateTransport,
  path: RouterAbEd25519PrivateSigningPath | RouterAbEcdsaDerivationPrivateSigningPath,
): string {
  const base = config.signingWorkerBaseUrl.trim().replace(/\/+$/, '');
  if (!base) throw new Error('Router A/B SigningWorker base URL is required');
  return `${base}${path}`;
}

export function buildRouterAbEd25519PrivateSigningWorkerBody(input: {
  body: Record<string, unknown>;
}): RouterAbEd25519PrivateSigningWorkerBody {
  return {
    kind: 'router_ab_ed25519_signing_worker_active_state_request_v1',
    request: stripRouterAbBudgetMetadata(input.body),
  };
}

function digest32FromB64u(value: string): RouterAbPublicDigest32V1Wire {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 32) {
    throw new Error('Router A/B digest must be 32 bytes');
  }
  return { bytes: Array.from(bytes) };
}

function ecdsaDerivationTrustedAdmission(input: {
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  requestDigest: RouterAbPublicDigest32V1Wire;
  signingDigestB64u: string;
  expiresAtMs: number;
}): RouterAbEcdsaDerivationTrustedAdmissionV1 {
  return {
    account_id: input.scope.wallet_id,
    session_id: routerAbEcdsaDerivationActiveStateSessionId({
      kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
      scope: input.scope,
    }),
    request_digest: input.requestDigest,
    signing_digest: digest32FromB64u(input.signingDigestB64u),
    admitted_at_ms: Math.max(1, Math.floor(Date.now())),
    expires_at_ms: input.expiresAtMs,
  };
}

export async function buildRouterAbEcdsaDerivationPrivateSigningWorkerBody(input: {
  phase: 'prepare' | 'finalize';
  body: Record<string, unknown>;
}): Promise<RouterAbEcdsaDerivationPrivateSigningWorkerBody> {
  if (input.phase === 'prepare') {
    const request = parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body);
    const requestDigest = await routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1(request);
    return {
      request,
      trusted_admission: ecdsaDerivationTrustedAdmission({
        scope: request.scope,
        requestDigest,
        signingDigestB64u: request.signing_digest_b64u,
        expiresAtMs: request.expires_at_ms,
      }),
    };
  }
  const publicRequest = parseRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1(input.body);
  const request = routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestFromBudgetedV1(publicRequest);
  const requestDigest = await routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1(request);
  return {
    request,
    trusted_admission: ecdsaDerivationTrustedAdmission({
      scope: request.scope,
      requestDigest,
      signingDigestB64u: request.signing_digest_b64u,
      expiresAtMs: request.expires_at_ms,
    }),
  };
}

export async function handleRouterAbEd25519NormalSigningRouteCore(input: {
  body: Record<string, unknown>;
  rawBody: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
  runtime: RouterAbNormalSigningRouteRuntime | null | undefined;
  admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  privatePath: RouterAbEd25519PrivateSigningPath;
  phase: RouterAbEd25519NormalSigningRoutePhase;
}): Promise<RouterAbJsonRouteResult> {
  const invalidSessionKind = rejectRouterAbCookieSessionKind(
    input.rawBody,
    'Router A/B Ed25519 normal-signing requires sessionKind=jwt',
  );
  if (invalidSessionKind) return invalidSessionKind;

  const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
    body: input.rawBody,
    headers: input.headers,
    session: input.session,
  });
  if (!validated.ok) {
    return {
      status: validated.code === 'sessions_disabled' ? 501 : 401,
      body: { ok: false, code: validated.code, message: validated.message },
    };
  }

  const admission = validateRouterAbEd25519NormalSigningRequestScope({
    claims: validated.claims,
    walletSessionAuth: validated.walletSessionAuth,
    body: input.body,
  });
  if (!admission.ok) {
    return { status: admission.error.status, body: admission.error.body };
  }

  const runtime = input.runtime;
  if (!runtime) {
    return {
      status: 501,
      body: {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B normal-signing runtime is not configured',
      },
    };
  }

  const admissionDecision = await evaluateRouterAbNormalSigningAdmission({
    adapter: input.admissionAdapter,
    curve: 'ed25519',
    phase: input.phase,
    claims: validated.claims,
    walletSessionAuth: validated.walletSessionAuth,
    admission,
  });
  if (!admissionDecision.ok) {
    return {
      status: admissionDecision.status,
      body: {
        ok: false,
        code: admissionDecision.code,
        message: admissionDecision.message,
      },
    };
  }

  const signingWorker = runtime.getSigningWorkerPrivateTransport();
  if (signingWorker.kind === 'unconfigured') {
    return {
      status: 501,
      body: {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B SigningWorker private HTTP target is not configured',
      },
    };
  }

  if (input.phase === 'prepare') {
    const replay = await runtime.reservePrepareReplay({
      curve: 'ed25519',
      thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
      requestId: admission.requestId,
      expiresAtMs: admission.expiresAtMs,
    });
    if (!replay.ok) {
      return {
        status: replay.status,
        body: { ok: false, code: replay.code, message: replay.message },
      };
    }
  }

  let budgetReservation: {
    reservationId: string;
    operationId: string;
    remainingUses: number;
    reservedUses: number;
    availableUses: number;
  } | null = null;
  if (input.phase === 'prepare') {
    const signingWorkerId = ed25519BudgetSigningWorkerId(validated.claims);
    const operationId = ed25519PrepareOperationId(input.body);
    const requestDigest = await ed25519BudgetRequestDigestB64u({
      body: input.body,
      operationId,
      signingWorkerId,
    });
    if (!operationId || !requestDigest) {
      return {
        status: 422,
        body: {
          ok: false,
          code: 'invalid_budget_request',
          message: 'Router A/B Ed25519 budget reservation requires operation and payload digest',
        },
      };
    }
    const reservation = await runtime.reserveBudget({
      curve: 'ed25519',
      thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
      signingGrantId: validated.walletSessionAuth.signingGrantId,
      signingWorkerId,
      operationId,
      requestDigest,
      signatureUses: 1,
      expiresAtMs: admission.expiresAtMs,
    });
    if (!reservation.ok) {
      return {
        status: reservation.status,
        body: { ok: false, code: reservation.code, message: reservation.message },
      };
    }
    budgetReservation = {
      reservationId: reservation.reservationId,
      operationId,
      remainingUses: reservation.remainingUses,
      reservedUses: reservation.reservedUses,
      availableUses: reservation.availableUses,
    };
  }

  if (input.phase === 'finalize') {
    const reservationId = budgetReservationId(input.body);
    const signingWorkerId = ed25519BudgetSigningWorkerId(validated.claims);
    const operationId = ed25519FinalizeOperationId(input.body);
    const requestDigest = await ed25519BudgetRequestDigestB64u({
      body: input.body,
      operationId,
      signingWorkerId,
    });
    if (!reservationId || !operationId || !requestDigest) {
      return {
        status: 422,
        body: {
          ok: false,
          code: 'invalid_budget_request',
          message: 'Router A/B Ed25519 finalize requires budget reservation metadata',
        },
      };
    }
    const validatedBudget = await runtime.validateBudget({
      curve: 'ed25519',
      thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
      signingGrantId: validated.walletSessionAuth.signingGrantId,
      reservationId,
      signingWorkerId,
      operationId,
      requestDigest,
    });
    if (!validatedBudget.ok) {
      await runtime.releaseBudgetForIdentity({
        curve: 'ed25519',
        thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
        signingGrantId: validated.walletSessionAuth.signingGrantId,
        reservationId,
        signingWorkerId,
        operationId,
        requestDigest,
      });
      return {
        status: validatedBudget.status,
        body: { ok: false, code: validatedBudget.code, message: validatedBudget.message },
      };
    }
    return await forwardThenCommitBudgetedSigning({
      runtime,
      signingWorker,
      path: input.privatePath,
      body: buildRouterAbEd25519PrivateSigningWorkerBody({
        body: input.body,
      }),
      budget: {
        curve: 'ed25519',
        thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
        signingGrantId: validated.walletSessionAuth.signingGrantId,
        reservationId,
        signingWorkerId,
        operationId,
        requestDigest,
      },
    });
  }

  const forwarded = await postRouterAbSigningWorkerJson({
    config: signingWorker,
    path: input.privatePath,
    body: buildRouterAbEd25519PrivateSigningWorkerBody({
      body: input.body,
    }),
  });
  if (!forwarded.ok) {
    if (budgetReservation) {
      await runtime.releaseBudget({
        curve: 'ed25519',
        phase: 'prepare',
        thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
        signingGrantId: validated.walletSessionAuth.signingGrantId,
        reservationId: budgetReservation.reservationId,
      });
    }
    return { status: forwarded.status, body: forwarded.body };
  }
  return {
    status: 200,
    body: budgetReservation
      ? withBudgetReservationMetadata(forwarded.body, budgetReservation)
      : forwarded.body,
  };
}

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || 'unknown error',
  );
}

export function validateRouterAbEd25519NormalSigningRequestScope(input: {
  claims: RouterAbEd25519WalletSessionClaims;
  walletSessionAuth: VerifiedEd25519WalletSessionAuth;
  body: Record<string, unknown>;
}): RouterAbNormalSigningRouteAdmission {
  const scope = isPlainObject(input.body.scope) ? input.body.scope : null;
  const requestId = nonEmptyString(scope?.request_id);
  const accountId = nonEmptyString(scope?.account_id);
  const sessionId = nonEmptyString(scope?.session_id);
  const signingWorkerId = nonEmptyString(scope?.signing_worker_id);
  if (!requestId || !accountId || !sessionId || !signingWorkerId) {
    return {
      ok: false,
      error: routerAbSigningError(
        400,
        'invalid_body',
        'Router A/B Ed25519 normal-signing scope is required',
      ),
    };
  }
  if (
    accountId !== input.walletSessionAuth.userId ||
    sessionId !== input.walletSessionAuth.thresholdSessionId
  ) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B Ed25519 normal-signing scope does not match Wallet Session claims',
      ),
    };
  }
  if (signingWorkerId !== input.claims.routerAbNormalSigning.signingWorkerId) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B Ed25519 normal-signing worker does not match Wallet Session claims',
      ),
    };
  }

  const expiresAtMs = Number(input.body.expires_at_ms);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    return {
      ok: false,
      error: routerAbSigningError(
        400,
        'invalid_body',
        'Router A/B Ed25519 normal-signing expires_at_ms is required',
      ),
    };
  }
  if (expiresAtMs <= Date.now()) {
    return {
      ok: false,
      error: routerAbSigningError(
        408,
        'expired_request',
        'Router A/B Ed25519 normal-signing request is expired',
      ),
    };
  }
  if (expiresAtMs > input.walletSessionAuth.expiresAtMs) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B Ed25519 normal-signing expiry exceeds Wallet Session expiry',
      ),
    };
  }
  return {
    ok: true,
    thresholdSessionId: sessionId,
    requestId,
    expiresAtMs,
  };
}

export function validateRouterAbEcdsaDerivationNormalSigningPrepareRequest(input: {
  claims: RouterAbEcdsaDerivationWalletSessionClaims;
  walletSessionAuth: VerifiedEcdsaWalletSessionAuth;
  body: Record<string, unknown>;
}): RouterAbNormalSigningRouteAdmission {
  const normalSigning = input.claims.routerAbEcdsaDerivationNormalSigning;
  if (!normalSigning) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B ECDSA derivation normal-signing state is required',
      ),
    };
  }
  let request: ReturnType<typeof parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1>;
  try {
    request = parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body);
  } catch (error) {
    return {
      ok: false,
      error: routerAbSigningError(400, 'invalid_body', errorMessage(error)),
    };
  }
  if (!sameRouterAbEcdsaDerivationNormalSigningScopeV1(request.scope, normalSigning.scope)) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B ECDSA derivation normal-signing scope does not match Wallet Session claims',
      ),
    };
  }
  if (request.expires_at_ms <= Date.now()) {
    return {
      ok: false,
      error: routerAbSigningError(
        408,
        'expired_request',
        'Router A/B ECDSA derivation normal-signing request is expired',
      ),
    };
  }
  if (request.expires_at_ms > input.walletSessionAuth.expiresAtMs) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B ECDSA derivation normal-signing expiry exceeds Wallet Session expiry',
      ),
    };
  }
  return {
    ok: true,
    thresholdSessionId: input.walletSessionAuth.thresholdSessionId,
    requestId: request.request_id,
    expiresAtMs: request.expires_at_ms,
  };
}

export function validateRouterAbEcdsaDerivationNormalSigningFinalizeRequest(input: {
  claims: RouterAbEcdsaDerivationWalletSessionClaims;
  walletSessionAuth: VerifiedEcdsaWalletSessionAuth;
  body: Record<string, unknown>;
}): RouterAbNormalSigningRouteAdmission {
  const normalSigning = input.claims.routerAbEcdsaDerivationNormalSigning;
  if (!normalSigning) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B ECDSA derivation normal-signing state is required',
      ),
    };
  }
  let request: ReturnType<typeof parseRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1>;
  try {
    request = parseRouterAbEcdsaDerivationEvmDigestSigningBudgetedFinalizeRequestV1(input.body);
  } catch (error) {
    return {
      ok: false,
      error: routerAbSigningError(400, 'invalid_body', errorMessage(error)),
    };
  }
  if (!sameRouterAbEcdsaDerivationNormalSigningScopeV1(request.scope, normalSigning.scope)) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B ECDSA derivation normal-signing scope does not match Wallet Session claims',
      ),
    };
  }
  if (request.expires_at_ms <= Date.now()) {
    return {
      ok: false,
      error: routerAbSigningError(
        408,
        'expired_request',
        'Router A/B ECDSA derivation normal-signing request is expired',
      ),
    };
  }
  if (request.expires_at_ms > input.walletSessionAuth.expiresAtMs) {
    return {
      ok: false,
      error: routerAbSigningError(
        403,
        'forbidden',
        'Router A/B ECDSA derivation normal-signing expiry exceeds Wallet Session expiry',
      ),
    };
  }
  return {
    ok: true,
    thresholdSessionId: input.walletSessionAuth.thresholdSessionId,
    requestId: request.request_id,
    expiresAtMs: request.expires_at_ms,
  };
}

export async function handleRouterAbEcdsaDerivationNormalSigningRouteCore(input: {
  body: Record<string, unknown>;
  rawBody: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
  runtime: RouterAbNormalSigningRouteRuntime | null | undefined;
  admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  privatePath: RouterAbEcdsaDerivationPrivateSigningPath;
  phase: 'prepare' | 'finalize';
}): Promise<RouterAbJsonRouteResult> {
  const invalidSessionKind = rejectRouterAbCookieSessionKind(
    input.rawBody,
    'Router A/B ECDSA derivation normal-signing requires sessionKind=jwt',
  );
  if (invalidSessionKind) return invalidSessionKind;

  const validated = await validateRouterAbEcdsaDerivationWalletSessionInputs({
    body: input.rawBody,
    headers: input.headers,
    session: input.session,
  });
  if (!validated.ok) {
    return { status: thresholdEcdsaStatusCode(validated), body: validated };
  }

  const admission =
    input.phase === 'prepare'
      ? validateRouterAbEcdsaDerivationNormalSigningPrepareRequest({
          claims: validated.claims,
          walletSessionAuth: validated.walletSessionAuth,
          body: input.body,
        })
      : validateRouterAbEcdsaDerivationNormalSigningFinalizeRequest({
          claims: validated.claims,
          walletSessionAuth: validated.walletSessionAuth,
          body: input.body,
        });
  if (!admission.ok) {
    return { status: admission.error.status, body: admission.error.body };
  }

  const runtime = input.runtime;
  if (!runtime) {
    return {
      status: 501,
      body: {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B SigningWorker private HTTP target is not configured',
      },
    };
  }

  const admissionDecision = await evaluateRouterAbNormalSigningAdmission({
    adapter: input.admissionAdapter,
    curve: 'ecdsa',
    phase: input.phase,
    claims: validated.claims,
    walletSessionAuth: validated.walletSessionAuth,
    admission,
  });
  if (!admissionDecision.ok) {
    return {
      status: admissionDecision.status,
      body: {
        ok: false,
        code: admissionDecision.code,
        message: admissionDecision.message,
      },
    };
  }

  const signingWorker = runtime.getSigningWorkerPrivateTransport();
  if (signingWorker.kind === 'unconfigured') {
    return {
      status: 501,
      body: {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B SigningWorker private HTTP target is not configured',
      },
    };
  }

  const privateBody = await buildRouterAbEcdsaDerivationPrivateSigningWorkerBody({
    phase: input.phase,
    body: input.body,
  });
  let prepareBudgetReservation: {
    reservationId: string;
    operationId: string;
    remainingUses: number;
    reservedUses: number;
    availableUses: number;
  } | null = null;
  if (input.phase === 'prepare') {
    const signingWorkerId = ecdsaDerivationBudgetSigningWorkerId(validated.claims);
    const operationId = await deriveRouterAbEcdsaDerivationBudgetOperationId({
      body: privateBody.request,
      signingWorkerId,
      thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
    });
    if (!operationId) {
      return {
        status: 422,
        body: {
          ok: false,
          code: 'invalid_budget_request',
          message: 'Router A/B ECDSA derivation prepare requires a canonical budget operation identity',
        },
      };
    }
    const requestDigest = await deriveRouterAbEcdsaDerivationBudgetRequestDigest({
      body: privateBody.request,
      signingWorkerId,
      thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
    });
    if (!requestDigest) {
      return {
        status: 422,
        body: {
          ok: false,
          code: 'invalid_budget_request',
          message: 'Router A/B ECDSA derivation prepare requires a canonical budget request digest',
        },
      };
    }
    const replay = await runtime.reservePrepareReplay({
      curve: 'ecdsa',
      thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
      requestId: admission.requestId,
      expiresAtMs: admission.expiresAtMs,
    });
    if (!replay.ok) {
      return {
        status: replay.status,
        body: { ok: false, code: replay.code, message: replay.message },
      };
    }
    const reservation = await runtime.reserveBudget({
      curve: 'ecdsa',
      thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
      signingGrantId: validated.walletSessionAuth.signingGrantId,
      signingWorkerId,
      operationId,
      requestDigest,
      signatureUses: 1,
      expiresAtMs: admission.expiresAtMs,
    });
    if (!reservation.ok) {
      return {
        status: reservation.status,
        body: { ok: false, code: reservation.code, message: reservation.message },
      };
    }
    prepareBudgetReservation = {
      reservationId: reservation.reservationId,
      operationId,
      remainingUses: reservation.remainingUses,
      reservedUses: reservation.reservedUses,
      availableUses: reservation.availableUses,
    };
  } else {
    const reservationId = budgetReservationId(input.body);
    const signingWorkerId = ecdsaDerivationBudgetSigningWorkerId(validated.claims);
    const requestOperationId = budgetOperationId(input.body);
    const expectedOperationId = await deriveRouterAbEcdsaDerivationBudgetOperationId({
      body: privateBody.request,
      signingWorkerId,
      thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
    });
    if (!reservationId || !requestOperationId || !expectedOperationId) {
      return {
        status: 422,
        body: {
          ok: false,
          code: 'invalid_budget_request',
          message: 'Router A/B ECDSA derivation finalize requires budget reservation metadata',
        },
      };
    }
    if (requestOperationId !== expectedOperationId) {
      return {
        status: 409,
        body: {
          ok: false,
          code: 'wallet_budget_reservation_mismatch',
          message: 'Router A/B ECDSA derivation budget operation identity mismatch',
        },
      };
    }
    const requestDigest = await deriveRouterAbEcdsaDerivationBudgetRequestDigest({
      body: privateBody.request,
      signingWorkerId,
      thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
    });
    if (!requestDigest) {
      return {
        status: 422,
        body: {
          ok: false,
          code: 'invalid_budget_request',
          message: 'Router A/B ECDSA derivation finalize requires a canonical budget request digest',
        },
      };
    }
    const validatedBudget = await runtime.validateBudget({
      curve: 'ecdsa',
      thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
      signingGrantId: validated.walletSessionAuth.signingGrantId,
      reservationId,
      signingWorkerId,
      operationId: requestOperationId,
      requestDigest,
    });
    if (!validatedBudget.ok) {
      await runtime.releaseBudgetForIdentity({
        curve: 'ecdsa',
        thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
        signingGrantId: validated.walletSessionAuth.signingGrantId,
        reservationId,
        signingWorkerId,
        operationId: requestOperationId,
        requestDigest,
      });
      return {
        status: validatedBudget.status,
        body: { ok: false, code: validatedBudget.code, message: validatedBudget.message },
      };
    }
    return await forwardThenCommitBudgetedSigning({
      runtime,
      signingWorker,
      path: input.privatePath,
      body: privateBody,
      budget: {
        curve: 'ecdsa',
        thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
        signingGrantId: validated.walletSessionAuth.signingGrantId,
        reservationId,
        signingWorkerId,
        operationId: requestOperationId,
        requestDigest,
      },
    });
  }

  const forwarded = await postRouterAbSigningWorkerJson({
    config: signingWorker,
    path: input.privatePath,
    body: privateBody,
  });
  if (!forwarded.ok) {
    if (prepareBudgetReservation) {
      await runtime.releaseBudget({
        curve: 'ecdsa',
        phase: input.phase,
        thresholdSessionId: validated.walletSessionAuth.thresholdSessionId,
        signingGrantId: validated.walletSessionAuth.signingGrantId,
        reservationId: prepareBudgetReservation.reservationId,
      });
    }
    return { status: forwarded.status, body: forwarded.body };
  }
  return {
    status: 200,
    body: prepareBudgetReservation
      ? withBudgetReservationMetadata(forwarded.body, prepareBudgetReservation)
      : forwarded.body,
  };
}

export async function postRouterAbSigningWorkerJson(input: {
  config: RouterAbConfiguredSigningWorkerPrivateTransport;
  path: RouterAbEd25519PrivateSigningPath | RouterAbEcdsaDerivationPrivateSigningPath;
  body: unknown;
  fetchImpl?: typeof fetch;
}): Promise<RouterAbSigningWorkerJsonResult> {
  const fetchImpl = resolveRouterAbSigningWorkerFetch(input.fetchImpl);
  if (!fetchImpl) {
    return routerAbSigningError(500, 'internal', 'fetch is not available in this runtime');
  }

  const url = privateSigningWorkerUrl(input.config, input.path);
  const response = await postRouterAbInternalServiceJson({
    url,
    body: input.body,
    authSecret: input.config.auth.secret,
    fetchImpl,
  });
  if (!response.ok && response.code === 'network_error') {
    return routerAbSigningError(
      502,
      'signing_worker_unreachable',
      `Router A/B SigningWorker request failed: ${response.message}`,
    );
  }

  if (!response.ok && response.code === 'http_error') {
    return routerAbSigningError(
      response.status || 502,
      'signing_worker_error',
      response.bodyText || `Router A/B SigningWorker returned HTTP ${response.status}`,
    );
  }

  if (!response.ok) {
    return routerAbSigningError(
      502,
      'invalid_signing_worker_response',
      `Router A/B SigningWorker returned invalid JSON: ${response.message}`,
    );
  }

  return { ok: true, body: response.json };
}
