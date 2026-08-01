import type {
  RouterAbNormalSigningAuthorizationIdentity,
  RouterAbNormalSigningBudgetFinalizeInput,
  RouterAbSigningWorkerPrivateTransport,
} from '../core/routerAbSigning/RouterAbNormalSigningRuntime';
import type { RouterAbNormalSigningRuntime } from '../core/routerAbSigning/RouterAbNormalSigningRuntime';
import type { ThresholdEd25519AuthorityScope } from '../core/types';
import { postRouterAbInternalServiceJson } from '../core/ThresholdService/routerAb/internalServiceHttp';
import type {
  RouterAbEcdsaDerivationWalletSessionClaims,
  RouterAbEd25519WalletSessionClaims,
} from '../core/ThresholdService/validation';
import {
  parseAppSessionClaims,
  thresholdEd25519AuthorityScopeFromWalletAuthAuthority,
} from '../core/ThresholdService/validation';
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
  parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  routerAbEcdsaDerivationActiveStateId,
  routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1,
  routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1,
  routerAbEcdsaDerivationNormalSigningScopeCanonicalBytesV1,
  sameRouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaOperationStepUpPreparationV1Wire,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbPublicDigest32V1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  WALLET_SESSION_FAILURE_CODES,
  type WalletSessionFailureCode,
} from '@shared/utils/walletSessionFailure';
import { walletSessionFailure, walletSessionFailureStatus } from './walletSessionFailure';
import type {
  RouterApiAuthorizationClaimService,
  RouterApiAuthorizationSessionService,
  RouterApiWalletRegistrationService,
} from './authServicePort';
import {
  buildEvmEcdsaMpcOperationRef,
  buildNearEd25519MpcOperationRef,
  parseCapabilityBindingId,
  parseAuthorizationAuditEventId,
  parseCapabilityGrantId,
  parseCapabilityGrantUseId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseCapabilityOperationResultStorageRef,
  parseGrantEvidenceId,
  parseGrantEvidenceSetId,
  parsePrincipalId,
  parseSeamsSessionId,
  parseTenantId,
  type AuthorizationParseResult,
  type AuthorizationAuditEventId,
  type CapabilityGrantId,
  type CapabilityGrantUseId,
  type CapabilityId,
  type CapabilityOperationId,
  type CapabilityOperationRef,
  type PrincipalId,
  type SeamsSessionId,
  type TenantId,
} from '@shared/authorization/capabilityKinds';
import { buildCapabilityOperationEnvelope } from '@shared/authorization/operationFingerprint';
import {
  buildActiveCapabilityGrant,
  buildCapabilityOperationClaim,
  type ClaimedCapabilityGrantUse,
} from '../authorization/domain';
import { buildVerifiedSessionEvidenceSet } from '../authorization/factorEvidence';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  sameRouterAbMpcMaterialActivationRef,
  type RouterAbNormalSigningAuthorizationWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import {
  parseMpcMaterialActivationId,
  parseWalletId,
  type MpcMaterialActivationId,
} from '@shared/utils/domainIds';

const ED25519_SIGNING_INTENT_VERSION_V2 = 'router-ab-protocol/ed25519-normal-signing/intent/v2';
const ED25519_SIGNING_PAYLOAD_VERSION_V2 = 'router-ab-protocol/ed25519-normal-signing/payload/v2';
const ED25519_ROUND1_BINDING_VERSION_V2 =
  'router-ab-protocol/ed25519-normal-signing/round1-binding/v2';
const ED25519_TRUSTED_SOURCE_VERSION_V2 = 'router-ab-cloudflare-trusted-source/v2';

export function routerAbEcdsaAtomicAuthorizationConfigured(
  claims: RouterApiAuthorizationClaimService,
): boolean {
  const runtime = claims as unknown as Record<string, unknown>;
  return (
    typeof runtime.claimEcdsaOperation === 'function' &&
    typeof runtime.claimEcdsaOperationStepUpFromGrant === 'function' &&
    typeof runtime.putEcdsaEvidenceAndGrant === 'function' &&
    typeof runtime.claimEcdsaReusableWalletSessionOperation === 'function'
  );
}

const PRIVATE_ED25519_SIGNING_PREPARE_PATH = '/router-ab/signing-worker/sign/prepare';
const PRIVATE_ED25519_SIGNING_FINALIZE_PATH = '/router-ab/signing-worker/sign';
const PRIVATE_ECDSA_DERIVATION_SIGNING_PREPARE_PATH =
  '/router-ab/signing-worker/ecdsa-derivation/sign/prepare';
const PRIVATE_ECDSA_DERIVATION_SIGNING_FINALIZE_PATH =
  '/router-ab/signing-worker/ecdsa-derivation/sign';
const PRIVATE_ROUTER_WALLET_BUDGET_PUT_GRANT_PATH =
  '/router-ab/router/wallet-budget/put-grant';

export type RouterAbWalletBudgetSignerBindingV1 = {
  readonly curve: 'ed25519' | 'ecdsa';
  readonly threshold_session_id: string;
  readonly signing_worker_id: string;
};

export type RouterAbWalletBudgetGrantProvisionInputV1 = {
  readonly signingGrantId: string;
  readonly walletId: string;
  readonly relyingPartyId: string;
  readonly authorizedSigners: readonly RouterAbWalletBudgetSignerBindingV1[];
  readonly initialSignatureUses: number;
  readonly expiresAtMs: number;
  readonly issuerIdempotencyKey: string;
};

export type RouterAbWalletBudgetGrantProvisionResultV1 =
  | {
      readonly ok: true;
      readonly signingGrantId: string;
      readonly remainingUses: number;
      readonly reservedUses: number;
      readonly availableUses: number;
      readonly expiresAtMs: number;
    }
  | { readonly ok: false; readonly code: string; readonly message: string };

export interface RouterAbWalletBudgetGrantProvisionerV1 {
  provisionGrant(
    input: RouterAbWalletBudgetGrantProvisionInputV1,
  ): Promise<RouterAbWalletBudgetGrantProvisionResultV1>;
}

export type RouterAbWalletBudgetGrantTransportV1 = {
  readonly routerBaseUrl: string;
  readonly internalServiceAuthSecret: string;
  readonly fetchImpl?: typeof fetch;
};

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

type AcceptedRouteAdmission = {
  ok: true;
  thresholdSessionId: string;
  requestId: string;
  expiresAtMs: number;
};

type AcceptedEcdsaRouteAdmission = AcceptedRouteAdmission & {
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
};

type RejectedRouteAdmission = {
  ok: false;
  error: RouterAbSigningWorkerJsonError;
};

export type RouterAbNormalSigningRouteAdmission =
  | AcceptedRouteAdmission
  | AcceptedEcdsaRouteAdmission
  | RejectedRouteAdmission;

type RouterAbEcdsaNormalSigningRouteAdmission =
  | AcceptedEcdsaRouteAdmission
  | RejectedRouteAdmission;

type RouterAbEd25519WalletSessionValidationSuccess = Extract<
  Awaited<ReturnType<typeof validateRouterAbEd25519WalletSessionTokenInputs>>,
  { readonly ok: true }
>;

type RouterAbEcdsaWalletSessionValidationSuccess = Extract<
  Awaited<ReturnType<typeof validateRouterAbEcdsaDerivationWalletSessionInputs>>,
  { readonly ok: true }
>;

export type RouterAbEd25519NormalSigningAuthorizationResult =
  | {
      readonly ok: true;
      readonly kind: 'reusable_wallet_session';
      readonly validated: RouterAbEd25519WalletSessionValidationSuccess;
      readonly admission: Extract<RouterAbNormalSigningRouteAdmission, { readonly ok: true }>;
    }
  | {
      readonly ok: true;
      readonly kind: 'operation_step_up';
      readonly phase: 'prepare';
      readonly session: RouterAbOperationStepUpAppSession;
      readonly use: ClaimedCapabilityGrantUse;
      readonly operationDigests: {
        readonly laneDigest: ReturnType<typeof parseDigestB64u>;
        readonly intentDigest: ReturnType<typeof parseDigestB64u>;
        readonly displayDigest: ReturnType<typeof parseDigestB64u>;
      };
    }
  | {
      readonly ok: true;
      readonly kind: 'operation_step_up';
      readonly phase: 'finalize';
      readonly session: RouterAbOperationStepUpAppSession;
    }
  | { readonly ok: false; readonly result: RouterAbJsonRouteResult };

export type RouterAbEcdsaNormalSigningAuthorizationResult =
  | {
      readonly ok: true;
      readonly kind: 'reusable_wallet_session';
      readonly validated: RouterAbEcdsaWalletSessionValidationSuccess;
      readonly admission: AcceptedEcdsaRouteAdmission;
    }
  | { readonly ok: true; readonly kind: 'operation_step_up' }
  | { readonly ok: false; readonly result: RouterAbJsonRouteResult };

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
      materialActivationId: MpcMaterialActivationId;
      authorizationIdentity: RouterAbNormalSigningAuthorizationIdentity;
      signingGrantId: string;
      requestId: string;
      expiresAtMs: number;
      signingWorkerId: string;
      keyHandle: string;
      runtimePolicyScope: RuntimePolicyScope;
    };

export interface RouterAbNormalSigningAdmissionAdapter {
  evaluatePolicy(
    input: RouterAbNormalSigningAdmissionInput,
  ): Promise<RouterAbNormalSigningAdmissionResult>;
  evaluate(
    input: Extract<RouterAbNormalSigningAdmissionInput, { readonly curve: 'ed25519' }>,
  ): Promise<RouterAbNormalSigningAdmissionResult>;
}

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
      admission: AcceptedEcdsaRouteAdmission;
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

  return await input.adapter.evaluatePolicy({
    curve: 'ecdsa',
    phase: input.phase,
    walletId: input.walletSessionAuth.userId,
    materialActivationId: requireMpcMaterialActivationId(
      input.admission.materialActivation.activation_id,
    ),
    authorizationIdentity: {
      kind: 'reusable_wallet_session',
      walletSessionId: input.walletSessionAuth.walletSessionId,
    },
    signingGrantId: input.walletSessionAuth.signingGrantId,
    requestId: input.admission.requestId,
    expiresAtMs: input.admission.expiresAtMs,
    signingWorkerId:
      input.claims.routerAbEcdsaDerivationNormalSigning.scope.signing_worker.server_id,
    keyHandle: input.walletSessionAuth.keyHandle,
    runtimePolicyScope: input.claims.runtimePolicyScope,
  });
}

type RouterAbEd25519NormalSigningAuthorizationV2 =
  | {
      readonly kind: 'reusable_wallet_session';
      readonly wallet_session_id: string;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly grant_id: string;
      readonly wallet_session_id?: never;
    };

type RouterAbMpcMaterialActivationRefV1 = {
  readonly kind: 'mpc_material_activation_ref';
  readonly activation_id: MpcMaterialActivationId;
  readonly capability: string;
  readonly material_owner: string;
  readonly key_binding: string;
  readonly lifecycle_binding: string;
  readonly signing_worker: string;
};

export type RouterAbEd25519NormalSigningScopeV2 = {
  readonly request_id: string;
  readonly account_id: string;
  readonly authorization: RouterAbEd25519NormalSigningAuthorizationV2;
  readonly material_activation: RouterAbMpcMaterialActivationRefV1;
  readonly signing_worker_id: string;
};

type RouterAbOperationStepUpAppSession = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly sessionId: SeamsSessionId;
  readonly walletId: string;
  readonly runtimePolicyScope: RuntimePolicyScope;
};

type RouterAbEd25519PrivateSigningAuthorization =
  | {
      readonly kind: 'reusable_wallet_session';
      readonly claims: RouterAbEd25519WalletSessionClaims;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly session: RouterAbOperationStepUpAppSession;
    };

type RouterAbEcdsaPrivateSigningAuthorization =
  | {
      readonly kind: 'reusable_wallet_session';
      readonly claims: RouterAbEcdsaDerivationWalletSessionClaims;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly session: RouterAbOperationStepUpAppSession;
    };

function reusableEd25519SigningGrantId(
  authorization: RouterAbEd25519PrivateSigningAuthorization,
): string {
  if (authorization.kind !== 'reusable_wallet_session') {
    throw new Error('Router A/B reusable authorization is unavailable');
  }
  return authorization.claims.signingGrantId;
}

type RouterAbAuthenticatedSessionContextV1 =
  | {
      readonly auth: 'authenticated_session';
      readonly subject_id: string;
      readonly session_id: string;
      readonly authorization_session_id?: never;
    }
  | {
      readonly auth: 'operation_step_up_session';
      readonly subject_id: string;
      readonly authorization_session_id: string;
      readonly session_id?: never;
    };

type RouterAbNormalSigningPrivateAuthorizationV2 =
  | {
      readonly kind: 'reusable_wallet_session';
      readonly wallet_session_id: string;
      readonly grant_id: string;
      readonly authorization_session_id?: never;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly authorization_session_id: string;
      readonly grant_id: string;
      readonly wallet_session_id?: never;
    };

type RouterAbNormalSigningTrustedMetadataV1 = {
  readonly org_id: string;
  readonly project_id: string;
  readonly environment: string;
  readonly account_id: string;
  readonly auth: RouterAbAuthenticatedSessionContextV1;
  readonly trusted_source_digest: RouterAbPublicDigest32V1Wire;
  readonly intent_digest: RouterAbPublicDigest32V1Wire;
};

type RouterAbNormalSigningTrustedAdmissionV1 = {
  readonly metadata: RouterAbNormalSigningTrustedMetadataV1;
  readonly decision: {
    readonly kind: 'accepted';
    readonly request_id: string;
  };
};

type RouterAbNormalSigningPrepareAdmissionCandidateV2 = {
  readonly org_id: string;
  readonly project_id: string;
  readonly environment: string;
  readonly account_id: string;
  readonly subject_id: string;
  readonly authorization: RouterAbNormalSigningPrivateAuthorizationV2;
  readonly signing_worker_id: string;
  readonly request_id: string;
  readonly intent_digest: RouterAbPublicDigest32V1Wire;
  readonly signing_payload_digest: RouterAbPublicDigest32V1Wire;
  readonly admitted_signing_digest: RouterAbPublicDigest32V1Wire;
  readonly round1_binding_digest: RouterAbPublicDigest32V1Wire;
  readonly trusted_source_digest: RouterAbPublicDigest32V1Wire;
  readonly expires_at_ms: number;
};

type RouterAbNormalSigningFinalizeAdmissionCandidateV2 = {
  readonly org_id: string;
  readonly project_id: string;
  readonly environment: string;
  readonly account_id: string;
  readonly subject_id: string;
  readonly authorization: RouterAbNormalSigningPrivateAuthorizationV2;
  readonly signing_worker_id: string;
  readonly request_id: string;
  readonly intent_digest: RouterAbPublicDigest32V1Wire;
  readonly signing_payload_digest: RouterAbPublicDigest32V1Wire;
  readonly round1_binding_digest: RouterAbPublicDigest32V1Wire;
  readonly trusted_source_digest: RouterAbPublicDigest32V1Wire;
  readonly expires_at_ms: number;
};

type RouterAbNormalSigningEffectClaimV1 =
  | {
      readonly kind: 'reusable_wallet_session';
      readonly budget: {
        readonly signing_grant_id: string;
        readonly reservation_id: string;
        readonly signing_worker_id: string;
        readonly operation_id: string;
        readonly request_digest: RouterAbPublicDigest32V1Wire;
      };
    }
  | {
      readonly kind: 'operation_step_up';
      readonly authorization_session_id: string;
      readonly grant_id: string;
    };

type RouterAbEd25519PrivatePrepareSigningWorkerBody = {
  readonly scope: RouterAbEd25519NormalSigningScopeV2;
  readonly expires_at_ms: number;
  readonly admission_candidate: RouterAbNormalSigningPrepareAdmissionCandidateV2;
  readonly trusted_admission: RouterAbNormalSigningTrustedAdmissionV1;
};

type RouterAbEd25519PrivateFinalizeSigningWorkerBody = {
  readonly request: Record<string, unknown>;
  readonly admission_candidate: RouterAbNormalSigningFinalizeAdmissionCandidateV2;
  readonly trusted_admission: RouterAbNormalSigningTrustedAdmissionV1;
  readonly effect_claim: RouterAbNormalSigningEffectClaimV1;
};

export type RouterAbEd25519PrivateSigningWorkerBody =
  | RouterAbEd25519PrivatePrepareSigningWorkerBody
  | RouterAbEd25519PrivateFinalizeSigningWorkerBody;

type RouterAbEcdsaDerivationPrivatePrepareSigningWorkerBody = {
  request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire;
  trusted_admission: RouterAbNormalSigningTrustedAdmissionV1;
};

type RouterAbEcdsaDerivationPrivateFinalizeSigningWorkerBody = {
  request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire;
  trusted_admission: RouterAbNormalSigningTrustedAdmissionV1;
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

function pushU64Be(out: number[], value: number): void {
  const encoded = BigInt(value);
  for (let shift = 56n; shift >= 0n; shift -= 8n) {
    out.push(Number((encoded >> shift) & 0xffn));
  }
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

async function sha256Digest32(bytes: Uint8Array): Promise<RouterAbPublicDigest32V1Wire> {
  return digest32FromB64u(await sha256B64u(bytes));
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
  signingGrantId: string;
}): Promise<string> {
  const requestId = routerAbScopeField(input.body, 'request_id');
  const accountId = routerAbScopeField(input.body, 'account_id');
  const scopeSigningWorkerId = routerAbScopeField(input.body, 'signing_worker_id');
  const scope = requirePrivateSigningScope(input.body.scope);
  if (scope.authorization.kind !== 'reusable_wallet_session') return '';
  const walletSessionId = scope.authorization.wallet_session_id;
  const materialActivationId = scope.material_activation.activation_id;
  const expiresAtMs = expiresAtMsField(input.body);
  const payloadDigest = await ed25519BudgetSigningPayloadDigestB64u(input.body);
  if (
    !requestId ||
    !accountId ||
    !walletSessionId ||
    !input.signingGrantId ||
    !materialActivationId ||
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
      ['wallet_session_id', walletSessionId],
      ['signing_grant_id', input.signingGrantId],
      ['material_activation_id', materialActivationId],
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

function ed25519BudgetSigningWorkerId(claims: RouterAbEd25519WalletSessionClaims): string {
  return nonEmptyString(claims.routerAbNormalSigning.signingWorkerId);
}

function budgetReservationId(body: Record<string, unknown>): string {
  return nonEmptyString(body.budget_reservation_id);
}

function budgetOperationId(body: Record<string, unknown>): string {
  return nonEmptyString(body.budget_operation_id);
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

function routerAbWalletSessionError(
  code: WalletSessionFailureCode,
): RouterAbSigningWorkerJsonError {
  const failure = walletSessionFailure(code);
  return routerAbSigningError(walletSessionFailureStatus(code), failure.code, failure.message);
}

function routerAbWalletSessionValidationStatus(
  code: 'sessions_disabled' | WalletSessionFailureCode,
): number {
  if (code === 'sessions_disabled') return 501;
  return walletSessionFailureStatus(code);
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

function digest32FromB64u(value: string): RouterAbPublicDigest32V1Wire {
  const bytes = base64UrlDecode(value);
  if (bytes.length !== 32) {
    throw new Error('Router A/B digest must be 32 bytes');
  }
  return { bytes: Array.from(bytes) };
}

function requirePrivateSigningRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isPlainObject(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requirePrivateSigningString(value: unknown, label: string): string {
  const normalized = nonEmptyString(value);
  if (!normalized) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return normalized;
}

function requirePrivateSigningPositiveSafeInteger(value: unknown, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return parsed;
}

function requirePrivateSigningExactFields(
  record: Record<string, unknown>,
  expectedFields: readonly string[],
  label: string,
): void {
  const actualFields = Object.keys(record).sort();
  const expected = [...expectedFields].sort();
  if (
    actualFields.length !== expected.length ||
    actualFields.some((field, index) => field !== expected[index])
  ) {
    throw new Error(`${label} has invalid fields`);
  }
}

function requirePrivateSigningAuthorization(
  value: unknown,
): RouterAbEd25519NormalSigningAuthorizationV2 {
  const authorization = requirePrivateSigningRecord(value, 'scope.authorization');
  switch (authorization.kind) {
    case 'reusable_wallet_session':
      requirePrivateSigningExactFields(
        authorization,
        ['kind', 'wallet_session_id'],
        'scope.authorization',
      );
      return {
        kind: 'reusable_wallet_session',
        wallet_session_id: requirePrivateSigningString(
          authorization.wallet_session_id,
          'scope.authorization.wallet_session_id',
        ),
      };
    case 'operation_step_up':
      requirePrivateSigningExactFields(authorization, ['kind', 'grant_id'], 'scope.authorization');
      return {
        kind: 'operation_step_up',
        grant_id: requirePrivateSigningString(
          authorization.grant_id,
          'scope.authorization.grant_id',
        ),
      };
    default:
      throw new Error('scope.authorization.kind is invalid');
  }
}

function requirePrivateSigningMaterialActivation(
  value: unknown,
): RouterAbMpcMaterialActivationRefV1 {
  const activation = requirePrivateSigningRecord(value, 'scope.material_activation');
  requirePrivateSigningExactFields(
    activation,
    [
      'kind',
      'activation_id',
      'capability',
      'material_owner',
      'key_binding',
      'lifecycle_binding',
      'signing_worker',
    ],
    'scope.material_activation',
  );
  if (activation.kind !== 'mpc_material_activation_ref') {
    throw new Error('scope.material_activation.kind is invalid');
  }
  return {
    kind: 'mpc_material_activation_ref',
    activation_id: requireMpcMaterialActivationId(activation.activation_id),
    capability: requirePrivateSigningString(
      activation.capability,
      'scope.material_activation.capability',
    ),
    material_owner: requirePrivateSigningString(
      activation.material_owner,
      'scope.material_activation.material_owner',
    ),
    key_binding: requirePrivateSigningString(
      activation.key_binding,
      'scope.material_activation.key_binding',
    ),
    lifecycle_binding: requirePrivateSigningString(
      activation.lifecycle_binding,
      'scope.material_activation.lifecycle_binding',
    ),
    signing_worker: requirePrivateSigningString(
      activation.signing_worker,
      'scope.material_activation.signing_worker',
    ),
  };
}

function requireMpcMaterialActivationId(value: unknown): MpcMaterialActivationId {
  const parsed = parseMpcMaterialActivationId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requirePrivateSigningScope(value: unknown): RouterAbEd25519NormalSigningScopeV2 {
  const scope = requirePrivateSigningRecord(value, 'scope');
  requirePrivateSigningExactFields(
    scope,
    ['request_id', 'account_id', 'authorization', 'material_activation', 'signing_worker_id'],
    'scope',
  );
  const parsed = {
    request_id: requirePrivateSigningString(scope.request_id, 'scope.request_id'),
    account_id: requirePrivateSigningString(scope.account_id, 'scope.account_id'),
    authorization: requirePrivateSigningAuthorization(scope.authorization),
    material_activation: requirePrivateSigningMaterialActivation(scope.material_activation),
    signing_worker_id: requirePrivateSigningString(
      scope.signing_worker_id,
      'scope.signing_worker_id',
    ),
  };
  if (parsed.material_activation.signing_worker !== parsed.signing_worker_id) {
    throw new Error('scope material activation SigningWorker mismatch');
  }
  return parsed;
}

function requirePrivateSigningDigest(value: unknown, label: string): RouterAbPublicDigest32V1Wire {
  const record = requirePrivateSigningRecord(value, label);
  const bytes = Array.isArray(record.bytes) ? record.bytes.map((entry) => Number(entry)) : [];
  if (
    bytes.length !== 32 ||
    !bytes.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)
  ) {
    throw new Error(`${label}.bytes must contain exactly 32 bytes`);
  }
  return { bytes };
}

function requirePrivateSigningDigestB64u(
  value: string,
  label: string,
): RouterAbPublicDigest32V1Wire {
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(value);
  } catch {
    throw new Error(`${label} must be a base64url digest`);
  }
  if (bytes.length !== 32) {
    throw new Error(`${label} must contain exactly 32 bytes`);
  }
  return { bytes: Array.from(bytes) };
}

function requirePrivateSigningStringArray(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new Error(`${label} must be an array`);
  }
  return value;
}

function pushPrivateSigningIntentCommon(out: number[], intent: Record<string, unknown>): void {
  pushLen32(
    out,
    textBytes(requirePrivateSigningString(intent.operation_id, 'intent.operation_id')),
  );
  pushLen32(
    out,
    textBytes(
      requirePrivateSigningString(intent.operation_fingerprint, 'intent.operation_fingerprint'),
    ),
  );
  pushLen32(
    out,
    textBytes(requirePrivateSigningString(intent.near_account_id, 'intent.near_account_id')),
  );
  pushLen32(
    out,
    textBytes(requirePrivateSigningString(intent.near_network_id, 'intent.near_network_id')),
  );
}

function pushPrivateSigningOptionalString(out: number[], value: unknown, label: string): void {
  if (value === undefined || value === null || value === '') {
    out.push(0);
    return;
  }
  out.push(1);
  pushLen32(out, textBytes(requirePrivateSigningString(value, label)));
}

function canonicalPrivateSigningIntentBytes(value: unknown): Uint8Array {
  const intent = requirePrivateSigningRecord(value, 'intent');
  const kind = requirePrivateSigningString(intent.kind, 'intent.kind');
  const out: number[] = [];
  pushLen32(out, textBytes(ED25519_SIGNING_INTENT_VERSION_V2));
  pushLen32(out, textBytes(kind));
  pushPrivateSigningIntentCommon(out, intent);
  switch (kind) {
    case 'near_transaction_v1': {
      const transactions = requirePrivateSigningStringArray(
        intent.transactions,
        'intent.transactions',
      );
      pushU32Be(out, transactions.length);
      for (const [index, transactionValue] of transactions.entries()) {
        const transaction = requirePrivateSigningRecord(
          transactionValue,
          `intent.transactions[${index}]`,
        );
        pushLen32(
          out,
          textBytes(
            requirePrivateSigningString(
              transaction.receiver_id,
              `intent.transactions[${index}].receiver_id`,
            ),
          ),
        );
        pushLen32(
          out,
          textBytes(
            requirePrivateSigningString(
              transaction.action_fingerprint,
              `intent.transactions[${index}].action_fingerprint`,
            ),
          ),
        );
      }
      pushLen32(
        out,
        textBytes(
          requirePrivateSigningString(
            intent.unsigned_transaction_borsh_b64u,
            'intent.unsigned_transaction_borsh_b64u',
          ),
        ),
      );
      return Uint8Array.from(out);
    }
    case 'nep413_v1':
      pushLen32(out, textBytes(requirePrivateSigningString(intent.recipient, 'intent.recipient')));
      pushLen32(out, textBytes(requirePrivateSigningString(intent.message, 'intent.message')));
      pushLen32(
        out,
        textBytes(requirePrivateSigningString(intent.nonce_b64u, 'intent.nonce_b64u')),
      );
      pushPrivateSigningOptionalString(out, intent.callback_url, 'intent.callback_url');
      return Uint8Array.from(out);
    case 'near_delegate_action_v1': {
      const delegate = requirePrivateSigningRecord(intent.delegate, 'intent.delegate');
      for (const field of [
        'sender_id',
        'receiver_id',
        'public_key',
        'nonce',
        'max_block_height',
        'action_fingerprint',
        'canonical_delegate_borsh_b64u',
      ] as const) {
        pushLen32(
          out,
          textBytes(requirePrivateSigningString(delegate[field], `intent.delegate.${field}`)),
        );
      }
      return Uint8Array.from(out);
    }
    default:
      throw new Error(`intent.kind is unsupported: ${kind}`);
  }
}

function privateSigningPayloadPreimage(value: unknown): {
  readonly canonical: Uint8Array;
  readonly preimage: Uint8Array;
  readonly expectedDigest: RouterAbPublicDigest32V1Wire;
} {
  const payload = requirePrivateSigningRecord(value, 'signing_payload');
  const kind = requirePrivateSigningString(payload.kind, 'signing_payload.kind');
  const expectedDigestB64u = requirePrivateSigningString(
    payload.expected_signing_digest_b64u,
    'signing_payload.expected_signing_digest_b64u',
  );
  const out: number[] = [];
  pushLen32(out, textBytes(ED25519_SIGNING_PAYLOAD_VERSION_V2));
  pushLen32(out, textBytes(kind));
  let preimageB64u: string;
  switch (kind) {
    case 'near_unsigned_transaction_borsh_v1':
      preimageB64u = requirePrivateSigningString(
        payload.unsigned_transaction_borsh_b64u,
        'signing_payload.unsigned_transaction_borsh_b64u',
      );
      break;
    case 'nep413_message_v1':
      preimageB64u = requirePrivateSigningString(
        payload.canonical_message_b64u,
        'signing_payload.canonical_message_b64u',
      );
      break;
    case 'near_delegate_action_v1':
      preimageB64u = requirePrivateSigningString(
        payload.canonical_delegate_borsh_b64u,
        'signing_payload.canonical_delegate_borsh_b64u',
      );
      break;
    default:
      throw new Error(`signing_payload.kind is unsupported: ${kind}`);
  }
  pushLen32(out, textBytes(preimageB64u));
  pushLen32(out, textBytes(expectedDigestB64u));
  return {
    canonical: Uint8Array.from(out),
    preimage: base64UrlDecode(preimageB64u),
    expectedDigest: digest32FromB64u(expectedDigestB64u),
  };
}

function privateSigningDigestsEqual(
  left: RouterAbPublicDigest32V1Wire,
  right: RouterAbPublicDigest32V1Wire,
): boolean {
  return left.bytes.every((byte, index) => byte === right.bytes[index]);
}

async function privateSigningAdmissionMaterial(input: {
  readonly intent: unknown;
  readonly signingPayload: unknown;
}): Promise<{
  readonly intentDigest: RouterAbPublicDigest32V1Wire;
  readonly signingPayloadDigest: RouterAbPublicDigest32V1Wire;
  readonly admittedSigningDigest: RouterAbPublicDigest32V1Wire;
}> {
  const payload = privateSigningPayloadPreimage(input.signingPayload);
  const [intentDigest, signingPayloadDigest, admittedSigningDigest] = await Promise.all([
    sha256Digest32(canonicalPrivateSigningIntentBytes(input.intent)),
    sha256Digest32(payload.canonical),
    sha256Digest32(payload.preimage),
  ]);
  if (!privateSigningDigestsEqual(admittedSigningDigest, payload.expectedDigest)) {
    throw new Error('signing_payload expected signing digest does not match its preimage');
  }
  return { intentDigest, signingPayloadDigest, admittedSigningDigest };
}

async function privateSigningRound1BindingDigest(input: {
  readonly scope: RouterAbEd25519NormalSigningScopeV2;
  readonly expiresAtMs: number;
  readonly displayDigest: RouterAbPublicDigest32V1Wire;
  readonly intentDigest: RouterAbPublicDigest32V1Wire;
  readonly signingPayloadDigest: RouterAbPublicDigest32V1Wire;
  readonly admittedSigningDigest: RouterAbPublicDigest32V1Wire;
}): Promise<RouterAbPublicDigest32V1Wire> {
  const out: number[] = [];
  pushLen32(out, textBytes(ED25519_ROUND1_BINDING_VERSION_V2));
  pushLen32(out, textBytes(input.scope.request_id));
  pushLen32(out, textBytes(input.scope.account_id));
  switch (input.scope.authorization.kind) {
    case 'reusable_wallet_session':
      pushLen32(out, textBytes('reusable_wallet_session'));
      pushLen32(out, textBytes(input.scope.authorization.wallet_session_id));
      break;
    case 'operation_step_up':
      pushLen32(out, textBytes('operation_step_up'));
      pushLen32(out, textBytes(input.scope.authorization.grant_id));
      break;
  }
  pushLen32(out, textBytes('mpc_material_activation_ref'));
  pushLen32(out, textBytes(input.scope.material_activation.activation_id));
  pushLen32(out, textBytes(input.scope.material_activation.capability));
  pushLen32(out, textBytes(input.scope.material_activation.material_owner));
  pushLen32(out, textBytes(input.scope.material_activation.key_binding));
  pushLen32(out, textBytes(input.scope.material_activation.lifecycle_binding));
  pushLen32(out, textBytes(input.scope.material_activation.signing_worker));
  pushLen32(out, textBytes(input.scope.signing_worker_id));
  pushU64Be(out, input.expiresAtMs);
  out.push(
    ...input.displayDigest.bytes,
    ...input.intentDigest.bytes,
    ...input.signingPayloadDigest.bytes,
    ...input.admittedSigningDigest.bytes,
  );
  return sha256Digest32(Uint8Array.from(out));
}

function normalizedPrivateSigningHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string,
): string {
  const entry = Object.entries(headers).find(([key]) => key.toLowerCase() === name);
  if (!entry) return '';
  return Array.isArray(entry[1]) ? entry[1].join(',') : String(entry[1] || '').trim();
}

async function privateSigningTrustedSourceDigest(
  headers: Record<string, string | string[] | undefined>,
): Promise<RouterAbPublicDigest32V1Wire> {
  const out = Array.from(textBytes(ED25519_TRUSTED_SOURCE_VERSION_V2));
  for (const name of ['cf-connecting-ip']) {
    const nameBytes = textBytes(name);
    const valueBytes = textBytes(normalizedPrivateSigningHeader(headers, name));
    pushU64Be(out, nameBytes.length);
    out.push(...nameBytes);
    pushU64Be(out, valueBytes.length);
    out.push(...valueBytes);
  }
  return sha256Digest32(Uint8Array.from(out));
}

function privateSigningTrustedAdmission(input: {
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly subjectId: string;
  readonly accountId: string;
  readonly sessionId: string;
  readonly authorizationKind: RouterAbEd25519NormalSigningAuthorizationV2['kind'];
  readonly requestId: string;
  readonly intentDigest: RouterAbPublicDigest32V1Wire;
  readonly trustedSourceDigest: RouterAbPublicDigest32V1Wire;
}): RouterAbNormalSigningTrustedAdmissionV1 {
  return {
    metadata: {
      org_id: input.runtimePolicyScope.orgId,
      project_id: input.runtimePolicyScope.projectId,
      environment: input.runtimePolicyScope.envId,
      account_id: input.accountId,
      auth:
        input.authorizationKind === 'reusable_wallet_session'
          ? {
              auth: 'authenticated_session',
              subject_id: input.subjectId,
              session_id: input.sessionId,
            }
          : {
              auth: 'operation_step_up_session',
              subject_id: input.subjectId,
              authorization_session_id: input.sessionId,
            },
      trusted_source_digest: input.trustedSourceDigest,
      intent_digest: input.intentDigest,
    },
    decision: {
      kind: 'accepted',
      request_id: input.requestId,
    },
  };
}

function privateSigningAuthorizationContext(
  scope: RouterAbEd25519NormalSigningScopeV2,
  authorization: RouterAbEd25519PrivateSigningAuthorization,
): {
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly subjectId: string;
  readonly authorizationSessionId: string;
} {
  if (
    authorization.kind === 'reusable_wallet_session' &&
    scope.authorization.kind === 'reusable_wallet_session'
  ) {
    if (
      scope.authorization.wallet_session_id !== authorization.claims.walletSessionId
    ) {
      throw new Error('Router A/B Ed25519 scope authorization does not match verified claims');
    }
    return {
      runtimePolicyScope: authorization.claims.runtimePolicyScope,
      subjectId: authorization.claims.sub,
      authorizationSessionId: scope.authorization.wallet_session_id,
    };
  }
  if (
    authorization.kind === 'operation_step_up' &&
    scope.authorization.kind === 'operation_step_up'
  ) {
    if (
      scope.account_id !== authorization.session.walletId ||
      scope.material_activation.material_owner !== authorization.session.walletId
    ) {
      throw new Error('Router A/B Ed25519 step-up scope does not match the app session');
    }
    return {
      runtimePolicyScope: authorization.session.runtimePolicyScope,
      subjectId: authorization.session.principalId,
      authorizationSessionId: authorization.session.sessionId,
    };
  }
  throw new Error('Router A/B Ed25519 authorization branch does not match verified claims');
}

type RouterAbEd25519PrivateSigningWorkerBuildInput =
  | {
      readonly phase: 'prepare';
      readonly body: Record<string, unknown>;
      readonly authorization: RouterAbEd25519PrivateSigningAuthorization;
      readonly headers: Record<string, string | string[] | undefined>;
      readonly effectClaim?: never;
    }
  | {
      readonly phase: 'finalize';
      readonly body: Record<string, unknown>;
      readonly authorization: RouterAbEd25519PrivateSigningAuthorization;
      readonly headers: Record<string, string | string[] | undefined>;
      readonly effectClaim: RouterAbNormalSigningEffectClaimV1;
    };

export async function buildRouterAbEd25519PrivateSigningWorkerBody(
  input: RouterAbEd25519PrivateSigningWorkerBuildInput,
): Promise<RouterAbEd25519PrivateSigningWorkerBody> {
  const scope = requirePrivateSigningScope(input.body.scope);
  const signingContext = privateSigningAuthorizationContext(scope, input.authorization);
  const trustedSourceDigest = await privateSigningTrustedSourceDigest(input.headers);
  if (input.phase === 'finalize') {
    const prepareBinding = requirePrivateSigningRecord(
      input.body.prepare_binding,
      'prepare_binding',
    );
    const intentDigest = requirePrivateSigningDigest(
      prepareBinding.intent_digest,
      'prepare_binding.intent_digest',
    );
    const signingPayloadDigest = requirePrivateSigningDigest(
      prepareBinding.signing_payload_digest,
      'prepare_binding.signing_payload_digest',
    );
    const round1BindingDigest = requirePrivateSigningDigest(
      prepareBinding.round1_binding_digest,
      'prepare_binding.round1_binding_digest',
    );
    const expiresAtMs = requirePrivateSigningPositiveSafeInteger(
      input.body.expires_at_ms,
      'expires_at_ms',
    );
    return {
      request: stripRouterAbBudgetMetadata(input.body),
      admission_candidate: {
        org_id: signingContext.runtimePolicyScope.orgId,
        project_id: signingContext.runtimePolicyScope.projectId,
        environment: signingContext.runtimePolicyScope.envId,
        account_id: scope.account_id,
        subject_id: signingContext.subjectId,
        authorization:
          scope.authorization.kind === 'reusable_wallet_session'
            ? {
                kind: 'reusable_wallet_session',
                wallet_session_id: scope.authorization.wallet_session_id,
                grant_id: reusableEd25519SigningGrantId(input.authorization),
              }
            : {
                kind: 'operation_step_up',
                authorization_session_id: signingContext.authorizationSessionId,
                grant_id: scope.authorization.grant_id,
              },
        signing_worker_id: scope.signing_worker_id,
        request_id: scope.request_id,
        intent_digest: intentDigest,
        signing_payload_digest: signingPayloadDigest,
        round1_binding_digest: round1BindingDigest,
        trusted_source_digest: trustedSourceDigest,
        expires_at_ms: expiresAtMs,
      },
      trusted_admission: privateSigningTrustedAdmission({
        runtimePolicyScope: signingContext.runtimePolicyScope,
        subjectId: signingContext.subjectId,
        accountId: scope.account_id,
        sessionId: signingContext.authorizationSessionId,
        authorizationKind: scope.authorization.kind,
        requestId: scope.request_id,
        intentDigest,
        trustedSourceDigest,
      }),
      effect_claim: input.effectClaim,
    };
  }

  const expiresAtMs = requirePrivateSigningPositiveSafeInteger(
    input.body.expires_at_ms,
    'expires_at_ms',
  );
  const material = await privateSigningAdmissionMaterial({
    intent: input.body.intent,
    signingPayload: input.body.signing_payload,
  });
  const round1BindingDigest = await privateSigningRound1BindingDigest({
    scope,
    expiresAtMs,
    displayDigest: requirePrivateSigningDigest(input.body.display_digest, 'display_digest'),
    ...material,
  });
  const trustedAdmission = privateSigningTrustedAdmission({
    runtimePolicyScope: signingContext.runtimePolicyScope,
    subjectId: signingContext.subjectId,
    accountId: scope.account_id,
    sessionId: signingContext.authorizationSessionId,
    authorizationKind: scope.authorization.kind,
    requestId: scope.request_id,
    intentDigest: material.intentDigest,
    trustedSourceDigest,
  });
  return {
    scope,
    expires_at_ms: expiresAtMs,
    admission_candidate: {
      org_id: signingContext.runtimePolicyScope.orgId,
      project_id: signingContext.runtimePolicyScope.projectId,
      environment: signingContext.runtimePolicyScope.envId,
      account_id: scope.account_id,
      subject_id: signingContext.subjectId,
      authorization:
        scope.authorization.kind === 'reusable_wallet_session'
          ? {
              kind: 'reusable_wallet_session',
              wallet_session_id: scope.authorization.wallet_session_id,
              grant_id: reusableEd25519SigningGrantId(input.authorization),
            }
          : {
              kind: 'operation_step_up',
              authorization_session_id: signingContext.authorizationSessionId,
              grant_id: scope.authorization.grant_id,
            },
      signing_worker_id: scope.signing_worker_id,
      request_id: scope.request_id,
      intent_digest: material.intentDigest,
      signing_payload_digest: material.signingPayloadDigest,
      admitted_signing_digest: material.admittedSigningDigest,
      round1_binding_digest: round1BindingDigest,
      trusted_source_digest: trustedSourceDigest,
      expires_at_ms: expiresAtMs,
    },
    trusted_admission: trustedAdmission,
  };
}

export async function buildRouterAbEcdsaDerivationPrivateSigningWorkerBody(input: {
  phase: 'prepare' | 'finalize';
  body: Record<string, unknown>;
  authorization: RouterAbEcdsaPrivateSigningAuthorization;
  headers: Record<string, string | string[] | undefined>;
}): Promise<RouterAbEcdsaDerivationPrivateSigningWorkerBody> {
  const runtimePolicyScope =
    input.authorization.kind === 'reusable_wallet_session'
      ? input.authorization.claims.runtimePolicyScope
      : input.authorization.session.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('Router A/B ECDSA derivation trusted admission requires runtime policy scope');
  }
  const subjectId =
    input.authorization.kind === 'reusable_wallet_session'
      ? input.authorization.claims.sub
      : input.authorization.session.principalId;
  const authorizationSessionId =
    input.authorization.kind === 'reusable_wallet_session'
      ? null
      : input.authorization.session.sessionId;
  const trustedSourceDigest = await privateSigningTrustedSourceDigest(input.headers);
  if (input.phase === 'prepare') {
    const request = parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body);
    const requestDigest = await routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1(request);
    return {
      request,
      trusted_admission: privateSigningTrustedAdmission({
        runtimePolicyScope,
        subjectId,
        accountId: request.scope.wallet_id,
        sessionId:
          authorizationSessionId ||
          routerAbEcdsaDerivationActiveStateId({
            kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
            scope: request.scope,
          }),
        authorizationKind: request.authorization.kind,
        requestId: request.request_id,
        intentDigest: requestDigest,
        trustedSourceDigest,
      }),
    };
  }
  const request = parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(input.body);
  const requestDigest =
    await routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1(request);
  return {
    request,
    trusted_admission: privateSigningTrustedAdmission({
      runtimePolicyScope,
      subjectId,
      accountId: request.scope.wallet_id,
      sessionId:
        authorizationSessionId ||
        routerAbEcdsaDerivationActiveStateId({
          kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
          scope: request.scope,
        }),
      authorizationKind: request.authorization.kind,
      requestId: request.request_id,
      intentDigest: requestDigest,
      trustedSourceDigest,
    }),
  };
}

async function handleRouterAbEd25519OperationStepUpRoute(input: {
  readonly body: Record<string, unknown>;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly session: SessionAdapter | null | undefined;
  readonly authorizationClaims: RouterApiAuthorizationClaimService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  readonly phase: RouterAbEd25519NormalSigningRoutePhase;
  readonly scope: RouterAbEd25519NormalSigningScopeV2;
}): Promise<
  | RouterAbJsonRouteResult
  | {
      readonly phase: 'prepare';
      readonly session: RouterAbOperationStepUpAppSession;
      readonly use: ClaimedCapabilityGrantUse;
      readonly operationDigests: {
        readonly laneDigest: ReturnType<typeof parseDigestB64u>;
        readonly intentDigest: ReturnType<typeof parseDigestB64u>;
        readonly displayDigest: ReturnType<typeof parseDigestB64u>;
      };
    }
  | {
      readonly phase: 'finalize';
      readonly session: RouterAbOperationStepUpAppSession;
    }
> {
  if (input.scope.authorization.kind !== 'operation_step_up') {
    return routerAbStepUpError(400, 'invalid_body', 'Operation step-up authority is required');
  }
  const authenticated = await authenticateRouterAbOperationStepUpAppSession({
    headers: input.headers,
    session: input.session,
    scope: input.scope,
    authorizationClaims: input.authorizationClaims,
    authorizationSessions: input.authorizationSessions,
  });
  if (!authenticated.ok) return authenticated.error;

  const expiresAtMs = Number(input.body.expires_at_ms);
  if (
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= Date.now() ||
    expiresAtMs > authenticated.expiresAtMs
  ) {
    return routerAbStepUpError(
      408,
      'expired_request',
      'Router A/B Ed25519 step-up request is expired',
    );
  }
  let privateBody: RouterAbEd25519PrivateSigningWorkerBody;
  try {
    privateBody =
      input.phase === 'prepare'
        ? await buildRouterAbEd25519PrivateSigningWorkerBody({
            phase: 'prepare',
            body: input.body,
            authorization: {
              kind: 'operation_step_up',
              session: authenticated.session,
            },
            headers: input.headers,
          })
        : await buildRouterAbEd25519PrivateSigningWorkerBody({
            phase: 'finalize',
            body: input.body,
            authorization: {
              kind: 'operation_step_up',
              session: authenticated.session,
            },
            headers: input.headers,
            effectClaim: {
              kind: 'operation_step_up',
              authorization_session_id: authenticated.session.sessionId,
              grant_id: input.scope.authorization.grant_id,
            },
          });
  } catch (error: unknown) {
    return routerAbStepUpError(400, 'invalid_body', errorMessage(error));
  }

  if (input.phase === 'prepare') {
    const operation = parseRouterAbOperationStepUpOperation(input.body.intent);
    if (!operation.ok) {
      return routerAbStepUpError(400, 'invalid_body', operation.message);
    }
    let grantId: CapabilityGrantId;
    let useId: CapabilityGrantUseId;
    let auditEventId: AuthorizationAuditEventId;
    let capabilityId: CapabilityId;
    let laneDigest: ReturnType<typeof parseDigestB64u>;
    let intentDigest: ReturnType<typeof parseDigestB64u>;
    let displayDigest: ReturnType<typeof parseDigestB64u>;
    try {
      grantId = requireAuthorizationValue(
        parseCapabilityGrantId(input.scope.authorization.grant_id),
      );
      useId = requireAuthorizationValue(
        parseCapabilityGrantUseId(`normal-signing-use:${input.scope.request_id}`),
      );
      auditEventId = requireAuthorizationValue(
        parseAuthorizationAuditEventId(`normal-signing-audit:${input.scope.request_id}`),
      );
      capabilityId = requireAuthorizationValue(
        parseCapabilityId(input.scope.material_activation.capability),
      );
      if (!('admission_candidate' in privateBody)) {
        throw new Error('Router A/B step-up prepare admission is missing');
      }
      laneDigest = parseDigestB64u(
        String((input.body.intent as { operation_fingerprint?: unknown }).operation_fingerprint),
      );
      intentDigest = parseDigestB64u(
        base64UrlEncode(Uint8Array.from(privateBody.admission_candidate.intent_digest.bytes)),
      );
      displayDigest = parseDigestB64u(
        base64UrlEncode(
          Uint8Array.from(
            requirePrivateSigningDigest(input.body.display_digest, 'display_digest').bytes,
          ),
        ),
      );
    } catch (error: unknown) {
      return routerAbStepUpError(400, 'invalid_body', errorMessage(error));
    }
    let claimResult: Awaited<
      ReturnType<RouterApiAuthorizationClaimService['claimOperationStepUpFromGrant']>
    >;
    try {
      claimResult = await authenticated.claims.claimOperationStepUpFromGrant({
        tenantId: authenticated.session.tenantId,
        grantId,
        useId,
        auditEventId,
        authorizationSessionId: authenticated.session.sessionId,
        principalId: authenticated.session.principalId,
        capabilityId,
        operationId: operation.operationId,
        operation: operation.operation,
        laneDigest,
        intentDigest,
        displayDigest,
        claimedAtMs: Date.now(),
      });
    } catch (error: unknown) {
      return routerAbStepUpError(400, 'invalid_body', errorMessage(error));
    }
    if (claimResult.kind === 'replayed') {
      return routerAbStepUpError(
        409,
        'operation_claim_completed',
        'Operation step-up grant has already completed its operation',
      );
    }
    const claimFailure = routerAbOperationStepUpClaimFailure(claimResult, useId);
    if (claimFailure) return claimFailure;
    if (claimResult.kind !== 'claimed' && claimResult.kind !== 'operation_in_progress') {
      return routerAbStepUpError(409, 'operation_claim_missing', 'Operation claim is unavailable');
    }
    return {
      phase: 'prepare',
      session: authenticated.session,
      use: claimResult.use,
      operationDigests: { laneDigest, intentDigest, displayDigest },
    };
  }
  return { phase: 'finalize', session: authenticated.session };
}

export async function authenticateRouterAbOperationStepUpAppSessionIdentity(input: {
  readonly headers: Record<string, string | string[] | undefined>;
  readonly session: SessionAdapter | null | undefined;
  readonly walletId: string;
  readonly materialOwner: string;
  readonly authorizationClaims: RouterApiAuthorizationClaimService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
}): Promise<
  | {
      readonly ok: true;
      readonly claims: RouterApiAuthorizationClaimService;
      readonly session: RouterAbOperationStepUpAppSession;
      readonly activeSession: NonNullable<
        Awaited<ReturnType<RouterApiAuthorizationSessionService['readActiveSession']>>
      >;
      readonly authorityRef: NonNullable<
        NonNullable<ReturnType<typeof parseAppSessionClaims>>['walletAuthAuthorityRef']
      >;
      readonly rawClaims: Record<string, unknown>;
      readonly expiresAtMs: number;
    }
  | { readonly ok: false; readonly error: RouterAbJsonRouteResult }
> {
  if (!input.session || !input.authorizationClaims || !input.authorizationSessions) {
    return {
      ok: false,
      error: routerAbStepUpError(
        501,
        'not_configured',
        'Router A/B operation step-up authorization is not configured',
      ),
    };
  }
  let parsed: Awaited<ReturnType<SessionAdapter['parse']>>;
  try {
    parsed = await input.session.parse(input.headers);
  } catch {
    return {
      ok: false,
      error: routerAbStepUpError(401, 'unauthorized', 'App session is unavailable'),
    };
  }
  if (!parsed.ok) {
    return {
      ok: false,
      error: routerAbStepUpError(401, 'unauthorized', 'App session is invalid'),
    };
  }
  const claims = parseAppSessionClaims(parsed.claims);
  const raw = isPlainObject(parsed.claims) ? parsed.claims : null;
  if (
    !claims ||
    !raw ||
    !claims.walletId ||
    !claims.runtimePolicyScope ||
    !claims.walletAuthAuthorityRef
  ) {
    return {
      ok: false,
      error: routerAbStepUpError(401, 'unauthorized', 'App session claims are invalid'),
    };
  }
  const tenantId = parseTenantId(raw.tenantId);
  const principalId = parsePrincipalId(claims.sub);
  const sessionId = parseSeamsSessionId(raw.seamsSessionId);
  if (!tenantId.ok || !principalId.ok || !sessionId.ok) {
    return {
      ok: false,
      error: routerAbStepUpError(401, 'unauthorized', 'App session identity is invalid'),
    };
  }
  const expiresAtMs = Number(claims.exp) * 1_000;
  if (
    tenantId.value !== input.authorizationClaims.tenantId ||
    claims.runtimePolicyScope.orgId !== tenantId.value ||
    claims.walletId !== input.walletId ||
    input.materialOwner !== claims.walletId ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= Date.now()
  ) {
    return {
      ok: false,
      error: routerAbStepUpError(403, 'scope_mismatch', 'App session scope is invalid'),
    };
  }
  const activeSession = await input.authorizationSessions.readActiveSession({
    tenantId: tenantId.value,
    sessionId: sessionId.value,
    nowMs: Date.now(),
  });
  const originHeader = Array.isArray(input.headers.origin)
    ? input.headers.origin[0]
    : input.headers.origin;
  const requestOrigin = String(originHeader || '').trim();
  const audienceMatches =
    activeSession?.audience.kind === 'first_party_web'
      ? activeSession.audience.origin === requestOrigin
      : activeSession?.audience.kind === 'hosted_wallet_iframe'
        ? activeSession.audience.walletOrigin === requestOrigin
        : false;
  if (!activeSession || activeSession.principalId !== principalId.value || !audienceMatches) {
    return {
      ok: false,
      error: routerAbStepUpError(401, 'unauthorized', 'Active app session is unavailable'),
    };
  }
  return {
    ok: true,
    claims: input.authorizationClaims,
    session: {
      tenantId: tenantId.value,
      principalId: principalId.value,
      sessionId: sessionId.value,
      walletId: claims.walletId,
      runtimePolicyScope: claims.runtimePolicyScope,
    },
    activeSession,
    authorityRef: claims.walletAuthAuthorityRef,
    rawClaims: raw,
    expiresAtMs,
  };
}

export async function authenticateRouterAbOperationStepUpAppSession(input: {
  readonly headers: Record<string, string | string[] | undefined>;
  readonly session: SessionAdapter | null | undefined;
  readonly scope: RouterAbEd25519NormalSigningScopeV2;
  readonly authorizationClaims: RouterApiAuthorizationClaimService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
}): ReturnType<typeof authenticateRouterAbOperationStepUpAppSessionIdentity> {
  return authenticateRouterAbOperationStepUpAppSessionIdentity({
    headers: input.headers,
    session: input.session,
    walletId: input.scope.account_id,
    materialOwner: input.scope.material_activation.material_owner,
    authorizationClaims: input.authorizationClaims,
    authorizationSessions: input.authorizationSessions,
  });
}

export async function authenticateRouterAbEcdsaOperationStepUpAppSession(input: {
  readonly headers: Record<string, string | string[] | undefined>;
  readonly session: SessionAdapter | null | undefined;
  readonly request:
    | RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire
    | RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire;
  readonly authorizationClaims: RouterApiAuthorizationClaimService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
}): ReturnType<typeof authenticateRouterAbOperationStepUpAppSessionIdentity> {
  return authenticateRouterAbOperationStepUpAppSessionIdentity({
    headers: input.headers,
    session: input.session,
    walletId: input.request.scope.wallet_id,
    materialOwner: input.request.material_activation.material_owner,
    authorizationClaims: input.authorizationClaims,
    authorizationSessions: input.authorizationSessions,
  });
}

export function parseRouterAbEd25519OperationStepUpScope(
  value: unknown,
): RouterAbEd25519NormalSigningScopeV2 {
  return requirePrivateSigningScope(value);
}

export function parseRouterAbOperationStepUpOperation(value: unknown):
  | {
      readonly ok: true;
      readonly operationId: CapabilityOperationId;
      readonly operation: CapabilityOperationRef;
    }
  | { readonly ok: false; readonly message: string } {
  const intent = isPlainObject(value) ? value : null;
  if (!intent) return { ok: false, message: 'Router A/B step-up intent is required' };
  let operationKind:
    | 'near.sign_transaction'
    | 'near.sign_delegate_action'
    | 'near.sign_nep413_message';
  switch (intent.kind) {
    case 'near_transaction_v1':
      operationKind = 'near.sign_transaction';
      break;
    case 'near_delegate_action_v1':
      operationKind = 'near.sign_delegate_action';
      break;
    case 'nep413_v1':
      operationKind = 'near.sign_nep413_message';
      break;
    default:
      return { ok: false, message: 'Router A/B step-up intent kind is invalid' };
  }
  const operationId = parseCapabilityOperationId(intent.operation_id);
  if (!operationId.ok) return { ok: false, message: operationId.error.message };
  return {
    ok: true,
    operationId: operationId.value,
    operation: buildNearEd25519MpcOperationRef(operationKind),
  };
}

function requireAuthorizationValue<T>(result: AuthorizationParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function routerAbOperationStepUpClaimFailure(
  result: Awaited<ReturnType<RouterApiAuthorizationClaimService['claimOperationStepUpFromGrant']>>,
  expectedUseId: CapabilityGrantUseId,
): RouterAbJsonRouteResult | null {
  switch (result.kind) {
    case 'claimed':
    case 'operation_in_progress':
    case 'replayed':
      return result.use.useId === expectedUseId
        ? null
        : routerAbStepUpError(
            409,
            'operation_claim_mismatch',
            'Operation step-up claim belongs to another request',
          );
    case 'grant_expired':
      return routerAbStepUpError(401, result.kind, 'Operation step-up grant is expired');
    case 'grant_exhausted':
      return routerAbStepUpError(409, result.kind, 'Operation step-up grant is exhausted');
    case 'grant_mismatch':
    case 'wallet_session_mismatch':
      return routerAbStepUpError(403, result.kind, 'Operation step-up grant does not match');
    case 'wallet_session_expired':
    case 'wallet_session_quota_exhausted':
      return routerAbStepUpError(409, result.kind, 'Operation step-up authorization is invalid');
  }
}

function routerAbStepUpError(
  status: number,
  code: string,
  message: string,
): RouterAbJsonRouteResult {
  return { status, body: { ok: false, code, message } };
}

export async function authorizeRouterAbEd25519NormalSigningRoute(input: {
  body: Record<string, unknown>;
  rawBody: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
  authorizationClaims: RouterApiAuthorizationClaimService | null | undefined;
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  phase: RouterAbEd25519NormalSigningRoutePhase;
}): Promise<RouterAbEd25519NormalSigningAuthorizationResult> {
  const invalidSessionKind = rejectRouterAbCookieSessionKind(
    input.rawBody,
    'Router A/B Ed25519 normal-signing requires sessionKind=jwt',
  );
  if (invalidSessionKind) return { ok: false, result: invalidSessionKind };

  let scope: RouterAbEd25519NormalSigningScopeV2;
  try {
    scope = requirePrivateSigningScope(input.body.scope);
  } catch {
    return {
      ok: false,
      result: {
        status: 400,
        body: {
          ok: false,
          code: 'invalid_body',
          message: 'Router A/B Ed25519 normal-signing scope is required',
        },
      },
    };
  }
  if (scope.authorization.kind === 'operation_step_up') {
    const result = await handleRouterAbEd25519OperationStepUpRoute({
        body: input.body,
        headers: input.headers,
        session: input.session,
        authorizationClaims: input.authorizationClaims,
        authorizationSessions: input.authorizationSessions,
        phase: input.phase,
        scope,
      });
    return 'status' in result
      ? { ok: false, result }
      : { ok: true, kind: 'operation_step_up', ...result };
  }

  const validated = await validateRouterAbEd25519WalletSessionTokenInputs({
    body: input.rawBody,
    headers: input.headers,
    session: input.session,
  });
  if (!validated.ok) {
    return {
      ok: false,
      result: {
        status: routerAbWalletSessionValidationStatus(validated.code),
        body: { ok: false, code: validated.code, message: validated.message },
      },
    };
  }

  const admission = validateRouterAbEd25519NormalSigningRequestScope({
    claims: validated.claims,
    walletSessionAuth: validated.walletSessionAuth,
    body: input.body,
  });
  if (!admission.ok) {
    return {
      ok: false,
      result: { status: admission.error.status, body: admission.error.body },
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
      ok: false,
      result: {
        status: admissionDecision.status,
        body: {
          ok: false,
          code: admissionDecision.code,
          message: admissionDecision.message,
        },
      },
    };
  }

  return { ok: true, kind: 'reusable_wallet_session', validated, admission };
}

export async function handleRouterAbEd25519NormalSigningRouteCore(input: {
  body: Record<string, unknown>;
  rawBody: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
  runtime: RouterAbNormalSigningRouteRuntime | null | undefined;
  authorizationClaims: RouterApiAuthorizationClaimService | null | undefined;
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  privatePath: RouterAbEd25519PrivateSigningPath;
  phase: RouterAbEd25519NormalSigningRoutePhase;
}): Promise<RouterAbJsonRouteResult> {
  const authorization = await authorizeRouterAbEd25519NormalSigningRoute(input);
  if (!authorization.ok) return authorization.result;
  if (authorization.kind === 'operation_step_up') {
    return routerAbStepUpError(500, 'internal', 'Operation step-up must execute through the MPC router');
  }
  const { validated, admission } = authorization;

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

  let privateBody: RouterAbEd25519PrivateSigningWorkerBody | null = null;
  if (input.phase === 'prepare') {
    try {
      privateBody = await buildRouterAbEd25519PrivateSigningWorkerBody({
        phase: 'prepare',
        body: input.body,
        authorization: {
          kind: 'reusable_wallet_session',
          claims: validated.claims,
        },
        headers: input.headers,
      });
    } catch (error: unknown) {
      return {
        status: 400,
        body: {
          ok: false,
          code: 'invalid_body',
          message: errorMessage(error),
        },
      };
    }
  }

  if (input.phase === 'prepare') {
    const replay = await runtime.reservePrepareReplay({
      curve: 'ed25519',
      authorizationIdentity: {
        kind: 'reusable_wallet_session',
        walletSessionId: validated.walletSessionAuth.walletSessionId,
      },
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
      signingGrantId: validated.walletSessionAuth.signingGrantId,
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
      signingGrantId: validated.walletSessionAuth.signingGrantId,
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
    let finalizeBody: RouterAbEd25519PrivateSigningWorkerBody;
    try {
      finalizeBody = await buildRouterAbEd25519PrivateSigningWorkerBody({
        phase: 'finalize',
        body: input.body,
        authorization: {
          kind: 'reusable_wallet_session',
          claims: validated.claims,
        },
        headers: input.headers,
        effectClaim: {
          kind: 'reusable_wallet_session',
          budget: {
            signing_grant_id: validated.walletSessionAuth.signingGrantId,
            reservation_id: reservationId,
            signing_worker_id: signingWorkerId,
            operation_id: operationId,
            request_digest: requirePrivateSigningDigestB64u(
              requestDigest,
              'budget request digest',
            ),
          },
        },
      });
    } catch (error: unknown) {
      return {
        status: 400,
        body: { ok: false, code: 'invalid_body', message: errorMessage(error) },
      };
    }
    const forwarded = await postRouterAbSigningWorkerJson({
      config: signingWorker,
      path: input.privatePath,
      body: finalizeBody,
    });
    return forwarded.ok
      ? { status: 200, body: forwarded.body }
      : { status: forwarded.status, body: forwarded.body };
  }

  if (!privateBody) {
    return {
      status: 500,
      body: {
        ok: false,
        code: 'internal',
        message: 'Router A/B Ed25519 prepare body is unavailable',
      },
    };
  }

  const forwarded = await postRouterAbSigningWorkerJson({
    config: signingWorker,
    path: input.privatePath,
    body: privateBody,
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
  let scope: RouterAbEd25519NormalSigningScopeV2;
  try {
    scope = requirePrivateSigningScope(input.body.scope);
  } catch {
    return {
      ok: false,
      error: routerAbSigningError(
        400,
        'invalid_body',
        'Router A/B Ed25519 normal-signing scope is required',
      ),
    };
  }
  const authorization = scope.authorization;
  if (authorization.kind !== 'reusable_wallet_session') {
    return {
      ok: false,
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
    };
  }
  if (
    scope.account_id !== input.walletSessionAuth.userId ||
    authorization.wallet_session_id !== input.walletSessionAuth.walletSessionId ||
    scope.material_activation.material_owner !== input.walletSessionAuth.userId
  ) {
    return {
      ok: false,
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
    };
  }
  if (scope.signing_worker_id !== input.claims.routerAbNormalSigning.signingWorkerId) {
    return {
      ok: false,
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
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
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
    };
  }
  return {
    ok: true,
    thresholdSessionId: input.walletSessionAuth.thresholdSessionId,
    requestId: scope.request_id,
    expiresAtMs,
  };
}

export function validateRouterAbEcdsaDerivationNormalSigningPrepareRequest(input: {
  claims: RouterAbEcdsaDerivationWalletSessionClaims;
  walletSessionAuth: VerifiedEcdsaWalletSessionAuth;
  body: Record<string, unknown>;
}): RouterAbEcdsaNormalSigningRouteAdmission {
  const normalSigning = input.claims.routerAbEcdsaDerivationNormalSigning;
  if (!normalSigning) {
    return {
      ok: false,
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.claimsInvalid),
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
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
    };
  }
  if (
    request.authorization.kind !== 'reusable_wallet_session' ||
    request.authorization.wallet_session_id !== input.claims.walletSessionId ||
    request.material_activation.material_owner !== input.claims.walletId ||
    request.material_activation.signing_worker !== normalSigning.scope.signing_worker.server_id
  ) {
    return {
      ok: false,
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
    };
  }
  if (
    !sameRouterAbMpcMaterialActivationRef(
      request.material_activation,
      normalSigning.scope.material_activation,
    )
  ) {
    return {
      ok: false,
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
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
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
    };
  }
  return {
    ok: true,
    thresholdSessionId: input.walletSessionAuth.thresholdSessionId,
    requestId: request.request_id,
    expiresAtMs: request.expires_at_ms,
    materialActivation: request.material_activation,
  };
}

/**
 * Re-resolve the complete activation reference immediately before a claim or
 * evidence write. The resolver is authoritative for capability identity and
 * all owner/key/lifecycle/worker bindings; a stale or superseded reference
 * must fail before any authorization side effect is attempted.
 */
export async function resolveFreshRouterAbEcdsaMaterialActivation(input: {
  readonly resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
  readonly walletId: string;
  readonly expected: RouterAbMpcMaterialActivationRefWire;
}): Promise<
  | {
      readonly ok: true;
      readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
      readonly keyHandle: string;
      readonly relayerKeyId: string;
      readonly participantIds: readonly [number, number];
    }
  | { readonly ok: false; readonly code: 'not_found' | 'internal'; readonly message: string }
  | { readonly ok: false; readonly code: 'scope_mismatch'; readonly message: string }
> {
  const resolved = await input.resolveEcdsaMaterialActivation({
    walletId: input.walletId,
    materialActivation: input.expected,
  });
  if (!resolved.ok) return resolved;
  if (!sameRouterAbMpcMaterialActivationRef(resolved.materialActivation, input.expected)) {
    return {
      ok: false,
      code: 'scope_mismatch',
      message: 'ECDSA material activation changed before authorization claim',
    };
  }
  return resolved;
}

export function validateRouterAbEcdsaDerivationNormalSigningFinalizeRequest(input: {
  claims: RouterAbEcdsaDerivationWalletSessionClaims;
  walletSessionAuth: VerifiedEcdsaWalletSessionAuth;
  body: Record<string, unknown>;
}): RouterAbEcdsaNormalSigningRouteAdmission {
  const normalSigning = input.claims.routerAbEcdsaDerivationNormalSigning;
  if (!normalSigning) {
    return {
      ok: false,
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.claimsInvalid),
    };
  }
  let request: ReturnType<
    typeof parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1
  >;
  try {
    request = parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(input.body);
  } catch (error) {
    return {
      ok: false,
      error: routerAbSigningError(400, 'invalid_body', errorMessage(error)),
    };
  }
  if (!sameRouterAbEcdsaDerivationNormalSigningScopeV1(request.scope, normalSigning.scope)) {
    return {
      ok: false,
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
    };
  }
  if (
    request.authorization.kind !== 'reusable_wallet_session' ||
    request.authorization.wallet_session_id !== input.claims.walletSessionId ||
    request.material_activation.material_owner !== input.claims.walletId ||
    request.material_activation.signing_worker !== normalSigning.scope.signing_worker.server_id
  ) {
    return {
      ok: false,
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
    };
  }
  if (
    !sameRouterAbMpcMaterialActivationRef(
      request.material_activation,
      normalSigning.scope.material_activation,
    )
  ) {
    return {
      ok: false,
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
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
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
    };
  }
  return {
    ok: true,
    thresholdSessionId: input.walletSessionAuth.thresholdSessionId,
    requestId: request.request_id,
    expiresAtMs: request.expires_at_ms,
    materialActivation: request.material_activation,
  };
}

async function admitRouterAbEcdsaReusableWalletSessionOperation(input: {
  request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire;
  materialActivation: RouterAbMpcMaterialActivationRefWire;
  claims: RouterAbEcdsaDerivationWalletSessionClaims;
  authorizationClaims: RouterApiAuthorizationClaimService;
  authorizationSessions: RouterApiAuthorizationSessionService;
  resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
}): Promise<
  | {
      readonly ok: true;
      readonly claim: NonNullable<
        Awaited<
          ReturnType<RouterApiAuthorizationClaimService['claimReusableWalletSessionOperation']>
        >['claim']
      >;
    }
  | { readonly ok: false; readonly error: RouterAbJsonRouteResult }
> {
  if (!routerAbEcdsaAtomicAuthorizationConfigured(input.authorizationClaims)) {
    return {
      ok: false,
      error: routerAbStepUpError(
        501,
        'not_configured',
        'ECDSA atomic authorization is not configured',
      ),
    };
  }
  if (input.request.authorization.kind !== 'reusable_wallet_session') {
    return {
      ok: false,
      error: routerAbStepUpError(
        400,
        'invalid_body',
        'Reusable Wallet Session authority is required',
      ),
    };
  }
  const nowMs = Date.now();
  try {
    const runtimePolicyScope = input.claims.runtimePolicyScope;
    if (!runtimePolicyScope) {
      throw new Error('ECDSA operation runtime policy scope is required');
    }
    const tenantId = requireAuthorizationValue(parseTenantId(runtimePolicyScope.orgId));
    const principalId = requireAuthorizationValue(parsePrincipalId(input.claims.sub));
    const authorizationSessionId = input.claims.authorizationSessionId;
    const activeSession = await input.authorizationSessions.readActiveSession({
      tenantId,
      sessionId: authorizationSessionId,
      nowMs,
    });
    if (
      tenantId !== input.authorizationClaims.tenantId ||
      tenantId !== input.authorizationSessions.tenantId ||
      !activeSession ||
      activeSession.principalId !== principalId ||
      input.request.authorization.wallet_session_id !== input.claims.walletSessionId
    ) {
      return {
        ok: false,
        error: routerAbStepUpError(
          403,
          'wallet_session_mismatch',
          'Reusable Wallet Session identity does not match',
        ),
      };
    }
    const freshMaterial = await resolveFreshRouterAbEcdsaMaterialActivation({
      resolveEcdsaMaterialActivation: input.resolveEcdsaMaterialActivation,
      walletId: input.claims.walletId,
      expected: input.materialActivation,
    });
    if (!freshMaterial.ok) {
      return {
        ok: false,
        error: routerAbStepUpError(
          freshMaterial.code === 'internal' ? 500 : 403,
          freshMaterial.code === 'internal' ? 'internal' : 'wallet_session_mismatch',
          freshMaterial.message,
        ),
      };
    }
    if (freshMaterial.keyHandle !== input.claims.keyHandle) {
      return {
        ok: false,
        error: routerAbStepUpError(
          403,
          'wallet_session_mismatch',
          'Reusable Wallet Session key does not match the active material',
        ),
      };
    }
    const capabilityId = requireAuthorizationValue(
      parseCapabilityId(freshMaterial.materialActivation.capability),
    );
    const operationId = requireAuthorizationValue(
      parseCapabilityOperationId(input.request.operation_id),
    );
    const operation = buildEvmEcdsaMpcOperationRef('evm.sign_transaction');
    const envelope = buildCapabilityOperationEnvelope({
      tenantId,
      principalId,
      capabilityId,
      operationId,
      operation,
      digests: {
        laneDigest: parseDigestB64u(input.request.operation_digests.lane_digest_b64u),
        intentDigest: parseDigestB64u(input.request.operation_digests.intent_digest_b64u),
        displayDigest: parseDigestB64u(input.request.operation_digests.display_digest_b64u),
      },
    });
    const evidenceId = requireAuthorizationValue(
      parseGrantEvidenceId(`ecdsa-session-evidence:${operationId}`),
    );
    const evidenceSetId = requireAuthorizationValue(
      parseGrantEvidenceSetId(`ecdsa-session-evidence-set:${operationId}`),
    );
    const expiresAtMs = Math.min(
      input.request.expires_at_ms,
      input.claims.thresholdExpiresAtMs,
      activeSession.lifecycle.expiresAtMs,
    );
    const evidenceSet = await buildVerifiedSessionEvidenceSet({
      session: activeSession,
      operation: envelope,
      evidenceId,
      evidenceSetId,
      expiresAtMs,
    });
    const grantId = requireAuthorizationValue(
      parseCapabilityGrantId(`ecdsa-operation-grant:${operationId}`),
    );
    const grant = buildActiveCapabilityGrant({
        tenantId,
        principalId,
        grantId,
        bindingId: requireAuthorizationValue(
          parseCapabilityBindingId(`ecdsa-operation-binding:${operationId}`),
        ),
        evidenceSetId,
        evidenceSetDigest: evidenceSet.evidenceSetDigest,
        capabilityId,
        operationId,
        operation,
        laneDigest: envelope.digests.laneDigest,
        intentDigest: envelope.digests.intentDigest,
        displayDigest: envelope.digests.displayDigest,
        authority: {
          kind: 'reusable_wallet_session',
          walletSessionId: input.claims.walletSessionId,
          quotaId: input.claims.quotaId,
        },
        remainingUses: 1,
        createdAtMs: nowMs,
        expiresAtMs,
      });
    const useId = requireAuthorizationValue(
      parseCapabilityGrantUseId(
        `ecdsa-operation-use:${operationId}:${input.request.request_id}`,
      ),
    );
    const auditEventId = requireAuthorizationValue(
      parseAuthorizationAuditEventId(`ecdsa-operation-audit:${operationId}`),
    );
    const claim = await buildCapabilityOperationClaim({
      tenantId,
      useId,
      auditEventId,
      grantId,
      operation: envelope,
      evidenceSetDigest: evidenceSet.evidenceSetDigest,
      claimedAtMs: nowMs,
      authorization: {
        kind: 'reusable_wallet_session',
        walletSessionId: input.claims.walletSessionId,
        quotaId: input.claims.quotaId,
      },
    });
    const outcome = await input.authorizationClaims.claimEcdsaReusableWalletSessionOperation({
      evidenceSet,
      grant,
      claim,
      material: {
        walletId: requireAuthorizationValue(parseWalletId(input.claims.walletId)),
        keyHandle: freshMaterial.keyHandle,
        runtimePolicyScope,
        materialActivation: freshMaterial.materialActivation,
      },
    });
    if (outcome.result.kind === 'material_mismatch') {
      return {
        ok: false,
        error: routerAbStepUpError(
          403,
          'wallet_session_mismatch',
          'ECDSA material activation is no longer active',
        ),
      };
    }
    const claimFailure = routerAbReusableWalletSessionClaimFailure(outcome.result, useId);
    if (claimFailure) return { ok: false, error: claimFailure };
    if (!outcome.claim) {
      return {
        ok: false,
        error: routerAbStepUpError(
          409,
          outcome.result.kind,
          'Exact ECDSA operation claim is unavailable',
        ),
      };
    }
    return { ok: true, claim: outcome.claim };
  } catch (error: unknown) {
    return {
      ok: false,
      error: routerAbStepUpError(400, 'invalid_body', errorMessage(error)),
    };
  }
}

function routerAbReusableWalletSessionClaimFailure(
  result: Awaited<ReturnType<RouterApiAuthorizationClaimService['claimReusableWalletSessionFromGrant']>>,
  expectedUseId: CapabilityGrantUseId,
): RouterAbJsonRouteResult | null {
  switch (result.kind) {
    case 'claimed':
    case 'operation_in_progress':
    case 'replayed':
      return result.use.useId === expectedUseId
        ? null
        : routerAbStepUpError(
            409,
            'operation_claim_mismatch',
            'Operation claim belongs to another request',
          );
    case 'grant_expired':
      return routerAbStepUpError(401, result.kind, 'Operation grant is expired');
    case 'grant_exhausted':
    case 'wallet_session_quota_exhausted':
      return routerAbStepUpError(409, result.kind, 'Reusable Wallet Session quota is exhausted');
    case 'grant_mismatch':
    case 'wallet_session_mismatch':
      return routerAbStepUpError(403, result.kind, 'Reusable Wallet Session grant does not match');
    case 'wallet_session_expired':
      return routerAbStepUpError(401, result.kind, 'Reusable Wallet Session is expired');
  }
}

async function completeRouterAbEcdsaOperation(input: {
  authorizationClaims: RouterApiAuthorizationClaimService;
  claim: NonNullable<
    Awaited<
      ReturnType<RouterApiAuthorizationClaimService['claimReusableWalletSessionOperation']>
    >['claim']
  >;
  requestId: string;
  result: 'succeeded' | 'failed_before_side_effect' | 'failed_after_side_effect';
  response: unknown;
}): Promise<void> {
  const resultDigest = parseDigestB64u(
    await sha256B64u(textBytes(alphabetizeStringify(input.response))),
  );
  const resultStorageRef = requireAuthorizationValue(
    parseCapabilityOperationResultStorageRef(`router-signing-result:${input.requestId}`),
  );
  const completed = await input.authorizationClaims.completeOperation({
    claim: input.claim,
    result: input.result,
    resultRef: {
      resultDigest,
      resultStorageRef,
    },
    completedAtMs: Date.now(),
  });
  if (completed.kind === 'claim_missing' || completed.kind === 'claim_mismatch') {
    throw new Error('Exact ECDSA operation completion did not match its claim');
  }
}

type RouterAbEcdsaOperationStepUpRequest =
  | RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire
  | RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire;

function parseRouterAbEcdsaOperationStepUpRequest(input: {
  readonly phase: 'prepare' | 'finalize';
  readonly body: Record<string, unknown>;
}): RouterAbEcdsaOperationStepUpRequest {
  return input.phase === 'prepare'
    ? parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body)
    : parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(input.body);
}

function validateRouterAbEcdsaOperationStepUpIdentity(input: {
  readonly request: RouterAbEcdsaOperationStepUpRequest;
  readonly session: RouterAbOperationStepUpAppSession;
  readonly sessionExpiresAtMs: number;
}): RouterAbJsonRouteResult | null {
  const request = input.request;
  if (
    request.authorization.kind !== 'operation_step_up' ||
    request.scope.wallet_id !== input.session.walletId ||
    request.material_activation.material_owner !== input.session.walletId ||
    request.material_activation.signing_worker !== request.scope.signing_worker.server_id ||
    !sameRouterAbMpcMaterialActivationRef(
      request.material_activation,
      request.scope.material_activation,
    )
  ) {
    return routerAbStepUpError(
      403,
      'scope_mismatch',
      'ECDSA operation step-up identity does not match',
    );
  }
  if (request.expires_at_ms <= Date.now()) {
    return routerAbStepUpError(
      408,
      'expired_request',
      'Router A/B ECDSA operation step-up request is expired',
    );
  }
  if (request.expires_at_ms > input.sessionExpiresAtMs) {
    return routerAbStepUpError(
      403,
      'scope_mismatch',
      'ECDSA operation step-up exceeds the app session lifetime',
    );
  }
  return null;
}

export async function claimRouterAbEcdsaOperationStepUp(input: {
  readonly operationKind: 'evm.sign_transaction' | 'evm.export_key';
  readonly operation: Pick<
    RouterAbEcdsaOperationStepUpPreparationV1Wire,
    'operation_id' | 'operation_digests' | 'material_activation'
  >;
  readonly grantId: string;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly keyHandle: string;
  readonly authenticated: Extract<
    Awaited<ReturnType<typeof authenticateRouterAbEcdsaOperationStepUpAppSession>>,
    { readonly ok: true }
  >;
}): Promise<RouterAbJsonRouteResult | null> {
  if (!routerAbEcdsaAtomicAuthorizationConfigured(input.authenticated.claims)) {
    return routerAbStepUpError(
      501,
      'not_configured',
      'ECDSA atomic authorization is not configured',
    );
  }
  let useId: CapabilityGrantUseId;
  let claimInput: Parameters<
    RouterApiAuthorizationClaimService['claimEcdsaOperationStepUpFromGrant']
  >[0]['claim'];
  try {
    const operationId = requireAuthorizationValue(
      parseCapabilityOperationId(input.operation.operation_id),
    );
    useId = requireAuthorizationValue(
      parseCapabilityGrantUseId(
        `ecdsa-operation-step-up-use:${input.operation.operation_id}`,
      ),
    );
    claimInput = {
      tenantId: input.authenticated.session.tenantId,
      grantId: requireAuthorizationValue(
        parseCapabilityGrantId(input.grantId),
      ),
      useId,
      auditEventId: requireAuthorizationValue(
        parseAuthorizationAuditEventId(
          `ecdsa-operation-step-up-audit:${input.operation.operation_id}`,
        ),
      ),
      authorizationSessionId: input.authenticated.session.sessionId,
      principalId: input.authenticated.session.principalId,
      capabilityId: requireAuthorizationValue(
        parseCapabilityId(input.materialActivation.capability),
      ),
      operationId,
      operation: buildEvmEcdsaMpcOperationRef(input.operationKind),
      laneDigest: parseDigestB64u(input.operation.operation_digests.lane_digest_b64u),
      intentDigest: parseDigestB64u(input.operation.operation_digests.intent_digest_b64u),
      displayDigest: parseDigestB64u(input.operation.operation_digests.display_digest_b64u),
      claimedAtMs: Date.now(),
    };
  } catch (error: unknown) {
    return routerAbStepUpError(400, 'invalid_body', errorMessage(error));
  }
  const result = await input.authenticated.claims.claimEcdsaOperationStepUpFromGrant({
    claim: claimInput,
    material: {
      walletId: requireAuthorizationValue(
        parseWalletId(input.authenticated.session.walletId),
      ),
      keyHandle: input.keyHandle,
      runtimePolicyScope: input.authenticated.session.runtimePolicyScope,
      materialActivation: input.materialActivation,
    },
  });
  if (result.kind === 'material_mismatch') {
    return routerAbStepUpError(
      403,
      'scope_mismatch',
      'ECDSA material activation changed before operation claim',
    );
  }
  return routerAbOperationStepUpClaimFailure(result, useId);
}

async function handleRouterAbEcdsaOperationStepUpRoute(input: {
  readonly body: Record<string, unknown>;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly session: SessionAdapter | null | undefined;
  readonly authorizationClaims: RouterApiAuthorizationClaimService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  readonly admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  readonly resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
  readonly phase: 'prepare' | 'finalize';
}): Promise<RouterAbJsonRouteResult | null> {
  let request: RouterAbEcdsaOperationStepUpRequest;
  try {
    request = parseRouterAbEcdsaOperationStepUpRequest(input);
  } catch (error: unknown) {
    return routerAbStepUpError(400, 'invalid_body', errorMessage(error));
  }
  if (request.authorization.kind !== 'operation_step_up') {
    return routerAbStepUpError(400, 'invalid_body', 'Operation step-up authority is required');
  }
  const authenticated = await authenticateRouterAbEcdsaOperationStepUpAppSession({
    headers: input.headers,
    session: input.session,
    request,
    authorizationClaims: input.authorizationClaims,
    authorizationSessions: input.authorizationSessions,
  });
  if (!authenticated.ok) return authenticated.error;
  const identityFailure = validateRouterAbEcdsaOperationStepUpIdentity({
    request,
    session: authenticated.session,
    sessionExpiresAtMs: authenticated.expiresAtMs,
  });
  if (identityFailure) return identityFailure;
  const activeMaterial = await input.resolveEcdsaMaterialActivation({
    walletId: authenticated.session.walletId,
    materialActivation: request.material_activation,
  });
  if (!activeMaterial.ok) {
    return routerAbStepUpError(
      activeMaterial.code === 'internal' ? 500 : 403,
      activeMaterial.code === 'internal' ? 'internal' : 'scope_mismatch',
      activeMaterial.code === 'internal'
        ? activeMaterial.message
        : 'ECDSA operation step-up material is no longer active',
    );
  }
  if (
    !sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      request.scope.material_activation,
    )
  ) {
    return routerAbStepUpError(
      403,
      'scope_mismatch',
      'ECDSA operation step-up scope does not name the active material',
    );
  }
  const materialActivationId = requireMpcMaterialActivationId(
    activeMaterial.materialActivation.activation_id,
  );
  if (!input.admissionAdapter) {
    return routerAbStepUpError(
      501,
      'not_configured',
      'Router A/B ECDSA operation step-up admission is not configured',
    );
  }
  const admission = await input.admissionAdapter.evaluatePolicy({
    curve: 'ecdsa',
    phase: input.phase,
    walletId: authenticated.session.walletId,
    materialActivationId,
    authorizationIdentity: {
      kind: 'operation_step_up',
      materialActivationId,
    },
    signingGrantId: request.authorization.grant_id,
    requestId: request.request_id,
    expiresAtMs: request.expires_at_ms,
    signingWorkerId: activeMaterial.materialActivation.signing_worker,
    keyHandle: activeMaterial.keyHandle,
    runtimePolicyScope: authenticated.session.runtimePolicyScope,
  });
  if (!admission.ok) {
    return {
      status: admission.status,
      body: { ok: false, code: admission.code, message: admission.message },
    };
  }
  const freshMaterial = await resolveFreshRouterAbEcdsaMaterialActivation({
    resolveEcdsaMaterialActivation: input.resolveEcdsaMaterialActivation,
    walletId: authenticated.session.walletId,
    expected: request.material_activation,
  });
  if (!freshMaterial.ok) {
    return routerAbStepUpError(
      freshMaterial.code === 'internal' ? 500 : 403,
      freshMaterial.code === 'internal' ? 'internal' : 'scope_mismatch',
      freshMaterial.message,
    );
  }
  if (
    freshMaterial.keyHandle !== activeMaterial.keyHandle ||
    freshMaterial.relayerKeyId !== activeMaterial.relayerKeyId ||
    freshMaterial.participantIds[0] !== activeMaterial.participantIds[0] ||
    freshMaterial.participantIds[1] !== activeMaterial.participantIds[1]
  ) {
    return routerAbStepUpError(
      403,
      'scope_mismatch',
      'ECDSA operation step-up signer facts changed before operation claim',
    );
  }
  if (input.phase === 'prepare') {
    const prepareRequest = parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body);
    const claimFailure = await claimRouterAbEcdsaOperationStepUp({
      operationKind: 'evm.sign_transaction',
      operation: {
        operation_id: prepareRequest.operation_id,
        operation_digests: prepareRequest.operation_digests,
        material_activation: prepareRequest.material_activation,
      },
      materialActivation: freshMaterial.materialActivation,
      keyHandle: freshMaterial.keyHandle,
      grantId:
        prepareRequest.authorization.kind === 'operation_step_up'
          ? prepareRequest.authorization.grant_id
          : '',
      authenticated,
    });
    if (claimFailure) return claimFailure;
  }
  return null;
}

export async function authorizeRouterAbEcdsaDerivationNormalSigningRoute(input: {
  body: Record<string, unknown>;
  rawBody: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
  authorizationClaims: RouterApiAuthorizationClaimService | null | undefined;
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
  phase: 'prepare' | 'finalize';
}): Promise<RouterAbEcdsaNormalSigningAuthorizationResult> {
  const invalidSessionKind = rejectRouterAbCookieSessionKind(
    input.rawBody,
    'Router A/B ECDSA derivation normal-signing requires sessionKind=jwt',
  );
  if (invalidSessionKind) return { ok: false, result: invalidSessionKind };

  let requestedAuthorizationKind: RouterAbNormalSigningAuthorizationWire['kind'];
  try {
    requestedAuthorizationKind = parseRouterAbEcdsaOperationStepUpRequest({
      phase: input.phase,
      body: input.body,
    }).authorization.kind;
  } catch (error: unknown) {
    return { ok: false, result: routerAbStepUpError(400, 'invalid_body', errorMessage(error)) };
  }
  if (requestedAuthorizationKind === 'operation_step_up') {
    const failure = await handleRouterAbEcdsaOperationStepUpRoute({
        body: input.body,
        headers: input.headers,
        session: input.session,
        authorizationClaims: input.authorizationClaims,
        authorizationSessions: input.authorizationSessions,
        admissionAdapter: input.admissionAdapter,
        resolveEcdsaMaterialActivation: input.resolveEcdsaMaterialActivation,
        phase: input.phase,
      });
    return failure
      ? { ok: false, result: failure }
      : { ok: true, kind: 'operation_step_up' };
  }

  const validated = await validateRouterAbEcdsaDerivationWalletSessionInputs({
    body: input.rawBody,
    headers: input.headers,
    session: input.session,
  });
  if (!validated.ok) {
    return {
      ok: false,
      result: {
        status: routerAbWalletSessionValidationStatus(validated.code),
        body: validated,
      },
    };
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
    return {
      ok: false,
      result: { status: admission.error.status, body: admission.error.body },
    };
  }

  const activeMaterial = await input.resolveEcdsaMaterialActivation({
    walletId: validated.walletSessionAuth.userId,
    materialActivation: admission.materialActivation,
  });
  if (!activeMaterial.ok) {
    return {
      ok: false,
      result: routerAbStepUpError(
        activeMaterial.code === 'internal' ? 500 : 403,
        activeMaterial.code === 'internal' ? 'internal' : 'wallet_session_scope_mismatch',
        activeMaterial.code === 'internal'
          ? activeMaterial.message
          : 'Reusable Wallet Session material is no longer active',
      ),
    };
  }
  if (
    activeMaterial.keyHandle !== validated.walletSessionAuth.keyHandle ||
    !sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      admission.materialActivation,
    )
  ) {
    return {
      ok: false,
      result: routerAbStepUpError(
        403,
        'wallet_session_scope_mismatch',
        'Reusable Wallet Session material does not match the active material',
      ),
    };
  }

  const canonicalAdmission: AcceptedEcdsaRouteAdmission = {
    ...admission,
    materialActivation: activeMaterial.materialActivation,
  };

  const admissionDecision = await evaluateRouterAbNormalSigningAdmission({
    adapter: input.admissionAdapter,
    curve: 'ecdsa',
    phase: input.phase,
    claims: validated.claims,
    walletSessionAuth: validated.walletSessionAuth,
    admission: canonicalAdmission,
  });
  if (!admissionDecision.ok) {
    return {
      ok: false,
      result: {
        status: admissionDecision.status,
        body: {
          ok: false,
          code: admissionDecision.code,
          message: admissionDecision.message,
        },
      },
    };
  }

  return {
    ok: true,
    kind: 'reusable_wallet_session',
    validated,
    admission: canonicalAdmission,
  };
}

export async function handleRouterAbEcdsaDerivationNormalSigningRouteCore(input: {
  body: Record<string, unknown>;
  rawBody: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
  runtime: RouterAbNormalSigningRouteRuntime | null | undefined;
  authorizationClaims: RouterApiAuthorizationClaimService | null | undefined;
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
  privatePath: RouterAbEcdsaDerivationPrivateSigningPath;
  phase: 'prepare' | 'finalize';
}): Promise<RouterAbJsonRouteResult> {
  const authorization = await authorizeRouterAbEcdsaDerivationNormalSigningRoute(input);
  if (!authorization.ok) return authorization.result;
  if (authorization.kind === 'operation_step_up') {
    return routerAbStepUpError(500, 'internal', 'Operation step-up must execute through the MPC router');
  }
  const { validated, admission } = authorization;

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
    authorization: {
      kind: 'reusable_wallet_session',
      claims: validated.claims,
    },
    headers: input.headers,
  });
  let prepareClaim: Parameters<typeof completeRouterAbEcdsaOperation>[0]['claim'] | null = null;
  if (input.phase === 'prepare') {
    if (!input.authorizationClaims || !input.authorizationSessions) {
      return routerAbStepUpError(
        501,
        'not_configured',
        'Reusable Wallet Session authorization is not configured',
      );
    }
    const request = parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body);
    const claimed = await admitRouterAbEcdsaReusableWalletSessionOperation({
      request,
      materialActivation: admission.materialActivation,
      claims: validated.claims,
      authorizationClaims: input.authorizationClaims,
      authorizationSessions: input.authorizationSessions,
      resolveEcdsaMaterialActivation: input.resolveEcdsaMaterialActivation,
    });
    if (!claimed.ok) return claimed.error;
    prepareClaim = claimed.claim;
    const replay = await runtime.reservePrepareReplay({
      curve: 'ecdsa',
      authorizationIdentity: {
        kind: 'reusable_wallet_session',
        walletSessionId: validated.walletSessionAuth.walletSessionId,
      },
      requestId: admission.requestId,
      expiresAtMs: admission.expiresAtMs,
    });
    if (!replay.ok) {
      await completeRouterAbEcdsaOperation({
        authorizationClaims: input.authorizationClaims,
        claim: prepareClaim,
        requestId: request.request_id,
        result: 'failed_before_side_effect',
        response: { code: replay.code, message: replay.message },
      });
      return {
        status: replay.status,
        body: { ok: false, code: replay.code, message: replay.message },
      };
    }
  }

  const forwarded = await postRouterAbSigningWorkerJson({
    config: signingWorker,
    path: input.privatePath,
    body: privateBody,
  });
  if (prepareClaim && input.authorizationClaims) {
    await completeRouterAbEcdsaOperation({
      authorizationClaims: input.authorizationClaims,
      claim: prepareClaim,
      requestId: admission.requestId,
      result: forwarded.ok
        ? 'succeeded'
        : forwarded.status < 500
          ? 'failed_before_side_effect'
          : 'failed_after_side_effect',
      response: forwarded.body,
    });
  }
  return forwarded.ok
    ? { status: 200, body: forwarded.body }
    : { status: forwarded.status, body: forwarded.body };
}

export async function postRouterAbSigningWorkerJson(input: {
  config: RouterAbConfiguredSigningWorkerPrivateTransport;
  path: RouterAbEd25519PrivateSigningPath | RouterAbEcdsaDerivationPrivateSigningPath;
  body: unknown;
}): Promise<RouterAbSigningWorkerJsonResult> {
  const fetchImpl = resolveRouterAbSigningWorkerFetch(input.config.fetchImpl);
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

function walletBudgetGrantString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function walletBudgetGrantPositiveInteger(value: unknown): number | null {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function walletBudgetGrantNonNegativeInteger(value: unknown): number | null {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
}

function walletBudgetGrantResponseRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseRouterAbWalletBudgetGrantProvisionResponseV1(
  value: unknown,
): RouterAbWalletBudgetGrantProvisionResultV1 {
  const record = walletBudgetGrantResponseRecord(value);
  const signingGrantId = walletBudgetGrantString(record?.signing_grant_id);
  const remainingUses = walletBudgetGrantNonNegativeInteger(record?.committed_remaining_uses);
  const reservedUses = walletBudgetGrantNonNegativeInteger(record?.reserved_uses);
  const availableUses = walletBudgetGrantNonNegativeInteger(record?.available_uses);
  const expiresAtMs = walletBudgetGrantPositiveInteger(record?.expires_at_ms);
  if (
    !signingGrantId ||
    remainingUses === null ||
    reservedUses === null ||
    availableUses === null ||
    expiresAtMs === null ||
    availableUses !== Math.max(0, remainingUses - reservedUses)
  ) {
    return {
      ok: false,
      code: 'invalid_router_response',
      message: 'Router returned an invalid SigningWorker wallet-budget projection',
    };
  }
  return {
    ok: true,
    signingGrantId,
    remainingUses,
    reservedUses,
    availableUses,
    expiresAtMs,
  };
}

function routerAbWalletBudgetGrantUrl(config: RouterAbWalletBudgetGrantTransportV1): string {
  const base = config.routerBaseUrl.trim().replace(/\/+$/, '');
  if (!base) throw new Error('Router wallet-budget transport requires routerBaseUrl');
  return `${base}${PRIVATE_ROUTER_WALLET_BUDGET_PUT_GRANT_PATH}`;
}

class RouterAbPrivateD1WalletBudgetGrantProvisionerV1 implements RouterAbWalletBudgetGrantProvisionerV1 {
  constructor(private readonly config: RouterAbWalletBudgetGrantTransportV1) {}

  async provisionGrant(
    input: RouterAbWalletBudgetGrantProvisionInputV1,
  ): Promise<RouterAbWalletBudgetGrantProvisionResultV1> {
    const fetchImpl = resolveRouterAbSigningWorkerFetch(this.config.fetchImpl);
    if (!fetchImpl) {
      return { ok: false, code: 'internal', message: 'fetch is not available in this runtime' };
    }
    const response = await postRouterAbInternalServiceJson({
      url: routerAbWalletBudgetGrantUrl(this.config),
      body: {
        signing_grant_id: input.signingGrantId,
        wallet_id: input.walletId,
        rp_id: input.relyingPartyId,
        authorized_signers: input.authorizedSigners,
        initial_signature_uses: input.initialSignatureUses,
        expires_at_ms: input.expiresAtMs,
        issuer_jwt_id: input.issuerIdempotencyKey,
        now_unix_ms: Date.now(),
      },
      authSecret: this.config.internalServiceAuthSecret,
      fetchImpl,
    });
    if (!response.ok) {
      return {
        ok: false,
        code: response.code,
        message:
          response.code === 'http_error'
            ? response.bodyText || `Router wallet-budget grant returned HTTP ${response.status}`
            : response.message,
      };
    }
    const parsed = parseRouterAbWalletBudgetGrantProvisionResponseV1(response.json);
    if (!parsed.ok) return parsed;
    if (
      parsed.signingGrantId !== input.signingGrantId ||
      parsed.expiresAtMs > input.expiresAtMs
    ) {
      return {
        ok: false,
        code: 'invalid_router_response',
        message: 'Router wallet-budget projection does not match the requested grant',
      };
    }
    return parsed;
  }
}

export function createRouterAbPrivateD1WalletBudgetGrantProvisionerV1(
  config: RouterAbWalletBudgetGrantTransportV1,
): RouterAbWalletBudgetGrantProvisionerV1 {
  return new RouterAbPrivateD1WalletBudgetGrantProvisionerV1(config);
}
