import type {
  RouterAbNormalSigningAuthorizationIdentity,
  RouterAbSigningWorkerPrivateTransport,
} from '../../../core/routerAbSigning/RouterAbNormalSigningRuntime';
import type { RouterAbNormalSigningRuntime } from '../../../core/routerAbSigning/RouterAbNormalSigningRuntime';
import type { ThresholdEd25519AuthorityScope } from '../../../core/types';
import { postRouterAbInternalServiceJson } from '../../../core/ThresholdService/routerAb/internalServiceHttp';
import {
  resolveWalletSessionOperationCredentialAdmission,
  validateRouterAbEcdsaDerivationWalletSessionInputs,
  validateRouterAbEd25519WalletSessionInputs,
  type ThresholdEd25519SessionInputs,
  type ThresholdEcdsaSessionInputs,
} from '../../auth/commonRouterUtils';
import type { SessionAdapter } from '../../framework/routerApi';
import { extractBearerCredential } from '../../auth/routerApiKeyAuth';
import {
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  routerAbEcdsaDerivationActiveStateId,
  routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1,
  routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1,
  sameRouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaOperationStepUpPreparationV1Wire,
  type RouterAbOwnerOperationAuthorizationDecisionV1Wire,
  type RouterAbPublicDigest32V1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  WALLET_SESSION_FAILURE_CODES,
  type WalletSessionFailureCode,
} from '@shared/utils/walletSessionFailure';
import { walletSessionFailure, walletSessionFailureStatus } from '../../auth/walletSessionFailure';
import type {
  RouterApiAuthorizedOperationService,
  RouterApiAuthorizationSessionService,
  RouterApiWalletRegistrationService,
  RouterApiWalletSessionAuthorizationV2AdmissionContext,
  RouterApiWalletSessionAuthorizationV2ExhaustedCandidateContext,
} from '../../framework/authServicePort';
import { resolveWalletSessionAuthorizationV2Admission } from './walletExecutionAdmission';
import type { WalletExecutionLaneAuthSource } from '../../../core/signingLanes/WalletExecutionLaneProjection';
import type { SigningWorkerLaneMaterialIdentityV1 } from '../../../core/signingLanes/signingWorkerLaneMaterialIdentity';
import {
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  buildEvmEcdsaMpcOperationRef,
  buildNearEd25519MpcOperationRef,
  buildAuthorizationGrantRef,
  parseAuthorizationAuditEventId,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parsePrincipalId,
  type AuthorizationParseResult,
  type AuthorizedOperationId,
  type CapabilityId,
  type CapabilityOperationId,
  type CapabilityOperationRef,
  type PrincipalId,
  type TenantId,
} from '@shared/authorization/capabilityKinds';
import {
  buildCapabilityOperationEnvelope,
  computeCapabilityOperationFingerprintDigest,
  parseSigningOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import {
  authorizedOperationReplayBodyInit,
  parseSessionOrigin,
  type AuthorizedOperation,
  type AuthorizedOperationReplayResponse,
  type OwnerOperationAuthorizationDecision,
  type OwnerOperationStepUpReason,
} from '../../../authorization/domain';
import {
  routerAbMpcMaterialActivationRefFromWire,
  routerAbMpcMaterialActivationRefToWire,
  sameRouterAbMpcMaterialActivationRef,
  type RouterAbNormalSigningAuthorizationWire,
  type RouterAbMpcMaterialActivationRefWire,
  type RouterAbEd25519OperationStepUpPreparationV1Wire,
  type RouterAbEd25519OwnerOperationAuthorizationDecisionV1Wire,
} from '@shared/utils/routerAbNormalSigningIdentity';
import {
  parseEd25519ReusableAuthorizedOperationReceipt,
  type Ed25519OperationKind,
  type Ed25519ReusableAuthorizedOperationReceipt,
} from './ed25519AuthorizedOperationReceipt';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationId,
  parseProviderSubject,
  parseWalletId,
  type WalletAuthMethodId,
  type MpcMaterialActivationId,
} from '@shared/utils/domainIds';

const ED25519_SIGNING_INTENT_VERSION_V2 = 'router-ab-protocol/ed25519-normal-signing/intent/v2';
const ED25519_SIGNING_PAYLOAD_VERSION_V2 = 'router-ab-protocol/ed25519-normal-signing/payload/v2';
const ED25519_ROUND1_BINDING_VERSION_V2 =
  'router-ab-protocol/ed25519-normal-signing/round1-binding/v2';
const ED25519_TRUSTED_SOURCE_VERSION_V2 = 'router-ab-cloudflare-trusted-source/v2';

export function routerAbEcdsaAtomicAuthorizationConfigured(
  authorizedOperations: Pick<RouterApiAuthorizedOperationService, 'admitAuthorizedOperation'>,
): boolean {
  const runtime = authorizedOperations as unknown as Record<string, unknown>;
  return typeof runtime.admitAuthorizedOperation === 'function';
}

type RouterAbAcceptedAuthorizedOperationBindingV1 =
  | {
      readonly kind: 'reusable_wallet_session';
      readonly walletSessionId: string;
      readonly quotaId: string;
    }
  | {
      readonly kind: 'gateway_owner_wallet_session';
      readonly subjectId: string;
      readonly accountId: string;
      readonly authorizationId: string;
      readonly walletSessionId: string;
      readonly quotaId: string;
      readonly thresholdSessionId: string;
      readonly orgId: string;
      readonly projectId: string;
      readonly environment: string;
      readonly signingWorkerId: string;
      readonly expiresAtMs: number;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly authorizationSessionId: string;
      readonly orgId: string;
      readonly projectId: string;
      readonly environment: string;
      readonly subjectId: string;
    };

export function buildRouterAbEd25519AcceptedAuthorizedOperationV1(input: {
  readonly operation: AuthorizedOperation;
  readonly binding: RouterAbAcceptedAuthorizedOperationBindingV1;
}) {
  const operation = input.operation;
  const operationRef = operation.operation.operation;
  if (operationRef.capabilityKind !== 'near_ed25519_mpc_signing') {
    throw new Error('Ed25519 authorized operation capability is invalid');
  }
  if (operationRef.operationKind === 'near.export_key') {
    throw new Error('Ed25519 export cannot use normal-signing admission');
  }
  return buildRouterAbAcceptedAuthorizedOperationV1({
    operation,
    operationKind: operationRef.operationKind,
    capabilityKind: 'near_ed25519_mpc_signing',
    binding: input.binding,
  });
}

export function buildRouterAbEcdsaAcceptedAuthorizedOperationV1(input: {
  readonly operation: AuthorizedOperation;
  readonly binding: RouterAbAcceptedAuthorizedOperationBindingV1;
}) {
  const operation = input.operation;
  const operationRef = operation.operation.operation;
  if (
    operationRef.capabilityKind !== 'evm_ecdsa_mpc_signing' ||
    operationRef.operationKind !== 'evm.sign_transaction'
  ) {
    throw new Error('ECDSA authorized operation capability or operation kind is invalid');
  }
  return buildRouterAbAcceptedAuthorizedOperationV1({
    operation,
    operationKind: 'evm.sign_transaction',
    capabilityKind: 'evm_ecdsa_mpc_signing',
    binding: input.binding,
  });
}

function buildRouterAbAcceptedAuthorizedOperationV1(input: {
  readonly operation: AuthorizedOperation;
  readonly capabilityKind: 'near_ed25519_mpc_signing' | 'evm_ecdsa_mpc_signing';
  readonly operationKind:
    | 'near.sign_transaction'
    | 'near.sign_delegate_action'
    | 'near.sign_nep413_message'
    | 'evm.sign_transaction';
  readonly binding: RouterAbAcceptedAuthorizedOperationBindingV1;
}) {
  const operation = input.operation;
  const commonAuthorizedOperation = {
    authorized_operation_id: operation.authorizedOperationId,
    operation_id: operation.operation.operationId,
    capability_kind: input.capabilityKind,
    operation_kind: input.operationKind,
    lane_digest_b64u: operation.operation.digests.laneDigest,
    intent_digest_b64u: operation.operation.digests.intentDigest,
    display_digest_b64u: operation.operation.digests.displayDigest,
    operation_fingerprint_digest: operation.operationFingerprintDigest,
  };
  switch (input.binding.kind) {
    case 'reusable_wallet_session':
      if (
        operation.authorization.kind !== 'authorization_grant' ||
        operation.quota.kind !== 'consume_reusable_wallet_session'
      ) {
        throw new Error('Reusable Wallet Session authorized operation is invalid');
      }
      return {
        binding: {
          kind: 'reusable_wallet_session' as const,
          authorization_id: operation.authorization.authorizationGrantRef.authorizationId,
          wallet_session_id: input.binding.walletSessionId,
          quota_id: input.binding.quotaId,
        },
        authorized_operation: {
          kind: 'reusable_wallet_session_authorized_operation_v1' as const,
          ...commonAuthorizedOperation,
        },
      };
    case 'gateway_owner_wallet_session':
      if (
        operation.authorization.kind !== 'authorization_grant' ||
        operation.quota.kind !== 'consume_reusable_wallet_session'
      ) {
        throw new Error('Gateway owner Wallet Session authorized operation is invalid');
      }
      return {
        binding: {
          kind: 'gateway_owner_wallet_session' as const,
          subject_id: input.binding.subjectId,
          account_id: input.binding.accountId,
          authorization_id: input.binding.authorizationId,
          wallet_session_id: input.binding.walletSessionId,
          quota_id: input.binding.quotaId,
          threshold_session_id: input.binding.thresholdSessionId,
          org_id: input.binding.orgId,
          project_id: input.binding.projectId,
          environment: input.binding.environment,
          signing_worker_id: input.binding.signingWorkerId,
          expires_at_ms: input.binding.expiresAtMs,
        },
        authorized_operation: {
          kind: 'reusable_wallet_session_authorized_operation_v1' as const,
          ...commonAuthorizedOperation,
        },
      };
    case 'operation_step_up':
      if (
        operation.authorization.kind !== 'verified_step_up' ||
        operation.quota.kind !== 'quota_neutral'
      ) {
        throw new Error('Verified step-up authorized operation is invalid');
      }
      return {
        binding: {
          kind: 'operation_step_up' as const,
          authorization_session_id: input.binding.authorizationSessionId,
          org_id: input.binding.orgId,
          project_id: input.binding.projectId,
          environment: input.binding.environment,
          subject_id: input.binding.subjectId,
        },
        authorized_operation: {
          kind: 'verified_step_up_authorized_operation_v1' as const,
          authorization_session_id: input.binding.authorizationSessionId,
          evidence_set_digest: operation.authorization.evidenceSetDigest,
          ...commonAuthorizedOperation,
        },
      };
  }
}

const PRIVATE_ED25519_SIGNING_PREPARE_PATH = '/router-ab/signing-worker/sign/prepare';
const PRIVATE_ED25519_SIGNING_FINALIZE_PATH = '/router-ab/signing-worker/sign';
const PRIVATE_ECDSA_DERIVATION_SIGNING_PREPARE_PATH =
  '/router-ab/signing-worker/ecdsa-derivation/sign/prepare';
const PRIVATE_ECDSA_DERIVATION_SIGNING_FINALIZE_PATH =
  '/router-ab/signing-worker/ecdsa-derivation/sign';
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
  | {
      ok: true;
      body: unknown;
      replay: AuthorizedOperationReplayResponse;
    }
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

export type RouterAbEcdsaOperationAdmissionKind = 'claimed' | 'operation_in_progress' | 'replayed';

export type RouterAbEcdsaOperationAdmission = {
  readonly kind: RouterAbEcdsaOperationAdmissionKind;
  readonly operation: AuthorizedOperation;
};

export function routerAbEcdsaOperationInProgressResult(): RouterAbJsonRouteResult {
  return routerAbStepUpError(
    409,
    'operation_in_progress',
    'ECDSA signing operation is already in progress',
  );
}

export function buildRouterAbEcdsaOwnerOperationStepUpPreparation(input: {
  readonly request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire;
  readonly keyHandle: string;
  readonly relayerKeyId: string;
  readonly participantIds: readonly number[];
}): RouterAbEcdsaOperationStepUpPreparationV1Wire | null {
  const [firstParticipantId, secondParticipantId] = input.participantIds;
  if (
    !input.keyHandle ||
    !input.relayerKeyId ||
    firstParticipantId === undefined ||
    secondParticipantId === undefined ||
    input.participantIds.length !== 2
  ) {
    return null;
  }
  return {
    wallet_id: input.request.scope.wallet_id,
    operation_kind: 'evm.sign_transaction',
    operation_id: input.request.operation_id,
    operation_digests: input.request.operation_digests,
    material_activation: input.request.material_activation,
    normal_signing_scope: input.request.scope,
    signing_worker_id: input.request.scope.signing_worker.server_id,
    key_handle: input.keyHandle,
    relayer_key_id: input.relayerKeyId,
    participant_ids: [firstParticipantId, secondParticipantId],
    expires_at_ms: input.request.expires_at_ms,
  };
}

async function resolveRouterAbEcdsaOwnerOperationStepUpPreparation(input: {
  readonly body: Record<string, unknown>;
  readonly phase: 'prepare' | 'finalize';
  readonly resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
}): Promise<RouterAbEcdsaOperationStepUpPreparationV1Wire | undefined> {
  if (input.phase !== 'prepare') return undefined;
  try {
    const request = parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body);
    const walletId = parseWalletId(request.scope.wallet_id);
    if (!walletId.ok) return undefined;
    const activeMaterial = await input.resolveEcdsaMaterialActivation({
      walletId: walletId.value,
      materialActivation: request.material_activation,
    });
    if (!activeMaterial.ok) return undefined;
    return (
      buildRouterAbEcdsaOwnerOperationStepUpPreparation({
        request,
        keyHandle: activeMaterial.keyHandle,
        relayerKeyId: activeMaterial.relayerKeyId,
        participantIds: activeMaterial.participantIds,
      }) ?? undefined
    );
  } catch {
    return undefined;
  }
}

export function decideRouterAbEcdsaOwnerOperationAuthorization(input: {
  readonly operation: AuthorizedOperation;
}): OwnerOperationAuthorizationDecision<RouterAbEcdsaOperationStepUpPreparationV1Wire> {
  if (
    input.operation.lifecycle !== 'claimed' ||
    input.operation.authorization.kind !== 'authorization_grant' ||
    input.operation.quota.kind !== 'consume_reusable_wallet_session' ||
    input.operation.authorization.authorizationGrantRef.kind !== 'wallet_session_authorization'
  ) {
    return {
      kind: 'denied',
      denial: {
        code: 'invalid_authority',
        message: 'ECDSA reusable Wallet Session authorization is invalid',
      },
    };
  }
  return {
    kind: 'authorized',
    operation: input.operation,
    source: {
      kind: 'authorization_grant',
      authorizationGrantRef: input.operation.authorization.authorizationGrantRef,
    },
  };
}

export function buildRouterAbEd25519OwnerOperationStepUpPreparation(input: {
  readonly scope: RouterAbEd25519NormalSigningScopeV2;
  readonly body: Record<string, unknown>;
  readonly material: {
    readonly nearAccountId: string;
    readonly signerSlot: number;
    readonly signingWorkerId: string;
    readonly participantIds: readonly [number, number];
  };
}): RouterAbEd25519OperationStepUpPreparationV1Wire | null {
  const operation = parseRouterAbOperationStepUpOperation(input.body.intent);
  const expiresAtMs = Number(input.body.expires_at_ms);
  if (
    !operation.ok ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= 0 ||
    input.scope.account_id !== input.scope.material_activation.material_owner ||
    input.material.signingWorkerId !== input.scope.signing_worker_id ||
    input.material.participantIds.length !== 2
  ) {
    return null;
  }
  return {
    wallet_id: input.scope.account_id,
    operation_kind: operation.operation.operationKind,
    operation_id: operation.operationId,
    request_id: input.scope.request_id,
    account_id: input.scope.account_id,
    material_activation: input.scope.material_activation,
    signing_worker_id: input.scope.signing_worker_id,
    near_account_id: input.material.nearAccountId,
    signer_slot: input.material.signerSlot,
    participant_ids: input.material.participantIds,
    expires_at_ms: expiresAtMs,
  };
}

async function resolveRouterAbEd25519OwnerOperationStepUpPreparation(input: {
  readonly scope: RouterAbEd25519NormalSigningScopeV2;
  readonly body: Record<string, unknown>;
  readonly phase: RouterAbEd25519NormalSigningRoutePhase;
  readonly resolveEd25519MaterialActivation: RouterApiWalletRegistrationService['resolveEd25519MaterialActivation'];
}): Promise<RouterAbEd25519OperationStepUpPreparationV1Wire | undefined> {
  if (input.phase !== 'prepare') return undefined;
  try {
    const activeMaterial = await input.resolveEd25519MaterialActivation({
      walletId: input.scope.account_id,
      materialActivation: input.scope.material_activation,
    });
    if (!activeMaterial.ok) return undefined;
    return (
      buildRouterAbEd25519OwnerOperationStepUpPreparation({
        scope: input.scope,
        body: input.body,
        material: activeMaterial,
      }) ?? undefined
    );
  } catch {
    return undefined;
  }
}

export function decideRouterAbEd25519OwnerOperationAuthorization(input: {
  readonly operation: AuthorizedOperation;
}): OwnerOperationAuthorizationDecision<RouterAbEd25519OperationStepUpPreparationV1Wire> {
  if (
    input.operation.lifecycle !== 'claimed' ||
    input.operation.authorization.kind !== 'authorization_grant' ||
    input.operation.authorization.authorizationGrantRef.kind !== 'wallet_session_authorization' ||
    input.operation.quota.kind !== 'consume_reusable_wallet_session'
  ) {
    return {
      kind: 'denied',
      denial: {
        code: 'invalid_authority',
        message: 'Ed25519 reusable Wallet Session authorization is invalid',
      },
    };
  }
  return {
    kind: 'authorized',
    operation: input.operation,
    source: {
      kind: 'authorization_grant',
      authorizationGrantRef: input.operation.authorization.authorizationGrantRef,
    },
  };
}

function routerAbEd25519OwnerOperationDecisionForFailure(input: {
  readonly code: string;
  readonly phase: RouterAbEd25519NormalSigningRoutePhase;
  readonly stepUp?: RouterAbEd25519OperationStepUpPreparationV1Wire;
}): RouterAbEd25519OwnerOperationAuthorizationDecisionV1Wire | null {
  const reason: OwnerOperationStepUpReason | null = (() => {
    switch (input.code) {
      case 'wallet_session_missing':
        return 'wallet_session_missing';
      case 'wallet_session_expired':
        return 'wallet_session_expired';
      case 'wallet_budget_exhausted':
      case 'wallet_session_quota_exhausted':
        return 'wallet_session_exhausted';
      case 'wallet_session_invalid':
        return 'wallet_session_ended';
      default:
        return null;
    }
  })();
  if (reason && input.phase === 'prepare' && input.stepUp) {
    return { kind: 'step_up_required', reason, step_up: input.stepUp };
  }
  if (reason && input.phase === 'prepare') {
    return {
      kind: 'denied',
      denial: {
        code: 'authorization_unavailable',
        message: 'Owner operation step-up preparation is unavailable',
      },
    };
  }
  switch (input.code) {
    case 'invalid_body':
      return {
        kind: 'denied',
        denial: { code: 'invalid_operation', message: 'Ed25519 operation request is invalid' },
      };
    case 'wallet_session_mismatch':
    case 'wallet_session_scope_mismatch':
    case 'scope_mismatch':
    case 'authorization_grant_rejected':
    case 'verified_step_up_rejected':
      return {
        kind: 'denied',
        denial: { code: 'invalid_authority', message: 'Ed25519 operation authority is invalid' },
      };
    case 'material_mismatch':
      return {
        kind: 'denied',
        denial: { code: 'inactive_material', message: 'Ed25519 signing material is inactive' },
      };
    case 'internal':
    case 'not_configured':
      return {
        kind: 'denied',
        denial: {
          code: 'authorization_unavailable',
          message: 'Ed25519 operation authorization is unavailable',
        },
      };
    default:
      return null;
  }
}

export function routerAbEd25519OwnerOperationFailureResult(input: {
  readonly status: number;
  readonly code: string;
  readonly message: string;
  readonly phase: RouterAbEd25519NormalSigningRoutePhase;
  readonly stepUp?: RouterAbEd25519OperationStepUpPreparationV1Wire;
}): RouterAbJsonRouteResult {
  const decision = routerAbEd25519OwnerOperationDecisionForFailure(input);
  return {
    status: input.status,
    body: {
      ok: false,
      code: input.code,
      message: input.message,
      ...(decision ? { authorization_decision: decision } : {}),
    },
  };
}

function routerAbEcdsaOwnerOperationDecisionForFailure(input: {
  readonly code: string;
  readonly phase: 'prepare' | 'finalize';
  readonly stepUp?: RouterAbEcdsaOperationStepUpPreparationV1Wire;
}): RouterAbOwnerOperationAuthorizationDecisionV1Wire | null {
  const reason: OwnerOperationStepUpReason | null = (() => {
    switch (input.code) {
      case 'wallet_session_missing':
        return 'wallet_session_missing';
      case 'wallet_session_expired':
        return 'wallet_session_expired';
      case 'wallet_budget_exhausted':
      case 'wallet_session_quota_exhausted':
        return 'wallet_session_exhausted';
      case 'wallet_session_invalid':
        return 'wallet_session_ended';
      default:
        return null;
    }
  })();
  if (reason && input.phase === 'prepare' && input.stepUp) {
    const decision: OwnerOperationAuthorizationDecision<RouterAbEcdsaOperationStepUpPreparationV1Wire> =
      {
        kind: 'step_up_required',
        reason,
        stepUp: input.stepUp,
      };
    return {
      kind: decision.kind,
      reason: decision.reason,
      step_up: decision.stepUp,
    };
  }
  if (reason && input.phase === 'prepare') {
    return {
      kind: 'denied',
      denial: {
        code: 'authorization_unavailable',
        message: 'Owner operation step-up preparation is unavailable',
      },
    };
  }
  switch (input.code) {
    case 'invalid_body':
      return {
        kind: 'denied',
        denial: { code: 'invalid_operation', message: 'ECDSA operation request is invalid' },
      };
    case 'wallet_session_mismatch':
    case 'wallet_session_scope_mismatch':
    case 'scope_mismatch':
    case 'authorization_grant_rejected':
    case 'verified_step_up_rejected':
      return {
        kind: 'denied',
        denial: { code: 'invalid_authority', message: 'ECDSA operation authority is invalid' },
      };
    case 'material_mismatch':
      return {
        kind: 'denied',
        denial: { code: 'inactive_material', message: 'ECDSA signing material is inactive' },
      };
    case 'internal':
    case 'not_configured':
      return {
        kind: 'denied',
        denial: {
          code: 'authorization_unavailable',
          message: 'ECDSA operation authorization is unavailable',
        },
      };
    default:
      return null;
  }
}

export function routerAbEcdsaOwnerOperationFailureResult(input: {
  readonly status: number;
  readonly code: string;
  readonly message: string;
  readonly phase: 'prepare' | 'finalize';
  readonly stepUp?: RouterAbEcdsaOperationStepUpPreparationV1Wire;
}): RouterAbJsonRouteResult {
  const decision = routerAbEcdsaOwnerOperationDecisionForFailure(input);
  return {
    status: input.status,
    body: {
      ok: false,
      code: input.code,
      message: input.message,
      ...(decision ? { authorization_decision: decision } : {}),
    },
  };
}

export function routerAbEcdsaReplayUnavailableResult(): RouterAbJsonRouteResult {
  return routerAbStepUpError(
    409,
    'authorized_operation_replay_unavailable',
    'Completed ECDSA signing operation has no replayable response',
  );
}

export function routerAbEcdsaRecordedResponse(
  operation: AuthorizedOperation,
): AuthorizedOperationReplayResponse | null {
  return operation.lifecycle === 'completed' ? operation.response : null;
}

export function routerAbEcdsaReplayResult(operation: AuthorizedOperation): RouterAbJsonRouteResult {
  const response = routerAbEcdsaRecordedResponse(operation);
  if (!response) return routerAbEcdsaReplayUnavailableResult();
  let body: unknown = response.bodyText;
  try {
    body = JSON.parse(response.bodyText);
  } catch {
    // Keep a non-JSON worker response as text for the JSON route adapter.
  }
  return { status: response.status, body };
}

export function routerAbEcdsaReplayHttpResponse(operation: AuthorizedOperation): Response | null {
  const response = routerAbEcdsaRecordedResponse(operation);
  if (!response) return null;
  return new Response(authorizedOperationReplayBodyInit(response), {
    status: response.status,
    headers: { 'content-type': response.contentType },
  });
}

function routerAbEcdsaPrivateSigningWorkerUnavailableResult(): RouterAbJsonRouteResult {
  return {
    status: 501,
    body: {
      ok: false,
      code: 'not_configured',
      message: 'Router A/B SigningWorker private HTTP target is not configured',
    },
  };
}

type RouterAbConfiguredSigningWorkerPrivateTransport = Extract<
  RouterAbSigningWorkerPrivateTransport,
  { readonly kind: 'configured' }
>;

export type RouterAbNormalSigningRouteRuntime = Pick<
  RouterAbNormalSigningRuntime,
  'getSigningWorkerPrivateTransport' | 'reservePrepareReplay'
>;

type AcceptedRouteAdmission = {
  ok: true;
  thresholdSessionId: string;
  requestId: string;
  expiresAtMs: number;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
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

type RouterAbEd25519WalletSessionValidationSuccess = Extract<
  ThresholdEd25519SessionInputs,
  { readonly ok: true }
>;

type RouterAbEd25519V2WalletSessionValidationSuccess = Extract<
  RouterAbEd25519WalletSessionValidationSuccess,
  { readonly kind: 'wallet_session_operation_credential_v1' }
>;

type ActiveEd25519MaterialActivation = Extract<
  Awaited<ReturnType<RouterApiWalletRegistrationService['resolveEd25519MaterialActivation']>>,
  { readonly ok: true }
>;

type RouterAbEcdsaWalletSessionValidationSuccess = Extract<
  ThresholdEcdsaSessionInputs,
  { readonly ok: true }
>;

type RouterAbEcdsaV2WalletSessionValidationSuccess = Extract<
  RouterAbEcdsaWalletSessionValidationSuccess,
  { readonly kind: 'wallet_session_operation_credential_v1' }
>;

type ActiveEcdsaMaterialActivation = Extract<
  Awaited<ReturnType<RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation']>>,
  { readonly ok: true }
>;

export type RouterAbEd25519NormalSigningAuthorizationResult =
  | {
      readonly ok: true;
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly validated: RouterAbEd25519V2WalletSessionValidationSuccess;
      readonly admission: Extract<RouterAbNormalSigningRouteAdmission, { readonly ok: true }>;
      readonly activeMaterial: ActiveEd25519MaterialActivation;
    }
  | {
      readonly ok: true;
      readonly kind: 'operation_step_up';
      readonly phase: 'prepare';
      readonly session: RouterAbOperationStepUpWalletSession;
      readonly operation: AuthorizedOperation;
      readonly operationDigests: {
        readonly laneDigest: ReturnType<typeof parseDigestB64u>;
        readonly intentDigest: ReturnType<typeof parseDigestB64u>;
        readonly displayDigest: ReturnType<typeof parseDigestB64u>;
      };
      readonly admissionKind: RouterAbEcdsaOperationAdmissionKind;
    }
  | {
      readonly ok: true;
      readonly kind: 'operation_step_up';
      readonly phase: 'finalize';
      readonly session: RouterAbOperationStepUpWalletSession;
    }
  | { readonly ok: false; readonly result: RouterAbJsonRouteResult };

export type RouterAbEcdsaNormalSigningAuthorizationResult =
  | {
      readonly ok: true;
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly validated: RouterAbEcdsaV2WalletSessionValidationSuccess;
      readonly admission: AcceptedEcdsaRouteAdmission;
      readonly activeMaterial: ActiveEcdsaMaterialActivation;
    }
  | {
      readonly ok: true;
      readonly kind: 'wallet_session_operation_credential_exhausted_candidate_v1';
      readonly candidate: RouterApiWalletSessionAuthorizationV2ExhaustedCandidateContext;
      readonly admission: AcceptedEcdsaRouteAdmission;
      readonly activeMaterial: ActiveEcdsaMaterialActivation;
    }
  | {
      readonly ok: true;
      readonly kind: 'operation_step_up';
      readonly phase: 'prepare' | 'finalize';
      readonly operation: AuthorizedOperation;
      readonly session: RouterAbOperationStepUpWalletSession;
      readonly admissionKind: RouterAbEcdsaOperationAdmissionKind;
    }
  | { readonly ok: false; readonly result: RouterAbJsonRouteResult };

export type RouterAbNormalSigningAdmissionFailureCode =
  | 'project_policy_rejected'
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
      authorityKind: 'wallet_authority_v1';
      authorityId: string;
      authorityScope?: never;
      phase: 'prepare' | 'finalize';
      walletId: string;
      thresholdSessionId: string;
      walletSessionId: string;
      quotaId: string;
      requestId: string;
      expiresAtMs: number;
      signingWorkerId: string;
      runtimePolicyScope: RuntimePolicyScope;
    }
  | {
      curve: 'ed25519';
      authorityKind?: never;
      authorityId?: never;
      phase: 'prepare' | 'finalize';
      walletId: string;
      authorityScope: ThresholdEd25519AuthorityScope;
      thresholdSessionId: string;
      walletSessionId: string;
      quotaId: string;
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
}

export type RouterAbNormalSigningAdmissionEvaluationInput =
  | {
      adapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
      curve: 'ed25519';
      authorizationKind: 'wallet_session_operation_credential_v1';
      phase: 'prepare' | 'finalize';
      walletId: string;
      authorityId: string;
      thresholdSessionId: string;
      walletSessionId: string;
      quotaId: string;
      requestId: string;
      expiresAtMs: number;
      signingWorkerId: string;
      runtimePolicyScope: RuntimePolicyScope;
    }
  | {
      adapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
      curve: 'ecdsa';
      authorizationKind: 'wallet_session_operation_credential_v1';
      phase: 'prepare' | 'finalize';
      walletId: string;
      walletSessionId: string;
      materialActivation: RouterAbMpcMaterialActivationRefWire;
      requestId: string;
      expiresAtMs: number;
      signingWorkerId: string;
      keyHandle: string;
      runtimePolicyScope: RuntimePolicyScope;
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
    return await input.adapter.evaluatePolicy({
      curve: 'ed25519',
      authorityKind: 'wallet_authority_v1',
      authorityId: input.authorityId,
      phase: input.phase,
      walletId: input.walletId,
      thresholdSessionId: input.thresholdSessionId,
      walletSessionId: input.walletSessionId,
      quotaId: input.quotaId,
      requestId: input.requestId,
      expiresAtMs: input.expiresAtMs,
      signingWorkerId: input.signingWorkerId,
      runtimePolicyScope: input.runtimePolicyScope,
    });
  }

  return await input.adapter.evaluatePolicy({
    curve: 'ecdsa',
    phase: input.phase,
    walletId: input.walletId,
    materialActivationId: requireMpcMaterialActivationId(
      input.admission.materialActivation.activation_id,
    ),
    authorizationIdentity: {
      kind: 'reusable_wallet_session',
      walletSessionId: input.walletSessionId,
    },
    requestId: input.admission.requestId,
    expiresAtMs: input.admission.expiresAtMs,
    signingWorkerId: input.signingWorkerId,
    keyHandle: input.keyHandle,
    runtimePolicyScope: input.runtimePolicyScope,
  });
}

type RouterAbEd25519NormalSigningAuthorizationV2 =
  | {
      readonly kind: 'reusable_wallet_session';
      readonly wallet_session_id: string;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly evidence_set_digest?: never;
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

type RouterAbOperationStepUpWalletSessionBase = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly sessionId: string;
  readonly walletId: string;
  readonly runtimePolicyScope: RuntimePolicyScope;
};

type RouterAbExactOperationStepUpWalletSession = RouterAbOperationStepUpWalletSessionBase & {
  readonly laneAuthorization: {
    readonly kind: 'wallet_auth_method';
    readonly walletAuthMethodId: WalletAuthMethodId;
  };
};

type RouterAbVerifiedOwnerOperationStepUpWalletSession =
  RouterAbOperationStepUpWalletSessionBase & {
    readonly laneAuthorization: {
      readonly kind: 'authority_ref';
      readonly authorityRef: WalletAuthAuthorityRef;
      readonly authSource: WalletExecutionLaneAuthSource;
    };
  };

type RouterAbOperationStepUpWalletSession =
  | RouterAbExactOperationStepUpWalletSession
  | RouterAbVerifiedOwnerOperationStepUpWalletSession;

type RouterAbEd25519PrivateSigningAuthorization =
  | {
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly walletSessionId: string;
      readonly principalId: string;
      readonly runtimePolicyScope: RuntimePolicyScope;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly session: RouterAbOperationStepUpWalletSession;
    };

type RouterAbEcdsaPrivateSigningAuthorization =
  | {
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly walletSessionId: string;
      readonly principalId: string;
      readonly runtimePolicyScope: RuntimePolicyScope;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly session: RouterAbOperationStepUpWalletSession;
    };

type RouterAbOwnerAdmissionAuthV1 =
  | {
      readonly auth: 'owner_wallet_session';
      readonly subject_id: string;
      readonly wallet_session_id: string;
      readonly authorization_session_id?: never;
    }
  | {
      readonly auth: 'owner_operation_step_up';
      readonly subject_id: string;
      readonly authorization_session_id: string;
      readonly wallet_session_id?: never;
    };

type RouterAbNormalSigningPrivateAuthorizationV2 =
  | {
      readonly kind: 'reusable_wallet_session';
      readonly wallet_session_id: string;
      readonly authorization_session_id?: never;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly authorization_session_id: string;
      readonly wallet_session_id?: never;
    };

type RouterAbNormalSigningTrustedMetadataV1 = {
  readonly org_id: string;
  readonly project_id: string;
  readonly environment: string;
  readonly account_id: string;
  readonly auth: RouterAbOwnerAdmissionAuthV1;
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
      readonly wallet_session_id: string;
      readonly authorized_operation_id: string;
      readonly operation_id: string;
      readonly operation_fingerprint_digest: string;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly authorization_session_id: string;
      readonly authorized_operation_id: string;
      readonly operation_id: string;
      readonly operation_fingerprint_digest: string;
    };

function validateRouterAbNormalSigningEffectClaim(
  claim: RouterAbNormalSigningEffectClaimV1,
  scope: RouterAbEd25519NormalSigningScopeV2,
  authorization: RouterAbPrivateSigningAuthorizationContext,
): void {
  requirePrivateSigningString(
    claim.authorized_operation_id,
    'effect_claim.authorized_operation_id',
  );
  requirePrivateSigningString(claim.operation_id, 'effect_claim.operation_id');
  requirePrivateSigningString(
    claim.operation_fingerprint_digest,
    'effect_claim.operation_fingerprint_digest',
  );
  if (claim.kind === 'reusable_wallet_session') {
    requirePrivateSigningString(claim.wallet_session_id, 'effect_claim.wallet_session_id');
    if (
      scope.authorization.kind !== 'reusable_wallet_session' ||
      claim.wallet_session_id !== scope.authorization.wallet_session_id
    ) {
      throw new Error('Reusable Wallet Session effect claim does not match request scope');
    }
    return;
  }
  requirePrivateSigningString(
    claim.authorization_session_id,
    'effect_claim.authorization_session_id',
  );
  if (
    scope.authorization.kind !== 'operation_step_up' ||
    authorization.kind !== 'operation_step_up' ||
    claim.authorization_session_id !== authorization.authorizationSessionId
  ) {
    throw new Error('Operation step-up effect claim does not match request scope');
  }
}

type RouterAbEd25519PrivatePrepareSigningWorkerBody = {
  readonly scope: RouterAbEd25519NormalSigningScopeV2;
  readonly expires_at_ms: number;
  readonly admission_candidate: RouterAbNormalSigningPrepareAdmissionCandidateV2;
  readonly trusted_admission: RouterAbNormalSigningTrustedAdmissionV1;
  readonly material_source: RouterAbNormalSigningMaterialSourceV1;
};

type RouterAbEd25519PrivateFinalizeSigningWorkerBody = {
  readonly request: Record<string, unknown>;
  readonly admission_candidate: RouterAbNormalSigningFinalizeAdmissionCandidateV2;
  readonly trusted_admission: RouterAbNormalSigningTrustedAdmissionV1;
  readonly effect_claim: RouterAbNormalSigningEffectClaimV1;
  readonly material_source: RouterAbNormalSigningMaterialSourceV1;
};

export type RouterAbEd25519PrivateSigningWorkerBody =
  | RouterAbEd25519PrivatePrepareSigningWorkerBody
  | RouterAbEd25519PrivateFinalizeSigningWorkerBody;

type RouterAbEcdsaDerivationPrivatePrepareSigningWorkerBody = {
  request: RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire;
  trusted_admission: RouterAbNormalSigningTrustedAdmissionV1;
  material_source: RouterAbNormalSigningMaterialSourceV1;
};

type RouterAbEcdsaDerivationPrivateFinalizeSigningWorkerBody = {
  request: RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire;
  trusted_admission: RouterAbNormalSigningTrustedAdmissionV1;
  material_source: RouterAbNormalSigningMaterialSourceV1;
};

export type RouterAbEcdsaDerivationPrivateSigningWorkerBody =
  | RouterAbEcdsaDerivationPrivatePrepareSigningWorkerBody
  | RouterAbEcdsaDerivationPrivateFinalizeSigningWorkerBody;

export type RouterAbNormalSigningMaterialSourceV1 =
  | {
      readonly kind: 'registration_activation';
      readonly lookup: {
        readonly account_id: string;
        readonly material_activation_id: string;
        readonly signing_worker_id: string;
      };
      readonly group_public_key?: never;
    }
  | {
      readonly kind: 'rotatable_lane';
      readonly lookup: {
        readonly identity: SigningWorkerLaneMaterialIdentityV1;
        readonly admittedLaneIdentityDigestB64u: string;
      };
      readonly group_public_key: string;
    };

function registrationMaterialSourceV1(input: {
  readonly accountId: string;
  readonly materialActivationId: string;
  readonly signingWorkerId: string;
}): RouterAbNormalSigningMaterialSourceV1 {
  return {
    kind: 'registration_activation',
    lookup: {
      account_id: input.accountId,
      material_activation_id: input.materialActivationId,
      signing_worker_id: input.signingWorkerId,
    },
  };
}

export function routerAbNormalSigningMaterialSourceFromActiveLaneV1(input: {
  readonly identity: SigningWorkerLaneMaterialIdentityV1;
  readonly admittedLaneIdentityDigestB64u: string;
  readonly groupPublicKey: string;
}): RouterAbNormalSigningMaterialSourceV1 {
  const groupPublicKey = input.groupPublicKey.trim();
  if (groupPublicKey.length === 0) throw new Error('active lane group public key is required');
  return {
    kind: 'rotatable_lane',
    lookup: {
      identity: input.identity,
      admittedLaneIdentityDigestB64u: input.admittedLaneIdentityDigestB64u,
    },
    group_public_key: groupPublicKey,
  };
}

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

function replayResponseFromSigningWorkerResult(
  result: RouterAbSigningWorkerJsonResult,
): AuthorizedOperationReplayResponse {
  if (result.ok) return result.replay;
  return {
    status: result.status,
    contentType: 'application/json',
    bodyText: JSON.stringify(result.body),
  };
}

function isRouterAbEcdsaSigningWorkerOperationInProgress(
  result: RouterAbSigningWorkerJsonResult,
): boolean {
  return (
    !result.ok &&
    result.status === 409 &&
    result.body.message.includes('ReplayedLocalRequest:') &&
    result.body.message.includes('SigningWorker ECDSA effect is already in progress')
  );
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
      requirePrivateSigningExactFields(authorization, ['kind'], 'scope.authorization');
      return { kind: 'operation_step_up' };
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

export function parseRouterAbEd25519NormalSigningScopeV2(
  value: unknown,
): RouterAbEd25519NormalSigningScopeV2 {
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

export async function computeRouterAbEd25519NormalSigningAdmissionMaterial(input: {
  readonly intent: unknown;
  readonly signingPayload: unknown;
}): Promise<{
  readonly intentDigest: RouterAbPublicDigest32V1Wire;
  readonly signingPayloadDigest: RouterAbPublicDigest32V1Wire;
  readonly admittedSigningDigest: RouterAbPublicDigest32V1Wire;
}> {
  return await privateSigningAdmissionMaterial(input);
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
  readonly authorization: RouterAbPrivateSigningAuthorizationContext;
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
        input.authorization.kind === 'reusable_wallet_session'
          ? {
              auth: 'owner_wallet_session',
              subject_id: input.subjectId,
              wallet_session_id: input.authorization.walletSessionId,
            }
          : {
              auth: 'owner_operation_step_up',
              subject_id: input.subjectId,
              authorization_session_id: input.authorization.authorizationSessionId,
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

type RouterAbPrivateSigningAuthorizationContext =
  | {
      readonly kind: 'reusable_wallet_session';
      readonly runtimePolicyScope: RuntimePolicyScope;
      readonly subjectId: string;
      readonly walletSessionId: string;
    }
  | {
      readonly kind: 'operation_step_up';
      readonly runtimePolicyScope: RuntimePolicyScope;
      readonly subjectId: string;
      readonly authorizationSessionId: string;
    };

function privateSigningAuthorizationContextFromAuthorization(
  authorization:
    | RouterAbEd25519PrivateSigningAuthorization
    | RouterAbEcdsaPrivateSigningAuthorization,
): RouterAbPrivateSigningAuthorizationContext {
  switch (authorization.kind) {
    case 'wallet_session_operation_credential_v1':
      return {
        kind: 'reusable_wallet_session',
        runtimePolicyScope: authorization.runtimePolicyScope,
        subjectId: authorization.principalId,
        walletSessionId: authorization.walletSessionId,
      };
    case 'operation_step_up':
      return {
        kind: 'operation_step_up',
        runtimePolicyScope: authorization.session.runtimePolicyScope,
        subjectId: authorization.session.principalId,
        authorizationSessionId: authorization.session.sessionId,
      };
  }
}

function validatePrivateSigningAuthorizationContext(
  authorization: RouterAbNormalSigningAuthorizationWire,
  context: RouterAbPrivateSigningAuthorizationContext,
): void {
  if (authorization.kind !== context.kind) {
    throw new Error('Router A/B private authorization branch does not match request');
  }
  if (
    authorization.kind === 'reusable_wallet_session' &&
    context.kind === 'reusable_wallet_session' &&
    authorization.wallet_session_id !== context.walletSessionId
  ) {
    throw new Error('Router A/B private Wallet Session does not match request');
  }
}

function privateSigningAuthorizationContext(
  scope: RouterAbEd25519NormalSigningScopeV2,
  authorization: RouterAbEd25519PrivateSigningAuthorization,
): RouterAbPrivateSigningAuthorizationContext {
  const context = privateSigningAuthorizationContextFromAuthorization(authorization);
  if (
    context.kind === 'reusable_wallet_session' &&
    scope.authorization.kind === 'reusable_wallet_session'
  ) {
    if (scope.authorization.wallet_session_id !== context.walletSessionId) {
      throw new Error('Router A/B Ed25519 scope authorization does not match exact session');
    }
    return context;
  }
  if (
    context.kind === 'operation_step_up' &&
    authorization.kind === 'operation_step_up' &&
    scope.authorization.kind === 'operation_step_up'
  ) {
    if (
      scope.account_id !== authorization.session.walletId ||
      scope.material_activation.material_owner !== authorization.session.walletId
    ) {
      throw new Error('Router A/B Ed25519 step-up scope does not match the wallet authorization');
    }
    return context;
  }
  throw new Error('Router A/B Ed25519 authorization branch does not match verified binding');
}

type RouterAbEd25519PrivateSigningWorkerBuildInput =
  | {
      readonly phase: 'prepare';
      readonly body: Record<string, unknown>;
      readonly authorization: RouterAbEd25519PrivateSigningAuthorization;
      readonly headers: Record<string, string | string[] | undefined>;
      readonly materialSource?: RouterAbNormalSigningMaterialSourceV1;
      readonly effectClaim?: never;
    }
  | {
      readonly phase: 'finalize';
      readonly body: Record<string, unknown>;
      readonly authorization: RouterAbEd25519PrivateSigningAuthorization;
      readonly headers: Record<string, string | string[] | undefined>;
      readonly effectClaim: RouterAbNormalSigningEffectClaimV1;
      readonly materialSource?: RouterAbNormalSigningMaterialSourceV1;
    };

export async function buildRouterAbEd25519PrivateSigningWorkerBody(
  input: RouterAbEd25519PrivateSigningWorkerBuildInput,
): Promise<RouterAbEd25519PrivateSigningWorkerBody> {
  const scope = parseRouterAbEd25519NormalSigningScopeV2(input.body.scope);
  const signingContext = privateSigningAuthorizationContext(scope, input.authorization);
  const trustedSourceDigest = await privateSigningTrustedSourceDigest(input.headers);
  if (input.phase === 'finalize') {
    validateRouterAbNormalSigningEffectClaim(input.effectClaim, scope, signingContext);
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
      request: input.body,
      admission_candidate: {
        org_id: signingContext.runtimePolicyScope.orgId,
        project_id: signingContext.runtimePolicyScope.projectId,
        environment: signingContext.runtimePolicyScope.envId,
        account_id: scope.account_id,
        subject_id: signingContext.subjectId,
        authorization:
          signingContext.kind === 'reusable_wallet_session'
            ? {
                kind: 'reusable_wallet_session',
                wallet_session_id: signingContext.walletSessionId,
              }
            : {
                kind: 'operation_step_up',
                authorization_session_id: signingContext.authorizationSessionId,
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
        authorization: signingContext,
        requestId: scope.request_id,
        intentDigest,
        trustedSourceDigest,
      }),
      effect_claim: input.effectClaim,
      material_source:
        input.materialSource ??
        registrationMaterialSourceV1({
          accountId: scope.account_id,
          materialActivationId: scope.material_activation.activation_id,
          signingWorkerId: scope.signing_worker_id,
        }),
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
    authorization: signingContext,
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
        signingContext.kind === 'reusable_wallet_session'
          ? {
              kind: 'reusable_wallet_session',
              wallet_session_id: signingContext.walletSessionId,
            }
          : {
              kind: 'operation_step_up',
              authorization_session_id: signingContext.authorizationSessionId,
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
    material_source:
      input.materialSource ??
      registrationMaterialSourceV1({
        accountId: scope.account_id,
        materialActivationId: scope.material_activation.activation_id,
        signingWorkerId: scope.signing_worker_id,
      }),
  };
}

export async function buildRouterAbEcdsaDerivationPrivateSigningWorkerBody(input: {
  phase: 'prepare' | 'finalize';
  body: Record<string, unknown>;
  authorization: RouterAbEcdsaPrivateSigningAuthorization;
  headers: Record<string, string | string[] | undefined>;
  materialSource?: RouterAbNormalSigningMaterialSourceV1;
}): Promise<RouterAbEcdsaDerivationPrivateSigningWorkerBody> {
  const signingContext = privateSigningAuthorizationContextFromAuthorization(input.authorization);
  const trustedSourceDigest = await privateSigningTrustedSourceDigest(input.headers);
  if (input.phase === 'prepare') {
    const request = parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body);
    validatePrivateSigningAuthorizationContext(request.authorization, signingContext);
    const requestDigest = await routerAbEcdsaDerivationEvmDigestSigningRequestDigestV1(request);
    return {
      request,
      trusted_admission: privateSigningTrustedAdmission({
        runtimePolicyScope: signingContext.runtimePolicyScope,
        subjectId: signingContext.subjectId,
        accountId: request.scope.wallet_id,
        authorization: signingContext,
        requestId: request.request_id,
        intentDigest: requestDigest,
        trustedSourceDigest,
      }),
      material_source:
        input.materialSource ??
        registrationMaterialSourceV1({
          accountId: request.scope.wallet_id,
          materialActivationId: request.scope.material_activation.activation_id,
          signingWorkerId: request.scope.signing_worker.server_id,
        }),
    };
  }
  const request = parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(input.body);
  validatePrivateSigningAuthorizationContext(request.authorization, signingContext);
  const requestDigest =
    await routerAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestDigestV1(request);
  return {
    request,
    trusted_admission: privateSigningTrustedAdmission({
      runtimePolicyScope: signingContext.runtimePolicyScope,
      subjectId: signingContext.subjectId,
      accountId: request.scope.wallet_id,
      authorization: signingContext,
      requestId: request.request_id,
      intentDigest: requestDigest,
      trustedSourceDigest,
    }),
    material_source:
      input.materialSource ??
      registrationMaterialSourceV1({
        accountId: request.scope.wallet_id,
        materialActivationId: request.scope.material_activation.activation_id,
        signingWorkerId: request.scope.signing_worker.server_id,
      }),
  };
}

async function handleRouterAbEd25519OperationStepUpRoute(input: {
  readonly body: Record<string, unknown>;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  readonly resolveEd25519MaterialActivation: RouterApiWalletRegistrationService['resolveEd25519MaterialActivation'];
  readonly phase: RouterAbEd25519NormalSigningRoutePhase;
  readonly scope: RouterAbEd25519NormalSigningScopeV2;
  readonly operationKind: Ed25519OperationKind;
}): Promise<
  | RouterAbJsonRouteResult
  | {
      readonly phase: 'prepare';
      readonly session: RouterAbOperationStepUpWalletSession;
      readonly operation: AuthorizedOperation;
      readonly operationDigests: {
        readonly laneDigest: ReturnType<typeof parseDigestB64u>;
        readonly intentDigest: ReturnType<typeof parseDigestB64u>;
        readonly displayDigest: ReturnType<typeof parseDigestB64u>;
      };
      readonly admissionKind: RouterAbEcdsaOperationAdmissionKind;
    }
  | {
      readonly phase: 'finalize';
      readonly session: RouterAbOperationStepUpWalletSession;
    }
> {
  if (input.scope.authorization.kind !== 'operation_step_up') {
    return routerAbStepUpError(400, 'invalid_body', 'Operation step-up authority is required');
  }
  const expiresAtMs = Number(input.body.expires_at_ms);
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    return routerAbStepUpError(
      408,
      'expired_request',
      'Router A/B Ed25519 step-up request is expired',
    );
  }
  const authenticated = await authenticateRouterAbWalletOperationStepUp({
    headers: input.headers,
    scope: input.scope,
    operationKind: input.operationKind,
    requestExpiresAtMs: expiresAtMs,
    authorizedOperations: input.authorizedOperations,
    authorizationSessions: input.authorizationSessions,
    resolveEd25519MaterialActivation: input.resolveEd25519MaterialActivation,
  });
  if (!authenticated.ok) return authenticated.error;

  const activeMaterial = await input.resolveEd25519MaterialActivation({
    walletId: authenticated.session.walletId,
    materialActivation: input.scope.material_activation,
  });
  if (!activeMaterial.ok) {
    return routerAbStepUpError(
      activeMaterial.code === 'internal' ? 500 : 403,
      activeMaterial.code === 'internal' ? 'internal' : 'scope_mismatch',
      activeMaterial.code === 'internal'
        ? activeMaterial.message
        : 'Operation step-up material is no longer active',
    );
  }
  if (
    !sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      input.scope.material_activation,
    )
  ) {
    return routerAbStepUpError(
      403,
      'scope_mismatch',
      'Operation step-up scope does not name the active material',
    );
  }

  if (input.phase === 'prepare') {
    let privateBody: RouterAbEd25519PrivateSigningWorkerBody;
    try {
      privateBody = await buildRouterAbEd25519PrivateSigningWorkerBody({
        phase: 'prepare',
        body: input.body,
        authorization: {
          kind: 'operation_step_up',
          session: authenticated.session,
        },
        headers: input.headers,
      });
    } catch (error: unknown) {
      return routerAbStepUpError(400, 'invalid_body', errorMessage(error));
    }
    const operation = parseRouterAbOperationStepUpOperation(input.body.intent);
    if (!operation.ok) {
      return routerAbStepUpError(400, 'invalid_body', operation.message);
    }
    let authorizedOperationId: AuthorizedOperationId;
    let capabilityId: CapabilityId;
    let laneDigest: ReturnType<typeof parseDigestB64u>;
    let intentDigest: ReturnType<typeof parseDigestB64u>;
    let displayDigest: ReturnType<typeof parseDigestB64u>;
    try {
      authorizedOperationId = requireAuthorizationValue(
        parseAuthorizedOperationId(`normal-signing-operation:${input.scope.request_id}`),
      );
      capabilityId = requireAuthorizationValue(
        parseCapabilityId(input.scope.material_activation.capability),
      );
      if (!('admission_candidate' in privateBody)) {
        throw new Error('Router A/B step-up prepare admission is missing');
      }
      laneDigest = parseSigningOperationFingerprintDigest(
        (input.body.intent as { operation_fingerprint?: unknown }).operation_fingerprint,
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
    const operationEnvelope = buildCapabilityOperationEnvelope({
      tenantId: authenticated.session.tenantId,
      principalId: authenticated.session.principalId,
      capabilityId,
      operationId: operation.operationId,
      operation: operation.operation,
      digests: { laneDigest, intentDigest, displayDigest },
    });
    const operationFingerprintDigest =
      await computeCapabilityOperationFingerprintDigest(operationEnvelope);
    const existing = await authenticated.authorizedOperations.readAuthorizedOperation({
      tenantId: authenticated.session.tenantId,
      operationFingerprintDigest,
    });
    if (!existing || existing.authorizedOperationId !== authorizedOperationId) {
      return routerAbStepUpError(
        409,
        'authorized_operation_missing',
        'Authorized operation is unavailable',
      );
    }
    if (
      existing.authorization.kind !== 'verified_step_up' ||
      existing.quota.kind !== 'quota_neutral'
    ) {
      return routerAbStepUpError(
        409,
        'authorized_operation_missing',
        'Operation authorization has an invalid source or quota',
      );
    }
    let claimResult: Awaited<
      ReturnType<RouterApiAuthorizedOperationService['admitAuthorizedOperation']>
    >;
    try {
      claimResult = await authenticated.authorizedOperations.admitAuthorizedOperation({
        operation: {
          tenantId: existing.tenantId,
          authorizedOperationId: existing.authorizedOperationId,
          auditEventId: existing.auditEventId,
          operation: existing.operation,
          authorization: existing.authorization,
          quota: existing.quota,
          claimedAtMs: Date.now(),
        },
      });
    } catch (error: unknown) {
      return routerAbStepUpError(400, 'invalid_body', errorMessage(error));
    }
    const claimFailure = routerAbOperationStepUpClaimFailure(claimResult);
    if (claimFailure) return claimFailure;
    if (
      claimResult.kind !== 'claimed' &&
      claimResult.kind !== 'operation_in_progress' &&
      claimResult.kind !== 'replayed'
    ) {
      return routerAbStepUpError(
        409,
        'authorized_operation_missing',
        'Authorized operation is unavailable',
      );
    }
    return {
      phase: 'prepare',
      session: authenticated.session,
      operation: claimResult.operation,
      operationDigests: { laneDigest, intentDigest, displayDigest },
      admissionKind: claimResult.kind,
    };
  }
  return { phase: 'finalize', session: authenticated.session };
}

type RouterAbExactOperationStepUpIdentityInput = {
  readonly kind: 'wallet_session_operation_credential_v1';
  readonly headers: Record<string, string | string[] | undefined>;
  readonly walletId: string;
  readonly materialOwner: string;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly requestExpiresAtMs: number;
  readonly authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
} & (
  | {
      readonly keyFamily: 'ed25519';
      readonly operationKind: Ed25519OperationKind;
      readonly resolveEd25519MaterialActivation: RouterApiWalletRegistrationService['resolveEd25519MaterialActivation'];
      readonly resolveEcdsaMaterialActivation?: never;
    }
  | {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly operationKind: 'evm.sign_transaction' | 'evm.export_key';
      readonly resolveEd25519MaterialActivation?: never;
      readonly resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
    }
);

type RouterAbVerifiedOwnerOperationStepUpIdentityInput = {
  readonly kind: 'verified_owner_proof';
  readonly headers: Record<string, string | string[] | undefined>;
  readonly walletId: string;
  readonly materialOwner: string;
  readonly operationId: string;
  readonly authority: WalletAuthAuthority;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly expiresAtMs: number;
  readonly authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  readonly authorizationSessions?: never;
  readonly keyFamily?: never;
  readonly operationKind?: never;
  readonly materialActivation?: never;
  readonly requestExpiresAtMs?: never;
  readonly resolveEd25519MaterialActivation?: never;
  readonly resolveEcdsaMaterialActivation?: never;
};

type RouterAbOperationStepUpAuthenticationFailure = {
  readonly ok: false;
  readonly error: RouterAbJsonRouteResult;
};

type RouterAbOperationStepUpAuthenticationSuccess<
  TSession extends RouterAbOperationStepUpWalletSession,
> = {
  readonly ok: true;
  readonly authorizedOperations: RouterApiAuthorizedOperationService;
  readonly session: TSession;
  readonly requestOrigin: import('../../../authorization/domain').SessionOrigin;
  readonly expiresAtMs: number;
};

type RouterAbExactOperationStepUpAuthenticationResult =
  | RouterAbOperationStepUpAuthenticationSuccess<RouterAbExactOperationStepUpWalletSession>
  | RouterAbOperationStepUpAuthenticationFailure;

type RouterAbVerifiedOwnerOperationStepUpAuthenticationResult =
  | (RouterAbOperationStepUpAuthenticationSuccess<RouterAbVerifiedOwnerOperationStepUpWalletSession> & {
      readonly authorityRef: WalletAuthAuthorityRef;
    })
  | RouterAbOperationStepUpAuthenticationFailure;

export function authenticateRouterAbWalletOperationStepUpIdentity(
  input: RouterAbExactOperationStepUpIdentityInput,
): Promise<RouterAbExactOperationStepUpAuthenticationResult>;
export function authenticateRouterAbWalletOperationStepUpIdentity(
  input: RouterAbVerifiedOwnerOperationStepUpIdentityInput,
): Promise<RouterAbVerifiedOwnerOperationStepUpAuthenticationResult>;
export async function authenticateRouterAbWalletOperationStepUpIdentity(
  input:
    | RouterAbExactOperationStepUpIdentityInput
    | RouterAbVerifiedOwnerOperationStepUpIdentityInput,
): Promise<
  | RouterAbExactOperationStepUpAuthenticationResult
  | RouterAbVerifiedOwnerOperationStepUpAuthenticationResult
> {
  if (!input.authorizedOperations) {
    return {
      ok: false,
      error: routerAbStepUpError(
        501,
        'not_configured',
        'Router A/B operation step-up authorization is not configured',
      ),
    };
  }
  const requestOriginRaw =
    (Array.isArray(input.headers.origin) ? input.headers.origin[0] : input.headers.origin) || '';
  let requestOrigin: import('../../../authorization/domain').SessionOrigin;
  try {
    requestOrigin = parseSessionOrigin(String(requestOriginRaw).trim());
  } catch {
    return {
      ok: false,
      error: routerAbStepUpError(401, 'unauthorized', 'Wallet owner proof origin is invalid'),
    };
  }
  if (input.kind === 'verified_owner_proof') {
    const tenantId = input.authorizedOperations.tenantId;
    const authorityRef = await walletAuthAuthorityRef({ authority: input.authority });
    const principal = parsePrincipalId(
      input.authority.factor.kind === 'email_otp'
        ? input.authority.factor.providerUserId
        : input.walletId,
    );
    const authSource = walletExecutionLaneAuthSourceFromAuthority(input.authority);
    if (
      !principal.ok ||
      !authSource ||
      input.walletId !== input.materialOwner ||
      input.authority.walletId !== input.walletId ||
      input.runtimePolicyScope.orgId !== tenantId ||
      input.expiresAtMs <= Date.now()
    ) {
      return {
        ok: false,
        error: routerAbStepUpError(403, 'scope_mismatch', 'Wallet owner proof scope is invalid'),
      };
    }
    return {
      ok: true,
      authorizedOperations: input.authorizedOperations,
      session: {
        tenantId,
        principalId: principal.value,
        sessionId: input.operationId,
        walletId: input.walletId,
        runtimePolicyScope: input.runtimePolicyScope,
        laneAuthorization: {
          kind: 'authority_ref',
          authorityRef,
          authSource,
        },
      },
      authorityRef,
      requestOrigin,
      expiresAtMs: input.expiresAtMs,
    };
  }
  if (!input.authorizationSessions) {
    return {
      ok: false,
      error: routerAbStepUpError(
        501,
        'not_configured',
        'Router A/B Wallet Sessions are not configured',
      ),
    };
  }
  const token = extractBearerCredential(input.headers);
  if (!token) {
    return {
      ok: false,
      error: routerAbStepUpError(401, 'unauthorized', 'Wallet Session is required'),
    };
  }
  let resolution: Awaited<ReturnType<typeof resolveWalletSessionOperationCredentialAdmission>>;
  try {
    const operation =
      input.keyFamily === 'ed25519'
        ? {
            keyFamily: 'ed25519' as const,
            operationKind: input.operationKind,
          }
        : {
            keyFamily: 'ecdsa_secp256k1' as const,
            operationKind: input.operationKind,
          };
    resolution = await resolveWalletSessionOperationCredentialAdmission({
      authorizationSessions: input.authorizationSessions,
      token,
      nowMs: Date.now(),
      operation,
    });
  } catch {
    return {
      ok: false,
      error: routerAbStepUpError(
        503,
        'wallet_session_unavailable',
        'Wallet Session is unavailable',
      ),
    };
  }
  if (resolution.kind === 'not_found') {
    return {
      ok: false,
      error: routerAbStepUpError(401, 'unauthorized', 'Wallet Session is invalid'),
    };
  }
  if (resolution.kind === 'rejected') {
    return {
      ok: false,
      error: routerAbStepUpError(403, 'scope_mismatch', 'Wallet Session scope is invalid'),
    };
  }
  const admission = resolution.admission;
  const session = admission.context.authorization.session;
  const admittedMaterialActivation = routerAbMpcMaterialActivationRefToWire(
    admission.admission.materialActivation,
  );
  if (
    admission.admission.keyFamily !== input.keyFamily ||
    admission.admission.operationKind !== input.operationKind ||
    String(session.walletId) !== input.walletId ||
    input.materialOwner !== input.walletId ||
    !Number.isSafeInteger(input.requestExpiresAtMs) ||
    input.requestExpiresAtMs > session.expiresAtMs ||
    !sameRouterAbMpcMaterialActivationRef(admittedMaterialActivation, input.materialActivation)
  ) {
    return {
      ok: false,
      error: routerAbStepUpError(403, 'scope_mismatch', 'Wallet Session scope is invalid'),
    };
  }
  let runtimePolicyScope: RuntimePolicyScope;
  try {
    if (admission.curve === 'ed25519' && input.keyFamily === 'ed25519') {
      const activeMaterial = await input.resolveEd25519MaterialActivation({
        walletId: input.walletId,
        materialActivation: admittedMaterialActivation,
      });
      if (
        !activeMaterial.ok ||
        !sameRouterAbMpcMaterialActivationRef(
          activeMaterial.materialActivation,
          admittedMaterialActivation,
        ) ||
        !sameRouterAbMpcMaterialActivationRef(
          activeMaterial.exportIdentity.scope.material_activation,
          admittedMaterialActivation,
        ) ||
        activeMaterial.exportIdentity.scope.account_id !== input.walletId ||
        activeMaterial.exportIdentity.application_binding.wallet_id !== input.walletId ||
        base64UrlEncode(Uint8Array.from(activeMaterial.exportIdentity.registered_public_key)) !==
          admission.admission.signer.registeredPublicKeyB64u
      ) {
        return {
          ok: false,
          error: routerAbStepUpError(
            activeMaterial.ok || activeMaterial.code !== 'internal' ? 403 : 503,
            activeMaterial.ok || activeMaterial.code !== 'internal'
              ? 'scope_mismatch'
              : 'wallet_session_unavailable',
            activeMaterial.ok
              ? 'Wallet Session material does not match the active Ed25519 material'
              : activeMaterial.message,
          ),
        };
      }
      runtimePolicyScope = activeMaterial.runtimePolicyScope;
    } else if (admission.curve === 'ecdsa' && input.keyFamily === 'ecdsa_secp256k1') {
      const activeMaterial = await input.resolveEcdsaMaterialActivation({
        walletId: input.walletId,
        materialActivation: admittedMaterialActivation,
      });
      const normalSigning = activeMaterial.ok
        ? activeMaterial.routerAbEcdsaDerivationNormalSigning
        : null;
      if (
        !activeMaterial.ok ||
        !normalSigning ||
        !sameRouterAbMpcMaterialActivationRef(
          activeMaterial.materialActivation,
          admittedMaterialActivation,
        ) ||
        !sameRouterAbMpcMaterialActivationRef(
          normalSigning.scope.material_activation,
          admittedMaterialActivation,
        ) ||
        normalSigning.scope.wallet_id !== input.walletId ||
        normalSigning.scope.public_identity.threshold_public_key33_b64u !==
          admission.admission.signer.thresholdPublicKey33B64u ||
        normalSigning.scope.public_identity.ethereum_address20_b64u !==
          evmAddress20B64u(admission.admission.signer.evmAddress)
      ) {
        return {
          ok: false,
          error: routerAbStepUpError(
            activeMaterial.ok || activeMaterial.code !== 'internal' ? 403 : 503,
            activeMaterial.ok || activeMaterial.code !== 'internal'
              ? 'scope_mismatch'
              : 'wallet_session_unavailable',
            activeMaterial.ok
              ? 'Wallet Session material does not match the active ECDSA material'
              : activeMaterial.message,
          ),
        };
      }
      runtimePolicyScope = activeMaterial.runtimePolicyScope;
    } else {
      return {
        ok: false,
        error: routerAbStepUpError(403, 'scope_mismatch', 'Wallet Session family is invalid'),
      };
    }
  } catch {
    return {
      ok: false,
      error: routerAbStepUpError(
        503,
        'wallet_session_unavailable',
        'Wallet Session is unavailable',
      ),
    };
  }
  if (
    session.tenantId !== input.authorizedOperations.tenantId ||
    runtimePolicyScope.orgId !== session.tenantId ||
    session.expiresAtMs <= Date.now()
  ) {
    return {
      ok: false,
      error: routerAbStepUpError(403, 'scope_mismatch', 'Wallet Session scope is invalid'),
    };
  }
  return {
    ok: true,
    authorizedOperations: input.authorizedOperations,
    session: {
      tenantId: session.tenantId,
      principalId: session.principalId,
      sessionId: String(session.authorizationId),
      walletId: String(session.walletId),
      runtimePolicyScope,
      laneAuthorization: {
        kind: 'wallet_auth_method',
        walletAuthMethodId: session.walletAuthMethodId,
      },
    },
    requestOrigin,
    expiresAtMs: session.expiresAtMs,
  };
}

function walletExecutionLaneAuthSourceFromAuthority(
  authority: WalletAuthAuthority,
): WalletExecutionLaneAuthSource | null {
  if (authority.factor.kind === 'passkey') {
    return {
      kind: 'passkey',
      credentialIdB64u: authority.factor.credentialIdB64u,
    };
  }
  const providerSubject = parseProviderSubject(authority.factor.providerUserId);
  return providerSubject.ok
    ? {
        kind: 'oidc_provider',
        providerId: authority.factor.provider === 'google' ? 'google_oidc' : 'oidc',
        providerSubject: providerSubject.value,
      }
    : null;
}

function evmAddress20B64u(value: string): string | null {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) return null;
  const bytes = new Uint8Array(20);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(2 + index * 2, 4 + index * 2), 16);
  }
  return base64UrlEncode(bytes);
}

export async function authenticateRouterAbWalletOperationStepUp(input: {
  readonly headers: Record<string, string | string[] | undefined>;
  readonly scope: RouterAbEd25519NormalSigningScopeV2;
  readonly operationKind: Ed25519OperationKind;
  readonly requestExpiresAtMs: number;
  readonly authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  readonly resolveEd25519MaterialActivation: RouterApiWalletRegistrationService['resolveEd25519MaterialActivation'];
}): Promise<RouterAbExactOperationStepUpAuthenticationResult> {
  return authenticateRouterAbWalletOperationStepUpIdentity({
    kind: 'wallet_session_operation_credential_v1',
    headers: input.headers,
    keyFamily: 'ed25519',
    operationKind: input.operationKind,
    walletId: input.scope.account_id,
    materialOwner: input.scope.material_activation.material_owner,
    materialActivation: input.scope.material_activation,
    requestExpiresAtMs: input.requestExpiresAtMs,
    authorizedOperations: input.authorizedOperations,
    authorizationSessions: input.authorizationSessions,
    resolveEd25519MaterialActivation: input.resolveEd25519MaterialActivation,
  });
}

export async function authenticateRouterAbEcdsaOperationStepUp(input: {
  readonly headers: Record<string, string | string[] | undefined>;
  readonly request:
    | RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire
    | RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire;
  readonly authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  readonly resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
}): Promise<RouterAbExactOperationStepUpAuthenticationResult> {
  return await authenticateRouterAbWalletOperationStepUpIdentity({
    kind: 'wallet_session_operation_credential_v1',
    headers: input.headers,
    keyFamily: 'ecdsa_secp256k1',
    operationKind: 'evm.sign_transaction',
    walletId: input.request.scope.wallet_id,
    materialOwner: input.request.material_activation.material_owner,
    materialActivation: input.request.material_activation,
    requestExpiresAtMs: input.request.expires_at_ms,
    authorizedOperations: input.authorizedOperations,
    authorizationSessions: input.authorizationSessions,
    resolveEcdsaMaterialActivation: input.resolveEcdsaMaterialActivation,
  });
}

export function parseRouterAbEd25519OperationStepUpScope(
  value: unknown,
): RouterAbEd25519NormalSigningScopeV2 {
  return parseRouterAbEd25519NormalSigningScopeV2(value);
}

export function parseRouterAbOperationStepUpOperation(value: unknown):
  | {
      readonly ok: true;
      readonly operationId: CapabilityOperationId;
      readonly operation: Extract<
        CapabilityOperationRef,
        { readonly capabilityKind: 'near_ed25519_mpc_signing' }
      > & {
        readonly operationKind:
          | 'near.sign_transaction'
          | 'near.sign_delegate_action'
          | 'near.sign_nep413_message';
      };
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

type RouterAbEd25519NormalSigningOperationForAdmission =
  | {
      readonly phase: 'prepare';
      readonly operationKind: Ed25519OperationKind;
    }
  | {
      readonly phase: 'finalize';
      readonly operationKind: Ed25519OperationKind;
      readonly receipt: Ed25519ReusableAuthorizedOperationReceipt;
    };

function parseRouterAbEd25519NormalSigningOperationForAdmission(input: {
  readonly phase: RouterAbEd25519NormalSigningRoutePhase;
  readonly body: Record<string, unknown>;
}):
  | { readonly ok: true; readonly operation: RouterAbEd25519NormalSigningOperationForAdmission }
  | { readonly ok: false; readonly message: string } {
  if (input.phase === 'prepare') {
    const requestedOperation = parseRouterAbOperationStepUpOperation(input.body.intent);
    if (!requestedOperation.ok) return requestedOperation;
    return {
      ok: true,
      operation: {
        phase: 'prepare',
        operationKind: requestedOperation.operation.operationKind,
      },
    };
  }
  try {
    const receipt = parseEd25519ReusableAuthorizedOperationReceipt(input.body.authorized_operation);
    return {
      ok: true,
      operation: {
        phase: 'finalize',
        operationKind: receipt.operation_kind,
        receipt,
      },
    };
  } catch (error: unknown) {
    return { ok: false, message: errorMessage(error) };
  }
}

async function validateRouterAbEd25519V2FinalizeAuthorizedOperation(input: {
  readonly receipt: Ed25519ReusableAuthorizedOperationReceipt;
  readonly authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  readonly phase: RouterAbEd25519NormalSigningRoutePhase;
}): Promise<
  | { readonly ok: true; readonly operationKind: Ed25519OperationKind }
  | { readonly ok: false; readonly result: RouterAbJsonRouteResult }
> {
  if (!input.authorizedOperations) {
    return {
      ok: false,
      result: routerAbEd25519OwnerOperationFailureResult({
        status: 501,
        code: 'not_configured',
        message: 'Reusable Wallet Session authorization is not configured',
        phase: input.phase,
      }),
    };
  }

  let authorizedOperationId: AuthorizedOperationId;
  try {
    authorizedOperationId = requireAuthorizationValue(
      parseAuthorizedOperationId(input.receipt.authorized_operation_id),
    );
    requireAuthorizationValue(parseCapabilityOperationId(input.receipt.operation_id));
  } catch (error: unknown) {
    return {
      ok: false,
      result: routerAbEd25519OwnerOperationFailureResult({
        status: 400,
        code: 'invalid_authorized_operation',
        message: errorMessage(error),
        phase: input.phase,
      }),
    };
  }

  let operation: AuthorizedOperation | null;
  try {
    operation = await input.authorizedOperations.readAuthorizedOperationById({
      tenantId: input.authorizedOperations.tenantId,
      authorizedOperationId,
    });
  } catch (error: unknown) {
    return {
      ok: false,
      result: routerAbEd25519OwnerOperationFailureResult({
        status: 500,
        code: 'internal',
        message: errorMessage(error),
        phase: input.phase,
      }),
    };
  }
  if (!operation) {
    return {
      ok: false,
      result: routerAbEd25519OwnerOperationFailureResult({
        status: 409,
        code: 'authorized_operation_missing',
        message: 'Authorized operation is unavailable',
        phase: input.phase,
      }),
    };
  }

  const operationRef = operation.operation.operation;
  if (
    operation.tenantId !== input.authorizedOperations.tenantId ||
    operation.authorizedOperationId !== authorizedOperationId ||
    operation.operation.operationId !== input.receipt.operation_id ||
    operation.operationFingerprintDigest !== input.receipt.operation_fingerprint_digest ||
    operation.operation.digests.laneDigest !== input.receipt.lane_digest_b64u ||
    operation.operation.digests.intentDigest !== input.receipt.intent_digest_b64u ||
    operation.operation.digests.displayDigest !== input.receipt.display_digest_b64u ||
    operationRef.capabilityKind !== 'near_ed25519_mpc_signing' ||
    operationRef.operationKind !== input.receipt.operation_kind
  ) {
    return {
      ok: false,
      result: routerAbEd25519OwnerOperationFailureResult({
        status: 400,
        code: 'invalid_authorized_operation',
        message: 'Ed25519 authorized operation does not match its receipt',
        phase: input.phase,
      }),
    };
  }

  switch (operationRef.operationKind) {
    case 'near.sign_transaction':
    case 'near.sign_delegate_action':
    case 'near.sign_nep413_message':
      return { ok: true, operationKind: operationRef.operationKind };
  }
}

function requireAuthorizationValue<T>(result: AuthorizationParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function routerAbOperationStepUpClaimFailure(
  result: Awaited<ReturnType<RouterApiAuthorizedOperationService['admitAuthorizedOperation']>>,
): RouterAbJsonRouteResult | null {
  switch (result.kind) {
    case 'claimed':
    case 'operation_in_progress':
    case 'replayed':
      return null;
    case 'authorization_grant_rejected':
    case 'verified_step_up_rejected':
      return routerAbStepUpError(403, result.kind, 'Operation step-up authorization is invalid');
    case 'wallet_session_quota_exhausted':
      return routerAbStepUpError(409, result.kind, 'Operation step-up authorization is invalid');
    case 'material_mismatch':
      return routerAbStepUpError(403, result.kind, 'Operation step-up material is invalid');
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
  authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  resolveEd25519MaterialActivation: RouterApiWalletRegistrationService['resolveEd25519MaterialActivation'];
  phase: RouterAbEd25519NormalSigningRoutePhase;
}): Promise<RouterAbEd25519NormalSigningAuthorizationResult> {
  let scope: RouterAbEd25519NormalSigningScopeV2;
  try {
    scope = parseRouterAbEd25519NormalSigningScopeV2(input.body.scope);
  } catch (error: unknown) {
    return {
      ok: false,
      result: routerAbEd25519OwnerOperationFailureResult({
        status: 400,
        code: 'invalid_body',
        message: errorMessage(error),
        phase: input.phase,
      }),
    };
  }
  const operationForAdmission = parseRouterAbEd25519NormalSigningOperationForAdmission({
    phase: input.phase,
    body: input.body,
  });
  if (!operationForAdmission.ok) {
    return {
      ok: false,
      result: routerAbEd25519OwnerOperationFailureResult({
        status: 400,
        code: 'invalid_body',
        message: operationForAdmission.message,
        phase: input.phase,
      }),
    };
  }
  if (scope.authorization.kind === 'operation_step_up') {
    const result = await handleRouterAbEd25519OperationStepUpRoute({
      body: input.body,
      headers: input.headers,
      authorizedOperations: input.authorizedOperations,
      authorizationSessions: input.authorizationSessions,
      resolveEd25519MaterialActivation: input.resolveEd25519MaterialActivation,
      phase: input.phase,
      scope,
      operationKind: operationForAdmission.operation.operationKind,
    });
    return 'status' in result
      ? { ok: false, result }
      : { ok: true, kind: 'operation_step_up', ...result };
  }

  const validated = await validateRouterAbEd25519WalletSessionInputs({
    body: input.rawBody,
    headers: input.headers,
    authorizationSessions: input.authorizationSessions,
    operationKind: operationForAdmission.operation.operationKind,
  });
  if (!validated.ok) {
    const stepUp = await resolveRouterAbEd25519OwnerOperationStepUpPreparation({
      scope,
      body: input.body,
      phase: input.phase,
      resolveEd25519MaterialActivation: input.resolveEd25519MaterialActivation,
    });
    return {
      ok: false,
      result: routerAbEd25519OwnerOperationFailureResult({
        status: routerAbWalletSessionValidationStatus(validated.code),
        code: validated.code,
        message: validated.message,
        phase: input.phase,
        stepUp,
      }),
    };
  }

  {
    if (operationForAdmission.operation.phase === 'finalize') {
      const exactOperation = await validateRouterAbEd25519V2FinalizeAuthorizedOperation({
        receipt: operationForAdmission.operation.receipt,
        authorizedOperations: input.authorizedOperations,
        phase: input.phase,
      });
      if (!exactOperation.ok) return { ok: false, result: exactOperation.result };
      if (exactOperation.operationKind !== validated.admission.admission.operationKind) {
        return {
          ok: false,
          result: routerAbEd25519OwnerOperationFailureResult({
            status: 403,
            code: 'wallet_session_scope_mismatch',
            message: 'Exact Wallet Session operation does not match the authorized operation',
            phase: input.phase,
          }),
        };
      }
    }
    const session = validated.admission.context.authorization.session;
    const expectedMaterialActivation = routerAbMpcMaterialActivationRefFromWire(
      scope.material_activation,
    );
    const admittedMaterialActivation = routerAbMpcMaterialActivationRefToWire(
      validated.admission.admission.materialActivation,
    );
    const expiresAtMs = Number(input.body.expires_at_ms);
    if (
      scope.authorization.wallet_session_id !== session.walletSessionId ||
      scope.account_id !== String(session.walletId) ||
      scope.material_activation.material_owner !== String(session.walletId) ||
      scope.signing_worker_id !== scope.material_activation.signing_worker ||
      !mpcMaterialActivationRefsEqual(
        expectedMaterialActivation,
        validated.admission.admission.materialActivation,
      ) ||
      !Number.isFinite(expiresAtMs) ||
      expiresAtMs <= 0
    ) {
      return {
        ok: false,
        result: routerAbEd25519OwnerOperationFailureResult({
          status: 403,
          code: 'wallet_session_scope_mismatch',
          message: 'Exact Wallet Session does not authorize this Ed25519 request',
          phase: input.phase,
        }),
      };
    }
    if (expiresAtMs <= Date.now()) {
      return {
        ok: false,
        result: routerAbEd25519OwnerOperationFailureResult({
          status: 408,
          code: 'expired_request',
          message: 'Router A/B Ed25519 normal-signing request is expired',
          phase: input.phase,
        }),
      };
    }
    if (expiresAtMs > session.expiresAtMs) {
      return {
        ok: false,
        result: routerAbEd25519OwnerOperationFailureResult({
          status: 403,
          code: 'wallet_session_scope_mismatch',
          message: 'Ed25519 request exceeds the exact Wallet Session lifetime',
          phase: input.phase,
        }),
      };
    }
    const activeMaterial = await input.resolveEd25519MaterialActivation({
      walletId: String(session.walletId),
      materialActivation: admittedMaterialActivation,
    });
    if (
      !activeMaterial.ok ||
      !sameRouterAbMpcMaterialActivationRef(
        activeMaterial.materialActivation,
        admittedMaterialActivation,
      ) ||
      activeMaterial.signingWorkerId !== scope.signing_worker_id ||
      base64UrlEncode(Uint8Array.from(activeMaterial.exportIdentity.registered_public_key)) !==
        validated.admission.admission.signer.registeredPublicKeyB64u
    ) {
      return {
        ok: false,
        result: routerAbEd25519OwnerOperationFailureResult({
          status: activeMaterial.ok || activeMaterial.code !== 'internal' ? 403 : 500,
          code:
            activeMaterial.ok || activeMaterial.code !== 'internal'
              ? 'material_mismatch'
              : 'internal',
          message: activeMaterial.ok
            ? 'Exact Wallet Session material does not match the active Ed25519 material'
            : activeMaterial.message,
          phase: input.phase,
        }),
      };
    }
    const admission = {
      ok: true as const,
      thresholdSessionId: activeMaterial.exportIdentity.scope.threshold_session_id,
      requestId: scope.request_id,
      expiresAtMs,
      materialActivation: admittedMaterialActivation,
    };
    const admissionDecision = await evaluateRouterAbNormalSigningAdmission({
      adapter: input.admissionAdapter,
      curve: 'ed25519',
      authorizationKind: 'wallet_session_operation_credential_v1',
      phase: input.phase,
      walletId: String(session.walletId),
      authorityId: String(validated.admission.context.authority.authorityId),
      thresholdSessionId: activeMaterial.exportIdentity.scope.threshold_session_id,
      walletSessionId: String(session.walletSessionId),
      quotaId: String(session.quotaId),
      requestId: scope.request_id,
      expiresAtMs,
      signingWorkerId: activeMaterial.signingWorkerId,
      runtimePolicyScope: activeMaterial.runtimePolicyScope,
    });
    if (!admissionDecision.ok) {
      return {
        ok: false,
        result: routerAbEd25519OwnerOperationFailureResult({
          status: admissionDecision.status,
          code: admissionDecision.code,
          message: admissionDecision.message,
          phase: input.phase,
        }),
      };
    }
    return {
      ok: true,
      kind: 'wallet_session_operation_credential_v1',
      validated,
      admission,
      activeMaterial,
    };
  }
}

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || 'unknown error',
  );
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
      readonly runtimePolicyScope: RuntimePolicyScope;
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
  return {
    ok: true,
    materialActivation: resolved.materialActivation,
    keyHandle: resolved.keyHandle,
    relayerKeyId: resolved.relayerKeyId,
    participantIds: resolved.participantIds,
    runtimePolicyScope: resolved.runtimePolicyScope,
  };
}

type RouterAbEcdsaWalletSessionOperationBinding =
  | {
      readonly kind: 'wallet_session_operation_credential_v1';
      readonly context: RouterApiWalletSessionAuthorizationV2AdmissionContext;
    }
  | {
      readonly kind: 'wallet_session_operation_credential_exhausted_candidate_v1';
      readonly candidate: RouterApiWalletSessionAuthorizationV2ExhaustedCandidateContext;
    };

type RouterAbEcdsaV2NormalSigningValidation =
  | {
      readonly ok: true;
      readonly request: RouterAbEcdsaOperationStepUpRequest;
      readonly admission: AcceptedEcdsaRouteAdmission;
    }
  | { readonly ok: false; readonly error: RouterAbJsonRouteResult };

function validateRouterAbEcdsaV2NormalSigningRequestForSession(input: {
  readonly phase: 'prepare' | 'finalize';
  readonly body: Record<string, unknown>;
  readonly session: RouterApiWalletSessionAuthorizationV2AdmissionContext['authorization']['session'];
  readonly admittedMaterialActivation: RouterAbMpcMaterialActivationRefWire;
}): RouterAbEcdsaV2NormalSigningValidation {
  let request: RouterAbEcdsaOperationStepUpRequest;
  try {
    request =
      input.phase === 'prepare'
        ? parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body)
        : parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(input.body);
  } catch (error: unknown) {
    return {
      ok: false,
      error: routerAbStepUpError(400, 'invalid_body', errorMessage(error)),
    };
  }
  if (
    request.authorization.kind !== 'reusable_wallet_session' ||
    request.authorization.wallet_session_id !== input.session.walletSessionId ||
    request.scope.wallet_id !== String(input.session.walletId) ||
    request.material_activation.material_owner !== String(input.session.walletId) ||
    request.material_activation.signing_worker !== request.scope.signing_worker.server_id ||
    !sameRouterAbMpcMaterialActivationRef(
      request.material_activation,
      request.scope.material_activation,
    ) ||
    !sameRouterAbMpcMaterialActivationRef(
      request.material_activation,
      input.admittedMaterialActivation,
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
  if (request.expires_at_ms > input.session.expiresAtMs) {
    return {
      ok: false,
      error: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
    };
  }
  return {
    ok: true,
    request,
    admission: {
      ok: true,
      thresholdSessionId: routerAbEcdsaDerivationActiveStateId({
        kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
        scope: request.scope,
      }),
      requestId: request.request_id,
      expiresAtMs: request.expires_at_ms,
      materialActivation: input.admittedMaterialActivation,
    },
  };
}

export async function admitRouterAbEcdsaReusableWalletSessionOperation(input: {
  request: RouterAbEcdsaOperationStepUpRequest;
  materialActivation: RouterAbMpcMaterialActivationRefWire;
  binding: RouterAbEcdsaWalletSessionOperationBinding;
  authorizedOperations: Pick<
    RouterApiAuthorizedOperationService,
    'tenantId' | 'admitAuthorizedOperation'
  >;
  resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
}): Promise<
  | {
      readonly ok: true;
      readonly admission: RouterAbEcdsaOperationAdmission;
    }
  | { readonly ok: false; readonly error: RouterAbJsonRouteResult }
> {
  if (!routerAbEcdsaAtomicAuthorizationConfigured(input.authorizedOperations)) {
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
    const session =
      input.binding.kind === 'wallet_session_operation_credential_v1'
        ? input.binding.context.authorization.session
        : input.binding.candidate.status.session;
    const tenantId = session.tenantId;
    const principalId = session.principalId;
    const walletId = session.walletId;
    const walletSessionId = session.walletSessionId;
    const authorizationId = session.authorizationId;
    const quotaId = session.quotaId;
    if (
      tenantId !== input.authorizedOperations.tenantId ||
      input.request.authorization.wallet_session_id !== walletSessionId
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
      walletId: String(walletId),
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
    const authorizedOperationId = requireAuthorizationValue(
      parseAuthorizedOperationId(
        `ecdsa-authorized-operation:${operationId}:${input.request.request_id}`,
      ),
    );
    const auditEventId = requireAuthorizationValue(
      parseAuthorizationAuditEventId(`ecdsa-operation-audit:${operationId}`),
    );
    const outcome = await input.authorizedOperations.admitAuthorizedOperation({
      operation: {
        tenantId,
        authorizedOperationId,
        auditEventId,
        operation: envelope,
        authorization: {
          kind: 'authorization_grant',
          authorizationGrantRef: buildAuthorizationGrantRef(authorizationId),
        },
        quota: { kind: 'consume_reusable_wallet_session', quotaId },
        claimedAtMs: nowMs,
      },
      material: {
        walletId,
        keyHandle: freshMaterial.keyHandle,
        runtimePolicyScope: freshMaterial.runtimePolicyScope,
        materialActivation: freshMaterial.materialActivation,
      },
    });
    const claimFailure = routerAbReusableWalletSessionClaimFailure(outcome);
    if (claimFailure) return { ok: false, error: claimFailure };
    if (
      outcome.kind === 'claimed' ||
      outcome.kind === 'operation_in_progress' ||
      outcome.kind === 'replayed'
    ) {
      return {
        ok: true,
        admission: {
          kind: outcome.kind,
          operation: outcome.operation,
        },
      };
    }
    return {
      ok: false,
      error: routerAbStepUpError(409, outcome.kind, 'Authorized operation is unavailable'),
    };
  } catch (error: unknown) {
    return {
      ok: false,
      error: routerAbStepUpError(400, 'invalid_body', errorMessage(error)),
    };
  }
}

function routerAbReusableWalletSessionClaimFailure(
  result: Awaited<ReturnType<RouterApiAuthorizedOperationService['admitAuthorizedOperation']>>,
): RouterAbJsonRouteResult | null {
  switch (result.kind) {
    case 'claimed':
    case 'operation_in_progress':
    case 'replayed':
      return null;
    case 'wallet_session_quota_exhausted':
      return routerAbStepUpError(409, result.kind, 'Reusable Wallet Session quota is exhausted');
    case 'authorization_grant_rejected':
      return routerAbStepUpError(
        403,
        result.kind,
        'Reusable Wallet Session authorization is invalid',
      );
    case 'verified_step_up_rejected':
      return routerAbStepUpError(
        403,
        result.kind,
        'Reusable Wallet Session authorization is invalid',
      );
    case 'material_mismatch':
      return routerAbStepUpError(403, result.kind, 'ECDSA material activation is no longer active');
  }
}

export async function completeRouterAbEcdsaOperation(input: {
  authorizedOperations: RouterApiAuthorizedOperationService;
  operation: AuthorizedOperation;
  result: 'succeeded' | 'failed_before_side_effect' | 'failed_after_side_effect';
  response: AuthorizedOperationReplayResponse;
}): Promise<void> {
  await input.authorizedOperations.completeAuthorizedOperation({
    operation: input.operation,
    result: input.result,
    response: input.response,
    completedAtMs: Date.now(),
  });
}

type RouterAbEcdsaOperationStepUpRequest =
  | RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire
  | RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire;

function parseRouterAbEcdsaOperationStepUpRequest(input: {
  readonly phase: 'prepare';
  readonly body: Record<string, unknown>;
}): RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire;
function parseRouterAbEcdsaOperationStepUpRequest(input: {
  readonly phase: 'finalize';
  readonly body: Record<string, unknown>;
}): RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire;
function parseRouterAbEcdsaOperationStepUpRequest(input: {
  readonly phase: 'prepare' | 'finalize';
  readonly body: Record<string, unknown>;
}): RouterAbEcdsaOperationStepUpRequest;
function parseRouterAbEcdsaOperationStepUpRequest(input: {
  readonly phase: 'prepare' | 'finalize';
  readonly body: Record<string, unknown>;
}): RouterAbEcdsaOperationStepUpRequest {
  return input.phase === 'prepare'
    ? parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body)
    : parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(input.body);
}

type RouterAbEcdsaWalletSessionAuthorization =
  | {
      readonly ok: true;
      readonly request: RouterAbEcdsaOperationStepUpRequest;
      readonly admission: AcceptedEcdsaRouteAdmission;
      readonly activeMaterial: ActiveEcdsaMaterialActivation;
    }
  | { readonly ok: false; readonly result: RouterAbJsonRouteResult };

async function authorizeRouterAbEcdsaWalletSessionRequest(input: {
  readonly phase: 'prepare' | 'finalize';
  readonly body: Record<string, unknown>;
  readonly session: RouterApiWalletSessionAuthorizationV2AdmissionContext['authorization']['session'];
  readonly admittedMaterialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  readonly resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
}): Promise<RouterAbEcdsaWalletSessionAuthorization> {
  const validated = validateRouterAbEcdsaV2NormalSigningRequestForSession(input);
  if (!validated.ok) return { ok: false, result: validated.error };

  const activeMaterial = await input.resolveEcdsaMaterialActivation({
    walletId: String(input.session.walletId),
    materialActivation: validated.admission.materialActivation,
  });
  if (!activeMaterial.ok) {
    return {
      ok: false,
      result: routerAbEcdsaOwnerOperationFailureResult({
        status: activeMaterial.code === 'internal' ? 500 : 403,
        code: activeMaterial.code === 'internal' ? 'internal' : 'material_mismatch',
        message:
          activeMaterial.code === 'internal'
            ? activeMaterial.message
            : 'Wallet Session V2 material is no longer active',
        phase: input.phase,
      }),
    };
  }
  if (
    !sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      validated.admission.materialActivation,
    ) ||
    !sameRouterAbEcdsaDerivationNormalSigningScopeV1(
      validated.request.scope,
      activeMaterial.routerAbEcdsaDerivationNormalSigning.scope,
    )
  ) {
    return {
      ok: false,
      result: routerAbStepUpError(
        403,
        'wallet_session_scope_mismatch',
        'Wallet Session V2 scope does not match the active material',
      ),
    };
  }
  const admissionDecision = await evaluateRouterAbNormalSigningAdmission({
    adapter: input.admissionAdapter,
    curve: 'ecdsa',
    authorizationKind: 'wallet_session_operation_credential_v1',
    phase: input.phase,
    walletId: String(input.session.walletId),
    walletSessionId: String(input.session.walletSessionId),
    materialActivation: activeMaterial.materialActivation,
    requestId: validated.admission.requestId,
    expiresAtMs: validated.admission.expiresAtMs,
    signingWorkerId: activeMaterial.materialActivation.signing_worker,
    keyHandle: activeMaterial.keyHandle,
    runtimePolicyScope: activeMaterial.runtimePolicyScope,
    admission: validated.admission,
  });
  if (!admissionDecision.ok) {
    return {
      ok: false,
      result: routerAbEcdsaOwnerOperationFailureResult({
        status: admissionDecision.status,
        code: admissionDecision.code,
        message: admissionDecision.message,
        phase: input.phase,
      }),
    };
  }
  return {
    ok: true,
    request: validated.request,
    admission: {
      ...validated.admission,
      materialActivation: activeMaterial.materialActivation,
    },
    activeMaterial,
  };
}

type RouterAbEcdsaExhaustedCandidateAuthorization =
  | {
      readonly ok: true;
      readonly kind: 'wallet_session_operation_credential_exhausted_candidate_v1';
      readonly candidate: RouterApiWalletSessionAuthorizationV2ExhaustedCandidateContext;
      readonly admission: AcceptedEcdsaRouteAdmission;
      readonly activeMaterial: ActiveEcdsaMaterialActivation;
    }
  | { readonly ok: false; readonly result: RouterAbJsonRouteResult };

async function resolveRouterAbEcdsaExhaustedCandidateAuthorization(input: {
  readonly phase: 'prepare' | 'finalize';
  readonly body: Record<string, unknown>;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly authorizationSessions: RouterApiAuthorizationSessionService;
  readonly admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  readonly resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
}): Promise<RouterAbEcdsaExhaustedCandidateAuthorization | null> {
  const token = extractBearerCredential(input.headers);
  if (!token) return null;
  let candidate: RouterApiWalletSessionAuthorizationV2ExhaustedCandidateContext | null;
  try {
    candidate =
      await input.authorizationSessions.readExhaustedWalletSessionAuthorizationV2CandidateByOperationCredential(
        {
          tenantId: input.authorizationSessions.tenantId,
          token,
          nowMs: Date.now(),
        },
      );
  } catch {
    return {
      ok: false,
      result: routerAbStepUpError(
        503,
        'wallet_session_unavailable',
        'Wallet Session is unavailable',
      ),
    };
  }
  if (!candidate) return null;

  const session = candidate.status.session;
  const admission = resolveWalletSessionAuthorizationV2Admission({
    authorization: session,
    authority: candidate.authority,
    authMethod: candidate.authMethod,
    operation: {
      tenantId: session.tenantId,
      principalId: session.principalId,
      walletId: session.walletId,
      keyFamily: 'ecdsa_secp256k1',
      operationKind: 'evm.sign_transaction',
    },
    retiredAtMs: candidate.retiredAtMs,
    nowMs: Date.now(),
  });
  if (!admission.ok || admission.keyFamily !== 'ecdsa_secp256k1') {
    return {
      ok: false,
      result: routerAbWalletSessionError(WALLET_SESSION_FAILURE_CODES.scopeMismatch),
    };
  }
  const authorized = await authorizeRouterAbEcdsaWalletSessionRequest({
    phase: input.phase,
    body: input.body,
    session,
    admittedMaterialActivation: routerAbMpcMaterialActivationRefToWire(
      admission.materialActivation,
    ),
    admissionAdapter: input.admissionAdapter,
    resolveEcdsaMaterialActivation: input.resolveEcdsaMaterialActivation,
  });
  if (!authorized.ok) return authorized;
  return {
    ok: true,
    kind: 'wallet_session_operation_credential_exhausted_candidate_v1',
    candidate,
    admission: authorized.admission,
    activeMaterial: authorized.activeMaterial,
  };
}

function validateRouterAbEcdsaOperationStepUpIdentity(input: {
  readonly request: RouterAbEcdsaOperationStepUpRequest;
  readonly session: RouterAbOperationStepUpWalletSession;
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
  return null;
}

export async function claimRouterAbEcdsaOperationStepUp(input: {
  readonly operationKind: 'evm.sign_transaction' | 'evm.export_key';
  readonly operation: Pick<
    RouterAbEcdsaOperationStepUpPreparationV1Wire,
    'operation_id' | 'operation_digests' | 'material_activation'
  >;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly keyHandle: string;
  readonly authenticated: Extract<
    Awaited<ReturnType<typeof authenticateRouterAbEcdsaOperationStepUp>>,
    { readonly ok: true }
  >;
}): Promise<RouterAbJsonRouteResult | RouterAbEcdsaOperationAdmission | null> {
  if (!routerAbEcdsaAtomicAuthorizationConfigured(input.authenticated.authorizedOperations)) {
    return routerAbStepUpError(
      501,
      'not_configured',
      'ECDSA atomic authorization is not configured',
    );
  }
  let authorizedOperationId: AuthorizedOperationId;
  let operationEnvelope: ReturnType<typeof buildCapabilityOperationEnvelope>;
  try {
    const operationId = requireAuthorizationValue(
      parseCapabilityOperationId(input.operation.operation_id),
    );
    authorizedOperationId = requireAuthorizationValue(
      parseAuthorizedOperationId(
        `ecdsa-step-up-authorized-operation:${input.operation.operation_id}`,
      ),
    );
    operationEnvelope = buildCapabilityOperationEnvelope({
      tenantId: input.authenticated.session.tenantId,
      principalId: input.authenticated.session.principalId,
      capabilityId: requireAuthorizationValue(
        parseCapabilityId(input.materialActivation.capability),
      ),
      operationId,
      operation: buildEvmEcdsaMpcOperationRef(input.operationKind),
      digests: {
        laneDigest: parseDigestB64u(input.operation.operation_digests.lane_digest_b64u),
        intentDigest: parseDigestB64u(input.operation.operation_digests.intent_digest_b64u),
        displayDigest: parseDigestB64u(input.operation.operation_digests.display_digest_b64u),
      },
    });
  } catch (error: unknown) {
    return routerAbStepUpError(400, 'invalid_body', errorMessage(error));
  }
  const existing = await input.authenticated.authorizedOperations.readAuthorizedOperation({
    tenantId: input.authenticated.session.tenantId,
    operationFingerprintDigest:
      await computeCapabilityOperationFingerprintDigest(operationEnvelope),
  });
  if (!existing || existing.authorizedOperationId !== authorizedOperationId) {
    return routerAbStepUpError(
      409,
      'authorized_operation_missing',
      'Operation authorization is unavailable',
    );
  }
  if (
    existing.authorization.kind !== 'verified_step_up' ||
    existing.quota.kind !== 'quota_neutral'
  ) {
    return routerAbStepUpError(
      409,
      'authorized_operation_missing',
      'Operation authorization has an invalid source or quota',
    );
  }
  const result = await input.authenticated.authorizedOperations.admitAuthorizedOperation({
    operation: {
      tenantId: existing.tenantId,
      authorizedOperationId: existing.authorizedOperationId,
      auditEventId: existing.auditEventId,
      operation: existing.operation,
      authorization: existing.authorization,
      quota: existing.quota,
      claimedAtMs: Date.now(),
    },
    material: {
      walletId: requireAuthorizationValue(parseWalletId(input.authenticated.session.walletId)),
      keyHandle: input.keyHandle,
      runtimePolicyScope: input.authenticated.session.runtimePolicyScope,
      materialActivation: input.materialActivation,
    },
  });
  if (result.kind === 'material_mismatch') {
    return routerAbStepUpError(
      403,
      'scope_mismatch',
      'ECDSA material activation changed before authorized-operation admission',
    );
  }
  const claimFailure = routerAbOperationStepUpClaimFailure(result);
  if (claimFailure) return claimFailure;
  if (
    result.kind === 'claimed' ||
    result.kind === 'operation_in_progress' ||
    result.kind === 'replayed'
  ) {
    return {
      kind: result.kind,
      operation: result.operation,
    };
  }
  return routerAbStepUpError(
    409,
    'authorized_operation_missing',
    'Authorized operation is unavailable',
  );
}

async function handleRouterAbEcdsaOperationStepUpRoute(input: {
  readonly body: Record<string, unknown>;
  readonly headers: Record<string, string | string[] | undefined>;
  readonly authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  readonly admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  readonly resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
  readonly phase: 'prepare' | 'finalize';
}): Promise<
  | RouterAbJsonRouteResult
  | {
      readonly operation: AuthorizedOperation;
      readonly session: RouterAbOperationStepUpWalletSession;
      readonly admissionKind: RouterAbEcdsaOperationAdmissionKind;
    }
> {
  let request: RouterAbEcdsaOperationStepUpRequest;
  try {
    request = parseRouterAbEcdsaOperationStepUpRequest(input);
  } catch (error: unknown) {
    return routerAbStepUpError(400, 'invalid_body', errorMessage(error));
  }
  if (request.authorization.kind !== 'operation_step_up') {
    return routerAbStepUpError(400, 'invalid_body', 'Operation step-up authority is required');
  }
  const authenticated = await authenticateRouterAbEcdsaOperationStepUp({
    headers: input.headers,
    request,
    authorizedOperations: input.authorizedOperations,
    authorizationSessions: input.authorizationSessions,
    resolveEcdsaMaterialActivation: input.resolveEcdsaMaterialActivation,
  });
  if (!authenticated.ok) return authenticated.error;
  const identityFailure = validateRouterAbEcdsaOperationStepUpIdentity({
    request,
    session: authenticated.session,
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
      'ECDSA operation step-up signer facts changed before authorized-operation admission',
    );
  }
  const claimResult = await claimRouterAbEcdsaOperationStepUp({
    operationKind: 'evm.sign_transaction',
    operation: {
      operation_id: request.operation_id,
      operation_digests: request.operation_digests,
      material_activation: request.material_activation,
    },
    materialActivation: freshMaterial.materialActivation,
    keyHandle: freshMaterial.keyHandle,
    authenticated,
  });
  if (!claimResult) {
    return routerAbStepUpError(
      409,
      'authorized_operation_missing',
      'Authorized operation is unavailable',
    );
  }
  if ('status' in claimResult) return claimResult;
  return {
    operation: claimResult.operation,
    session: authenticated.session,
    admissionKind: claimResult.kind,
  };
}

export async function authorizeRouterAbEcdsaDerivationNormalSigningRoute(input: {
  body: Record<string, unknown>;
  rawBody: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
  authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
  phase: 'prepare' | 'finalize';
}): Promise<RouterAbEcdsaNormalSigningAuthorizationResult> {
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
    const stepUp = await handleRouterAbEcdsaOperationStepUpRoute({
      body: input.body,
      headers: input.headers,
      authorizedOperations: input.authorizedOperations,
      authorizationSessions: input.authorizationSessions,
      admissionAdapter: input.admissionAdapter,
      resolveEcdsaMaterialActivation: input.resolveEcdsaMaterialActivation,
      phase: input.phase,
    });
    if ('status' in stepUp) return { ok: false, result: stepUp };
    return {
      ok: true,
      kind: 'operation_step_up',
      phase: input.phase,
      operation: stepUp.operation,
      session: stepUp.session,
      admissionKind: stepUp.admissionKind,
    };
  }

  const validated = await validateRouterAbEcdsaDerivationWalletSessionInputs({
    body: input.rawBody,
    headers: input.headers,
    authorizationSessions: input.authorizationSessions,
    operationKind: 'evm.sign_transaction',
  });
  if (!validated.ok) {
    if (validated.code === 'wallet_session_unavailable' && input.authorizationSessions) {
      const exhaustedCandidate = await resolveRouterAbEcdsaExhaustedCandidateAuthorization({
        phase: input.phase,
        body: input.body,
        headers: input.headers,
        authorizationSessions: input.authorizationSessions,
        admissionAdapter: input.admissionAdapter,
        resolveEcdsaMaterialActivation: input.resolveEcdsaMaterialActivation,
      });
      if (exhaustedCandidate) return exhaustedCandidate;
    }
    const stepUp = await resolveRouterAbEcdsaOwnerOperationStepUpPreparation({
      body: input.body,
      phase: input.phase,
      resolveEcdsaMaterialActivation: input.resolveEcdsaMaterialActivation,
    });
    return {
      ok: false,
      result: routerAbEcdsaOwnerOperationFailureResult({
        status: routerAbWalletSessionValidationStatus(validated.code),
        code: validated.code,
        message: validated.message,
        phase: input.phase,
        stepUp,
      }),
    };
  }

  const session = validated.admission.context.authorization.session;
  const authorized = await authorizeRouterAbEcdsaWalletSessionRequest({
    phase: input.phase,
    body: input.body,
    session,
    admittedMaterialActivation: routerAbMpcMaterialActivationRefToWire(
      validated.admission.admission.materialActivation,
    ),
    admissionAdapter: input.admissionAdapter,
    resolveEcdsaMaterialActivation: input.resolveEcdsaMaterialActivation,
  });
  if (!authorized.ok) return authorized;
  return {
    ok: true,
    kind: 'wallet_session_operation_credential_v1',
    validated,
    admission: authorized.admission,
    activeMaterial: authorized.activeMaterial,
  };
}

export async function handleRouterAbEcdsaDerivationNormalSigningRouteCore(input: {
  body: Record<string, unknown>;
  rawBody: unknown;
  headers: Record<string, string | string[] | undefined>;
  session: SessionAdapter | null | undefined;
  runtime: RouterAbNormalSigningRouteRuntime | null | undefined;
  authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  admissionAdapter: RouterAbNormalSigningAdmissionAdapter | null | undefined;
  resolveEcdsaMaterialActivation: RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation'];
  privatePath: RouterAbEcdsaDerivationPrivateSigningPath;
  phase: 'prepare' | 'finalize';
}): Promise<RouterAbJsonRouteResult> {
  const authorization = await authorizeRouterAbEcdsaDerivationNormalSigningRoute(input);
  if (!authorization.ok) return authorization.result;
  if (authorization.kind === 'operation_step_up') {
    return routerAbStepUpError(
      500,
      'internal',
      'Operation step-up must execute through the MPC router',
    );
  }
  const walletSession =
    authorization.kind === 'wallet_session_operation_credential_v1'
      ? authorization.validated.admission.context.authorization.session
      : authorization.candidate.status.session;
  const privateBody = await buildRouterAbEcdsaDerivationPrivateSigningWorkerBody({
    phase: input.phase,
    body: input.body,
    authorization: {
      kind: 'wallet_session_operation_credential_v1',
      walletSessionId: String(walletSession.walletSessionId),
      principalId: String(walletSession.principalId),
      runtimePolicyScope: authorization.activeMaterial.runtimePolicyScope,
    },
    headers: input.headers,
  });
  if (!input.authorizedOperations) {
    return routerAbStepUpError(
      501,
      'not_configured',
      'Reusable Wallet Session authorization is not configured',
    );
  }
  const request =
    input.phase === 'prepare'
      ? parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body)
      : parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(input.body);
  const claimed = await admitRouterAbEcdsaReusableWalletSessionOperation({
    request,
    materialActivation: authorization.admission.materialActivation,
    binding:
      authorization.kind === 'wallet_session_operation_credential_v1'
        ? {
            kind: 'wallet_session_operation_credential_v1' as const,
            context: authorization.validated.admission.context,
          }
        : {
            kind: 'wallet_session_operation_credential_exhausted_candidate_v1' as const,
            candidate: authorization.candidate,
          },
    authorizedOperations: input.authorizedOperations,
    resolveEcdsaMaterialActivation: input.resolveEcdsaMaterialActivation,
  });
  if (!claimed.ok) return claimed.error;
  if (claimed.admission.kind === 'replayed') {
    return routerAbEcdsaReplayResult(claimed.admission.operation);
  }
  const runtime = input.runtime;
  if (!runtime) return routerAbEcdsaPrivateSigningWorkerUnavailableResult();
  const signingWorker = runtime.getSigningWorkerPrivateTransport();
  if (signingWorker.kind === 'unconfigured') {
    return routerAbEcdsaPrivateSigningWorkerUnavailableResult();
  }
  if (input.phase === 'prepare') {
    if (claimed.admission.kind === 'operation_in_progress') {
      return routerAbEcdsaOperationInProgressResult();
    }
    const operation = claimed.admission.operation;
    const replay = await runtime.reservePrepareReplay({
      curve: 'ecdsa',
      authorizationIdentity: {
        kind: 'reusable_wallet_session',
        walletSessionId: String(walletSession.walletSessionId),
      },
      requestId: authorization.admission.requestId,
      expiresAtMs: authorization.admission.expiresAtMs,
    });
    if (!replay.ok) {
      await completeRouterAbEcdsaOperation({
        authorizedOperations: input.authorizedOperations,
        operation,
        result: 'failed_before_side_effect',
        response: {
          status: replay.status,
          contentType: 'application/json',
          bodyText: JSON.stringify({ ok: false, code: replay.code, message: replay.message }),
        },
      });
      return {
        status: replay.status,
        body: { ok: false, code: replay.code, message: replay.message },
      };
    }
    const forwarded = await postRouterAbSigningWorkerJson({
      config: signingWorker,
      path: input.privatePath,
      body: privateBody,
    });
    if (!forwarded.ok && !isRouterAbEcdsaSigningWorkerOperationInProgress(forwarded)) {
      await completeRouterAbEcdsaOperation({
        authorizedOperations: input.authorizedOperations,
        operation,
        result: forwarded.status < 500 ? 'failed_before_side_effect' : 'failed_after_side_effect',
        response: replayResponseFromSigningWorkerResult(forwarded),
      });
    }
    return forwarded.ok
      ? { status: 200, body: forwarded.body }
      : { status: forwarded.status, body: forwarded.body };
  }
  if (claimed.admission.kind === 'claimed') {
    return routerAbStepUpError(
      409,
      'authorized_operation_missing',
      'ECDSA finalize requires a claimed prepare operation',
    );
  }
  const forwarded = await postRouterAbSigningWorkerJson({
    config: signingWorker,
    path: input.privatePath,
    body: privateBody,
  });
  await completeRouterAbEcdsaOperation({
    authorizedOperations: input.authorizedOperations,
    operation: claimed.admission.operation,
    result: forwarded.ok
      ? 'succeeded'
      : forwarded.status < 500
        ? 'failed_before_side_effect'
        : 'failed_after_side_effect',
    response: replayResponseFromSigningWorkerResult(forwarded),
  });
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

  return {
    ok: true,
    body: response.json,
    replay: {
      status: response.status,
      contentType: 'application/json',
      bodyText: response.bodyText,
    },
  };
}
