import type { FetchRouterApiContext } from '../createFetchRouter';
import { json, readJson } from '../../../framework/http';
import {} from '../../../../core/ThresholdService/validation';
import type { OpaqueOwnerWalletSessionBinding } from '../../../../authorization/service';
type OpaqueOwnerEcdsaWalletSessionBinding = Extract<
  OpaqueOwnerWalletSessionBinding,
  { readonly curve: 'ecdsa' }
>;
import { thresholdEcdsaStatusCode } from '../../../../threshold/statusCodes';
import {
  issueRouterAbEcdsaDerivationOpaqueWalletSessionToken,
  resolveOpaqueOwnerWalletSessionAdmission,
  validateRouterAbEcdsaDerivationWalletSessionInputs,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../../auth/commonRouterUtils';
import {
  parseRouterAbEcdsaDerivationActivationRefreshCommitRequestV1,
  parseRouterAbEcdsaDerivationExplicitExportRequestV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  parseRouterAbEcdsaOperationStepUpAuthorizationRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1,
  parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
  computeRouterAbEcdsaOperationStepUpChallengeB64u,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH,
  ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
  ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH,
  ROUTER_AB_ECDSA_DERIVATION_SESSION_ACTIVATION_PATH,
  type RouterAbEcdsaDerivationActivationRefreshCommitRequestV1,
  type RouterAbEcdsaDerivationActivationRefreshRequestV1,
  type RouterAbEcdsaDerivationExplicitExportRequestV1,
  type RouterAbEcdsaOperationStepUpAuthorizationRequestV1Wire,
  type RouterAbEcdsaOperationStepUpPreparationV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningRequestV1Wire,
  type RouterAbEcdsaDerivationEvmDigestSigningFinalizeCoreRequestV1Wire,
  type RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  authenticateRouterAbWalletOperationStepUpIdentity,
  authorizeRouterAbEcdsaDerivationNormalSigningRoute,
  admitRouterAbEcdsaReusableWalletSessionOperation,
  claimRouterAbEcdsaOperationStepUp,
  completeRouterAbEcdsaOperation,
  routerAbEcdsaOperationInProgressResult,
  routerAbEcdsaReplayHttpResponse,
  routerAbEcdsaReplayUnavailableResult,
  buildRouterAbEcdsaOwnerOperationStepUpPreparation,
  decideRouterAbEcdsaOwnerOperationAuthorization,
  resolveFreshRouterAbEcdsaMaterialActivation,
  routerAbEcdsaAtomicAuthorizationConfigured,
  routerAbEcdsaOwnerOperationFailureResult,
  type RouterAbEcdsaOperationAdmissionKind,
} from '../../../domains/signingOperations/routerAbPrivateSigningWorker';
import {
  parseRouterAbEcdsaDerivationPoolFillInitRouteRequest,
  parseRouterAbEcdsaDerivationPoolFillStepRouteRequest,
  type RouterAbEcdsaPoolFillInitRouteRequest,
  type RouterAbEcdsaPoolFillStepRouteRequest,
} from '../../../domains/ecdsa/thresholdEcdsaRequestValidation';
import type {
  RouterAbEcdsaDerivationPoolFillInitRequest,
  RouterAbEcdsaDerivationPoolFillStepRequest,
} from '../../../../core/types';
import type {
  RouterAbEcdsaStrictPostRegistrationPort,
  RouterAbEcdsaStrictExportResult,
  RouterAbEcdsaStrictRefreshResult,
  RouterAbEcdsaStrictExportAuthority,
  RouterAbEcdsaStrictRegistrationAuthority,
} from '../../../domains/ecdsa/routerAbEcdsaStrictRegistration';
import type {
  RouterApiAuthorizedOperationService,
  RouterApiAuthorizationSessionService,
  RouterApiWalletAuthMethodService,
} from '../../../framework/authServicePort';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import {
  walletSessionFailure,
  walletSessionFailureStatus,
  type WalletSessionBoundaryFailure,
} from '../../../auth/walletSessionFailure';
import { extractBearerCredential } from '../../../auth/routerApiKeyAuth';
import {
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseEcdsaAuthorizationSessionId,
  type MpcWalletSigningQuotaId,
  type PrincipalId,
  type ReusableWalletSessionMintId,
  type EcdsaAuthorizationSessionId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  parseAuthFactorId,
  parseAuthorizationAuditEventId,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseAuthorizationEvidenceId,
  parseAuthorizationEvidenceSetId,
} from '@shared/authorization/capabilityKinds';
import {
  buildCapabilityOperationEnvelope,
  computeCapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import { buildEvmEcdsaMpcOperationRef } from '@shared/authorization/capabilityKinds';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { AuthorizedOperation, VerifiedOwnerProof } from '../../../../authorization/domain';
import {
  buildVerifiedWalletOperationEmailOtpFactorResult,
  buildVerifiedWalletOperationPasskeyFactorResult,
  type VerifiedWalletOperationFactorResult,
} from '../../../../authorization/factorEvidence';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';

async function verifyActiveEcdsaOperationStepUpAuthority(
  walletAuthMethods: RouterApiWalletAuthMethodService,
  proof: RouterAbEcdsaOperationStepUpAuthorizationRequestV1Wire['proof'],
) {
  switch (proof.kind) {
    case 'passkey':
      return await walletAuthMethods.verifyActivePasskeyAuthority(proof.authority);
    case 'email_otp':
      return await walletAuthMethods.verifyActiveEmailOtpAuthority(proof.authority);
    default:
      proof satisfies never;
      throw new Error('Unsupported ECDSA operation step-up proof');
  }
}
import {
  parseEmailOtpChallengeId,
  parseWalletId,
  parseProviderSubject,
} from '@shared/utils/domainIds';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
} from '@shared/utils/emailOtpDomain';

type VerifiedOwnerWalletSessionProof = Extract<
  VerifiedOwnerProof,
  { readonly purpose: 'wallet_session' }
>;
import { hashEmailOtpOperationBinding } from '../../../domains/emailOtp/emailOtpSessionRouteHelpers';
import { proxyOwnerLaneAdmittedNormalSigningRequest } from './normalSigningRouterProxy';
import { handleLinkedDeviceEcdsaNormalSigning } from './linkedDeviceNormalSigning';
import {
  handleLinkedDeviceEcdsaPresign,
  ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_EXPORT_SHARE_PATH,
  ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_PRESIGN_INIT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_PRESIGN_STEP_PATH,
} from './linkedDeviceEcdsaPresign';
import {
  sameRouterAbMpcMaterialActivationRef,
  type RouterAbMpcMaterialActivationRefWire,
} from '@shared/utils/routerAbNormalSigningIdentity';

const NOT_IMPLEMENTED = {
  ok: false,
  code: 'not_implemented',
  message: 'threshold-ecdsa is not implemented',
} as const;

function requireAuthorizationValue<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

type RouterAbEcdsaAuthorizedOperationWire = {
  readonly binding:
    | {
        readonly kind: 'reusable_wallet_session';
        readonly authorization_id: string;
        readonly wallet_session_id: string;
        readonly quota_id: string;
      }
    | {
        readonly kind: 'gateway_owner_wallet_session';
        readonly subject_id: string;
        readonly account_id: string;
        readonly authorization_session_id: string;
        readonly authorization_id: string;
        readonly wallet_session_id: string;
        readonly quota_id: string;
        readonly threshold_session_id: string;
        readonly org_id: string;
        readonly project_id: string;
        readonly environment: string;
        readonly signing_worker_id: string;
        readonly expires_at_ms: number;
      }
    | {
        readonly kind: 'operation_step_up';
        readonly authorization_session_id: string;
        readonly org_id: string;
        readonly project_id: string;
        readonly environment: string;
        readonly subject_id: string;
      };
  readonly authorized_operation:
    | {
        readonly kind: 'reusable_wallet_session_authorized_operation_v1';
        readonly authorized_operation_id: string;
        readonly operation_id: string;
        readonly capability_kind: 'evm_ecdsa_mpc_signing';
        readonly operation_kind: 'evm.sign_transaction';
        readonly lane_digest_b64u: string;
        readonly intent_digest_b64u: string;
        readonly display_digest_b64u: string;
        readonly operation_fingerprint_digest: string;
      }
    | {
        readonly kind: 'verified_step_up_authorized_operation_v1';
        readonly authorization_session_id: string;
        readonly evidence_set_digest: string;
        readonly authorized_operation_id: string;
        readonly operation_id: string;
        readonly capability_kind: 'evm_ecdsa_mpc_signing';
        readonly operation_kind: 'evm.sign_transaction';
        readonly lane_digest_b64u: string;
        readonly intent_digest_b64u: string;
        readonly display_digest_b64u: string;
        readonly operation_fingerprint_digest: string;
      };
};

type RouterAbEcdsaAuthorizedOperationWireInput =
  | {
      readonly operation: AuthorizedOperation;
      readonly binding: {
        readonly kind: 'reusable_wallet_session';
        readonly walletSessionId: string;
        readonly quotaId: string;
      };
    }
  | {
      readonly operation: AuthorizedOperation;
      readonly binding: {
        readonly kind: 'gateway_owner_wallet_session';
        readonly subjectId: string;
        readonly accountId: string;
        readonly authorizationSessionId: string;
        readonly authorizationId: string;
        readonly walletSessionId: string;
        readonly quotaId: string;
        readonly thresholdSessionId: string;
        readonly orgId: string;
        readonly projectId: string;
        readonly environment: string;
        readonly signingWorkerId: string;
        readonly expiresAtMs: number;
      };
    }
  | {
      readonly operation: AuthorizedOperation;
      readonly binding: {
        readonly kind: 'operation_step_up';
        readonly authorizationSessionId: string;
        readonly orgId: string;
        readonly projectId: string;
        readonly environment: string;
        readonly subjectId: string;
      };
    };

function buildRouterAbEcdsaAuthorizedOperationWire(
  input: RouterAbEcdsaAuthorizedOperationWireInput,
): RouterAbEcdsaAuthorizedOperationWire {
  const operation = input.operation;
  const operationRef = operation.operation.operation;
  if (
    operationRef.capabilityKind !== 'evm_ecdsa_mpc_signing' ||
    operationRef.operationKind !== 'evm.sign_transaction'
  ) {
    throw new Error('ECDSA authorized operation capability or operation kind is invalid');
  }
  const commonAuthorizedOperation = {
    authorized_operation_id: operation.authorizedOperationId,
    operation_id: operation.operation.operationId,
    capability_kind: 'evm_ecdsa_mpc_signing' as const,
    operation_kind: 'evm.sign_transaction' as const,
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
          kind: 'reusable_wallet_session',
          authorization_id: operation.authorization.authorizationGrantRef.authorizationId,
          wallet_session_id: input.binding.walletSessionId,
          quota_id: input.binding.quotaId,
        },
        authorized_operation: {
          kind: 'reusable_wallet_session_authorized_operation_v1',
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
          kind: 'gateway_owner_wallet_session',
          subject_id: input.binding.subjectId,
          account_id: input.binding.accountId,
          authorization_session_id: input.binding.authorizationSessionId,
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
          kind: 'reusable_wallet_session_authorized_operation_v1',
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
          kind: 'operation_step_up',
          authorization_session_id: input.binding.authorizationSessionId,
          org_id: input.binding.orgId,
          project_id: input.binding.projectId,
          environment: input.binding.environment,
          subject_id: input.binding.subjectId,
        },
        authorized_operation: {
          kind: 'verified_step_up_authorized_operation_v1',
          authorization_session_id: input.binding.authorizationSessionId,
          evidence_set_digest: operation.authorization.evidenceSetDigest,
          ...commonAuthorizedOperation,
        },
      };
  }
}

type RouterAbEcdsaOperationStepUpExecutionDecision =
  | { readonly kind: 'execute'; readonly operation: AuthorizedOperation }
  | { readonly kind: 'replay'; readonly operation: AuthorizedOperation }
  | { readonly kind: 'missing' };

export function decideRouterAbEcdsaOperationStepUpExecution(input: {
  readonly phase: 'prepare' | 'finalize';
  readonly admissionKind: RouterAbEcdsaOperationAdmissionKind;
  readonly operation: AuthorizedOperation;
}): RouterAbEcdsaOperationStepUpExecutionDecision {
  if (input.admissionKind === 'replayed') {
    return { kind: 'replay', operation: input.operation };
  }
  if (input.admissionKind === 'claimed' && input.phase === 'finalize') {
    return { kind: 'missing' };
  }
  return { kind: 'execute', operation: input.operation };
}

async function handleRouterAbEcdsaDerivationNormalSigningRoute(input: {
  ctx: FetchRouterApiContext;
  body: Record<string, unknown>;
  phase: 'prepare' | 'finalize';
}): Promise<Response> {
  const authorization = await authorizeRouterAbEcdsaDerivationNormalSigningRoute({
    body: input.body,
    rawBody: input.body,
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    authorizedOperations: input.ctx.service.authorizedOperations,
    authorizationSessions: input.ctx.service.authorizationSessions,
    admissionAdapter: input.ctx.opts.routerAbNormalSigningAdmission,
    resolveEcdsaMaterialActivation:
      input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation.bind(
        input.ctx.service.walletRegistration,
      ),
    phase: input.phase,
  });
  if (!authorization.ok) {
    return json(authorization.result.body, { status: authorization.result.status });
  }
  let authorizedOperation: AuthorizedOperation;
  let authorizedOperationWire: RouterAbEcdsaAuthorizedOperationWire;
  if (authorization.kind === 'operation_step_up') {
    const decision = decideRouterAbEcdsaOperationStepUpExecution({
      phase: input.phase,
      admissionKind: authorization.admissionKind,
      operation: authorization.operation,
    });
    if (decision.kind === 'replay') {
      return routerAbEcdsaReplayResponse(decision.operation);
    }
    if (decision.kind === 'missing') {
      return json(
        {
          ok: false,
          code: 'authorized_operation_missing',
          message: 'ECDSA finalize requires a claimed prepare operation',
        },
        { status: 409 },
      );
    }
    authorizedOperation = decision.operation;
    authorizedOperationWire = buildRouterAbEcdsaAuthorizedOperationWire({
      operation: authorizedOperation,
      binding: {
        kind: 'operation_step_up',
        authorizationSessionId: authorization.session.sessionId,
        orgId: authorization.session.runtimePolicyScope.orgId,
        projectId: authorization.session.runtimePolicyScope.projectId,
        environment: authorization.session.runtimePolicyScope.envId,
        subjectId: authorization.session.principalId,
      },
    });
  } else {
    const request =
      input.phase === 'prepare'
        ? parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body)
        : parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(input.body);
    const operation = await admitRouterAbEcdsaReusableWalletSessionOperation({
      request,
      materialActivation: authorization.admission.materialActivation,
      binding: authorization.validated.binding,
      authorizedOperations: input.ctx.service.authorizedOperations,
      resolveEcdsaMaterialActivation:
        input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation.bind(
          input.ctx.service.walletRegistration,
        ),
    });
    if (!operation.ok) {
      const failureBody = operation.error.body;
      const failureCode =
        typeof failureBody === 'object' &&
        failureBody !== null &&
        'code' in failureBody &&
        typeof failureBody.code === 'string'
          ? failureBody.code
          : 'authorization_unavailable';
      const failureMessage =
        typeof failureBody === 'object' &&
        failureBody !== null &&
        'message' in failureBody &&
        typeof failureBody.message === 'string'
          ? failureBody.message
          : 'ECDSA operation authorization is unavailable';
      const stepUp =
        input.phase === 'prepare'
          ? (buildRouterAbEcdsaOwnerOperationStepUpPreparation({
              request: parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body),
              keyHandle: authorization.validated.binding.keyHandle,
              relayerKeyId: authorization.validated.binding.relayerKeyId,
              participantIds: [...authorization.validated.binding.participantIds],
            }) ?? undefined)
          : undefined;
      const decision = routerAbEcdsaOwnerOperationFailureResult({
        status: operation.error.status,
        code: failureCode,
        message: failureMessage,
        phase: input.phase,
        stepUp,
      });
      return json(decision.body, { status: decision.status });
    }
    if (operation.admission.kind === 'operation_in_progress' && input.phase === 'prepare') {
      const failure = routerAbEcdsaOperationInProgressResult();
      return json(failure.body, { status: failure.status });
    }
    if (operation.admission.kind === 'replayed') {
      return routerAbEcdsaReplayResponse(operation.admission.operation);
    }
    if (operation.admission.kind === 'claimed' && input.phase === 'finalize') {
      return json(
        {
          ok: false,
          code: 'authorized_operation_missing',
          message: 'ECDSA finalize requires a claimed prepare operation',
        },
        { status: 409 },
      );
    }
    const ownerDecision = decideRouterAbEcdsaOwnerOperationAuthorization({
      operation: operation.admission.operation,
    });
    switch (ownerDecision.kind) {
      case 'authorized':
        break;
      case 'denied':
        return json(
          {
            ok: false,
            code: ownerDecision.denial.code,
            message: ownerDecision.denial.message,
            authorization_decision: {
              kind: 'denied' as const,
              denial: ownerDecision.denial,
            },
          },
          { status: 403 },
        );
      case 'step_up_required':
        return json(
          {
            ok: false,
            code: 'authorization_unavailable',
            message: 'ECDSA operation step-up was not admitted',
            authorization_decision: {
              kind: 'denied' as const,
              denial: {
                code: 'authorization_unavailable' as const,
                message: 'ECDSA operation step-up was not admitted',
              },
            },
          },
          { status: 403 },
        );
    }
    authorizedOperation = operation.admission.operation;
    const runtimePolicyScope = authorization.validated.binding.runtimePolicyScope;
    if (!runtimePolicyScope) {
      return json(
        {
          ok: false,
          code: 'wallet_session_scope_mismatch',
          message: 'ECDSA Wallet Session runtime policy scope is required',
        },
        { status: 403 },
      );
    }
    const normalSigning = authorization.validated.binding.routerAbEcdsaDerivationNormalSigning;
    authorizedOperationWire = buildRouterAbEcdsaAuthorizedOperationWire({
      operation: authorizedOperation,
      binding: {
        kind: 'gateway_owner_wallet_session',
        subjectId: authorization.validated.binding.subjectId,
        accountId: authorization.validated.binding.walletId,
        authorizationSessionId: authorization.validated.binding.authorizationSessionId,
        authorizationId: authorization.validated.binding.authorizationId,
        walletSessionId: authorization.validated.binding.walletSessionId,
        quotaId: authorization.validated.binding.quotaId,
        thresholdSessionId: authorization.validated.binding.thresholdSessionId,
        orgId: runtimePolicyScope.orgId,
        projectId: runtimePolicyScope.projectId,
        environment: runtimePolicyScope.envId,
        signingWorkerId: normalSigning.scope.signing_worker.server_id,
        expiresAtMs: authorization.validated.binding.thresholdExpiresAtMs,
      },
    });
  }
  const signingRequest =
    input.phase === 'prepare'
      ? parseRouterAbEcdsaDerivationEvmDigestSigningRequestV1(input.body)
      : parseRouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1(input.body);
  const signingWalletId = parseWalletId(signingRequest.scope.wallet_id);
  if (!signingWalletId.ok) {
    return json(
      { ok: false, code: 'invalid_body', message: 'ECDSA signing wallet is invalid' },
      { status: 400 },
    );
  }
  const laneAuthorization =
    authorization.kind === 'operation_step_up'
      ? {
          kind: 'authority_ref' as const,
          authorityRef: authorization.session.walletAuthAuthorityRef,
          authSource: authorization.session.authSource,
        }
      : {
          kind: 'authority_ref' as const,
          authorityRef: authorization.validated.walletSessionAuth.walletAuthAuthorityRef,
          authSource: authorization.validated.walletSessionAuth.authSource,
        };
  const upstream = await proxyOwnerLaneAdmittedNormalSigningRequest({
    request: input.ctx.request,
    proxy: input.ctx.opts.routerAbNormalSigningRouterProxy,
    authorizedOperation,
    walletId: signingWalletId.value,
    expectedMaterialActivation: signingRequest.material_activation,
    authorization: laneAuthorization,
    walletRegistration: input.ctx.service.walletRegistration,
    body: {
      ...input.body,
      authorized_operation: authorizedOperationWire,
    },
  });
  const upstreamBodyText = await upstream
    .clone()
    .text()
    .catch(() => '');
  if (
    isRouterAbEcdsaOperationInProgressResponse({
      status: upstream.status,
      bodyText: upstreamBodyText,
    })
  ) {
    return upstream;
  }
  if (input.phase === 'prepare' && upstream.ok) {
    return upstream;
  }
  await completeRouterAbEcdsaOperation({
    authorizedOperations: input.ctx.service.authorizedOperations,
    operation: authorizedOperation,
    result: upstream.ok
      ? 'succeeded'
      : upstream.status < 500
        ? 'failed_before_side_effect'
        : 'failed_after_side_effect',
    response: {
      status: upstream.status,
      contentType: upstream.headers.get('content-type') || 'application/json',
      bodyText: upstreamBodyText,
    },
  });
  return upstream;
}

function isRouterAbEcdsaOperationInProgressResponse(input: {
  readonly status: number;
  readonly bodyText: string;
}): boolean {
  return (
    input.status === 409 &&
    input.bodyText.includes('ReplayedLocalRequest:') &&
    input.bodyText.includes('SigningWorker ECDSA effect is already in progress')
  );
}

function routerAbEcdsaReplayResponse(operation: AuthorizedOperation): Response {
  const response = routerAbEcdsaReplayHttpResponse(operation);
  if (response) return response;
  const failure = routerAbEcdsaReplayUnavailableResult();
  return json(failure.body, { status: failure.status });
}

async function issueEcdsaOperationStepUpAuthorization(input: {
  readonly ctx: FetchRouterApiContext;
  readonly request: RouterAbEcdsaOperationStepUpAuthorizationRequestV1Wire;
}): Promise<Response> {
  if (!routerAbEcdsaAtomicAuthorizationConfigured(input.ctx.service.authorizedOperations)) {
    return json(
      {
        ok: false,
        code: 'not_configured',
        message: 'ECDSA atomic authorization is not configured',
      },
      { status: 501 },
    );
  }
  const operation = input.request.operation;
  if (
    operation.normal_signing_scope.wallet_id !== operation.wallet_id ||
    operation.normal_signing_scope.signing_worker.server_id !== operation.signing_worker_id ||
    operation.material_activation.material_owner !== operation.wallet_id ||
    operation.material_activation.signing_worker !== operation.signing_worker_id ||
    operation.expires_at_ms <= Date.now()
  ) {
    return json(
      { ok: false, code: 'scope_mismatch', message: 'ECDSA operation step-up scope is invalid' },
      { status: 403 },
    );
  }
  const activeMaterial = await input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation({
    walletId: operation.wallet_id,
    materialActivation: operation.material_activation,
  });
  if (!activeMaterial.ok) {
    return json(
      {
        ok: false,
        code: activeMaterial.code,
        message: activeMaterial.message,
      },
      { status: activeMaterial.code === 'internal' ? 500 : 403 },
    );
  }
  if (
    activeMaterial.keyHandle !== operation.key_handle ||
    activeMaterial.relayerKeyId !== operation.relayer_key_id ||
    activeMaterial.participantIds[0] !== operation.participant_ids[0] ||
    activeMaterial.participantIds[1] !== operation.participant_ids[1] ||
    !sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      operation.normal_signing_scope.material_activation,
    )
  ) {
    return json(
      {
        ok: false,
        code: 'scope_mismatch',
        message: 'ECDSA normal-signing scope does not name the active material',
      },
      { status: 403 },
    );
  }
  const proof = input.request.proof;
  const authority = proof.authority;
  const activeAuthority = await verifyActiveEcdsaOperationStepUpAuthority(
    input.ctx.service.walletAuthMethods,
    proof,
  );
  if (!activeAuthority.ok) {
    return json(
      { ok: false, code: 'scope_mismatch', message: 'Operation step-up authority is not active' },
      { status: 403 },
    );
  }
  const authenticated = await authenticateRouterAbWalletOperationStepUpIdentity({
    kind: 'verified_owner_proof',
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    walletId: operation.wallet_id,
    materialOwner: operation.material_activation.material_owner,
    operationId: operation.operation_id,
    authority,
    runtimePolicyScope: activeMaterial.runtimePolicyScope,
    expiresAtMs: operation.expires_at_ms,
    authorizedOperations: input.ctx.service.authorizedOperations,
  });
  if (!authenticated.ok) {
    return json(authenticated.error.body, { status: authenticated.error.status });
  }
  if (authority.walletId !== authenticated.session.walletId) {
    return json(
      { ok: false, code: 'scope_mismatch', message: 'Operation step-up authority changed' },
      { status: 403 },
    );
  }
  let envelope: ReturnType<typeof buildCapabilityOperationEnvelope>;
  try {
    envelope = buildCapabilityOperationEnvelope({
      tenantId: authenticated.session.tenantId,
      principalId: authenticated.session.principalId,
      capabilityId: requireAuthorizationValue(
        parseCapabilityId(activeMaterial.materialActivation.capability),
      ),
      operationId: requireAuthorizationValue(parseCapabilityOperationId(operation.operation_id)),
      operation: buildEvmEcdsaMpcOperationRef(operation.operation_kind),
      digests: {
        laneDigest: parseDigestB64u(operation.operation_digests.lane_digest_b64u),
        intentDigest: parseDigestB64u(operation.operation_digests.intent_digest_b64u),
        displayDigest: parseDigestB64u(operation.operation_digests.display_digest_b64u),
      },
    });
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: error instanceof Error ? error.message : 'Operation fingerprint is invalid',
      },
      { status: 400 },
    );
  }
  const expectedChallenge = await computeRouterAbEcdsaOperationStepUpChallengeB64u(operation);
  const nowMs = Date.now();
  const requestId = operation.operation_id;
  const freshMaterial = await resolveFreshRouterAbEcdsaMaterialActivation({
    resolveEcdsaMaterialActivation:
      input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation.bind(
        input.ctx.service.walletRegistration,
      ),
    walletId: authenticated.session.walletId,
    expected: operation.material_activation,
  });
  if (!freshMaterial.ok) {
    return json(
      {
        ok: false,
        code: freshMaterial.code === 'internal' ? 'internal' : 'scope_mismatch',
        message: freshMaterial.message,
      },
      { status: freshMaterial.code === 'internal' ? 500 : 403 },
    );
  }
  if (
    freshMaterial.keyHandle !== operation.key_handle ||
    freshMaterial.relayerKeyId !== operation.relayer_key_id ||
    freshMaterial.participantIds[0] !== operation.participant_ids[0] ||
    freshMaterial.participantIds[1] !== operation.participant_ids[1] ||
    !sameRouterAbMpcMaterialActivationRef(
      freshMaterial.materialActivation,
      operation.normal_signing_scope.material_activation,
    )
  ) {
    return json(
      {
        ok: false,
        code: 'scope_mismatch',
        message: 'ECDSA operation step-up material changed before evidence admission',
      },
      { status: 403 },
    );
  }
  const evidenceId = requireAuthorizationValue(
    parseAuthorizationEvidenceId(`ecdsa-step-up-evidence:${requestId}`),
  );
  const evidenceSetId = requireAuthorizationValue(
    parseAuthorizationEvidenceSetId(`ecdsa-step-up-evidence-set:${requestId}`),
  );
  const expiresAtMs = operation.expires_at_ms;
  const requestOrigin = authenticated.requestOrigin;
  let emailOtpUnseal: { readonly grant: string; readonly challengeId: string } | undefined;
  let factor!: VerifiedWalletOperationFactorResult;
  switch (proof.kind) {
    case 'passkey': {
      if (
        authenticated.session.authSource.kind !== 'passkey' ||
        proof.authority.factor.credentialIdB64u !==
          authenticated.session.authSource.credentialIdB64u
      ) {
        return json(
          { ok: false, code: 'scope_mismatch', message: 'Passkey authority changed' },
          { status: 403 },
        );
      }
      const credential = proof.webauthn_authentication;
      const credentialId = String(credential.rawId || credential.id).trim();
      if (credentialId !== authenticated.session.authSource.credentialIdB64u) {
        return json(
          { ok: false, code: 'unauthorized', message: 'Passkey credential changed' },
          { status: 401 },
        );
      }
      const verified = await input.ctx.service.webAuthn.verifyWebAuthnAuthenticationLite({
        userId: authenticated.session.walletId,
        rpId: proof.authority.verifier.rpId,
        expectedChallenge,
        expected_origin: requestOrigin,
        webauthn_authentication: credential,
      });
      if (!verified.success || !verified.verified) {
        return json(
          {
            ok: false,
            code: verified.code || 'not_verified',
            message: verified.message || 'WebAuthn authentication verification failed',
          },
          { status: 401 },
        );
      }
      factor = buildVerifiedWalletOperationPasskeyFactorResult({
        tenantId: authenticated.session.tenantId,
        principalId: authenticated.session.principalId,
        walletId: walletIdFromString(authenticated.session.walletId),
        requestOrigin,
        audience: requestOrigin,
        factorId: requireAuthorizationValue(
          parseAuthFactorId(`passkey:${authenticated.session.authSource.credentialIdB64u}`),
        ),
        authorityRef: authenticated.authorityRef,
        operation: envelope,
        credentialIdB64u: proof.authority.factor.credentialIdB64u,
        assertionDigest: parseDigestB64u(
          base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(credential))),
        ),
        verifiedAtMs: nowMs,
        expiresAtMs,
      });
      break;
    }
    case 'email_otp': {
      const operationBinding = await hashEmailOtpOperationBinding({
        walletId: authenticated.session.walletId,
        providerUserId: proof.authority.factor.providerUserId,
        orgId: authenticated.session.tenantId,
        operation:
          operation.operation_kind === 'evm.export_key'
            ? WALLET_EMAIL_OTP_EXPORT_OPERATION
            : WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
        requestOrigin,
        audience: requestOrigin,
        authorityRef: authenticated.authorityRef,
      });
      const verified = await input.ctx.service.emailOtp.verifyEmailOtpChallenge({
        userId: authenticated.session.principalId,
        walletId: authenticated.session.walletId,
        orgId: authenticated.session.tenantId,
        challengeId: proof.challenge_id,
        otpCode: proof.otp_code,
        otpChannel: EMAIL_OTP_CHANNEL,
        ownerProofBindingDigest: operationBinding,
        operation:
          operation.operation_kind === 'evm.export_key'
            ? WALLET_EMAIL_OTP_EXPORT_OPERATION
            : WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      });
      if (!verified.ok) {
        return json(verified, { status: verified.code === 'invalid_body' ? 400 : 401 });
      }
      const consumed =
        operation.operation_kind === 'evm.export_key'
          ? null
          : await input.ctx.service.emailOtp.consumeEmailOtpGrant({
              subject: {
                kind: 'authorization_session',
                tenantId: authenticated.session.tenantId,
                principalId: authenticated.session.principalId,
                walletId: walletIdFromString(authenticated.session.walletId),
              },
              loginGrant: verified.loginGrant,
              otpChannel: EMAIL_OTP_CHANNEL,
            });
      if (consumed && !consumed.ok) {
        return json(consumed, { status: consumed.code === 'invalid_body' ? 400 : 401 });
      }
      if (operation.operation_kind === 'evm.export_key') {
        emailOtpUnseal = {
          grant: verified.loginGrant,
          challengeId: verified.challengeId,
        };
      }
      const verifiedChallengeId = consumed?.ok ? consumed.challengeId : verified.challengeId;
      factor = buildVerifiedWalletOperationEmailOtpFactorResult({
        tenantId: authenticated.session.tenantId,
        principalId: authenticated.session.principalId,
        walletId: walletIdFromString(authenticated.session.walletId),
        requestOrigin,
        audience: requestOrigin,
        factorId: requireAuthorizationValue(
          parseAuthFactorId(
            `email_otp:${proof.authority.factor.provider}:${proof.authority.factor.providerUserId}`,
          ),
        ),
        authorityRef: authenticated.authorityRef,
        operation: envelope,
        challengeId: requireAuthorizationValue(parseEmailOtpChallengeId(verifiedChallengeId)),
        verificationReceiptDigest: parseDigestB64u(
          base64UrlEncode(
            await sha256BytesUtf8(
              alphabetizeStringify({
                challengeId: verifiedChallengeId,
                operationFingerprint: expectedChallenge,
              }),
            ),
          ),
        ),
        verifiedAtMs: nowMs,
        expiresAtMs: Math.min(expiresAtMs, verified.grantExpiresAtMs),
      });
      break;
    }
  }
  const evidenceSet =
    await input.ctx.service.authorizedOperations.recordVerifiedWalletOperationFactorEvidenceSet({
      operation: envelope,
      evidenceId,
      evidenceSetId,
      factor,
    });
  const authorizedOperationId = requireAuthorizationValue(
    parseAuthorizedOperationId(`ecdsa-step-up-authorized-operation:${operation.operation_id}`),
  );
  const atomicOperation = await input.ctx.service.authorizedOperations.admitAuthorizedOperation({
    operation: {
      tenantId: authenticated.session.tenantId,
      authorizedOperationId,
      auditEventId: requireAuthorizationValue(
        parseAuthorizationAuditEventId(`ecdsa-operation-audit:${operation.operation_id}`),
      ),
      operation: envelope,
      authorization: {
        kind: 'verified_step_up',
        evidenceSetDigest: evidenceSet.evidenceSetDigest,
      },
      quota: { kind: 'quota_neutral' },
      claimedAtMs: nowMs,
    },
    material: {
      walletId: walletIdFromString(authenticated.session.walletId),
      keyHandle: freshMaterial.keyHandle,
      runtimePolicyScope: authenticated.session.runtimePolicyScope,
      materialActivation: freshMaterial.materialActivation,
    },
  });
  switch (atomicOperation.kind) {
    case 'claimed':
    case 'operation_in_progress':
    case 'replayed':
      break;
    case 'material_mismatch':
      return json(
        {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA material activation changed before authorized-operation admission',
        },
        { status: 403 },
      );
    case 'authorization_grant_rejected':
    case 'verified_step_up_rejected':
      return json(
        {
          ok: false,
          code: atomicOperation.kind,
          message: 'ECDSA operation step-up authorization is invalid',
        },
        { status: 403 },
      );
    case 'wallet_session_quota_exhausted':
      return json(
        {
          ok: false,
          code: atomicOperation.kind,
          message: 'ECDSA operation step-up authorization is unavailable',
        },
        { status: 409 },
      );
  }
  return json(
    {
      ok: true,
      kind: 'verified_step_up',
      authorization: {
        kind: 'operation_step_up',
        evidence_set_digest: evidenceSet.evidenceSetDigest,
        unseal: emailOtpUnseal
          ? {
              kind: 'email_otp_grant',
              grant: emailOtpUnseal.grant,
              challenge_id: emailOtpUnseal.challengeId,
            }
          : { kind: 'not_requested' },
      },
      expires_at_ms: expiresAtMs,
    },
    { status: 200 },
  );
}

type RouterAbEcdsaPoolFillBinding = Omit<
  Pick<
    OpaqueOwnerEcdsaWalletSessionBinding,
    | 'walletId'
    | 'relayerKeyId'
    | 'keyHandle'
    | 'runtimePolicyScope'
    | 'participantIds'
    | 'thresholdExpiresAtMs'
    | 'routerAbEcdsaDerivationNormalSigning'
  >,
  'participantIds'
> & { readonly participantIds: number[] };

type RouterAbEcdsaPoolFillAuthorizationResult =
  | {
      readonly ok: true;
      readonly binding: RouterAbEcdsaPoolFillBinding;
    }
  | {
      readonly ok: false;
      readonly error: {
        readonly status: number;
        readonly body: unknown;
      };
    };

function poolFillMaterialActivation(
  request: RouterAbEcdsaPoolFillInitRouteRequest | RouterAbEcdsaPoolFillStepRouteRequest,
): RouterAbMpcMaterialActivationRefWire | null {
  return 'poolFill' in request ? request.poolFill.scope.material_activation : null;
}

function validateEcdsaPoolFillOperationIdentity(
  operation: RouterAbEcdsaOperationStepUpPreparationV1Wire,
): boolean {
  return (
    operation.wallet_id === operation.normal_signing_scope.wallet_id &&
    operation.signing_worker_id === operation.normal_signing_scope.signing_worker.server_id &&
    operation.material_activation.material_owner === operation.wallet_id &&
    operation.material_activation.signing_worker === operation.signing_worker_id &&
    sameRouterAbMpcMaterialActivationRef(
      operation.material_activation,
      operation.normal_signing_scope.material_activation,
    ) &&
    operation.expires_at_ms > Date.now()
  );
}

async function authorizeEcdsaPoolFillOperationStepUp(input: {
  readonly ctx: FetchRouterApiContext;
  readonly authorization: Extract<
    RouterAbEcdsaPoolFillInitRouteRequest['authorization'],
    { readonly kind: 'operation_step_up' }
  >;
  readonly operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
  readonly poolFillMaterialActivation: RouterAbMpcMaterialActivationRefWire | null;
}): Promise<RouterAbEcdsaPoolFillAuthorizationResult> {
  if (!validateEcdsaPoolFillOperationIdentity(input.operation)) {
    return {
      ok: false,
      error: {
        status: 403,
        body: {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA pool-fill operation scope is invalid',
        },
      },
    };
  }
  const ownerAdmissionInput = {
    kind: 'opaque_wallet_session' as const,
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    walletId: input.operation.wallet_id,
    materialOwner: input.operation.material_activation.material_owner,
    authorizedOperations: input.ctx.service.authorizedOperations,
    authorizationSessions: input.ctx.service.authorizationSessions,
  };
  const ecdsaOwner = await authenticateRouterAbWalletOperationStepUpIdentity({
    ...ownerAdmissionInput,
    curve: 'ecdsa',
  });
  const authenticated = ecdsaOwner.ok
    ? ecdsaOwner
    : await authenticateRouterAbWalletOperationStepUpIdentity({
        ...ownerAdmissionInput,
        curve: 'ed25519',
      });
  if (!authenticated.ok) return authenticated;
  const activeMaterial = await input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation({
    walletId: authenticated.session.walletId,
    materialActivation: input.operation.material_activation,
  });
  if (!activeMaterial.ok) {
    return {
      ok: false,
      error: {
        status: activeMaterial.code === 'internal' ? 500 : 403,
        body: {
          ok: false,
          code: activeMaterial.code === 'internal' ? 'internal' : 'scope_mismatch',
          message:
            activeMaterial.code === 'internal'
              ? activeMaterial.message
              : 'ECDSA pool-fill material is no longer active',
        },
      },
    };
  }
  if (
    activeMaterial.keyHandle !== input.operation.key_handle ||
    activeMaterial.relayerKeyId !== input.operation.relayer_key_id ||
    activeMaterial.participantIds[0] !== input.operation.participant_ids[0] ||
    activeMaterial.participantIds[1] !== input.operation.participant_ids[1] ||
    !sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      input.operation.material_activation,
    ) ||
    !sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      input.operation.normal_signing_scope.material_activation,
    ) ||
    (input.poolFillMaterialActivation !== null &&
      !sameRouterAbMpcMaterialActivationRef(
        activeMaterial.materialActivation,
        input.poolFillMaterialActivation,
      ))
  ) {
    return {
      ok: false,
      error: {
        status: 403,
        body: {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA pool-fill scopes do not name the active material',
        },
      },
    };
  }
  const freshMaterial = await resolveFreshRouterAbEcdsaMaterialActivation({
    resolveEcdsaMaterialActivation:
      input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation.bind(
        input.ctx.service.walletRegistration,
      ),
    walletId: authenticated.session.walletId,
    expected: input.operation.material_activation,
  });
  if (!freshMaterial.ok) {
    return {
      ok: false,
      error: {
        status: freshMaterial.code === 'internal' ? 500 : 403,
        body: {
          ok: false,
          code: freshMaterial.code === 'internal' ? 'internal' : 'scope_mismatch',
          message: freshMaterial.message,
        },
      },
    };
  }
  if (
    freshMaterial.keyHandle !== input.operation.key_handle ||
    freshMaterial.relayerKeyId !== input.operation.relayer_key_id ||
    freshMaterial.participantIds[0] !== input.operation.participant_ids[0] ||
    freshMaterial.participantIds[1] !== input.operation.participant_ids[1] ||
    !sameRouterAbMpcMaterialActivationRef(
      freshMaterial.materialActivation,
      input.operation.normal_signing_scope.material_activation,
    ) ||
    (input.poolFillMaterialActivation !== null &&
      !sameRouterAbMpcMaterialActivationRef(
        freshMaterial.materialActivation,
        input.poolFillMaterialActivation,
      ))
  ) {
    return {
      ok: false,
      error: {
        status: 403,
        body: {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA pool-fill material changed before operation admission',
        },
      },
    };
  }
  const claimFailure = await claimRouterAbEcdsaOperationStepUp({
    operationKind: 'evm.sign_transaction',
    operation: input.operation,
    materialActivation: freshMaterial.materialActivation,
    keyHandle: freshMaterial.keyHandle,
    authenticated,
  });
  if (claimFailure && 'status' in claimFailure) {
    return {
      ok: false,
      error: claimFailure,
    };
  }
  const walletId = parseWalletId(input.operation.wallet_id);
  if (!walletId.ok) {
    return {
      ok: false,
      error: {
        status: 403,
        body: { ok: false, code: 'scope_mismatch', message: 'ECDSA wallet identity is invalid' },
      },
    };
  }
  return {
    ok: true,
    binding: {
      walletId: walletId.value,
      relayerKeyId: input.operation.relayer_key_id,
      keyHandle: input.operation.key_handle,
      runtimePolicyScope: authenticated.session.runtimePolicyScope,
      participantIds: [...input.operation.participant_ids],
      thresholdExpiresAtMs: input.operation.expires_at_ms,
      routerAbEcdsaDerivationNormalSigning: {
        kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
        scope: input.operation.normal_signing_scope,
      },
    },
  };
}

async function authorizeEcdsaPoolFill(input: {
  readonly ctx: FetchRouterApiContext;
  readonly request: RouterAbEcdsaPoolFillInitRouteRequest | RouterAbEcdsaPoolFillStepRouteRequest;
}): Promise<RouterAbEcdsaPoolFillAuthorizationResult> {
  switch (input.request.authorization.kind) {
    case 'reusable_wallet_session': {
      const validated = await validateRouterAbEcdsaDerivationWalletSessionInputs({
        body: input.request,
        headers: Object.fromEntries(input.ctx.request.headers.entries()),
        authorizationSessions: input.ctx.service.authorizationSessions,
      });
      if (!validated.ok) {
        return {
          ok: false,
          error: {
            status: thresholdEcdsaStatusCode(validated),
            body: validated,
          },
        };
      }
      if (input.request.authorization.wallet_session_id !== validated.binding.walletSessionId) {
        return {
          ok: false,
          error: {
            status: 403,
            body: {
              ok: false,
              code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
              message: 'Pool-fill authorization does not match the Wallet Session',
            },
          },
        };
      }
      if (!validated.binding.runtimePolicyScope) {
        return {
          ok: false,
          error: {
            status: 403,
            body: {
              ok: false,
              code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
              message: 'Pool-fill Wallet Session runtime policy scope is missing',
            },
          },
        };
      }
      const normalSigning = validated.binding.routerAbEcdsaDerivationNormalSigning;
      const requestedPoolFillMaterial = poolFillMaterialActivation(input.request);
      const activeMaterial =
        await input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation({
          walletId: validated.binding.walletId,
          materialActivation: normalSigning.scope.material_activation,
        });
      if (!activeMaterial.ok) {
        return {
          ok: false,
          error: {
            status: activeMaterial.code === 'internal' ? 500 : 403,
            body: {
              ok: false,
              code:
                activeMaterial.code === 'internal'
                  ? 'internal'
                  : WALLET_SESSION_FAILURE_CODES.scopeMismatch,
              message:
                activeMaterial.code === 'internal'
                  ? activeMaterial.message
                  : 'Pool-fill Wallet Session material is no longer active',
            },
          },
        };
      }
      if (
        !sameRouterAbMpcMaterialActivationRef(
          activeMaterial.materialActivation,
          normalSigning.scope.material_activation,
        ) ||
        (requestedPoolFillMaterial !== null &&
          !sameRouterAbMpcMaterialActivationRef(
            activeMaterial.materialActivation,
            requestedPoolFillMaterial,
          ))
      ) {
        return {
          ok: false,
          error: {
            status: 403,
            body: {
              ok: false,
              code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
              message: 'Pool-fill scopes do not match the active material',
            },
          },
        };
      }
      return {
        ok: true,
        binding: {
          walletId: validated.binding.walletId,
          relayerKeyId: validated.binding.relayerKeyId,
          keyHandle: validated.binding.keyHandle,
          runtimePolicyScope: validated.binding.runtimePolicyScope,
          participantIds: [...validated.binding.participantIds],
          thresholdExpiresAtMs: validated.binding.thresholdExpiresAtMs,
          routerAbEcdsaDerivationNormalSigning:
            validated.binding.routerAbEcdsaDerivationNormalSigning,
        },
      };
    }
    case 'operation_step_up': {
      const operation = input.request.operation;
      if (!operation) {
        return {
          ok: false,
          error: {
            status: 400,
            body: {
              ok: false,
              code: 'invalid_body',
              message: 'Operation step-up pool fill requires operation preparation',
            },
          },
        };
      }
      return authorizeEcdsaPoolFillOperationStepUp({
        ctx: input.ctx,
        authorization: input.request.authorization,
        operation,
        poolFillMaterialActivation: poolFillMaterialActivation(input.request),
      });
    }
  }
}

function ecdsaPoolFillInitRuntimeRequest(
  request: RouterAbEcdsaPoolFillInitRouteRequest,
): RouterAbEcdsaDerivationPoolFillInitRequest {
  return {
    ...(request.keyHandle === undefined ? {} : { keyHandle: request.keyHandle }),
    ...(request.ecdsaThresholdKeyId === undefined
      ? {}
      : { ecdsaThresholdKeyId: request.ecdsaThresholdKeyId }),
    ...(request.count === undefined ? {} : { count: request.count }),
    ...(request.requestTag === undefined ? {} : { requestTag: request.requestTag }),
    poolFill: request.poolFill,
  };
}

function ecdsaPoolFillStepRuntimeRequest(
  request: RouterAbEcdsaPoolFillStepRouteRequest,
): RouterAbEcdsaDerivationPoolFillStepRequest {
  return {
    presignSessionId: request.presignSessionId,
    stage: request.stage,
    ...(request.outgoingMessagesB64u === undefined
      ? {}
      : { outgoingMessagesB64u: request.outgoingMessagesB64u }),
    ...(request.requestTag === undefined ? {} : { requestTag: request.requestTag }),
  };
}

type PresignTrafficClass = 'foreground' | 'background';

type PresignPriorityTicket = {
  release: () => void;
};

class PresignPriorityGate {
  private foregroundInFlight = 0;
  private backgroundInFlight = 0;
  private readonly backgroundQueue: Array<{
    resolve: (ticket: PresignPriorityTicket) => void;
  }> = [];

  async acquire(trafficClass: PresignTrafficClass): Promise<PresignPriorityTicket> {
    if (trafficClass === 'foreground') {
      this.foregroundInFlight += 1;
      return this.createTicket('foreground');
    }
    if (this.canRunBackgroundNow()) {
      this.backgroundInFlight += 1;
      return this.createTicket('background');
    }
    return await new Promise((resolve) => {
      this.backgroundQueue.push({ resolve });
    });
  }

  private createTicket(trafficClass: PresignTrafficClass): PresignPriorityTicket {
    let released = false;
    return {
      release: () => {
        if (released) return;
        released = true;
        if (trafficClass === 'foreground') {
          this.foregroundInFlight = Math.max(0, this.foregroundInFlight - 1);
        } else {
          this.backgroundInFlight = Math.max(0, this.backgroundInFlight - 1);
        }
        this.drainBackgroundQueue();
      },
    };
  }

  private canRunBackgroundNow(): boolean {
    return this.foregroundInFlight === 0 && this.backgroundInFlight === 0;
  }

  private drainBackgroundQueue(): void {
    if (!this.canRunBackgroundNow()) return;
    const next = this.backgroundQueue.shift();
    if (!next) return;
    this.backgroundInFlight += 1;
    next.resolve(this.createTicket('background'));
  }
}

function parsePresignRequestTag(body: unknown): string | undefined {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return undefined;
  const tag = String((body as { requestTag?: unknown }).requestTag || '').trim();
  return tag || undefined;
}

function resolvePresignTrafficClass(requestTag: string | undefined): PresignTrafficClass {
  return requestTag === 'background_presign_pool_refill' ? 'background' : 'foreground';
}

const presignPriorityGate = new PresignPriorityGate();

type StrictEcdsaPostRegistrationRequest =
  | {
      readonly kind: 'export';
      readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
      readonly requestDigestB64u: string;
    }
  | {
      readonly kind: 'refresh';
      readonly command: RouterAbEcdsaDerivationActivationRefreshCommitRequestV1;
      readonly request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
      readonly requestDigestB64u: string;
    };

type StrictEcdsaPostRegistrationAuthorization =
  | {
      readonly ok: true;
      readonly kind: 'opaque_wallet_session';
      readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
      readonly ecdsaBinding: OpaqueOwnerEcdsaWalletSessionBinding | null;
    }
  | {
      readonly ok: true;
      readonly kind: 'verified_operation';
      readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
      readonly ecdsaBinding?: never;
    }
  | {
      readonly ok: false;
      readonly code: 'unauthorized' | 'identity_mismatch';
      readonly message: string;
    }
  | WalletSessionBoundaryFailure;

type StrictEcdsaAuthorizationBinding = {
  readonly ecdsaBinding: OpaqueOwnerEcdsaWalletSessionBinding;
  readonly expiresAtMs: number;
};

type StrictEcdsaAuthorizationBindingResult =
  | { readonly ok: true; readonly binding: StrictEcdsaAuthorizationBinding }
  | WalletSessionBoundaryFailure;

type OpaqueOwnerWalletSessionAdmissionValue = NonNullable<
  Awaited<ReturnType<typeof resolveOpaqueOwnerWalletSessionAdmission>>
>;
type OpaqueEcdsaOwnerWalletSessionAdmission = Extract<
  OpaqueOwnerWalletSessionAdmissionValue,
  { readonly curve: 'ecdsa' }
>;

function strictEcdsaAuthorizationFailureStatus(
  failure: Extract<StrictEcdsaPostRegistrationAuthorization, { readonly ok: false }>,
): number {
  switch (failure.code) {
    case 'unauthorized':
      return 401;
    case 'identity_mismatch':
      return 403;
    default:
      return walletSessionFailureStatus(failure.code);
  }
}

async function resolveStrictEcdsaAuthorizationSession(
  ctx: FetchRouterApiContext,
): Promise<
  | { readonly ok: true; readonly admission: OpaqueEcdsaOwnerWalletSessionAdmission }
  | WalletSessionBoundaryFailure
> {
  const token = extractBearerCredential(ctx.request.headers);
  if (!token) return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.missing);
  try {
    const nowMs = Date.now();
    const resolved = await resolveOpaqueOwnerWalletSessionAdmission({
      authorizationSessions: ctx.service.authorizationSessions,
      token,
      curve: 'ecdsa',
      nowMs,
    });
    if (!resolved || resolved.curve !== 'ecdsa') {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.invalid);
    }
    return { ok: true, admission: resolved };
  } catch {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
  }
}

async function resolveStrictEcdsaAuthorizationBinding(input: {
  readonly admission: OpaqueEcdsaOwnerWalletSessionAdmission;
}): Promise<StrictEcdsaAuthorizationBindingResult> {
  const ecdsaBinding = input.admission.binding;
  const expiresAtMs = ecdsaBinding.thresholdExpiresAtMs;
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= 0) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.invalid);
  }
  if (expiresAtMs <= Date.now()) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.expired);
  }
  return {
    ok: true,
    binding: {
      ecdsaBinding,
      expiresAtMs,
    },
  };
}

/**
 * Every post-registration call carries `{request, requestDigestB64u}`.
 *
 * The digest is not trusted here — Router recomputes it from the forwarded
 * request — but the Gateway must sign a request policy over it, so the caller
 * has to state which request the policy covers.
 */
function parseStrictEcdsaRequestDigestEnvelope(
  body: unknown,
  label: string,
): { readonly request: unknown; readonly requestDigestB64u: string } {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error(`Strict ECDSA ${label} body must be an object`);
  }
  const record = body as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.length !== 2 || keys[0] !== 'request' || keys[1] !== 'requestDigestB64u') {
    throw new Error(`Strict ECDSA ${label} body fields are invalid`);
  }
  const requestDigestB64u = String(record.requestDigestB64u || '').trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(requestDigestB64u)) {
    throw new Error(`Strict ECDSA ${label} request digest must contain 32 base64url bytes`);
  }
  return { request: record.request, requestDigestB64u };
}

function parseStrictEcdsaPostRegistrationRequest(
  pathname: string,
  body: unknown,
): StrictEcdsaPostRegistrationRequest {
  switch (pathname) {
    case ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH: {
      const envelope = parseStrictEcdsaRequestDigestEnvelope(body, 'export');
      return {
        kind: 'export',
        request: parseRouterAbEcdsaDerivationExplicitExportRequestV1(envelope.request),
        requestDigestB64u: envelope.requestDigestB64u,
      };
    }
    case ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH: {
      const envelope = parseStrictEcdsaRequestDigestEnvelope(body, 'refresh');
      const command = parseRouterAbEcdsaDerivationActivationRefreshCommitRequestV1(
        envelope.request,
      );
      return {
        kind: 'refresh',
        command,
        request: command.refresh_request,
        requestDigestB64u: envelope.requestDigestB64u,
      };
    }
    default:
      throw new Error('Strict ECDSA post-registration path is invalid');
  }
}

function strictEcdsaPostRegistrationRequestAuthority(
  input: StrictEcdsaPostRegistrationRequest,
): RouterAbEcdsaStrictRegistrationAuthority {
  return {
    subjectId: input.request.client_id,
    sessionId: input.request.lifecycle.session_id,
    accountId: input.request.lifecycle.account_id,
    expiresAtMs: input.request.expires_at_ms,
  };
}

type StrictEcdsaRequestExpiryValidation =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: 'unauthorized' }
  | { readonly ok: false; readonly code: typeof WALLET_SESSION_FAILURE_CODES.scopeMismatch };

function validateStrictEcdsaPostRegistrationRequestExpiry(input: {
  readonly requestExpiresAtMs: number;
  readonly sessionExpiresAtMs: number;
}): StrictEcdsaRequestExpiryValidation {
  const nowMs = Date.now();
  if (input.requestExpiresAtMs <= nowMs || input.requestExpiresAtMs > nowMs + 10 * 60_000) {
    return { ok: false, code: 'unauthorized' };
  }
  if (input.requestExpiresAtMs > input.sessionExpiresAtMs) {
    return { ok: false, code: WALLET_SESSION_FAILURE_CODES.scopeMismatch };
  }
  return { ok: true };
}

async function authorizeStrictEcdsaPostRegistrationRequest(input: {
  readonly ctx: FetchRouterApiContext;
  readonly request: StrictEcdsaPostRegistrationRequest;
}): Promise<StrictEcdsaPostRegistrationAuthorization> {
  const authority = strictEcdsaPostRegistrationRequestAuthority(input.request);
  if (
    authority.subjectId !== authority.accountId ||
    input.request.request.signer_set.signer_set_id !==
      input.request.request.lifecycle.signer_set_id ||
    input.request.request.signer_set.selected_server.server_id !==
      input.request.request.lifecycle.selected_server_id
  ) {
    return {
      ok: false,
      code: 'identity_mismatch',
      message: 'Strict ECDSA request identity does not match its lifecycle',
    };
  }
  if (
    input.request.kind === 'export' &&
    input.request.request.authorization.kind === 'operation_step_up'
  ) {
    return { ok: true, kind: 'verified_operation', authority };
  }
  const parsedSession = await resolveStrictEcdsaAuthorizationSession(input.ctx);
  if (!parsedSession.ok) {
    return parsedSession;
  }
  const resolvedBinding = await resolveStrictEcdsaAuthorizationBinding({
    admission: parsedSession.admission,
  });
  if (!resolvedBinding.ok) return resolvedBinding;
  const { ecdsaBinding, expiresAtMs } = resolvedBinding.binding;
  const expiry = validateStrictEcdsaPostRegistrationRequestExpiry({
    requestExpiresAtMs: authority.expiresAtMs,
    sessionExpiresAtMs: expiresAtMs,
  });
  if (!expiry.ok && expiry.code === WALLET_SESSION_FAILURE_CODES.scopeMismatch) {
    return walletSessionFailure(expiry.code);
  }
  if (!expiry.ok) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'Strict ECDSA request expiry is invalid',
    };
  }
  if (
    ecdsaBinding.walletId === authority.accountId &&
    ecdsaBinding.thresholdSessionId === authority.sessionId
  ) {
    return { ok: true, kind: 'opaque_wallet_session', authority, ecdsaBinding };
  }
  return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
}

async function handleStrictEcdsaPostRegistrationRoute(input: {
  readonly ctx: FetchRouterApiContext;
  readonly body: unknown;
  readonly pathname: string;
  readonly port: RouterAbEcdsaStrictPostRegistrationPort | null | undefined;
}): Promise<Response> {
  if (!input.port) {
    return json(
      {
        ok: false,
        code: 'not_configured',
        message: 'Strict Router A/B ECDSA post-registration port is not configured',
      },
      { status: 503 },
    );
  }
  let parsed: StrictEcdsaPostRegistrationRequest;
  try {
    parsed = parseStrictEcdsaPostRegistrationRequest(input.pathname, input.body);
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message:
          error instanceof Error
            ? error.message
            : 'Strict ECDSA post-registration request is invalid',
      },
      { status: 400 },
    );
  }
  const authorized = await authorizeStrictEcdsaPostRegistrationRequest({
    ctx: input.ctx,
    request: parsed,
  });
  if (!authorized.ok) {
    return json(authorized, {
      status: strictEcdsaAuthorizationFailureStatus(authorized),
    });
  }
  switch (parsed.kind) {
    case 'export': {
      const exportAuthorization = await authorizeStrictEcdsaExport({
        ctx: input.ctx,
        request: parsed.request,
        authorization: authorized,
      });
      if (!exportAuthorization.ok) {
        return json(exportAuthorization.error.body, {
          status: exportAuthorization.error.status,
        });
      }
      const result = await input.port.explicitExport({
        request: parsed.request,
        requestDigestB64u: parsed.requestDigestB64u,
        authority: exportAuthorization.authority,
      });
      if (!result.ok) return strictPostRegistrationFailureResponse(result);
      return json(result.value, { status: 200 });
    }
    case 'refresh': {
      const result = await input.port.refresh({
        request: parsed.command,
        requestDigestB64u: parsed.requestDigestB64u,
        authority: authorized.authority,
      });
      if (!result.ok) return strictPostRegistrationFailureResponse(result);
      if (result.value.result === 'forwarded') {
        const recorded =
          await input.ctx.service.walletRegistration.recordEcdsaPostRegistrationProof({
            operation: 'refresh',
            request: parsed.request,
            response: result.value,
          });
        if (!recorded.ok) {
          return json(recorded, { status: recorded.code === 'internal' ? 500 : 400 });
        }
      }
      return json(result.value, { status: 200 });
    }
  }
}

type StrictEcdsaExportAuthorizationResult =
  | { readonly ok: true; readonly authority: RouterAbEcdsaStrictExportAuthority }
  | {
      readonly ok: false;
      readonly error: { readonly status: number; readonly body: unknown };
    };

type StrictEcdsaExportFailure = Extract<
  StrictEcdsaExportAuthorizationResult,
  { readonly ok: false }
>;

type StrictEcdsaExportOperationStepUpAdmissionResult =
  | { readonly ok: true; readonly evidenceSetDigest: string }
  | StrictEcdsaExportFailure;

function strictEcdsaExportScopeMatchesRequest(input: {
  readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
  readonly scope: RouterAbEcdsaOperationStepUpPreparationV1Wire['normal_signing_scope'];
}): boolean {
  return (
    input.scope.wallet_id === input.request.lifecycle.account_id &&
    input.scope.context.application_binding_digest_b64u ===
      input.request.context.application_binding_digest_b64u &&
    input.scope.public_identity.context_binding_b64u ===
      input.request.public_identity.context_binding_b64u &&
    input.scope.public_identity.threshold_public_key33_b64u ===
      input.request.public_identity.threshold_public_key33_b64u &&
    input.scope.signing_worker.server_id === input.request.lifecycle.selected_server_id &&
    input.scope.activation_epoch === input.request.lifecycle.root_share_epoch &&
    sameRouterAbMpcMaterialActivationRef(
      input.scope.material_activation,
      input.request.material_activation,
    )
  );
}

function strictEcdsaExportFailure(
  status: number,
  code: string,
  message: string,
): Extract<StrictEcdsaExportAuthorizationResult, { readonly ok: false }> {
  return { ok: false, error: { status, body: { ok: false, code, message } } };
}

type StrictEcdsaExportOperationStepUpInput = {
  readonly operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
  readonly keyHandle: string;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly authorizedOperations: RouterApiAuthorizedOperationService;
};

async function admitStrictEcdsaExportOperationStepUp(
  input: StrictEcdsaExportOperationStepUpInput,
): Promise<StrictEcdsaExportOperationStepUpAdmissionResult> {
  if (!routerAbEcdsaAtomicAuthorizationConfigured(input.authorizedOperations)) {
    return strictEcdsaExportFailure(
      501,
      'not_configured',
      'ECDSA atomic authorization is not configured',
    );
  }
  let authorizedOperationId;
  try {
    authorizedOperationId = requireAuthorizationValue(
      parseAuthorizedOperationId(
        `ecdsa-step-up-authorized-operation:${input.operation.operation_id}`,
      ),
    );
  } catch (error: unknown) {
    return strictEcdsaExportFailure(
      400,
      'invalid_body',
      error instanceof Error ? error.message : 'Export operation step-up admission is invalid',
    );
  }
  const existing = await input.authorizedOperations.readAuthorizedOperationById({
    tenantId: input.authorizedOperations.tenantId,
    authorizedOperationId,
  });
  if (!existing) {
    return strictEcdsaExportFailure(
      409,
      'authorized_operation_missing',
      'Operation authorization is unavailable',
    );
  }
  if (
    existing.authorization.kind !== 'verified_step_up' ||
    existing.quota.kind !== 'quota_neutral' ||
    existing.authorizedOperationId !== authorizedOperationId ||
    existing.operation.operationId !== input.operation.operation_id ||
    existing.operation.capabilityId !== input.materialActivation.capability ||
    existing.operation.operation.capabilityKind !== 'evm_ecdsa_mpc_signing' ||
    existing.operation.operation.operationKind !== 'evm.export_key' ||
    existing.operation.digests.laneDigest !== input.operation.operation_digests.lane_digest_b64u ||
    existing.operation.digests.intentDigest !==
      input.operation.operation_digests.intent_digest_b64u ||
    existing.operation.digests.displayDigest !==
      input.operation.operation_digests.display_digest_b64u
  ) {
    return strictEcdsaExportFailure(
      409,
      'authorized_operation_missing',
      'ECDSA export operation authorization has an invalid source or quota',
    );
  }
  const result = await input.authorizedOperations.admitAuthorizedOperation({
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
      walletId: walletIdFromString(input.operation.wallet_id),
      keyHandle: input.keyHandle,
      runtimePolicyScope: input.runtimePolicyScope,
      materialActivation: input.materialActivation,
    },
  });
  switch (result.kind) {
    case 'material_mismatch':
      return strictEcdsaExportFailure(
        403,
        'scope_mismatch',
        'ECDSA material activation changed before export admission',
      );
    case 'claimed':
    case 'operation_in_progress':
    case 'replayed':
      return {
        ok: true,
        evidenceSetDigest: existing.authorization.evidenceSetDigest,
      };
    case 'authorization_grant_rejected':
    case 'verified_step_up_rejected':
      return strictEcdsaExportFailure(
        403,
        result.kind,
        'Operation step-up authorization is invalid',
      );
    case 'wallet_session_quota_exhausted':
      return strictEcdsaExportFailure(
        409,
        result.kind,
        'Operation step-up authorization is invalid',
      );
  }
}

async function authorizeStrictEcdsaExport(input: {
  readonly ctx: FetchRouterApiContext;
  readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
  readonly authorization: Extract<StrictEcdsaPostRegistrationAuthorization, { readonly ok: true }>;
}): Promise<StrictEcdsaExportAuthorizationResult> {
  if (input.request.authorization.kind === 'operation_step_up') {
    if (input.authorization.kind !== 'verified_operation') {
      return strictEcdsaExportFailure(
        403,
        'scope_mismatch',
        'ECDSA export operation authority is invalid',
      );
    }
    const operation = input.request.operation;
    if (!operation) {
      return strictEcdsaExportFailure(
        400,
        'invalid_body',
        'Operation step-up export requires operation preparation',
      );
    }
    if (
      operation.operation_kind !== 'evm.export_key' ||
      operation.wallet_id !== input.request.lifecycle.account_id ||
      operation.material_activation.material_owner !== input.request.lifecycle.account_id ||
      !sameRouterAbMpcMaterialActivationRef(
        operation.material_activation,
        input.request.material_activation,
      ) ||
      operation.material_activation.signing_worker !== input.request.lifecycle.selected_server_id ||
      operation.signing_worker_id !== input.request.lifecycle.selected_server_id ||
      operation.expires_at_ms < input.request.expires_at_ms ||
      !strictEcdsaExportScopeMatchesRequest({
        request: input.request,
        scope: operation.normal_signing_scope,
      })
    ) {
      return strictEcdsaExportFailure(
        403,
        'scope_mismatch',
        'ECDSA export operation scope does not match the request',
      );
    }
    const activeMaterial =
      await input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation({
        walletId: operation.wallet_id,
        materialActivation: input.request.material_activation,
      });
    if (!activeMaterial.ok) {
      return strictEcdsaExportFailure(
        activeMaterial.code === 'internal' ? 500 : 403,
        activeMaterial.code,
        activeMaterial.message,
      );
    }
    if (
      activeMaterial.keyHandle !== operation.key_handle ||
      activeMaterial.relayerKeyId !== operation.relayer_key_id ||
      activeMaterial.participantIds[0] !== operation.participant_ids[0] ||
      activeMaterial.participantIds[1] !== operation.participant_ids[1] ||
      !sameRouterAbMpcMaterialActivationRef(
        activeMaterial.materialActivation,
        operation.material_activation,
      ) ||
      !sameRouterAbMpcMaterialActivationRef(
        activeMaterial.materialActivation,
        operation.normal_signing_scope.material_activation,
      )
    ) {
      return strictEcdsaExportFailure(
        403,
        'scope_mismatch',
        'ECDSA export material is no longer active',
      );
    }
    const freshMaterial = await resolveFreshRouterAbEcdsaMaterialActivation({
      resolveEcdsaMaterialActivation:
        input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation.bind(
          input.ctx.service.walletRegistration,
        ),
      walletId: operation.wallet_id,
      expected: operation.material_activation,
    });
    if (!freshMaterial.ok) {
      return strictEcdsaExportFailure(
        freshMaterial.code === 'internal' ? 500 : 403,
        freshMaterial.code === 'internal' ? 'internal' : 'scope_mismatch',
        freshMaterial.message,
      );
    }
    if (
      freshMaterial.keyHandle !== operation.key_handle ||
      freshMaterial.relayerKeyId !== operation.relayer_key_id ||
      freshMaterial.participantIds[0] !== operation.participant_ids[0] ||
      freshMaterial.participantIds[1] !== operation.participant_ids[1] ||
      !sameRouterAbMpcMaterialActivationRef(
        freshMaterial.materialActivation,
        operation.normal_signing_scope.material_activation,
      )
    ) {
      return strictEcdsaExportFailure(
        403,
        'scope_mismatch',
        'ECDSA export material changed before operation admission',
      );
    }
    const admission = await admitStrictEcdsaExportOperationStepUp({
      operation,
      materialActivation: freshMaterial.materialActivation,
      keyHandle: freshMaterial.keyHandle,
      runtimePolicyScope: activeMaterial.runtimePolicyScope,
      authorizedOperations: input.ctx.service.authorizedOperations,
    });
    if (!admission.ok) return admission;
    return {
      ok: true,
      authority: {
        subjectId: input.authorization.authority.subjectId,
        sessionId: input.authorization.authority.sessionId,
        accountId: input.authorization.authority.accountId,
        expiresAtMs: input.authorization.authority.expiresAtMs,
        keyHandle: operation.key_handle,
        authorization: input.request.authorization,
        normalSigningScope: operation.normal_signing_scope,
        privateAuthorization: {
          kind: 'operation_step_up',
          evidenceSetDigest: admission.evidenceSetDigest,
        },
      },
    };
  }
  if (input.authorization.kind !== 'opaque_wallet_session') {
    return strictEcdsaExportFailure(
      403,
      'scope_mismatch',
      'ECDSA export Wallet Session authority is invalid',
    );
  }
  const binding = input.authorization.ecdsaBinding;
  if (
    !binding ||
    binding.walletId !== input.request.lifecycle.account_id ||
    binding.thresholdSessionId !== input.request.lifecycle.session_id
  ) {
    return strictEcdsaExportFailure(403, 'scope_mismatch', 'ECDSA export session is invalid');
  }
  // The authenticated reusable Wallet Session is the attested authority. The
  // router additionally rejects any request whose own authorization branch
  // names a different session, so a step-up-authorized export cannot be
  // presented on a reusable-session route.
  if (
    input.request.authorization.kind !== 'reusable_wallet_session' ||
    input.request.authorization.wallet_session_id !== binding.walletSessionId
  ) {
    return strictEcdsaExportFailure(
      403,
      'scope_mismatch',
      'ECDSA export Wallet Session does not match the request',
    );
  }
  const scope = binding.routerAbEcdsaDerivationNormalSigning.scope;
  if (
    scope.wallet_id !== input.request.lifecycle.account_id ||
    scope.context.application_binding_digest_b64u !==
      input.request.context.application_binding_digest_b64u ||
    scope.public_identity.context_binding_b64u !==
      input.request.public_identity.context_binding_b64u ||
    scope.public_identity.threshold_public_key33_b64u !==
      input.request.public_identity.threshold_public_key33_b64u ||
    scope.signing_worker.server_id !== input.request.lifecycle.selected_server_id ||
    scope.activation_epoch !== input.request.lifecycle.root_share_epoch ||
    !sameRouterAbMpcMaterialActivationRef(
      scope.material_activation,
      input.request.material_activation,
    )
  ) {
    return strictEcdsaExportFailure(403, 'scope_mismatch', 'ECDSA export scope is invalid');
  }
  const activeMaterial = await input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation({
    walletId: input.request.lifecycle.account_id,
    materialActivation: input.request.material_activation,
  });
  if (!activeMaterial.ok) {
    return strictEcdsaExportFailure(
      activeMaterial.code === 'internal' ? 500 : 403,
      activeMaterial.code,
      activeMaterial.message,
    );
  }
  if (
    activeMaterial.keyHandle !== binding.keyHandle ||
    !sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      scope.material_activation,
    )
  ) {
    return strictEcdsaExportFailure(
      403,
      'scope_mismatch',
      'ECDSA export material is no longer active',
    );
  }
  return {
    ok: true,
    authority: {
      subjectId: input.authorization.authority.subjectId,
      sessionId: input.authorization.authority.sessionId,
      accountId: input.authorization.authority.accountId,
      expiresAtMs: input.authorization.authority.expiresAtMs,
      keyHandle: binding.keyHandle,
      authorization: {
        kind: 'reusable_wallet_session',
        wallet_session_id: binding.walletSessionId,
      },
      normalSigningScope: scope,
      privateAuthorization: {
        kind: 'reusable_wallet_session',
        walletSessionId: binding.walletSessionId,
      },
    },
  };
}

function strictPostRegistrationFailureResponse(
  result: Extract<
    RouterAbEcdsaStrictExportResult | RouterAbEcdsaStrictRefreshResult,
    { readonly ok: false }
  >,
): Response {
  return json(
    {
      ok: false,
      code: result.code,
      message: result.message,
    },
    { status: result.retryable ? 502 : 400 },
  );
}

type StrictEcdsaReusableWalletSessionAuthorization =
  | {
      readonly ok: true;
      readonly kind: 'reuse_reusable_wallet_session';
      readonly proof: VerifiedOwnerWalletSessionProof;
      readonly principalId: PrincipalId;
      readonly authorizationSessionId: EcdsaAuthorizationSessionId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly quotaId: MpcWalletSigningQuotaId;
      readonly expiresAtMs: number;
      readonly remainingUses: number;
      readonly authorityRef: WalletAuthAuthorityRef;
      readonly authSource: OpaqueOwnerEcdsaWalletSessionBinding['authSource'];
    }
  | {
      readonly ok: false;
      readonly code: 'unauthorized' | 'identity_mismatch';
      readonly message: string;
    }
  | WalletSessionBoundaryFailure;

async function authorizeStrictEcdsaSessionActivationFromOpaqueEd25519Session(input: {
  readonly ctx: FetchRouterApiContext;
  readonly walletId: string;
  readonly walletSessionToken: string;
  readonly proof: VerifiedOwnerWalletSessionProof;
}): Promise<StrictEcdsaReusableWalletSessionAuthorization> {
  let admission: OpaqueOwnerWalletSessionAdmissionValue | null;
  try {
    admission = await resolveOpaqueOwnerWalletSessionAdmission({
      authorizationSessions: input.ctx.service.authorizationSessions,
      token: input.walletSessionToken,
      curve: 'ed25519',
      nowMs: Date.now(),
    });
  } catch {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
  }
  if (!admission || admission.curve !== 'ed25519') {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.invalid);
  }
  const { binding, resolved } = admission;
  if (
    binding.walletId !== input.walletId ||
    binding.walletSessionId !== resolved.authorization.walletSessionId ||
    binding.authorizationId !== resolved.authorization.authorizationId ||
    binding.quotaId !== resolved.authorization.quotaId ||
    binding.thresholdExpiresAtMs !== resolved.authorization.expiresAtMs
  ) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  if (
    input.proof.tenantId !== resolved.authorization.tenantId ||
    input.proof.walletId !== resolved.authorization.walletId ||
    input.proof.principalId !== resolved.authorization.principalId ||
    String(input.proof.authority.authorityDigest) !== String(resolved.authorization.authorityDigest)
  ) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  const principalId = parsePrincipalId(walletSessionPrincipalSubject(binding.authority));
  if (!principalId.ok) {
    return {
      ok: false,
      code: 'identity_mismatch',
      message: 'Ed25519 Wallet Session principal is invalid',
    };
  }
  const nowMs = Date.now();
  if (resolved.authorization.principalId !== principalId.value) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.expired);
  }
  const status = await input.ctx.service.authorizationSessions.readReusableWalletSessionStatus({
    tenantId: input.ctx.service.authorizationSessions.tenantId,
    principalId: principalId.value,
    walletSessionId: binding.walletSessionId,
    quotaId: binding.quotaId,
    nowMs,
  });
  if (status.kind !== 'active') {
    return walletSessionFailure(
      status.kind === 'expired'
        ? WALLET_SESSION_FAILURE_CODES.expired
        : status.kind === 'exhausted'
          ? WALLET_SESSION_FAILURE_CODES.budgetExhausted
          : WALLET_SESSION_FAILURE_CODES.scopeMismatch,
    );
  }
  const authSource = strictEcdsaAuthSourceFromAuthority(binding.authority);
  if (!authSource) {
    return {
      ok: false,
      code: 'identity_mismatch',
      message: 'Ed25519 Wallet Session authority is invalid',
    };
  }
  const authorizationSessionId = parseEcdsaAuthorizationSessionId(input.proof.proofId);
  if (!authorizationSessionId.ok) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  return {
    ok: true,
    kind: 'reuse_reusable_wallet_session',
    proof: input.proof,
    principalId: principalId.value,
    authorizationSessionId: authorizationSessionId.value,
    authorizationId: binding.authorizationId,
    walletSessionId: binding.walletSessionId,
    quotaId: binding.quotaId,
    expiresAtMs: status.expiresAtMs,
    remainingUses: status.remainingUses,
    authorityRef: await walletAuthAuthorityRef({ authority: binding.authority }),
    authSource,
  };
}

function strictEcdsaAuthSourceFromAuthority(
  authority: WalletAuthAuthority,
): OpaqueOwnerEcdsaWalletSessionBinding['authSource'] | null {
  switch (authority.factor.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        credentialIdB64u: authority.factor.credentialIdB64u,
      };
    case 'email_otp': {
      const providerSubject = parseProviderSubject(authority.factor.providerUserId);
      if (!providerSubject.ok) return null;
      return {
        kind: 'oidc_provider',
        providerId: authority.factor.provider === 'google' ? 'google_oidc' : 'oidc',
        providerSubject: providerSubject.value,
      };
    }
  }
}

async function authorizeStrictEcdsaSessionActivation(input: {
  readonly ctx: FetchRouterApiContext;
  readonly walletId: string;
  readonly source: 'verified_wallet_unlock' | 'additional_wallet_target';
  readonly proof: VerifiedOwnerWalletSessionProof;
}): Promise<
  | {
      readonly ok: true;
      readonly kind: 'issue_reusable_wallet_session';
      readonly proof: VerifiedOwnerWalletSessionProof;
      readonly principalId: PrincipalId;
      readonly authorizationSessionId: EcdsaAuthorizationSessionId;
      readonly authority: WalletAuthAuthorityRef;
      readonly authSource: OpaqueOwnerEcdsaWalletSessionBinding['authSource'];
    }
  | StrictEcdsaReusableWalletSessionAuthorization
> {
  if (String(input.proof.walletId) !== input.walletId) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  const authorizationSessionId = parseEcdsaAuthorizationSessionId(input.proof.proofId);
  if (!authorizationSessionId.ok) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  return {
    ok: true,
    kind: 'issue_reusable_wallet_session',
    proof: input.proof,
    principalId: input.proof.principalId,
    authorizationSessionId: authorizationSessionId.value,
    authority: input.proof.authority,
    authSource: input.proof.authSource,
  };
}

async function authorizeStrictEcdsaSessionActivationFromEd25519(input: {
  readonly ctx: FetchRouterApiContext;
  readonly walletId: string;
  readonly walletSessionToken: string;
  readonly proof: VerifiedOwnerWalletSessionProof;
}): Promise<StrictEcdsaReusableWalletSessionAuthorization> {
  return authorizeStrictEcdsaSessionActivationFromOpaqueEd25519Session({
    ctx: input.ctx,
    walletId: input.walletId,
    walletSessionToken: input.walletSessionToken,
    proof: input.proof,
  });
}

function walletSessionPrincipalSubject(authority: WalletAuthAuthority): string {
  switch (authority.factor.kind) {
    case 'email_otp':
      return authority.factor.providerUserId;
    case 'passkey':
      return authority.walletId;
  }
}

type StrictEcdsaSessionActivationInput =
  | {
      readonly ctx: FetchRouterApiContext;
      readonly body: unknown;
      readonly source: 'verified_wallet_unlock' | 'additional_wallet_target';
      readonly proof: VerifiedOwnerWalletSessionProof;
    }
  | {
      readonly ctx: FetchRouterApiContext;
      readonly body: unknown;
      readonly source: 'verified_ed25519_wallet_session';
      readonly walletSessionToken: string;
      readonly proof: VerifiedOwnerWalletSessionProof;
    };

export async function handleStrictEcdsaSessionActivation(
  input: StrictEcdsaSessionActivationInput,
): Promise<Response> {
  let request: RouterAbEcdsaPostRegistrationSessionActivationRequestV1;
  try {
    request = parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1(input.body);
  } catch (error: unknown) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message:
          error instanceof Error
            ? error.message
            : 'ECDSA post-registration session activation is invalid',
      },
      { status: 400 },
    );
  }
  const authorized =
    input.source === 'verified_ed25519_wallet_session'
      ? await authorizeStrictEcdsaSessionActivationFromEd25519({
          ctx: input.ctx,
          walletId: request.public_capability.client_id,
          walletSessionToken: input.walletSessionToken,
          proof: input.proof,
        })
      : await authorizeStrictEcdsaSessionActivation({
          ctx: input.ctx,
          walletId: request.public_capability.client_id,
          source: input.source,
          proof: input.proof,
        });
  if (!authorized.ok) {
    return json(authorized, {
      status: strictEcdsaAuthorizationFailureStatus(authorized),
    });
  }
  const activated =
    await input.ctx.service.walletRegistration.activateEcdsaPostRegistrationSession(request);
  if (!activated.ok) {
    return json(activated, {
      status: activated.code === 'not_found' ? 404 : activated.code === 'internal' ? 500 : 400,
    });
  }
  const walletKey = activated.walletKey;
  const normalSigning = activated.normalSigning;
  let walletSessionId: WalletSessionId;
  let quotaId: MpcWalletSigningQuotaId;
  let authorizationId: WalletSessionAuthorizationId;
  let walletAuthAuthorityRef: WalletAuthAuthorityRef;
  let authSource: OpaqueOwnerEcdsaWalletSessionBinding['authSource'];
  let expiresAtMs = activated.session.expiresAtMs;
  let remainingUses = activated.session.remainingUses;
  if (authorized.kind === 'issue_reusable_wallet_session') {
    const mintId = parseReusableWalletSessionMintId(request.session_policy.wallet_session_mint_id);
    if (!mintId.ok) {
      return json(
        {
          ok: false,
          code: 'invalid_body',
          message: 'ECDSA Wallet Session mint identity is invalid',
        },
        { status: 400 },
      );
    }
    const issued = await input.ctx.service.authorizationSessions.issueReusableWalletSession({
      tenantId: input.ctx.service.authorizationSessions.tenantId,
      principalId: authorized.principalId,
      walletId: walletIdFromString(walletKey.walletId),
      authority: authorized.authority,
      mintId: mintId.value,
      remainingUses: activated.session.remainingUses,
      issuedAtMs: activated.session.expiresAtMs - request.session_policy.ttl_ms,
      expiresAtMs: activated.session.expiresAtMs,
    });
    walletSessionId = issued.quota.walletSessionId;
    quotaId = issued.quota.quotaId;
    authorizationId = issued.session.authorizationId;
    walletAuthAuthorityRef = authorized.authority;
    authSource = authorized.authSource;
  } else {
    authorizationId = authorized.authorizationId;
    walletSessionId = authorized.walletSessionId;
    quotaId = authorized.quotaId;
    expiresAtMs = authorized.expiresAtMs;
    remainingUses = authorized.remainingUses;
    walletAuthAuthorityRef = authorized.authorityRef;
    authSource = authorized.authSource;
  }
  const signed = await issueRouterAbEcdsaDerivationOpaqueWalletSessionToken({
    opaqueWalletSessions: input.ctx.service.authorizationSessions,
    tenantId: input.ctx.service.authorizationSessions.tenantId,
    proof: authorized.proof,
    walletAuthAuthorityRef,
    authSource,
    userId: walletKey.walletId,
    relayerKeyId: walletKey.relayerKeyId,
    sessionInfo: {
      sessionKind: 'opaque',
      authorizationKind: 'owner_wallet_session',
      authorizationSessionId: authorized.authorizationSessionId,
      authorizationId,
      thresholdSessionId: activated.session.thresholdSessionId,
      walletSessionId,
      quotaId,
      expiresAtMs,
      participantIds: walletKey.participantIds,
      runtimePolicyScope: request.session_policy.runtime_policy_scope,
      keyManifestDigestB64u: activated.keyManifestDigestB64u,
      keyHandle: walletKey.keyHandle,
      stableKeyContext: {
        walletId: walletKey.walletId,
        keyScope: walletKey.keyScope,
        ecdsaThresholdKeyId: walletKey.ecdsaThresholdKeyId,
        signingRootId: walletKey.signingRootId,
        signingRootVersion: walletKey.signingRootVersion,
        applicationBindingDigestB64u: normalSigning.scope.context.application_binding_digest_b64u,
        contextBinding32B64u: normalSigning.scope.public_identity.context_binding_b64u,
      },
      publicIdentity: {
        derivationClientSharePublicKey33B64u:
          normalSigning.scope.public_identity.derivation_client_share_public_key33_b64u,
        relayerPublicKey33B64u: normalSigning.scope.public_identity.server_public_key33_b64u,
        groupPublicKey33B64u: normalSigning.scope.public_identity.threshold_public_key33_b64u,
        ethereumAddress: walletKey.thresholdOwnerAddress,
      },
      activationEpoch: normalSigning.scope.activation_epoch,
      signingWorkerId: normalSigning.scope.signing_worker.server_id,
      routerAbEcdsaDerivationNormalSigning: normalSigning,
    },
    fallbackParticipantIds: walletKey.participantIds,
    invalidPayloadErrorMessage: 'invalid Router A/B ECDSA post-registration Wallet Session payload',
  });
  if (!signed.ok) {
    return json(
      {
        ok: false,
        code: signed.code,
        message: signed.message,
      },
      { status: signed.status },
    );
  }
  if (signed.authorizationKind !== 'owner_wallet_session') {
    return json(
      {
        ok: false,
        code: 'internal',
        message: 'ECDSA post-registration Wallet Session issuance returned the wrong authority',
      },
      { status: 500 },
    );
  }
  return json(
    {
      kind: 'router_ab_ecdsa_post_registration_session_activated_v1',
      public_capability: request.public_capability,
      session: {
        authorization_session_id: authorized.authorizationSessionId,
        threshold_session_id: activated.session.thresholdSessionId,
        wallet_session_id: walletSessionId,
        quota_id: quotaId,
        expires_at_ms: expiresAtMs,
        remaining_uses: remainingUses,
        wallet_session_token: signed.token,
      },
      normal_signing: normalSigning,
    },
    { status: 200 },
  );
}

export async function handleThresholdEcdsa(ctx: FetchRouterApiContext): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH) {
    const runtime = ctx.service.thresholdRuntime.getRouterAbEcdsaPresignRuntime();
    if (!runtime) {
      const body = {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B ECDSA presign runtime is not configured on this server',
        configured: false,
      };
      return json(body, { status: thresholdEcdsaStatusCode(body) });
    }
    const health = runtime.healthz();
    if (health.ok) return json({ ok: true, configured: true }, { status: 200 });
    const body = { ...NOT_IMPLEMENTED, configured: true };
    return json(body, { status: thresholdEcdsaStatusCode(body) });
  }

  if (ctx.method !== 'POST') return null;

  const pathname = ctx.pathname;
  if (
    pathname !== ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_SESSION_ACTIVATION_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_EXPORT_SHARE_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_PRESIGN_INIT_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_PRESIGN_STEP_PATH
  ) {
    return null;
  }

  const bodyUnknown = await readJson(ctx.request.clone());
  if (
    pathname === ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_EXPORT_SHARE_PATH ||
    pathname === ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_PRESIGN_INIT_PATH ||
    pathname === ROUTER_AB_ECDSA_DERIVATION_LINKED_DEVICE_PRESIGN_STEP_PATH
  ) {
    return await handleLinkedDeviceEcdsaPresign(ctx);
  }
  if (pathname === ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_PATH) {
    let request: RouterAbEcdsaOperationStepUpAuthorizationRequestV1Wire;
    try {
      request = parseRouterAbEcdsaOperationStepUpAuthorizationRequestV1(bodyUnknown);
    } catch (error: unknown) {
      return json(
        {
          ok: false,
          code: 'invalid_body',
          message: error instanceof Error ? error.message : 'Operation step-up request is invalid',
        },
        { status: 400 },
      );
    }
    return issueEcdsaOperationStepUpAuthorization({ ctx, request });
  }
  if (pathname === ROUTER_AB_ECDSA_DERIVATION_SESSION_ACTIVATION_PATH) {
    return json(
      {
        ok: false,
        code: 'owner_proof_required',
        message: 'ECDSA Wallet Session activation requires verified owner authorization',
      },
      { status: 401 },
    );
  }
  if (
    pathname === ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH ||
    pathname === ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH
  ) {
    return handleStrictEcdsaPostRegistrationRoute({
      ctx,
      body: bodyUnknown,
      pathname,
      port: ctx.opts.routerAbEcdsaStrictPostRegistration,
    });
  }
  const body =
    bodyUnknown && typeof bodyUnknown === 'object' && !Array.isArray(bodyUnknown)
      ? (bodyUnknown as Record<string, unknown>)
      : {};
  if (pathname === ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH) {
    const linked = await handleLinkedDeviceEcdsaNormalSigning({
      ctx,
      body,
      phase: 'prepare',
    });
    if (linked) return linked;
    return handleRouterAbEcdsaDerivationNormalSigningRoute({
      ctx,
      body,
      phase: 'prepare',
    });
  }

  if (pathname === ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH) {
    const linked = await handleLinkedDeviceEcdsaNormalSigning({
      ctx,
      body,
      phase: 'finalize',
    });
    if (linked) return linked;
    return handleRouterAbEcdsaDerivationNormalSigningRoute({
      ctx,
      body,
      phase: 'finalize',
    });
  }

  if (pathname === ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH) {
    const runtime = ctx.service.thresholdRuntime.getRouterAbEcdsaPresignRuntime();
    if (!runtime) {
      const failure = {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B ECDSA presign runtime is not configured on this server',
      };
      return json(failure, { status: thresholdEcdsaStatusCode(failure) });
    }
    const parsedBody = parseRouterAbEcdsaDerivationPoolFillInitRouteRequest(body);
    const requestTag = parsedBody.ok ? parsedBody.request.requestTag : undefined;
    const gateTicket = await presignPriorityGate.acquire(resolvePresignTrafficClass(requestTag));
    try {
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEcdsaStatusCode(parsedBody.body) });
      }
      const authorized = await authorizeEcdsaPoolFill({
        ctx,
        request: parsedBody.request,
      });
      if (!authorized.ok) {
        return json(authorized.error.body, { status: authorized.error.status });
      }
      const result = await runtime.initializePoolFill({
        binding: authorized.binding,
        request: ecdsaPoolFillInitRuntimeRequest(parsedBody.request),
      });
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    } finally {
      gateTicket.release();
    }
  }
  if (pathname === ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH) {
    const runtime = ctx.service.thresholdRuntime.getRouterAbEcdsaPresignRuntime();
    if (!runtime) {
      const failure = {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B ECDSA presign runtime is not configured on this server',
      };
      return json(failure, { status: thresholdEcdsaStatusCode(failure) });
    }
    const parsedBody = parseRouterAbEcdsaDerivationPoolFillStepRouteRequest(body);
    const requestTag = parsedBody.ok ? parsedBody.request.requestTag : undefined;
    const gateTicket = await presignPriorityGate.acquire(resolvePresignTrafficClass(requestTag));
    try {
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEcdsaStatusCode(parsedBody.body) });
      }
      const authorized = await authorizeEcdsaPoolFill({
        ctx,
        request: parsedBody.request,
      });
      if (!authorized.ok) {
        return json(authorized.error.body, { status: authorized.error.status });
      }
      const result = await runtime.advancePoolFill({
        binding: authorized.binding,
        request: ecdsaPoolFillStepRuntimeRequest(parsedBody.request),
      });
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    } finally {
      gateTicket.release();
    }
  }
  return null;
}
