import type { FetchRouterApiContext } from '../createFetchRouter';
import { json, readJson } from '../../../framework/http';
import { thresholdEcdsaStatusCode } from '../../../../threshold/statusCodes';
import {
  resolveWalletSessionOperationCredentialAdmission,
  validateRouterAbEcdsaDerivationWalletSessionInputs,
  type WalletSessionOperationCredentialAdmission,
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
  type RouterAbEcdsaOperationStepUpExportTopologyV1Wire,
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
  RouterApiWalletAuthMethodService,
  RouterApiWalletRegistrationService,
} from '../../../framework/authServicePort';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import {
  walletSessionFailure,
  walletSessionFailureStatus,
  type WalletSessionBoundaryFailure,
} from '../../../auth/walletSessionFailure';
import { extractBearerCredential } from '../../../auth/routerApiKeyAuth';
import {
  EVM_ECDSA_MPC_OPERATION_KINDS,
  parseWalletSessionMintId,
  parseEcdsaAuthorizationSessionId,
  WALLET_SESSION_CLIENT_CAPABILITY_V1,
  type PrincipalId,
  type EcdsaAuthorizationSessionId,
} from '@shared/authorization/capabilityKinds';
import type { WalletSessionOperationCredentialV1 } from '@shared/device-linking/contracts';
import {
  walletAuthAuthorityRef,
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
import { buildCapabilityOperationEnvelope } from '@shared/authorization/operationFingerprint';
import { buildEvmEcdsaMpcOperationRef } from '@shared/authorization/capabilityKinds';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  buildWalletSessionCapabilitySubjectsV1,
  projectActiveWalletSession,
  WALLET_ECDSA_ACTIVATION_EXACT_RESPONSE_FAMILY_V1,
  type AuthorizedOperation,
  type VerifiedOwnerProof,
  type WalletSessionCapabilitySubjectsV1,
} from '../../../../authorization/domain';
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
  parseOrgId,
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
import {
  proxyNormalSigningRequestToMpcRouter,
  proxyOwnerLaneAdmittedNormalSigningRequest,
} from './normalSigningRouterProxy';
import {
  sameRouterAbMpcMaterialActivationRef,
  routerAbMpcMaterialActivationRefToWire,
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
      binding: {
        kind: 'wallet_session_operation_credential_v1',
        context: authorization.validated.admission.context,
      },
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
              keyHandle: authorization.activeMaterial.keyHandle,
              relayerKeyId: authorization.activeMaterial.relayerKeyId,
              participantIds: [...authorization.activeMaterial.participantIds],
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
    const session = authorization.validated.admission.context.authorization.session;
    const runtimePolicyScope = authorization.activeMaterial.runtimePolicyScope;
    authorizedOperationWire = buildRouterAbEcdsaAuthorizedOperationWire({
      operation: authorizedOperation,
      binding: {
        kind: 'gateway_owner_wallet_session',
        subjectId: String(session.principalId),
        accountId: String(session.walletId),
        authorizationSessionId: String(session.authorizationId),
        authorizationId: String(session.authorizationId),
        walletSessionId: String(session.walletSessionId),
        quotaId: String(session.quotaId),
        thresholdSessionId: String(session.walletSessionId),
        orgId: runtimePolicyScope.orgId,
        projectId: runtimePolicyScope.projectId,
        environment: runtimePolicyScope.envId,
        signingWorkerId: authorization.activeMaterial.materialActivation.signing_worker,
        expiresAtMs: session.expiresAtMs,
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
      ? authorization.session.laneAuthorization
      : {
          kind: 'wallet_auth_method' as const,
          walletAuthMethodId:
            authorization.validated.admission.context.authorization.session.walletAuthMethodId,
        };
  const admittedBody = {
    ...input.body,
    authorized_operation: authorizedOperationWire,
  };
  const upstream =
    authorization.kind === 'wallet_session_operation_credential_v1'
      ? await proxyNormalSigningRequestToMpcRouter({
          request: input.ctx.request,
          proxy: input.ctx.opts.routerAbNormalSigningRouterProxy,
          body: admittedBody,
        })
      : await proxyOwnerLaneAdmittedNormalSigningRequest({
          request: input.ctx.request,
          proxy: input.ctx.opts.routerAbNormalSigningRouterProxy,
          authorizedOperation,
          walletId: signingWalletId.value,
          expectedMaterialActivation: signingRequest.material_activation,
          authorization: laneAuthorization,
          walletRegistration: input.ctx.service.walletRegistration,
          body: admittedBody,
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

type RouterAbEcdsaResolvedMaterialActivation = Omit<
  Extract<
    Awaited<ReturnType<RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation']>>,
    { readonly ok: true }
  >,
  'routerAbEcdsaDerivationNormalSigning'
>;

type RouterAbEcdsaV2OperationStepUpResolution =
  | { readonly kind: 'not_found' }
  | {
      readonly kind: 'admitted';
      readonly operationKind: 'evm.sign_transaction';
      readonly admission: WalletSessionOperationCredentialAdmission;
      readonly activeMaterial: RouterAbEcdsaResolvedMaterialActivation;
      readonly exportTopology?: never;
    }
  | {
      readonly kind: 'admitted';
      readonly operationKind: 'evm.export_key';
      readonly admission: WalletSessionOperationCredentialAdmission;
      readonly activeMaterial: RouterAbEcdsaResolvedMaterialActivation;
      readonly exportTopology: RouterAbEcdsaOperationStepUpExportTopologyV1Wire;
    }
  | { readonly kind: 'rejected'; readonly message: string }
  | { readonly kind: 'unavailable' };

async function resolveV2EcdsaOperationStepUpAdmission(input: {
  readonly ctx: FetchRouterApiContext;
  readonly operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
}): Promise<RouterAbEcdsaV2OperationStepUpResolution> {
  const token = extractBearerCredential(input.ctx.request.headers);
  if (!token) return { kind: 'not_found' };
  let resolution: Awaited<ReturnType<typeof resolveWalletSessionOperationCredentialAdmission>>;
  try {
    resolution = await resolveWalletSessionOperationCredentialAdmission({
      authorizationSessions: input.ctx.service.authorizationSessions,
      token,
      nowMs: Date.now(),
      operation: {
        keyFamily: 'ecdsa_secp256k1',
        operationKind: input.operation.operation_kind,
      },
    });
  } catch {
    return { kind: 'unavailable' };
  }
  if (resolution.kind === 'not_found') return { kind: 'not_found' };
  if (resolution.kind === 'rejected') {
    return {
      kind: 'rejected',
      message: 'ECDSA operation step-up Wallet Session authorization is invalid',
    };
  }
  if (resolution.admission.curve !== 'ecdsa') {
    return {
      kind: 'rejected',
      message: 'ECDSA operation step-up Wallet Session family is invalid',
    };
  }
  const session = resolution.admission.context.authorization.session;
  const admittedSigner = resolution.admission.admission.signer;
  if (
    input.operation.wallet_id !== String(session.walletId) ||
    input.operation.material_activation.material_owner !== String(session.walletId) ||
    input.operation.expires_at_ms > session.expiresAtMs ||
    input.operation.expires_at_ms <= Date.now()
  ) {
    return {
      kind: 'rejected',
      message: 'ECDSA operation step-up Wallet Session scope is invalid',
    };
  }
  const continuity = await input.ctx.service.walletRegistration.listWalletEcdsaCustodyContinuity({
    walletId: String(session.walletId),
  });
  const signer = resolveV2EcdsaCustodySigner({
    continuity,
    walletId: String(session.walletId),
    admittedThresholdPublicKey33B64u: admittedSigner.thresholdPublicKey33B64u,
    admittedEvmAddress: admittedSigner.evmAddress,
    operation: input.operation,
  });
  if (!signer) {
    return {
      kind: 'rejected',
      message: 'ECDSA operation step-up material is not uniquely active',
    };
  }
  if (
    input.operation.signing_worker_id !==
      input.operation.normal_signing_scope.signing_worker.server_id ||
    !sameRouterAbMpcMaterialActivationRef(
      input.operation.material_activation,
      input.operation.normal_signing_scope.material_activation,
    ) ||
    !sameRouterAbMpcMaterialActivationRef(
      input.operation.material_activation,
      routerAbMpcMaterialActivationRefToWire(resolution.admission.admission.materialActivation),
    )
  ) {
    return {
      kind: 'rejected',
      message: 'ECDSA operation step-up material activation is invalid',
    };
  }
  const activeMaterial: RouterAbEcdsaResolvedMaterialActivation = {
    ok: true,
    materialActivation: routerAbMpcMaterialActivationRefToWire(
      resolution.admission.admission.materialActivation,
    ),
    keyHandle: signer.walletKey.keyHandle,
    relayerKeyId: signer.walletKey.relayerKeyId,
    participantIds: signer.walletKey.participantIds,
    runtimePolicyScope: signer.runtimePolicyScope,
  };
  if (input.operation.operation_kind === 'evm.sign_transaction') {
    return {
      kind: 'admitted',
      operationKind: 'evm.sign_transaction',
      admission: resolution.admission,
      activeMaterial,
    };
  }
  return {
    kind: 'admitted',
    operationKind: 'evm.export_key',
    admission: resolution.admission,
    activeMaterial,
    exportTopology: {
      signer_set: signer.walletKey.publicCapability.signer_set,
      deriver_recipient_keys: signer.walletKey.publicCapability.deriver_recipient_keys,
      router_id: signer.walletKey.publicCapability.router_id,
    },
  };
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
  const v2Resolution = await resolveV2EcdsaOperationStepUpAdmission({
    ctx: input.ctx,
    operation,
  });
  if (v2Resolution.kind === 'unavailable') {
    return json(
      {
        ok: false,
        code: 'wallet_session_unavailable',
        message: 'Wallet Session authorization is unavailable',
      },
      { status: 503 },
    );
  }
  if (v2Resolution.kind === 'rejected') {
    return json(
      { ok: false, code: 'scope_mismatch', message: v2Resolution.message },
      { status: 403 },
    );
  }
  const activeMaterial =
    v2Resolution.kind === 'admitted'
      ? v2Resolution.activeMaterial
      : await input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation({
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
  let v2AuthorityRef: WalletAuthAuthorityRef | undefined;
  if (v2Resolution.kind === 'admitted') {
    v2AuthorityRef = await walletAuthAuthorityRef({ authority });
    const session = v2Resolution.admission.context.authorization.session;
    const context = v2Resolution.admission.context;
    if (
      authority.walletId !== String(session.walletId) ||
      authority.bindingId !== context.authMethod.walletAuthMethodId ||
      context.authMethod.walletAuthorityId !== context.authority.authorityId
    ) {
      return json(
        {
          ok: false,
          code: 'scope_mismatch',
          message: 'Operation step-up authority does not match the Wallet Session authority',
        },
        { status: 403 },
      );
    }
  }
  const proofAuthenticated = await authenticateRouterAbWalletOperationStepUpIdentity({
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
  if (!proofAuthenticated.ok) {
    return json(proofAuthenticated.error.body, { status: proofAuthenticated.error.status });
  }
  if (authority.walletId !== proofAuthenticated.session.walletId) {
    return json(
      { ok: false, code: 'scope_mismatch', message: 'Operation step-up authority changed' },
      { status: 403 },
    );
  }
  const authenticated =
    v2Resolution.kind === 'admitted' && v2AuthorityRef
      ? {
          ok: true as const,
          authorizedOperations: proofAuthenticated.authorizedOperations,
          session: {
            tenantId: v2Resolution.admission.context.authorization.session.tenantId,
            principalId: v2Resolution.admission.context.authorization.session.principalId,
            sessionId: String(v2Resolution.admission.context.authorization.session.authorizationId),
            walletId: String(v2Resolution.admission.context.authorization.session.walletId),
            runtimePolicyScope: activeMaterial.runtimePolicyScope,
            laneAuthorization: {
              kind: 'authority_ref' as const,
              authorityRef: v2AuthorityRef,
              authSource: proofAuthenticated.session.laneAuthorization.authSource,
            },
          },
          authorityRef: v2AuthorityRef,
          requestOrigin: proofAuthenticated.requestOrigin,
          expiresAtMs: operation.expires_at_ms,
        }
      : proofAuthenticated;
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
  let freshMaterial: RouterAbEcdsaResolvedMaterialActivation;
  if (v2Resolution.kind === 'admitted') {
    const refreshedV2Resolution = await resolveV2EcdsaOperationStepUpAdmission({
      ctx: input.ctx,
      operation,
    });
    if (refreshedV2Resolution.kind === 'unavailable') {
      return json(
        {
          ok: false,
          code: 'wallet_session_unavailable',
          message: 'Wallet Session authorization is unavailable',
        },
        { status: 503 },
      );
    }
    if (
      refreshedV2Resolution.kind !== 'admitted' ||
      !sameWalletSessionOperationCredentialAdmission(
        v2Resolution.admission,
        refreshedV2Resolution.admission,
      )
    ) {
      return json(
        {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA operation step-up Wallet Session authorization changed',
        },
        { status: 403 },
      );
    }
    freshMaterial = refreshedV2Resolution.activeMaterial;
  } else {
    const resolvedRegistrationMaterial = await resolveFreshRouterAbEcdsaMaterialActivation({
      resolveEcdsaMaterialActivation:
        input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation.bind(
          input.ctx.service.walletRegistration,
        ),
      walletId: authenticated.session.walletId,
      expected: operation.material_activation,
    });
    if (!resolvedRegistrationMaterial.ok) {
      return json(
        {
          ok: false,
          code: resolvedRegistrationMaterial.code === 'internal' ? 'internal' : 'scope_mismatch',
          message: resolvedRegistrationMaterial.message,
        },
        { status: resolvedRegistrationMaterial.code === 'internal' ? 500 : 403 },
      );
    }
    freshMaterial = resolvedRegistrationMaterial;
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
        authenticated.session.laneAuthorization.authSource.kind !== 'passkey' ||
        proof.authority.factor.credentialIdB64u !==
          authenticated.session.laneAuthorization.authSource.credentialIdB64u
      ) {
        return json(
          { ok: false, code: 'scope_mismatch', message: 'Passkey authority changed' },
          { status: 403 },
        );
      }
      const credential = proof.webauthn_authentication;
      const credentialId = String(credential.rawId || credential.id).trim();
      if (credentialId !== authenticated.session.laneAuthorization.authSource.credentialIdB64u) {
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
          parseAuthFactorId(
            `passkey:${authenticated.session.laneAuthorization.authSource.credentialIdB64u}`,
          ),
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
        ...(operation.operation_kind === 'evm.sign_transaction'
          ? { operationFingerprintDigest: envelope.digests.laneDigest }
          : {}),
      });
      const verified = await input.ctx.service.emailOtp.verifyEmailOtpChallenge({
        userId: proof.authority.factor.providerUserId,
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
                kind: 'provider_identity',
                orgId: requireAuthorizationValue(parseOrgId(authenticated.session.tenantId)),
                providerSubject: requireAuthorizationValue(
                  parseProviderSubject(proof.authority.factor.providerUserId),
                ),
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
  const responseAuthorization = {
    kind: 'operation_step_up' as const,
    evidence_set_digest: evidenceSet.evidenceSetDigest,
    unseal: emailOtpUnseal
      ? {
          kind: 'email_otp_grant' as const,
          grant: emailOtpUnseal.grant,
          challenge_id: emailOtpUnseal.challengeId,
        }
      : { kind: 'not_requested' as const },
  };
  if (operation.operation_kind === 'evm.export_key') {
    const exportTopology =
      v2Resolution.kind === 'admitted' && v2Resolution.operationKind === 'evm.export_key'
        ? v2Resolution.exportTopology
        : await resolveStrictEcdsaExportTopology({
            ctx: input.ctx,
            operation,
          });
    if (!exportTopology) {
      return json(
        {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA export topology is not uniquely active',
        },
        { status: 403 },
      );
    }
    return json(
      {
        ok: true,
        kind: 'verified_step_up',
        operation_kind: 'evm.export_key',
        export_topology: exportTopology,
        authorization: responseAuthorization,
        expires_at_ms: expiresAtMs,
      },
      { status: 200 },
    );
  }
  return json(
    {
      ok: true,
      kind: 'verified_step_up',
      operation_kind: 'evm.sign_transaction',
      authorization: responseAuthorization,
      expires_at_ms: expiresAtMs,
    },
    { status: 200 },
  );
}

type RouterAbEcdsaActiveMaterial = Extract<
  Awaited<ReturnType<RouterApiWalletRegistrationService['resolveEcdsaMaterialActivation']>>,
  { readonly ok: true }
>;

type RouterAbEcdsaPoolFillBinding = Pick<
  RouterAbEcdsaActiveMaterial,
  | 'keyHandle'
  | 'relayerKeyId'
  | 'runtimePolicyScope'
  | 'participantIds'
  | 'routerAbEcdsaDerivationNormalSigning'
> & {
  readonly walletId: string;
  readonly thresholdExpiresAtMs: number;
};

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

function evmAddress20B64u(value: string): string | null {
  if (!/^0x[0-9a-fA-F]{40}$/.test(value)) return null;
  const bytes = new Uint8Array(20);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(2 + index * 2, 4 + index * 2), 16);
  }
  return base64UrlEncode(bytes);
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
  const authenticated = await authenticateRouterAbWalletOperationStepUpIdentity({
    kind: 'wallet_session_operation_credential_v1',
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    keyFamily: 'ecdsa_secp256k1',
    operationKind: input.operation.operation_kind,
    walletId: input.operation.wallet_id,
    materialOwner: input.operation.material_activation.material_owner,
    materialActivation: input.operation.material_activation,
    requestExpiresAtMs: input.operation.expires_at_ms,
    authorizedOperations: input.ctx.service.authorizedOperations,
    authorizationSessions: input.ctx.service.authorizationSessions,
    resolveEcdsaMaterialActivation:
      input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation.bind(
        input.ctx.service.walletRegistration,
      ),
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

export async function authorizeEcdsaPoolFill(input: {
  readonly ctx: FetchRouterApiContext;
  readonly request: RouterAbEcdsaPoolFillInitRouteRequest | RouterAbEcdsaPoolFillStepRouteRequest;
}): Promise<RouterAbEcdsaPoolFillAuthorizationResult> {
  switch (input.request.authorization.kind) {
    case 'reusable_wallet_session': {
      const validated = await validateRouterAbEcdsaDerivationWalletSessionInputs({
        body: input.request,
        headers: Object.fromEntries(input.ctx.request.headers.entries()),
        authorizationSessions: input.ctx.service.authorizationSessions,
        operationKind: 'evm.sign_transaction',
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
      const session = validated.admission.context.authorization.session;
      if (input.request.authorization.wallet_session_id !== session.walletSessionId) {
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
      const admitted = validated.admission.admission;
      const activeMaterial =
        await input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation({
          walletId: String(session.walletId),
          materialActivation: routerAbMpcMaterialActivationRefToWire(admitted.materialActivation),
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
      const normalSigning = activeMaterial.routerAbEcdsaDerivationNormalSigning;
      const requestedPoolFillMaterial = poolFillMaterialActivation(input.request);
      const requestedKeyHandle = 'keyHandle' in input.request ? input.request.keyHandle : undefined;
      if (
        !sameRouterAbMpcMaterialActivationRef(
          activeMaterial.materialActivation,
          routerAbMpcMaterialActivationRefToWire(admitted.materialActivation),
        ) ||
        normalSigning.scope.wallet_id !== String(session.walletId) ||
        normalSigning.scope.public_identity.threshold_public_key33_b64u !==
          admitted.signer.thresholdPublicKey33B64u ||
        normalSigning.scope.public_identity.ethereum_address20_b64u !==
          evmAddress20B64u(admitted.signer.evmAddress) ||
        (requestedKeyHandle !== undefined && requestedKeyHandle !== activeMaterial.keyHandle) ||
        (requestedPoolFillMaterial !== null &&
          (!sameRouterAbMpcMaterialActivationRef(
            activeMaterial.materialActivation,
            requestedPoolFillMaterial,
          ) ||
            !('poolFill' in input.request) ||
            alphabetizeStringify(input.request.poolFill.scope) !==
              alphabetizeStringify(normalSigning.scope)))
      ) {
        return {
          ok: false,
          error: {
            status: 403,
            body: {
              ok: false,
              code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
              message: 'Pool-fill scopes do not match the active Wallet Authority material',
            },
          },
        };
      }
      return {
        ok: true,
        binding: {
          walletId: session.walletId,
          relayerKeyId: activeMaterial.relayerKeyId,
          keyHandle: activeMaterial.keyHandle,
          runtimePolicyScope: activeMaterial.runtimePolicyScope,
          participantIds: activeMaterial.participantIds,
          thresholdExpiresAtMs: session.expiresAtMs,
          routerAbEcdsaDerivationNormalSigning: normalSigning,
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

// Workers cannot safely resolve a Promise created by another request context.
function resolvePresignPriorityTurn(resolve: (value: void | PromiseLike<void>) => void): void {
  setTimeout(resolve, 5);
}

function waitForPresignPriorityTurn(): Promise<void> {
  return new Promise(resolvePresignPriorityTurn);
}

class PresignPriorityGate {
  private foregroundInFlight = 0;
  private backgroundInFlight = 0;

  async acquire(trafficClass: PresignTrafficClass): Promise<PresignPriorityTicket> {
    if (trafficClass === 'foreground') {
      this.foregroundInFlight += 1;
      return this.createTicket('foreground');
    }
    while (!this.canRunBackgroundNow()) {
      await waitForPresignPriorityTurn();
    }
    this.backgroundInFlight += 1;
    return this.createTicket('background');
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
      },
    };
  }

  private canRunBackgroundNow(): boolean {
    return this.foregroundInFlight === 0 && this.backgroundInFlight === 0;
  }
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

type StrictEcdsaOperationCredentialAdmission = Extract<
  WalletSessionOperationCredentialAdmission,
  { readonly curve: 'ecdsa' }
>;

type StrictEcdsaPostRegistrationAuthorization =
  | {
      readonly ok: true;
      readonly kind: 'verified_operation';
      readonly operationKind: 'evm.export_key';
      readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
    }
  | {
      readonly ok: true;
      readonly kind: 'wallet_session_operation_credential_v2';
      readonly operationKind: 'evm.sign_transaction';
      readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
      readonly v2Admission: StrictEcdsaOperationCredentialAdmission;
    }
  | {
      readonly ok: true;
      readonly kind: 'wallet_session_operation_step_up_v2';
      readonly operationKind: 'evm.export_key';
      readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
      readonly v2Admission: StrictEcdsaOperationCredentialAdmission;
    }
  | {
      readonly ok: false;
      readonly code: 'unauthorized' | 'identity_mismatch';
      readonly message: string;
    }
  | WalletSessionBoundaryFailure;

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

async function resolveStrictEcdsaAuthorizationSession(input: {
  readonly ctx: FetchRouterApiContext;
  readonly operationKind: 'evm.sign_transaction' | 'evm.export_key';
}): Promise<StrictEcdsaOperationCredentialAdmission | WalletSessionBoundaryFailure> {
  const token = extractBearerCredential(input.ctx.request.headers);
  if (!token) return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.missing);
  try {
    const resolution = await resolveWalletSessionOperationCredentialAdmission({
      authorizationSessions: input.ctx.service.authorizationSessions,
      token,
      nowMs: Date.now(),
      operation: { keyFamily: 'ecdsa_secp256k1', operationKind: input.operationKind },
    });
    switch (resolution.kind) {
      case 'not_found':
        return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.invalid);
      case 'rejected':
        return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
      case 'admitted':
        if (resolution.admission.curve !== 'ecdsa') {
          return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
        }
        return resolution.admission;
    }
  } catch {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
  }
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
  const isOperationStepUpExport =
    input.request.kind === 'export' &&
    input.request.request.authorization.kind === 'operation_step_up';
  if (isOperationStepUpExport && !extractBearerCredential(input.ctx.request.headers)) {
    return {
      ok: true,
      kind: 'verified_operation',
      operationKind: 'evm.export_key',
      authority,
    };
  }
  const parsedSession = await resolveStrictEcdsaAuthorizationSession({
    ctx: input.ctx,
    operationKind: input.request.kind === 'export' ? 'evm.export_key' : 'evm.sign_transaction',
  });
  if ('ok' in parsedSession) {
    return parsedSession;
  }
  const session = parsedSession.context.authorization.session;
  if (
    authority.subjectId !== String(session.walletId) ||
    authority.accountId !== String(session.walletId) ||
    !sameRouterAbMpcMaterialActivationRef(
      input.request.request.material_activation,
      routerAbMpcMaterialActivationRefToWire(parsedSession.admission.materialActivation),
    )
  ) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  let activeMaterial: Awaited<ReturnType<typeof resolveFreshRouterAbEcdsaMaterialActivation>>;
  try {
    activeMaterial = await resolveFreshRouterAbEcdsaMaterialActivation({
      resolveEcdsaMaterialActivation:
        input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation.bind(
          input.ctx.service.walletRegistration,
        ),
      walletId: String(session.walletId),
      expected: input.request.request.material_activation,
    });
  } catch {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
  }
  if (
    !activeMaterial.ok ||
    !sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      routerAbMpcMaterialActivationRefToWire(parsedSession.admission.materialActivation),
    )
  ) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  const expiry = validateStrictEcdsaPostRegistrationRequestExpiry({
    requestExpiresAtMs: authority.expiresAtMs,
    sessionExpiresAtMs: session.expiresAtMs,
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
  if (input.request.kind === 'export' && !isOperationStepUpExport) {
    // Export requires a separately authenticated operation step-up.
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  if (input.request.kind === 'export') {
    return {
      ok: true,
      kind: 'wallet_session_operation_step_up_v2',
      operationKind: 'evm.export_key',
      authority,
      v2Admission: parsedSession,
    };
  }
  return {
    ok: true,
    kind: 'wallet_session_operation_credential_v2',
    operationKind: 'evm.sign_transaction',
    authority,
    v2Admission: parsedSession,
  };
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

type RouterAbEcdsaCustodySigner = Awaited<
  ReturnType<RouterApiWalletRegistrationService['listWalletEcdsaCustodyContinuity']>
>[number];

function sameV2EcdsaCustodyIdentity(
  left: RouterAbEcdsaCustodySigner,
  right: RouterAbEcdsaCustodySigner,
): boolean {
  return (
    left.walletId === right.walletId &&
    left.walletKey.keyHandle === right.walletKey.keyHandle &&
    left.walletKey.thresholdEcdsaPublicKeyB64u === right.walletKey.thresholdEcdsaPublicKeyB64u &&
    left.walletKey.thresholdOwnerAddress === right.walletKey.thresholdOwnerAddress &&
    left.walletKey.relayerKeyId === right.walletKey.relayerKeyId &&
    left.walletKey.participantIds[0] === right.walletKey.participantIds[0] &&
    left.walletKey.participantIds[1] === right.walletKey.participantIds[1] &&
    alphabetizeStringify(left.walletKey.publicCapability) ===
      alphabetizeStringify(right.walletKey.publicCapability) &&
    alphabetizeStringify(left.runtimePolicyScope) === alphabetizeStringify(right.runtimePolicyScope)
  );
}

function strictEcdsaNormalSigningPublicIdentityMatchesSigner(input: {
  readonly signer: RouterAbEcdsaCustodySigner;
  readonly scope: RouterAbEcdsaOperationStepUpPreparationV1Wire['normal_signing_scope'];
}): boolean {
  const capability = input.signer.walletKey.publicCapability;
  return (
    input.scope.wallet_id === String(input.signer.walletId) &&
    input.scope.context.application_binding_digest_b64u ===
      capability.context.application_binding_digest_b64u &&
    input.scope.public_identity.context_binding_b64u ===
      capability.public_identity.context_binding_b64u &&
    input.scope.public_identity.threshold_public_key33_b64u ===
      capability.public_identity.threshold_public_key33_b64u &&
    input.scope.signing_worker.server_id === capability.signer_set.selected_server.server_id &&
    input.scope.activation_epoch === capability.activation_epoch
  );
}

export function resolveV2EcdsaCustodySigner(input: {
  readonly continuity: readonly RouterAbEcdsaCustodySigner[];
  readonly walletId: string;
  readonly admittedThresholdPublicKey33B64u: string;
  readonly admittedEvmAddress: string;
  readonly operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
}): RouterAbEcdsaCustodySigner | null {
  const matching: RouterAbEcdsaCustodySigner[] = [];
  for (const candidate of input.continuity) {
    if (
      candidate.walletId === input.walletId &&
      candidate.walletKey.thresholdEcdsaPublicKeyB64u === input.admittedThresholdPublicKey33B64u &&
      candidate.walletKey.thresholdOwnerAddress === input.admittedEvmAddress &&
      candidate.walletKey.keyHandle === input.operation.key_handle &&
      candidate.walletKey.relayerKeyId === input.operation.relayer_key_id &&
      candidate.walletKey.participantIds[0] === input.operation.participant_ids[0] &&
      candidate.walletKey.participantIds[1] === input.operation.participant_ids[1]
    ) {
      matching.push(candidate);
    }
  }
  const [canonical] = matching;
  if (!canonical) return null;
  for (const candidate of matching) {
    if (
      !strictEcdsaNormalSigningPublicIdentityMatchesSigner({
        signer: candidate,
        scope: input.operation.normal_signing_scope,
      }) ||
      !sameV2EcdsaCustodyIdentity(canonical, candidate)
    ) {
      return null;
    }
  }
  return canonical;
}

function strictEcdsaExportScopeMatchesSigner(input: {
  readonly signer: RouterAbEcdsaCustodySigner;
  readonly scope: RouterAbEcdsaOperationStepUpPreparationV1Wire['normal_signing_scope'];
}): boolean {
  const capability = input.signer.walletKey.publicCapability;
  return (
    strictEcdsaNormalSigningPublicIdentityMatchesSigner(input) &&
    sameRouterAbMpcMaterialActivationRef(
      input.scope.material_activation,
      capability.material_activation,
    )
  );
}

async function resolveStrictEcdsaExportTopology(input: {
  readonly ctx: FetchRouterApiContext;
  readonly operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
}): Promise<RouterAbEcdsaOperationStepUpExportTopologyV1Wire | null> {
  const continuity = await input.ctx.service.walletRegistration.listWalletEcdsaCustodyContinuity({
    walletId: input.operation.wallet_id,
  });
  const matches = continuity.filter(
    (candidate) =>
      candidate.walletId === input.operation.wallet_id &&
      candidate.walletKey.keyHandle === input.operation.key_handle &&
      candidate.walletKey.relayerKeyId === input.operation.relayer_key_id &&
      candidate.walletKey.participantIds[0] === input.operation.participant_ids[0] &&
      candidate.walletKey.participantIds[1] === input.operation.participant_ids[1] &&
      sameRouterAbMpcMaterialActivationRef(
        candidate.walletKey.publicCapability.material_activation,
        input.operation.material_activation,
      ) &&
      strictEcdsaExportScopeMatchesSigner({
        signer: candidate,
        scope: input.operation.normal_signing_scope,
      }),
  );
  const [signer] = matches;
  if (!signer) return null;
  for (const candidate of matches) {
    if (!sameV2EcdsaCustodyIdentity(signer, candidate)) return null;
  }
  const topology = signer.walletKey.publicCapability;
  if (
    topology.signer_set.selected_server.server_id !==
      input.operation.normal_signing_scope.signing_worker.server_id ||
    topology.public_identity.context_binding_b64u !==
      input.operation.normal_signing_scope.public_identity.context_binding_b64u ||
    topology.context.application_binding_digest_b64u !==
      input.operation.normal_signing_scope.context.application_binding_digest_b64u
  ) {
    return null;
  }
  return {
    signer_set: topology.signer_set,
    deriver_recipient_keys: topology.deriver_recipient_keys,
    router_id: topology.router_id,
  };
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

function sameWalletSessionOperationCredentialAdmission(
  left: WalletSessionOperationCredentialAdmission,
  right: WalletSessionOperationCredentialAdmission,
): boolean {
  const leftSession = left.context.authorization.session;
  const rightSession = right.context.authorization.session;
  return (
    leftSession.tenantId === rightSession.tenantId &&
    leftSession.principalId === rightSession.principalId &&
    leftSession.walletId === rightSession.walletId &&
    leftSession.authorityId === rightSession.authorityId &&
    leftSession.walletAuthMethodId === rightSession.walletAuthMethodId &&
    leftSession.authorityDigestB64u === rightSession.authorityDigestB64u &&
    leftSession.authorityRevocationEpoch === rightSession.authorityRevocationEpoch &&
    leftSession.authorizationId === rightSession.authorizationId &&
    leftSession.walletSessionId === rightSession.walletSessionId &&
    leftSession.quotaId === rightSession.quotaId &&
    leftSession.expiresAtMs === rightSession.expiresAtMs &&
    left.context.authority.authorityId === right.context.authority.authorityId &&
    left.context.authority.authorityDigestB64u === right.context.authority.authorityDigestB64u &&
    left.context.authMethod.walletAuthMethodId === right.context.authMethod.walletAuthMethodId &&
    left.context.authMethod.walletAuthorityId === right.context.authMethod.walletAuthorityId &&
    left.context.retiredAtMs === right.context.retiredAtMs &&
    sameRouterAbMpcMaterialActivationRef(
      routerAbMpcMaterialActivationRefToWire(left.admission.materialActivation),
      routerAbMpcMaterialActivationRefToWire(right.admission.materialActivation),
    )
  );
}

async function authorizeStrictEcdsaV2ExportOperationStepUp(input: {
  readonly ctx: FetchRouterApiContext;
  readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
  readonly authorization: Extract<
    StrictEcdsaPostRegistrationAuthorization,
    { readonly ok: true; readonly kind: 'wallet_session_operation_step_up_v2' }
  >;
}): Promise<StrictEcdsaExportAuthorizationResult> {
  const operation = input.request.operation;
  if (!operation) {
    return strictEcdsaExportFailure(
      400,
      'invalid_body',
      'Operation step-up export requires operation preparation',
    );
  }
  const resolution = await resolveV2EcdsaOperationStepUpAdmission({
    ctx: input.ctx,
    operation,
  });
  if (resolution.kind === 'unavailable') {
    return strictEcdsaExportFailure(
      503,
      'wallet_session_unavailable',
      'Wallet Session authorization is unavailable',
    );
  }
  if (resolution.kind !== 'admitted') {
    return strictEcdsaExportFailure(
      403,
      'scope_mismatch',
      'ECDSA export operation step-up Wallet Session authorization is invalid',
    );
  }
  if (
    !sameWalletSessionOperationCredentialAdmission(
      input.authorization.v2Admission,
      resolution.admission,
    )
  ) {
    return strictEcdsaExportFailure(
      403,
      'scope_mismatch',
      'ECDSA export operation step-up Wallet Session changed',
    );
  }
  const session = resolution.admission.context.authorization.session;
  const activeMaterial = resolution.activeMaterial;
  if (
    input.request.authorization.kind !== 'operation_step_up' ||
    operation.operation_kind !== 'evm.export_key' ||
    operation.wallet_id !== String(session.walletId) ||
    operation.wallet_id !== input.request.lifecycle.account_id ||
    operation.material_activation.material_owner !== String(session.walletId) ||
    operation.material_activation.signing_worker !== input.request.lifecycle.selected_server_id ||
    operation.signing_worker_id !== input.request.lifecycle.selected_server_id ||
    !sameRouterAbMpcMaterialActivationRef(
      operation.material_activation,
      input.request.material_activation,
    ) ||
    operation.expires_at_ms < input.request.expires_at_ms ||
    !strictEcdsaExportScopeMatchesRequest({
      request: input.request,
      scope: operation.normal_signing_scope,
    }) ||
    activeMaterial.keyHandle !== operation.key_handle ||
    activeMaterial.relayerKeyId !== operation.relayer_key_id ||
    activeMaterial.participantIds[0] !== operation.participant_ids[0] ||
    activeMaterial.participantIds[1] !== operation.participant_ids[1] ||
    !sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      operation.material_activation,
    )
  ) {
    return strictEcdsaExportFailure(
      403,
      'scope_mismatch',
      'ECDSA export operation step-up scope does not match the active Wallet Session material',
    );
  }
  const admission = await admitStrictEcdsaExportOperationStepUp({
    operation,
    materialActivation: activeMaterial.materialActivation,
    keyHandle: activeMaterial.keyHandle,
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
      keyHandle: activeMaterial.keyHandle,
      authorization: input.request.authorization,
      normalSigningScope: operation.normal_signing_scope,
      privateAuthorization: {
        kind: 'operation_step_up',
        evidenceSetDigest: admission.evidenceSetDigest,
      },
    },
  };
}

async function authorizeStrictEcdsaExport(input: {
  readonly ctx: FetchRouterApiContext;
  readonly request: RouterAbEcdsaDerivationExplicitExportRequestV1;
  readonly authorization: Extract<StrictEcdsaPostRegistrationAuthorization, { readonly ok: true }>;
}): Promise<StrictEcdsaExportAuthorizationResult> {
  if (input.authorization.kind === 'wallet_session_operation_credential_v2') {
    return strictEcdsaExportFailure(
      403,
      'scope_mismatch',
      'ECDSA export requires an export operation step-up',
    );
  }
  if (input.request.authorization.kind === 'operation_step_up') {
    if (input.authorization.kind === 'wallet_session_operation_step_up_v2') {
      return authorizeStrictEcdsaV2ExportOperationStepUp({
        ctx: input.ctx,
        request: input.request,
        authorization: input.authorization,
      });
    }
    if (input.authorization.authority.subjectId !== input.request.lifecycle.account_id) {
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
  return strictEcdsaExportFailure(
    403,
    'scope_mismatch',
    'ECDSA export requires an operation step-up',
  );
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

export type StrictEcdsaOperationCredentialAuthorization =
  | {
      readonly ok: true;
      readonly kind: 'reuse_wallet_session_operation_credential_v1';
      readonly proof: VerifiedOwnerWalletSessionProof;
      readonly admission: Extract<
        WalletSessionOperationCredentialAdmission,
        { readonly curve: 'ecdsa' }
      >;
      readonly authorizationSessionId: EcdsaAuthorizationSessionId;
    }
  | WalletSessionBoundaryFailure;

type StrictEcdsaDirectWalletSessionAuthorization = {
  readonly ok: true;
  readonly kind: 'issue_direct_wallet_session_v2';
  readonly proof: VerifiedOwnerWalletSessionProof;
  readonly principalId: PrincipalId;
  readonly authorizationSessionId: EcdsaAuthorizationSessionId;
  readonly authorityRef: WalletAuthAuthorityRef;
  readonly authSource: VerifiedOwnerWalletSessionProof['authSource'];
};

function assertNeverStrictEcdsaSessionActivationAuthorization(value: never): never {
  throw new Error(`Unsupported ECDSA session activation authorization: ${String(value)}`);
}

async function authorizeStrictEcdsaSessionActivation(input: {
  readonly walletId: string;
  readonly proof: VerifiedOwnerWalletSessionProof;
}): Promise<StrictEcdsaDirectWalletSessionAuthorization | WalletSessionBoundaryFailure> {
  if (String(input.proof.walletId) !== input.walletId) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  const authorizationSessionId = parseEcdsaAuthorizationSessionId(input.proof.proofId);
  if (!authorizationSessionId.ok) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  return {
    ok: true,
    kind: 'issue_direct_wallet_session_v2',
    proof: input.proof,
    principalId: input.proof.principalId,
    authorizationSessionId: authorizationSessionId.value,
    authorityRef: input.proof.authority,
    authSource: input.proof.authSource,
  };
}

export async function authorizeStrictEcdsaSessionActivationFromOperationCredential(input: {
  readonly authorizationSessions: FetchRouterApiContext['service']['authorizationSessions'];
  readonly walletId: string;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly proof: VerifiedOwnerWalletSessionProof;
}): Promise<StrictEcdsaOperationCredentialAuthorization> {
  let resolution: Awaited<ReturnType<typeof resolveWalletSessionOperationCredentialAdmission>>;
  try {
    resolution = await resolveWalletSessionOperationCredentialAdmission({
      authorizationSessions: input.authorizationSessions,
      token: input.operationCredential.token,
      nowMs: Date.now(),
      operation: {
        keyFamily: 'ecdsa_secp256k1',
        operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
      },
    });
  } catch {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
  }
  if (resolution.kind !== 'admitted' || resolution.admission.curve !== 'ecdsa') {
    return walletSessionFailure(
      resolution.kind === 'not_found'
        ? WALLET_SESSION_FAILURE_CODES.invalid
        : WALLET_SESSION_FAILURE_CODES.scopeMismatch,
    );
  }
  const admission = resolution.admission;
  const session = admission.context.authorization.session;
  if (
    String(session.walletId) !== input.walletId ||
    input.operationCredential.walletSessionId !== session.walletSessionId ||
    input.proof.tenantId !== session.tenantId ||
    input.proof.principalId !== session.principalId ||
    input.proof.walletId !== session.walletId ||
    input.proof.authority.walletId !== session.walletId ||
    input.proof.authority.walletAuthMethodId !== session.walletAuthMethodId ||
    String(input.proof.authority.authorityDigest) !== String(session.authorityDigestB64u)
  ) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  const authorizationSessionId = parseEcdsaAuthorizationSessionId(input.proof.proofId);
  if (!authorizationSessionId.ok) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  return {
    ok: true,
    kind: 'reuse_wallet_session_operation_credential_v1',
    proof: input.proof,
    admission,
    authorizationSessionId: authorizationSessionId.value,
  };
}

function exactEcdsaMaterialMatchesActivation(
  capabilitySubjects: WalletSessionCapabilitySubjectsV1,
  request: RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
): boolean {
  for (const subject of capabilitySubjects) {
    if (subject.kind !== 'sign' || subject.keyFamily !== 'ecdsa_secp256k1') continue;
    return sameRouterAbMpcMaterialActivationRef(
      request.public_capability.material_activation,
      routerAbMpcMaterialActivationRefToWire(subject.materialActivation),
    );
  }
  return false;
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
      readonly source: 'wallet_session_operation_credential_v1';
      readonly operationCredential: WalletSessionOperationCredentialV1;
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
    input.source === 'wallet_session_operation_credential_v1'
      ? await authorizeStrictEcdsaSessionActivationFromOperationCredential({
          authorizationSessions: input.ctx.service.authorizationSessions,
          walletId: request.public_capability.client_id,
          operationCredential: input.operationCredential,
          proof: input.proof,
        })
      : await authorizeStrictEcdsaSessionActivation({
          walletId: request.public_capability.client_id,
          proof: input.proof,
        });
  if (!authorized.ok) {
    return json(authorized, {
      status: strictEcdsaAuthorizationFailureStatus(authorized),
    });
  }
  if (
    authorized.kind === 'reuse_wallet_session_operation_credential_v1' &&
    (!sameRouterAbMpcMaterialActivationRef(
      request.public_capability.material_activation,
      routerAbMpcMaterialActivationRefToWire(authorized.admission.admission.materialActivation),
    ) ||
      request.session_policy.wallet_session_mint_id !==
        authorized.admission.context.authorization.session.mintId ||
      request.session_policy.remaining_uses !==
        authorized.admission.context.authorization.quota.remainingUses ||
      authorized.admission.context.authorization.session.tenantId !==
        authorized.admission.context.authorization.quota.tenantId ||
      authorized.admission.context.authorization.session.principalId !==
        authorized.admission.context.authorization.quota.principalId ||
      authorized.admission.context.authorization.session.walletSessionId !==
        authorized.admission.context.authorization.quota.walletSessionId ||
      authorized.admission.context.authorization.session.quotaId !==
        authorized.admission.context.authorization.quota.quotaId ||
      authorized.admission.context.authorization.session.expiresAtMs !==
        authorized.admission.context.authorization.quota.expiresAtMs)
  ) {
    return json(
      {
        ok: false,
        code: WALLET_SESSION_FAILURE_CODES.scopeMismatch,
        message: 'ECDSA activation material is outside the exact Wallet Session capability',
      },
      { status: walletSessionFailureStatus(WALLET_SESSION_FAILURE_CODES.scopeMismatch) },
    );
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
  if (
    activated.session.thresholdSessionId !== request.session_policy.threshold_session_id ||
    walletKey.walletId !== request.public_capability.client_id
  ) {
    return json(
      {
        ok: false,
        code: 'scope_mismatch',
        message: 'ECDSA activation did not preserve the requested wallet and threshold session',
      },
      { status: 403 },
    );
  }
  if (authorized.kind === 'reuse_wallet_session_operation_credential_v1') {
    const session = authorized.admission.context.authorization.session;
    const quota = authorized.admission.context.authorization.quota;
    if (session.walletId !== walletKey.walletId) {
      return json(
        {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA activation did not preserve the exact Wallet Session',
        },
        { status: 403 },
      );
    }
    return json(
      {
        kind: 'router_ab_ecdsa_credential_free_session_activated_v1',
        public_capability: request.public_capability,
        session: {
          authorization_session_id: authorized.authorizationSessionId,
          authorization_id: session.authorizationId,
          threshold_session_id: activated.session.thresholdSessionId,
          wallet_session_id: session.walletSessionId,
          quota_id: session.quotaId,
          expires_at_ms: session.expiresAtMs,
          remaining_uses: quota.remainingUses,
        },
        normal_signing: normalSigning,
      },
      { status: 200 },
    );
  }
  if (authorized.kind === 'issue_direct_wallet_session_v2') {
    const mintId = parseWalletSessionMintId(request.session_policy.wallet_session_mint_id);
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
    const activeAuthority =
      await input.ctx.service.walletAuthMethods.resolveActiveWalletSessionAuthority({
        walletId: walletIdFromString(walletKey.walletId),
        authorityRef: authorized.authorityRef,
        authSource: authorized.authSource,
      });
    if (activeAuthority.kind === 'rejected') {
      return json(
        {
          ok: false,
          code: activeAuthority.code,
          message: activeAuthority.message,
        },
        { status: 401 },
      );
    }
    const capabilitySubjects = buildWalletSessionCapabilitySubjectsV1(activeAuthority.authority);
    if (!exactEcdsaMaterialMatchesActivation(capabilitySubjects, request)) {
      return json(
        {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA activation material is outside the resolved Wallet Session authority',
        },
        { status: 403 },
      );
    }
    const directIssue =
      await input.ctx.service.authorizationSessions.issueDirectWalletSessionAuthorizationV2({
        tenantId: input.ctx.service.authorizationSessions.tenantId,
        principalId: authorized.principalId,
        walletId: walletIdFromString(walletKey.walletId),
        authority: activeAuthority.authority,
        walletAuthMethodId: activeAuthority.authMethod.walletAuthMethodId,
        mintId: mintId.value,
        remainingUses: activated.session.remainingUses,
        issuedAtMs: activated.session.expiresAtMs - request.session_policy.ttl_ms,
        expiresAtMs: activated.session.expiresAtMs,
        walletSessionClientCapability: WALLET_SESSION_CLIENT_CAPABILITY_V1,
        responseFamily: WALLET_ECDSA_ACTIVATION_EXACT_RESPONSE_FAMILY_V1,
      });
    if (directIssue.kind === 'protocol_mismatch') {
      return json(directIssue, { status: 409 });
    }
    if (directIssue.kind === 'already_committed') {
      return json(
        {
          ok: false,
          code: 'already_committed',
          next: directIssue.next,
          wallet_id: directIssue.walletId,
          authority_id: directIssue.authorityId,
          wallet_auth_method_id: directIssue.walletAuthMethodId,
          authorization_id: directIssue.authorizationId,
          wallet_session_id: directIssue.walletSessionId,
          quota_id: directIssue.quotaId,
        },
        { status: 409 },
      );
    }
    return json(
      {
        kind: 'router_ab_ecdsa_post_registration_session_activated_v1',
        public_capability: request.public_capability,
        session: {
          authorization_session_id: authorized.authorizationSessionId,
          authorization_id: directIssue.session.authorizationId,
          threshold_session_id: activated.session.thresholdSessionId,
          wallet_session_id: directIssue.session.walletSessionId,
          quota_id: directIssue.session.quotaId,
          expires_at_ms: directIssue.session.expiresAtMs,
          remaining_uses: directIssue.quota.remainingUses,
          wallet_session: projectActiveWalletSession(directIssue),
          operation_credential: directIssue.operationCredential,
        },
        normal_signing: normalSigning,
      },
      { status: 200 },
    );
  }
  return assertNeverStrictEcdsaSessionActivationAuthorization(authorized);
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
    pathname !== ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH
  ) {
    return null;
  }

  const bodyUnknown = await readJson(ctx.request.clone());
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
    return handleRouterAbEcdsaDerivationNormalSigningRoute({
      ctx,
      body,
      phase: 'prepare',
    });
  }

  if (pathname === ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH) {
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
