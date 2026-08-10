import type { FetchRouterApiContext } from '../createFetchRouter';
import { json, readJson } from '../../../framework/http';
import {
  parseAppSessionClaims,
  parseRouterAbEcdsaDerivationWalletSessionClaims,
  type RouterAbEcdsaDerivationOwnerWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
  type RouterAbEd25519OwnerWalletSessionClaims,
  resolveAppSessionWalletIdForWalletScope,
  resolveAppSessionProviderUserIdForWalletScope,
} from '../../../../core/ThresholdService/validation';
import { thresholdEcdsaStatusCode } from '../../../../threshold/statusCodes';
import { parseSessionKind } from '../../../framework/routerApi';
import {
  signRouterAbEcdsaDerivationWalletSessionJwt,
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
  authenticateRouterAbOperationStepUpAppSessionIdentity,
  authorizeRouterAbEcdsaDerivationNormalSigningRoute,
  admitRouterAbEcdsaReusableWalletSessionOperation,
  claimRouterAbEcdsaOperationStepUp,
  completeRouterAbEcdsaOperation,
  routerAbEcdsaOperationInProgressResult,
  routerAbEcdsaReplayHttpResponse,
  routerAbEcdsaReplayUnavailableResult,
  resolveFreshRouterAbEcdsaMaterialActivation,
  routerAbEcdsaAtomicAuthorizationConfigured,
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
} from '../../../framework/authServicePort';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import {
  walletSessionFailure,
  walletSessionFailureStatus,
  walletSessionParseFailure,
  type WalletSessionBoundaryFailure,
} from '../../../auth/walletSessionFailure';
import {
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseSeamsSessionId,
  type MpcWalletSigningQuotaId,
  type PrincipalId,
  type ReusableWalletSessionMintId,
  type SeamsSessionId,
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
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { AuthorizedOperation } from '../../../../authorization/domain';
import {
  buildVerifiedEmailOtpFactorResult,
  buildVerifiedPasskeyFactorResult,
  type VerifiedAuthorizationFactorResult,
} from '../../../../authorization/factorEvidence';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { parseEmailOtpChallengeId, parseWalletId } from '@shared/utils/domainIds';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { hashEmailOtpAppSessionClaims } from '../../../domains/emailOtp/emailOtpSessionRouteHelpers';
import { proxyOwnerLaneAdmittedNormalSigningRequest } from './normalSigningRouterProxy';
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
      claims: authorization.validated.claims,
      authorizedOperations: input.ctx.service.authorizedOperations,
      authorizationSessions: input.ctx.service.authorizationSessions,
      resolveEcdsaMaterialActivation:
        input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation.bind(
          input.ctx.service.walletRegistration,
        ),
    });
    if (!operation.ok) {
      return json(operation.error.body, { status: operation.error.status });
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
    authorizedOperation = operation.admission.operation;
    authorizedOperationWire = buildRouterAbEcdsaAuthorizedOperationWire({
      operation: authorizedOperation,
      binding: {
        kind: 'reusable_wallet_session',
        walletSessionId: authorization.validated.claims.walletSessionId,
        quotaId: authorization.validated.claims.quotaId,
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
  const authenticated = await authenticateRouterAbOperationStepUpAppSessionIdentity({
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    walletId: operation.wallet_id,
    materialOwner: operation.material_activation.material_owner,
    authorizedOperations: input.ctx.service.authorizedOperations,
    authorizationSessions: input.ctx.service.authorizationSessions,
  });
  if (!authenticated.ok) {
    return json(authenticated.error.body, { status: authenticated.error.status });
  }
  if (
    operation.wallet_id !== authenticated.session.walletId ||
    operation.normal_signing_scope.wallet_id !== operation.wallet_id ||
    operation.normal_signing_scope.signing_worker.server_id !== operation.signing_worker_id ||
    operation.material_activation.material_owner !== authenticated.session.walletId ||
    operation.material_activation.signing_worker !== operation.signing_worker_id ||
    operation.expires_at_ms <= Date.now() ||
    operation.expires_at_ms > authenticated.expiresAtMs
  ) {
    return json(
      { ok: false, code: 'scope_mismatch', message: 'ECDSA operation step-up scope is invalid' },
      { status: 403 },
    );
  }
  const activeMaterial = await input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation({
    walletId: authenticated.session.walletId,
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
  const authorityRef = await walletAuthAuthorityRef({ authority });
  const activeSession = authenticated.activeSession;
  if (
    authorityRef.walletId !== authenticated.authorityRef.walletId ||
    authorityRef.authorityDigest !== authenticated.authorityRef.authorityDigest ||
    authority.walletId !== authenticated.session.walletId
  ) {
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
  const expiresAtMs = Math.min(operation.expires_at_ms, authenticated.expiresAtMs);
  let emailOtpUnseal: { readonly grant: string; readonly challengeId: string } | undefined;
  let factor!: VerifiedAuthorizationFactorResult;
  switch (proof.kind) {
    case 'passkey': {
      if (
        activeSession.authSource.kind !== 'passkey' ||
        proof.authority.factor.credentialIdB64u !== activeSession.authSource.credentialIdB64u
      ) {
        return json(
          { ok: false, code: 'scope_mismatch', message: 'Passkey authority changed' },
          { status: 403 },
        );
      }
      const credential = proof.webauthn_authentication;
      const credentialId = String(credential.rawId || credential.id).trim();
      if (credentialId !== activeSession.authSource.credentialIdB64u) {
        return json(
          { ok: false, code: 'unauthorized', message: 'Passkey credential changed' },
          { status: 401 },
        );
      }
      const origin =
        activeSession.audience.kind === 'first_party_web'
          ? activeSession.audience.origin
          : activeSession.audience.walletOrigin;
      const verified = await input.ctx.service.webAuthn.verifyWebAuthnAuthenticationLite({
        userId: authenticated.session.walletId,
        rpId: proof.authority.verifier.rpId,
        expectedChallenge,
        expected_origin: origin,
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
      factor = buildVerifiedPasskeyFactorResult({
        tenantId: authenticated.session.tenantId,
        principalId: authenticated.session.principalId,
        sessionId: authenticated.session.sessionId,
        deviceId: activeSession.deviceId,
        factorId: requireAuthorizationValue(
          parseAuthFactorId(`passkey:${activeSession.authSource.credentialIdB64u}`),
        ),
        authorityRef: authenticated.authorityRef,
        operation: envelope,
        credentialIdB64u: activeSession.authSource.credentialIdB64u,
        assertionDigest: parseDigestB64u(
          base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(credential))),
        ),
        verifiedAtMs: nowMs,
        expiresAtMs,
      });
      break;
    }
    case 'email_otp': {
      const sessionHash = await hashEmailOtpAppSessionClaims(authenticated.rawClaims);
      const verified = await input.ctx.service.emailOtp.verifyEmailOtpChallenge({
        userId: authenticated.session.principalId,
        walletId: authenticated.session.walletId,
        orgId: authenticated.session.tenantId,
        challengeId: proof.challenge_id,
        otpCode: proof.otp_code,
        otpChannel: EMAIL_OTP_CHANNEL,
        sessionHash,
        appSessionVersion: activeSession.appSessionVersion,
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
      factor = buildVerifiedEmailOtpFactorResult({
        tenantId: authenticated.session.tenantId,
        principalId: authenticated.session.principalId,
        sessionId: authenticated.session.sessionId,
        deviceId: activeSession.deviceId,
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
  const evidenceSet = await input.ctx.service.authorizedOperations.recordVerifiedFactorEvidenceSet({
    session: activeSession,
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

type RouterAbEcdsaPoolFillClaims = Pick<
  RouterAbEcdsaDerivationOwnerWalletSessionClaims,
  | 'walletId'
  | 'relayerKeyId'
  | 'keyHandle'
  | 'runtimePolicyScope'
  | 'participantIds'
  | 'thresholdExpiresAtMs'
  | 'routerAbEcdsaDerivationNormalSigning'
>;

type RouterAbEcdsaPoolFillAuthorizationResult =
  | {
      readonly ok: true;
      readonly claims: RouterAbEcdsaPoolFillClaims;
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
  const authenticated = await authenticateRouterAbOperationStepUpAppSessionIdentity({
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    walletId: input.operation.wallet_id,
    materialOwner: input.operation.material_activation.material_owner,
    authorizedOperations: input.ctx.service.authorizedOperations,
    authorizationSessions: input.ctx.service.authorizationSessions,
  });
  if (!authenticated.ok) return authenticated;
  if (input.operation.expires_at_ms > authenticated.expiresAtMs) {
    return {
      ok: false,
      error: {
        status: 403,
        body: {
          ok: false,
          code: 'scope_mismatch',
          message: 'ECDSA pool-fill operation exceeds the app session lifetime',
        },
      },
    };
  }
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
  return {
    ok: true,
    claims: {
      walletId: input.operation.wallet_id,
      relayerKeyId: input.operation.relayer_key_id,
      keyHandle: input.operation.key_handle,
      runtimePolicyScope: authenticated.session.runtimePolicyScope,
      participantIds: [...input.operation.participant_ids],
      thresholdExpiresAtMs: Math.min(input.operation.expires_at_ms, authenticated.expiresAtMs),
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
        session: input.ctx.opts.session,
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
      if (input.request.authorization.wallet_session_id !== validated.claims.walletSessionId) {
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
      if (!validated.claims.runtimePolicyScope) {
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
      const normalSigning = validated.claims.routerAbEcdsaDerivationNormalSigning;
      const requestedPoolFillMaterial = poolFillMaterialActivation(input.request);
      const activeMaterial =
        await input.ctx.service.walletRegistration.resolveEcdsaMaterialActivation({
          walletId: validated.claims.walletId,
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
        claims: {
          walletId: validated.claims.walletId,
          relayerKeyId: validated.claims.relayerKeyId,
          keyHandle: validated.claims.keyHandle,
          runtimePolicyScope: validated.claims.runtimePolicyScope,
          participantIds: validated.claims.participantIds,
          thresholdExpiresAtMs: validated.claims.thresholdExpiresAtMs,
          routerAbEcdsaDerivationNormalSigning:
            validated.claims.routerAbEcdsaDerivationNormalSigning,
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
      readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
      readonly ecdsaClaims: RouterAbEcdsaDerivationOwnerWalletSessionClaims | null;
    }
  | {
      readonly ok: false;
      readonly code: 'unauthorized' | 'identity_mismatch';
      readonly message: string;
    }
  | WalletSessionBoundaryFailure;

type StrictEcdsaAuthorizationClaims = {
  readonly appSessionClaims: NonNullable<ReturnType<typeof parseAppSessionClaims>> | null;
  readonly ecdsaClaims: RouterAbEcdsaDerivationOwnerWalletSessionClaims | null;
  readonly ed25519Claims: RouterAbEd25519OwnerWalletSessionClaims | null;
  readonly expiresAtMs: number;
};

type StrictEcdsaAuthorizationClaimsResult =
  | { readonly ok: true; readonly claims: StrictEcdsaAuthorizationClaims }
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

async function parseStrictEcdsaAuthorizationSession(
  ctx: FetchRouterApiContext,
): Promise<
  { readonly ok: true; readonly claims: Record<string, unknown> } | WalletSessionBoundaryFailure
> {
  const session = ctx.opts.session;
  if (!session) return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
  try {
    const parsed = await session.parse(Object.fromEntries(ctx.request.headers.entries()));
    if (!parsed.ok) return walletSessionParseFailure(parsed.reason);
    return { ok: true, claims: parsed.claims };
  } catch {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
  }
}

async function resolveStrictEcdsaAuthorizationClaims(input: {
  readonly ctx: FetchRouterApiContext;
  readonly rawClaims: Record<string, unknown>;
}): Promise<StrictEcdsaAuthorizationClaimsResult> {
  const appSessionClaims = parseAppSessionClaims(input.rawClaims);
  const parsedEcdsaClaims = parseRouterAbEcdsaDerivationWalletSessionClaims(input.rawClaims);
  const parsedEd25519Claims = parseRouterAbEd25519WalletSessionClaims(input.rawClaims);
  const ecdsaClaims =
    parsedEcdsaClaims?.authorizationKind === 'owner_wallet_session' ? parsedEcdsaClaims : null;
  const ed25519Claims =
    parsedEd25519Claims?.authorizationKind === 'owner_wallet_session' ? parsedEd25519Claims : null;
  if (!appSessionClaims && !ecdsaClaims && !ed25519Claims) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.claimsInvalid);
  }
  if (appSessionClaims) {
    try {
      const version = await input.ctx.service.sessionVersions.validateAppSessionVersion({
        userId: appSessionClaims.sub,
        appSessionVersion: appSessionClaims.appSessionVersion,
      });
      if (!version.ok) {
        return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.claimsInvalid);
      }
    } catch {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
    }
  }
  const expSeconds = appSessionClaims?.exp ?? ecdsaClaims?.exp ?? ed25519Claims?.exp;
  if (expSeconds === undefined || !Number.isSafeInteger(expSeconds) || expSeconds <= 0) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.claimsInvalid);
  }
  const expiresAtMs = expSeconds * 1000;
  if (!Number.isSafeInteger(expiresAtMs)) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.claimsInvalid);
  }
  if (expiresAtMs <= Date.now()) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.expired);
  }
  return {
    ok: true,
    claims: {
      appSessionClaims,
      ecdsaClaims,
      ed25519Claims,
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
  const parsedSession = await parseStrictEcdsaAuthorizationSession(input.ctx);
  if (!parsedSession.ok) {
    return parsedSession;
  }
  const resolvedClaims = await resolveStrictEcdsaAuthorizationClaims({
    ctx: input.ctx,
    rawClaims: parsedSession.claims,
  });
  if (!resolvedClaims.ok) return resolvedClaims;
  const { appSessionClaims, ecdsaClaims, ed25519Claims, expiresAtMs } = resolvedClaims.claims;
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
    ecdsaClaims?.walletId === authority.accountId ||
    ed25519Claims?.walletId === authority.accountId
  ) {
    return { ok: true, authority, ecdsaClaims };
  }
  const appSessionWalletId = resolveAppSessionWalletIdForWalletScope(
    appSessionClaims,
    authority.accountId,
  );
  if (appSessionWalletId === authority.accountId) {
    return { ok: true, authority, ecdsaClaims: null };
  }
  const providerUserId = resolveAppSessionProviderUserIdForWalletScope(
    appSessionClaims,
    authority.accountId,
  );
  if (providerUserId) {
    try {
      const enrollment = await input.ctx.service.emailOtp.readActiveEmailOtpEnrollment({
        walletId: authority.accountId,
        orgId: appSessionClaims?.runtimePolicyScope?.orgId,
        providerUserId,
      });
      if (enrollment.ok && enrollment.enrollment.providerUserId === providerUserId) {
        return { ok: true, authority, ecdsaClaims: null };
      }
    } catch {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
    }
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
  readonly authenticated: Extract<
    Awaited<ReturnType<typeof authenticateRouterAbOperationStepUpAppSessionIdentity>>,
    { readonly ok: true }
  >;
};

function buildStrictEcdsaExportOperationStepUpAdmission(
  input: StrictEcdsaExportOperationStepUpInput,
) {
  const operationId = requireAuthorizationValue(
    parseCapabilityOperationId(input.operation.operation_id),
  );
  const authorizedOperationId = requireAuthorizationValue(
    parseAuthorizedOperationId(
      `ecdsa-step-up-authorized-operation:${input.operation.operation_id}`,
    ),
  );
  return {
    authorizedOperationId,
    request: {
      material: {
        walletId: walletIdFromString(input.authenticated.session.walletId),
        keyHandle: input.keyHandle,
        runtimePolicyScope: input.authenticated.session.runtimePolicyScope,
        materialActivation: input.materialActivation,
      },
      operation: {
        tenantId: input.authenticated.session.tenantId,
        authorizedOperationId,
        auditEventId: requireAuthorizationValue(
          parseAuthorizationAuditEventId(
            `ecdsa-operation-step-up-audit:${input.operation.operation_id}`,
          ),
        ),
        operation: buildCapabilityOperationEnvelope({
          tenantId: input.authenticated.session.tenantId,
          principalId: input.authenticated.session.principalId,
          capabilityId: requireAuthorizationValue(
            parseCapabilityId(input.materialActivation.capability),
          ),
          operationId,
          operation: buildEvmEcdsaMpcOperationRef('evm.export_key'),
          digests: {
            laneDigest: parseDigestB64u(input.operation.operation_digests.lane_digest_b64u),
            intentDigest: parseDigestB64u(input.operation.operation_digests.intent_digest_b64u),
            displayDigest: parseDigestB64u(input.operation.operation_digests.display_digest_b64u),
          },
        }),
      },
    },
  };
}

async function admitStrictEcdsaExportOperationStepUp(
  input: StrictEcdsaExportOperationStepUpInput,
): Promise<StrictEcdsaExportOperationStepUpAdmissionResult> {
  if (!routerAbEcdsaAtomicAuthorizationConfigured(input.authenticated.authorizedOperations)) {
    return strictEcdsaExportFailure(
      501,
      'not_configured',
      'ECDSA atomic authorization is not configured',
    );
  }
  let admission;
  try {
    admission = buildStrictEcdsaExportOperationStepUpAdmission(input);
  } catch (error: unknown) {
    return strictEcdsaExportFailure(
      400,
      'invalid_body',
      error instanceof Error ? error.message : 'Export operation step-up admission is invalid',
    );
  }
  const fingerprint = await computeCapabilityOperationFingerprintDigest(
    admission.request.operation.operation,
  );
  const existing = await input.authenticated.authorizedOperations.readAuthorizedOperation({
    tenantId: admission.request.operation.tenantId,
    operationFingerprintDigest: fingerprint,
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
    existing.quota.kind !== 'quota_neutral'
  ) {
    return strictEcdsaExportFailure(
      409,
      'authorized_operation_missing',
      'ECDSA export operation authorization has an invalid source or quota',
    );
  }
  const result = await input.authenticated.authorizedOperations.admitAuthorizedOperation({
    operation: {
      tenantId: existing.tenantId,
      authorizedOperationId: existing.authorizedOperationId,
      auditEventId: existing.auditEventId,
      operation: admission.request.operation.operation,
      authorization: existing.authorization,
      quota: existing.quota,
      claimedAtMs: Date.now(),
    },
    material: admission.request.material,
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
    const authenticated = await authenticateRouterAbOperationStepUpAppSessionIdentity({
      headers: Object.fromEntries(input.ctx.request.headers.entries()),
      session: input.ctx.opts.session,
      walletId: operation.wallet_id,
      materialOwner: operation.material_activation.material_owner,
      authorizedOperations: input.ctx.service.authorizedOperations,
      authorizationSessions: input.ctx.service.authorizationSessions,
    });
    if (!authenticated.ok) {
      return { ok: false, error: authenticated.error };
    }
    if (operation.expires_at_ms > authenticated.expiresAtMs) {
      return strictEcdsaExportFailure(
        403,
        'scope_mismatch',
        'ECDSA export operation exceeds the app session lifetime',
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
      authenticated,
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
  const claims = input.authorization.ecdsaClaims;
  if (
    !claims ||
    claims.walletId !== input.request.lifecycle.account_id ||
    claims.thresholdSessionId !== input.request.lifecycle.session_id
  ) {
    return strictEcdsaExportFailure(403, 'scope_mismatch', 'ECDSA export session is invalid');
  }
  // The authenticated reusable Wallet Session is the attested authority. The
  // router additionally rejects any request whose own authorization branch
  // names a different session, so a step-up-authorized export cannot be
  // presented on a reusable-session route.
  if (
    input.request.authorization.kind !== 'reusable_wallet_session' ||
    input.request.authorization.wallet_session_id !== claims.walletSessionId
  ) {
    return strictEcdsaExportFailure(
      403,
      'scope_mismatch',
      'ECDSA export Wallet Session does not match the request',
    );
  }
  const scope = claims.routerAbEcdsaDerivationNormalSigning.scope;
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
    activeMaterial.keyHandle !== claims.keyHandle ||
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
      keyHandle: claims.keyHandle,
      authorization: {
        kind: 'reusable_wallet_session',
        wallet_session_id: claims.walletSessionId,
      },
      normalSigningScope: scope,
      privateAuthorization: {
        kind: 'reusable_wallet_session',
        walletSessionId: claims.walletSessionId,
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
      readonly principalId: PrincipalId;
      readonly authorizationSessionId: SeamsSessionId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly quotaId: MpcWalletSigningQuotaId;
      readonly expiresAtMs: number;
      readonly remainingUses: number;
      readonly authorityRef: WalletAuthAuthorityRef;
      readonly authSource: RouterAbEcdsaDerivationOwnerWalletSessionClaims['authSource'];
    }
  | {
      readonly ok: false;
      readonly code: 'unauthorized' | 'identity_mismatch';
      readonly message: string;
    }
  | WalletSessionBoundaryFailure;

async function authorizeStrictEcdsaSessionActivationFromEd25519Claims(input: {
  readonly ctx: FetchRouterApiContext;
  readonly walletId: string;
  readonly claims: RouterAbEd25519OwnerWalletSessionClaims;
}): Promise<StrictEcdsaReusableWalletSessionAuthorization> {
  const { claims } = input;
  if (claims.walletId !== input.walletId || !claims.sid) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  const principalId = parsePrincipalId(walletSessionPrincipalSubject(claims.authority));
  if (!principalId.ok) {
    return {
      ok: false,
      code: 'identity_mismatch',
      message: 'Ed25519 Wallet Session principal is invalid',
    };
  }
  const nowMs = Date.now();
  const activeSession = await input.ctx.service.authorizationSessions.readActiveSession({
    tenantId: input.ctx.service.authorizationSessions.tenantId,
    sessionId: claims.sid,
    nowMs,
  });
  if (!activeSession || activeSession.principalId !== principalId.value) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.expired);
  }
  const status = await input.ctx.service.authorizationSessions.readReusableWalletSessionStatus({
    tenantId: input.ctx.service.authorizationSessions.tenantId,
    principalId: principalId.value,
    walletSessionId: claims.walletSessionId,
    quotaId: claims.quotaId,
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
  return {
    ok: true,
    kind: 'reuse_reusable_wallet_session',
    principalId: principalId.value,
    authorizationSessionId: claims.sid,
    authorizationId: claims.authorizationId,
    walletSessionId: claims.walletSessionId,
    quotaId: claims.quotaId,
    expiresAtMs: status.expiresAtMs,
    remainingUses: status.remainingUses,
    authorityRef: await walletAuthAuthorityRef({ authority: claims.authority }),
    authSource: activeSession.authSource,
  };
}

async function authorizeStrictEcdsaSessionActivation(input: {
  readonly ctx: FetchRouterApiContext;
  readonly walletId: string;
  readonly source: 'verified_wallet_unlock' | 'additional_wallet_target';
  readonly verifiedAuthority?: WalletAuthAuthorityRef;
}): Promise<
  | {
      readonly ok: true;
      readonly kind: 'issue_reusable_wallet_session';
      readonly principalId: PrincipalId;
      readonly authorizationSessionId: SeamsSessionId;
      readonly authority: WalletAuthAuthorityRef;
      readonly authSource: RouterAbEcdsaDerivationOwnerWalletSessionClaims['authSource'];
    }
  | StrictEcdsaReusableWalletSessionAuthorization
> {
  const parsedSession = await parseStrictEcdsaAuthorizationSession(input.ctx);
  if (!parsedSession.ok) return parsedSession;
  const resolvedClaims = await resolveStrictEcdsaAuthorizationClaims({
    ctx: input.ctx,
    rawClaims: parsedSession.claims,
  });
  if (!resolvedClaims.ok) return resolvedClaims;
  const { appSessionClaims, ecdsaClaims, ed25519Claims } = resolvedClaims.claims;
  if (input.verifiedAuthority) {
    if (
      input.source !== 'verified_wallet_unlock' ||
      input.verifiedAuthority.walletId !== input.walletId ||
      !appSessionClaims?.seamsSessionId
    ) {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
    }
    const principalId = parsePrincipalId(appSessionClaims.sub);
    if (!principalId.ok) {
      return {
        ok: false,
        code: 'identity_mismatch',
        message: 'App session principal is invalid',
      };
    }
    const activeSession = await input.ctx.service.authorizationSessions.readActiveSession({
      tenantId: input.ctx.service.authorizationSessions.tenantId,
      sessionId: appSessionClaims.seamsSessionId,
      nowMs: Date.now(),
    });
    if (!activeSession || activeSession.principalId !== principalId.value) {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.expired);
    }
    return {
      ok: true,
      kind: 'issue_reusable_wallet_session',
      principalId: principalId.value,
      authorizationSessionId: appSessionClaims.seamsSessionId,
      authority: input.verifiedAuthority,
      authSource: activeSession.authSource,
    };
  }
  if (ecdsaClaims?.walletId === input.walletId) {
    if (input.source === 'verified_wallet_unlock') {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
    }
    const nowMs = Date.now();
    const activeSession = await input.ctx.service.authorizationSessions.readActiveSession({
      tenantId: input.ctx.service.authorizationSessions.tenantId,
      sessionId: ecdsaClaims.authorizationSessionId,
      nowMs,
    });
    if (!activeSession) {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.expired);
    }
    // ECDSA Wallet Session `sub` identifies the wallet key. Reusable grants are
    // owned by the authorization-session principal, which may be a provider
    // subject for Email OTP wallets.
    const principalId = activeSession.principalId;
    const status = await input.ctx.service.authorizationSessions.readReusableWalletSessionStatus({
      tenantId: input.ctx.service.authorizationSessions.tenantId,
      principalId,
      walletSessionId: ecdsaClaims.walletSessionId,
      quotaId: ecdsaClaims.quotaId,
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
    return {
      ok: true,
      kind: 'reuse_reusable_wallet_session',
      principalId,
      authorizationSessionId: ecdsaClaims.authorizationSessionId,
      authorizationId: ecdsaClaims.authorizationId,
      walletSessionId: ecdsaClaims.walletSessionId,
      quotaId: ecdsaClaims.quotaId,
      expiresAtMs: status.expiresAtMs,
      remainingUses: status.remainingUses,
      authorityRef: ecdsaClaims.walletAuthAuthorityRef,
      authSource: ecdsaClaims.authSource,
    };
  }
  if (ed25519Claims) {
    return authorizeStrictEcdsaSessionActivationFromEd25519Claims({
      ctx: input.ctx,
      walletId: input.walletId,
      claims: ed25519Claims,
    });
  }
  if (input.source === 'additional_wallet_target') {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  let appSessionAuthorized =
    resolveAppSessionWalletIdForWalletScope(appSessionClaims, input.walletId) === input.walletId;
  const providerUserId = resolveAppSessionProviderUserIdForWalletScope(
    appSessionClaims,
    input.walletId,
  );
  if (!appSessionAuthorized && providerUserId) {
    try {
      const enrollment = await input.ctx.service.emailOtp.readActiveEmailOtpEnrollment({
        walletId: input.walletId,
        orgId: appSessionClaims?.runtimePolicyScope?.orgId,
        providerUserId,
      });
      if (enrollment.ok && enrollment.enrollment.providerUserId === providerUserId) {
        appSessionAuthorized = true;
      }
    } catch {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
    }
  }
  if (
    appSessionAuthorized &&
    appSessionClaims?.seamsSessionId &&
    appSessionClaims.walletAuthAuthorityRef
  ) {
    const principalId = parsePrincipalId(appSessionClaims.sub);
    if (!principalId.ok) {
      return {
        ok: false,
        code: 'identity_mismatch',
        message: 'App session principal is invalid',
      };
    }
    const activeSession = await input.ctx.service.authorizationSessions.readActiveSession({
      tenantId: input.ctx.service.authorizationSessions.tenantId,
      sessionId: appSessionClaims.seamsSessionId,
      nowMs: Date.now(),
    });
    if (!activeSession || activeSession.principalId !== principalId.value) {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.expired);
    }
    return {
      ok: true,
      kind: 'issue_reusable_wallet_session',
      principalId: principalId.value,
      authorizationSessionId: appSessionClaims.seamsSessionId,
      authority: appSessionClaims.walletAuthAuthorityRef,
      authSource: activeSession.authSource,
    };
  }
  return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
}

async function authorizeStrictEcdsaSessionActivationFromEd25519(input: {
  readonly ctx: FetchRouterApiContext;
  readonly walletId: string;
  readonly walletSessionJwt: string;
}): Promise<StrictEcdsaReusableWalletSessionAuthorization> {
  const session = input.ctx.opts.session;
  if (!session) return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
  let parsedEd25519Session: Awaited<ReturnType<typeof session.parse>>;
  try {
    parsedEd25519Session = await session.parse({
      authorization: `Bearer ${input.walletSessionJwt}`,
    });
  } catch {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.unavailable);
  }
  if (!parsedEd25519Session.ok) {
    return walletSessionParseFailure(parsedEd25519Session.reason);
  }
  const ed25519ClaimsResult = await resolveStrictEcdsaAuthorizationClaims({
    ctx: input.ctx,
    rawClaims: parsedEd25519Session.claims,
  });
  if (!ed25519ClaimsResult.ok) return ed25519ClaimsResult;
  const ed25519Claims = ed25519ClaimsResult.claims.ed25519Claims;
  if (!ed25519Claims) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
  }
  return authorizeStrictEcdsaSessionActivationFromEd25519Claims({
    ctx: input.ctx,
    walletId: input.walletId,
    claims: ed25519Claims,
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
      readonly verifiedAuthority?: WalletAuthAuthorityRef;
    }
  | {
      readonly ctx: FetchRouterApiContext;
      readonly body: unknown;
      readonly source: 'verified_ed25519_wallet_session';
      readonly walletSessionJwt: string;
    }
  | {
      readonly ctx: FetchRouterApiContext;
      readonly body: unknown;
      readonly source: 'verified_passkey_session_exchange';
      readonly authorization: {
        readonly walletId: string;
        readonly principalId: PrincipalId;
        readonly authorizationSessionId: SeamsSessionId;
        readonly authority: WalletAuthAuthorityRef;
        readonly authSource: RouterAbEcdsaDerivationOwnerWalletSessionClaims['authSource'];
      };
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
    input.source === 'verified_passkey_session_exchange'
      ? request.public_capability.client_id === input.authorization.walletId
        ? {
            ok: true as const,
            kind: 'issue_reusable_wallet_session' as const,
            principalId: input.authorization.principalId,
            authorizationSessionId: input.authorization.authorizationSessionId,
            authority: input.authorization.authority,
            authSource: input.authorization.authSource,
          }
        : {
            ok: false as const,
            code: 'identity_mismatch' as const,
            message: 'ECDSA activation wallet does not match the verified passkey principal',
          }
      : input.source === 'verified_ed25519_wallet_session'
        ? await authorizeStrictEcdsaSessionActivationFromEd25519({
            ctx: input.ctx,
            walletId: request.public_capability.client_id,
            walletSessionJwt: input.walletSessionJwt,
          })
        : await authorizeStrictEcdsaSessionActivation({
            ctx: input.ctx,
            walletId: request.public_capability.client_id,
            source: input.source,
            verifiedAuthority: input.verifiedAuthority,
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
  let authSource: RouterAbEcdsaDerivationOwnerWalletSessionClaims['authSource'];
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
  const signed = await signRouterAbEcdsaDerivationWalletSessionJwt({
    session: input.ctx.opts.session,
    walletAuthAuthorityRef,
    authSource,
    userId: walletKey.walletId,
    relayerKeyId: walletKey.relayerKeyId,
    sessionInfo: {
      sessionKind: 'jwt',
      authorizationKind: 'owner_wallet_session',
      authorizationSessionId: authorized.authorizationSessionId,
      authorizationId,
      thresholdSessionId: activated.session.thresholdSessionId,
      walletSessionId,
      quotaId,
      expiresAtMs,
      participantIds: walletKey.participantIds,
      runtimePolicyScope: request.session_policy.runtime_policy_scope,
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
    requireJwtErrorMessage:
      'Router A/B ECDSA post-registration Wallet Session must use jwt sessionKind',
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
        wallet_session_jwt: signed.jwt,
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
    return handleStrictEcdsaSessionActivation({
      ctx,
      body: bodyUnknown,
      source: 'additional_wallet_target',
    });
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
        claims: authorized.claims,
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
        claims: authorized.claims,
        request: ecdsaPoolFillStepRuntimeRequest(parsedBody.request),
      });
      return json(result, { status: thresholdEcdsaStatusCode(result) });
    } finally {
      gateTicket.release();
    }
  }
  return null;
}
