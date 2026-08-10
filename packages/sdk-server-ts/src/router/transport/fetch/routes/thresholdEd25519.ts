import type { FetchRouterApiContext } from '../createFetchRouter';
import { json, readJson } from '../../../framework/http';
import { thresholdEd25519StatusCode } from '../../../../threshold/statusCodes';
import {
  ROUTER_AB_ED25519_HEALTH_PATH,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PATH,
  ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH,
  ROUTER_AB_ED25519_WALLET_SESSION_PATH,
} from '@shared/utils/signingSessionSeal';
import { resolveThresholdRuntimePolicyScope } from '../../../auth/commonRouterUtils';
import { normalizeCorsOrigin } from '../../../../core/SessionService';
import {
  authenticateRouterAbOperationStepUpAppSession,
  authorizeRouterAbEd25519NormalSigningRoute,
  buildRouterAbEd25519PrivateSigningWorkerBody,
  parseRouterAbEd25519OperationStepUpScope,
  parseRouterAbOperationStepUpOperation,
  type RouterAbEd25519NormalSigningRoutePhase,
} from '../../../domains/signingOperations/routerAbPrivateSigningWorker';
import {
  parseThresholdEd25519OperationStepUpGrantRequest,
  parseThresholdEd25519SessionRouteRequest,
} from '../../../domains/ed25519Yao/session/thresholdEd25519RequestValidation';
import {
  isPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { isPlainObject } from '@shared/utils/validation';
import { sameRouterAbMpcMaterialActivationRef } from '@shared/utils/routerAbNormalSigningIdentity';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseAuthorizationAuditEventId,
  buildAuthorizationGrantRef,
  buildNearEd25519MpcOperationRef,
  parseAuthFactorId,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseAuthorizationEvidenceId,
  parseAuthorizationEvidenceSetId,
  parsePrincipalId,
  parseTenantId,
} from '@shared/authorization/capabilityKinds';
import {
  buildCapabilityOperationEnvelope,
  computeCapabilityOperationFingerprintDigest,
  parseCapabilityOperationFingerprintDigest,
  parseSigningOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import type { CapabilityOperationEnvelope } from '@shared/authorization/operationFingerprint';
import type { CapabilityOperationRef } from '@shared/authorization/capabilityKinds';
import {
  authorizedOperationReplayBodyInit,
  type AuthorizedOperation,
  type AuthorizedOperationInput,
  type AuthorizedOperationReplayResponse,
} from '../../../../authorization/domain';
import {
  buildVerifiedEmailOtpFactorResult,
  buildVerifiedPasskeyFactorResult,
  type VerifiedAuthorizationFactorResult,
} from '../../../../authorization/factorEvidence';
import {
  parseAppSessionClaims,
  resolveAppSessionWalletIdForWalletScope,
} from '../../../../core/ThresholdService/validation';
import type {
  RouterAbEd25519YaoBudgetRefreshAuthorizationV1,
  RouterAbEd25519YaoOperationStepUpGrantCommandV1,
  RouterAbEd25519YaoSessionRouteCommandV1,
} from '../../../domains/ed25519Yao/session/routerAbEd25519YaoWalletSession';
import { proxyOwnerLaneAdmittedNormalSigningRequest } from './normalSigningRouterProxy';
import { handleLinkedDeviceEd25519NormalSigning } from './linkedDeviceNormalSigning';
import { parseEmailOtpChallengeId, parseWalletId } from '@shared/utils/domainIds';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  emailOtpStatusCode,
  hashEmailOtpAppSessionClaims,
} from '../../../domains/emailOtp/emailOtpSessionRouteHelpers';
import type {
  RouterAbEd25519YaoOperationStepUpMaterialRecoveryRequest,
  RouterAbEd25519YaoOperationStepUpMaterialRecoveryResponse,
} from '../../../domains/ed25519Yao/session/routerAbEd25519YaoWalletSession';

type Ed25519ReusableAuthorizedOperationReceipt = {
  readonly kind: 'reusable_wallet_session_authorized_operation_v1';
  readonly authorized_operation_id: string;
  readonly operation_id: string;
  readonly capability_kind: 'near_ed25519_mpc_signing';
  readonly operation_kind:
    | 'near.sign_transaction'
    | 'near.sign_delegate_action'
    | 'near.sign_nep413_message';
  readonly lane_digest_b64u: string;
  readonly intent_digest_b64u: string;
  readonly display_digest_b64u: string;
  readonly operation_fingerprint_digest: string;
};

type Ed25519VerifiedStepUpAuthorizedOperationReceipt = {
  readonly kind: 'verified_step_up_authorized_operation_v1';
  readonly authorization_session_id: string;
  readonly evidence_set_digest: string;
  readonly authorized_operation_id: string;
  readonly operation_id: string;
  readonly capability_kind: 'near_ed25519_mpc_signing';
  readonly operation_kind:
    | 'near.sign_transaction'
    | 'near.sign_delegate_action'
    | 'near.sign_nep413_message';
  readonly lane_digest_b64u: string;
  readonly intent_digest_b64u: string;
  readonly display_digest_b64u: string;
  readonly operation_fingerprint_digest: string;
};

type Ed25519OperationKind = Ed25519ReusableAuthorizedOperationReceipt['operation_kind'];

type Ed25519AuthorizedOperationAdmission =
  | {
      readonly kind: 'claimed';
      readonly operation: AuthorizedOperation;
      readonly receipt: Ed25519ReusableAuthorizedOperationReceipt;
    }
  | {
      readonly kind: 'operation_in_progress';
      readonly operation: AuthorizedOperation;
    }
  | {
      readonly kind: 'replayed';
      readonly operation: AuthorizedOperation;
    };

function reusableWalletSessionPrincipalSubject(authority: WalletAuthAuthority): string {
  switch (authority.factor.kind) {
    case 'email_otp':
      return authority.factor.providerUserId;
    case 'passkey':
      return authority.walletId;
  }
}

type RouterAbEd25519AuthorizedOperationWire = {
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
    | Ed25519ReusableAuthorizedOperationReceipt
    | (Ed25519VerifiedStepUpAuthorizedOperationReceipt & {
        readonly evidence_set_digest: string;
      });
};

type RouterAbEd25519AuthorizedOperationWireInput =
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

function buildRouterAbEd25519AuthorizedOperationWire(
  input: RouterAbEd25519AuthorizedOperationWireInput,
): RouterAbEd25519AuthorizedOperationWire {
  const operation = input.operation;
  const operationRef = operation.operation.operation;
  if (operationRef.capabilityKind !== 'near_ed25519_mpc_signing') {
    throw new Error('Ed25519 authorized operation capability is invalid');
  }
  const operationKind = requireEd25519OperationKind(operationRef.operationKind);
  const commonAuthorizedOperation = {
    authorized_operation_id: operation.authorizedOperationId,
    operation_id: operation.operation.operationId,
    capability_kind: 'near_ed25519_mpc_signing' as const,
    operation_kind: operationKind,
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

function requireReceiptString(record: Record<string, unknown>, name: string): string {
  const field = typeof record[name] === 'string' ? record[name].trim() : '';
  if (!field) throw new Error(`authorized_operation.${name} is required`);
  return field;
}

function requireEd25519OperationKind(value: unknown): Ed25519OperationKind {
  if (
    value !== 'near.sign_transaction' &&
    value !== 'near.sign_delegate_action' &&
    value !== 'near.sign_nep413_message'
  ) {
    throw new Error('authorized_operation.operation_kind is invalid');
  }
  return value;
}

function requireExactAuthorizedOperationFields(
  record: Record<string, unknown>,
  branchFields: readonly string[] = [],
): void {
  const expected = [
    'capability_kind',
    'display_digest_b64u',
    'intent_digest_b64u',
    'kind',
    'lane_digest_b64u',
    'operation_fingerprint_digest',
    'operation_id',
    'operation_kind',
    'authorized_operation_id',
    ...branchFields,
  ];
  expected.sort();
  const actual = Object.keys(record).sort();
  if (
    actual.length !== expected.length ||
    actual.some((field, index) => field !== expected[index])
  ) {
    throw new Error('authorized_operation has invalid fields');
  }
}

type PasskeyEd25519AuthorizationResult =
  | {
      ok: true;
      authorization: Extract<
        RouterAbEd25519YaoBudgetRefreshAuthorizationV1,
        {
          kind:
            | 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1'
            | 'verified_passkey_app_session_router_ab_ed25519_yao_budget_refresh_v1';
        }
      >;
    }
  | { ok: false; response: Response };

async function validatePasskeyEd25519SessionAuthorization(input: {
  ctx: FetchRouterApiContext;
  request: RouterAbEd25519YaoSessionRouteCommandV1;
  authority: PasskeyWalletAuthAuthority;
}): Promise<PasskeyEd25519AuthorizationResult> {
  const credential = input.request.routeAuth;
  if (credential.kind !== 'passkey') {
    throw new Error('validatePasskeyEd25519SessionAuthorization requires passkey route auth');
  }
  const credentialIdB64u = String(
    credential.webauthnAuthentication.rawId || credential.webauthnAuthentication.id || '',
  ).trim();
  if (!credentialIdB64u || credentialIdB64u !== input.authority.factor.credentialIdB64u) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'unauthorized',
          message: 'WebAuthn proof does not match the active Ed25519 Wallet Session authority',
        },
        { status: 401 },
      ),
    };
  }
  const expectedOrigin = normalizeCorsOrigin(input.ctx.request.headers.get('origin') || undefined);
  if (!expectedOrigin) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn authentication verification',
        },
        { status: 400 },
      ),
    };
  }
  const expectedChallenge = base64UrlEncode(
    await sha256BytesUtf8(alphabetizeStringify(input.request.sessionPolicy)),
  );
  const verified = await input.ctx.service.webAuthn.verifyWebAuthnAuthenticationLite({
    userId: input.authority.walletId,
    rpId: input.authority.verifier.rpId,
    expectedChallenge,
    expected_origin: expectedOrigin,
    webauthn_authentication: credential.webauthnAuthentication,
  });
  if (verified.success && verified.verified) {
    return {
      ok: true,
      authorization: {
        kind: 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1',
        authority: input.authority,
        verifiedChallengeId: expectedChallenge,
      },
    };
  }
  return {
    ok: false,
    response: json(
      {
        ok: false,
        code: verified.code || 'not_verified',
        message: verified.message || 'WebAuthn authentication verification failed',
      },
      { status: 401 },
    ),
  };
}

async function validateSignedEd25519SessionAuthorization(input: {
  ctx: FetchRouterApiContext;
  request: RouterAbEd25519YaoSessionRouteCommandV1;
  authority: PasskeyWalletAuthAuthority;
}): Promise<PasskeyEd25519AuthorizationResult> {
  if (input.request.routeAuth.kind !== 'signed_session') {
    throw new Error('validateSignedEd25519SessionAuthorization requires signed-session route auth');
  }
  const session = input.ctx.opts.session;
  if (!session) {
    return {
      ok: false,
      response: json(
        { ok: false, code: 'unauthorized', message: 'Signed session authorization is unavailable' },
        { status: 401 },
      ),
    };
  }
  const parsedSession = await session.parse(
    Object.fromEntries(input.ctx.request.headers.entries()),
  );
  if (!parsedSession.ok) {
    return {
      ok: false,
      response: json(
        { ok: false, code: 'unauthorized', message: 'Signed session authorization is required' },
        { status: 401 },
      ),
    };
  }
  let appSessionClaims = parseAppSessionClaims(parsedSession.claims);
  if (
    appSessionClaims &&
    (!isPlainObject(parsedSession.claims) || parsedSession.claims.provider !== 'passkey')
  ) {
    appSessionClaims = null;
  }
  if (appSessionClaims) {
    const version = await input.ctx.service.sessionVersions.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!version.ok) appSessionClaims = null;
  }
  const appSessionWalletId = resolveAppSessionWalletIdForWalletScope(
    appSessionClaims,
    input.authority.walletId,
  );
  if (
    !appSessionClaims ||
    appSessionWalletId !== input.authority.walletId ||
    !appSessionClaims.seamsSessionId
  ) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'unauthorized',
          message: 'Passkey app session does not authorize the active Ed25519 wallet',
        },
        { status: 401 },
      ),
    };
  }
  const expectedAuthorityRef = await walletAuthAuthorityRef({ authority: input.authority });
  const signedAuthorityRef = appSessionClaims.walletAuthAuthorityRef;
  if (
    !signedAuthorityRef ||
    signedAuthorityRef.walletId !== expectedAuthorityRef.walletId ||
    signedAuthorityRef.authorityDigest !== expectedAuthorityRef.authorityDigest
  ) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'unauthorized',
          message: 'Passkey app session authority does not match the active Ed25519 authority',
        },
        { status: 401 },
      ),
    };
  }
  const signedRuntimePolicyScope = appSessionClaims.runtimePolicyScope;
  if (
    !signedRuntimePolicyScope ||
    alphabetizeStringify(signedRuntimePolicyScope) !==
      alphabetizeStringify(input.request.sessionPolicy.runtimePolicyScope)
  ) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'scope_mismatch',
          message: 'Passkey app session runtime scope does not match the Ed25519 session policy',
        },
        { status: 403 },
      ),
    };
  }
  return {
    ok: true,
    authorization: {
      kind: 'verified_passkey_app_session_router_ab_ed25519_yao_budget_refresh_v1',
      authority: input.authority,
      authorityRef: signedAuthorityRef,
      runtimePolicyScope: signedRuntimePolicyScope,
      seamsSessionId: appSessionClaims.seamsSessionId,
    },
  };
}

function requireAuthorizationValue<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function digestWireB64u(value: unknown, label: string): string {
  const record = isPlainObject(value) ? value : null;
  const bytes = Array.isArray(record?.bytes) ? record.bytes.map(Number) : [];
  if (
    bytes.length !== 32 ||
    !bytes.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)
  ) {
    throw new Error(`${label} must contain exactly 32 bytes`);
  }
  return base64UrlEncode(Uint8Array.from(bytes));
}

function parseEd25519ReusableAuthorizedOperationReceipt(
  value: unknown,
): Ed25519ReusableAuthorizedOperationReceipt {
  const record = isPlainObject(value) ? value : null;
  if (!record || record.kind !== 'reusable_wallet_session_authorized_operation_v1') {
    throw new Error('Ed25519 reusable Wallet Session authorized operation is required');
  }
  requireExactAuthorizedOperationFields(record);
  const capabilityKind = requireReceiptString(record, 'capability_kind');
  if (capabilityKind !== 'near_ed25519_mpc_signing') {
    throw new Error('authorized_operation.capability_kind is invalid');
  }
  const operationKind = requireEd25519OperationKind(requireReceiptString(record, 'operation_kind'));
  const laneDigest = requireReceiptString(record, 'lane_digest_b64u');
  const intentDigest = requireReceiptString(record, 'intent_digest_b64u');
  const displayDigest = requireReceiptString(record, 'display_digest_b64u');
  parseDigestB64u(laneDigest);
  parseDigestB64u(intentDigest);
  parseDigestB64u(displayDigest);
  const fingerprint = requireReceiptString(record, 'operation_fingerprint_digest');
  parseCapabilityOperationFingerprintDigest(fingerprint);
  return {
    kind: 'reusable_wallet_session_authorized_operation_v1',
    authorized_operation_id: requireReceiptString(record, 'authorized_operation_id'),
    operation_id: requireReceiptString(record, 'operation_id'),
    capability_kind: 'near_ed25519_mpc_signing',
    operation_kind: operationKind,
    lane_digest_b64u: laneDigest,
    intent_digest_b64u: intentDigest,
    display_digest_b64u: displayDigest,
    operation_fingerprint_digest: fingerprint,
  };
}

function parseEd25519VerifiedStepUpAuthorizedOperationReceipt(
  value: unknown,
): Ed25519VerifiedStepUpAuthorizedOperationReceipt {
  const record = isPlainObject(value) ? value : null;
  if (!record || record.kind !== 'verified_step_up_authorized_operation_v1') {
    throw new Error('Ed25519 verified step-up authorized operation is required');
  }
  requireExactAuthorizedOperationFields(record, [
    'authorization_session_id',
    'evidence_set_digest',
  ]);
  const capabilityKind = requireReceiptString(record, 'capability_kind');
  if (capabilityKind !== 'near_ed25519_mpc_signing') {
    throw new Error('authorized_operation.capability_kind is invalid');
  }
  const operationKind = requireEd25519OperationKind(requireReceiptString(record, 'operation_kind'));
  const evidenceSetDigest = requireReceiptString(record, 'evidence_set_digest');
  parseDigestB64u(evidenceSetDigest);
  const laneDigest = requireReceiptString(record, 'lane_digest_b64u');
  const intentDigest = requireReceiptString(record, 'intent_digest_b64u');
  const displayDigest = requireReceiptString(record, 'display_digest_b64u');
  parseDigestB64u(laneDigest);
  parseDigestB64u(intentDigest);
  parseDigestB64u(displayDigest);
  const fingerprint = requireReceiptString(record, 'operation_fingerprint_digest');
  parseCapabilityOperationFingerprintDigest(fingerprint);
  return {
    kind: 'verified_step_up_authorized_operation_v1',
    authorization_session_id: requireReceiptString(record, 'authorization_session_id'),
    evidence_set_digest: evidenceSetDigest,
    authorized_operation_id: requireReceiptString(record, 'authorized_operation_id'),
    operation_id: requireReceiptString(record, 'operation_id'),
    capability_kind: 'near_ed25519_mpc_signing',
    operation_kind: operationKind,
    lane_digest_b64u: laneDigest,
    intent_digest_b64u: intentDigest,
    display_digest_b64u: displayDigest,
    operation_fingerprint_digest: fingerprint,
  };
}

async function authorizeEd25519ReusableWalletSessionOperation(input: {
  ctx: FetchRouterApiContext;
  body: Record<string, unknown>;
  authorization: Extract<
    Awaited<ReturnType<typeof authorizeRouterAbEd25519NormalSigningRoute>>,
    { readonly ok: true; readonly kind: 'reusable_wallet_session' }
  >;
}): Promise<
  | {
      readonly ok: true;
      readonly admission: Ed25519AuthorizedOperationAdmission;
    }
  | { readonly ok: false; readonly response: Response }
> {
  try {
    const scope = parseRouterAbEd25519OperationStepUpScope(input.body.scope);
    if (scope.authorization.kind !== 'reusable_wallet_session') {
      throw new Error('Reusable Wallet Session authority is required');
    }
    const operation = parseRouterAbOperationStepUpOperation(input.body.intent);
    if (!operation.ok) throw new Error(operation.message);
    const intent = isPlainObject(input.body.intent) ? input.body.intent : null;
    if (!intent) throw new Error('Ed25519 normal-signing intent is required');
    const privateBody = await buildRouterAbEd25519PrivateSigningWorkerBody({
      phase: 'prepare',
      body: input.body,
      authorization: {
        kind: 'reusable_wallet_session',
        claims: input.authorization.validated.claims,
      },
      headers: Object.fromEntries(input.ctx.request.headers.entries()),
    });
    if (!('admission_candidate' in privateBody)) {
      throw new Error('Ed25519 normal-signing prepare admission is required');
    }
    const claims = input.authorization.validated.claims;
    const nowMs = Date.now();
    const tenantId = requireAuthorizationValue(parseTenantId(claims.runtimePolicyScope.orgId));
    const principalId = requireAuthorizationValue(
      parsePrincipalId(reusableWalletSessionPrincipalSubject(claims.authority)),
    );
    if (
      tenantId !== input.ctx.service.authorizedOperations.tenantId ||
      tenantId !== input.ctx.service.authorizationSessions.tenantId ||
      scope.authorization.wallet_session_id !== claims.walletSessionId
    ) {
      return {
        ok: false,
        response: json(
          { ok: false, code: 'wallet_session_mismatch', message: 'Wallet Session changed' },
          { status: 403 },
        ),
      };
    }
    const capabilityId = requireAuthorizationValue(
      parseCapabilityId(scope.material_activation.capability),
    );
    const laneDigest = parseSigningOperationFingerprintDigest(intent.operation_fingerprint);
    const intentDigest = parseDigestB64u(
      base64UrlEncode(Uint8Array.from(privateBody.admission_candidate.intent_digest.bytes)),
    );
    const displayDigest = parseDigestB64u(
      digestWireB64u(input.body.display_digest, 'display_digest'),
    );
    const envelope = buildCapabilityOperationEnvelope({
      tenantId,
      principalId,
      capabilityId,
      operationId: operation.operationId,
      operation: operation.operation,
      digests: { laneDigest, intentDigest, displayDigest },
    });
    const authorizedOperationId = requireAuthorizationValue(
      parseAuthorizedOperationId(`ed25519-operation:${operation.operationId}:${scope.request_id}`),
    );
    const outcome = await input.ctx.service.authorizedOperations.admitAuthorizedOperation({
      operation: {
        tenantId,
        authorizedOperationId,
        auditEventId: requireAuthorizationValue(
          parseAuthorizationAuditEventId(`ed25519-operation-audit:${operation.operationId}`),
        ),
        operation: envelope,
        authorization: {
          kind: 'authorization_grant',
          authorizationGrantRef: buildAuthorizationGrantRef(claims.authorizationId),
        },
        quota: { kind: 'consume_reusable_wallet_session', quotaId: claims.quotaId },
        claimedAtMs: nowMs,
      },
    });
    if (
      outcome.kind !== 'claimed' &&
      outcome.kind !== 'operation_in_progress' &&
      outcome.kind !== 'replayed'
    ) {
      return {
        ok: false,
        response: json(
          { ok: false, code: outcome.kind, message: 'Ed25519 authorized operation rejected' },
          { status: outcome.kind === 'authorization_grant_rejected' ? 403 : 409 },
        ),
      };
    }
    if (outcome.kind === 'operation_in_progress' || outcome.kind === 'replayed') {
      return {
        ok: true,
        admission: {
          kind: outcome.kind,
          operation: outcome.operation,
        },
      };
    }
    return {
      ok: true,
      admission: {
        kind: 'claimed',
        operation: outcome.operation,
        receipt: {
          kind: 'reusable_wallet_session_authorized_operation_v1',
          authorized_operation_id: outcome.operation.authorizedOperationId,
          operation_id: outcome.operation.operation.operationId,
          capability_kind: 'near_ed25519_mpc_signing',
          operation_kind: requireEd25519OperationKind(
            outcome.operation.operation.operation.operationKind,
          ),
          lane_digest_b64u: laneDigest,
          intent_digest_b64u: intentDigest,
          display_digest_b64u: displayDigest,
          operation_fingerprint_digest: outcome.operation.operationFingerprintDigest,
        },
      },
    };
  } catch (error: unknown) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'invalid_body',
          message:
            error instanceof Error ? error.message : 'Ed25519 authorized operation is invalid',
        },
        { status: 400 },
      ),
    };
  }
}

async function revalidateEd25519AuthorizedOperation(input: {
  readonly ctx: FetchRouterApiContext;
  readonly operation: AuthorizedOperation;
}): Promise<
  | { readonly ok: true; readonly operation: AuthorizedOperation }
  | { readonly ok: false; readonly response: Response }
> {
  let admission: AuthorizedOperationInput;
  if (input.operation.authorization.kind === 'verified_step_up') {
    if (input.operation.quota.kind !== 'quota_neutral') {
      return {
        ok: false,
        response: json(
          {
            ok: false,
            code: 'verified_step_up_rejected',
            message: 'Ed25519 operation step-up authorization has an invalid quota',
          },
          { status: 403 },
        ),
      };
    }
    admission = {
      tenantId: input.operation.tenantId,
      authorizedOperationId: input.operation.authorizedOperationId,
      auditEventId: input.operation.auditEventId,
      operation: input.operation.operation,
      authorization: input.operation.authorization,
      quota: input.operation.quota,
      claimedAtMs: Date.now(),
    };
  } else {
    if (input.operation.quota.kind !== 'consume_reusable_wallet_session') {
      return {
        ok: false,
        response: json(
          {
            ok: false,
            code: 'authorization_grant_rejected',
            message: 'Ed25519 reusable operation authorization has an invalid quota',
          },
          { status: 403 },
        ),
      };
    }
    const operation = buildEd25519ReusableOperationEnvelope(input.operation);
    if (!operation) {
      return {
        ok: false,
        response: json(
          {
            ok: false,
            code: 'authorization_grant_rejected',
            message: 'Ed25519 reusable operation kind is invalid',
          },
          { status: 403 },
        ),
      };
    }
    admission = {
      tenantId: input.operation.tenantId,
      authorizedOperationId: input.operation.authorizedOperationId,
      auditEventId: input.operation.auditEventId,
      operation,
      authorization: input.operation.authorization,
      quota: input.operation.quota,
      claimedAtMs: Date.now(),
    };
  }
  const result = await input.ctx.service.authorizedOperations.admitAuthorizedOperation({
    operation: admission,
  });
  switch (result.kind) {
    case 'claimed':
    case 'operation_in_progress':
    case 'replayed':
      if (result.operation.authorizedOperationId !== input.operation.authorizedOperationId) {
        throw new Error('Ed25519 authorized operation changed during revalidation');
      }
      return { ok: true, operation: result.operation };
    case 'authorization_grant_rejected':
    case 'verified_step_up_rejected':
      return {
        ok: false,
        response: json(
          {
            ok: false,
            code: result.kind,
            message: 'Ed25519 operation authorization is no longer active',
          },
          { status: 403 },
        ),
      };
    case 'wallet_session_quota_exhausted':
    case 'material_mismatch':
      return {
        ok: false,
        response: json(
          { ok: false, code: result.kind, message: 'Ed25519 operation admission failed' },
          { status: 409 },
        ),
      };
  }
}

type Ed25519ReusableOperationRef = Extract<
  CapabilityOperationRef,
  { readonly capabilityKind: 'near_ed25519_mpc_signing' }
> & {
  readonly operationKind:
    | 'near.sign_transaction'
    | 'near.sign_delegate_action'
    | 'near.sign_nep413_message';
};

function buildEd25519ReusableOperationEnvelope(
  operation: AuthorizedOperation,
): CapabilityOperationEnvelope<Ed25519ReusableOperationRef> | null {
  const operationRef = operation.operation.operation;
  if (operationRef.capabilityKind !== 'near_ed25519_mpc_signing') return null;
  switch (operationRef.operationKind) {
    case 'near.sign_transaction':
    case 'near.sign_delegate_action':
    case 'near.sign_nep413_message':
      return buildCapabilityOperationEnvelope({
        tenantId: operation.operation.tenantId,
        principalId: operation.operation.principalId,
        capabilityId: operation.operation.capabilityId,
        operationId: operation.operation.operationId,
        operation: buildNearEd25519MpcOperationRef(operationRef.operationKind),
        digests: operation.operation.digests,
      });
    case 'near.export_key':
      return null;
  }
}

async function validateEd25519ReusableAuthorizedOperation(input: {
  ctx: FetchRouterApiContext;
  body: Record<string, unknown>;
  authorization: Extract<
    Awaited<ReturnType<typeof authorizeRouterAbEd25519NormalSigningRoute>>,
    { readonly ok: true; readonly kind: 'reusable_wallet_session' }
  >;
}): Promise<
  | {
      readonly ok: true;
      readonly receipt: Ed25519ReusableAuthorizedOperationReceipt;
      readonly operation: AuthorizedOperation;
    }
  | { readonly ok: false; readonly response: Response }
> {
  try {
    const receipt = parseEd25519ReusableAuthorizedOperationReceipt(input.body.authorized_operation);
    const scope = parseRouterAbEd25519OperationStepUpScope(input.body.scope);
    if (scope.authorization.kind !== 'reusable_wallet_session') {
      throw new Error('Reusable Wallet Session authority is required');
    }
    const claims = input.authorization.validated.claims;
    const tenantId = requireAuthorizationValue(parseTenantId(claims.runtimePolicyScope.orgId));
    const principalId = requireAuthorizationValue(
      parsePrincipalId(reusableWalletSessionPrincipalSubject(claims.authority)),
    );
    const capabilityId = requireAuthorizationValue(
      parseCapabilityId(scope.material_activation.capability),
    );
    const operationId = requireAuthorizationValue(parseCapabilityOperationId(receipt.operation_id));
    const envelope = buildCapabilityOperationEnvelope({
      tenantId,
      principalId,
      capabilityId,
      operationId,
      operation: {
        capabilityKind: 'near_ed25519_mpc_signing',
        operationKind: receipt.operation_kind,
      },
      digests: {
        laneDigest: parseDigestB64u(receipt.lane_digest_b64u),
        intentDigest: parseDigestB64u(receipt.intent_digest_b64u),
        displayDigest: parseDigestB64u(receipt.display_digest_b64u),
      },
    });
    const fingerprint = await computeCapabilityOperationFingerprintDigest(envelope);
    if (
      fingerprint !==
      parseCapabilityOperationFingerprintDigest(receipt.operation_fingerprint_digest)
    ) {
      throw new Error('Ed25519 authorized operation fingerprint changed');
    }
    const prepareBinding = isPlainObject(input.body.prepare_binding)
      ? input.body.prepare_binding
      : null;
    if (
      digestWireB64u(prepareBinding?.intent_digest, 'prepare_binding.intent_digest') !==
      receipt.intent_digest_b64u
    ) {
      throw new Error('Ed25519 authorized operation intent changed after prepare');
    }
    const operationResult = await input.ctx.service.authorizedOperations.readAuthorizedOperation({
      tenantId,
      operationFingerprintDigest: fingerprint,
    });
    if (!operationResult) {
      return {
        ok: false,
        response: json(
          {
            ok: false,
            code: 'authorized_operation_missing',
            message: 'Authorized operation is unavailable',
          },
          { status: 409 },
        ),
      };
    }
    if (
      operationResult.authorizedOperationId !==
        requireAuthorizationValue(parseAuthorizedOperationId(receipt.authorized_operation_id)) ||
      operationResult.operationFingerprintDigest !== fingerprint
    ) {
      throw new Error('Ed25519 authorized operation identity changed after prepare');
    }
    const revalidated = await revalidateEd25519AuthorizedOperation({
      ctx: input.ctx,
      operation: operationResult,
    });
    return revalidated.ok ? { ok: true, receipt, operation: revalidated.operation } : revalidated;
  } catch (error: unknown) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'invalid_authorized_operation',
          message: error instanceof Error ? error.message : 'Authorized operation is invalid',
        },
        { status: 400 },
      ),
    };
  }
}

function buildEd25519VerifiedStepUpAuthorizedOperationReceipt(input: {
  authorization: Extract<
    Awaited<ReturnType<typeof authorizeRouterAbEd25519NormalSigningRoute>>,
    {
      readonly ok: true;
      readonly kind: 'operation_step_up';
      readonly phase: 'prepare';
    }
  >;
}): Ed25519VerifiedStepUpAuthorizedOperationReceipt {
  const { operation, operationDigests } = input.authorization;
  if (operation.authorization.kind !== 'verified_step_up') {
    throw new Error('Verified step-up authorization is required');
  }
  return {
    kind: 'verified_step_up_authorized_operation_v1',
    authorization_session_id: input.authorization.session.sessionId,
    evidence_set_digest: operation.authorization.evidenceSetDigest,
    authorized_operation_id: operation.authorizedOperationId,
    operation_id: operation.operation.operationId,
    capability_kind: 'near_ed25519_mpc_signing',
    operation_kind: requireEd25519OperationKind(operation.operation.operation.operationKind),
    lane_digest_b64u: operationDigests.laneDigest,
    intent_digest_b64u: operationDigests.intentDigest,
    display_digest_b64u: operationDigests.displayDigest,
    operation_fingerprint_digest: operation.operationFingerprintDigest,
  };
}

async function validateEd25519VerifiedStepUpAuthorizedOperation(input: {
  ctx: FetchRouterApiContext;
  body: Record<string, unknown>;
  authorization: Extract<
    Awaited<ReturnType<typeof authorizeRouterAbEd25519NormalSigningRoute>>,
    {
      readonly ok: true;
      readonly kind: 'operation_step_up';
      readonly phase: 'finalize';
    }
  >;
}): Promise<
  | {
      readonly ok: true;
      readonly receipt: Ed25519VerifiedStepUpAuthorizedOperationReceipt;
      readonly operation: AuthorizedOperation;
    }
  | { readonly ok: false; readonly response: Response }
> {
  try {
    const receipt = parseEd25519VerifiedStepUpAuthorizedOperationReceipt(
      input.body.authorized_operation,
    );
    const scope = parseRouterAbEd25519OperationStepUpScope(input.body.scope);
    if (scope.authorization.kind !== 'operation_step_up') {
      throw new Error('Operation step-up authority is required');
    }
    if (receipt.authorization_session_id !== input.authorization.session.sessionId) {
      throw new Error('Operation step-up authorization changed after prepare');
    }
    const envelope = buildCapabilityOperationEnvelope({
      tenantId: input.authorization.session.tenantId,
      principalId: input.authorization.session.principalId,
      capabilityId: requireAuthorizationValue(
        parseCapabilityId(scope.material_activation.capability),
      ),
      operationId: requireAuthorizationValue(parseCapabilityOperationId(receipt.operation_id)),
      operation: {
        capabilityKind: 'near_ed25519_mpc_signing',
        operationKind: receipt.operation_kind,
      },
      digests: {
        laneDigest: parseDigestB64u(receipt.lane_digest_b64u),
        intentDigest: parseDigestB64u(receipt.intent_digest_b64u),
        displayDigest: parseDigestB64u(receipt.display_digest_b64u),
      },
    });
    const fingerprint = await computeCapabilityOperationFingerprintDigest(envelope);
    if (
      fingerprint !==
      parseCapabilityOperationFingerprintDigest(receipt.operation_fingerprint_digest)
    ) {
      throw new Error('Operation step-up authorized operation fingerprint changed');
    }
    const prepareBinding = isPlainObject(input.body.prepare_binding)
      ? input.body.prepare_binding
      : null;
    if (
      digestWireB64u(prepareBinding?.intent_digest, 'prepare_binding.intent_digest') !==
      receipt.intent_digest_b64u
    ) {
      throw new Error('Operation step-up intent changed after prepare');
    }
    const operationResult = await input.ctx.service.authorizedOperations.readAuthorizedOperation({
      tenantId: input.authorization.session.tenantId,
      operationFingerprintDigest: fingerprint,
    });
    if (!operationResult) {
      return {
        ok: false,
        response: json(
          {
            ok: false,
            code: 'authorized_operation_missing',
            message: 'Authorized operation is unavailable',
          },
          { status: 409 },
        ),
      };
    }
    if (
      operationResult.authorizedOperationId !==
        requireAuthorizationValue(parseAuthorizedOperationId(receipt.authorized_operation_id)) ||
      operationResult.operationFingerprintDigest !== fingerprint
    ) {
      throw new Error('Operation step-up authorized operation identity changed after prepare');
    }
    if (
      operationResult.authorization.kind !== 'verified_step_up' ||
      operationResult.authorization.evidenceSetDigest !==
        parseDigestB64u(receipt.evidence_set_digest)
    ) {
      throw new Error('Operation step-up evidence changed after prepare');
    }
    const revalidated = await revalidateEd25519AuthorizedOperation({
      ctx: input.ctx,
      operation: operationResult,
    });
    return revalidated.ok ? { ok: true, receipt, operation: revalidated.operation } : revalidated;
  } catch (error: unknown) {
    return {
      ok: false,
      response: json(
        {
          ok: false,
          code: 'invalid_authorized_operation',
          message: error instanceof Error ? error.message : 'Authorized operation is invalid',
        },
        { status: 400 },
      ),
    };
  }
}

async function completeEd25519Operation(input: {
  ctx: FetchRouterApiContext;
  operation: AuthorizedOperation;
  result: 'succeeded' | 'failed_before_side_effect' | 'failed_after_side_effect';
  response: AuthorizedOperationReplayResponse;
}): Promise<AuthorizedOperation> {
  return await input.ctx.service.authorizedOperations.completeAuthorizedOperation({
    operation: input.operation,
    result: input.result,
    response: input.response,
    completedAtMs: Date.now(),
  });
}

export function replayCompletedEd25519Operation(operation: AuthorizedOperation): Response | null {
  if (operation.lifecycle !== 'completed') return null;
  return new Response(authorizedOperationReplayBodyInit(operation.response), {
    status: operation.response.status,
    headers: { 'content-type': operation.response.contentType },
  });
}

/**
 * Completion readback is the authority for a terminal response. A claimed
 * operation must never fall back to the live upstream response after the
 * completion write, since that would make retries non-idempotent.
 */
export function requireCompletedEd25519OperationResponse(operation: AuthorizedOperation): Response {
  const replay = replayCompletedEd25519Operation(operation);
  if (!replay) throw new Error('Ed25519 operation completion readback is not completed');
  return replay;
}

export function buildEd25519ReplayResponse(input: {
  readonly response: Response;
  readonly bodyText: string;
}): AuthorizedOperationReplayResponse {
  return {
    status: input.response.status,
    contentType: input.response.headers.get('content-type') || 'application/json',
    bodyText: input.bodyText,
  };
}

type Ed25519NormalSigningExecutionDecision =
  | { readonly kind: 'execute'; readonly operation: AuthorizedOperation }
  | { readonly kind: 'operation_in_progress'; readonly response: Response }
  | { readonly kind: 'replayed'; readonly response: Response };

export function decideEd25519NormalSigningExecution(input: {
  readonly phase: RouterAbEd25519NormalSigningRoutePhase;
  readonly admissionKind: 'claimed' | 'operation_in_progress' | 'replayed';
  readonly operation: AuthorizedOperation;
}): Ed25519NormalSigningExecutionDecision {
  if (input.phase === 'finalize') {
    const replay = replayCompletedEd25519Operation(input.operation);
    return replay
      ? { kind: 'replayed', response: replay }
      : { kind: 'execute', operation: input.operation };
  }
  switch (input.admissionKind) {
    case 'claimed':
      return { kind: 'execute', operation: input.operation };
    case 'operation_in_progress':
      return {
        kind: 'operation_in_progress',
        response: json(
          {
            ok: false,
            code: 'operation_in_progress',
            message: 'Ed25519 operation is already in progress',
          },
          { status: 409 },
        ),
      };
    case 'replayed': {
      const replay = replayCompletedEd25519Operation(input.operation);
      if (!replay) throw new Error('Ed25519 replayed operation is not completed');
      return { kind: 'replayed', response: replay };
    }
  }
}

type Ed25519OperationStepUpExecutionDecision =
  | { readonly kind: 'execute'; readonly operation: AuthorizedOperation }
  | { readonly kind: 'replay'; readonly response: Response };

export function decideEd25519OperationStepUpExecution(input: {
  readonly admissionKind: 'claimed' | 'operation_in_progress' | 'replayed';
  readonly operation: AuthorizedOperation;
}): Ed25519OperationStepUpExecutionDecision {
  if (input.admissionKind === 'replayed') {
    const replay = replayCompletedEd25519Operation(input.operation);
    if (!replay) throw new Error('Ed25519 replayed operation is not completed');
    return { kind: 'replay', response: replay };
  }
  return { kind: 'execute', operation: input.operation };
}

export function isRouterAbEd25519OperationInProgressResponse(input: {
  readonly status: number;
  readonly bodyText: string;
}): boolean {
  return (
    input.status === 409 &&
    input.bodyText.includes('ReplayedLocalRequest:') &&
    input.bodyText.includes('SigningWorker normal-signing effect is already in progress')
  );
}

async function issueEd25519OperationStepUpGrant(input: {
  ctx: FetchRouterApiContext;
  request: RouterAbEd25519YaoOperationStepUpGrantCommandV1;
}): Promise<Response> {
  const scope = parseRouterAbEd25519OperationStepUpScope(input.request.normalSigningRequest.scope);
  if (scope.authorization.kind !== 'operation_step_up') {
    return json(
      { ok: false, code: 'invalid_body', message: 'Operation step-up scope is required' },
      { status: 400 },
    );
  }
  const authenticated = await authenticateRouterAbOperationStepUpAppSession({
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    scope,
    authorizedOperations: input.ctx.service.authorizedOperations,
    authorizationSessions: input.ctx.service.authorizationSessions,
  });
  if (!authenticated.ok) {
    return json(authenticated.error.body, { status: authenticated.error.status });
  }
  const activeMaterial =
    await input.ctx.service.walletRegistration.resolveEd25519MaterialActivation({
      walletId: authenticated.session.walletId,
      materialActivation: scope.material_activation,
    });
  if (!activeMaterial.ok) {
    return json(
      {
        ok: false,
        code: activeMaterial.code === 'internal' ? 'internal' : 'scope_mismatch',
        message:
          activeMaterial.code === 'internal'
            ? activeMaterial.message
            : 'Operation step-up scope does not name the active material',
      },
      { status: activeMaterial.code === 'internal' ? 500 : 403 },
    );
  }
  if (
    !sameRouterAbMpcMaterialActivationRef(
      activeMaterial.materialActivation,
      scope.material_activation,
    )
  ) {
    return json(
      {
        ok: false,
        code: 'scope_mismatch',
        message: 'Operation step-up scope does not name the active material',
      },
      { status: 403 },
    );
  }
  let privateBody: Awaited<ReturnType<typeof buildRouterAbEd25519PrivateSigningWorkerBody>>;
  try {
    privateBody = await buildRouterAbEd25519PrivateSigningWorkerBody({
      phase: 'prepare',
      body: input.request.normalSigningRequest,
      authorization: { kind: 'operation_step_up', session: authenticated.session },
      headers: Object.fromEntries(input.ctx.request.headers.entries()),
    });
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
  if (!('admission_candidate' in privateBody)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Operation step-up prepare is required' },
      { status: 400 },
    );
  }
  const operation = parseRouterAbOperationStepUpOperation(
    input.request.normalSigningRequest.intent,
  );
  if (!operation.ok) {
    return json({ ok: false, code: 'invalid_body', message: operation.message }, { status: 400 });
  }
  const intent = input.request.normalSigningRequest.intent;
  if (!isPlainObject(intent)) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Operation step-up intent is invalid' },
      { status: 400 },
    );
  }
  const capabilityId = requireAuthorizationValue(
    parseCapabilityId(scope.material_activation.capability),
  );
  const envelope = buildCapabilityOperationEnvelope({
    tenantId: authenticated.session.tenantId,
    principalId: authenticated.session.principalId,
    capabilityId,
    operationId: operation.operationId,
    operation: operation.operation,
    digests: {
      laneDigest: parseSigningOperationFingerprintDigest(intent.operation_fingerprint),
      intentDigest: parseDigestB64u(
        base64UrlEncode(Uint8Array.from(privateBody.admission_candidate.intent_digest.bytes)),
      ),
      displayDigest: parseDigestB64u(input.request.displayDigest),
    },
  });
  const challengeB64u = await computeCapabilityOperationFingerprintDigest(envelope);
  const proof = input.request.proof;
  const authorityRef =
    proof.kind === 'passkey'
      ? await walletAuthAuthorityRef({ authority: proof.authority })
      : proof.authorityRef;
  if (
    authorityRef.walletId !== authenticated.authorityRef.walletId ||
    authorityRef.authorityDigest !== authenticated.authorityRef.authorityDigest ||
    authorityRef.walletId !== authenticated.session.walletId
  ) {
    return json(
      { ok: false, code: 'scope_mismatch', message: 'Operation step-up authority changed' },
      { status: 403 },
    );
  }
  const activeSession = authenticated.activeSession;
  const nowMs = Date.now();
  const expiresAtMs = Math.min(
    Number(input.request.normalSigningRequest.expires_at_ms),
    authenticated.expiresAtMs,
  );
  const requestId = String(scope.request_id);
  const evidenceId = requireAuthorizationValue(
    parseAuthorizationEvidenceId(`evidence:${requestId}`),
  );
  const evidenceSetId = requireAuthorizationValue(
    parseAuthorizationEvidenceSetId(`evidence-set:${requestId}`),
  );
  let factor: VerifiedAuthorizationFactorResult;
  let materialRecovery: RouterAbEd25519YaoOperationStepUpMaterialRecoveryResponse;
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
      const credential = proof.webauthnAuthentication;
      const credentialId = String(credential.rawId || credential.id || '').trim();
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
        expectedChallenge: challengeB64u,
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
      materialRecovery = { kind: 'not_requested' };
      break;
    }
    case 'email_otp': {
      if (
        activeSession.authSource.kind !== 'oidc_provider' ||
        String(activeSession.authSource.providerSubject) !== proof.providerSubjectId
      ) {
        return json(
          { ok: false, code: 'scope_mismatch', message: 'Email OTP authority changed' },
          { status: 403 },
        );
      }
      const sessionHash = await hashEmailOtpAppSessionClaims(authenticated.rawClaims);
      const verified = await input.ctx.service.emailOtp.verifyEmailOtpChallenge({
        userId: authenticated.session.principalId,
        walletId: authenticated.session.walletId,
        orgId: authenticated.session.tenantId,
        challengeId: proof.challengeId,
        otpCode: proof.otpCode,
        otpChannel: EMAIL_OTP_CHANNEL,
        sessionHash,
        appSessionVersion: activeSession.appSessionVersion,
        operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      });
      if (!verified.ok) {
        return json(verified, { status: verified.code === 'invalid_body' ? 400 : 401 });
      }
      const consumed = await input.ctx.service.emailOtp.consumeEmailOtpGrant({
        subject: {
          kind: 'authorization_session',
          tenantId: authenticated.session.tenantId,
          principalId: authenticated.session.principalId,
          walletId: walletIdFromString(authenticated.session.walletId),
        },
        loginGrant: verified.loginGrant,
        otpChannel: EMAIL_OTP_CHANNEL,
      });
      if (!consumed.ok) {
        return json(consumed, { status: consumed.code === 'invalid_body' ? 400 : 401 });
      }
      materialRecovery = { kind: 'not_requested' };
      factor = buildVerifiedEmailOtpFactorResult({
        tenantId: authenticated.session.tenantId,
        principalId: authenticated.session.principalId,
        sessionId: authenticated.session.sessionId,
        deviceId: activeSession.deviceId,
        factorId: requireAuthorizationValue(
          parseAuthFactorId(
            `email_otp:${
              activeSession.authSource.providerId === 'google_oidc' ? 'google' : 'email'
            }:${proof.providerSubjectId}`,
          ),
        ),
        authorityRef: authenticated.authorityRef,
        operation: envelope,
        challengeId: requireAuthorizationValue(parseEmailOtpChallengeId(consumed.challengeId)),
        verificationReceiptDigest: parseDigestB64u(
          base64UrlEncode(
            await sha256BytesUtf8(
              alphabetizeStringify({
                challengeId: consumed.challengeId,
                operationFingerprint: challengeB64u,
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
  const atomicOperation = await input.ctx.service.authorizedOperations.admitAuthorizedOperation({
    operation: {
      tenantId: authenticated.session.tenantId,
      authorizedOperationId: requireAuthorizationValue(
        parseAuthorizedOperationId(`normal-signing-operation:${scope.request_id}`),
      ),
      auditEventId: requireAuthorizationValue(
        parseAuthorizationAuditEventId(`normal-signing-audit:${scope.request_id}`),
      ),
      operation: envelope,
      authorization: {
        kind: 'verified_step_up',
        evidenceSetDigest: evidenceSet.evidenceSetDigest,
      },
      quota: { kind: 'quota_neutral' },
      claimedAtMs: nowMs,
    },
  });
  switch (atomicOperation.kind) {
    case 'claimed':
    case 'operation_in_progress':
    case 'replayed':
      break;
    case 'authorization_grant_rejected':
    case 'verified_step_up_rejected':
      return json(
        {
          ok: false,
          code: atomicOperation.kind,
          message: 'Ed25519 operation step-up authorization is invalid',
        },
        { status: 403 },
      );
    case 'wallet_session_quota_exhausted':
    case 'material_mismatch':
      return json(
        {
          ok: false,
          code: atomicOperation.kind,
          message: 'Ed25519 operation step-up authorization is unavailable',
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
      },
      expiresAtMs,
      materialRecovery,
    },
    { status: 200 },
  );
}

type AcceptedEd25519NormalSigningAuthorization = Extract<
  Awaited<ReturnType<typeof authorizeRouterAbEd25519NormalSigningRoute>>,
  { readonly ok: true }
>;

async function proxyEd25519OwnerLaneExecution(input: {
  readonly ctx: FetchRouterApiContext;
  readonly body: Record<string, unknown>;
  readonly authorization: AcceptedEd25519NormalSigningAuthorization;
  readonly authorizedOperation: AuthorizedOperation;
}): Promise<Response> {
  const scope = parseRouterAbEd25519OperationStepUpScope(input.body.scope);
  const walletId = parseWalletId(scope.account_id);
  if (!walletId.ok) {
    return json(
      { ok: false, code: 'invalid_body', message: 'Ed25519 signing wallet is invalid' },
      { status: 400 },
    );
  }
  const laneAuthorization =
    input.authorization.kind === 'operation_step_up'
      ? {
          kind: 'authority_ref' as const,
          authorityRef: input.authorization.session.walletAuthAuthorityRef,
          authSource: input.authorization.session.authSource,
        }
      : {
          kind: 'wallet_auth_method' as const,
          walletAuthMethodId: input.authorization.validated.walletSessionAuth.authority.bindingId,
        };
  return await proxyOwnerLaneAdmittedNormalSigningRequest({
    request: input.ctx.request,
    proxy: input.ctx.opts.routerAbNormalSigningRouterProxy,
    body: input.body,
    authorizedOperation: input.authorizedOperation,
    walletId: walletId.value,
    expectedMaterialActivation: scope.material_activation,
    authorization: laneAuthorization,
    walletRegistration: input.ctx.service.walletRegistration,
  });
}

async function handleRouterAbEd25519NormalSigningRoute(input: {
  ctx: FetchRouterApiContext;
  body: Record<string, unknown>;
  phase: RouterAbEd25519NormalSigningRoutePhase;
}): Promise<Response> {
  const authorization = await authorizeRouterAbEd25519NormalSigningRoute({
    body: input.body,
    rawBody: input.body,
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    authorizedOperations: input.ctx.service.authorizedOperations,
    authorizationSessions: input.ctx.service.authorizationSessions,
    admissionAdapter: input.ctx.opts.routerAbNormalSigningAdmission,
    resolveEd25519MaterialActivation:
      input.ctx.service.walletRegistration.resolveEd25519MaterialActivation.bind(
        input.ctx.service.walletRegistration,
      ),
    phase: input.phase,
  });
  if (!authorization.ok) {
    return json(authorization.result.body, { status: authorization.result.status });
  }
  if (authorization.kind === 'operation_step_up') {
    if (input.phase === 'prepare') {
      if (authorization.phase !== 'prepare') {
        throw new Error('Operation step-up prepare authorization phase changed');
      }
      const execution = decideEd25519OperationStepUpExecution({
        admissionKind: authorization.admissionKind,
        operation: authorization.operation,
      });
      if (execution.kind !== 'execute') return execution.response;
      const upstream = await proxyEd25519OwnerLaneExecution({
        ctx: input.ctx,
        authorization,
        authorizedOperation: execution.operation,
        body: {
          ...input.body,
          authorized_operation: buildRouterAbEd25519AuthorizedOperationWire({
            operation: execution.operation,
            binding: {
              kind: 'operation_step_up',
              authorizationSessionId: authorization.session.sessionId,
              orgId: authorization.session.runtimePolicyScope.orgId,
              projectId: authorization.session.runtimePolicyScope.projectId,
              environment: authorization.session.runtimePolicyScope.envId,
              subjectId: authorization.session.principalId,
            },
          }),
        },
      });
      const upstreamBodyText = await upstream
        .clone()
        .text()
        .catch(() => '');
      let upstreamBody: unknown = null;
      try {
        upstreamBody = upstreamBodyText ? JSON.parse(upstreamBodyText) : null;
      } catch {
        upstreamBody = null;
      }
      if (
        isRouterAbEd25519OperationInProgressResponse({
          status: upstream.status,
          bodyText: upstreamBodyText,
        })
      ) {
        return upstream;
      }
      if (!upstream.ok || !isPlainObject(upstreamBody)) {
        const completed = await completeEd25519Operation({
          ctx: input.ctx,
          operation: execution.operation,
          result: upstream.status < 500 ? 'failed_before_side_effect' : 'failed_after_side_effect',
          response: buildEd25519ReplayResponse({ response: upstream, bodyText: upstreamBodyText }),
        });
        return requireCompletedEd25519OperationResponse(completed);
      }
      return new Response(
        JSON.stringify({
          ...upstreamBody,
          authorized_operation: buildEd25519VerifiedStepUpAuthorizedOperationReceipt({
            authorization,
          }),
        }),
        {
          status: upstream.status,
          statusText: upstream.statusText,
          headers: new Headers(upstream.headers),
        },
      );
    }
    if (authorization.phase !== 'finalize') {
      throw new Error('Operation step-up finalize authorization phase changed');
    }
    const validatedAuthorization = await validateEd25519VerifiedStepUpAuthorizedOperation({
      ctx: input.ctx,
      body: input.body,
      authorization,
    });
    if (!validatedAuthorization.ok) return validatedAuthorization.response;
    const replay = replayCompletedEd25519Operation(validatedAuthorization.operation);
    if (replay) return replay;
    const upstream = await proxyEd25519OwnerLaneExecution({
      ctx: input.ctx,
      authorization,
      authorizedOperation: validatedAuthorization.operation,
      body: {
        ...input.body,
        authorized_operation: buildRouterAbEd25519AuthorizedOperationWire({
          operation: validatedAuthorization.operation,
          binding: {
            kind: 'operation_step_up',
            authorizationSessionId: authorization.session.sessionId,
            orgId: authorization.session.runtimePolicyScope.orgId,
            projectId: authorization.session.runtimePolicyScope.projectId,
            environment: authorization.session.runtimePolicyScope.envId,
            subjectId: authorization.session.principalId,
          },
        }),
      },
    });
    const upstreamBodyText = await upstream
      .clone()
      .text()
      .catch(() => '');
    if (
      isRouterAbEd25519OperationInProgressResponse({
        status: upstream.status,
        bodyText: upstreamBodyText,
      })
    ) {
      return upstream;
    }
    const completed = await completeEd25519Operation({
      ctx: input.ctx,
      operation: validatedAuthorization.operation,
      result: upstream.ok
        ? 'succeeded'
        : upstream.status < 500
          ? 'failed_before_side_effect'
          : 'failed_after_side_effect',
      response: buildEd25519ReplayResponse({ response: upstream, bodyText: upstreamBodyText }),
    });
    return requireCompletedEd25519OperationResponse(completed);
  }
  if (input.phase === 'prepare') {
    const authorized = await authorizeEd25519ReusableWalletSessionOperation({
      ctx: input.ctx,
      body: input.body,
      authorization,
    });
    if (!authorized.ok) return authorized.response;
    const execution = decideEd25519NormalSigningExecution({
      phase: 'prepare',
      admissionKind: authorized.admission.kind,
      operation: authorized.admission.operation,
    });
    if (execution.kind !== 'execute') return execution.response;
    if (authorized.admission.kind !== 'claimed') {
      throw new Error('Ed25519 prepare execution claim changed');
    }
    const upstream = await proxyEd25519OwnerLaneExecution({
      ctx: input.ctx,
      authorization,
      authorizedOperation: execution.operation,
      body: {
        ...input.body,
        authorized_operation: buildRouterAbEd25519AuthorizedOperationWire({
          operation: execution.operation,
          binding: {
            kind: 'reusable_wallet_session',
            walletSessionId: authorization.validated.claims.walletSessionId,
            quotaId: authorization.validated.claims.quotaId,
          },
        }),
      },
    });
    const upstreamBodyText = await upstream
      .clone()
      .text()
      .catch(() => '');
    let upstreamBody: unknown = null;
    try {
      upstreamBody = upstreamBodyText ? JSON.parse(upstreamBodyText) : null;
    } catch {
      upstreamBody = null;
    }
    if (
      isRouterAbEd25519OperationInProgressResponse({
        status: upstream.status,
        bodyText: upstreamBodyText,
      })
    ) {
      return upstream;
    }
    if (!upstream.ok || !isPlainObject(upstreamBody)) {
      const completed = await completeEd25519Operation({
        ctx: input.ctx,
        operation: execution.operation,
        result: upstream.status < 500 ? 'failed_before_side_effect' : 'failed_after_side_effect',
        response: buildEd25519ReplayResponse({ response: upstream, bodyText: upstreamBodyText }),
      });
      return requireCompletedEd25519OperationResponse(completed);
    }
    return new Response(
      JSON.stringify({
        ...upstreamBody,
        authorized_operation: authorized.admission.receipt,
      }),
      {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: new Headers(upstream.headers),
      },
    );
  }
  const validatedAuthorization = await validateEd25519ReusableAuthorizedOperation({
    ctx: input.ctx,
    body: input.body,
    authorization,
  });
  if (!validatedAuthorization.ok) return validatedAuthorization.response;
  const replay = replayCompletedEd25519Operation(validatedAuthorization.operation);
  if (replay) return replay;
  const upstream = await proxyEd25519OwnerLaneExecution({
    ctx: input.ctx,
    authorization,
    authorizedOperation: validatedAuthorization.operation,
    body: {
      ...input.body,
      authorized_operation: buildRouterAbEd25519AuthorizedOperationWire({
        operation: validatedAuthorization.operation,
        binding: {
          kind: 'reusable_wallet_session',
          walletSessionId: authorization.validated.claims.walletSessionId,
          quotaId: authorization.validated.claims.quotaId,
        },
      }),
    },
  });
  const upstreamBodyText = await upstream
    .clone()
    .text()
    .catch(() => '');
  if (
    isRouterAbEd25519OperationInProgressResponse({
      status: upstream.status,
      bodyText: upstreamBodyText,
    })
  ) {
    return upstream;
  }
  const completed = await completeEd25519Operation({
    ctx: input.ctx,
    operation: validatedAuthorization.operation,
    result: upstream.ok
      ? 'succeeded'
      : upstream.status < 500
        ? 'failed_before_side_effect'
        : 'failed_after_side_effect',
    response: buildEd25519ReplayResponse({ response: upstream, bodyText: upstreamBodyText }),
  });
  return requireCompletedEd25519OperationResponse(completed);
}

export async function handleThresholdEd25519(ctx: FetchRouterApiContext): Promise<Response | null> {
  if (ctx.method === 'GET' && ctx.pathname === ROUTER_AB_ED25519_HEALTH_PATH) {
    if (!ctx.opts.routerAbNormalSigningRouterProxy) {
      const body = {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B Ed25519 signing runtime is not configured on this server',
        configured: false,
      };
      return json(body, { status: thresholdEd25519StatusCode(body) });
    }
    return json({ ok: true, configured: true }, { status: 200 });
  }

  if (ctx.method !== 'POST') return null;

  const pathname = ctx.pathname;
  if (
    pathname !== ROUTER_AB_ED25519_WALLET_SESSION_PATH &&
    pathname !== ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH &&
    pathname !== ROUTER_AB_ED25519_NORMAL_SIGNING_PATH
  ) {
    return null;
  }

  const bodyUnknown = await readJson(ctx.request.clone());
  const body =
    bodyUnknown && typeof bodyUnknown === 'object' && !Array.isArray(bodyUnknown)
      ? (bodyUnknown as Record<string, unknown>)
      : {};

  switch (pathname) {
    case ROUTER_AB_ED25519_NORMAL_SIGNING_PREPARE_PATH:
      {
        const linked = await handleLinkedDeviceEd25519NormalSigning({
          ctx,
          body,
          phase: 'prepare',
        });
        if (linked) return linked;
      }
      return handleRouterAbEd25519NormalSigningRoute({
        ctx,
        body,
        phase: 'prepare',
      });

    case ROUTER_AB_ED25519_NORMAL_SIGNING_PATH:
      {
        const linked = await handleLinkedDeviceEd25519NormalSigning({
          ctx,
          body,
          phase: 'finalize',
        });
        if (linked) return linked;
      }
      return handleRouterAbEd25519NormalSigningRoute({
        ctx,
        body,
        phase: 'finalize',
      });
  }

  switch (pathname) {
    case ROUTER_AB_ED25519_WALLET_SESSION_PATH: {
      const session = ctx.opts.session;
      if (!session) {
        ctx.logger.warn('[threshold-ed25519] request', {
          route: pathname,
          method: ctx.method,
          sessions: false,
        });
        return json(
          {
            ok: false,
            code: 'sessions_disabled',
            message: 'Sessions are not configured on this server',
          },
          { status: 501 },
        );
      }

      if (body.kind === 'router_ab_ed25519_yao_operation_step_up_grant_v1') {
        const parsedGrant = parseThresholdEd25519OperationStepUpGrantRequest(body);
        if (!parsedGrant.ok) {
          return json(parsedGrant.body, {
            status: thresholdEd25519StatusCode(parsedGrant.body),
          });
        }
        return await issueEd25519OperationStepUpGrant({
          ctx,
          request: parsedGrant.request,
        });
      }

      const parsedBody = parseThresholdEd25519SessionRouteRequest(body);
      if (!parsedBody.ok) {
        return json(parsedBody.body, { status: thresholdEd25519StatusCode(parsedBody.body) });
      }
      const b = parsedBody.request;
      ctx.logger.info('[threshold-ed25519] request', {
        route: pathname,
        method: ctx.method,
        relayerKeyId: typeof b.relayerKeyId === 'string' ? b.relayerKeyId : undefined,
        sessionPolicy: b.sessionPolicy ? { version: b.sessionPolicy.version } : undefined,
      });

      const authority = b.sessionPolicy.authority;
      if (!isPasskeyWalletAuthAuthority(authority)) {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'Ed25519 Yao WebAuthn budget refresh requires passkey authority',
          },
          { status: 400 },
        );
      }
      if (b.relayerKeyId !== b.sessionPolicy.relayerKeyId) {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'relayerKeyId must match the Ed25519 Yao session policy',
          },
          { status: 400 },
        );
      }

      const runtimePolicyScopeResolution = await resolveThresholdRuntimePolicyScope({
        explicitScopeRaw: b.sessionPolicy.runtimePolicyScope,
        projectEnvironmentIdRaw: b.projectEnvironmentId,
        headers: ctx.request.headers,
        origin: ctx.request.headers.get('origin'),
        publishableKeyAuth: ctx.opts.publishableKeyAuth || null,
        orgProjectEnv: ctx.opts.orgProjectEnv || null,
      });
      if (!runtimePolicyScopeResolution.ok) {
        return json(
          {
            ok: false,
            code: runtimePolicyScopeResolution.code,
            message: runtimePolicyScopeResolution.message,
          },
          { status: runtimePolicyScopeResolution.status },
        );
      }
      const runtimePolicyScope = runtimePolicyScopeResolution.scope;
      if (
        !runtimePolicyScope ||
        alphabetizeStringify(runtimePolicyScope) !==
          alphabetizeStringify(b.sessionPolicy.runtimePolicyScope)
      ) {
        return json(
          {
            ok: false,
            code: 'scope_mismatch',
            message: 'Ed25519 Yao runtime policy scope does not match the active environment',
          },
          { status: 403 },
        );
      }
      const authorization =
        b.routeAuth.kind === 'passkey'
          ? await validatePasskeyEd25519SessionAuthorization({
              ctx,
              request: b,
              authority,
            })
          : await validateSignedEd25519SessionAuthorization({
              ctx,
              request: b,
              authority,
            });
      if (!authorization.ok) return authorization.response;

      const result = await ctx.service.walletRegistration.refreshEd25519YaoWalletSession({
        kind: 'router_ab_ed25519_yao_budget_refresh_v1',
        sessionPolicy: b.sessionPolicy,
        authorization: authorization.authorization,
      });
      const status = thresholdEd25519StatusCode(result);
      ctx.logger.info('[threshold-ed25519] response', {
        route: pathname,
        status,
        ok: result.ok,
        ...('code' in result && result.code ? { code: result.code } : {}),
      });
      return json(result, { status });
    }
    default:
      return null;
  }
}
