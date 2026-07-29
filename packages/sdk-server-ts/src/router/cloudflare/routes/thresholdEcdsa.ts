import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import {
  parseAppSessionClaims,
  parseRouterAbEcdsaDerivationWalletSessionClaims,
  type RouterAbEcdsaDerivationWalletSessionClaims,
  parseRouterAbEd25519WalletSessionClaims,
  resolveAppSessionWalletIdForWalletScope,
  resolveAppSessionProviderUserIdForWalletScope,
} from '../../../core/ThresholdService/validation';
import { thresholdEcdsaStatusCode } from '../../../threshold/statusCodes';
import { parseSessionKind } from '../../routerApi';
import {
  signRouterAbEcdsaDerivationWalletSessionJwt,
  validateRouterAbEcdsaDerivationWalletSessionInputs,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from '../../commonRouterUtils';
import {
  parseRouterAbEcdsaDerivationActivationRefreshCommitRequestV1,
  parseRouterAbEcdsaDerivationExplicitExportRequestV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationRequestV1,
  parseRouterAbEcdsaDerivationRecoveryRequestV1,
  parseRouterAbEcdsaOperationStepUpGrantRequestV1,
  computeRouterAbEcdsaOperationStepUpChallengeB64u,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_HEALTH_PATH,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH,
  ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_GRANT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
  ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PATH,
  ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH,
  ROUTER_AB_ECDSA_DERIVATION_SESSION_ACTIVATION_PATH,
  type RouterAbEcdsaDerivationActivationRefreshCommitRequestV1,
  type RouterAbEcdsaDerivationActivationRefreshRequestV1,
  type RouterAbEcdsaDerivationExplicitExportRequestV1,
  type RouterAbEcdsaDerivationRecoveryRequestV1,
  type RouterAbEcdsaOperationStepUpGrantRequestV1Wire,
  type RouterAbEcdsaOperationStepUpPreparationV1Wire,
  type RouterAbEcdsaPostRegistrationSessionActivationRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  authenticateRouterAbOperationStepUpAppSessionIdentity,
  claimRouterAbEcdsaOperationStepUp,
  handleRouterAbEcdsaDerivationNormalSigningRouteCore,
  ROUTER_AB_ECDSA_DERIVATION_PRIVATE_SIGNING_PATHS,
  type RouterAbEcdsaDerivationPrivateSigningPath,
} from '../../routerAbPrivateSigningWorker';
import {
  parseRouterAbEcdsaDerivationPoolFillInitRouteRequest,
  parseRouterAbEcdsaDerivationPoolFillStepRouteRequest,
  type RouterAbEcdsaPoolFillInitRouteRequest,
  type RouterAbEcdsaPoolFillStepRouteRequest,
} from '../../thresholdEcdsaRequestValidation';
import type {
  RouterAbEcdsaDerivationPoolFillInitRequest,
  RouterAbEcdsaDerivationPoolFillStepRequest,
} from '../../../core/types';
import type { ThresholdEcdsaSessionClaims } from '../../../core/ThresholdService/validation';
import type {
  RouterAbEcdsaStrictPostRegistrationPort,
  RouterAbEcdsaStrictPostRegistrationResult,
  RouterAbEcdsaStrictExportAuthority,
  RouterAbEcdsaStrictRegistrationAuthority,
} from '../../routerAbEcdsaStrictRegistration';
import { WALLET_SESSION_FAILURE_CODES } from '@shared/utils/walletSessionFailure';
import {
  walletSessionFailure,
  walletSessionFailureStatus,
  walletSessionParseFailure,
  type WalletSessionBoundaryFailure,
} from '../../walletSessionFailure';
import {
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseSeamsSessionId,
  type MpcWalletSigningQuotaId,
  type PrincipalId,
  type ReusableWalletSessionMintId,
  type SeamsSessionId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  walletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  parseAuthFactorId,
  parseAuthorizationAuditEventId,
  parseCapabilityBindingId,
  parseCapabilityGrantId,
  parseCapabilityGrantUseId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseGrantEvidenceId,
  parseGrantEvidenceSetId,
} from '@shared/authorization/capabilityKinds';
import { buildCapabilityOperationEnvelope } from '@shared/authorization/operationFingerprint';
import { buildEvmEcdsaMpcOperationRef } from '@shared/authorization/capabilityKinds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { buildActiveCapabilityGrant } from '../../../authorization/domain';
import {
  buildVerifiedEmailOtpFactorResult,
  buildVerifiedPasskeyFactorResult,
  type VerifiedGrantFactorResult,
} from '../../../authorization/factorEvidence';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { parseEmailOtpChallengeId } from '@shared/utils/domainIds';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { hashEmailOtpAppSessionClaims } from '../../emailOtpSessionRouteHelpers';
import { parseEvmFamilySigningKeySlotIdOrNull } from '@shared/signing-lanes';

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

async function handleRouterAbEcdsaDerivationNormalSigningRoute(input: {
  ctx: CloudflareRouterApiContext;
  body: Record<string, unknown>;
  privatePath: RouterAbEcdsaDerivationPrivateSigningPath;
  phase: 'prepare' | 'finalize';
}): Promise<Response> {
  const result = await handleRouterAbEcdsaDerivationNormalSigningRouteCore({
    body: input.body,
    rawBody: input.body,
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    runtime: input.ctx.service.thresholdRuntime.getRouterAbNormalSigningRuntime(),
    authorizationClaims: input.ctx.service.authorizationClaims,
    authorizationSessions: input.ctx.service.authorizationSessions,
    admissionAdapter: input.ctx.opts.routerAbNormalSigningAdmission,
    privatePath: input.privatePath,
    phase: input.phase,
  });
  return json(result.body, { status: result.status });
}

async function issueEcdsaOperationStepUpGrant(input: {
  readonly ctx: CloudflareRouterApiContext;
  readonly request: RouterAbEcdsaOperationStepUpGrantRequestV1Wire;
}): Promise<Response> {
  const operation = input.request.operation;
  const authenticated = await authenticateRouterAbOperationStepUpAppSessionIdentity({
    headers: Object.fromEntries(input.ctx.request.headers.entries()),
    session: input.ctx.opts.session,
    walletId: operation.wallet_id,
    materialOwner: operation.material_activation.material_owner,
    authorizationClaims: input.ctx.service.authorizationClaims,
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
        parseCapabilityId(operation.material_activation.capability),
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
  const evidenceId = requireAuthorizationValue(
    parseGrantEvidenceId(`ecdsa-step-up-evidence:${requestId}`),
  );
  const evidenceSetId = requireAuthorizationValue(
    parseGrantEvidenceSetId(`ecdsa-step-up-evidence-set:${requestId}`),
  );
  const expiresAtMs = Math.min(operation.expires_at_ms, authenticated.expiresAtMs);
  let factor: VerifiedGrantFactorResult;
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
      const consumed = await input.ctx.service.emailOtp.consumeEmailOtpGrant({
        loginGrant: verified.loginGrant,
        userId: authenticated.session.principalId,
        walletId: authenticated.session.walletId,
        orgId: authenticated.session.tenantId,
        otpChannel: EMAIL_OTP_CHANNEL,
      });
      if (!consumed.ok) {
        return json(consumed, { status: consumed.code === 'invalid_body' ? 400 : 401 });
      }
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
        challengeId: requireAuthorizationValue(parseEmailOtpChallengeId(consumed.challengeId)),
        verificationReceiptDigest: parseDigestB64u(
          base64UrlEncode(
            await sha256BytesUtf8(
              alphabetizeStringify({
                challengeId: consumed.challengeId,
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
  const evidenceSet = await input.ctx.service.authorizationClaims.recordVerifiedFactorEvidenceSet({
    session: activeSession,
    operation: envelope,
    evidenceId,
    evidenceSetId,
    factor,
  });
  const grantId = requireAuthorizationValue(
    parseCapabilityGrantId(`ecdsa-step-up-grant:${operation.operation_id}`),
  );
  const grant = buildActiveCapabilityGrant({
    tenantId: authenticated.session.tenantId,
    principalId: authenticated.session.principalId,
    grantId,
    bindingId: requireAuthorizationValue(
      parseCapabilityBindingId(`ecdsa-step-up-binding:${requestId}`),
    ),
    evidenceSetId,
    evidenceSetDigest: evidenceSet.evidenceSetDigest,
    capabilityId: envelope.capabilityId,
    operationId: envelope.operationId,
    operation: envelope.operation,
    laneDigest: envelope.digests.laneDigest,
    intentDigest: envelope.digests.intentDigest,
    displayDigest: envelope.digests.displayDigest,
    authority: { kind: 'operation_step_up' },
    remainingUses: 1,
    createdAtMs: nowMs,
    expiresAtMs,
  });
  await input.ctx.service.authorizationClaims.issueGrant({
    operation: envelope,
    evidenceSet,
    grant,
  });
  return json(
    {
      ok: true,
      kind: 'operation_step_up',
      authorization: {
        kind: 'operation_step_up',
        grant_id: grantId,
      },
      authorization_session_id: authenticated.session.sessionId,
      expires_at_ms: expiresAtMs,
    },
    { status: 200 },
  );
}

type RouterAbEcdsaPoolFillClaims = Pick<
  ThresholdEcdsaSessionClaims,
  | 'walletId'
  | 'evmFamilySigningKeySlotId'
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

function validateEcdsaPoolFillOperationIdentity(
  operation: RouterAbEcdsaOperationStepUpPreparationV1Wire,
): boolean {
  return (
    operation.wallet_id === operation.normal_signing_scope.wallet_id &&
    operation.signing_worker_id === operation.normal_signing_scope.signing_worker.server_id &&
    operation.material_activation.material_owner === operation.wallet_id &&
    operation.material_activation.signing_worker === operation.signing_worker_id &&
    operation.expires_at_ms > Date.now()
  );
}

async function authorizeEcdsaPoolFillOperationStepUp(input: {
  readonly ctx: CloudflareRouterApiContext;
  readonly authorization: Extract<
    RouterAbEcdsaPoolFillInitRouteRequest['authorization'],
    { readonly kind: 'operation_step_up' }
  >;
  readonly operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
}): Promise<RouterAbEcdsaPoolFillAuthorizationResult> {
  const evmFamilySigningKeySlotId = parseEvmFamilySigningKeySlotIdOrNull(
    input.operation.evm_family_signing_key_slot_id,
  );
  if (!evmFamilySigningKeySlotId || !validateEcdsaPoolFillOperationIdentity(input.operation)) {
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
    authorizationClaims: input.ctx.service.authorizationClaims,
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
  const claimFailure = await claimRouterAbEcdsaOperationStepUp({
    operation: input.operation,
    grantId: input.authorization.grant_id,
    authenticated,
  });
  if (claimFailure) {
    return {
      ok: false,
      error: claimFailure,
    };
  }
  return {
    ok: true,
    claims: {
      walletId: input.operation.wallet_id,
      evmFamilySigningKeySlotId,
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
  readonly ctx: CloudflareRouterApiContext;
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
      return { ok: true, claims: validated.claims };
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
    }
  | {
      readonly kind: 'recovery';
      readonly request: RouterAbEcdsaDerivationRecoveryRequestV1;
    }
  | {
      readonly kind: 'refresh';
      readonly command: RouterAbEcdsaDerivationActivationRefreshCommitRequestV1;
      readonly request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
    };

type StrictEcdsaPostRegistrationAuthorization =
  | {
      readonly ok: true;
      readonly authority: RouterAbEcdsaStrictRegistrationAuthority;
      readonly ecdsaClaims: RouterAbEcdsaDerivationWalletSessionClaims | null;
    }
  | {
      readonly ok: false;
      readonly code: 'unauthorized' | 'identity_mismatch';
      readonly message: string;
    }
  | WalletSessionBoundaryFailure;

type StrictEcdsaAuthorizationClaims = {
  readonly appSessionClaims: NonNullable<ReturnType<typeof parseAppSessionClaims>> | null;
  readonly ecdsaClaims: RouterAbEcdsaDerivationWalletSessionClaims | null;
  readonly ed25519Claims: NonNullable<
    ReturnType<typeof parseRouterAbEd25519WalletSessionClaims>
  > | null;
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
  ctx: CloudflareRouterApiContext,
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
  readonly ctx: CloudflareRouterApiContext;
  readonly rawClaims: Record<string, unknown>;
}): Promise<StrictEcdsaAuthorizationClaimsResult> {
  const appSessionClaims = parseAppSessionClaims(input.rawClaims);
  const ecdsaClaims = parseRouterAbEcdsaDerivationWalletSessionClaims(input.rawClaims);
  const ed25519Claims = parseRouterAbEd25519WalletSessionClaims(input.rawClaims);
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

function parseStrictEcdsaPostRegistrationRequest(
  pathname: string,
  body: unknown,
): StrictEcdsaPostRegistrationRequest {
  switch (pathname) {
    case ROUTER_AB_ECDSA_DERIVATION_EXPORT_PATH:
      return {
        kind: 'export',
        request: parseRouterAbEcdsaDerivationExplicitExportRequestV1(body),
      };
    case ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PATH:
      return {
        kind: 'recovery',
        request: parseRouterAbEcdsaDerivationRecoveryRequestV1(body),
      };
    case ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH: {
      const command = parseRouterAbEcdsaDerivationActivationRefreshCommitRequestV1(body);
      return {
        kind: 'refresh',
        command,
        request: command.refresh_request,
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
  readonly ctx: CloudflareRouterApiContext;
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
  readonly ctx: CloudflareRouterApiContext;
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
        authority: exportAuthorization.authority,
      });
      if (!result.ok) return strictPostRegistrationFailureResponse(result);
      return json(result.value, { status: 200 });
    }
    case 'recovery': {
      const result = await input.port.recover({
        request: parsed.request,
        authority: authorized.authority,
      });
      if (!result.ok) return strictPostRegistrationFailureResponse(result);
      const recorded = await input.ctx.service.walletRegistration.recordEcdsaPostRegistrationProof({
        operation: 'recovery',
        request: parsed.request,
        response: result.value,
      });
      if (!recorded.ok) {
        return json(recorded, { status: recorded.code === 'internal' ? 500 : 400 });
      }
      return json(result.value, { status: 200 });
    }
    case 'refresh': {
      const result = await input.port.refresh({
        request: parsed.command,
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
    input.scope.activation_epoch === input.request.lifecycle.root_share_epoch
  );
}

function strictEcdsaExportFailure(
  status: number,
  code: string,
  message: string,
): Extract<StrictEcdsaExportAuthorizationResult, { readonly ok: false }> {
  return { ok: false, error: { status, body: { ok: false, code, message } } };
}

async function claimStrictEcdsaExportOperationStepUp(input: {
  readonly operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
  readonly grantId: string;
  readonly authenticated: Extract<
    Awaited<ReturnType<typeof authenticateRouterAbOperationStepUpAppSessionIdentity>>,
    { readonly ok: true }
  >;
}): Promise<Extract<StrictEcdsaExportAuthorizationResult, { readonly ok: false }> | null> {
  try {
    const operationId = requireAuthorizationValue(
      parseCapabilityOperationId(input.operation.operation_id),
    );
    const useId = requireAuthorizationValue(
      parseCapabilityGrantUseId(`ecdsa-operation-step-up-use:${input.operation.operation_id}`),
    );
    const result = await input.authenticated.claims.claimOperationStepUpFromGrant({
      tenantId: input.authenticated.session.tenantId,
      grantId: requireAuthorizationValue(parseCapabilityGrantId(input.grantId)),
      useId,
      auditEventId: requireAuthorizationValue(
        parseAuthorizationAuditEventId(
          `ecdsa-operation-step-up-audit:${input.operation.operation_id}`,
        ),
      ),
      authorizationSessionId: input.authenticated.session.sessionId,
      principalId: input.authenticated.session.principalId,
      capabilityId: requireAuthorizationValue(
        parseCapabilityId(input.operation.material_activation.capability),
      ),
      operationId,
      operation: buildEvmEcdsaMpcOperationRef('evm.export_key'),
      laneDigest: parseDigestB64u(input.operation.operation_digests.lane_digest_b64u),
      intentDigest: parseDigestB64u(input.operation.operation_digests.intent_digest_b64u),
      displayDigest: parseDigestB64u(input.operation.operation_digests.display_digest_b64u),
      claimedAtMs: Date.now(),
    });
    switch (result.kind) {
      case 'claimed':
      case 'operation_in_progress':
      case 'replayed':
        return result.use.useId === useId
          ? null
          : strictEcdsaExportFailure(
              409,
              'operation_claim_mismatch',
              'Operation step-up claim belongs to another request',
            );
      case 'grant_expired':
        return strictEcdsaExportFailure(401, result.kind, 'Operation step-up grant is expired');
      case 'grant_exhausted':
        return strictEcdsaExportFailure(409, result.kind, 'Operation step-up grant is exhausted');
      case 'grant_mismatch':
      case 'wallet_session_mismatch':
        return strictEcdsaExportFailure(403, result.kind, 'Operation step-up grant does not match');
      case 'wallet_session_expired':
      case 'wallet_session_quota_exhausted':
        return strictEcdsaExportFailure(
          409,
          result.kind,
          'Operation step-up authorization is invalid',
        );
    }
  } catch (error: unknown) {
    return strictEcdsaExportFailure(
      400,
      'invalid_body',
      error instanceof Error ? error.message : 'Export operation step-up claim is invalid',
    );
  }
}

async function authorizeStrictEcdsaExport(input: {
  readonly ctx: CloudflareRouterApiContext;
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
      operation.material_activation.activation_id !== input.request.material_activation_id ||
      operation.material_activation.signing_worker !==
        input.request.lifecycle.selected_server_id ||
      operation.signing_worker_id !== input.request.lifecycle.selected_server_id ||
      operation.expires_at_ms < input.request.expires_at_ms ||
      !strictEcdsaExportScopeMatchesRequest({ request: input.request, scope: operation.normal_signing_scope })
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
      authorizationClaims: input.ctx.service.authorizationClaims,
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
    const claimFailure = await claimStrictEcdsaExportOperationStepUp({
      operation,
      grantId: input.request.authorization.grant_id,
      authenticated,
    });
    if (claimFailure) return claimFailure;
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
    scope.activation_epoch !== input.request.lifecycle.root_share_epoch
  ) {
    return strictEcdsaExportFailure(403, 'scope_mismatch', 'ECDSA export scope is invalid');
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
    },
  };
}

function strictPostRegistrationFailureResponse(
  result: Extract<RouterAbEcdsaStrictPostRegistrationResult, { readonly ok: false }>,
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

async function authorizeStrictEcdsaSessionActivation(input: {
  readonly ctx: CloudflareRouterApiContext;
  readonly walletId: string;
  readonly source: 'verified_wallet_unlock' | 'additional_wallet_target';
}): Promise<
  | {
      readonly ok: true;
      readonly kind: 'issue_reusable_wallet_session';
      readonly principalId: PrincipalId;
      readonly authorizationSessionId: SeamsSessionId;
      readonly authority: WalletAuthAuthorityRef;
    }
  | {
      readonly ok: true;
      readonly kind: 'reuse_reusable_wallet_session';
      readonly principalId: PrincipalId;
      readonly authorizationSessionId: SeamsSessionId;
      readonly walletSessionId: WalletSessionId;
      readonly quotaId: MpcWalletSigningQuotaId;
    }
  | {
      readonly ok: false;
      readonly code: 'unauthorized' | 'identity_mismatch';
      readonly message: string;
    }
  | WalletSessionBoundaryFailure
> {
  const parsedSession = await parseStrictEcdsaAuthorizationSession(input.ctx);
  if (!parsedSession.ok) return parsedSession;
  const resolvedClaims = await resolveStrictEcdsaAuthorizationClaims({
    ctx: input.ctx,
    rawClaims: parsedSession.claims,
  });
  if (!resolvedClaims.ok) return resolvedClaims;
  const { appSessionClaims, ecdsaClaims, ed25519Claims } = resolvedClaims.claims;
  if (ecdsaClaims?.walletId === input.walletId) {
    if (input.source === 'verified_wallet_unlock') {
      return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
    }
    const principalId = parsePrincipalId(ecdsaClaims.sub);
    if (!principalId.ok) {
      return {
        ok: false,
        code: 'identity_mismatch',
        message: 'ECDSA Wallet Session principal is invalid',
      };
    }
    return {
      ok: true,
      kind: 'reuse_reusable_wallet_session',
      principalId: principalId.value,
      authorizationSessionId: ecdsaClaims.authorizationSessionId,
      walletSessionId: ecdsaClaims.walletSessionId,
      quotaId: ecdsaClaims.quotaId,
    };
  }
  if (ed25519Claims?.walletId === input.walletId) {
    return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
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
    };
  }
  return walletSessionFailure(WALLET_SESSION_FAILURE_CODES.scopeMismatch);
}

type StrictEcdsaSessionActivationInput =
  | {
      readonly ctx: CloudflareRouterApiContext;
      readonly body: unknown;
      readonly source: 'verified_wallet_unlock' | 'additional_wallet_target';
    }
  | {
      readonly ctx: CloudflareRouterApiContext;
      readonly body: unknown;
      readonly source: 'verified_passkey_session_exchange';
      readonly authorization: {
        readonly walletId: string;
        readonly principalId: PrincipalId;
        readonly authorizationSessionId: SeamsSessionId;
        readonly authority: WalletAuthAuthorityRef;
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
          }
        : {
            ok: false as const,
            code: 'identity_mismatch' as const,
            message: 'ECDSA activation wallet does not match the verified passkey principal',
          }
      : await authorizeStrictEcdsaSessionActivation({
          ctx: input.ctx,
          walletId: request.public_capability.client_id,
          source: input.source,
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
    walletSessionId = issued.session.walletSessionId;
    quotaId = issued.quota.quotaId;
  } else {
    walletSessionId = authorized.walletSessionId;
    quotaId = authorized.quotaId;
  }
  const signed = await signRouterAbEcdsaDerivationWalletSessionJwt({
    session: input.ctx.opts.session,
    userId: walletKey.walletId,
    evmFamilySigningKeySlotId: walletKey.evmFamilySigningKeySlotId,
    relayerKeyId: walletKey.relayerKeyId,
    sessionInfo: {
      sessionKind: 'jwt',
      authorizationSessionId: authorized.authorizationSessionId,
      thresholdSessionId: activated.session.thresholdSessionId,
      signingGrantId: activated.session.signingGrantId,
      walletSessionId,
      quotaId,
      expiresAtMs: activated.session.expiresAtMs,
      participantIds: walletKey.participantIds,
      runtimePolicyScope: request.session_policy.runtime_policy_scope,
      keyHandle: walletKey.keyHandle,
      stableKeyContext: {
        walletId: walletKey.walletId,
        evmFamilySigningKeySlotId: walletKey.evmFamilySigningKeySlotId,
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
        signing_grant_id: activated.session.signingGrantId,
        wallet_session_id: walletSessionId,
        quota_id: quotaId,
        expires_at_ms: activated.session.expiresAtMs,
        remaining_uses: activated.session.remainingUses,
        wallet_session_jwt: signed.jwt,
      },
      normal_signing: normalSigning,
    },
    { status: 200 },
  );
}

export async function handleThresholdEcdsa(
  ctx: CloudflareRouterApiContext,
): Promise<Response | null> {
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
    pathname !== ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PREPARE_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_GRANT_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_SESSION_ACTIVATION_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH &&
    pathname !== ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH
  ) {
    return null;
  }

  const bodyUnknown = await readJson(ctx.request);
  if (pathname === ROUTER_AB_ECDSA_DERIVATION_OPERATION_STEP_UP_GRANT_PATH) {
    let request: RouterAbEcdsaOperationStepUpGrantRequestV1Wire;
    try {
      request = parseRouterAbEcdsaOperationStepUpGrantRequestV1(bodyUnknown);
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
    return issueEcdsaOperationStepUpGrant({ ctx, request });
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
    pathname === ROUTER_AB_ECDSA_DERIVATION_RECOVERY_PATH ||
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
      privatePath: ROUTER_AB_ECDSA_DERIVATION_PRIVATE_SIGNING_PATHS.prepare,
      phase: 'prepare',
    });
  }

  if (pathname === ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_PATH) {
    return handleRouterAbEcdsaDerivationNormalSigningRoute({
      ctx,
      body,
      privatePath: ROUTER_AB_ECDSA_DERIVATION_PRIVATE_SIGNING_PATHS.finalize,
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
