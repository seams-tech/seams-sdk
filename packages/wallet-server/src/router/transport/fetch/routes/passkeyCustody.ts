import type { FetchRouterApiContext } from '../createFetchRouter';
import type {
  PasskeyCustodyEnvelopeRetrievalWireRequest,
  WalletRecoveryPasskeyRouteFinalizationRequest,
  WalletRecoveryGoogleEmailOtpRouteFinalizationRequest,
} from '../../../cloudflare/d1/passkeyCustody/d1PasskeyCustodyRouteService';
import type { WalletRecoveryCodeLocatorRecord } from '../../../cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import {
  findRouteDefinitionById,
  matchesRouteDefinitionRequest,
} from '../../../framework/routeDefinitions';
import { toFetchRouteResponse } from '../../../framework/routeResponses';
import { readJson } from '../../../framework/http';
import {
  extractBearerCredential,
  resolveSourceIpFromFetchHeaders,
} from '../../../auth/routerApiKeyAuth';
import {
  isHostWithinRpId,
  originHostnameOrEmpty,
} from '../../../../core/authService/webauthnOidcHelpers';
import {
  parseRecoveryCodeReservationId,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import {
  parseAuthorizationAuditEventId,
  parseAuthorizationEvidenceId,
  parseAuthorizationEvidenceSetId,
  parseAuthorizedOperationId,
  parseAuthFactorId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parsePrincipalId,
  parseTenantId,
  buildVaultOperationRef,
} from '@shared/authorization/capabilityKinds';
import {
  buildCapabilityOperationEnvelope,
  computeCapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import {
  computeWalletCustodyAdminChallengeDigest,
  type WalletCustodyAdminOperation,
} from '@shared/authorization/walletCustodyOperation';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  parseEmailOtpChallengeId,
  type EmailOtpChallengeId,
  parseOrgId,
  parseProviderSubject,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  parseWalletId,
  parseWalletRecoveryOperationId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletRecoveryOperationId,
  type WalletId,
} from '@shared/utils/domainIds';
import { parseDeviceId, type DeviceId } from '@shared/authorization/capabilityKinds';
import {
  parseWalletRecoveryTargetV1,
  type WalletRecoveryTargetV1,
} from '@shared/wallet-recovery/walletRecoveryTarget';
import type { WebAuthnAuthenticationCredential } from '../../../../core/types';
import { parseWebAuthnAuthenticationCredential } from '../../../auth/webAuthnCredentialCodecs';
import {
  hashEmailOtpOperationBinding,
  emailOtpStatusCode,
} from '../../../domains/emailOtp/emailOtpSessionRouteHelpers';
import {
  buildVerifiedWalletOperationEmailOtpFactorResult,
  buildVerifiedWalletOperationPasskeyFactorResult,
  type VerifiedWalletOperationFactorResult,
} from '../../../../authorization/factorEvidence';
import {
  parseSessionOrigin,
  parseVerifiedOwnerProofId,
  type AuthorizedOperation,
} from '../../../../authorization/domain';
import { EMAIL_OTP_CHANNEL, WALLET_EMAIL_OTP_UNLOCK_OPERATION } from '@shared/utils/emailOtpDomain';
import { parsePasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import { parseWalletRecoverySetRotationWireV1 } from '@shared/wallet-recovery/walletRecoveryEnvelopeSet';
import { parseRecoveryCodeLocatorV1 } from '@shared/wallet-recovery/recoveryCodeLocator';
import { parseDerivedWalletRecoveryKeyId } from '@shared/wallet-recovery/recoveryKeyId';
import {
  parseWalletRecoveryEcdsaPossessionProofV1,
  type WalletRecoveryEcdsaPossessionProofV1,
} from '@shared/wallet-recovery/walletRecoveryEcdsaPossession';
import { base64UrlDecode } from '@shared/utils/base64';
import type { EmailOtpEnrollmentMaterialBoundaryInput } from '../../../cloudflare/d1/emailOtp/d1EmailOtpRecords';

/**
 * The transport for custody envelope retrieval.
 *
 * Thin on purpose: it parses a body, hands it to the port, and returns what
 * the port decided. Every gate — assertion verification, credential match,
 * lifecycle, digest — lives below, and the status each failure earns is fixed
 * in one wire mapping. A transport that re-decided any of that would be a
 * second opinion on whether a wallet opens.
 */

const ROUTE_ID = 'passkey_custody_envelope_retrieve';
const CREDENTIALS_LIST_ROUTE_ID = 'wallet_custody_credentials_list';
const CREDENTIAL_LABEL_ROUTE_ID = 'wallet_custody_credential_label';
const RECOVERY_PREPARE_ROUTE_ID = 'wallet_recovery_prepare';
const RECOVERY_GOOGLE_VERIFY_ROUTE_ID = 'wallet_recovery_google_verify';
const RECOVERY_EMAIL_OTP_VERIFY_ROUTE_ID = 'wallet_recovery_email_otp_verify';
const RECOVERY_EMAIL_OTP_RELEASE_ROUTE_ID = 'wallet_recovery_email_otp_release';
const RECOVERY_GOOGLE_EMAIL_OTP_FINALIZE_ROUTE_ID = 'wallet_recovery_google_email_otp_finalize';
const RECOVERY_FINALIZE_ROUTE_ID = 'wallet_recovery_finalize';
const RECOVERY_ACK_ROUTE_ID = 'wallet_recovery_backup_acknowledge';
const RECOVERY_ROTATE_ROUTE_ID = 'wallet_recovery_codes_rotate';
const RECOVERY_READ_ROUTE_ID = 'wallet_recovery_codes_read';
const RECOVERY_STATUS_ROUTE_ID = 'wallet_recovery_status';
const EMAIL_OTP_CHALLENGE_ROUTE_ID = 'wallet_custody_email_otp_challenge';
const ENVELOPE_OWNERSHIP_UPGRADE_ROUTE_ID = 'wallet_custody_envelope_ownership_upgrade';

type WalletCustodyOwnerProofWire =
  | {
      readonly kind: 'passkey';
      readonly walletId: string;
      readonly rpId: string;
      readonly credentialIdB64u: string;
      readonly challenge_digest: string;
      readonly webauthn_authentication: WebAuthnAuthenticationCredential;
    }
  | {
      readonly kind: 'email_otp';
      readonly provider_subject_id: string;
      readonly challenge_id: string;
      readonly otp_code: string;
      readonly challenge_digest: string;
    };

type WalletCustodyAuthorizationResult =
  | { readonly ok: true; readonly operation: AuthorizedOperation }
  | { readonly ok: false; readonly response: Response };

const CUSTODY_OPERATION_CAPABILITY_ID = 'wallet-custody-admin';
const CUSTODY_PROOF_TTL_MS = 60_000;

function parseRequiredString(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${field} is required`);
  }
  return value.trim();
}

function requireExactObjectFields(
  value: Record<string, unknown>,
  fields: readonly string[],
  label: string,
): void {
  const keys = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains unsupported fields`);
  }
}

function parseCustodyOwnerProof(value: unknown): WalletCustodyOwnerProofWire {
  if (!isObject(value)) throw new Error('factorProof is required');
  const kind = trimmed(value.kind);
  if (kind === 'passkey') {
    requireExactObjectFields(
      value,
      [
        'kind',
        'walletId',
        'rpId',
        'credentialIdB64u',
        'challenge_digest',
        'webauthn_authentication',
      ],
      'factorProof',
    );
    const webauthnAuthentication = parseWebAuthnAuthenticationCredential(
      value.webauthn_authentication,
    );
    if (!webauthnAuthentication) throw new Error('factorProof.webauthn_authentication is invalid');
    return {
      kind,
      walletId: parseRequiredString(value.walletId, 'factorProof.walletId'),
      rpId: parseRequiredString(value.rpId, 'factorProof.rpId'),
      credentialIdB64u: parseRequiredString(value.credentialIdB64u, 'factorProof.credentialIdB64u'),
      challenge_digest: parseRequiredString(value.challenge_digest, 'factorProof.challenge_digest'),
      webauthn_authentication: webauthnAuthentication,
    };
  }
  if (kind === 'email_otp') {
    requireExactObjectFields(
      value,
      ['kind', 'provider_subject_id', 'challenge_id', 'otp_code', 'challenge_digest'],
      'factorProof',
    );
    return {
      kind,
      provider_subject_id: parseRequiredString(
        value.provider_subject_id,
        'factorProof.provider_subject_id',
      ),
      challenge_id: parseRequiredString(value.challenge_id, 'factorProof.challenge_id'),
      otp_code: parseRequiredString(value.otp_code, 'factorProof.otp_code'),
      challenge_digest: parseRequiredString(value.challenge_digest, 'factorProof.challenge_digest'),
    };
  }
  throw new Error('factorProof.kind must be passkey or email_otp');
}

function parseRequiredAuthorizationValue<T>(
  parsed:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

async function custodyDigest(domain: string, value: Record<string, unknown>): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256BytesUtf8(`${domain}|${alphabetizeStringify(value)}`)),
  );
}

async function buildWalletCustodyOperation(input: {
  readonly tenantId: string;
  readonly principalId: string;
  readonly walletId: string;
  readonly operation: WalletCustodyAdminOperation;
  readonly payload: Record<string, unknown>;
  readonly requestOrigin: string;
}): Promise<{
  readonly operation: Awaited<ReturnType<typeof buildCapabilityOperationEnvelope>>;
  readonly challengeDigest: DigestB64u;
}> {
  const tenantId = parseRequiredAuthorizationValue(parseTenantId(input.tenantId));
  const principalId = parseRequiredAuthorizationValue(parsePrincipalId(input.principalId));
  const capabilityId = parseRequiredAuthorizationValue(
    parseCapabilityId(CUSTODY_OPERATION_CAPABILITY_ID),
  );
  const operationRef = buildVaultOperationRef('vault.reveal');
  const laneDigest = await custodyDigest('seams:wallet-custody:lane:v1', {
    capabilityId,
    operation: input.operation,
    operationRef,
  });
  const challengeDigest = await computeWalletCustodyAdminChallengeDigest({
    walletId: input.walletId,
    operation: input.operation,
    payload: input.payload,
    requestOrigin: input.requestOrigin,
  });
  const intentDigest = challengeDigest;
  const displayDigest = await custodyDigest('seams:wallet-custody:display:v1', {
    walletId: input.walletId,
    operation: input.operation,
  });
  const operationId = parseRequiredAuthorizationValue(
    parseCapabilityOperationId(`wallet-custody:${input.operation}:${intentDigest}`),
  );
  return {
    operation: buildCapabilityOperationEnvelope({
      tenantId,
      principalId,
      capabilityId,
      operationId,
      operation: operationRef,
      digests: { laneDigest, intentDigest, displayDigest },
    }),
    challengeDigest,
  };
}

async function authorizeWalletCustodyOperation(input: {
  readonly ctx: FetchRouterApiContext;
  readonly walletId: string;
  readonly operation: WalletCustodyAdminOperation;
  readonly payload: Record<string, unknown>;
  readonly factorProof: unknown;
}): Promise<WalletCustodyAuthorizationResult> {
  const requestOrigin = trimmed(input.ctx.request.headers.get('origin'));
  if (!requestOrigin) {
    return toCustodyAuthorizationFailure(400, 'invalid_origin', 'request Origin is required');
  }
  let origin: ReturnType<typeof parseSessionOrigin>;
  let proof: WalletCustodyOwnerProofWire;
  let walletId: WalletId;
  try {
    origin = parseSessionOrigin(requestOrigin);
    walletId = parseRequiredAuthorizationValue(parseWalletId(input.walletId));
    proof = parseCustodyOwnerProof(input.factorProof);
  } catch (error: unknown) {
    return toCustodyAuthorizationFailure(
      400,
      'invalid_owner_proof',
      error instanceof Error ? error.message : 'owner proof is invalid',
    );
  }
  if (proof.kind === 'passkey' && proof.walletId !== input.walletId) {
    return toCustodyAuthorizationFailure(403, 'scope_mismatch', 'owner proof wallet differs');
  }

  let principalId: string;
  let factor: VerifiedWalletOperationFactorResult;
  let operation: Awaited<ReturnType<typeof buildCapabilityOperationEnvelope>>;
  let challengeDigest: DigestB64u;
  try {
    principalId = proof.kind === 'passkey' ? input.walletId : proof.provider_subject_id;
    const built = await buildWalletCustodyOperation({
      tenantId: input.ctx.service.authorizedOperations.tenantId,
      principalId,
      walletId: input.walletId,
      operation: input.operation,
      payload: input.payload,
      requestOrigin,
    });
    operation = built.operation;
    challengeDigest = built.challengeDigest;
  } catch (error: unknown) {
    return toCustodyAuthorizationFailure(
      400,
      'invalid_owner_proof',
      error instanceof Error ? error.message : 'owner proof binding is invalid',
    );
  }
  const operationFingerprintDigest = await computeCapabilityOperationFingerprintDigest(operation);
  const nowMs = Date.now();
  if (proof.challenge_digest !== String(challengeDigest)) {
    return toCustodyAuthorizationFailure(
      403,
      'scope_mismatch',
      'factor proof challenge does not match the requested operation',
    );
  }

  if (proof.kind === 'passkey') {
    let authority: PasskeyWalletAuthAuthority;
    try {
      authority = buildPasskeyWalletAuthAuthority({
        walletId,
        rpId: proof.rpId,
        credentialIdB64u: proof.credentialIdB64u,
      });
    } catch (error: unknown) {
      return toCustodyAuthorizationFailure(
        400,
        'invalid_owner_proof',
        error instanceof Error ? error.message : 'passkey authority is invalid',
      );
    }
    const active =
      await input.ctx.service.walletAuthMethods.verifyActivePasskeyAuthority(authority);
    if (!active.ok) return toCustodyAuthorizationFailure(403, active.code, active.message);
    const credential = parseWebAuthnAuthenticationCredential(proof.webauthn_authentication);
    if (!credential) {
      return toCustodyAuthorizationFailure(
        400,
        'invalid_owner_proof',
        'passkey assertion is invalid',
      );
    }
    const credentialId = String(credential.rawId || credential.id).trim();
    if (credentialId !== authority.factor.credentialIdB64u) {
      return toCustodyAuthorizationFailure(401, 'unauthorized', 'passkey credential changed');
    }
    const verified = await input.ctx.service.webAuthn.verifyWebAuthnAuthenticationLite({
      userId: input.walletId,
      rpId: authority.verifier.rpId,
      expectedChallenge: challengeDigest,
      expected_origin: requestOrigin,
      webauthn_authentication: credential,
    });
    if (!verified.success || !verified.verified) {
      return toCustodyAuthorizationFailure(
        401,
        verified.code || 'not_verified',
        verified.message || 'WebAuthn authentication verification failed',
      );
    }
    factor = buildVerifiedWalletOperationPasskeyFactorResult({
      tenantId: operation.tenantId,
      principalId: operation.principalId,
      walletId,
      authorityRef: await walletAuthAuthorityRef({ authority }),
      requestOrigin: origin,
      audience: origin,
      factorId: parseRequiredAuthorizationValue(
        parseAuthFactorId(`passkey:${authority.factor.credentialIdB64u}`),
      ),
      credentialIdB64u: parseRequiredAuthorizationValue(
        parseWebAuthnCredentialIdB64u(authority.factor.credentialIdB64u),
      ),
      assertionDigest: await custodyDigest('seams:wallet-custody:assertion:v1', { credential }),
      operation,
      verifiedAtMs: nowMs,
      expiresAtMs: nowMs + CUSTODY_PROOF_TTL_MS,
    });
  } else {
    const providerSubject = parseRequiredAuthorizationValue(
      parseProviderSubject(proof.provider_subject_id),
    );
    const orgId = parseRequiredAuthorizationValue(
      parseOrgId(input.ctx.service.authorizedOperations.tenantId),
    );
    const active =
      await input.ctx.service.walletAuthMethods.resolveActiveEmailOtpAuthorityForVerifiedSubject({
        walletId: input.walletId,
        providerUserId: proof.provider_subject_id,
      });
    if (!active.ok) return toCustodyAuthorizationFailure(403, active.code, active.message);
    const activeAuthorityRef = await walletAuthAuthorityRef({ authority: active.authority });
    const ownerProofBindingDigest = await hashEmailOtpOperationBinding({
      walletId: input.walletId,
      providerUserId: proof.provider_subject_id,
      orgId,
      operation: `wallet_custody:${input.operation}`,
      requestOrigin,
      audience: requestOrigin,
      authorityRef: activeAuthorityRef,
      operationFingerprintDigest: challengeDigest,
    });
    const verified = await input.ctx.service.emailOtp.verifyEmailOtpChallenge({
      userId: proof.provider_subject_id,
      walletId: input.walletId,
      orgId,
      challengeId: proof.challenge_id,
      otpCode: proof.otp_code,
      otpChannel: EMAIL_OTP_CHANNEL,
      ownerProofBindingDigest,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    if (!verified.ok) {
      return toCustodyAuthorizationFailure(
        verified.code === 'invalid_body' ? 400 : 401,
        verified.code,
        verified.message,
      );
    }
    const consumed = await input.ctx.service.emailOtp.consumeEmailOtpGrant({
      subject: {
        kind: 'provider_identity',
        orgId,
        providerSubject,
        walletId,
      },
      loginGrant: verified.loginGrant,
      otpChannel: EMAIL_OTP_CHANNEL,
    });
    if (!consumed.ok) {
      return toCustodyAuthorizationFailure(
        emailOtpStatusCode(consumed.code),
        consumed.code,
        consumed.message,
      );
    }
    factor = buildVerifiedWalletOperationEmailOtpFactorResult({
      tenantId: operation.tenantId,
      principalId: operation.principalId,
      walletId,
      authorityRef: activeAuthorityRef,
      requestOrigin: origin,
      audience: origin,
      factorId: parseRequiredAuthorizationValue(
        parseAuthFactorId(
          `email_otp:${active.authority.factor.provider}:${proof.provider_subject_id}`,
        ),
      ),
      operation,
      challengeId: parseRequiredAuthorizationValue(parseEmailOtpChallengeId(consumed.challengeId)),
      verificationReceiptDigest: await custodyDigest('seams:wallet-custody:otp-receipt:v1', {
        challengeId: consumed.challengeId,
        operationFingerprintDigest,
      }),
      verifiedAtMs: nowMs,
      expiresAtMs: Math.min(nowMs + CUSTODY_PROOF_TTL_MS, verified.grantExpiresAtMs),
    });
  }

  const ownerProof = await input.ctx.service.authorizedOperations.buildVerifiedOwnerProof({
    purpose: 'operation',
    proofId: parseVerifiedOwnerProofId(`wallet-custody:${operation.operationId}`),
    factor,
  });
  if (
    ownerProof.purpose !== 'operation' ||
    ownerProof.operation.operationFingerprintDigest !== operationFingerprintDigest
  ) {
    return toCustodyAuthorizationFailure(
      403,
      'owner_proof_rejected',
      'owner proof binding is invalid',
    );
  }
  const evidenceSet =
    await input.ctx.service.authorizedOperations.recordVerifiedWalletOperationFactorEvidenceSet({
      operation,
      evidenceId: parseRequiredAuthorizationValue(
        parseAuthorizationEvidenceId(`wallet-custody:evidence:${operation.operationId}`),
      ),
      evidenceSetId: parseRequiredAuthorizationValue(
        parseAuthorizationEvidenceSetId(`wallet-custody:evidence-set:${operation.operationId}`),
      ),
      factor,
    });
  const admission = await input.ctx.service.authorizedOperations.admitAuthorizedOperation({
    operation: {
      tenantId: operation.tenantId,
      authorizedOperationId: parseRequiredAuthorizationValue(
        parseAuthorizedOperationId(`wallet-custody:authorized:${operation.operationId}`),
      ),
      auditEventId: parseRequiredAuthorizationValue(
        parseAuthorizationAuditEventId(`wallet-custody:audit:${operation.operationId}`),
      ),
      operation,
      authorization: { kind: 'verified_step_up', evidenceSetDigest: evidenceSet.evidenceSetDigest },
      quota: { kind: 'quota_neutral' },
      claimedAtMs: nowMs,
    },
  });
  switch (admission.kind) {
    case 'claimed':
      return { ok: true, operation: admission.operation };
    case 'replayed':
    case 'operation_in_progress':
      return { ok: false, response: authorizedOperationReplay(admission.operation) };
    case 'authorization_grant_rejected':
    case 'verified_step_up_rejected':
    case 'wallet_session_quota_exhausted':
    case 'material_mismatch':
      return toCustodyAuthorizationFailure(403, 'owner_proof_rejected', 'owner proof was rejected');
  }
}

function toCustodyAuthorizationFailure(
  status: number,
  code: string,
  message: string,
): WalletCustodyAuthorizationResult {
  return {
    ok: false,
    response: toFetchRouteResponse({ status, body: { ok: false, code, message } }),
  };
}

async function completeWalletCustodyOperation(
  ctx: FetchRouterApiContext,
  operation: AuthorizedOperation,
  status: number,
  body: Record<string, unknown>,
  result: 'succeeded' | 'failed_before_side_effect' = 'succeeded',
): Promise<Response> {
  const bodyText = JSON.stringify(body);
  await ctx.service.authorizedOperations.completeAuthorizedOperation({
    operation,
    result,
    response: { status, contentType: 'application/json', bodyText },
    completedAtMs: Date.now(),
  });
  return toFetchRouteResponse({ status, body });
}

export async function handlePasskeyCustody(ctx: FetchRouterApiContext): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const body = await readJsonObject(ctx.request);
  const request = parseWireRequest(body, ctx.request.headers.get('origin'));
  if (!request) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: 'custody retrieval needs a locator, a challenge id, and an assertion',
      },
    });
  }

  const response = await ctx.service.passkeyCustody.retrieveEnvelope(request);
  return toFetchRouteResponse(response);
}

function parseWalletCustodyEmailOtpChallengeRequest(
  value: unknown,
  actualOrigin: string,
): {
  readonly walletId: string;
  readonly providerSubjectId: string;
  readonly operation: WalletCustodyAdminOperation;
  readonly payload: Record<string, unknown>;
  readonly requestOrigin: string;
} {
  if (!isObject(value)) throw new Error('Email OTP custody challenge body must be an object');
  const keys = Object.keys(value).sort();
  const expected = ['operation', 'payload', 'providerSubjectId', 'requestOrigin', 'walletId'];
  const required = ['operation', 'payload', 'providerSubjectId', 'walletId'];
  const withoutOptional = keys.filter((key) => key !== 'requestOrigin');
  if (
    withoutOptional.length !== required.length ||
    withoutOptional.some((key, index) => key !== required.slice().sort()[index]) ||
    (keys.includes('requestOrigin') && keys.length !== expected.length)
  ) {
    throw new Error('Email OTP custody challenge body contains unsupported fields');
  }
  const walletId = parseRequiredAuthorizationValue(parseWalletId(value.walletId));
  const providerSubjectId = parseRequiredAuthorizationValue(
    parseProviderSubject(value.providerSubjectId),
  );
  const operation = value.operation;
  if (
    operation !== 'credentials_list' &&
    operation !== 'credential_label' &&
    operation !== 'recovery_rotate' &&
    operation !== 'recovery_read'
  ) {
    throw new Error('Email OTP custody challenge operation is invalid');
  }
  if (!isObject(value.payload)) throw new Error('Email OTP custody challenge payload is invalid');
  if (value.requestOrigin !== undefined && value.requestOrigin !== actualOrigin) {
    throw new Error('Email OTP custody challenge requestOrigin does not match Origin');
  }
  return {
    walletId,
    providerSubjectId,
    operation,
    payload: value.payload,
    requestOrigin: actualOrigin,
  };
}

/** Issues one operation-bound Email OTP challenge without exposing authority metadata. */
export async function handleWalletCustodyEmailOtpChallenge(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, EMAIL_OTP_CHALLENGE_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${EMAIL_OTP_CHALLENGE_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;
  const originHeader = trimmed(ctx.request.headers.get('origin'));
  let request: ReturnType<typeof parseWalletCustodyEmailOtpChallengeRequest>;
  try {
    const origin = parseSessionOrigin(originHeader);
    request = parseWalletCustodyEmailOtpChallengeRequest(await readJson(ctx.request), origin);
  } catch (error: unknown) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: error instanceof Error ? error.message : 'Email OTP custody challenge is invalid',
      },
    });
  }

  const active =
    await ctx.service.walletAuthMethods.resolveActiveEmailOtpAuthorityForVerifiedSubject({
      walletId: request.walletId,
      providerUserId: request.providerSubjectId,
    });
  if (!active.ok) {
    return toFetchRouteResponse({
      status: 403,
      body: { ok: false, code: active.code, message: active.message },
    });
  }
  const authoritativeOrgId = parseRequiredAuthorizationValue(
    parseOrgId(ctx.service.authorizedOperations.tenantId),
  );
  const challengeDigest = await computeWalletCustodyAdminChallengeDigest(request);
  const ownerProofBindingDigest = await hashEmailOtpOperationBinding({
    walletId: request.walletId,
    providerUserId: request.providerSubjectId,
    orgId: authoritativeOrgId,
    operation: `wallet_custody:${request.operation}`,
    requestOrigin: request.requestOrigin,
    audience: request.requestOrigin,
    authorityRef: await walletAuthAuthorityRef({ authority: active.authority }),
    operationFingerprintDigest: challengeDigest,
  });
  const result = await ctx.service.emailOtp.createEmailOtpChallenge({
    userId: request.providerSubjectId,
    walletId: request.walletId,
    orgId: authoritativeOrgId,
    otpChannel: EMAIL_OTP_CHANNEL,
    ownerProofBindingDigest,
    reuseActiveChallenge: true,
    requestOrigin: request.requestOrigin,
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  });
  if (!result.ok) {
    return toFetchRouteResponse({
      status: emailOtpStatusCode(result.code),
      body: {
        ok: false,
        code: result.code,
        message: result.message,
        ...(result.retryAfterMs ? { retryAfterMs: result.retryAfterMs } : {}),
      },
    });
  }
  return toFetchRouteResponse({
    status: 200,
    body: {
      ok: true,
      challengeId: result.challenge.challengeId,
      challenge_digest: challengeDigest,
      expiresAtMs: result.challenge.expiresAtMs,
      otpChannel: result.challenge.otpChannel,
    },
  });
}

/** Lists public passkey envelope identities with their sibling activity rows. */
export async function handleWalletCustodyCredentialsList(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, CREDENTIALS_LIST_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${CREDENTIALS_LIST_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;
  const walletId = walletIdFromPath(route.path, ctx.pathname);
  if (!walletId) {
    return toFetchRouteResponse({
      status: 400,
      body: { ok: false, code: 'invalid_request', message: 'credential list needs a wallet' },
    });
  }
  const body = await readJsonObject(ctx.request);
  const authorized = await authorizeWalletCustodyOperation({
    ctx,
    walletId,
    operation: 'credentials_list',
    payload: { walletId },
    factorProof: body?.factorProof,
  });
  if (!authorized.ok) return authorized.response;
  const parsedWalletId = parseWalletId(walletId);
  if (!parsedWalletId.ok) {
    return toFetchRouteResponse({
      status: 400,
      body: { ok: false, code: 'invalid_request', message: 'wallet id is invalid' },
    });
  }
  const result = await ctx.service.passkeyCustody.listWalletCredentials({
    walletId: parsedWalletId.value,
  });
  return await completeWalletCustodyOperation(ctx, authorized.operation, 200, {
    ok: true,
    credentials: result,
  });
}

/**
 * Refactor 109C: binds a pre-109C custody envelope to the method that opened it.
 *
 * The exact operation credential names the auth method that opened the
 * envelope. Unlock already proved that method, so finishing the ownership
 * upgrade requires no second user assertion.
 */
export async function handleWalletCustodyEnvelopeOwnershipUpgrade(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, ENVELOPE_OWNERSHIP_UPGRADE_ROUTE_ID);
  if (!route)
    throw new Error(`Missing route definition for ${ENVELOPE_OWNERSHIP_UPGRADE_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const parsedWalletId = parseWalletId(walletIdFromPath(route.path, ctx.pathname));
  if (!parsedWalletId.ok) {
    return toFetchRouteResponse({
      status: 400,
      body: { ok: false, code: 'invalid_request', message: 'wallet id is invalid' },
    });
  }
  const token = extractBearerCredential(ctx.request.headers);
  if (!token) {
    return toFetchRouteResponse({
      status: 401,
      body: { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
    });
  }
  const exact =
    await ctx.service.authorizationSessions.readWalletSessionAuthorizationV2ByOperationCredential({
      tenantId: ctx.service.authorizationSessions.tenantId,
      token,
      nowMs: Date.now(),
    });
  if (!exact || String(exact.authorization.session.walletId) !== String(parsedWalletId.value)) {
    return toFetchRouteResponse({
      status: 401,
      body: { ok: false, code: 'unauthorized', message: 'No valid Wallet Session' },
    });
  }
  const walletAuthMethodId = exact.authMethod.walletAuthMethodId;

  const body = await readJsonObject(ctx.request);
  let envelope: PasskeyCustodyEnvelopeRecord;
  try {
    envelope = parsePasskeyCustodyEnvelopeRecord(body?.envelope);
  } catch (error: unknown) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: error instanceof Error ? error.message : 'custody envelope is invalid',
      },
    });
  }

  const result = await ctx.service.passkeyCustody.upgradeEnvelopeOwnership({
    walletId: parsedWalletId.value,
    walletAuthMethodId,
    envelope,
  });
  switch (result.kind) {
    case 'upgraded':
      return toFetchRouteResponse({
        status: 200,
        body: { ok: true, upgraded: true, envelopeRevision: result.envelopeRevision },
      });
    case 'already_owned':
      return toFetchRouteResponse({ status: 200, body: { ok: true, upgraded: false } });
    case 'not_found':
      return toFetchRouteResponse({
        status: 404,
        body: { ok: false, code: 'not_found', message: 'no custody envelope to upgrade' },
      });
    case 'conflict':
      return toFetchRouteResponse({
        status: 409,
        body: { ok: false, code: 'conflict', message: result.reason },
      });
    case 'refused':
      return toFetchRouteResponse({
        status: 403,
        body: { ok: false, code: 'forbidden', message: result.reason },
      });
  }
}

/** Renames one passkey credential; the label is metadata and never AAD. */
export async function handleWalletCustodyCredentialLabel(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, CREDENTIAL_LABEL_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${CREDENTIAL_LABEL_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;
  const walletId = walletIdFromPath(route.path, ctx.pathname);
  const body = await readJsonObject(ctx.request);
  const envelopeId = trimmed(body?.envelopeId);
  const label = body?.label;
  if (!walletId || !envelopeId || (label !== undefined && typeof label !== 'string')) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: 'credential rename needs a wallet, envelope, and optional label',
      },
    });
  }
  const authorized = await authorizeWalletCustodyOperation({
    ctx,
    walletId,
    operation: 'credential_label',
    payload: { walletId, envelopeId, ...(label === undefined ? {} : { label }) },
    factorProof: body?.factorProof,
  });
  if (!authorized.ok) return authorized.response;
  const parsedWalletId = parseWalletId(walletId);
  if (!parsedWalletId.ok) {
    return toFetchRouteResponse({
      status: 400,
      body: { ok: false, code: 'invalid_request', message: 'wallet id is invalid' },
    });
  }
  const result = await ctx.service.passkeyCustody.renameWalletCredential({
    walletId: parsedWalletId.value,
    envelopeId,
    ...(label === undefined ? {} : { label }),
  });
  switch (result.kind) {
    case 'updated':
      return await completeWalletCustodyOperation(ctx, authorized.operation, 200, {
        ok: true,
        credential: result.projection,
      });
    case 'missing':
      return await completeWalletCustodyOperation(
        ctx,
        authorized.operation,
        404,
        { ok: false, code: 'credential_not_found', message: 'credential not found' },
        'failed_before_side_effect',
      );
    case 'conflict':
      return await completeWalletCustodyOperation(
        ctx,
        authorized.operation,
        409,
        { ok: false, code: 'credential_activity_conflict', message: 'credential changed; retry' },
        'failed_before_side_effect',
      );
    case 'invalid_envelope_id':
      return await completeWalletCustodyOperation(
        ctx,
        authorized.operation,
        400,
        { ok: false, code: 'invalid_envelope_id', message: 'credential envelope id is invalid' },
        'failed_before_side_effect',
      );
    case 'invalid_label':
      return await completeWalletCustodyOperation(
        ctx,
        authorized.operation,
        400,
        { ok: false, code: 'invalid_label', message: result.reason },
        'failed_before_side_effect',
      );
  }
}

/**
 * Spending a recovery code.
 *
 * The refusal is one shape for every cause — unknown wallet, unknown code,
 * spent code. The domain deliberately makes them indistinguishable so the
 * route cannot be used to count how many of a user's ten codes remain, and
 * this must not helpfully re-separate them on the way out.
 */
export async function handleWalletRecoveryPrepare(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_PREPARE_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_PREPARE_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const body = await readJsonObject(ctx.request);
  let parsed:
    | {
        readonly target: WalletRecoveryTargetV1;
        readonly recoveryCodeB64u: string;
        readonly reservationId: RecoveryCodeReservationId;
      }
    | undefined;
  try {
    if (!body) throw new Error('wallet recovery preparation body is required');
    requireExactObjectFields(
      body,
      ['target', 'recoveryCodeB64u', 'reservationId'],
      'wallet recovery preparation',
    );
    const target = parseWalletRecoveryTargetV1(body.target);
    const recoveryCodeB64u = parseRequiredString(body.recoveryCodeB64u, 'recoveryCodeB64u');
    if (!/^[A-Za-z0-9_-]+$/.test(recoveryCodeB64u)) {
      throw new Error('wallet recovery preparation is invalid');
    }
    parsed = {
      target,
      recoveryCodeB64u,
      reservationId: parseRecoveryCodeReservationId(body.reservationId),
    };
  } catch {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: 'wallet recovery preparation is invalid',
      },
    });
  }

  const origin = trimmed(ctx.request.headers.get('origin'));
  if (
    !origin ||
    (parsed.target.kind === 'passkey' &&
      !isHostWithinRpId(originHostnameOrEmpty(origin), parsed.target.rpId))
  ) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_origin',
        message: 'wallet recovery origin does not match the relying party',
      },
    });
  }

  let recoveryCodeBytes: Uint8Array;
  try {
    recoveryCodeBytes = base64UrlDecode(parsed.recoveryCodeB64u);
    if (recoveryCodeBytes.length === 0) throw new Error('recovery code is empty');
  } catch {
    return toFetchRouteResponse(refusedSpend());
  }

  try {
    const result = await ctx.service.passkeyCustody.prepareRecovery({
      target: parsed.target,
      origin,
      recoveryCodeBytes,
      reservationId: parsed.reservationId,
    });
    switch (result.kind) {
      case 'prepared':
        return toFetchRouteResponse({
          status: 200,
          body: {
            ok: true,
            walletId: result.walletId,
            wrap: result.wrap,
            entries: result.entries,
            keyManifest: result.keyManifest,
            target: result.target,
            recoveryOperationId: result.recoveryOperationId,
            targetDeviceId: result.targetDeviceId,
            targetAuthorityId: result.targetAuthorityId,
            targetWalletAuthMethodId: result.targetWalletAuthMethodId,
            ...(result.target.kind === 'passkey' ? { registration: result.registration } : {}),
            reservationId: result.reservationId,
            reservationExpiresAtMs: result.reservationExpiresAtMs,
            storeVersion: result.storeVersion,
          },
        });
      case 'conflict':
        return toFetchRouteResponse({
          status: 409,
          body: {
            ok: false,
            code: 'recovery_set_conflict',
            message: 'the recovery set changed during this attempt',
          },
        });
      case 'refused':
        return toFetchRouteResponse(refusedSpend());
      case 'reserved':
      case 'consumed':
        return toFetchRouteResponse({
          status: 401,
          body: {
            ok: false,
            code: 'recovery_code_used',
            message: 'that recovery code has already been used',
          },
        });
      case 'manifest_unavailable':
      case 'registration_unavailable':
        return toFetchRouteResponse({
          status: 409,
          body: {
            ok: false,
            code: 'recovery_preparation_conflict',
            message: 'wallet recovery could not be prepared',
          },
        });
    }
  } finally {
    recoveryCodeBytes.fill(0);
  }
}

export async function handleWalletRecoveryGoogleVerify(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_GOOGLE_VERIFY_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_GOOGLE_VERIFY_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  let request: WalletRecoveryGoogleVerifyRequest;
  try {
    request = parseWalletRecoveryGoogleVerifyRequest(await readJsonObject(ctx.request));
  } catch {
    return walletRecoveryRequestError();
  }
  const requestOrigin = trimmed(ctx.request.headers.get('origin'));
  if (!requestOrigin) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_origin',
        message: 'wallet recovery origin is required',
      },
    });
  }
  try {
    const result = await ctx.service.passkeyCustody.verifyGoogleRecovery({
      recoveryOperationId: request.recoveryOperationId,
      reservationId: String(request.reservationId),
      idToken: request.idToken,
      requestOrigin,
      clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    });
    if (!result.ok) return walletRecoveryGoogleFailureResponse(result);
    return toFetchRouteResponse({
      status: 200,
      body: {
        ok: true,
        recoveryOperationId: result.recoveryOperationId,
        reservationId: result.reservationId,
        challengeId: result.challengeId,
        delivery: result.delivery,
        expiresAtMs: result.expiresAtMs,
      },
    });
  } catch {
    return walletRecoveryInternalError();
  }
}

export async function handleWalletRecoveryEmailOtpVerify(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_EMAIL_OTP_VERIFY_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_EMAIL_OTP_VERIFY_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  let request: WalletRecoveryEmailOtpVerifyRequest;
  try {
    request = parseWalletRecoveryEmailOtpVerifyRequest(await readJsonObject(ctx.request));
  } catch {
    return walletRecoveryRequestError();
  }
  try {
    const result = await ctx.service.passkeyCustody.verifyRecoveryEmailOtp({
      recoveryOperationId: request.recoveryOperationId,
      reservationId: String(request.reservationId),
      challengeId: String(request.challengeId),
      otpCode: request.otpCode,
      clientIp: resolveSourceIpFromFetchHeaders(ctx.request.headers) || undefined,
    });
    if (!result.ok) return walletRecoveryGoogleFailureResponse(result);
    return toFetchRouteResponse({
      status: 200,
      body: {
        ok: true,
        recoveryOperationId: String(result.recovery.recoveryOperationId),
        reservationId: String(result.recovery.reservationId),
        challengeId: String(result.recovery.challengeId),
      },
    });
  } catch {
    return walletRecoveryInternalError();
  }
}

export async function handleWalletRecoveryEmailOtpRelease(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_EMAIL_OTP_RELEASE_ROUTE_ID);
  if (!route)
    throw new Error(`Missing route definition for ${RECOVERY_EMAIL_OTP_RELEASE_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  let request: WalletRecoveryEmailOtpReleaseRequest;
  try {
    request = parseWalletRecoveryEmailOtpReleaseRequest(await readJsonObject(ctx.request));
  } catch {
    return walletRecoveryRequestError();
  }
  try {
    const result = await ctx.service.passkeyCustody.releaseRecoveryEmailOtpFactor({
      recoveryOperationId: request.recoveryOperationId,
      reservationId: String(request.reservationId),
      workerEphemeralPublicKey65B64u: request.workerEphemeralPublicKey65B64u,
    });
    if (!result.ok) return walletRecoveryGoogleFailureResponse(result);
    switch (result.kind) {
      case 'email_otp_factor_release_v1':
        return toFetchRouteResponse({
          status: 200,
          body: {
            ok: true,
            kind: result.kind,
            recoveryOperationId: String(result.recovery.recoveryOperationId),
            reservationId: String(result.recovery.reservationId),
            challengeId: String(result.recovery.challengeId),
            providerSubject: result.recovery.providerSubject,
            verifiedEmail: result.recovery.verifiedEmail,
            enrollmentId: result.enrollment.enrollmentId,
            enrollmentSealKeyVersion: result.enrollment.enrollmentSealKeyVersion,
            serverEphemeralPublicKey65B64u: result.serverEphemeralPublicKey65B64u,
            nonce12B64u: result.nonce12B64u,
            ciphertextB64u: result.ciphertextB64u,
          },
        });
      case 'wallet_recovery_google_email_otp_new_enrollment_v1':
        return toFetchRouteResponse({
          status: 200,
          body: {
            ok: true,
            kind: result.kind,
            recoveryOperationId: String(result.recovery.recoveryOperationId),
            reservationId: String(result.recovery.reservationId),
            enrollment: {
              kind: 'create',
              providerSubject: result.enrollment.providerSubject,
              verifiedEmail: result.enrollment.verifiedEmail,
            },
          },
        });
    }
  } catch {
    return walletRecoveryInternalError();
  }
}

/**
 * Installs the Google/Email OTP recovery target selected by the persisted
 * `otp_verified` attempt. Recovery identity and enrollment identifiers stay
 * server-side; the body can add only a new-enrollment material bundle.
 */
export async function handleWalletRecoveryGoogleEmailOtpFinalize(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(
    ctx.routeDefinitions,
    RECOVERY_GOOGLE_EMAIL_OTP_FINALIZE_ROUTE_ID,
  );
  if (!route) {
    throw new Error(`Missing route definition for ${RECOVERY_GOOGLE_EMAIL_OTP_FINALIZE_ROUTE_ID}`);
  }
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  let request: WalletRecoveryGoogleEmailOtpRouteFinalizationRequest;
  try {
    request = parseWalletRecoveryGoogleEmailOtpFinalizeRequest(await readJson(ctx.request));
  } catch {
    return walletRecoveryRequestError();
  }

  const finalizer = ctx.service.passkeyCustody.finalizeGoogleEmailOtpRecovery;
  if (!finalizer) {
    return toFetchRouteResponse({
      status: 503,
      body: {
        ok: false,
        code: 'not_configured',
        message: 'Google Email OTP recovery is not configured',
      },
    });
  }

  try {
    const result = await finalizer(request);
    switch (result.kind) {
      case 'promoted':
        return toFetchRouteResponse({
          status: 200,
          body: {
            ok: true,
            projection: result.projection,
          },
        });
      case 'conflict':
        return toFetchRouteResponse({
          status: 409,
          body: { ok: false, code: 'recovery_conflict', message: 'wallet recovery conflicted' },
        });
      case 'refused':
      case 'envelope_rejected':
      case 'enrollment_rejected':
        return toFetchRouteResponse({
          status: 400,
          body: { ok: false, code: 'recovery_rejected', message: 'wallet recovery was rejected' },
        });
    }
  } catch {
    return walletRecoveryInternalError();
  }
}

type WalletRecoveryOperationRequest = {
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly reservationId: RecoveryCodeReservationId;
};

type WalletRecoveryGoogleVerifyRequest = WalletRecoveryOperationRequest & {
  readonly idToken: string;
};

type WalletRecoveryEmailOtpVerifyRequest = WalletRecoveryOperationRequest & {
  readonly challengeId: EmailOtpChallengeId;
  readonly otpCode: string;
};

type WalletRecoveryEmailOtpReleaseRequest = WalletRecoveryOperationRequest & {
  readonly workerEphemeralPublicKey65B64u: string;
};

function parseWalletRecoveryOperationRequest(
  body: Record<string, unknown> | null,
  fields: readonly string[],
  label: string,
): WalletRecoveryOperationRequest {
  if (!body) throw new Error(`${label} body is required`);
  requireExactObjectFields(body, fields, label);
  return {
    recoveryOperationId: parseRequiredAuthorizationValue(
      parseWalletRecoveryOperationId(body.recoveryOperationId),
    ),
    reservationId: parseRecoveryCodeReservationId(body.reservationId),
  };
}

function parseWalletRecoveryGoogleVerifyRequest(
  body: Record<string, unknown> | null,
): WalletRecoveryGoogleVerifyRequest {
  return {
    ...parseWalletRecoveryOperationRequest(
      body,
      ['recoveryOperationId', 'reservationId', 'idToken'],
      'wallet recovery Google verification',
    ),
    idToken: parseRequiredString(body?.idToken, 'idToken'),
  };
}

function parseWalletRecoveryEmailOtpVerifyRequest(
  body: Record<string, unknown> | null,
): WalletRecoveryEmailOtpVerifyRequest {
  const operation = parseWalletRecoveryOperationRequest(
    body,
    ['recoveryOperationId', 'reservationId', 'challengeId', 'otpCode'],
    'wallet recovery Email OTP verification',
  );
  return {
    ...operation,
    challengeId: parseRequiredAuthorizationValue(parseEmailOtpChallengeId(body?.challengeId)),
    otpCode: parseRequiredString(body?.otpCode, 'otpCode'),
  };
}

function parseWalletRecoveryEmailOtpReleaseRequest(
  body: Record<string, unknown> | null,
): WalletRecoveryEmailOtpReleaseRequest {
  return {
    ...parseWalletRecoveryOperationRequest(
      body,
      ['recoveryOperationId', 'reservationId', 'workerEphemeralPublicKey65B64u'],
      'wallet recovery Email OTP factor release',
    ),
    workerEphemeralPublicKey65B64u: parseRequiredString(
      body?.workerEphemeralPublicKey65B64u,
      'workerEphemeralPublicKey65B64u',
    ),
  };
}

function parseWalletRecoveryGoogleEmailOtpFinalizeRequest(
  value: unknown,
): WalletRecoveryGoogleEmailOtpRouteFinalizationRequest {
  if (!isObject(value)) {
    throw new Error('wallet recovery Google Email OTP finalization body must be an object');
  }
  const recoveryOperationId = parseWalletRecoveryOperationId(value.recoveryOperationId);
  if (!recoveryOperationId.ok) {
    throw new Error('wallet recovery Google Email OTP finalization operation is invalid');
  }
  const reservationId = parseRecoveryCodeReservationId(value.reservationId);
  const replacementEnvelope = parsePasskeyCustodyEnvelopeRecord(
    value.replacementEnvelope,
    'walletRecoveryGoogleEmailOtpFinalize.replacementEnvelope',
  );
  if (value.kind === 'replay') {
    requireExactObjectFields(
      value,
      ['kind', 'recoveryOperationId', 'reservationId', 'replacementEnvelope'],
      'wallet recovery Google Email OTP replay',
    );
    return {
      kind: 'replay',
      recoveryOperationId: recoveryOperationId.value,
      reservationId,
      replacementEnvelope,
    };
  }
  if (value.kind !== 'finalize') {
    throw new Error('wallet recovery Google Email OTP finalization kind is invalid');
  }
  requireExactObjectFields(
    value,
    [
      'kind',
      'recoveryOperationId',
      'reservationId',
      'replacementEnvelope',
      'ecdsaMaterialPossessionProofs',
      ...(value.emailOtpEnrollment === undefined ? [] : ['emailOtpEnrollment']),
    ],
    'wallet recovery Google Email OTP finalization',
  );
  const emailOtpEnrollment =
    value.emailOtpEnrollment === undefined
      ? null
      : parseWalletRecoveryGoogleEmailOtpCreateEnrollment(value.emailOtpEnrollment);
  return {
    kind: 'finalize',
    recoveryOperationId: recoveryOperationId.value,
    reservationId,
    replacementEnvelope,
    ecdsaMaterialPossessionProofs: parseEcdsaMaterialPossessionProofs(
      value.ecdsaMaterialPossessionProofs,
    ),
    emailOtpEnrollment,
  };
}

function parseWalletRecoveryGoogleEmailOtpCreateEnrollment(
  value: unknown,
): NonNullable<
  Extract<
    WalletRecoveryGoogleEmailOtpRouteFinalizationRequest,
    { readonly kind: 'finalize' }
  >['emailOtpEnrollment']
> {
  if (!isObject(value)) {
    throw new Error('new recovery Email enrollment is invalid');
  }
  requireExactObjectFields(value, ['kind', 'material'], 'new recovery Email enrollment');
  if (value.kind !== 'create' || !isObject(value.material)) {
    throw new Error('new recovery Email enrollment is invalid');
  }
  const material = value.material;
  requireExactObjectFields(
    material,
    [
      'enrollmentSealKeyVersion',
      'clientUnlockPublicKeyB64u',
      'unlockKeyVersion',
      'serverSealedFactorCiphertextB64u',
    ],
    'new recovery Email enrollment material',
  );
  const normalized: EmailOtpEnrollmentMaterialBoundaryInput = {
    enrollmentSealKeyVersion: parseRequiredString(
      material.enrollmentSealKeyVersion,
      'enrollmentSealKeyVersion',
    ),
    clientUnlockPublicKeyB64u: parseRequiredString(
      material.clientUnlockPublicKeyB64u,
      'clientUnlockPublicKeyB64u',
    ),
    unlockKeyVersion: parseRequiredString(material.unlockKeyVersion, 'unlockKeyVersion'),
    serverSealedFactorCiphertextB64u: parseRequiredString(
      material.serverSealedFactorCiphertextB64u,
      'serverSealedFactorCiphertextB64u',
    ),
  };
  return { kind: 'create', material: normalized };
}

function walletRecoveryRequestError(): Response {
  return toFetchRouteResponse({
    status: 400,
    body: {
      ok: false,
      code: 'invalid_body',
      message: 'wallet recovery request is invalid',
    },
  });
}

function walletRecoveryInternalError(): Response {
  return toFetchRouteResponse({
    status: 500,
    body: {
      ok: false,
      code: 'internal',
      message: 'wallet recovery could not continue',
    },
  });
}

function walletRecoveryGoogleFailureResponse(result: {
  readonly ok: false;
  readonly code: string;
}): Response {
  return toFetchRouteResponse({
    status: walletRecoveryGoogleStatusCode(result.code),
    body: {
      ok: false,
      code: result.code,
      message: 'wallet recovery could not continue',
    },
  });
}

function walletRecoveryGoogleStatusCode(code: string): number {
  if (code === 'internal') return 500;
  if (code === 'not_configured') return 503;
  if (code === 'recovery_conflict') return 409;
  if (code === 'rate_limited' || code === 'otp_locked_out' || code === 'otp_attempts_exhausted') {
    return 429;
  }
  if (
    code === 'recovery_attempt_unavailable' ||
    code === 'provider_identity_mismatch' ||
    code === 'challenge_expired_or_invalid' ||
    code === 'invalid_otp'
  ) {
    return 401;
  }
  return emailOtpStatusCode(code);
}

function refusedSpend() {
  return {
    status: 401,
    body: {
      ok: false,
      code: 'recovery_code_rejected',
      message: 'that recovery code cannot be used',
    },
  };
}

function parseWireRequest(
  body: Record<string, unknown> | null,
  originHeader: string | null,
): PasskeyCustodyEnvelopeRetrievalWireRequest | null {
  if (!body || typeof body !== 'object') return null;

  const challengeId = trimmed(body.challengeId);
  const locator = parseEnvelopeRetrievalLocator(body.locator);
  const webauthnAuthentication = parseWebAuthnAuthenticationCredential(body.webauthnAuthentication);
  if (!challengeId || !locator || !webauthnAuthentication) return null;

  /* Shape-checked here, content-checked below. This only establishes that an
     assertion was sent at all — whether it verifies is the retrieval's
     decision, and a transport that judged it would be a second gate. */
  /* The header, with no body fallback (frozen 2026-08-09). The sibling
     WebAuthn service takes `expected_origin` from its caller because it is
     called by an app server; on a browser-reachable route a value the
     requester supplies is not evidence of anything — it would let a caller
     name the origin its own assertion is checked against.

     A request with no Origin header is refused rather than read from the
     body: browsers set it on cross-origin POSTs, so its absence means the
     caller is not the browser this route exists for. */
  const expectedOrigin = trimmed(originHeader);
  if (!expectedOrigin) return null;

  return {
    challengeId,
    expectedOrigin,
    locator,
    webauthnAuthentication,
  };
}

function parseEnvelopeRetrievalLocator(
  value: unknown,
): PasskeyCustodyEnvelopeRetrievalWireRequest['locator'] | null {
  if (!isObject(value) || !isObject(value.factor)) return null;
  try {
    requireExactObjectFields(value, ['walletId', 'factor'], 'custody locator');
    requireExactObjectFields(
      value.factor,
      ['kind', 'rpId', 'credentialIdB64u'],
      'custody locator.factor',
    );
  } catch {
    return null;
  }
  const walletId = parseWalletId(value.walletId);
  const rpId = parseWebAuthnRpId(value.factor.rpId);
  const credentialIdB64u = parseWebAuthnCredentialIdB64u(value.factor.credentialIdB64u);
  if (!walletId.ok || !rpId.ok || !credentialIdB64u.ok) return null;
  if (value.factor.kind !== 'passkey') return null;
  return {
    walletId: walletId.value,
    factor: {
      kind: 'passkey',
      rpId: rpId.value,
      credentialIdB64u: credentialIdB64u.value,
    },
  };
}

function trimmed(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

async function readJsonObject(request: Request): Promise<Record<string, unknown> | null> {
  const value = await readJson(request);
  return isObject(value) ? value : null;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseRecoveryCodeLocatorRecords(
  values: readonly Record<string, unknown>[],
  walletId: WalletId,
  recoveryKeyIds: readonly ReturnType<typeof parseDerivedWalletRecoveryKeyId>[],
): readonly WalletRecoveryCodeLocatorRecord[] {
  if (values.length !== recoveryKeyIds.length) {
    throw new Error('recovery code locators do not match the recovery wraps');
  }
  const locators = values.map((value, index) => {
    requireExactObjectFields(value, ['locatorB64u', 'recoveryKeyId'], 'recovery code locator');
    const locatorB64u = parseRecoveryCodeLocatorV1(value.locatorB64u);
    const recoveryKeyId = parseDerivedWalletRecoveryKeyId(value.recoveryKeyId);
    const expectedRecoveryKeyId = recoveryKeyIds[index];
    if (!expectedRecoveryKeyId || String(recoveryKeyId) !== String(expectedRecoveryKeyId)) {
      throw new Error('recovery code locator does not match its recovery wrap');
    }
    return { locatorB64u, walletId, recoveryKeyId };
  });
  const uniqueLocators = new Set(locators.map((locator) => String(locator.locatorB64u)));
  if (uniqueLocators.size !== locators.length) {
    throw new Error('recovery code locators must be unique');
  }
  return locators;
}

/**
 * Installing the credential a recovery enrolled.
 *
 * The envelope arrives sealed, but its complete wire shape is parsed here.
 * The server has no seed and cannot open the ciphertext. Exact key coverage
 * comes from its signer registry and durable activation receipts.
 */
export async function handleWalletRecoveryFinalize(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_FINALIZE_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_FINALIZE_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  let requestBody: WalletRecoveryFinalizeBody;
  try {
    requestBody = parseWalletRecoveryFinalizeBody(await readJson(ctx.request));
  } catch {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: 'wallet recovery finalization is invalid',
      },
    });
  }

  let serviceRequest: WalletRecoveryPasskeyRouteFinalizationRequest;
  if (requestBody.kind === 'finalize') {
    const expectedOrigin = trimmed(ctx.request.headers.get('origin'));
    if (!expectedOrigin) {
      return toFetchRouteResponse({
        status: 400,
        body: {
          ok: false,
          code: 'invalid_origin',
          message: 'wallet recovery finalization requires the request Origin header',
        },
      });
    }
    serviceRequest = {
      kind: 'finalize',
      walletId: requestBody.walletId,
      reservationId: requestBody.reservationId,
      recoveryOperationId: requestBody.recoveryOperationId,
      targetDeviceId: requestBody.targetDeviceId,
      targetAuthorityId: requestBody.targetAuthorityId,
      targetWalletAuthMethodId: requestBody.targetWalletAuthMethodId,
      challengeId: requestBody.challengeId,
      replacementId: requestBody.replacementId,
      webauthnRegistration: requestBody.webauthnRegistration,
      expectedOrigin,
      replacementEnvelope: requestBody.replacementEnvelope,
      ecdsaMaterialPossessionProofs: requestBody.ecdsaMaterialPossessionProofs,
    };
  } else {
    serviceRequest = {
      kind: 'replay',
      walletId: requestBody.walletId,
      reservationId: requestBody.reservationId,
      recoveryOperationId: requestBody.recoveryOperationId,
      targetDeviceId: requestBody.targetDeviceId,
      targetAuthorityId: requestBody.targetAuthorityId,
      targetWalletAuthMethodId: requestBody.targetWalletAuthMethodId,
      replacementId: requestBody.replacementId,
      replacementEnvelope: requestBody.replacementEnvelope,
    };
  }

  const result = await ctx.service.passkeyCustody.finalizeRecovery(serviceRequest);

  switch (result.kind) {
    case 'promoted':
      return toFetchRouteResponse({
        status: 200,
        body: {
          ok: true,
          projection: result.projection,
        },
      });
    case 'conflict':
      return toFetchRouteResponse({
        status: 409,
        body: { ok: false, code: 'recovery_conflict', message: 'wallet recovery conflicted' },
      });
    case 'refused':
    case 'envelope_rejected':
    case 'registration_rejected':
      return toFetchRouteResponse({
        status: 400,
        body: { ok: false, code: 'recovery_rejected', message: 'wallet recovery was rejected' },
      });
  }
}
type WalletRecoveryFinalizeBody =
  | Omit<
      Extract<WalletRecoveryPasskeyRouteFinalizationRequest, { readonly kind: 'finalize' }>,
      'expectedOrigin'
    >
  | Extract<WalletRecoveryPasskeyRouteFinalizationRequest, { readonly kind: 'replay' }>;

function parseWalletRecoveryFinalizeBody(value: unknown): WalletRecoveryFinalizeBody {
  if (!isObject(value)) throw new Error('wallet recovery finalization body must be an object');
  const walletId = parseWalletId(value.walletId);
  const recoveryOperationId = parseWalletRecoveryOperationId(value.recoveryOperationId);
  const targetDeviceId = parseDeviceId(value.targetDeviceId);
  const targetAuthorityId = parseWalletAuthorityId(value.targetAuthorityId);
  const targetWalletAuthMethodId = parseWalletAuthMethodId(value.targetWalletAuthMethodId);
  if (
    !walletId.ok ||
    !recoveryOperationId.ok ||
    !targetDeviceId.ok ||
    !targetAuthorityId.ok ||
    !targetWalletAuthMethodId.ok
  ) {
    throw new Error('wallet recovery finalization identity is invalid');
  }
  const identity = {
    walletId: walletId.value,
    reservationId: parseRecoveryCodeReservationId(value.reservationId),
    recoveryOperationId: recoveryOperationId.value,
    targetDeviceId: targetDeviceId.value,
    targetAuthorityId: targetAuthorityId.value,
    targetWalletAuthMethodId: targetWalletAuthMethodId.value,
    replacementId: parseRequiredString(value.replacementId, 'replacementId'),
    replacementEnvelope: parsePasskeyCustodyEnvelopeRecord(
      value.replacementEnvelope,
      'walletRecoveryFinalize.replacementEnvelope',
    ),
  };
  if (value.kind === 'replay') {
    requireExactObjectFields(
      value,
      [
        'kind',
        'walletId',
        'reservationId',
        'recoveryOperationId',
        'targetDeviceId',
        'targetAuthorityId',
        'targetWalletAuthMethodId',
        'replacementId',
        'replacementEnvelope',
      ],
      'wallet recovery replay',
    );
    return { kind: 'replay', ...identity };
  }
  if (value.kind !== 'finalize') {
    throw new Error('wallet recovery finalization kind is invalid');
  }
  requireExactObjectFields(
    value,
    [
      'kind',
      'walletId',
      'reservationId',
      'recoveryOperationId',
      'targetDeviceId',
      'targetAuthorityId',
      'targetWalletAuthMethodId',
      'challengeId',
      'replacementId',
      'webauthnRegistration',
      'replacementEnvelope',
      'ecdsaMaterialPossessionProofs',
    ],
    'wallet recovery finalization',
  );
  if (!isObject(value.webauthnRegistration)) {
    throw new Error('wallet recovery finalization registration is invalid');
  }
  return {
    kind: 'finalize',
    ...identity,
    challengeId: parseRequiredString(value.challengeId, 'challengeId'),
    webauthnRegistration: value.webauthnRegistration,
    ecdsaMaterialPossessionProofs: parseEcdsaMaterialPossessionProofs(
      value.ecdsaMaterialPossessionProofs,
    ),
  };
}

function parseEcdsaMaterialPossessionProofs(value: unknown): readonly {
  readonly keySetId: string;
  readonly proof: WalletRecoveryEcdsaPossessionProofV1;
}[] {
  if (!Array.isArray(value)) {
    throw new Error('wallet recovery finalization ECDSA proofs must be an array');
  }
  const seen = new Set<string>();
  return value.map((item, index) => {
    if (!isObject(item)) {
      throw new Error(`wallet recovery finalization ECDSA proof ${index} is invalid`);
    }
    requireExactObjectFields(item, ['keySetId', 'proof'], `ECDSA proof ${index}`);
    const keySetId = trimmed(item.keySetId);
    if (!/^evm_family_ecdsa:\S+$/.test(keySetId)) {
      throw new Error(`wallet recovery finalization ECDSA proof ${index} is invalid`);
    }
    if (seen.has(keySetId)) {
      throw new Error(`wallet recovery finalization ECDSA proof ${index} is duplicated`);
    }
    seen.add(keySetId);
    return {
      keySetId,
      proof: parseWalletRecoveryEcdsaPossessionProofV1(item.proof),
    };
  });
}
function authorizedOperationReplay(operation: AuthorizedOperation): Response {
  if (operation.lifecycle !== 'completed') {
    return toFetchRouteResponse({
      status: 409,
      body: {
        ok: false,
        code: 'recovery_in_progress',
        message: 'wallet recovery is still in progress',
      },
    });
  }
  return new Response(operation.response.bodyText, {
    status: operation.response.status,
    headers: { 'content-type': operation.response.contentType },
  });
}

export async function handleWalletRecoveryBackupAcknowledge(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_ACK_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_ACK_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const body = await readJsonObject(ctx.request);
  let walletId = '';
  try {
    if (!body) throw new Error('acknowledgement body is required');
    requireExactObjectFields(body, ['walletId'], 'recovery backup acknowledgement');
    walletId = parseRequiredString(body.walletId, 'walletId');
  } catch {
    return toFetchRouteResponse({
      status: 400,
      body: { ok: false, code: 'invalid_request', message: 'an acknowledgement needs a wallet' },
    });
  }

  const result = await ctx.service.passkeyCustody.acknowledgeRecoveryBackup({ walletId });
  if (result.kind === 'no_recovery_set') {
    return toFetchRouteResponse({
      status: 404,
      body: {
        ok: false,
        code: 'no_recovery_set',
        message: 'this wallet has no issued recovery codes to acknowledge',
      },
    });
  }
  return toFetchRouteResponse({
    status: 200,
    body: { ok: true, issuedAtMs: result.issuedAtMs },
  });
}

/**
 * Rotating a wallet's recovery codes.
 *
 * The wraps pass through as opaque records — the server cannot check that
 * they wrap the right KEK, because it has neither. What it does check is the
 * set's shape, and it does so before writing: a set that reaches the store
 * with the wrong number of wraps leaves a wallet holding fewer codes than its
 * owner wrote down, and nothing surfaces that until someone counts.
 */
export async function handleWalletRecoveryRotate(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_ROTATE_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_ROTATE_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const body = await readJsonObject(ctx.request);
  const walletId = trimmed(body?.walletId);
  const expectedStoreVersion = trimmed(body?.expectedStoreVersion);
  const manifestKekWraps = Array.isArray(body?.manifestKekWraps)
    ? body.manifestKekWraps.filter(isObject)
    : [];
  const entries = Array.isArray(body?.entries) ? body.entries.filter(isObject) : [];
  const rawRecoveryCodeLocators = Array.isArray(body?.recoveryCodeLocators)
    ? body.recoveryCodeLocators
    : [];
  const recoveryCodeLocators = rawRecoveryCodeLocators.filter(isObject);
  if (
    !walletId ||
    !expectedStoreVersion ||
    manifestKekWraps.length === 0 ||
    entries.length !== 1 ||
    recoveryCodeLocators.length !== rawRecoveryCodeLocators.length ||
    recoveryCodeLocators.length !== manifestKekWraps.length
  ) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: 'a rotation needs a wallet and its complete replacement recovery set',
      },
    });
  }
  const parsedWalletId = parseWalletId(walletId);
  if (!parsedWalletId.ok) {
    return toFetchRouteResponse({
      status: 400,
      body: { ok: false, code: 'invalid_request', message: 'wallet id is invalid' },
    });
  }

  let replacement: ReturnType<typeof parseWalletRecoverySetRotationWireV1>;
  let parsedRecoveryCodeLocators: readonly WalletRecoveryCodeLocatorRecord[];
  try {
    replacement = parseWalletRecoverySetRotationWireV1(
      { walletId, manifestKekWraps, entries },
      { expectedWalletId: parsedWalletId.value },
    );
    parsedRecoveryCodeLocators = parseRecoveryCodeLocatorRecords(
      recoveryCodeLocators,
      parsedWalletId.value,
      replacement.manifestKekWraps.map((wrap) => wrap.recoveryKeyId),
    );
  } catch (error: unknown) {
    return toFetchRouteResponse({
      status: 400,
      body: {
        ok: false,
        code: 'invalid_request',
        message: error instanceof Error ? error.message : 'replacement recovery set is invalid',
      },
    });
  }

  const authorized = await authorizeWalletCustodyOperation({
    ctx,
    walletId,
    operation: 'recovery_rotate',
    payload: {
      walletId,
      expectedStoreVersion,
      manifestKekWraps,
      entries,
      recoveryCodeLocators,
    },
    factorProof: body?.factorProof,
  });
  if (!authorized.ok) return authorized.response;

  const result = await ctx.service.passkeyCustody.rotateRecoveryCodes({
    walletId,
    replacement,
    recoveryCodeLocators: parsedRecoveryCodeLocators,
    expectedStoreVersion,
  });

  switch (result.kind) {
    case 'rotated':
      return await completeWalletCustodyOperation(ctx, authorized.operation, 200, {
        ok: true,
        issuedAtMs: result.issuedAtMs,
        storeVersion: result.storeVersion,
      });
    case 'no_recovery_set':
      return await completeWalletCustodyOperation(
        ctx,
        authorized.operation,
        404,
        { ok: false, code: 'no_recovery_set', message: 'this wallet has no codes to rotate' },
        'failed_before_side_effect',
      );
    case 'conflict':
      return await completeWalletCustodyOperation(
        ctx,
        authorized.operation,
        409,
        {
          ok: false,
          code: 'recovery_set_conflict',
          message: 'the recovery set changed during this rotation; try again',
        },
        'failed_before_side_effect',
      );
    case 'rejected':
      return await completeWalletCustodyOperation(
        ctx,
        authorized.operation,
        400,
        { ok: false, code: 'rotation_rejected', message: result.reason },
        'failed_before_side_effect',
      );
  }
}

export async function handleWalletRecoveryRead(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_READ_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_READ_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;
  const body = await readJsonObject(ctx.request);
  const walletId = trimmed(body?.walletId);
  if (!walletId) {
    return toFetchRouteResponse({
      status: 400,
      body: { ok: false, code: 'invalid_request', message: 'a read needs a wallet' },
    });
  }
  const authorized = await authorizeWalletCustodyOperation({
    ctx,
    walletId,
    operation: 'recovery_read',
    payload: { walletId },
    factorProof: body?.factorProof,
  });
  if (!authorized.ok) return authorized.response;
  const result = await ctx.service.passkeyCustody.readRecoverySet({ walletId });
  if (result.kind === 'no_recovery_set') {
    return await completeWalletCustodyOperation(
      ctx,
      authorized.operation,
      404,
      { ok: false, code: 'no_recovery_set', message: 'this wallet has no issued recovery codes' },
      'failed_before_side_effect',
    );
  }
  return await completeWalletCustodyOperation(ctx, authorized.operation, 200, {
    ok: true,
    recoverySet: result.record,
    storeVersion: result.storeVersion,
  });
}

/**
 * Reporting recovery status to the wallet's owner.
 *
 * The wallet comes from the path. Origin binding keeps this count endpoint
 * scoped to browser callers without exposing recovery identifiers.
 *
 * Counts only, never identifiers. Which codes remain is not something even
 * the owner's browser needs, and a list would be one leak away from being
 * useful to someone else.
 */
export async function handleWalletRecoveryStatus(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  const route = findRouteDefinitionById(ctx.routeDefinitions, RECOVERY_STATUS_ROUTE_ID);
  if (!route) throw new Error(`Missing route definition for ${RECOVERY_STATUS_ROUTE_ID}`);
  if (!matchesRouteDefinitionRequest(route, ctx.method, ctx.pathname)) return null;

  const walletId = walletIdFromPath(route.path, ctx.pathname);
  if (!walletId) {
    return toFetchRouteResponse({
      status: 400,
      body: { ok: false, code: 'invalid_request', message: 'status needs a wallet' },
    });
  }
  const origin = trimmed(ctx.request.headers.get('origin'));
  try {
    parseSessionOrigin(origin);
  } catch {
    return toFetchRouteResponse({
      status: 400,
      body: { ok: false, code: 'invalid_origin', message: 'request Origin is invalid' },
    });
  }

  const result = await ctx.service.passkeyCustody.readRecoveryStatus({ walletId });
  if (result.kind === 'no_recovery_set') {
    return toFetchRouteResponse({
      status: 404,
      body: { ok: false, code: 'no_recovery_set', message: 'this wallet has no recovery codes' },
    });
  }
  return toFetchRouteResponse({
    status: 200,
    body: {
      ok: true,
      activeCodeCount: result.activeCodeCount,
      totalCodeCount: result.totalCodeCount,
      issuedAtMs: result.issuedAtMs,
      storeVersion: result.storeVersion,
      backupOutstanding: result.backupOutstanding,
    },
  });
}

function walletIdFromPath(routePath: string, pathname: string): string {
  const routeSegments = routePath.split('/').filter(Boolean);
  const pathSegments = pathname.split('/').filter(Boolean);
  const index = routeSegments.indexOf(':walletId');
  if (index < 0) return '';
  const segment = pathSegments[index];
  return segment ? decodeURIComponent(segment).trim() : '';
}
