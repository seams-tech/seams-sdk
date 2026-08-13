import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';
import { ROUTER_AB_ED25519_WALLET_SESSION_PATH } from '@shared/utils/signingSessionSeal';
import { type Ed25519SessionPolicy, type ThresholdRuntimePolicyScope } from '../sessionPolicy';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import {
  getPrfFirstB64uFromCredential,
  redactCredentialExtensionOutputs,
} from '../crypto/webauthn';
import {
  buildWebAuthnPrfFirstSecretSource,
  type RequiredPrfAuthenticatorSuccess,
  type WebAuthnPrfFirstSecretSource,
} from '@/core/platform/types';
import { toRpId } from '../../session/identity/evmFamilyEcdsaIdentity';
import type {
  RouterAbEd25519NormalSigningCredential,
  RouterAbNormalSigningPrepareRequestV2Wire,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
} from '@/core/rpcClients/relayer/relayerHttp';
import type { PasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  parseThresholdEd25519SessionId,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';

const ED25519_WALLET_SESSION_MINT_TIMEOUT_MS = 15_000;

function abortEd25519WalletSessionMint(controller: AbortController): void {
  controller.abort('timeout');
}

export type ThresholdEd25519WebAuthnPrfSecretSource = {
  kind: 'webauthn_prf_first_credential';
  credential: WebAuthnAuthenticationCredential;
  secretSource: WebAuthnPrfFirstSecretSource;
  prfFirstB64u?: never;
};

export type Ed25519WalletSessionMintAuthorization =
  | {
      kind: 'app_session_jwt';
      appSessionJwt: string;
      localSecretSource: ThresholdEd25519WebAuthnPrfSecretSource;
      priorWalletSessionJwt?: never;
      thresholdEcdsaSessionJwt?: never;
      policySecretSource?: never;
      useAppSessionCookie?: never;
      webauthnAuthentication?: never;
      localPrfCredential?: never;
      localPrfFirstB64u?: never;
    }
  | {
      kind: 'app_session_cookie';
      localSecretSource: ThresholdEd25519WebAuthnPrfSecretSource;
      appSessionJwt?: never;
      priorWalletSessionJwt?: never;
      thresholdEcdsaSessionJwt?: never;
      policySecretSource?: never;
      useAppSessionCookie?: never;
      webauthnAuthentication?: never;
      localPrfCredential?: never;
      localPrfFirstB64u?: never;
    }
  | {
      kind: 'threshold_session_policy_webauthn';
      policySecretSource: ThresholdEd25519WebAuthnPrfSecretSource;
      appSessionJwt?: never;
      priorWalletSessionJwt?: never;
      thresholdEcdsaSessionJwt?: never;
      localSecretSource?: never;
      useAppSessionCookie?: never;
      localPrfCredential?: never;
      webauthnAuthentication?: never;
      localPrfFirstB64u?: never;
    };

function requireNonEmptyEd25519SecretSourceString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`[threshold-ed25519] ${field} is required`);
  }
  return normalized;
}

function buildRequiredPrfAuthenticatorSuccess(args: {
  credential: WebAuthnAuthenticationCredential;
  rpId: string;
}): RequiredPrfAuthenticatorSuccess {
  const prfFirstB64u = requireNonEmptyEd25519SecretSourceString(
    getPrfFirstB64uFromCredential(args.credential),
    'prfFirstB64u',
  );
  return {
    ok: true,
    operation: 'get_passkey',
    requirePrfFirst: true,
    credential: args.credential,
    credentialIdB64u: requireNonEmptyEd25519SecretSourceString(
      args.credential.rawId || args.credential.id,
      'credentialIdB64u',
    ),
    rawIdB64u: String(args.credential.rawId || '').trim(),
    rpId: toRpId(args.rpId),
    prf: {
      kind: 'required',
      prfFirstB64u,
    },
  };
}

export function buildThresholdEd25519WebAuthnPrfSecretSource(args: {
  credential: WebAuthnAuthenticationCredential;
  rpId: string;
}): ThresholdEd25519WebAuthnPrfSecretSource {
  return {
    kind: 'webauthn_prf_first_credential',
    credential: args.credential,
    secretSource: buildWebAuthnPrfFirstSecretSource(buildRequiredPrfAuthenticatorSuccess(args)),
  };
}

export function localPrfFirstForEd25519WalletSessionMintAuthorization(
  auth: Ed25519WalletSessionMintAuthorization,
): string {
  switch (auth.kind) {
    case 'app_session_jwt':
    case 'app_session_cookie':
      return auth.localSecretSource.secretSource.prfFirstB64u;
    case 'threshold_session_policy_webauthn':
      return auth.policySecretSource.secretSource.prfFirstB64u;
    default: {
      const exhaustive: never = auth;
      return exhaustive;
    }
  }
}

/**
 * Ed25519 Wallet Session mint.
 *
 * `threshold_session_policy_webauthn` sends a WebAuthn assertion whose challenge
 * is the `sessionPolicyDigest32`. App-session branches authorize the route with
 * the app session; the local PRF credential stays in wallet origin.
 *
 * Notes:
 * - PRF outputs must never be sent to the Router API; they should be used only in wallet origin.
 */
export async function mintEd25519WalletSession(args: {
  relayerUrl: string;
  sessionKind: 'jwt';
  relayerKeyId: string;
  sessionPolicy: Ed25519SessionPolicy;
  auth: Ed25519WalletSessionMintAuthorization;
  projectEnvironmentId?: string;
  publishableKey?: string;
}): Promise<{
  ok: boolean;
  thresholdSessionId?: ThresholdEd25519SessionId;
  walletSessionId?: WalletSessionId;
  quotaId?: MpcWalletSigningQuotaId;
  expiresAtMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  jwt?: string;
  code?: string;
  message?: string;
}> {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(args.relayerUrl));
  if (!relayerUrl) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing relayerUrl for Wallet Session mint',
    };
  }

  if (typeof fetch !== 'function') {
    return {
      ok: false,
      code: 'unsupported',
      message: 'fetch is not available for Wallet Session mint',
    };
  }

  const webauthn_authentication =
    args.auth.kind === 'threshold_session_policy_webauthn'
      ? redactCredentialExtensionOutputs(args.auth.policySecretSource.credential)
      : undefined;

  type Ed25519WalletSessionMintResponseBody = Partial<{
    ok: boolean;
    thresholdSessionId: string;
    walletSessionId: string;
    quotaId: string;
    expiresAt: string;
    remainingUses: number;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    jwt: string;
    code: string;
    message: string;
  }>;

  const controller = new AbortController();
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  try {
    const url = `${relayerUrl}${ROUTER_AB_ED25519_WALLET_SESSION_PATH}`;
    const appSessionJwt =
      args.auth.kind === 'app_session_jwt'
        ? String(args.auth.appSessionJwt || '').trim() || undefined
        : undefined;
    const useAppSessionCookie = args.auth.kind === 'app_session_cookie';
    const publishableKey = String(args.publishableKey || '').trim() || undefined;
    const bearerToken = appSessionJwt || publishableKey;
    const usesPublishableKeyBearer = Boolean(publishableKey && !appSessionJwt);
    const projectEnvironmentId = usesPublishableKeyBearer
      ? String(args.projectEnvironmentId || '').trim() || undefined
      : undefined;
    timeoutId = setTimeout(
      abortEd25519WalletSessionMint,
      ED25519_WALLET_SESSION_MINT_TIMEOUT_MS,
      controller,
    );
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(bearerToken ? { Authorization: `Bearer ${bearerToken}` } : {}),
      },
      credentials: useAppSessionCookie ? 'include' : 'omit',
      signal: controller.signal,
      body: JSON.stringify({
        sessionKind: args.sessionKind,
        relayerKeyId: args.relayerKeyId,
        sessionPolicy: args.sessionPolicy,
        ...(projectEnvironmentId ? { projectEnvironmentId } : {}),
        ...(webauthn_authentication ? { webauthn_authentication } : {}),
      }),
    });

    let data: Ed25519WalletSessionMintResponseBody;
    try {
      data = (await response.json()) as Ed25519WalletSessionMintResponseBody;
    } catch (error: unknown) {
      if (controller.signal.aborted) throw error;
      data = {};
    }
    if (!response.ok) {
      return {
        ok: false,
        code: data.code || 'http_error',
        message: data.message || `HTTP ${response.status}`,
      };
    }

    const expiresAtMs = (() => {
      const raw = data.expiresAt ? Date.parse(data.expiresAt) : NaN;
      return Number.isFinite(raw) ? raw : undefined;
    })();

    const thresholdSessionId = data.thresholdSessionId
      ? parseThresholdEd25519SessionId(data.thresholdSessionId)
      : null;
    if (data.thresholdSessionId && !thresholdSessionId?.ok) {
      return {
        ok: false,
        code: 'invalid_response',
        message: 'Wallet Session mint returned an invalid thresholdSessionId',
      };
    }
    const walletSessionId = parseWalletSessionId(data.walletSessionId);
    const quotaId = parseMpcWalletSigningQuotaId(data.quotaId);
    if (!walletSessionId.ok || !quotaId.ok) {
      return {
        ok: false,
        code: 'invalid_response',
        message: 'Wallet Session mint returned invalid authorization identity',
      };
    }
    return {
      ok: data.ok === true,
      ...(thresholdSessionId?.ok ? { thresholdSessionId: thresholdSessionId.value } : {}),
      walletSessionId: walletSessionId.value,
      quotaId: quotaId.value,
      expiresAtMs,
      remainingUses: data.remainingUses,
      ...(data.runtimePolicyScope ? { runtimePolicyScope: data.runtimePolicyScope } : {}),
      jwt: data.jwt,
      ...(data.code ? { code: data.code } : {}),
      ...(data.message ? { message: data.message } : {}),
    };
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Failed to mint threshold session',
    );
    const timedOut = controller.signal.aborted;
    return {
      ok: false,
      code: timedOut ? 'timeout' : 'network_error',
      message: timedOut
        ? `Wallet Session mint timed out after ${ED25519_WALLET_SESSION_MINT_TIMEOUT_MS}ms`
        : msg,
    };
  } finally {
    if (timeoutId !== null) clearTimeout(timeoutId);
  }
}

export type Ed25519OperationStepUpProof =
  | {
      kind: 'passkey';
      authority: PasskeyWalletAuthAuthority;
      credential: WebAuthnAuthenticationCredential;
      challengeId?: never;
      otpCode?: never;
    }
  | {
      kind: 'email_otp';
      authorityRef: WalletAuthAuthorityRef;
      providerSubjectId: string;
      challengeId: string;
      otpCode: string;
      credential?: never;
      authority?: never;
    };

export type Ed25519OperationStepUpMaterialRecoveryRequest =
  | { kind: 'not_requested' }
  | {
      kind: 'email_otp_factor_release_v1';
      workerEphemeralPublicKey65B64u: string;
    };

export type Ed25519OperationStepUpMaterialRecoveryResponse =
  | { kind: 'not_requested' }
  | {
      kind: 'email_otp_factor_release_v1';
      challengeId: string;
      enrollmentId: string;
      enrollmentSealKeyVersion: string;
      serverEphemeralPublicKey65B64u: string;
      nonce12B64u: string;
      ciphertextB64u: string;
    };

type Ed25519EmailOtpOperationStepUpProof = Extract<
  Ed25519OperationStepUpProof,
  { kind: 'email_otp' }
>;
type Ed25519NoMaterialRecoveryRequest = Extract<
  Ed25519OperationStepUpMaterialRecoveryRequest,
  { kind: 'not_requested' }
>;
type Ed25519EmailOtpFactorReleaseRequest = Extract<
  Ed25519OperationStepUpMaterialRecoveryRequest,
  { kind: 'email_otp_factor_release_v1' }
>;

type Ed25519OperationStepUpAuthorizationRequestBase = {
  relayerUrl: string;
  normalSigningRequest: RouterAbNormalSigningPrepareRequestV2Wire;
  displayDigest: string;
  credential: Ed25519OperationStepUpCredential;
};

export type Ed25519OperationStepUpCredential = Exclude<
  RouterAbEd25519NormalSigningCredential,
  { kind: 'wallet_session_jwt' }
>;

export type Ed25519OperationStepUpAuthorizationRequest =
  Ed25519OperationStepUpAuthorizationRequestBase &
    (
      | {
          proof: Extract<Ed25519OperationStepUpProof, { kind: 'passkey' }>;
          materialRecovery: Ed25519NoMaterialRecoveryRequest;
        }
      | {
          proof: Ed25519EmailOtpOperationStepUpProof;
          materialRecovery:
            | Ed25519NoMaterialRecoveryRequest
            | Ed25519EmailOtpFactorReleaseRequest;
        }
    );

type Ed25519OperationStepUpProofWire =
  | {
      kind: 'passkey';
      authority: PasskeyWalletAuthAuthority;
      webauthn_authentication: WebAuthnAuthenticationCredential;
    }
  | {
      kind: 'email_otp';
      authority_ref: WalletAuthAuthorityRef;
      provider_subject_id: string;
      challenge_id: string;
      otp_code: string;
    };

function serializeEd25519OperationStepUpProof(
  proof: Ed25519OperationStepUpProof,
): Ed25519OperationStepUpProofWire {
  switch (proof.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        authority: proof.authority,
        webauthn_authentication: redactCredentialExtensionOutputs(proof.credential),
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        authority_ref: proof.authorityRef,
        provider_subject_id: requireNonEmptyEd25519SecretSourceString(
          proof.providerSubjectId,
          'providerSubjectId',
        ),
        challenge_id: requireNonEmptyEd25519SecretSourceString(proof.challengeId, 'challengeId'),
        otp_code: requireNonEmptyEd25519SecretSourceString(proof.otpCode, 'otpCode'),
      };
    default:
      proof satisfies never;
      throw new Error('[threshold-ed25519] unsupported operation step-up proof');
  }
}

export type IssuedEd25519OperationStepUpAuthorization = {
  kind: 'verified_step_up';
  authorization: { kind: 'operation_step_up'; evidence_set_digest: string };
  expiresAtMs: number;
  materialRecovery: Ed25519OperationStepUpMaterialRecoveryResponse;
};

function requireEd25519OperationStepUpResponseRecord(
  value: unknown,
  label: string,
): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`[threshold-ed25519] ${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactEd25519OperationStepUpResponseKeys(
  record: Record<string, unknown>,
  expectedKeys: readonly string[],
  label: string,
): void {
  const actual = Object.keys(record).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length) {
    throw new Error(`[threshold-ed25519] ${label} contains unexpected fields`);
  }
  for (let index = 0; index < actual.length; index += 1) {
    if (actual[index] !== expected[index]) {
      throw new Error(`[threshold-ed25519] ${label} contains unexpected fields`);
    }
  }
}

function requireNormalizedEd25519OperationStepUpString(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`[threshold-ed25519] ${field} must be a non-empty normalized string`);
  }
  return value;
}

function buildEd25519OperationStepUpMaterialRecoveryRequest(
  request: Ed25519OperationStepUpAuthorizationRequest,
): Ed25519OperationStepUpMaterialRecoveryRequest {
  switch (request.proof.kind) {
    case 'passkey':
      if (request.materialRecovery.kind !== 'not_requested') {
        throw new Error(
          '[threshold-ed25519] passkey operation step-up cannot request material recovery',
        );
      }
      return { kind: 'not_requested' };
    case 'email_otp':
      switch (request.materialRecovery.kind) {
        case 'not_requested':
          return { kind: 'not_requested' };
        case 'email_otp_factor_release_v1':
          return {
            kind: 'email_otp_factor_release_v1',
            workerEphemeralPublicKey65B64u: requireNormalizedEd25519OperationStepUpString(
              request.materialRecovery.workerEphemeralPublicKey65B64u,
              'workerEphemeralPublicKey65B64u',
            ),
          };
        default:
          request.materialRecovery satisfies never;
          throw new Error('[threshold-ed25519] unsupported material recovery request');
      }
    default:
      request.proof satisfies never;
      throw new Error('[threshold-ed25519] unsupported operation step-up proof');
  }
}

function parseEd25519OperationStepUpMaterialRecoveryResponse(args: {
  value: unknown;
  requested: Ed25519OperationStepUpMaterialRecoveryRequest;
}): Ed25519OperationStepUpMaterialRecoveryResponse {
  const response = requireEd25519OperationStepUpResponseRecord(
    args.value,
    'operation step-up material recovery',
  );
  switch (response.kind) {
    case 'not_requested': {
      requireExactEd25519OperationStepUpResponseKeys(
        response,
        ['kind'],
        'operation step-up material recovery',
      );
      if (args.requested.kind !== 'not_requested') {
        throw new Error(
          '[threshold-ed25519] operation step-up material recovery response does not match the request',
        );
      }
      return { kind: 'not_requested' };
    }
    case 'email_otp_factor_release_v1': {
      requireExactEd25519OperationStepUpResponseKeys(
        response,
        [
          'kind',
          'challengeId',
          'enrollmentId',
          'enrollmentSealKeyVersion',
          'serverEphemeralPublicKey65B64u',
          'nonce12B64u',
          'ciphertextB64u',
        ],
        'operation step-up material recovery',
      );
      if (args.requested.kind !== 'email_otp_factor_release_v1') {
        throw new Error(
          '[threshold-ed25519] operation step-up material recovery response does not match the request',
        );
      }
      return {
        kind: 'email_otp_factor_release_v1',
        challengeId: requireNormalizedEd25519OperationStepUpString(
          response.challengeId,
          'materialRecovery.challengeId',
        ),
        enrollmentId: requireNormalizedEd25519OperationStepUpString(
          response.enrollmentId,
          'materialRecovery.enrollmentId',
        ),
        enrollmentSealKeyVersion: requireNormalizedEd25519OperationStepUpString(
          response.enrollmentSealKeyVersion,
          'materialRecovery.enrollmentSealKeyVersion',
        ),
        serverEphemeralPublicKey65B64u: requireNormalizedEd25519OperationStepUpString(
          response.serverEphemeralPublicKey65B64u,
          'materialRecovery.serverEphemeralPublicKey65B64u',
        ),
        nonce12B64u: requireNormalizedEd25519OperationStepUpString(
          response.nonce12B64u,
          'materialRecovery.nonce12B64u',
        ),
        ciphertextB64u: requireNormalizedEd25519OperationStepUpString(
          response.ciphertextB64u,
          'materialRecovery.ciphertextB64u',
        ),
      };
    }
    default:
      throw new Error('[threshold-ed25519] operation step-up material recovery kind is invalid');
  }
}

function parseIssuedEd25519OperationStepUpAuthorization(args: {
  body: unknown;
  requestedMaterialRecovery: Ed25519OperationStepUpMaterialRecoveryRequest;
}): IssuedEd25519OperationStepUpAuthorization {
  const body = requireEd25519OperationStepUpResponseRecord(args.body, 'operation step-up response');
  requireExactEd25519OperationStepUpResponseKeys(
    body,
    ['ok', 'kind', 'authorization', 'expiresAtMs', 'materialRecovery'],
    'operation step-up response',
  );
  if (body.ok !== true || body.kind !== 'verified_step_up') {
    throw new Error('[threshold-ed25519] operation step-up response kind is invalid');
  }
  const authorization = requireEd25519OperationStepUpResponseRecord(
    body.authorization,
    'operation step-up authorization',
  );
  requireExactEd25519OperationStepUpResponseKeys(
    authorization,
    ['kind', 'evidence_set_digest'],
    'operation step-up authorization',
  );
  if (authorization.kind !== 'operation_step_up') {
    throw new Error('[threshold-ed25519] operation step-up authorization marker is invalid');
  }
  const evidenceSetDigest = requireNormalizedEd25519OperationStepUpString(
    authorization.evidence_set_digest,
    'operation step-up authorization.evidence_set_digest',
  );
  parseDigestB64u(evidenceSetDigest);
  if (
    typeof body.expiresAtMs !== 'number' ||
    !Number.isSafeInteger(body.expiresAtMs) ||
    body.expiresAtMs <= Date.now()
  ) {
    throw new Error('[threshold-ed25519] operation step-up expiry is invalid');
  }
  return {
    kind: 'verified_step_up',
    authorization: { kind: 'operation_step_up', evidence_set_digest: evidenceSetDigest },
    expiresAtMs: body.expiresAtMs,
    materialRecovery: parseEd25519OperationStepUpMaterialRecoveryResponse({
      value: body.materialRecovery,
      requested: args.requestedMaterialRecovery,
    }),
  };
}

export async function issueEd25519OperationStepUpAuthorization(
  args: Ed25519OperationStepUpAuthorizationRequest,
): Promise<IssuedEd25519OperationStepUpAuthorization> {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(args.relayerUrl));
  if (!relayerUrl) throw new Error('[threshold-ed25519] operation step-up relayerUrl is required');
  const materialRecovery = buildEd25519OperationStepUpMaterialRecoveryRequest(args);
  const requestInit = buildRelayerJsonPostRequestInit({
    ...(args.credential.kind === 'app_session_jwt'
      ? {
          headers: buildBearerAuthorizationHeader({
            token: args.credential.appSessionJwt,
            missingMessage: 'appSessionJwt is required',
          }),
        }
      : {}),
    body: {
      kind: 'router_ab_ed25519_yao_operation_step_up_grant_v1',
      normalSigningRequest: args.normalSigningRequest,
      displayDigest: args.displayDigest,
      proof: serializeEd25519OperationStepUpProof(args.proof),
      materialRecovery:
        materialRecovery.kind === 'email_otp_factor_release_v1'
          ? {
              kind: materialRecovery.kind,
              worker_ephemeral_public_key_65_b64u:
                materialRecovery.workerEphemeralPublicKey65B64u,
            }
          : materialRecovery,
    },
  });
  const response = await fetch(`${relayerUrl}${ROUTER_AB_ED25519_WALLET_SESSION_PATH}`, {
    ...requestInit,
    ...(args.credential.kind === 'app_session_cookie' ? { credentials: 'include' } : {}),
  });
  const body: unknown = await response.json().catch(() => ({}));
  if (!response.ok) {
    const errorBody =
      body && typeof body === 'object' && !Array.isArray(body)
        ? (body as Record<string, unknown>)
        : {};
    throw new Error(
      `[threshold-ed25519] operation step-up failed: ${String(
        errorBody.message || `HTTP ${response.status}`,
      )}`,
    );
  }
  return parseIssuedEd25519OperationStepUpAuthorization({
    body,
    requestedMaterialRecovery: materialRecovery,
  });
}
