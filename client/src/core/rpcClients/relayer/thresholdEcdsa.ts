import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import { errorMessage } from '@shared/utils/errors';
import { normalizeJwtCookieSessionKind, stripTrailingSlashes } from '@shared/utils/normalize';
import { redactCredentialExtensionOutputs } from '../../signingEngine/signers/webauthn/credentials';
import type { ThresholdRuntimePolicyScope } from '../../signingEngine/threshold/session/sessionPolicy';

type ThresholdSessionPolicyV1 = {
  version: 'threshold_session_v1';
  userId: string;
  rpId: string;
  sessionId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  participantIds?: number[];
  ttlMs: number;
  remainingUses: number;
};

type ThresholdEcdsaHssPrepareHttpResponse = {
  ok?: boolean;
  code?: string;
  message?: string;
  ceremonyId?: string;
  preparedServerSessionB64u?: string;
  serverAssistInitB64u?: string;
};

type ThresholdEcdsaHssRespondHttpResponse = {
  ok?: boolean;
  code?: string;
  message?: string;
  responseMessageB64u?: string;
};

type ThresholdEcdsaHssFinalizeHttpResponse = {
  ok?: boolean;
  code?: string;
  message?: string;
  ecdsaThresholdKeyId?: string;
  clientVerifyingShareB64u?: string;
  clientAdditiveShare32B64u?: string;
  thresholdEcdsaPublicKeyB64u?: string;
  ethereumAddress?: string;
  participantIds?: number[];
  relayerKeyId?: string;
  relayerVerifyingShareB64u?: string;
  chainId?: number;
  factory?: string;
  entryPoint?: string;
  salt?: string;
  counterfactualAddress?: string;
  sessionId?: string;
  expiresAtMs?: number;
  expiresAt?: string;
  remainingUses?: number;
  jwt?: string;
  canonicalPublicKeyHex?: string;
  privateKeyHex?: string;
  canonicalEthereumAddress?: string;
};

function buildRelayRequestInit(args: {
  authorizationJwt?: string;
  sessionKind?: 'jwt' | 'cookie';
  body: unknown;
}): RequestInit {
  const sessionKind = normalizeJwtCookieSessionKind(args.sessionKind);
  const authorizationJwt = String(args.authorizationJwt || '').trim();
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (authorizationJwt) headers.Authorization = `Bearer ${authorizationJwt}`;
  return {
    method: 'POST',
    headers,
    credentials: authorizationJwt ? 'omit' : sessionKind === 'cookie' ? 'include' : 'omit',
    body: JSON.stringify(args.body),
  };
}

async function parseRelayJson<T>(response: Response): Promise<T> {
  return (await response.json()) as T;
}

export async function thresholdEcdsaHssPrepare(
  relayServerUrl: string,
  args: {
    userId: string;
    rpId: string;
    operation:
      | 'registration_bootstrap'
      | 'email_otp_bootstrap'
      | 'session_bootstrap'
      | 'explicit_key_export';
    ecdsaThresholdKeyId?: string;
    keygenSessionId?: string;
    sessionPolicy?: ThresholdSessionPolicyV1;
    webauthnAuthentication?: WebAuthnAuthenticationCredential;
    runtimeEnvironmentId?: string;
    authorizationJwt?: string;
    sessionKind?: 'jwt' | 'cookie';
  },
): Promise<
  ThresholdEcdsaHssPrepareHttpResponse & {
    error?: string;
  }
> {
  try {
    const base = stripTrailingSlashes(String(relayServerUrl || '').trim());
    if (!base) throw new Error('Missing relayServerUrl');
    const userId = String(args.userId || '').trim();
    const rpId = String(args.rpId || '').trim();
    const operation = String(args.operation || '').trim();
    if (!userId) throw new Error('Missing userId');
    if (!rpId) throw new Error('Missing rpId');
    if (!operation) throw new Error('Missing operation');
    const response = await fetch(
      `${base}/threshold-ecdsa/hss/prepare`,
      buildRelayRequestInit({
        authorizationJwt: args.authorizationJwt,
        sessionKind: args.sessionKind,
        body: {
          userId,
          rpId,
          operation,
          ...(args.ecdsaThresholdKeyId
            ? { ecdsaThresholdKeyId: String(args.ecdsaThresholdKeyId).trim() }
            : {}),
          ...(args.keygenSessionId ? { keygenSessionId: String(args.keygenSessionId).trim() } : {}),
          ...(args.sessionPolicy ? { sessionPolicy: args.sessionPolicy } : {}),
          ...(args.runtimeEnvironmentId
            ? { runtimeEnvironmentId: String(args.runtimeEnvironmentId).trim() }
            : {}),
          ...(args.webauthnAuthentication
            ? { webauthn_authentication: redactCredentialExtensionOutputs(args.webauthnAuthentication) }
            : {}),
          ...(args.sessionKind ? { sessionKind: normalizeJwtCookieSessionKind(args.sessionKind) } : {}),
        },
      }),
    );
    const json = await parseRelayJson<ThresholdEcdsaHssPrepareHttpResponse>(response);
    if (!response.ok) {
      return { ok: false, code: json.code || 'http_error', message: json.message || `HTTP ${response.status}` };
    }
    return {
      ok: json.ok === true,
      code: json.code,
      message: json.message,
      ceremonyId: json.ceremonyId,
      preparedServerSessionB64u: json.preparedServerSessionB64u,
      serverAssistInitB64u: json.serverAssistInitB64u,
    };
  } catch (error: unknown) {
    return { ok: false, error: errorMessage(error) || 'Failed to prepare threshold-ecdsa hss bootstrap' };
  }
}

export async function thresholdEcdsaHssRespond(
  relayServerUrl: string,
  args: {
    ceremonyId: string;
    requestMessageB64u: string;
    authorizationJwt?: string;
    sessionKind?: 'jwt' | 'cookie';
  },
): Promise<
  ThresholdEcdsaHssRespondHttpResponse & {
    error?: string;
  }
> {
  try {
    const base = stripTrailingSlashes(String(relayServerUrl || '').trim());
    if (!base) throw new Error('Missing relayServerUrl');
    const ceremonyId = String(args.ceremonyId || '').trim();
    const requestMessageB64u = String(args.requestMessageB64u || '').trim();
    if (!ceremonyId) throw new Error('Missing ceremonyId');
    if (!requestMessageB64u) throw new Error('Missing requestMessageB64u');
    const response = await fetch(
      `${base}/threshold-ecdsa/hss/respond`,
      buildRelayRequestInit({
        authorizationJwt: args.authorizationJwt,
        sessionKind: args.sessionKind,
        body: { ceremonyId, requestMessageB64u },
      }),
    );
    const json = await parseRelayJson<ThresholdEcdsaHssRespondHttpResponse>(response);
    if (!response.ok) {
      return { ok: false, code: json.code || 'http_error', message: json.message || `HTTP ${response.status}` };
    }
    return {
      ok: json.ok === true,
      code: json.code,
      message: json.message,
      responseMessageB64u: json.responseMessageB64u,
    };
  } catch (error: unknown) {
    return { ok: false, error: errorMessage(error) || 'Failed to respond to threshold-ecdsa hss bootstrap' };
  }
}

export async function thresholdEcdsaHssFinalize(
  relayServerUrl: string,
  args: {
    ceremonyId: string;
    clientFinalizeMessageB64u: string;
    authorizationJwt?: string;
    sessionKind?: 'jwt' | 'cookie';
  },
): Promise<
  ThresholdEcdsaHssFinalizeHttpResponse & {
    error?: string;
  }
> {
  try {
    const base = stripTrailingSlashes(String(relayServerUrl || '').trim());
    if (!base) throw new Error('Missing relayServerUrl');
    const ceremonyId = String(args.ceremonyId || '').trim();
    const clientFinalizeMessageB64u = String(args.clientFinalizeMessageB64u || '').trim();
    if (!ceremonyId) throw new Error('Missing ceremonyId');
    if (!clientFinalizeMessageB64u) throw new Error('Missing clientFinalizeMessageB64u');
    const response = await fetch(
      `${base}/threshold-ecdsa/hss/finalize`,
      buildRelayRequestInit({
        authorizationJwt: args.authorizationJwt,
        sessionKind: args.sessionKind,
        body: { ceremonyId, clientFinalizeMessageB64u },
      }),
    );
    const json = await parseRelayJson<ThresholdEcdsaHssFinalizeHttpResponse>(response);
    if (!response.ok) {
      return { ok: false, code: json.code || 'http_error', message: json.message || `HTTP ${response.status}` };
    }
    return {
      ok: json.ok === true,
      code: json.code,
      message: json.message,
      ecdsaThresholdKeyId: json.ecdsaThresholdKeyId,
      clientVerifyingShareB64u: json.clientVerifyingShareB64u,
      clientAdditiveShare32B64u: json.clientAdditiveShare32B64u,
      thresholdEcdsaPublicKeyB64u: json.thresholdEcdsaPublicKeyB64u,
      ethereumAddress: json.ethereumAddress,
      participantIds: json.participantIds,
      relayerKeyId: json.relayerKeyId,
      relayerVerifyingShareB64u: json.relayerVerifyingShareB64u,
      chainId: json.chainId,
      factory: json.factory,
      entryPoint: json.entryPoint,
      salt: json.salt,
      counterfactualAddress: json.counterfactualAddress,
      sessionId: json.sessionId,
      expiresAtMs: json.expiresAtMs,
      expiresAt: json.expiresAt,
      remainingUses: json.remainingUses,
      jwt: json.jwt,
      canonicalPublicKeyHex: json.canonicalPublicKeyHex,
      privateKeyHex: json.privateKeyHex,
      canonicalEthereumAddress: json.canonicalEthereumAddress,
    };
  } catch (error: unknown) {
    return { ok: false, error: errorMessage(error) || 'Failed to finalize threshold-ecdsa hss bootstrap' };
  }
}
