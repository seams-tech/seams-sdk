import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import { errorMessage } from '@shared/utils/errors';
import { normalizeJwtCookieSessionKind, stripTrailingSlashes } from '@shared/utils/normalize';
import {
  requireAppSessionJwt,
  requireThresholdSessionAuthToken,
  type AppOrThresholdSessionAuth,
  type CookieSessionAuth,
} from '@shared/utils/sessionTokens';
import { redactCredentialExtensionOutputs } from '../../signingEngine/webauthnAuth/credentials/credentialExtensions';
import type { EcdsaHssSessionPolicy } from '../../signingEngine/threshold/sessionPolicy';
import type {
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaThresholdKeyId,
  WalletSessionUserId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import {
  parseServerPlannedEcdsaHssContext,
  type ServerPlannedEcdsaHssContext,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';

type ThresholdSessionPolicyV1 = EcdsaHssSessionPolicy;

type RawThresholdEcdsaHssPrepareHttpResponse = {
  ok?: boolean;
  code?: string;
  message?: string;
  ceremonyId?: string;
  preparedServerSessionB64u?: string;
  serverAssistInitB64u?: string;
  hssContext?: {
    walletSessionUserId: string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    ecdsaThresholdKeyId: string;
    signingRootId: string;
    signingRootVersion: string;
    keyPurpose: string;
    keyVersion: string;
  };
};

type ThresholdEcdsaHssPrepareHttpResponse = Omit<
  RawThresholdEcdsaHssPrepareHttpResponse,
  'hssContext'
> & {
  hssContext?: ServerPlannedEcdsaHssContext;
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
  sessionId?: string;
  walletSigningSessionId?: string;
  subjectId?: string;
  chainTarget?: ThresholdEcdsaChainTarget;
  expiresAtMs?: number;
  expiresAt?: string;
  remainingUses?: number;
  signingRootId?: string;
  signingRootVersion?: string;
  jwt?: string;
  canonicalPublicKeyHex?: string;
  privateKeyHex?: string;
  canonicalEthereumAddress?: string;
};

type ThresholdEcdsaHssPrepareRequestBase = {
  walletSessionUserId: WalletSessionUserId;
  rpId: string;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  runtimeEnvironmentId?: string;
  sessionKind?: 'jwt' | 'cookie';
};

type ThresholdEcdsaHssPrepareRequest =
  | (ThresholdEcdsaHssPrepareRequestBase & {
      operation: 'registration_bootstrap';
      keygenSessionId: string;
      sessionPolicy: ThresholdSessionPolicyV1;
      auth?: ThresholdEcdsaHssRouteAuth;
    })
  | (ThresholdEcdsaHssPrepareRequestBase & {
      operation: 'email_otp_bootstrap';
      keygenSessionId: string;
      sessionPolicy: ThresholdSessionPolicyV1;
      ecdsaThresholdKeyId?: EcdsaThresholdKeyId;
      auth?: ThresholdEcdsaHssRouteAuth;
    })
  | (ThresholdEcdsaHssPrepareRequestBase & {
      operation: 'session_bootstrap';
      keygenSessionId: string;
      sessionPolicy: ThresholdSessionPolicyV1;
      ecdsaThresholdKeyId: EcdsaThresholdKeyId;
      auth: ThresholdEcdsaHssRouteAuth;
    })
  | (ThresholdEcdsaHssPrepareRequestBase & {
      operation: 'explicit_key_export';
      subjectId: WalletSubjectId;
      chainTarget: ThresholdEcdsaChainTarget;
      ecdsaThresholdKeyId: EcdsaThresholdKeyId;
      auth: ThresholdEcdsaHssRouteAuth;
    });

type ThresholdEcdsaHssPrepareBody = {
  walletSessionUserId: string;
  rpId: string;
  operation: ThresholdEcdsaHssPrepareRequest['operation'];
  ecdsaThresholdKeyId?: string;
  subjectId?: string;
  chainTarget?: ThresholdEcdsaChainTarget;
  keygenSessionId?: string;
  sessionPolicy?: ThresholdSessionPolicyV1;
  runtimeEnvironmentId?: string;
  webauthn_authentication?: ReturnType<typeof redactCredentialExtensionOutputs>;
  sessionKind?: 'jwt' | 'cookie';
};

export type ThresholdEcdsaHssRouteAuth =
  | AppOrThresholdSessionAuth
  | CookieSessionAuth
  | { kind: 'bootstrap_grant'; token: string }
  | { kind: 'publishable_key'; token: string }
  | { kind: 'registration_continuation'; token: string };

function requireNonEmptyString(value: unknown, field: string): string {
  const text = String(value || '').trim();
  if (!text) throw new Error(`Missing ${field}`);
  return text;
}

function optionalNonEmptyString(value: unknown): string | undefined {
  const text = String(value || '').trim();
  return text || undefined;
}

function resolveBearerToken(auth?: ThresholdEcdsaHssRouteAuth): string {
  if (!auth || auth.kind === 'cookie') return '';
  if (auth.kind === 'app_session') return requireAppSessionJwt(auth.jwt);
  if (auth.kind === 'threshold_session') return requireThresholdSessionAuthToken(auth.jwt);
  return String(auth.token || '').trim();
}

function buildThresholdEcdsaHssPrepareBody(
  args: ThresholdEcdsaHssPrepareRequest,
): ThresholdEcdsaHssPrepareBody {
  const runtimeEnvironmentId = optionalNonEmptyString(args.runtimeEnvironmentId);
  const base: ThresholdEcdsaHssPrepareBody = {
    walletSessionUserId: requireNonEmptyString(
      args.walletSessionUserId,
      'walletSessionUserId',
    ),
    rpId: requireNonEmptyString(args.rpId, 'rpId'),
    operation: args.operation,
    ...(runtimeEnvironmentId ? { runtimeEnvironmentId } : {}),
    ...(args.webauthnAuthentication
      ? { webauthn_authentication: redactCredentialExtensionOutputs(args.webauthnAuthentication) }
      : {}),
    ...(args.sessionKind ? { sessionKind: normalizeJwtCookieSessionKind(args.sessionKind) } : {}),
  };
  switch (args.operation) {
    case 'registration_bootstrap':
      return {
        ...base,
        keygenSessionId: requireNonEmptyString(args.keygenSessionId, 'keygenSessionId'),
        sessionPolicy: args.sessionPolicy,
      };
    case 'email_otp_bootstrap': {
      const ecdsaThresholdKeyId = optionalNonEmptyString(args.ecdsaThresholdKeyId);
      return {
        ...base,
        ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
        keygenSessionId: requireNonEmptyString(args.keygenSessionId, 'keygenSessionId'),
        sessionPolicy: args.sessionPolicy,
      };
    }
    case 'session_bootstrap':
      return {
        ...base,
        ecdsaThresholdKeyId: requireNonEmptyString(args.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
        keygenSessionId: requireNonEmptyString(args.keygenSessionId, 'keygenSessionId'),
        sessionPolicy: args.sessionPolicy,
      };
    case 'explicit_key_export':
      return {
        ...base,
        subjectId: requireNonEmptyString(args.subjectId, 'subjectId'),
        chainTarget: args.chainTarget,
        ecdsaThresholdKeyId: requireNonEmptyString(args.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
      };
  }
  args satisfies never;
  throw new Error('Unsupported threshold ECDSA HSS prepare operation');
}

function buildRelayRequestInit(args: {
  auth?: ThresholdEcdsaHssRouteAuth;
  sessionKind?: 'jwt' | 'cookie';
  body: unknown;
}): RequestInit {
  const sessionKind = normalizeJwtCookieSessionKind(args.sessionKind);
  const bearerToken = resolveBearerToken(args.auth);
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (bearerToken) headers.Authorization = `Bearer ${bearerToken}`;
  return {
    method: 'POST',
    headers,
    credentials: bearerToken ? 'omit' : sessionKind === 'cookie' ? 'include' : 'omit',
    body: JSON.stringify(args.body),
  };
}

async function parseRelayJson<T>(response: Response): Promise<T> {
  return (await response.json()) as T;
}

export async function thresholdEcdsaHssPrepare(
  relayServerUrl: string,
  args: ThresholdEcdsaHssPrepareRequest,
): Promise<
  ThresholdEcdsaHssPrepareHttpResponse & {
    error?: string;
  }
> {
  try {
    const base = stripTrailingSlashes(String(relayServerUrl || '').trim());
    if (!base) throw new Error('Missing relayServerUrl');
    const body = buildThresholdEcdsaHssPrepareBody(args);
    const response = await fetch(
      `${base}/threshold-ecdsa/hss/prepare`,
      buildRelayRequestInit({
        auth: args.auth,
        sessionKind: args.sessionKind,
        body,
      }),
    );
    const json = await parseRelayJson<RawThresholdEcdsaHssPrepareHttpResponse>(response);
    if (!response.ok) {
      return {
        ok: false,
        code: json.code || 'http_error',
        message: json.message || `HTTP ${response.status}`,
      };
    }
    return {
      ok: json.ok === true,
      code: json.code,
      message: json.message,
      ceremonyId: json.ceremonyId,
      preparedServerSessionB64u: json.preparedServerSessionB64u,
      serverAssistInitB64u: json.serverAssistInitB64u,
      hssContext: json.hssContext
        ? parseServerPlannedEcdsaHssContext(json.hssContext)
        : undefined,
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
    auth?: ThresholdEcdsaHssRouteAuth;
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
        auth: args.auth,
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
    auth?: ThresholdEcdsaHssRouteAuth;
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
        auth: args.auth,
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
      sessionId: json.sessionId,
      walletSigningSessionId: json.walletSigningSessionId,
      subjectId: json.subjectId,
      chainTarget: json.chainTarget,
      expiresAtMs: json.expiresAtMs,
      expiresAt: json.expiresAt,
      remainingUses: json.remainingUses,
      signingRootId: json.signingRootId,
      signingRootVersion: json.signingRootVersion,
      jwt: json.jwt,
      canonicalPublicKeyHex: json.canonicalPublicKeyHex,
      privateKeyHex: json.privateKeyHex,
      canonicalEthereumAddress: json.canonicalEthereumAddress,
    };
  } catch (error: unknown) {
    return { ok: false, error: errorMessage(error) || 'Failed to finalize threshold-ecdsa hss bootstrap' };
  }
}
