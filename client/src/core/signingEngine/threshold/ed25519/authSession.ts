import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';
import {
  type Ed25519SessionPolicy,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '../sessionPolicy';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { redactCredentialExtensionOutputs } from '../crypto/webauthn';

export type ThresholdEd25519SessionMintAuthorization =
  | {
      kind: 'app_session_jwt';
      appSessionJwt: string;
      localPrfCredential: WebAuthnAuthenticationCredential;
      thresholdEcdsaSessionJwt?: never;
      localPrfFirstB64u?: never;
      useAppSessionCookie?: never;
      webauthnAuthentication?: never;
    }
  | {
      kind: 'app_session_cookie';
      localPrfCredential: WebAuthnAuthenticationCredential;
      appSessionJwt?: never;
      thresholdEcdsaSessionJwt?: never;
      localPrfFirstB64u?: never;
      useAppSessionCookie?: never;
      webauthnAuthentication?: never;
    }
  | {
      kind: 'threshold_ecdsa_session_jwt';
      thresholdEcdsaSessionJwt: string;
      localPrfFirstB64u: string;
      appSessionJwt?: never;
      localPrfCredential?: never;
      useAppSessionCookie?: never;
      webauthnAuthentication?: never;
    }
  | {
      kind: 'threshold_session_policy_webauthn';
      webauthnAuthentication: WebAuthnAuthenticationCredential;
      appSessionJwt?: never;
      thresholdEcdsaSessionJwt?: never;
      localPrfFirstB64u?: never;
      useAppSessionCookie?: never;
      localPrfCredential?: never;
    };

export function localPrfFirstForThresholdEd25519SessionMintAuthorization(args: {
  auth: ThresholdEd25519SessionMintAuthorization;
  prfFirstFromCredential: (credential: WebAuthnAuthenticationCredential) => string | null;
}): string {
  switch (args.auth.kind) {
    case 'app_session_jwt':
    case 'app_session_cookie':
      return args.prfFirstFromCredential(args.auth.localPrfCredential) || '';
    case 'threshold_ecdsa_session_jwt':
      return args.auth.localPrfFirstB64u;
    case 'threshold_session_policy_webauthn':
      return args.prfFirstFromCredential(args.auth.webauthnAuthentication) || '';
    default: {
      const exhaustive: never = args.auth;
      return exhaustive;
    }
  }
}

/**
 * Threshold Ed25519 session mint.
 *
 * `threshold_session_policy_webauthn` sends a WebAuthn assertion whose challenge
 * is the `sessionPolicyDigest32`. App-session branches authorize the route with
 * the app session; the local PRF credential stays in wallet origin.
 *
 * Notes:
 * - PRF outputs must never be sent to the relay; they should be used only in wallet origin.
 */
export async function mintEd25519AuthSession(args: {
  relayerUrl: string;
  sessionKind: ThresholdSessionKind;
  relayerKeyId: string;
  sessionPolicy: Ed25519SessionPolicy;
  auth: ThresholdEd25519SessionMintAuthorization;
  runtimeEnvironmentId?: string;
  publishableKey?: string;
}): Promise<{
  ok: boolean;
  sessionId?: string;
  walletSigningSessionId?: string;
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
      message: 'Missing relayerUrl for threshold session mint',
    };
  }

  if (typeof fetch !== 'function') {
    return {
      ok: false,
      code: 'unsupported',
      message: 'fetch is not available for threshold session mint',
    };
  }

  const webauthn_authentication =
    args.auth.kind === 'threshold_session_policy_webauthn'
      ? redactCredentialExtensionOutputs(args.auth.webauthnAuthentication)
      : undefined;

  type ThresholdEd25519SessionMintResponseBody = Partial<{
    ok: boolean;
    sessionId: string;
    walletSigningSessionId: string;
    expiresAt: string;
    remainingUses: number;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    jwt: string;
    code: string;
    message: string;
  }>;

  try {
    const url = `${relayerUrl}/threshold-ed25519/session`;
    const runtimeEnvironmentId = String(args.runtimeEnvironmentId || '').trim() || undefined;
    const appSessionJwt =
      args.auth.kind === 'app_session_jwt'
        ? String(args.auth.appSessionJwt || '').trim() || undefined
        : undefined;
    const thresholdEcdsaSessionJwt =
      args.auth.kind === 'threshold_ecdsa_session_jwt'
        ? String(args.auth.thresholdEcdsaSessionJwt || '').trim() || undefined
        : undefined;
    const useAppSessionCookie = args.auth.kind === 'app_session_cookie';
    const publishableKey = String(args.publishableKey || '').trim() || undefined;
    const bearerToken = appSessionJwt || thresholdEcdsaSessionJwt || publishableKey;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(bearerToken ? { Authorization: `Bearer ${bearerToken}` } : {}),
      },
      credentials: useAppSessionCookie || args.sessionKind === 'cookie' ? 'include' : 'omit',
      body: JSON.stringify({
        sessionKind: args.sessionKind,
        relayerKeyId: args.relayerKeyId,
        sessionPolicy: args.sessionPolicy,
        ...(runtimeEnvironmentId ? { runtimeEnvironmentId } : {}),
        ...(webauthn_authentication ? { webauthn_authentication } : {}),
      }),
    });

    const data = (await response
      .json()
      .catch(() => ({}))) as ThresholdEd25519SessionMintResponseBody;
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

    return {
      ok: data.ok === true,
      sessionId: data.sessionId,
      walletSigningSessionId: data.walletSigningSessionId,
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
    return { ok: false, code: 'network_error', message: msg };
  }
}
