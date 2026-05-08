import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';
import {
  type Ed25519SessionPolicy,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '../sessionPolicy';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { redactCredentialExtensionOutputs } from '../crypto/webauthn';

/**
 * WebAuthn-only threshold session mint.
 *
 * The server verifies the WebAuthn assertion directly and binds the session to the
 * `sessionPolicyDigest32` by using it as the WebAuthn challenge bytes (base64url string).
 *
 * Notes:
 * - Callers must ensure the WebAuthn `challenge` equals `sessionPolicyDigest32`.
 * - PRF outputs must never be sent to the relay; they should be used only in wallet origin.
 */
export async function mintEd25519AuthSession(args: {
  relayerUrl: string;
  sessionKind: ThresholdSessionKind;
  relayerKeyId: string;
  sessionPolicy: Ed25519SessionPolicy;
  webauthnAuthentication?: WebAuthnAuthenticationCredential;
  appSessionJwt?: string;
  useAppSessionCookie?: boolean;
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

  // Never send PRF outputs to the relay.
  const webauthn_authentication = args.webauthnAuthentication
    ? redactCredentialExtensionOutputs(args.webauthnAuthentication)
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
    const appSessionJwt = String(args.appSessionJwt || '').trim() || undefined;
    const useAppSessionCookie = args.useAppSessionCookie === true;
    const publishableKey = String(args.publishableKey || '').trim() || undefined;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(appSessionJwt
          ? { Authorization: `Bearer ${appSessionJwt}` }
          : publishableKey
            ? { Authorization: `Bearer ${publishableKey}` }
            : {}),
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
