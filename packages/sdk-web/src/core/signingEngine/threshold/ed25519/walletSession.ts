import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';
import { ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2 } from '@shared/utils/signingSessionSeal';
import {
  type Ed25519SessionPolicy,
  type ThresholdRuntimePolicyScope,
} from '../sessionPolicy';
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

export type ThresholdEd25519WebAuthnPrfSecretSource = {
  kind: 'webauthn_prf_first_credential';
  credential: WebAuthnAuthenticationCredential;
  secretSource: WebAuthnPrfFirstSecretSource;
  prfFirstB64u?: never;
};

export type ThresholdEd25519ProvidedPrfSecretSource = {
  kind: 'provided_prf_first_v1';
  prfFirstB64u: string;
  credential?: never;
  secretSource?: never;
};

export type ThresholdEd25519LocalSecretSource =
  | ThresholdEd25519WebAuthnPrfSecretSource
  | ThresholdEd25519ProvidedPrfSecretSource;

export type Ed25519WalletSessionMintAuthorization =
  | {
      kind: 'app_session_jwt';
      appSessionJwt: string;
      localSecretSource: ThresholdEd25519WebAuthnPrfSecretSource;
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
      thresholdEcdsaSessionJwt?: never;
      policySecretSource?: never;
      useAppSessionCookie?: never;
      webauthnAuthentication?: never;
      localPrfCredential?: never;
      localPrfFirstB64u?: never;
    }
  | {
      kind: 'threshold_ecdsa_session_jwt';
      thresholdEcdsaSessionJwt: string;
      localSecretSource: ThresholdEd25519ProvidedPrfSecretSource;
      appSessionJwt?: never;
      localPrfCredential?: never;
      useAppSessionCookie?: never;
      webauthnAuthentication?: never;
      policySecretSource?: never;
      localPrfFirstB64u?: never;
    }
  | {
      kind: 'threshold_session_policy_webauthn';
      policySecretSource: ThresholdEd25519WebAuthnPrfSecretSource;
      appSessionJwt?: never;
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
    secretSource: buildWebAuthnPrfFirstSecretSource(
      buildRequiredPrfAuthenticatorSuccess(args),
    ),
  };
}

export function buildThresholdEd25519ProvidedPrfSecretSource(args: {
  prfFirstB64u: string;
}): ThresholdEd25519ProvidedPrfSecretSource {
  return {
    kind: 'provided_prf_first_v1',
    prfFirstB64u: requireNonEmptyEd25519SecretSourceString(
      args.prfFirstB64u,
      'prfFirstB64u',
    ),
  };
}

function localPrfFirstForThresholdEd25519SecretSource(
  source: ThresholdEd25519LocalSecretSource,
): string {
  switch (source.kind) {
    case 'webauthn_prf_first_credential':
      return source.secretSource.prfFirstB64u;
    case 'provided_prf_first_v1':
      return source.prfFirstB64u;
    default: {
      const exhaustive: never = source;
      return exhaustive;
    }
  }
}

export function localPrfFirstForEd25519WalletSessionMintAuthorization(
  auth: Ed25519WalletSessionMintAuthorization,
): string {
  switch (auth.kind) {
    case 'app_session_jwt':
    case 'app_session_cookie':
      return localPrfFirstForThresholdEd25519SecretSource(auth.localSecretSource);
    case 'threshold_ecdsa_session_jwt':
      return localPrfFirstForThresholdEd25519SecretSource(auth.localSecretSource);
    case 'threshold_session_policy_webauthn':
      return localPrfFirstForThresholdEd25519SecretSource(auth.policySecretSource);
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
 * - PRF outputs must never be sent to the relay; they should be used only in wallet origin.
 */
export async function mintEd25519WalletSession(args: {
  relayerUrl: string;
  sessionKind: 'jwt';
  relayerKeyId: string;
  sessionPolicy: Ed25519SessionPolicy;
  auth: Ed25519WalletSessionMintAuthorization;
  runtimeEnvironmentId?: string;
  publishableKey?: string;
}): Promise<{
  ok: boolean;
  sessionId?: string;
  signingGrantId?: string;
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
    signingGrantId: string;
    expiresAt: string;
    remainingUses: number;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    jwt: string;
    code: string;
    message: string;
  }>;

  try {
    const url = `${relayerUrl}${ROUTER_AB_ED25519_WALLET_SESSION_PATH_V2}`;
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
    const usesPublishableKeyBearer = Boolean(
      publishableKey && !appSessionJwt && !thresholdEcdsaSessionJwt,
    );
    const runtimeEnvironmentId = usesPublishableKeyBearer
      ? String(args.runtimeEnvironmentId || '').trim() || undefined
      : undefined;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(bearerToken ? { Authorization: `Bearer ${bearerToken}` } : {}),
      },
      credentials: useAppSessionCookie ? 'include' : 'omit',
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
      .catch(() => ({}))) as Ed25519WalletSessionMintResponseBody;
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
      sessionId: data.thresholdSessionId,
      signingGrantId: data.signingGrantId,
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
