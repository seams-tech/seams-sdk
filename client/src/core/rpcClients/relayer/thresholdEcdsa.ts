import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import { errorMessage } from '@shared/utils/errors';
import { normalizeJwtCookieSessionKind, stripTrailingSlashes } from '@shared/utils/normalize';
import {
  requireAppSessionJwt,
  requireThresholdSessionAuthToken,
  type AppOrThresholdSessionAuth,
  type CookieSessionAuth,
} from '@shared/utils/sessionTokens';
import type { ThresholdRuntimePolicyScope } from '../../signingEngine/threshold/sessionPolicy';
import {
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaThresholdKeyId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import { toEcdsaHssThresholdKeyId } from '@/core/signingEngine/session/identity/emailOtpHssIdentity';

export type EcdsaHssRoleLocalPublicIdentity = {
  clientPublicKey33B64u: string;
  relayerPublicKey33B64u: string;
  groupPublicKey33B64u: string;
  ethereumAddress: string;
};

export type ThresholdEcdsaHssRoleLocalClientRootProof = {
  version: 'ecdsa-hss:role-local:first-bootstrap-root-proof:v2';
  digest32B64u: string;
  signature65B64u: string;
};

export type ThresholdEcdsaHssRoleLocalPasskeyBootstrapAuthorization = {
  kind: 'passkey_bootstrap';
  webauthn_authentication: WebAuthnAuthenticationCredential;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  runtimeEnvironmentId?: string;
};

export type ThresholdEcdsaHssRoleLocalBootstrapRequest = {
  formatVersion: 'ecdsa-hss-role-local';
  walletId: WalletId;
  rpId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  clientPublicKey33B64u: string;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  sessionId: string;
  walletSigningSessionId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
  auth?: ThresholdEcdsaHssRouteAuth;
  sessionKind?: 'jwt' | 'cookie';
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
} & (
  | {
      clientRootProof: ThresholdEcdsaHssRoleLocalClientRootProof;
      passkeyBootstrapAuthorization?: never;
    }
  | {
      clientRootProof?: never;
      passkeyBootstrapAuthorization: ThresholdEcdsaHssRoleLocalPasskeyBootstrapAuthorization;
    }
  | {
      clientRootProof?: never;
      passkeyBootstrapAuthorization?: never;
    }
);

type ThresholdEcdsaHssRoleLocalBootstrapBodyBase = {
  formatVersion: 'ecdsa-hss-role-local';
  walletId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  clientPublicKey33B64u: string;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  sessionId: string;
  walletSigningSessionId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

type ThresholdEcdsaHssRoleLocalBootstrapBody = {
  formatVersion: 'ecdsa-hss-role-local';
  walletId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  clientPublicKey33B64u: string;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  sessionId: string;
  walletSigningSessionId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
} & (
  | {
      clientRootProof: ThresholdEcdsaHssRoleLocalClientRootProof;
      passkeyBootstrapAuthorization?: never;
    }
  | {
      clientRootProof?: never;
      passkeyBootstrapAuthorization: ThresholdEcdsaHssRoleLocalPasskeyBootstrapAuthorization;
    }
  | {
      clientRootProof?: never;
      passkeyBootstrapAuthorization?: never;
    }
);

export type ThresholdEcdsaHssRoleLocalBootstrapValue = {
  formatVersion: 'ecdsa-hss-role-local';
  walletId: WalletId;
  rpId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssRoleLocalPublicIdentity;
  publicTranscriptDigest32B64u: string;
  keyHandle: string;
  signingRootId: string;
  signingRootVersion: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  relayerVerifyingShareB64u: string;
  participantIds: number[];
  sessionId: string;
  walletSigningSessionId: string;
  expiresAtMs: number;
  expiresAt: string;
  remainingUses: number;
  jwt?: string;
};

export type ThresholdEcdsaHssRoleLocalExportShareRequest = {
  formatVersion: 'ecdsa-hss-role-local-export';
  walletId: WalletId;
  rpId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssRoleLocalPublicIdentity;
  exportRequestNonce32B64u: string;
  confirmationDigest32B64u: string;
  authorizationDigest32B64u: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  clientDeviceId: string;
  clientSessionId: string;
  auth: ThresholdEcdsaHssRouteAuth;
  sessionKind?: 'jwt' | 'cookie';
};

type ThresholdEcdsaHssRoleLocalExportShareBody = {
  formatVersion: 'ecdsa-hss-role-local-export';
  walletId: string;
  rpId: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssRoleLocalPublicIdentity;
  exportRequestNonce32B64u: string;
  confirmationDigest32B64u: string;
  authorizationDigest32B64u: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  clientDeviceId: string;
  clientSessionId: string;
};

export type ThresholdEcdsaHssRoleLocalExportShareValue = {
  formatVersion: 'ecdsa-hss-role-local-export';
  walletId: WalletId;
  rpId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssRoleLocalPublicIdentity;
  exportAuthorizationDigest32B64u: string;
  serverExportShare32B64u: string;
};

export type ThresholdEcdsaHssRoleLocalRouteResult<T> =
  | { ok: true; value: T }
  | { ok: false; code?: string; message?: string; error?: string };

type RawThresholdEcdsaHssRoleLocalRouteResponse<T> = {
  ok?: boolean;
  code?: string;
  message?: string;
  value?: T;
};

export type ThresholdEcdsaHssRouteAuth =
  | AppOrThresholdSessionAuth
  | CookieSessionAuth
  | { kind: 'bootstrap_grant'; token: string }
  | { kind: 'publishable_key'; token: string };

function requireNonEmptyString(value: unknown, field: string): string {
  const text = String(value || '').trim();
  if (!text) throw new Error(`Missing ${field}`);
  return text;
}

function requireNumber(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) throw new Error(`Missing ${field}`);
  return value;
}

function requireNonNegativeInteger(value: unknown, field: string): number {
  const number = requireNumber(value, field);
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new Error(`${field} must be a non-negative integer`);
  }
  return number;
}

function requireParticipantIds(value: unknown): number[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('participantIds must be a non-empty array');
  }
  return value.map((entry) => {
    const participantId = Number(entry);
    if (!Number.isSafeInteger(participantId) || participantId <= 0) {
      throw new Error('participantIds must contain positive integer ids');
    }
    return participantId;
  });
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Missing ${field}`);
  }
  return value as Record<string, unknown>;
}

const NON_EXPORT_BOOTSTRAP_RESPONSE_FORBIDDEN_FIELDS = [
  'clientShare32B64u',
  'relayerShare32B64u',
  'serverExportShare32B64u',
  'relayerRootShare32B64u',
  'relayerBackendInputB64u',
  'mappedPrivateShare32B64u',
  'relayerMappedPrivateShare32B64u',
  'canonicalPrivateKeyHex',
  'privateKeyHex',
] as const;

function rejectForbiddenFields(
  record: Record<string, unknown>,
  fields: readonly string[],
  label: string,
): void {
  const field = fields.find((candidate) => record[candidate] !== undefined);
  if (field) throw new Error(`${label} contains forbidden field ${field}`);
}

function parseEcdsaHssRoleLocalPublicIdentity(
  value: unknown,
): EcdsaHssRoleLocalPublicIdentity {
  const record = requireRecord(value, 'publicIdentity');
  return {
    clientPublicKey33B64u: requireNonEmptyString(
      record.clientPublicKey33B64u,
      'publicIdentity.clientPublicKey33B64u',
    ),
    relayerPublicKey33B64u: requireNonEmptyString(
      record.relayerPublicKey33B64u,
      'publicIdentity.relayerPublicKey33B64u',
    ),
    groupPublicKey33B64u: requireNonEmptyString(
      record.groupPublicKey33B64u,
      'publicIdentity.groupPublicKey33B64u',
    ),
    ethereumAddress: requireNonEmptyString(
      record.ethereumAddress,
      'publicIdentity.ethereumAddress',
    ),
  };
}

function parseThresholdEcdsaHssRoleLocalBootstrapValue(
  value: unknown,
): ThresholdEcdsaHssRoleLocalBootstrapValue {
  const record = requireRecord(value, 'value');
  rejectForbiddenFields(record, NON_EXPORT_BOOTSTRAP_RESPONSE_FORBIDDEN_FIELDS, 'value');
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: toWalletId(record.walletId),
    rpId: requireNonEmptyString(record.rpId, 'rpId'),
    ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(record.ecdsaThresholdKeyId),
    relayerKeyId: requireNonEmptyString(record.relayerKeyId, 'relayerKeyId'),
    contextBinding32B64u: requireNonEmptyString(
      record.contextBinding32B64u,
      'contextBinding32B64u',
    ),
    publicIdentity: parseEcdsaHssRoleLocalPublicIdentity(record.publicIdentity),
    publicTranscriptDigest32B64u: requireNonEmptyString(
      record.publicTranscriptDigest32B64u,
      'publicTranscriptDigest32B64u',
    ),
    keyHandle: requireNonEmptyString(record.keyHandle, 'keyHandle'),
    signingRootId: requireNonEmptyString(record.signingRootId, 'signingRootId'),
    signingRootVersion: requireNonEmptyString(record.signingRootVersion, 'signingRootVersion'),
    thresholdEcdsaPublicKeyB64u: requireNonEmptyString(
      record.thresholdEcdsaPublicKeyB64u,
      'thresholdEcdsaPublicKeyB64u',
    ),
    ethereumAddress: requireNonEmptyString(record.ethereumAddress, 'ethereumAddress'),
    relayerVerifyingShareB64u: requireNonEmptyString(
      record.relayerVerifyingShareB64u,
      'relayerVerifyingShareB64u',
    ),
    participantIds: requireParticipantIds(record.participantIds),
    sessionId: requireNonEmptyString(record.sessionId, 'sessionId'),
    walletSigningSessionId: requireNonEmptyString(
      record.walletSigningSessionId,
      'walletSigningSessionId',
    ),
    expiresAtMs: requireNumber(record.expiresAtMs, 'expiresAtMs'),
    expiresAt: requireNonEmptyString(record.expiresAt, 'expiresAt'),
    remainingUses: requireNumber(record.remainingUses, 'remainingUses'),
    ...(String(record.jwt || '').trim() ? { jwt: String(record.jwt).trim() } : {}),
  };
}

function parseThresholdEcdsaHssRoleLocalExportShareValue(
  value: unknown,
): ThresholdEcdsaHssRoleLocalExportShareValue {
  const record = requireRecord(value, 'value');
  return {
    formatVersion: 'ecdsa-hss-role-local-export',
    walletId: toWalletId(record.walletId),
    rpId: requireNonEmptyString(record.rpId, 'rpId'),
    ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(record.ecdsaThresholdKeyId),
    relayerKeyId: requireNonEmptyString(record.relayerKeyId, 'relayerKeyId'),
    contextBinding32B64u: requireNonEmptyString(
      record.contextBinding32B64u,
      'contextBinding32B64u',
    ),
    publicIdentity: parseEcdsaHssRoleLocalPublicIdentity(record.publicIdentity),
    exportAuthorizationDigest32B64u: requireNonEmptyString(
      record.exportAuthorizationDigest32B64u,
      'exportAuthorizationDigest32B64u',
    ),
    serverExportShare32B64u: requireNonEmptyString(
      record.serverExportShare32B64u,
      'serverExportShare32B64u',
    ),
  };
}

function resolveBearerToken(auth?: ThresholdEcdsaHssRouteAuth): string {
  if (!auth || auth.kind === 'cookie') return '';
  if (auth.kind === 'app_session') return requireAppSessionJwt(auth.jwt);
  if (auth.kind === 'threshold_session') return requireThresholdSessionAuthToken(auth.jwt);
  return String(auth.token || '').trim();
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

export async function thresholdEcdsaHssRoleLocalBootstrap(
  relayServerUrl: string,
  args: ThresholdEcdsaHssRoleLocalBootstrapRequest,
): Promise<
  ThresholdEcdsaHssRoleLocalRouteResult<ThresholdEcdsaHssRoleLocalBootstrapValue>
> {
  try {
    const base = stripTrailingSlashes(String(relayServerUrl || '').trim());
    if (!base) throw new Error('Missing relayServerUrl');
    const bodyBase: ThresholdEcdsaHssRoleLocalBootstrapBodyBase = {
      formatVersion: 'ecdsa-hss-role-local',
      walletId: requireNonEmptyString(args.walletId, 'walletId'),
      rpId: requireNonEmptyString(args.rpId, 'rpId'),
      ecdsaThresholdKeyId: requireNonEmptyString(args.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
      signingRootId: requireNonEmptyString(args.signingRootId, 'signingRootId'),
      signingRootVersion: requireNonEmptyString(args.signingRootVersion, 'signingRootVersion'),
      keyScope: 'evm-family',
      relayerKeyId: requireNonEmptyString(args.relayerKeyId, 'relayerKeyId'),
      clientPublicKey33B64u: requireNonEmptyString(
        args.clientPublicKey33B64u,
        'clientPublicKey33B64u',
      ),
      clientShareRetryCounter: requireNumber(
        args.clientShareRetryCounter,
        'clientShareRetryCounter',
      ),
      contextBinding32B64u: requireNonEmptyString(
        args.contextBinding32B64u,
        'contextBinding32B64u',
      ),
      requestId: requireNonEmptyString(args.requestId, 'requestId'),
      sessionId: requireNonEmptyString(args.sessionId, 'sessionId'),
      walletSigningSessionId: requireNonEmptyString(
        args.walletSigningSessionId,
        'walletSigningSessionId',
      ),
      ttlMs: requireNonNegativeInteger(args.ttlMs, 'ttlMs'),
      remainingUses: requireNonNegativeInteger(args.remainingUses, 'remainingUses'),
      participantIds: requireParticipantIds(args.participantIds),
      ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    };
    const body: ThresholdEcdsaHssRoleLocalBootstrapBody = args.clientRootProof
      ? {
          ...bodyBase,
          clientRootProof: {
            version: 'ecdsa-hss:role-local:first-bootstrap-root-proof:v2',
            digest32B64u: requireNonEmptyString(
              args.clientRootProof.digest32B64u,
              'clientRootProof.digest32B64u',
            ),
            signature65B64u: requireNonEmptyString(
              args.clientRootProof.signature65B64u,
              'clientRootProof.signature65B64u',
            ),
          },
        }
      : args.passkeyBootstrapAuthorization
        ? {
            ...bodyBase,
            passkeyBootstrapAuthorization: {
              kind: 'passkey_bootstrap',
              webauthn_authentication:
                args.passkeyBootstrapAuthorization.webauthn_authentication,
              ...(args.passkeyBootstrapAuthorization.runtimePolicyScope
                ? { runtimePolicyScope: args.passkeyBootstrapAuthorization.runtimePolicyScope }
                : {}),
              ...(args.passkeyBootstrapAuthorization.runtimeEnvironmentId
                ? {
                    runtimeEnvironmentId: requireNonEmptyString(
                      args.passkeyBootstrapAuthorization.runtimeEnvironmentId,
                      'passkeyBootstrapAuthorization.runtimeEnvironmentId',
                    ),
                  }
                : {}),
            },
          }
        : bodyBase;
    const response = await fetch(
      `${base}/threshold-ecdsa/hss/bootstrap`,
      buildRelayRequestInit({
        auth: args.auth,
        sessionKind: args.sessionKind,
        body,
      }),
    );
    const json =
      await parseRelayJson<RawThresholdEcdsaHssRoleLocalRouteResponse<unknown>>(response);
    if (!response.ok || json.ok !== true) {
      return {
        ok: false,
        code: json.code || (response.ok ? 'server_rejected' : 'http_error'),
        message: json.message || `HTTP ${response.status}`,
      };
    }
    return { ok: true, value: parseThresholdEcdsaHssRoleLocalBootstrapValue(json.value) };
  } catch (error: unknown) {
    return {
      ok: false,
      error: errorMessage(error) || 'Failed to bootstrap threshold-ecdsa role-local hss',
    };
  }
}

export async function thresholdEcdsaHssRoleLocalExportShare(
  relayServerUrl: string,
  args: ThresholdEcdsaHssRoleLocalExportShareRequest,
): Promise<
  ThresholdEcdsaHssRoleLocalRouteResult<ThresholdEcdsaHssRoleLocalExportShareValue>
> {
  try {
    const base = stripTrailingSlashes(String(relayServerUrl || '').trim());
    if (!base) throw new Error('Missing relayServerUrl');
    const body: ThresholdEcdsaHssRoleLocalExportShareBody = {
      formatVersion: 'ecdsa-hss-role-local-export',
      walletId: requireNonEmptyString(args.walletId, 'walletId'),
      rpId: requireNonEmptyString(args.rpId, 'rpId'),
      ecdsaThresholdKeyId: requireNonEmptyString(args.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
      relayerKeyId: requireNonEmptyString(args.relayerKeyId, 'relayerKeyId'),
      contextBinding32B64u: requireNonEmptyString(
        args.contextBinding32B64u,
        'contextBinding32B64u',
      ),
      publicIdentity: {
        clientPublicKey33B64u: requireNonEmptyString(
          args.publicIdentity.clientPublicKey33B64u,
          'publicIdentity.clientPublicKey33B64u',
        ),
        relayerPublicKey33B64u: requireNonEmptyString(
          args.publicIdentity.relayerPublicKey33B64u,
          'publicIdentity.relayerPublicKey33B64u',
        ),
        groupPublicKey33B64u: requireNonEmptyString(
          args.publicIdentity.groupPublicKey33B64u,
          'publicIdentity.groupPublicKey33B64u',
        ),
        ethereumAddress: requireNonEmptyString(
          args.publicIdentity.ethereumAddress,
          'publicIdentity.ethereumAddress',
        ),
      },
      exportRequestNonce32B64u: requireNonEmptyString(
        args.exportRequestNonce32B64u,
        'exportRequestNonce32B64u',
      ),
      confirmationDigest32B64u: requireNonEmptyString(
        args.confirmationDigest32B64u,
        'confirmationDigest32B64u',
      ),
      authorizationDigest32B64u: requireNonEmptyString(
        args.authorizationDigest32B64u,
        'authorizationDigest32B64u',
      ),
      issuedAtUnixMs: requireNumber(args.issuedAtUnixMs, 'issuedAtUnixMs'),
      expiresAtUnixMs: requireNumber(args.expiresAtUnixMs, 'expiresAtUnixMs'),
      clientDeviceId: requireNonEmptyString(args.clientDeviceId, 'clientDeviceId'),
      clientSessionId: requireNonEmptyString(args.clientSessionId, 'clientSessionId'),
    };
    const response = await fetch(
      `${base}/threshold-ecdsa/hss/export/share`,
      buildRelayRequestInit({
        auth: args.auth,
        sessionKind: args.sessionKind,
        body,
      }),
    );
    const json =
      await parseRelayJson<RawThresholdEcdsaHssRoleLocalRouteResponse<unknown>>(response);
    if (!response.ok || json.ok !== true) {
      return {
        ok: false,
        code: json.code || (response.ok ? 'server_rejected' : 'http_error'),
        message: json.message || `HTTP ${response.status}`,
      };
    }
    return { ok: true, value: parseThresholdEcdsaHssRoleLocalExportShareValue(json.value) };
  } catch (error: unknown) {
    return {
      ok: false,
      error: errorMessage(error) || 'Failed to export threshold-ecdsa role-local hss share',
    };
  }
}
