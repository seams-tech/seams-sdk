import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import { errorMessage } from '@shared/utils/errors';
import {
  requireAppSessionJwt,
  requireWalletSessionJwt,
  type AppOrWalletSessionAuth,
} from '@shared/utils/sessionTokens';
import {
  ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH,
  ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH,
  parseRouterAbEcdsaHssNormalSigningFromWalletRegistrationJwtV1,
  type RouterAbEcdsaHssNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaHss';
import type { ThresholdRuntimePolicyScope } from '../../signingEngine/threshold/sessionPolicy';
import {
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaThresholdKeyId,
} from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import { toEcdsaHssThresholdKeyId } from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import type {
  EcdsaClientRootPublicKey33B64u,
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';

const WRANGLER_WORKER_RESTARTED_MID_REQUEST = 'Your worker restarted mid-request';

export type EcdsaHssRoleLocalPublicIdentity = {
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
  groupPublicKey33B64u: string;
  ethereumAddress: string;
};

export type ThresholdEcdsaHssRoleLocalClientRootProof = {
  version: 'ecdsa-hss:role-local:first-bootstrap-root-proof:v2';
  clientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u;
  digest32B64u: string;
  signature65B64u: string;
};

export type ThresholdEcdsaHssRoleLocalPasskeyBootstrapAuthorization =
  | {
      kind: 'passkey_bootstrap';
      rpId: string;
      webauthn_authentication: WebAuthnAuthenticationCredential;
      runtimePolicyScope: ThresholdRuntimePolicyScope;
      projectEnvironmentId?: never;
      projectEnvironmentPublishableKey?: never;
    }
  | {
      kind: 'passkey_bootstrap';
      rpId: string;
      webauthn_authentication: WebAuthnAuthenticationCredential;
      projectEnvironmentId: string;
      projectEnvironmentPublishableKey: string;
      runtimePolicyScope?: never;
    };

export type ThresholdEcdsaHssRoleLocalBootstrapRequest = {
  formatVersion: 'ecdsa-hss-role-local';
  walletId: WalletId;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  sessionId: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
  auth?: ThresholdEcdsaHssRouteAuth;
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
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  sessionId: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

type ThresholdEcdsaHssRoleLocalBootstrapBodyPasskeyAuthorization =
  | {
      kind: 'passkey_bootstrap';
      rpId: string;
      webauthn_authentication: WebAuthnAuthenticationCredential;
      runtimePolicyScope: ThresholdRuntimePolicyScope;
      projectEnvironmentId?: never;
    }
  | {
      kind: 'passkey_bootstrap';
      rpId: string;
      webauthn_authentication: WebAuthnAuthenticationCredential;
      projectEnvironmentId: string;
      runtimePolicyScope?: never;
    };

type ThresholdEcdsaHssRoleLocalBootstrapBody = {
  formatVersion: 'ecdsa-hss-role-local';
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  sessionId: string;
  signingGrantId: string;
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
      passkeyBootstrapAuthorization: ThresholdEcdsaHssRoleLocalBootstrapBodyPasskeyAuthorization;
    }
  | {
      clientRootProof?: never;
      passkeyBootstrapAuthorization?: never;
    }
);

export type ThresholdEcdsaHssRoleLocalBootstrapValue = {
  formatVersion: 'ecdsa-hss-role-local';
  walletId: WalletId;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: string;
  applicationBindingDigestB64u: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaHssRoleLocalPublicIdentity;
  clientShareRetryCounter: number;
  relayerShareRetryCounter: number;
  publicTranscriptDigest32B64u: string;
  keyHandle: string;
  signingRootId: string;
  signingRootVersion: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  relayerVerifyingShareB64u: string;
  participantIds: number[];
  thresholdSessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  expiresAt: string;
  remainingUses: number;
  jwt?: string;
  routerAbEcdsaHssNormalSigning: RouterAbEcdsaHssNormalSigningStateV1;
};

export type ThresholdEcdsaHssRoleLocalExportShareRequest = {
  formatVersion: 'ecdsa-hss-role-local-export';
  walletId: WalletId;
  evmFamilySigningKeySlotId: string;
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
};

type ThresholdEcdsaHssRoleLocalExportShareBody = {
  formatVersion: 'ecdsa-hss-role-local-export';
  walletId: string;
  evmFamilySigningKeySlotId: string;
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
  evmFamilySigningKeySlotId: string;
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
  | AppOrWalletSessionAuth
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

const NON_EXPORT_BOOTSTRAP_RESPONSE_FIELDS = new Set([
  'formatVersion',
  'walletId',
  'evmFamilySigningKeySlotId',
  'ecdsaThresholdKeyId',
  'relayerKeyId',
  'applicationBindingDigestB64u',
  'contextBinding32B64u',
  'publicIdentity',
  'clientShareRetryCounter',
  'relayerShareRetryCounter',
  'publicTranscriptDigest32B64u',
  'keyHandle',
  'signingRootId',
  'signingRootVersion',
  'thresholdEcdsaPublicKeyB64u',
  'ethereumAddress',
  'relayerVerifyingShareB64u',
  'participantIds',
  'thresholdSessionId',
  'signingGrantId',
  'expiresAtMs',
  'expiresAt',
  'remainingUses',
  'jwt',
]);

function rejectUnexpectedFields(
  record: Record<string, unknown>,
  fields: ReadonlySet<string>,
  label: string,
): void {
  const field = Object.keys(record).find((candidate) => !fields.has(candidate));
  if (field) throw new Error(`${label} contains unexpected field ${field}`);
}

function parseEcdsaHssRoleLocalPublicIdentity(
  value: unknown,
): EcdsaHssRoleLocalPublicIdentity {
  const record = requireRecord(value, 'publicIdentity');
  const hssClientSharePublicKey33B64u = requireNonEmptyString(
    record.hssClientSharePublicKey33B64u,
    'publicIdentity.hssClientSharePublicKey33B64u',
  ) as EcdsaHssClientSharePublicKey33B64u;
  const relayerPublicKey33B64u = requireNonEmptyString(
    record.relayerPublicKey33B64u,
    'publicIdentity.relayerPublicKey33B64u',
  ) as EcdsaRelayerHssPublicKey33B64u;
  return {
    hssClientSharePublicKey33B64u,
    relayerPublicKey33B64u,
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
  rejectUnexpectedFields(record, NON_EXPORT_BOOTSTRAP_RESPONSE_FIELDS, 'value');
  const walletId = toWalletId(record.walletId);
  const evmFamilySigningKeySlotId = requireNonEmptyString(record.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId');
  const ecdsaThresholdKeyId = toEcdsaHssThresholdKeyId(record.ecdsaThresholdKeyId);
  const relayerKeyId = requireNonEmptyString(record.relayerKeyId, 'relayerKeyId');
  const applicationBindingDigestB64u = requireNonEmptyString(
    record.applicationBindingDigestB64u,
    'applicationBindingDigestB64u',
  );
  const contextBinding32B64u = requireNonEmptyString(
    record.contextBinding32B64u,
    'contextBinding32B64u',
  );
  const publicIdentity = parseEcdsaHssRoleLocalPublicIdentity(record.publicIdentity);
  const clientShareRetryCounter = requireNonNegativeInteger(
    record.clientShareRetryCounter,
    'clientShareRetryCounter',
  );
  const relayerShareRetryCounter = requireNonNegativeInteger(
    record.relayerShareRetryCounter,
    'relayerShareRetryCounter',
  );
  const keyHandle = requireNonEmptyString(record.keyHandle, 'keyHandle');
  const signingRootId = requireNonEmptyString(record.signingRootId, 'signingRootId');
  const signingRootVersion = requireNonEmptyString(
    record.signingRootVersion,
    'signingRootVersion',
  );
  const participantIds = requireParticipantIds(record.participantIds);
  const thresholdSessionId = requireNonEmptyString(
    record.thresholdSessionId,
    'thresholdSessionId',
  );
  const signingGrantId = requireNonEmptyString(
    record.signingGrantId,
    'signingGrantId',
  );
  const expiresAtMs = requireNumber(record.expiresAtMs, 'expiresAtMs');
  const jwt = String(record.jwt || '').trim();
  const routerAbEcdsaHssNormalSigning =
    parseRouterAbEcdsaHssNormalSigningFromWalletRegistrationJwtV1({
      walletSessionJwt: jwt,
      expected: {
        walletId,
        evmFamilySigningKeySlotId,
        keyHandle,
        relayerKeyId,
        ecdsaThresholdKeyId,
        signingRootId,
        signingRootVersion,
        thresholdSessionId,
        signingGrantId,
        expiresAtMs,
        participantIds,
        applicationBindingDigestB64u,
        contextBinding32B64u,
        clientPublicKey33B64u: publicIdentity.hssClientSharePublicKey33B64u,
        serverPublicKey33B64u: publicIdentity.relayerPublicKey33B64u,
        thresholdPublicKey33B64u: publicIdentity.groupPublicKey33B64u,
        ethereumAddress: publicIdentity.ethereumAddress,
        clientShareRetryCounter,
        serverShareRetryCounter: relayerShareRetryCounter,
      },
    });
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    relayerKeyId,
    applicationBindingDigestB64u,
    contextBinding32B64u,
    publicIdentity,
    clientShareRetryCounter,
    relayerShareRetryCounter,
    publicTranscriptDigest32B64u: requireNonEmptyString(
      record.publicTranscriptDigest32B64u,
      'publicTranscriptDigest32B64u',
    ),
    keyHandle,
    signingRootId,
    signingRootVersion,
    thresholdEcdsaPublicKeyB64u: requireNonEmptyString(
      record.thresholdEcdsaPublicKeyB64u,
      'thresholdEcdsaPublicKeyB64u',
    ),
    ethereumAddress: requireNonEmptyString(record.ethereumAddress, 'ethereumAddress'),
    relayerVerifyingShareB64u: requireNonEmptyString(
      record.relayerVerifyingShareB64u,
      'relayerVerifyingShareB64u',
    ),
    participantIds,
    thresholdSessionId,
    signingGrantId,
    expiresAtMs,
    expiresAt: requireNonEmptyString(record.expiresAt, 'expiresAt'),
    remainingUses: requireNumber(record.remainingUses, 'remainingUses'),
    ...(jwt ? { jwt } : {}),
    routerAbEcdsaHssNormalSigning,
  };
}

function parseThresholdEcdsaHssRoleLocalExportShareValue(
  value: unknown,
): ThresholdEcdsaHssRoleLocalExportShareValue {
  const record = requireRecord(value, 'value');
  return {
    formatVersion: 'ecdsa-hss-role-local-export',
    walletId: toWalletId(record.walletId),
    evmFamilySigningKeySlotId: requireNonEmptyString(record.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId'),
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
  if (!auth) return '';
  if (auth.kind === 'app_session') return requireAppSessionJwt(auth.jwt);
  if (auth.kind === 'wallet_session') return requireWalletSessionJwt(auth.jwt);
  return String(auth.token || '').trim();
}

function buildRelayRequestInit(args: {
  auth?: ThresholdEcdsaHssRouteAuth;
  publishableKeyAuth?: string;
  body: unknown;
}): RequestInit {
  const bearerToken = resolveBearerToken(args.auth);
  const publishableKeyAuth = String(args.publishableKeyAuth || '').trim();
  const headers = bearerToken
    ? buildBearerAuthorizationHeader({
        token: bearerToken,
        missingMessage: 'bearer token is required',
      })
    : publishableKeyAuth
      ? buildBearerAuthorizationHeader({
          token: publishableKeyAuth,
          missingMessage: 'publishable key auth is required',
        })
      : undefined;
  return buildRelayerJsonPostRequestInit({
    headers,
    body: args.body,
  });
}

async function parseRelayJson<T>(response: Response): Promise<T> {
  const text = await readResponseText(response);
  if (isWranglerWorkerRestartedMidRequestResponse(text)) {
    return {
      ok: false,
      code: 'worker_restarted_mid_request',
      message: WRANGLER_WORKER_RESTARTED_MID_REQUEST,
    } as T;
  }
  return parseJsonText<T>(text);
}

async function readResponseText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return '';
  }
}

function isWranglerWorkerRestartedMidRequestResponse(text: string): boolean {
  return text.includes(WRANGLER_WORKER_RESTARTED_MID_REQUEST);
}

function parseJsonText<T>(text: string): T {
  try {
    return JSON.parse(text || '{}') as T;
  } catch (error) {
    throw new Error(`Failed to parse threshold ECDSA relayer response JSON: ${errorMessage(error)}`);
  }
}

export async function thresholdEcdsaHssRoleLocalBootstrap(
  relayServerUrl: string,
  args: ThresholdEcdsaHssRoleLocalBootstrapRequest,
): Promise<
  ThresholdEcdsaHssRoleLocalRouteResult<ThresholdEcdsaHssRoleLocalBootstrapValue>
> {
  try {
    const base = normalizeRelayerBaseUrl(relayServerUrl);
    if (!base) throw new Error('Missing relayServerUrl');
    const bodyBase: ThresholdEcdsaHssRoleLocalBootstrapBodyBase = {
      formatVersion: 'ecdsa-hss-role-local',
      walletId: requireNonEmptyString(args.walletId, 'walletId'),
      evmFamilySigningKeySlotId: requireNonEmptyString(args.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId'),
      ecdsaThresholdKeyId: requireNonEmptyString(args.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
      signingRootId: requireNonEmptyString(args.signingRootId, 'signingRootId'),
      signingRootVersion: requireNonEmptyString(args.signingRootVersion, 'signingRootVersion'),
      keyScope: 'evm-family',
      relayerKeyId: requireNonEmptyString(args.relayerKeyId, 'relayerKeyId'),
      hssClientSharePublicKey33B64u: requireNonEmptyString(
        args.hssClientSharePublicKey33B64u,
        'hssClientSharePublicKey33B64u',
      ) as EcdsaHssClientSharePublicKey33B64u,
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
      signingGrantId: requireNonEmptyString(
        args.signingGrantId,
        'signingGrantId',
      ),
      ttlMs: requireNonNegativeInteger(args.ttlMs, 'ttlMs'),
      remainingUses: requireNonNegativeInteger(args.remainingUses, 'remainingUses'),
      participantIds: requireParticipantIds(args.participantIds),
      ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    };
    const bodyPasskeyAuthorization = ():
      | ThresholdEcdsaHssRoleLocalBootstrapBodyPasskeyAuthorization
      | null => {
      const authorization = args.passkeyBootstrapAuthorization;
      if (!authorization) return null;
      const runtimePolicyScope = authorization.runtimePolicyScope;
      if (runtimePolicyScope) {
        return {
          kind: 'passkey_bootstrap',
          rpId: requireNonEmptyString(authorization.rpId, 'passkeyBootstrapAuthorization.rpId'),
          webauthn_authentication: authorization.webauthn_authentication,
          runtimePolicyScope,
        };
      }
      return {
        kind: 'passkey_bootstrap',
        rpId: requireNonEmptyString(authorization.rpId, 'passkeyBootstrapAuthorization.rpId'),
        webauthn_authentication: authorization.webauthn_authentication,
        projectEnvironmentId: requireNonEmptyString(
          authorization.projectEnvironmentId,
          'passkeyBootstrapAuthorization.projectEnvironmentId',
        ),
      };
    };
    const passkeyAuthorizationBody = bodyPasskeyAuthorization();
    const body: ThresholdEcdsaHssRoleLocalBootstrapBody = args.clientRootProof
      ? {
          ...bodyBase,
          clientRootProof: {
            version: 'ecdsa-hss:role-local:first-bootstrap-root-proof:v2',
            clientRootPublicKey33B64u: requireNonEmptyString(
              args.clientRootProof.clientRootPublicKey33B64u,
              'clientRootProof.clientRootPublicKey33B64u',
            ) as EcdsaClientRootPublicKey33B64u,
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
      : passkeyAuthorizationBody
        ? {
            ...bodyBase,
            passkeyBootstrapAuthorization: passkeyAuthorizationBody,
          }
        : bodyBase;
    const response = await fetch(
      `${base}${ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH}`,
      buildRelayRequestInit({
        auth: args.auth,
        publishableKeyAuth:
          args.passkeyBootstrapAuthorization &&
          'projectEnvironmentPublishableKey' in args.passkeyBootstrapAuthorization
            ? args.passkeyBootstrapAuthorization.projectEnvironmentPublishableKey
            : undefined,
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
    const base = normalizeRelayerBaseUrl(relayServerUrl);
    if (!base) throw new Error('Missing relayServerUrl');
    const body: ThresholdEcdsaHssRoleLocalExportShareBody = {
      formatVersion: 'ecdsa-hss-role-local-export',
      walletId: requireNonEmptyString(args.walletId, 'walletId'),
      evmFamilySigningKeySlotId: requireNonEmptyString(args.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId'),
      ecdsaThresholdKeyId: requireNonEmptyString(args.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
      relayerKeyId: requireNonEmptyString(args.relayerKeyId, 'relayerKeyId'),
      contextBinding32B64u: requireNonEmptyString(
        args.contextBinding32B64u,
        'contextBinding32B64u',
      ),
      publicIdentity: {
        hssClientSharePublicKey33B64u: requireNonEmptyString(
          args.publicIdentity.hssClientSharePublicKey33B64u,
          'publicIdentity.hssClientSharePublicKey33B64u',
        ) as EcdsaHssClientSharePublicKey33B64u,
        relayerPublicKey33B64u: requireNonEmptyString(
          args.publicIdentity.relayerPublicKey33B64u,
          'publicIdentity.relayerPublicKey33B64u',
        ) as EcdsaRelayerHssPublicKey33B64u,
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
      `${base}${ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH}`,
      buildRelayRequestInit({
        auth: args.auth,
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
