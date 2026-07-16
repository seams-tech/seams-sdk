import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import { errorMessage } from '@shared/utils/errors';
import {
  requireAppSessionJwt,
  requireWalletSessionJwt,
  type AppOrWalletSessionAuth,
} from '@shared/utils/sessionTokens';
import {
  ROUTER_AB_ECDSA_DERIVATION_BOOTSTRAP_PATH,
  ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_PATH,
  parseRouterAbEcdsaDerivationNormalSigningFromWalletRegistrationJwtV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { ThresholdRuntimePolicyScope } from '../../signingEngine/threshold/sessionPolicy';
import {
  toWalletId,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaThresholdKeyId,
} from '@/core/signingEngine/session/identity/emailOtpEcdsaDerivationIdentity';
import { toEcdsaDerivationThresholdKeyId } from '@/core/signingEngine/session/identity/emailOtpEcdsaDerivationIdentity';
import type {
  EcdsaClientRootPublicKey33B64u,
  DerivationClientSharePublicKey33B64u,
  EcdsaDerivationRelayerPublicKey33B64u,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';

const WRANGLER_WORKER_RESTARTED_MID_REQUEST = 'Your worker restarted mid-request';

export type EcdsaDerivationRoleLocalPublicIdentity = {
  derivationClientSharePublicKey33B64u: DerivationClientSharePublicKey33B64u;
  relayerPublicKey33B64u: EcdsaDerivationRelayerPublicKey33B64u;
  groupPublicKey33B64u: string;
  ethereumAddress: string;
};

export type ThresholdEcdsaDerivationRoleLocalClientRootProof = {
  version: 'ecdsa-derivation:role-local:first-bootstrap-root-proof:v2';
  clientRootPublicKey33B64u: EcdsaClientRootPublicKey33B64u;
  digest32B64u: string;
  signature65B64u: string;
};

export type ThresholdEcdsaDerivationRoleLocalPasskeyBootstrapAuthorization =
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

export type ThresholdEcdsaDerivationRoleLocalBootstrapRequest = {
  formatVersion: 'ecdsa-derivation-role-local';
  walletId: WalletId;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  derivationClientSharePublicKey33B64u: DerivationClientSharePublicKey33B64u;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  requestId: string;
  sessionId: string;
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
  auth?: ThresholdEcdsaDerivationRouteAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
} & (
  | {
      clientRootProof: ThresholdEcdsaDerivationRoleLocalClientRootProof;
      passkeyBootstrapAuthorization?: never;
    }
  | {
      clientRootProof?: never;
      passkeyBootstrapAuthorization: ThresholdEcdsaDerivationRoleLocalPasskeyBootstrapAuthorization;
    }
  | {
      clientRootProof?: never;
      passkeyBootstrapAuthorization?: never;
    }
);

type ThresholdEcdsaDerivationRoleLocalBootstrapBodyBase = {
  formatVersion: 'ecdsa-derivation-role-local';
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  derivationClientSharePublicKey33B64u: DerivationClientSharePublicKey33B64u;
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

type ThresholdEcdsaDerivationRoleLocalBootstrapBodyPasskeyAuthorization =
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

type ThresholdEcdsaDerivationRoleLocalBootstrapBody = {
  formatVersion: 'ecdsa-derivation-role-local';
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  derivationClientSharePublicKey33B64u: DerivationClientSharePublicKey33B64u;
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
      clientRootProof: ThresholdEcdsaDerivationRoleLocalClientRootProof;
      passkeyBootstrapAuthorization?: never;
    }
  | {
      clientRootProof?: never;
      passkeyBootstrapAuthorization: ThresholdEcdsaDerivationRoleLocalBootstrapBodyPasskeyAuthorization;
    }
  | {
      clientRootProof?: never;
      passkeyBootstrapAuthorization?: never;
    }
);

export type ThresholdEcdsaDerivationRoleLocalBootstrapValue = {
  formatVersion: 'ecdsa-derivation-role-local';
  walletId: WalletId;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: string;
  applicationBindingDigestB64u: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaDerivationRoleLocalPublicIdentity;
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
  routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
};

export type ThresholdEcdsaDerivationRoleLocalExportShareRequest = {
  formatVersion: 'ecdsa-derivation-role-local-export';
  walletId: WalletId;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaDerivationRoleLocalPublicIdentity;
  exportRequestNonce32B64u: string;
  confirmationDigest32B64u: string;
  authorizationDigest32B64u: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  clientDeviceId: string;
  clientSessionId: string;
  auth: ThresholdEcdsaDerivationRouteAuth;
};

type ThresholdEcdsaDerivationRoleLocalExportShareBody = {
  formatVersion: 'ecdsa-derivation-role-local-export';
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaDerivationRoleLocalPublicIdentity;
  exportRequestNonce32B64u: string;
  confirmationDigest32B64u: string;
  authorizationDigest32B64u: string;
  issuedAtUnixMs: number;
  expiresAtUnixMs: number;
  clientDeviceId: string;
  clientSessionId: string;
};

export type ThresholdEcdsaDerivationRoleLocalExportShareValue = {
  formatVersion: 'ecdsa-derivation-role-local-export';
  walletId: WalletId;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaDerivationRoleLocalPublicIdentity;
  exportAuthorizationDigest32B64u: string;
  serverExportShare32B64u: string;
};

export type ThresholdEcdsaDerivationRoleLocalRouteResult<T> =
  | { ok: true; value: T }
  | { ok: false; code?: string; message?: string; error?: string };

type RawThresholdEcdsaDerivationRoleLocalRouteResponse<T> = {
  ok?: boolean;
  code?: string;
  message?: string;
  value?: T;
};

export type ThresholdEcdsaDerivationRouteAuth =
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

function parseEcdsaDerivationRoleLocalPublicIdentity(
  value: unknown,
): EcdsaDerivationRoleLocalPublicIdentity {
  const record = requireRecord(value, 'publicIdentity');
  const derivationClientSharePublicKey33B64u = requireNonEmptyString(
    record.derivationClientSharePublicKey33B64u,
    'publicIdentity.derivationClientSharePublicKey33B64u',
  ) as DerivationClientSharePublicKey33B64u;
  const relayerPublicKey33B64u = requireNonEmptyString(
    record.relayerPublicKey33B64u,
    'publicIdentity.relayerPublicKey33B64u',
  ) as EcdsaDerivationRelayerPublicKey33B64u;
  return {
    derivationClientSharePublicKey33B64u,
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

function parseThresholdEcdsaDerivationRoleLocalBootstrapValue(
  value: unknown,
): ThresholdEcdsaDerivationRoleLocalBootstrapValue {
  const record = requireRecord(value, 'value');
  rejectUnexpectedFields(record, NON_EXPORT_BOOTSTRAP_RESPONSE_FIELDS, 'value');
  const walletId = toWalletId(record.walletId);
  const evmFamilySigningKeySlotId = requireNonEmptyString(record.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId');
  const ecdsaThresholdKeyId = toEcdsaDerivationThresholdKeyId(record.ecdsaThresholdKeyId);
  const relayerKeyId = requireNonEmptyString(record.relayerKeyId, 'relayerKeyId');
  const applicationBindingDigestB64u = requireNonEmptyString(
    record.applicationBindingDigestB64u,
    'applicationBindingDigestB64u',
  );
  const contextBinding32B64u = requireNonEmptyString(
    record.contextBinding32B64u,
    'contextBinding32B64u',
  );
  const publicIdentity = parseEcdsaDerivationRoleLocalPublicIdentity(record.publicIdentity);
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
  const routerAbEcdsaDerivationNormalSigning =
    parseRouterAbEcdsaDerivationNormalSigningFromWalletRegistrationJwtV1({
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
        clientPublicKey33B64u: publicIdentity.derivationClientSharePublicKey33B64u,
        serverPublicKey33B64u: publicIdentity.relayerPublicKey33B64u,
        thresholdPublicKey33B64u: publicIdentity.groupPublicKey33B64u,
        ethereumAddress: publicIdentity.ethereumAddress,
        clientShareRetryCounter,
        serverShareRetryCounter: relayerShareRetryCounter,
      },
    });
  return {
    formatVersion: 'ecdsa-derivation-role-local',
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
    routerAbEcdsaDerivationNormalSigning,
  };
}

function parseThresholdEcdsaDerivationRoleLocalExportShareValue(
  value: unknown,
): ThresholdEcdsaDerivationRoleLocalExportShareValue {
  const record = requireRecord(value, 'value');
  return {
    formatVersion: 'ecdsa-derivation-role-local-export',
    walletId: toWalletId(record.walletId),
    evmFamilySigningKeySlotId: requireNonEmptyString(record.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId'),
    ecdsaThresholdKeyId: toEcdsaDerivationThresholdKeyId(record.ecdsaThresholdKeyId),
    relayerKeyId: requireNonEmptyString(record.relayerKeyId, 'relayerKeyId'),
    contextBinding32B64u: requireNonEmptyString(
      record.contextBinding32B64u,
      'contextBinding32B64u',
    ),
    publicIdentity: parseEcdsaDerivationRoleLocalPublicIdentity(record.publicIdentity),
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

function resolveBearerToken(auth?: ThresholdEcdsaDerivationRouteAuth): string {
  if (!auth) return '';
  if (auth.kind === 'app_session') return requireAppSessionJwt(auth.jwt);
  if (auth.kind === 'wallet_session') return requireWalletSessionJwt(auth.jwt);
  return String(auth.token || '').trim();
}

function buildRelayRequestInit(args: {
  auth?: ThresholdEcdsaDerivationRouteAuth;
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

export async function thresholdEcdsaDerivationRoleLocalBootstrap(
  relayServerUrl: string,
  args: ThresholdEcdsaDerivationRoleLocalBootstrapRequest,
): Promise<
  ThresholdEcdsaDerivationRoleLocalRouteResult<ThresholdEcdsaDerivationRoleLocalBootstrapValue>
> {
  try {
    const base = normalizeRelayerBaseUrl(relayServerUrl);
    if (!base) throw new Error('Missing relayServerUrl');
    const bodyBase: ThresholdEcdsaDerivationRoleLocalBootstrapBodyBase = {
      formatVersion: 'ecdsa-derivation-role-local',
      walletId: requireNonEmptyString(args.walletId, 'walletId'),
      evmFamilySigningKeySlotId: requireNonEmptyString(args.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId'),
      ecdsaThresholdKeyId: requireNonEmptyString(args.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
      signingRootId: requireNonEmptyString(args.signingRootId, 'signingRootId'),
      signingRootVersion: requireNonEmptyString(args.signingRootVersion, 'signingRootVersion'),
      keyScope: 'evm-family',
      relayerKeyId: requireNonEmptyString(args.relayerKeyId, 'relayerKeyId'),
      derivationClientSharePublicKey33B64u: requireNonEmptyString(
        args.derivationClientSharePublicKey33B64u,
        'derivationClientSharePublicKey33B64u',
      ) as DerivationClientSharePublicKey33B64u,
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
      | ThresholdEcdsaDerivationRoleLocalBootstrapBodyPasskeyAuthorization
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
    const body: ThresholdEcdsaDerivationRoleLocalBootstrapBody = args.clientRootProof
      ? {
          ...bodyBase,
          clientRootProof: {
            version: 'ecdsa-derivation:role-local:first-bootstrap-root-proof:v2',
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
      `${base}${ROUTER_AB_ECDSA_DERIVATION_BOOTSTRAP_PATH}`,
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
      await parseRelayJson<RawThresholdEcdsaDerivationRoleLocalRouteResponse<unknown>>(response);
    if (!response.ok || json.ok !== true) {
      return {
        ok: false,
        code: json.code || (response.ok ? 'server_rejected' : 'http_error'),
        message: json.message || `HTTP ${response.status}`,
      };
    }
    return { ok: true, value: parseThresholdEcdsaDerivationRoleLocalBootstrapValue(json.value) };
  } catch (error: unknown) {
    return {
      ok: false,
      error: errorMessage(error) || 'Failed to bootstrap threshold-ecdsa role-local derivation',
    };
  }
}

export async function thresholdEcdsaDerivationRoleLocalExportShare(
  relayServerUrl: string,
  args: ThresholdEcdsaDerivationRoleLocalExportShareRequest,
): Promise<
  ThresholdEcdsaDerivationRoleLocalRouteResult<ThresholdEcdsaDerivationRoleLocalExportShareValue>
> {
  try {
    const base = normalizeRelayerBaseUrl(relayServerUrl);
    if (!base) throw new Error('Missing relayServerUrl');
    const body: ThresholdEcdsaDerivationRoleLocalExportShareBody = {
      formatVersion: 'ecdsa-derivation-role-local-export',
      walletId: requireNonEmptyString(args.walletId, 'walletId'),
      evmFamilySigningKeySlotId: requireNonEmptyString(args.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId'),
      ecdsaThresholdKeyId: requireNonEmptyString(args.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
      relayerKeyId: requireNonEmptyString(args.relayerKeyId, 'relayerKeyId'),
      contextBinding32B64u: requireNonEmptyString(
        args.contextBinding32B64u,
        'contextBinding32B64u',
      ),
      publicIdentity: {
        derivationClientSharePublicKey33B64u: requireNonEmptyString(
          args.publicIdentity.derivationClientSharePublicKey33B64u,
          'publicIdentity.derivationClientSharePublicKey33B64u',
        ) as DerivationClientSharePublicKey33B64u,
        relayerPublicKey33B64u: requireNonEmptyString(
          args.publicIdentity.relayerPublicKey33B64u,
          'publicIdentity.relayerPublicKey33B64u',
        ) as EcdsaDerivationRelayerPublicKey33B64u,
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
      `${base}${ROUTER_AB_ECDSA_DERIVATION_EXPORT_SHARE_PATH}`,
      buildRelayRequestInit({
        auth: args.auth,
        body,
      }),
    );
    const json =
      await parseRelayJson<RawThresholdEcdsaDerivationRoleLocalRouteResponse<unknown>>(response);
    if (!response.ok || json.ok !== true) {
      return {
        ok: false,
        code: json.code || (response.ok ? 'server_rejected' : 'http_error'),
        message: json.message || `HTTP ${response.status}`,
      };
    }
    return { ok: true, value: parseThresholdEcdsaDerivationRoleLocalExportShareValue(json.value) };
  } catch (error: unknown) {
    return {
      ok: false,
      error: errorMessage(error) || 'Failed to export threshold-ecdsa role-local derivation share',
    };
  }
}
