import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  MAX_WALLET_SESSION_REMAINING_USES,
  MAX_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import { isPlainObject } from '@shared/utils/validation';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { parseWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { WebAuthnAuthenticationCredential } from '../core/types';
import type {
  RouterAbEd25519YaoSessionPolicyV1,
  RouterAbEd25519YaoSessionRouteCommandV1,
} from './routerAbEd25519YaoWalletSession';
import {
  findUnexpectedRouteKey,
  optionalRouteTrimmedString,
  parseWebAuthnAuthenticationCredential,
} from './routeRequestValidation';

export type ThresholdEd25519RouteErrorBody = {
  ok: false;
  code: 'invalid_body';
  message: string;
};

type ThresholdEd25519RouteParseError = { ok: false; body: ThresholdEd25519RouteErrorBody };

export type ThresholdEd25519RouteParseResult<T> =
  | { ok: true; request: T }
  | ThresholdEd25519RouteParseError;

const SESSION_KEYS = [
  'relayerKeyId',
  'sessionPolicy',
  'projectEnvironmentId',
  'webauthn_authentication',
  'sessionKind',
] as const;

const SESSION_POLICY_KEYS = [
  'version',
  'nearAccountId',
  'nearEd25519SigningKeyId',
  'authority',
  'relayerKeyId',
  'thresholdSessionId',
  'signingGrantId',
  'runtimePolicyScope',
  'routerAbNormalSigning',
  'participantIds',
  'ttlMs',
  'remainingUses',
] as const;

function invalidThresholdEd25519Body(message: string): ThresholdEd25519RouteParseError {
  return { ok: false, body: { ok: false, code: 'invalid_body', message } };
}

function requiredStringField(
  record: Record<string, unknown>,
  field: string,
): ThresholdEd25519RouteParseResult<string> {
  const value = record[field];
  if (typeof value !== 'string' || !value.trim()) {
    return invalidThresholdEd25519Body(`${field} is required`);
  }
  return { ok: true, request: value.trim() };
}

function optionalStringField(record: Record<string, unknown>, field: string): string | undefined {
  return optionalRouteTrimmedString(record, field);
}

function parseOptionalWebAuthnAuthentication(
  record: Record<string, unknown>,
): ThresholdEd25519RouteParseResult<WebAuthnAuthenticationCredential | null> {
  if (record.webauthn_authentication === undefined) {
    return { ok: true, request: null };
  }
  const credential = parseWebAuthnAuthenticationCredential(record.webauthn_authentication);
  return credential
    ? { ok: true, request: credential }
    : invalidThresholdEd25519Body('webauthn_authentication is invalid');
}

export function parseRouterAbEd25519YaoSessionPolicyV1(
  raw: unknown,
): ThresholdEd25519RouteParseResult<RouterAbEd25519YaoSessionPolicyV1> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('sessionPolicy is required');
  if (Object.prototype.hasOwnProperty.call(raw, 'rpId')) {
    return invalidThresholdEd25519Body('sessionPolicy.rpId belongs in sessionPolicy.authority');
  }
  const unsupported = findUnexpectedRouteKey(raw, SESSION_POLICY_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(
      `Unsupported threshold-ed25519 sessionPolicy field: ${unsupported}`,
    );
  }
  if (raw.version !== 'threshold_session_v1') {
    return invalidThresholdEd25519Body('sessionPolicy.version must be threshold_session_v1');
  }
  const nearAccountId = requiredStringField(raw, 'nearAccountId');
  if (!nearAccountId.ok) return nearAccountId;
  const nearEd25519SigningKeyId = requiredStringField(raw, 'nearEd25519SigningKeyId');
  if (!nearEd25519SigningKeyId.ok) return nearEd25519SigningKeyId;
  const authority = parseWalletAuthAuthority(raw.authority);
  if (!authority) {
    return invalidThresholdEd25519Body('sessionPolicy.authority is invalid');
  }
  const relayerKeyId = requiredStringField(raw, 'relayerKeyId');
  if (!relayerKeyId.ok) return relayerKeyId;
  const thresholdSessionId = requiredStringField(raw, 'thresholdSessionId');
  if (!thresholdSessionId.ok) return thresholdSessionId;
  const signingGrantId = requiredStringField(raw, 'signingGrantId');
  if (!signingGrantId.ok) return signingGrantId;
  if (
    typeof raw.ttlMs !== 'number' ||
    !Number.isSafeInteger(raw.ttlMs) ||
    raw.ttlMs <= 0 ||
    raw.ttlMs > MAX_WALLET_SESSION_TTL_MS
  ) {
    return invalidThresholdEd25519Body('sessionPolicy.ttlMs is required');
  }
  if (
    typeof raw.remainingUses !== 'number' ||
    !Number.isSafeInteger(raw.remainingUses) ||
    raw.remainingUses <= 0 ||
    raw.remainingUses > MAX_WALLET_SESSION_REMAINING_USES
  ) {
    return invalidThresholdEd25519Body('sessionPolicy.remainingUses is required');
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  if (!participantIds || participantIds.length !== 2 || participantIds[0] === participantIds[1]) {
    return invalidThresholdEd25519Body(
      'sessionPolicy.participantIds must contain exactly two distinct participants',
    );
  }
  let runtimePolicyScope: RouterAbEd25519YaoSessionPolicyV1['runtimePolicyScope'];
  try {
    runtimePolicyScope = normalizeRuntimePolicyScope(raw.runtimePolicyScope);
  } catch {
    return invalidThresholdEd25519Body('sessionPolicy.runtimePolicyScope is required');
  }
  const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(raw.routerAbNormalSigning);
  if (!routerAbNormalSigning) {
    return invalidThresholdEd25519Body('sessionPolicy.routerAbNormalSigning is required');
  }
  return {
    ok: true,
    request: {
      version: 'threshold_session_v1',
      nearAccountId: nearAccountId.request,
      nearEd25519SigningKeyId: nearEd25519SigningKeyId.request,
      authority,
      relayerKeyId: relayerKeyId.request,
      thresholdSessionId: thresholdSessionId.request,
      signingGrantId: signingGrantId.request,
      runtimePolicyScope,
      routerAbNormalSigning,
      participantIds: [participantIds[0]!, participantIds[1]!],
      ttlMs: raw.ttlMs,
      remainingUses: raw.remainingUses,
    },
  };
}

export function parseThresholdEd25519SessionRouteRequest(
  raw: unknown,
): ThresholdEd25519RouteParseResult<RouterAbEd25519YaoSessionRouteCommandV1> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('Expected JSON object body');
  if (raw.sessionKind !== 'jwt') {
    return invalidThresholdEd25519Body(
      'Router A/B Ed25519 Wallet Session issuance requires sessionKind=jwt',
    );
  }
  const unsupported = findUnexpectedRouteKey(raw, SESSION_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(
      `Unsupported threshold-ed25519 session field: ${unsupported}`,
    );
  }
  const relayerKeyId = requiredStringField(raw, 'relayerKeyId');
  if (!relayerKeyId.ok) return relayerKeyId;
  const sessionPolicy = parseRouterAbEd25519YaoSessionPolicyV1(raw.sessionPolicy);
  if (!sessionPolicy.ok) return sessionPolicy;
  if (sessionPolicy.request.relayerKeyId !== relayerKeyId.request) {
    return invalidThresholdEd25519Body('relayerKeyId must match sessionPolicy.relayerKeyId');
  }
  const webauthnAuthentication = parseOptionalWebAuthnAuthentication(raw);
  if (!webauthnAuthentication.ok) return webauthnAuthentication;
  const projectEnvironmentId = optionalStringField(raw, 'projectEnvironmentId');
  return {
    ok: true,
    request: {
      relayerKeyId: relayerKeyId.request,
      sessionPolicy: sessionPolicy.request,
      ...(projectEnvironmentId ? { projectEnvironmentId } : {}),
      routeAuth: webauthnAuthentication.request
        ? {
            kind: 'passkey',
            webauthnAuthentication: webauthnAuthentication.request,
          }
        : { kind: 'signed_session' },
      sessionKind: 'jwt',
    },
  };
}
