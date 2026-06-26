import { base64UrlDecode } from '@shared/utils/encoders';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { isPlainObject } from '@shared/utils/validation';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type {
  Ed25519SessionPolicy,
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope,
  ThresholdEd25519HssFinalizeWithSessionRequest,
  ThresholdEd25519HssPrepareWithSessionRequest,
  ThresholdEd25519HssRespondWithSessionRequest,
  ThresholdEd25519HssServerVisibleClientRequestEnvelope,
  ThresholdEd25519HssSessionOperation,
  WebAuthnAuthenticationCredential,
} from '../core/types';
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

export type ThresholdEd25519SessionRouteCommand = {
  relayerKeyId: string;
  sessionPolicy: Ed25519SessionPolicy;
  runtimeEnvironmentId?: string;
  routeAuth:
    | { kind: 'signed_session_header' }
    | {
        kind: 'passkey';
        webauthnAuthentication: WebAuthnAuthenticationCredential;
      };
  sessionKind?: 'jwt';
};

const SESSION_KEYS = [
  'relayerKeyId',
  'sessionPolicy',
  'runtimeEnvironmentId',
  'webauthn_authentication',
  'sessionKind',
] as const;

const SESSION_POLICY_KEYS = [
  'version',
  'walletId',
  'nearAccountId',
  'nearEd25519SigningKeyId',
  'rpId',
  'relayerKeyId',
  'thresholdSessionId',
  'signingGrantId',
  'runtimePolicyScope',
  'routerAbNormalSigning',
  'participantIds',
  'ttlMs',
  'remainingUses',
] as const;

const HSS_PREPARE_KEYS = ['relayerKeyId', 'operation', 'context', 'sessionKind'] as const;
const HSS_RESPOND_KEYS = ['ceremonyHandle', 'clientRequest', 'sessionKind'] as const;
const HSS_FINALIZE_KEYS = ['ceremonyHandle', 'evaluationResult', 'sessionKind'] as const;
const HSS_CONTEXT_KEYS = ['applicationBindingDigestB64u', 'participantIds'] as const;
const CLIENT_REQUEST_KEYS = ['clientRequestMessageB64u'] as const;
const EVALUATION_RESULT_KEYS = ['contextBindingB64u', 'stagedEvaluatorArtifactB64u'] as const;

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

function optionalWebAuthnAuthentication(
  record: Record<string, unknown>,
): WebAuthnAuthenticationCredential | undefined {
  return parseWebAuthnAuthenticationCredential(record.webauthn_authentication) || undefined;
}

function optionalSessionKind(record: Record<string, unknown>): 'jwt' | undefined {
  return record.sessionKind === 'jwt' ? 'jwt' : undefined;
}

function rejectNonJwtSessionKind(
  record: Record<string, unknown>,
  message: string,
): ThresholdEd25519RouteParseError | null {
  if (record.sessionKind === undefined || record.sessionKind === 'jwt') return null;
  return invalidThresholdEd25519Body(message);
}

function isHssSessionOperation(value: unknown): value is ThresholdEd25519HssSessionOperation {
  switch (value) {
    case 'tx_signing':
    case 'link_device':
    case 'email_recovery':
    case 'warm_session_reconstruction':
    case 'explicit_key_export':
      return true;
    default:
      return false;
  }
}

function parseEd25519SessionPolicy(raw: unknown): ThresholdEd25519RouteParseResult<Ed25519SessionPolicy> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('sessionPolicy is required');
  const unsupported = findUnexpectedRouteKey(raw, SESSION_POLICY_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(`Unsupported threshold-ed25519 sessionPolicy field: ${unsupported}`);
  }
  if (raw.version !== 'threshold_session_v1') {
    return invalidThresholdEd25519Body('sessionPolicy.version must be threshold_session_v1');
  }
  const walletId = requiredStringField(raw, 'walletId');
  if (!walletId.ok) return walletId;
  const nearAccountId = requiredStringField(raw, 'nearAccountId');
  if (!nearAccountId.ok) return nearAccountId;
  const nearEd25519SigningKeyId = requiredStringField(raw, 'nearEd25519SigningKeyId');
  if (!nearEd25519SigningKeyId.ok) return nearEd25519SigningKeyId;
  const rpId = requiredStringField(raw, 'rpId');
  if (!rpId.ok) return rpId;
  const relayerKeyId = requiredStringField(raw, 'relayerKeyId');
  if (!relayerKeyId.ok) return relayerKeyId;
  const thresholdSessionId = requiredStringField(raw, 'thresholdSessionId');
  if (!thresholdSessionId.ok) return thresholdSessionId;
  if (typeof raw.ttlMs !== 'number' || !Number.isFinite(raw.ttlMs)) {
    return invalidThresholdEd25519Body('sessionPolicy.ttlMs is required');
  }
  if (typeof raw.remainingUses !== 'number' || !Number.isFinite(raw.remainingUses)) {
    return invalidThresholdEd25519Body('sessionPolicy.remainingUses is required');
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  let runtimePolicyScope: Ed25519SessionPolicy['runtimePolicyScope'];
  if (raw.runtimePolicyScope !== undefined) {
    try {
      runtimePolicyScope = normalizeRuntimePolicyScope(raw.runtimePolicyScope);
    } catch {
      return invalidThresholdEd25519Body('sessionPolicy.runtimePolicyScope is invalid');
    }
  }
  const routerAbNormalSigning =
    raw.routerAbNormalSigning === undefined
      ? undefined
      : parseRouterAbEd25519NormalSigningState(raw.routerAbNormalSigning);
  if (raw.routerAbNormalSigning !== undefined && !routerAbNormalSigning) {
    return invalidThresholdEd25519Body('sessionPolicy.routerAbNormalSigning is invalid');
  }
  return {
    ok: true,
    request: {
      version: 'threshold_session_v1',
      walletId: walletId.request,
      nearAccountId: nearAccountId.request,
      nearEd25519SigningKeyId: nearEd25519SigningKeyId.request,
      rpId: rpId.request,
      relayerKeyId: relayerKeyId.request,
      thresholdSessionId: thresholdSessionId.request,
      ...(optionalStringField(raw, 'signingGrantId')
        ? { signingGrantId: optionalStringField(raw, 'signingGrantId') }
        : {}),
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      ...(routerAbNormalSigning ? { routerAbNormalSigning } : {}),
      ...(participantIds ? { participantIds } : {}),
      ttlMs: raw.ttlMs,
      remainingUses: raw.remainingUses,
    },
  };
}

function parseHssContext(raw: unknown): ThresholdEd25519RouteParseResult<ThresholdEd25519HssCanonicalContext> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('context is required');
  const unsupported = findUnexpectedRouteKey(raw, HSS_CONTEXT_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(`Unsupported threshold-ed25519 HSS context field: ${unsupported}`);
  }
  const applicationBindingDigestB64u = requiredStringField(raw, 'applicationBindingDigestB64u');
  if (!applicationBindingDigestB64u.ok) return applicationBindingDigestB64u;
  try {
    if (base64UrlDecode(applicationBindingDigestB64u.request).length !== 32) {
      return invalidThresholdEd25519Body('context.applicationBindingDigestB64u must decode to 32 bytes');
    }
  } catch {
    return invalidThresholdEd25519Body('context.applicationBindingDigestB64u must be valid base64url');
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds(raw.participantIds);
  if (!participantIds || participantIds.length < 2) {
    return invalidThresholdEd25519Body('context.participantIds is required');
  }
  return {
    ok: true,
    request: {
      applicationBindingDigestB64u: applicationBindingDigestB64u.request,
      participantIds,
    },
  };
}

function parseClientRequestEnvelope(
  raw: unknown,
): ThresholdEd25519RouteParseResult<ThresholdEd25519HssServerVisibleClientRequestEnvelope> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('clientRequest is required');
  const unsupported = findUnexpectedRouteKey(raw, CLIENT_REQUEST_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(`Unsupported threshold-ed25519 clientRequest field: ${unsupported}`);
  }
  const clientRequestMessageB64u = requiredStringField(raw, 'clientRequestMessageB64u');
  if (!clientRequestMessageB64u.ok) return clientRequestMessageB64u;
  return { ok: true, request: { clientRequestMessageB64u: clientRequestMessageB64u.request } };
}

function parseEvaluationResultEnvelope(
  raw: unknown,
): ThresholdEd25519RouteParseResult<ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('evaluationResult is required');
  const unsupported = findUnexpectedRouteKey(raw, EVALUATION_RESULT_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(`Unsupported threshold-ed25519 evaluationResult field: ${unsupported}`);
  }
  const contextBindingB64u = requiredStringField(raw, 'contextBindingB64u');
  if (!contextBindingB64u.ok) return contextBindingB64u;
  const stagedEvaluatorArtifactB64u = requiredStringField(raw, 'stagedEvaluatorArtifactB64u');
  if (!stagedEvaluatorArtifactB64u.ok) return stagedEvaluatorArtifactB64u;
  return {
    ok: true,
    request: {
      contextBindingB64u: contextBindingB64u.request,
      stagedEvaluatorArtifactB64u: stagedEvaluatorArtifactB64u.request,
    },
  };
}

export function parseThresholdEd25519SessionRouteRequest(
  raw: unknown,
): ThresholdEd25519RouteParseResult<ThresholdEd25519SessionRouteCommand> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('Expected JSON object body');
  const sessionKindError = rejectNonJwtSessionKind(
    raw,
    'Router A/B Ed25519 Wallet Session issuance requires sessionKind=jwt',
  );
  if (sessionKindError) return sessionKindError;
  const unsupported = findUnexpectedRouteKey(raw, SESSION_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(`Unsupported threshold-ed25519 session field: ${unsupported}`);
  }
  const relayerKeyId = requiredStringField(raw, 'relayerKeyId');
  if (!relayerKeyId.ok) return relayerKeyId;
  const sessionPolicy = parseEd25519SessionPolicy(raw.sessionPolicy);
  if (!sessionPolicy.ok) return sessionPolicy;
  const webauthnAuthentication = optionalWebAuthnAuthentication(raw);
  if (raw.webauthn_authentication !== undefined && !webauthnAuthentication) {
    return invalidThresholdEd25519Body('webauthn_authentication is invalid');
  }
  return {
    ok: true,
    request: {
      relayerKeyId: relayerKeyId.request,
      sessionPolicy: sessionPolicy.request,
      ...(optionalStringField(raw, 'runtimeEnvironmentId')
        ? { runtimeEnvironmentId: optionalStringField(raw, 'runtimeEnvironmentId') }
        : {}),
      routeAuth: webauthnAuthentication
        ? {
            kind: 'passkey',
            webauthnAuthentication,
          }
        : { kind: 'signed_session_header' },
      ...(optionalSessionKind(raw) ? { sessionKind: 'jwt' } : {}),
    },
  };
}

export function parseThresholdEd25519HssPrepareWithSessionRouteRequest(
  raw: unknown,
): ThresholdEd25519RouteParseResult<ThresholdEd25519HssPrepareWithSessionRequest> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('Expected JSON object body');
  const sessionKindError = rejectNonJwtSessionKind(
    raw,
    'Router A/B Ed25519 HSS requires sessionKind=jwt',
  );
  if (sessionKindError) return sessionKindError;
  const unsupported = findUnexpectedRouteKey(raw, HSS_PREPARE_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(`Unsupported threshold-ed25519 HSS prepare field: ${unsupported}`);
  }
  const relayerKeyId = requiredStringField(raw, 'relayerKeyId');
  if (!relayerKeyId.ok) return relayerKeyId;
  if (!isHssSessionOperation(raw.operation)) {
    return invalidThresholdEd25519Body('operation is required');
  }
  const context = parseHssContext(raw.context);
  if (!context.ok) return context;
  return {
    ok: true,
    request: {
      relayerKeyId: relayerKeyId.request,
      operation: raw.operation,
      context: context.request,
    },
  };
}

export function parseThresholdEd25519HssRespondWithSessionRouteRequest(
  raw: unknown,
): ThresholdEd25519RouteParseResult<ThresholdEd25519HssRespondWithSessionRequest> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('Expected JSON object body');
  const sessionKindError = rejectNonJwtSessionKind(
    raw,
    'Router A/B Ed25519 HSS requires sessionKind=jwt',
  );
  if (sessionKindError) return sessionKindError;
  const unsupported = findUnexpectedRouteKey(raw, HSS_RESPOND_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(`Unsupported threshold-ed25519 HSS respond field: ${unsupported}`);
  }
  const ceremonyHandle = requiredStringField(raw, 'ceremonyHandle');
  if (!ceremonyHandle.ok) return ceremonyHandle;
  const clientRequest = parseClientRequestEnvelope(raw.clientRequest);
  if (!clientRequest.ok) return clientRequest;
  return {
    ok: true,
    request: {
      ceremonyHandle: ceremonyHandle.request,
      clientRequest: clientRequest.request,
    },
  };
}

export function parseThresholdEd25519HssFinalizeWithSessionRouteRequest(
  raw: unknown,
): ThresholdEd25519RouteParseResult<ThresholdEd25519HssFinalizeWithSessionRequest> {
  if (!isPlainObject(raw)) return invalidThresholdEd25519Body('Expected JSON object body');
  const sessionKindError = rejectNonJwtSessionKind(
    raw,
    'Router A/B Ed25519 HSS requires sessionKind=jwt',
  );
  if (sessionKindError) return sessionKindError;
  const unsupported = findUnexpectedRouteKey(raw, HSS_FINALIZE_KEYS);
  if (unsupported) {
    return invalidThresholdEd25519Body(`Unsupported threshold-ed25519 HSS finalize field: ${unsupported}`);
  }
  const ceremonyHandle = requiredStringField(raw, 'ceremonyHandle');
  if (!ceremonyHandle.ok) return ceremonyHandle;
  const evaluationResult = parseEvaluationResultEnvelope(raw.evaluationResult);
  if (!evaluationResult.ok) return evaluationResult;
  return {
    ok: true,
    request: {
      ceremonyHandle: ceremonyHandle.request,
      evaluationResult: evaluationResult.request,
    },
  };
}
