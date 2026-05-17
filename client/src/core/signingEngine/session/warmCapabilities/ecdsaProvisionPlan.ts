import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { decodeJwtPayloadRecord } from '@shared/utils/sessionTokens';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import type {
  ThresholdRuntimePolicyScope,
  ThresholdSessionKind,
} from '../../threshold/sessionPolicy';
import {
  SigningSessionIds,
  type ThresholdEcdsaSessionId,
  type WalletSigningSessionId,
} from '../operationState/types';

export type EcdsaSessionIdentity = {
  thresholdSessionId: ThresholdEcdsaSessionId;
  walletSigningSessionId: WalletSigningSessionId;
};

export type EcdsaSigningKeyContext = {
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  participantIds: readonly number[];
};

export type VerifiedEcdsaThresholdSessionAuth = {
  kind: 'threshold_session';
  curve: 'ecdsa';
  identity: EcdsaSessionIdentity;
  thresholdSessionAuthToken: string;
  expiresAtMs: number;

  // Curve-specific fields.
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  ed25519RelayerKeyId?: never;
};

export type PasskeyEcdsaSessionProvision = {
  kind: 'passkey_ecdsa_session_provision';
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  newSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: ThresholdSessionKind;
  sessionBudgetUses: number;

  // Branch-specific fields.
  clientRootShare32B64u: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  thresholdSessionAuth?: never;
  emailOtpAuthContext?: never;
};

export type ThresholdSessionAuthEcdsaReconnect = {
  kind: 'threshold_session_auth_ecdsa_reconnect';
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  existingSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: 'jwt';
  sessionBudgetUses: number;

  // Branch-specific fields.
  thresholdSessionAuth: VerifiedEcdsaThresholdSessionAuth;
  webauthnAuthentication?: never;
  clientRootShare32B64u?: never;
  emailOtpAuthContext?: never;
};

export type CookieEcdsaReconnect = {
  kind: 'cookie_ecdsa_reconnect';
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  existingSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: 'cookie';
  sessionBudgetUses: number;

  // Branch-specific fields.
  thresholdSessionAuth?: never;
  webauthnAuthentication?: never;
  clientRootShare32B64u?: never;
  emailOtpAuthContext?: never;
};

export type EmailOtpEcdsaSessionProvision = {
  kind: 'email_otp_ecdsa_session_provision';
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  newSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: ThresholdSessionKind;
  sessionBudgetUses: number;

  // Branch-specific fields.
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  clientRootShare32B64u: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  webauthnAuthentication?: never;
  thresholdSessionAuth?: never;
};

export type EcdsaSessionProvisionPlan =
  | PasskeyEcdsaSessionProvision
  | ThresholdSessionAuthEcdsaReconnect
  | CookieEcdsaReconnect
  | EmailOtpEcdsaSessionProvision;

export type EcdsaReconnectMaterial = {
  kind: 'record_and_key_ref';
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  record: ThresholdEcdsaSessionRecord;
};

type BuildPasskeyEcdsaSessionProvisionPlanArgs = {
  kind: 'passkey_ecdsa_session_provision';
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  sessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: ThresholdSessionKind;
  sessionBudgetUses: number;
  clientRootShare32B64u: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  emailOtpAuthContext?: never;
  reconnectMaterial?: never;
};

type BuildEmailOtpEcdsaSessionProvisionPlanArgs = {
  kind: 'email_otp_ecdsa_session_provision';
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  sessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: ThresholdSessionKind;
  sessionBudgetUses: number;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  clientRootShare32B64u: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  webauthnAuthentication?: never;
  reconnectMaterial?: never;
};

type BuildReconnectEcdsaSessionProvisionPlanArgs = {
  kind: 'ecdsa_session_reconnect';
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  sessionIdentity: EcdsaSessionIdentity;
  sessionBudgetUses: number;
  reconnectMaterial: EcdsaReconnectMaterial;
  signingKeyContext?: never;
  sessionKind?: never;
  runtimePolicyScope?: never;
  clientRootShare32B64u?: never;
  webauthnAuthentication?: never;
  emailOtpAuthContext?: never;
};

export type BuildEcdsaSessionProvisionPlanArgs =
  | BuildPasskeyEcdsaSessionProvisionPlanArgs
  | BuildEmailOtpEcdsaSessionProvisionPlanArgs
  | BuildReconnectEcdsaSessionProvisionPlanArgs;

export function getEcdsaSessionProvisionIdentity(
  plan: EcdsaSessionProvisionPlan,
): EcdsaSessionIdentity {
  return 'newSessionIdentity' in plan ? plan.newSessionIdentity : plan.existingSessionIdentity;
}

function requireNonEmptyString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`[SigningEngine][ecdsa] ${field} is required`);
  }
  return normalized;
}

function requirePositiveInteger(value: unknown, field: string): number {
  const normalized = Math.floor(Number(value) || 0);
  if (normalized <= 0) {
    throw new Error(`[SigningEngine][ecdsa] ${field} must be a positive integer`);
  }
  return normalized;
}

function requireParticipantIds(
  value: unknown,
  field: string,
): readonly number[] {
  const normalized = normalizeThresholdEd25519ParticipantIds(value);
  if (!normalized?.length) {
    throw new Error(`[SigningEngine][ecdsa] ${field} is required`);
  }
  return normalized;
}

function participantIdsKey(value: readonly number[]): string {
  return normalizeThresholdEd25519ParticipantIds([...value])?.join(',') || '';
}

function signingRootVersionKey(value: unknown): string {
  return String(value ?? '').trim() || 'default';
}

function requireMatchingSigningKeyContext(args: {
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
}): EcdsaSigningKeyContext {
  const recordContext = buildEcdsaSigningKeyContext({ record: args.record });
  const keyRefContext = buildEcdsaSigningKeyContext({ keyRef: args.keyRef });
  if (
    recordContext.ecdsaThresholdKeyId !== keyRefContext.ecdsaThresholdKeyId ||
    recordContext.signingRootId !== keyRefContext.signingRootId ||
    signingRootVersionKey(recordContext.signingRootVersion) !==
      signingRootVersionKey(keyRefContext.signingRootVersion) ||
    participantIdsKey(recordContext.participantIds) !==
      participantIdsKey(keyRefContext.participantIds)
  ) {
    throw new Error('[SigningEngine][ecdsa] reconnect material has mismatched key identity');
  }
  const participantIds = normalizeThresholdEd25519ParticipantIds([
    ...keyRefContext.participantIds,
  ]);
  if (!participantIds?.length) {
    throw new Error('[SigningEngine][ecdsa] reconnect material has invalid participant ids');
  }
  return {
    ecdsaThresholdKeyId: keyRefContext.ecdsaThresholdKeyId,
    signingRootId: keyRefContext.signingRootId,
    signingRootVersion: signingRootVersionKey(keyRefContext.signingRootVersion),
    participantIds,
  };
}

function normalizeThresholdSessionKind(value: unknown): ThresholdSessionKind {
  return String(value ?? '').trim() === 'cookie' ? 'cookie' : 'jwt';
}

export function buildEcdsaSessionIdentity(args: {
  thresholdSessionId: unknown;
  walletSigningSessionId: unknown;
}): EcdsaSessionIdentity {
  return {
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(args.thresholdSessionId),
    walletSigningSessionId: SigningSessionIds.walletSigningSession(args.walletSigningSessionId),
  };
}

export function tryBuildEcdsaSessionIdentity(args: {
  thresholdSessionId: unknown;
  walletSigningSessionId: unknown;
}): EcdsaSessionIdentity | null {
  try {
    return buildEcdsaSessionIdentity(args);
  } catch {
    return null;
  }
}

export function ecdsaSessionIdentitiesEqual(
  left: EcdsaSessionIdentity,
  right: EcdsaSessionIdentity,
): boolean {
  return (
    left.thresholdSessionId === right.thresholdSessionId &&
    left.walletSigningSessionId === right.walletSigningSessionId
  );
}

export function ecdsaSessionIdentityMatches(
  identity: EcdsaSessionIdentity,
  candidate: { thresholdSessionId: unknown; walletSigningSessionId: unknown },
): boolean {
  const candidateIdentity = tryBuildEcdsaSessionIdentity(candidate);
  return Boolean(candidateIdentity && ecdsaSessionIdentitiesEqual(identity, candidateIdentity));
}

function tryBuildEcdsaSessionIdentityFromClaims(
  claims: Record<string, unknown>,
): EcdsaSessionIdentity | null {
  return tryBuildEcdsaSessionIdentity({
    thresholdSessionId: claims.sessionId,
    walletSigningSessionId: claims.walletSigningSessionId,
  });
}

export function buildEcdsaSigningKeyContext(args: {
  keyRef?: ThresholdEcdsaSecp256k1KeyRef | null;
  record?: ThresholdEcdsaSessionRecord | null;
}): EcdsaSigningKeyContext {
  const keyRef = args.keyRef;
  const record = args.record;
  return {
    ecdsaThresholdKeyId: requireNonEmptyString(
      keyRef?.ecdsaThresholdKeyId || record?.ecdsaThresholdKeyId,
      'ecdsaThresholdKeyId',
    ),
    signingRootId: requireNonEmptyString(
      keyRef?.signingRootId || record?.signingRootId,
      'signingRootId',
    ),
    signingRootVersion: requireNonEmptyString(
      keyRef?.signingRootVersion || record?.signingRootVersion,
      'signingRootVersion',
    ),
    participantIds: requireParticipantIds(
      keyRef?.participantIds || record?.participantIds,
      'participantIds',
    ),
  };
}

export function buildEcdsaReconnectMaterial(args: {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  record: ThresholdEcdsaSessionRecord;
}): EcdsaReconnectMaterial {
  const recordIdentity = buildEcdsaSessionIdentity(args.record);
  const keyRefIdentity = buildEcdsaSessionIdentity(args.keyRef);
  if (!ecdsaSessionIdentitiesEqual(recordIdentity, keyRefIdentity)) {
    throw new Error('[SigningEngine][ecdsa] reconnect material has mismatched session identity');
  }
  if (String(args.record.subjectId) !== String(args.keyRef.subjectId)) {
    throw new Error('[SigningEngine][ecdsa] reconnect material has mismatched subject identity');
  }
  if (!thresholdEcdsaChainTargetsEqual(args.record.chainTarget, args.keyRef.chainTarget)) {
    throw new Error(
      [
        '[SigningEngine][ecdsa] reconnect material has mismatched chain target',
        `record=${thresholdEcdsaChainTargetKey(args.record.chainTarget)}`,
        `keyRef=${thresholdEcdsaChainTargetKey(args.keyRef.chainTarget)}`,
      ].join(' '),
    );
  }
  requireMatchingSigningKeyContext({ record: args.record, keyRef: args.keyRef });
  return {
    kind: 'record_and_key_ref',
    keyRef: args.keyRef,
    record: args.record,
  };
}

function verifyEcdsaThresholdSessionAuth(args: {
  identity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  thresholdSessionAuthToken: string;
  relayerKeyId: string;
}): VerifiedEcdsaThresholdSessionAuth {
  const thresholdSessionAuthToken = requireNonEmptyString(
    args.thresholdSessionAuthToken,
    'thresholdSessionAuthToken',
  );
  const claims = decodeJwtPayloadRecord(thresholdSessionAuthToken);
  if (!claims) {
    throw new Error('[SigningEngine][ecdsa] threshold session auth token is invalid');
  }
  const claimIdentity = tryBuildEcdsaSessionIdentityFromClaims(claims);
  if (
    !claimIdentity ||
    !ecdsaSessionIdentitiesEqual(claimIdentity, args.identity)
  ) {
    throw new Error(
      '[SigningEngine][ecdsa] threshold session auth token does not match planned reconnect identity',
    );
  }
  const expSeconds = Math.floor(Number(claims.exp) || 0);
  return {
    kind: 'threshold_session',
    curve: 'ecdsa',
    identity: args.identity,
    thresholdSessionAuthToken,
    expiresAtMs: expSeconds > 0 ? expSeconds * 1000 : 0,

    // Curve-specific fields.
    ecdsaThresholdKeyId: args.signingKeyContext.ecdsaThresholdKeyId,
    relayerKeyId: requireNonEmptyString(args.relayerKeyId, 'relayerKeyId'),
  };
}

function selectReconnectThresholdSessionAuthToken(args: {
  identity: EcdsaSessionIdentity;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef | null;
  record?: ThresholdEcdsaSessionRecord | null;
}): string | null {
  const candidates = [
    String(args.keyRef?.thresholdSessionAuthToken || '').trim(),
    String(args.record?.thresholdSessionAuthToken || '').trim(),
  ].filter(Boolean);
  for (const token of candidates) {
    const claims = decodeJwtPayloadRecord(token);
    if (!claims) continue;
    const claimIdentity = tryBuildEcdsaSessionIdentityFromClaims(claims);
    if (claimIdentity && ecdsaSessionIdentitiesEqual(claimIdentity, args.identity)) {
      return token;
    }
  }
  return candidates[0] || null;
}

export function buildPasskeyEcdsaSessionProvision(args: {
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  newSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: ThresholdSessionKind;
  sessionBudgetUses: number;
  clientRootShare32B64u: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): PasskeyEcdsaSessionProvision {
  return {
    kind: 'passkey_ecdsa_session_provision',
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
    newSessionIdentity: args.newSessionIdentity,
    signingKeyContext: args.signingKeyContext,
    sessionKind: normalizeThresholdSessionKind(args.sessionKind),
    sessionBudgetUses: requirePositiveInteger(args.sessionBudgetUses, 'sessionBudgetUses'),

    // Branch-specific fields.
    clientRootShare32B64u: requireNonEmptyString(
      args.clientRootShare32B64u,
      'clientRootShare32B64u',
    ),
    webauthnAuthentication: args.webauthnAuthentication,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
  } satisfies PasskeyEcdsaSessionProvision;
}

export function buildThresholdSessionAuthEcdsaReconnect(args: {
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  existingSessionIdentity: EcdsaSessionIdentity;
  sessionBudgetUses: number;
  reconnectMaterial: EcdsaReconnectMaterial;
}): ThresholdSessionAuthEcdsaReconnect | CookieEcdsaReconnect {
  const keyRef = args.reconnectMaterial.keyRef;
  const record = args.reconnectMaterial.record;
  const signingKeyContext = requireMatchingSigningKeyContext({ record, keyRef });
  const sessionKind = normalizeThresholdSessionKind(
    keyRef.thresholdSessionKind || record.thresholdSessionKind,
  );
  if (sessionKind === 'cookie') {
    return {
      kind: 'cookie_ecdsa_reconnect',
      subjectId: args.subjectId,
      chainTarget: args.chainTarget,
      existingSessionIdentity: args.existingSessionIdentity,
      signingKeyContext,
      sessionKind: 'cookie',
      sessionBudgetUses: requirePositiveInteger(args.sessionBudgetUses, 'sessionBudgetUses'),
    } satisfies CookieEcdsaReconnect;
  }
  const thresholdSessionAuthToken = selectReconnectThresholdSessionAuthToken({
    identity: args.existingSessionIdentity,
    keyRef,
    record,
  });
  const relayerKeyId = requireNonEmptyString(
    record?.relayerKeyId || keyRef?.backendBinding?.relayerKeyId,
    'relayerKeyId',
  );
  return {
    kind: 'threshold_session_auth_ecdsa_reconnect',
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
    existingSessionIdentity: args.existingSessionIdentity,
    signingKeyContext,
    sessionKind: 'jwt',
    sessionBudgetUses: requirePositiveInteger(args.sessionBudgetUses, 'sessionBudgetUses'),

    // Branch-specific fields.
    thresholdSessionAuth: verifyEcdsaThresholdSessionAuth({
      identity: args.existingSessionIdentity,
      signingKeyContext,
      thresholdSessionAuthToken: requireNonEmptyString(
        thresholdSessionAuthToken,
        'thresholdSessionAuthToken',
      ),
      relayerKeyId,
    }),
  } satisfies ThresholdSessionAuthEcdsaReconnect;
}

export function buildEmailOtpEcdsaSessionProvision(args: {
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  newSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: ThresholdSessionKind;
  sessionBudgetUses: number;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  clientRootShare32B64u: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): EmailOtpEcdsaSessionProvision {
  return {
    kind: 'email_otp_ecdsa_session_provision',
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
    newSessionIdentity: args.newSessionIdentity,
    signingKeyContext: args.signingKeyContext,
    sessionKind: normalizeThresholdSessionKind(args.sessionKind),
    sessionBudgetUses: requirePositiveInteger(args.sessionBudgetUses, 'sessionBudgetUses'),

    // Branch-specific fields.
    emailOtpAuthContext: args.emailOtpAuthContext,
    clientRootShare32B64u: requireNonEmptyString(
      args.clientRootShare32B64u,
      'clientRootShare32B64u',
    ),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
  } satisfies EmailOtpEcdsaSessionProvision;
}

export function buildEcdsaSessionProvisionPlan(
  args: BuildEcdsaSessionProvisionPlanArgs,
): EcdsaSessionProvisionPlan {
  switch (args.kind) {
    case 'email_otp_ecdsa_session_provision':
      return buildEmailOtpEcdsaSessionProvision({
        subjectId: args.subjectId,
        chainTarget: args.chainTarget,
        newSessionIdentity: args.sessionIdentity,
        signingKeyContext: args.signingKeyContext,
        sessionKind: args.sessionKind,
        sessionBudgetUses: args.sessionBudgetUses,
        emailOtpAuthContext: args.emailOtpAuthContext,
        clientRootShare32B64u: requireNonEmptyString(
          args.clientRootShare32B64u,
          'clientRootShare32B64u',
        ),
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      });
    case 'passkey_ecdsa_session_provision':
      return buildPasskeyEcdsaSessionProvision({
        subjectId: args.subjectId,
        chainTarget: args.chainTarget,
        newSessionIdentity: args.sessionIdentity,
        signingKeyContext: args.signingKeyContext,
        sessionKind: args.sessionKind,
        sessionBudgetUses: args.sessionBudgetUses,
        clientRootShare32B64u: requireNonEmptyString(
          args.clientRootShare32B64u,
          'clientRootShare32B64u',
        ),
        webauthnAuthentication: args.webauthnAuthentication,
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      });
    case 'ecdsa_session_reconnect':
      return buildThresholdSessionAuthEcdsaReconnect({
        subjectId: args.subjectId,
        chainTarget: args.chainTarget,
        existingSessionIdentity: args.sessionIdentity,
        sessionBudgetUses: args.sessionBudgetUses,
        reconnectMaterial: args.reconnectMaterial,
      });
  }
  args satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported ECDSA provision plan kind');
}
