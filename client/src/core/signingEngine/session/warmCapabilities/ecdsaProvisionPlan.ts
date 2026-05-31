import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { decodeJwtPayloadRecord } from '@shared/utils/sessionTokens';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaEmailOtpAuthContext } from '../identity/laneIdentity';
import {
  resolveThresholdEcdsaKeyIdFromRecord,
  resolveThresholdSigningRootBindingFromRecord,
  type EvmFamilyEcdsaKeyIdentity,
} from '../identity/evmFamilyEcdsaIdentity';
import { buildThresholdEcdsaSecp256k1KeyRefFromRecord } from '../identity/thresholdEcdsaSignerAdapter';
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

export type PasskeyEcdsaProvisionSecretSource = {
  kind: 'webauthn_prf_first_client_root_share_v1';
  clientRootShare32B64u: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  emailOtpAuthContext?: never;
};

export type EmailOtpEcdsaProvisionSecretSource = {
  kind: 'email_otp_worker_client_root_share_v1';
  clientRootShare32B64u: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  webauthnAuthentication?: never;
};

export type PasskeyEcdsaSessionProvision = {
  kind: 'passkey_ecdsa_session_provision';
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  newSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: ThresholdSessionKind;
  sessionBudgetUses: number;
  requestId: string;

  // Branch-specific fields.
  provisionSecretSource: PasskeyEcdsaProvisionSecretSource;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  thresholdSessionAuth?: never;
  emailOtpAuthContext?: never;
  clientRootShare32B64u?: never;
  webauthnAuthentication?: never;
};

export type ThresholdSessionAuthEcdsaReconnect = {
  kind: 'threshold_session_auth_ecdsa_reconnect';
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
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  newSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: ThresholdSessionKind;
  sessionBudgetUses: number;

  // Branch-specific fields.
  provisionSecretSource: EmailOtpEcdsaProvisionSecretSource;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  emailOtpAuthContext?: never;
  clientRootShare32B64u?: never;
  webauthnAuthentication?: never;
  thresholdSessionAuth?: never;
};

export type EcdsaSessionProvisionPlan =
  | PasskeyEcdsaSessionProvision
  | ThresholdSessionAuthEcdsaReconnect
  | CookieEcdsaReconnect
  | EmailOtpEcdsaSessionProvision;

export type EcdsaReconnectMaterial = {
  kind: 'ecdsa_session_record';
  record: ThresholdEcdsaSessionRecord;
  keyRef?: never;
};

type BuildPasskeyEcdsaSessionProvisionPlanArgs = {
  kind: 'passkey_ecdsa_session_provision';
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  sessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: ThresholdSessionKind;
  sessionBudgetUses: number;
  requestId: string;
  provisionSecretSource: PasskeyEcdsaProvisionSecretSource;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  emailOtpAuthContext?: never;
  reconnectMaterial?: never;
  clientRootShare32B64u?: never;
  webauthnAuthentication?: never;
};

type BuildEmailOtpEcdsaSessionProvisionPlanArgs = {
  kind: 'email_otp_ecdsa_session_provision';
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  sessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: ThresholdSessionKind;
  sessionBudgetUses: number;
  provisionSecretSource: EmailOtpEcdsaProvisionSecretSource;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  emailOtpAuthContext?: never;
  clientRootShare32B64u?: never;
  webauthnAuthentication?: never;
  reconnectMaterial?: never;
};

type BuildReconnectEcdsaSessionProvisionPlanArgs = {
  kind: 'ecdsa_session_reconnect';
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

export function buildPasskeyEcdsaProvisionSecretSource(args: {
  clientRootShare32B64u: string;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
}): PasskeyEcdsaProvisionSecretSource {
  return {
    kind: 'webauthn_prf_first_client_root_share_v1',
    clientRootShare32B64u: requireNonEmptyString(
      args.clientRootShare32B64u,
      'clientRootShare32B64u',
    ),
    webauthnAuthentication: args.webauthnAuthentication,
  };
}

export function buildEmailOtpEcdsaProvisionSecretSource(args: {
  clientRootShare32B64u: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
}): EmailOtpEcdsaProvisionSecretSource {
  return {
    kind: 'email_otp_worker_client_root_share_v1',
    clientRootShare32B64u: requireNonEmptyString(
      args.clientRootShare32B64u,
      'clientRootShare32B64u',
    ),
    emailOtpAuthContext: args.emailOtpAuthContext,
  };
}

export function buildEcdsaSigningKeyContextFromRecord(
  record: ThresholdEcdsaSessionRecord,
): EcdsaSigningKeyContext {
  const signingRootBinding = resolveThresholdSigningRootBindingFromRecord({
    record,
  });
  return {
    ecdsaThresholdKeyId: String(resolveThresholdEcdsaKeyIdFromRecord({ record })),
    signingRootId: String(signingRootBinding.signingRootId),
    signingRootVersion: String(signingRootBinding.signingRootVersion),
    participantIds: requireParticipantIds(record.participantIds, 'participantIds'),
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

export function buildEcdsaReconnectMaterial(args: {
  record: ThresholdEcdsaSessionRecord;
}): EcdsaReconnectMaterial {
  buildEcdsaSessionIdentity(args.record);
  buildEcdsaSigningKeyContextFromRecord(args.record);
  return {
    kind: 'ecdsa_session_record',
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
  record: ThresholdEcdsaSessionRecord;
}): string | null {
  const candidates = [
    String(args.record.thresholdSessionAuthToken || '').trim(),
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
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  newSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: ThresholdSessionKind;
  sessionBudgetUses: number;
  requestId: string;
  provisionSecretSource: PasskeyEcdsaProvisionSecretSource;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): PasskeyEcdsaSessionProvision {
  return {
    kind: 'passkey_ecdsa_session_provision',
    key: args.key,
    chainTarget: args.chainTarget,
    newSessionIdentity: args.newSessionIdentity,
    signingKeyContext: args.signingKeyContext,
    sessionKind: normalizeThresholdSessionKind(args.sessionKind),
    sessionBudgetUses: requirePositiveInteger(args.sessionBudgetUses, 'sessionBudgetUses'),
    requestId: requireNonEmptyString(args.requestId, 'requestId'),

    // Branch-specific fields.
    provisionSecretSource: args.provisionSecretSource,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
  } satisfies PasskeyEcdsaSessionProvision;
}

export function buildThresholdSessionAuthEcdsaReconnect(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  existingSessionIdentity: EcdsaSessionIdentity;
  sessionBudgetUses: number;
  reconnectMaterial: EcdsaReconnectMaterial;
}): ThresholdSessionAuthEcdsaReconnect | CookieEcdsaReconnect {
  const record = args.reconnectMaterial.record;
  const keyRef = buildThresholdEcdsaSecp256k1KeyRefFromRecord({ record });
  const recordIdentity = buildEcdsaSessionIdentity(record);
  if (!ecdsaSessionIdentitiesEqual(recordIdentity, args.existingSessionIdentity)) {
    throw new Error('[SigningEngine][ecdsa] reconnect material has mismatched session identity');
  }
  if (!thresholdEcdsaChainTargetsEqual(record.chainTarget, args.chainTarget)) {
    throw new Error(
      [
        '[SigningEngine][ecdsa] reconnect material has mismatched chain target',
        `record=${thresholdEcdsaChainTargetKey(record.chainTarget)}`,
        `plan=${thresholdEcdsaChainTargetKey(args.chainTarget)}`,
      ].join(' '),
    );
  }
  const signingKeyContext = buildEcdsaSigningKeyContextFromRecord(record);
  const sessionKind = normalizeThresholdSessionKind(record.thresholdSessionKind);
  if (sessionKind === 'cookie') {
    return {
      kind: 'cookie_ecdsa_reconnect',
      chainTarget: args.chainTarget,
      existingSessionIdentity: args.existingSessionIdentity,
      signingKeyContext,
      sessionKind: 'cookie',
      sessionBudgetUses: requirePositiveInteger(args.sessionBudgetUses, 'sessionBudgetUses'),
    } satisfies CookieEcdsaReconnect;
  }
  const thresholdSessionAuthToken = selectReconnectThresholdSessionAuthToken({
    identity: args.existingSessionIdentity,
    record,
  });
  const relayerKeyId = requireNonEmptyString(
    record.relayerKeyId || keyRef.backendBinding?.relayerKeyId,
    'relayerKeyId',
  );
  return {
    kind: 'threshold_session_auth_ecdsa_reconnect',
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
  key: EvmFamilyEcdsaKeyIdentity;
  chainTarget: ThresholdEcdsaChainTarget;
  newSessionIdentity: EcdsaSessionIdentity;
  signingKeyContext: EcdsaSigningKeyContext;
  sessionKind: ThresholdSessionKind;
  sessionBudgetUses: number;
  provisionSecretSource: EmailOtpEcdsaProvisionSecretSource;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): EmailOtpEcdsaSessionProvision {
  return {
    kind: 'email_otp_ecdsa_session_provision',
    key: args.key,
    chainTarget: args.chainTarget,
    newSessionIdentity: args.newSessionIdentity,
    signingKeyContext: args.signingKeyContext,
    sessionKind: normalizeThresholdSessionKind(args.sessionKind),
    sessionBudgetUses: requirePositiveInteger(args.sessionBudgetUses, 'sessionBudgetUses'),

    // Branch-specific fields.
    provisionSecretSource: args.provisionSecretSource,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
  } satisfies EmailOtpEcdsaSessionProvision;
}

export function buildEcdsaSessionProvisionPlan(
  args: BuildEcdsaSessionProvisionPlanArgs,
): EcdsaSessionProvisionPlan {
  switch (args.kind) {
    case 'email_otp_ecdsa_session_provision':
      return buildEmailOtpEcdsaSessionProvision({
        key: args.key,
        chainTarget: args.chainTarget,
        newSessionIdentity: args.sessionIdentity,
        signingKeyContext: args.signingKeyContext,
        sessionKind: args.sessionKind,
        sessionBudgetUses: args.sessionBudgetUses,
        provisionSecretSource: args.provisionSecretSource,
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      });
    case 'passkey_ecdsa_session_provision':
      return buildPasskeyEcdsaSessionProvision({
        key: args.key,
        chainTarget: args.chainTarget,
        newSessionIdentity: args.sessionIdentity,
        signingKeyContext: args.signingKeyContext,
        sessionKind: args.sessionKind,
        sessionBudgetUses: args.sessionBudgetUses,
        requestId: args.requestId,
        provisionSecretSource: args.provisionSecretSource,
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      });
    case 'ecdsa_session_reconnect':
      return buildThresholdSessionAuthEcdsaReconnect({
        chainTarget: args.chainTarget,
        existingSessionIdentity: args.sessionIdentity,
        sessionBudgetUses: args.sessionBudgetUses,
        reconnectMaterial: args.reconnectMaterial,
      });
  }
  args satisfies never;
  throw new Error('[SigningEngine][ecdsa] unsupported ECDSA provision plan kind');
}
