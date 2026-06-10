import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { normalizePositiveInteger } from '@shared/utils/normalize';
import type { AccountId } from '@/core/types/accountIds';
import {
  type ThresholdEd25519SessionRecord,
  upsertStoredThresholdEd25519SessionRecord,
} from '../persistence/records';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import {
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
  type ThresholdSessionKind,
} from '../../threshold/sessionPolicy';
import { publishResolvedIdentity } from '../persistence/sealedSessionStore';

type PersistWarmSessionEd25519CapabilityCommon = {
  nearAccountId: AccountId;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  participantIds: readonly number[];
  sessionId: string;
  walletSigningSessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  xClientBaseB64u?: string;
  updatedAtMs?: number;
};

export type PersistWarmSessionEd25519JwtEmailOtpCapabilityArgs =
  PersistWarmSessionEd25519CapabilityCommon & {
    kind: 'jwt_email_otp';
    sessionKind: 'jwt';
    jwt: string;
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  };

export type PersistWarmSessionEd25519JwtPasskeyCapabilityArgs =
  PersistWarmSessionEd25519CapabilityCommon & {
    kind: 'jwt_passkey';
    sessionKind: 'jwt';
    jwt: string;
    source: Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'>;
    emailOtpAuthContext?: never;
  };

export type PersistWarmSessionEd25519CookiePasskeyCapabilityArgs =
  PersistWarmSessionEd25519CapabilityCommon & {
    kind: 'cookie_passkey';
    sessionKind: 'cookie';
    source: Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'>;
    jwt?: never;
    emailOtpAuthContext?: never;
  };

export type PersistWarmSessionEd25519CapabilityArgs =
  | PersistWarmSessionEd25519JwtEmailOtpCapabilityArgs
  | PersistWarmSessionEd25519JwtPasskeyCapabilityArgs
  | PersistWarmSessionEd25519CookiePasskeyCapabilityArgs;

export function persistWarmSessionEd25519Capability(
  args: PersistWarmSessionEd25519CapabilityArgs,
): ThresholdEd25519SessionRecord {
  const sessionId = String(args.sessionId || '').trim();
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  const remainingUses = normalizePositiveInteger(args.remainingUses) ?? 0;
  if (!sessionId) {
    throw new Error('Missing sessionId for warm threshold-ed25519 capability');
  }
  if (!walletSigningSessionId) {
    throw new Error('Missing walletSigningSessionId for warm threshold-ed25519 capability');
  }
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('Invalid expiresAtMs for warm threshold-ed25519 capability');
  }
  if (remainingUses <= 0) {
    throw new Error('Invalid remainingUses for warm threshold-ed25519 capability');
  }

  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  if (!participantIds) {
    throw new Error('Missing participantIds for warm threshold-ed25519 capability');
  }

  const xClientBaseB64u = String(args.xClientBaseB64u || '').trim();
  const jwt = args.kind === 'cookie_passkey' ? '' : String(args.jwt || '').trim();
  const runtimePolicyScope =
    args.runtimePolicyScope || parseThresholdRuntimePolicyScopeFromJwt(jwt);
  const authMethod = args.kind === 'jwt_email_otp' ? 'email_otp' : 'passkey';
  const thresholdSessionKind: ThresholdSessionKind =
    args.kind === 'cookie_passkey' ? 'cookie' : 'jwt';
  const source = args.source;

  const record = upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: args.nearAccountId,
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(xClientBaseB64u ? { xClientBaseB64u } : {}),
    thresholdSessionKind,
    thresholdSessionId: sessionId,
    walletSigningSessionId,
    ...(jwt ? { thresholdSessionAuthToken: jwt } : {}),
    expiresAtMs,
    remainingUses,
    ...(args.kind === 'jwt_email_otp'
      ? { emailOtpAuthContext: args.emailOtpAuthContext }
      : {}),
    updatedAtMs: Math.floor(Number(args.updatedAtMs ?? Date.now()) || 0),
    source,
  });
  if (!record) {
    throw new Error('Failed to persist warm threshold-ed25519 capability');
  }
  publishResolvedIdentity({
    walletId: record.nearAccountId,
    authMethod,
    curve: 'ed25519',
    chain: 'near',
    walletSigningSessionId,
    thresholdSessionId: sessionId,
  });
  return record;
}
