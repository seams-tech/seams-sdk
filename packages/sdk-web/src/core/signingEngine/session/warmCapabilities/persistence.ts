import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { normalizePositiveInteger } from '@shared/utils/normalize';
import type { AccountId } from '@/core/types/accountIds';
import {
  type ThresholdEd25519SessionRecord,
  upsertStoredThresholdEd25519SessionRecord,
} from '../persistence/records';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import {
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { publishResolvedIdentity } from '../persistence/sealedSessionStore';

type PersistWarmSessionEd25519CapabilityCommon = {
  nearAccountId: AccountId;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  participantIds: readonly number[];
  sessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  remainingUses: number;
  clientVerifyingShareB64u?: string;
  ed25519HssMaterialHandle?: string;
  ed25519HssMaterialBindingDigest?: string;
  routerAbNormalSigning?: RouterAbEd25519NormalSigningState;
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

export type PersistWarmSessionEd25519CapabilityArgs =
  | PersistWarmSessionEd25519JwtEmailOtpCapabilityArgs
  | PersistWarmSessionEd25519JwtPasskeyCapabilityArgs;

export function persistWarmSessionEd25519Capability(
  args: PersistWarmSessionEd25519CapabilityArgs,
): ThresholdEd25519SessionRecord {
  const sessionId = String(args.sessionId || '').trim();
  const signingGrantId = String(args.signingGrantId || '').trim();
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  const remainingUses = normalizePositiveInteger(args.remainingUses) ?? 0;
  if (!sessionId) {
    throw new Error('Missing sessionId for warm threshold-ed25519 capability');
  }
  if (!signingGrantId) {
    throw new Error('Missing signingGrantId for warm threshold-ed25519 capability');
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

  const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
  const ed25519HssMaterialHandle = String(args.ed25519HssMaterialHandle || '').trim();
  const ed25519HssMaterialBindingDigest = String(
    args.ed25519HssMaterialBindingDigest || '',
  ).trim();
  const jwt = String(args.jwt || '').trim();
  const runtimePolicyScope = args.runtimePolicyScope || parseThresholdRuntimePolicyScopeFromJwt(jwt);
  const signingRootBinding = runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)
    : null;
  const signingRootId =
    String(args.signingRootId || '').trim() ||
    String(signingRootBinding?.signingRootId || '').trim();
  const signingRootVersion =
    String(args.signingRootVersion || '').trim() ||
    String(signingRootBinding?.signingRootVersion || '').trim();
  const authMethod = args.kind === 'jwt_email_otp' ? 'email_otp' : 'passkey';
  const source = args.source;

  const record = upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: args.nearAccountId,
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds,
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(clientVerifyingShareB64u ? { clientVerifyingShareB64u } : {}),
    ...(ed25519HssMaterialHandle ? { ed25519HssMaterialHandle } : {}),
    ...(ed25519HssMaterialBindingDigest ? { ed25519HssMaterialBindingDigest } : {}),
    ...(args.routerAbNormalSigning ? { routerAbNormalSigning: args.routerAbNormalSigning } : {}),
    thresholdSessionKind: 'jwt',
    thresholdSessionId: sessionId,
    signingGrantId,
    ...(jwt ? { walletSessionJwt: jwt } : {}),
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
    signingGrantId,
    thresholdSessionId: sessionId,
  });
  return record;
}
