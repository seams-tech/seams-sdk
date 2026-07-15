import type { AccountId } from '@/core/types/accountIds';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { normalizePositiveInteger } from '@shared/utils/normalize';
import type { RouterAbEd25519NormalSigningState } from '../../threshold/ed25519/routerAbNormalSigningState';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type {
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEd25519SessionStoreSource,
} from '../identity/laneIdentity';
import {
  upsertThresholdEd25519SessionFact,
  type ThresholdEd25519SessionRecord,
} from '../persistence/records';
import { publishResolvedIdentity } from '../persistence/sealedSessionStore';

type PersistWarmSessionEd25519CapabilityIdentity = {
  walletId: string;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  participantIds: readonly number[];
  sessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  remainingUses: number;
  signerSlot: number;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  jwt: string;
};

export type PersistWarmSessionEd25519JwtEmailOtpCapabilityArgs =
  PersistWarmSessionEd25519CapabilityIdentity & {
    kind: 'jwt_email_otp';
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    passkeyCredentialIdB64u?: never;
  };

export type PersistWarmSessionEd25519JwtPasskeyCapabilityArgs =
  PersistWarmSessionEd25519CapabilityIdentity & {
    kind: 'jwt_passkey';
    passkeyCredentialIdB64u: string;
    source: Exclude<ThresholdEd25519SessionStoreSource, 'email_otp'>;
    emailOtpAuthContext?: never;
  };

export type PersistWarmSessionEd25519CapabilityArgs =
  | PersistWarmSessionEd25519JwtEmailOtpCapabilityArgs
  | PersistWarmSessionEd25519JwtPasskeyCapabilityArgs;

function requireNonEmpty(value: unknown, label: string): string {
  const parsed = String(value ?? '').trim();
  if (!parsed) throw new Error(`${label} is required for Router A/B Ed25519 session persistence`);
  return parsed;
}

function requirePositiveInteger(value: unknown, label: string): number {
  const parsed = normalizePositiveInteger(value) ?? 0;
  if (parsed <= 0) {
    throw new Error(`${label} must be positive for Router A/B Ed25519 session persistence`);
  }
  return parsed;
}

export function persistWarmSessionEd25519Capability(
  args: PersistWarmSessionEd25519CapabilityArgs,
): ThresholdEd25519SessionRecord {
  const walletId = requireNonEmpty(args.walletId, 'walletId');
  const nearEd25519SigningKeyId = requireNonEmpty(
    args.nearEd25519SigningKeyId,
    'nearEd25519SigningKeyId',
  );
  const rpId = requireNonEmpty(args.rpId, 'rpId');
  const relayerUrl = requireNonEmpty(args.relayerUrl, 'relayerUrl');
  const relayerKeyId = requireNonEmpty(args.relayerKeyId, 'relayerKeyId');
  const thresholdSessionId = requireNonEmpty(args.sessionId, 'sessionId');
  const signingGrantId = requireNonEmpty(args.signingGrantId, 'signingGrantId');
  const walletSessionJwt = requireNonEmpty(args.jwt, 'walletSessionJwt');
  const expiresAtMs = requirePositiveInteger(args.expiresAtMs, 'expiresAtMs');
  const remainingUses = requirePositiveInteger(args.remainingUses, 'remainingUses');
  const signerSlot = requirePositiveInteger(args.signerSlot, 'signerSlot');
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  if (!participantIds) {
    throw new Error('participantIds are required for Router A/B Ed25519 session persistence');
  }
  const signingRoot = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
  if (!signingRoot) {
    throw new Error('runtimePolicyScope must resolve an Ed25519 signing root');
  }
  const passkeyCredentialIdB64u =
    args.kind === 'jwt_passkey'
      ? requireNonEmpty(args.passkeyCredentialIdB64u, 'passkeyCredentialIdB64u')
      : null;
  const updatedAtMs = Date.now();
  const record = upsertThresholdEd25519SessionFact({
    walletId,
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId,
    rpId,
    ...(passkeyCredentialIdB64u ? { passkeyCredentialIdB64u } : {}),
    relayerUrl,
    relayerKeyId,
    participantIds,
    signingRootId: signingRoot.signingRootId,
    signingRootVersion: signingRoot.signingRootVersion,
    runtimePolicyScope: args.runtimePolicyScope,
    signerSlot,
    routerAbNormalSigning: args.routerAbNormalSigning,
    thresholdSessionKind: 'jwt',
    thresholdSessionId,
    signingGrantId,
    walletSessionJwt,
    expiresAtMs,
    remainingUses,
    ...(args.kind === 'jwt_email_otp' ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    updatedAtMs,
    source: args.source,
  });
  if (!record) {
    throw new Error('Router A/B Ed25519 public session persistence rejected the record');
  }
  publishResolvedIdentity({
    walletId: record.walletId,
    authMethod: args.kind === 'jwt_email_otp' ? 'email_otp' : 'passkey',
    curve: 'ed25519',
    chain: 'near',
    signingGrantId,
    thresholdSessionId,
    updatedAtMs,
  });
  return record;
}
