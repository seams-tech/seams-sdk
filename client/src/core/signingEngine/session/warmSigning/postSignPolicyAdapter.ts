import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../../api/thresholdLifecycle/thresholdSessionStore';
import type { ThresholdEcdsaActivationChain } from '../../orchestration/thresholdActivation';
import {
  getPrimaryAndSecondaryEcdsaCapabilities,
} from './ecdsaProvisioner';
import type { WarmSessionEcdsaCapabilityRef, WarmSessionEnvelope } from './types';
import {
  applyEcdsaPostSignPolicy as applySigningEcdsaPostSignPolicy,
  assertEcdsaOperationAllowed as assertSigningEcdsaOperationAllowed,
} from '../signingSession/postSignPolicy';

export type WarmSessionPostSignPolicyAdapterDeps = {
  getWarmSession: (nearAccountId: AccountId | string) => Promise<WarmSessionEnvelope>;
  resolveCurrentEcdsaRecord: (args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaSessionRecord | null;
  markEmailOtpSessionConsumed?: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => void;
  clearEcdsaEphemeralMaterial: (args: {
    nearAccountId: AccountId;
    chain: ThresholdEcdsaActivationChain;
    thresholdSessionId?: string;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => Promise<void>;
};

async function resolveSecondaryEcdsaRecord(args: {
  getWarmSession: WarmSessionPostSignPolicyAdapterDeps['getWarmSession'];
  accountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  source?: ThresholdEcdsaSessionStoreSource;
}): Promise<ThresholdEcdsaSessionRecord | null> {
  if (args.source) return null;
  return (
    getPrimaryAndSecondaryEcdsaCapabilities({
      warmSession: await args.getWarmSession(args.accountId),
      chain: args.chain,
    }).secondary.record || null
  );
}

export async function applyWarmSessionEcdsaPostSignPolicy(
  deps: WarmSessionPostSignPolicyAdapterDeps,
  args: WarmSessionEcdsaCapabilityRef & {
    source?: ThresholdEcdsaSessionStoreSource;
  },
): Promise<void> {
  const accountId = toAccountId(args.nearAccountId);
  const record = deps.resolveCurrentEcdsaRecord({
    nearAccountId: accountId,
    chain: args.chain,
    ...(args.source ? { source: args.source } : {}),
  });
  const secondaryRecord = await resolveSecondaryEcdsaRecord({
    getWarmSession: deps.getWarmSession,
    accountId,
    chain: args.chain,
    ...(args.source ? { source: args.source } : {}),
  });
  await applySigningEcdsaPostSignPolicy({
    nearAccountId: accountId,
    chain: args.chain,
    ...(args.thresholdSessionId ? { thresholdSessionId: args.thresholdSessionId } : {}),
    ...(args.source ? { source: args.source } : {}),
    ...(record ? { selectedRecord: record } : {}),
    ...(secondaryRecord ? { secondaryRecord } : {}),
    markEmailOtpSessionConsumed: deps.markEmailOtpSessionConsumed,
    clearEcdsaEphemeralMaterial: deps.clearEcdsaEphemeralMaterial,
  });
}

export async function assertWarmSessionEcdsaOperationAllowed(
  deps: Pick<WarmSessionPostSignPolicyAdapterDeps, 'getWarmSession' | 'resolveCurrentEcdsaRecord'>,
  args: WarmSessionEcdsaCapabilityRef & {
    operationLabel: string;
    source?: ThresholdEcdsaSessionStoreSource;
    sensitivePolicy?: SensitiveOperationPolicy;
  },
): Promise<void> {
  const accountId = toAccountId(args.nearAccountId);
  const record = deps.resolveCurrentEcdsaRecord({
    nearAccountId: accountId,
    chain: args.chain,
    ...(args.source ? { source: args.source } : {}),
  });
  const secondaryRecord = await resolveSecondaryEcdsaRecord({
    getWarmSession: deps.getWarmSession,
    accountId,
    chain: args.chain,
    ...(args.source ? { source: args.source } : {}),
  });
  assertSigningEcdsaOperationAllowed({
    chain: args.chain,
    operationLabel: args.operationLabel,
    ...(args.thresholdSessionId ? { thresholdSessionId: args.thresholdSessionId } : {}),
    ...(args.source ? { source: args.source } : {}),
    ...(record ? { selectedRecord: record } : {}),
    ...(secondaryRecord ? { secondaryRecord } : {}),
    ...(args.sensitivePolicy ? { sensitivePolicy: args.sensitivePolicy } : {}),
  });
}
