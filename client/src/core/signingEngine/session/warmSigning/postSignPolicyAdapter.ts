import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { getPrimaryAndSecondaryEcdsaCapabilities } from './ecdsaProvisioner';
import type {
  ApplyWarmEcdsaPostSignPolicyArgs,
  WarmSessionEcdsaCapabilityRef,
  WarmSessionEnvelope,
} from './types';
import {
  applyEcdsaPostSignPolicy as applySigningEcdsaPostSignPolicy,
  assertEcdsaOperationAllowed as assertSigningEcdsaOperationAllowed,
  ecdsaPostSignPolicyMaterialFromRecord,
  ecdsaPostSignPolicySessionFromRecord,
} from '../signingSession/postSignPolicy';

export type WarmSessionPostSignPolicyAdapterDeps = {
  getWarmSession: (nearAccountId: AccountId | string) => Promise<WarmSessionEnvelope>;
  resolveCurrentEcdsaRecord: (args: {
    nearAccountId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaSessionRecord | null;
  markEmailOtpSessionConsumed?: (args: {
    nearAccountId: AccountId | string;
    chainTarget: ThresholdEcdsaChainTarget;
    uses?: number;
  }) => void;
  clearEcdsaEphemeralMaterial: (args: {
    record: ThresholdEcdsaSessionRecord;
    thresholdSessionId?: string;
  }) => Promise<void>;
};

async function resolveSecondaryEcdsaRecord(args: {
  getWarmSession: WarmSessionPostSignPolicyAdapterDeps['getWarmSession'];
  accountId: AccountId;
  chainTarget: ThresholdEcdsaChainTarget;
  source?: ThresholdEcdsaSessionStoreSource;
}): Promise<ThresholdEcdsaSessionRecord | null> {
  if (args.source) return null;
  return (
    getPrimaryAndSecondaryEcdsaCapabilities({
      warmSession: await args.getWarmSession(args.accountId),
      chainTarget: args.chainTarget,
    }).secondary.record || null
  );
}

export async function applyWarmSessionEcdsaPostSignPolicy(
  deps: WarmSessionPostSignPolicyAdapterDeps,
  args: ApplyWarmEcdsaPostSignPolicyArgs,
): Promise<void> {
  const accountId = toAccountId(args.nearAccountId);
  const secondaryRecord = await resolveSecondaryEcdsaRecord({
    getWarmSession: deps.getWarmSession,
    accountId,
    chainTarget: args.chainTarget,
    ...(args.source ? { source: args.source } : {}),
  });
  await applySigningEcdsaPostSignPolicy({
    thresholdSessionId: args.thresholdSessionId || null,
    source: args.source || null,
    selectedMaterial: ecdsaPostSignPolicyMaterialFromRecord({
      record: args.selectedRecord,
      clearEcdsaEphemeralMaterial: deps.clearEcdsaEphemeralMaterial,
    }),
    secondaryMaterial: secondaryRecord
      ? ecdsaPostSignPolicyMaterialFromRecord({
          record: secondaryRecord,
          clearEcdsaEphemeralMaterial: deps.clearEcdsaEphemeralMaterial,
        })
      : null,
    markEmailOtpSessionConsumed: deps.markEmailOtpSessionConsumed,
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
    chainTarget: args.chainTarget,
    ...(args.source ? { source: args.source } : {}),
  });
  const secondaryRecord = await resolveSecondaryEcdsaRecord({
    getWarmSession: deps.getWarmSession,
    accountId,
    chainTarget: args.chainTarget,
    ...(args.source ? { source: args.source } : {}),
  });
  assertSigningEcdsaOperationAllowed({
    chainTarget: args.chainTarget,
    operationLabel: args.operationLabel,
    thresholdSessionId: args.thresholdSessionId || null,
    source: args.source || null,
    selectedSession: record ? ecdsaPostSignPolicySessionFromRecord(record) : null,
    secondarySession: secondaryRecord
      ? ecdsaPostSignPolicySessionFromRecord(secondaryRecord)
      : null,
    ...(args.sensitivePolicy ? { sensitivePolicy: args.sensitivePolicy } : {}),
  });
}
