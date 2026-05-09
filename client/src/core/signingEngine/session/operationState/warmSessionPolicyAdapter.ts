import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  applyEcdsaPostSignPolicy,
  assertEcdsaOperationAllowed,
  ecdsaPostSignPolicyMaterialFromRecord,
  ecdsaPostSignPolicySessionFromRecord,
} from './postSignPolicy';

type WarmSessionEcdsaCapabilityRecordView = {
  record: ThresholdEcdsaSessionRecord | null;
};

type WarmSessionPolicyEnvelope = {
  capabilities: {
    ecdsa: {
      evm: WarmSessionEcdsaCapabilityRecordView;
      tempo: WarmSessionEcdsaCapabilityRecordView;
    };
  };
};

export type ApplyWarmEcdsaPostSignPolicyArgs = {
  nearAccountId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  selectedRecord: ThresholdEcdsaSessionRecord;
  thresholdSessionId?: string;
  source?: ThresholdEcdsaSessionStoreSource;
};

export type WarmSessionEcdsaCapabilityRef = {
  nearAccountId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId?: string;
};

export type WarmSessionPostSignPolicyAdapterDeps = {
  getWarmSession: (nearAccountId: AccountId | string) => Promise<WarmSessionPolicyEnvelope>;
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
  const warmSession = await args.getWarmSession(args.accountId);
  return args.chainTarget.kind === 'tempo'
    ? warmSession.capabilities.ecdsa.evm.record
    : warmSession.capabilities.ecdsa.tempo.record;
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
  await applyEcdsaPostSignPolicy({
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
  assertEcdsaOperationAllowed({
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
