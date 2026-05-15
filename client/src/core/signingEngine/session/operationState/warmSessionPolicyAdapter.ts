import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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
  walletId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  selectedRecord: ThresholdEcdsaSessionRecord;
  thresholdSessionId: string;
};

export type WarmSessionEcdsaCapabilityRef = {
  walletId: AccountId | string;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
};

export type WarmSessionPostSignPolicyAdapterDeps = {
  getWarmSession: (walletId: AccountId | string) => Promise<WarmSessionPolicyEnvelope>;
  resolveExactEcdsaRecord: (args: {
    walletId: AccountId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: string;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaSessionRecord | null;
  markEmailOtpSessionConsumed?: (args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    uses?: number;
  }) => void;
  clearEcdsaEphemeralMaterial: (args: {
    record: ThresholdEcdsaSessionRecord;
    thresholdSessionId: string;
  }) => Promise<void>;
};

async function resolveSecondaryEcdsaRecord(args: {
  getWarmSession: WarmSessionPostSignPolicyAdapterDeps['getWarmSession'];
  walletId: AccountId;
  chainTarget: ThresholdEcdsaChainTarget;
  source: ThresholdEcdsaSessionStoreSource;
}): Promise<ThresholdEcdsaSessionRecord | null> {
  if (args.source) return null;
  const warmSession = await args.getWarmSession(args.walletId);
  return args.chainTarget.kind === 'tempo'
    ? warmSession.capabilities.ecdsa.evm.record
    : warmSession.capabilities.ecdsa.tempo.record;
}

export async function applyWarmSessionEcdsaPostSignPolicy(
  deps: WarmSessionPostSignPolicyAdapterDeps,
  args: ApplyWarmEcdsaPostSignPolicyArgs,
): Promise<void> {
  const walletId = toAccountId(args.walletId);
  const secondaryRecord = await resolveSecondaryEcdsaRecord({
    getWarmSession: deps.getWarmSession,
    walletId,
    chainTarget: args.chainTarget,
    source: args.selectedRecord.source,
  });
  await applyEcdsaPostSignPolicy({
    thresholdSessionId: args.thresholdSessionId,
    source: args.selectedRecord.source,
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
  deps: Pick<WarmSessionPostSignPolicyAdapterDeps, 'getWarmSession' | 'resolveExactEcdsaRecord'>,
  args: WarmSessionEcdsaCapabilityRef & {
    operationLabel: string;
    source: ThresholdEcdsaSessionStoreSource;
    sensitivePolicy?: SensitiveOperationPolicy;
  },
): Promise<void> {
  const walletId = toAccountId(args.walletId);
  const record = deps.resolveExactEcdsaRecord({
    walletId,
    chainTarget: args.chainTarget,
    thresholdSessionId: args.thresholdSessionId,
    source: args.source,
  });
  const secondaryRecord = await resolveSecondaryEcdsaRecord({
    getWarmSession: deps.getWarmSession,
    walletId,
    chainTarget: args.chainTarget,
    source: args.source,
  });
  assertEcdsaOperationAllowed({
    chainTarget: args.chainTarget,
    operationLabel: args.operationLabel,
    thresholdSessionId: args.thresholdSessionId,
    source: args.source,
    selectedSession: record ? ecdsaPostSignPolicySessionFromRecord(record) : null,
    secondarySession: secondaryRecord
      ? ecdsaPostSignPolicySessionFromRecord(secondaryRecord)
      : null,
    ...(args.sensitivePolicy ? { sensitivePolicy: args.sensitivePolicy } : {}),
  });
}
