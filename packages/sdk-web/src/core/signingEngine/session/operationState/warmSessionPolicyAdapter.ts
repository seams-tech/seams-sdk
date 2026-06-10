import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  applyEcdsaPostSignPolicy,
  assertEcdsaOperationAllowed,
  ecdsaPostSignPolicySessionFromRecord,
  secondaryEcdsaPostSignPolicyMaterialFromRecord,
  selectedEcdsaPostSignPolicyMaterialFromRecord,
} from './postSignPolicy';
import type {
  ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  ConsumeSingleUseEmailOtpEcdsaLaneResult,
} from '../persistence/records';

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
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  selectedRecord: ThresholdEcdsaSessionRecord;
  thresholdSessionId: string;
};

export type WarmSessionEcdsaCapabilityRef = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
};

export type WarmSessionPostSignPolicyAdapterDeps = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionPolicyEnvelope>;
  resolveExactEcdsaRecord: (args: {
    walletId: WalletId;
    chainTarget: ThresholdEcdsaChainTarget;
    thresholdSessionId: string;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ThresholdEcdsaSessionRecord | null;
  consumeSingleUseEmailOtpEcdsaLane?: (
    command: ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  ) => ConsumeSingleUseEmailOtpEcdsaLaneResult;
  clearEcdsaEphemeralMaterial: (args: {
    record: ThresholdEcdsaSessionRecord;
    thresholdSessionId: string;
  }) => Promise<void>;
};

async function resolveSecondaryEcdsaRecord(args: {
  getWarmSession: WarmSessionPostSignPolicyAdapterDeps['getWarmSession'];
  walletId: WalletId;
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
  const secondaryRecord = await resolveSecondaryEcdsaRecord({
    getWarmSession: deps.getWarmSession,
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    source: args.selectedRecord.source,
  });
  await applyEcdsaPostSignPolicy({
    thresholdSessionId: args.thresholdSessionId,
    source: args.selectedRecord.source,
    selectedMaterial: selectedEcdsaPostSignPolicyMaterialFromRecord({
      record: args.selectedRecord,
      clearEcdsaEphemeralMaterial: deps.clearEcdsaEphemeralMaterial,
    }),
    secondaryMaterial: secondaryRecord
      ? secondaryEcdsaPostSignPolicyMaterialFromRecord({
          record: secondaryRecord,
          clearEcdsaEphemeralMaterial: deps.clearEcdsaEphemeralMaterial,
        })
      : null,
    consumeSingleUseEmailOtpEcdsaLane: deps.consumeSingleUseEmailOtpEcdsaLane,
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
  const record = deps.resolveExactEcdsaRecord({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    thresholdSessionId: args.thresholdSessionId,
    source: args.source,
  });
  const secondaryRecord = await resolveSecondaryEcdsaRecord({
    getWarmSession: deps.getWarmSession,
    walletId: args.walletId,
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
