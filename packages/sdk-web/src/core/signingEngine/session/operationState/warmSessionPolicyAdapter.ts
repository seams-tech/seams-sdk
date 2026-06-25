import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import type { ResolveExactEcdsaRecordResult } from '../warmCapabilities/statusReader';
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
  lane: ExactEcdsaSigningLaneIdentity;
  selectedRecord: ThresholdEcdsaSessionRecord;
  walletId?: never;
  chainTarget?: never;
  thresholdSessionId?: never;
};

export type WarmSessionEcdsaCapabilityRef = {
  lane: ExactEcdsaSigningLaneIdentity;
  walletId?: never;
  chainTarget?: never;
  thresholdSessionId?: never;
};

export type WarmSessionPostSignPolicyAdapterDeps = {
  getWarmSession: (walletId: WalletId) => Promise<WarmSessionPolicyEnvelope>;
  resolveExactEcdsaRecord: (args: {
    lane: ExactEcdsaSigningLaneIdentity;
    source?: ThresholdEcdsaSessionStoreSource;
  }) => ResolveExactEcdsaRecordResult;
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

function foundExactEcdsaRecordOrNull(
  result: ResolveExactEcdsaRecordResult,
  context: string,
): ThresholdEcdsaSessionRecord | null {
  switch (result.kind) {
    case 'found':
      return result.record;
    case 'not_found':
      return null;
    case 'duplicate_records':
      throw new Error(`[WarmSessionStore] duplicate exact ECDSA records for ${context}`);
  }
  result satisfies never;
  throw new Error('[WarmSessionStore] unsupported exact ECDSA record result');
}

export async function applyWarmSessionEcdsaPostSignPolicy(
  deps: WarmSessionPostSignPolicyAdapterDeps,
  args: ApplyWarmEcdsaPostSignPolicyArgs,
): Promise<void> {
  const secondaryRecord = await resolveSecondaryEcdsaRecord({
    getWarmSession: deps.getWarmSession,
    walletId: args.lane.walletId,
    chainTarget: args.lane.chainTarget,
    source: args.selectedRecord.source,
  });
  await applyEcdsaPostSignPolicy({
    thresholdSessionId: String(args.lane.thresholdSessionId),
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
  const record = foundExactEcdsaRecordOrNull(
    deps.resolveExactEcdsaRecord({
      lane: args.lane,
      source: args.source,
    }),
    `${args.operationLabel}:${String(args.lane.thresholdSessionId)}`,
  );
  const secondaryRecord = await resolveSecondaryEcdsaRecord({
    getWarmSession: deps.getWarmSession,
    walletId: args.lane.walletId,
    chainTarget: args.lane.chainTarget,
    source: args.source,
  });
  assertEcdsaOperationAllowed({
    chainTarget: args.lane.chainTarget,
    operationLabel: args.operationLabel,
    thresholdSessionId: String(args.lane.thresholdSessionId),
    source: args.source,
    selectedSession: record ? ecdsaPostSignPolicySessionFromRecord(record) : null,
    secondarySession: secondaryRecord
      ? ecdsaPostSignPolicySessionFromRecord(secondaryRecord)
      : null,
    ...(args.sensitivePolicy ? { sensitivePolicy: args.sensitivePolicy } : {}),
  });
}
