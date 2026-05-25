import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';
import type { EvmFamilyEcdsaWalletKey } from '../identity/evmFamilyEcdsaIdentity';
import {
  planUnlockEcdsaWarmup,
  type ActiveEcdsaSignerRecord,
  type EcdsaWarmupPlannerResult,
  type RepairRequiredEcdsaSignerRecord,
  type WalletUnlockSelection,
} from './unlockEcdsaWarmupPlanner';

declare const chainTarget: ThresholdEcdsaChainTarget;
declare const walletKey: EvmFamilyEcdsaWalletKey;

const invalidEd25519OnlySelectionWithEcdsa = {
  mode: 'ed25519_only',
  ed25519: true,
  // @ts-expect-error Ed25519-only unlock cannot carry ECDSA selection state.
  ecdsa: true,
} satisfies WalletUnlockSelection;
void invalidEd25519OnlySelectionWithEcdsa;

const activeRecord: ActiveEcdsaSignerRecord = {
  kind: 'active_ecdsa_signer_record',
  targetKey: 'tempo:978',
  chainTarget,
  walletKey,
  source: 'profile_continuity',
};

const repairRecord: RepairRequiredEcdsaSignerRecord = {
  kind: 'repair_required',
  targetKey: 'tempo:978',
  chainTarget,
  keyHandle: 'ecdsa-handle',
  reason: 'missing_key_facts',
};

// @ts-expect-error ready unlock plans reject repair records.
const invalidReadyPlanWithRepairRecords: EcdsaWarmupPlannerResult = {
  kind: 'ready',
  readyTargets: [
    {
      targetKey: 'tempo:978',
      chainTarget,
      walletKey,
    },
  ],
  repairRecords: [repairRecord],
};
void invalidReadyPlanWithRepairRecords;

declare const broadUnlockPlanShape: {
  repairRecords?: unknown[];
  blockedRecords?: unknown[];
};

// @ts-expect-error broad spreads with foreign lifecycle fields cannot build a ready plan.
const invalidReadyPlanFromBroadSpread: EcdsaWarmupPlannerResult = {
  ...broadUnlockPlanShape,
  kind: 'ready',
  readyTargets: [
    {
      targetKey: 'tempo:978',
      chainTarget,
      walletKey,
    },
  ],
};
void invalidReadyPlanFromBroadSpread;

planUnlockEcdsaWarmup({
  selection: { mode: 'ecdsa_only', ecdsa: true },
  configuredTargets: [chainTarget],
  // @ts-expect-error planner input requires parsed active ECDSA signer records.
  activeSignerRecords: [{ metadata: { keyHandle: 'ecdsa-handle' } }],
  localSessionRecords: [],
});

planUnlockEcdsaWarmup({
  selection: { mode: 'ecdsa_only', ecdsa: true },
  configuredTargets: [chainTarget],
  activeSignerRecords: [activeRecord],
  localSessionRecords: [],
});
