import type { ThresholdEcdsaChainTarget, WalletId } from '../../interfaces/ecdsaChainTarget';
import type { EvmFamilyEcdsaWalletKey } from '../identity/evmFamilyEcdsaIdentity';
import {
  parseActiveEcdsaSignerRecordForUnlock,
  planUnlockEcdsaWarmup,
  type ActiveEcdsaSignerRecord,
  type EcdsaWarmupPlannerResult,
  type KeyFactsInventoryRequiredEcdsaSignerRecord,
  type WalletUnlockSelection,
} from './unlockEcdsaWarmupPlanner';
import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';

declare const chainTarget: ThresholdEcdsaChainTarget;
declare const walletKey: EvmFamilyEcdsaWalletKey;
declare const walletId: WalletId;
declare const accountSignerRecord: AccountSignerRecord;
declare const rawSignerRecord: Record<string, unknown>;

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

const keyFactsInventoryRequiredRecord: KeyFactsInventoryRequiredEcdsaSignerRecord = {
  kind: 'key_facts_inventory_required',
  targetKey: 'tempo:978',
  chainTarget,
  keyHandle: 'ecdsa-handle',
  reason: 'missing_key_facts',
};

// @ts-expect-error ready unlock plans reject key-facts inventory records.
const invalidReadyPlanWithInventoryRecords: EcdsaWarmupPlannerResult = {
  kind: 'ready',
  readyTargets: [
    {
      targetKey: 'tempo:978',
      chainTarget,
      walletKey,
    },
  ],
  keyFactsInventoryRequiredRecords: [keyFactsInventoryRequiredRecord],
};
void invalidReadyPlanWithInventoryRecords;

declare const broadUnlockPlanShape: {
  keyFactsInventoryRequiredRecords?: unknown[];
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

parseActiveEcdsaSignerRecordForUnlock({
  walletId,
  configuredTargets: [chainTarget],
  signer: accountSignerRecord,
});

parseActiveEcdsaSignerRecordForUnlock({
  walletId,
  configuredTargets: [chainTarget],
  // @ts-expect-error raw DB signer rows must be parsed before unlock planning.
  signer: rawSignerRecord,
});
