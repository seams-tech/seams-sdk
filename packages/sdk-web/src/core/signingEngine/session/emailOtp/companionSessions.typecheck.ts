import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { listStoredThresholdEcdsaSessionRecordsForWallet } from '@/core/signingEngine/session/persistence/records';
import {
  selectEmailOtpEcdsaCompanionLaneForEd25519Signing,
  type EmailOtpEcdsaCompanionLaneForEd25519Signing,
  type EmailOtpEcdsaCompanionForEd25519Signing,
  type EmailOtpCompanionSessionAttachResult,
  type EmailOtpEcdsaCompanionSelectionResult,
} from './companionSessions';

declare const walletId: WalletId;
declare const listRecords: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
declare const signingGrantId: string;
declare const selectionResult: EmailOtpEcdsaCompanionSelectionResult;
declare const companion: EmailOtpEcdsaCompanionForEd25519Signing;
declare const emailOtpCompanionLane: EmailOtpEcdsaCompanionLaneForEd25519Signing;

type SingleEmailOtpCompanion = Extract<
  EmailOtpEcdsaCompanionForEd25519Signing,
  { kind: 'single_companion_lane' }
>;
type ChainDistinctEmailOtpCompanion = Extract<
  EmailOtpEcdsaCompanionForEd25519Signing,
  { kind: 'chain_distinct_companion_lanes' }
>;

void selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
  kind: 'latest_wallet_record',
  walletId,
  listThresholdEcdsaSessionRecordsForWallet: listRecords,
});

void selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
  kind: 'signing_grant_exact',
  walletId,
  signingGrantId,
  listThresholdEcdsaSessionRecordsForWallet: listRecords,
});

// @ts-expect-error Exact companion selection requires signingGrantId.
void selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
  kind: 'signing_grant_exact',
  walletId,
  listThresholdEcdsaSessionRecordsForWallet: listRecords,
});

void selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
  kind: 'latest_wallet_record',
  // @ts-expect-error Email OTP ECDSA companion selection requires WalletId.
  walletId: 'alice.testnet',
  listThresholdEcdsaSessionRecordsForWallet: listRecords,
});

function assertNeverEmailOtpEcdsaRecordSelection(result: never): never {
  throw new Error(String((result as { kind?: unknown })?.kind || 'unknown'));
}

switch (selectionResult.kind) {
  case 'ready':
  case 'duplicate_chain_lanes':
  case 'not_found':
  case 'display_only_fallback':
    break;
  default:
    assertNeverEmailOtpEcdsaRecordSelection(selectionResult);
}

switch (companion.kind) {
  case 'single_companion_lane':
    void companion.lane;
    break;
  case 'chain_distinct_companion_lanes':
    void companion.primaryLane;
    void companion.lanes;
    break;
  default:
    assertNeverEmailOtpEcdsaRecordSelection(companion);
}

const invalidPasskeyCompanionLane: EmailOtpEcdsaCompanionLaneForEd25519Signing = {
  ...emailOtpCompanionLane,
  // @ts-expect-error Email OTP companion lanes cannot carry passkey auth.
  authMethod: 'passkey',
};
void invalidPasskeyCompanionLane;

const invalidCompanionLaneWithPasskeyRecord: EmailOtpEcdsaCompanionLaneForEd25519Signing = {
  ...emailOtpCompanionLane,
  // @ts-expect-error Email OTP companion lanes reject passkey record material.
  passkeyRecord: {},
};
void invalidCompanionLaneWithPasskeyRecord;

const invalidCompanionLaneWithDirectRecord: EmailOtpEcdsaCompanionLaneForEd25519Signing = {
  ...emailOtpCompanionLane,
  // @ts-expect-error Companion lanes expose ECDSA records through committedLane only.
  record: {},
};
void invalidCompanionLaneWithDirectRecord;

const invalidCompanionLaneWithSiblingAuthority: EmailOtpEcdsaCompanionLaneForEd25519Signing = {
  ...emailOtpCompanionLane,
  // @ts-expect-error Companion lanes carry wallet authority inside committedLane.
  walletSessionAuthority: {},
};
void invalidCompanionLaneWithSiblingAuthority;

const invalidSingleLaneWithChainDistinctLanes: SingleEmailOtpCompanion = {
  kind: 'single_companion_lane',
  lane: emailOtpCompanionLane,
  // @ts-expect-error Single companion lanes cannot carry chain-distinct lane sets.
  lanes: [emailOtpCompanionLane, emailOtpCompanionLane],
};
void invalidSingleLaneWithChainDistinctLanes;

const invalidChainDistinctWithDirectLane: ChainDistinctEmailOtpCompanion = {
  kind: 'chain_distinct_companion_lanes',
  primaryLane: emailOtpCompanionLane,
  lanes: [emailOtpCompanionLane, emailOtpCompanionLane],
  // @ts-expect-error Chain-distinct companion sets expose primaryLane instead of lane.
  lane: emailOtpCompanionLane,
};
void invalidChainDistinctWithDirectLane;

const invalidChainDistinctWithOneLane: ChainDistinctEmailOtpCompanion = {
  kind: 'chain_distinct_companion_lanes',
  primaryLane: emailOtpCompanionLane,
  // @ts-expect-error Chain-distinct companion sets require at least two lanes.
  lanes: [emailOtpCompanionLane],
};
void invalidChainDistinctWithOneLane;

function assertNeverEmailOtpCompanionSessionAttachResult(result: never): never {
  throw new Error(String((result as { kind?: unknown })?.kind || 'unknown'));
}

declare const attachResult: EmailOtpCompanionSessionAttachResult;

switch (attachResult.kind) {
  case 'attached':
  case 'already_attached':
  case 'not_required':
  case 'missing_required_material':
  case 'failed':
    break;
  default:
    assertNeverEmailOtpCompanionSessionAttachResult(attachResult);
}

export {};
