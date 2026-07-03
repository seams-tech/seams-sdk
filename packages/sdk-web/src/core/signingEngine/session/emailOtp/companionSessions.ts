import {
  listStoredThresholdEcdsaSessionRecordsForWallet,
  thresholdEcdsaLaneCandidateFromSessionRecord,
  toExactEcdsaSigningLaneIdentity,
} from '@/core/signingEngine/session/persistence/records';
import type {
  EmailOtpEcdsaSessionRecord,
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  thresholdEcdsaChainTargetKey,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ExactEcdsaSigningLaneIdentity } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type {
  BuildCurrentSealedSessionRecordInput,
  SigningSessionSealedRecordFilter,
  SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { emailOtpAuthContextRetention } from '../identity/laneIdentity';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { buildEcdsaMaterialStateForCandidate } from '../../flows/signEvmFamily/ecdsaMaterialState';
import {
  commitEmailOtpEcdsaLaneFromRecordForMaterial,
  EmailOtpEcdsaCommittedLaneStateError,
  resolvedEvmFamilyEcdsaSigningLaneFromCandidate,
  type RecordBackedEcdsaCommittedLane,
} from '../../flows/signEvmFamily/ecdsaSelection';

type EmailOtpEcdsaRecordForEd25519SigningSelection =
  | {
      kind: 'signing_grant_exact';
      walletId: WalletId;
      signingGrantId: string;
      listThresholdEcdsaSessionRecordsForWallet?: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
    }
  | {
      kind: 'latest_wallet_record';
      walletId: WalletId;
      signingGrantId?: never;
      listThresholdEcdsaSessionRecordsForWallet?: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
    };

export type EmailOtpEcdsaCompanionLaneForEd25519Signing = {
  kind: 'email_otp_ecdsa_companion_lane';
  authMethod: 'email_otp';
  walletId: WalletId;
  signingGrantId: string;
  chainTargetKey: string;
  committedLane: RecordBackedEcdsaCommittedLane<EmailOtpWalletAuthAuthority>;
  record?: never;
  passkeyRecord?: never;
  exactIdentity: ExactEcdsaSigningLaneIdentity;
  walletSessionAuthority?: never;
};

export type ChainDistinctEmailOtpEcdsaCompanionLanes = readonly [
  EmailOtpEcdsaCompanionLaneForEd25519Signing,
  EmailOtpEcdsaCompanionLaneForEd25519Signing,
  ...EmailOtpEcdsaCompanionLaneForEd25519Signing[],
];

export type EmailOtpEcdsaCompanionForEd25519Signing =
  | {
      kind: 'single_companion_lane';
      lane: EmailOtpEcdsaCompanionLaneForEd25519Signing;
      primaryLane?: never;
      lanes?: never;
    }
  | {
      kind: 'chain_distinct_companion_lanes';
      primaryLane: EmailOtpEcdsaCompanionLaneForEd25519Signing;
      lanes: ChainDistinctEmailOtpEcdsaCompanionLanes;
      lane?: never;
    };

export type EmailOtpEcdsaCompanionSelectionResult =
  | {
      kind: 'ready';
      companion: EmailOtpEcdsaCompanionForEd25519Signing;
    }
  | {
      kind: 'duplicate_chain_lanes';
      chainTargetKey: string;
      count: number;
    }
  | {
      kind: 'not_found';
    }
  | {
      kind: 'display_only_fallback';
      lane: EmailOtpEcdsaCompanionLaneForEd25519Signing;
    };

function emailOtpEcdsaSessionRecord(
  record: ThresholdEcdsaSessionRecord,
): record is EmailOtpEcdsaSessionRecord {
  return record.source === 'email_otp';
}

function duplicateChainTarget(
  lanes: readonly EmailOtpEcdsaCompanionLaneForEd25519Signing[],
): { chainTargetKey: string; count: number } | null {
  const counts = new Map<string, number>();
  for (const lane of lanes) {
    counts.set(lane.chainTargetKey, (counts.get(lane.chainTargetKey) || 0) + 1);
  }
  for (const [chainTargetKey, count] of counts.entries()) {
    if (count > 1) return { chainTargetKey, count };
  }
  return null;
}

function commitEmailOtpEcdsaCompanionLaneForEd25519Signing(
  record: EmailOtpEcdsaSessionRecord,
): EmailOtpEcdsaCompanionLaneForEd25519Signing {
  const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({ record });
  const lane = resolvedEvmFamilyEcdsaSigningLaneFromCandidate(candidate);
  const material = buildEcdsaMaterialStateForCandidate({
    candidate,
    record,
    authMethod: 'email_otp',
    source: 'email_otp',
    chainTarget: record.chainTarget,
    materialChainTarget: record.chainTarget,
  });
  const committedLane = commitEmailOtpEcdsaLaneFromRecordForMaterial({
    lane,
    record,
    material,
  });
  if (committedLane.source !== 'record_backed') {
    throw new Error('Email OTP ECDSA companion lane requires record-backed committed lane');
  }
  return {
    kind: 'email_otp_ecdsa_companion_lane',
    authMethod: 'email_otp',
    walletId: record.walletId,
    signingGrantId: record.signingGrantId,
    chainTargetKey: thresholdEcdsaChainTargetKey(record.chainTarget),
    committedLane,
    exactIdentity: toExactEcdsaSigningLaneIdentity(record),
  };
}

function isMissingEmailOtpEcdsaCompanionAuthority(error: unknown): boolean {
  return (
    error instanceof EmailOtpEcdsaCommittedLaneStateError &&
    error.failure.kind === 'authority_missing'
  );
}

function tryCommitEmailOtpEcdsaCompanionLaneForEd25519Signing(
  record: EmailOtpEcdsaSessionRecord,
): EmailOtpEcdsaCompanionLaneForEd25519Signing | null {
  try {
    return commitEmailOtpEcdsaCompanionLaneForEd25519Signing(record);
  } catch (error) {
    if (!isMissingEmailOtpEcdsaCompanionAuthority(error)) throw error;
    return null;
  }
}

function toChainDistinctEmailOtpEcdsaCompanionLanes(
  lanes: readonly EmailOtpEcdsaCompanionLaneForEd25519Signing[],
): ChainDistinctEmailOtpEcdsaCompanionLanes {
  const firstLane = lanes[0];
  const secondLane = lanes[1];
  if (!firstLane || !secondLane) {
    throw new Error('Email OTP chain-distinct companion selection requires at least two lanes');
  }
  return [firstLane, secondLane, ...lanes.slice(2)];
}

function emailOtpEcdsaRecordHasSigningMaterial(record: EmailOtpEcdsaSessionRecord): boolean {
  return (
    String(record.keyHandle || '').trim().length > 0 &&
    Array.isArray(record.participantIds) &&
    record.participantIds.length > 0
  );
}

function compareEmailOtpEcdsaCompanionLanesForEd25519Signing(
  left: EmailOtpEcdsaCompanionLaneForEd25519Signing,
  right: EmailOtpEcdsaCompanionLaneForEd25519Signing,
): number {
  return (
    Math.floor(Number(right.committedLane.record.updatedAtMs) || 0) -
      Math.floor(Number(left.committedLane.record.updatedAtMs) || 0) ||
    left.chainTargetKey.localeCompare(right.chainTargetKey) ||
    String(left.committedLane.record.thresholdSessionId).localeCompare(
      String(right.committedLane.record.thresholdSessionId),
    )
  );
}

function emailOtpEcdsaCompanionLanesMatchingSigningGrantId(args: {
  lanes: readonly EmailOtpEcdsaCompanionLaneForEd25519Signing[];
  signingGrantId: string;
}): EmailOtpEcdsaCompanionLaneForEd25519Signing[] {
  const matches: EmailOtpEcdsaCompanionLaneForEd25519Signing[] = [];
  for (const lane of args.lanes) {
    if (lane.signingGrantId === args.signingGrantId) matches.push(lane);
  }
  return matches;
}

function companionSelectionFromExactLanes(
  lanes: readonly EmailOtpEcdsaCompanionLaneForEd25519Signing[],
): EmailOtpEcdsaCompanionSelectionResult {
  const firstLane = lanes[0];
  if (!firstLane) return { kind: 'not_found' };
  const duplicate = duplicateChainTarget(lanes);
  if (duplicate) {
    return {
      kind: 'duplicate_chain_lanes',
      chainTargetKey: duplicate.chainTargetKey,
      count: duplicate.count,
    };
  }
  if (lanes.length === 1) {
    return {
      kind: 'ready',
      companion: {
        kind: 'single_companion_lane',
        lane: firstLane,
      },
    };
  }
  return {
    kind: 'ready',
    companion: {
      kind: 'chain_distinct_companion_lanes',
      primaryLane: firstLane,
      lanes: toChainDistinctEmailOtpEcdsaCompanionLanes(lanes),
    },
  };
}

function committedEmailOtpEcdsaCompanionLanesForWallet(args: {
  walletId: WalletId;
  listThresholdEcdsaSessionRecordsForWallet?: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
}): EmailOtpEcdsaCompanionLaneForEd25519Signing[] {
  const lanes: EmailOtpEcdsaCompanionLaneForEd25519Signing[] = [];
  const records = (
    args.listThresholdEcdsaSessionRecordsForWallet?.(args.walletId) ??
    listStoredThresholdEcdsaSessionRecordsForWallet(args.walletId)
  )
    .filter((record) => record.walletId === args.walletId)
    .filter(emailOtpEcdsaSessionRecord)
    .filter(emailOtpEcdsaRecordHasSigningMaterial);
  for (const record of records) {
    const lane = tryCommitEmailOtpEcdsaCompanionLaneForEd25519Signing(record);
    if (lane) lanes.push(lane);
  }
  return lanes.sort(compareEmailOtpEcdsaCompanionLanesForEd25519Signing);
}

export function selectEmailOtpEcdsaCompanionLaneForEd25519Signing(
  args: EmailOtpEcdsaRecordForEd25519SigningSelection,
): EmailOtpEcdsaCompanionSelectionResult {
  const lanes = committedEmailOtpEcdsaCompanionLanesForWallet({
    walletId: args.walletId,
    listThresholdEcdsaSessionRecordsForWallet: args.listThresholdEcdsaSessionRecordsForWallet,
  });
  switch (args.kind) {
    case 'signing_grant_exact': {
      const signingGrantId = String(args.signingGrantId || '').trim();
      if (!signingGrantId) return { kind: 'not_found' };
      const matches = emailOtpEcdsaCompanionLanesMatchingSigningGrantId({
        lanes,
        signingGrantId,
      });
      return companionSelectionFromExactLanes(matches);
    }
    case 'latest_wallet_record': {
      const lane = lanes[0];
      if (!lane) return { kind: 'not_found' };
      return {
        kind: 'display_only_fallback',
        lane,
      };
    }
    default: {
      const exhaustive: never = args;
      throw new Error(
        `[EmailOtpSession] unsupported ECDSA companion selection: ${String(
          (exhaustive as { kind?: unknown })?.kind || '',
        )}`,
      );
    }
  }
}

type EmailOtpEcdsaCompanionSealCandidate = {
  existingRecord: SigningSessionSealedStoreRecord;
  ecdsaRecord: ThresholdEcdsaSessionRecord;
};

export type EmailOtpCompanionSessionAttachResult =
  | {
      kind: 'attached';
    }
  | {
      kind: 'already_attached';
    }
  | {
      kind: 'not_required';
      reason: 'session_persistence_disabled' | 'handle_backed_companion_not_supported';
    }
  | {
      kind: 'missing_required_material';
      reason:
        | 'missing_threshold_session_id'
        | 'missing_ecdsa_sealed_session'
        | 'missing_email_otp_ed25519_record'
        | 'signing_grant_mismatch';
    }
  | {
      kind: 'failed';
      message: string;
    };

async function readEmailOtpEcdsaCompanionSealCandidate(args: {
  ecdsaThresholdSessionId: string;
  readExactSealedSession: (
    thresholdSessionId: string,
    filter: SigningSessionSealedRecordFilter,
  ) => Promise<SigningSessionSealedStoreRecord | null>;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
}): Promise<EmailOtpEcdsaCompanionSealCandidate | null> {
  const ecdsaRecord = args.getThresholdEcdsaSessionRecordByThresholdSessionId(
    args.ecdsaThresholdSessionId,
  );
  if (!ecdsaRecord || ecdsaRecord.source !== 'email_otp' || !ecdsaRecord.chainTarget) return null;
  const existingRecord = await args
    .readExactSealedSession(args.ecdsaThresholdSessionId, {
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: ecdsaRecord.chainTarget,
    })
    .catch(() => null);
  if (!existingRecord || existingRecord.authMethod !== 'email_otp') return null;
  return { existingRecord, ecdsaRecord };
}

export async function attachEd25519SessionToEmailOtpSigningSessionSeal(args: {
  sessionPersistenceMode?: string | null;
  ecdsaThresholdSessionId: string;
  ed25519ThresholdSessionId: string;
  readExactSealedSession: (
    thresholdSessionId: string,
    filter: SigningSessionSealedRecordFilter,
  ) => Promise<SigningSessionSealedStoreRecord | null>;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  getThresholdEd25519SessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
  registerSigningSession: (record: BuildCurrentSealedSessionRecordInput) => Promise<void>;
}): Promise<EmailOtpCompanionSessionAttachResult> {
  if (args.sessionPersistenceMode !== 'sealed_refresh_v1') {
    return { kind: 'not_required', reason: 'session_persistence_disabled' };
  }
  const ecdsaThresholdSessionId = String(args.ecdsaThresholdSessionId || '').trim();
  const ed25519ThresholdSessionId = String(args.ed25519ThresholdSessionId || '').trim();
  if (!ecdsaThresholdSessionId || !ed25519ThresholdSessionId) {
    return { kind: 'missing_required_material', reason: 'missing_threshold_session_id' };
  }
  const candidate = await readEmailOtpEcdsaCompanionSealCandidate({
    ecdsaThresholdSessionId,
    readExactSealedSession: args.readExactSealedSession,
    getThresholdEcdsaSessionRecordByThresholdSessionId:
      args.getThresholdEcdsaSessionRecordByThresholdSessionId,
  });
  if (!candidate) {
    return { kind: 'missing_required_material', reason: 'missing_ecdsa_sealed_session' };
  }
  const ed25519Record =
    args.getThresholdEd25519SessionRecordByThresholdSessionId(ed25519ThresholdSessionId);
  if (!ed25519Record || ed25519Record.source !== 'email_otp') {
    return { kind: 'missing_required_material', reason: 'missing_email_otp_ed25519_record' };
  }
  if (
    !ed25519Record.emailOtpAuthContext ||
    emailOtpAuthContextRetention(ed25519Record.emailOtpAuthContext) !== 'session' ||
    ed25519Record.signingGrantId !== candidate.existingRecord.signingGrantId
  ) {
    return { kind: 'missing_required_material', reason: 'signing_grant_mismatch' };
  }
  // The current sealed companion schema can only carry raw Ed25519 material.
  // Keep this no-op until Phase 15.12 replaces it with handle-backed metadata.
  return { kind: 'not_required', reason: 'handle_backed_companion_not_supported' };
}
