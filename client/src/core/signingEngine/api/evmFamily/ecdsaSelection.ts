import type { AccountAuthMetadata } from '@/core/signingEngine/auth';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { SigningLaneContext } from '../../session/signingSession/types';
import type {
  EvmFamilyEcdsaConcreteSnapshotLane,
  EvmFamilyEcdsaTransactionLane,
} from '../../session/signingSession/transactionState';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../thresholdLifecycle/thresholdSessionStore';
import { resolveEvmFamilyTransactionAccountAuth, type EvmFamilyAccountMetadataDeps } from './accountAuth';
import {
  buildEvmFamilyEcdsaSigningLaneContext,
  isSingleUseEmailOtpEcdsaRecord,
  logEvmFamilyEcdsaLaneDiagnostic,
  readSelectedEcdsaKeyRefForLane,
  readSelectedEcdsaRecordForLane,
  summarizeEvmFamilyEcdsaKeyRef,
  summarizeEvmFamilyEcdsaLane,
  summarizeEvmFamilyEcdsaSessionRecord,
  tryGetEmailOtpThresholdEcdsaKeyRefForSigning,
  tryGetEmailOtpThresholdEcdsaSessionRecordForSigning,
  tryGetPasskeyThresholdEcdsaKeyRefForSigning,
  tryGetPasskeyThresholdEcdsaSessionRecordForSigning,
  validateSelectedEcdsaKeyRefCandidateForLane,
  validateSelectedEcdsaRecordCandidateForLane,
  type EvmFamilyEcdsaSessionReaderDeps,
  type PasskeyEcdsaSessionStoreSource,
} from './ecdsaLanes';
import type {
  EvmFamilyChain,
  EvmFamilySenderSignatureAlgorithm,
} from './types';

const PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY = [
  'login',
  'manual-bootstrap',
  'registration',
] as const satisfies readonly PasskeyEcdsaSessionStoreSource[];

export type EvmFamilyEcdsaSigningSelectionDeps = EvmFamilyAccountMetadataDeps &
  EvmFamilyEcdsaSessionReaderDeps;

export type EvmFamilyEcdsaSigningSelection = {
  accountAuth: AccountAuthMetadata;
  authMethod: typeof SIGNER_AUTH_METHODS.emailOtp | typeof SIGNER_AUTH_METHODS.passkey;
  source: ThresholdEcdsaSessionStoreSource;
  warmRecord?: ThresholdEcdsaSessionRecord;
  warmKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  reauthRecord?: ThresholdEcdsaSessionRecord;
  lane?: SigningLaneContext;
};

function accountAuthWithSelectedPrimary(
  accountAuth: AccountAuthMetadata,
  authMethod: typeof SIGNER_AUTH_METHODS.emailOtp | typeof SIGNER_AUTH_METHODS.passkey,
): AccountAuthMetadata {
  return {
    ...accountAuth,
    primaryAuthMethod: authMethod,
    linkedAuthMethods: Array.from(new Set([...accountAuth.linkedAuthMethods, authMethod])),
  };
}

function logMissingEcdsaSelectionLane(args: {
  nearAccountId: string;
  chain: EvmFamilyChain;
  authMethod: typeof SIGNER_AUTH_METHODS.emailOtp | typeof SIGNER_AUTH_METHODS.passkey;
  source: ThresholdEcdsaSessionStoreSource;
  emailOtpRecord?: ThresholdEcdsaSessionRecord;
  emailOtpKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  passkeyRecord?: ThresholdEcdsaSessionRecord;
  passkeyKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  selectedRecord?: ThresholdEcdsaSessionRecord;
  selectedKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  lane?: SigningLaneContext;
}): void {
  if (args.lane) return;
  logEvmFamilyEcdsaLaneDiagnostic('lane selection returned no selected lane', {
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    authMethod: args.authMethod,
    source: args.source,
    emailOtpRecord: summarizeEvmFamilyEcdsaSessionRecord(args.emailOtpRecord),
    emailOtpKeyRef: summarizeEvmFamilyEcdsaKeyRef(args.emailOtpKeyRef),
    passkeyRecord: summarizeEvmFamilyEcdsaSessionRecord(args.passkeyRecord),
    passkeyKeyRef: summarizeEvmFamilyEcdsaKeyRef(args.passkeyKeyRef),
    selectedRecord: summarizeEvmFamilyEcdsaSessionRecord(args.selectedRecord),
    selectedKeyRef: summarizeEvmFamilyEcdsaKeyRef(args.selectedKeyRef),
    lane: summarizeEvmFamilyEcdsaLane(args.lane),
  });
}

function pickUnambiguousEcdsaAuthRecord(args: {
  emailOtpRecord?: ThresholdEcdsaSessionRecord;
  emailOtpKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  passkeyRecord?: ThresholdEcdsaSessionRecord;
  passkeyKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): {
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
} {
  const hasEmailOtpLane = !!args.emailOtpRecord || !!args.emailOtpKeyRef;
  const hasPasskeyLane = !!args.passkeyRecord || !!args.passkeyKeyRef;
  if (hasEmailOtpLane === hasPasskeyLane) return {};
  return hasEmailOtpLane
    ? {
        ...(args.emailOtpRecord ? { record: args.emailOtpRecord } : {}),
        ...(args.emailOtpKeyRef ? { keyRef: args.emailOtpKeyRef } : {}),
      }
    : {
        ...(args.passkeyRecord ? { record: args.passkeyRecord } : {}),
        ...(args.passkeyKeyRef ? { keyRef: args.passkeyKeyRef } : {}),
      };
}

function ecdsaMaterialMatchesSnapshotCandidate(args: {
  candidate: EvmFamilyEcdsaConcreteSnapshotLane;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): boolean {
  const expectedThresholdSessionId = String(args.candidate.thresholdSessionId || '').trim();
  const expectedWalletSigningSessionId = String(
    args.candidate.walletSigningSessionId || '',
  ).trim();
  const recordThresholdSessionId = String(args.record?.thresholdSessionId || '').trim();
  const keyRefThresholdSessionId = String(args.keyRef?.thresholdSessionId || '').trim();
  const recordWalletSigningSessionId = String(args.record?.walletSigningSessionId || '').trim();
  const keyRefWalletSigningSessionId = String(args.keyRef?.walletSigningSessionId || '').trim();
  const recordMatches =
    recordThresholdSessionId === expectedThresholdSessionId &&
    recordWalletSigningSessionId === expectedWalletSigningSessionId;
  const keyRefMatches =
    keyRefThresholdSessionId === expectedThresholdSessionId &&
    keyRefWalletSigningSessionId === expectedWalletSigningSessionId;
  const recordChainMatches = !args.record?.chain || args.record.chain === args.candidate.chain;
  return (recordMatches || keyRefMatches) && recordChainMatches;
}

function requireExactEcdsaCandidateMaterial(args: {
  nearAccountId: string;
  chain: EvmFamilyChain;
  candidate: EvmFamilyEcdsaConcreteSnapshotLane;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): void {
  if (args.record || args.keyRef) return;
  logEvmFamilyEcdsaLaneDiagnostic('exact snapshot lane is not present in runtime stores', {
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    candidate: {
      authMethod: args.candidate.authMethod,
      thresholdSessionId: args.candidate.thresholdSessionId,
      walletSigningSessionId: args.candidate.walletSigningSessionId,
      state: args.candidate.state,
      source: args.candidate.source,
    },
  });
  throw new Error('[SigningEngine][ecdsa] exact snapshot lane is unavailable after restore');
}

function assertTransactionLaneMatchesSnapshotCandidate(args: {
  transactionLane?: EvmFamilyEcdsaTransactionLane;
  candidate?: EvmFamilyEcdsaConcreteSnapshotLane;
}): void {
  if (!args.transactionLane || !args.candidate) return;
  if (
    args.transactionLane.authMethod !== args.candidate.authMethod ||
    args.transactionLane.chain !== args.candidate.chain ||
    String(args.transactionLane.walletSigningSessionId) !==
      String(args.candidate.walletSigningSessionId) ||
    String(args.transactionLane.thresholdSessionId) !== String(args.candidate.thresholdSessionId)
  ) {
    throw new Error('[SigningEngine][ecdsa] transaction lane does not match snapshot candidate');
  }
}

function listPasskeyEcdsaSigningCandidates(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  nearAccountId: string;
  chain: EvmFamilyChain;
}): Array<{
  source: PasskeyEcdsaSessionStoreSource;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}> {
  const candidates: Array<{
    source: PasskeyEcdsaSessionStoreSource;
    record?: ThresholdEcdsaSessionRecord;
    keyRef?: ThresholdEcdsaSecp256k1KeyRef;
  }> = [];
  for (const source of PASSKEY_ECDSA_SIGNING_SOURCE_PRIORITY) {
    const record = tryGetPasskeyThresholdEcdsaSessionRecordForSigning({
      deps: args.deps,
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      source,
    });
    const keyRef = tryGetPasskeyThresholdEcdsaKeyRefForSigning({
      deps: args.deps,
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      source,
    });
    if (!record && !keyRef) continue;
    candidates.push({
      source,
      ...(record ? { record } : {}),
      ...(keyRef ? { keyRef } : {}),
    });
  }
  return candidates;
}

export async function resolveEvmFamilyEcdsaSigningSelection(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  nearAccountId: string;
  chain: EvmFamilyChain;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  authMethod: typeof SIGNER_AUTH_METHODS.emailOtp | typeof SIGNER_AUTH_METHODS.passkey;
  transactionLane?: EvmFamilyEcdsaTransactionLane;
  snapshotCandidate?: EvmFamilyEcdsaConcreteSnapshotLane;
}): Promise<EvmFamilyEcdsaSigningSelection> {
  assertTransactionLaneMatchesSnapshotCandidate({
    ...(args.transactionLane ? { transactionLane: args.transactionLane } : {}),
    ...(args.snapshotCandidate ? { candidate: args.snapshotCandidate } : {}),
  });
  const emailOtpRecord = tryGetEmailOtpThresholdEcdsaSessionRecordForSigning({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    chain: args.chain,
  });
  const emailOtpKeyRef = tryGetEmailOtpThresholdEcdsaKeyRefForSigning({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    chain: args.chain,
  });

  const passkeyCandidates = listPasskeyEcdsaSigningCandidates({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    chain: args.chain,
  });
  const selectedPasskeyCandidate =
    args.snapshotCandidate?.authMethod === SIGNER_AUTH_METHODS.passkey
      ? passkeyCandidates.find((candidate) =>
          ecdsaMaterialMatchesSnapshotCandidate({
            candidate: args.snapshotCandidate!,
            ...(candidate.record ? { record: candidate.record } : {}),
            ...(candidate.keyRef ? { keyRef: candidate.keyRef } : {}),
          }),
        )
      : passkeyCandidates[0];
  const passkeyRecord = selectedPasskeyCandidate?.record;
  const passkeyKeyRef = selectedPasskeyCandidate?.keyRef;

  const unambiguousLane = pickUnambiguousEcdsaAuthRecord({
    ...(emailOtpRecord ? { emailOtpRecord } : {}),
    ...(emailOtpKeyRef ? { emailOtpKeyRef } : {}),
    ...(passkeyRecord ? { passkeyRecord } : {}),
    ...(passkeyKeyRef ? { passkeyKeyRef } : {}),
  });
  const accountAuth = await resolveEvmFamilyTransactionAccountAuth({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    senderSignatureAlgorithm: args.senderSignatureAlgorithm,
    ...unambiguousLane,
  });

  const selectedAuthMethod = args.transactionLane?.authMethod || args.authMethod;
  const selectedAccountAuth = accountAuthWithSelectedPrimary(accountAuth, selectedAuthMethod);

  if (selectedAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
    const exactCandidate = args.snapshotCandidate;
    const selectedEmailOtpRecord =
      exactCandidate?.authMethod === SIGNER_AUTH_METHODS.emailOtp
        ? ecdsaMaterialMatchesSnapshotCandidate({
            candidate: exactCandidate,
            ...(emailOtpRecord ? { record: emailOtpRecord } : {}),
          })
          ? emailOtpRecord
          : undefined
        : emailOtpRecord;
    const selectedEmailOtpKeyRef =
      exactCandidate?.authMethod === SIGNER_AUTH_METHODS.emailOtp
        ? ecdsaMaterialMatchesSnapshotCandidate({
            candidate: exactCandidate,
            ...(emailOtpKeyRef ? { keyRef: emailOtpKeyRef } : {}),
          })
          ? emailOtpKeyRef
          : undefined
        : emailOtpKeyRef;
    if (exactCandidate?.authMethod === SIGNER_AUTH_METHODS.emailOtp) {
      requireExactEcdsaCandidateMaterial({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        candidate: exactCandidate,
        ...(selectedEmailOtpRecord ? { record: selectedEmailOtpRecord } : {}),
        ...(selectedEmailOtpKeyRef ? { keyRef: selectedEmailOtpKeyRef } : {}),
      });
    }
    const signingLane = buildEvmFamilyEcdsaSigningLaneContext({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      source: SIGNER_AUTH_METHODS.emailOtp,
      ...(selectedEmailOtpRecord ? { record: selectedEmailOtpRecord } : {}),
      ...(selectedEmailOtpKeyRef ? { keyRef: selectedEmailOtpKeyRef } : {}),
    });
    const selectedRecord = selectedEmailOtpRecord
      ? validateSelectedEcdsaRecordCandidateForLane({
          lane: signingLane,
          record: selectedEmailOtpRecord,
          context: 'Email OTP ECDSA selection',
        })
      : readSelectedEcdsaRecordForLane({ deps: args.deps, lane: signingLane });
    const selectedKeyRef = selectedEmailOtpKeyRef
      ? validateSelectedEcdsaKeyRefCandidateForLane({
          lane: signingLane,
          keyRef: selectedEmailOtpKeyRef,
          context: 'Email OTP ECDSA selection',
        })
      : readSelectedEcdsaKeyRefForLane({ deps: args.deps, lane: signingLane });
    const warmRecord =
      selectedRecord && !isSingleUseEmailOtpEcdsaRecord(selectedRecord)
        ? selectedRecord
        : undefined;
    logMissingEcdsaSelectionLane({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      source: SIGNER_AUTH_METHODS.emailOtp,
      ...(emailOtpRecord ? { emailOtpRecord } : {}),
      ...(emailOtpKeyRef ? { emailOtpKeyRef } : {}),
      ...(passkeyRecord ? { passkeyRecord } : {}),
      ...(passkeyKeyRef ? { passkeyKeyRef } : {}),
      ...(selectedRecord ? { selectedRecord } : {}),
      ...(selectedKeyRef ? { selectedKeyRef } : {}),
      ...(signingLane ? { lane: signingLane } : {}),
    });
    return {
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      accountAuth: selectedAccountAuth,
      source: SIGNER_AUTH_METHODS.emailOtp,
      ...(warmRecord ? { warmRecord } : {}),
      ...(warmRecord && selectedKeyRef ? { warmKeyRef: selectedKeyRef } : {}),
      ...(selectedRecord ? { reauthRecord: selectedRecord } : {}),
      ...(signingLane ? { lane: signingLane } : {}),
    };
  }

  if (args.snapshotCandidate?.authMethod === SIGNER_AUTH_METHODS.passkey) {
    requireExactEcdsaCandidateMaterial({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      candidate: args.snapshotCandidate,
      ...(passkeyRecord ? { record: passkeyRecord } : {}),
      ...(passkeyKeyRef ? { keyRef: passkeyKeyRef } : {}),
    });
  }
  const passkeySource = selectedPasskeyCandidate?.source || 'manual-bootstrap';
  const signingLane = buildEvmFamilyEcdsaSigningLaneContext({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    authMethod: SIGNER_AUTH_METHODS.passkey,
    source: passkeySource,
    ...(passkeyRecord ? { record: passkeyRecord } : {}),
    ...(passkeyKeyRef ? { keyRef: passkeyKeyRef } : {}),
  });
  const selectedPasskeyRecord = passkeyRecord
    ? validateSelectedEcdsaRecordCandidateForLane({
        lane: signingLane,
        record: passkeyRecord,
        context: 'passkey ECDSA selection',
      })
    : readSelectedEcdsaRecordForLane({
        deps: args.deps,
        lane: signingLane,
      });
  const selectedPasskeyKeyRef = passkeyKeyRef
    ? validateSelectedEcdsaKeyRefCandidateForLane({
        lane: signingLane,
        keyRef: passkeyKeyRef,
        context: 'passkey ECDSA selection',
      })
    : readSelectedEcdsaKeyRefForLane({
        deps: args.deps,
        lane: signingLane,
      });
  const selectedWarmRecord =
    selectedPasskeyRecord && !isSingleUseEmailOtpEcdsaRecord(selectedPasskeyRecord)
      ? selectedPasskeyRecord
      : undefined;
  logMissingEcdsaSelectionLane({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    authMethod: SIGNER_AUTH_METHODS.passkey,
    source: passkeySource,
    ...(emailOtpRecord ? { emailOtpRecord } : {}),
    ...(emailOtpKeyRef ? { emailOtpKeyRef } : {}),
    ...(passkeyRecord ? { passkeyRecord } : {}),
    ...(passkeyKeyRef ? { passkeyKeyRef } : {}),
    ...(selectedPasskeyRecord ? { selectedRecord: selectedPasskeyRecord } : {}),
    ...(selectedPasskeyKeyRef ? { selectedKeyRef: selectedPasskeyKeyRef } : {}),
    ...(signingLane ? { lane: signingLane } : {}),
  });
  return {
    authMethod: SIGNER_AUTH_METHODS.passkey,
    accountAuth: selectedAccountAuth,
    source: passkeySource,
    ...(selectedWarmRecord ? { warmRecord: selectedWarmRecord } : {}),
    ...(selectedWarmRecord && selectedPasskeyKeyRef ? { warmKeyRef: selectedPasskeyKeyRef } : {}),
    ...(signingLane ? { lane: signingLane } : {}),
  };
}
