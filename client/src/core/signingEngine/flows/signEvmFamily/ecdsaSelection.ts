import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { EcdsaLaneCandidate, ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import { SigningSessionIds } from '../../session/signingSession/types';
import { emitSigningSessionFlowFailure } from '../../session/signingSession/trace';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import {
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '../../session/signingSession/lanes';
import {
  resolveEvmFamilyTransactionAccountAuth,
  type EvmFamilyAccountMetadataDeps,
} from './accountAuth';
import {
  buildEvmFamilyEcdsaSigningLaneContext,
  findExactEcdsaKeyRefForSelectedLane,
  findExactEcdsaSessionRecordForSelectedLane,
  isEmailOtpThresholdEcdsaSigningContext,
  isSingleUseEmailOtpEcdsaRecord,
  logEvmFamilyEcdsaLaneDiagnostic,
  readSelectedEcdsaKeyRefForLane,
  readSelectedEcdsaRecordForLane,
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaKeyRef,
  summarizeEvmFamilyEcdsaLane,
  summarizeEvmFamilyEcdsaSessionRecord,
  tryGetEmailOtpThresholdEcdsaKeyRefForSigning,
  tryGetEmailOtpThresholdEcdsaSessionRecordForSigning,
  tryGetPasskeyThresholdEcdsaKeyRefForSigning,
  tryGetPasskeyThresholdEcdsaSessionRecordForSigning,
  validateSelectedEcdsaKeyRefCandidateForLane,
  validateSelectedEcdsaRecordCandidateForLane,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type {
  EvmFamilyEcdsaSessionReaderDeps,
  PasskeyEcdsaSessionStoreSource,
} from '../../interfaces/operationDeps';
import type { EvmFamilyChain, EvmFamilySenderSignatureAlgorithm } from './types';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

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
  lane?: ResolvedEvmFamilyEcdsaSigningLane;
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
  lane?: ResolvedEvmFamilyEcdsaSigningLane;
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

function ecdsaMaterialMatchesLaneCandidate(args: {
  candidate: EcdsaLaneCandidate;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): boolean {
  const expectedSubjectId = String(args.candidate.subjectId || '').trim();
  const expectedThresholdKeyId = String(args.candidate.ecdsaThresholdKeyId || '').trim();
  const expectedSigningRootId = String(args.candidate.signingRootId || '').trim();
  const expectedSigningRootVersion = String(args.candidate.signingRootVersion || '').trim();
  const expectedThresholdSessionId = String(args.candidate.thresholdSessionId || '').trim();
  const expectedWalletSigningSessionId = String(args.candidate.walletSigningSessionId || '').trim();
  const recordMatches =
    !!args.record &&
    String(args.record.subjectId || '').trim() === expectedSubjectId &&
    thresholdEcdsaChainTargetsEqual(args.record.chainTarget, args.candidate.chainTarget) &&
    String(args.record.ecdsaThresholdKeyId || '').trim() === expectedThresholdKeyId &&
    String(args.record.signingRootId || '').trim() === expectedSigningRootId &&
    String(args.record.signingRootVersion || 'default').trim() === expectedSigningRootVersion &&
    String(args.record.walletSigningSessionId || '').trim() === expectedWalletSigningSessionId &&
    String(args.record.thresholdSessionId || '').trim() === expectedThresholdSessionId;
  const keyRefMatches =
    !!args.keyRef &&
    String(args.keyRef.subjectId || '').trim() === expectedSubjectId &&
    thresholdEcdsaChainTargetsEqual(args.keyRef.chainTarget, args.candidate.chainTarget) &&
    String(args.keyRef.ecdsaThresholdKeyId || '').trim() === expectedThresholdKeyId &&
    String(args.keyRef.signingRootId || '').trim() === expectedSigningRootId &&
    String(args.keyRef.signingRootVersion || 'default').trim() === expectedSigningRootVersion &&
    String(args.keyRef.walletSigningSessionId || '').trim() === expectedWalletSigningSessionId &&
    String(args.keyRef.thresholdSessionId || '').trim() === expectedThresholdSessionId;
  return recordMatches || keyRefMatches;
}

function requireExactEcdsaCandidateMaterial(args: {
  nearAccountId: string;
  chain: EvmFamilyChain;
  candidate: EcdsaLaneCandidate;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): void {
  if (args.record || args.keyRef) return;
  logEvmFamilyEcdsaLaneDiagnostic('exact available lane is not present in runtime stores', {
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
  emitSigningSessionFlowFailure('evm-family', {
    stage: 'ecdsa_selection.exact_material_missing',
    accountId: args.nearAccountId,
    chain: args.chain,
    candidate: {
      authMethod: args.candidate.authMethod,
      thresholdSessionId: args.candidate.thresholdSessionId,
      walletSigningSessionId: args.candidate.walletSigningSessionId,
      state: args.candidate.state,
      source: args.candidate.source,
    },
    record: summarizeEvmFamilyEcdsaSessionRecord(args.record),
    keyRef: summarizeEvmFamilyEcdsaKeyRef(args.keyRef),
  });
  throw new Error('[SigningEngine][ecdsa] exact available lane is unavailable after restore');
}

function exactEcdsaCandidateRequiresHotMaterial(
  candidate: EcdsaLaneCandidate | undefined,
): boolean {
  if (!candidate) return false;
  return (
    candidate.state === 'ready' ||
    candidate.state === 'restorable' ||
    candidate.state === 'deferred'
  );
}

function signingLaneFromExactLaneCandidate(
  candidate: EcdsaLaneCandidate | undefined,
): ResolvedEvmFamilyEcdsaSigningLane | undefined {
  if (!candidate) return undefined;
  const buildLane =
    candidate.chainTarget.kind === 'tempo'
      ? buildTempoTransactionSigningLane
      : buildEvmTransactionSigningLane;
  const base = {
    accountId: candidate.accountId,
    subjectId: candidate.subjectId,
    chainTarget: candidate.chainTarget,
    ecdsaThresholdKeyId: candidate.ecdsaThresholdKeyId,
    signingRootId: candidate.signingRootId,
    signingRootVersion: candidate.signingRootVersion,
    walletSigningSessionId: SigningSessionIds.walletSigningSession(
      candidate.walletSigningSessionId,
    ),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(candidate.thresholdSessionId),
  };
  const lane = buildLane(
    candidate.authMethod === SIGNER_AUTH_METHODS.emailOtp
      ? {
          ...base,
          authMethod: SIGNER_AUTH_METHODS.emailOtp,
          retention: 'session',
          sessionOrigin: 'per_operation',
        }
      : {
          ...base,
          authMethod: SIGNER_AUTH_METHODS.passkey,
          storageSource: 'manual-bootstrap',
        },
  );
  return requireResolvedEvmFamilyEcdsaSigningLane({
    lane,
    chain: candidate.chain,
    context: 'build exact ECDSA candidate signing lane',
  });
}

function listPasskeyEcdsaSigningCandidates(args: {
  deps: EvmFamilyEcdsaSigningSelectionDeps;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
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
      subjectId: args.subjectId,
      chainTarget: args.chainTarget,
      source,
    });
    const keyRef = tryGetPasskeyThresholdEcdsaKeyRefForSigning({
      deps: args.deps,
      subjectId: args.subjectId,
      chainTarget: args.chainTarget,
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
  subjectId: WalletSubjectId;
  chain: EvmFamilyChain;
  chainTarget: ThresholdEcdsaChainTarget;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  authMethod: typeof SIGNER_AUTH_METHODS.emailOtp | typeof SIGNER_AUTH_METHODS.passkey;
  laneCandidate?: EcdsaLaneCandidate;
  allowMissingHotMaterial?: boolean;
}): Promise<EvmFamilyEcdsaSigningSelection> {
  const exactSelectedLane = signingLaneFromExactLaneCandidate(args.laneCandidate);
  const exactRecordForCandidate = exactSelectedLane
    ? findExactEcdsaSessionRecordForSelectedLane({
        deps: args.deps,
        lane: exactSelectedLane,
      })
    : undefined;
  const exactKeyRefMatchForCandidate = exactSelectedLane
    ? findExactEcdsaKeyRefForSelectedLane({
        deps: args.deps,
        lane: exactSelectedLane,
      })
    : undefined;
  const exactKeyRefForCandidate = exactKeyRefMatchForCandidate?.keyRef;

  const genericEmailOtpRecord = tryGetEmailOtpThresholdEcdsaSessionRecordForSigning({
    deps: args.deps,
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
  });
  const genericEmailOtpKeyRef = tryGetEmailOtpThresholdEcdsaKeyRefForSigning({
    deps: args.deps,
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
  });
  const emailOtpRecord =
    args.laneCandidate?.authMethod === SIGNER_AUTH_METHODS.emailOtp
      ? exactRecordForCandidate
      : genericEmailOtpRecord;
  const emailOtpKeyRef =
    args.laneCandidate?.authMethod === SIGNER_AUTH_METHODS.emailOtp
      ? exactKeyRefForCandidate
      : genericEmailOtpKeyRef;

  const passkeyCandidates = listPasskeyEcdsaSigningCandidates({
    deps: args.deps,
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
  });
  const exactPasskeyCandidate =
    args.laneCandidate?.authMethod === SIGNER_AUTH_METHODS.passkey &&
    (exactRecordForCandidate || exactKeyRefForCandidate) &&
    exactKeyRefMatchForCandidate?.source !== SIGNER_AUTH_METHODS.emailOtp
      ? {
          source: (exactRecordForCandidate?.source ||
            exactKeyRefMatchForCandidate?.source ||
            'manual-bootstrap') as PasskeyEcdsaSessionStoreSource,
          ...(exactRecordForCandidate ? { record: exactRecordForCandidate } : {}),
          ...(exactKeyRefForCandidate ? { keyRef: exactKeyRefForCandidate } : {}),
        }
      : undefined;
  const selectedPasskeyCandidate =
    exactPasskeyCandidate ||
    (args.laneCandidate?.authMethod === SIGNER_AUTH_METHODS.passkey
      ? passkeyCandidates.find((candidate) =>
          ecdsaMaterialMatchesLaneCandidate({
            candidate: args.laneCandidate!,
            ...(candidate.record ? { record: candidate.record } : {}),
            ...(candidate.keyRef ? { keyRef: candidate.keyRef } : {}),
          }),
        )
      : passkeyCandidates[0]);
  const passkeyRecord = selectedPasskeyCandidate?.record;
  const passkeyKeyRef = selectedPasskeyCandidate?.keyRef;

  try {
    console.info('[SigningEngine][ecdsa][post-restore-inventory]', {
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      requestedAuthMethod: args.authMethod,
      allowMissingHotMaterial: args.allowMissingHotMaterial === true,
      selectedLaneCandidate: args.laneCandidate
        ? {
            authMethod: args.laneCandidate.authMethod,
            chain: args.laneCandidate.chainTarget.kind,
            chainTarget: args.laneCandidate.chainTarget,
            state: args.laneCandidate.state,
            source: args.laneCandidate.source,
            walletSigningSessionId: args.laneCandidate.walletSigningSessionId,
            thresholdSessionId: args.laneCandidate.thresholdSessionId,
            remainingUses: args.laneCandidate.remainingUses,
            expiresAtMs: args.laneCandidate.expiresAtMs,
            updatedAtMs: args.laneCandidate.updatedAtMs,
          }
        : { present: false },
      visibleEmailOtp: {
        record: summarizeEvmFamilyEcdsaSessionRecord(genericEmailOtpRecord),
        keyRef: summarizeEvmFamilyEcdsaKeyRef(genericEmailOtpKeyRef),
      },
      exactCandidateMaterial: {
        record: summarizeEvmFamilyEcdsaSessionRecord(exactRecordForCandidate),
        keyRef: summarizeEvmFamilyEcdsaKeyRef(exactKeyRefForCandidate),
        keyRefSource: exactKeyRefMatchForCandidate?.source || null,
      },
      visiblePasskeyCandidates: passkeyCandidates.map((candidate) => ({
        source: candidate.source,
        record: summarizeEvmFamilyEcdsaSessionRecord(candidate.record),
        keyRef: summarizeEvmFamilyEcdsaKeyRef(candidate.keyRef),
      })),
      selectedPasskeyCandidate: selectedPasskeyCandidate
        ? {
            source: selectedPasskeyCandidate.source,
            record: summarizeEvmFamilyEcdsaSessionRecord(selectedPasskeyCandidate.record),
            keyRef: summarizeEvmFamilyEcdsaKeyRef(selectedPasskeyCandidate.keyRef),
          }
        : { present: false },
    });
  } catch {}

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
    ...(unambiguousLane.record ? { sessionSource: unambiguousLane.record.source } : {}),
    isEmailOtpThresholdContext: isEmailOtpThresholdEcdsaSigningContext(unambiguousLane),
  });

  const selectedAuthMethod = args.laneCandidate?.authMethod || args.authMethod;
  const selectedAccountAuth = accountAuthWithSelectedPrimary(accountAuth, selectedAuthMethod);

  if (selectedAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
    const exactCandidate = args.laneCandidate;
    const selectedEmailOtpRecord =
      exactCandidate?.authMethod === SIGNER_AUTH_METHODS.emailOtp
        ? exactRecordForCandidate ||
          (ecdsaMaterialMatchesLaneCandidate({
            candidate: exactCandidate,
            ...(genericEmailOtpRecord ? { record: genericEmailOtpRecord } : {}),
          })
            ? genericEmailOtpRecord
            : undefined)
        : emailOtpRecord;
    const selectedEmailOtpKeyRef =
      exactCandidate?.authMethod === SIGNER_AUTH_METHODS.emailOtp
        ? exactKeyRefForCandidate ||
          (ecdsaMaterialMatchesLaneCandidate({
            candidate: exactCandidate,
            ...(genericEmailOtpKeyRef ? { keyRef: genericEmailOtpKeyRef } : {}),
          })
            ? genericEmailOtpKeyRef
            : undefined)
        : emailOtpKeyRef;
    if (
      !args.allowMissingHotMaterial &&
      exactCandidate?.authMethod === SIGNER_AUTH_METHODS.emailOtp &&
      exactEcdsaCandidateRequiresHotMaterial(exactCandidate)
    ) {
      requireExactEcdsaCandidateMaterial({
        nearAccountId: args.nearAccountId,
        chain: args.chain,
        candidate: exactCandidate,
        ...(selectedEmailOtpRecord ? { record: selectedEmailOtpRecord } : {}),
        ...(selectedEmailOtpKeyRef ? { keyRef: selectedEmailOtpKeyRef } : {}),
      });
    }
    const signingLaneFromMaterial =
      selectedEmailOtpRecord && selectedEmailOtpKeyRef
        ? buildEvmFamilyEcdsaSigningLaneContext({
            nearAccountId: args.nearAccountId,
            chain: args.chain,
            chainTarget: args.chainTarget,
            authMethod: SIGNER_AUTH_METHODS.emailOtp,
            source: SIGNER_AUTH_METHODS.emailOtp,
            material: 'record_and_key_ref',
            record: selectedEmailOtpRecord,
            keyRef: selectedEmailOtpKeyRef,
          })
        : selectedEmailOtpRecord
          ? buildEvmFamilyEcdsaSigningLaneContext({
              nearAccountId: args.nearAccountId,
              chain: args.chain,
              chainTarget: args.chainTarget,
              authMethod: SIGNER_AUTH_METHODS.emailOtp,
              source: SIGNER_AUTH_METHODS.emailOtp,
              material: 'record',
              record: selectedEmailOtpRecord,
            })
          : selectedEmailOtpKeyRef
            ? buildEvmFamilyEcdsaSigningLaneContext({
                nearAccountId: args.nearAccountId,
                chain: args.chain,
                chainTarget: args.chainTarget,
                authMethod: SIGNER_AUTH_METHODS.emailOtp,
                source: SIGNER_AUTH_METHODS.emailOtp,
                material: 'key_ref',
                keyRef: selectedEmailOtpKeyRef,
              })
            : undefined;
    const signingLane =
      signingLaneFromMaterial || signingLaneFromExactLaneCandidate(args.laneCandidate);
    const selectedRecord = selectedEmailOtpRecord
      ? validateSelectedEcdsaRecordCandidateForLane({
          lane: signingLane,
          record: selectedEmailOtpRecord,
          context: 'Email OTP ECDSA selection',
        })
      : exactCandidate?.authMethod === SIGNER_AUTH_METHODS.emailOtp
        ? undefined
        : readSelectedEcdsaRecordForLane({ deps: args.deps, lane: signingLane });
    const selectedKeyRef = selectedEmailOtpKeyRef
      ? validateSelectedEcdsaKeyRefCandidateForLane({
          lane: signingLane,
          keyRef: selectedEmailOtpKeyRef,
          context: 'Email OTP ECDSA selection',
        })
      : exactCandidate?.authMethod === SIGNER_AUTH_METHODS.emailOtp
        ? undefined
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

  if (
    !args.allowMissingHotMaterial &&
    args.laneCandidate?.authMethod === SIGNER_AUTH_METHODS.passkey &&
    exactEcdsaCandidateRequiresHotMaterial(args.laneCandidate)
  ) {
    requireExactEcdsaCandidateMaterial({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      candidate: args.laneCandidate,
      ...(passkeyRecord ? { record: passkeyRecord } : {}),
      ...(passkeyKeyRef ? { keyRef: passkeyKeyRef } : {}),
    });
  }
  const passkeySource = selectedPasskeyCandidate?.source || 'manual-bootstrap';
  const signingLaneFromMaterial =
    passkeyRecord && passkeyKeyRef
      ? buildEvmFamilyEcdsaSigningLaneContext({
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          chainTarget: args.chainTarget,
          authMethod: SIGNER_AUTH_METHODS.passkey,
          source: passkeySource,
          material: 'record_and_key_ref',
          record: passkeyRecord,
          keyRef: passkeyKeyRef,
        })
      : passkeyRecord
        ? buildEvmFamilyEcdsaSigningLaneContext({
            nearAccountId: args.nearAccountId,
            chain: args.chain,
            chainTarget: args.chainTarget,
            authMethod: SIGNER_AUTH_METHODS.passkey,
            source: passkeySource,
            material: 'record',
            record: passkeyRecord,
          })
        : passkeyKeyRef
          ? buildEvmFamilyEcdsaSigningLaneContext({
              nearAccountId: args.nearAccountId,
              chain: args.chain,
              chainTarget: args.chainTarget,
              authMethod: SIGNER_AUTH_METHODS.passkey,
              source: passkeySource,
              material: 'key_ref',
              keyRef: passkeyKeyRef,
            })
          : undefined;
  const signingLane =
    signingLaneFromMaterial || signingLaneFromExactLaneCandidate(args.laneCandidate);
  const selectedPasskeyRecord = passkeyRecord
    ? validateSelectedEcdsaRecordCandidateForLane({
        lane: signingLane,
        record: passkeyRecord,
        context: 'passkey ECDSA selection',
      })
    : args.laneCandidate?.authMethod === SIGNER_AUTH_METHODS.passkey
      ? undefined
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
    : args.laneCandidate?.authMethod === SIGNER_AUTH_METHODS.passkey
      ? undefined
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
