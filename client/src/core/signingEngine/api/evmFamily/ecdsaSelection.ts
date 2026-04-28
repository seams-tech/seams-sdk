import type { AccountAuthMetadata } from '@/core/signingEngine/auth';
import { resolveAccountAuthMetadataForSignerSource } from '@/core/signingEngine/auth';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { SigningLaneContext } from '../../session/signingSession/types';
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
}): Promise<EvmFamilyEcdsaSigningSelection> {
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
  const passkeyCandidate = passkeyCandidates[0];
  const passkeyRecord = passkeyCandidate?.record;
  const passkeyKeyRef = passkeyCandidate?.keyRef;

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

  if (accountAuth.primaryAuthMethod === SIGNER_AUTH_METHODS.emailOtp) {
    const signingLane = buildEvmFamilyEcdsaSigningLaneContext({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
      source: SIGNER_AUTH_METHODS.emailOtp,
      ...(emailOtpRecord ? { record: emailOtpRecord } : {}),
      ...(emailOtpKeyRef ? { keyRef: emailOtpKeyRef } : {}),
    });
    const selectedRecord = emailOtpRecord
      ? validateSelectedEcdsaRecordCandidateForLane({
          lane: signingLane,
          record: emailOtpRecord,
          context: 'Email OTP ECDSA selection',
        })
      : readSelectedEcdsaRecordForLane({ deps: args.deps, lane: signingLane });
    const selectedKeyRef = emailOtpKeyRef
      ? validateSelectedEcdsaKeyRefCandidateForLane({
          lane: signingLane,
          keyRef: emailOtpKeyRef,
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
      accountAuth: resolveAccountAuthMetadataForSignerSource({
        source: SIGNER_AUTH_METHODS.emailOtp,
      }),
      source: SIGNER_AUTH_METHODS.emailOtp,
      ...(warmRecord ? { warmRecord } : {}),
      ...(warmRecord && selectedKeyRef ? { warmKeyRef: selectedKeyRef } : {}),
      ...(selectedRecord ? { reauthRecord: selectedRecord } : {}),
      ...(signingLane ? { lane: signingLane } : {}),
    };
  }

  const passkeySource = passkeyCandidate?.source || 'manual-bootstrap';
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
    accountAuth,
    source: passkeySource,
    ...(selectedWarmRecord ? { warmRecord: selectedWarmRecord } : {}),
    ...(selectedWarmRecord && selectedPasskeyKeyRef ? { warmKeyRef: selectedPasskeyKeyRef } : {}),
    ...(signingLane ? { lane: signingLane } : {}),
  };
}
