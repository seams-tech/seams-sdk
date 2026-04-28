import type { AccountAuthMetadata } from '@/core/signingEngine/auth';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../thresholdLifecycle/thresholdSessionStore';
import type { SigningSessionSnapshot } from '../../session/snapshotReader';
import { emitSigningLaneResolutionTrace } from '../../session/signingSession/trace';
import {
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaKeyRef,
  summarizeEvmFamilyEcdsaLane,
  summarizeEvmFamilyEcdsaSessionRecord,
  type EcdsaSigningLookupArgs,
  type EvmFamilyEcdsaAuthMethod,
  type PasskeyEcdsaSigningLookupArgs,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import {
  resolveEvmFamilyEcdsaSigningSelection,
  type EvmFamilyEcdsaSigningSelectionDeps,
} from './ecdsaSelection';
import type { EvmFamilyChain } from './types';

export type PreparedEvmFamilyEcdsaSigningSession = {
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  snapshotGeneration: number;
  signingLane: ResolvedEvmFamilyEcdsaSigningLane;
  warmRecord?: ThresholdEcdsaSessionRecord;
  warmKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
};

export type PrepareEvmFamilyEcdsaSigningDeps = EvmFamilyEcdsaSigningSelectionDeps & {
  restorePersistedSessionForSigning: (args: {
    walletId: string;
    authMethod: 'email_otp';
    curve: 'ecdsa';
    chain: EvmFamilyChain;
    reason: 'transaction' | 'export' | 'session_status';
  }) => Promise<unknown>;
  readSigningSessionSnapshotForSigning: (args: {
    walletId: string;
    authMethod?: 'email_otp' | 'passkey';
  }) => Promise<SigningSessionSnapshot>;
  getEmailOtpThresholdEcdsaKeyRefForSigning: (
    args: EcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSecp256k1KeyRef;
  getEmailOtpThresholdEcdsaSessionRecordForSigning: (
    args: EcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSessionRecord;
  getPasskeyThresholdEcdsaKeyRefForSigning: (
    args: PasskeyEcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSecp256k1KeyRef;
  getPasskeyThresholdEcdsaSessionRecordForSigning: (
    args: PasskeyEcdsaSigningLookupArgs,
  ) => ThresholdEcdsaSessionRecord;
};

export async function prepareEvmFamilyEcdsaSigningSession(args: {
  deps: PrepareEvmFamilyEcdsaSigningDeps;
  nearAccountId: string;
  chain: EvmFamilyChain;
  diagnostics: Record<string, unknown>;
}): Promise<PreparedEvmFamilyEcdsaSigningSession> {
  // Restore is an explicit transaction command boundary. Lane selection must
  // happen after this so reload-restored Email OTP sessions are visible.
  args.diagnostics.sealedRestoreBeforeSelection = {
    attempted: true,
    completed: false,
  };
  await args.deps
    .restorePersistedSessionForSigning({
      walletId: args.nearAccountId,
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chain: args.chain,
      reason: 'transaction',
    })
    .then(
      () => {
        args.diagnostics.sealedRestoreBeforeSelection = {
          attempted: true,
          completed: true,
        };
      },
      (error) => {
        const message = error instanceof Error ? error.message : String(error);
        args.diagnostics.sealedRestoreBeforeSelection = {
          attempted: true,
          completed: false,
          error: message,
        };
        console.debug(
          '[SigningEngine][ecdsa] Email OTP sealed restore before lane selection skipped',
          {
            nearAccountId: args.nearAccountId,
            chain: args.chain,
            message,
          },
        );
      },
    );

  const selection = await resolveEvmFamilyEcdsaSigningSelection({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    senderSignatureAlgorithm: 'secp256k1',
  });
  const snapshot = await args.deps.readSigningSessionSnapshotForSigning({
    walletId: args.nearAccountId,
    authMethod: selection.authMethod,
  });
  const signingLane = selection.lane;
  emitSigningLaneResolutionTrace('evm-family', signingLane, {
    reason: 'evm_family_ecdsa_selection',
  });
  args.diagnostics.selection = {
    authMethod: selection.authMethod,
    source: selection.source,
    lane: summarizeEvmFamilyEcdsaLane(signingLane),
    warmRecord: summarizeEvmFamilyEcdsaSessionRecord(selection.warmRecord),
    warmKeyRef: summarizeEvmFamilyEcdsaKeyRef(selection.warmKeyRef),
    reauthRecord: summarizeEvmFamilyEcdsaSessionRecord(selection.reauthRecord),
  };
  if (!signingLane) {
    console.warn('[SigningEngine][ecdsa] EVM-family signing has no selected lane after selection', {
      ...args.diagnostics,
    });
  }

  return {
    accountAuth: selection.accountAuth,
    authMethod: selection.authMethod,
    source: selection.source,
    snapshotGeneration: snapshot.generation,
    signingLane: requireResolvedEvmFamilyEcdsaSigningLane({
      lane: signingLane,
      chain: args.chain,
      context: 'EVM-family signing preparation',
      diagnostics: args.diagnostics,
    }),
    ...(selection.warmRecord ? { warmRecord: selection.warmRecord } : {}),
    ...(selection.warmKeyRef ? { warmKeyRef: selection.warmKeyRef } : {}),
    ...(selection.reauthRecord ? { emailOtpReauthRecord: selection.reauthRecord } : {}),
  };
}
