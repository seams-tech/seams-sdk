import type { AccountAuthMetadata } from '@/core/signingEngine/auth';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../thresholdLifecycle/thresholdSessionStore';
import type {
  SigningSessionSnapshot,
  SigningSessionSnapshotEcdsaLane,
} from '../../session/snapshotReader';
import type { SigningSessionPreparedBudgetIdentity } from '../../session/signingSession/budget';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  prepareThresholdSigningOperation,
  type PreparedThresholdSigningOperation,
} from '../../session/signingSession/preparedOperation';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningLaneResolutionTrace,
  emitSigningPlannerDecisionTrace,
} from '../../session/signingSession/trace';
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
import {
  resolveEvmFamilyEcdsaPlannerReadiness,
  type EvmFamilyPreConfirmSigningDeps,
} from './authPlanning';
import { resolveEvmFamilyTransactionAccountAuth } from './accountAuth';
import type { EvmFamilyChain } from './types';

function resolveEcdsaSnapshotCandidate(args: {
  snapshot: SigningSessionSnapshot;
  chain: EvmFamilyChain;
  accountAuth: AccountAuthMetadata;
}): SigningSessionSnapshotEcdsaLane | null {
  const snapshotCandidates = args.snapshot.candidates?.ecdsa?.[args.chain] || [];
  const candidates =
    snapshotCandidates.length > 0
      ? snapshotCandidates
      : [args.snapshot.lanes.ecdsa[args.chain]];
  const concreteCandidates = candidates.filter(
    (lane) =>
      lane.state !== 'missing' &&
      (lane.authMethod === 'email_otp' || lane.authMethod === 'passkey'),
  );
  if (concreteCandidates.length === 0) return null;
  const primaryAuthMethod =
    args.accountAuth.primaryAuthMethod === 'email_otp' ? 'email_otp' : 'passkey';
  const primaryCandidate = concreteCandidates.find(
    (lane) => lane.authMethod === primaryAuthMethod,
  );
  if (primaryCandidate) return primaryCandidate;
  const readyCandidate = concreteCandidates.find((lane) => lane.state === 'ready');
  return readyCandidate || concreteCandidates[0] || null;
}

function assertSelectionMatchesSnapshotCandidate(args: {
  candidate: SigningSessionSnapshotEcdsaLane | null;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
}): void {
  const candidate = args.candidate;
  if (!candidate) return;
  if (candidate.authMethod && candidate.authMethod !== args.lane.authMethod) {
    throw new Error(
      `[SigningEngine][ecdsa] prepared restore auth method ${candidate.authMethod} did not match selected lane auth method ${args.lane.authMethod}`,
    );
  }
  if (
    candidate.thresholdSessionId &&
    candidate.thresholdSessionId !== String(args.lane.thresholdSessionId)
  ) {
    throw new Error(
      '[SigningEngine][ecdsa] prepared restore threshold session did not match selected lane',
    );
  }
  if (
    candidate.walletSigningSessionId &&
    candidate.walletSigningSessionId !== String(args.lane.walletSigningSessionId)
  ) {
    throw new Error(
      '[SigningEngine][ecdsa] prepared restore wallet signing session did not match selected lane',
    );
  }
}

export type PreparedEvmFamilyEcdsaSigningSession = {
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  snapshotGeneration: number;
  budgetIdentity?: SigningSessionPreparedBudgetIdentity;
  budgetProjectionVersion?: string;
  budgetIdentityThresholdSessionId?: string;
  signingLane: ResolvedEvmFamilyEcdsaSigningLane;
  preparedOperation: PreparedThresholdSigningOperation<
    ResolvedEvmFamilyEcdsaSigningLane,
    Record<string, unknown>
  >;
  warmRecord?: ThresholdEcdsaSessionRecord;
  warmKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
};

export type PrepareEvmFamilyEcdsaSigningDeps = EvmFamilyEcdsaSigningSelectionDeps &
  EvmFamilyPreConfirmSigningDeps & {
    restorePersistedSessionForSigning: (args: {
      walletId: string;
      authMethod: 'email_otp' | 'passkey';
      curve: 'ecdsa';
      chain: EvmFamilyChain;
      walletSigningSessionId?: string;
      thresholdSessionId?: string;
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
  signingSessionCoordinator: SigningSessionCoordinator;
  forceFreshAuth?: boolean;
}): Promise<PreparedEvmFamilyEcdsaSigningSession> {
  const preparedOperation = await prepareThresholdSigningOperation({
    intent: {
      kind: 'transaction_sign',
      chain: args.chain,
      curve: 'ecdsa',
      walletId: args.nearAccountId,
      reason: 'transaction',
    },
    coordinator: args.signingSessionCoordinator,
    forceFreshAuth: args.forceFreshAuth === true,
    missingWhenExpiresAtMissing: true,
    prepareBudgetIdentity: true,
    onPlannerTrace: (event) => emitSigningPlannerDecisionTrace('evm-family', event),
    lifecycleAdapter: {
      prepare: async () => {
        const candidateSnapshot = await args.deps.readSigningSessionSnapshotForSigning({
          walletId: args.nearAccountId,
        });
        const accountAuth = await resolveEvmFamilyTransactionAccountAuth({
          deps: args.deps,
          nearAccountId: args.nearAccountId,
          senderSignatureAlgorithm: 'secp256k1',
        });
        const snapshotCandidate = resolveEcdsaSnapshotCandidate({
          snapshot: candidateSnapshot,
          chain: args.chain,
          accountAuth,
        });
        const snapshotAuthMethod = snapshotCandidate?.authMethod || null;
        const authMethod =
          snapshotAuthMethod ||
          (accountAuth.primaryAuthMethod === 'email_otp' ? 'email_otp' : 'passkey');
        // Transaction prepare first reads the side-effect-free signing-session
        // snapshot, then restores only the selected exact auth-method lane.
        // Broad probing belongs to startup/session-status maintenance paths.
        args.diagnostics.sealedRestoreBeforeSelection = {
          attempted: true,
          completed: false,
          authMethod,
          snapshotCandidate: snapshotAuthMethod || null,
        };
        const restoreResults: Record<string, unknown> = {};
        await args.deps
          .restorePersistedSessionForSigning({
            walletId: args.nearAccountId,
            authMethod,
            curve: 'ecdsa',
            chain: args.chain,
            ...(snapshotCandidate?.walletSigningSessionId
              ? { walletSigningSessionId: snapshotCandidate.walletSigningSessionId }
              : {}),
            ...(snapshotCandidate?.thresholdSessionId
              ? { thresholdSessionId: snapshotCandidate.thresholdSessionId }
              : {}),
            reason: 'transaction',
          })
          .then(
            (result) => {
              restoreResults[authMethod] = result;
            },
            (error) => {
              const message = error instanceof Error ? error.message : String(error);
              restoreResults[authMethod] = { error: message };
              console.debug(
                '[SigningEngine][ecdsa] sealed restore before lane selection skipped',
                {
                  nearAccountId: args.nearAccountId,
                  chain: args.chain,
                  authMethod,
                  message,
                },
              );
            },
          );
        args.diagnostics.sealedRestoreBeforeSelection = {
          attempted: true,
          completed: true,
          authMethod,
          results: restoreResults,
          selectedSnapshotCandidate: snapshotCandidate
            ? {
                authMethod: snapshotCandidate.authMethod,
                state: snapshotCandidate.state,
                thresholdSessionId: snapshotCandidate.thresholdSessionId,
                walletSigningSessionId: snapshotCandidate.walletSigningSessionId,
                source: snapshotCandidate.source,
              }
            : null,
        };

        const selection = await resolveEvmFamilyEcdsaSigningSelection({
          deps: args.deps,
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          senderSignatureAlgorithm: 'secp256k1',
          authMethod,
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
          console.warn(
            '[SigningEngine][ecdsa] EVM-family signing has no selected lane after selection',
            {
              ...args.diagnostics,
            },
          );
        }
        const resolvedLane = requireResolvedEvmFamilyEcdsaSigningLane({
          lane: signingLane,
          chain: args.chain,
          context: 'EVM-family signing preparation',
          diagnostics: args.diagnostics,
        });
        assertSelectionMatchesSnapshotCandidate({
          candidate: snapshotCandidate,
          lane: resolvedLane,
        });
        const readiness = await resolveEvmFamilyEcdsaPlannerReadiness({
          deps: args.deps,
          lane: resolvedLane,
          ...(selection.warmRecord ? { record: selection.warmRecord } : {}),
          ...(selection.warmKeyRef ? { keyRef: selection.warmKeyRef } : {}),
        });
        emitSigningBoundaryTrace(
          'evm-family',
          createSigningBoundaryTraceEvent({
            event: 'pre_confirm_readiness_checked',
            lane: resolvedLane,
            readinessStatus: readiness.readiness.status,
            phase: 'pre_confirm',
          }),
        );
        return {
          lane: resolvedLane,
          readiness: {
            readiness: readiness.readiness,
            expiresAtMs: readiness.expiresAtMs,
            remainingUses: readiness.remainingUses,
          },
          snapshotGeneration: snapshot.generation,
          metadata: {
            accountAuth: selection.accountAuth,
            authMethod: selection.authMethod,
            source: selection.source,
            snapshotGeneration: snapshot.generation,
            ...(selection.warmRecord ? { warmRecord: selection.warmRecord } : {}),
            ...(selection.warmKeyRef ? { warmKeyRef: selection.warmKeyRef } : {}),
            ...(selection.reauthRecord ? { emailOtpReauthRecord: selection.reauthRecord } : {}),
            ...(readiness.signingRootId ? { signingRootId: readiness.signingRootId } : {}),
          },
        };
      },
    },
  });
  const metadata = preparedOperation.metadata as {
    accountAuth: AccountAuthMetadata;
    authMethod: EvmFamilyEcdsaAuthMethod;
    source: ThresholdEcdsaSessionStoreSource;
    snapshotGeneration: number;
    warmRecord?: ThresholdEcdsaSessionRecord;
    warmKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
    emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
  };

  return {
    accountAuth: metadata.accountAuth,
    authMethod: metadata.authMethod,
    source: metadata.source,
    snapshotGeneration: metadata.snapshotGeneration,
    signingLane: preparedOperation.lane,
    preparedOperation,
    ...(preparedOperation.budgetIdentity
      ? {
          budgetIdentity: preparedOperation.budgetIdentity,
          budgetProjectionVersion: preparedOperation.budgetIdentity.projectionVersion,
          budgetIdentityThresholdSessionId: String(preparedOperation.lane.thresholdSessionId),
        }
      : {}),
    ...(metadata.warmRecord ? { warmRecord: metadata.warmRecord } : {}),
    ...(metadata.warmKeyRef ? { warmKeyRef: metadata.warmKeyRef } : {}),
    ...(metadata.emailOtpReauthRecord
      ? { emailOtpReauthRecord: metadata.emailOtpReauthRecord }
      : {}),
  };
}
