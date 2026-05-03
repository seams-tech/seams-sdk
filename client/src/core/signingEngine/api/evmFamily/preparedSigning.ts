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
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { RestorePersistedSessionForSigningInput } from '../../session/restoreCoordinator';
import type { SigningSessionBudgetStatusAuth } from '../../session/signingSession/budget';
import {
  prepareTransactionSigningOperation,
  selectTransactionLane,
  type EvmFamilyEcdsaConcreteSnapshotLane,
  type EvmFamilyEcdsaTransactionLane,
  type PreparedTransactionBudgetState,
  type PreparedTransactionOperation,
  type TransactionSigningIntent,
} from '../../session/signingSession/transactionState';
import {
  type PreparedThresholdSigningOperation,
} from '../../session/signingSession/preparedOperation';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningLaneResolutionTrace,
  emitSigningPlannerDecisionTrace,
  emitSigningSessionFlowFailure,
  emitSigningSessionFlowTrace,
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

function isRuntimeBackedEcdsaSnapshotLane(
  lane: SigningSessionSnapshotEcdsaLane | null | undefined,
): lane is EvmFamilyEcdsaConcreteSnapshotLane {
  return (
    Boolean(lane) &&
    lane!.curve === 'ecdsa' &&
    (lane!.chain === 'tempo' || lane!.chain === 'evm') &&
    (lane!.source === 'runtime_session_record' ||
      lane!.source === 'runtime_and_durable') &&
    (lane!.authMethod === 'email_otp' || lane!.authMethod === 'passkey') &&
    Boolean(String(lane!.walletSigningSessionId || '').trim()) &&
    Boolean(String(lane!.thresholdSessionId || '').trim())
  );
}

function getSingleRuntimeBackedEcdsaSnapshotLane(args: {
  snapshot: SigningSessionSnapshot;
  chain: EvmFamilyChain;
}): EvmFamilyEcdsaConcreteSnapshotLane | null {
  const runtimeCandidates = (args.snapshot.candidates.ecdsa[args.chain] || []).filter(
    isRuntimeBackedEcdsaSnapshotLane,
  );
  if (runtimeCandidates.length === 1) return runtimeCandidates[0];
  // Multiple runtime lanes are not a single current-lane anchor; let the
  // account-class policy choose instead of hiding a live lane before selection.
  return null;
}

function summarizeEcdsaSnapshotLane(
  lane: SigningSessionSnapshotEcdsaLane | null | undefined,
): Record<string, unknown> {
  if (!lane) return { present: false };
  return {
    present: true,
    authMethod: lane.authMethod,
    curve: lane.curve,
    chain: lane.chain,
    state: lane.state,
    source: lane.source,
    walletSigningSessionId: lane.walletSigningSessionId,
    thresholdSessionId: lane.thresholdSessionId,
    remainingUses: lane.remainingUses,
    expiresAtMs: lane.expiresAtMs,
    updatedAtMs: lane.updatedAtMs,
  };
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
  signingLane: ResolvedEvmFamilyEcdsaSigningLane;
  preparedOperation: PreparedThresholdSigningOperation<
    ResolvedEvmFamilyEcdsaSigningLane,
    Record<string, unknown>
  >;
  transactionOperation: PreparedTransactionOperation<EvmFamilyEcdsaTransactionLane>;
  budget: PreparedTransactionBudgetState<EvmFamilyEcdsaTransactionLane>;
  budgetStatusAuth?: SigningSessionBudgetStatusAuth;
  warmRecord?: ThresholdEcdsaSessionRecord;
  warmKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
};

export type PrepareEvmFamilyEcdsaSigningDeps = EvmFamilyEcdsaSigningSelectionDeps &
  EvmFamilyPreConfirmSigningDeps & {
    restorePersistedSessionForSigning: (
      args: Extract<RestorePersistedSessionForSigningInput, { curve: 'ecdsa' }>,
    ) => Promise<unknown>;
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
  const preparedTransaction = await prepareTransactionSigningOperation({
    intent: {
      walletId: args.nearAccountId,
      curve: 'ecdsa',
      chain: args.chain,
      authSelectionPolicy: { kind: 'account_class', authMethod: 'passkey' },
      operationUsesNeeded: 1,
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
        const currentRuntimeLane = getSingleRuntimeBackedEcdsaSnapshotLane({
          snapshot: candidateSnapshot,
          chain: args.chain,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.snapshot_read',
          accountId: args.nearAccountId,
          chain: args.chain,
          candidateCount: candidateSnapshot.candidates.ecdsa[args.chain]?.length || 0,
          currentRuntimeLane: summarizeEcdsaSnapshotLane(currentRuntimeLane),
        });
        const accountAuth = await resolveEvmFamilyTransactionAccountAuth({
          deps: args.deps,
          nearAccountId: args.nearAccountId,
          senderSignatureAlgorithm: 'secp256k1',
        });
        const primaryAuthMethod =
          accountAuth.primaryAuthMethod === 'email_otp' ? 'email_otp' : 'passkey';
        const transactionIntent: TransactionSigningIntent = {
          walletId: args.nearAccountId,
          curve: 'ecdsa',
          chain: args.chain,
          authSelectionPolicy: { kind: 'account_class', authMethod: primaryAuthMethod },
          operationUsesNeeded: 1,
        };
        const selectedLane = selectTransactionLane({
          intent: transactionIntent,
          snapshot: candidateSnapshot,
          currentRuntimeLane,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.lane_selected',
          accountId: args.nearAccountId,
          chain: args.chain,
          primaryAuthMethod,
          selectionOk: selectedLane.ok,
          ...(selectedLane.ok
            ? {
                selectedSnapshotLane: summarizeEcdsaSnapshotLane(
                  selectedLane.snapshotLane as SigningSessionSnapshotEcdsaLane,
                ),
                transactionLane: selectedLane.lane,
              }
            : { failure: selectedLane.failure }),
        });
        if (!selectedLane.ok) {
          if (selectedLane.failure.kind !== 'no_candidate') {
            emitSigningSessionFlowFailure('evm-family', {
              stage: 'ecdsa_prepare.lane_selection_failed',
              accountId: args.nearAccountId,
              chain: args.chain,
              primaryAuthMethod,
              failure: selectedLane.failure,
            });
            throw new Error(
              `[SigningEngine][ecdsa] transaction lane selection failed: ${selectedLane.failure.kind}`,
            );
          }
        }
        if (
          selectedLane.ok &&
          (selectedLane.lane.curve !== 'ecdsa' || selectedLane.snapshotLane.curve !== 'ecdsa')
        ) {
          throw new Error('[SigningEngine][ecdsa] selector returned a non-ECDSA lane');
        }
        const snapshotCandidate = selectedLane.ok
          ? (selectedLane.snapshotLane as EvmFamilyEcdsaConcreteSnapshotLane)
          : null;
        const transactionLane = selectedLane.ok
          ? (selectedLane.lane as EvmFamilyEcdsaTransactionLane)
          : null;
        if (!snapshotCandidate || !transactionLane) {
          emitSigningSessionFlowFailure('evm-family', {
            stage: 'ecdsa_prepare.exact_snapshot_lane_missing',
            accountId: args.nearAccountId,
            chain: args.chain,
            primaryAuthMethod,
            candidateCount: candidateSnapshot.candidates.ecdsa[args.chain]?.length || 0,
          });
          throw new Error(
            `[SigningEngine][ecdsa] transaction restore requires an exact snapshot lane for ${args.chain}`,
          );
        }
        const authMethod = transactionLane.authMethod;
        // Transaction prepare first reads the side-effect-free signing-session
        // snapshot, then restores only the selected exact auth-method lane.
        // Broad probing belongs to startup/session-status maintenance paths.
        const restoreResults: Record<string, unknown> = {};
        const shouldRestoreSnapshotCandidate =
          snapshotCandidate.state === 'restorable' || snapshotCandidate.state === 'deferred';
        if (shouldRestoreSnapshotCandidate) {
          emitSigningSessionFlowTrace('evm-family', {
            stage: 'ecdsa_prepare.restore_start',
            accountId: args.nearAccountId,
            chain: args.chain,
            authMethod,
            selectedSnapshotLane: summarizeEcdsaSnapshotLane(snapshotCandidate),
          });
          args.diagnostics.sealedRestoreBeforeSelection = {
            attempted: true,
            completed: false,
            authMethod,
            snapshotCandidate: authMethod,
          };
          try {
            const result = await args.deps.restorePersistedSessionForSigning({
              walletId: args.nearAccountId,
              authMethod,
              curve: 'ecdsa',
              chain: args.chain,
              walletSigningSessionId: snapshotCandidate.walletSigningSessionId,
              thresholdSessionId: snapshotCandidate.thresholdSessionId,
              reason: 'transaction',
            });
            restoreResults[authMethod] = result;
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            restoreResults[authMethod] = { error: message };
            emitSigningSessionFlowFailure('evm-family', {
              stage: 'ecdsa_prepare.restore_failed',
              accountId: args.nearAccountId,
              chain: args.chain,
              authMethod,
              selectedSnapshotLane: summarizeEcdsaSnapshotLane(snapshotCandidate),
              error: message,
            });
            args.diagnostics.sealedRestoreBeforeSelection = {
              attempted: true,
              completed: false,
              authMethod,
              results: restoreResults,
              selectedSnapshotCandidate: {
                authMethod: snapshotCandidate.authMethod,
                state: snapshotCandidate.state,
                thresholdSessionId: snapshotCandidate.thresholdSessionId,
                walletSigningSessionId: snapshotCandidate.walletSigningSessionId,
                source: snapshotCandidate.source,
              },
            };
            throw new Error(
              `[SigningEngine][ecdsa] exact transaction restore failed for ${args.chain} ${authMethod}: ${message}`,
            );
          }
          emitSigningSessionFlowTrace('evm-family', {
            stage: 'ecdsa_prepare.restore_succeeded',
            accountId: args.nearAccountId,
            chain: args.chain,
            authMethod,
            selectedSnapshotLane: summarizeEcdsaSnapshotLane(snapshotCandidate),
          });
        } else {
          args.diagnostics.sealedRestoreBeforeSelection = {
            attempted: false,
            completed: true,
            authMethod,
            reason: 'selected_snapshot_candidate_ready',
          };
        }
        args.diagnostics.sealedRestoreBeforeSelection = {
          attempted: shouldRestoreSnapshotCandidate,
          completed: true,
          authMethod,
          results: restoreResults,
          selectedSnapshotCandidate: {
            authMethod: snapshotCandidate.authMethod,
            state: snapshotCandidate.state,
            thresholdSessionId: snapshotCandidate.thresholdSessionId,
            walletSigningSessionId: snapshotCandidate.walletSigningSessionId,
            source: snapshotCandidate.source,
          },
        };

        const selection = await resolveEvmFamilyEcdsaSigningSelection({
          deps: args.deps,
          nearAccountId: args.nearAccountId,
          chain: args.chain,
          senderSignatureAlgorithm: 'secp256k1',
          authMethod,
          transactionLane,
          snapshotCandidate,
          allowMissingHotMaterial: args.forceFreshAuth === true,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.material_selected',
          accountId: args.nearAccountId,
          chain: args.chain,
          authMethod: selection.authMethod,
          source: selection.source,
          lane: summarizeEvmFamilyEcdsaLane(selection.lane),
          warmRecord: summarizeEvmFamilyEcdsaSessionRecord(selection.warmRecord),
          warmKeyRef: summarizeEvmFamilyEcdsaKeyRef(selection.warmKeyRef),
          reauthRecord: summarizeEvmFamilyEcdsaSessionRecord(selection.reauthRecord),
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
          emitSigningSessionFlowFailure('evm-family', {
            stage: 'ecdsa_prepare.material_selection_missing_lane',
            accountId: args.nearAccountId,
            chain: args.chain,
            authMethod: selection.authMethod,
            source: selection.source,
            selectedSnapshotLane: summarizeEcdsaSnapshotLane(snapshotCandidate),
          });
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
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.readiness',
          accountId: args.nearAccountId,
          chain: args.chain,
          authMethod: selection.authMethod,
          lane: summarizeEvmFamilyEcdsaLane(resolvedLane),
          readinessStatus: readiness.readiness.status,
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
          transactionLane,
          ...(transactionIntent ? { transactionIntent } : {}),
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
  const preparedOperation = preparedTransaction.thresholdOperation as PreparedThresholdSigningOperation<
    ResolvedEvmFamilyEcdsaSigningLane,
    Record<string, unknown>
  >;
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
    transactionOperation: preparedTransaction.transactionOperation,
    budget: preparedTransaction.budget,
    ...(metadata.warmRecord ? { warmRecord: metadata.warmRecord } : {}),
    ...(metadata.warmKeyRef ? { warmKeyRef: metadata.warmKeyRef } : {}),
    ...(metadata.emailOtpReauthRecord
      ? { emailOtpReauthRecord: metadata.emailOtpReauthRecord }
      : {}),
  };
}
