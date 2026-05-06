import type { AccountAuthMetadata } from '@/core/signingEngine/auth';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionStoreSource,
} from '../thresholdLifecycle/thresholdSessionStore';
import type {
  ReadSigningSessionSnapshotForSigningInput,
  SigningSessionSnapshot,
  SigningSessionSnapshotEcdsaLane,
} from '../../session/snapshotReader';
import {
  ecdsaSnapshotCandidatesForTarget,
  isConcreteSigningSessionSnapshotLane,
} from '../../session/snapshotReader';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { RestorePersistedSessionForSigningInput } from '../../session/restoreCoordinator';
import type { SigningSessionBudgetStatusAuth } from '../../session/signingSession/budget';
import {
  prepareTransactionSigningOperation,
  selectTransactionLane,
  type EvmFamilyEcdsaConcreteSnapshotLane,
  type EvmFamilyEcdsaTransactionSigningIntent,
  type EvmFamilyEcdsaTransactionLane,
  type PreparedTransactionBudgetState,
  type PreparedTransactionOperation,
  type TransactionAuthSelectionPolicy,
  type TransactionSigningIntent,
} from '../../session/signingSession/transactionState';
import {
  thresholdEcdsaChainTargetsEqual,
  type WalletSubjectId,
} from '../../session/signingSession/ecdsaChainTarget';
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
import type { EvmFamilySigningTarget } from './types';

function buildEvmFamilyTransactionSigningIntent(args: {
  walletId: string;
  signingTarget: EvmFamilySigningTarget;
  authSelectionPolicy: TransactionAuthSelectionPolicy;
  operationUsesNeeded: number;
}): EvmFamilyEcdsaTransactionSigningIntent {
  const base = {
    walletId: args.walletId,
    curve: 'ecdsa' as const,
    authSelectionPolicy: args.authSelectionPolicy,
    operationUsesNeeded: args.operationUsesNeeded,
  };
  return args.signingTarget.chain === 'tempo'
    ? {
        ...base,
        chain: 'tempo',
        chainTarget: args.signingTarget.chainTarget,
      }
    : {
        ...base,
        chain: 'evm',
        chainTarget: args.signingTarget.chainTarget,
      };
}

function isRuntimeBackedEcdsaSnapshotLane(
  lane: SigningSessionSnapshotEcdsaLane | null | undefined,
): lane is EvmFamilyEcdsaConcreteSnapshotLane {
  return (
    Boolean(lane) &&
    lane!.curve === 'ecdsa' &&
    Boolean(lane!.chainTarget) &&
    isConcreteSigningSessionSnapshotLane(lane!) &&
    (lane!.source === 'runtime_session_record' ||
      lane!.source === 'runtime_and_durable') &&
    (lane!.authMethod === 'email_otp' || lane!.authMethod === 'passkey')
  );
}

function getSingleRuntimeBackedEcdsaSnapshotLane(args: {
  snapshot: SigningSessionSnapshot;
  signingTarget: EvmFamilySigningTarget;
}): EvmFamilyEcdsaConcreteSnapshotLane | null {
  const runtimeCandidates = ecdsaSnapshotCandidatesForTarget(
    args.snapshot,
    args.signingTarget.chainTarget,
  ).filter(
    (lane): lane is EvmFamilyEcdsaConcreteSnapshotLane =>
      isRuntimeBackedEcdsaSnapshotLane(lane) &&
      thresholdEcdsaChainTargetsEqual(lane.chainTarget, args.signingTarget.chainTarget),
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
  if (!isConcreteSigningSessionSnapshotLane(lane)) {
    return {
      present: true,
      curve: lane.curve,
      chain: lane.chainTarget.kind,
      chainTarget: lane.chainTarget,
      state: lane.state,
    };
  }
  return {
    present: true,
    authMethod: lane.authMethod,
    curve: lane.curve,
    chain: lane.chainTarget?.kind,
    chainTarget: lane.chainTarget,
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
  if (!candidate || !isConcreteSigningSessionSnapshotLane(candidate)) return;
  if (candidate.authMethod !== args.lane.authMethod) {
    throw new Error(
      `[SigningEngine][ecdsa] prepared restore auth method ${candidate.authMethod} did not match selected lane auth method ${args.lane.authMethod}`,
    );
  }
  if (
    candidate.thresholdSessionId !== String(args.lane.thresholdSessionId)
  ) {
    throw new Error(
      '[SigningEngine][ecdsa] prepared restore threshold session did not match selected lane',
    );
  }
  if (
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
    readSigningSessionSnapshotForSigning: (
      args: Extract<ReadSigningSessionSnapshotForSigningInput, { curve: 'ecdsa' }>,
    ) => Promise<SigningSessionSnapshot>;
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
  subjectId: WalletSubjectId;
  signingTarget: EvmFamilySigningTarget;
  diagnostics: Record<string, unknown>;
  signingSessionCoordinator: SigningSessionCoordinator;
  forceFreshAuth?: boolean;
}): Promise<PreparedEvmFamilyEcdsaSigningSession> {
  const { chain, chainTarget } = args.signingTarget;
  const preparedTransaction = await prepareTransactionSigningOperation({
    intent: buildEvmFamilyTransactionSigningIntent({
      walletId: args.nearAccountId,
      authSelectionPolicy: { kind: 'account_class', authMethod: 'passkey' },
      operationUsesNeeded: 1,
      signingTarget: args.signingTarget,
    }),
    coordinator: args.signingSessionCoordinator,
    forceFreshAuth: args.forceFreshAuth === true,
    missingWhenExpiresAtMissing: true,
    prepareBudgetIdentity: true,
    onPlannerTrace: (event) => emitSigningPlannerDecisionTrace('evm-family', event),
    lifecycleAdapter: {
      prepare: async () => {
        const candidateSnapshot = await args.deps.readSigningSessionSnapshotForSigning({
          walletId: args.nearAccountId,
          subjectId: args.subjectId,
          curve: 'ecdsa',
          ecdsaChainTargets: [args.signingTarget.chainTarget],
        });
        const currentRuntimeLane = getSingleRuntimeBackedEcdsaSnapshotLane({
          snapshot: candidateSnapshot,
          signingTarget: args.signingTarget,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.snapshot_read',
          accountId: args.nearAccountId,
          chain,
          chainTarget,
          candidateCount: ecdsaSnapshotCandidatesForTarget(
            candidateSnapshot,
            args.signingTarget.chainTarget,
          ).length,
          currentRuntimeLane: summarizeEcdsaSnapshotLane(currentRuntimeLane),
        });
        const accountAuth = await resolveEvmFamilyTransactionAccountAuth({
          deps: args.deps,
          nearAccountId: args.nearAccountId,
          senderSignatureAlgorithm: 'secp256k1',
        });
        const primaryAuthMethod =
          accountAuth.primaryAuthMethod === 'email_otp' ? 'email_otp' : 'passkey';
        const transactionIntent: TransactionSigningIntent = buildEvmFamilyTransactionSigningIntent({
          walletId: args.nearAccountId,
          authSelectionPolicy: { kind: 'account_class', authMethod: primaryAuthMethod },
          operationUsesNeeded: 1,
          signingTarget: args.signingTarget,
        });
        const selectedLane = selectTransactionLane({
          intent: transactionIntent,
          snapshot: candidateSnapshot,
          currentRuntimeLane,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.lane_selected',
          accountId: args.nearAccountId,
          chain,
          chainTarget,
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
              chain,
              chainTarget,
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
            chain,
            chainTarget,
            primaryAuthMethod,
            candidateCount: ecdsaSnapshotCandidatesForTarget(
              candidateSnapshot,
              args.signingTarget.chainTarget,
            ).length,
          });
          throw new Error(
            `[SigningEngine][ecdsa] transaction restore requires an exact snapshot lane for ${chain}`,
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
            chain,
            chainTarget,
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
              chainTarget,
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
              chain,
              chainTarget,
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
              `[SigningEngine][ecdsa] exact transaction restore failed for ${chain} ${authMethod}: ${message}`,
            );
          }
          emitSigningSessionFlowTrace('evm-family', {
            stage: 'ecdsa_prepare.restore_succeeded',
            accountId: args.nearAccountId,
            chain,
            chainTarget,
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
          subjectId: transactionLane.subjectId,
          chain,
          chainTarget,
          senderSignatureAlgorithm: 'secp256k1',
          authMethod,
          transactionLane,
          snapshotCandidate,
          allowMissingHotMaterial: args.forceFreshAuth === true,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.material_selected',
          accountId: args.nearAccountId,
          chain,
          chainTarget,
          authMethod: selection.authMethod,
          source: selection.source,
          lane: summarizeEvmFamilyEcdsaLane(selection.lane),
          warmRecord: summarizeEvmFamilyEcdsaSessionRecord(selection.warmRecord),
          warmKeyRef: summarizeEvmFamilyEcdsaKeyRef(selection.warmKeyRef),
          reauthRecord: summarizeEvmFamilyEcdsaSessionRecord(selection.reauthRecord),
        });
        const snapshot = await args.deps.readSigningSessionSnapshotForSigning({
          walletId: args.nearAccountId,
          subjectId: transactionLane.subjectId,
          curve: 'ecdsa',
          ecdsaChainTargets: [args.signingTarget.chainTarget],
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
            chain,
            chainTarget,
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
          chain,
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
          chain,
          chainTarget,
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
