import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  EcdsaLaneCandidate,
  SelectedEcdsaLane,
  ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type {
  ReadAvailableSigningLanesForSigningInput,
  AvailableSigningLanes,
  AvailableEcdsaSigningLane,
} from '../../session/availability/availableSigningLanes';
import {
  ecdsaAvailableLaneCandidatesForTarget,
  isConcreteAvailableSigningLane,
} from '../../session/availability/availableSigningLanes';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { RestorePersistedSessionForSigningInput } from '../../session/sealedRecovery/types';
import type { SigningSessionBudgetStatusAuth } from '../../session/budget/budget';
import {
  selectTransactionLane,
  type EvmFamilyEcdsaAvailableLane,
} from '../../session/identity/selectLane';
import {
  prepareTransactionSigningOperation,
  type EvmFamilyEcdsaTransactionSigningIntent,
  type PreparedTransactionBudgetState,
  type PreparedTransactionOperation,
  type TransactionAuthSelectionPolicy,
  type TransactionSigningIntent,
} from '../../session/operationState/transactionState';
import { SigningSessionIds } from '../../session/operationState/types';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type WalletSessionRef,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { type PreparedThresholdSigningOperation } from '../../session/operationState/preparedOperation';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningLaneResolutionTrace,
  emitSigningPlannerDecisionTrace,
  emitSigningSessionFlowFailure,
  emitSigningSessionFlowTrace,
} from '../../session/operationState/trace';
import {
  materialIdentityMatchesResolvedLane,
  summarizeEcdsaMaterialState,
  type EcdsaMaterialState,
  type ReadyEcdsaMaterial,
} from './ecdsaMaterialState';
import {
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaLane,
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type {
  EcdsaSigningLookupArgs,
  PasskeyEcdsaSigningLookupArgs,
} from '../../interfaces/operationDeps';
import {
  resolveEvmFamilyEcdsaSigningSelection,
  type EvmFamilyEcdsaSigningSelectionResult,
  type EvmFamilyEcdsaSigningSelectionDeps,
  type ReadyEvmFamilyEcdsaSigningSelection,
  type ReauthRequiredEvmFamilyEcdsaSigningSelection,
} from './ecdsaSelection';
import {
  resolveEvmFamilyEcdsaPlannerReadiness,
  type EvmFamilyPreConfirmSigningDeps,
} from './authPlanning';
import { resolveEvmFamilyTransactionWalletAuth } from './accountAuth';
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
  return args.signingTarget.kind === 'tempo'
    ? {
        ...base,
        chain: 'tempo',
        chainTarget: args.signingTarget,
      }
    : {
        ...base,
        chain: 'evm',
        chainTarget: args.signingTarget,
      };
}

function isRuntimeBackedEcdsaAvailableLane(
  lane: AvailableEcdsaSigningLane | null | undefined,
): lane is EvmFamilyEcdsaAvailableLane {
  return (
    Boolean(lane) &&
    lane!.curve === 'ecdsa' &&
    Boolean(lane!.chainTarget) &&
    isConcreteAvailableSigningLane(lane!) &&
    (lane!.source === 'runtime_session_record' || lane!.source === 'runtime_and_durable') &&
    (lane!.authMethod === 'email_otp' || lane!.authMethod === 'passkey')
  );
}

function getSingleRuntimeBackedEcdsaAvailableLane(args: {
  availableLanes: AvailableSigningLanes;
  signingTarget: EvmFamilySigningTarget;
}): EvmFamilyEcdsaAvailableLane | null {
  const runtimeCandidates = ecdsaAvailableLaneCandidatesForTarget(
    args.availableLanes,
    args.signingTarget,
  ).filter(
    (lane): lane is EvmFamilyEcdsaAvailableLane =>
      isRuntimeBackedEcdsaAvailableLane(lane) &&
      thresholdEcdsaChainTargetsEqual(lane.chainTarget, args.signingTarget),
  );
  if (runtimeCandidates.length === 1) return runtimeCandidates[0];
  // Multiple runtime lanes are not a single current-lane anchor; let the
  // account-class policy choose instead of hiding a live lane before selection.
  return null;
}

function summarizeEcdsaAvailableLane(
  lane: AvailableEcdsaSigningLane | null | undefined,
): Record<string, unknown> {
  if (!lane) return { present: false };
  if (!isConcreteAvailableSigningLane(lane)) {
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

function summarizeEcdsaAvailableCandidatesByTarget(
  availableLanes: AvailableSigningLanes,
): Record<string, unknown[]> {
  return Object.fromEntries(
    Object.entries(availableLanes.ecdsa.candidatesByTarget).map(([targetKey, candidates]) => [
      targetKey,
      candidates.map((candidate) => summarizeEcdsaAvailableLane(candidate)),
    ]),
  );
}

function emitVisibleEcdsaLaneDiagnostic(label: string, payload: Record<string, unknown>): void {
  try {
    console.warn(label, JSON.stringify(payload, null, 2));
  } catch {
    try {
      console.warn(label, payload);
    } catch {}
  }
}

function summarizeEcdsaSelectedLanesByTarget(
  availableLanes: AvailableSigningLanes,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(availableLanes.ecdsa.lanesByTarget).map(([targetKey, lane]) => [
      targetKey,
      summarizeEcdsaAvailableLane(lane),
    ]),
  );
}

function summarizeEcdsaLaneCandidate(
  candidate: EcdsaLaneCandidate | null | undefined,
): Record<string, unknown> {
  if (!candidate) return { present: false };
  return {
    present: true,
    authMethod: candidate.authMethod,
    curve: candidate.curve,
    chain: candidate.chainTarget.kind,
    chainTarget: candidate.chainTarget,
    state: candidate.state,
    source: candidate.source,
    walletSigningSessionId: candidate.walletSigningSessionId,
    thresholdSessionId: candidate.thresholdSessionId,
    remainingUses: candidate.remainingUses,
    expiresAtMs: candidate.expiresAtMs,
    updatedAtMs: candidate.updatedAtMs,
  };
}

function assertSelectionMatchesLaneCandidate(args: {
  candidate: EcdsaLaneCandidate;
  selection: ReadyEvmFamilyEcdsaSigningSelection;
}): void {
  const candidate = args.candidate;
  if (candidate.authMethod !== args.selection.lane.authMethod) {
    throw new Error(
      `[SigningEngine][ecdsa] prepared restore auth method ${candidate.authMethod} did not match selected lane auth method ${args.selection.lane.authMethod}`,
    );
  }
  if (candidate.thresholdSessionId !== String(args.selection.lane.thresholdSessionId)) {
    throw new Error(
      '[SigningEngine][ecdsa] prepared restore threshold session did not match selected lane',
    );
  }
  if (candidate.walletSigningSessionId !== String(args.selection.lane.walletSigningSessionId)) {
    throw new Error(
      '[SigningEngine][ecdsa] prepared restore wallet signing session did not match selected lane',
    );
  }
  if (
    !materialIdentityMatchesResolvedLane({
      state: args.selection.material,
      lane: args.selection.lane,
    })
  ) {
    throw new Error('[SigningEngine][ecdsa] prepared restore material did not match selected lane');
  }
}

function readinessFromSelection(selection: EvmFamilyEcdsaSigningSelectionResult): {
  readiness: {
    status:
      | 'ready'
      | 'missing_session'
      | 'expired'
      | 'exhausted'
      | 'budget_unknown';
    thresholdSessionId: ResolvedEvmFamilyEcdsaSigningLane['thresholdSessionId'];
  };
  expiresAtMs: number;
  remainingUses: number;
  signingRootId?: string;
} {
  switch (selection.kind) {
    case 'ready':
      return {
        readiness: {
          status: 'ready',
          thresholdSessionId: selection.lane.thresholdSessionId,
        },
        expiresAtMs: Math.floor(Number(selection.material.record.expiresAtMs) || 0),
        remainingUses: Math.max(0, Math.floor(Number(selection.material.record.remainingUses) || 0)),
        signingRootId: selection.material.signingKeyContext.signingRootId,
      };
    case 'reauth_required':
      return {
        readiness: {
          status:
            selection.reason === 'expired'
              ? 'expired'
              : selection.reason === 'exhausted'
                ? 'exhausted'
                : 'missing_session',
          thresholdSessionId: selection.lane.thresholdSessionId,
        },
        expiresAtMs: 0,
        remainingUses: 0,
        ...(selection.material.kind === 'missing'
          ? {}
          : { signingRootId: selection.material.signingKeyContext.signingRootId }),
      };
    case 'budget_blocked':
      return {
        readiness: {
          status: 'budget_unknown',
          thresholdSessionId: selection.lane.thresholdSessionId,
        },
        expiresAtMs: Math.floor(Number(selection.material.record.expiresAtMs) || 0),
        remainingUses: 0,
        signingRootId: selection.material.signingKeyContext.signingRootId,
      };
    case 'missing_material':
      return {
        readiness: {
          status: 'missing_session',
          thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
            selection.candidate.thresholdSessionId,
          ),
        },
        expiresAtMs: 0,
        remainingUses: 0,
      };
  }
}

type PreparedEvmFamilyEcdsaMetadata = {
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  selection: ReadyEvmFamilyEcdsaSigningSelection | ReauthRequiredEvmFamilyEcdsaSigningSelection;
  material: EcdsaMaterialState;
  availableLanesGeneration: number;
  signingRootId?: string;
};

export type PreparedEvmFamilyEcdsaSigningSession = {
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  selection: ReadyEvmFamilyEcdsaSigningSelection | ReauthRequiredEvmFamilyEcdsaSigningSelection;
  material: EcdsaMaterialState;
  availableLanesGeneration: number;
  signingLane: ResolvedEvmFamilyEcdsaSigningLane;
  preparedOperation: PreparedThresholdSigningOperation<
    ResolvedEvmFamilyEcdsaSigningLane,
    Record<string, unknown>
  >;
  transactionOperation: PreparedTransactionOperation<SelectedEcdsaLane>;
  budget: PreparedTransactionBudgetState<SelectedEcdsaLane>;
  budgetStatusAuth?: SigningSessionBudgetStatusAuth;
};

export type PrepareEvmFamilyEcdsaSigningDeps = EvmFamilyEcdsaSigningSelectionDeps &
  EvmFamilyPreConfirmSigningDeps & {
    restorePersistedSessionForSigning: (
      args: Extract<RestorePersistedSessionForSigningInput, { curve: 'ecdsa' }>,
    ) => Promise<unknown>;
    readAvailableSigningLanesForSigning: (
      args: Extract<ReadAvailableSigningLanesForSigningInput, { curve: 'ecdsa' }>,
    ) => Promise<AvailableSigningLanes>;
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
  walletSession: WalletSessionRef;
  subjectId: WalletSubjectId;
  signingTarget: EvmFamilySigningTarget;
  diagnostics: Record<string, unknown>;
  signingSessionCoordinator: SigningSessionCoordinator;
  forceFreshAuth?: boolean;
}): Promise<PreparedEvmFamilyEcdsaSigningSession> {
  const chainTarget = args.signingTarget;
  const chain = chainTarget.kind;
  const walletId = String(args.walletSession.walletId);
  const preparedTransaction = await prepareTransactionSigningOperation({
    intent: buildEvmFamilyTransactionSigningIntent({
      walletId,
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
        const candidateAvailableLanes = await args.deps.readAvailableSigningLanesForSigning({
          walletId,
          subjectId: args.subjectId,
          curve: 'ecdsa',
          ecdsaChainTargets: [chainTarget],
        });
        const currentRuntimeLane = getSingleRuntimeBackedEcdsaAvailableLane({
          availableLanes: candidateAvailableLanes,
          signingTarget: args.signingTarget,
        });
        const laneReadDiagnostic = {
          accountId: walletId,
          subjectId: args.subjectId,
          chain,
          chainTarget,
          targetKey: thresholdEcdsaChainTargetKey(chainTarget),
          candidateCount: ecdsaAvailableLaneCandidatesForTarget(
            candidateAvailableLanes,
            chainTarget,
          ).length,
          currentRuntimeLane: summarizeEcdsaAvailableLane(currentRuntimeLane),
          selectedLanesByTarget: summarizeEcdsaSelectedLanesByTarget(candidateAvailableLanes),
          candidatesByTarget: summarizeEcdsaAvailableCandidatesByTarget(candidateAvailableLanes),
        };
        if (laneReadDiagnostic.candidateCount === 0) {
          emitVisibleEcdsaLaneDiagnostic(
            '[ECDSA_LANE_READ_DIAGNOSTIC][no-candidates]',
            laneReadDiagnostic,
          );
        }
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.available_lanes_read',
          ...laneReadDiagnostic,
        });
        const accountAuth = await resolveEvmFamilyTransactionWalletAuth({
          deps: args.deps,
          walletId,
          senderSignatureAlgorithm: 'secp256k1',
        });
        const primaryAuthMethod =
          accountAuth.primaryAuthMethod === 'email_otp' ? 'email_otp' : 'passkey';
        const transactionIntent: TransactionSigningIntent = buildEvmFamilyTransactionSigningIntent({
          walletId,
          authSelectionPolicy: { kind: 'account_class', authMethod: primaryAuthMethod },
          operationUsesNeeded: 1,
          signingTarget: args.signingTarget,
        });
        const selectedLane = selectTransactionLane({
          intent: transactionIntent,
          availableLanes: candidateAvailableLanes,
          currentRuntimeLane,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.lane_selected',
          accountId: walletId,
          chain,
          chainTarget,
          primaryAuthMethod,
          selectionOk: selectedLane.ok,
          ...(selectedLane.ok
            ? {
                selectedAvailableLane: summarizeEcdsaAvailableLane(
                  selectedLane.availableLane as AvailableEcdsaSigningLane,
                ),
                selectedLaneCandidate: summarizeEcdsaLaneCandidate(
                  selectedLane.candidate as EcdsaLaneCandidate,
                ),
                transactionLane: selectedLane.lane,
              }
            : { failure: selectedLane.failure }),
        });
        if (!selectedLane.ok) {
          if (selectedLane.failure.kind !== 'no_candidate') {
            emitSigningSessionFlowFailure('evm-family', {
              stage: 'ecdsa_prepare.lane_selection_failed',
              accountId: walletId,
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
          (selectedLane.lane.curve !== 'ecdsa' || selectedLane.availableLane.curve !== 'ecdsa')
        ) {
          throw new Error('[SigningEngine][ecdsa] selector returned a non-ECDSA lane');
        }
        const selectedAvailableLane = selectedLane.ok
          ? (selectedLane.availableLane as EvmFamilyEcdsaAvailableLane)
          : null;
        const laneCandidate = selectedLane.ok
          ? (selectedLane.candidate as EcdsaLaneCandidate)
          : null;
        const transactionLane = selectedLane.ok
          ? (selectedLane.lane as SelectedEcdsaLane)
          : null;
        if (!selectedAvailableLane || !laneCandidate || !transactionLane) {
          const noLaneDiagnostic = {
            stage: 'ecdsa_prepare.exact_available_lane_missing',
            accountId: walletId,
            subjectId: args.subjectId,
            chain,
            chainTarget,
            targetKey: thresholdEcdsaChainTargetKey(chainTarget),
            primaryAuthMethod,
            candidateCount: ecdsaAvailableLaneCandidatesForTarget(
              candidateAvailableLanes,
              chainTarget,
            ).length,
            ecdsaTargets: candidateAvailableLanes.ecdsa.targets,
            selectedLanesByTarget: summarizeEcdsaSelectedLanesByTarget(candidateAvailableLanes),
            candidatesByTarget: summarizeEcdsaAvailableCandidatesByTarget(candidateAvailableLanes),
            selectedLaneFailure: selectedLane.ok ? undefined : selectedLane.failure,
          };
          emitVisibleEcdsaLaneDiagnostic('[ECDSA_NO_LANE_DIAGNOSTIC]', noLaneDiagnostic);
          emitSigningSessionFlowFailure('evm-family', noLaneDiagnostic);
          throw new Error(
            `[SigningEngine][ecdsa] transaction restore requires an exact available lane for ${chain}`,
          );
        }
        const authMethod = transactionLane.authMethod;
        const hasExactHotMaterial = Boolean(
          args.deps.getThresholdEcdsaSessionRecordByKey(transactionLane) ||
            args.deps.getThresholdEcdsaKeyRefByKey(transactionLane),
        );
        // Transaction prepare first reads side-effect-free available signing
        // lanes, then restores only the selected exact auth-method lane.
        // Broad probing belongs to startup/session-status maintenance paths.
        const restoreResults: Record<string, unknown> = {};
        const shouldRestoreAvailableLane =
          laneCandidate.state === 'restorable' ||
          laneCandidate.state === 'deferred' ||
          !hasExactHotMaterial;
        if (shouldRestoreAvailableLane) {
          emitSigningSessionFlowTrace('evm-family', {
            stage: 'ecdsa_prepare.restore_start',
            accountId: walletId,
            chain,
            chainTarget,
            authMethod,
            hasExactHotMaterial,
            selectedAvailableLane: summarizeEcdsaAvailableLane(selectedAvailableLane),
            selectedLaneCandidate: summarizeEcdsaLaneCandidate(laneCandidate),
          });
          args.diagnostics.sealedRestoreBeforeSelection = {
            attempted: true,
            completed: false,
            authMethod,
            selectedAvailableLane: summarizeEcdsaAvailableLane(selectedAvailableLane),
          };
          try {
            const result = await args.deps.restorePersistedSessionForSigning({
              walletId,
              authMethod,
              curve: 'ecdsa',
              chainTarget,
              walletSigningSessionId: laneCandidate.walletSigningSessionId,
              thresholdSessionId: laneCandidate.thresholdSessionId,
              reason: 'transaction',
            });
            restoreResults[authMethod] = result;
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            restoreResults[authMethod] = { error: message };
            emitSigningSessionFlowFailure('evm-family', {
              stage: 'ecdsa_prepare.restore_failed',
              accountId: walletId,
              chain,
              chainTarget,
              authMethod,
              selectedAvailableLane: summarizeEcdsaAvailableLane(selectedAvailableLane),
              selectedLaneCandidate: summarizeEcdsaLaneCandidate(laneCandidate),
              error: message,
            });
            args.diagnostics.sealedRestoreBeforeSelection = {
              attempted: true,
              completed: false,
              authMethod,
              results: restoreResults,
              selectedLaneCandidate: summarizeEcdsaLaneCandidate(laneCandidate),
            };
            throw new Error(
              `[SigningEngine][ecdsa] exact transaction restore failed for ${chain} ${authMethod}: ${message}`,
            );
          }
          emitSigningSessionFlowTrace('evm-family', {
            stage: 'ecdsa_prepare.restore_succeeded',
            accountId: walletId,
            chain,
            chainTarget,
            authMethod,
            selectedAvailableLane: summarizeEcdsaAvailableLane(selectedAvailableLane),
            selectedLaneCandidate: summarizeEcdsaLaneCandidate(laneCandidate),
          });
        } else {
          args.diagnostics.sealedRestoreBeforeSelection = {
            attempted: false,
            completed: true,
            authMethod,
            reason: 'selected_available_lane_ready',
          };
        }
        args.diagnostics.sealedRestoreBeforeSelection = {
          attempted: shouldRestoreAvailableLane,
          completed: true,
          authMethod,
          results: restoreResults,
          selectedLaneCandidate: summarizeEcdsaLaneCandidate(laneCandidate),
        };

        const selection = await resolveEvmFamilyEcdsaSigningSelection({
          deps: args.deps,
          walletId,
          subjectId: transactionLane.subjectId,
          chain,
          chainTarget,
          senderSignatureAlgorithm: 'secp256k1',
          authMethod,
          laneCandidate,
          allowMissingHotMaterial: args.forceFreshAuth === true,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.material_selected',
          accountId: walletId,
          chain,
          chainTarget,
          selectionKind: selection.kind,
          authMethod: selection.authMethod,
          lane:
            'lane' in selection
              ? summarizeEvmFamilyEcdsaLane(selection.lane)
              : { present: false },
          material: summarizeEcdsaMaterialState(selection.material),
          diagnostics: selection.diagnostics,
        });
        if (selection.kind === 'missing_material') {
          emitSigningSessionFlowFailure('evm-family', {
            stage: 'ecdsa_selection.exact_material_missing',
            accountId: walletId,
            chain,
            chainTarget,
            authMethod: selection.authMethod,
            candidate: selection.diagnostics.selectedLaneCandidate,
            material: summarizeEcdsaMaterialState(selection.material),
          });
          throw new Error(
            '[SigningEngine][ecdsa] exact available lane is unavailable after restore',
          );
        }
        if (selection.kind === 'budget_blocked') {
          emitSigningSessionFlowFailure('evm-family', {
            stage: 'ecdsa_prepare.selection_budget_blocked',
            accountId: walletId,
            chain,
            chainTarget,
            authMethod: selection.authMethod,
            lane: summarizeEvmFamilyEcdsaLane(selection.lane),
            material: summarizeEcdsaMaterialState(selection.material),
            budget: selection.budget,
          });
          throw new Error(
            '[SigningEngine][ecdsa] selected ECDSA lane budget is budget_unknown',
          );
        }
        const availableLanes = await args.deps.readAvailableSigningLanesForSigning({
          walletId,
          subjectId: transactionLane.subjectId,
          curve: 'ecdsa',
          ecdsaChainTargets: [chainTarget],
          authMethod: selection.authMethod,
        });
        emitSigningLaneResolutionTrace('evm-family', selection.lane, {
          reason: 'evm_family_ecdsa_selection',
        });
        args.diagnostics.selection = {
          kind: selection.kind,
          authMethod: selection.authMethod,
          source: selection.kind === 'ready' ? selection.source : selection.material.source,
          lane: summarizeEvmFamilyEcdsaLane(selection.lane),
          material: summarizeEcdsaMaterialState(selection.material),
          diagnostics: selection.diagnostics,
        };
        const resolvedLane = requireResolvedEvmFamilyEcdsaSigningLane({
          lane: selection.lane,
          chain,
          context: 'EVM-family signing preparation',
          diagnostics: args.diagnostics,
        });
        if (selection.kind === 'ready') {
          assertSelectionMatchesLaneCandidate({
            candidate: laneCandidate,
            selection,
          });
        }
        const readiness =
          selection.kind === 'ready'
            ? await resolveEvmFamilyEcdsaPlannerReadiness({
                deps: args.deps,
                lane: resolvedLane,
                material: selection.material,
              })
            : readinessFromSelection(selection);
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.readiness',
          accountId: walletId,
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
          availableLanesGeneration: availableLanes.generation,
          metadata: {
            accountAuth: selection.accountAuth,
            authMethod: selection.authMethod,
            source: selection.kind === 'ready' ? selection.source : selection.material.source,
            selection,
            material: selection.material,
            availableLanesGeneration: availableLanes.generation,
            ...(readiness.signingRootId ? { signingRootId: readiness.signingRootId } : {}),
          },
        };
      },
    },
  });
  const preparedOperation =
    preparedTransaction.thresholdOperation as PreparedThresholdSigningOperation<
      ResolvedEvmFamilyEcdsaSigningLane,
      Record<string, unknown>
    >;
  const metadata = preparedOperation.metadata as PreparedEvmFamilyEcdsaMetadata;
  return {
    accountAuth: metadata.accountAuth,
    authMethod: metadata.authMethod,
    source: metadata.source,
    selection: metadata.selection,
    material: metadata.material,
    availableLanesGeneration: metadata.availableLanesGeneration,
    signingLane: preparedOperation.lane,
    preparedOperation,
    transactionOperation: preparedTransaction.transactionOperation,
    budget: preparedTransaction.budget,
  };
}
