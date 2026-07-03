import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import type {
  EcdsaLaneCandidate,
  SelectedEcdsaLane,
  ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import {
  laneCandidateAuthMethod,
  selectedLaneAuthMethod,
} from '../../session/identity/laneIdentity';
import type {
  ReadAvailableSigningLanesForSigningInput,
  AvailableSigningLanes,
  AvailableEcdsaSigningLane,
} from '../../session/availability/availableSigningLanes';
import {
  availableEcdsaSigningLaneAuthMethod,
  buildReauthAnchorIdentityFromAvailableLane,
  ecdsaAvailableLaneCandidatesForTarget,
  isConcreteAvailableSigningLane,
} from '../../session/availability/availableSigningLanes';
import {
  exactEcdsaSigningLaneIdentity,
  exactEcdsaSigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityKey,
  requireEvmFamilyEcdsaSigner,
} from '../../session/identity/exactSigningLaneIdentity';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import type { RestorePersistedSessionForSigningInput } from '../../session/sealedRecovery/sealedRecovery.types';
import type { SigningSessionBudgetStatusAuth } from '../../session/budget/budget';
import {
  selectTransactionLane,
  type EvmFamilyEcdsaAvailableLane,
} from '../../session/identity/selectLane';
import { deriveEvmFamilyKeyFingerprintFromPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  prepareTransactionSigningOperation,
  recordPreparedTransactionNoBudget,
  type EvmFamilyEcdsaTransactionSigningIntent,
  type PreparedTransactionBudgetState,
  type PreparedTransactionOperation,
  type TransactionAuthSelectionPolicy,
  type TransactionSigningIntent,
} from '../../session/operationState/transactionState';
import {
  SigningSessionIds,
  type SigningOperationContext,
} from '../../session/operationState/types';
import { computeSigningOperationFingerprint } from '../../session/planning/operationFingerprint';
import type { SigningSessionReadiness } from '../../session/planning/planner';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  type WalletId,
  type WalletSessionRef,
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
import {
  ecdsaCommittedLaneAuthMethod,
  resolveEvmFamilyEcdsaSigningSelection,
  type EvmFamilyEcdsaSigningSelectionResult,
  type EvmFamilyEcdsaSigningSelectionDeps,
  type ReadyEvmFamilyEcdsaSigningSelection,
  type ReauthRequiredEvmFamilyEcdsaSigningSelection,
} from './ecdsaSelection';
import {
  resolveEvmFamilyEcdsaPlannerReadiness,
  type EvmFamilyPlannerReadiness,
  type EvmFamilyPreConfirmSigningDeps,
} from './authPlanning';
import { resolveEvmFamilyTransactionWalletAuth } from './accountAuth';
import type { EvmFamilySigningTarget } from './types';

export function buildEvmFamilyTransactionSigningIntent(args: {
  walletId: WalletId;
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

export function resolveEvmFamilyTransactionAuthSelectionPolicy(args: {
  candidateAuthMethod?: EvmFamilyEcdsaAuthMethod;
}): TransactionAuthSelectionPolicy {
  return args.candidateAuthMethod
    ? { kind: 'account_class', authMethod: args.candidateAuthMethod }
    : { kind: 'any' };
}

function singleConcreteAuthMethodForEcdsaTarget(args: {
  availableLanes: AvailableSigningLanes;
  signingTarget: EvmFamilySigningTarget;
}): EvmFamilyEcdsaAuthMethod | undefined {
  const authMethods = new Set<EvmFamilyEcdsaAuthMethod>();
  for (const lane of ecdsaAvailableLaneCandidatesForTarget(
    args.availableLanes,
    args.signingTarget,
  )) {
    if (!isConcreteAvailableSigningLane(lane)) continue;
    if (!thresholdEcdsaChainTargetsEqual(lane.chainTarget, args.signingTarget)) continue;
    authMethods.add(availableEcdsaSigningLaneAuthMethod(lane));
  }
  return authMethods.size === 1 ? Array.from(authMethods)[0] : undefined;
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
  const evmFamilyKeyFingerprint = deriveEvmFamilyKeyFingerprintFromPublicFacts({
    walletId: lane.key.walletId,
    publicFacts: lane.publicFacts,
  });
  return {
    present: true,
    authMethod: availableEcdsaSigningLaneAuthMethod(lane),
    curve: lane.curve,
    chain: lane.chainTarget?.kind,
    chainTarget: lane.chainTarget,
    ...(evmFamilyKeyFingerprint ? { evmFamilyKeyFingerprint } : {}),
    state: lane.state,
    source: lane.source,
    ...(lane.source === 'evm_family_shared_key'
      ? { sourceChainTarget: lane.sourceChainTarget }
      : {}),
    signingGrantId: lane.signingGrantId,
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
    authMethod: laneCandidateAuthMethod(candidate),
    curve: candidate.curve,
    chain: candidate.chainTarget.kind,
    chainTarget: candidate.chainTarget,
    ...(candidate.source === 'evm_family_shared_key'
      ? { sourceChainTarget: candidate.sourceChainTarget }
      : {}),
    state: candidate.state,
    source: candidate.source,
    signingGrantId: candidate.signingGrantId,
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
  const candidateAuthMethod = laneCandidateAuthMethod(candidate);
  const committedAuthMethod = ecdsaCommittedLaneAuthMethod(args.selection.committedLane);
  if (candidateAuthMethod !== committedAuthMethod) {
    throw new Error(
      `[SigningEngine][ecdsa] prepared restore auth method ${candidateAuthMethod} did not match committed lane auth method ${committedAuthMethod}`,
    );
  }
  if (args.selection.authMethod !== committedAuthMethod) {
    throw new Error(
      `[SigningEngine][ecdsa] selected auth method ${args.selection.authMethod} did not match committed lane auth method ${committedAuthMethod}`,
    );
  }
  const selectionLaneAuthMethod = selectedLaneAuthMethod(args.selection.lane);
  if (selectionLaneAuthMethod !== committedAuthMethod) {
    throw new Error(
      `[SigningEngine][ecdsa] selected lane auth method ${selectionLaneAuthMethod} did not match committed lane auth method ${committedAuthMethod}`,
    );
  }
  if (candidate.thresholdSessionId !== String(args.selection.lane.thresholdSessionId)) {
    throw new Error(
      '[SigningEngine][ecdsa] prepared restore threshold session did not match selected lane',
    );
  }
  if (candidate.signingGrantId !== String(args.selection.lane.signingGrantId)) {
    throw new Error(
      '[SigningEngine][ecdsa] prepared restore signing grant did not match selected lane',
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
  const committedLaneKey = exactSigningLaneIdentityKey(
    exactEcdsaSigningLaneIdentityFromSelectedLane(args.selection.committedLane.lane),
  );
  const selectionLaneKey = exactSigningLaneIdentityKey(
    exactEcdsaSigningLaneIdentityFromSelectedLane(args.selection.lane),
  );
  if (committedLaneKey !== selectionLaneKey) {
    throw new Error('[SigningEngine][ecdsa] committed lane did not match selected lane');
  }
  if (
    args.selection.committedLane.candidate.thresholdSessionId !==
      args.candidate.thresholdSessionId ||
    args.selection.committedLane.candidate.signingGrantId !== args.candidate.signingGrantId
  ) {
    throw new Error('[SigningEngine][ecdsa] committed lane candidate did not match selected candidate');
  }
  if (
    !materialIdentityMatchesResolvedLane({
      state: args.selection.committedLane.material,
      lane: args.selection.lane,
    })
  ) {
    throw new Error('[SigningEngine][ecdsa] committed lane material did not match selected lane');
  }
}

function readinessFromSelection(
  selection: EvmFamilyEcdsaSigningSelectionResult,
): EvmFamilyPlannerReadiness {
  switch (selection.kind) {
    case 'ready': {
      const expiresAtMs = Math.floor(Number(selection.material.record.expiresAtMs) || 0);
      const remainingUses = Math.max(
        0,
        Math.floor(Number(selection.material.record.remainingUses) || 0),
      );
      return {
        readiness: {
          status: 'ready',
          thresholdSessionId: selection.lane.thresholdSessionId,
          expiresAtMs,
          remainingUses,
        },
        expiresAtMs,
        remainingUses,
        trustedBudgetStatusAuth: {
          kind: 'no_trusted_budget_status_auth',
        },
      };
    }
    case 'reauth_required': {
      const committedAuthMethod = ecdsaCommittedLaneAuthMethod(selection.committedLane);
      if (
        committedAuthMethod === 'passkey' &&
        selection.reason === 'missing_hot_material' &&
        selection.material.kind === 'reauth_required' &&
        selection.material.reason === 'missing_inline_share'
      ) {
        const expiresAtMs = Math.max(
          0,
          Math.floor(Number(selection.material.record.expiresAtMs) || 0),
        );
        const remainingUses = Math.max(
          0,
          Math.floor(Number(selection.material.record.remainingUses) || 0),
        );
        return {
          readiness: {
            status: 'ready',
            thresholdSessionId: selection.lane.thresholdSessionId,
            expiresAtMs,
            remainingUses,
          },
          expiresAtMs,
          remainingUses,
          trustedBudgetStatusAuth: {
            kind: 'no_trusted_budget_status_auth',
          },
        };
      }
      const status =
        selection.material.kind === 'public_identity_unavailable'
          ? 'missing_session'
          : selection.reason === 'expired'
            ? 'expired'
            : selection.reason === 'exhausted'
              ? 'exhausted'
              : 'missing_session';
      const readiness: SigningSessionReadiness =
        status === 'expired'
          ? { status, thresholdSessionId: selection.lane.thresholdSessionId, expiresAtMs: 0 }
          : status === 'exhausted'
            ? {
                status,
                thresholdSessionId: selection.lane.thresholdSessionId,
                expiresAtMs: 0,
                remainingUses: 0,
              }
            : { status, thresholdSessionId: selection.lane.thresholdSessionId };
      return {
        readiness,
        expiresAtMs: 0,
        remainingUses: 0,
        trustedBudgetStatusAuth: {
          kind: 'no_trusted_budget_status_auth',
        },
      };
    }
    case 'budget_blocked':
      return {
        readiness: {
          status: 'budget_unknown',
          thresholdSessionId: selection.lane.thresholdSessionId,
        },
        expiresAtMs: Math.floor(Number(selection.material.record.expiresAtMs) || 0),
        remainingUses: 0,
        trustedBudgetStatusAuth: {
          kind: 'no_trusted_budget_status_auth',
        },
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
        trustedBudgetStatusAuth: {
          kind: 'no_trusted_budget_status_auth',
        },
      };
  }
}

type PreparedEvmFamilyEcdsaMetadata = {
  accountAuth: AccountAuthMetadata;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  selection: ReadyEvmFamilyEcdsaSigningSelection | ReauthRequiredEvmFamilyEcdsaSigningSelection;
  materialBinding: {
    operationId: SigningOperationContext['operationId'];
    operationFingerprint?: SigningOperationContext['operationFingerprint'];
    laneIdentityKey: ReturnType<typeof exactSigningLaneIdentityKey>;
    material: EcdsaMaterialState;
  };
  availableLanesGeneration: number;
};

function budgetStatusAuthFromReadyEcdsaMaterial(args: {
  selection: ReadyEvmFamilyEcdsaSigningSelection;
  material: ReadyEcdsaMaterial;
}): SigningSessionBudgetStatusAuth | null {
  const authority = args.selection.committedLane.walletSessionAuthority;
  const committedAuthMethod = ecdsaCommittedLaneAuthMethod(args.selection.committedLane);
  if (authority.kind !== 'wallet_session_authority') {
    return null;
  }
  const signerSession = args.material.signerSession;
  const relayerUrl = String(signerSession.transport.relayerUrl || '').trim();
  const thresholdSessionId = String(authority.thresholdSessionId || '').trim();
  const signingGrantId = String(authority.signingGrantId || '').trim();
  const walletSessionJwt = String(authority.walletSessionJwt || '').trim();
  if (!relayerUrl || !thresholdSessionId || !signingGrantId || !walletSessionJwt) return null;
  if (
    String(signerSession.session.thresholdSessionId) !== thresholdSessionId ||
    String(signerSession.session.signingGrantId) !== signingGrantId
  ) {
    throw new Error(
      `[SigningSessionBudget] committed ${committedAuthMethod} ECDSA lane does not match ready signer session`,
    );
  }
  return {
    relayerUrl,
    thresholdSessionId,
    walletSessionJwt,
  };
}

function assertPreparedMaterialBindingMatchesOperation(args: {
  metadata: PreparedEvmFamilyEcdsaMetadata;
  preparedOperation: PreparedThresholdSigningOperation<
    ResolvedEvmFamilyEcdsaSigningLane,
    Record<string, unknown>
  >;
}): void {
  const operation = args.preparedOperation.operation;
  if (!operation) {
    throw new Error('[SigningEngine][ecdsa] prepared material requires an operation identity');
  }
  if (args.metadata.materialBinding.operationId !== operation.operationId) {
    throw new Error('[SigningEngine][ecdsa] prepared material operation identity mismatch');
  }
  if (
    args.metadata.materialBinding.operationFingerprint &&
    operation.operationFingerprint &&
    args.metadata.materialBinding.operationFingerprint !== operation.operationFingerprint
  ) {
    throw new Error('[SigningEngine][ecdsa] prepared material fingerprint mismatch');
  }
  const laneIdentityKey = exactSigningLaneIdentityKey(
    exactSigningLaneIdentityFromSelectedLane(args.preparedOperation.lane),
  );
  if (args.metadata.materialBinding.laneIdentityKey !== laneIdentityKey) {
    throw new Error('[SigningEngine][ecdsa] prepared material lane identity mismatch');
  }
}

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
  };

export async function prepareEvmFamilyEcdsaSigningSession(args: {
  deps: PrepareEvmFamilyEcdsaSigningDeps;
  walletSession: WalletSessionRef;
  signingTarget: EvmFamilySigningTarget;
  signingOperation: SigningOperationContext;
  diagnostics: Record<string, unknown>;
  signingSessionCoordinator: SigningSessionCoordinator;
  forceFreshAuth?: boolean;
}): Promise<PreparedEvmFamilyEcdsaSigningSession> {
  const chainTarget = args.signingTarget;
  const chain = chainTarget.kind;
  const walletId = toWalletId(args.walletSession.walletId);
  const preparedTransaction = await prepareTransactionSigningOperation({
    intent: buildEvmFamilyTransactionSigningIntent({
      walletId,
      authSelectionPolicy: { kind: 'any' },
      operationUsesNeeded: 1,
      signingTarget: args.signingTarget,
    }),
    coordinator: args.signingSessionCoordinator,
    operation: args.signingOperation,
    forceFreshAuth: args.forceFreshAuth === true,
    missingWhenExpiresAtMissing: true,
    prepareBudgetIdentity: false,
    onPlannerTrace: (event) => emitSigningPlannerDecisionTrace('evm-family', event),
    lifecycleAdapter: {
      prepare: async (input) => {
        const candidateAvailableLanes = await args.deps.readAvailableSigningLanesForSigning({
          walletId,
          curve: 'ecdsa',
          ecdsaChainTargets: [chainTarget],
        });
        const laneReadDiagnostic = {
          accountId: walletId,
          chain,
          chainTarget,
          targetKey: thresholdEcdsaChainTargetKey(chainTarget),
          candidateCount: ecdsaAvailableLaneCandidatesForTarget(
            candidateAvailableLanes,
            chainTarget,
          ).length,
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
        const candidateAuthMethod =
          singleConcreteAuthMethodForEcdsaTarget({
            availableLanes: candidateAvailableLanes,
            signingTarget: args.signingTarget,
          });
        const transactionIntent: TransactionSigningIntent = buildEvmFamilyTransactionSigningIntent({
          walletId,
          authSelectionPolicy: resolveEvmFamilyTransactionAuthSelectionPolicy({
            candidateAuthMethod,
          }),
          operationUsesNeeded: 1,
          signingTarget: args.signingTarget,
        });
        const selectedLane = selectTransactionLane({
          intent: transactionIntent,
          availableLanes: candidateAvailableLanes,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.lane_selected',
          accountId: walletId,
          chain,
          chainTarget,
          primaryAuthMethod: selectedLane.ok
            ? laneCandidateAuthMethod(selectedLane.candidate as EcdsaLaneCandidate)
            : candidateAuthMethod,
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
              primaryAuthMethod: candidateAuthMethod,
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
        const transactionLane = selectedLane.ok ? (selectedLane.lane as SelectedEcdsaLane) : null;
        if (!selectedAvailableLane || !laneCandidate || !transactionLane) {
          const noLaneDiagnostic = {
            stage: 'ecdsa_prepare.exact_available_lane_missing',
            accountId: walletId,
            chain,
            chainTarget,
            targetKey: thresholdEcdsaChainTargetKey(chainTarget),
            primaryAuthMethod: candidateAuthMethod,
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
        const authMethod = selectedLaneAuthMethod(transactionLane);
        const restoreResults: Record<string, unknown> = {};
        const laneRequiresFreshAuth =
          laneCandidate.state === 'expired' || laneCandidate.state === 'exhausted';
        const reauthAnchor = laneRequiresFreshAuth
          ? buildReauthAnchorIdentityFromAvailableLane({
              walletId,
              operationId: SigningSessionIds.signingOperation(
                input.operation?.operationId ||
                  `evm-family-reauth:${walletId}:${thresholdEcdsaChainTargetKey(chainTarget)}`,
              ),
              operationFingerprint:
                input.operation?.operationFingerprint ||
                (await computeSigningOperationFingerprint({
                  kind: 'evm-family:reauth-anchor',
                  payload: {
                    walletId,
                    chainTarget,
                    signingGrantId: laneCandidate.signingGrantId,
                    thresholdSessionId: laneCandidate.thresholdSessionId,
                  },
                })),
              lane: selectedAvailableLane,
            })
          : null;
        if (laneRequiresFreshAuth && !reauthAnchor) {
          throw new Error(
            '[SigningEngine][ecdsa] exhausted/expired lane did not produce a reauth anchor',
          );
        }
        const resolveSelectedEcdsaMaterial = async () =>
          await resolveEvmFamilyEcdsaSigningSelection({
            deps: args.deps,
            walletId,
            chain,
            chainTarget,
            senderSignatureAlgorithm: 'secp256k1',
            authMethod,
            laneCandidate,
            ...(reauthAnchor ? { reauthAnchor } : {}),
            allowMissingHotMaterial: args.forceFreshAuth === true,
          });
        let selection = await resolveSelectedEcdsaMaterial();
        const hasSelectedHotMaterial = selection.kind === 'ready';
        // Material selection understands shared EVM-family source targets. Only
        // restore after selection proves the selected lane lacks usable material.
        const shouldRestoreAvailableLane =
          !laneRequiresFreshAuth &&
          !hasSelectedHotMaterial &&
          (laneCandidate.state === 'restorable' ||
            laneCandidate.state === 'deferred' ||
            selection.kind === 'missing_material' ||
            (selection.kind === 'reauth_required' && selection.reason === 'missing_hot_material'));
        const restoreChainTarget =
          selectedAvailableLane.source === 'evm_family_shared_key'
            ? selectedAvailableLane.sourceChainTarget
            : chainTarget;
        if (shouldRestoreAvailableLane) {
          emitSigningSessionFlowTrace('evm-family', {
            stage: 'ecdsa_prepare.restore_start',
            accountId: walletId,
            chain,
            chainTarget,
            restoreChainTarget,
            authMethod,
            hasSelectedHotMaterial,
            selectionKind: selection.kind,
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
            const transactionLaneSigner = requireEvmFamilyEcdsaSigner(
              transactionLane.identity,
              'EVM-family restore material identity',
            );
            const result = await args.deps.restorePersistedSessionForSigning({
              walletId,
              authMethod,
              curve: 'ecdsa',
              chainTarget: restoreChainTarget,
              signingGrantId: laneCandidate.signingGrantId,
              thresholdSessionId: laneCandidate.thresholdSessionId,
              reason: 'transaction',
              materialRestoreIdentity: {
                kind: 'ecdsa_role_local_restore',
                lane: exactEcdsaSigningLaneIdentityFromSelectedLane(transactionLane),
                ecdsaThresholdKeyId: transactionLaneSigner.key.ecdsaThresholdKeyId,
              },
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
              restoreChainTarget,
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
            restoreChainTarget,
            authMethod,
            selectedAvailableLane: summarizeEcdsaAvailableLane(selectedAvailableLane),
            selectedLaneCandidate: summarizeEcdsaLaneCandidate(laneCandidate),
          });
          selection = await resolveSelectedEcdsaMaterial();
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
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.material_selected',
          accountId: walletId,
          chain,
          chainTarget,
          selectionKind: selection.kind,
          authMethod: selection.authMethod,
          lane:
            'lane' in selection ? summarizeEvmFamilyEcdsaLane(selection.lane) : { present: false },
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
          throw new Error('[SigningEngine][ecdsa] selected ECDSA lane budget is budget_unknown');
        }
        const committedSelectionAuthMethod = ecdsaCommittedLaneAuthMethod(
          selection.committedLane,
        );
        if (selection.authMethod !== committedSelectionAuthMethod) {
          throw new Error(
            `[SigningEngine][ecdsa] selection auth method ${selection.authMethod} did not match committed lane authority ${committedSelectionAuthMethod}`,
          );
        }
        const availableLanes = await args.deps.readAvailableSigningLanesForSigning({
          walletId,
          curve: 'ecdsa',
          ecdsaChainTargets: [chainTarget],
          authMethod: committedSelectionAuthMethod,
        });
        emitSigningLaneResolutionTrace('evm-family', selection.lane, {
          reason: 'evm_family_ecdsa_selection',
        });
        args.diagnostics.selection = {
          kind: selection.kind,
          authMethod: committedSelectionAuthMethod,
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
          authMethod: committedSelectionAuthMethod,
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
            ...(readiness.trustedBudgetStatusAuth.kind === 'trusted_budget_status_auth'
              ? { trustedStatusAuth: readiness.trustedBudgetStatusAuth.auth }
              : {}),
          },
          availableLanesGeneration: availableLanes.generation,
          metadata: {
            accountAuth: selection.accountAuth,
            authMethod: committedSelectionAuthMethod,
            source: selection.kind === 'ready' ? selection.source : selection.material.source,
            selection,
            materialBinding: {
              operationId: args.signingOperation.operationId,
              ...(args.signingOperation.operationFingerprint
                ? { operationFingerprint: args.signingOperation.operationFingerprint }
                : {}),
              laneIdentityKey: exactSigningLaneIdentityKey(
                exactSigningLaneIdentityFromSelectedLane(resolvedLane),
              ),
              material: selection.material,
            },
            availableLanesGeneration: availableLanes.generation,
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
  assertPreparedMaterialBindingMatchesOperation({ metadata, preparedOperation });
  const material = metadata.materialBinding.material;
  const budget =
    material.kind === 'ready_to_sign'
      ? preparedTransaction.budget
      : recordPreparedTransactionNoBudget(
          preparedTransaction.transactionOperation,
          'budget_identity_not_prepared',
        );
  const budgetStatusAuth =
    material.kind === 'ready_to_sign' && metadata.selection.kind === 'ready'
      ? budgetStatusAuthFromReadyEcdsaMaterial({
          selection: metadata.selection,
          material,
        })
      : null;
  return {
    accountAuth: metadata.accountAuth,
    authMethod: metadata.authMethod,
    source: metadata.source,
    selection: metadata.selection,
    material,
    availableLanesGeneration: metadata.availableLanesGeneration,
    signingLane: preparedOperation.lane,
    preparedOperation,
    transactionOperation: preparedTransaction.transactionOperation,
    budget,
    ...(budgetStatusAuth ? { budgetStatusAuth } : {}),
  };
}
