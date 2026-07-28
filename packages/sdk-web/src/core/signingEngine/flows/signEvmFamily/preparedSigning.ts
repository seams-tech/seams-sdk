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
  buildReauthAnchorIdentityFromEcdsaLaneCandidate,
  ecdsaAvailableLaneCandidatesForTarget,
  isConcreteAvailableSigningLane,
} from '../../session/availability/availableSigningLanes';
import {
  exactEcdsaSigningLaneIdentity,
  exactEcdsaSigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityKey,
} from '../../session/identity/exactSigningLaneIdentity';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  selectTransactionLane,
  type EvmFamilyEcdsaAvailableLane,
} from '../../session/identity/selectLane';
import { deriveEvmFamilyKeyFingerprintFromPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  prepareTransactionSigningOperation,
  type EvmFamilyEcdsaTransactionSigningIntent,
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
  type ThresholdEcdsaChainTarget,
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
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaLane,
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import {
  ecdsaCommittedLaneAuthMethod,
  resolveEvmFamilyEcdsaSigningSelection,
  type EvmFamilyEcdsaSigningSelectionDeps,
  type ReadyEvmFamilyEcdsaSigningSelection,
  type ReauthRequiredEvmFamilyEcdsaSigningSelection,
} from './ecdsaSelection';
import type { EvmFamilyPreConfirmSigningDeps } from './authPlanning';
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
    walletSessionId: lane.authorization?.projection.walletSessionId,
    materialActivationId: lane.materialActivation.activationId,
    remainingUses: lane.authorization?.status.remainingUses,
    expiresAtMs: lane.authorization?.status.expiresAtMs,
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
    walletSessionId: candidate.authorization.projection.walletSessionId,
    materialActivationId: candidate.materialActivation.activationId,
    remainingUses: candidate.authorization.status.remainingUses,
    expiresAtMs: candidate.authorization.status.expiresAtMs,
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
      `[SigningEngine][ecdsa] prepared auth method ${candidateAuthMethod} did not match committed lane auth method ${committedAuthMethod}`,
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
  if (
    candidate.authorization.projection.walletSessionId !==
    args.selection.lane.authorization.projection.walletSessionId
  ) {
    throw new Error('[SigningEngine][ecdsa] prepared authorization did not match lane');
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
}

type EvmFamilyPlannerReadiness = {
  readiness: SigningSessionReadiness;
  expiresAtMs: number;
  remainingUses: number;
};

function readinessFromSelection(
  selection: ReadyEvmFamilyEcdsaSigningSelection | ReauthRequiredEvmFamilyEcdsaSigningSelection,
): EvmFamilyPlannerReadiness {
  switch (selection.kind) {
    case 'ready': {
      const expiresAtMs = Math.floor(
        Number(selection.lane.authorization.status.expiresAtMs) || 0,
      );
      const remainingUses = Math.max(
        0,
        Math.floor(Number(selection.lane.authorization.status.remainingUses) || 0),
      );
      return {
        readiness: {
          status: 'ready',
          curve: 'ecdsa',
          materialActivation: selection.lane.materialActivation,
          authorization: selection.lane.authorization,
          expiresAtMs,
          remainingUses,
        },
        expiresAtMs,
        remainingUses,
      };
    }
    case 'reauth_required': {
      const status =
        selection.reason === 'expired'
            ? 'expired'
            : selection.reason === 'exhausted'
              ? 'exhausted'
              : 'missing_session';
      const readiness: SigningSessionReadiness =
        status === 'expired'
          ? {
              status,
              curve: 'ecdsa',
              materialActivation: selection.lane.materialActivation,
              authorization: selection.lane.authorization,
              expiresAtMs: 0,
            }
          : status === 'exhausted'
            ? {
                status,
                curve: 'ecdsa',
                materialActivation: selection.lane.materialActivation,
                authorization: selection.lane.authorization,
                expiresAtMs: 0,
                remainingUses: 0,
              }
            : {
                status,
                curve: 'ecdsa',
                materialActivation: selection.lane.materialActivation,
                authorization: selection.lane.authorization,
              };
      return {
        readiness,
        expiresAtMs: 0,
        remainingUses: 0,
      };
    }
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
  };
  availableLanesGeneration: number;
};

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
  availableLanesGeneration: number;
  signingLane: ResolvedEvmFamilyEcdsaSigningLane;
  preparedOperation: PreparedThresholdSigningOperation<
    ResolvedEvmFamilyEcdsaSigningLane,
    Record<string, unknown>
  >;
  transactionOperation: PreparedTransactionOperation<SelectedEcdsaLane>;
};

export type PrepareEvmFamilyEcdsaSigningDeps = EvmFamilyEcdsaSigningSelectionDeps &
  EvmFamilyPreConfirmSigningDeps & {
    readAvailableSigningLanesForSigning: (
      args: Extract<ReadAvailableSigningLanesForSigningInput, { curve: 'ecdsa' }>,
    ) => Promise<AvailableSigningLanes>;
  };

async function buildEcdsaReauthAnchorForOperation(args: {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  signingOperation: SigningOperationContext;
  candidate: EcdsaLaneCandidate;
}) {
  return buildReauthAnchorIdentityFromEcdsaLaneCandidate({
    walletId: args.walletId,
    operationId: SigningSessionIds.signingOperation(
      args.signingOperation.operationId ||
        `evm-family-reauth:${args.walletId}:${thresholdEcdsaChainTargetKey(args.chainTarget)}`,
    ),
    operationFingerprint:
      args.signingOperation.operationFingerprint ||
      (await computeSigningOperationFingerprint({
        kind: 'evm-family:reauth-anchor',
        payload: {
          walletId: args.walletId,
          chainTarget: args.chainTarget,
          walletSessionId: args.candidate.authorization.projection.walletSessionId,
          materialActivationId: args.candidate.materialActivation.activationId,
        },
      })),
    candidate: args.candidate,
  });
}

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
          walletId,
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
        const candidateAuthMethod = singleConcreteAuthMethodForEcdsaTarget({
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
          walletId,
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
              walletId,
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
            walletId,
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
            `[SigningEngine][ecdsa] transaction signing requires an exact available lane for ${chain}`,
          );
        }
        const authMethod = selectedLaneAuthMethod(transactionLane);
        const laneRequiresFreshAuth =
          laneCandidate.state === 'expired' || laneCandidate.state === 'exhausted';
        const reauthAnchor = laneRequiresFreshAuth
          ? await buildEcdsaReauthAnchorForOperation({
              walletId,
              chainTarget,
              signingOperation: args.signingOperation,
              candidate: laneCandidate,
            })
          : null;
        if (laneRequiresFreshAuth && !reauthAnchor) {
          throw new Error(
            '[SigningEngine][ecdsa] exhausted/expired lane did not produce a reauth anchor',
          );
        }
        const selection = await resolveEvmFamilyEcdsaSigningSelection({
          deps: args.deps,
          walletId,
          chain,
          chainTarget,
          senderSignatureAlgorithm: 'secp256k1',
          authMethod,
          laneCandidate,
          reauth:
            reauthAnchor && selectedAvailableLane.source === 'durable_sealed_record'
              ? {
                  kind: 'public_anchor',
                  reauthAnchor,
                  publicRestore: selectedAvailableLane.publicReauthAuthority,
                }
              : { kind: 'not_required' },
          allowMissingHotMaterial: args.forceFreshAuth === true,
        });
        if (selection.kind === 'missing_material' || selection.kind === 'restore_required') {
          emitSigningSessionFlowFailure('evm-family', {
            stage: 'ecdsa_selection.canonical_material_unavailable',
            walletId,
            chain,
            chainTarget,
            authMethod: selection.authMethod,
            candidate: selection.diagnostics.selectedLaneCandidate,
          });
          throw new Error('[SigningEngine][ecdsa] canonical ECDSA material is unavailable');
        }
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.material_selected',
          walletId,
          chain,
          chainTarget,
          selectionKind: selection.kind,
          authMethod: selection.authMethod,
          lane:
            'lane' in selection ? summarizeEvmFamilyEcdsaLane(selection.lane) : { present: false },
          diagnostics: selection.diagnostics,
        });
        const committedSelectionAuthMethod = selection.authMethod;
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
          lane: summarizeEvmFamilyEcdsaLane(selection.lane),
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
        const readiness = readinessFromSelection(selection);
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.readiness',
          walletId,
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
          },
          availableLanesGeneration: availableLanes.generation,
          metadata: {
            accountAuth: selection.accountAuth,
            authMethod: committedSelectionAuthMethod,
              selection,
            materialBinding: {
              operationId: args.signingOperation.operationId,
              ...(args.signingOperation.operationFingerprint
                ? { operationFingerprint: args.signingOperation.operationFingerprint }
                : {}),
              laneIdentityKey: exactSigningLaneIdentityKey(
                exactSigningLaneIdentityFromSelectedLane(resolvedLane),
              ),
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
  return {
    accountAuth: metadata.accountAuth,
    authMethod: metadata.authMethod,
    source: metadata.source,
    selection: metadata.selection,
    availableLanesGeneration: metadata.availableLanesGeneration,
    signingLane: preparedOperation.lane,
    preparedOperation,
    transactionOperation: preparedTransaction.transactionOperation,
  };
}
