import type { AccountAuthMetadata } from '@/core/signingEngine/interfaces/accountAuthMetadata';
import type {
  AuthorizationRequiredEcdsaLaneCandidate,
  AuthorizedEcdsaLaneCandidate,
  EcdsaLaneCandidate,
  SelectedEcdsaLane,
  ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import { laneCandidateAuthMethod } from '../../session/identity/laneIdentity';
import { signingLaneAuthMethod } from '../../session/identity/signingLaneAuthBinding';
import type {
  ReadAvailableSigningLanesForSigningInput,
  AvailableSigningLanes,
  AvailableEcdsaSigningLane,
} from '../../session/availability/availableSigningLanes';
import {
  availableEcdsaSigningLaneAuthMethod,
  ecdsaAvailableLaneCandidatesForTarget,
  isConcreteAvailableSigningLane,
} from '../../session/availability/availableSigningLanes';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
  exactEcdsaSigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityKey,
  type ExactEcdsaSigningLaneIdentity,
} from '../../session/identity/exactSigningLaneIdentity';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import { selectEvmFamilyEcdsaMaterialCandidate } from '../../session/identity/selectLane';
import { deriveEvmFamilyKeyFingerprintFromPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  prepareTransactionSigningOperation,
  type EvmFamilyEcdsaTransactionSigningIntent,
  type PreparedTransactionOperation,
  type TransactionAuthSelectionPolicy,
} from '../../session/operationState/transactionState';
import type {
  SigningOperationContext,
  SigningOperationId,
} from '../../session/operationState/types';
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
  requireResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaLane,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import {
  resolveEvmFamilyEcdsaSigningSelection,
  type EvmFamilyEcdsaSigningSelectionDeps,
  type ReadyEvmFamilyEcdsaSigningSelection,
} from './ecdsaSelection';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { EvmFamilySigningTarget } from './types';

export function buildEvmFamilyTransactionSigningIntent(args: {
  walletId: WalletId;
  signingTarget: EvmFamilySigningTarget;
  authSelectionPolicy: TransactionAuthSelectionPolicy;
  operationUsesNeeded: number;
  operationId?: SigningOperationId;
}): EvmFamilyEcdsaTransactionSigningIntent {
  const base = {
    walletId: args.walletId,
    curve: 'ecdsa' as const,
    authSelectionPolicy: args.authSelectionPolicy,
    operationUsesNeeded: args.operationUsesNeeded,
    // Router A/B normal signing binds the exact operation id, so the intent
    // must carry the operation it was prepared for.
    ...(args.operationId ? { operationId: args.operationId } : {}),
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
  candidateAuthMethod: WalletAuthAuthority['factor']['kind'];
}): TransactionAuthSelectionPolicy {
  return { kind: 'account_class', authMethod: args.candidateAuthMethod };
}

function requireSingleConcreteAuthMethodForEcdsaTarget(args: {
  availableLanes: AvailableSigningLanes;
  signingTarget: EvmFamilySigningTarget;
}): WalletAuthAuthority['factor']['kind'] {
  const authMethods = new Set<WalletAuthAuthority['factor']['kind']>();
  for (const lane of ecdsaAvailableLaneCandidatesForTarget(
    args.availableLanes,
    args.signingTarget,
  )) {
    if (!isConcreteAvailableSigningLane(lane)) continue;
    if (!thresholdEcdsaChainTargetsEqual(lane.chainTarget, args.signingTarget)) continue;
    authMethods.add(availableEcdsaSigningLaneAuthMethod(lane));
  }
  if (authMethods.size !== 1) {
    throw new Error(
      '[SigningEngine][ecdsa] exact capability authority is unavailable or ambiguous',
    );
  }
  return Array.from(authMethods)[0];
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
    state: candidate.state,
    source: candidate.source,
    materialActivationId: candidate.materialActivation.activationId,
    authorizationState: candidate.authorizationState,
    ...(candidate.authorizationState === 'authorized'
      ? {
          walletSessionId: candidate.authorization.projection.walletSessionId,
          remainingUses: candidate.authorization.status.remainingUses,
          expiresAtMs: candidate.authorization.status.expiresAtMs,
        }
      : {}),
  };
}

function assertSelectionMatchesLaneCandidate(args: {
  candidate: AuthorizedEcdsaLaneCandidate;
  selection: ReadyEvmFamilyEcdsaSigningSelection;
}): void {
  const candidate = args.candidate;
  const candidateAuthMethod = laneCandidateAuthMethod(candidate);
  const committedAuthMethod = args.selection.committedLane.authority.factor.kind;
  if (candidateAuthMethod !== committedAuthMethod) {
    throw new Error(
      `[SigningEngine][ecdsa] prepared auth method ${candidateAuthMethod} did not match committed lane auth method ${committedAuthMethod}`,
    );
  }
  const selectionLaneAuthMethod = signingLaneAuthMethod(args.selection.lane.auth);
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
  selection: ReadyEvmFamilyEcdsaSigningSelection,
): EvmFamilyPlannerReadiness {
  const candidateState = selection.diagnostics.selectedLaneCandidate.state;
  if (candidateState === 'expired') {
    return {
      readiness: {
        status: 'expired',
        curve: 'ecdsa',
        materialActivation: selection.lane.materialActivation,
        authorization: selection.lane.authorization,
        expiresAtMs: 0,
      },
      expiresAtMs: 0,
      remainingUses: 0,
    };
  }
  if (candidateState === 'exhausted') {
    return {
      readiness: {
        status: 'exhausted',
        curve: 'ecdsa',
        materialActivation: selection.lane.materialActivation,
        authorization: selection.lane.authorization,
        expiresAtMs: 0,
        remainingUses: 0,
      },
      expiresAtMs: 0,
      remainingUses: 0,
    };
  }
  const expiresAtMs = Math.floor(Number(selection.lane.authorization.status.expiresAtMs) || 0);
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

type PreparedEvmFamilyEcdsaMetadata = {
  accountAuth: AccountAuthMetadata;
  authMethod: WalletAuthAuthority['factor']['kind'];
  source: ThresholdEcdsaSessionStoreSource;
  selection: ReadyEvmFamilyEcdsaSigningSelection;
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

/** Prepared against an active reusable Wallet Session. Only this branch owns a
 * `SelectedEcdsaLane`: a selected lane carries the authorization that made it
 * selectable, so it cannot describe auth-neutral material. */
export type AuthorizedEvmFamilyEcdsaSigningSession = {
  kind: 'authorized';
  accountAuth: AccountAuthMetadata;
  authMethod: WalletAuthAuthority['factor']['kind'];
  source: ThresholdEcdsaSessionStoreSource;
  selection: ReadyEvmFamilyEcdsaSigningSelection;
  availableLanesGeneration: number;
  signingLane: ResolvedEvmFamilyEcdsaSigningLane;
  preparedOperation: PreparedThresholdSigningOperation<
    ResolvedEvmFamilyEcdsaSigningLane,
    Record<string, unknown>
  >;
  transactionOperation: PreparedTransactionOperation<SelectedEcdsaLane>;
  identity?: never;
  candidate?: never;
  intent?: never;
};

/** Prepared from an auth-neutral material candidate: exact material is known,
 * nothing authorizes it yet. The carrier is the exact lane identity, which
 * names wallet, chain target and material activation and holds no
 * authorization at all. The operation is authorized by a step-up on the
 * capability's own factor and the grant is attached after confirmation. */
export type AuthorizationRequiredEvmFamilyEcdsaSigningSession = {
  kind: 'authorization_required';
  authMethod: WalletAuthAuthority['factor']['kind'];
  availableLanesGeneration: number;
  identity: ExactEcdsaSigningLaneIdentity;
  candidate: AuthorizationRequiredEcdsaLaneCandidate;
  intent: EvmFamilyEcdsaTransactionSigningIntent;
  accountAuth?: never;
  source?: never;
  selection?: never;
  signingLane?: never;
  preparedOperation?: never;
  transactionOperation?: never;
};

export type PreparedEvmFamilyEcdsaSigningSession =
  | AuthorizedEvmFamilyEcdsaSigningSession
  | AuthorizationRequiredEvmFamilyEcdsaSigningSession;

export type PrepareEvmFamilyEcdsaSigningDeps = EvmFamilyEcdsaSigningSelectionDeps & {
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

  // Material selection runs ahead of the reusable-session planner. The planner
  // is selected-lane-only, and a selected lane exists only where a reusable
  // Wallet Session already authorizes the material, so an auth-neutral
  // candidate must be recognized before it can reach one.
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
    candidateCount: ecdsaAvailableLaneCandidatesForTarget(candidateAvailableLanes, chainTarget)
      .length,
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
  const candidateAuthMethod = requireSingleConcreteAuthMethodForEcdsaTarget({
    availableLanes: candidateAvailableLanes,
    signingTarget: args.signingTarget,
  });
  const transactionIntent: EvmFamilyEcdsaTransactionSigningIntent =
    buildEvmFamilyTransactionSigningIntent({
      walletId,
      authSelectionPolicy: resolveEvmFamilyTransactionAuthSelectionPolicy({
        candidateAuthMethod,
      }),
      operationUsesNeeded: 1,
      signingTarget: args.signingTarget,
      ...(args.signingOperation.operationId
        ? { operationId: args.signingOperation.operationId }
        : {}),
    });
  const materialSelection = selectEvmFamilyEcdsaMaterialCandidate({
    intent: transactionIntent,
    availableLanes: candidateAvailableLanes,
  });
  emitSigningSessionFlowTrace('evm-family', {
    stage: 'ecdsa_prepare.material_candidate_selected',
    walletId,
    chain,
    chainTarget,
    primaryAuthMethod: materialSelection.ok
      ? laneCandidateAuthMethod(materialSelection.candidate)
      : candidateAuthMethod,
    selectionOk: materialSelection.ok,
    ...(materialSelection.ok
      ? {
          authorizationState: materialSelection.kind,
          selectedAvailableLane: summarizeEcdsaAvailableLane(
            materialSelection.availableLane as AvailableEcdsaSigningLane,
          ),
          selectedLaneCandidate: summarizeEcdsaLaneCandidate(materialSelection.candidate),
          ...(materialSelection.kind === 'authorized'
            ? { transactionLane: materialSelection.lane }
            : {}),
        }
      : { failure: materialSelection.failure }),
  });
  if (!materialSelection.ok) {
    const noMaterialDiagnostic = {
      stage: 'ecdsa_prepare.exact_material_candidate_missing',
      walletId,
      chain,
      chainTarget,
      targetKey: thresholdEcdsaChainTargetKey(chainTarget),
      primaryAuthMethod: candidateAuthMethod,
      candidateCount: laneReadDiagnostic.candidateCount,
      ecdsaTargets: candidateAvailableLanes.ecdsa.targets,
      selectedLanesByTarget: laneReadDiagnostic.selectedLanesByTarget,
      candidatesByTarget: laneReadDiagnostic.candidatesByTarget,
      selectionFailure: materialSelection.failure,
    };
    emitVisibleEcdsaLaneDiagnostic('[ECDSA_NO_LANE_DIAGNOSTIC]', noMaterialDiagnostic);
    emitSigningSessionFlowFailure('evm-family', noMaterialDiagnostic);
    throw new Error(
      `[SigningEngine][ecdsa] transaction signing requires exact ECDSA material for ${chain}`,
    );
  }
  if (materialSelection.kind === 'authorization_required') {
    const candidate = materialSelection.candidate;
    args.diagnostics.selection = {
      kind: 'authorization_required',
      authMethod: availableEcdsaSigningLaneAuthMethod(materialSelection.availableLane),
      candidate: summarizeEcdsaLaneCandidate(candidate),
    };
    return {
      kind: 'authorization_required',
      authMethod: availableEcdsaSigningLaneAuthMethod(materialSelection.availableLane),
      availableLanesGeneration: candidateAvailableLanes.generation,
      identity: exactEcdsaSigningLaneIdentity({
        signer: buildEvmFamilyEcdsaSignerBinding({
          walletId: candidate.walletId,
          chainTarget: candidate.chainTarget,
          keyHandle: candidate.keyHandle,
          key: candidate.key,
          materialActivation: candidate.materialActivation,
        }),
        auth: candidate.auth,
      }),
      candidate,
      intent: transactionIntent,
    };
  }
  const laneCandidate: AuthorizedEcdsaLaneCandidate = materialSelection.candidate;
  const transactionLane: SelectedEcdsaLane = materialSelection.lane;
  const preparedTransaction = await prepareTransactionSigningOperation({
    intent: transactionIntent,
    coordinator: args.signingSessionCoordinator,
    operation: args.signingOperation,
    forceFreshAuth: args.forceFreshAuth === true,
    missingWhenExpiresAtMissing: true,
    onPlannerTrace: (event) => emitSigningPlannerDecisionTrace('evm-family', event),
    lifecycleAdapter: {
      prepare: async () => {
        const selection = await resolveEvmFamilyEcdsaSigningSelection({
          deps: args.deps,
          walletId,
          chainTarget,
          senderSignatureAlgorithm: 'secp256k1',
          laneCandidate,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_prepare.material_selected',
          walletId,
          chain,
          chainTarget,
          selectionKind: selection.kind,
          authMethod: selection.committedLane.authority.factor.kind,
          lane: summarizeEvmFamilyEcdsaLane(selection.lane),
          diagnostics: selection.diagnostics,
        });
        const committedSelectionAuthMethod = selection.committedLane.authority.factor.kind;
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
        assertSelectionMatchesLaneCandidate({
          candidate: laneCandidate,
          selection,
        });
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
          transactionIntent,
          readiness: {
            readiness: readiness.readiness,
            expiresAtMs: readiness.expiresAtMs,
            remainingUses: readiness.remainingUses,
          },
          availableLanesGeneration: availableLanes.generation,
          metadata: {
            accountAuth: selection.accountAuth,
            authMethod: committedSelectionAuthMethod,
            source: selection.diagnostics.selectedLaneCandidate.source,
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
    kind: 'authorized',
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
