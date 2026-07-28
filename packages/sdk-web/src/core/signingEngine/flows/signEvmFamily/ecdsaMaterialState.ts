import type {
  EcdsaLaneCandidate,
  ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import type { EcdsaSigningKeyContext } from '../../session/warmCapabilities/ecdsaProvisionPlan';
import {
  deriveEvmFamilyKeyFingerprintFromPublicFacts,
  type ReadyEcdsaSignerSession,
  type ReadyEvmFamilyEcdsaMaterial,
  type VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import { requireEvmFamilyEcdsaSigner } from '../../session/identity/exactSigningLaneIdentity';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';

type EcdsaMaterialBase = {
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  materialActivation: EcdsaLaneCandidate['materialActivation'];
  authorization: EcdsaLaneCandidate['authorization'];
};

export type PositiveSignatureUses = number & { readonly __brand: 'PositiveSignatureUses' };
export type FutureEpochMs = number & { readonly __brand: 'FutureEpochMs' };

export type EvmFamilySharedEcdsaSignerMaterial =
  | {
      kind: 'worker_handle';
      workerSessionId: string;
      sourceChainTarget?: never;
    }
  | {
      kind: 'source_chain_material';
      sourceChainTarget: ThresholdEcdsaChainTarget;
      workerSessionId?: never;
    };

export type EvmFamilySharedEcdsaReadyState = {
  kind: 'ready_to_sign';
  walletId: string;
  authMethod: EvmFamilyEcdsaAuthMethod;
  sourceChainTarget: ThresholdEcdsaChainTarget;
  publishedTargets: readonly ThresholdEcdsaChainTarget[];
  sharedPublicFacts: VerifiedEcdsaPublicFacts;
  walletSessionId: EcdsaLaneCandidate['authorization']['projection']['walletSessionId'];
  remainingSignatureUses: PositiveSignatureUses;
  expiresAtMs: FutureEpochMs;
  signerMaterial: EvmFamilySharedEcdsaSignerMaterial;
  restore?: never;
};

export type EmailOtpEcdsaReadinessSource =
  | {
      kind: 'persisted_record_policy';
      expiresAtMs: number;
      remainingUses: number;
    }
  | {
      kind: 'unavailable';
      expiresAtMs?: never;
      remainingUses?: never;
    };

export type MissingEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'public_identity_unavailable';
  record?: never;
  keyRef?: never;
  publicFacts?: never;
  signerSession?: never;
};

export type ReadyEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'ready_to_sign';
  publicFacts: VerifiedEcdsaPublicFacts;
  signingKeyContext: EcdsaSigningKeyContext;
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
  signerSession: ReadyEcdsaSignerSession;
  sharedKeyState: EvmFamilySharedEcdsaReadyState;
  keyRef?: never;
};

// Only absence and readiness remain. The intermediate record-carrying states
// described a composite record that has no writer, so nothing could construct
// them; public identity now travels with the manifest and sealed runtime.
export type EcdsaMaterialState = MissingEcdsaMaterial | ReadyEcdsaMaterial;

export type EcdsaMaterialSummary = {
  present: boolean;
  kind: EcdsaMaterialState['kind'];
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  walletSessionId: string;
  materialActivationId: string;
  evmFamilyKeyFingerprint?: string;
  publicIdentityPresent: boolean;
  signerMaterialPresent: boolean;
};

export type BuildEcdsaMaterialStateForCandidateArgs = {
  candidate: EcdsaLaneCandidate;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  materialChainTarget: ThresholdEcdsaChainTarget;
};

export function buildEcdsaMaterialStateForCandidate(
  args: BuildEcdsaMaterialStateForCandidateArgs,
): EcdsaMaterialState {
  if (!thresholdEcdsaChainTargetsEqual(args.chainTarget, args.candidate.chainTarget)) {
    throw new Error(
      '[SigningEngine][ecdsa] material-state builder chain target must match candidate chain target',
    );
  }
  // Canonical material is not resolved here: the composite record that used to
  // carry public facts and signer material has no writer, so the exact material
  // for this candidate is always unresolved and resolution fails closed. Lane
  // identity, material activation, and authorization stay on the state so the
  // canonical hydration boundary can bind them.
  return {
    authMethod: args.authMethod,
    source: args.source,
    chainTarget: args.chainTarget,
    materialActivation: args.candidate.materialActivation,
    authorization: args.candidate.authorization,
    kind: 'public_identity_unavailable',
  };
}

export function requireReadyEcdsaMaterial(
  state: EcdsaMaterialState,
  context: string,
): ReadyEcdsaMaterial {
  if (state.kind === 'ready_to_sign') return state;
  throw new Error(
    `[SigningEngine][ecdsa] ${context} requires ready ECDSA material, got ${state.kind}`,
  );
}

export function summarizeEcdsaMaterialState(state: EcdsaMaterialState): EcdsaMaterialSummary {
  // The signer session carries the verified public facts directly, so the
  // fingerprint no longer has to be reconstructed from a record.
  const evmFamilyKeyFingerprint =
    state.kind === 'ready_to_sign'
      ? safePublicFactsFingerprint({
          walletId: state.signerSession.walletId,
          publicFacts: state.signerSession.publicFacts,
        })
      : undefined;
  const publicIdentityPresent = state.kind !== 'public_identity_unavailable';
  const signerMaterialPresent = state.kind === 'ready_to_sign';
  return {
    present: publicIdentityPresent,
    kind: state.kind,
    authMethod: state.authMethod,
    source: state.source,
    chainTarget: state.chainTarget,
    walletSessionId: state.authorization.projection.walletSessionId,
    materialActivationId: state.materialActivation.activationId,
    ...(evmFamilyKeyFingerprint ? { evmFamilyKeyFingerprint } : {}),
    publicIdentityPresent,
    signerMaterialPresent,
  };
}

function safePublicFactsFingerprint(args: {
  walletId: ReadyEcdsaSignerSession['walletId'];
  publicFacts: VerifiedEcdsaPublicFacts;
}): string | undefined {
  try {
    return deriveEvmFamilyKeyFingerprintFromPublicFacts({
      walletId: args.walletId,
      publicFacts: args.publicFacts,
    });
  } catch {
    return undefined;
  }
}

export function summarizeReadyEcdsaMaterialForDiagnostics(
  state: ReadyEcdsaMaterial | undefined,
): Record<string, unknown> {
  if (!state) return { present: false };
  return { material: summarizeEcdsaMaterialState(state) };
}

export function materialIdentityMatchesResolvedLane(args: {
  state: ReadyEcdsaMaterial;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
}): boolean {
  // Key handle comes from the signer session's verified public facts; the
  // material activation is the identity that actually names the material.
  const materialKeyHandle = String(args.state.signerSession.publicFacts.keyHandle || '').trim();
  const signer = requireEvmFamilyEcdsaSigner(
    args.lane.identity,
    'ECDSA material identity comparison',
  );
  const laneKeyHandle = String(signer.keyHandle || '').trim();
  return (
    args.lane.authorization.projection.walletSessionId ===
      args.state.authorization.projection.walletSessionId &&
    Boolean(materialKeyHandle) &&
    materialKeyHandle === laneKeyHandle &&
    String(signer.materialActivation.activationId) ===
      String(args.state.materialActivation.activationId) &&
    thresholdEcdsaChainTargetsEqual(signer.chainTarget, args.state.chainTarget)
  );
}
