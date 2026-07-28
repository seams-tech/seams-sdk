import type {
  EcdsaLaneCandidate,
  ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import type { EcdsaSigningKeyContext } from '../../session/warmCapabilities/ecdsaProvisionPlan';
import {
  deriveEvmFamilyKeyFingerprintFromRecordPublicFacts,
  type ReadyEcdsaSignerSession,
  type ReadyEvmFamilyEcdsaMaterial,
  type VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import { requireEvmFamilyEcdsaSigner } from '../../session/identity/exactSigningLaneIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import { classifyThresholdEcdsaSessionRecordRoleLocalState } from '../../session/persistence/ecdsaRoleLocalRecords';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaSessionRecord,
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

export type PublicIdentityAvailableEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'public_identity_available';
  publicFacts: VerifiedEcdsaPublicFacts;
  record: ThresholdEcdsaSessionRecord;
  keyRef?: never;
  signerSession?: never;
};

export type ReauthRequiredEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'reauth_required';
  publicFacts: VerifiedEcdsaPublicFacts;
  record: ThresholdEcdsaSessionRecord;
  keyRef?: never;
  reason: 'missing_worker_share' | 'missing_inline_share' | 'expired' | 'exhausted';
  signerSession?: never;
};

export type ReadyEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'ready_to_sign';
  publicFacts: VerifiedEcdsaPublicFacts;
  signingKeyContext: EcdsaSigningKeyContext;
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
  signerSession: ReadyEcdsaSignerSession;
  sharedKeyState: EvmFamilySharedEcdsaReadyState;
  record: ThresholdEcdsaSessionRecord;
  keyRef?: never;
};

export type EcdsaMaterialState =
  | MissingEcdsaMaterial
  | PublicIdentityAvailableEcdsaMaterial
  | ReauthRequiredEcdsaMaterial
  | ReadyEcdsaMaterial;

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
  const evmFamilyKeyFingerprint =
    state.kind === 'ready_to_sign'
      ? safeDeriveRecordPublicFactsFingerprint({
          walletId: state.readyMaterial.key.walletId,
          record: state.readyMaterial.record,
        })
      : state.kind === 'public_identity_available' || state.kind === 'reauth_required'
        ? safeDeriveRecordPublicFactsFingerprint({
            walletId: state.record.walletId,
            record: state.record,
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

function safeDeriveRecordPublicFactsFingerprint(args: {
  walletId: string;
  record: ThresholdEcdsaSessionRecord;
}): string | undefined {
  try {
    return deriveEvmFamilyKeyFingerprintFromRecordPublicFacts({
      walletId: args.walletId,
      record: args.record,
    });
  } catch {
    return undefined;
  }
}

export function getEcdsaMaterialRecord(
  state: EcdsaMaterialState,
): ThresholdEcdsaSessionRecord | undefined {
  switch (state.kind) {
    case 'public_identity_unavailable':
      return undefined;
    case 'public_identity_available':
    case 'reauth_required':
    case 'ready_to_sign':
      return state.record;
  }
}

export function resolveEmailOtpEcdsaReadinessSource(args: {
  record: ThresholdEcdsaSessionRecord;
  nowMs: number;
}): EmailOtpEcdsaReadinessSource {
  const roleLocalState = classifyThresholdEcdsaSessionRecordRoleLocalState({
    record: args.record,
    nowMs: args.nowMs,
  });
  if (roleLocalState.kind !== 'ready_email_otp_role_local_material_v1') {
    return { kind: 'unavailable' };
  }
  return {
    kind: 'persisted_record_policy',
    expiresAtMs: Math.floor(Number(args.record.expiresAtMs) || 0),
    remainingUses: Math.floor(Number(args.record.remainingUses) || 0),
  };
}

export function summarizeReadyEcdsaMaterialForDiagnostics(
  state: ReadyEcdsaMaterial | undefined,
): Record<string, unknown> {
  if (!state) return { present: false };
  return {
    material: summarizeEcdsaMaterialState(state),
    record: summarizeEvmFamilyEcdsaSessionRecord(state.record),
  };
}

export function materialIdentityMatchesResolvedLane(args: {
  state: ReadyEcdsaMaterial;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
}): boolean {
  const materialKeyHandle = String(args.state.record.keyHandle || '').trim();
  const signer = requireEvmFamilyEcdsaSigner(
    args.lane.identity,
    'ECDSA material identity comparison',
  );
  const laneKeyHandle = String(signer.keyHandle || '').trim();
  return (
    args.lane.authorization.projection.walletSessionId ===
      args.state.authorization.projection.walletSessionId &&
    materialKeyHandle === laneKeyHandle &&
    String(args.state.record.keyHandle || '').trim() === laneKeyHandle &&
    thresholdEcdsaChainTargetsEqual(signer.chainTarget, args.state.chainTarget)
  );
}
