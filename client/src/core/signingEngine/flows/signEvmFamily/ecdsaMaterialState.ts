import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { EcdsaLaneCandidate, ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import {
  buildEcdsaSessionIdentity,
  buildEcdsaSigningKeyContext,
  type EcdsaSessionIdentity,
  type EcdsaSigningKeyContext,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import {
  deriveEvmFamilyKeyFingerprint,
  resolveReadyEvmFamilyEcdsaMaterial,
  type ReadyEvmFamilyEcdsaMaterial,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  type EvmFamilyEcdsaAuthMethod,
  type ResolvedEvmFamilyEcdsaSigningLane,
  summarizeEvmFamilyEcdsaKeyRef,
  summarizeEvmFamilyEcdsaSessionRecord,
} from './ecdsaLanes';

type EcdsaMaterialBase = {
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  identity: EcdsaSessionIdentity;
};

export type MissingEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'missing';
  hasRecord: boolean;
  hasKeyRef: boolean;
};

export type ReadyEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'ready_material';
  signingKeyContext: EcdsaSigningKeyContext;
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
};

export type EcdsaMaterialState = MissingEcdsaMaterial | ReadyEcdsaMaterial;

export type EcdsaMaterialSummary = {
  present: boolean;
  kind: EcdsaMaterialState['kind'];
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  evmFamilyKeyFingerprint?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  ecdsaThresholdKeyId?: string;
  hasRecord: boolean;
  hasKeyRef: boolean;
};

export type BuildEcdsaMaterialStateForCandidateArgs = {
  candidate: EcdsaLaneCandidate;
  record: ThresholdEcdsaSessionRecord | undefined;
  keyRef: ThresholdEcdsaSecp256k1KeyRef | undefined;
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
  const identity = buildEcdsaSessionIdentity({
    thresholdSessionId: args.candidate.thresholdSessionId,
    walletSigningSessionId: args.candidate.walletSigningSessionId,
  });
  const base = {
    authMethod: args.authMethod,
    source: args.source,
    chainTarget: args.chainTarget,
    identity,
  } as const;

  const readyResolution = resolveReadyEvmFamilyEcdsaMaterial({
    record: args.record || null,
    keyRef: args.keyRef || null,
    rpId: args.candidate.key.rpId,
    expected: {
      walletId: args.candidate.walletId,
      subjectId: args.candidate.key.subjectId,
      chainTarget: args.materialChainTarget,
      authMethod: args.authMethod,
      source: args.source,
      thresholdSessionId: identity.thresholdSessionId,
      walletSigningSessionId: identity.walletSigningSessionId,
    },
  });
  if (readyResolution.kind === 'ready') {
    const signingKeyContext = buildEcdsaSigningKeyContext({
      record: readyResolution.material.record,
      keyRef: readyResolution.material.keyRef,
    });
    return {
      ...base,
      kind: 'ready_material',
      signingKeyContext,
      readyMaterial: readyResolution.material,
      record: readyResolution.material.record,
      keyRef: readyResolution.material.keyRef,
    };
  }
  return {
    ...base,
    kind: 'missing',
    hasRecord: Boolean(args.record),
    hasKeyRef: Boolean(args.keyRef),
  };
}

export function buildEcdsaMaterialStateForResolvedLane(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): EcdsaMaterialState {
  return buildEcdsaMaterialStateForCandidate({
    candidate: {
      kind: 'lane_candidate',
      walletId: args.lane.walletId,
      key: args.lane.key,
      authMethod: args.authMethod,
      curve: 'ecdsa',
      chain: args.lane.chainFamily,
      walletSigningSessionId: String(args.lane.walletSigningSessionId),
      thresholdSessionId: String(args.lane.thresholdSessionId),
      state: 'ready',
      remainingUses: null,
      expiresAtMs: null,
      updatedAtMs: null,
      source: 'runtime_session_record',
      chainTarget: args.lane.chainTarget,
    },
    record: args.record,
    keyRef: args.keyRef,
    authMethod: args.authMethod,
    source: args.source,
    chainTarget: args.lane.chainTarget,
    materialChainTarget: args.lane.chainTarget,
  });
}

export function requireReadyEcdsaMaterial(
  state: EcdsaMaterialState,
  context: string,
): ReadyEcdsaMaterial {
  if (state.kind === 'ready_material') return state;
  throw new Error(
    `[SigningEngine][ecdsa] ${context} requires ready ECDSA material, got ${state.kind}`,
  );
}

export function requireReadyEcdsaMaterialForResolvedLane(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
  context: string;
}): ReadyEcdsaMaterial {
  return requireReadyEcdsaMaterial(
    buildEcdsaMaterialStateForResolvedLane({
      lane: args.lane,
      authMethod: args.authMethod,
      source: args.source,
      record: args.record,
      keyRef: args.keyRef,
    }),
    args.context,
  );
}

export function summarizeEcdsaMaterialState(state: EcdsaMaterialState): EcdsaMaterialSummary {
  const evmFamilyKeyFingerprint =
    state.kind === 'ready_material'
      ? deriveEvmFamilyKeyFingerprint(state.readyMaterial.key)
      : undefined;
  return {
    present: state.kind !== 'missing',
    kind: state.kind,
    authMethod: state.authMethod,
    source: state.source,
    chainTarget: state.chainTarget,
    thresholdSessionId: state.identity.thresholdSessionId,
    walletSigningSessionId: state.identity.walletSigningSessionId,
    ...(evmFamilyKeyFingerprint ? { evmFamilyKeyFingerprint } : {}),
    signingRootId: state.kind === 'missing' ? undefined : state.signingKeyContext.signingRootId,
    signingRootVersion:
      state.kind === 'missing' ? undefined : state.signingKeyContext.signingRootVersion,
    ecdsaThresholdKeyId:
      state.kind === 'missing' ? undefined : state.signingKeyContext.ecdsaThresholdKeyId,
    hasRecord: state.kind === 'ready_material' ? true : state.hasRecord,
    hasKeyRef: state.kind === 'ready_material' ? true : state.hasKeyRef,
  };
}

export function summarizeVisibleEcdsaMaterial(args: {
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  materialChainTarget: ThresholdEcdsaChainTarget;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): EcdsaMaterialSummary | { present: false } {
  const record = args.record;
  const keyRef = args.keyRef;
  if (!record || !keyRef) return { present: false };
  const identity = buildEcdsaSessionIdentity({
    thresholdSessionId: record.thresholdSessionId,
    walletSigningSessionId: record.walletSigningSessionId,
  });
  const readyResolution = resolveReadyEvmFamilyEcdsaMaterial({
    record,
    keyRef,
    rpId: record.rpId,
    expected: {
      walletId: record.walletId,
      subjectId: record.subjectId,
      chainTarget: args.materialChainTarget,
      authMethod: args.authMethod,
      source: args.source,
      thresholdSessionId: identity.thresholdSessionId,
      walletSigningSessionId: identity.walletSigningSessionId,
    },
  });
  if (readyResolution.kind !== 'ready') return { present: false };
  const readyMaterial = readyResolution.material;
  const signingKeyContext = buildEcdsaSigningKeyContext({
    record: readyMaterial.record,
    keyRef: readyMaterial.keyRef,
  });
  return {
    present: true,
    kind: 'ready_material',
    authMethod: args.authMethod,
    source: args.source,
    chainTarget: args.chainTarget,
    thresholdSessionId: identity.thresholdSessionId,
    walletSigningSessionId: identity.walletSigningSessionId,
    evmFamilyKeyFingerprint: deriveEvmFamilyKeyFingerprint(readyMaterial.key),
    signingRootId: signingKeyContext.signingRootId,
    signingRootVersion: signingKeyContext.signingRootVersion,
    ecdsaThresholdKeyId: signingKeyContext.ecdsaThresholdKeyId,
    hasRecord: true,
    hasKeyRef: true,
  };
}

export function getEcdsaMaterialRecord(
  state: EcdsaMaterialState,
): ThresholdEcdsaSessionRecord | undefined {
  switch (state.kind) {
    case 'missing':
      return undefined;
    case 'ready_material':
      return state.record;
  }
}

export function getEcdsaMaterialKeyRef(
  state: EcdsaMaterialState,
): ThresholdEcdsaSecp256k1KeyRef | undefined {
  switch (state.kind) {
    case 'missing':
      return undefined;
    case 'ready_material':
      return state.keyRef;
  }
}

export function summarizeReadyEcdsaMaterialForDiagnostics(
  state: ReadyEcdsaMaterial | undefined,
): Record<string, unknown> {
  if (!state) return { present: false };
  return {
    material: summarizeEcdsaMaterialState(state),
    record: summarizeEvmFamilyEcdsaSessionRecord(state.record),
    keyRef: summarizeEvmFamilyEcdsaKeyRef(state.keyRef),
  };
}

export function materialIdentityMatchesResolvedLane(args: {
  state: ReadyEcdsaMaterial;
  lane: ResolvedEvmFamilyEcdsaSigningLane;
}): boolean {
  return (
    String(args.lane.thresholdSessionId) === args.state.identity.thresholdSessionId &&
    String(args.lane.walletSigningSessionId) === args.state.identity.walletSigningSessionId &&
    String(args.lane.signingRootId) === args.state.signingKeyContext.signingRootId &&
    String(args.lane.signingRootVersion) === args.state.signingKeyContext.signingRootVersion &&
    String(args.lane.ecdsaThresholdKeyId) === args.state.signingKeyContext.ecdsaThresholdKeyId &&
    thresholdEcdsaChainTargetsEqual(args.lane.chainTarget, args.state.chainTarget)
  );
}
