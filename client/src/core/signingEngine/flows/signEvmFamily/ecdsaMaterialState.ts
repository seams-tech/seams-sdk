import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type { EcdsaLaneCandidate, ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import {
  buildEcdsaSessionIdentity,
  buildEcdsaSigningKeyContext,
  ecdsaSessionIdentityMatches,
  type EcdsaSessionIdentity,
  type EcdsaSigningKeyContext,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type { ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  isEmailOtpThresholdEcdsaSigningContext,
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
};

export type RecordOnlyEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'record_only';
  signingKeyContext: EcdsaSigningKeyContext;
  record: ThresholdEcdsaSessionRecord;
};

export type KeyRefOnlyEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'key_ref_only';
  signingKeyContext: EcdsaSigningKeyContext;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
};

export type ReadyEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'ready_material';
  signingKeyContext: EcdsaSigningKeyContext;
  record: ThresholdEcdsaSessionRecord;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
};

export type EcdsaMaterialState =
  | MissingEcdsaMaterial
  | RecordOnlyEcdsaMaterial
  | KeyRefOnlyEcdsaMaterial
  | ReadyEcdsaMaterial;

export type EcdsaMaterialSummary = {
  present: boolean;
  kind: EcdsaMaterialState['kind'];
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  walletSigningSessionId: string;
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
};

function matchesCandidateIdentity(args: {
  candidate: EcdsaLaneCandidate;
  value: ThresholdEcdsaSessionRecord | ThresholdEcdsaSecp256k1KeyRef;
}): boolean {
  const candidateIdentity = buildEcdsaSessionIdentity({
    thresholdSessionId: args.candidate.thresholdSessionId,
    walletSigningSessionId: args.candidate.walletSigningSessionId,
  });
  return (
    String(args.value.subjectId || '').trim() === String(args.candidate.subjectId || '').trim() &&
    thresholdEcdsaChainTargetsEqual(args.value.chainTarget, args.candidate.chainTarget) &&
    String(args.value.ecdsaThresholdKeyId || '').trim() ===
      String(args.candidate.ecdsaThresholdKeyId || '').trim() &&
    String(args.value.signingRootId || '').trim() === String(args.candidate.signingRootId || '').trim() &&
    String(args.value.signingRootVersion || 'default').trim() ===
      String(args.candidate.signingRootVersion || '').trim() &&
    ecdsaSessionIdentityMatches(candidateIdentity, args.value)
  );
}

function matchesExpectedAuthMethod(args: {
  authMethod: EvmFamilyEcdsaAuthMethod;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): boolean {
  const isEmailOtpContext = isEmailOtpThresholdEcdsaSigningContext({
    ...(args.record ? { record: args.record } : {}),
    ...(args.keyRef ? { keyRef: args.keyRef } : {}),
  });
  return args.authMethod === SIGNER_AUTH_METHODS.emailOtp ? isEmailOtpContext : !isEmailOtpContext;
}

function participantIdsMatch(
  record: ThresholdEcdsaSessionRecord | undefined,
  keyRef: ThresholdEcdsaSecp256k1KeyRef | undefined,
): boolean {
  if (!record?.participantIds?.length || !keyRef?.participantIds?.length) return true;
  const left = record.participantIds.map((value) => Number(value)).join(',');
  const right = keyRef.participantIds.map((value) => Number(value)).join(',');
  return left === right;
}

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

  const record =
    args.record &&
    matchesCandidateIdentity({ candidate: args.candidate, value: args.record }) &&
    matchesExpectedAuthMethod({ authMethod: args.authMethod, record: args.record })
      ? args.record
      : undefined;
  const keyRef =
    args.keyRef &&
    matchesCandidateIdentity({ candidate: args.candidate, value: args.keyRef }) &&
    matchesExpectedAuthMethod({ authMethod: args.authMethod, keyRef: args.keyRef })
      ? args.keyRef
      : undefined;

  if (record && keyRef) {
    if (!participantIdsMatch(record, keyRef)) {
      throw new Error(
        '[SigningEngine][ecdsa] exact ECDSA material has mismatched participant identities',
      );
    }
    const signingKeyContext = buildEcdsaSigningKeyContext({ record, keyRef });
    return {
      ...base,
      kind: 'ready_material',
      signingKeyContext,
      record,
      keyRef,
    };
  }
  if (record) {
    return {
      ...base,
      kind: 'record_only',
      signingKeyContext: buildEcdsaSigningKeyContext({ record }),
      record,
    };
  }
  if (keyRef) {
    return {
      ...base,
      kind: 'key_ref_only',
      signingKeyContext: buildEcdsaSigningKeyContext({ keyRef }),
      keyRef,
    };
  }
  return {
    ...base,
    kind: 'missing',
  };
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

export function summarizeEcdsaMaterialState(state: EcdsaMaterialState): EcdsaMaterialSummary {
  const record = getEcdsaMaterialRecord(state);
  const keyRef = getEcdsaMaterialKeyRef(state);
  return {
    present: state.kind !== 'missing',
    kind: state.kind,
    authMethod: state.authMethod,
    source: state.source,
    chainTarget: state.chainTarget,
    thresholdSessionId: state.identity.thresholdSessionId,
    walletSigningSessionId: state.identity.walletSigningSessionId,
    signingRootId: state.kind === 'missing' ? undefined : state.signingKeyContext.signingRootId,
    signingRootVersion:
      state.kind === 'missing' ? undefined : state.signingKeyContext.signingRootVersion,
    ecdsaThresholdKeyId:
      state.kind === 'missing' ? undefined : state.signingKeyContext.ecdsaThresholdKeyId,
    hasRecord: Boolean(record),
    hasKeyRef: Boolean(keyRef),
  };
}

export function summarizeVisibleEcdsaMaterial(args: {
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  record?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): EcdsaMaterialSummary | { present: false } {
  const record = args.record;
  const keyRef = args.keyRef;
  if (!record && !keyRef) return { present: false };
  const identity = buildEcdsaSessionIdentity({
    thresholdSessionId: record?.thresholdSessionId || keyRef?.thresholdSessionId,
    walletSigningSessionId: record?.walletSigningSessionId || keyRef?.walletSigningSessionId,
  });
  return {
    present: true,
    kind: record && keyRef ? 'ready_material' : record ? 'record_only' : 'key_ref_only',
    authMethod: args.authMethod,
    source: args.source,
    chainTarget: args.chainTarget,
    thresholdSessionId: identity.thresholdSessionId,
    walletSigningSessionId: identity.walletSigningSessionId,
    signingRootId: String(record?.signingRootId || keyRef?.signingRootId || '').trim() || undefined,
    signingRootVersion:
      String(record?.signingRootVersion || keyRef?.signingRootVersion || '').trim() || undefined,
    ecdsaThresholdKeyId:
      String(record?.ecdsaThresholdKeyId || keyRef?.ecdsaThresholdKeyId || '').trim() || undefined,
    hasRecord: Boolean(record),
    hasKeyRef: Boolean(keyRef),
  };
}

export function getEcdsaMaterialRecord(
  state: EcdsaMaterialState,
): ThresholdEcdsaSessionRecord | undefined {
  switch (state.kind) {
    case 'missing':
    case 'key_ref_only':
      return undefined;
    case 'record_only':
    case 'ready_material':
      return state.record;
  }
}

export function getEcdsaMaterialKeyRef(
  state: EcdsaMaterialState,
): ThresholdEcdsaSecp256k1KeyRef | undefined {
  switch (state.kind) {
    case 'missing':
    case 'record_only':
      return undefined;
    case 'key_ref_only':
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
