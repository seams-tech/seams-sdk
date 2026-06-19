import type {
  EcdsaLaneCandidate,
  ThresholdEcdsaSessionStoreSource,
} from '../../session/identity/laneIdentity';
import {
  buildEcdsaSessionIdentity,
  type EcdsaSessionIdentity,
  type EcdsaSigningKeyContext,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import {
  buildReadyEcdsaSignerSessionFromReadyMaterial,
  buildVerifiedEcdsaPublicFacts,
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  deriveEvmFamilyKeyFingerprintFromRecordPublicFacts,
  resolveReadyEvmFamilyEcdsaMaterial,
  type ReadyEcdsaSignerSession,
  type ReadyEvmFamilyEcdsaMaterial,
  type VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  thresholdEcdsaRecordRpId,
  type ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import {
  classifyThresholdEcdsaSessionRecordRoleLocalState,
} from '../../session/persistence/ecdsaRoleLocalRecords';
import {
  thresholdEcdsaChainTargetKey,
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
  identity: EcdsaSessionIdentity;
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

export type EvmFamilySharedEcdsaUnavailableState = {
  kind: 'unavailable';
  reason: 'missing_record' | 'invalid_record' | 'unsupported_target';
  walletId: string;
  requestChainTarget: ThresholdEcdsaChainTarget;
  sourceChainTarget?: never;
  publishedTargets?: never;
  sharedPublicFacts?: never;
  signingGrantId?: never;
  thresholdSessionId?: never;
  signerMaterial?: never;
};

export type EvmFamilySharedEcdsaPublicIdentityOnlyState = {
  kind: 'public_identity_only';
  walletId: string;
  authMethod: EvmFamilyEcdsaAuthMethod;
  sourceChainTarget: ThresholdEcdsaChainTarget;
  publishedTargets: readonly ThresholdEcdsaChainTarget[];
  sharedPublicFacts: VerifiedEcdsaPublicFacts;
  signingGrantId?: never;
  thresholdSessionId?: never;
  signerMaterial?: never;
};

export type EvmFamilySharedEcdsaRestorableState = {
  kind: 'restorable';
  walletId: string;
  authMethod: EvmFamilyEcdsaAuthMethod;
  sourceChainTarget: ThresholdEcdsaChainTarget;
  publishedTargets: readonly ThresholdEcdsaChainTarget[];
  sharedPublicFacts: VerifiedEcdsaPublicFacts;
  signingGrantId: EcdsaSessionIdentity['signingGrantId'];
  thresholdSessionId: EcdsaSessionIdentity['thresholdSessionId'];
  restore:
    | { kind: 'email_otp_worker'; workerSessionId: string; credentialIdB64u?: never }
    | { kind: 'passkey_seal'; credentialIdB64u: string; workerSessionId?: never };
  signerMaterial?: never;
};

export type EvmFamilySharedEcdsaReadyState = {
  kind: 'ready_to_sign';
  walletId: string;
  authMethod: EvmFamilyEcdsaAuthMethod;
  sourceChainTarget: ThresholdEcdsaChainTarget;
  publishedTargets: readonly ThresholdEcdsaChainTarget[];
  sharedPublicFacts: VerifiedEcdsaPublicFacts;
  signingGrantId: EcdsaSessionIdentity['signingGrantId'];
  thresholdSessionId: EcdsaSessionIdentity['thresholdSessionId'];
  remainingSignatureUses: PositiveSignatureUses;
  expiresAtMs: FutureEpochMs;
  signerMaterial: EvmFamilySharedEcdsaSignerMaterial;
  restore?: never;
};

export type EvmFamilySharedEcdsaExportReadyState = {
  kind: 'ready_for_export';
  walletId: string;
  authMethod: EvmFamilyEcdsaAuthMethod;
  sourceChainTarget: ThresholdEcdsaChainTarget;
  publishedTargets: readonly ThresholdEcdsaChainTarget[];
  sharedPublicFacts: VerifiedEcdsaPublicFacts;
  signingGrantId: EcdsaSessionIdentity['signingGrantId'];
  thresholdSessionId: EcdsaSessionIdentity['thresholdSessionId'];
  exportMaterial: { kind: 'canonical_export_artifact'; artifactPresent: true };
  signerMaterial?: never;
  restore?: never;
};

export type EvmFamilySharedEcdsaState =
  | EvmFamilySharedEcdsaUnavailableState
  | EvmFamilySharedEcdsaPublicIdentityOnlyState
  | EvmFamilySharedEcdsaRestorableState
  | EvmFamilySharedEcdsaReadyState
  | EvmFamilySharedEcdsaExportReadyState;

export type EmailOtpEcdsaReadinessSource =
  | {
      kind: 'persisted_record_policy';
      expiresAtMs: number;
      remainingUses: number;
      workerSessionId?: never;
    }
  | {
      kind: 'worker_session_status';
      workerSessionId: string;
      expiresAtMs?: never;
      remainingUses?: never;
    }
  | {
      kind: 'unavailable';
      workerSessionId?: never;
      expiresAtMs?: never;
      remainingUses?: never;
    };

export type TargetSpecificEvmFamilyEcdsaLaneState = {
  kind: 'target_specific_evm_family_ecdsa_lane_state';
  targetChainTarget: ThresholdEcdsaChainTarget;
  sharedKeyState: EvmFamilySharedEcdsaReadyState;
};

export type MissingEcdsaMaterial = EcdsaMaterialBase & {
  kind: 'public_identity_unavailable';
  hasRecord: boolean;
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
  thresholdSessionId: string;
  signingGrantId: string;
  evmFamilyKeyFingerprint?: string;
  hasRecord: boolean;
  publicIdentityPresent: boolean;
  signerMaterialPresent: boolean;
};

export type BuildEcdsaMaterialStateForCandidateArgs = {
  candidate: EcdsaLaneCandidate;
  record: ThresholdEcdsaSessionRecord | undefined;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  materialChainTarget: ThresholdEcdsaChainTarget;
};

export type ResolvedEcdsaMaterialInput =
  | {
      kind: 'resolved_ecdsa_session_record';
      record: ThresholdEcdsaSessionRecord;
    }
  | {
      kind: 'resolved_ecdsa_material_missing';
      record?: never;
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
    signingGrantId: args.candidate.signingGrantId,
  });
  const base = {
    authMethod: args.authMethod,
    source: args.source,
    chainTarget: args.chainTarget,
    identity,
  } as const;
  const publicFacts = args.record
    ? tryBuildVerifiedPublicFactsFromRecord({
        record: args.record,
      })
    : null;

  const readyResolution = resolveReadyEvmFamilyEcdsaMaterial({
    record: args.record || null,
    rpId: args.candidate.key.rpId,
    expected: {
      walletId: args.candidate.walletId,
      chainTarget: args.materialChainTarget,
      authMethod: args.authMethod,
      source: args.source,
      thresholdSessionId: identity.thresholdSessionId,
      signingGrantId: identity.signingGrantId,
    },
  });
  if (readyResolution.kind === 'ready') {
    if (!publicFacts) {
      return {
        ...base,
        kind: 'public_identity_unavailable',
        hasRecord: Boolean(args.record),
      };
    }
    const signerSession = buildReadyEcdsaSignerSessionFromReadyMaterial({
      material: readyResolution.material,
      publicFacts,
    });
    return {
      ...base,
      kind: 'ready_to_sign',
      publicFacts,
      signingKeyContext: readyResolution.material.signingKeyContext,
      readyMaterial: readyResolution.material,
      signerSession,
      sharedKeyState: buildReadySharedEcdsaState({
        authMethod: args.authMethod,
        chainTarget: args.chainTarget,
        sourceChainTarget: args.materialChainTarget,
        publicFacts,
        material: readyResolution.material,
        signerSession,
      }),
      record: readyResolution.material.record,
    };
  }
  if (args.record && publicFacts) {
    const reauthReason = reauthReasonFromMaterialResolution({
      reason: readyResolution.reason,
      record: args.record,
    });
    if (reauthReason) {
      return {
        ...base,
        kind: 'reauth_required',
        publicFacts,
        record: args.record,
        reason: reauthReason,
      };
    }
    return {
      ...base,
      kind: 'public_identity_available',
      publicFacts,
      record: args.record,
    };
  }
  return {
    ...base,
    kind: 'public_identity_unavailable',
    hasRecord: Boolean(args.record),
  };
}

export function buildEcdsaMaterialStateForResolvedLane(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  material: ResolvedEcdsaMaterialInput;
}): EcdsaMaterialState {
  const record =
    args.material.kind === 'resolved_ecdsa_session_record' ? args.material.record : undefined;
  return buildEcdsaMaterialStateForCandidate({
    candidate: {
      kind: 'lane_candidate',
      walletId: args.lane.walletId,
      key: args.lane.key,
      keyHandle: args.lane.keyHandle,
      authMethod: args.authMethod,
      curve: 'ecdsa',
      chain: args.lane.chainFamily,
      signingGrantId: String(args.lane.signingGrantId),
      thresholdSessionId: String(args.lane.thresholdSessionId),
      state: 'ready',
      remainingUses: null,
      expiresAtMs: null,
      updatedAtMs: null,
      source: 'runtime_session_record',
      chainTarget: args.lane.chainTarget,
    },
    record,
    authMethod: args.authMethod,
    source: args.source,
    chainTarget: args.lane.chainTarget,
    materialChainTarget: args.lane.chainTarget,
  });
}

export function resolvedEcdsaMaterialInputFromOptionalRecord(args: {
  record: ThresholdEcdsaSessionRecord | undefined;
  context: string;
}): ResolvedEcdsaMaterialInput {
  if (args.record) {
    return {
      kind: 'resolved_ecdsa_session_record',
      record: args.record,
    };
  }
  return { kind: 'resolved_ecdsa_material_missing' };
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

export function requireReadyEcdsaMaterialForResolvedLane(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  record: ThresholdEcdsaSessionRecord;
  context: string;
}): ReadyEcdsaMaterial {
  return requireReadyEcdsaMaterial(
    buildEcdsaMaterialStateForResolvedLane({
      lane: args.lane,
      authMethod: args.authMethod,
      source: args.source,
      material: {
        kind: 'resolved_ecdsa_session_record',
        record: args.record,
      },
    }),
    args.context,
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
    thresholdSessionId: state.identity.thresholdSessionId,
    signingGrantId: state.identity.signingGrantId,
    ...(evmFamilyKeyFingerprint ? { evmFamilyKeyFingerprint } : {}),
    hasRecord: state.kind === 'public_identity_unavailable' ? state.hasRecord : true,
    publicIdentityPresent,
    signerMaterialPresent,
  };
}

export function summarizeVisibleEcdsaMaterial(args: {
  authMethod: EvmFamilyEcdsaAuthMethod;
  source: ThresholdEcdsaSessionStoreSource;
  chainTarget: ThresholdEcdsaChainTarget;
  materialChainTarget: ThresholdEcdsaChainTarget;
  record?: ThresholdEcdsaSessionRecord;
}): EcdsaMaterialSummary | { present: false } {
  const record = args.record;
  if (!record) return { present: false };
  const identity = buildEcdsaSessionIdentity({
    thresholdSessionId: record.thresholdSessionId,
    signingGrantId: record.signingGrantId,
  });
  const readyResolution = resolveReadyEvmFamilyEcdsaMaterial({
    record,
    rpId: thresholdEcdsaRecordRpId(record),
    expected: {
      walletId: record.walletId,
      chainTarget: args.materialChainTarget,
      authMethod: args.authMethod,
      source: args.source,
      thresholdSessionId: identity.thresholdSessionId,
      signingGrantId: identity.signingGrantId,
    },
  });
  return summarizeEcdsaMaterialState(
    buildEcdsaMaterialStateForCandidate({
      candidate: {
        kind: 'lane_candidate',
        walletId: record.walletId,
        key:
          readyResolution.kind === 'ready'
            ? readyResolution.material.key
            : buildEvmFamilyEcdsaKeyIdentityFromRecord({
                record,
                rpId: thresholdEcdsaRecordRpId(record),
              }),
        keyHandle: record.keyHandle,
        authMethod: args.authMethod,
        curve: 'ecdsa',
        chain: args.chainTarget.kind,
        signingGrantId: record.signingGrantId,
        thresholdSessionId: record.thresholdSessionId,
        state: 'ready',
        remainingUses: record.remainingUses,
        expiresAtMs: record.expiresAtMs,
        updatedAtMs: record.updatedAtMs,
        source: 'runtime_session_record',
        chainTarget: args.chainTarget,
      },
      record,
      authMethod: args.authMethod,
      source: args.source,
      chainTarget: args.chainTarget,
      materialChainTarget: args.materialChainTarget,
    }),
  );
}

function tryBuildVerifiedPublicFactsFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
}): VerifiedEcdsaPublicFacts | null {
  try {
    return buildVerifiedEcdsaPublicFacts({
      keyHandle: args.record.keyHandle,
      publicKeyB64u: args.record.thresholdEcdsaPublicKeyB64u,
      participantIds: args.record.participantIds,
      thresholdOwnerAddress: args.record.ethereumAddress,
    });
  } catch {
    return null;
  }
}

function reauthReasonFromMaterialResolution(args: {
  reason?: { kind: string; reason?: string };
  record: ThresholdEcdsaSessionRecord;
}): ReauthRequiredEcdsaMaterial['reason'] | null {
  if (args.reason?.kind !== 'stale_or_unrestorable_material') return null;
  switch (args.reason.reason) {
    case 'expired':
      return 'expired';
    case 'exhausted':
      return 'exhausted';
    case 'auth_missing':
      return missingShareReasonForRecord(args.record);
    case 'invalid_identity':
    default:
      return null;
  }
}

function missingShareReasonForRecord(
  record: ThresholdEcdsaSessionRecord,
): Extract<ReauthRequiredEcdsaMaterial['reason'], 'missing_worker_share' | 'missing_inline_share'> {
  const handle = record.clientAdditiveShareHandle;
  if (record.source === 'email_otp' || handle?.kind === 'email_otp_worker_session') {
    return 'missing_worker_share';
  }
  return 'missing_inline_share';
}

function buildReadySharedEcdsaState(args: {
  authMethod: EvmFamilyEcdsaAuthMethod;
  chainTarget: ThresholdEcdsaChainTarget;
  sourceChainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  material: ReadyEvmFamilyEcdsaMaterial;
  signerSession: ReadyEcdsaSignerSession;
}): EvmFamilySharedEcdsaReadyState {
  return {
    kind: 'ready_to_sign',
    walletId: String(args.material.key.walletId),
    authMethod: args.authMethod,
    sourceChainTarget: args.sourceChainTarget,
    publishedTargets: uniqueChainTargets([args.sourceChainTarget, args.chainTarget]),
    sharedPublicFacts: args.publicFacts,
    signingGrantId: args.material.lane.signingGrantId,
    thresholdSessionId: args.material.lane.thresholdSessionId,
    remainingSignatureUses: positiveSignatureUses(args.material.lane.remainingUses),
    expiresAtMs: futureEpochMs(args.material.lane.expiresAtMs),
    signerMaterial: sharedSignerMaterial({
      requestChainTarget: args.chainTarget,
      sourceChainTarget: args.sourceChainTarget,
      signerSession: args.signerSession,
    }),
  };
}

function sharedSignerMaterial(args: {
  requestChainTarget: ThresholdEcdsaChainTarget;
  sourceChainTarget: ThresholdEcdsaChainTarget;
  signerSession: ReadyEcdsaSignerSession;
}): EvmFamilySharedEcdsaSignerMaterial {
  if (!thresholdEcdsaChainTargetsEqual(args.requestChainTarget, args.sourceChainTarget)) {
    return {
      kind: 'source_chain_material',
      sourceChainTarget: args.sourceChainTarget,
    };
  }
  switch (args.signerSession.clientShare.kind) {
    case 'email_otp_worker_share':
      return {
        kind: 'worker_handle',
        workerSessionId: args.signerSession.clientShare.handle.sessionId,
      };
    case 'role_local_worker_share':
      return {
        kind: 'worker_handle',
        workerSessionId: args.signerSession.clientShare.handle.materialHandle,
      };
  }
}

function positiveSignatureUses(value: number): PositiveSignatureUses {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error('[SigningEngine][ecdsa] ready shared ECDSA state requires positive uses');
  }
  return value as PositiveSignatureUses;
}

function futureEpochMs(value: number): FutureEpochMs {
  if (!Number.isSafeInteger(value) || value <= Date.now()) {
    throw new Error('[SigningEngine][ecdsa] ready shared ECDSA state requires future expiry');
  }
  return value as FutureEpochMs;
}

function uniqueChainTargets(
  chainTargets: readonly ThresholdEcdsaChainTarget[],
): readonly ThresholdEcdsaChainTarget[] {
  const seen = new Set<string>();
  const unique: ThresholdEcdsaChainTarget[] = [];
  for (const chainTarget of chainTargets) {
    const key = thresholdEcdsaChainTargetKey(chainTarget);
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(chainTarget);
  }
  return unique;
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
  switch (roleLocalState.inlineSigningMaterial.kind) {
    case 'role_local_ready_state_blob':
      return {
        kind: 'persisted_record_policy',
        expiresAtMs: Math.floor(Number(args.record.expiresAtMs) || 0),
        remainingUses: Math.floor(Number(args.record.remainingUses) || 0),
      };
    case 'email_otp_worker_share':
      return {
        kind: 'worker_session_status',
        workerSessionId: roleLocalState.inlineSigningMaterial.workerSessionId,
      };
  }
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
  const laneKeyHandle = String(args.lane.keyHandle || '').trim();
  return (
    String(args.lane.thresholdSessionId) === args.state.identity.thresholdSessionId &&
    String(args.lane.signingGrantId) === args.state.identity.signingGrantId &&
    materialKeyHandle === laneKeyHandle &&
    String(args.state.record.keyHandle || '').trim() === laneKeyHandle &&
    thresholdEcdsaChainTargetsEqual(args.lane.chainTarget, args.state.chainTarget)
  );
}
