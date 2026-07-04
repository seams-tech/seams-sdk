import type { ThresholdEcdsaCanonicalExportArtifact } from '../../interfaces/signing';
import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
  WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  assertMatchingVerifiedEcdsaPublicFacts,
  buildReadyEcdsaSignerSessionFromReadyMaterial,
  deriveEvmFamilyKeyFingerprintFromPublicFacts,
  resolveReadyEvmFamilyEcdsaMaterial,
  toVerifiedEcdsaPublicFactsFromDurableRecord,
  toVerifiedEcdsaPublicFactsFromRecord,
  toVerifiedEcdsaPublicFactsFromReadyMaterial,
  type EvmFamilyKeyFingerprint,
  type EvmFamilyEcdsaKeyIdentity,
  type ReadyEcdsaSignerSession,
  type ReadyEvmFamilyEcdsaMaterial,
  type ThresholdEcdsaSessionId,
  type VerifiedEcdsaPublicFacts,
  type SigningGrantId,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type {
  AvailableEcdsaSigningLane,
  ConcreteAvailableEcdsaSigningLane,
} from '../../session/availability/availableSigningLanes';
import { isConcreteAvailableSigningLane } from '../../session/availability/availableSigningLanes';
import {
  deriveThresholdEcdsaRuntimeLaneKey,
  getThresholdEcdsaSessionRecordByKey,
  thresholdEcdsaEmailOtpAuthContext,
  thresholdEcdsaLaneCandidateFromSessionRecord,
  type ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import {
  listExactSealedSessionsForWallet,
  type SigningSessionSealedStoreRecord,
} from '../../session/persistence/sealedSessionStore';
import {
  type ThresholdEcdsaChainTarget,
  type ThresholdEcdsaSessionRecordKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import type { EvmFamilySigningTarget } from '../signEvmFamily/types';
import type { ExactEcdsaSigningLaneIdentity } from '../../session/identity/exactSigningLaneIdentity';
import {
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProviderUserId,
} from '../../session/identity/laneIdentity';
import {
  buildEcdsaMaterialStateForCandidate,
  requireReadyEcdsaMaterial,
  type EcdsaMaterialState,
  type ReadyEcdsaMaterial,
} from '../signEvmFamily/ecdsaMaterialState';
import {
  commitEmailOtpEcdsaLaneFromRecordForMaterial,
  commitReadyEmailOtpEcdsaLaneFromRecord,
  commitReadyPasskeyEcdsaLaneFromRecord,
  EmailOtpEcdsaCommittedLaneStateError,
  resolvedEvmFamilyEcdsaSigningLaneFromCandidate,
  type RecordBackedEcdsaCommittedLane,
} from '../signEvmFamily/ecdsaSelection';

export type EcdsaExportMaterialAvailability =
  | { kind: 'loaded_worker_material' }
  | { kind: 'sealed_worker_material' }
  | { kind: 'material_pending'; reason: 'email_otp_route_auth' };

export type ExactEcdsaExportLane = {
  curve: 'ecdsa';
  laneIdentity: ExactEcdsaSigningLaneIdentity;
  key: EvmFamilyEcdsaKeyIdentity;
  publicFacts: VerifiedEcdsaPublicFacts;
  session: {
    chainTarget: ThresholdEcdsaChainTarget;
    authMethod: 'email_otp' | 'passkey';
    signingGrantId: SigningGrantId;
    thresholdSessionId: ThresholdEcdsaSessionId;
    state: ConcreteAvailableEcdsaSigningLane['state'];
    source: ConcreteAvailableEcdsaSigningLane['source'];
    material: EcdsaExportMaterialAvailability;
    ecdsaThresholdKeyId?: never;
    signingRootId?: never;
    signingRootVersion?: never;
    participantIds?: never;
    thresholdOwnerAddress?: never;
  };
};

export type EcdsaExportSessionStoreDeps = {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  exportArtifactsByLane: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
};

type ReadyThresholdEcdsaExportMaterialBase = {
  kind: 'ready_threshold_ecdsa_export_material';
  signerSession: ReadyEcdsaSignerSession;
  publicFacts: VerifiedEcdsaPublicFacts;
  cachedExportArtifact: ThresholdEcdsaCanonicalExportArtifact | null;
  evmFamilyKeyFingerprint: EvmFamilyKeyFingerprint;
  record?: never;
  ecdsaThresholdKeyId?: never;
  keyRef?: never;
  readyMaterial?: never;
};

export type ReadyPasskeyThresholdEcdsaExportMaterial = ReadyThresholdEcdsaExportMaterialBase & {
  authMethod: 'passkey';
  committedLane: ReadyEcdsaExportLane<PasskeyWalletAuthAuthority>;
};

export type ReadyEmailOtpThresholdEcdsaExportMaterial = ReadyThresholdEcdsaExportMaterialBase & {
  authMethod: 'email_otp';
  committedLane: ReadyEcdsaExportLane<EmailOtpWalletAuthAuthority>;
};

export type ReadyThresholdEcdsaExportMaterial =
  | ReadyPasskeyThresholdEcdsaExportMaterial
  | ReadyEmailOtpThresholdEcdsaExportMaterial;

export type ReadyEcdsaExportMaterial = ReadyThresholdEcdsaExportMaterial;

export type EcdsaExportLane<A extends WalletAuthAuthority = WalletAuthAuthority> =
  RecordBackedEcdsaCommittedLane<A>;

export type ReadyEcdsaExportLane<A extends WalletAuthAuthority = WalletAuthAuthority> =
  RecordBackedEcdsaCommittedLane<A> & { material: ReadyEcdsaMaterial };

function isReadyPasskeyEcdsaExportLane(
  lane: ReadyEcdsaExportLane,
): lane is ReadyEcdsaExportLane<PasskeyWalletAuthAuthority> {
  return lane.authority.factor.kind === 'passkey';
}

type ReadyEcdsaExportMaterialBoundary = {
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
  committedLane: ReadyEcdsaExportLane;
};

type FreshEmailOtpEcdsaExportSubject =
  | {
      providerIdentityMode: 'explicit_provider_user';
      providerUserId: string;
    }
  | {
      providerIdentityMode: 'wallet_session_subject';
      providerUserId?: never;
    };

export type FreshEmailOtpEcdsaExportMaterialNeedsChallenge = FreshEmailOtpEcdsaExportSubject & {
  kind: 'fresh_email_otp_needs_challenge';
  chainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  emailHashHex: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

export type FreshEmailOtpEcdsaExportMaterialRouteAuthReady = {
  kind: 'fresh_email_otp_route_auth_ready';
  chainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>;
  record?: never;
  authLane?: never;
};

export type FreshEmailOtpEcdsaExportMaterial =
  | FreshEmailOtpEcdsaExportMaterialNeedsChallenge
  | FreshEmailOtpEcdsaExportMaterialRouteAuthReady;

export type FreshPasskeyEcdsaExportMaterial = {
  kind: 'fresh_passkey_needs_authorization';
  chainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  record: ThresholdEcdsaSessionRecord;
};

export type EcdsaExportMaterial =
  | ReadyEcdsaExportMaterial
  | FreshEmailOtpEcdsaExportMaterial
  | FreshPasskeyEcdsaExportMaterial;

type EcdsaExportSessionRecordLookupKey = ThresholdEcdsaSessionRecordKey;

export function ecdsaExportBoundaryChain(lane: ExactEcdsaExportLane): 'evm' | 'tempo' {
  return lane.session.chainTarget.kind;
}

export function ecdsaExportSessionRecordKey(
  lane: ExactEcdsaExportLane,
): EcdsaExportSessionRecordLookupKey {
  return {
    walletId: toWalletId(lane.key.walletId),
    keyHandle: String(lane.publicFacts.keyHandle),
    authMethod: lane.session.authMethod,
    curve: 'ecdsa',
    chainTarget: lane.session.chainTarget,
    signingGrantId: String(lane.session.signingGrantId),
    thresholdSessionId: String(lane.session.thresholdSessionId),
  };
}

export function ecdsaSigningTargetFromChainTarget(
  chainTarget: ThresholdEcdsaChainTarget,
): EvmFamilySigningTarget {
  return chainTarget;
}

export function isConcreteEcdsaExportLane(
  lane: AvailableEcdsaSigningLane | null | undefined,
): lane is ConcreteAvailableEcdsaSigningLane {
  return (
    Boolean(lane) &&
    lane!.curve === 'ecdsa' &&
    Boolean(lane!.chainTarget) &&
    isConcreteAvailableSigningLane(lane!) &&
    Boolean(String(lane!.publicFacts.keyHandle || '').trim())
  );
}

export function readEcdsaExportRecordForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): ThresholdEcdsaSessionRecord | null {
  return getThresholdEcdsaSessionRecordByKey(deps, ecdsaExportSessionRecordKey(exportLane));
}

function buildEmailOtpEcdsaExportMaterialState(args: {
  record: ThresholdEcdsaSessionRecord;
  chainTarget: ThresholdEcdsaChainTarget;
}): EcdsaMaterialState {
  const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({ record: args.record });
  return buildEcdsaMaterialStateForCandidate({
    candidate,
    record: args.record,
    authMethod: 'email_otp',
    source: 'email_otp',
    chainTarget: args.chainTarget,
    materialChainTarget: args.chainTarget,
  });
}

function commitRecordBackedEmailOtpEcdsaExportLane(args: {
  record: ThresholdEcdsaSessionRecord;
  material: EcdsaMaterialState;
}): EcdsaExportLane<EmailOtpWalletAuthAuthority> {
  const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({ record: args.record });
  const lane = resolvedEvmFamilyEcdsaSigningLaneFromCandidate(candidate);
  const committedLane = commitEmailOtpEcdsaLaneFromRecordForMaterial({
    lane,
    record: args.record,
    material: args.material,
  });
  if (committedLane.source !== 'record_backed') {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP export requires record-backed lane');
  }
  return committedLane;
}

function commitRecordBackedReadyEmailOtpEcdsaExportLane(args: {
  lane: ReturnType<typeof resolvedEvmFamilyEcdsaSigningLaneFromCandidate>;
  record: ThresholdEcdsaSessionRecord;
  material: ReturnType<typeof requireReadyEcdsaMaterial>;
}): ReadyEcdsaExportLane<EmailOtpWalletAuthAuthority> {
  const committedLane = commitReadyEmailOtpEcdsaLaneFromRecord(args);
  if (committedLane.source !== 'record_backed') {
    throw new Error(
      '[SigningEngine][ecdsa-export] ready Email OTP export requires record-backed lane',
    );
  }
  return committedLane;
}

function isMissingEmailOtpRouteAuthority(error: unknown): boolean {
  return (
    error instanceof EmailOtpEcdsaCommittedLaneStateError &&
    error.failure.kind === 'authority_missing'
  );
}

function tryCommitRecordBackedEmailOtpEcdsaExportLane(args: {
  record: ThresholdEcdsaSessionRecord;
  material: EcdsaMaterialState;
}): EcdsaExportLane<EmailOtpWalletAuthAuthority> | null {
  try {
    return commitRecordBackedEmailOtpEcdsaExportLane(args);
  } catch (error) {
    if (isMissingEmailOtpRouteAuthority(error)) return null;
    throw error;
  }
}

function commitReadyRecordBackedEcdsaExportLane(args: {
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
}): ReadyEcdsaExportLane | null {
  if (args.readyMaterial.record.source !== 'email_otp') {
    const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({
      record: args.readyMaterial.record,
    });
    const materialState = buildEcdsaMaterialStateForCandidate({
      candidate,
      record: args.readyMaterial.record,
      authMethod: 'passkey',
      source: args.readyMaterial.record.source,
      chainTarget: args.readyMaterial.record.chainTarget,
      materialChainTarget: args.readyMaterial.record.chainTarget,
    });
    const readySigningMaterial = requireReadyEcdsaMaterial(
      materialState,
      'ready passkey ECDSA export committed lane',
    );
    return commitReadyPasskeyEcdsaLaneFromRecord({
      lane: resolvedEvmFamilyEcdsaSigningLaneFromCandidate(candidate),
      record: args.readyMaterial.record,
      material: readySigningMaterial,
      source: args.readyMaterial.record.source,
    });
  }
  const materialState = buildEmailOtpEcdsaExportMaterialState({
    record: args.readyMaterial.record,
    chainTarget: args.readyMaterial.record.chainTarget,
  });
  const readySigningMaterial = requireReadyEcdsaMaterial(
    materialState,
    'ready Email OTP ECDSA export committed lane',
  );
  const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({
    record: args.readyMaterial.record,
  });
  try {
    return commitRecordBackedReadyEmailOtpEcdsaExportLane({
      lane: resolvedEvmFamilyEcdsaSigningLaneFromCandidate(candidate),
      record: args.readyMaterial.record,
      material: readySigningMaterial,
    });
  } catch (error) {
    if (isMissingEmailOtpRouteAuthority(error)) return null;
    throw error;
  }
}

export function buildReadyThresholdEcdsaExportMaterial(args: {
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
  publicFacts: VerifiedEcdsaPublicFacts;
  committedLane: ReadyEcdsaExportLane;
}): ReadyThresholdEcdsaExportMaterial {
  const signerSession = buildReadyEcdsaSignerSessionFromReadyMaterial({
    material: args.readyMaterial,
    publicFacts: args.publicFacts,
  });
  const evmFamilyKeyFingerprint = deriveEvmFamilyKeyFingerprintFromPublicFacts({
    walletId: args.readyMaterial.key.walletId,
    publicFacts: args.publicFacts,
  });
  if (isReadyPasskeyEcdsaExportLane(args.committedLane)) {
    return {
      kind: 'ready_threshold_ecdsa_export_material',
      signerSession,
      publicFacts: args.publicFacts,
      cachedExportArtifact: args.readyMaterial.cachedExportArtifact,
      evmFamilyKeyFingerprint,
      authMethod: 'passkey',
      committedLane: args.committedLane,
    };
  }
  return {
    kind: 'ready_threshold_ecdsa_export_material',
    signerSession,
    publicFacts: args.publicFacts,
    cachedExportArtifact: args.readyMaterial.cachedExportArtifact,
    evmFamilyKeyFingerprint,
    authMethod: 'email_otp',
    committedLane: args.committedLane,
  };
}

function readReadyEcdsaExportMaterialBoundaryForExportLane(args: {
  deps: EcdsaExportSessionStoreDeps;
  exportLane: ExactEcdsaExportLane;
}): ReadyEcdsaExportMaterialBoundary | null {
  const record = readEcdsaExportRecordForLane(args.deps, args.exportLane);
  if (!record || !isFreshEcdsaExportSessionRecord(record)) return null;
  const cachedExportArtifact =
    args.deps.exportArtifactsByLane.get(deriveThresholdEcdsaRuntimeLaneKey(record)) || null;
  const materialResolution = resolveReadyEvmFamilyEcdsaMaterial({
    record,
    cachedExportArtifact,
    expected: {
      walletId: args.exportLane.key.walletId,
      evmFamilySigningKeySlotId: args.exportLane.key.evmFamilySigningKeySlotId,
      chainTarget: args.exportLane.session.chainTarget,
      authMethod: args.exportLane.session.authMethod,
      source: record.source,
      thresholdSessionId: args.exportLane.session.thresholdSessionId,
      signingGrantId: args.exportLane.session.signingGrantId,
    },
  });
  if (materialResolution.kind !== 'ready') {
    const reason =
      materialResolution.reason.kind === 'stale_or_unrestorable_material'
        ? `${materialResolution.reason.kind}:${materialResolution.reason.reason}`
        : materialResolution.reason.kind;
    throw new Error(`[SigningEngine][ecdsa-export] ready export material rejected: ${reason}`);
  }
  const committedLane = commitReadyRecordBackedEcdsaExportLane({
    readyMaterial: materialResolution.material,
  });
  if (!committedLane) return null;
  return {
    readyMaterial: materialResolution.material,
    committedLane,
  };
}

export function isFreshEcdsaExportSessionRecord(record: ThresholdEcdsaSessionRecord): boolean {
  const remainingUses = Math.floor(Number(record.remainingUses));
  const expiresAtMs = Math.floor(Number(record.expiresAtMs));
  return (
    Number.isFinite(remainingUses) &&
    remainingUses > 0 &&
    (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0 || expiresAtMs > Date.now())
  );
}

function sealedEmailOtpEcdsaRestoreEmailHashHex(
  restore: SigningSessionSealedStoreRecord['ecdsaRestore'],
): string {
  if (!restore || !('emailHashHex' in restore)) return '';
  return String(restore.emailHashHex || '').trim();
}

export async function resolveExactSealedEcdsaExportRecordForLane(
  exportLane: ExactEcdsaExportLane,
): Promise<SigningSessionSealedStoreRecord> {
  const matches = (
    await listExactSealedSessionsForWallet({
      walletId: String(exportLane.key.walletId),
      filter: {
        authMethod: exportLane.session.authMethod,
        curve: 'ecdsa',
        chainTarget: exportLane.session.chainTarget,
      },
    })
  ).filter((record) => {
    const signingGrantId = String(record.signingGrantId || '').trim();
    const thresholdSessionId = String(record.thresholdSessionIds.ecdsa || '').trim();
    const sealedWalletId = String(record.walletId || '').trim();
    const sealedKeyHandle = String(record.ecdsaRestore?.keyHandle || '').trim();
    return (
      signingGrantId === String(exportLane.session.signingGrantId) &&
      thresholdSessionId === String(exportLane.session.thresholdSessionId) &&
      sealedWalletId === String(exportLane.key.walletId) &&
      sealedKeyHandle === String(exportLane.publicFacts.keyHandle)
    );
  });
  if (matches.length !== 1) {
    throw new Error(
      `[SigningEngine][ecdsa-export] exact sealed export lane not found for ${ecdsaExportBoundaryChain(exportLane)} ${exportLane.session.authMethod}`,
    );
  }
  return matches[0];
}

export async function resolveFreshEmailOtpEcdsaExportMaterialForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): Promise<FreshEmailOtpEcdsaExportMaterial> {
  if (exportLane.session.authMethod !== 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] fresh Email OTP export requires Email OTP lane');
  }
  const runtimeRecord = readEcdsaExportRecordForLane(deps, exportLane);
  const sealedRecord = runtimeRecord
    ? null
    : await resolveExactSealedEcdsaExportRecordForLane(exportLane);
  const sealedRestore = sealedRecord?.ecdsaRestore;
  const publicFacts = runtimeRecord
    ? await toVerifiedEcdsaPublicFactsFromRecord({ record: runtimeRecord })
    : await toVerifiedEcdsaPublicFactsFromDurableRecord({
        record: {
          ecdsaRestore: {
            keyHandle: sealedRestore?.keyHandle || exportLane.publicFacts.keyHandle,
            thresholdEcdsaPublicKeyB64u: sealedRestore?.thresholdEcdsaPublicKeyB64u,
            participantIds: sealedRestore?.participantIds,
            ethereumAddress: sealedRestore?.ethereumAddress,
          },
        },
      });
  assertMatchingVerifiedEcdsaPublicFacts({
    expected: exportLane.publicFacts,
    actual: publicFacts,
    context: 'fresh Email OTP export lane',
  });
  const emailOtpAuthContext = thresholdEcdsaEmailOtpAuthContext(runtimeRecord);
  const providerUserId = String(
    emailOtpAuthContext ? emailOtpAuthContextProviderUserId(emailOtpAuthContext) : '',
  ).trim();
  const emailHashHex = String(
    emailOtpAuthContext
      ? emailOtpAuthContextEmailHashHex(emailOtpAuthContext)
      : sealedEmailOtpEcdsaRestoreEmailHashHex(sealedRestore),
  ).trim();
  if (!emailHashHex) {
    throw new Error('[SigningEngine][ecdsa-export] fresh Email OTP export requires emailHashHex');
  }
  const runtimePolicyScope =
    runtimeRecord?.runtimePolicyScope ||
    normalizeThresholdRuntimePolicyScope(sealedRestore?.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error(
      '[SigningEngine][ecdsa-export] fresh Email OTP export requires runtimePolicyScope',
    );
  }
  if (runtimeRecord) {
    const material = buildEmailOtpEcdsaExportMaterialState({
      record: runtimeRecord,
      chainTarget: exportLane.session.chainTarget,
    });
    const committedLane = tryCommitRecordBackedEmailOtpEcdsaExportLane({
      record: runtimeRecord,
      material,
    });
    if (committedLane) {
      return {
        kind: 'fresh_email_otp_route_auth_ready',
        chainTarget: exportLane.session.chainTarget,
        publicFacts,
        runtimePolicyScope,
        committedLane,
      };
    }
  }
  const base = {
    kind: 'fresh_email_otp_needs_challenge' as const,
    chainTarget: exportLane.session.chainTarget,
    publicFacts,
    emailHashHex,
    runtimePolicyScope,
  };
  return providerUserId
    ? {
        ...base,
        providerIdentityMode: 'explicit_provider_user',
        providerUserId,
      }
    : {
        ...base,
        providerIdentityMode: 'wallet_session_subject',
      };
}

export async function resolveEcdsaExportMaterialForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): Promise<EcdsaExportMaterial> {
  const readyBoundary = readReadyEcdsaExportMaterialBoundaryForExportLane({ deps, exportLane });
  if (readyBoundary) {
    const publicFacts = await toVerifiedEcdsaPublicFactsFromReadyMaterial({
      material: readyBoundary.readyMaterial,
    });
    assertMatchingVerifiedEcdsaPublicFacts({
      expected: exportLane.publicFacts,
      actual: publicFacts,
      context: 'ready export lane',
    });
    return buildReadyThresholdEcdsaExportMaterial({
      readyMaterial: readyBoundary.readyMaterial,
      publicFacts,
      committedLane: readyBoundary.committedLane,
    });
  }
  if (exportLane.session.authMethod === 'email_otp') {
    return await resolveFreshEmailOtpEcdsaExportMaterialForLane(deps, exportLane);
  }
  const runtimeRecord = readEcdsaExportRecordForLane(deps, exportLane);
  if (runtimeRecord && runtimeRecord.source !== 'email_otp') {
    const publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({ record: runtimeRecord });
    assertMatchingVerifiedEcdsaPublicFacts({
      expected: exportLane.publicFacts,
      actual: publicFacts,
      context: 'fresh passkey export lane',
    });
    const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
      runtimeRecord.runtimePolicyScope,
    );
    if (!runtimePolicyScope) {
      throw new Error(
        '[SigningEngine][ecdsa-export] fresh passkey export requires runtimePolicyScope',
      );
    }
    return {
      kind: 'fresh_passkey_needs_authorization',
      chainTarget: exportLane.session.chainTarget,
      publicFacts,
      runtimePolicyScope,
      record: runtimeRecord,
    };
  }
  throw new Error(
    `[SigningEngine][ecdsa-export] exact export ready material unavailable for ${ecdsaExportBoundaryChain(exportLane)} ${exportLane.session.authMethod}`,
  );
}
