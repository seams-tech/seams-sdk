import type {
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../interfaces/signing';
import {
  resolveReadyEvmFamilyEcdsaMaterial,
  type EvmFamilyEcdsaKeyIdentity,
  type ReadyEvmFamilyEcdsaMaterial,
  type ThresholdEcdsaSessionId,
  type WalletSigningSessionId,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type {
  AvailableEcdsaSigningLane,
  ConcreteAvailableEcdsaSigningLane,
} from '../../session/availability/availableSigningLanes';
import { isConcreteAvailableSigningLane } from '../../session/availability/availableSigningLanes';
import {
  getThresholdEcdsaKeyRefByKey,
  getThresholdEcdsaSessionRecordByKey,
  type ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import {
  listExactSealedSessionsForWallet,
  type SigningSessionSealedStoreRecord,
} from '../../session/persistence/sealedSessionStore';
import {
  type ThresholdEcdsaChainTarget,
  type ThresholdEcdsaSessionRecordKey,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import type { EvmFamilySigningTarget } from '../signEvmFamily/types';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';

export type ExactEcdsaExportLane = {
  curve: 'ecdsa';
  key: EvmFamilyEcdsaKeyIdentity;
  session: {
    chainTarget: ThresholdEcdsaChainTarget;
    authMethod: 'email_otp' | 'passkey';
    walletSigningSessionId: WalletSigningSessionId;
    thresholdSessionId: ThresholdEcdsaSessionId;
    state: ConcreteAvailableEcdsaSigningLane['state'];
    source: ConcreteAvailableEcdsaSigningLane['source'];
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

export type ReadyEcdsaExportMaterial = {
  kind: 'ready';
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
};

export type FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp';
  chainTarget: ThresholdEcdsaChainTarget;
  publicKey: string;
  ecdsaThresholdKeyId: string;
  participantIds: number[];
  authSubjectId?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

export type EcdsaExportMaterial = ReadyEcdsaExportMaterial | FreshEmailOtpEcdsaExportMaterial;

type EcdsaExportSessionRecordLookupKey = ThresholdEcdsaSessionRecordKey & {
  walletId: string;
};

export function ecdsaExportBoundaryChain(lane: ExactEcdsaExportLane): 'evm' | 'tempo' {
  return lane.session.chainTarget.kind;
}

export function ecdsaExportSessionRecordKey(
  lane: ExactEcdsaExportLane,
): EcdsaExportSessionRecordLookupKey {
  return {
    walletId: String(lane.key.walletId),
    subjectId: lane.key.subjectId,
    authMethod: lane.session.authMethod,
    curve: 'ecdsa',
    chainTarget: lane.session.chainTarget,
    ecdsaThresholdKeyId: String(lane.key.ecdsaThresholdKeyId),
    signingRootId: String(lane.key.signingRootId),
    signingRootVersion: String(lane.key.signingRootVersion),
    walletSigningSessionId: String(lane.session.walletSigningSessionId),
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
    Boolean(String(lane!.key.ecdsaThresholdKeyId || '').trim())
  );
}

export function readEcdsaExportKeyRefForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): ThresholdEcdsaSecp256k1KeyRef | null {
  return getThresholdEcdsaKeyRefByKey(deps, ecdsaExportSessionRecordKey(exportLane))?.keyRef || null;
}

export function readEcdsaExportRecordForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): ThresholdEcdsaSessionRecord | null {
  return getThresholdEcdsaSessionRecordByKey(deps, ecdsaExportSessionRecordKey(exportLane));
}

export function isUsableEcdsaExportSessionRecord(record: ThresholdEcdsaSessionRecord): boolean {
  const remainingUses = Math.floor(Number(record.remainingUses));
  const expiresAtMs = Math.floor(Number(record.expiresAtMs));
  const hasAuthToken = Boolean(String(record.thresholdSessionAuthToken || '').trim());
  return (
    Number.isFinite(remainingUses) &&
    remainingUses > 0 &&
    (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0 || expiresAtMs > Date.now()) &&
    (record.thresholdSessionKind === 'cookie' || hasAuthToken)
  );
}

function sealedEcdsaSigningRoot(
  record: SigningSessionSealedStoreRecord,
): { signingRootId: string; signingRootVersion: string } | null {
  const explicitSigningRootId = String(record.signingRootId || '').trim();
  const explicitSigningRootVersion = String(record.signingRootVersion || '').trim();
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
    record.ecdsaRestore?.runtimePolicyScope,
  );
  const scope = runtimePolicyScope ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope) : null;
  const signingRootId = explicitSigningRootId || String(scope?.signingRootId || '').trim();
  const signingRootVersion =
    explicitSigningRootVersion || String(scope?.signingRootVersion || 'default').trim();
  if (!signingRootId || !signingRootVersion) return null;
  return { signingRootId, signingRootVersion };
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
    const walletSigningSessionId = String(record.walletSigningSessionId || '').trim();
    const thresholdSessionId = String(record.thresholdSessionIds.ecdsa || '').trim();
    const signingRoot = sealedEcdsaSigningRoot(record);
    const sealedWalletId = String(record.walletId || '').trim();
    return (
      walletSigningSessionId === String(exportLane.session.walletSigningSessionId) &&
      thresholdSessionId === String(exportLane.session.thresholdSessionId) &&
      String(record.subjectId || '').trim() === String(exportLane.key.subjectId) &&
      sealedWalletId === String(exportLane.key.walletId) &&
      signingRoot?.signingRootId === String(exportLane.key.signingRootId) &&
      signingRoot.signingRootVersion === String(exportLane.key.signingRootVersion) &&
      String(record.ecdsaRestore?.ecdsaThresholdKeyId || '').trim() ===
        String(exportLane.key.ecdsaThresholdKeyId)
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
  const sealedRecord = runtimeRecord ? null : await resolveExactSealedEcdsaExportRecordForLane(exportLane);
  const sealedRestore = sealedRecord?.ecdsaRestore;
  const ecdsaThresholdKeyId = String(
    runtimeRecord?.ecdsaThresholdKeyId || sealedRestore?.ecdsaThresholdKeyId || '',
  ).trim();
  if (!ecdsaThresholdKeyId) {
    throw new Error('[SigningEngine][ecdsa-export] exact export lane is missing ECDSA key id');
  }
  const participantIds = (runtimeRecord?.participantIds || sealedRestore?.participantIds || [])
    .map((participantId) => Math.floor(Number(participantId)))
    .filter((participantId) => Number.isSafeInteger(participantId) && participantId > 0);
  if (!participantIds.length) {
    throw new Error('[SigningEngine][ecdsa-export] exact export lane is missing participants');
  }
  const authSubjectId = String(runtimeRecord?.emailOtpAuthContext?.authSubjectId || '').trim();
  const runtimePolicyScope =
    runtimeRecord?.runtimePolicyScope ||
    normalizeThresholdRuntimePolicyScope(sealedRestore?.runtimePolicyScope);
  return {
    kind: 'fresh_email_otp',
    chainTarget: exportLane.session.chainTarget,
    publicKey: ecdsaThresholdKeyId,
    ecdsaThresholdKeyId,
    participantIds,
    ...(authSubjectId ? { authSubjectId } : {}),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
}

export async function resolveEcdsaExportMaterialForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
  rpId: string,
): Promise<EcdsaExportMaterial> {
  const keyRef = readEcdsaExportKeyRefForLane(deps, exportLane);
  const record = readEcdsaExportRecordForLane(deps, exportLane);
  if (keyRef && record && isUsableEcdsaExportSessionRecord(record)) {
    const materialResolution = resolveReadyEvmFamilyEcdsaMaterial({
      record,
      keyRef,
      rpId,
      expected: {
        walletId: exportLane.key.walletId,
        subjectId: exportLane.key.subjectId,
        chainTarget: exportLane.session.chainTarget,
        authMethod: exportLane.session.authMethod,
        source: record.source,
        thresholdSessionId: exportLane.session.thresholdSessionId,
        walletSigningSessionId: exportLane.session.walletSigningSessionId,
      },
    });
    if (materialResolution.kind !== 'ready') {
      throw new Error(
        `[SigningEngine][ecdsa-export] ready export material rejected: ${materialResolution.reason.kind}`,
      );
    }
    return { kind: 'ready', readyMaterial: materialResolution.material };
  }
  if (exportLane.session.authMethod === 'email_otp') {
    return await resolveFreshEmailOtpEcdsaExportMaterialForLane(deps, exportLane);
  }
  throw new Error(
    `[SigningEngine][ecdsa-export] exact export keyRef not ready for ${ecdsaExportBoundaryChain(exportLane)} ${exportLane.session.authMethod}`,
  );
}
