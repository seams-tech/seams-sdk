import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../interfaces/signing';
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
  listExactSealedSessionsForAccount,
  type SigningSessionSealedStoreRecord,
} from '../../session/persistence/sealedSessionStore';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type ThresholdEcdsaSessionRecordKey,
  type WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  normalizeThresholdRuntimePolicyScope,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import type { EvmFamilySigningTarget } from '../signEvmFamily/types';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';

export type ExactEcdsaExportLane = {
  curve: 'ecdsa';
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  nearAccountId: AccountId;
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  state: ConcreteAvailableEcdsaSigningLane['state'];
  source: ConcreteAvailableEcdsaSigningLane['source'];
};

export type EcdsaExportSessionStoreDeps = {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  exportArtifactsByLane: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
};

export type ReadyEcdsaExportMaterial = {
  kind: 'ready';
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
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

export function ecdsaExportBoundaryChain(lane: ExactEcdsaExportLane): 'evm' | 'tempo' {
  return lane.chainTarget.kind;
}

export function ecdsaExportSessionRecordKey(lane: ExactEcdsaExportLane): ThresholdEcdsaSessionRecordKey {
  return {
    subjectId: lane.subjectId,
    authMethod: lane.authMethod,
    curve: 'ecdsa',
    chainTarget: lane.chainTarget,
    ecdsaThresholdKeyId: lane.ecdsaThresholdKeyId,
    signingRootId: lane.signingRootId,
    signingRootVersion: lane.signingRootVersion,
    walletSigningSessionId: lane.walletSigningSessionId,
    thresholdSessionId: lane.thresholdSessionId,
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
    Boolean(String(lane!.ecdsaThresholdKeyId || '').trim())
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

export function resolveEcdsaExportRecordForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): ThresholdEcdsaSessionRecord {
  const record = readEcdsaExportRecordForLane(deps, exportLane);
  if (!record) {
    throw new Error(
      `[SigningEngine][ecdsa-export] exact export session record not ready for ${ecdsaExportBoundaryChain(exportLane)} ${exportLane.authMethod}`,
    );
  }
  return record;
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
    await listExactSealedSessionsForAccount({
      accountId: String(exportLane.nearAccountId),
      filter: {
        authMethod: exportLane.authMethod,
        curve: 'ecdsa',
        chainTarget: exportLane.chainTarget,
      },
    })
  ).filter((record) => {
    const walletSigningSessionId = String(record.walletSigningSessionId || '').trim();
    const thresholdSessionId = String(record.thresholdSessionIds.ecdsa || '').trim();
    const signingRoot = sealedEcdsaSigningRoot(record);
    const sealedAccountId = String(record.walletId || record.userId || '').trim();
    return (
      walletSigningSessionId === exportLane.walletSigningSessionId &&
      thresholdSessionId === exportLane.thresholdSessionId &&
      String(record.subjectId || '').trim() === String(exportLane.subjectId) &&
      sealedAccountId === String(exportLane.nearAccountId) &&
      signingRoot?.signingRootId === exportLane.signingRootId &&
      signingRoot.signingRootVersion === exportLane.signingRootVersion &&
      String(record.ecdsaRestore?.ecdsaThresholdKeyId || '').trim() ===
        exportLane.ecdsaThresholdKeyId
    );
  });
  if (matches.length !== 1) {
    throw new Error(
      `[SigningEngine][ecdsa-export] exact sealed export lane not found for ${ecdsaExportBoundaryChain(exportLane)} ${exportLane.authMethod}`,
    );
  }
  return matches[0];
}

export async function resolveFreshEmailOtpEcdsaExportMaterialForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): Promise<FreshEmailOtpEcdsaExportMaterial> {
  if (exportLane.authMethod !== 'email_otp') {
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
    chainTarget: exportLane.chainTarget,
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
): Promise<EcdsaExportMaterial> {
  const keyRef = readEcdsaExportKeyRefForLane(deps, exportLane);
  const record = readEcdsaExportRecordForLane(deps, exportLane);
  if (keyRef && record && isUsableEcdsaExportSessionRecord(record)) {
    return { kind: 'ready', keyRef };
  }
  if (exportLane.authMethod === 'email_otp') {
    return await resolveFreshEmailOtpEcdsaExportMaterialForLane(deps, exportLane);
  }
  throw new Error(
    `[SigningEngine][ecdsa-export] exact export keyRef not ready for ${ecdsaExportBoundaryChain(exportLane)} ${exportLane.authMethod}`,
  );
}

export function assertEcdsaExportKeyRefMatchesLane(args: {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  exportLane: ExactEcdsaExportLane;
}): void {
  if (String(args.keyRef.subjectId || '').trim() !== String(args.exportLane.subjectId)) {
    throw new Error('[SigningEngine][ecdsa-export] keyRef subject id drifted');
  }
  if (!thresholdEcdsaChainTargetsEqual(args.keyRef.chainTarget, args.exportLane.chainTarget)) {
    throw new Error('[SigningEngine][ecdsa-export] keyRef chain target drifted');
  }
  if (String(args.keyRef.ecdsaThresholdKeyId || '').trim() !== args.exportLane.ecdsaThresholdKeyId) {
    throw new Error('[SigningEngine][ecdsa-export] keyRef threshold key drifted');
  }
  if (String(args.keyRef.signingRootId || '').trim() !== args.exportLane.signingRootId) {
    throw new Error('[SigningEngine][ecdsa-export] keyRef signing root drifted');
  }
  if (
    String(args.keyRef.signingRootVersion || 'default').trim() !== args.exportLane.signingRootVersion
  ) {
    throw new Error('[SigningEngine][ecdsa-export] keyRef signing root version drifted');
  }
  if (
    String(args.keyRef.walletSigningSessionId || '').trim() !== args.exportLane.walletSigningSessionId
  ) {
    throw new Error('[SigningEngine][ecdsa-export] keyRef wallet session drifted');
  }
  if (String(args.keyRef.thresholdSessionId || '').trim() !== args.exportLane.thresholdSessionId) {
    throw new Error('[SigningEngine][ecdsa-export] keyRef threshold session drifted');
  }
}
