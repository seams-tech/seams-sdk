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
  thresholdEcdsaLaneCandidateFromSessionRecord,
  type ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../../session/identity/laneIdentity';
import {
  listExactSealedSessionsForWallet,
  type CurrentEcdsaSealedSessionRecord,
  type EcdsaReauthAnchorPublicRestore,
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
import type { EmailOtpEcdsaSigningSessionAuthority } from '../../session/emailOtp/ecdsaSigningSessionAuthority';
import { emailOtpEcdsaSigningSessionAuthorityFromSealedRecord } from '../../session/emailOtp/sealedSigningSessionAuth';
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
  type RecordBacked,
  type RecordBackedEcdsaCommittedLane,
} from '../signEvmFamily/ecdsaSelection';
import type { RouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';

export type EcdsaExportMaterialAvailability =
  | { kind: 'loaded_worker_material' }
  | { kind: 'sealed_worker_material' }
  | { kind: 'material_pending'; reason: 'email_otp_route_auth' };

type ExactEcdsaExportSessionBase = {
  chainTarget: ThresholdEcdsaChainTarget;
  authMethod: 'email_otp' | 'passkey';
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  material: EcdsaExportMaterialAvailability;
  ecdsaThresholdKeyId?: never;
  signingRootId?: never;
  signingRootVersion?: never;
  participantIds?: never;
  thresholdOwnerAddress?: never;
};

type CurrentExactEcdsaExportSession = ExactEcdsaExportSessionBase & {
  state: Exclude<ConcreteAvailableEcdsaSigningLane['state'], 'expired' | 'exhausted'>;
  source: Exclude<ConcreteAvailableEcdsaSigningLane['source'], 'durable_sealed_record'>;
  publicReauthAuthority?: never;
};

type PublicReauthExactEcdsaExportSession = ExactEcdsaExportSessionBase & {
  state: ConcreteAvailableEcdsaSigningLane['state'];
  source: 'durable_sealed_record';
  publicReauthAuthority: EcdsaReauthAnchorPublicRestore;
};

export type ExactEcdsaExportSession =
  | CurrentExactEcdsaExportSession
  | PublicReauthExactEcdsaExportSession;

export type ExactEcdsaExportLane = {
  curve: 'ecdsa';
  laneIdentity: ExactEcdsaSigningLaneIdentity;
  key: EvmFamilyEcdsaKeyIdentity;
  publicFacts: VerifiedEcdsaPublicFacts;
  session: ExactEcdsaExportSession;
};

export type EcdsaExportSessionStoreDeps = {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  exportArtifactsByLane: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
};

export type EmailOtpEcdsaExportSessionRecord = Extract<
  ThresholdEcdsaSessionRecord,
  { source: 'email_otp' }
> & {
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

type RecordBackedEmailOtpEcdsaExportLane = RecordBacked<
  RecordBackedEcdsaCommittedLane<EmailOtpWalletAuthAuthority>,
  EmailOtpEcdsaExportSessionRecord
>;

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
  A extends EmailOtpWalletAuthAuthority
    ? RecordBackedEmailOtpEcdsaExportLane
    : RecordBackedEcdsaCommittedLane<A>;

export type ReadyEcdsaExportLane<A extends WalletAuthAuthority = WalletAuthAuthority> =
  EcdsaExportLane<A> & { material: ReadyEcdsaMaterial };

function isReadyPasskeyEcdsaExportLane(
  lane: ReadyEcdsaExportLane,
): lane is ReadyEcdsaExportLane<PasskeyWalletAuthAuthority> {
  return lane.authority.factor.kind === 'passkey';
}

type ReadyEcdsaExportMaterialBoundary = {
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
  committedLane: ReadyEcdsaExportLane;
};

type FreshEmailOtpEcdsaRecordBackedExportAuthority = {
  kind: 'record_backed';
  committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>;
  signingSessionAuthority?: never;
  publicReauthAuthority?: never;
};

type FreshEmailOtpEcdsaDurableExportAuthority = {
  kind: 'durable_authority_backed';
  signingSessionAuthority: EmailOtpEcdsaSigningSessionAuthority;
  committedLane?: never;
  publicReauthAuthority?: never;
};

export type EmailOtpEcdsaPublicReauthExportAuthority = Extract<
  EcdsaReauthAnchorPublicRestore,
  { source: 'email_otp' }
>;

type FreshEmailOtpEcdsaPublicReauthExportAuthority = {
  kind: 'public_reauth_authority_backed';
  publicReauthAuthority: EmailOtpEcdsaPublicReauthExportAuthority;
  committedLane?: never;
  signingSessionAuthority?: never;
};

export type FreshEmailOtpEcdsaExportMaterial = {
  kind: 'fresh_email_otp_route_auth_ready';
  chainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  authorization:
    | FreshEmailOtpEcdsaRecordBackedExportAuthority
    | FreshEmailOtpEcdsaDurableExportAuthority
    | FreshEmailOtpEcdsaPublicReauthExportAuthority;
  record?: never;
  authLane?: never;
};

export type FreshPasskeyEcdsaExportMaterial = {
  kind: 'fresh_passkey_needs_authorization';
  chainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  bootstrap: PasskeyEcdsaExportBootstrapContext;
};

export type PasskeyEcdsaExportBootstrapContext = {
  source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  relayerUrl: string;
  relayerKeyId: string;
  ecdsaThresholdKeyId: string;
  evmFamilySigningKeySlotId: string;
  signingRootId: string;
  signingRootVersion: string;
  participantIds: readonly number[];
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

function isEmailOtpEcdsaExportSessionRecord(
  record: ThresholdEcdsaSessionRecord,
): record is EmailOtpEcdsaExportSessionRecord {
  return record.source === 'email_otp' && Boolean(record.runtimePolicyScope);
}

function requireEmailOtpEcdsaExportSessionRecord(
  record: ThresholdEcdsaSessionRecord,
): EmailOtpEcdsaExportSessionRecord {
  if (isEmailOtpEcdsaExportSessionRecord(record)) return record;
  throw new Error('[SigningEngine][ecdsa-export] Email OTP export requires runtimePolicyScope');
}

function commitRecordBackedEmailOtpEcdsaExportLane(args: {
  record: ThresholdEcdsaSessionRecord;
  material: EcdsaMaterialState;
}): EcdsaExportLane<EmailOtpWalletAuthAuthority> {
  const record = requireEmailOtpEcdsaExportSessionRecord(args.record);
  const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({ record });
  const lane = resolvedEvmFamilyEcdsaSigningLaneFromCandidate(candidate);
  const committedLane = commitEmailOtpEcdsaLaneFromRecordForMaterial({
    lane,
    record,
    material: args.material,
  });
  if (committedLane.source !== 'record_backed') {
    throw new Error('[SigningEngine][ecdsa-export] Email OTP export requires record-backed lane');
  }
  return {
    source: 'record_backed',
    lane: committedLane.lane,
    authority: committedLane.authority,
    authLane: committedLane.authLane,
    walletSessionAuthority: committedLane.walletSessionAuthority,
    material: committedLane.material,
    record,
    durableRestore: 'record_restore_metadata',
  };
}

function commitRecordBackedReadyEmailOtpEcdsaExportLane(args: {
  lane: ReturnType<typeof resolvedEvmFamilyEcdsaSigningLaneFromCandidate>;
  record: EmailOtpEcdsaExportSessionRecord;
  material: ReturnType<typeof requireReadyEcdsaMaterial>;
}): ReadyEcdsaExportLane<EmailOtpWalletAuthAuthority> {
  const committedLane = commitReadyEmailOtpEcdsaLaneFromRecord(args);
  if (committedLane.source !== 'record_backed') {
    throw new Error(
      '[SigningEngine][ecdsa-export] ready Email OTP export requires record-backed lane',
    );
  }
  return {
    source: 'record_backed',
    lane: committedLane.lane,
    authority: committedLane.authority,
    authLane: committedLane.authLane,
    walletSessionAuthority: committedLane.walletSessionAuthority,
    material: committedLane.material,
    record: args.record,
    durableRestore: 'record_restore_metadata',
  };
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
  const record = requireEmailOtpEcdsaExportSessionRecord(args.readyMaterial.record);
  const materialState = buildEmailOtpEcdsaExportMaterialState({
    record,
    chainTarget: record.chainTarget,
  });
  const readySigningMaterial = requireReadyEcdsaMaterial(
    materialState,
    'ready Email OTP ECDSA export committed lane',
  );
  const candidate = thresholdEcdsaLaneCandidateFromSessionRecord({
    record,
  });
  try {
    return commitRecordBackedReadyEmailOtpEcdsaExportLane({
      lane: resolvedEvmFamilyEcdsaSigningLaneFromCandidate(candidate),
      record,
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

export async function resolveExactSealedEcdsaExportRecordForLane(
  exportLane: ExactEcdsaExportLane,
): Promise<CurrentEcdsaSealedSessionRecord> {
  const matches = (
    await listExactSealedSessionsForWallet({
      walletId: String(exportLane.key.walletId),
      filter: {
        authMethod: exportLane.session.authMethod,
        curve: 'ecdsa',
        chainTarget: exportLane.session.chainTarget,
      },
    })
  ).filter((record): record is CurrentEcdsaSealedSessionRecord => {
    if (record.curve !== 'ecdsa' || !record.ecdsaRestore) return false;
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

function requirePasskeyEcdsaExportField(value: unknown, label: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`[SigningEngine][ecdsa-export] passkey export requires ${label}`);
  }
  return normalized;
}

function requirePasskeyEcdsaExportParticipants(
  participantIds: readonly number[],
): readonly number[] {
  if (
    participantIds.length === 0 ||
    participantIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || participantId < 1,
    )
  ) {
    throw new Error('[SigningEngine][ecdsa-export] passkey export participants are invalid');
  }
  return [...participantIds];
}

function passkeyEcdsaExportBootstrapFromRuntimeRecord(
  record: Exclude<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>,
  exportLane: ExactEcdsaExportLane,
): PasskeyEcdsaExportBootstrapContext {
  return {
    source: record.source,
    relayerUrl: requirePasskeyEcdsaExportField(record.relayerUrl, 'relayerUrl'),
    relayerKeyId: requirePasskeyEcdsaExportField(record.relayerKeyId, 'relayerKeyId'),
    ecdsaThresholdKeyId: requirePasskeyEcdsaExportField(
      record.ecdsaThresholdKeyId,
      'ecdsaThresholdKeyId',
    ),
    evmFamilySigningKeySlotId: requirePasskeyEcdsaExportField(
      record.evmFamilySigningKeySlotId,
      'evmFamilySigningKeySlotId',
    ),
    signingRootId: requirePasskeyEcdsaExportField(record.signingRootId, 'signingRootId'),
    signingRootVersion: requirePasskeyEcdsaExportField(
      record.signingRootVersion || exportLane.key.signingRootVersion,
      'signingRootVersion',
    ),
    participantIds: requirePasskeyEcdsaExportParticipants(record.participantIds),
  };
}

function passkeyEcdsaExportBootstrapFromSealedRecord(
  record: CurrentEcdsaSealedSessionRecord,
  exportLane: ExactEcdsaExportLane,
): PasskeyEcdsaExportBootstrapContext {
  const restore = record.ecdsaRestore;
  if (restore.source === 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] durable passkey export source is invalid');
  }
  return {
    source: restore.source,
    relayerUrl: requirePasskeyEcdsaExportField(record.relayerUrl, 'relayerUrl'),
    relayerKeyId: requirePasskeyEcdsaExportField(restore.relayerKeyId, 'relayerKeyId'),
    ecdsaThresholdKeyId: requirePasskeyEcdsaExportField(
      restore.ecdsaThresholdKeyId || exportLane.key.ecdsaThresholdKeyId,
      'ecdsaThresholdKeyId',
    ),
    evmFamilySigningKeySlotId: requirePasskeyEcdsaExportField(
      restore.evmFamilySigningKeySlotId,
      'evmFamilySigningKeySlotId',
    ),
    signingRootId: requirePasskeyEcdsaExportField(restore.signingRootId, 'signingRootId'),
    signingRootVersion: requirePasskeyEcdsaExportField(
      restore.signingRootVersion,
      'signingRootVersion',
    ),
    participantIds: requirePasskeyEcdsaExportParticipants(restore.participantIds),
  };
}

function emailOtpPublicReauthAuthorityForExportLane(
  exportLane: ExactEcdsaExportLane,
): EmailOtpEcdsaPublicReauthExportAuthority | null {
  if (exportLane.session.source !== 'durable_sealed_record') return null;
  const authority = exportLane.session.publicReauthAuthority;
  if (authority.source !== 'email_otp') {
    throw new Error(
      '[SigningEngine][ecdsa-export] Email OTP public reauth lane has non-Email-OTP authority',
    );
  }
  return authority;
}

async function verifiedEcdsaPublicFactsFromPublicReauthAuthority(
  authority: EmailOtpEcdsaPublicReauthExportAuthority,
): Promise<VerifiedEcdsaPublicFacts> {
  return await toVerifiedEcdsaPublicFactsFromDurableRecord({
    record: {
      ecdsaRestore: {
        keyHandle: authority.keyHandle,
        thresholdEcdsaPublicKeyB64u: authority.thresholdEcdsaPublicKeyB64u,
        participantIds: authority.participantIds,
        ethereumAddress: authority.ethereumAddress,
      },
    },
  });
}

export async function resolveFreshEmailOtpEcdsaExportMaterialForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): Promise<FreshEmailOtpEcdsaExportMaterial> {
  if (exportLane.session.authMethod !== 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] fresh Email OTP export requires Email OTP lane');
  }
  const runtimeRecord = readEcdsaExportRecordForLane(deps, exportLane);
  const publicReauthAuthority = emailOtpPublicReauthAuthorityForExportLane(exportLane);
  let sealedRecord: CurrentEcdsaSealedSessionRecord | null = null;
  if (!runtimeRecord && !publicReauthAuthority) {
    sealedRecord = await resolveExactSealedEcdsaExportRecordForLane(exportLane);
  }
  const sealedRestore = sealedRecord?.ecdsaRestore;
  let publicFacts: VerifiedEcdsaPublicFacts;
  if (runtimeRecord) {
    publicFacts = await toVerifiedEcdsaPublicFactsFromRecord({ record: runtimeRecord });
  } else if (publicReauthAuthority) {
    publicFacts = await verifiedEcdsaPublicFactsFromPublicReauthAuthority(publicReauthAuthority);
  } else {
    publicFacts = await toVerifiedEcdsaPublicFactsFromDurableRecord({
      record: {
        ecdsaRestore: {
          keyHandle: sealedRestore?.keyHandle || exportLane.publicFacts.keyHandle,
          thresholdEcdsaPublicKeyB64u: sealedRestore?.thresholdEcdsaPublicKeyB64u,
          participantIds: sealedRestore?.participantIds,
          ethereumAddress: sealedRestore?.ethereumAddress,
        },
      },
    });
  }
  assertMatchingVerifiedEcdsaPublicFacts({
    expected: exportLane.publicFacts,
    actual: publicFacts,
    context: 'fresh Email OTP export lane',
  });
  const runtimePolicyScope =
    runtimeRecord?.runtimePolicyScope ||
    publicReauthAuthority?.runtimePolicyScope ||
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
        authorization: {
          kind: 'record_backed',
          committedLane,
        },
      };
    }
  }
  if (publicReauthAuthority) {
    return {
      kind: 'fresh_email_otp_route_auth_ready',
      chainTarget: exportLane.session.chainTarget,
      publicFacts,
      runtimePolicyScope,
      authorization: {
        kind: 'public_reauth_authority_backed',
        publicReauthAuthority,
      },
    };
  }
  sealedRecord ||= await resolveExactSealedEcdsaExportRecordForLane(exportLane);
  const signingSessionAuthority = emailOtpEcdsaSigningSessionAuthorityFromSealedRecord({
    lane: exportLane.laneIdentity,
    sealedRecord,
  });
  if (!signingSessionAuthority) {
    throw new Error(
      '[SigningEngine][ecdsa-export] exact durable Email OTP signing-session authority is unavailable',
    );
  }
  return {
    kind: 'fresh_email_otp_route_auth_ready',
    chainTarget: exportLane.session.chainTarget,
    publicFacts,
    runtimePolicyScope,
    authorization: {
      kind: 'durable_authority_backed',
      signingSessionAuthority,
    },
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
      publicCapability: runtimeRecord.ecdsaRoleLocalPublicFacts.publicCapability,
      bootstrap: passkeyEcdsaExportBootstrapFromRuntimeRecord(runtimeRecord, exportLane),
    };
  }
  const durableAuthority =
    exportLane.session.source === 'durable_sealed_record'
      ? exportLane.session.publicReauthAuthority
      : null;
  const sealedRecord = durableAuthority
    ? null
    : await resolveExactSealedEcdsaExportRecordForLane(exportLane);
  const restore = durableAuthority || sealedRecord?.ecdsaRestore;
  const relayerUrl = durableAuthority?.relayerUrl || sealedRecord?.relayerUrl;
  if (!restore || restore.source === 'email_otp') {
    throw new Error('[SigningEngine][ecdsa-export] durable passkey export authority is invalid');
  }
  const publicFacts = await toVerifiedEcdsaPublicFactsFromDurableRecord({
    record: {
      ecdsaRestore: {
        keyHandle: restore.keyHandle,
        thresholdEcdsaPublicKeyB64u: restore.thresholdEcdsaPublicKeyB64u,
        participantIds: restore.participantIds,
        ethereumAddress: restore.ethereumAddress,
      },
    },
  });
  assertMatchingVerifiedEcdsaPublicFacts({
    expected: exportLane.publicFacts,
    actual: publicFacts,
    context: 'durable passkey export lane',
  });
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(restore.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error(
      '[SigningEngine][ecdsa-export] durable passkey export requires runtimePolicyScope',
    );
  }
  return {
    kind: 'fresh_passkey_needs_authorization',
    chainTarget: exportLane.session.chainTarget,
    publicFacts,
    runtimePolicyScope,
    publicCapability: restore.publicCapability,
    bootstrap: {
      source: restore.source,
      relayerUrl: requirePasskeyEcdsaExportField(relayerUrl, 'relayerUrl'),
      relayerKeyId: requirePasskeyEcdsaExportField(restore.relayerKeyId, 'relayerKeyId'),
      ecdsaThresholdKeyId: requirePasskeyEcdsaExportField(
        restore.ecdsaThresholdKeyId || exportLane.key.ecdsaThresholdKeyId,
        'ecdsaThresholdKeyId',
      ),
      evmFamilySigningKeySlotId: requirePasskeyEcdsaExportField(
        restore.evmFamilySigningKeySlotId,
        'evmFamilySigningKeySlotId',
      ),
      signingRootId: requirePasskeyEcdsaExportField(restore.signingRootId, 'signingRootId'),
      signingRootVersion: requirePasskeyEcdsaExportField(
        restore.signingRootVersion,
        'signingRootVersion',
      ),
      participantIds: requirePasskeyEcdsaExportParticipants(restore.participantIds),
    },
  };
}
