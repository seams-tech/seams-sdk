import type { ThresholdEcdsaCanonicalExportArtifact } from '../../interfaces/signing';
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
  type WalletSigningSessionId,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type {
  AvailableEcdsaSigningLane,
  ConcreteAvailableEcdsaSigningLane,
} from '../../session/availability/availableSigningLanes';
import { isConcreteAvailableSigningLane } from '../../session/availability/availableSigningLanes';
import {
  deriveThresholdEcdsaRuntimeLaneKey,
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
import {
  toAuthorizingWalletSigningSessionId,
  type EmailOtpAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EvmFamilySigningTarget } from '../signEvmFamily/types';

export type ExactEcdsaExportLane = {
  curve: 'ecdsa';
  key: EvmFamilyEcdsaKeyIdentity;
  publicFacts: VerifiedEcdsaPublicFacts;
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

export type ReadyThresholdEcdsaExportMaterial = {
  kind: 'ready_threshold_ecdsa_export_material';
  signerSession: ReadyEcdsaSignerSession;
  publicFacts: VerifiedEcdsaPublicFacts;
  record: ThresholdEcdsaSessionRecord;
  cachedExportArtifact: ThresholdEcdsaCanonicalExportArtifact | null;
  evmFamilyKeyFingerprint: EvmFamilyKeyFingerprint;
  ecdsaThresholdKeyId?: never;
  keyRef?: never;
  readyMaterial?: never;
};

export type ReadyEcdsaExportMaterial = ReadyThresholdEcdsaExportMaterial;

type FreshEmailOtpEcdsaExportSubject =
  | {
      authSubjectMode: 'explicit_auth_subject';
      authSubjectId: string;
    }
  | {
      authSubjectMode: 'wallet_session_subject';
      authSubjectId?: never;
    };

export type FreshEmailOtpEcdsaExportMaterialNeedsChallenge =
  FreshEmailOtpEcdsaExportSubject & {
    kind: 'fresh_email_otp_needs_challenge';
    chainTarget: ThresholdEcdsaChainTarget;
    publicFacts: VerifiedEcdsaPublicFacts;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
  };

export type FreshEmailOtpEcdsaExportMaterialRouteAuthReady = {
  kind: 'fresh_email_otp_route_auth_ready';
  chainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  record: ThresholdEcdsaSessionRecord;
  authLane: EmailOtpAuthLane;
};

export type FreshEmailOtpEcdsaExportMaterial =
  | FreshEmailOtpEcdsaExportMaterialNeedsChallenge
  | FreshEmailOtpEcdsaExportMaterialRouteAuthReady;

export type EcdsaExportMaterial = ReadyEcdsaExportMaterial | FreshEmailOtpEcdsaExportMaterial;

type EcdsaExportSessionRecordLookupKey = ThresholdEcdsaSessionRecordKey;

export function ecdsaExportBoundaryChain(lane: ExactEcdsaExportLane): 'evm' | 'tempo' {
  return lane.session.chainTarget.kind;
}

export function ecdsaExportSessionRecordKey(
  lane: ExactEcdsaExportLane,
): EcdsaExportSessionRecordLookupKey {
  return {
    walletId: String(lane.key.walletId),
    keyHandle: String(lane.publicFacts.keyHandle),
    authMethod: lane.session.authMethod,
    curve: 'ecdsa',
    chainTarget: lane.session.chainTarget,
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
    Boolean(String(lane!.publicFacts.keyHandle || '').trim())
  );
}

export function readEcdsaExportRecordForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
): ThresholdEcdsaSessionRecord | null {
  return getThresholdEcdsaSessionRecordByKey(deps, ecdsaExportSessionRecordKey(exportLane));
}

export function buildReadyThresholdEcdsaExportMaterial(args: {
  readyMaterial: ReadyEvmFamilyEcdsaMaterial;
  publicFacts: VerifiedEcdsaPublicFacts;
}): ReadyThresholdEcdsaExportMaterial {
  return {
    kind: 'ready_threshold_ecdsa_export_material',
    signerSession: buildReadyEcdsaSignerSessionFromReadyMaterial({
      material: args.readyMaterial,
      publicFacts: args.publicFacts,
    }),
    publicFacts: args.publicFacts,
    record: args.readyMaterial.record,
    cachedExportArtifact: args.readyMaterial.cachedExportArtifact,
    evmFamilyKeyFingerprint: deriveEvmFamilyKeyFingerprintFromPublicFacts({
      walletId: args.readyMaterial.key.walletId,
      publicFacts: args.publicFacts,
    }),
  };
}

function readReadyEvmFamilyEcdsaMaterialForExportLane(args: {
  deps: EcdsaExportSessionStoreDeps;
  exportLane: ExactEcdsaExportLane;
  rpId: string;
}): ReadyEvmFamilyEcdsaMaterial | null {
  const record = readEcdsaExportRecordForLane(args.deps, args.exportLane);
  if (!record || !isUsableEcdsaExportSessionRecord(record)) return null;
  const cachedExportArtifact =
    args.deps.exportArtifactsByLane.get(deriveThresholdEcdsaRuntimeLaneKey(record)) || null;
  const materialResolution = resolveReadyEvmFamilyEcdsaMaterial({
    record,
    rpId: args.rpId,
    cachedExportArtifact,
    expected: {
      walletId: args.exportLane.key.walletId,
      chainTarget: args.exportLane.session.chainTarget,
      authMethod: args.exportLane.session.authMethod,
      source: record.source,
      thresholdSessionId: args.exportLane.session.thresholdSessionId,
      walletSigningSessionId: args.exportLane.session.walletSigningSessionId,
    },
  });
  if (materialResolution.kind !== 'ready') {
    throw new Error(
      `[SigningEngine][ecdsa-export] ready export material rejected: ${materialResolution.reason.kind}`,
    );
  }
  return materialResolution.material;
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
    const sealedWalletId = String(record.walletId || '').trim();
    const sealedKeyHandle = String(record.ecdsaRestore?.keyHandle || '').trim();
    return (
      walletSigningSessionId === String(exportLane.session.walletSigningSessionId) &&
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
  const authSubjectId = String(runtimeRecord?.emailOtpAuthContext?.authSubjectId || '').trim();
  const runtimePolicyScope =
    runtimeRecord?.runtimePolicyScope ||
    normalizeThresholdRuntimePolicyScope(sealedRestore?.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error(
      '[SigningEngine][ecdsa-export] fresh Email OTP export requires runtimePolicyScope',
    );
  }
  const thresholdSessionAuthToken = String(runtimeRecord?.thresholdSessionAuthToken || '').trim();
  const walletSigningSessionId = String(runtimeRecord?.walletSigningSessionId || '').trim();
  if (runtimeRecord && thresholdSessionAuthToken && walletSigningSessionId) {
    return {
      kind: 'fresh_email_otp_route_auth_ready',
      chainTarget: exportLane.session.chainTarget,
      publicFacts,
      runtimePolicyScope,
      record: runtimeRecord,
      authLane: {
        kind: 'signing_session',
        jwt: thresholdSessionAuthToken,
        thresholdSessionId: runtimeRecord.thresholdSessionId,
        authorizingWalletSigningSessionId:
          toAuthorizingWalletSigningSessionId(walletSigningSessionId),
        curve: 'ecdsa',
        chainTarget: exportLane.session.chainTarget,
      },
    };
  }
  const base = {
    kind: 'fresh_email_otp_needs_challenge' as const,
    chainTarget: exportLane.session.chainTarget,
    publicFacts,
    runtimePolicyScope,
  };
  return authSubjectId
    ? {
        ...base,
        authSubjectMode: 'explicit_auth_subject',
        authSubjectId,
      }
    : {
        ...base,
        authSubjectMode: 'wallet_session_subject',
      };
}

export async function resolveEcdsaExportMaterialForLane(
  deps: EcdsaExportSessionStoreDeps,
  exportLane: ExactEcdsaExportLane,
  rpId: string,
): Promise<EcdsaExportMaterial> {
  const readyMaterial = readReadyEvmFamilyEcdsaMaterialForExportLane({ deps, exportLane, rpId });
  if (readyMaterial) {
    const publicFacts = await toVerifiedEcdsaPublicFactsFromReadyMaterial({
      material: readyMaterial,
    });
    assertMatchingVerifiedEcdsaPublicFacts({
      expected: exportLane.publicFacts,
      actual: publicFacts,
      context: 'ready export lane',
    });
    return buildReadyThresholdEcdsaExportMaterial({
      readyMaterial,
      publicFacts,
    });
  }
  if (exportLane.session.authMethod === 'email_otp') {
    return await resolveFreshEmailOtpEcdsaExportMaterialForLane(deps, exportLane);
  }
  throw new Error(
    `[SigningEngine][ecdsa-export] exact export ready material unavailable for ${ecdsaExportBoundaryChain(exportLane)} ${exportLane.session.authMethod}`,
  );
}
