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
  type ThresholdEcdsaSessionRecord,
} from '../../session/persistence/records';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from '../../session/warmCapabilities/routerAbEcdsaWalletSessionAuth';
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
import {
  toAuthorizingSigningGrantId,
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
    signingGrantId: SigningGrantId;
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
      signingGrantId: args.exportLane.session.signingGrantId,
    },
  });
  if (materialResolution.kind !== 'ready') {
    const reason =
      materialResolution.reason.kind === 'stale_or_unrestorable_material'
        ? `${materialResolution.reason.kind}:${materialResolution.reason.reason}`
        : materialResolution.reason.kind;
    throw new Error(
      `[SigningEngine][ecdsa-export] ready export material rejected: ${reason}`,
    );
  }
  return materialResolution.material;
}

export function isUsableEcdsaExportSessionRecord(record: ThresholdEcdsaSessionRecord): boolean {
  const remainingUses = Math.floor(Number(record.remainingUses));
  const expiresAtMs = Math.floor(Number(record.expiresAtMs));
  const walletSessionAuth = resolveRouterAbEcdsaWalletSessionAuthFromRecord(record);
  return (
    Number.isFinite(remainingUses) &&
    remainingUses > 0 &&
    (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0 || expiresAtMs > Date.now()) &&
    walletSessionAuth.kind === 'ready'
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
  const authSubjectId = String(
    runtimeRecord?.source === 'email_otp' ? runtimeRecord.emailOtpAuthContext.authSubjectId : '',
  ).trim();
  const runtimePolicyScope =
    runtimeRecord?.runtimePolicyScope ||
    normalizeThresholdRuntimePolicyScope(sealedRestore?.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error(
      '[SigningEngine][ecdsa-export] fresh Email OTP export requires runtimePolicyScope',
    );
  }
  const walletSessionAuth = runtimeRecord
    ? resolveRouterAbEcdsaWalletSessionAuthFromRecord(runtimeRecord)
    : null;
  const signingGrantId = String(runtimeRecord?.signingGrantId || '').trim();
  if (runtimeRecord && walletSessionAuth?.kind === 'ready' && signingGrantId) {
    return {
      kind: 'fresh_email_otp_route_auth_ready',
      chainTarget: exportLane.session.chainTarget,
      publicFacts,
      runtimePolicyScope,
      record: runtimeRecord,
      authLane: {
        kind: 'signing_session',
        jwt: walletSessionAuth.walletSessionJwt,
        thresholdSessionId: runtimeRecord.thresholdSessionId,
        authorizingSigningGrantId:
          toAuthorizingSigningGrantId(signingGrantId),
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
