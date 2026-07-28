import { mpcMaterialActivationRefsEqual, type MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { CurrentEcdsaSealedSessionRecord } from '../persistence/sealedSessionStore';
import {
  parseEcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalPersistedMaterialRef,
} from '../keyMaterialBrands';
import type { MpcCapabilityHydrationBlockedReason } from './mpcCapabilityHydration';
import type { ActiveEcdsaCapabilityManifest } from './ecdsaCapabilityManifest';

// The manifest and the sealed store own complementary halves of one capability:
// the manifest selects the exact capability, its public facts, and the material
// activation; the sealed record supplies the session-scoped runtime state that
// signing needs (normal-signing scope, transport identity, current allowance).
// Prefill, Email OTP refresh, and provisioning each need the same correlation,
// so it lives here once.
//
// Material is identified by materialActivation. A threshold-session id is
// runtime state carried on the result, never a key used to find it.

export type ExactEcdsaSealedRuntimeAuthBinding =
  | {
      readonly kind: 'passkey';
      readonly rpId: string;
      readonly credentialIdB64u: string;
      readonly providerSubjectId?: never;
    }
  | {
      readonly kind: 'email_otp';
      readonly providerSubjectId: string;
      readonly rpId?: never;
      readonly credentialIdB64u?: never;
    };

/** The exact sealed record this runtime was read from. Carried so callers can
 * write allowance changes back to the same record they resolved. */
export type ExactEcdsaSealedRecordIdentity = {
  readonly storeKey: string;
  readonly thresholdSessionId: string;
  readonly authMethod: 'passkey' | 'email_otp';
};

export type ExactEcdsaSealedRuntime = {
  readonly kind: 'exact_ecdsa_sealed_runtime_v1';
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  readonly relayerUrl: string;
  readonly relayerKeyId: string;
  readonly clientVerifyingShareB64u: string;
  readonly participantIds: readonly number[];
  readonly ecdsaThresholdKeyId: string;
  readonly thresholdEcdsaPublicKeyB64u: string;
  readonly keyHandle: string;
  /** The durable material this runtime unlocks, in the canonical persisted form
   * the role-local material resolver consumes. */
  readonly roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
  readonly authBinding: ExactEcdsaSealedRuntimeAuthBinding;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly sealedRecord: ExactEcdsaSealedRecordIdentity;
};

export type ExactEcdsaSealedRuntimeResolution =
  | { readonly kind: 'resolved'; readonly runtime: ExactEcdsaSealedRuntime; readonly reason?: never }
  | {
      readonly kind: 'blocked';
      readonly reason: Extract<
        MpcCapabilityHydrationBlockedReason,
        'missing_material' | 'binding_mismatch' | 'exact_record_conflict' | 'corrupt'
      >;
      readonly runtime?: never;
    };

function blocked(
  reason: Extract<ExactEcdsaSealedRuntimeResolution, { kind: 'blocked' }>['reason'],
): ExactEcdsaSealedRuntimeResolution {
  return { kind: 'blocked', reason };
}

function normalizedNonEmpty(value: unknown): string {
  return String(value ?? '').trim();
}

/** Exact match on stable material identity. Rotating session and grant
 * identifiers deliberately take no part: they change under a reusable Wallet
 * Session without changing which material this record describes. */
function sealedRecordBindsManifestMaterial(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly record: CurrentEcdsaSealedSessionRecord;
}): boolean {
  const restore = args.record.ecdsaRestore;
  const durable = args.manifest.durableMaterial;
  if (normalizedNonEmpty(args.record.walletId) !== String(args.walletId)) return false;
  if (!thresholdEcdsaChainTargetsEqual(restore.chainTarget, args.chainTarget)) return false;
  if (
    !mpcMaterialActivationRefsEqual(
      restore.roleLocalMaterialRef.materialActivation,
      durable.materialActivation,
    )
  ) {
    return false;
  }
  if (
    !mpcMaterialActivationRefsEqual(
      durable.materialActivation,
      args.manifest.activation.materialActivation,
    )
  ) {
    return false;
  }
  if (normalizedNonEmpty(restore.keyHandle) !== normalizedNonEmpty(durable.roleLocalPublicFacts.keyHandle)) {
    return false;
  }
  return (
    normalizedNonEmpty(restore.roleLocalMaterialRef.durableMaterialRef) ===
    normalizedNonEmpty(durable.durableMaterialRef)
  );
}

function authBindingFromRestore(
  restore: CurrentEcdsaSealedSessionRecord['ecdsaRestore'],
): ExactEcdsaSealedRuntimeAuthBinding | null {
  if (restore.source === 'email_otp') {
    const providerSubjectId = normalizedNonEmpty(restore.providerSubjectId);
    return providerSubjectId ? { kind: 'email_otp', providerSubjectId } : null;
  }
  const rpId = normalizedNonEmpty(restore.rpId);
  const credentialIdB64u = normalizedNonEmpty(restore.credentialIdB64u);
  return rpId && credentialIdB64u ? { kind: 'passkey', rpId, credentialIdB64u } : null;
}

function runtimeFromSealedRecord(args: {
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly record: CurrentEcdsaSealedSessionRecord;
}): ExactEcdsaSealedRuntime | null {
  const restore = args.record.ecdsaRestore;
  const authBinding = authBindingFromRestore(restore);
  const relayerUrl = normalizedNonEmpty(args.record.relayerUrl).replace(/\/+$/g, '');
  const relayerKeyId = normalizedNonEmpty(restore.relayerKeyId);
  const clientVerifyingShareB64u =
    normalizedNonEmpty(restore.clientVerifyingShareB64u) ||
    normalizedNonEmpty(
      restore.routerAbEcdsaDerivationNormalSigning.scope.public_identity
        .derivation_client_share_public_key33_b64u,
    );
  const ecdsaThresholdKeyId =
    normalizedNonEmpty(restore.ecdsaThresholdKeyId) ||
    normalizedNonEmpty(restore.routerAbEcdsaDerivationNormalSigning.scope.ecdsa_threshold_key_id);
  const thresholdEcdsaPublicKeyB64u =
    normalizedNonEmpty(restore.thresholdEcdsaPublicKeyB64u) ||
    normalizedNonEmpty(
      restore.routerAbEcdsaDerivationNormalSigning.scope.public_identity
        .threshold_public_key33_b64u,
    );
  const keyHandle = normalizedNonEmpty(restore.keyHandle);
  const participantIds = Array.isArray(restore.participantIds)
    ? restore.participantIds.filter((value) => Number.isSafeInteger(value))
    : [];
  const expiresAtMs = Math.floor(Number(args.record.expiresAtMs));
  const remainingUses = Math.floor(Number(args.record.remainingUses));
  const thresholdSessionId = normalizedNonEmpty(args.record.thresholdSessionIds?.ecdsa);
  const storeKey = normalizedNonEmpty(args.record.storeKey);
  // Parsed through the production boundary parser: a sealed ref that cannot
  // become canonical persisted material makes the whole runtime corrupt.
  let roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
  try {
    roleLocalMaterialRef = parseEcdsaRoleLocalPersistedMaterialRef(restore.roleLocalMaterialRef);
  } catch {
    return null;
  }
  if (
    !authBinding ||
    !relayerUrl ||
    !relayerKeyId ||
    !clientVerifyingShareB64u ||
    !ecdsaThresholdKeyId ||
    !thresholdEcdsaPublicKeyB64u ||
    !keyHandle ||
    !storeKey ||
    !thresholdSessionId ||
    participantIds.length === 0 ||
    !Number.isSafeInteger(expiresAtMs) ||
    !Number.isSafeInteger(remainingUses)
  ) {
    return null;
  }
  return {
    kind: 'exact_ecdsa_sealed_runtime_v1',
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    materialActivation: restore.roleLocalMaterialRef.materialActivation,
    normalSigning: restore.routerAbEcdsaDerivationNormalSigning,
    relayerUrl,
    relayerKeyId,
    clientVerifyingShareB64u,
    participantIds,
    ecdsaThresholdKeyId,
    thresholdEcdsaPublicKeyB64u,
    keyHandle,
    roleLocalMaterialRef,
    authBinding,
    expiresAtMs,
    remainingUses,
    sealedRecord: {
      storeKey,
      thresholdSessionId,
      authMethod: restore.source === 'email_otp' ? 'email_otp' : 'passkey',
    },
  };
}

export function resolveExactEcdsaSealedRuntime(input: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly sealedRecords: readonly CurrentEcdsaSealedSessionRecord[];
}): ExactEcdsaSealedRuntimeResolution {
  const matches = input.sealedRecords.filter((record) =>
    sealedRecordBindsManifestMaterial({
      manifest: input.manifest,
      walletId: input.walletId,
      chainTarget: input.chainTarget,
      record,
    }),
  );
  if (matches.length === 0) return blocked('missing_material');
  // Two sealed records claiming one material activation is a store conflict,
  // not a preference: fail closed rather than pick a winner.
  if (matches.length > 1) return blocked('exact_record_conflict');
  const runtime = runtimeFromSealedRecord({
    walletId: input.walletId,
    chainTarget: input.chainTarget,
    record: matches[0]!,
  });
  return runtime ? { kind: 'resolved', runtime } : blocked('corrupt');
}
