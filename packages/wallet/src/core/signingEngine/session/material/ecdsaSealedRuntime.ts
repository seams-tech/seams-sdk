import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  CurrentEcdsaSealedSessionRecord,
  EcdsaInactiveSealedMaterialRecord,
} from '../persistence/sealedSessionStore';
import {
  parseEcdsaRoleLocalPersistedMaterialRef,
  type EcdsaClientVerifyingPublicKey33B64u,
  type EcdsaRoleLocalPersistedMaterialRef,
} from '../keyMaterialBrands';
import type { MpcCapabilityHydrationBlockedReason } from './mpcCapabilityHydration';
import type { ActiveEcdsaCapabilityManifest } from './ecdsaCapabilityManifest';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { SigningSessionSealAuthMethod } from '@shared/utils/signingSessionSeal';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';

// The manifest owns the durable capability and material binding. A sealed
// record adds restorable signing-session state for prefill and refresh paths;
// direct authorization can pair the durable capability with live quota facts.
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
      readonly emailHashHex: string;
      readonly emailOtpAuthority: EmailOtpWalletAuthAuthority;
      readonly rpId?: never;
      readonly credentialIdB64u?: never;
    };

/** The exact sealed record this runtime was read from. Carried so callers can
 * write allowance changes back to the same record they resolved. */
export type ExactEcdsaSealedRecordIdentity = {
  readonly storeKey: string;
  readonly thresholdSessionId: string;
  readonly authMethod: SigningSessionSealAuthMethod;
};

export type ExactEcdsaMaterialRuntime = {
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly normalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
  readonly relayerUrl: string;
  readonly relayerKeyId: string;
  readonly clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
  readonly participantIds: readonly [number, number];
  readonly ecdsaThresholdKeyId: string;
  readonly thresholdEcdsaPublicKeyB64u: string;
  readonly keyHandle: string;
  /** Canonical policy scope from the durable capability or its sealed copy.
   * Consumers that require a scoped signing session validate it at use. */
  readonly runtimePolicyScope: RuntimePolicyScope | null;
  /** The durable material this runtime unlocks, in the canonical persisted form
   * the role-local material resolver consumes. */
  readonly roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
  readonly authBinding: ExactEcdsaSealedRuntimeAuthBinding;
};

export type ExactEcdsaCapabilityRuntime = Omit<ExactEcdsaMaterialRuntime, 'authBinding'> & {
  readonly kind: 'exact_ecdsa_capability_runtime_v1';
  readonly authBinding?: never;
};

export type ExactEcdsaSealedRuntime = ExactEcdsaMaterialRuntime & {
  readonly kind: 'exact_ecdsa_sealed_runtime_v1';
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly sealedRecord: ExactEcdsaSealedRecordIdentity;
};

/**
 * A durable capability paired with an authenticated exact Wallet Session.
 * Registration has already persisted the role-local material and capability
 * manifest, so immediate signing does not require a separate warm-session
 * envelope. Sealed-session restore remains a distinct source below.
 */
export type ExactEcdsaDirectCapabilityRuntime = ExactEcdsaMaterialRuntime & {
  readonly kind: 'exact_ecdsa_direct_capability_runtime_v1';
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly sealedRecord?: never;
};

export type ExactEcdsaWalletSessionRuntime =
  | ExactEcdsaDirectCapabilityRuntime
  | ExactEcdsaSealedRuntime;

export type ExactInactiveEcdsaMaterialRuntime = ExactEcdsaMaterialRuntime & {
  readonly kind: 'exact_inactive_ecdsa_material_runtime_v1';
  readonly inactiveMaterialRecord: {
    readonly storeKey: string;
    readonly authMethod: SigningSessionSealAuthMethod;
    readonly authorizationRetirementReason: 'expired' | 'exhausted';
  };
  readonly expiresAtMs?: never;
  readonly remainingUses?: never;
  readonly sealedRecord?: never;
  readonly thresholdSessionId?: never;
  readonly authorization?: never;
};

export type ExactEcdsaSealedRuntimeResolution =
  | {
      readonly kind: 'resolved';
      readonly runtime: ExactEcdsaSealedRuntime;
      readonly reason?: never;
    }
  | {
      readonly kind: 'blocked';
      readonly reason: Extract<
        MpcCapabilityHydrationBlockedReason,
        'missing_material' | 'binding_mismatch' | 'exact_record_conflict' | 'corrupt'
      >;
      readonly runtime?: never;
    };

export type ExactInactiveEcdsaMaterialRuntimeResolution =
  | {
      readonly kind: 'resolved';
      readonly runtime: ExactInactiveEcdsaMaterialRuntime;
      readonly reason?: never;
    }
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

function authMethodForEcdsaSealedSource(
  source: ExactEcdsaMaterialRecord['ecdsaRestore']['source'],
): ExactEcdsaSealedRecordIdentity['authMethod'] {
  switch (source) {
    case 'email_otp':
      return 'email_otp';
    case 'login':
    case 'registration':
    case 'manual-bootstrap':
      return 'passkey';
    default:
      source satisfies never;
      throw new Error('[SigningEngine] unsupported sealed ECDSA source');
  }
}

function normalizedNonEmpty(value: unknown): string {
  return String(value ?? '').trim();
}

type ExactEcdsaMaterialRecord = CurrentEcdsaSealedSessionRecord | EcdsaInactiveSealedMaterialRecord;

type ExactEcdsaMaterialRestore = ExactEcdsaMaterialRecord['ecdsaRestore'];

/** Exact match on stable material identity. Rotating session and grant
 * identifiers deliberately take no part: they change under a reusable Wallet
 * Session without changing which material this record describes. */
function sealedRecordNamesManifestMaterial(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly record: ExactEcdsaMaterialRecord;
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
  return (
    normalizedNonEmpty(restore.roleLocalMaterialRef.durableMaterialRef) ===
    normalizedNonEmpty(durable.durableMaterialRef)
  );
}

function canonicalValuesEqual(left: unknown, right: unknown): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

function participantIdsEqual(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function authorityRefsEqual(
  left: ExactEcdsaMaterialRestore['authority'],
  right: ActiveEcdsaCapabilityManifest['signer']['authority'],
): boolean {
  return (
    left.kind === right.kind &&
    String(left.walletId) === String(right.walletId) &&
    String(left.authorityDigest) === String(right.authorityDigest)
  );
}

function manifestIncludesTarget(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly chainTarget: ThresholdEcdsaChainTarget;
}): boolean {
  return args.manifest.signer.scope.targetMemberships.some((target) =>
    thresholdEcdsaChainTargetsEqual(target, args.chainTarget),
  );
}

function sealedRecordBindsManifestFacts(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly record: ExactEcdsaMaterialRecord;
}): boolean {
  const restore = args.record.ecdsaRestore;
  const durable = args.manifest.durableMaterial;
  const binding = durable.roleLocalBinding;
  const publicFacts = durable.roleLocalPublicFacts;
  const normalScope = restore.routerAbEcdsaDerivationNormalSigning.scope;
  const expectedAuthMethod = authMethodForEcdsaSealedSource(restore.source);
  const resolvedThresholdKeyId =
    normalizedNonEmpty(restore.ecdsaThresholdKeyId) ||
    normalizedNonEmpty(normalScope.ecdsa_threshold_key_id);
  const resolvedClientVerifyingShare =
    'recordKind' in args.record
      ? normalizedNonEmpty(binding.clientVerifyingPublicKey33B64u)
      : normalizedNonEmpty(restore.clientVerifyingShareB64u) ||
        normalizedNonEmpty(normalScope.public_identity.derivation_client_share_public_key33_b64u);
  const resolvedThresholdPublicKey =
    normalizedNonEmpty(restore.thresholdEcdsaPublicKeyB64u) ||
    normalizedNonEmpty(normalScope.public_identity.threshold_public_key33_b64u);

  return (
    String(args.manifest.signer.walletId) === String(args.walletId) &&
    String(publicFacts.walletId) === String(args.walletId) &&
    manifestIncludesTarget(args) &&
    args.record.authMethod === expectedAuthMethod &&
    authorityRefsEqual(restore.authority, args.manifest.signer.authority) &&
    normalizedNonEmpty(restore.roleLocalMaterialRef.bindingDigest) ===
      normalizedNonEmpty(durable.bindingDigest) &&
    normalizedNonEmpty(restore.keyHandle) === normalizedNonEmpty(binding.keyHandle) &&
    normalizedNonEmpty(restore.keyHandle) === normalizedNonEmpty(publicFacts.keyHandle) &&
    resolvedThresholdKeyId === normalizedNonEmpty(binding.ecdsaThresholdKeyId) &&
    resolvedThresholdKeyId === normalizedNonEmpty(publicFacts.ecdsaThresholdKeyId) &&
    resolvedClientVerifyingShare === normalizedNonEmpty(binding.clientVerifyingPublicKey33B64u) &&
    resolvedClientVerifyingShare ===
      normalizedNonEmpty(publicFacts.derivationClientSharePublicKey33B64u) &&
    resolvedThresholdPublicKey === normalizedNonEmpty(publicFacts.groupPublicKey33B64u) &&
    normalizedNonEmpty(restore.relayerKeyId) === normalizedNonEmpty(binding.relayerKeyId) &&
    participantIdsEqual(restore.participantIds, binding.participantIds) &&
    participantIdsEqual(restore.participantIds, publicFacts.participantIds) &&
    normalizedNonEmpty(restore.signingRootId) ===
      normalizedNonEmpty(args.manifest.signer.signingRootId) &&
    normalizedNonEmpty(restore.signingRootId) === normalizedNonEmpty(publicFacts.signingRootId) &&
    normalizedNonEmpty(restore.signingRootVersion) ===
      normalizedNonEmpty(args.manifest.signer.signingRootVersion) &&
    normalizedNonEmpty(restore.signingRootVersion) ===
      normalizedNonEmpty(publicFacts.signingRootVersion) &&
    normalizedNonEmpty(restore.ethereumAddress).toLowerCase() ===
      normalizedNonEmpty(publicFacts.ethereumAddress).toLowerCase() &&
    canonicalValuesEqual(restore.publicCapability, publicFacts.publicCapability) &&
    canonicalValuesEqual(normalScope, {
      wallet_id: String(args.walletId),
      ecdsa_threshold_key_id: String(publicFacts.ecdsaThresholdKeyId),
      signing_root_id: String(publicFacts.signingRootId),
      signing_root_version: String(publicFacts.signingRootVersion),
      context: publicFacts.publicCapability.context,
      public_identity: publicFacts.publicCapability.public_identity,
      signing_worker: publicFacts.publicCapability.signer_set.selected_server,
      activation_epoch: publicFacts.publicCapability.activation_epoch,
      material_activation: routerAbMpcMaterialActivationRefToWire(durable.materialActivation),
    })
  );
}

function authBindingFromRestore(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly restore: ExactEcdsaMaterialRestore;
}): ExactEcdsaSealedRuntimeAuthBinding | null {
  const restore = args.restore;
  if (restore.source === 'email_otp') {
    const providerSubjectId = normalizedNonEmpty(restore.providerSubjectId);
    const emailHashHex = normalizedNonEmpty(restore.emailHashHex);
    const sealedAuthority = restore.emailOtpAuthority;
    const manifestAuthority = args.manifest.signer.authority;
    if (
      !providerSubjectId ||
      !emailHashHex ||
      !sealedAuthority ||
      String(sealedAuthority.walletId) !== String(manifestAuthority.walletId) ||
      String(sealedAuthority.factor.providerUserId) !== providerSubjectId ||
      String(sealedAuthority.verifier.emailHashHex) !== emailHashHex
    ) {
      return null;
    }
    // The sealed record predates the V2 authority binding and may carry the
    // deterministic pre-method id. The manifest is the correlated durable
    // authority, so its method id is the only one valid for a new proof.
    const emailOtpAuthority: EmailOtpWalletAuthAuthority = {
      walletId: sealedAuthority.walletId,
      factor: sealedAuthority.factor,
      verifier: sealedAuthority.verifier,
      bindingId: manifestAuthority.walletAuthMethodId,
    };
    return { kind: 'email_otp', providerSubjectId, emailHashHex, emailOtpAuthority };
  }
  const rpId = normalizedNonEmpty(restore.rpId);
  const credentialIdB64u = normalizedNonEmpty(restore.credentialIdB64u);
  return rpId && credentialIdB64u ? { kind: 'passkey', rpId, credentialIdB64u } : null;
}

function exactTwoPartyParticipantIds(value: readonly number[]): readonly [number, number] | null {
  if (value.length !== 2) return null;
  const first = value[0];
  const second = value[1];
  if (
    !Number.isSafeInteger(first) ||
    !Number.isSafeInteger(second) ||
    first <= 0 ||
    second <= 0 ||
    first === second
  ) {
    return null;
  }
  return [first, second];
}

function materialRuntimeFromRecord(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly record: ExactEcdsaMaterialRecord;
}): ExactEcdsaMaterialRuntime | null {
  const restore = args.record.ecdsaRestore;
  const authBinding = authBindingFromRestore({ manifest: args.manifest, restore });
  const relayerUrl = normalizedNonEmpty(args.record.relayerUrl).replace(/\/+$/g, '');
  const relayerKeyId = normalizedNonEmpty(restore.relayerKeyId);
  const clientVerifyingPublicKey33B64u =
    args.manifest.durableMaterial.roleLocalBinding.clientVerifyingPublicKey33B64u;
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
    ? exactTwoPartyParticipantIds(restore.participantIds)
    : null;
  // Parsed through the production boundary parser: a sealed ref that cannot
  // become canonical persisted material makes the whole runtime corrupt.
  let roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
  try {
    roleLocalMaterialRef = parseEcdsaRoleLocalPersistedMaterialRef(restore.roleLocalMaterialRef);
  } catch {
    return null;
  }
  let runtimePolicyScope: RuntimePolicyScope | null = null;
  try {
    runtimePolicyScope = normalizeRuntimePolicyScope(restore.runtimePolicyScope);
  } catch {
    runtimePolicyScope = null;
  }
  if (
    !authBinding ||
    !relayerUrl ||
    !relayerKeyId ||
    !clientVerifyingPublicKey33B64u ||
    !ecdsaThresholdKeyId ||
    !thresholdEcdsaPublicKeyB64u ||
    !keyHandle ||
    !participantIds
  ) {
    return null;
  }
  return {
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    materialActivation: restore.roleLocalMaterialRef.materialActivation,
    normalSigning: restore.routerAbEcdsaDerivationNormalSigning,
    relayerUrl,
    relayerKeyId,
    clientVerifyingPublicKey33B64u,
    participantIds,
    ecdsaThresholdKeyId,
    thresholdEcdsaPublicKeyB64u,
    keyHandle,
    runtimePolicyScope,
    roleLocalMaterialRef,
    authBinding,
  };
}

function runtimeFromSealedRecord(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly record: CurrentEcdsaSealedSessionRecord;
}): ExactEcdsaSealedRuntime | null {
  const materialRuntime = materialRuntimeFromRecord(args);
  const expiresAtMs = Number(args.record.expiresAtMs);
  const remainingUses = Number(args.record.remainingUses);
  const thresholdSessionId = normalizedNonEmpty(args.record.thresholdSessionIds.ecdsa);
  const storeKey = normalizedNonEmpty(args.record.storeKey);
  if (
    !materialRuntime ||
    !storeKey ||
    !thresholdSessionId ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= 0 ||
    !Number.isSafeInteger(remainingUses) ||
    remainingUses < 0
  ) {
    return null;
  }
  return {
    ...materialRuntime,
    kind: 'exact_ecdsa_sealed_runtime_v1',
    expiresAtMs,
    remainingUses,
    sealedRecord: {
      storeKey,
      thresholdSessionId,
      authMethod: args.record.authMethod,
    },
  };
}

function runtimeFromInactiveMaterialRecord(args: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly record: EcdsaInactiveSealedMaterialRecord;
}): ExactInactiveEcdsaMaterialRuntime | null {
  const materialRuntime = materialRuntimeFromRecord(args);
  const storeKey = normalizedNonEmpty(args.record.storeKey);
  if (!materialRuntime || !storeKey) return null;
  return {
    ...materialRuntime,
    kind: 'exact_inactive_ecdsa_material_runtime_v1',
    inactiveMaterialRecord: {
      storeKey,
      authMethod: args.record.authMethod,
      authorizationRetirementReason: args.record.authorizationRetirementReason,
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
    sealedRecordNamesManifestMaterial({
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
    manifest: input.manifest,
    walletId: input.walletId,
    chainTarget: input.chainTarget,
    record: matches[0]!,
  });
  if (!runtime) return blocked('corrupt');
  if (
    !sealedRecordBindsManifestFacts({
      manifest: input.manifest,
      walletId: input.walletId,
      chainTarget: input.chainTarget,
      record: matches[0]!,
    })
  ) {
    return blocked('binding_mismatch');
  }
  return { kind: 'resolved', runtime };
}

export function resolveExactInactiveEcdsaMaterialRuntime(input: {
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly authMethod: SigningSessionSealAuthMethod;
  readonly inactiveRecords: readonly EcdsaInactiveSealedMaterialRecord[];
}): ExactInactiveEcdsaMaterialRuntimeResolution {
  const matches = input.inactiveRecords.filter(
    (record) =>
      record.authMethod === input.authMethod &&
      sealedRecordNamesManifestMaterial({
        manifest: input.manifest,
        walletId: input.walletId,
        chainTarget: input.chainTarget,
        record,
      }),
  );
  if (matches.length === 0) return { kind: 'blocked', reason: 'missing_material' };
  if (matches.length > 1) return { kind: 'blocked', reason: 'exact_record_conflict' };
  const record = matches[0]!;
  const runtime = runtimeFromInactiveMaterialRecord({
    manifest: input.manifest,
    walletId: input.walletId,
    chainTarget: input.chainTarget,
    record,
  });
  if (!runtime) return { kind: 'blocked', reason: 'corrupt' };
  if (
    !sealedRecordBindsManifestFacts({
      manifest: input.manifest,
      walletId: input.walletId,
      chainTarget: input.chainTarget,
      record,
    })
  ) {
    return { kind: 'blocked', reason: 'binding_mismatch' };
  }
  return { kind: 'resolved', runtime };
}
