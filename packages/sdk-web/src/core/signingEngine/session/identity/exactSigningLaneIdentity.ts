import { alphabetizeStringify } from '@shared/utils/digests';
import {
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  isImplicitNearAccountId,
  parseNearAccountId,
  type NearAccountId,
} from '@shared/utils/near';
import {
  buildImplicitNearAccountBinding,
  buildNamedNearAccountBinding,
  buildNearEd25519SignerBinding,
  buildWalletIdentity,
  nearEd25519SignerBindingFromRaw,
  type NearEd25519SignerBinding,
} from '@shared/utils/walletCapabilityBindings';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetFromRequest,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
  WalletId,
} from './evmFamilyEcdsaIdentity';
import type { SelectedEcdsaLane, SelectedEd25519Lane, SelectedLane } from './laneIdentity';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from './evmFamilyEcdsaIdentity';
import type { SigningLaneAuthBinding } from './signingLaneAuthBinding';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import {
  SigningSessionIds,
  type ThresholdEcdsaSessionId,
  type ThresholdEd25519SessionId,
  type ThresholdSessionId,
} from '../operationState/types';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';

export type ExactSigningLaneIdentityKey = string & {
  readonly __brand: 'ExactSigningLaneIdentityKey';
};

export type NonEmptyThresholdSessionIds = readonly [ThresholdSessionId, ...ThresholdSessionId[]];

export type EvmFamilyEcdsaSignerBinding = {
  readonly kind: 'evm_family_ecdsa_signer';
  readonly walletId: WalletId;
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly keyHandle: EvmFamilyEcdsaKeyHandle;
  readonly key: EvmFamilyEcdsaKeyIdentity;
  readonly materialActivation: MpcMaterialActivationRef;
};

export type ExactEd25519SigningLaneIdentity<
  A extends SigningLaneAuthBinding = SigningLaneAuthBinding,
> = {
  readonly kind: 'exact_signing_lane';
  readonly signer: NearEd25519SignerBinding;
  readonly auth: A;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
};

/**
 * Export material is selected before a reusable Wallet Session exists. Keep
 * that carrier separate from the signing identity, whose session and quota
 * fields are required for normal signing authorization.
 */
export type ExactEd25519ExportMaterialIdentity<
  A extends SigningLaneAuthBinding = SigningLaneAuthBinding,
> = {
  readonly kind: 'exact_ed25519_export_material';
  readonly signer: NearEd25519SignerBinding;
  readonly auth: A;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
};

export type ExactEcdsaSigningLaneIdentity = {
  readonly kind: 'exact_signing_lane';
  readonly signer: EvmFamilyEcdsaSignerBinding;
  readonly auth: SigningLaneAuthBinding;
};

export type ExactSigningLaneIdentity =
  | ExactEd25519SigningLaneIdentity
  | ExactEcdsaSigningLaneIdentity;

type ExactSigningLaneIdentityCarrier = {
  readonly identity: ExactSigningLaneIdentity;
};

type ExactEd25519SigningLaneIdentityCarrier = {
  readonly identity: ExactEd25519SigningLaneIdentity;
};

type ExactEcdsaSigningLaneIdentityCarrier = {
  readonly identity: ExactEcdsaSigningLaneIdentity;
};

export type ExactEd25519SigningLaneIdentityInput<
  A extends SigningLaneAuthBinding = SigningLaneAuthBinding,
> = {
  signer: NearEd25519SignerBinding;
  auth: A;
  walletSessionId: unknown;
  quotaId: unknown;
  thresholdSessionId: unknown;
};

export type ExactEd25519ExportMaterialIdentityInput<
  A extends SigningLaneAuthBinding = SigningLaneAuthBinding,
> = {
  signer: NearEd25519SignerBinding;
  auth: A;
  thresholdSessionId: unknown;
};

export type ExactEcdsaSigningLaneIdentityInput = {
  signer: EvmFamilyEcdsaSignerBinding;
  auth: SigningLaneAuthBinding;
};

export type NearEd25519SignerBoundaryFields = {
  walletId: WalletId;
  nearAccountId: NearAccountId | string;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: unknown;
};

type EvmFamilyEcdsaSignerBindingInput = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
  materialActivation: MpcMaterialActivationRef;
};

export type ExactSigningLaneIdentityInput =
  | ExactEd25519SigningLaneIdentityInput
  | ExactEcdsaSigningLaneIdentityInput;

function assertNeverExactLane(value: never): never {
  throw new Error(`[SigningSession] unsupported exact signing lane branch: ${String(value)}`);
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`[SigningSession] ${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`[SigningSession] ${field} is required`);
  }
  return normalized;
}

function rejectPresent(
  record: Record<string, unknown>,
  fields: readonly string[],
  branch: string,
): void {
  for (const field of fields) {
    if (record[field] !== undefined) {
      throw new Error(`[SigningSession] ${branch} exact lane cannot include ${field}`);
    }
  }
}

function parseSigningLaneAuthBinding(value: unknown): SigningLaneAuthBinding {
  const auth = requireRecord(value, 'exact lane auth');
  switch (auth.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        rpId: toRpId(auth.rpId),
        credentialIdB64u: requireString(auth.credentialIdB64u, 'credentialIdB64u'),
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        providerSubjectId: requireString(auth.providerSubjectId, 'providerSubjectId'),
      };
    default:
      throw new Error('[SigningSession] exact lane auth kind is unsupported');
  }
}

function parseExactLaneChainTarget(value: unknown): ThresholdEcdsaChainTarget {
  const target = requireRecord(value, 'ECDSA exact lane chainTarget');
  const parsed = thresholdEcdsaChainTargetFromRequest({
    kind: target.kind,
    namespace: target.namespace,
    chainId: target.chainId,
    networkSlug: target.networkSlug,
  });
  if (target.key != null && String(target.key) !== thresholdEcdsaChainTargetKey(parsed)) {
    throw new Error('[SigningSession] exact ECDSA lane chain target key mismatch');
  }
  return parsed;
}

function parseEvmFamilyEcdsaKeyIdentity(value: unknown): EvmFamilyEcdsaKeyIdentity {
  const key = requireRecord(value, 'ECDSA exact lane key identity');
  if (key.keyScope !== 'evm-family') {
    throw new Error('[SigningSession] exact ECDSA lane keyScope must be evm-family');
  }
  return buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: key.walletId,
    ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
    signingRootId: key.signingRootId,
    signingRootVersion: key.signingRootVersion,
    participantIds: key.participantIds,
    thresholdOwnerAddress: key.thresholdOwnerAddress,
  });
}

function parseExactLaneMaterialActivation(value: unknown): MpcMaterialActivationRef {
  const parsed = parseMpcMaterialActivationRef(value);
  if (!parsed.ok) {
    throw new Error(parsed.error.message);
  }
  return parsed.value;
}

function nearAccountBindingForIdentity(args: {
  walletId: WalletId;
  nearAccountId: NearAccountId | string;
}) {
  const parsedNearAccountId = parseNearAccountId(args.nearAccountId);
  if (!parsedNearAccountId.ok) {
    throw new Error(
      `[SigningSession] invalid exact Ed25519 NEAR account: ${parsedNearAccountId.message}`,
    );
  }
  const wallet = buildWalletIdentity({ walletId: toWalletId(args.walletId) });
  if (isImplicitNearAccountId(parsedNearAccountId.value)) {
    return buildImplicitNearAccountBinding({
      wallet,
      nearAccountId: parsedNearAccountId.value,
    });
  }
  return buildNamedNearAccountBinding({
    wallet,
    nearAccountId: parsedNearAccountId.value,
  });
}

export function nearEd25519SignerBindingFromBoundaryFields(
  input: NearEd25519SignerBoundaryFields,
): NearEd25519SignerBinding {
  const signerSlot = Number(input.signerSlot);
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 1) {
    throw new Error('[SigningSession] exact Ed25519 signer requires signerSlot >= 1');
  }
  return buildNearEd25519SignerBinding({
    account: nearAccountBindingForIdentity({
      walletId: input.walletId,
      nearAccountId: input.nearAccountId,
    }),
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    signerSlot,
  });
}

export function buildEvmFamilyEcdsaSignerBinding(
  args: EvmFamilyEcdsaSignerBindingInput,
): EvmFamilyEcdsaSignerBinding {
  if (String(args.key.walletId) !== String(args.walletId)) {
    throw new Error('[SigningSession] exact ECDSA lane identity wallet mismatch');
  }
  const materialActivation = parseExactLaneMaterialActivation(args.materialActivation);
  if (String(materialActivation.materialOwner) !== String(args.walletId)) {
    throw new Error('[SigningSession] exact ECDSA lane material owner mismatch');
  }
  return {
    kind: 'evm_family_ecdsa_signer',
    walletId: toWalletId(args.walletId),
    chainTarget: args.chainTarget,
    keyHandle: args.keyHandle,
    key: args.key,
    materialActivation,
  };
}

function parseEvmFamilyEcdsaSignerBinding(value: unknown): EvmFamilyEcdsaSignerBinding {
  const signer = requireRecord(value, 'ECDSA exact lane signer');
  if (signer.kind !== 'evm_family_ecdsa_signer') {
    throw new Error('[SigningSession] expected EVM-family ECDSA signer');
  }
  const chainTarget = parseExactLaneChainTarget(signer.chainTarget);
  const key = parseEvmFamilyEcdsaKeyIdentity(signer.key);
  return buildEvmFamilyEcdsaSignerBinding({
    walletId: toWalletId(signer.walletId),
    chainTarget,
    keyHandle: toEvmFamilyEcdsaKeyHandle(signer.keyHandle),
    key,
    materialActivation: parseExactLaneMaterialActivation(signer.materialActivation),
  });
}

type CanonicalSigningLaneAuthBinding =
  | {
      kind: 'passkey';
      rpId: string;
      credentialIdB64u: string;
    }
  | {
      kind: 'email_otp';
      providerSubjectId: string;
    };

type CanonicalEd25519SigningLaneIdentity = {
  kind: 'exact_signing_lane';
  signer: {
    kind: 'near_ed25519_signer';
    account: {
      kind: NearEd25519SignerBinding['account']['kind'];
      walletId: string;
      nearAccountId: string;
    };
    nearEd25519SigningKeyId: string;
    signerSlot: number;
  };
  auth: CanonicalSigningLaneAuthBinding;
  walletSessionId: string;
  quotaId: string;
  thresholdSessionId: string;
};

type CanonicalEcdsaSigningLaneIdentity = {
  kind: 'exact_signing_lane';
  signer: {
        kind: 'evm_family_ecdsa_signer';
        walletId: string;
        keyHandle: string;
        chainTarget: {
          key: string;
          kind: ThresholdEcdsaChainTarget['kind'];
          namespace?: 'eip155';
          chainId: number;
        };
        key: {
          walletId: string;
          keyScope: EvmFamilyEcdsaKeyIdentity['keyScope'];
          ecdsaThresholdKeyId: string;
          signingRootId: string;
          signingRootVersion: string;
          participantIds: readonly number[];
          thresholdOwnerAddress: string;
        };
        materialActivation: {
          kind: 'mpc_material_activation_ref';
          activationId: string;
          capability: string;
          materialOwner: string;
          keyBinding: string;
          lifecycleBinding: string;
          signingWorker: string;
        };
      };
  auth: CanonicalSigningLaneAuthBinding;
};

function canonicalChainTarget(target: ThresholdEcdsaChainTarget): Extract<
  CanonicalEcdsaSigningLaneIdentity['signer'],
  { kind: 'evm_family_ecdsa_signer' }
>['chainTarget'] {
  if (target.kind === 'evm') {
    return {
      key: thresholdEcdsaChainTargetKey(target),
      kind: 'evm',
      namespace: 'eip155',
      chainId: target.chainId,
    };
  }
  return {
    key: thresholdEcdsaChainTargetKey(target),
    kind: 'tempo',
    chainId: target.chainId,
  };
}

function canonicalKeyIdentity(key: EvmFamilyEcdsaKeyIdentity): Extract<
  CanonicalEcdsaSigningLaneIdentity['signer'],
  { kind: 'evm_family_ecdsa_signer' }
>['key'] {
  return {
    walletId: String(key.walletId),
    keyScope: key.keyScope,
    ecdsaThresholdKeyId: String(key.ecdsaThresholdKeyId),
    signingRootId: String(key.signingRootId),
    signingRootVersion: String(key.signingRootVersion),
    participantIds: [...key.participantIds].map((id) => Number(id)),
    thresholdOwnerAddress: String(key.thresholdOwnerAddress).toLowerCase(),
  };
}

function canonicalAuthBinding(auth: SigningLaneAuthBinding): CanonicalSigningLaneAuthBinding {
  switch (auth.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        rpId: String(auth.rpId),
        credentialIdB64u: String(auth.credentialIdB64u),
      };
    case 'email_otp':
      return {
        kind: 'email_otp',
        providerSubjectId: String(auth.providerSubjectId),
      };
    default:
      return assertNeverExactLane(auth);
  }
}

function canonicalSigner(signer: EvmFamilyEcdsaSignerBinding): CanonicalEcdsaSigningLaneIdentity['signer'] {
  return {
        kind: 'evm_family_ecdsa_signer',
        walletId: String(signer.walletId),
        keyHandle: String(signer.keyHandle),
        chainTarget: canonicalChainTarget(signer.chainTarget),
        key: canonicalKeyIdentity(signer.key),
        materialActivation: {
          kind: signer.materialActivation.kind,
          activationId: String(signer.materialActivation.activationId),
          capability: String(signer.materialActivation.capability),
          materialOwner: String(signer.materialActivation.materialOwner),
          keyBinding: String(signer.materialActivation.keyBinding),
          lifecycleBinding: String(signer.materialActivation.lifecycleBinding),
          signingWorker: String(signer.materialActivation.signingWorker),
        },
      };
}

function canonicalExactSigningLaneIdentity(identity: ExactSigningLaneIdentity):
  | CanonicalEd25519SigningLaneIdentity
  | CanonicalEcdsaSigningLaneIdentity {
  if (isExactEcdsaSigningLaneIdentity(identity)) {
    return {
      kind: 'exact_signing_lane',
      signer: canonicalSigner(identity.signer),
      auth: canonicalAuthBinding(identity.auth),
    };
  }
  return {
    kind: 'exact_signing_lane',
    signer: {
      kind: 'near_ed25519_signer',
      account: {
        kind: identity.signer.account.kind,
        walletId: String(identity.signer.account.wallet.walletId),
        nearAccountId: String(identity.signer.account.nearAccountId),
      },
      nearEd25519SigningKeyId: String(identity.signer.nearEd25519SigningKeyId),
      signerSlot: Number(identity.signer.signerSlot),
    },
    auth: canonicalAuthBinding(identity.auth),
    walletSessionId: String(identity.walletSessionId),
    quotaId: String(identity.quotaId),
    thresholdSessionId: String(identity.thresholdSessionId),
  };
}

export function exactSigningLaneIdentityKey(
  identity: ExactSigningLaneIdentity,
): ExactSigningLaneIdentityKey {
  return alphabetizeStringify(
    canonicalExactSigningLaneIdentity(identity),
  ) as ExactSigningLaneIdentityKey;
}

export function deferredEd25519MaterialIdentityKey(input: {
  materialActivation: MpcMaterialActivationRef;
}): ExactSigningLaneIdentityKey {
  return alphabetizeStringify({
    kind: 'deferred_ed25519_material_identity',
    materialActivation: {
      activationId: String(input.materialActivation.activationId),
      capability: String(input.materialActivation.capability),
      materialOwner: String(input.materialActivation.materialOwner),
      keyBinding: String(input.materialActivation.keyBinding),
      lifecycleBinding: String(input.materialActivation.lifecycleBinding),
      signingWorker: String(input.materialActivation.signingWorker),
    },
  }) as ExactSigningLaneIdentityKey;
}

export function exactEd25519SigningLaneIdentity<A extends SigningLaneAuthBinding>(
  lane: ExactEd25519SigningLaneIdentityInput<A>,
): ExactEd25519SigningLaneIdentity<A> {
  return {
    kind: 'exact_signing_lane',
    signer: lane.signer,
    auth: lane.auth,
    walletSessionId: SigningSessionIds.walletSession(lane.walletSessionId),
    quotaId: SigningSessionIds.walletSessionQuota(lane.quotaId),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(lane.thresholdSessionId),
  };
}

export function exactEd25519ExportMaterialIdentity<A extends SigningLaneAuthBinding>(
  lane: ExactEd25519ExportMaterialIdentityInput<A>,
): ExactEd25519ExportMaterialIdentity<A> {
  return {
    kind: 'exact_ed25519_export_material',
    signer: lane.signer,
    auth: lane.auth,
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(lane.thresholdSessionId),
  };
}

export function exactEcdsaSigningLaneIdentity(
  lane: ExactEcdsaSigningLaneIdentityInput,
): ExactEcdsaSigningLaneIdentity {
  return {
    kind: 'exact_signing_lane',
    signer: lane.signer,
    auth: lane.auth,
  };
}

export function exactSigningLaneIdentity(
  lane: ExactSigningLaneIdentityInput,
): ExactSigningLaneIdentity {
  const signer = lane.signer;
  switch (signer.kind) {
    case 'near_ed25519_signer':
      if (
        !('walletSessionId' in lane) ||
        !('quotaId' in lane) ||
        !('thresholdSessionId' in lane)
      ) {
        throw new Error('[SigningSession] Ed25519 exact lane requires session identity');
      }
      return exactEd25519SigningLaneIdentity({
        signer,
        auth: lane.auth,
        walletSessionId: lane.walletSessionId,
        quotaId: lane.quotaId,
        thresholdSessionId: lane.thresholdSessionId,
      });
    case 'evm_family_ecdsa_signer':
      return exactEcdsaSigningLaneIdentity({
        signer,
        auth: lane.auth,
      });
    default:
      return assertNeverExactLane(signer);
  }
}

export function exactSigningLaneIdentityFromSelectedLane(
  lane: SelectedLane | ExactSigningLaneIdentityCarrier,
): ExactSigningLaneIdentity {
  return lane.identity;
}

export function exactEd25519SigningLaneIdentityFromSelectedLane(
  lane: SelectedEd25519Lane | ExactEd25519SigningLaneIdentityCarrier,
): ExactEd25519SigningLaneIdentity {
  return lane.identity;
}

export function exactEcdsaSigningLaneIdentityFromSelectedLane(
  lane: SelectedEcdsaLane | ExactEcdsaSigningLaneIdentityCarrier,
): ExactEcdsaSigningLaneIdentity {
  return lane.identity;
}

export function parseExactEd25519SigningLaneIdentity(
  value: unknown,
): ExactEd25519SigningLaneIdentity {
  const identity = parseExactSigningLaneIdentity(value);
  if (isExactEd25519SigningLaneIdentity(identity)) return identity;
  throw new Error('[SigningSession] expected exact Ed25519 lane identity');
}

export function parseExactEd25519ExportMaterialIdentity(
  value: unknown,
): ExactEd25519ExportMaterialIdentity {
  const lane = requireRecord(value, 'exact Ed25519 export material identity');
  if (lane.kind !== 'exact_ed25519_export_material') {
    throw new Error('[SigningSession] expected exact Ed25519 export material identity');
  }
  rejectPresent(
    lane,
    [
      'walletSessionId',
      'quotaId',
      'walletId',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'chainTarget',
      'keyHandle',
      'key',
      'curve',
      'chainFamily',
      'accountId',
      'subjectId',
      'authMethod',
      'authorization',
    ],
    'nested',
  );
  const signer = nearEd25519SignerBindingFromRaw(
    requireRecord(lane.signer, 'exact Ed25519 export material signer'),
  );
  if (!signer.ok) throw new Error(signer.error.message);
  return exactEd25519ExportMaterialIdentity({
    signer: signer.value,
    auth: parseSigningLaneAuthBinding(lane.auth),
    thresholdSessionId: lane.thresholdSessionId,
  });
}

export function parseExactEcdsaSigningLaneIdentity(value: unknown): ExactEcdsaSigningLaneIdentity {
  const identity = parseExactSigningLaneIdentity(value);
  if (isExactEcdsaSigningLaneIdentity(identity)) return identity;
  throw new Error('[SigningSession] expected exact ECDSA lane identity');
}

export function parseExactSigningLaneIdentity(value: unknown): ExactSigningLaneIdentity {
  const lane = requireRecord(value, 'exact signing lane identity');
  if (lane.kind !== 'exact_signing_lane') {
    throw new Error('[SigningSession] expected exact signing lane identity');
  }
  rejectPresent(
    lane,
    [
      'walletId',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'chainTarget',
      'keyHandle',
      'key',
      'curve',
      'chainFamily',
      'accountId',
      'subjectId',
      'authMethod',
      'authorization',
    ],
    'nested',
  );
  const signerRecord = requireRecord(lane.signer, 'exact lane signer');
  const auth = parseSigningLaneAuthBinding(lane.auth);
  switch (signerRecord.kind) {
    case 'near_ed25519_signer': {
      const signer = nearEd25519SignerBindingFromRaw(signerRecord);
      if (!signer.ok) throw new Error(signer.error.message);
      return exactEd25519SigningLaneIdentity({
        signer: signer.value,
        auth,
        walletSessionId: lane.walletSessionId,
        quotaId: lane.quotaId,
        thresholdSessionId: lane.thresholdSessionId,
      });
    }
    case 'evm_family_ecdsa_signer':
      return exactEcdsaSigningLaneIdentity({
        signer: parseEvmFamilyEcdsaSignerBinding(signerRecord),
        auth,
      });
    default:
      throw new Error('[SigningSession] exact signing lane signer kind is unsupported');
  }
}

export function isExactEd25519SigningLaneIdentity(
  identity: ExactSigningLaneIdentity,
): identity is ExactEd25519SigningLaneIdentity {
  return identity.signer.kind === 'near_ed25519_signer';
}

export function isExactEcdsaSigningLaneIdentity(
  identity: ExactSigningLaneIdentity,
): identity is ExactEcdsaSigningLaneIdentity {
  return identity.signer.kind === 'evm_family_ecdsa_signer';
}

export function exactSigningLaneWalletId(identity: ExactSigningLaneIdentity): WalletId {
  switch (identity.signer.kind) {
    case 'near_ed25519_signer':
      return identity.signer.account.wallet.walletId;
    case 'evm_family_ecdsa_signer':
      return identity.signer.walletId;
    default:
      return assertNeverExactLane(identity.signer);
  }
}

export type ExactSigningLaneCurve = 'ed25519' | 'ecdsa';

export function exactSigningLaneCurve(identity: ExactSigningLaneIdentity): ExactSigningLaneCurve {
  switch (identity.signer.kind) {
    case 'near_ed25519_signer':
      return 'ed25519';
    case 'evm_family_ecdsa_signer':
      return 'ecdsa';
    default:
      return assertNeverExactLane(identity.signer);
  }
}

export function requireEvmFamilyEcdsaSigner(
  identity: ExactSigningLaneIdentity,
  context: string,
): EvmFamilyEcdsaSignerBinding {
  if (identity.signer.kind !== 'evm_family_ecdsa_signer') {
    throw new Error(`[SigningSession] ${context} requires an EVM-family ECDSA signer`);
  }
  return identity.signer;
}

export function requireNearEd25519Signer(
  identity: ExactSigningLaneIdentity,
  context: string,
): NearEd25519SignerBinding {
  if (identity.signer.kind !== 'near_ed25519_signer') {
    throw new Error(`[SigningSession] ${context} requires a NEAR Ed25519 signer`);
  }
  return identity.signer;
}

export type NearProtocolProjection = {
  walletId: WalletId;
  nearAccountId: NearEd25519SignerBinding['account']['nearAccountId'];
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  signerSlot: number;
};

export function nearProtocolProjectionFromExactLane(
  identity: ExactSigningLaneIdentity,
  context = 'NEAR protocol projection',
): NearProtocolProjection {
  const signer = requireNearEd25519Signer(identity, context);
  return {
    walletId: signer.account.wallet.walletId,
    nearAccountId: signer.account.nearAccountId,
    nearEd25519SigningKeyId: signer.nearEd25519SigningKeyId,
    signerSlot: signer.signerSlot,
  };
}

export type EvmFamilyProtocolProjection = {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: EvmFamilyEcdsaKeyHandle;
  key: EvmFamilyEcdsaKeyIdentity;
};

export function evmFamilyProtocolProjectionFromExactLane(
  identity: ExactSigningLaneIdentity,
  context = 'EVM-family protocol projection',
): EvmFamilyProtocolProjection {
  const signer = requireEvmFamilyEcdsaSigner(identity, context);
  return {
    walletId: signer.walletId,
    chainTarget: signer.chainTarget,
    keyHandle: signer.keyHandle,
    key: signer.key,
  };
}

export function thresholdSessionIdsFromExactSigningLaneIdentity(
  identity: ExactSigningLaneIdentity,
): NonEmptyThresholdSessionIds {
  if (isExactEcdsaSigningLaneIdentity(identity)) {
    throw new Error('[SigningSession] ECDSA authorization has no threshold session identity');
  }
  return [identity.thresholdSessionId];
}

export function exactSigningLaneIdentityMatches(
  left: ExactSigningLaneIdentity,
  right: ExactSigningLaneIdentity,
): boolean {
  return exactSigningLaneIdentityKey(left) === exactSigningLaneIdentityKey(right);
}
