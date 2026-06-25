import { alphabetizeStringify } from '@shared/utils/digests';
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
  type SigningGrantId,
} from '../operationState/types';

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
};

export type ExactEd25519SigningLaneIdentity = {
  readonly kind: 'exact_signing_lane';
  readonly signer: NearEd25519SignerBinding;
  readonly auth: SigningLaneAuthBinding;
  readonly signingGrantId: SigningGrantId;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
};

export type ExactEcdsaSigningLaneIdentity = {
  readonly kind: 'exact_signing_lane';
  readonly signer: EvmFamilyEcdsaSignerBinding;
  readonly auth: SigningLaneAuthBinding;
  readonly signingGrantId: SigningGrantId;
  readonly thresholdSessionId: ThresholdEcdsaSessionId;
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

export type ExactEd25519SigningLaneIdentityInput = {
  signer: NearEd25519SignerBinding;
  auth: SigningLaneAuthBinding;
  signingGrantId: unknown;
  thresholdSessionId: unknown;
};

export type ExactEcdsaSigningLaneIdentityInput = {
  signer: EvmFamilyEcdsaSignerBinding;
  auth: SigningLaneAuthBinding;
  signingGrantId: unknown;
  thresholdSessionId: unknown;
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
    walletKeyId: key.walletKeyId,
    ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
    signingRootId: key.signingRootId,
    signingRootVersion: key.signingRootVersion,
    participantIds: key.participantIds,
    thresholdOwnerAddress: key.thresholdOwnerAddress,
  });
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
  return {
    kind: 'evm_family_ecdsa_signer',
    walletId: toWalletId(args.walletId),
    chainTarget: args.chainTarget,
    keyHandle: args.keyHandle,
    key: args.key,
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

type CanonicalExactSigningLaneIdentity = {
  kind: 'exact_signing_lane';
  signer:
    | {
        kind: 'near_ed25519_signer';
        account: {
          kind: NearEd25519SignerBinding['account']['kind'];
          walletId: string;
          nearAccountId: string;
        };
        nearEd25519SigningKeyId: string;
        signerSlot: number;
      }
    | {
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
          walletKeyId: string;
          keyScope: EvmFamilyEcdsaKeyIdentity['keyScope'];
          ecdsaThresholdKeyId: string;
          signingRootId: string;
          signingRootVersion: string;
          participantIds: readonly number[];
          thresholdOwnerAddress: string;
        };
      };
  auth: CanonicalSigningLaneAuthBinding;
  signingGrantId: string;
  thresholdSessionId: string;
};

function canonicalChainTarget(target: ThresholdEcdsaChainTarget): Extract<
  CanonicalExactSigningLaneIdentity['signer'],
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
  CanonicalExactSigningLaneIdentity['signer'],
  { kind: 'evm_family_ecdsa_signer' }
>['key'] {
  return {
    walletId: String(key.walletId),
    walletKeyId: String(key.walletKeyId),
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

function canonicalSigner(
  signer: ExactSigningLaneIdentity['signer'],
): CanonicalExactSigningLaneIdentity['signer'] {
  switch (signer.kind) {
    case 'near_ed25519_signer':
      return {
        kind: 'near_ed25519_signer',
        account: {
          kind: signer.account.kind,
          walletId: String(signer.account.wallet.walletId),
          nearAccountId: String(signer.account.nearAccountId),
        },
        nearEd25519SigningKeyId: String(signer.nearEd25519SigningKeyId),
        signerSlot: Number(signer.signerSlot),
      };
    case 'evm_family_ecdsa_signer':
      return {
        kind: 'evm_family_ecdsa_signer',
        walletId: String(signer.walletId),
        keyHandle: String(signer.keyHandle),
        chainTarget: canonicalChainTarget(signer.chainTarget),
        key: canonicalKeyIdentity(signer.key),
      };
    default:
      return assertNeverExactLane(signer);
  }
}

function canonicalExactSigningLaneIdentity(
  identity: ExactSigningLaneIdentity,
): CanonicalExactSigningLaneIdentity {
  return {
    kind: 'exact_signing_lane',
    signer: canonicalSigner(identity.signer),
    auth: canonicalAuthBinding(identity.auth),
    signingGrantId: String(identity.signingGrantId),
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

export function exactEd25519SigningLaneIdentity(
  lane: ExactEd25519SigningLaneIdentityInput,
): ExactEd25519SigningLaneIdentity {
  return {
    kind: 'exact_signing_lane',
    signer: lane.signer,
    auth: lane.auth,
    signingGrantId: SigningSessionIds.signingGrant(lane.signingGrantId),
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
    signingGrantId: SigningSessionIds.signingGrant(lane.signingGrantId),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(lane.thresholdSessionId),
  };
}

export function exactSigningLaneIdentity(
  lane: ExactSigningLaneIdentityInput,
): ExactSigningLaneIdentity {
  const signer = lane.signer;
  switch (signer.kind) {
    case 'near_ed25519_signer':
      return exactEd25519SigningLaneIdentity({
        signer,
        auth: lane.auth,
        signingGrantId: lane.signingGrantId,
        thresholdSessionId: lane.thresholdSessionId,
      });
    case 'evm_family_ecdsa_signer':
      return exactEcdsaSigningLaneIdentity({
        signer,
        auth: lane.auth,
        signingGrantId: lane.signingGrantId,
        thresholdSessionId: lane.thresholdSessionId,
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
        signingGrantId: lane.signingGrantId,
        thresholdSessionId: lane.thresholdSessionId,
      });
    }
    case 'evm_family_ecdsa_signer':
      return exactEcdsaSigningLaneIdentity({
        signer: parseEvmFamilyEcdsaSignerBinding(signerRecord),
        auth,
        signingGrantId: lane.signingGrantId,
        thresholdSessionId: lane.thresholdSessionId,
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

export function exactEcdsaSigningLaneSigner(
  identity: ExactEcdsaSigningLaneIdentity,
): EvmFamilyEcdsaSignerBinding {
  return identity.signer;
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

export function displaySummaryFromExactLane(identity: ExactSigningLaneIdentity): {
  walletId: WalletId;
  curve: ExactSigningLaneCurve;
  signingGrantId: SigningGrantId;
  thresholdSessionId: ThresholdSessionId;
  signerKind: ExactSigningLaneIdentity['signer']['kind'];
} {
  return {
    walletId: exactSigningLaneWalletId(identity),
    curve: exactSigningLaneCurve(identity),
    signingGrantId: identity.signingGrantId,
    thresholdSessionId: identity.thresholdSessionId,
    signerKind: identity.signer.kind,
  };
}

export function exactEd25519SigningLaneSigner(
  identity: ExactEd25519SigningLaneIdentity,
): NearEd25519SignerBinding {
  return identity.signer;
}

export function thresholdSessionIdsFromExactSigningLaneIdentity(
  identity: ExactSigningLaneIdentity,
): NonEmptyThresholdSessionIds {
  return [identity.thresholdSessionId];
}

export function exactSigningLaneIdentityMatches(
  left: ExactSigningLaneIdentity,
  right: ExactSigningLaneIdentity,
): boolean {
  return exactSigningLaneIdentityKey(left) === exactSigningLaneIdentityKey(right);
}
