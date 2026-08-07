import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '../signing-lanes/ids';
import { parseLaneShareEpoch, parseSigningLaneId, parseWalletKeyId } from '../signing-lanes/ids';
import type { EvmFamilySigningKeySlotId } from '../signing-lanes/evmFamilySigningKeySlotId';
import { requireEvmFamilySigningKeySlotId } from '../signing-lanes/evmFamilySigningKeySlotId';
import type { ThresholdEcdsaSessionId } from '../utils/domainIds';
import { parseThresholdEcdsaSessionId } from '../utils/domainIds';
import type { NearEd25519SigningKeyId } from '../utils/registrationIntent';
import { parseNearEd25519SigningKeyId } from '../utils/registrationIntent';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import type { Ed25519PublicKeyB64u, Secp256k1CompressedPublicKeyB64u } from './primitives';
import {
  parseDigestField,
  parseEd25519PublicKeyB64u,
  parseSecp256k1CompressedPublicKeyB64u,
  rejectUnknownFields,
  requireRecord,
} from './primitives';

/**
 * The protocol capability an opened envelope restores.
 *
 * Owner custody is one wallet-scoped seed: every owner signing root derives
 * from it in parallel, so there is nothing per-curve to seal separately. Lane
 * holder shares stay per-lane because Refactor 102 provisions them
 * individually — they are not seed-derived.
 */
export type PasskeyCustodySecretKind =
  | 'wallet_custody_seed_v1'
  | 'ed25519_lane_holder_share_v1'
  | 'ecdsa_lane_holder_share_v1';

/** The only derivation scheme owner custody supports. */
export const WALLET_SEED_DERIVATION_SCHEME_V1 = 'wallet_seed_parallel_hkdf_sha256_v1' as const;
export type WalletSeedDerivationScheme = typeof WALLET_SEED_DERIVATION_SCHEME_V1;

export type PasskeyCustodySecretBinding =
  | {
      /**
       * One random seed per wallet. Every owner signing root derives from it in
       * parallel with domain-separated HKDF; no signing root is ever derived
       * from another signing root. Each enrolled factor wraps this same seed,
       * which is what makes passkey and Email OTP interchangeable.
       *
       * Wallet-scoped by construction: it carries no lane identity, because it
       * covers every owner key rather than one lane's material.
       *
       * It names no key set either. Key sets are provisioned independently — an
       * EVM wallet today, NEAR later — and each records its own manifest on its
       * own registration state. A seed that named its key sets would have to be
       * resealed, and its recovery codes rewrapped, every time one arrived.
       */
      kind: 'wallet_custody_seed_v1';
      derivationScheme: WalletSeedDerivationScheme;
      keyManifestDigestB64u?: never;
      nearEd25519SigningKeyId?: never;
      registeredPublicKeyB64u?: never;
      evmFamilySigningKeySlotId?: never;
      clientRootPublicKey33B64u?: never;
      walletKeyId?: never;
      laneId?: never;
      laneShareEpoch?: never;
      participantBindingDigestB64u?: never;
      thresholdSessionId?: never;
      thresholdPublicKey33B64u?: never;
    }
  | {
      kind: 'ed25519_lane_holder_share_v1';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      nearEd25519SigningKeyId: NearEd25519SigningKeyId;
      registeredPublicKeyB64u: Ed25519PublicKeyB64u;
      participantBindingDigestB64u: DigestB64u;
      derivationScheme?: never;
      keyManifestDigestB64u?: never;
      evmFamilySigningKeySlotId?: never;
      clientRootPublicKey33B64u?: never;
      thresholdSessionId?: never;
      thresholdPublicKey33B64u?: never;
    }
  | {
      kind: 'ecdsa_lane_holder_share_v1';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
      // Curve-local protocol-session binding only. It may rotate with the
      // threshold protocol and is never a durable key, lane, material, or
      // authorization identity, and never replaces MpcMaterialActivationRef.
      thresholdSessionId: ThresholdEcdsaSessionId;
      thresholdPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
      derivationScheme?: never;
      keyManifestDigestB64u?: never;
      nearEd25519SigningKeyId?: never;
      registeredPublicKeyB64u?: never;
      participantBindingDigestB64u?: never;
      clientRootPublicKey33B64u?: never;
    };

export type PasskeyCustodySecretBindingOfKind<TKind extends PasskeyCustodySecretKind> = Extract<
  PasskeyCustodySecretBinding,
  { kind: TKind }
>;

/** True when this binding covers owner custody rather than one lane's share. */
export function isWalletCustodySeedBinding(
  binding: PasskeyCustodySecretBinding,
): binding is PasskeyCustodySecretBindingOfKind<'wallet_custody_seed_v1'> {
  return binding.kind === 'wallet_custody_seed_v1';
}

// Builders are branch-specific on purpose: a shared builder plus a spread would
// let one branch's identity fields reach another branch's envelope.

export function buildWalletCustodySeedBinding(): PasskeyCustodySecretBindingOfKind<'wallet_custody_seed_v1'> {
  return {
    kind: 'wallet_custody_seed_v1',
    derivationScheme: WALLET_SEED_DERIVATION_SCHEME_V1,
  };
}

export function buildEd25519LaneHolderShareBinding(args: {
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  registeredPublicKeyB64u: Ed25519PublicKeyB64u;
  participantBindingDigestB64u: DigestB64u;
}): PasskeyCustodySecretBindingOfKind<'ed25519_lane_holder_share_v1'> {
  return {
    kind: 'ed25519_lane_holder_share_v1',
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneShareEpoch: args.laneShareEpoch,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    registeredPublicKeyB64u: args.registeredPublicKeyB64u,
    participantBindingDigestB64u: args.participantBindingDigestB64u,
  };
}

export function buildEcdsaLaneHolderShareBinding(args: {
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  thresholdSessionId: ThresholdEcdsaSessionId;
  thresholdPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
}): PasskeyCustodySecretBindingOfKind<'ecdsa_lane_holder_share_v1'> {
  return {
    kind: 'ecdsa_lane_holder_share_v1',
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneShareEpoch: args.laneShareEpoch,
    evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId,
    thresholdSessionId: args.thresholdSessionId,
    thresholdPublicKey33B64u: args.thresholdPublicKey33B64u,
  };
}

const LANE_SCOPE_FIELDS = ['kind', 'walletKeyId', 'laneId', 'laneShareEpoch'] as const;

const ALLOWED_FIELDS_BY_KIND: Record<PasskeyCustodySecretKind, readonly string[]> = {
  // No lane scope: owner custody is wallet-scoped.
  wallet_custody_seed_v1: ['kind', 'derivationScheme'],
  ed25519_lane_holder_share_v1: [
    ...LANE_SCOPE_FIELDS,
    'nearEd25519SigningKeyId',
    'registeredPublicKeyB64u',
    'participantBindingDigestB64u',
  ],
  ecdsa_lane_holder_share_v1: [
    ...LANE_SCOPE_FIELDS,
    'evmFamilySigningKeySlotId',
    'thresholdSessionId',
    'thresholdPublicKey33B64u',
  ],
};

// Every field that is a legitimate public binding on some branch. A field from
// this set on the wrong branch is a branch mismatch, not a secret leak.
const ALL_BRANCH_FIELDS: readonly string[] = Array.from(
  new Set(Object.values(ALLOWED_FIELDS_BY_KIND).flat()),
);

function requireCustodySecretKind(value: unknown, label: string): PasskeyCustodySecretKind {
  if (
    value === 'wallet_custody_seed_v1' ||
    value === 'ed25519_lane_holder_share_v1' ||
    value === 'ecdsa_lane_holder_share_v1'
  ) {
    return value;
  }
  throw new Error(`${label}.kind must be a known passkey custody secret kind`);
}

type LaneScope = {
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
};

function requireLaneScope(record: Record<string, unknown>, label: string): LaneScope {
  const walletKeyId = parseWalletKeyId(record.walletKeyId);
  if (!walletKeyId.ok) throw new Error(`${label}.walletKeyId ${walletKeyId.error.message}`);
  const laneId = parseSigningLaneId(record.laneId);
  if (!laneId.ok) throw new Error(`${label}.laneId ${laneId.error.message}`);
  const laneShareEpoch = parseLaneShareEpoch(record.laneShareEpoch);
  if (!laneShareEpoch.ok) {
    throw new Error(`${label}.laneShareEpoch ${laneShareEpoch.error.message}`);
  }
  return {
    walletKeyId: walletKeyId.value,
    laneId: laneId.value,
    laneShareEpoch: laneShareEpoch.value,
  };
}

function requireThresholdEcdsaSessionId(value: unknown, label: string): ThresholdEcdsaSessionId {
  const parsed = parseThresholdEcdsaSessionId(value);
  if (!parsed.ok) throw new Error(`${label} ${parsed.error.message}`);
  return parsed.value;
}

/**
 * Parses one raw persistence or wire shape into an exact custody-secret branch.
 * Cross-branch fields, unknown fields, and plaintext-secret fields are rejected
 * rather than dropped, so a mismatched record can never be narrowed into a
 * branch it does not satisfy.
 */
export function parsePasskeyCustodySecretBinding(
  raw: unknown,
  label = 'passkeyCustodySecretBinding',
): PasskeyCustodySecretBinding {
  const record = requireRecord(raw, label);
  const kind = requireCustodySecretKind(record.kind, label);
  rejectUnknownFields(record, ALLOWED_FIELDS_BY_KIND[kind], label, ALL_BRANCH_FIELDS);

  switch (kind) {
    case 'wallet_custody_seed_v1': {
      if (record.derivationScheme !== WALLET_SEED_DERIVATION_SCHEME_V1) {
        throw new Error(`${label}.derivationScheme must be ${WALLET_SEED_DERIVATION_SCHEME_V1}`);
      }
      return buildWalletCustodySeedBinding();
    }
    case 'ed25519_lane_holder_share_v1': {
      const lane = requireLaneScope(record, label);
      return buildEd25519LaneHolderShareBinding({
        walletKeyId: lane.walletKeyId,
        laneId: lane.laneId,
        laneShareEpoch: lane.laneShareEpoch,
        nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(record.nearEd25519SigningKeyId),
        registeredPublicKeyB64u: parseEd25519PublicKeyB64u(
          record.registeredPublicKeyB64u,
          `${label}.registeredPublicKeyB64u`,
        ),
        participantBindingDigestB64u: parseDigestField(
          record.participantBindingDigestB64u,
          `${label}.participantBindingDigestB64u`,
        ),
      });
    }
    case 'ecdsa_lane_holder_share_v1': {
      const lane = requireLaneScope(record, label);
      return buildEcdsaLaneHolderShareBinding({
        walletKeyId: lane.walletKeyId,
        laneId: lane.laneId,
        laneShareEpoch: lane.laneShareEpoch,
        evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
          record.evmFamilySigningKeySlotId,
          `${label}.evmFamilySigningKeySlotId`,
        ),
        thresholdSessionId: requireThresholdEcdsaSessionId(
          record.thresholdSessionId,
          `${label}.thresholdSessionId`,
        ),
        thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
          record.thresholdPublicKey33B64u,
          `${label}.thresholdPublicKey33B64u`,
        ),
      });
    }
  }
}
