import { parseSigningLaneRecord, parseWalletKeyRecord } from '@shared/signing-lanes/recordParsers';
import { parseLaneShareEpoch, type LaneShareEpoch } from '@shared/signing-lanes/ids';
import type {
  ActiveSigningLaneReference,
  Ed25519WalletKeyRecord,
  EvmFamilyWalletKeyRecord,
  OwnerLaneParticipantContinuityV1,
  SigningLaneRecord,
  WalletKeyRecord,
} from '@shared/signing-lanes';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  assertLaneHolderParticipantBindingDigestV1,
  assertSigningWorkerParticipantBindingDigestV1,
  computeLaneParticipantSetBindingDigestV1,
} from '@shared/signing-lanes/participantDigest';
import type { LaneParticipantBindingDigestB64u } from '@shared/signing-lanes/participants';
import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import {
  resolveNearEd25519YaoCapabilityHydrationV1,
  type NearEd25519YaoCapabilityHydrationInputV1,
} from '../material/nearEd25519YaoMaterialActivation';
import {
  resolveEcdsaCapabilityHydration,
  type EcdsaCapabilityHydrationInput,
  type EcdsaCapabilityRuntimeObservation,
} from '../material/ecdsaCapabilityHydration';
import type { MpcCapabilityHydrationPlan } from '../material/mpcCapabilityHydration';
import type { EcdsaCapabilityManifestLookup } from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes/evmFamilySigningKeySlotId';

export type WalletExecutionLaneMaterialHydrationInput =
  | {
      readonly keyFamily: 'ed25519';
      /** The lane epoch carried by the exact Yao lane manifest. */
      readonly laneShareEpoch: unknown;
      readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
      readonly hydration: NearEd25519YaoCapabilityHydrationInputV1;
    }
  | {
      readonly keyFamily: 'ecdsa_secp256k1';
      /** The lane epoch carried by the exact ECDSA capability manifest. */
      readonly laneShareEpoch: unknown;
      readonly lookup: EcdsaCapabilityManifestLookup;
      readonly runtime: EcdsaCapabilityRuntimeObservation;
    };

export type WalletExecutionLaneHydrationInput = {
  readonly walletKey: unknown;
  readonly lane: unknown;
  readonly material: WalletExecutionLaneMaterialHydrationInput;
};

export type ParsedWalletExecutionLaneRecords = {
  readonly walletKey: WalletKeyRecord;
  readonly lane: SigningLaneRecord;
};

export type WalletExecutionLaneRefusalReason =
  | 'invalid_boundary_record'
  | 'wallet_key_inactive'
  | 'lane_inactive'
  | 'wallet_key_mismatch'
  | 'key_family_mismatch'
  | 'unsupported_lane_kind'
  | 'share_epoch_mismatch'
  | 'participant_binding_mismatch'
  | 'hydration_blocked'
  | 'material_activation_mismatch'
  | 'public_identity_mismatch'
  | 'activation_receipt_mismatch';

type WalletExecutionLaneRefusalWithoutIdentity = {
  readonly kind: 'wallet_execution_lane_refused_v1';
  readonly reason: 'invalid_boundary_record';
  readonly walletId?: never;
  readonly walletKeyId?: never;
  readonly laneId?: never;
};

export type WalletExecutionLaneRefusal =
  | WalletExecutionLaneRefusalWithoutIdentity
  | {
      readonly kind: 'wallet_execution_lane_refused_v1';
      readonly reason: Exclude<WalletExecutionLaneRefusalReason, 'invalid_boundary_record'>;
      readonly walletId: WalletKeyRecord['walletId'];
      readonly walletKeyId: WalletKeyRecord['walletKeyId'];
      readonly laneId: SigningLaneRecord['laneId'];
    };

export type WalletExecutionLanePublicIdentity =
  | {
      readonly keyFamily: 'ed25519';
      readonly registeredPublicKeyB64u: Ed25519WalletKeyRecord['registeredPublicKeyB64u'];
      readonly nearEd25519SigningKeyId: Ed25519WalletKeyRecord['nearEd25519SigningKeyId'];
      readonly keyCreationSignerSlot: Ed25519WalletKeyRecord['keyCreationSignerSlot'];
    }
  | {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly thresholdPublicKey33B64u: EvmFamilyWalletKeyRecord['thresholdPublicKey33B64u'];
      readonly evmAddress: EvmFamilyWalletKeyRecord['evmAddress'];
      readonly evmFamilySigningKeySlotId: EvmFamilyWalletKeyRecord['evmFamilySigningKeySlotId'];
    };

export type ActiveWalletExecutionLaneHydration = {
  readonly kind: 'active_wallet_execution_lane_v1';
  readonly keyFamily: WalletKeyRecord['keyFamily'];
  readonly walletKey: WalletKeyRecord;
  readonly lane: ActiveSigningLaneReference;
  readonly ownerParticipantContinuity: OwnerLaneParticipantContinuityV1;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly activationReceiptDigestB64u: string;
  readonly publicIdentity: WalletExecutionLanePublicIdentity;
};

export type WalletExecutionLaneHydrationResult =
  | ActiveWalletExecutionLaneHydration
  | WalletExecutionLaneRefusal;

export type RotatableWalletExecutionLaneHydrationInputV1 = {
  readonly walletKey: unknown;
  readonly lane: unknown;
  readonly keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  readonly laneShareEpoch: unknown;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly participantBindingDigestB64u: LaneParticipantBindingDigestB64u;
};

export type ActiveRotatableWalletExecutionLaneHydrationV1 = {
  readonly kind: 'active_rotatable_wallet_execution_lane_v1';
  readonly keyFamily: WalletKeyRecord['keyFamily'];
  readonly walletKey: WalletKeyRecord;
  readonly lane: ActiveSigningLaneReference;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly activationReceiptDigestB64u: string;
  readonly participantBindingDigestB64u: LaneParticipantBindingDigestB64u;
  readonly publicIdentity: WalletExecutionLanePublicIdentity;
};

export type RotatableWalletExecutionLaneHydrationResultV1 =
  | ActiveRotatableWalletExecutionLaneHydrationV1
  | WalletExecutionLaneRefusal;

function parseLaneEpoch(raw: unknown): LaneShareEpoch {
  const parsed = parseLaneShareEpoch(raw);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

/**
 * Parse only the durable boundary records here. Curve-specific material is
 * already parsed by its capability/Yao adapter and is consumed as an exact
 * typed projection below.
 */
export function parseWalletExecutionLaneRecords(
  input: Pick<WalletExecutionLaneHydrationInput, 'walletKey' | 'lane'>,
): ParsedWalletExecutionLaneRecords {
  return {
    walletKey: parseWalletKeyRecord(input.walletKey),
    lane: parseSigningLaneRecord(input.lane),
  };
}

function refusal(
  reason: Exclude<WalletExecutionLaneRefusalReason, 'invalid_boundary_record'>,
  records: ParsedWalletExecutionLaneRecords,
): WalletExecutionLaneRefusal {
  return {
    kind: 'wallet_execution_lane_refused_v1',
    reason,
    walletId: records.walletKey.walletId,
    walletKeyId: records.walletKey.walletKeyId,
    laneId: records.lane.laneId,
  };
}

function invalidBoundaryRefusal(): WalletExecutionLaneRefusal {
  return {
    kind: 'wallet_execution_lane_refused_v1',
    reason: 'invalid_boundary_record',
  };
}

function activeLaneReference(args: {
  lane: SigningLaneRecord;
  materialActivation: MpcMaterialActivationRef;
}): ActiveSigningLaneReference {
  if (args.lane.lifecycle.state !== 'active') {
    throw new Error('active lane reference requires an active lane');
  }
  return {
    kind: 'signing_lane_reference_v1',
    walletId: args.lane.walletId,
    walletKeyId: args.lane.walletKeyId,
    laneId: args.lane.laneId,
    laneKind: args.lane.laneKind,
    laneShareEpoch: args.lane.laneShareEpoch,
    participantBindingDigestB64u: args.lane.participantBindingDigestB64u,
    lifecycle: args.lane.lifecycle,
    materialActivation: args.materialActivation,
  };
}

function ownerParticipantContinuityForLane(
  lane: SigningLaneRecord,
): OwnerLaneParticipantContinuityV1 | null {
  switch (lane.laneKind) {
    case 'owner_passkey':
    case 'owner_email_otp':
    case 'recovery':
    case 'break_glass':
      return lane.ownerParticipantContinuity;
    case 'linked_device':
    case 'delegated_execution':
      return null;
  }
}

function participantIdsMatch(
  ownerParticipantContinuity: OwnerLaneParticipantContinuityV1,
  materialParticipantIds: readonly number[],
): boolean {
  return (
    materialParticipantIds.length === ownerParticipantContinuity.participantIds.length &&
    materialParticipantIds.every(
      (participantId, index) => participantId === ownerParticipantContinuity.participantIds[index],
    )
  );
}

function commonRefusal(
  records: ParsedWalletExecutionLaneRecords,
  material: WalletExecutionLaneMaterialHydrationInput,
): WalletExecutionLaneRefusal | null {
  const { walletKey, lane } = records;
  if (walletKey.lifecycle.state !== 'active') return refusal('wallet_key_inactive', records);
  if (lane.lifecycle.state !== 'active') return refusal('lane_inactive', records);
  if (
    String(walletKey.walletId) !== String(lane.walletId) ||
    String(walletKey.walletKeyId) !== String(lane.walletKeyId)
  ) {
    return refusal('wallet_key_mismatch', records);
  }
  if (walletKey.keyFamily !== material.keyFamily) {
    return refusal('key_family_mismatch', records);
  }
  if (lane.laneKind === 'linked_device' || lane.laneKind === 'delegated_execution') {
    return refusal('unsupported_lane_kind', records);
  }
  const ownerParticipantContinuity = ownerParticipantContinuityForLane(lane);
  if (ownerParticipantContinuity === null) return invalidBoundaryRefusal();
  let materialEpoch: LaneShareEpoch;
  try {
    materialEpoch = parseLaneEpoch(material.laneShareEpoch);
  } catch {
    return invalidBoundaryRefusal();
  }
  if (String(materialEpoch) !== String(lane.laneShareEpoch)) {
    return refusal('share_epoch_mismatch', records);
  }
  if (
    !String(lane.participantBindingDigestB64u) ||
    !String(ownerParticipantContinuity.signerId) ||
    !String(ownerParticipantContinuity.signingWorkerId) ||
    ownerParticipantContinuity.participantIds.length !== 2
  ) {
    return refusal('participant_binding_mismatch', records);
  }
  return null;
}

function isActiveHydrationPlan(
  plan: MpcCapabilityHydrationPlan,
): plan is Extract<
  MpcCapabilityHydrationPlan,
  { kind: 'use_live_runtime' | 'rehydrate_material_activation' }
> {
  return plan.kind === 'use_live_runtime' || plan.kind === 'rehydrate_material_activation';
}

function hydrateEd25519(
  records: ParsedWalletExecutionLaneRecords,
  material: Extract<WalletExecutionLaneMaterialHydrationInput, { keyFamily: 'ed25519' }>,
): WalletExecutionLaneHydrationResult {
  const common = commonRefusal(records, material);
  if (common) return common;
  const walletKey = records.walletKey;
  const lane = records.lane;
  const ownerParticipantContinuity = ownerParticipantContinuityForLane(lane);
  if (walletKey.keyFamily !== 'ed25519' || lane.lifecycle.state !== 'active') {
    return refusal('key_family_mismatch', records);
  }
  if (ownerParticipantContinuity === null) return invalidBoundaryRefusal();
  const plan = resolveNearEd25519YaoCapabilityHydrationV1(material.hydration);
  if (!isActiveHydrationPlan(plan)) return refusal('hydration_blocked', records);
  if (
    !mpcMaterialActivationRefsEqual(plan.materialActivation, material.metadata.materialActivation)
  ) {
    return refusal('material_activation_mismatch', records);
  }
  const application = material.metadata.applicationBinding;
  const publicLocator = material.hydration.publicLocator;
  if (
    publicLocator.kind !== 'available' ||
    String(publicLocator.walletId) !== String(walletKey.walletId) ||
    publicLocator.signerSlot !== application.key_creation_signer_slot ||
    !mpcMaterialActivationRefsEqual(
      publicLocator.materialActivation,
      material.metadata.materialActivation,
    ) ||
    String(plan.authority.walletId) !== String(walletKey.walletId) ||
    String(application.wallet_id) !== String(walletKey.walletId) ||
    String(material.metadata.scope.account_id) !== String(application.wallet_id) ||
    String(material.metadata.scope.signing_worker_id) !==
      String(plan.materialActivation.signingWorker) ||
    String(application.near_ed25519_signing_key_id) !== String(walletKey.nearEd25519SigningKeyId) ||
    application.key_creation_signer_slot !== walletKey.keyCreationSignerSlot ||
    base64UrlEncode(material.metadata.registeredPublicKey) !==
      String(walletKey.registeredPublicKeyB64u)
  ) {
    return refusal('public_identity_mismatch', records);
  }
  if (
    String(ownerParticipantContinuity.signingWorkerId) !==
      String(plan.materialActivation.signingWorker) ||
    !participantIdsMatch(ownerParticipantContinuity, material.metadata.participantIds)
  ) {
    return refusal('participant_binding_mismatch', records);
  }
  if (
    material.metadata.participantIds.length !== 2 ||
    material.metadata.participantIds[0] === material.metadata.participantIds[1] ||
    material.metadata.participantIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || participantId < 1,
    )
  ) {
    return refusal('participant_binding_mismatch', records);
  }
  const materialActivation = plan.materialActivation;
  return {
    kind: 'active_wallet_execution_lane_v1',
    keyFamily: 'ed25519',
    walletKey,
    lane: activeLaneReference({ lane, materialActivation }),
    ownerParticipantContinuity,
    materialActivation,
    laneShareEpoch: lane.laneShareEpoch,
    activationReceiptDigestB64u: lane.lifecycle.activationReceiptDigestB64u,
    publicIdentity: {
      keyFamily: 'ed25519',
      registeredPublicKeyB64u: walletKey.registeredPublicKeyB64u,
      nearEd25519SigningKeyId: walletKey.nearEd25519SigningKeyId,
      keyCreationSignerSlot: walletKey.keyCreationSignerSlot,
    },
  };
}

function hydrateEcdsa(
  records: ParsedWalletExecutionLaneRecords,
  material: Extract<WalletExecutionLaneMaterialHydrationInput, { keyFamily: 'ecdsa_secp256k1' }>,
): WalletExecutionLaneHydrationResult {
  const common = commonRefusal(records, material);
  if (common) return common;
  const walletKey = records.walletKey;
  const lane = records.lane;
  const ownerParticipantContinuity = ownerParticipantContinuityForLane(lane);
  if (walletKey.keyFamily !== 'ecdsa_secp256k1' || lane.lifecycle.state !== 'active') {
    return refusal('key_family_mismatch', records);
  }
  if (ownerParticipantContinuity === null) return invalidBoundaryRefusal();
  const hydrationInput: EcdsaCapabilityHydrationInput = {
    lookup: material.lookup,
    runtime: material.runtime,
  };
  const plan = resolveEcdsaCapabilityHydration(hydrationInput);
  if (!isActiveHydrationPlan(plan) || material.lookup.kind !== 'active') {
    return refusal('hydration_blocked', records);
  }
  const manifest = material.lookup.manifest;
  const binding = manifest.durableMaterial;
  const facts = binding.roleLocalPublicFacts;
  const registered = manifest.signer.registeredPublicFacts;
  const receipt = manifest.activation.serverActivation.serverActivationReceipt;
  const protocolIdentity = receipt.protocolReceipt.ecdsa_activation.public_identity;
  const expectedSlot = deriveEvmFamilySigningKeySlotId({
    walletId: facts.walletId,
    signingRootId: facts.signingRootId,
    signingRootVersion: facts.signingRootVersion,
  });
  if (
    !mpcMaterialActivationRefsEqual(
      plan.materialActivation,
      manifest.activation.materialActivation,
    ) ||
    !mpcMaterialActivationRefsEqual(plan.materialActivation, binding.materialActivation) ||
    String(plan.authority.walletId) !== String(walletKey.walletId) ||
    String(manifest.signer.walletId) !== String(walletKey.walletId) ||
    String(facts.walletId) !== String(walletKey.walletId) ||
    String(walletKey.evmFamilySigningKeySlotId) !== String(expectedSlot) ||
    String(walletKey.thresholdPublicKey33B64u) !== String(facts.groupPublicKey33B64u) ||
    String(walletKey.thresholdPublicKey33B64u) !== String(registered.publicKeyB64u) ||
    walletKey.evmAddress.toLowerCase() !== String(facts.ethereumAddress).toLowerCase() ||
    walletKey.evmAddress.toLowerCase() !== String(registered.thresholdOwnerAddress).toLowerCase() ||
    String(protocolIdentity.context_binding_b64u) !== String(binding.bindingDigest) ||
    String(protocolIdentity.derivation_client_share_public_key33_b64u) !==
      String(facts.derivationClientSharePublicKey33B64u) ||
    String(protocolIdentity.threshold_public_key33_b64u) !==
      String(walletKey.thresholdPublicKey33B64u) ||
    String(receipt.activationDigest) !== String(lane.lifecycle.activationReceiptDigestB64u)
  ) {
    return refusal('activation_receipt_mismatch', records);
  }
  if (
    String(ownerParticipantContinuity.signingWorkerId) !==
      String(plan.materialActivation.signingWorker) ||
    !participantIdsMatch(ownerParticipantContinuity, facts.participantIds)
  ) {
    return refusal('participant_binding_mismatch', records);
  }
  const materialActivation = plan.materialActivation;
  return {
    kind: 'active_wallet_execution_lane_v1',
    keyFamily: 'ecdsa_secp256k1',
    walletKey,
    lane: activeLaneReference({ lane, materialActivation }),
    ownerParticipantContinuity,
    materialActivation,
    laneShareEpoch: lane.laneShareEpoch,
    activationReceiptDigestB64u: lane.lifecycle.activationReceiptDigestB64u,
    publicIdentity: {
      keyFamily: 'ecdsa_secp256k1',
      thresholdPublicKey33B64u: walletKey.thresholdPublicKey33B64u,
      evmAddress: walletKey.evmAddress,
      evmFamilySigningKeySlotId: walletKey.evmFamilySigningKeySlotId,
    },
  };
}

export function hydrateWalletExecutionLane(
  input: WalletExecutionLaneHydrationInput,
): WalletExecutionLaneHydrationResult {
  let records: ParsedWalletExecutionLaneRecords;
  try {
    records = parseWalletExecutionLaneRecords(input);
  } catch {
    return invalidBoundaryRefusal();
  }
  try {
    switch (input.material.keyFamily) {
      case 'ed25519':
        return hydrateEd25519(records, input.material);
      case 'ecdsa_secp256k1':
        return hydrateEcdsa(records, input.material);
      default:
        input.material satisfies never;
        return invalidBoundaryRefusal();
    }
  } catch {
    return invalidBoundaryRefusal();
  }
}

/**
 * Hydrate linked/delegated lanes through their exact lane activation. Owner
 * continuity is intentionally absent for these rotatable lanes; the caller
 * supplies the already verified material activation and participant digest.
 */
export async function hydrateRotatableWalletExecutionLaneV1(
  input: RotatableWalletExecutionLaneHydrationInputV1,
): Promise<RotatableWalletExecutionLaneHydrationResultV1> {
  let records: ParsedWalletExecutionLaneRecords;
  try {
    records = parseWalletExecutionLaneRecords(input);
  } catch {
    return invalidBoundaryRefusal();
  }
  const { walletKey, lane } = records;
  if (walletKey.lifecycle.state !== 'active') return refusal('wallet_key_inactive', records);
  if (lane.lifecycle.state !== 'active') return refusal('lane_inactive', records);
  if (walletKey.keyFamily !== input.keyFamily) return refusal('key_family_mismatch', records);
  if (lane.laneKind !== 'linked_device') {
    return refusal('unsupported_lane_kind', records);
  }
  let laneShareEpoch: LaneShareEpoch;
  try {
    laneShareEpoch = parseLaneEpoch(input.laneShareEpoch);
  } catch {
    return invalidBoundaryRefusal();
  }
  if (
    String(laneShareEpoch) !== String(lane.laneShareEpoch) ||
    String(input.participantBindingDigestB64u) !== String(lane.participantBindingDigestB64u) ||
    !String(input.materialActivation.activationId).trim()
  ) {
    return refusal('participant_binding_mismatch', records);
  }
  try {
    await assertLaneHolderParticipantBindingDigestV1(lane.holderParticipant);
    await assertSigningWorkerParticipantBindingDigestV1(lane.serverParticipant);
    const participantSetDigest = await computeLaneParticipantSetBindingDigestV1({
      holderParticipant: lane.holderParticipant,
      signingWorkerParticipant: lane.serverParticipant,
    });
    if (participantSetDigest !== lane.participantBindingDigestB64u) {
      return refusal('participant_binding_mismatch', records);
    }
  } catch {
    return refusal('participant_binding_mismatch', records);
  }
  return {
    kind: 'active_rotatable_wallet_execution_lane_v1',
    keyFamily: walletKey.keyFamily,
    walletKey,
    lane: activeLaneReference({ lane, materialActivation: input.materialActivation }),
    materialActivation: input.materialActivation,
    laneShareEpoch,
    activationReceiptDigestB64u: lane.lifecycle.activationReceiptDigestB64u,
    participantBindingDigestB64u: input.participantBindingDigestB64u,
    publicIdentity:
      walletKey.keyFamily === 'ed25519'
        ? {
            keyFamily: 'ed25519',
            registeredPublicKeyB64u: walletKey.registeredPublicKeyB64u,
            nearEd25519SigningKeyId: walletKey.nearEd25519SigningKeyId,
            keyCreationSignerSlot: walletKey.keyCreationSignerSlot,
          }
        : {
            keyFamily: 'ecdsa_secp256k1',
            thresholdPublicKey33B64u: walletKey.thresholdPublicKey33B64u,
            evmAddress: walletKey.evmAddress,
            evmFamilySigningKeySlotId: walletKey.evmFamilySigningKeySlotId,
          },
  };
}
