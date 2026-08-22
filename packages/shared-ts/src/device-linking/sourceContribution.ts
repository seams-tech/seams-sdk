import { parseDeviceId, type DeviceId } from '../authorization/capabilityKinds';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkDeviceSessionId,
  parseWalletKeyId,
  type LinkedDeviceEnrollmentId,
  type LinkDeviceSessionId,
  type WalletKeyId,
} from '../signing-lanes/ids';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationRef,
  parseWalletAuthorityId,
  type MpcMaterialActivationRef,
  type WalletAuthorityId,
} from '../utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import {
  parseEnvelopeCiphertextB64u,
  parseEd25519PublicKeyB64u,
  parseSecp256k1CompressedPublicKeyB64u,
  type Ed25519PublicKeyB64u,
  type Secp256k1CompressedPublicKeyB64u,
} from '../passkey-custody/primitives';
import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import {
  parseRouterAbEd25519YaoCeremonyBindingV1,
  parseRouterAbEd25519YaoApplicationBindingFactsV1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoActivationPublicReceiptV1,
  parseRouterAbEd25519YaoEncryptedPackageV1,
  parseRouterAbEd25519YaoParticipantIdsV1,
  type RouterAbEd25519YaoCeremonyBindingV1,
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoActivationPublicReceiptV1,
  type RouterAbEd25519YaoApplicationBindingFactsV1,
  type RouterAbEd25519YaoEncryptedPackageV1,
  type RouterAbEd25519YaoActivationClientPackageV1,
} from '../utils/routerAbEd25519Yao';
import { routerAbMpcMaterialActivationRefFromWire } from '../utils/routerAbNormalSigningIdentity';

/** Exact discriminator accepted by the ECDSA source-contribution core. */
export const LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_ENVELOPE_KIND_V1 =
  'seams/linked-device/ecdsa-source-contribution-envelope/v1' as const;

/** Source derivation facts required by the Cloudflare ECDSA reservation wire. */
export type LinkedDeviceEcdsaSourceDerivationV1 = {
  readonly applicationBindingDigestB64u: DigestB64u;
  readonly clientShareRetryCounter: number;
};

/** Public ECDSA source identity copied from the family protocol wire. */
export type LinkedDeviceEcdsaSourceSignerIdentityV1 = {
  /** Exact activation object expected by the ECDSA WASM protocol. */
  readonly activation: MpcMaterialActivationRef;
  readonly clientPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
  readonly relayerPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
  readonly thresholdPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
  readonly thresholdEthereumAddress20B64u: string;
};

/** Exact Device 2 ECDSA recipient/factor preparation copied from Rust. */
export type LinkedDeviceEcdsaTargetRecipientPreparationV1 = {
  /** Exact fresh target activation object expected by the ECDSA WASM protocol. */
  readonly activation: MpcMaterialActivationRef;
  readonly targetDeviceId: DeviceId;
  readonly targetFactorVerificationDigestB64u: DigestB64u;
  readonly clientRecipientPublicKeyB64u: string;
  readonly signingWorkerRecipientPublicKeyB64u: string;
};

/** Public source/target input that Device 2 sends before Device 1 seals. */
export type LinkedDeviceEcdsaSourceContributionPreparationV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly sourceAuthorityId: WalletAuthorityId;
  readonly source: LinkedDeviceEcdsaSourceSignerIdentityV1;
  readonly target: LinkedDeviceEcdsaTargetRecipientPreparationV1;
};

/** Public Ed25519 source-preserving request published after target-factor verification. */
export type LinkedDeviceEd25519SourceContributionPreparationV1 = {
  readonly kind: 'linked_device_ed25519_source_contribution_preparation_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly sourceAuthorityId: WalletAuthorityId;
  readonly walletKeyId: WalletKeyId;
  readonly targetDeviceId: DeviceId;
  readonly targetFactorVerificationDigestB64u: DigestB64u;
  readonly sourceBinding: RouterAbEd25519YaoCeremonyBindingV1;
  readonly targetAdmission: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
  readonly applicationBinding: RouterAbEd25519YaoApplicationBindingFactsV1;
  readonly sourceRevocationEpoch: number;
  readonly participantIds: readonly [number, number];
  readonly targetMaterialActivation: MpcMaterialActivationRef;
  readonly targetClientRecipientPublicKeyB64u: string;
  readonly targetSigningWorkerRecipientPublicKeyB64u: string;
  readonly sourceRegisteredPublicKeyB64u: Ed25519PublicKeyB64u;
};

/** Exact ECDSA binding accepted by the family protocol. */
export type LinkedDeviceEcdsaSourceContributionBindingV1 = {
  readonly linkSessionId: string;
  readonly enrollmentId: string;
  readonly sourceAuthorityId: string;
  readonly source: LinkedDeviceEcdsaSourceSignerIdentityV1;
  readonly target: LinkedDeviceEcdsaTargetRecipientPreparationV1;
  readonly targetClientPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
};

export type LinkedDeviceEcdsaEncryptedSourceContributionV1 = {
  readonly kind: typeof LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_ENVELOPE_KIND_V1;
  readonly recipientPublicKeyB64u: string;
  readonly bindingDigestB64u: DigestB64u;
  readonly encappedKeyB64u: string;
  readonly ciphertextB64u: string;
};

/** The package contains ciphertext only; plaintext delta/share never has a TS shape. */
export type LinkedDeviceEcdsaSourceContributionPackageV1 = {
  readonly binding: LinkedDeviceEcdsaSourceContributionBindingV1;
  readonly encryptedDelta: LinkedDeviceEcdsaEncryptedSourceContributionV1;
  readonly encryptedTargetClientShare: LinkedDeviceEcdsaEncryptedSourceContributionV1;
};

/** Public inactive receipt returned by the source-preserving ECDSA worker. */
export type LinkedDeviceEcdsaSourcePreservingActivationReceiptV1 = {
  readonly state: 'inactive';
  readonly binding: LinkedDeviceEcdsaSourceContributionBindingV1;
  readonly sourceDerivation: LinkedDeviceEcdsaSourceDerivationV1;
  readonly targetRelayerPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
  readonly thresholdPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
  readonly thresholdEthereumAddress20B64u: string;
};

/** Final ECDSA contribution returned by Device 1's worker boundary. */
export type LinkedDeviceEcdsaSourceContributionV1 = {
  readonly kind: 'linked_device_ecdsa_source_contribution_v1';
  readonly keyFamily: 'ecdsa_secp256k1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly sourceAuthorityId: WalletAuthorityId;
  readonly walletKeyId: WalletKeyId;
  readonly targetDeviceId: DeviceId;
  readonly targetFactorVerificationDigestB64u: DigestB64u;
  readonly sourceSigner: LinkedDeviceEcdsaSourceSignerIdentityV1;
  readonly sourceDerivation: LinkedDeviceEcdsaSourceDerivationV1;
  readonly target: LinkedDeviceEcdsaTargetRecipientPreparationV1;
  readonly package: LinkedDeviceEcdsaSourceContributionPackageV1;
};

export type LinkedDeviceEd25519SourceContributionV1 = {
  readonly kind: 'linked_device_ed25519_source_contribution_v1';
  readonly keyFamily: 'ed25519';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly sourceAuthorityId: WalletAuthorityId;
  readonly walletKeyId: WalletKeyId;
  readonly targetDeviceId: DeviceId;
  readonly targetFactorVerificationDigestB64u: DigestB64u;
  readonly targetMaterialActivation: MpcMaterialActivationRef;
  readonly targetClientRecipientPublicKeyB64u: string;
  readonly targetSigningWorkerRecipientPublicKeyB64u: string;
  readonly sourceRegisteredPublicKeyB64u: Ed25519PublicKeyB64u;
  readonly sourceBinding: RouterAbEd25519YaoCeremonyBindingV1;
  /** Exact inactive reservation returned by Router source-preserving execution. */
  readonly reservationId: string;
  readonly targetBinding: RouterAbEd25519YaoCeremonyBindingV1;
  readonly activationReceipt: RouterAbEd25519YaoActivationPublicReceiptV1;
  readonly participantIds: readonly [number, number];
  readonly deriver_a_client_package: RouterAbEd25519YaoActivationClientPackageV1<'deriver_a'>;
  readonly deriver_b_client_package: RouterAbEd25519YaoActivationClientPackageV1<'deriver_b'>;
};

export type LinkedDeviceEd25519SourcePreservingReservationV1 = {
  readonly state: 'inactive';
  readonly reservationId: string;
  readonly participantIds: readonly [number, number];
  readonly activationReceipt: RouterAbEd25519YaoActivationPublicReceiptV1;
  readonly deriver_a_client_package: RouterAbEd25519YaoActivationClientPackageV1<'deriver_a'>;
  readonly deriver_b_client_package: RouterAbEd25519YaoActivationClientPackageV1<'deriver_b'>;
};

export type LinkedDeviceOrdinaryMaterialSourceContributionV1 =
  | LinkedDeviceEd25519SourceContributionV1
  | LinkedDeviceEcdsaSourceContributionV1;

export type LinkedDeviceOrdinaryMaterialSourceContributionPreparationV1 =
  | LinkedDeviceEd25519SourceContributionPreparationV1
  | LinkedDeviceEcdsaSourceContributionPreparationV1;

/** Durable public target preparation retained while Device 1 seals contributions. */
export type LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1 = readonly [
  LinkedDeviceOrdinaryMaterialSourceContributionPreparationV1,
  ...LinkedDeviceOrdinaryMaterialSourceContributionPreparationV1[],
];

export type LinkedDeviceOrdinaryMaterialSourceContributionTupleV1 = readonly [
  LinkedDeviceOrdinaryMaterialSourceContributionV1,
  ...LinkedDeviceOrdinaryMaterialSourceContributionV1[],
];

export function parseLinkedDeviceOrdinaryMaterialSourceContributionV1(
  raw: unknown,
): LinkedDeviceOrdinaryMaterialSourceContributionV1 {
  const record = requireRecord(raw, 'linked-device ordinary source contribution');
  switch (record.kind) {
    case 'linked_device_ed25519_source_contribution_v1':
      return parseEd25519Contribution(record);
    case 'linked_device_ecdsa_source_contribution_v1':
      return parseEcdsaContribution(record);
    default:
      throw new Error('linked-device ordinary source contribution kind is invalid');
  }
}

export function parseLinkedDeviceEd25519SourcePreservingReservationV1(
  raw: unknown,
): LinkedDeviceEd25519SourcePreservingReservationV1 {
  const record = exactRecord(
    raw,
    [
      'state',
      'reservation_id',
      'participant_ids',
      'activation_receipt',
      'deriver_a_client_package',
      'deriver_b_client_package',
    ],
    'linked-device Ed25519 source-preserving reservation',
  );
  if (record.state !== 'inactive') {
    throw new Error('linked-device Ed25519 source-preserving reservation is not inactive');
  }
  const activationReceipt = parseRouterAbEd25519YaoActivationPublicReceiptV1(
    record.activation_receipt,
  );
  const participantIds = parseRouterAbEd25519YaoParticipantIdsV1(record.participant_ids);
  const deriverA = parseEd25519ClientPackage(
    record.deriver_a_client_package,
    'deriver_a',
  );
  const deriverB = parseEd25519ClientPackage(
    record.deriver_b_client_package,
    'deriver_b',
  );
  if (
    !sameBytes(activationReceipt.transcript, deriverA.transcript) ||
    !sameBytes(activationReceipt.transcript, deriverB.transcript)
  ) {
    throw new Error('linked-device Ed25519 reservation packages have mismatched transcripts');
  }
  return {
    state: 'inactive',
    reservationId: requireText(record.reservation_id, 'reservation_id'),
    participantIds,
    activationReceipt,
    deriver_a_client_package: deriverA,
    deriver_b_client_package: deriverB,
  };
}

export function parseLinkedDeviceOrdinaryMaterialSourceContributionTupleV1(
  raw: unknown,
): LinkedDeviceOrdinaryMaterialSourceContributionTupleV1 {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > 2) {
    throw new Error('linked-device ordinary source contributions must contain one or two entries');
  }
  const contributions = raw.map(parseLinkedDeviceOrdinaryMaterialSourceContributionV1);
  const families = contributions.map((entry) => entry.keyFamily);
  if (new Set(families).size !== families.length) {
    throw new Error('linked-device ordinary source contributions repeat a key family');
  }
  if (
    contributions.length === 2 &&
    (contributions[0]?.keyFamily !== 'ed25519' ||
      contributions[1]?.keyFamily !== 'ecdsa_secp256k1')
  ) {
    throw new Error('linked-device ordinary source contributions must be Ed25519 then ECDSA');
  }
  const first = contributions[0];
  if (!first) throw new Error('linked-device ordinary source contributions are empty');
  return [first, ...contributions.slice(1)];
}

export function parseLinkedDeviceEcdsaSourceContributionPreparationV1(
  raw: unknown,
): LinkedDeviceEcdsaSourceContributionPreparationV1 {
  const record = exactRecord(
    raw,
    [
      'linkSessionId',
      'enrollmentId',
      'sourceAuthorityId',
      'source',
      'target',
    ],
    'linked-device ECDSA source contribution preparation',
  );
  const source = parseEcdsaSourceSigner(record.source);
  const target = parseEcdsaTarget(record.target);
  assertEcdsaSourceTargetActivations(source.activation, target.activation);
  return {
    linkSessionId: parseSessionId(record.linkSessionId),
    enrollmentId: parseEnrollmentId(record.enrollmentId),
    sourceAuthorityId: parseAuthorityId(record.sourceAuthorityId),
    source,
    target,
  };
}

export function parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationV1(
  raw: unknown,
): LinkedDeviceOrdinaryMaterialSourceContributionPreparationV1 {
  const record = requireRecord(raw, 'linked-device ordinary source contribution preparation');
  if (record.kind === 'linked_device_ed25519_source_contribution_preparation_v1') {
    return parseEd25519SourceContributionPreparation(record);
  }
  // The ECDSA preparation is the exact family wire and has no discriminator.
  if (
    Object.prototype.hasOwnProperty.call(record, 'source') &&
    Object.prototype.hasOwnProperty.call(record, 'target')
  ) {
    return parseLinkedDeviceEcdsaSourceContributionPreparationV1(record);
  }
  throw new Error('linked-device ordinary source contribution preparation family is invalid');
}

export function parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1(
  raw: unknown,
): LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1 {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > 2) {
    throw new Error(
      'linked-device ordinary source contribution preparations must contain one or two entries',
    );
  }
  const preparations = raw.map(parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationV1);
  const families = preparations.map((entry) =>
    'kind' in entry ? 'ed25519' : 'ecdsa_secp256k1',
  );
  if (new Set(families).size !== families.length) {
    throw new Error('linked-device ordinary source contribution preparations repeat a key family');
  }
  if (
    preparations.length === 2 &&
    (families[0] !== 'ed25519' || families[1] !== 'ecdsa_secp256k1')
  ) {
    throw new Error(
      'linked-device ordinary source contribution preparations must be ordered Ed25519 then ECDSA',
    );
  }
  const first = preparations[0];
  if (!first) throw new Error('linked-device ordinary source contribution preparation is empty');
  return [first, ...preparations.slice(1)];
}

function parseEd25519SourceContributionPreparation(
  record: Record<string, unknown>,
): LinkedDeviceEd25519SourceContributionPreparationV1 {
  exactRecord(
    record,
    [
      'kind',
      'linkSessionId',
      'enrollmentId',
      'sourceAuthorityId',
      'walletKeyId',
      'targetDeviceId',
      'targetFactorVerificationDigestB64u',
      'sourceBinding',
      'targetAdmission',
      'applicationBinding',
      'sourceRevocationEpoch',
      'participantIds',
      'targetMaterialActivation',
      'targetClientRecipientPublicKeyB64u',
      'targetSigningWorkerRecipientPublicKeyB64u',
      'sourceRegisteredPublicKeyB64u',
    ],
    'linked-device Ed25519 source contribution preparation',
  );
  if (record.kind !== 'linked_device_ed25519_source_contribution_preparation_v1') {
    throw new Error('linked-device Ed25519 source contribution preparation kind is invalid');
  }
  const sourceBinding = parseRegistrationBinding(record.sourceBinding, 'sourceBinding');
  const targetAdmissionResult = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(
    record.targetAdmission,
  );
  if (!targetAdmissionResult.ok) {
    throw new Error(`targetAdmission ${targetAdmissionResult.message}`);
  }
  const targetAdmission = targetAdmissionResult.value;
  const applicationBinding = parseRouterAbEd25519YaoApplicationBindingFactsV1(
    record.applicationBinding,
  );
  if (
    typeof record.sourceRevocationEpoch !== 'number' ||
    !Number.isSafeInteger(record.sourceRevocationEpoch) ||
    record.sourceRevocationEpoch < 0
  ) {
    throw new Error('sourceRevocationEpoch must be a non-negative safe integer');
  }
  const targetMaterialActivation = parseActivation(
    record.targetMaterialActivation,
    'targetMaterialActivation',
  );
  const linkSessionId = parseSessionId(record.linkSessionId);
  const enrollmentId = parseEnrollmentId(record.enrollmentId);
  const sourceAuthorityId = parseAuthorityId(record.sourceAuthorityId);
  const walletKeyId = parseWalletKeyIdField(record.walletKeyId);
  const targetDeviceId = parseDeviceIdField(record.targetDeviceId);
  const targetFactorVerificationDigestB64u = parseDigestField(
    record.targetFactorVerificationDigestB64u,
    'targetFactorVerificationDigestB64u',
  );
  const targetClientRecipientPublicKeyB64u = parseFixedBase64(
    record.targetClientRecipientPublicKeyB64u,
    32,
    'targetClientRecipientPublicKeyB64u',
  );
  const targetSigningWorkerRecipientPublicKeyB64u = parseFixedBase64(
    record.targetSigningWorkerRecipientPublicKeyB64u,
    32,
    'targetSigningWorkerRecipientPublicKeyB64u',
  );
  if (targetClientRecipientPublicKeyB64u === targetSigningWorkerRecipientPublicKeyB64u) {
    throw new Error('linked-device Ed25519 source contribution recipients must differ');
  }
  const participantIds = parseRouterAbEd25519YaoParticipantIdsV1(record.participantIds);
  assertSourceBindingContext(sourceBinding, linkSessionId, 'sourceBinding');
  if (
    !mpcMaterialActivationRefsEqual(
      targetMaterialActivation,
      routerAbMpcMaterialActivationRefFromWire(targetAdmission.binding.material_activation),
    )
  ) {
    throw new Error('targetAdmission activation differs from targetMaterialActivation');
  }
  if (!sameEdStableIdentity(sourceBinding, targetAdmission.binding)) {
    throw new Error('source and target Ed25519 contribution bindings differ');
  }
  if (
    sourceBinding.material_activation.activation_id ===
    targetMaterialActivation.activationId
  ) {
    throw new Error('source and target Ed25519 contribution activations must differ');
  }
  return {
    kind: 'linked_device_ed25519_source_contribution_preparation_v1',
    linkSessionId,
    enrollmentId,
    sourceAuthorityId,
    walletKeyId,
    targetDeviceId,
    targetFactorVerificationDigestB64u,
    sourceBinding,
    targetAdmission,
    applicationBinding,
    sourceRevocationEpoch: record.sourceRevocationEpoch,
    participantIds,
    targetMaterialActivation,
    targetClientRecipientPublicKeyB64u,
    targetSigningWorkerRecipientPublicKeyB64u,
    sourceRegisteredPublicKeyB64u: parseEd25519PublicKeyB64u(
      record.sourceRegisteredPublicKeyB64u,
      'sourceRegisteredPublicKeyB64u',
    ),
  };
}

export function assertLinkedDeviceOrdinaryMaterialSourceContributionMatchesContextV1(input: {
  readonly contribution: LinkedDeviceOrdinaryMaterialSourceContributionV1;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly sourceAuthorityId: WalletAuthorityId;
  readonly walletKeyId: WalletKeyId;
  readonly targetDeviceId: DeviceId;
  readonly targetFactorVerificationDigestB64u: DigestB64u;
  readonly sourceMaterialActivation: MpcMaterialActivationRef;
  readonly targetMaterialActivation: MpcMaterialActivationRef;
  readonly sourceSigner:
    | {
        readonly keyFamily: 'ed25519';
        readonly walletKeyId: WalletKeyId;
        readonly registeredPublicKeyB64u: Ed25519PublicKeyB64u;
      }
    | {
        readonly keyFamily: 'ecdsa_secp256k1';
        readonly walletKeyId: WalletKeyId;
        readonly thresholdPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
      };
}): void {
  const contribution = input.contribution;
  if (
    contribution.linkSessionId !== input.linkSessionId ||
    contribution.enrollmentId !== input.enrollmentId ||
    contribution.sourceAuthorityId !== input.sourceAuthorityId ||
    contribution.walletKeyId !== input.walletKeyId ||
    contribution.targetDeviceId !== input.targetDeviceId ||
    contribution.targetFactorVerificationDigestB64u !== input.targetFactorVerificationDigestB64u
  ) {
    throw new Error('linked-device ordinary source contribution identity differs from the link');
  }
  if (
    contribution.keyFamily !== input.sourceSigner.keyFamily ||
    contribution.walletKeyId !== input.sourceSigner.walletKeyId
  ) {
    throw new Error('linked-device ordinary source contribution signer family or key differs');
  }
  const targetActivation = contribution.keyFamily === 'ed25519'
    ? contribution.targetMaterialActivation
    : contribution.target.activation;
  const sourceActivation = contribution.keyFamily === 'ed25519'
    ? routerAbMpcMaterialActivationRefFromWire(contribution.sourceBinding.material_activation)
    : contribution.sourceSigner.activation;
  if (!mpcMaterialActivationRefsEqual(sourceActivation, input.sourceMaterialActivation)) {
    throw new Error('linked-device ordinary source contribution source activation differs');
  }
  if (!mpcMaterialActivationRefsEqual(targetActivation, input.targetMaterialActivation)) {
    throw new Error('linked-device ordinary source contribution target activation differs');
  }
  if (contribution.keyFamily === 'ed25519') {
    if (input.sourceSigner.keyFamily !== 'ed25519') {
      throw new Error('linked-device Ed25519 source contribution signer family differs');
    }
    if (contribution.sourceRegisteredPublicKeyB64u !== input.sourceSigner.registeredPublicKeyB64u) {
      throw new Error('linked-device Ed25519 source contribution public key differs');
    }
    return;
  }
  if (input.sourceSigner.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('linked-device ECDSA source contribution signer family differs');
  }
  if (contribution.sourceSigner.thresholdPublicKey33B64u !== input.sourceSigner.thresholdPublicKey33B64u) {
    throw new Error('linked-device ECDSA source contribution public key differs');
  }
}

function parseEd25519Contribution(
  record: Record<string, unknown>,
): LinkedDeviceEd25519SourceContributionV1 {
  exactRecord(
    record,
    [
      'kind',
      'keyFamily',
      'linkSessionId',
      'enrollmentId',
      'sourceAuthorityId',
      'walletKeyId',
      'targetDeviceId',
      'targetFactorVerificationDigestB64u',
      'targetMaterialActivation',
      'targetClientRecipientPublicKeyB64u',
      'targetSigningWorkerRecipientPublicKeyB64u',
      'sourceBinding',
      'reservationId',
      'targetBinding',
      'activationReceipt',
      'participantIds',
      'deriver_a_client_package',
      'deriver_b_client_package',
      'sourceRegisteredPublicKeyB64u',
    ],
    'linked-device Ed25519 source contribution',
  );
  if (record.kind !== 'linked_device_ed25519_source_contribution_v1') {
    throw new Error('linked-device Ed25519 source contribution kind is invalid');
  }
  if (record.keyFamily !== 'ed25519') {
    throw new Error('linked-device Ed25519 source contribution family is invalid');
  }
  const sourceBinding = parseRegistrationBinding(record.sourceBinding, 'sourceBinding');
  const targetMaterialActivation = parseActivation(
    record.targetMaterialActivation,
    'source contribution targetMaterialActivation',
  );
  const targetBinding = parseRegistrationBinding(record.targetBinding, 'targetBinding');
  const activationReceipt = parseRouterAbEd25519YaoActivationPublicReceiptV1(
    record.activationReceipt,
  );
  const reservationId = requireText(record.reservationId, 'reservationId');
  const participantIds = parseRouterAbEd25519YaoParticipantIdsV1(record.participantIds);
  const linkSessionId = parseSessionId(record.linkSessionId);
  const enrollmentId = parseEnrollmentId(record.enrollmentId);
  const sourceAuthorityId = parseAuthorityId(record.sourceAuthorityId);
  const walletKeyId = parseWalletKeyIdField(record.walletKeyId);
  const targetDeviceId = parseDeviceIdField(record.targetDeviceId);
  const targetFactorVerificationDigestB64u = parseDigestField(
    record.targetFactorVerificationDigestB64u,
    'targetFactorVerificationDigestB64u',
  );
  const targetClientRecipientPublicKeyB64u = parseFixedBase64(
    record.targetClientRecipientPublicKeyB64u,
    32,
    'targetClientRecipientPublicKeyB64u',
  );
  const targetSigningWorkerRecipientPublicKeyB64u = parseFixedBase64(
    record.targetSigningWorkerRecipientPublicKeyB64u,
    32,
    'targetSigningWorkerRecipientPublicKeyB64u',
  );
  if (targetClientRecipientPublicKeyB64u === targetSigningWorkerRecipientPublicKeyB64u) {
    throw new Error('linked-device Ed25519 source contribution recipients must differ');
  }
  assertSourceBindingContext(sourceBinding, linkSessionId, 'sourceBinding');
  assertBindingContext(targetBinding, linkSessionId, targetMaterialActivation, 'targetBinding');
  if (!sameEdStableIdentity(sourceBinding, targetBinding)) {
    throw new Error('linked-device Ed25519 source contribution stable identity differs');
  }
  if (
    !mpcMaterialActivationRefsEqual(
      routerAbMpcMaterialActivationRefFromWire(activationReceipt.material_activation),
      targetMaterialActivation,
    )
  ) {
    throw new Error('linked-device Ed25519 source contribution receipt activation differs');
  }
  const sourceRegisteredPublicKeyB64u = parseEd25519PublicKeyB64u(
    record.sourceRegisteredPublicKeyB64u,
    'sourceRegisteredPublicKeyB64u',
  );
  if (
    !sameBytes(
      activationReceipt.registered_public_key,
      Array.from(base64UrlDecode(sourceRegisteredPublicKeyB64u)),
    )
  ) {
    throw new Error('linked-device Ed25519 source contribution receipt public key differs');
  }
  const deriverA = parseEd25519ClientPackage(
    record.deriver_a_client_package,
    'deriver_a',
  );
  const deriverB = parseEd25519ClientPackage(
    record.deriver_b_client_package,
    'deriver_b',
  );
  if (
    !sameBytes(activationReceipt.transcript, deriverA.transcript) ||
    !sameBytes(activationReceipt.transcript, deriverB.transcript)
  ) {
    throw new Error('linked-device Ed25519 source contribution package transcript differs');
  }
  if (sourceBinding.material_activation.activation_id === targetMaterialActivation.activationId) {
    throw new Error('linked-device Ed25519 source contribution reuses the source activation');
  }
  return {
    kind: 'linked_device_ed25519_source_contribution_v1',
    keyFamily: 'ed25519',
    linkSessionId,
    enrollmentId,
    sourceAuthorityId,
    walletKeyId,
    targetDeviceId,
    targetFactorVerificationDigestB64u,
    targetMaterialActivation,
    targetClientRecipientPublicKeyB64u,
    targetSigningWorkerRecipientPublicKeyB64u,
    sourceBinding,
    reservationId,
    targetBinding,
    activationReceipt,
    participantIds,
    deriver_a_client_package: deriverA,
    deriver_b_client_package: deriverB,
    sourceRegisteredPublicKeyB64u,
  };
}

function parseEcdsaContribution(
  record: Record<string, unknown>,
): LinkedDeviceEcdsaSourceContributionV1 {
  exactRecord(
    record,
    [
      'kind',
      'keyFamily',
      'linkSessionId',
      'enrollmentId',
      'sourceAuthorityId',
      'walletKeyId',
      'targetDeviceId',
      'targetFactorVerificationDigestB64u',
      'sourceSigner',
      'sourceDerivation',
      'target',
      'package',
    ],
    'linked-device ECDSA source contribution',
  );
  if (record.kind !== 'linked_device_ecdsa_source_contribution_v1') {
    throw new Error('linked-device ECDSA source contribution kind is invalid');
  }
  if (record.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('linked-device ECDSA source contribution family is invalid');
  }
  const linkSessionId = parseSessionId(record.linkSessionId);
  const enrollmentId = parseEnrollmentId(record.enrollmentId);
  const sourceAuthorityId = parseAuthorityId(record.sourceAuthorityId);
  const walletKeyId = parseWalletKeyIdField(record.walletKeyId);
  const targetDeviceId = parseDeviceIdField(record.targetDeviceId);
  const targetFactorVerificationDigestB64u = parseDigestField(
    record.targetFactorVerificationDigestB64u,
    'targetFactorVerificationDigestB64u',
  );
  const sourceSigner = parseEcdsaSourceSigner(record.sourceSigner);
  const sourceDerivation = parseLinkedDeviceEcdsaSourceDerivationV1(record.sourceDerivation);
  const target = parseEcdsaTarget(record.target);
  assertEcdsaSourceTargetActivations(sourceSigner.activation, target.activation);
  const packageValue = parseLinkedDeviceEcdsaSourceContributionPackageV1(record.package);
  if (
    packageValue.binding.linkSessionId !== linkSessionId ||
    packageValue.binding.enrollmentId !== enrollmentId ||
    packageValue.binding.sourceAuthorityId !== sourceAuthorityId ||
    packageValue.binding.target.targetDeviceId !== targetDeviceId ||
    packageValue.binding.target.targetFactorVerificationDigestB64u !==
      targetFactorVerificationDigestB64u
  ) {
    throw new Error('linked-device ECDSA source contribution package binding differs');
  }
  if (!sameEcdsaSourceSigner(packageValue.binding.source, sourceSigner)) {
    throw new Error('linked-device ECDSA source contribution signer differs from package binding');
  }
  if (!sameEcdsaTarget(packageValue.binding.target, target)) {
    throw new Error('linked-device ECDSA source contribution target differs from package binding');
  }
  return {
    kind: 'linked_device_ecdsa_source_contribution_v1',
    keyFamily: 'ecdsa_secp256k1',
    linkSessionId,
    enrollmentId,
    sourceAuthorityId,
    walletKeyId,
    targetDeviceId,
    targetFactorVerificationDigestB64u,
    sourceSigner,
    sourceDerivation,
    target,
    package: packageValue,
  };
}

export function parseLinkedDeviceEcdsaSourceDerivationV1(
  raw: unknown,
): LinkedDeviceEcdsaSourceDerivationV1 {
  const record = exactRecord(
    raw,
    ['applicationBindingDigestB64u', 'clientShareRetryCounter'],
    'linked-device ECDSA source derivation',
  );
  const clientShareRetryCounter = record.clientShareRetryCounter;
  if (
    typeof clientShareRetryCounter !== 'number' ||
    !Number.isSafeInteger(clientShareRetryCounter) ||
    clientShareRetryCounter < 0
  ) {
    throw new Error('linked-device ECDSA source derivation retry counter is invalid');
  }
  return {
    applicationBindingDigestB64u: parseDigestField(
      record.applicationBindingDigestB64u,
      'sourceDerivation.applicationBindingDigestB64u',
    ),
    clientShareRetryCounter,
  };
}

export function parseLinkedDeviceEcdsaSourcePreservingActivationReceiptV1(
  raw: unknown,
): LinkedDeviceEcdsaSourcePreservingActivationReceiptV1 {
  const record = exactRecord(
    raw,
    [
      'state',
      'binding',
      'sourceDerivation',
      'targetRelayerPublicKey33B64u',
      'thresholdPublicKey33B64u',
      'thresholdEthereumAddress20B64u',
    ],
    'linked-device ECDSA source-preserving activation receipt',
  );
  if (record.state !== 'inactive') {
    throw new Error('linked-device ECDSA source-preserving activation receipt is not inactive');
  }
  return {
    state: 'inactive',
    binding: parseLinkedDeviceEcdsaSourceContributionBindingV1(record.binding),
    sourceDerivation: parseLinkedDeviceEcdsaSourceDerivationV1(record.sourceDerivation),
    targetRelayerPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      record.targetRelayerPublicKey33B64u,
      'targetRelayerPublicKey33B64u',
    ),
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      record.thresholdPublicKey33B64u,
      'thresholdPublicKey33B64u',
    ),
    thresholdEthereumAddress20B64u: parseFixedBase64(
      record.thresholdEthereumAddress20B64u,
      20,
      'thresholdEthereumAddress20B64u',
    ),
  };
}

function parseEd25519ClientPackage(
  raw: unknown,
  role: 'deriver_a',
): RouterAbEd25519YaoActivationClientPackageV1<'deriver_a'>;
function parseEd25519ClientPackage(
  raw: unknown,
  role: 'deriver_b',
): RouterAbEd25519YaoActivationClientPackageV1<'deriver_b'>;
function parseEd25519ClientPackage(
  raw: unknown,
  role: 'deriver_a' | 'deriver_b',
):
  | RouterAbEd25519YaoActivationClientPackageV1<'deriver_a'>
  | RouterAbEd25519YaoActivationClientPackageV1<'deriver_b'> {
  const packageValue = parseRouterPackage(raw, `${role} client package`);
  if (packageValue.kind !== 'activation_client' || packageValue.deriver !== role) {
    throw new Error(`${role} client package is not an activation client package`);
  }
  if (role === 'deriver_a') {
    return {
      kind: 'activation_client',
      deriver: 'deriver_a',
      session: packageValue.session,
      transcript: packageValue.transcript,
      encapsulated_key: packageValue.encapsulated_key,
      ciphertext: packageValue.ciphertext,
    };
  }
  return {
    kind: 'activation_client',
    deriver: 'deriver_b',
    session: packageValue.session,
    transcript: packageValue.transcript,
    encapsulated_key: packageValue.encapsulated_key,
    ciphertext: packageValue.ciphertext,
  };
}

function parseRouterPackage(raw: unknown, label: string): RouterAbEd25519YaoEncryptedPackageV1 {
  const parsed = parseRouterAbEd25519YaoEncryptedPackageV1(raw);
  if (!parsed.ok) throw new Error(`${label} ${parsed.message}`);
  return parsed.value;
}

export function parseLinkedDeviceEcdsaSourceContributionPackageV1(
  raw: unknown,
): LinkedDeviceEcdsaSourceContributionPackageV1 {
  const record = exactRecord(
    raw,
    ['binding', 'encryptedDelta', 'encryptedTargetClientShare'],
    'linked-device ECDSA source contribution package',
  );
  const binding = parseLinkedDeviceEcdsaSourceContributionBindingV1(record.binding);
  const encryptedDelta = parseLinkedDeviceEcdsaEncryptedSourceContributionV1(
    record.encryptedDelta,
    'encryptedDelta',
  );
  const encryptedTargetClientShare = parseLinkedDeviceEcdsaEncryptedSourceContributionV1(
    record.encryptedTargetClientShare,
    'encryptedTargetClientShare',
  );
  const bindingDigest = encryptedDelta.bindingDigestB64u;
  if (encryptedTargetClientShare.bindingDigestB64u !== bindingDigest) {
    throw new Error('linked-device ECDSA source contribution envelope bindings differ');
  }
  if (
    encryptedDelta.recipientPublicKeyB64u !== binding.target.signingWorkerRecipientPublicKeyB64u ||
    encryptedTargetClientShare.recipientPublicKeyB64u !== binding.target.clientRecipientPublicKeyB64u
  ) {
    throw new Error('linked-device ECDSA source contribution envelope recipients differ');
  }
  return { binding, encryptedDelta, encryptedTargetClientShare };
}

export function parseLinkedDeviceEcdsaSourceContributionBindingV1(
  raw: unknown,
): LinkedDeviceEcdsaSourceContributionBindingV1 {
  const record = exactRecord(
    raw,
    ['linkSessionId', 'enrollmentId', 'sourceAuthorityId', 'source', 'target', 'targetClientPublicKey33B64u'],
    'linked-device ECDSA source contribution binding',
  );
  const source = parseEcdsaSourceSigner(record.source);
  const target = parseEcdsaTarget(record.target);
  assertEcdsaSourceTargetActivations(source.activation, target.activation);
  return {
    linkSessionId: requireText(record.linkSessionId, 'binding.linkSessionId'),
    enrollmentId: requireText(record.enrollmentId, 'binding.enrollmentId'),
    sourceAuthorityId: requireText(record.sourceAuthorityId, 'binding.sourceAuthorityId'),
    source,
    target,
    targetClientPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      record.targetClientPublicKey33B64u,
      'binding.targetClientPublicKey33B64u',
    ),
  };
}

function parseEcdsaSourceSigner(raw: unknown): LinkedDeviceEcdsaSourceSignerIdentityV1 {
  const record = exactRecord(
    raw,
    [
      'activation',
      'clientPublicKey33B64u',
      'relayerPublicKey33B64u',
      'thresholdPublicKey33B64u',
      'thresholdEthereumAddress20B64u',
    ],
    'linked-device ECDSA source signer',
  );
  return {
    activation: parseActivation(record.activation, 'source.activation'),
    clientPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      record.clientPublicKey33B64u,
      'source.clientPublicKey33B64u',
    ),
    relayerPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      record.relayerPublicKey33B64u,
      'source.relayerPublicKey33B64u',
    ),
    thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
      record.thresholdPublicKey33B64u,
      'source.thresholdPublicKey33B64u',
    ),
    thresholdEthereumAddress20B64u: parseFixedBase64(
      record.thresholdEthereumAddress20B64u,
      20,
      'source.thresholdEthereumAddress20B64u',
    ),
  };
}

function parseEcdsaTarget(raw: unknown): LinkedDeviceEcdsaTargetRecipientPreparationV1 {
  const record = exactRecord(
    raw,
    [
      'activation',
      'targetDeviceId',
      'targetFactorVerificationDigestB64u',
      'clientRecipientPublicKeyB64u',
      'signingWorkerRecipientPublicKeyB64u',
    ],
    'linked-device ECDSA target recipient',
  );
  const clientRecipientPublicKeyB64u = parseFixedBase64(
    record.clientRecipientPublicKeyB64u,
    32,
    'target.clientRecipientPublicKeyB64u',
  );
  const signingWorkerRecipientPublicKeyB64u = parseFixedBase64(
    record.signingWorkerRecipientPublicKeyB64u,
    32,
    'target.signingWorkerRecipientPublicKeyB64u',
  );
  if (clientRecipientPublicKeyB64u === signingWorkerRecipientPublicKeyB64u) {
    throw new Error('linked-device ECDSA target recipients must differ');
  }
  return {
    activation: parseActivation(record.activation, 'target.activation'),
    targetDeviceId: parseDeviceIdField(record.targetDeviceId),
    targetFactorVerificationDigestB64u: parseDigestField(
      record.targetFactorVerificationDigestB64u,
      'target.targetFactorVerificationDigestB64u',
    ),
    clientRecipientPublicKeyB64u,
    signingWorkerRecipientPublicKeyB64u,
  };
}

export function parseLinkedDeviceEcdsaEncryptedSourceContributionV1(
  raw: unknown,
  label: string,
): LinkedDeviceEcdsaEncryptedSourceContributionV1 {
  const record = exactRecord(
    raw,
    ['kind', 'recipientPublicKeyB64u', 'bindingDigestB64u', 'encappedKeyB64u', 'ciphertextB64u'],
    `linked-device ECDSA ${label}`,
  );
  if (record.kind !== LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_ENVELOPE_KIND_V1) {
    throw new Error(`${label}.kind is invalid`);
  }
  return {
    kind: LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_ENVELOPE_KIND_V1,
    recipientPublicKeyB64u: parseFixedBase64(record.recipientPublicKeyB64u, 32, `${label}.recipientPublicKeyB64u`),
    bindingDigestB64u: parseDigestField(record.bindingDigestB64u, `${label}.bindingDigestB64u`),
    encappedKeyB64u: parseFixedBase64(record.encappedKeyB64u, 32, `${label}.encappedKeyB64u`),
    ciphertextB64u: parseEnvelopeCiphertextB64u(record.ciphertextB64u, `${label}.ciphertextB64u`),
  };
}

function parseRegistrationBinding(
  raw: unknown,
  label: string,
): RouterAbEd25519YaoCeremonyBindingV1 {
  const binding = parseRouterAbEd25519YaoCeremonyBindingV1(raw);
  if (binding.operation !== 'registration') {
    throw new Error(`${label} must use the registration operation`);
  }
  return binding;
}

function assertBindingContext(
  binding: RouterAbEd25519YaoCeremonyBindingV1,
  linkSessionId: LinkDeviceSessionId,
  targetMaterialActivation: MpcMaterialActivationRef,
  label: string,
): void {
  if (binding.material_activation.activation_id !== targetMaterialActivation.activationId) {
    throw new Error(`${label} activation does not match the target activation`);
  }
  if (binding.material_activation.material_owner !== targetMaterialActivation.materialOwner) {
    throw new Error(`${label} material owner does not match the target activation`);
  }
  if (binding.material_activation.signing_worker !== targetMaterialActivation.signingWorker) {
    throw new Error(`${label} signing worker does not match the target activation`);
  }
  if (binding.session_id.length !== 32 || String(linkSessionId).length === 0) {
    throw new Error(`${label} link binding is invalid`);
  }
}

function assertSourceBindingContext(
  binding: RouterAbEd25519YaoCeremonyBindingV1,
  linkSessionId: LinkDeviceSessionId,
  label: string,
): void {
  if (binding.session_id.length !== 32 || String(linkSessionId).length === 0) {
    throw new Error(`${label} link binding is invalid`);
  }
}

function sameEdStableIdentity(
  left: RouterAbEd25519YaoCeremonyBindingV1,
  right: RouterAbEd25519YaoCeremonyBindingV1,
): boolean {
  return (
    left.operation === right.operation &&
    left.stable_key_context_binding.every(
      (value, index) => value === right.stable_key_context_binding[index],
    ) &&
    left.material_activation.capability === right.material_activation.capability &&
    left.material_activation.material_owner === right.material_activation.material_owner &&
    left.material_activation.key_binding === right.material_activation.key_binding &&
    left.material_activation.lifecycle_binding === right.material_activation.lifecycle_binding &&
    left.material_activation.signing_worker === right.material_activation.signing_worker &&
    left.lifecycle.root_share_epoch === right.lifecycle.root_share_epoch &&
    left.lifecycle.account_id === right.lifecycle.account_id &&
    left.lifecycle.signer_set_id === right.lifecycle.signer_set_id &&
    left.lifecycle.selected_server_id === right.lifecycle.selected_server_id
  );
}

function sameEcdsaSourceSigner(
  left: LinkedDeviceEcdsaSourceSignerIdentityV1,
  right: LinkedDeviceEcdsaSourceSignerIdentityV1,
): boolean {
  return (
    mpcMaterialActivationRefsEqual(left.activation, right.activation) &&
    left.clientPublicKey33B64u === right.clientPublicKey33B64u &&
    left.relayerPublicKey33B64u === right.relayerPublicKey33B64u &&
    left.thresholdPublicKey33B64u === right.thresholdPublicKey33B64u &&
    left.thresholdEthereumAddress20B64u === right.thresholdEthereumAddress20B64u
  );
}

function assertEcdsaSourceTargetActivations(
  source: MpcMaterialActivationRef,
  target: MpcMaterialActivationRef,
): void {
  if (
    mpcMaterialActivationRefsEqual(source, target) ||
    source.materialOwner !== target.materialOwner ||
    source.signingWorker !== target.signingWorker
  ) {
    throw new Error('linked-device ECDSA source and target activations are invalid');
  }
}

function sameEcdsaTarget(
  left: LinkedDeviceEcdsaTargetRecipientPreparationV1,
  right: LinkedDeviceEcdsaTargetRecipientPreparationV1,
): boolean {
  return (
    mpcMaterialActivationRefsEqual(left.activation, right.activation) &&
    left.targetDeviceId === right.targetDeviceId &&
    left.targetFactorVerificationDigestB64u === right.targetFactorVerificationDigestB64u &&
    left.clientRecipientPublicKeyB64u === right.clientRecipientPublicKeyB64u &&
    left.signingWorkerRecipientPublicKeyB64u === right.signingWorkerRecipientPublicKeyB64u
  );
}

function parseActivation(raw: unknown, label: string): MpcMaterialActivationRef {
  const parsed = parseMpcMaterialActivationRef(raw);
  if (!parsed.ok) throw new Error(`${label} ${parsed.error.message}`);
  return parsed.value;
}

function parseSessionId(raw: unknown): LinkDeviceSessionId {
  const parsed = parseLinkDeviceSessionId(requireText(raw, 'linkSessionId'));
  if (!parsed.ok) throw new Error(`linkSessionId ${parsed.error.message}`);
  return parsed.value;
}

function parseEnrollmentId(raw: unknown): LinkedDeviceEnrollmentId {
  const parsed = parseLinkedDeviceEnrollmentId(requireText(raw, 'enrollmentId'));
  if (!parsed.ok) throw new Error(`enrollmentId ${parsed.error.message}`);
  return parsed.value;
}

function parseAuthorityId(raw: unknown): WalletAuthorityId {
  const parsed = parseWalletAuthorityId(requireText(raw, 'sourceAuthorityId'));
  if (!parsed.ok) throw new Error(`sourceAuthorityId ${parsed.error.message}`);
  return parsed.value;
}

function parseWalletKeyIdField(raw: unknown): WalletKeyId {
  const parsed = parseWalletKeyId(requireText(raw, 'walletKeyId'));
  if (!parsed.ok) throw new Error(`walletKeyId ${parsed.error.message}`);
  return parsed.value;
}

function parseDeviceIdField(raw: unknown): DeviceId {
  const parsed = parseDeviceId(requireText(raw, 'targetDeviceId'));
  if (!parsed.ok) throw new Error(`targetDeviceId ${parsed.error.message}`);
  return parsed.value;
}

function parseDigestField(raw: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parseFixedBase64(raw: unknown, byteLength: number, label: string): string {
  if (typeof raw !== 'string' || !/^[A-Za-z0-9_-]+$/.test(raw)) {
    throw new Error(`${label} must be canonical base64url`);
  }
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(raw);
  } catch {
    throw new Error(`${label} must be canonical base64url`);
  }
  if (decoded.length !== byteLength || base64UrlEncode(decoded) !== raw) {
    throw new Error(`${label} must decode to ${byteLength} bytes`);
  }
  return raw;
}

function sameBytes(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function requireText(raw: unknown, label: string): string {
  if (
    typeof raw !== 'string' ||
    raw.length === 0 ||
    raw.trim() !== raw ||
    [...raw].some((character) => {
      const code = character.charCodeAt(0);
      return code < 0x20 || code === 0x7f;
    })
  ) {
    throw new Error(`${label} must be a non-empty visible string`);
  }
  return raw;
}

function requireRecord(raw: unknown, label: string): Record<string, unknown> {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error(`${label} must be an object`);
  }
  return Object.fromEntries(Object.entries(raw));
}

function exactRecord(
  raw: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  const record = requireRecord(raw, label);
  const expected = new Set(keys);
  const actual = Object.keys(record);
  if (
    actual.length !== keys.length ||
    actual.some((key) => !expected.has(key)) ||
    keys.some((key) => !Object.prototype.hasOwnProperty.call(record, key))
  ) {
    throw new Error(`${label} contains unknown or missing fields`);
  }
  return record;
}
