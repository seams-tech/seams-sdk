import {
  parseExactAdministeredSignerManifestV1,
  type ExactAdministeredEcdsaSignerV1,
  type ExactAdministeredEd25519SignerV1,
} from '@shared/device-linking/delegatedActivationPlan';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  requireRouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  parseRouterAbEd25519YaoCeremonyBindingV1,
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationExecuteRequestV1,
  type RouterAbEd25519YaoCeremonyBindingV1,
  type RouterAbEd25519YaoActivationPublicReceiptV1,
  type RouterAbEd25519YaoActivationClientPackageV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_ENVELOPE_KIND_V1,
  parseLinkedDeviceEcdsaSourceContributionPackageV1,
  parseLinkedDeviceOrdinaryMaterialSourceContributionV1,
  type LinkedDeviceEcdsaSourcePreservingActivationReceiptV1,
} from '@shared/device-linking/sourceContribution';
import { parseSdkEcdsaDerivationThresholdKeyId } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  OrdinaryEcdsaSignerMaterialReservationPreparationV1,
  OrdinaryEd25519SignerMaterialReservationPreparationV1,
} from '../../../packages/wallet-server/src/core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import type { WalletAuthoritySignerMaterialRecordV1 } from '../../../packages/wallet/src/core/indexedDB/passkeyClientDB.types';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  buildMpcMaterialActivationRef,
  parseMpcMaterialActivationId,
  type MpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletAuthorityId,
} from '@shared/utils/domainIds';
import { buildMpcMaterialActivationRefFixture } from './ecdsaMaterialRef.fixtures';

export function buildOrdinaryEd25519SignerFixture(label: string): ExactAdministeredEd25519SignerV1 {
  const manifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519'],
    signers: [
      {
        kind: 'exact_administered_ed25519_signer_v1',
        keyFamily: 'ed25519',
        walletId: `wallet:ordinary-reservation:${label}`,
        walletKeyId: `wallet-key:ordinary-reservation:${label}`,
        registeredPublicKeyB64u: encodedBytes(32, label.length + 1),
      },
    ],
  });
  const signer = manifest.signers[0];
  if (signer.keyFamily !== 'ed25519') {
    throw new Error('ordinary Ed25519 signer fixture has the wrong family');
  }
  return signer;
}

export function buildOrdinaryEd25519SignerMaterialRecordFixture(args: {
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly sealedMaterialB64u: string;
  readonly sealedMaterialDigestB64u: DigestB64u;
}): Extract<
  WalletAuthoritySignerMaterialRecordV1,
  { readonly kind: 'wallet_authority_signer_material_v1'; readonly keyFamily: 'ed25519' }
> {
  return {
    kind: 'wallet_authority_signer_material_v1',
    authorityId: args.authorityId,
    walletAuthMethodId: args.walletAuthMethodId,
    activationId: args.materialActivation.activationId,
    keyFamily: 'ed25519',
    materialActivation: args.materialActivation,
    sealedMaterialB64u: args.sealedMaterialB64u,
    sealedMaterialDigestB64u: args.sealedMaterialDigestB64u,
  };
}

export function buildOrdinaryEcdsaSignerFixture(label: string): ExactAdministeredEcdsaSignerV1 {
  const manifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ecdsa_secp256k1'],
    signers: [
      {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId: `wallet:ordinary-reservation:${label}`,
        walletKeyId: `wallet-key:ordinary-reservation:${label}`,
        thresholdPublicKey33B64u: encodedBytes(33, label.length + 2, 2),
        evmAddress: '0x1111111111111111111111111111111111111111',
      },
    ],
  });
  const signer = manifest.signers[0];
  if (signer.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('ordinary ECDSA signer fixture has the wrong family');
  }
  return signer;
}

export function buildOrdinaryEd25519ClientMaterialFixture(label: string) {
  const session = bytes(32, label.length + 9);
  const transcript = bytes(32, label.length + 10);
  return {
    kind: 'ordinary_ed25519_client_material_v1' as const,
    deriver_a_client_package: buildEd25519ClientPackage(
      'deriver_a',
      label.length + 11,
      session,
      transcript,
    ),
    deriver_b_client_package: buildEd25519ClientPackage(
      'deriver_b',
      label.length + 17,
      session,
      transcript,
    ),
  };
}

export function buildOrdinaryEd25519ActivationReceiptFixture(
  label: string,
  materialActivation: MpcMaterialActivationRef,
): RouterAbEd25519YaoActivationPublicReceiptV1 {
  return {
    transcript: bytes(32, label.length + 10),
    registered_public_key: bytes(32, label.length + 71),
    joined_client_commitment: bytes(32, label.length + 72),
    joined_signing_worker_commitment: bytes(32, label.length + 73),
    signing_worker_verifying_share: bytes(32, label.length + 74),
    state_epoch: 1,
    material_activation: routerAbMpcMaterialActivationRefToWire(materialActivation),
  };
}

export function buildOrdinaryMaterialActivationFixture(label: string): MpcMaterialActivationRef {
  return buildMpcMaterialActivationRefFixture(
    `ordinary-reservation-${label}`,
    `wallet:ordinary-reservation:${label}`,
    `worker:ordinary-reservation:${label}`,
  );
}

export function buildOrdinaryEd25519ActivationExecuteRequestFixture(
  label: string,
  targetBinding: RouterAbEd25519YaoCeremonyBindingV1,
): RouterAbEd25519YaoActivationExecuteRequestV1<'registration'> {
  const parsed = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1({
    binding: targetBinding,
    deriver_a_input: ordinaryEd25519ActivationInput(
      'deriver_a',
      targetBinding,
      label.length + 80,
    ),
    deriver_b_input: ordinaryEd25519ActivationInput(
      'deriver_b',
      targetBinding,
      label.length + 83,
    ),
  });
  if (!parsed.ok) {
    throw new Error(parsed.message);
  }
  return parsed.value;
}

export function buildOrdinaryEcdsaActivationReceiptFixture(
  preparation: OrdinaryEcdsaSignerMaterialReservationPreparationV1,
  signer: ExactAdministeredEcdsaSignerV1,
): LinkedDeviceEcdsaSourcePreservingActivationReceiptV1 {
  const binding = preparation.sourceContribution.binding;
  const sourceNormalSigning = preparation.sourceDerivation.sourceNormalSigning;
  const sourceScope = sourceNormalSigning.scope;
  const targetRelayerPublicKey33B64u = binding.source.relayerPublicKey33B64u;
  const thresholdEthereumAddress20B64u = binding.source.thresholdEthereumAddress20B64u;
  const normalSigning = requireRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: sourceScope.wallet_id,
      ecdsa_threshold_key_id: sourceScope.ecdsa_threshold_key_id,
      signing_root_id: sourceScope.signing_root_id,
      signing_root_version: sourceScope.signing_root_version,
      context: sourceScope.context,
      public_identity: {
        context_binding_b64u: sourceScope.public_identity.context_binding_b64u,
        derivation_client_share_public_key33_b64u: binding.targetClientPublicKey33B64u,
        server_public_key33_b64u: targetRelayerPublicKey33B64u,
        threshold_public_key33_b64u: signer.thresholdPublicKey33B64u,
        ethereum_address20_b64u: thresholdEthereumAddress20B64u,
        client_share_retry_counter: sourceScope.public_identity.client_share_retry_counter,
        server_share_retry_counter: sourceScope.public_identity.server_share_retry_counter,
      },
      material_activation: routerAbMpcMaterialActivationRefToWire(binding.target.activation),
      signing_worker: {
        server_id: binding.target.activation.signingWorker,
        key_epoch: sourceScope.signing_worker.key_epoch,
        recipient_encryption_key: x25519PublicKeyFromB64u(
          binding.target.signingWorkerRecipientPublicKeyB64u,
        ),
      },
      activation_epoch: sourceScope.activation_epoch,
    },
  });
  return {
    state: 'inactive',
    binding,
    sourceDerivation: preparation.sourceDerivation,
    targetRelayerPublicKey33B64u,
    thresholdPublicKey33B64u: signer.thresholdPublicKey33B64u,
    thresholdEthereumAddress20B64u,
    normalSigning,
  };
}

export function buildOrdinaryEd25519ReservationPreparationFixture(
  label: string,
  materialActivation: MpcMaterialActivationRef,
): OrdinaryEd25519SignerMaterialReservationPreparationV1 {
  const sourceActivation = sourceMaterialActivation(materialActivation, label);
  const sourceBinding = parseRouterAbEd25519YaoCeremonyBindingV1(
    ordinaryEd25519Binding(sourceActivation, label),
  );
  const targetBinding = parseRouterAbEd25519YaoCeremonyBindingV1(
    ordinaryEd25519Binding(materialActivation, label),
  );
  const transcript = bytes(32, label.length + 44);
  const sourceRegisteredPublicKeyB64u = encodedBytes(32, label.length + 45);
  const sourceContribution = parseLinkedDeviceOrdinaryMaterialSourceContributionV1({
    kind: 'linked_device_ed25519_source_contribution_v1',
    keyFamily: 'ed25519',
    linkSessionId: `link-session:ordinary-reservation:${label}`,
    enrollmentId: `linked-enrollment:ordinary-reservation:${label}`,
    sourceAuthorityId: `wallet-authority:ordinary-reservation:${label}`,
    walletKeyId: `wallet-key:ordinary-reservation:${label}`,
    targetDeviceId: `linked-device:ordinary-reservation:${label}`,
    targetFactorVerificationDigestB64u: encodedBytes(32, label.length + 46),
    targetMaterialActivation: materialActivation,
    targetClientRecipientPublicKeyB64u: encodedBytes(32, label.length + 47),
    targetSigningWorkerRecipientPublicKeyB64u: encodedBytes(32, label.length + 48),
    sourceBinding,
    reservationId: `ed25519-reservation:ordinary-reservation:${label}`,
    targetBinding,
    activationReceipt: {
      transcript,
      registered_public_key: Array.from(base64UrlDecode(sourceRegisteredPublicKeyB64u)),
      joined_client_commitment: bytes(32, label.length + 49),
      joined_signing_worker_commitment: bytes(32, label.length + 50),
      signing_worker_verifying_share: bytes(32, label.length + 51),
      state_epoch: 1,
      material_activation: routerAbMpcMaterialActivationRefToWire(materialActivation),
    },
    participantIds: [1, 2],
    deriver_a_client_package: buildEd25519ClientPackage(
      'deriver_a',
      label.length + 52,
      targetBinding.session_id,
      transcript,
    ),
    deriver_b_client_package: buildEd25519ClientPackage(
      'deriver_b',
      label.length + 54,
      targetBinding.session_id,
      transcript,
    ),
    sourceRegisteredPublicKeyB64u,
  });
  if (sourceContribution.keyFamily !== 'ed25519') {
    throw new Error('ordinary Ed25519 source contribution has the wrong family');
  }
  return {
    kind: 'ordinary_ed25519_signer_material_reservation_preparation_v1',
    sourceContribution,
    targetBinding,
    applicationBinding: {
      wallet_id: String(materialActivation.materialOwner),
      near_ed25519_signing_key_id: `near-signing-key:ordinary-reservation:${label}`,
      signing_root_id: `signing-root:ordinary-reservation:${label}`,
      key_creation_signer_slot: 1,
    },
  };
}

export function buildOrdinaryEcdsaReservationPreparationFixture(
  label: string,
  materialActivation: MpcMaterialActivationRef,
): OrdinaryEcdsaSignerMaterialReservationPreparationV1 {
  const sourceActivation = sourceMaterialActivation(materialActivation, label);
  const sourcePublicKey33B64u = encodedBytes(33, label.length + 61, 2);
  const sourceRelayerPublicKey33B64u = encodedBytes(33, label.length + 62, 2);
  const sourceThresholdPublicKey33B64u = encodedBytes(33, label.length + 63, 2);
  const thresholdEthereumAddress20B64u = encodedBytes(20, label.length + 64);
  const applicationBindingDigestB64u = encodedBytes(32, label.length + 65);
  const ecdsaThresholdKeyId = parseSdkEcdsaDerivationThresholdKeyId(
    `ecdsa-threshold-key:ordinary-reservation:${label}`,
  );
  const sourceNormalSigning = requireRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: String(materialActivation.materialOwner),
      ecdsa_threshold_key_id: ecdsaThresholdKeyId,
      signing_root_id: `signing-root:ordinary-reservation:${label}`,
      signing_root_version: `signing-root-version:ordinary-reservation:${label}`,
      context: { application_binding_digest_b64u: applicationBindingDigestB64u },
      public_identity: {
        context_binding_b64u: encodedBytes(32, label.length + 66),
        derivation_client_share_public_key33_b64u: sourcePublicKey33B64u,
        server_public_key33_b64u: sourceRelayerPublicKey33B64u,
        threshold_public_key33_b64u: sourceThresholdPublicKey33B64u,
        ethereum_address20_b64u: thresholdEthereumAddress20B64u,
        client_share_retry_counter: 2,
        server_share_retry_counter: 3,
      },
      material_activation: routerAbMpcMaterialActivationRefToWire(sourceActivation),
      signing_worker: {
        server_id: String(materialActivation.signingWorker),
        key_epoch: `signing-worker-key-epoch:ordinary-reservation:${label}`,
        recipient_encryption_key: `x25519:${'ab'.repeat(32)}`,
      },
      activation_epoch: `root-share-epoch:ordinary-reservation:${label}`,
    },
  });
  const targetClientPublicKey33B64u = encodedBytes(33, label.length + 67, 2);
  const targetClientRecipientPublicKeyB64u = encodedBytes(32, label.length + 68);
  const targetSigningWorkerRecipientPublicKeyB64u = encodedBytes(32, label.length + 69);
  const bindingDigestB64u = encodedBytes(32, label.length + 70);
  const binding = {
    linkSessionId: `link-session:ordinary-reservation:${label}`,
    enrollmentId: `linked-enrollment:ordinary-reservation:${label}`,
    sourceAuthorityId: `wallet-authority:ordinary-reservation:${label}`,
    source: {
      activation: sourceActivation,
      clientPublicKey33B64u: sourcePublicKey33B64u,
      relayerPublicKey33B64u: sourceRelayerPublicKey33B64u,
      thresholdPublicKey33B64u: sourceThresholdPublicKey33B64u,
      thresholdEthereumAddress20B64u,
    },
    target: {
      activation: materialActivation,
      targetDeviceId: `linked-device:ordinary-reservation:${label}`,
      targetFactorVerificationDigestB64u: encodedBytes(32, label.length + 70),
      clientRecipientPublicKeyB64u: targetClientRecipientPublicKeyB64u,
      signingWorkerRecipientPublicKeyB64u: targetSigningWorkerRecipientPublicKeyB64u,
    },
    targetClientPublicKey33B64u,
  };
  const sourceContribution = parseLinkedDeviceEcdsaSourceContributionPackageV1({
    binding,
    encryptedDelta: ecdsaSourceContributionEnvelope(
      targetSigningWorkerRecipientPublicKeyB64u,
      bindingDigestB64u,
      label.length + 71,
    ),
    encryptedTargetClientShare: ecdsaSourceContributionEnvelope(
      targetClientRecipientPublicKeyB64u,
      bindingDigestB64u,
      label.length + 73,
    ),
  });
  return {
    kind: 'ordinary_ecdsa_signer_material_reservation_preparation_v1',
    sourceDerivation: {
      applicationBindingDigestB64u: parseDigestB64u(applicationBindingDigestB64u),
      clientShareRetryCounter: 2,
      ecdsaThresholdKeyId,
      sourceNormalSigning,
    },
    sourceContribution,
  };
}

function sourceMaterialActivation(
  target: MpcMaterialActivationRef,
  label: string,
): MpcMaterialActivationRef {
  const activationId = parseMpcMaterialActivationId(
    `activation:ordinary-reservation:${label}:source`,
  );
  if (!activationId.ok) throw new Error(activationId.error.message);
  return buildMpcMaterialActivationRef({
    activationId: activationId.value,
    capability: target.capability,
    materialOwner: target.materialOwner,
    keyBinding: target.keyBinding,
    lifecycleBinding: target.lifecycleBinding,
    signingWorker: target.signingWorker,
  });
}

function ordinaryEd25519Binding(
  materialActivation: MpcMaterialActivationRef,
  label: string,
) {
  return {
    lifecycle: {
      lifecycle_id: `ordinary-reservation:${label}`,
      work_kind: 'registration_prepare' as const,
      primitive_request_kind: 'registration' as const,
      root_share_epoch: `epoch:ordinary-reservation:${label}`,
      account_id: String(materialActivation.materialOwner),
      session_id: `session:ordinary-reservation:${label}`,
      signer_set_id: `signer-set:ordinary-reservation:${label}`,
      selected_server_id: String(materialActivation.signingWorker),
    },
    operation: 'registration' as const,
    session_id: bytes(32, label.length + 43),
    stable_key_context_binding: bytes(32, label.length + 47),
    material_activation: routerAbMpcMaterialActivationRefToWire(materialActivation),
  };
}

function ordinaryEd25519ActivationInput(
  deriver: 'deriver_a' | 'deriver_b',
  binding: RouterAbEd25519YaoCeremonyBindingV1,
  seed: number,
) {
  return {
    kind: 'activation' as const,
    deriver,
    operation: 'registration' as const,
    session: binding.session_id,
    stable_context_binding: binding.stable_key_context_binding,
    encapsulated_key: bytes(32, seed),
    ciphertext: bytes(16, seed + 1),
  };
}

function ecdsaSourceContributionEnvelope(
  recipientPublicKeyB64u: string,
  bindingDigestB64u: string,
  seed: number,
) {
  return {
    kind: LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_ENVELOPE_KIND_V1,
    recipientPublicKeyB64u,
    bindingDigestB64u,
    encappedKeyB64u: encodedBytes(32, seed + 2),
    ciphertextB64u: encodedBytes(32, seed + 3),
  };
}

function x25519PublicKeyFromB64u(value: string): string {
  const decoded = base64UrlDecode(value);
  if (decoded.length !== 32 || base64UrlEncode(decoded) !== value) {
    throw new Error('ordinary ECDSA signing-worker recipient key is invalid');
  }
  let hex = '';
  for (const byte of decoded) hex += byte.toString(16).padStart(2, '0');
  return `x25519:${hex}`;
}

function buildEd25519ClientPackage(
  deriver: 'deriver_a' | 'deriver_b',
  seed: number,
  session: readonly number[],
  transcript: readonly number[],
): RouterAbEd25519YaoActivationClientPackageV1<typeof deriver> {
  return {
    kind: 'activation_client',
    deriver,
    session,
    transcript,
    encapsulated_key: bytes(32, seed + 2),
    ciphertext: bytes(32, seed + 3),
  };
}

function encodedBytes(length: number, seed: number, firstByte?: number): string {
  const value = bytes(length, seed);
  if (firstByte !== undefined) value[0] = firstByte;
  return base64UrlEncode(new Uint8Array(value));
}

function bytes(length: number, seed: number): number[] {
  return Array.from({ length }, (_, index) => (seed + index) % 256);
}
