import {
  parseExactAdministeredSignerManifestV1,
  type ExactAdministeredEcdsaSignerV1,
  type ExactAdministeredEd25519SignerV1,
} from '@shared/device-linking/delegatedActivationPlan';
import {
  parseLinkedDeviceEcdsaSourceContributionPackageV1,
  parseLinkedDeviceOrdinaryMaterialSourceContributionV1,
  LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_ENVELOPE_KIND_V1,
} from '@shared/device-linking/sourceContribution';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseSdkEcdsaDerivationThresholdKeyId } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { requireRouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  buildMpcMaterialActivationRef,
  parseCapabilityInstanceRef,
  parseMpcKeyBindingRef,
  parseMpcLifecycleBindingRef,
  parseMpcMaterialActivationId,
  parseMpcMaterialOwnerRef,
  parseMpcSigningWorkerRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { parseRouterAbEd25519YaoCeremonyBindingV1 } from '@shared/utils/routerAbEd25519Yao';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type {
  OrdinaryEcdsaSignerMaterialReservationRequestV1,
  OrdinaryEd25519SignerMaterialReservationRequestV1,
} from '../../../packages/wallet-server/src/core/signingMaterial/ordinaryInactiveSignerMaterialReservation';

export function buildSourcePreservingEd25519ReservationRequestFixture(
  label = 'http-ed25519',
): OrdinaryEd25519SignerMaterialReservationRequestV1 {
  const sourceActivation = buildActivation(label, 'source');
  const targetActivation = buildFreshActivation(sourceActivation, `${label}-target`);
  const sourceBinding = parseRouterAbEd25519YaoCeremonyBindingV1(
    buildEd25519Binding(sourceActivation, label),
  );
  const targetBinding = parseRouterAbEd25519YaoCeremonyBindingV1(
    buildEd25519Binding(targetActivation, label),
  );
  const sourceContribution = parseLinkedDeviceOrdinaryMaterialSourceContributionV1({
    kind: 'linked_device_ed25519_source_contribution_v1',
    keyFamily: 'ed25519',
    linkSessionId: `link-session:${label}`,
    enrollmentId: `linked-enrollment:${label}`,
    sourceAuthorityId: `wallet-authority:${label}`,
    walletKeyId: `wallet-key:${label}`,
    targetDeviceId: `linked-device:${label}`,
    targetFactorVerificationDigestB64u: encodedBytes(32, 21),
    targetMaterialActivation: targetActivation,
    targetClientRecipientPublicKeyB64u: encodedBytes(32, 23),
    targetSigningWorkerRecipientPublicKeyB64u: encodedBytes(32, 25),
    sourceBinding,
    reservationId: `ed25519-reservation:${label}`,
    targetBinding,
    activationReceipt: {
      transcript: bytes(32, 41),
      registered_public_key: bytes(32, 53),
      joined_client_commitment: bytes(32, 55),
      joined_signing_worker_commitment: bytes(32, 57),
      signing_worker_verifying_share: bytes(32, 59),
      state_epoch: 1,
      material_activation: routerAbMpcMaterialActivationRefToWire(targetActivation),
    },
    participantIds: [1, 2],
    deriver_a_client_package: buildEd25519Package(
      'activation_client',
      'deriver_a',
      targetBinding,
      41,
    ),
    deriver_b_client_package: buildEd25519Package(
      'activation_client',
      'deriver_b',
      targetBinding,
      41,
    ),
    sourceRegisteredPublicKeyB64u: encodedBytes(32, 53),
  });
  if (sourceContribution.keyFamily !== 'ed25519') {
    throw new Error('Ed25519 fixture has the wrong key family');
  }

  return {
    kind: 'ordinary_ed25519_signer_material_reservation_request_v1',
    keyFamily: 'ed25519',
    signer: buildEd25519Signer(label),
    plannedActivationRef: targetActivation,
    preparation: {
      kind: 'ordinary_ed25519_signer_material_reservation_preparation_v1',
      sourceContribution,
      targetBinding,
      applicationBinding: {
        wallet_id: `wallet:${label}`,
        near_ed25519_signing_key_id: `near-signing-key:${label}`,
        signing_root_id: `signing-root:${label}`,
        key_creation_signer_slot: 1,
      },
    },
  };
}

export function buildSourcePreservingEcdsaReservationRequestFixture(
  label = 'http-ecdsa',
): OrdinaryEcdsaSignerMaterialReservationRequestV1 {
  const sourceActivation = buildActivation(label, 'source');
  const targetActivation = buildActivation(label, 'target');
  const sourcePublicKey = encodedBytes(33, 61, 2);
  const relayerPublicKey = encodedBytes(33, 63, 2);
  const thresholdPublicKey = encodedBytes(33, 65, 2);
  const clientRecipient = encodedBytes(32, 67);
  const signingWorkerRecipient = encodedBytes(32, 69);
  const ecdsaThresholdKeyId = parseSdkEcdsaDerivationThresholdKeyId('ecdsa-threshold-key:r103');
  const sourceNormalSigning = requireRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: sourceActivation.materialOwner,
      ecdsa_threshold_key_id: ecdsaThresholdKeyId,
      signing_root_id: `signing-root:${label}`,
      signing_root_version: `signing-root-version:${label}`,
      context: {
        application_binding_digest_b64u: encodedBytes(32, 89),
      },
      public_identity: {
        context_binding_b64u: encodedBytes(32, 91),
        derivation_client_share_public_key33_b64u: sourcePublicKey,
        server_public_key33_b64u: relayerPublicKey,
        threshold_public_key33_b64u: thresholdPublicKey,
        ethereum_address20_b64u: encodedBytes(20, 71),
        client_share_retry_counter: 2,
        server_share_retry_counter: 3,
      },
      material_activation: routerAbMpcMaterialActivationRefToWire(sourceActivation),
      signing_worker: {
        server_id: sourceActivation.signingWorker,
        key_epoch: `signing-worker-key-epoch:${label}`,
        recipient_encryption_key: `x25519:${'ab'.repeat(32)}`,
      },
      activation_epoch: `root-share-epoch:${label}`,
    },
  });
  const binding = {
    linkSessionId: `link-session:${label}`,
    enrollmentId: `linked-enrollment:${label}`,
    sourceAuthorityId: `wallet-authority:${label}`,
    source: {
      activation: sourceActivation,
      clientPublicKey33B64u: sourcePublicKey,
      relayerPublicKey33B64u: relayerPublicKey,
      thresholdPublicKey33B64u: thresholdPublicKey,
      thresholdEthereumAddress20B64u: encodedBytes(20, 71),
    },
    target: {
      activation: targetActivation,
      targetDeviceId: `linked-device:${label}`,
      targetFactorVerificationDigestB64u: encodedBytes(32, 73),
      clientRecipientPublicKeyB64u: clientRecipient,
      signingWorkerRecipientPublicKeyB64u: signingWorkerRecipient,
    },
    targetClientPublicKey33B64u: encodedBytes(33, 75, 2),
  };
  const sourceContribution = parseLinkedDeviceEcdsaSourceContributionPackageV1({
    binding,
    encryptedDelta: buildEcdsaEnvelope(signingWorkerRecipient, 77),
    encryptedTargetClientShare: buildEcdsaEnvelope(clientRecipient, 83),
  });

  return {
    kind: 'ordinary_ecdsa_signer_material_reservation_request_v1',
    keyFamily: 'ecdsa_secp256k1',
    signer: buildEcdsaSigner(label),
    plannedActivationRef: targetActivation,
    preparation: {
      kind: 'ordinary_ecdsa_signer_material_reservation_preparation_v1',
      sourceDerivation: {
        applicationBindingDigestB64u: parseDigestB64u(encodedBytes(32, 89)),
        clientShareRetryCounter: 2,
        ecdsaThresholdKeyId,
        sourceNormalSigning,
      },
      sourceContribution,
    },
  };
}

function buildEd25519Signer(label: string): ExactAdministeredEd25519SignerV1 {
  const manifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519'],
    signers: [
      {
        kind: 'exact_administered_ed25519_signer_v1',
        keyFamily: 'ed25519',
        walletId: `wallet:${label}`,
        walletKeyId: `wallet-key:${label}`,
        registeredPublicKeyB64u: encodedBytes(32, 97),
      },
    ],
  });
  const signer = manifest.signers[0];
  if (!signer || signer.keyFamily !== 'ed25519') {
    throw new Error('Ed25519 signer fixture is invalid');
  }
  return signer;
}

function buildEcdsaSigner(label: string): ExactAdministeredEcdsaSignerV1 {
  const manifest = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ecdsa_secp256k1'],
    signers: [
      {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId: `wallet:${label}`,
        walletKeyId: `wallet-key:${label}`,
        thresholdPublicKey33B64u: encodedBytes(33, 101, 2),
        evmAddress: '0x1111111111111111111111111111111111111111',
      },
    ],
  });
  const signer = manifest.signers[0];
  if (!signer || signer.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('ECDSA signer fixture is invalid');
  }
  return signer;
}

function buildActivation(label: string, role: string): MpcMaterialActivationRef {
  return buildMpcMaterialActivationRef({
    activationId: unwrap(parseMpcMaterialActivationId(`activation:${label}:${role}`)),
    capability: unwrap(parseCapabilityInstanceRef(`capability:${label}`)),
    materialOwner: unwrap(parseMpcMaterialOwnerRef(`owner:${label}`)),
    keyBinding: unwrap(parseMpcKeyBindingRef(`key:${label}`)),
    lifecycleBinding: unwrap(parseMpcLifecycleBindingRef(`lifecycle:${label}`)),
    signingWorker: unwrap(parseMpcSigningWorkerRef(`worker:${label}`)),
  });
}

function buildFreshActivation(
  source: MpcMaterialActivationRef,
  label: string,
): MpcMaterialActivationRef {
  return buildMpcMaterialActivationRef({
    activationId: unwrap(parseMpcMaterialActivationId(`activation:${label}`)),
    capability: source.capability,
    materialOwner: source.materialOwner,
    keyBinding: source.keyBinding,
    lifecycleBinding: source.lifecycleBinding,
    signingWorker: source.signingWorker,
  });
}

function buildEd25519Binding(
  activation: MpcMaterialActivationRef,
  label: string,
): Record<string, unknown> {
  return {
    lifecycle: {
      lifecycle_id: `lifecycle:${label}`,
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: `epoch:${label}`,
      account_id: activation.materialOwner,
      session_id: `session:${label}`,
      signer_set_id: `signer-set:${label}`,
      selected_server_id: activation.signingWorker,
    },
    operation: 'registration',
    session_id: bytes(32, 107),
    stable_key_context_binding: bytes(32, 109),
    material_activation: routerAbMpcMaterialActivationRefToWire(activation),
  };
}

function buildEd25519Package(
  kind: 'activation_client' | 'activation_signing_worker',
  deriver: 'deriver_a' | 'deriver_b',
  binding: Record<string, unknown>,
  seed: number,
): Record<string, unknown> {
  return {
    kind,
    deriver,
    session: binding.session_id,
    transcript: bytes(32, seed),
    encapsulated_key: bytes(32, seed + 1),
    ciphertext: bytes(32, seed + 2),
  };
}

function buildEcdsaEnvelope(recipientPublicKeyB64u: string, seed: number): Record<string, unknown> {
  return {
    kind: LINKED_DEVICE_ECDSA_SOURCE_CONTRIBUTION_ENVELOPE_KIND_V1,
    recipientPublicKeyB64u,
    bindingDigestB64u: encodedBytes(32, 113),
    encappedKeyB64u: encodedBytes(32, seed),
    ciphertextB64u: encodedBytes(32, seed + 1),
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

function unwrap<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}
