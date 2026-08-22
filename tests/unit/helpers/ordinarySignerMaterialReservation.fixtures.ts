import {
  parseExactAdministeredSignerManifestV1,
  type ExactAdministeredEcdsaSignerV1,
  type ExactAdministeredEd25519SignerV1,
} from '@shared/device-linking/delegatedActivationPlan';
import { base64UrlEncode } from '@shared/utils/base64';
import type { RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1 } from '@shared/utils/routerAbEcdsaDerivation';
import {
  parseRouterAbEcdsaRegistrationRequestV1,
  type RouterAbEcdsaRegistrationRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1,
  type RouterAbEd25519YaoActivationPublicReceiptV1,
  type RouterAbEd25519YaoActivationClientPackageV1,
} from '@shared/utils/routerAbEd25519Yao';
import type {
  OrdinaryEcdsaSignerMaterialReservationPreparationV1,
  OrdinaryEd25519SignerMaterialReservationPreparationV1,
} from '../../../packages/wallet-server/src/core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
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

export function buildOrdinaryEcdsaClientMaterialFixture(
  label: string,
  recipientPublicKey = `x25519:${'22'.repeat(32)}`,
  keyEpoch = `epoch:ordinary-reservation:${label}`,
): {
  readonly kind: 'ordinary_ecdsa_client_material_v1';
  readonly deriver_a_client_package: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_a'>;
  readonly deriver_b_client_package: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_b'>;
} {
  return {
    kind: 'ordinary_ecdsa_client_material_v1',
    deriver_a_client_package: buildEcdsaClientPackage(
      'signer_a',
      label.length + 23,
      recipientPublicKey,
      keyEpoch,
    ),
    deriver_b_client_package: buildEcdsaClientPackage(
      'signer_b',
      label.length + 29,
      recipientPublicKey,
      keyEpoch,
    ),
  };
}

export function buildOrdinaryMaterialActivationFixture(label: string) {
  return buildMpcMaterialActivationRefFixture(
    `ordinary-reservation-${label}`,
    `wallet:ordinary-reservation:${label}`,
    `worker:ordinary-reservation:${label}`,
  );
}

export function buildOrdinaryEd25519ReservationPreparationFixture(
  label: string,
  materialActivation: MpcMaterialActivationRef,
): OrdinaryEd25519SignerMaterialReservationPreparationV1 {
  const binding = {
    lifecycle: {
      lifecycle_id: `ordinary-reservation:${label}`,
      work_kind: 'registration_prepare' as const,
      primitive_request_kind: 'registration' as const,
      root_share_epoch: `epoch:ordinary-reservation:${label}`,
      account_id: materialActivation.materialOwner,
      session_id: `session:ordinary-reservation:${label}`,
      signer_set_id: `signer-set:ordinary-reservation:${label}`,
      selected_server_id: materialActivation.signingWorker,
    },
    operation: 'registration' as const,
    session_id: bytes(32, label.length + 43),
    stable_key_context_binding: bytes(32, label.length + 47),
    material_activation: routerAbMpcMaterialActivationRefToWire(materialActivation),
  };
  const parsed = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1({
    binding,
    deriver_a_input: activationInput('deriver_a', binding, label.length + 51),
    deriver_b_input: activationInput('deriver_b', binding, label.length + 53),
  });
  if (!parsed.ok) throw new Error(parsed.message);
  return {
    kind: 'ordinary_ed25519_signer_material_reservation_preparation_v1',
    activationRequest: parsed.value,
    participantIds: [1, 2],
  };
}

export function buildOrdinaryEcdsaReservationPreparationFixture(
  label: string,
  materialActivation: MpcMaterialActivationRef,
): OrdinaryEcdsaSignerMaterialReservationPreparationV1 {
  const digest = { bytes: bytes(32, label.length + 61) };
  const registrationRequest: RouterAbEcdsaRegistrationRequestV1 =
    parseRouterAbEcdsaRegistrationRequestV1({
      registration_purpose: 'wallet_add_signer',
      context: { application_binding_digest_b64u: encodedBytes(32, label.length + 63) },
      lifecycle: {
        lifecycle_id: `ordinary-reservation:${label}`,
        work_kind: 'registration_prepare',
        primitive_request_kind: 'registration',
        root_share_epoch: `epoch:ordinary-reservation:${label}`,
        account_id: materialActivation.materialOwner,
        session_id: `session:ordinary-reservation:${label}`,
        signer_set_id: `signer-set:ordinary-reservation:${label}`,
        selected_server_id: materialActivation.signingWorker,
      },
      signer_set: {
        signer_set_id: `signer-set:ordinary-reservation:${label}`,
        policy: 'all_2',
        signer_a: {
          role: 'signer_a',
          signer_id: `signer-a:ordinary-reservation:${label}`,
          key_epoch: `epoch:ordinary-reservation:${label}`,
        },
        signer_b: {
          role: 'signer_b',
          signer_id: `signer-b:ordinary-reservation:${label}`,
          key_epoch: `epoch:ordinary-reservation:${label}`,
        },
        selected_server: {
          server_id: materialActivation.signingWorker,
          key_epoch: `epoch:ordinary-reservation:${label}`,
          recipient_encryption_key: `x25519:${'11'.repeat(32)}`,
        },
      },
      router_id: `router:ordinary-reservation:${label}`,
      client_id: `client:ordinary-reservation:${label}`,
      client_ephemeral_public_key: `x25519:${'22'.repeat(32)}`,
      replay_nonce: `nonce:ordinary-reservation:${label}`,
      expires_at_ms: 4_000_000_000,
      deriver_a_envelope: {
        recipient_role: 'signer_a',
        header_digest: digest,
        aad_digest: { bytes: bytes(32, label.length + 65) },
        ciphertext: { bytes: bytes(16, label.length + 67) },
      },
      deriver_b_envelope: {
        recipient_role: 'signer_b',
        header_digest: { bytes: bytes(32, label.length + 69) },
        aad_digest: { bytes: bytes(32, label.length + 71) },
        ciphertext: { bytes: bytes(16, label.length + 73) },
      },
    });
  return {
    kind: 'ordinary_ecdsa_signer_material_reservation_preparation_v1',
    registrationRequest,
    materialActivation,
  };
}

function activationInput(
  deriver: 'deriver_a' | 'deriver_b',
  binding: {
    readonly lifecycle: { readonly lifecycle_id: string };
    readonly operation: 'registration';
    readonly session_id: readonly number[];
    readonly stable_key_context_binding: readonly number[];
  },
  seed: number,
) {
  return {
    kind: 'activation' as const,
    deriver,
    operation: 'registration' as const,
    session: binding.session_id,
    stable_context_binding: binding.stable_key_context_binding,
    encapsulated_key: bytes(32, seed),
    ciphertext: bytes(32, seed + 1),
  };
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

function buildEcdsaClientPackage<Role extends 'signer_a' | 'signer_b'>(
  role: Role,
  seed: number,
  recipientPublicKey: string,
  keyEpoch: string,
): RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<Role> {
  const aadDigest = bytes(32, seed + 1);
  return {
    recipient_role: role,
    header_digest: { bytes: bytes(32, seed) },
    aad_digest: { bytes: aadDigest },
    ciphertext: {
      bytes: encodeEcdsaSignerEnvelopePayload(
        role,
        keyEpoch,
        recipientPublicKey,
        aadDigest,
        seed + 2,
      ),
    },
  };
}

function encodeEcdsaSignerEnvelopePayload(
  role: 'signer_a' | 'signer_b',
  keyEpoch: string,
  recipientPublicKey: string,
  aadDigest: readonly number[],
  seed: number,
): number[] {
  const output: number[] = [];
  appendLengthPrefixed(output, 'router-ab-protocol/signer-envelope-hpke/v1');
  appendLengthPrefixed(output, 'hpke-x25519-hkdf-sha256-aes256gcm/v1');
  appendLengthPrefixed(output, role);
  appendLengthPrefixed(output, keyEpoch);
  appendLengthPrefixed(output, recipientPublicKey);
  appendLengthPrefixed(output, aadDigest);
  appendLengthPrefixed(output, bytes(32, seed + 1));
  appendU32(output, 16);
  appendLengthPrefixed(output, bytes(32, seed + 2));
  return output;
}

function appendLengthPrefixed(output: number[], value: string | readonly number[]): void {
  const bytesValue = typeof value === 'string' ? Array.from(new TextEncoder().encode(value)) : value;
  appendU32(output, bytesValue.length);
  output.push(...bytesValue);
}

function appendU32(output: number[], value: number): void {
  output.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function encodedBytes(length: number, seed: number, firstByte?: number): string {
  const value = bytes(length, seed);
  if (firstByte !== undefined) value[0] = firstByte;
  return base64UrlEncode(new Uint8Array(value));
}

function bytes(length: number, seed: number): number[] {
  return Array.from({ length }, (_, index) => (seed + index) % 256);
}
