import {
  parseExactAdministeredSignerManifestV1,
  type ExactAdministeredEcdsaSignerV1,
  type ExactAdministeredEd25519SignerV1,
} from '@shared/device-linking/delegatedActivationPlan';
import { base64UrlEncode } from '@shared/utils/base64';
import type { RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbEd25519YaoActivationClientPackageV1 } from '@shared/utils/routerAbEd25519Yao';
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
  return {
    kind: 'ordinary_ed25519_client_material_v1' as const,
    deriver_a_client_package: buildEd25519ClientPackage('deriver_a', label.length + 11),
    deriver_b_client_package: buildEd25519ClientPackage('deriver_b', label.length + 17),
  };
}

export function buildOrdinaryEcdsaClientMaterialFixture(label: string): {
  readonly kind: 'ordinary_ecdsa_client_material_v1';
  readonly deriver_a_client_package: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_a'>;
  readonly deriver_b_client_package: RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<'signer_b'>;
} {
  return {
    kind: 'ordinary_ecdsa_client_material_v1',
    deriver_a_client_package: buildEcdsaClientPackage('signer_a', label.length + 23),
    deriver_b_client_package: buildEcdsaClientPackage('signer_b', label.length + 29),
  };
}

export function buildOrdinaryMaterialActivationFixture(label: string) {
  return buildMpcMaterialActivationRefFixture(
    `ordinary-reservation-${label}`,
    `wallet:ordinary-reservation:${label}`,
    `worker:ordinary-reservation:${label}`,
  );
}

function buildEd25519ClientPackage(
  deriver: 'deriver_a' | 'deriver_b',
  seed: number,
): RouterAbEd25519YaoActivationClientPackageV1<typeof deriver> {
  return {
    kind: 'activation_client',
    deriver,
    session: bytes(32, seed),
    transcript: bytes(32, seed + 1),
    encapsulated_key: bytes(32, seed + 2),
    ciphertext: bytes(32, seed + 3),
  };
}

function buildEcdsaClientPackage<Role extends 'signer_a' | 'signer_b'>(
  role: Role,
  seed: number,
): RouterAbEcdsaDerivationRoleEncryptedEnvelopeV1<Role> {
  return {
    recipient_role: role,
    header_digest: { bytes: bytes(32, seed) },
    aad_digest: { bytes: bytes(32, seed + 1) },
    ciphertext: { bytes: bytes(32, seed + 2) },
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
