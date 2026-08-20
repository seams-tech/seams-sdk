import { expect, test } from '@playwright/test';
import {
  buildFullOwnerDelegatedWalletAuthorityV1,
  buildSigningOnlyDelegatedWalletAuthorityV1,
  delegatedWalletPermissionNamesV1,
  hasDelegatedWalletPermissionV1,
  parseDelegatedWalletAuthorityV1,
  parseDelegatedWalletPermissionSetV1,
  sameDelegatedWalletAuthorityV1,
  validateDelegatedWalletAuthorityAttenuationV1,
} from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import {
  buildDelegatedDeviceActivationPlanV1,
  buildExactAdministeredSignerManifestV1,
  parseDelegatedDeviceActivationPlanV1,
  parseExactAdministeredSignerManifestV1,
  parseFactorBoundEd25519ExportRootPackageV1,
} from '../../packages/shared-ts/src/device-linking/delegatedActivationPlan';
import {
  parseQrLinkedDeviceSessionPayloadV5,
  parseQrLinkedDeviceSessionTextV5,
  serializeQrLinkedDeviceSessionPayloadV5,
} from '../../packages/shared-ts/src/device-linking/parsers';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';

const ED25519_PUBLIC_KEY_B64U = base64UrlEncode(new Uint8Array(32).fill(1));
const ECDSA_PUBLIC_KEY_B64U = base64UrlEncode(Uint8Array.from([2, ...new Uint8Array(32).fill(2)]));
const DIGEST_B64U = base64UrlEncode(new Uint8Array(32).fill(3));
const RECIPIENT_PUBLIC_KEY_B64U = base64UrlEncode(new Uint8Array(32).fill(4));
const EPHEMERAL_PUBLIC_KEY_B64U = base64UrlEncode(new Uint8Array(32).fill(6));
const NONCE_B64U = base64UrlEncode(new Uint8Array(12).fill(7));
const CIPHERTEXT_B64U = base64UrlEncode(new Uint8Array(17).fill(5));

function ed25519Signer(): Record<string, unknown> {
  return {
    kind: 'exact_administered_ed25519_signer_v1',
    keyFamily: 'ed25519',
    walletId: 'wallet:r103d',
    walletKeyId: 'wallet-key:ed25519:r103d',
    registeredPublicKeyB64u: ED25519_PUBLIC_KEY_B64U,
  };
}

function ecdsaSigner(): Record<string, unknown> {
  return {
    kind: 'exact_administered_ecdsa_signer_v1',
    keyFamily: 'ecdsa_secp256k1',
    walletId: 'wallet:r103d',
    walletKeyId: 'wallet-key:ecdsa:r103d',
    thresholdPublicKey33B64u: ECDSA_PUBLIC_KEY_B64U,
    evmAddress: '0x1111111111111111111111111111111111111111',
  };
}

function exportRootPackage(): Record<string, unknown> {
  return {
    kind: 'linked_device_ed25519_export_root_package_v1',
    linkSessionId: 'link-session:r103d',
    walletId: 'wallet:r103d',
    walletKeyId: 'wallet-key:ed25519:r103d',
    transferAlg: 'x25519-hkdf-sha256-chacha20poly1305-v1',
    applicationBindingDigestB64u: DIGEST_B64U,
    registeredPublicKeyB64u: ED25519_PUBLIC_KEY_B64U,
    enrollmentId: 'enrollment:r103d',
    deviceId: 'device:r103d',
    targetFactor: { kind: 'passkey_prf' },
    recipientPublicKeyB64u: RECIPIENT_PUBLIC_KEY_B64U,
    ephemeralPublicKeyB64u: EPHEMERAL_PUBLIC_KEY_B64U,
    nonceB64u: NONCE_B64U,
    sealedExportRootB64u: CIPHERTEXT_B64U,
    ciphertextDigestB64u: DIGEST_B64U,
    bindingDigestB64u: DIGEST_B64U,
    revocationEpoch: 0,
    sealedAtMs: 1,
  };
}

test('permission parser returns sorted opaque sets and rejects boundary mistakes', () => {
  const parsed = parseDelegatedWalletPermissionSetV1(['sign', 'export_keys', 'link_devices']);
  expect(parsed.ok).toBe(true);
  if (!parsed.ok) return;
  expect([...parsed.value]).toEqual(['export_keys', 'link_devices', 'sign']);
  expect(parseDelegatedWalletPermissionSetV1([]).ok).toBe(false);
  expect(parseDelegatedWalletPermissionSetV1(['sign', 'sign']).ok).toBe(false);
  expect(parseDelegatedWalletPermissionSetV1(['unknown']).ok).toBe(false);
});

test('authority builders round-trip through the canonical wire shape', () => {
  const authority = buildFullOwnerDelegatedWalletAuthorityV1();
  expect(JSON.parse(JSON.stringify(authority))).toEqual({
    kind: 'delegated_wallet_authority_v1',
    permissions: ['export_keys', 'link_devices', 'revoke_devices', 'sign'],
  });
  expect(delegatedWalletPermissionNamesV1(authority)).toEqual([
    'export_keys',
    'link_devices',
    'revoke_devices',
    'sign',
  ]);
  const parsed = parseDelegatedWalletAuthorityV1(JSON.parse(JSON.stringify(authority)));
  expect(parsed.ok).toBe(true);
  if (!parsed.ok) return;
  expect([...parsed.value.permissions]).toEqual([
    'export_keys',
    'link_devices',
    'revoke_devices',
    'sign',
  ]);
  expect(sameDelegatedWalletAuthorityV1(authority, parsed.value)).toBe(true);
});

test('linked-device QR boundaries carry the delegated authority', () => {
  const payload = parseQrLinkedDeviceSessionPayloadV5({
    version: 'v5',
    purpose: 'linked_device_lane_creation',
    linkSessionId: 'link-session:r103d',
    linkPublicKeyB64u: RECIPIENT_PUBLIC_KEY_B64U,
    devicePublicKeyB64u: RECIPIENT_PUBLIC_KEY_B64U,
    requestedPermission: {
      kind: 'delegated_wallet_authority_v1',
      permissions: ['sign', 'link_devices'],
    },
    targetFactor: { kind: 'passkey_prf' },
    issuedAtMs: 1,
    expiresAtMs: 2,
  });
  const roundTrip = parseQrLinkedDeviceSessionTextV5(
    serializeQrLinkedDeviceSessionPayloadV5(payload),
  );
  expect([...roundTrip.requestedPermission.permissions]).toEqual(['link_devices', 'sign']);
});

test('attenuation allows only a child subset and presets are not persisted branches', () => {
  const parent = buildFullOwnerDelegatedWalletAuthorityV1();
  const child = buildSigningOnlyDelegatedWalletAuthorityV1();
  expect(validateDelegatedWalletAuthorityAttenuationV1({ parent, child })).toEqual({
    ok: true,
    value: true,
  });
  expect(hasDelegatedWalletPermissionV1(child, 'export_keys')).toBe(false);
  expect(parseDelegatedWalletAuthorityV1({ kind: 'full_owner' }).ok).toBe(false);
});

test('activation plan binds complete families and derives permission material', () => {
  const ed25519 = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519'],
    signers: [ed25519Signer()],
  });
  const ecdsa = parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ecdsa_secp256k1'],
    signers: [ecdsaSigner()],
  });
  const dual = buildExactAdministeredSignerManifestV1([...ed25519.signers, ...ecdsa.signers]);
  const packageValue = parseFactorBoundEd25519ExportRootPackageV1(exportRootPackage());
  const plan = buildDelegatedDeviceActivationPlanV1({
    authority: buildFullOwnerDelegatedWalletAuthorityV1(),
    sourceSignerManifest: dual,
    ed25519ExportRootPackage: packageValue,
  });

  expect(plan.signing.kind).toBe('required');
  expect(plan.signing.activations.keyFamilies).toEqual(['ed25519', 'ecdsa_secp256k1']);
  expect(plan.ed25519Export.kind).toBe('required');
  expect(plan.ecdsaExport.kind).toBe('required');
  expect(
    buildDelegatedDeviceActivationPlanV1({
      authority: buildSigningOnlyDelegatedWalletAuthorityV1(),
      sourceSignerManifest: ed25519,
      ed25519ExportRootPackage: null,
    }).ed25519Export.kind,
  ).toBe('not_granted');
  expect(
    buildDelegatedDeviceActivationPlanV1({
      authority: buildFullOwnerDelegatedWalletAuthorityV1(),
      sourceSignerManifest: ecdsa,
      ed25519ExportRootPackage: null,
    }).ed25519Export.kind,
  ).toBe('family_absent');
});

test('activation boundary rejects missing or contradictory Ed25519 export material', () => {
  const authority = { kind: 'delegated_wallet_authority_v1', permissions: ['export_keys'] };
  const manifest = {
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ed25519'],
    signers: [ed25519Signer()],
  };
  expect(
    parseDelegatedDeviceActivationPlanV1({
      authority,
      sourceSignerManifest: manifest,
      ed25519ExportRootPackage: null,
    }).ok,
  ).toBe(false);
  expect(
    parseDelegatedDeviceActivationPlanV1({
      authority,
      sourceSignerManifest: manifest,
      ed25519ExportRootPackage: { ...exportRootPackage(), transferAlg: 'wrong' },
    }).ok,
  ).toBe(false);
});
