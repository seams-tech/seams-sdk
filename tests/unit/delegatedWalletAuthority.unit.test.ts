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
  buildExactAdministeredSignerManifestV1,
  parseExactAdministeredSignerManifestV1,
} from '../../packages/shared-ts/src/device-linking/delegatedActivationPlan';
import {
  parseQrLinkedDeviceSessionPayloadV5,
  parseQrLinkedDeviceSessionTextV5,
  serializeQrLinkedDeviceSessionPayloadV5,
} from '../../packages/shared-ts/src/device-linking/parsers';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/base64';

const ED25519_PUBLIC_KEY_B64U = base64UrlEncode(new Uint8Array(32).fill(1));
const ECDSA_PUBLIC_KEY_B64U = base64UrlEncode(Uint8Array.from([2, ...new Uint8Array(32).fill(2)]));
const RECIPIENT_PUBLIC_KEY_B64U = base64UrlEncode(new Uint8Array(32).fill(4));

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

test('administered signer manifest binds one exact canonical family set', () => {
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
  expect(dual.keyFamilies).toEqual(['ed25519', 'ecdsa_secp256k1']);
  expect(dual.signers).toEqual([ed25519.signers[0], ecdsa.signers[0]]);
});
