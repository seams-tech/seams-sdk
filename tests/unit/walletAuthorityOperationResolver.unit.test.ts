import { expect, test } from '@playwright/test';
import {
  buildFullOwnerPermissionsV1,
  buildSigningOnlyPermissionsV1,
} from '@shared/authorization/delegatedAuthority';
import {
  buildActiveWalletAuthorityV1,
  buildRevokedWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type ActiveWalletAuthorityV1,
  type WalletEcdsaSignerActivationV1,
  type WalletEd25519SignerActivationV1,
} from '@shared/authorization/walletAuthority';
import { parseDeviceId } from '@shared/authorization/capabilityKinds';
import { parseExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import {
  resolveWalletAuthorityOperation,
  type SelectedWalletAuthorityV1,
  type WalletAuthorityOperationV1,
} from '../../packages/wallet/src/core/signingEngine/session/authority';

type SignerFamily = 'ed25519' | 'ecdsa_secp256k1';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function encodedBytes(length: number, fill: number, firstByte?: number): string {
  const bytes = new Uint8Array(length);
  bytes.fill(fill);
  if (firstByte !== undefined) bytes[0] = firstByte;
  return base64UrlEncode(bytes);
}

function buildSignerManifest(
  family: SignerFamily,
  walletId: string,
  label: string,
): ReturnType<typeof parseExactAdministeredSignerManifestV1> {
  if (family === 'ed25519') {
    return parseExactAdministeredSignerManifestV1({
      kind: 'exact_administered_signer_manifest_v1',
      keyFamilies: ['ed25519'],
      signers: [
        {
          kind: 'exact_administered_ed25519_signer_v1',
          keyFamily: 'ed25519',
          walletId,
          walletKeyId: `wallet-key:authority-resolver-${label}`,
          registeredPublicKeyB64u: encodedBytes(32, 3),
        },
      ],
    });
  }
  return parseExactAdministeredSignerManifestV1({
    kind: 'exact_administered_signer_manifest_v1',
    keyFamilies: ['ecdsa_secp256k1'],
    signers: [
      {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId,
        walletKeyId: `wallet-key:authority-resolver-${label}`,
        thresholdPublicKey33B64u: encodedBytes(33, 4, 2),
        evmAddress: '0x1111111111111111111111111111111111111111',
      },
    ],
  });
}

function buildSignerActivations(family: SignerFamily, walletId: string, label: string) {
  const manifest = buildSignerManifest(family, walletId, label);
  const materialActivation = buildMpcMaterialActivationRefFixture(
    `authority-resolver-${label}`,
    walletId,
  );
  if (family === 'ed25519') {
    return buildWalletSignerActivationSetV1({
      manifest,
      materialActivations: {
        keyFamilies: ['ed25519'],
        ed25519: materialActivation,
      },
    });
  }
  return buildWalletSignerActivationSetV1({
    manifest,
    materialActivations: {
      keyFamilies: ['ecdsa_secp256k1'],
      ecdsa: materialActivation,
    },
  });
}

async function buildAuthority(
  family: SignerFamily,
  permissions = buildFullOwnerPermissionsV1(),
): Promise<ActiveWalletAuthorityV1> {
  const label = family === 'ed25519' ? 'ed25519' : 'ecdsa';
  const walletId = required(parseWalletId(`wallet:authority-resolver-${label}`));
  const authorityId = required(parseWalletAuthorityId(`authority:authority-resolver-${label}`));
  const deviceId = required(parseDeviceId(`device:authority-resolver-${label}`));
  const signerActivations = buildSignerActivations(family, walletId, label);
  const signerActivationSetDigestB64u = parseDigestB64u(
    await computeWalletSignerActivationSetDigestB64u(signerActivations),
  );
  const draft = buildActiveWalletAuthorityV1({
    kind: 'wallet_authority_v1',
    authorityId,
    walletId,
    principal: { kind: 'owner_device', deviceId },
    provenance: { kind: 'wallet_registration' },
    permissions,
    signerActivations,
    signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(encodedBytes(32, 8)),
    revocationEpoch: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    state: 'active',
    activatedAtMs: 200,
  });
  return buildActiveWalletAuthorityV1({
    kind: draft.kind,
    authorityId: draft.authorityId,
    walletId: draft.walletId,
    principal: draft.principal,
    provenance: draft.provenance,
    permissions: draft.permissions,
    signerActivations: draft.signerActivations,
    signerActivationSetDigestB64u: draft.signerActivationSetDigestB64u,
    authorityDigestB64u: parseDigestB64u(await computeWalletAuthorityDigestB64u(draft)),
    revocationEpoch: draft.revocationEpoch,
    createdAtMs: draft.createdAtMs,
    updatedAtMs: draft.updatedAtMs,
    state: draft.state,
    activatedAtMs: draft.activatedAtMs,
  });
}

function buildActiveAuthMethod(
  authority: ActiveWalletAuthorityV1,
  label: string,
): Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }> {
  return buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: required(
      parseWalletAuthMethodId(`auth-method:authority-resolver-${label}`),
    ),
    walletId: authority.walletId,
    walletAuthorityId: authority.authorityId,
    kind: 'passkey',
    status: 'active',
    rpId: required(parseWebAuthnRpId('example.com')),
    credentialIdB64u: required(
      parseWebAuthnCredentialIdB64u(`credential:authority-resolver-${label}`),
    ),
    credentialPublicKeyB64u: encodedBytes(32, 9),
    counter: 0,
    createdAtMs: 100,
    updatedAtMs: 200,
    activatedAtMs: 200,
  });
}

function buildPendingAuthMethod(
  active: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>,
): Extract<WalletAuthMethodRecordV2, { readonly status: 'pending_local_install' }> {
  if (active.kind !== 'passkey') throw new Error('expected passkey authority fixture');
  return buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: active.walletAuthMethodId,
    walletId: active.walletId,
    walletAuthorityId: active.walletAuthorityId,
    kind: 'passkey',
    status: 'pending_local_install',
    rpId: active.rpId,
    credentialIdB64u: active.credentialIdB64u,
    credentialPublicKeyB64u: active.credentialPublicKeyB64u,
    counter: active.counter,
    createdAtMs: active.createdAtMs,
    updatedAtMs: active.updatedAtMs,
  });
}

async function buildSelected(
  family: SignerFamily,
  permissions = buildFullOwnerPermissionsV1(),
): Promise<SelectedWalletAuthorityV1> {
  const label = family === 'ed25519' ? 'ed25519' : 'ecdsa';
  const authority = await buildAuthority(family, permissions);
  return {
    authMethod: buildActiveAuthMethod(authority, label),
    authority,
  };
}

function ed25519Activation(authority: ActiveWalletAuthorityV1): WalletEd25519SignerActivationV1 {
  if (
    authority.signerActivations.keyFamilies.length !== 1 ||
    authority.signerActivations.keyFamilies[0] !== 'ed25519'
  ) {
    throw new Error('expected Ed25519 authority fixture');
  }
  return authority.signerActivations.ed25519;
}

function ecdsaActivation(authority: ActiveWalletAuthorityV1): WalletEcdsaSignerActivationV1 {
  if (
    authority.signerActivations.keyFamilies.length !== 1 ||
    authority.signerActivations.keyFamilies[0] !== 'ecdsa_secp256k1'
  ) {
    throw new Error('expected ECDSA authority fixture');
  }
  return authority.signerActivations.ecdsa;
}

function operationFor(family: SignerFamily): WalletAuthorityOperationV1 {
  if (family === 'ed25519') {
    return { kind: 'near_sign', operation: 'sign', keyFamily: 'ed25519' };
  }
  return { kind: 'evm_export', operation: 'export_keys', keyFamily: 'ecdsa_secp256k1' };
}

test('resolves exact Ed25519 and ECDSA signer facts', async () => {
  const ed = await buildSelected('ed25519');
  const edResult = await resolveWalletAuthorityOperation({
    selected: ed,
    operation: operationFor('ed25519'),
  });
  expect(edResult.kind).toBe('resolved');
  if (edResult.kind !== 'resolved') throw new Error('Ed25519 authority should resolve');
  const edActivation = ed25519Activation(ed.authority);
  expect(edResult.value.keyFamily).toBe('ed25519');
  expect(edResult.value.operation).toBe('sign');
  expect(edResult.value.walletKeyId).toBe(edActivation.signer.walletKeyId);
  expect(edResult.value.registeredPublicKeyB64u).toBe(edActivation.signer.registeredPublicKeyB64u);
  expect(edResult.value.materialActivation).toEqual(edActivation.materialActivation);

  const ecdsa = await buildSelected('ecdsa_secp256k1');
  const ecdsaResult = await resolveWalletAuthorityOperation({
    selected: ecdsa,
    operation: operationFor('ecdsa_secp256k1'),
  });
  expect(ecdsaResult.kind).toBe('resolved');
  if (ecdsaResult.kind !== 'resolved') throw new Error('ECDSA authority should resolve');
  const ecdsaActivationRef = ecdsaActivation(ecdsa.authority);
  expect(ecdsaResult.value.keyFamily).toBe('ecdsa_secp256k1');
  expect(ecdsaResult.value.operation).toBe('export_keys');
  expect(ecdsaResult.value.walletKeyId).toBe(ecdsaActivationRef.signer.walletKeyId);
  expect(ecdsaResult.value.thresholdPublicKey33B64u).toBe(
    ecdsaActivationRef.signer.thresholdPublicKey33B64u,
  );
  expect(ecdsaResult.value.evmAddress).toBe(ecdsaActivationRef.signer.evmAddress);
  expect(ecdsaResult.value.materialActivation).toEqual(ecdsaActivationRef.materialActivation);
});

test('rejects inactive, mismatched, unauthorized, and unavailable operations', async () => {
  const selected = await buildSelected('ed25519');
  const revokedAuthority = buildRevokedWalletAuthorityV1({
    kind: selected.authority.kind,
    authorityId: selected.authority.authorityId,
    walletId: selected.authority.walletId,
    principal: selected.authority.principal,
    provenance: selected.authority.provenance,
    permissions: selected.authority.permissions,
    signerActivations: selected.authority.signerActivations,
    signerActivationSetDigestB64u: selected.authority.signerActivationSetDigestB64u,
    authorityDigestB64u: selected.authority.authorityDigestB64u,
    revocationEpoch: selected.authority.revocationEpoch,
    createdAtMs: selected.authority.createdAtMs,
    updatedAtMs: selected.authority.updatedAtMs,
    state: 'revoked',
    activatedAtMs: selected.authority.activatedAtMs,
    revokedAtMs: 300,
  });
  const inactiveResult = await resolveWalletAuthorityOperation({
    selected: { authMethod: selected.authMethod, authority: revokedAuthority },
    operation: operationFor('ed25519'),
  });
  expect(inactiveResult).toEqual({
    kind: 'rejected',
    reason: { kind: 'authority_not_active', authorityId: revokedAuthority.authorityId },
  });

  const inactiveMethodResult = await resolveWalletAuthorityOperation({
    selected: {
      authMethod: buildPendingAuthMethod(selected.authMethod),
      authority: selected.authority,
    },
    operation: operationFor('ed25519'),
  });
  expect(inactiveMethodResult).toEqual({
    kind: 'rejected',
    reason: {
      kind: 'auth_method_not_active',
      authMethodId: selected.authMethod.walletAuthMethodId,
    },
  });

  const other = await buildSelected('ecdsa_secp256k1');
  const mismatchResult = await resolveWalletAuthorityOperation({
    selected: { authMethod: selected.authMethod, authority: other.authority },
    operation: operationFor('ed25519'),
  });
  expect(mismatchResult.kind).toBe('rejected');
  if (mismatchResult.kind !== 'rejected') throw new Error('mismatched authority should reject');
  expect(mismatchResult.reason.kind).toBe('wallet_id_mismatch');

  const signingOnly = await buildSelected('ed25519', buildSigningOnlyPermissionsV1());
  const permissionResult = await resolveWalletAuthorityOperation({
    selected: signingOnly,
    operation: { kind: 'near_export', operation: 'export_keys', keyFamily: 'ed25519' },
  });
  expect(permissionResult.kind).toBe('rejected');
  if (permissionResult.kind !== 'rejected') throw new Error('missing permission should reject');
  expect(permissionResult.reason.kind).toBe('permission_missing');

  const missingFamilyResult = await resolveWalletAuthorityOperation({
    selected,
    operation: { kind: 'evm_sign', operation: 'sign', keyFamily: 'ecdsa_secp256k1' },
  });
  expect(missingFamilyResult.kind).toBe('rejected');
  if (missingFamilyResult.kind !== 'rejected') throw new Error('missing family should reject');
  expect(missingFamilyResult.reason.kind).toBe('signer_family_unavailable');
});
