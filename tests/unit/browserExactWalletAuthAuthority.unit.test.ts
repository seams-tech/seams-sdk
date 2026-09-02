import { expect, test } from '@playwright/test';
import { resolveExactWalletAuthAuthority } from '@/SeamsWeb/assembly/browserSigningSurfaceAssembly';
import {
  resolveLinkedDevicePasskeyAuthoritySelection,
  resolveLinkedDeviceUnlockSubjectSet,
} from '@/SeamsWeb/operations/auth/login';
import { IndexedDBManager } from '@/core/indexedDB';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  parseEmailOtpProviderUserId,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import type {
  LocalWalletAuthMethodRecord,
  WalletAuthoritySignerMaterialRecordV1,
} from '@/core/indexedDB/passkeyClientDB.types';
import { parseEcdsaThresholdKeyId } from '@/core/signingEngine/session/keyMaterialBrands';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  linkedDevicePermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';

const noLocalAuthMethods = async (): Promise<readonly LocalWalletAuthMethodRecord[]> => [];
const recoveredGoogleProviderSubject = 'google:recovered-provider-user';

async function readRecoveredGoogleProviderSubject(): Promise<string> {
  return recoveredGoogleProviderSubject;
}

function required<T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T {
  if (!result.ok) throw new Error(String(result.error));
  return result.value;
}

function passkeyMethod(args: {
  walletId: string;
  rpId: string;
  credentialIdB64u: string;
  status?: 'active' | 'revoked';
}): WalletAuthMethodRecordV2 {
  const status = args.status || 'active';
  return {
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: required(parseWalletAuthMethodId('wallet-auth-method:exact-test')),
    walletId: required(parseWalletId(args.walletId)),
    walletAuthorityId: required(parseWalletAuthorityId('wallet-authority:exact-test')),
    kind: 'passkey',
    status,
    rpId: required(parseWebAuthnRpId(args.rpId)),
    credentialIdB64u: required(parseWebAuthnCredentialIdB64u(args.credentialIdB64u)),
    credentialPublicKeyB64u: 'AQID',
    counter: 0,
    createdAtMs: 1,
    updatedAtMs: 1,
    activatedAtMs: 1,
    ...(status === 'revoked' ? { revokedAtMs: 2 } : {}),
  };
}

function passkeyAuthority(method: Extract<WalletAuthMethodRecordV2, { kind: 'passkey' }>) {
  return {
    walletId: method.walletId,
    factor: { kind: 'passkey' as const, credentialIdB64u: method.credentialIdB64u },
    verifier: { kind: 'webauthn' as const, rpId: method.rpId },
    bindingId: method.walletAuthMethodId,
  };
}

function emailOtpMethod(args: {
  walletId: string;
  walletAuthMethodId: string;
  emailHashHex: string;
}): Extract<WalletAuthMethodRecordV2, { kind: 'email_otp' }> {
  return {
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: required(parseWalletAuthMethodId(args.walletAuthMethodId)),
    walletId: required(parseWalletId(args.walletId)),
    walletAuthorityId: required(parseWalletAuthorityId('wallet-authority:email-exact-test')),
    kind: 'email_otp',
    status: 'active',
    emailHashHex: args.emailHashHex,
    registrationAuthorityId: 'email-registration-authority',
    createdAtMs: 1,
    updatedAtMs: 1,
    activatedAtMs: 1,
  };
}

test('resolves the exact passkey authority from the canonical wallet auth method', async () => {
  const method = passkeyMethod({
    walletId: 'registered-wallet',
    rpId: 'registration.example.localhost',
    credentialIdB64u: 'registered-credential',
  });
  if (method.kind !== 'passkey') throw new Error('expected passkey method');
  const exactAuthority = passkeyAuthority(method);
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  const authority = await resolveExactWalletAuthAuthority(authorityRef, {
    getWalletAuthMethodV2: async () => method,
    listWalletAuthMethodsForWallet: noLocalAuthMethods,
  });

  expect(authority).toEqual(exactAuthority);
});

test('resolves the exact Email OTP authority from its canonical and local records', async () => {
  const method = emailOtpMethod({
    walletId: 'registered-email-wallet',
    walletAuthMethodId: 'wallet-auth-method:email-exact-test',
    emailHashHex: 'email-hash',
  });
  const exactAuthority = {
    walletId: method.walletId,
    factor: {
      kind: 'email_otp' as const,
      provider: 'email' as const,
      providerUserId: required(parseEmailOtpProviderUserId('email-provider-user')),
    },
    verifier: {
      kind: 'email_otp_wallet_auth_method' as const,
      emailHashHex: method.emailHashHex,
    },
    bindingId: method.walletAuthMethodId,
  };
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  const localMethod: Extract<LocalWalletAuthMethodRecord, { kind: 'email_otp' }> = {
    version: 'wallet_auth_method_v1',
    kind: 'email_otp',
    status: 'active',
    walletId: method.walletId,
    emailHashHex: method.emailHashHex,
    registrationAuthorityId: method.registrationAuthorityId,
    createdAtMs: 1,
    updatedAtMs: 1,
    localStatus: 'synced',
    authority: exactAuthority,
  };

  const authority = await resolveExactWalletAuthAuthority(authorityRef, {
    getWalletAuthMethodV2: async () => method,
    listWalletAuthMethodsForWallet: async () => [localMethod],
  });

  expect(authority).toEqual(exactAuthority);
});

test('resolves a recovered Email OTP authority from its verified provider subject', async () => {
  const method = emailOtpMethod({
    walletId: 'recovered-email-wallet',
    walletAuthMethodId: 'wallet-auth-method:recovered-email-test',
    emailHashHex: 'recovered-email-hash',
  });
  const exactAuthority = {
    walletId: method.walletId,
    factor: {
      kind: 'email_otp' as const,
      provider: 'google' as const,
      providerUserId: required(parseEmailOtpProviderUserId(recoveredGoogleProviderSubject)),
    },
    verifier: {
      kind: 'email_otp_wallet_auth_method' as const,
      emailHashHex: method.emailHashHex,
    },
    bindingId: method.walletAuthMethodId,
  };
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });

  const authority = await resolveExactWalletAuthAuthority(authorityRef, {
    getWalletAuthMethodV2: async () => method,
    listWalletAuthMethodsForWallet: noLocalAuthMethods,
    readEmailOtpProviderSubjectForWallet: readRecoveredGoogleProviderSubject,
  });

  expect(authority).toEqual(exactAuthority);
});

// R103C: the active auth-method store is the only resolution source. A wallet
// whose authority reference has no active auth method fails closed — sealed
// runtime restores and loose authenticator rows can no longer answer for it.
test('fails closed when no active wallet auth method matches the authority', async () => {
  const method = passkeyMethod({
    walletId: 'registered-wallet',
    rpId: 'registration.example.localhost',
    credentialIdB64u: 'registered-credential',
  });
  if (method.kind !== 'passkey') throw new Error('expected passkey method');
  const exactAuthority = passkeyAuthority(method);
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  await expect(
    resolveExactWalletAuthAuthority(authorityRef, {
      getWalletAuthMethodV2: async () => null,
      listWalletAuthMethodsForWallet: noLocalAuthMethods,
    }),
  ).rejects.toThrow('Exact wallet authentication authority is unavailable');
});

test('a revoked wallet auth method cannot resolve the active authority', async () => {
  const method = passkeyMethod({
    walletId: 'registered-wallet',
    rpId: 'registration.example.localhost',
    credentialIdB64u: 'registered-credential',
  });
  if (method.kind !== 'passkey') throw new Error('expected passkey method');
  const exactAuthority = passkeyAuthority(method);
  const authorityRef = await walletAuthAuthorityRef({ authority: exactAuthority });
  await expect(
    resolveExactWalletAuthAuthority(authorityRef, {
      getWalletAuthMethodV2: async () => ({ ...method, status: 'revoked', revokedAtMs: 2 }),
      listWalletAuthMethodsForWallet: noLocalAuthMethods,
    }),
  ).rejects.toThrow('Exact wallet authentication authority is unavailable');
});

test('linked unlock resolves an opaque selected passkey auth method id', async () => {
  const target = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'opaque-target',
    permissions: linkedDevicePermissionsForManagementFixture(),
    provenance: 'device_link',
    keyFamily: 'ecdsa_secp256k1',
  });
  const ecdsaActivation = target.authority.signerActivations.ecdsa;
  if (!ecdsaActivation) throw new Error('linked ECDSA fixture is missing its activation');
  const signerMaterial: WalletAuthoritySignerMaterialRecordV1 = {
    kind: 'wallet_authority_signer_material_v1',
    authorityId: target.authority.authorityId,
    walletAuthMethodId: target.authMethod.walletAuthMethodId,
    activationId: ecdsaActivation.materialActivation.activationId,
    keyFamily: 'ecdsa_secp256k1',
    materialActivation: ecdsaActivation.materialActivation,
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ecdsa-threshold-key:opaque-target'),
    sealedMaterialB64u: 'sealed-material-opaque-target',
    sealedMaterialDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(47))),
  };
  const resolved = {
    kind: 'resolved' as const,
    selection: {
      kind: 'wallet_selection_v1' as const,
      walletId: target.authority.walletId,
      walletAuthMethodId: target.authMethod.walletAuthMethodId,
      lockGeneration: 0,
      lockState: 'unlocked' as const,
      updatedAtMs: 1,
    },
    authMethod: target.authMethod,
    authority: target.authority,
    signerMaterials: [signerMaterial],
    exportRoot: null,
  };
  const original = IndexedDBManager.resolveSelectedWalletAuthority;
  IndexedDBManager.resolveSelectedWalletAuthority = async () => resolved;
  let result: {
    readonly kind: 'evm_family_ecdsa_wallet';
    readonly walletAuthMethodId: string;
    readonly ecdsaThresholdKeyId: string;
  } | null = null;
  try {
    const subjectSet = await resolveLinkedDeviceUnlockSubjectSet(String(target.authority.walletId));
    const subject = subjectSet?.subjects[0];
    result =
      subject?.kind === 'evm_family_ecdsa_wallet'
        ? {
            kind: subject.kind,
            walletAuthMethodId: subject.authority.walletAuthMethodId,
            ecdsaThresholdKeyId: subject.ecdsaThresholdKeyId,
          }
        : null;
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = original;
  }

  expect(result).toEqual({
    kind: 'evm_family_ecdsa_wallet',
    walletAuthMethodId: String(target.authMethod.walletAuthMethodId),
    ecdsaThresholdKeyId: 'ecdsa-threshold-key:opaque-target',
  });
});

test('wallet-registration authority stays on the custody unlock path', async () => {
  const target = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'registration-owner',
    permissions: linkedDevicePermissionsForManagementFixture(),
    provenance: 'wallet_registration',
    keyFamily: 'ecdsa_secp256k1',
  });
  const original = IndexedDBManager.resolveSelectedWalletAuthority;
  IndexedDBManager.resolveSelectedWalletAuthority = async () => ({
    kind: 'resolved',
    selection: {
      kind: 'wallet_selection_v1',
      walletId: target.authority.walletId,
      walletAuthMethodId: target.authMethod.walletAuthMethodId,
      lockGeneration: 0,
      lockState: 'unlocked',
      updatedAtMs: 1,
    },
    authMethod: target.authMethod,
    authority: target.authority,
    signerMaterials: [],
    exportRoot: null,
  });
  try {
    expect(
      await resolveLinkedDevicePasskeyAuthoritySelection(String(target.authority.walletId)),
    ).toBeNull();
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = original;
  }
});
