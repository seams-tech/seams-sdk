import { expect, test } from '@playwright/test';
import {
  activateAuthenticatedWalletState,
  hasPasskeyCredential,
  nearAuthenticatorsByAccount,
  storeWalletEcdsaSignerRecords,
  finalizeWalletEd25519SignerRegistration,
  storeWalletEd25519RegistrationData,
  storeWalletEmailOtpMixedRegistrationData,
  storeWalletMixedRegistrationData,
} from '../../packages/sdk-web/src/core/signingEngine/flows/registration/accountLifecycle';
import type {
  AccountRef,
  AccountSignerRecord,
  ProfileRecord,
} from '../../packages/sdk-web/src/core/indexedDB/passkeyClientDB.types';
import type { StoreWalletRegistrationFinalizeBatchInput } from '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/repositories';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../../packages/sdk-web/src/core/types/webauthn';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import {
  nearEd25519SigningKeyIdFromString,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';

const credential = {
  id: 'credential-id',
  rawId: 'credential-raw-id',
  response: {
    attestationObject: 'attestation-object',
    clientDataJSON: 'client-data-json',
    transports: ['internal'],
  },
  type: 'public-key',
} as unknown as WebAuthnRegistrationCredential;

const authenticationCredential = {
  id: 'credential-id',
  rawId: 'credential-raw-id',
  response: {
    clientDataJSON: 'client-data-json',
    authenticatorData: 'authenticator-data',
    signature: 'signature',
    userHandle: null,
  },
  type: 'public-key',
  authenticatorAttachment: null,
  clientExtensionResults: {},
} as unknown as WebAuthnAuthenticationCredential;

class MixedRegistrationStoreCapture {
  readonly registrationFinalizeBatches: StoreWalletRegistrationFinalizeBatchInput[] = [];
  signerFinalizeCalls = 0;

  async persistWalletRegistrationFinalize(batch: StoreWalletRegistrationFinalizeBatchInput) {
    this.registrationFinalizeBatches.push(batch);
    const signerActivations = [];
    for (let index = 0; index < batch.signerActivations.length; index += 1) {
      const signerSlot = index + 11;
      signerActivations.push({ signerSlot, signer: { signerSlot } });
    }
    return { signerActivations };
  }

  async persistWalletSignerFinalize() {
    this.signerFinalizeCalls += 1;
    throw new Error('mixed registration must use one registration finalize batch');
  }
}

class AuthenticatedWalletActivationFixture {
  readonly calls: string[] = [];

  constructor(
    private readonly signerWalletId: string,
    private readonly persistedSignerSlot: number = 2,
  ) {}

  async resolveProfileAccountContext(accountRef: AccountRef) {
    return {
      profileId: 'near-profile:email-registration.testnet',
      accountRef,
    };
  }

  async getProfile(profileId: string): Promise<ProfileRecord | null> {
    return {
      profileId,
      defaultSignerSlot: this.persistedSignerSlot,
      createdAt: 1,
      updatedAt: 1,
    };
  }

  async listAccountSigners(): Promise<AccountSignerRecord[]> {
    return [
      {
        profileId: 'near-profile:email-registration.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'email-registration.testnet',
        signerId: 'ed25519:email-registration-public',
        signerSlot: this.persistedSignerSlot,
        signerType: 'threshold',
        signerKind: 'threshold-ed25519',
        signerAuthMethod: 'email_otp',
        signerSource: 'email_otp_registration',
        status: 'active',
        addedAt: 1,
        updatedAt: 1,
        metadata: {
          walletId: this.signerWalletId,
          nearAccountId: 'email-registration.testnet',
          nearEd25519SigningKeyId: 'ed25519-key-email-registration',
          operationalPublicKey: 'ed25519:email-registration-public',
        },
      },
    ];
  }

  async setLastProfileStateForProfile(profileId: string, signerSlot: number): Promise<void> {
    this.calls.push(`last:${profileId}:${signerSlot}`);
  }

  setCurrentWallet(walletId: string): void {
    this.calls.push(`preferences:${walletId}`);
  }

  async reloadUserSettings(): Promise<void> {
    this.calls.push('preferences:reload');
  }

  initializeNearAccessKey(input: {
    walletId: string;
    nearAccountId: string;
    publicKey: string;
  }): void {
    this.calls.push(`nonce:${input.walletId}:${input.nearAccountId}:${input.publicKey}`);
  }

  async prefetchNearContext(): Promise<void> {}

  deps() {
    return {
      accountStore: this,
      userPreferencesManager: this,
      nonceCoordinator: this,
    };
  }
}

test('authenticated wallet activation resolves wallet identity through the exact NEAR signer', async () => {
  const fixture = new AuthenticatedWalletActivationFixture('wallet_email_registration');

  await activateAuthenticatedWalletState(fixture.deps(), {
    walletId: walletIdFromString('wallet_email_registration'),
    nearAccountId: toAccountId('email-registration.testnet'),
    signerSlot: 2,
  });

  expect(fixture.calls).toEqual([
    'last:near-profile:email-registration.testnet:2',
    'preferences:wallet_email_registration',
    'preferences:reload',
    'nonce:wallet_email_registration:email-registration.testnet:ed25519:email-registration-public',
  ]);
});

test('authenticated wallet activation rejects a NEAR signer owned by another wallet', async () => {
  const fixture = new AuthenticatedWalletActivationFixture('wallet_substituted');

  await expect(
    activateAuthenticatedWalletState(fixture.deps(), {
      walletId: walletIdFromString('wallet_email_registration'),
      nearAccountId: toAccountId('email-registration.testnet'),
      signerSlot: 2,
    }),
  ).rejects.toThrow('exact wallet signer binding');
  expect(fixture.calls).toEqual([]);
});

test('authenticated wallet activation rejects a missing exact signer slot', async () => {
  const fixture = new AuthenticatedWalletActivationFixture('wallet_email_registration', 3);

  await expect(
    activateAuthenticatedWalletState(fixture.deps(), {
      walletId: walletIdFromString('wallet_email_registration'),
      nearAccountId: toAccountId('email-registration.testnet'),
      signerSlot: 2,
    }),
  ).rejects.toThrow('exact NEAR signer projection');
  expect(fixture.calls).toEqual([]);
});

test('NEAR authenticator lookup resolves the canonical wallet passkey auth method', async () => {
  const deps = {
    indexedDB: {
      resolveProfileAccountContext: async (accountRef: {
        chainIdKey: string;
        accountAddress: string;
      }) => ({
        profileId: 'near-profile:alice.testnet',
        accountRef,
      }),
      listAccountSigners: async () => [
        {
          profileId: 'near-profile:alice.testnet',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          signerId: 'ed25519:public',
          signerSlot: 2,
          signerType: 'threshold',
          signerKind: 'threshold-ed25519',
          signerAuthMethod: 'passkey',
          signerSource: 'passkey_registration',
          status: 'active',
          addedAt: 1,
          updatedAt: 1,
          metadata: {
            walletId: 'wallet_alice',
            passkeyCredentialRawId: 'credential-raw-id',
          },
        },
      ],
      listProfileAuthenticators: async (profileId: string) =>
        profileId === 'wallet_alice'
          ? [
              {
                profileId: 'wallet_alice',
                signerSlot: 99,
                credentialId: 'credential-raw-id',
                credentialPublicKey: new Uint8Array([1, 2, 3]),
                transports: ['internal'],
                registered: new Date(0).toISOString(),
                syncedAt: new Date(0).toISOString(),
              },
              {
                profileId: 'wallet_alice',
                signerSlot: 1,
                credentialId: 'stale-credential',
                credentialPublicKey: new Uint8Array([4, 5, 6]),
                transports: [],
                registered: new Date(0).toISOString(),
                syncedAt: new Date(0).toISOString(),
              },
            ]
          : [],
    },
  };
  (deps as any).accountStore = deps.indexedDB;

  const authenticators = await nearAuthenticatorsByAccount(
    deps as any,
    toAccountId('alice.testnet'),
  );

  expect(authenticators).toHaveLength(1);
  expect(authenticators[0]).toMatchObject({
    nearAccountId: 'alice.testnet',
    signerSlot: 2,
    credentialId: 'credential-raw-id',
    transports: ['internal'],
  });
  await expect(hasPasskeyCredential(deps as any, toAccountId('alice.testnet'))).resolves.toBe(true);
});

test('wallet registration persists wallet signer before NEAR projection', async () => {
  const calls: string[] = [];
  const activations: unknown[] = [];
  const authenticators: unknown[] = [];
  const authMethods: unknown[] = [];
  const deps = {
    indexedDB: {
      upsertProfile: async (input: { profileId: string }) => {
        calls.push(`profile:${input.profileId}`);
      },
      activateAccountSigner: async (input: unknown) => {
        calls.push(
          `signer:${String((input as { account?: { profileId?: unknown } }).account?.profileId || '')}`,
        );
        activations.push(input);
        return { signerSlot: 2, signer: { signerSlot: 2 } };
      },
      upsertProfileAuthenticator: async (input: unknown) => {
        calls.push(`auth:${String((input as { profileId?: unknown }).profileId || '')}`);
        authenticators.push(input);
      },
      setLastProfileStateForProfile: async (profileId: string, signerSlot: number) => {
        calls.push(`last:${profileId}:${signerSlot}`);
      },
      persistWalletRegistrationFinalize: async (batch: {
        profiles: Array<{ profileId: string }>;
        initialAuthMethod: unknown;
        authenticators: unknown[];
        signerActivations: unknown[];
        lastProfileState?: { profileId: string; activeSignerSlot: number };
      }) => {
        for (const profile of batch.profiles) {
          calls.push(`profile:${profile.profileId}`);
        }
        authMethods.push(batch.initialAuthMethod);
        for (const authenticator of batch.authenticators) {
          calls.push(`auth:${String((authenticator as { profileId?: unknown }).profileId || '')}`);
          authenticators.push(authenticator);
        }
        const signerActivations = batch.signerActivations.map((input) => {
          calls.push(
            `signer:${String((input as { account?: { profileId?: unknown } }).account?.profileId || '')}`,
          );
          activations.push(input);
          return { signerSlot: 2, signer: { signerSlot: 2 } };
        });
        if (batch.lastProfileState) {
          calls.push(
            `last:${batch.lastProfileState.profileId}:${batch.lastProfileState.activeSignerSlot}`,
          );
        }
        return { signerActivations };
      },
    },
  };
  (deps as any).accountStore = deps.indexedDB;

  const result = await storeWalletEd25519RegistrationData(deps as any, {
    walletId: walletIdFromString('wallet_alice'),
    nearAccountId: toAccountId('alice.testnet'),
    nearEd25519SigningKeyId: String(nearEd25519SigningKeyIdFromString('wallet_alice')),
    credential,
    credentialPublicKeyB64u: 'AQID',
    signerSlot: 2,
    operationalPublicKey: 'ed25519:public',
    relayerKeyId: 'relayer-key',
    keyVersion: 'router-ab-ed25519-yao-v1',
    participantIds: [1, 2],
  });

  expect(result.signerSlot).toBe(2);
  expect(calls).toEqual([
    'profile:wallet_alice',
    'profile:near-profile:alice.testnet',
    'auth:wallet_alice',
    'auth:near-profile:alice.testnet',
    'signer:wallet_alice',
    'signer:near-profile:alice.testnet',
    'last:wallet_alice:2',
  ]);
  expect(authMethods[0]).toMatchObject({
    kind: 'passkey',
    walletId: 'wallet_alice',
    credentialIdB64u: 'credential-raw-id',
  });
  expect(activations[0]).toMatchObject({
    account: {
      profileId: 'wallet_alice',
      chainIdKey: 'wallet',
      accountAddress: 'wallet_alice',
      accountModel: 'wallet',
    },
    signer: {
      signerId: 'ed25519:public',
      metadata: {
        walletId: 'wallet_alice',
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'wallet_alice',
        operationalPublicKey: 'ed25519:public',
        relayerKeyId: 'relayer-key',
      },
    },
  });
  expect(authenticators[0]).toMatchObject({
    profileId: 'wallet_alice',
    signerSlot: 2,
    credentialId: 'credential-raw-id',
  });
});

test('mixed wallet registration atomically persists Ed25519 and every ECDSA target', async () => {
  const store = new MixedRegistrationStoreCapture();
  const deps = {
    indexedDB: store,
    accountStore: store,
  };
  const walletId = walletIdFromString('wallet_mixed');
  const walletKeys = [
    {
      keyScope: 'evm-family' as const,
      chainTarget: {
        kind: 'evm' as const,
        namespace: 'eip155' as const,
        chainId: 1,
        networkSlug: 'ethereum',
      },
      walletId: 'wallet_mixed',
      evmFamilySigningKeySlotId: 'evm-family-slot-mixed',
      walletKeyId: 'wallet-key-ethereum',
      keyHandle: 'ehss-key-ethereum',
      ecdsaThresholdKeyId: 'ehss-key-id-ethereum',
      signingRootId: 'project_registration:dev',
      signingRootVersion: 'root_v1',
      thresholdEcdsaPublicKeyB64u: 'A1111111111111111111111111111111111111111111',
      thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
      relayerKeyId: 'relayer-key-ethereum',
      relayerVerifyingShareB64u: 'relayer-share-ethereum',
      participantIds: [1, 2],
    },
    {
      keyScope: 'evm-family' as const,
      chainTarget: {
        kind: 'tempo' as const,
        chainId: 42431,
        networkSlug: 'tempo-moderato',
      },
      walletId: 'wallet_mixed',
      evmFamilySigningKeySlotId: 'evm-family-slot-mixed',
      walletKeyId: 'wallet-key-tempo',
      keyHandle: 'ehss-key-tempo',
      ecdsaThresholdKeyId: 'ehss-key-id-tempo',
      signingRootId: 'project_registration:dev',
      signingRootVersion: 'root_v1',
      thresholdEcdsaPublicKeyB64u: 'A2222222222222222222222222222222222222222222',
      thresholdOwnerAddress: '0x2222222222222222222222222222222222222222',
      relayerKeyId: 'relayer-key-tempo',
      relayerVerifyingShareB64u: 'relayer-share-tempo',
      participantIds: [1, 2],
    },
  ];

  const result = await storeWalletMixedRegistrationData(deps as any, {
    walletId,
    nearAccountId: toAccountId('mixed.testnet'),
    nearEd25519SigningKeyId: String(nearEd25519SigningKeyIdFromString(String(walletId))),
    credential,
    credentialPublicKeyB64u: 'AQID',
    signerSlot: 2,
    operationalPublicKey: 'ed25519:mixed-public',
    relayerKeyId: 'relayer-key-ed25519',
    keyVersion: 'router-ab-ed25519-yao-v1',
    participantIds: [1, 2],
    walletKeys,
  });

  expect(store.registrationFinalizeBatches).toHaveLength(1);
  expect(store.signerFinalizeCalls).toBe(0);
  const batch = store.registrationFinalizeBatches[0];
  expect(batch.profiles).toEqual([
    {
      profileId: 'wallet_mixed',
      defaultSignerSlot: 2,
      passkeyCredential: { id: 'credential-id', rawId: 'credential-raw-id' },
    },
    {
      profileId: 'near-profile:mixed.testnet',
      defaultSignerSlot: 2,
      passkeyCredential: { id: 'credential-id', rawId: 'credential-raw-id' },
    },
  ]);
  expect(batch.initialAuthMethod).toMatchObject({
    kind: 'passkey',
    walletId: 'wallet_mixed',
    credentialIdB64u: 'credential-raw-id',
  });
  expect(batch.authenticators).toHaveLength(2);
  expect(batch.authenticators).toMatchObject([
    {
      profileId: 'wallet_mixed',
      signerSlot: 2,
      credentialId: 'credential-raw-id',
    },
    {
      profileId: 'near-profile:mixed.testnet',
      signerSlot: 2,
      credentialId: 'credential-raw-id',
    },
  ]);
  expect(batch.signerActivations).toHaveLength(4);
  expect(batch.signerActivations).toMatchObject([
    {
      account: {
        profileId: 'wallet_mixed',
        chainIdKey: 'wallet',
        accountAddress: 'wallet_mixed',
        accountModel: 'wallet',
      },
      signer: {
        signerId: 'ed25519:mixed-public',
        signerKind: 'threshold-ed25519',
      },
    },
    {
      account: {
        profileId: 'near-profile:mixed.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'mixed.testnet',
        accountModel: 'near-native',
      },
      signer: {
        signerId: 'ed25519:mixed-public',
        signerKind: 'threshold-ed25519',
      },
    },
    {
      account: {
        profileId: 'wallet_mixed',
        chainIdKey: 'evm:eip155:1',
        accountAddress: '0x1111111111111111111111111111111111111111',
        accountModel: 'threshold-ecdsa',
      },
      signer: {
        signerId: '0x1111111111111111111111111111111111111111',
        signerKind: 'threshold-ecdsa',
      },
    },
    {
      account: {
        profileId: 'wallet_mixed',
        chainIdKey: 'tempo:42431',
        accountAddress: '0x2222222222222222222222222222222222222222',
        accountModel: 'threshold-ecdsa',
      },
      signer: {
        signerId: '0x2222222222222222222222222222222222222222',
        signerKind: 'threshold-ecdsa',
      },
    },
  ]);
  expect(batch.keyMaterials).toHaveLength(4);
  expect(batch.keyMaterials).toMatchObject([
    {
      profileId: 'wallet_mixed',
      chainIdKey: 'wallet',
      algorithm: 'ed25519',
      publicKey: 'ed25519:mixed-public',
    },
    {
      profileId: 'near-profile:mixed.testnet',
      chainIdKey: 'near:testnet',
      algorithm: 'ed25519',
      publicKey: 'ed25519:mixed-public',
    },
    {
      profileId: 'wallet_mixed',
      chainIdKey: 'evm:eip155:1',
      algorithm: 'secp256k1',
      publicKey: 'A1111111111111111111111111111111111111111111',
    },
    {
      profileId: 'wallet_mixed',
      chainIdKey: 'tempo:42431',
      algorithm: 'secp256k1',
      publicKey: 'A2222222222222222222222222222222222222222222',
    },
  ]);
  expect(batch.lastProfileState).toEqual({
    profileId: 'wallet_mixed',
    activeSignerSlot: 2,
  });
  expect(result).toEqual({
    signerSlot: 12,
    storedSigners: [
      {
        chainTarget: walletKeys[0].chainTarget,
        targetKey: 'evm:eip155:1',
        signerSlot: 13,
        signerId: '0x1111111111111111111111111111111111111111',
      },
      {
        chainTarget: walletKeys[1].chainTarget,
        targetKey: 'tempo:42431',
        signerSlot: 14,
        signerId: '0x2222222222222222222222222222222222222222',
      },
    ],
  });
});

test('Email OTP mixed registration atomically persists Ed25519 and every ECDSA target', async () => {
  const store = new MixedRegistrationStoreCapture();
  const deps = {
    indexedDB: store,
    accountStore: store,
  };
  const walletId = walletIdFromString('wallet_email_mixed');
  const walletKeys = [
    {
      keyScope: 'evm-family' as const,
      chainTarget: {
        kind: 'evm' as const,
        namespace: 'eip155' as const,
        chainId: 1,
        networkSlug: 'ethereum',
      },
      walletId: 'wallet_email_mixed',
      evmFamilySigningKeySlotId: 'evm-family-slot-email-mixed',
      keyHandle: 'ehss-key-email-ethereum',
      ecdsaThresholdKeyId: 'ehss-key-id-email-ethereum',
      signingRootId: 'project_registration:dev',
      signingRootVersion: 'root_v1',
      thresholdEcdsaPublicKeyB64u: 'A3333333333333333333333333333333333333333333',
      thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
      relayerKeyId: 'relayer-key-email-ethereum',
      relayerVerifyingShareB64u: 'relayer-share-email-ethereum',
      participantIds: [1, 2],
    },
    {
      keyScope: 'evm-family' as const,
      chainTarget: {
        kind: 'tempo' as const,
        chainId: 42431,
        networkSlug: 'tempo-moderato',
      },
      walletId: 'wallet_email_mixed',
      evmFamilySigningKeySlotId: 'evm-family-slot-email-mixed',
      keyHandle: 'ehss-key-email-tempo',
      ecdsaThresholdKeyId: 'ehss-key-id-email-tempo',
      signingRootId: 'project_registration:dev',
      signingRootVersion: 'root_v1',
      thresholdEcdsaPublicKeyB64u: 'A4444444444444444444444444444444444444444444',
      thresholdOwnerAddress: '0x4444444444444444444444444444444444444444',
      relayerKeyId: 'relayer-key-email-tempo',
      relayerVerifyingShareB64u: 'relayer-share-email-tempo',
      participantIds: [1, 2],
    },
  ];

  const result = await storeWalletEmailOtpMixedRegistrationData(deps as any, {
    walletId,
    nearAccountId: toAccountId('email-mixed.testnet'),
    nearEd25519SigningKeyId: String(nearEd25519SigningKeyIdFromString(String(walletId))),
    email: 'Alice@Example.com',
    registrationAuthorityId: 'google:alice-subject',
    signerSlot: 2,
    operationalPublicKey: 'ed25519:email-mixed-public',
    relayerKeyId: 'relayer-key-email-ed25519',
    keyVersion: 'router-ab-ed25519-yao-v1',
    participantIds: [1, 2],
    walletKeys,
  });

  expect(store.registrationFinalizeBatches).toHaveLength(1);
  expect(store.signerFinalizeCalls).toBe(0);
  const batch = store.registrationFinalizeBatches[0];
  expect(batch.profiles).toEqual([
    {
      profileId: 'wallet_email_mixed',
      defaultSignerSlot: 2,
    },
    {
      profileId: 'near-profile:email-mixed.testnet',
      defaultSignerSlot: 2,
    },
  ]);
  expect(batch.initialAuthMethod).toMatchObject({
    kind: 'email_otp',
    walletId: 'wallet_email_mixed',
    registrationAuthorityId: 'google:alice-subject',
  });
  expect(batch.authenticators).toEqual([]);
  expect(batch.signerActivations).toHaveLength(4);
  for (const activation of batch.signerActivations) {
    expect(activation.signer).toMatchObject({
      signerAuthMethod: 'email_otp',
      signerSource: 'email_otp_registration',
    });
  }
  expect(batch.signerActivations).toMatchObject([
    {
      account: {
        profileId: 'wallet_email_mixed',
        chainIdKey: 'wallet',
        accountAddress: 'wallet_email_mixed',
        accountModel: 'wallet',
      },
      signer: {
        signerId: 'ed25519:email-mixed-public',
        signerKind: 'threshold-ed25519',
      },
    },
    {
      account: {
        profileId: 'near-profile:email-mixed.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'email-mixed.testnet',
        accountModel: 'near-native',
      },
      signer: {
        signerId: 'ed25519:email-mixed-public',
        signerKind: 'threshold-ed25519',
      },
    },
    {
      account: {
        profileId: 'wallet_email_mixed',
        chainIdKey: 'evm:eip155:1',
        accountAddress: '0x3333333333333333333333333333333333333333',
        accountModel: 'threshold-ecdsa',
      },
      signer: {
        signerId: '0x3333333333333333333333333333333333333333',
        signerKind: 'threshold-ecdsa',
      },
    },
    {
      account: {
        profileId: 'wallet_email_mixed',
        chainIdKey: 'tempo:42431',
        accountAddress: '0x4444444444444444444444444444444444444444',
        accountModel: 'threshold-ecdsa',
      },
      signer: {
        signerId: '0x4444444444444444444444444444444444444444',
        signerKind: 'threshold-ecdsa',
      },
    },
  ]);
  expect(batch.keyMaterials).toHaveLength(4);
  expect(batch.lastProfileState).toEqual({
    profileId: 'wallet_email_mixed',
    activeSignerSlot: 2,
  });
  expect(result).toEqual({
    signerSlot: 12,
    storedSigners: [
      {
        chainTarget: walletKeys[0].chainTarget,
        targetKey: 'evm:eip155:1',
        signerSlot: 13,
        signerId: '0x3333333333333333333333333333333333333333',
      },
      {
        chainTarget: walletKeys[1].chainTarget,
        targetKey: 'tempo:42431',
        signerSlot: 14,
        signerId: '0x4444444444444444444444444444444444444444',
      },
    ],
  });
});

test('wallet add-signer persists Ed25519 signer records without re-registering authenticator', async () => {
  const calls: string[] = [];
  const activations: unknown[] = [];
  const keyMaterials: unknown[] = [];
  const authenticators: unknown[] = [];
  const deps = {
    indexedDB: {
      upsertProfile: async (input: { profileId: string }) => {
        calls.push(`profile:${input.profileId}`);
      },
      activateAccountSigner: async (input: unknown) => {
        calls.push(
          `signer:${String((input as { account?: { profileId?: unknown } }).account?.profileId || '')}`,
        );
        activations.push(input);
        return { signerSlot: 3, signer: { signerSlot: 3 } };
      },
      upsertProfileAuthenticator: async (input: unknown) => {
        authenticators.push(input);
      },
      setLastProfileStateForProfile: async (profileId: string, signerSlot: number) => {
        calls.push(`last:${profileId}:${signerSlot}`);
      },
      persistWalletSignerFinalize: async (batch: {
        profiles: Array<{ profileId: string }>;
        signerActivations: unknown[];
        keyMaterials: unknown[];
        lastProfileState?: { profileId: string; activeSignerSlot: number };
      }) => {
        for (const profile of batch.profiles) {
          calls.push(`profile:${profile.profileId}`);
        }
        const signerActivations = batch.signerActivations.map((input) => {
          calls.push(
            `signer:${String((input as { account?: { profileId?: unknown } }).account?.profileId || '')}`,
          );
          activations.push(input);
          return { signerSlot: 3, signer: { signerSlot: 3 } };
        });
        keyMaterials.push(...batch.keyMaterials);
        if (batch.lastProfileState) {
          calls.push(
            `last:${batch.lastProfileState.profileId}:${batch.lastProfileState.activeSignerSlot}`,
          );
        }
        return { signerActivations };
      },
    },
  };
  (deps as any).accountStore = deps.indexedDB;

  const result = await finalizeWalletEd25519SignerRegistration(deps as any, {
    walletId: walletIdFromString('wallet_alice'),
    nearAccountId: toAccountId('alice.testnet'),
    nearEd25519SigningKeyId: String(nearEd25519SigningKeyIdFromString('alice.testnet')),
    credential: authenticationCredential,
    signerSlot: 3,
    operationalPublicKey: 'ed25519:public',
    relayerKeyId: 'relayer-key',
    keyVersion: 'router-ab-ed25519-yao-v1',
    participantIds: [1, 2],
  });

  expect(result.signerSlot).toBe(3);
  expect(calls).toEqual([
    'profile:wallet_alice',
    'profile:near-profile:alice.testnet',
    'signer:wallet_alice',
    'signer:near-profile:alice.testnet',
    'last:wallet_alice:3',
  ]);
  expect(authenticators).toEqual([]);
  expect(activations[0]).toMatchObject({
    account: {
      profileId: 'wallet_alice',
      chainIdKey: 'wallet',
      accountAddress: 'wallet_alice',
      accountModel: 'wallet',
    },
    signer: {
      signerId: 'ed25519:public',
      metadata: {
        walletId: 'wallet_alice',
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'alice.testnet',
        operationalPublicKey: 'ed25519:public',
        relayerKeyId: 'relayer-key',
      },
    },
  });
  expect(keyMaterials[0]).toMatchObject({
    profileId: 'wallet_alice',
    accountAddress: 'wallet_alice',
    payload: {
      walletId: 'wallet_alice',
      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'alice.testnet',
      relayerKeyId: 'relayer-key',
      keyVersion: 'router-ab-ed25519-yao-v1',
    },
  });
});

test('wallet add-signer persists ECDSA signer records without re-registering authenticator', async () => {
  const calls: string[] = [];
  const activations: unknown[] = [];
  const authenticators: unknown[] = [];
  const deps = {
    indexedDB: {
      upsertProfile: async (input: { profileId: string }) => {
        calls.push(`profile:${input.profileId}`);
      },
      activateAccountSigner: async (input: unknown) => {
        const chainIdKey = String(
          (input as { account?: { chainIdKey?: unknown } }).account?.chainIdKey || '',
        );
        calls.push(`signer:${chainIdKey}`);
        activations.push(input);
        return { signerSlot: activations.length, signer: { signerSlot: activations.length } };
      },
      upsertProfileAuthenticator: async (input: unknown) => {
        authenticators.push(input);
      },
      persistWalletSignerFinalize: async (batch: {
        profiles: Array<{ profileId: string }>;
        signerActivations: unknown[];
      }) => {
        for (const profile of batch.profiles) {
          calls.push(`profile:${profile.profileId}`);
        }
        const signerActivations = batch.signerActivations.map((input) => {
          const chainIdKey = String(
            (input as { account?: { chainIdKey?: unknown } }).account?.chainIdKey || '',
          );
          calls.push(`signer:${chainIdKey}`);
          activations.push(input);
          return { signerSlot: activations.length, signer: { signerSlot: activations.length } };
        });
        return { signerActivations };
      },
    },
  };
  (deps as any).accountStore = deps.indexedDB;

  const walletId = walletIdFromString('wallet_alice');
  const walletKeys = [
    {
      keyScope: 'evm-family' as const,
      chainTarget: {
        kind: 'evm' as const,
        namespace: 'eip155' as const,
        chainId: 1,
        networkSlug: 'ethereum',
      },
      walletId: 'wallet_alice',
      walletKeyId: 'wallet-key-alice',
      evmFamilySigningKeySlotId: 'evm-family-slot-alice',
      keyHandle: 'ehss-key-alice',
      ecdsaThresholdKeyId: 'ehss-key-id-alice',
      signingRootId: 'project_registration:dev',
      signingRootVersion: 'root_v1',
      thresholdEcdsaPublicKeyB64u: 'A1111111111111111111111111111111111111111111',
      thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
      relayerKeyId: 'relayer-key-ecdsa',
      relayerVerifyingShareB64u: 'relayer-share',
      participantIds: [1, 2],
    },
  ];

  const result = await storeWalletEcdsaSignerRecords(deps as any, {
    walletId,
    walletKeys,
  });

  expect(result.storedSigners).toEqual([
    {
      chainTarget: walletKeys[0].chainTarget,
      targetKey: 'evm:eip155:1',
      signerSlot: 1,
      signerId: '0x1111111111111111111111111111111111111111',
    },
  ]);
  expect(calls).toEqual(['profile:wallet_alice', 'signer:evm:eip155:1']);
  expect(authenticators).toEqual([]);
  expect(activations[0]).toMatchObject({
    account: {
      profileId: 'wallet_alice',
      chainIdKey: 'evm:eip155:1',
      accountAddress: '0x1111111111111111111111111111111111111111',
      accountModel: 'threshold-ecdsa',
    },
    signer: {
      signerId: '0x1111111111111111111111111111111111111111',
      signerKind: 'threshold-ecdsa',
      signerAuthMethod: 'passkey',
      metadata: {
        keyHandle: 'ehss-key-alice',
        walletId: 'wallet_alice',
        evmFamilySigningKeySlotId: 'evm-family-slot-alice',
        ecdsaThresholdKeyId: 'ehss-key-id-alice',
        signingRootId: 'project_registration:dev',
        signingRootVersion: 'root_v1',
        chainTarget: walletKeys[0].chainTarget,
        sharedEvmFamilyKey: {
          walletId: 'wallet_alice',
          keyHandle: 'ehss-key-alice',
          thresholdEcdsaPublicKeyB64u: 'A1111111111111111111111111111111111111111111',
        },
      },
    },
    activationPolicy: { mode: 'allocate_next_free' },
    mutation: { routeThroughOutbox: false },
  });
});

test('wallet ECDSA signer validation fails before finalize batch side effects', async () => {
  let batchCalled = false;
  const deps = {
    indexedDB: {
      persistWalletSignerFinalize: async () => {
        batchCalled = true;
        return { signerActivations: [] };
      },
    },
  };
  (deps as any).accountStore = deps.indexedDB;

  await expect(
    storeWalletEcdsaSignerRecords(deps as any, {
      walletId: walletIdFromString('wallet_alice'),
      walletKeys: [
        {
          keyScope: 'evm-family' as const,
          chainTarget: {
            kind: 'evm' as const,
            namespace: 'eip155' as const,
            chainId: 1,
            networkSlug: 'ethereum',
          },
          walletId: 'wallet_bob',
          evmFamilySigningKeySlotId: 'wallet-key-bob',
          keyHandle: 'ehss-key-alice',
          ecdsaThresholdKeyId: 'ehss-key-id-alice',
          signingRootId: 'project_registration:dev',
          signingRootVersion: 'root_v1',
          thresholdEcdsaPublicKeyB64u: 'A1111111111111111111111111111111111111111111',
          thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
          relayerKeyId: 'relayer-key-ecdsa',
          relayerVerifyingShareB64u: 'relayer-share',
          participantIds: [1, 2],
        },
      ],
    }),
  ).rejects.toThrow('wallet key walletId mismatch');
  expect(batchCalled).toBe(false);
});

test('wallet add-signer persistence supports both later signer-family orders', async () => {
  const makeDeps = () => {
    const calls: string[] = [];
    const authenticators: unknown[] = [];
    const activations: unknown[] = [];
    return {
      calls,
      authenticators,
      activations,
      deps: {
        indexedDB: {
          upsertProfile: async (input: { profileId: string }) => {
            calls.push(`profile:${input.profileId}`);
          },
          activateAccountSigner: async (input: unknown) => {
            const account = (input as { account?: { chainIdKey?: unknown; profileId?: unknown } })
              .account;
            calls.push(`signer:${String(account?.chainIdKey || account?.profileId || '')}`);
            activations.push(input);
            return {
              signerSlot: activations.length,
              signer: { signerSlot: activations.length },
            };
          },
          upsertProfileAuthenticator: async (input: unknown) => {
            authenticators.push(input);
            calls.push(`auth:${String((input as { profileId?: unknown }).profileId || '')}`);
          },
          setLastProfileStateForProfile: async (profileId: string, signerSlot: number) => {
            calls.push(`last:${profileId}:${signerSlot}`);
          },
          persistWalletRegistrationFinalize: async (batch: {
            profiles: Array<{ profileId: string }>;
            authenticators: unknown[];
            signerActivations: unknown[];
            lastProfileState?: { profileId: string; activeSignerSlot: number };
          }) => {
            for (const profile of batch.profiles) {
              calls.push(`profile:${profile.profileId}`);
            }
            for (const authenticator of batch.authenticators) {
              authenticators.push(authenticator);
              calls.push(
                `auth:${String((authenticator as { profileId?: unknown }).profileId || '')}`,
              );
            }
            const signerActivations = batch.signerActivations.map((input) => {
              const account = (input as { account?: { chainIdKey?: unknown; profileId?: unknown } })
                .account;
              calls.push(`signer:${String(account?.chainIdKey || account?.profileId || '')}`);
              activations.push(input);
              return {
                signerSlot: activations.length,
                signer: { signerSlot: activations.length },
              };
            });
            if (batch.lastProfileState) {
              calls.push(
                `last:${batch.lastProfileState.profileId}:${batch.lastProfileState.activeSignerSlot}`,
              );
            }
            return { signerActivations };
          },
          persistWalletSignerFinalize: async (batch: {
            profiles: Array<{ profileId: string }>;
            signerActivations: unknown[];
            lastProfileState?: { profileId: string; activeSignerSlot: number };
          }) => {
            for (const profile of batch.profiles) {
              calls.push(`profile:${profile.profileId}`);
            }
            const signerActivations = batch.signerActivations.map((input) => {
              const account = (input as { account?: { chainIdKey?: unknown; profileId?: unknown } })
                .account;
              calls.push(`signer:${String(account?.chainIdKey || account?.profileId || '')}`);
              activations.push(input);
              return {
                signerSlot: activations.length,
                signer: { signerSlot: activations.length },
              };
            });
            if (batch.lastProfileState) {
              calls.push(
                `last:${batch.lastProfileState.profileId}:${batch.lastProfileState.activeSignerSlot}`,
              );
            }
            return { signerActivations };
          },
        },
      },
    };
  };
  const walletId = walletIdFromString('wallet_matrix');
  const walletKeys = [
    {
      keyScope: 'evm-family' as const,
      chainTarget: {
        kind: 'evm' as const,
        namespace: 'eip155' as const,
        chainId: 1,
        networkSlug: 'ethereum',
      },
      walletId: 'wallet_matrix',
      walletKeyId: 'wallet-key-matrix',
      evmFamilySigningKeySlotId: 'evm-family-slot-matrix',
      keyHandle: 'ehss-key-matrix',
      ecdsaThresholdKeyId: 'ehss-key-id-matrix',
      signingRootId: 'project_registration:dev',
      signingRootVersion: 'root_v1',
      thresholdEcdsaPublicKeyB64u: 'A1111111111111111111111111111111111111111111',
      thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
      relayerKeyId: 'relayer-key-ecdsa',
      relayerVerifyingShareB64u: 'relayer-share',
      participantIds: [1, 2],
    },
  ];

  const ed25519ThenEcdsa = makeDeps();
  (ed25519ThenEcdsa.deps as any).accountStore = ed25519ThenEcdsa.deps.indexedDB;
  await storeWalletEd25519RegistrationData(ed25519ThenEcdsa.deps as any, {
    walletId,
    nearAccountId: toAccountId('matrix.testnet'),
    nearEd25519SigningKeyId: String(nearEd25519SigningKeyIdFromString(String(walletId))),
    credential,
    credentialPublicKeyB64u: 'AQID',
    signerSlot: 1,
    operationalPublicKey: 'ed25519:public',
    relayerKeyId: 'relayer-key',
    keyVersion: 'router-ab-ed25519-yao-v1',
    participantIds: [1, 2],
  });
  await storeWalletEcdsaSignerRecords(ed25519ThenEcdsa.deps as any, {
    walletId,
    walletKeys,
  });
  expect(ed25519ThenEcdsa.calls).toContain('signer:wallet');
  expect(ed25519ThenEcdsa.calls).toContain('signer:evm:eip155:1');
  expect(ed25519ThenEcdsa.calls).toContain('signer:near:testnet');
  expect(ed25519ThenEcdsa.authenticators).toHaveLength(2);

  const ecdsaThenEd25519 = makeDeps();
  (ecdsaThenEd25519.deps as any).accountStore = ecdsaThenEd25519.deps.indexedDB;
  await storeWalletEcdsaSignerRecords(ecdsaThenEd25519.deps as any, {
    walletId,
    walletKeys,
  });
  await finalizeWalletEd25519SignerRegistration(ecdsaThenEd25519.deps as any, {
    walletId,
    nearAccountId: toAccountId('matrix.testnet'),
    nearEd25519SigningKeyId: String(nearEd25519SigningKeyIdFromString('matrix.testnet')),
    credential: authenticationCredential,
    signerSlot: 2,
    operationalPublicKey: 'ed25519:public',
    relayerKeyId: 'relayer-key',
    keyVersion: 'router-ab-ed25519-yao-v1',
    participantIds: [1, 2],
  });
  expect(ecdsaThenEd25519.calls).toContain('signer:evm:eip155:1');
  expect(ecdsaThenEd25519.calls).toContain('signer:wallet');
  expect(ecdsaThenEd25519.calls).toContain('signer:near:testnet');
  expect(ecdsaThenEd25519.authenticators).toEqual([]);
});
