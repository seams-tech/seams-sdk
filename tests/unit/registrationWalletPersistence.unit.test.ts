import { expect, test } from '@playwright/test';
import {
  hasPasskeyCredential,
  nearAuthenticatorsByAccount,
  storeWalletEcdsaSignerRecords,
  finalizeWalletEd25519SignerRegistration,
  storeWalletEd25519RegistrationData,
} from '../../packages/sdk-web/src/core/signingEngine/flows/registration/accountLifecycle';
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
        calls.push(
          `auth:${String((input as { profileId?: unknown }).profileId || '')}`,
        );
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
    keyVersion: 'threshold-ed25519-hss-v1',
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
    keyVersion: 'threshold-ed25519-hss-v1',
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
      keyVersion: 'threshold-ed25519-hss-v1',
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
      keyHandle: 'ehss-key-alice',
      ecdsaThresholdKeyId: 'ehss-key-id-alice',
      signingRootId: 'project_registration:dev',
      signingRootVersion: 'root_v1',
      thresholdEcdsaPublicKeyB64u:
        'A1111111111111111111111111111111111111111111',
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
        walletKeyId: 'wallet-key-alice',
        ecdsaThresholdKeyId: 'ehss-key-id-alice',
        signingRootId: 'project_registration:dev',
        signingRootVersion: 'root_v1',
        chainTarget: walletKeys[0].chainTarget,
        sharedEvmFamilyKey: {
          walletId: 'wallet_alice',
          keyHandle: 'ehss-key-alice',
          thresholdEcdsaPublicKeyB64u:
            'A1111111111111111111111111111111111111111111',
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
          walletKeyId: 'wallet-key-bob',
          keyHandle: 'ehss-key-alice',
          ecdsaThresholdKeyId: 'ehss-key-id-alice',
          signingRootId: 'project_registration:dev',
          signingRootVersion: 'root_v1',
          thresholdEcdsaPublicKeyB64u:
            'A1111111111111111111111111111111111111111111',
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
            calls.push(
              `signer:${String(account?.chainIdKey || account?.profileId || '')}`,
            );
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
              calls.push(`auth:${String((authenticator as { profileId?: unknown }).profileId || '')}`);
            }
            const signerActivations = batch.signerActivations.map((input) => {
              const account = (input as { account?: { chainIdKey?: unknown; profileId?: unknown } })
                .account;
              calls.push(
                `signer:${String(account?.chainIdKey || account?.profileId || '')}`,
              );
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
              calls.push(
                `signer:${String(account?.chainIdKey || account?.profileId || '')}`,
              );
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
      keyHandle: 'ehss-key-matrix',
      ecdsaThresholdKeyId: 'ehss-key-id-matrix',
      signingRootId: 'project_registration:dev',
      signingRootVersion: 'root_v1',
      thresholdEcdsaPublicKeyB64u:
        'A1111111111111111111111111111111111111111111',
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
    keyVersion: 'threshold-ed25519-hss-v1',
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
    keyVersion: 'threshold-ed25519-hss-v1',
    participantIds: [1, 2],
  });
  expect(ecdsaThenEd25519.calls).toContain('signer:evm:eip155:1');
  expect(ecdsaThenEd25519.calls).toContain('signer:wallet');
  expect(ecdsaThenEd25519.calls).toContain('signer:near:testnet');
  expect(ecdsaThenEd25519.authenticators).toEqual([]);
});
