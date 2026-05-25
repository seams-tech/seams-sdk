import { expect, test } from '@playwright/test';
import {
  storeWalletSubjectEcdsaSignerRecords,
  storeWalletSubjectEd25519SignerRecord,
  storeWalletSubjectEd25519RegistrationData,
} from '../../client/src/core/signingEngine/flows/registration/accountLifecycle';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../../client/src/core/types/webauthn';
import { toAccountId } from '../../client/src/core/types/accountIds';
import { walletSubjectIdFromString } from '../../shared/src/utils/registrationIntent';

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

test('wallet registration persists wallet-subject signer before NEAR projection', async () => {
  const calls: string[] = [];
  const activations: unknown[] = [];
  const authenticators: unknown[] = [];
  const deps = {
    extractCosePublicKey: async () => new Uint8Array([1, 2, 3]),
    indexedDB: {
      clientDB: {
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
      },
    },
  };

  const result = await storeWalletSubjectEd25519RegistrationData(deps as any, {
    walletSubjectId: walletSubjectIdFromString('wallet_alice'),
    nearAccountId: toAccountId('alice.testnet'),
    credential,
    signerSlot: 2,
    operationalPublicKey: 'ed25519:public',
    relayerKeyId: 'relayer-key',
    keyVersion: 'threshold-ed25519-hss-v1',
    participantIds: [1, 2],
  });

  expect(result.signerSlot).toBe(2);
  expect(calls).toEqual([
    'profile:wallet_alice',
    'signer:wallet_alice',
    'auth:wallet_alice',
    'profile:near-profile:alice.testnet',
    'signer:near-profile:alice.testnet',
    'auth:near-profile:alice.testnet',
    'last:near-profile:alice.testnet:2',
  ]);
  expect(activations[0]).toMatchObject({
    account: {
      profileId: 'wallet_alice',
      chainIdKey: 'wallet-subject',
      accountAddress: 'wallet_alice',
      accountModel: 'wallet-subject',
    },
    signer: {
      signerId: 'credential-raw-id',
      metadata: {
        walletSubjectId: 'wallet_alice',
        nearAccountId: 'alice.testnet',
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
  const authenticators: unknown[] = [];
  const deps = {
    extractCosePublicKey: async () => new Uint8Array([1, 2, 3]),
    indexedDB: {
      clientDB: {
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
      },
    },
  };

  const result = await storeWalletSubjectEd25519SignerRecord(deps as any, {
    walletSubjectId: walletSubjectIdFromString('wallet_alice'),
    nearAccountId: toAccountId('alice.testnet'),
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
    'signer:wallet_alice',
    'profile:near-profile:alice.testnet',
    'signer:near-profile:alice.testnet',
    'last:near-profile:alice.testnet:3',
  ]);
  expect(authenticators).toEqual([]);
  expect(activations[0]).toMatchObject({
    account: {
      profileId: 'wallet_alice',
      chainIdKey: 'wallet-subject',
      accountAddress: 'wallet_alice',
      accountModel: 'wallet-subject',
    },
    signer: {
      signerId: 'credential-raw-id',
      metadata: {
        walletSubjectId: 'wallet_alice',
        nearAccountId: 'alice.testnet',
        operationalPublicKey: 'ed25519:public',
        relayerKeyId: 'relayer-key',
      },
    },
  });
});

test('wallet add-signer persists ECDSA signer records without re-registering authenticator', async () => {
  const calls: string[] = [];
  const activations: unknown[] = [];
  const authenticators: unknown[] = [];
  const deps = {
    extractCosePublicKey: async () => new Uint8Array([1, 2, 3]),
    indexedDB: {
      clientDB: {
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
      },
    },
  };

  const walletSubjectId = walletSubjectIdFromString('wallet_alice');
  const walletKeys = [
    {
      keyScope: 'evm-family' as const,
      chainTarget: {
        kind: 'evm' as const,
        namespace: 'eip155' as const,
        chainId: 1,
        networkSlug: 'ethereum',
      },
      walletId: 'wallet-session-user',
      rpId: 'example.localhost',
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

  const result = await storeWalletSubjectEcdsaSignerRecords(deps as any, {
    walletSubjectId,
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
        rpId: 'example.localhost',
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
        extractCosePublicKey: async () => new Uint8Array([1, 2, 3]),
        indexedDB: {
          clientDB: {
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
          },
        },
      },
    };
  };
  const walletSubjectId = walletSubjectIdFromString('wallet_matrix');
  const walletKeys = [
    {
      keyScope: 'evm-family' as const,
      chainTarget: {
        kind: 'evm' as const,
        namespace: 'eip155' as const,
        chainId: 1,
        networkSlug: 'ethereum',
      },
      walletId: 'wallet-session-user',
      rpId: 'example.localhost',
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
  await storeWalletSubjectEd25519RegistrationData(ed25519ThenEcdsa.deps as any, {
    walletSubjectId,
    nearAccountId: toAccountId('matrix.testnet'),
    credential,
    signerSlot: 1,
    operationalPublicKey: 'ed25519:public',
    relayerKeyId: 'relayer-key',
    keyVersion: 'threshold-ed25519-hss-v1',
    participantIds: [1, 2],
  });
  await storeWalletSubjectEcdsaSignerRecords(ed25519ThenEcdsa.deps as any, {
    walletSubjectId,
    walletKeys,
  });
  expect(ed25519ThenEcdsa.calls).toContain('signer:wallet-subject');
  expect(ed25519ThenEcdsa.calls).toContain('signer:evm:eip155:1');
  expect(ed25519ThenEcdsa.calls).toContain('signer:near:testnet');
  expect(ed25519ThenEcdsa.authenticators).toHaveLength(2);

  const ecdsaThenEd25519 = makeDeps();
  await storeWalletSubjectEcdsaSignerRecords(ecdsaThenEd25519.deps as any, {
    walletSubjectId,
    walletKeys,
  });
  await storeWalletSubjectEd25519SignerRecord(ecdsaThenEd25519.deps as any, {
    walletSubjectId,
    nearAccountId: toAccountId('matrix.testnet'),
    credential: authenticationCredential,
    signerSlot: 2,
    operationalPublicKey: 'ed25519:public',
    relayerKeyId: 'relayer-key',
    keyVersion: 'threshold-ed25519-hss-v1',
    participantIds: [1, 2],
  });
  expect(ecdsaThenEd25519.calls).toContain('signer:evm:eip155:1');
  expect(ecdsaThenEd25519.calls).toContain('signer:wallet-subject');
  expect(ecdsaThenEd25519.calls).toContain('signer:near:testnet');
  expect(ecdsaThenEd25519.authenticators).toEqual([]);
});
