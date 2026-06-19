import { expect, test } from '@playwright/test';
import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import type { ActivateAccountSignerInput } from '@/core/indexedDB/accountSignerLifecycle';
import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  persistThresholdEcdsaBootstrapForWalletTarget,
  type ThresholdEcdsaBootstrapStorePort,
  type ThresholdEcdsaBootstrapSignerAuth,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';

type UpsertProfileCall = Parameters<ThresholdEcdsaBootstrapStorePort['upsertProfile']>[0];

const PASSKEY_SIGNER_AUTH: ThresholdEcdsaBootstrapSignerAuth = {
  authMethod: SIGNER_AUTH_METHODS.passkey,
  signerSource: SIGNER_SOURCES.passkeyRegistration,
};

const EMAIL_OTP_SIGNER_AUTH: ThresholdEcdsaBootstrapSignerAuth = {
  authMethod: SIGNER_AUTH_METHODS.emailOtp,
  signerSource: SIGNER_SOURCES.emailOtpRegistration,
};

const EVM_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'sepolia',
} as const;

const TEMPO_TARGET = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
} as const;
const VALID_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_RELAYER_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_SHARE_32_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function bootstrap(args: {
  chainId: number | string;
  ownerAddress: `0x${string}`;
  keyHandle?: string;
  ecdsaThresholdKeyId?: string;
}): ThresholdEcdsaSessionBootstrapResult {
  const keyHandle = args.keyHandle || 'key-handle-1';
  const ecdsaThresholdKeyId = args.ecdsaThresholdKeyId || 'threshold-key-1';
  const ecdsaRoleLocalReadyRecord = buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: VALID_SHARE_32_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: toWalletId('alice.testnet'),
      rpId: 'localhost',
      chainTarget: EVM_TARGET,
      keyHandle,
      ecdsaThresholdKeyId,
      signingRootId: 'signing-root-1',
      signingRootVersion: 'signing-root-v1',
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      contextBinding32B64u: VALID_SHARE_32_B64U,
      hssClientSharePublicKey33B64u: VALID_PUBLIC_KEY_B64U,
      relayerPublicKey33B64u: VALID_RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: VALID_PUBLIC_KEY_B64U,
      ethereumAddress: args.ownerAddress,
    }),
    authMethod: buildEcdsaRoleLocalPasskeyAuthMethod({
      credentialIdB64u: 'credential-1',
      rpId: 'localhost',
    }),
  });
  return {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: 'alice.testnet',
      chainTarget: EVM_TARGET,
      relayerUrl: 'https://relay.example',
      keyHandle,
      ecdsaThresholdKeyId,
      thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
      participantIds: [1, 2],
      backendBinding: {
        materialKind: 'role_local_ready_state_blob',
        relayerKeyId: 'relayer-key-1',
        clientVerifyingShareB64u: VALID_PUBLIC_KEY_B64U,
        stateBlob: ecdsaRoleLocalReadyRecord.stateBlob,
        ecdsaRoleLocalReadyRecord,
      },
      thresholdSessionId: 'tehss_1',
      signingGrantId: 'wss_1',
    },
    keygen: {
      ok: true,
      chainId: args.chainId,
      ethereumAddress: args.ownerAddress,
      keyHandle,
      ecdsaThresholdKeyId,
      rpId: 'localhost',
      relayerKeyId: 'relayer-key-1',
      relayerVerifyingShareB64u: VALID_RELAYER_PUBLIC_KEY_B64U,
      thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
      participantIds: [1, 2],
    } as ThresholdEcdsaSessionBootstrapResult['keygen'],
    session: {
      ok: true,
      sessionId: 'tehss_1',
      signingGrantId: 'wss_1',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 3,
    } as ThresholdEcdsaSessionBootstrapResult['session'],
  };
}

function createBootstrapStore(calls: {
  profiles: UpsertProfileCall[];
  signers: ActivateAccountSignerInput[];
}): ThresholdEcdsaBootstrapStorePort {
  return {
    upsertProfile: async (input) => {
      calls.profiles.push(input);
      return {};
    },
    activateAccountSigner: async (input) => {
      calls.signers.push(input);
      return {
        signerSlot: input.preferredSlot || 1,
        signer: {
          profileId: input.account.profileId,
          chainIdKey: input.account.chainIdKey,
          accountAddress: input.account.accountAddress,
          signerId: input.signer.signerId,
          signerType: input.signer.signerType,
          signerKind: input.signer.signerKind,
          signerAuthMethod: input.signer.signerAuthMethod,
          signerSource: input.signer.signerSource,
          signerSlot: input.preferredSlot || 1,
          status: 'active',
          metadata: input.signer.metadata,
          addedAt: Date.now(),
          updatedAt: Date.now(),
        } satisfies AccountSignerRecord,
      };
    },
  };
}

test.describe('threshold ECDSA bootstrap persistence', () => {
  test('persists threshold ECDSA signer identity rows', async () => {
    const calls = { profiles: [] as UpsertProfileCall[], signers: [] as ActivateAccountSignerInput[] };

    await persistThresholdEcdsaBootstrapForWalletTarget({
      bootstrapStore: createBootstrapStore(calls),
      walletId: toWalletId('alice.testnet'),
      chainTarget: EVM_TARGET,
      bootstrap: bootstrap({
        chainId: 11155111,
        ownerAddress: `0x${'ab'.repeat(20)}`,
      }),
      signerAuth: PASSKEY_SIGNER_AUTH,
    });

    expect(calls.profiles).toEqual([
      {
        profileId: 'alice.testnet',
      },
    ]);
    expect(calls.signers).toHaveLength(1);
    expect(calls.signers[0]).toMatchObject({
      account: {
        profileId: 'alice.testnet',
        chainIdKey: 'evm:eip155:11155111',
        accountAddress: `0x${'ab'.repeat(20)}`,
        accountModel: 'threshold-ecdsa',
      },
      signer: {
        signerId: `0x${'ab'.repeat(20)}`,
        signerKind: 'threshold-ecdsa',
        signerAuthMethod: 'passkey',
        signerSource: 'passkey_registration',
      },
    });
    expect(calls.signers[0]?.signer.metadata).toMatchObject({
      keyHandle: 'key-handle-1',
      ecdsaThresholdKeyId: 'threshold-key-1',
      thresholdOwnerAddress: `0x${'ab'.repeat(20)}`,
      chainTarget: EVM_TARGET,
      sharedEvmFamilyKey: {
        walletId: 'alice.testnet',
        keyHandle: 'key-handle-1',
      },
    });
  });

  test('uses requested chain target when bootstrap chain id is invalid', async () => {
    const calls = { profiles: [] as UpsertProfileCall[], signers: [] as ActivateAccountSignerInput[] };

    await persistThresholdEcdsaBootstrapForWalletTarget({
      bootstrapStore: createBootstrapStore(calls),
      walletId: toWalletId('alice.testnet'),
      chainTarget: EVM_TARGET,
      bootstrap: bootstrap({
        chainId: 'invalid',
        ownerAddress: `0x${'ab'.repeat(20)}`,
      }),
      signerAuth: PASSKEY_SIGNER_AUTH,
    });

    expect(calls.signers[0]?.account.chainIdKey).toBe('evm:eip155:11155111');
  });

  test('Email OTP bootstrap writes wallet signer state without NEAR projection compatibility rows', async () => {
    const calls = { profiles: [] as UpsertProfileCall[], signers: [] as ActivateAccountSignerInput[] };

    await persistThresholdEcdsaBootstrapForWalletTarget({
      bootstrapStore: createBootstrapStore(calls),
      walletId: toWalletId('google-user.testnet'),
      chainTarget: TEMPO_TARGET,
      bootstrap: bootstrap({
        chainId: 42431,
        ownerAddress: `0x${'34'.repeat(20)}`,
      }),
      signerAuth: EMAIL_OTP_SIGNER_AUTH,
    });

    expect(calls.profiles).toEqual([
      {
        profileId: 'google-user.testnet',
      },
    ]);
    expect(calls.signers).toHaveLength(1);
    expect(calls.signers[0]).toMatchObject({
      account: {
        profileId: 'google-user.testnet',
        chainIdKey: 'tempo:42431',
        accountAddress: `0x${'34'.repeat(20)}`,
        accountModel: 'threshold-ecdsa',
      },
      signer: {
        signerAuthMethod: 'email_otp',
        signerSource: 'email_otp_registration',
      },
      selectAsActive: false,
      mutation: { routeThroughOutbox: false },
    });
  });
});
