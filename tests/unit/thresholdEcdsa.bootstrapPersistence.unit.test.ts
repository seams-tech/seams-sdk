import { expect, test } from '@playwright/test';
import { SIGNER_AUTH_METHODS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import type { ActivateAccountSignerInput } from '@/core/indexedDB/accountSignerLifecycle';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  persistThresholdEcdsaBootstrapForWalletTarget,
  type ThresholdEcdsaBootstrapStorePort,
  type ThresholdEcdsaBootstrapSignerAuth,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { accountSignerRecordFromActivateInput } from './helpers/accountSignerRecord.fixtures';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';

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

function bootstrap(args: {
  chain: ThresholdEcdsaActivationChain;
  walletId: string;
  ownerAddress: `0x${string}`;
  roleLocalAuthMethod?: 'passkey' | 'email_otp';
}): ThresholdEcdsaSessionBootstrapResult {
  return createThresholdEcdsaBootstrapFixture({
    nearAccountId: args.walletId,
    chain: args.chain,
    keyHandle: 'key-handle-1',
    ecdsaThresholdKeyId: 'threshold-key-1',
    ethereumAddress: args.ownerAddress,
    ...(args.roleLocalAuthMethod ? { roleLocalAuthMethod: args.roleLocalAuthMethod } : {}),
  });
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
      const signer = accountSignerRecordFromActivateInput(input);
      return {
        signerSlot: signer.signerSlot,
        signer,
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
        chain: 'evm',
        walletId: 'alice.testnet',
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
    const validBootstrap = bootstrap({
      chain: 'evm',
      walletId: 'alice.testnet',
      ownerAddress: `0x${'ab'.repeat(20)}`,
    });

    await persistThresholdEcdsaBootstrapForWalletTarget({
      bootstrapStore: createBootstrapStore(calls),
      walletId: toWalletId('alice.testnet'),
      chainTarget: EVM_TARGET,
      bootstrap: {
        ...validBootstrap,
        // Deliberately invalid: keygen reports a non-numeric chain id.
        keygen: {
          ...validBootstrap.keygen,
          chainId: 'invalid',
        } as unknown as ThresholdEcdsaSessionBootstrapResult['keygen'],
      },
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
        chain: 'tempo',
        walletId: 'google-user.testnet',
        ownerAddress: `0x${'34'.repeat(20)}`,
        roleLocalAuthMethod: 'email_otp',
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
