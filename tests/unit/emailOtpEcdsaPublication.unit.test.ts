import { expect, test } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEmailOtpEcdsaReadyPersistInput,
  buildEmailOtpEcdsaSealBinding,
  emailOtpEcdsaPublicationChainTargets,
} from '@/core/signingEngine/session/emailOtp/ecdsaPublication';
import { buildEmailOtpAuthContextForCanonicalWallet } from '@/core/signingEngine/session/identity/laneIdentity';
import { routerAbEcdsaDerivationActiveStateId } from '@shared/utils/routerAbEcdsaDerivation';
import { makeRouterAbEcdsaDerivationNormalSigningStateFixture } from './helpers/ecdsaSessionRecordVariants.fixtures';

const tempoTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42_431,
  networkSlug: 'tempo-testnet',
});
const evmTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 5_042_002,
  networkSlug: 'arc-testnet',
});

const sessionLoginAuthContext = buildEmailOtpAuthContextForCanonicalWallet({
  policy: 'session',
  retention: 'session',
  reason: 'login',
  walletId: 'wallet.testnet',
  provider: 'google',
  providerUserId: 'wallet.testnet',
  emailHashHex: 'email-hash-wallet-testnet',
});

const singleUseSignAuthContext = buildEmailOtpAuthContextForCanonicalWallet({
  policy: 'per_operation',
  retention: 'single_use',
  walletId: 'wallet.testnet',
  provider: 'google',
  providerUserId: 'wallet.testnet',
  emailHashHex: 'email-hash-wallet-testnet',
});

const configs = buildConfigsFromEnv({
  chains: [
    {
      network: 'near-testnet',
      rpcUrl: 'https://rpc.testnet.near.org',
    },
    {
      network: 'tempo-testnet',
      rpcUrl: 'https://rpc.testnet.tempo.xyz',
      chainId: 42_431,
    },
    {
      network: 'arc-testnet',
      rpcUrl: 'https://rpc.testnet.arc.network',
      chainId: 5_042_002,
    },
    {
      network: 'tempo-testnet',
      rpcUrl: 'https://duplicate.testnet.tempo.xyz',
      chainId: 42_431,
    },
  ],
  relayer: {
    url: 'https://relayer.example.test',
  },
  iframeWallet: {
    walletOrigin: 'https://wallet.example.test',
  },
});

function targetKeys(targets: ReturnType<typeof emailOtpEcdsaPublicationChainTargets>): string[] {
  return targets.map(thresholdEcdsaChainTargetKey);
}

test.describe('Email OTP ECDSA publication targets', () => {
  test('session login publishes every configured concrete ECDSA target once', () => {
    expect(
      targetKeys(
        emailOtpEcdsaPublicationChainTargets({
          configs,
          chainTarget: tempoTarget,
          emailOtpAuthContext: sessionLoginAuthContext,
        }),
      ),
    ).toEqual(['tempo:42431', 'evm:eip155:5042002']);
  });

  test('single-use signing publishes only the requested primary target', () => {
    expect(
      targetKeys(
        emailOtpEcdsaPublicationChainTargets({
          configs,
          chainTarget: evmTarget,
          emailOtpAuthContext: singleUseSignAuthContext,
        }),
      ),
    ).toEqual(['evm:eip155:5042002']);
  });

  test('sealed refresh persistence input stays Email OTP owned and ECDSA scoped', () => {
    expect(
      buildEmailOtpEcdsaReadyPersistInput({
        walletId: toWalletId('wallet.testnet'),
        chainTarget: tempoTarget,
        walletSessionId: 'wallet-session-ecdsa-publication',
        quotaId: 'wallet-quota-ecdsa-publication',
        thresholdSessionId: 'threshold-ecdsa-session-1',
        emailOtpAuthContext: sessionLoginAuthContext,
      }),
    ).toEqual({
      authMethod: 'email_otp',
      curve: 'ecdsa',
      walletId: 'wallet.testnet',
      chainTarget: tempoTarget,
      walletSessionId: 'wallet-session-ecdsa-publication',
      quotaId: 'wallet-quota-ecdsa-publication',
      thresholdSessionId: 'threshold-ecdsa-session-1',
      emailOtpAuthContext: sessionLoginAuthContext,
      material: {
        kind: 'worker_handle',
        workerSessionId: 'threshold-ecdsa-session-1',
      },
    });
  });

  test('added-method unlock seals the fresh warm material under its exact ECDSA authorization scope', () => {
    const warmThresholdSessionId = 'threshold-ecdsa-login-fresh';
    const normalSigning = makeRouterAbEcdsaDerivationNormalSigningStateFixture({
      ecdsaThresholdKeyId: 'registration-lifecycle-key',
      activationEpoch: 'added-email-otp-activation',
    });

    const binding = buildEmailOtpEcdsaSealBinding({
      warmThresholdSessionId,
      normalSigning,
    });

    expect(binding).toEqual({
      warmMaterialTarget: { kind: 'ecdsa', thresholdSessionId: warmThresholdSessionId },
      authorizationThresholdSessionId: routerAbEcdsaDerivationActiveStateId(normalSigning),
    });
    expect(binding.authorizationThresholdSessionId).not.toBe(warmThresholdSessionId);
  });
});
