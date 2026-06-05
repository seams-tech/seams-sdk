import {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromChainFamily,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SeamsWeb } from './index';

declare const seams: SeamsWeb;

const nearAccount = nearAccountRefFromAccountId('alice.testnet');
const walletSession = walletSessionRefFromSession({
  walletId: 'alice.testnet',
  walletSessionUserId: 'alice.testnet',
});
const evmChainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 1,
  networkSlug: 'ethereum',
});

void seams.registration.enrollEmailOtp({
  nearAccountId: 'alice.testnet',
  otpCode: '123456',
});

void seams.auth.unlock('alice.testnet');
void seams.auth.getWalletSession('alice.testnet');

void seams.near.signNEP413Message({
  nearAccount,
  params: {
    message: 'Sign in to Seams',
    recipient: 'seams.app',
  },
  options: {},
});

void seams.evm.registerEvmWallet({
  chainTargets: [evmChainTarget],
  participantIds: [1, 2],
});

void seams.evm.bootstrapEcdsaSession({
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: evmChainTarget,
});

void seams.tempo.signTempo({
  walletSession,
  chainTarget: evmChainTarget,
  request: {
    chain: 'evm',
    kind: 'eip1559',
    senderSignatureAlgorithm: 'secp256k1',
    tx: {
      chainId: 1,
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 1n,
      gasLimit: 21_000n,
      to: '0x1111111111111111111111111111111111111111',
      value: 0n,
      data: '0x',
    },
  },
});

void seams.recovery.syncAccount({ accountId: 'alice.testnet' });
void seams.recovery.getEmailOtpRecoveryCodeStatus({ walletId: 'alice.testnet' });

void seams.devices.stopDevice2LinkingFlow();

void seams.keys.exportKeypairWithUI({
  kind: 'near',
  nearAccount,
  options: {
    chain: 'near',
  },
});

seams.preferences.setConfirmBehavior('requireClick');
void seams.preferences.getConfirmationConfig();
