import {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromChainFamily,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import type { SeamsWeb } from './index';

declare const seams: SeamsWeb;
declare const rpId: WebAuthnRpId;

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
const tempoChainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 4217,
  networkSlug: 'tempo',
});

void seams.registration.enrollEmailOtp({
  walletId: 'alice.testnet',
  otpCode: '123456',
});

void seams.auth.unlock('alice.testnet');
void seams.auth.getWalletSession('alice.testnet');

void seams.near.signNEP413Message({
  walletSession,
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
  authMethod: { kind: 'passkey', rpId },
});

void seams.evm.bootstrapEcdsaSession({
  kind: 'reuse_warm_ecdsa_bootstrap',
  walletSession,
  chainTarget: evmChainTarget,
});

void seams.tempo.signTempo({
  walletSession,
  chainTarget: tempoChainTarget,
  request: {
    chain: 'tempo',
    kind: 'tempoTransaction',
    senderSignatureAlgorithm: 'secp256k1',
    tx: {
      chainId: 4217,
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 1n,
      gasLimit: 21_000n,
      calls: [
        {
          to: '0x1111111111111111111111111111111111111111',
          value: 0n,
          input: '0x',
        },
      ],
      nonceKey: 0n,
    },
  },
});

void seams.tempo.getFeeTokenPreference({
  chainTarget: tempoChainTarget,
  account: '0x1111111111111111111111111111111111111111',
});
void seams.tempo.validateFeeToken({
  chainTarget: tempoChainTarget,
  feeToken: '0x20c0000000000000000000000000000000000001',
});
void seams.tempo.setFeeTokenPreference({
  walletSession,
  chainTarget: tempoChainTarget,
  account: '0x1111111111111111111111111111111111111111',
  feeToken: '0x20c0000000000000000000000000000000000001',
  feeCaps: {
    maxPriorityFeePerGas: 1n,
    maxFeePerGas: 2n,
  },
});

void seams.evm.signTransaction({
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

void seams.recovery.syncAccount({ walletId: 'frost-vermillion-k7p9m2' });
// @ts-expect-error syncAccount identifies a wallet, not a NEAR account-shaped accountId.
void seams.recovery.syncAccount({ accountId: 'alice.testnet' });
void seams.recovery.getRecoveryEmails('frost-vermillion-k7p9m2');
void seams.recovery.setRecoveryEmails({
  walletId: 'frost-vermillion-k7p9m2',
  recoveryEmails: ['alice@example.com'],
  options: {},
});
void seams.recovery.setRecoveryEmails({
  // @ts-expect-error setRecoveryEmails identifies a wallet, not a NEAR account-shaped accountId.
  accountId: 'alice.testnet',
  recoveryEmails: ['alice@example.com'],
  options: {},
});
void seams.recovery.getWalletRecoveryCodeStatus({ walletId: 'frost-vermillion-k7p9m2' });
void seams.recovery.acknowledgeWalletRecoveryCodeBackup({ walletId: 'frost-vermillion-k7p9m2' });

void seams.devices.cancelDeviceLinking();
void seams.devices.listLinkedDevices({ walletId: 'frost-vermillion-k7p9m2' });
void seams.devices.revokeLinkedDevice({
  walletId: 'frost-vermillion-k7p9m2',
  deviceId: 'device-1',
  requestedAtMs: Date.now(),
});
// @ts-expect-error revocation requires the exact requested-at timestamp.
void seams.devices.revokeLinkedDevice({ walletId: 'frost-vermillion-k7p9m2', deviceId: 'device-1' });

seams.preferences.setConfirmBehavior('requireClick');
void seams.preferences.getConfirmationConfig();
