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

void seams.recovery.syncAccount({ walletId: 'frost-vermillion-k7p9m2' });
// @ts-expect-error syncAccount identifies a wallet, not a NEAR account-shaped accountId.
void seams.recovery.syncAccount({ accountId: 'alice.testnet' });
void seams.recovery.startEmailRecovery({ walletId: 'frost-vermillion-k7p9m2' });
// @ts-expect-error startEmailRecovery identifies a wallet, not a NEAR account-shaped accountId.
void seams.recovery.startEmailRecovery({ accountId: 'alice.testnet' });
void seams.recovery.finalizeEmailRecovery({ walletId: 'frost-vermillion-k7p9m2' });
// @ts-expect-error finalizeEmailRecovery identifies a wallet, not a NEAR account-shaped accountId.
void seams.recovery.finalizeEmailRecovery({ accountId: 'alice.testnet' });
void seams.recovery.cancelEmailRecovery({ walletId: 'frost-vermillion-k7p9m2' });
// @ts-expect-error cancelEmailRecovery identifies a wallet, not a NEAR account-shaped accountId.
void seams.recovery.cancelEmailRecovery({ accountId: 'alice.testnet' });
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
void seams.recovery.getEmailOtpRecoveryCodeStatus({ walletId: 'alice.testnet' });
void seams.recovery.rotateEmailOtpRecoveryCodes({ walletId: 'alice.testnet' });
// @ts-expect-error public recovery status reads cannot accept plaintext recovery codes.
void seams.recovery.getEmailOtpRecoveryCodeStatus({ walletId: 'alice.testnet', recoveryKeys: ['secret-code'] });
// @ts-expect-error public recovery rotation cannot accept caller-supplied recovery codes.
void seams.recovery.rotateEmailOtpRecoveryCodes({ walletId: 'alice.testnet', recoveryCodes: ['secret-code'] });
// @ts-expect-error public recovery rotation cannot accept optional recovery-code material.
void seams.recovery.rotateEmailOtpRecoveryCodes({ walletId: 'alice.testnet', recoveryKey: 'secret-code' });

void seams.devices.stopDevice2LinkingFlow();
void seams.devices.deleteDeviceKey({
  walletSession,
  nearAccount,
  publicKeyToDelete: 'ed25519:11111111111111111111111111111111',
  options: {},
});
void seams.devices.viewAccessKeyList({
  walletSession,
  nearAccount,
});
// @ts-expect-error listing NEAR access keys requires a wallet-scoped subject and NEAR account ref.
void seams.devices.viewAccessKeyList('alice.testnet');
// @ts-expect-error deleting a NEAR access key requires the wallet session subject.
void seams.devices.deleteDeviceKey({
  nearAccount,
  publicKeyToDelete: 'ed25519:11111111111111111111111111111111',
  options: {},
});
// @ts-expect-error deleting a NEAR access key no longer accepts raw account id arguments.
void seams.devices.deleteDeviceKey('alice.testnet', 'ed25519:11111111111111111111111111111111', {});

void seams.keys.exportKeypairWithUI({
  kind: 'near',
  walletSession,
  nearAccount,
  options: {
    chain: 'near',
  },
});

seams.preferences.setConfirmBehavior('requireClick');
void seams.preferences.getConfirmationConfig();
