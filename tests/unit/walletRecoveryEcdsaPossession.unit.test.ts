import { expect, test } from '@playwright/test';
import { base64UrlDecode } from '../../packages/shared-ts/src/utils/encoders';
import {
  parseWalletRecoveryEcdsaPossessionChallengeV1,
  walletRecoveryEcdsaPossessionChallengeDigestB64uV1,
} from '../../packages/shared-ts/src/wallet-recovery/walletRecoveryEcdsaPossession';

const CHALLENGE = parseWalletRecoveryEcdsaPossessionChallengeV1({
  kind: 'wallet_recovery_ecdsa_possession_challenge_v1',
  walletId: 'wallet-1',
  reservationId: 'reservation-1',
  replacementId: 'replacement-1',
  keySetId: 'evm_family_ecdsa:key-handle-1',
  keyHandle: 'key-handle-1',
  recordedKeyManifestDigestB64u: 'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE',
  publicCapabilityDigestB64u: 'QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI',
  authorityRefDigestB64u: 'Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M',
  derivationClientSharePublicKey33B64u: 'Aly98GRuXbTqo5jzZfLqeg49QZt-AzDjnOkr3e3KxPm8',
  expectedServerGeneration: 'server-generation-1',
  serverNonceB64u: 'REREREREREREREREREREREREREREREREREREREREREQ',
  expiresAtMs: 1_900_000_000_000,
});

test('wallet recovery ECDSA possession challenge matches the Rust canonical digest', async () => {
  const digest = await walletRecoveryEcdsaPossessionChallengeDigestB64uV1(CHALLENGE);

  expect(digest).toBe('wfeQkHMxRe41zQQEmpBsz99_2wG4If08matEKYP-2L4');
  expect(Buffer.from(base64UrlDecode(digest)).toString('hex')).toBe(
    'c1f79090733145ee35cd04049a906ccfdf7fdb01b821fd3c99ab442983fed8be',
  );
});

test('wallet recovery ECDSA possession challenge binds the recovery reservation', async () => {
  const substituted = parseWalletRecoveryEcdsaPossessionChallengeV1({
    ...CHALLENGE,
    reservationId: 'reservation-2',
  });

  await expect(walletRecoveryEcdsaPossessionChallengeDigestB64uV1(substituted)).resolves.not.toBe(
    await walletRecoveryEcdsaPossessionChallengeDigestB64uV1(CHALLENGE),
  );
});
