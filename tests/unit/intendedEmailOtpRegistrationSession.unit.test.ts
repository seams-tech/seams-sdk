import { expect, test } from '@playwright/test';
import { resolveEmailOtpRegistrationSession } from '../../apps/seams-site/src/pages/intended-e2e/registrationSession';

test('Email OTP registration rereads the exact session when NEAR is already ready', async () => {
  type Session = { state: 'ecdsa_snapshot' | 'near_ready_snapshot' };
  const completedSession: Session = { state: 'ecdsa_snapshot' };
  const readySession: Session = { state: 'near_ready_snapshot' };
  const walletIds: string[] = [];

  const session = await resolveEmailOtpRegistrationSession({
    walletId: 'wallet.testnet',
    completedSession,
    nearProvisioning: { status: 'near_ready' },
    auth: {
      getWalletSession: async (walletId) => {
        walletIds.push(walletId);
        return readySession;
      },
    },
  });

  expect(session).toBe(readySession);
  expect(walletIds).toEqual(['wallet.testnet']);
});
