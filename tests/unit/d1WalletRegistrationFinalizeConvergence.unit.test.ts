import { expect, test } from '@playwright/test';
import {
  createFinalizeConvergenceHarness,
  type FinalizeConvergenceFault,
} from './helpers/d1WalletRegistrationFinalizeConvergence.fixtures';

const RESPONSE_LOSS_FAULTS: readonly FinalizeConvergenceFault[] = [
  'finalize_claim_response_loss',
  'activation_consume_response_loss',
  'session_mint_response_loss',
  'normal_signing_response_loss',
  'wallet_commit_response_loss',
  'capability_install_response_loss',
  'finalize_replay_response_loss',
  'ceremony_delete_response_loss',
  'finalize_completion_response_loss',
];

function withoutDiagnostics<T extends { readonly registrationDiagnostics?: unknown }>(
  response: T,
): Omit<T, 'registrationDiagnostics'> {
  const { registrationDiagnostics: _diagnostics, ...stable } = response;
  return stable;
}

for (const fault of RESPONSE_LOSS_FAULTS) {
  test(`wallet registration finalize converges after ${fault}`, async () => {
    const harness = await createFinalizeConvergenceHarness();
    try {
      harness.arm(fault);
      const first = await harness.service.walletRegistration.finalizeWalletRegistration(
        harness.request,
      );
      const retried = await harness.service.walletRegistration.finalizeWalletRegistration(
        harness.request,
      );

      expect(retried.ok, retried.ok ? undefined : retried.message).toBe(true);
      if (!retried.ok) throw new Error(retried.message);
      if (first.ok) {
        expect(withoutDiagnostics(first)).toEqual(withoutDiagnostics(retried));
      } else {
        expect(first.code).toBe('internal');
      }

      const replayed = await harness.service.walletRegistration.finalizeWalletRegistration(
        harness.request,
      );
      expect(replayed.ok).toBe(true);
      if (!replayed.ok) throw new Error(replayed.message);
      expect(withoutDiagnostics(replayed)).toEqual(withoutDiagnostics(retried));
      await expect(harness.countRows('wallets')).resolves.toBe(1);
      await expect(harness.countRows('wallet_signers')).resolves.toBe(1);
      await expect(harness.countRows('wallet_auth_methods')).resolves.toBe(1);
      await expect(harness.countRows('webauthn_authenticators')).resolves.toBe(1);
      await expect(harness.countRows('webauthn_credential_bindings')).resolves.toBe(1);
    } finally {
      harness.cleanup();
    }
  });
}

test('concurrent wallet registration finalize attempts converge to one exact response', async () => {
  const harness = await createFinalizeConvergenceHarness();
  try {
    const [first, second] = await Promise.all([
      harness.service.walletRegistration.finalizeWalletRegistration(harness.request),
      harness.service.walletRegistration.finalizeWalletRegistration(harness.request),
    ]);

    expect(first.ok, first.ok ? undefined : first.message).toBe(true);
    expect(second.ok, second.ok ? undefined : second.message).toBe(true);
    if (!first.ok || !second.ok) return;
    expect(withoutDiagnostics(second)).toEqual(withoutDiagnostics(first));
    await expect(harness.countRows('wallets')).resolves.toBe(1);
    await expect(harness.countRows('wallet_signers')).resolves.toBe(1);
    await expect(harness.countRows('wallet_auth_methods')).resolves.toBe(1);
  } finally {
    harness.cleanup();
  }
});
