import { expect, test } from '@playwright/test';
import {
  buildMismatchedFinalizeConvergenceRequest,
  createFinalizeConvergenceHarness,
  createSponsoredFinalizeConvergenceHarness,
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

for (const fault of RESPONSE_LOSS_FAULTS) {
  test(`wallet registration finalize converges after ${fault}`, async () => {
    const harness = await createFinalizeConvergenceHarness();
    try {
      harness.arm(fault);
      const first = await harness.service.walletRegistration.finalizeWalletRegistration(
        harness.request,
      );
      if (!first.ok) await harness.expireFinalizeClaim();
      const retried = await harness.service.walletRegistration.finalizeWalletRegistration(
        harness.request,
      );

      expect(retried.ok, retried.ok ? undefined : retried.message).toBe(true);
      if (!retried.ok) throw new Error(retried.message);
      if (first.ok) {
        expect(first).toEqual(retried);
      } else {
        expect(first.code).toBe('internal');
      }

      const replayed = await harness.service.walletRegistration.finalizeWalletRegistration(
        harness.request,
      );
      expect(replayed.ok).toBe(true);
      if (!replayed.ok) throw new Error(replayed.message);
      expect(replayed).toEqual(retried);
      await expect(harness.countRows('wallets')).resolves.toBe(1);
      await expect(harness.countRows('wallet_signers')).resolves.toBe(1);
      await expect(harness.countRows('wallet_auth_methods')).resolves.toBe(1);
      await expect(harness.countRows('webauthn_authenticators')).resolves.toBe(1);
      await expect(harness.countRows('webauthn_credential_bindings')).resolves.toBe(1);
    } finally {
      await harness.cleanup();
    }
  });
}

test('a live finalize claim prevents concurrent duplicate execution', async () => {
  const harness = await createFinalizeConvergenceHarness();
  try {
    const [first, second] = await Promise.all([
      harness.service.walletRegistration.finalizeWalletRegistration(harness.request),
      harness.service.walletRegistration.finalizeWalletRegistration(harness.request),
    ]);

    const successful = [first, second].filter((response) => response.ok);
    const contended = [first, second].filter((response) => !response.ok);
    expect(successful).toHaveLength(1);
    expect(contended).toHaveLength(1);
    expect(contended[0]).toMatchObject({
      ok: false,
      code: 'conflict',
      retryAfterMs: 30_000,
    });
    const replayed = await harness.service.walletRegistration.finalizeWalletRegistration(
      harness.request,
    );
    expect(replayed).toEqual(successful[0]);
    await expect(harness.countRows('wallets')).resolves.toBe(1);
    await expect(harness.countRows('wallet_signers')).resolves.toBe(1);
    await expect(harness.countRows('wallet_auth_methods')).resolves.toBe(1);
  } finally {
    await harness.cleanup();
  }
});

test('deterministic finalize failures are terminal and replay exactly', async () => {
  const harness = await createFinalizeConvergenceHarness();
  try {
    const mismatched = buildMismatchedFinalizeConvergenceRequest(harness.request);
    const first = await harness.service.walletRegistration.finalizeWalletRegistration(mismatched);
    const replayed =
      await harness.service.walletRegistration.finalizeWalletRegistration(mismatched);

    expect(first.ok).toBe(false);
    expect(replayed).toEqual(first);
    const corrected = await harness.service.walletRegistration.finalizeWalletRegistration(
      harness.request,
    );
    expect(corrected).toMatchObject({ ok: false, code: 'idempotency_conflict' });
  } finally {
    await harness.cleanup();
  }
});

test('sponsored named-account finalize reconciles broadcast response loss without a duplicate effect', async () => {
  const harness = await createSponsoredFinalizeConvergenceHarness();
  try {
    const first = await harness.service.walletRegistration.finalizeWalletRegistration(
      harness.request,
    );
    expect(first).toMatchObject({ ok: false, code: 'internal' });
    expect(harness.sponsoredNearRpcCounts()).toEqual({ broadcastCount: 1, txStatusCount: 0 });

    await harness.expireFinalizeClaim();
    const retried = await harness.service.walletRegistration.finalizeWalletRegistration(
      harness.request,
    );
    expect(retried.ok, retried.ok ? undefined : retried.message).toBe(true);
    expect(harness.sponsoredNearRpcCounts()).toEqual({ broadcastCount: 1, txStatusCount: 1 });

    const replayed = await harness.service.walletRegistration.finalizeWalletRegistration(
      harness.request,
    );
    expect(replayed).toEqual(retried);
    expect(harness.sponsoredNearRpcCounts()).toEqual({ broadcastCount: 1, txStatusCount: 1 });
    await expect(harness.countRows('wallets')).resolves.toBe(1);
    await expect(harness.countRows('wallet_signers')).resolves.toBe(1);
  } finally {
    await harness.cleanup();
  }
});

test('sponsored named-account finalize rejects a corrupted D1 prepared artifact before network access', async () => {
  const harness = await createSponsoredFinalizeConvergenceHarness();
  try {
    const first = await harness.service.walletRegistration.finalizeWalletRegistration(
      harness.request,
    );
    expect(first).toMatchObject({ ok: false, code: 'internal' });
    expect(harness.sponsoredNearRpcCounts()).toEqual({ broadcastCount: 1, txStatusCount: 0 });

    await harness.corruptSponsoredPreparedArtifact();
    await harness.expireFinalizeClaim();
    const retried = await harness.service.walletRegistration.finalizeWalletRegistration(
      harness.request,
    );

    expect(retried).toMatchObject({
      ok: false,
      code: 'internal',
      message: 'Persisted NEAR transaction receiver does not match its account metadata',
    });
    expect(harness.sponsoredNearRpcCounts()).toEqual({ broadcastCount: 1, txStatusCount: 0 });
  } finally {
    await harness.cleanup();
  }
});
