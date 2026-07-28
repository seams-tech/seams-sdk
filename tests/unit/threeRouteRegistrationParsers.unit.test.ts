import { expect, test } from '@playwright/test';
import {
  respondWalletRegistration,
  activateWalletRegistration,
} from '../../packages/sdk-web/src/core/rpcClients/relayer/walletRegistration';

/**
 * Refactor 94C. Strict boundary parsers for routes 2 and 3.
 *
 * The discriminated signer plan is the mechanism that keeps a mixed-plan
 * wallet from silently registering as ECDSA-only when its deferred NEAR work
 * never arrives. These pin that the parser enforces it rather than narrowing.
 */

const RELAYER = 'https://relay.example';

function withStubbedFetch<T>(body: unknown, run: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    })) as typeof fetch;
  return run().finally(() => {
    globalThis.fetch = original;
  });
}

const RESPOND_ARGS = {
  relayerUrl: RELAYER,
  registrationCeremonyId: 'wrc_test',
  signedSetup: 'signed-setup-token',
  kind: 'passkey' as const,
  webauthnRegistration: {},
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_v1' as const,
    strictRegistration: {} as never,
  },
};

test('respond rejects a mixed plan whose deferred NEAR work is missing', async () => {
  /* The caller asked for a NEAR branch. Narrowing this to ECDSA-only would
     register a wallet the user believes has NEAR and silently does not. */
  await expect(
    withStubbedFetch(
      {
        ok: true,
        registrationCeremonyId: 'wrc_test',
        kind: 'near_ed25519_and_evm_family_ecdsa',
        ecdsa: { kind: 'router_ab_ecdsa_registration_forwarded_v1', strictResult: {} },
      },
      () => respondWalletRegistration(RESPOND_ARGS),
    ),
  ).rejects.toThrow(/ed25519/i);
});

test('respond rejects an ECDSA-only plan that carries deferred NEAR work', async () => {
  await expect(
    withStubbedFetch(
      {
        ok: true,
        registrationCeremonyId: 'wrc_test',
        kind: 'evm_family_ecdsa',
        ecdsa: { kind: 'router_ab_ecdsa_registration_forwarded_v1', strictResult: {} },
        ed25519: { status: 'deferred', admissionRequest: {}, admissionReceipt: {} },
      },
      () => respondWalletRegistration(RESPOND_ARGS),
    ),
  ).rejects.toThrow(/unknown fields: ed25519/);
});

test('respond rejects an unknown signer-plan kind', async () => {
  await expect(
    withStubbedFetch(
      {
        ok: true,
        registrationCeremonyId: 'wrc_test',
        kind: 'near_ed25519',
        ecdsa: { kind: 'router_ab_ecdsa_registration_forwarded_v1', strictResult: {} },
      },
      () => respondWalletRegistration(RESPOND_ARGS),
    ),
  ).rejects.toThrow(/kind is invalid/);
});

test('respond rejects deferred NEAR work claiming a non-deferred status', async () => {
  /* Only the client decides when this work runs. A server claiming it is
     already provisioning would invite the caller to await it. */
  await expect(
    withStubbedFetch(
      {
        ok: true,
        registrationCeremonyId: 'wrc_test',
        kind: 'near_ed25519_and_evm_family_ecdsa',
        ecdsa: { kind: 'router_ab_ecdsa_registration_forwarded_v1', strictResult: {} },
        ed25519: { status: 'provisioning', admissionRequest: {}, admissionReceipt: {} },
      },
      () => respondWalletRegistration(RESPOND_ARGS),
    ),
  ).rejects.toThrow(/status is invalid/);
});

const ACTIVATE_ARGS = {
  relayerUrl: RELAYER,
  registrationCeremonyId: 'wrc_test',
  signedSetup: 'signed-setup-token',
  idempotencyKey: 'idem-1',
  ecdsa: { clientActivation: {} as never },
};

test('activate rejects a nearProvisioning snapshot carrying more than a status', async () => {
  /* NEAR identifiers before readiness are exactly what the deferred lifecycle
     exists to prevent; the snapshot is a status and nothing else. */
  await expect(
    withStubbedFetch(
      {
        ok: true,
        kind: 'evm_family_ecdsa',
        walletId: 'w.testnet',
        nearProvisioning: { status: 'pending', nearAccountId: 'leaked.testnet' },
      },
      () => activateWalletRegistration(ACTIVATE_ARGS),
    ),
  ).rejects.toThrow(/nearProvisioning contains unknown fields: nearAccountId/);
});

test('activate rejects a nearProvisioning status other than pending', async () => {
  await expect(
    withStubbedFetch(
      {
        ok: true,
        kind: 'evm_family_ecdsa',
        walletId: 'w.testnet',
        nearProvisioning: { status: 'ready' },
      },
      () => activateWalletRegistration(ACTIVATE_ARGS),
    ),
  ).rejects.toThrow(/nearProvisioning status is invalid/);
});
