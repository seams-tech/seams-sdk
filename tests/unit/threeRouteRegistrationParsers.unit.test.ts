import { expect, test } from '@playwright/test';
import {
  respondWalletRegistration,
  activateWalletRegistration,
} from '../../packages/wallet/src/core/rpcClients/relayer/walletRegistration';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';

/**
 * Refactor 94C. Strict boundary parsers for routes 2 and 3.
 *
 * The discriminated signer plan is the mechanism that keeps a mixed-plan
 * wallet from silently registering as ECDSA-only when its deferred NEAR work
 * never arrives. These pin that the parser enforces it rather than narrowing.
 */

const RELAYER = 'https://relay.example';

function withStubbedFetch<T>(
  body: unknown,
  run: () => Promise<T>,
  observeRequest?: (init: RequestInit | undefined) => void,
): Promise<T> {
  const original = globalThis.fetch;
  globalThis.fetch = (async (_input, init) => {
    observeRequest?.(init);
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  return run().finally(() => {
    globalThis.fetch = original;
  });
}

const RESPOND_ARGS = {
  relayerUrl: RELAYER,
  registrationCeremonyId: 'wrc_test',
  signerPlanKind: 'near_ed25519_and_evm_family_ecdsa' as const,
  signedSetup: 'signed-setup-token',
  kind: 'passkey' as const,
  webauthnRegistration: {},
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_v1' as const,
    strictRegistration: {} as never,
    requestDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  },
};

test('respond sends the signer plan and authority proof at the route boundary', async () => {
  const { buildFixtureRespondEd25519DeferredWork } =
    await import('../helpers/ed25519YaoAdmissionFixtures');
  let requestBody: Record<string, unknown> | null = null;
  await withStubbedFetch(
    {
      ok: true,
      registrationCeremonyId: 'wrc_test',
      kind: 'near_ed25519',
      ed25519: buildFixtureRespondEd25519DeferredWork({ lifecycleId: 'wrc_test' }),
    },
    () =>
      respondWalletRegistration({
        relayerUrl: RELAYER,
        registrationCeremonyId: 'wrc_test',
        signerPlanKind: 'near_ed25519',
        signedSetup: 'signed-setup-token',
        kind: 'email_otp',
        emailOtpRegistrationProof: {} as never,
      }),
    (init) => {
      requestBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
    },
  );
  expect(requestBody).toMatchObject({
    registrationCeremonyId: 'wrc_test',
    kind: 'near_ed25519',
    emailOtpRegistrationProof: {},
  });
  expect(requestBody).not.toHaveProperty('authority');
});

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
        kind: 'secp256r1_passkey_only',
        ecdsa: { kind: 'router_ab_ecdsa_registration_forwarded_v1', strictResult: {} },
      },
      () => respondWalletRegistration(RESPOND_ARGS),
    ),
  ).rejects.toThrow(/kind is invalid/);
});

test('respond rejects an Ed25519-only plan carrying ECDSA proof bundles', async () => {
  /* No ECDSA leg ran for this plan, so bundles cannot exist. Accepting them
     would mean verifying proofs for a ceremony that never produced any. */
  await expect(
    withStubbedFetch(
      {
        ok: true,
        registrationCeremonyId: 'wrc_test',
        kind: 'near_ed25519',
        ecdsa: { kind: 'router_ab_ecdsa_registration_forwarded_v1', strictResult: {} },
        ed25519: { status: 'deferred', admissionRequest: {}, admissionReceipt: {} },
      },
      () => respondWalletRegistration(RESPOND_ARGS),
    ),
  ).rejects.toThrow(/unknown fields: ecdsa/);
});

test('respond accepts an Ed25519-only plan with only deferred NEAR work', async () => {
  const { buildFixtureRespondEd25519DeferredWork } =
    await import('../helpers/ed25519YaoAdmissionFixtures');
  const result = await withStubbedFetch(
    {
      ok: true,
      registrationCeremonyId: 'wrc_test',
      kind: 'near_ed25519',
      ed25519: buildFixtureRespondEd25519DeferredWork({ lifecycleId: 'wrc_test' }),
    },
    () => respondWalletRegistration(RESPOND_ARGS),
  );
  expect(result.kind).toBe('near_ed25519');
  /* The wallet's sole signer is still deferred — never awaited here. */
  expect(result.ed25519?.status).toBe('deferred');
  expect('ecdsa' in result).toBe(false);
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
  signerPlanKind: 'evm_family_ecdsa' as const,
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
        ecdsa: { walletKeys: [] },
        nearProvisioning: { status: 'near_pending', nearAccountId: 'leaked.testnet' },
      },
      () => activateWalletRegistration(ACTIVATE_ARGS),
    ),
  ).rejects.toThrow(/nearProvisioning contains unknown fields: nearAccountId/);
});

test('activate rejects a nearProvisioning status other than near_pending', async () => {
  await expect(
    withStubbedFetch(
      {
        ok: true,
        kind: 'evm_family_ecdsa',
        walletId: 'w.testnet',
        ecdsa: { walletKeys: [] },
        nearProvisioning: { status: 'ready' },
      },
      () => activateWalletRegistration(ACTIVATE_ARGS),
    ),
  ).rejects.toThrow(/nearProvisioning status is invalid/);
});

test('activate rejects a response missing the activation payload', async () => {
  /* Activate absorbed derivation/activate as well as finalize, so `ecdsa`
     carries the wallet keys *and* the activation payload. Without `activation`
     and `bootstrap` the client cannot build its ECDSA session, and the wallet
     would register server-side while being unable to sign — so this fails at
     the boundary rather than producing an unusable wallet. */
  await expect(
    withStubbedFetch(
      { ok: true, kind: 'evm_family_ecdsa', walletId: 'w.testnet', ecdsa: { walletKeys: [] } },
      () => activateWalletRegistration(ACTIVATE_ARGS),
    ),
  ).rejects.toThrow(/missing the activation payload/);
});

test('activate accepts an Ed25519 wallet pending signer provisioning', async () => {
  const walletId = 'pending-ed25519.testnet';
  const rpId = 'example.test';
  const credentialIdB64u = 'credential-id';
  const authority = buildPasskeyWalletAuthAuthority({ walletId, rpId, credentialIdB64u });

  const result = await withStubbedFetch(
    {
      ok: true,
      kind: 'near_ed25519',
      walletId,
      authority,
      rpId,
      authMethod: {
        kind: 'passkey',
        credentialIdB64u,
        credentialPublicKeyB64u: 'credential-public-key',
      },
      nearProvisioning: { status: 'near_pending' },
    },
    () =>
      activateWalletRegistration({
        relayerUrl: RELAYER,
        registrationCeremonyId: 'wrc_pending_ed25519',
        signerPlanKind: 'near_ed25519',
        signedSetup: 'signed-setup-token',
        idempotencyKey: 'idem-pending-ed25519',
      }),
  );

  expect(result).toMatchObject({
    ok: true,
    kind: 'near_ed25519',
    walletId,
    nearProvisioning: { status: 'near_pending' },
  });
  expect(result).not.toHaveProperty('authorityScope');
});
