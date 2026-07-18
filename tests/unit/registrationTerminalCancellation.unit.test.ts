import { expect, test } from '@playwright/test';
import type { RouterAbEcdsaRegistrationRequestV1 } from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { ThresholdStoreDurableObject } from '../../packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore';
import { createRouterAbEcdsaStrictRegistrationPort } from '../../packages/sdk-server-ts/src/router/routerAbEcdsaStrictRegistration';

class MemoryStorage {
  readonly values = new Map<string, unknown>();
  transactionCount = 0;

  async get(key: string): Promise<unknown> {
    return this.values.get(key) ?? null;
  }

  async put(key: string, value: unknown): Promise<void> {
    this.values.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.values.delete(key);
  }

  async transaction<T>(operation: (storage: MemoryStorage) => Promise<T>): Promise<T> {
    this.transactionCount += 1;
    return await operation(this);
  }
}

async function post(
  durableObject: ThresholdStoreDurableObject,
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const response = await durableObject.fetch(
    new Request('https://threshold-store.invalid/', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
  return (await response.json()) as Record<string, unknown>;
}

async function configurationFailureFetch(): Promise<Response> {
  return new Response(
    'InvalidLocalServiceConfig: router_project_policy.evaluate returned HTTP status 422',
    { status: 500 },
  );
}

async function issueCeremonyToken(): Promise<string> {
  return 'ceremony-token';
}

function emptyJwks(): { readonly keys: readonly JsonWebKey[] } {
  return { keys: [] };
}

test('terminal registration cancellation atomically releases its wallet reservation', async () => {
  const storage = new MemoryStorage();
  const durableObject = new ThresholdStoreDurableObject({ storage }, {});
  const ceremonyKey = 'wallet-registration:ceremony:wrc_smoke';
  const reservationKey =
    'wallet-registration:server-allocated-wallet-reservation:frost-fjord-rgcmpa';
  const walletId = 'frost-fjord-rgcmpa';
  const expiresAtMs = Date.now() + 60_000;

  await expect(
    post(durableObject, {
      op: 'registrationReserveWalletId',
      key: reservationKey,
      walletId,
      expiresAtMs,
    }),
  ).resolves.toMatchObject({ ok: true });
  await post(durableObject, {
    op: 'set',
    key: ceremonyKey,
    value: {
      registrationCeremonyId: 'wrc_smoke',
      intent: { walletId },
      expiresAtMs,
    },
  });

  await expect(
    post(durableObject, {
      op: 'registrationCancelTerminal',
      ceremonyKey,
      registrationCeremonyId: 'wrc_smoke',
      walletId: 'frost-fjord-zzzzzz',
      reservation: { kind: 'server_allocated_wallet', key: reservationKey },
    }),
  ).resolves.toMatchObject({
    ok: false,
    code: 'registration_ceremony_identity_mismatch',
  });
  expect(storage.values.has(ceremonyKey)).toBe(true);
  expect(storage.values.has(reservationKey)).toBe(true);

  storage.values.set(reservationKey, {
    kind: 'registration_wallet_reservation_v1',
    walletId: 'frost-fjord-zzzzzz',
    expiresAtMs,
  });
  await expect(
    post(durableObject, {
      op: 'registrationCancelTerminal',
      ceremonyKey,
      registrationCeremonyId: 'wrc_smoke',
      walletId,
      reservation: { kind: 'server_allocated_wallet', key: reservationKey },
    }),
  ).resolves.toMatchObject({
    ok: false,
    code: 'registration_wallet_reservation_identity_mismatch',
  });
  expect(storage.values.has(ceremonyKey)).toBe(true);
  expect(storage.values.has(reservationKey)).toBe(true);
  storage.values.set(reservationKey, {
    kind: 'registration_wallet_reservation_v1',
    walletId,
    expiresAtMs,
  });

  await expect(
    post(durableObject, {
      op: 'registrationCancelTerminal',
      ceremonyKey,
      registrationCeremonyId: 'wrc_smoke',
      walletId,
      reservation: { kind: 'server_allocated_wallet', key: reservationKey },
    }),
  ).resolves.toEqual({
    ok: true,
    value: {
      kind: 'cancelled',
      ceremonyDeleted: true,
      walletReservationReleased: true,
    },
  });
  expect(storage.values.has(ceremonyKey)).toBe(false);
  expect(storage.values.has(reservationKey)).toBe(false);
  expect(storage.transactionCount).toBe(4);
});

test('coordinator configuration failures are terminal registration failures', async () => {
  const request = strictRegistrationRequest();
  const port = createRouterAbEcdsaStrictRegistrationPort({
    router: {
      fetch: configurationFailureFetch,
    },
    tokenIssuer: {
      issue: issueCeremonyToken,
      publicJwks: emptyJwks,
    },
    tokenScope: {
      orgId: 'local-smoke-org',
      projectId: 'local-smoke-project',
      environment: 'local',
    },
    topology: {
      routerId: request.router_id,
      signerSet: request.signer_set,
      deriverRecipientKeys: {
        deriver_a: {
          role: 'signer_a',
          key_epoch: 'epoch-1',
          public_key: 'deriver-a-public-key',
        },
        deriver_b: {
          role: 'signer_b',
          key_epoch: 'epoch-1',
          public_key: 'deriver-b-public-key',
        },
      },
    },
  });

  await expect(
    port.register({
      request,
      authority: {
        subjectId: request.client_id,
        sessionId: request.lifecycle.session_id,
        accountId: request.lifecycle.account_id,
        expiresAtMs: request.expires_at_ms,
      },
    }),
  ).resolves.toEqual({
    ok: false,
    code: 'invalid_local_service_config',
    message: 'InvalidLocalServiceConfig: router_project_policy.evaluate returned HTTP status 422',
    retryable: false,
  });
});

function strictRegistrationRequest(): RouterAbEcdsaRegistrationRequestV1 {
  const digest = { bytes: new Array<number>(32).fill(0) };
  return {
    registration_purpose: 'wallet_registration',
    context: { application_binding_digest_b64u: 'application-binding' },
    lifecycle: {
      lifecycle_id: 'wrc_terminal_failure',
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: 'root-share-epoch-1',
      account_id: 'frost-fjord-rgcmpa',
      session_id: 'threshold-session-1',
      signer_set_id: 'signer-set-v1',
      selected_server_id: 'signing-worker-1',
    },
    signer_set: {
      signer_set_id: 'signer-set-v1',
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'signer-a',
        key_epoch: 'epoch-1',
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'signer-b',
        key_epoch: 'epoch-1',
      },
      selected_server: {
        server_id: 'signing-worker-1',
        key_epoch: 'epoch-1',
        recipient_encryption_key: 'signing-worker-public-key',
      },
    },
    router_id: 'local-router',
    client_id: 'frost-fjord-rgcmpa',
    replay_nonce: 'registration-replay',
    expires_at_ms: Date.now() + 60_000,
    client_ephemeral_public_key: 'client-ephemeral-public-key',
    deriver_a_envelope: {
      recipient_role: 'signer_a',
      header_digest: digest,
      aad_digest: digest,
      ciphertext: { bytes: [1] },
    },
    deriver_b_envelope: {
      recipient_role: 'signer_b',
      header_digest: digest,
      aad_digest: digest,
      ciphertext: { bytes: [2] },
    },
  };
}
