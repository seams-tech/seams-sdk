import { expect, test } from '@playwright/test';
import type { WebAuthnRegistrationCredential } from '../../packages/wallet/src/core/types/webauthn';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/wallet-server/src/router/framework/routeDefinitions';
import { finalizeWalletRecovery } from '../../packages/wallet/src/core/rpcClients/relayer/walletRecoveryFinalize';
import {
  ENVELOPE_ID,
  WALLET_ID,
  passkeyCustodyEnvelope,
} from './helpers/passkeyCustodyEnvelope.fixtures';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';
import { buildFullOwnerDelegatedWalletAuthorityV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';

const REGISTRATION: WebAuthnRegistrationCredential = {
  id: 'replacement-credential',
  rawId: 'replacement-credential',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'client-data',
    attestationObject: 'attestation',
    transports: ['internal'],
  },
  clientExtensionResults: {
    prf: {
      results: {
        first: 'secret-first',
        second: 'secret-second',
      },
    },
  },
};

type CapturedRequest = {
  url: string;
  body: Record<string, unknown> | null;
};

function captureRequest(capture: CapturedRequest, body: unknown): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    capture.url = String(input);
    capture.body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }) as typeof fetch;
}

function respondWith(status: number, body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })) as unknown as typeof fetch;
}

function finalizeWith(fetchImpl: typeof fetch) {
  return finalizeWalletRecovery({
    relayUrl: 'https://relay.localhost/',
    walletId: WALLET_ID,
    reservationId: 'reservation-1',
    challengeId: 'challenge-1',
    replacementId: ENVELOPE_ID,
    webauthnRegistration: REGISTRATION,
    replacementEnvelope: passkeyCustodyEnvelope(),
    ecdsaMaterialPossessionProofs: [],
    fetchImpl,
  });
}

async function recoveryProjectionFixture() {
  return await buildLinkedDeviceManagementAuthorityFixture({
    label: 'recovery-wire',
    permissions: buildFullOwnerDelegatedWalletAuthorityV1().permissions,
    provenance: 'wallet_registration',
    identity: {
      walletId: WALLET_ID,
      authorityId: 'wallet-authority:replacement',
      walletAuthMethodId: 'wallet-auth-method:replacement',
      rpId: 'example.localhost',
    },
  });
}

test('the route is registered where the client posts', () => {
  const routeDefinitions = createRouterApiRouteDefinitions();
  const route = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_finalize');
  expect(route?.path).toBe('/wallets/recovery/finalize');
});

test('finalize posts only the atomic R114 promotion request', async () => {
  const captured: CapturedRequest = { url: '', body: null };
  const projection = await recoveryProjectionFixture();
  const result = await finalizeWith(
    captureRequest(captured, {
      ok: true,
      storeVersion: '2',
      authority: projection.authority,
      authMethod: projection.authMethod,
    }),
  );

  expect(captured.url).toBe('https://relay.localhost/wallets/recovery/finalize');
  expect(Object.keys(captured.body ?? {}).sort()).toEqual([
    'challengeId',
    'ecdsaMaterialPossessionProofs',
    'replacementEnvelope',
    'replacementId',
    'reservationId',
    'walletId',
    'webauthnRegistration',
  ]);
  expect(captured.body).toMatchObject({
    walletId: WALLET_ID,
    reservationId: 'reservation-1',
    challengeId: 'challenge-1',
    replacementId: ENVELOPE_ID,
    ecdsaMaterialPossessionProofs: [],
    webauthnRegistration: { clientExtensionResults: null },
  });
  expect(result).toEqual({
    kind: 'promoted',
    storeVersion: '2',
    authority: projection.authority,
    authMethod: projection.authMethod,
  });
});

test('finalize accepts only the exact success response', async () => {
  const legacyResponse = await finalizeWith(
    respondWith(200, {
      ok: true,
      storeVersion: '2',
      retiredEnvelopeIds: ['old-envelope'],
    }),
  );

  expect(legacyResponse).toEqual({ kind: 'transport_uncertain' });
});

test('finalize preserves the three exact failure classifications', async () => {
  const refused = await finalizeWith(respondWith(400, { ok: false }));
  const conflict = await finalizeWith(respondWith(409, { ok: false }));
  const uncertain = await finalizeWith(respondWith(503, { ok: false }));

  expect(refused).toEqual({ kind: 'refused' });
  expect(conflict).toEqual({ kind: 'retryable_conflict' });
  expect(uncertain).toEqual({ kind: 'transport_uncertain' });
});
