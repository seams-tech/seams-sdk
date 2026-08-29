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
import { buildWalletRecoveryCommittedProjectionV1 } from '../../packages/shared-ts/src/wallet-recovery/walletRecoveryCommittedProjection';
import { parseDeviceId } from '../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletRecoveryOperationId,
} from '../../packages/shared-ts/src/utils/domainIds';

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

function required<T>(result: { readonly ok: true; readonly value: T } | { readonly ok: false }): T {
  if (!result.ok) throw new Error('invalid recovery fixture identity');
  return result.value;
}

const RECOVERY_OPERATION_ID = required(
  parseWalletRecoveryOperationId('wallet-recovery-operation:wire-1'),
);
const TARGET_DEVICE_ID = required(parseDeviceId('device:management-wire-1'));
const TARGET_AUTHORITY_ID = required(parseWalletAuthorityId('wallet-authority:replacement'));
const TARGET_AUTH_METHOD_ID = required(parseWalletAuthMethodId('wallet-auth-method:replacement'));

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
    recoveryOperationId: 'wallet-recovery-operation:wire-1',
    targetDeviceId: String(TARGET_DEVICE_ID),
    targetAuthorityId: 'wallet-authority:replacement',
    targetWalletAuthMethodId: String(TARGET_AUTH_METHOD_ID),
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
    label: 'wire-1',
    permissions: buildFullOwnerDelegatedWalletAuthorityV1().permissions,
    provenance: 'wallet_recovery',
    identity: {
      walletId: WALLET_ID,
      authorityId: 'wallet-authority:replacement',
      walletAuthMethodId: 'wallet-auth-method:replacement',
      rpId: 'wallet.example.localhost',
      credentialIdB64u: 'Y3JlZGVudGlhbC0x',
    },
  });
}

test('the route is registered where the client posts', () => {
  const routeDefinitions = createRouterApiRouteDefinitions();
  const route = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_finalize');
  expect(route?.path).toBe('/wallets/recovery/finalize');
});

test('finalize posts only the atomic R115 promotion request', async () => {
  const captured: CapturedRequest = { url: '', body: null };
  const projection = await recoveryProjectionFixture();
  const committedProjection = buildWalletRecoveryCommittedProjectionV1({
    kind: 'passkey',
    storeVersion: '2',
    walletId: required(parseWalletId(WALLET_ID)),
    recoveryOperationId: RECOVERY_OPERATION_ID,
    targetDeviceId: TARGET_DEVICE_ID,
    targetAuthorityId: TARGET_AUTHORITY_ID,
    targetWalletAuthMethodId: TARGET_AUTH_METHOD_ID,
    authority: projection.authority,
    authMethod: projection.authMethod,
  });
  const result = await finalizeWith(
    captureRequest(captured, {
      ok: true,
      projection: committedProjection,
    }),
  );

  expect(captured.url).toBe('https://relay.localhost/wallets/recovery/finalize');
  expect(Object.keys(captured.body ?? {}).sort()).toEqual([
    'challengeId',
    'ecdsaMaterialPossessionProofs',
    'recoveryOperationId',
    'replacementEnvelope',
    'replacementId',
    'reservationId',
    'targetAuthorityId',
    'targetDeviceId',
    'targetWalletAuthMethodId',
    'walletId',
    'webauthnRegistration',
  ]);
  expect(captured.body).toMatchObject({
    walletId: WALLET_ID,
    reservationId: 'reservation-1',
    recoveryOperationId: 'wallet-recovery-operation:wire-1',
    targetDeviceId: String(TARGET_DEVICE_ID),
    targetAuthorityId: 'wallet-authority:replacement',
    targetWalletAuthMethodId: 'wallet-auth-method:replacement',
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
