import { expect, test } from '@playwright/test';
import { handleWalletRecoveryRotate } from '../../packages/wallet-server/src/router/transport/fetch/routes/passkeyCustody';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/wallet-server/src/router/framework/routeDefinitions';
import { rotateWalletRecoverySet } from '../../packages/wallet/src/core/rpcClients/relayer/walletRecoveryRotate';
import { parseWalletRecoverySetRotationWireV1 } from '@shared/wallet-recovery/walletRecoveryEnvelopeSet';
import { parseWalletId } from '@shared/utils/domainIds';

/**
 * The rotation wire, both ends.
 *
 * `issuedAtMs` is what these tests protect. It re-arms the backup prompt, so
 * a rotation that does not carry it back leaves the client unable to tell
 * whether the user acknowledged the codes now on screen — and the user is
 * either nagged about codes they saved or never asked about codes they did
 * not.
 */

const routeDefinitions = createRouterApiRouteDefinitions();

function context(body: unknown, service: unknown) {
  return {
    routeDefinitions,
    method: 'POST',
    pathname: '/wallets/recovery/rotate',
    request: new Request('https://relay.localhost/wallets/recovery/rotate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    service,
    logger: { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} },
    opts: {},
  } as never;
}

function respondWith(status: number, body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })) as unknown as typeof fetch;
}

const WALLET_ID = 'alice.testnet';
const DIGEST_B64U = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA';
const NONCE_B64U = 'AQIDBAUGBwgJCgsM';
const CIPHERTEXT_B64U = 'BwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2';
const FACTOR_PROOF = {
  kind: 'email_otp',
  provider_subject_id: 'subject-1',
  challenge_id: 'challenge-1',
  otp_code: '123456',
  challenge_digest: 'digest-1',
} as const;

function replacement() {
  const walletId = parseWalletId(WALLET_ID);
  if (!walletId.ok) throw new Error(walletId.error.message);
  return parseWalletRecoverySetRotationWireV1(
    {
      walletId: WALLET_ID,
      manifestKekWraps: Array.from({ length: 10 }, (_, index) => ({
        recoveryKeyId: `wallet-rkid-v1-${String.fromCharCode(65 + index)}${DIGEST_B64U.slice(1)}`,
        nonceB64u: NONCE_B64U,
        ciphertextB64u: CIPHERTEXT_B64U,
        aadHashB64u: DIGEST_B64U,
      })),
      entries: [
        {
          custodySecretKind: 'wallet_custody_seed_v1',
          nonceB64u: NONCE_B64U,
          wrappedCustodySecretB64u: CIPHERTEXT_B64U,
          aadHashB64u: DIGEST_B64U,
        },
      ],
    },
    { expectedWalletId: walletId.value },
  );
}

function recoveryCodeLocators() {
  return replacement().manifestKekWraps.map((wrap, index) => ({
    locatorB64u: `${String.fromCharCode(75 + index)}${DIGEST_B64U.slice(1)}`,
    recoveryKeyId: wrap.recoveryKeyId,
  }));
}

const VALID_BODY = {
  walletId: WALLET_ID,
  expectedStoreVersion: '4',
  manifestKekWraps: replacement().manifestKekWraps,
  entries: [replacement().entry],
  recoveryCodeLocators: recoveryCodeLocators(),
  factorProof: FACTOR_PROOF,
};

test('the route is registered where the client posts', () => {
  const route = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_codes_rotate');
  expect(route?.path).toBe('/wallets/recovery/rotate');
});

test('the route requires locator rows before authorization', async () => {
  const response = await handleWalletRecoveryRotate(
    context({ ...VALID_BODY, recoveryCodeLocators: [] }, {}),
  );
  expect(response?.status).toBe(400);
  const body = await response!.json();
  expect(body.code).toBe('invalid_request');
});

test('the client refuses a rotation with no issuance timestamp', async () => {
  const result = await rotateWalletRecoverySet({
    relayUrl: 'https://relay.localhost',
    walletId: WALLET_ID,
    factorProof: FACTOR_PROOF,
    expectedStoreVersion: '4',
    replacement: replacement(),
    recoveryCodeLocators: recoveryCodeLocators(),
    fetchImpl: respondWith(200, { ok: true, storeVersion: '5' }),
  });
  // Reporting success would leave the caller unable to record which issuance
  // the user is about to acknowledge.
  expect(result.kind).toBe('transport_failed');
});

test('each server refusal keeps its own meaning', async () => {
  const missing = await rotateWalletRecoverySet({
    relayUrl: 'https://relay.localhost',
    walletId: WALLET_ID,
    factorProof: FACTOR_PROOF,
    expectedStoreVersion: '4',
    replacement: replacement(),
    recoveryCodeLocators: recoveryCodeLocators(),
    fetchImpl: respondWith(404, { ok: false, code: 'no_recovery_set' }),
  });
  const conflict = await rotateWalletRecoverySet({
    relayUrl: 'https://relay.localhost',
    walletId: WALLET_ID,
    factorProof: FACTOR_PROOF,
    expectedStoreVersion: '4',
    replacement: replacement(),
    recoveryCodeLocators: recoveryCodeLocators(),
    fetchImpl: respondWith(409, { ok: false, code: 'recovery_set_conflict' }),
  });
  const rejected = await rotateWalletRecoverySet({
    relayUrl: 'https://relay.localhost',
    walletId: WALLET_ID,
    factorProof: FACTOR_PROOF,
    expectedStoreVersion: '4',
    replacement: replacement(),
    recoveryCodeLocators: recoveryCodeLocators(),
    fetchImpl: respondWith(400, { ok: false, code: 'rotation_rejected' }),
  });

  // Retry helps the second and never the third; the first is not a failure of
  // the rotation at all.
  expect(missing.kind).toBe('no_recovery_set');
  expect(conflict.kind).toBe('conflict');
  expect(rejected.kind).toBe('rejected');
});

test('a rotation with no wraps never reaches the service', async () => {
  const response = await handleWalletRecoveryRotate(
    context(
      { walletId: WALLET_ID, expectedStoreVersion: '4', manifestKekWraps: [], entries: [] },
      {},
    ),
  );
  expect(response?.status).toBe(400);
});
