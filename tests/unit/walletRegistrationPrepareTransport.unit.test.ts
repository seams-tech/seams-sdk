import { expect, test } from '@playwright/test';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  registrationIntentGrantFromString,
  walletIdFromString,
  type RegistrationIntentV1,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { prepareWalletRegistration } from '@/core/rpcClients/relayer/walletRegistration';

const RELAYER_URL = 'https://relay.example.test';
const REGISTRATION_INTENT_DIGEST_B64U = 'registration-intent-digest';

const REGISTRATION_INTENT: RegistrationIntentV1 = {
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_transport_retry'),
  authMethod: { kind: 'passkey', rpId: parseWebAuthnRpId('localhost') },
  signerSelection: {
    kind: 'signer_set',
    signers: [
      {
        kind: 'near_ed25519',
        accountProvisioning: {
          kind: 'implicit_account',
          accountIdSource: 'ed25519_public_key',
        },
        signerSlot: 1,
        participantIds: [1, 2],
        derivationVersion: 1,
      },
    ],
  },
  nonceB64u: 'nonce',
};

const PREPARE_RESPONSE = {
  ok: true,
  state: 'prepared',
  registrationPreparationId: 'wrp_transport_retry',
  expiresAtMs: 1_900_000_000_000,
  ed25519: {
    ceremonyHandle: 'ceremony-handle',
    preparedSession: {},
    clientOtOfferMessageB64u: 'client-ot-offer',
  },
};

function jsonResponse(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: init?.status || 200,
    headers: {
      'content-type': 'application/json',
      ...(init?.headers || {}),
    },
  });
}

function textResponse(body: string, init: ResponseInit): Response {
  return new Response(body, init);
}

async function callPrepareWalletRegistration(): Promise<void> {
  await prepareWalletRegistration({
    relayerUrl: RELAYER_URL,
    registrationIntentGrant: registrationIntentGrantFromString('rig_transport_retry'),
    registrationIntentDigestB64u: REGISTRATION_INTENT_DIGEST_B64U,
    intent: REGISTRATION_INTENT,
    work: { kind: 'ed25519_hss' },
    kind: 'passkey',
    webauthnRegistration: { id: 'credential-id' },
  });
}

test('retries registration prepare once when Wrangler restarts the worker mid-request', async () => {
  const originalFetch = globalThis.fetch;
  const calls: string[] = [];
  globalThis.fetch = async (input: RequestInfo | URL) => {
    calls.push(String(input));
    if (calls.length === 1) {
      return textResponse(
        'Your worker restarted mid-request. Please try sending the request again. Only GET or HEAD requests are retried automatically.',
        { status: 503 },
      );
    }
    return jsonResponse(PREPARE_RESPONSE);
  };
  try {
    await callPrepareWalletRegistration();
  } finally {
    globalThis.fetch = originalFetch;
  }

  expect(calls).toEqual([
    `${RELAYER_URL}/wallets/register/prepare`,
    `${RELAYER_URL}/wallets/register/prepare`,
  ]);
});

test('does not retry other registration prepare failures', async () => {
  const originalFetch = globalThis.fetch;
  let callCount = 0;
  globalThis.fetch = async () => {
    callCount += 1;
    return jsonResponse({ ok: false, code: 'invalid_body', message: 'bad request' }, { status: 400 });
  };
  try {
    await expect(callPrepareWalletRegistration()).rejects.toThrow('bad request');
  } finally {
    globalThis.fetch = originalFetch;
  }

  expect(callCount).toBe(1);
});
