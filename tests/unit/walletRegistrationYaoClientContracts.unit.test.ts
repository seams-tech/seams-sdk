import { expect, test } from '@playwright/test';
import {
  completeWalletRegistrationNearProvisioning,
  parseWalletAddSignerFinalizeResponse,
  parseWalletAddSignerStartResponse,
} from '../../packages/sdk-web/src/core/rpcClients/relayer/walletRegistration';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';

const SESSION_ID = new Array<number>(32).fill(19);

test('deferred NEAR completion sends only the opaque one-use activation reference', async () => {
  /* The activation reference is the whole of the client's claim on the
     deferred Yao result; nothing about the key or the session may ride
     alongside it. The finalize route this once covered is gone, but the
     invariant moved with the payload to route 4. */
  let sentBody: unknown = null;
  const original = globalThis.fetch;
  globalThis.fetch = (async (_input: unknown, init?: { body?: string }) => {
    sentBody = JSON.parse(String(init?.body ?? '{}'));
    return new Response(JSON.stringify({ ok: false, code: 'stub', message: 'stub' }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  }) as typeof fetch;
  try {
    /* `postJson` throws on a non-ok body, so the stub's rejection is expected;
       only the request this sent is under test. */
    await completeWalletRegistrationNearProvisioning({
      relayerUrl: 'http://127.0.0.1:8787',
      registrationCeremonyId: 'registration-42',
      signedSetup: 'signed-setup-42',
      idempotencyKey: 'registration-near-provisioning-42',
      ed25519: {
        activationReference: {
          kind: 'router_ab_ed25519_yao_activation_reference_v1',
          lifecycle_id: 'registration-42',
          session_id: SESSION_ID,
        },
      },
      auth: { kind: 'passkey' },
    }).catch(() => undefined);
  } finally {
    globalThis.fetch = original;
  }
  expect(sentBody).toEqual({
    registrationCeremonyId: 'registration-42',
    signedSetup: 'signed-setup-42',
    idempotencyKey: 'registration-near-provisioning-42',
    ed25519: {
      activationReference: {
        kind: 'router_ab_ed25519_yao_activation_reference_v1',
        lifecycle_id: 'registration-42',
        session_id: SESSION_ID,
      },
    },
  });
});

test('add-signer start parser rejects a branch substituted by the relayer', () => {
  const walletId = walletIdFromString('wallet-parser-substitution');
  const expectedIntent = {
    version: 'add_signer_intent_v1' as const,
    walletId,
    signerSelection: {
      mode: 'ed25519' as const,
      ed25519: {
        mode: 'create_implicit_near_account' as const,
        signerSlot: 2,
        participantIds: [1, 2],
        keyPurpose: 'signing',
        keyVersion: 'router-ab-ed25519-yao-v1',
        derivationVersion: 1,
      },
    },
    nonceB64u: 'add-signer-parser-nonce',
  };
  expect(() =>
    parseWalletAddSignerStartResponse({
      expectedIntent,
      value: {
        ok: true,
        addSignerCeremonyId: 'add-signer-parser-ceremony',
        intent: expectedIntent,
        authorizationKind: 'app_session',
        kind: 'evm_family_ecdsa',
        ecdsa: { kind: 'evm_family_ecdsa_keygen', targets: [] },
      },
    }),
  ).toThrow('substituted signer branch');
});

test('add-signer finalize parser rejects malformed and extra response fields', () => {
  expect(() =>
    parseWalletAddSignerFinalizeResponse({
      expectedKind: 'near_ed25519',
      value: {
        ok: true,
        walletId: 'wallet-parser-malformed',
        kind: 'near_ed25519',
        rpId: 'wallet.example.test',
        credentialIdB64u: 'credential-parser',
        ed25519: {},
        serverMaterial: 'forbidden',
      },
    }),
  ).toThrow('unexpected serverMaterial');
});
