import { expect, test } from '@playwright/test';
import {
  buildWalletRegistrationFinalizeBody,
  parseWalletAddSignerFinalizeResponse,
  parseWalletAddSignerStartResponse,
} from '../../packages/sdk-web/src/core/rpcClients/relayer/walletRegistration';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';

const SESSION_ID = new Array<number>(32).fill(19);

test('builds Ed25519 finalize with only the opaque one-use activation reference', () => {
  expect(
    buildWalletRegistrationFinalizeBody({
      relayerUrl: 'http://127.0.0.1:8787',
      registrationCeremonyId: 'registration-42',
      kind: 'near_ed25519',
      ed25519: {
        activationReference: {
          kind: 'router_ab_ed25519_yao_activation_reference_v1',
          lifecycle_id: 'registration-42',
          session_id: SESSION_ID,
        },
      },
    }),
  ).toEqual({
    registrationCeremonyId: 'registration-42',
    kind: 'near_ed25519',
    ed25519: {
      activationReference: {
        kind: 'router_ab_ed25519_yao_activation_reference_v1',
        lifecycle_id: 'registration-42',
        session_id: SESSION_ID,
      },
    },
  });
});

test('builds mixed finalize only through its coherent mixed variant', () => {
  expect(
    buildWalletRegistrationFinalizeBody({
      relayerUrl: 'http://127.0.0.1:8787',
      registrationCeremonyId: 'registration-42',
      kind: 'near_ed25519_and_evm_family_ecdsa',
      ed25519: {
        activationReference: {
          kind: 'router_ab_ed25519_yao_activation_reference_v1',
          lifecycle_id: 'registration-42',
          session_id: SESSION_ID,
        },
      },
      ecdsa: { expectedKeyHandles: ['ecdsa-key-1'] },
    }),
  ).toMatchObject({
    kind: 'near_ed25519_and_evm_family_ecdsa',
    ed25519: { activationReference: { lifecycle_id: 'registration-42' } },
    ecdsa: { expectedKeyHandles: ['ecdsa-key-1'] },
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
