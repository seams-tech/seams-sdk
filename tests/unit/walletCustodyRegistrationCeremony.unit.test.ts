import { expect, test } from '@playwright/test';
import {
  establishNearEd25519CustodyV1,
  walletCustodyCommitPayloadForWire,
} from '../../packages/sdk-web/src/core/signingEngine/walletCustody/registrationCeremony';
import { base64UrlDecode } from '../../packages/shared-ts/src/utils/encoders';
import { normalizeWalletRecoveryCode } from '../../packages/shared-ts/src/wallet-recovery/recoveryCodes';
import { buildWalletCustodyCommitPayloadFixture } from './helpers/passkeyCustodyEnvelope.fixtures';

/**
 * Establishing one NEAR key set from the custody seed.
 *
 * Two properties this owns, both of which fail silently if wrong: the recovery
 * codes reach the caller (the wraps are one-way, so codes that are not shown
 * are codes nobody can ever produce), and the client's signing material never
 * reaches the payload that goes on the wire.
 */

const WALLET_ID = 'alice.testnet';

type Step = { type: string; payload: Record<string, unknown> };

function recordingRunner(steps: Step[]) {
  return (async (type: string, payload: Record<string, unknown>) => {
    steps.push({ type, payload });
    switch (type) {
      case 'beginWalletCustodyKeySetRun':
        return { yaoExecuteRequestJson: '{"execute":"request"}' };
      case 'completeWalletCustodyKeySetRun':
        return {};
      case 'finishWalletCustodyKeySetRun':
        return buildWalletCustodyCommitPayloadFixture({
          walletId: WALLET_ID,
          keySet: 'near_ed25519_v1',
        });
      default:
        return {};
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  }) as any;
}

function establishArgs(steps: Step[]) {
  return {
    runStep: recordingRunner(steps),
    walletId: WALLET_ID,
    factorJson: JSON.stringify({ kind: 'passkey' }),
    factorSecret: new ArrayBuffer(32),
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    registrationCeremonyId: 'wrc_test',
    yaoAdmission: { admission: true },
    yaoApplication: { application: true },
    participantIds: [1, 2] as const,
    runRouterRound: async () => JSON.stringify({ binding: { session_id: [1, 2, 3, 4] } }),
  };
}

test('ten recovery codes are issued and returned to be shown', async () => {
  const steps: Step[] = [];
  const established = await establishNearEd25519CustodyV1(establishArgs(steps));

  expect(established.recoveryCodes).toHaveLength(10);
  // Distinct, and each a real code the user can type back.
  expect(new Set(established.recoveryCodes).size).toBe(10);
  for (const code of established.recoveryCodes) {
    expect(normalizeWalletRecoveryCode(code)).toHaveLength(32);
  }
});

test('the ceremony receives code bytes and no ids', async () => {
  /* The id is derived where the wrap is sealed. A caller that supplied one
     could point two codes at one wrap, or name a wrap no code opens. */
  const steps: Step[] = [];
  await establishNearEd25519CustodyV1(establishArgs(steps));

  const begun = steps.find((step) => step.type === 'finishWalletCustodyKeySetRun');
  const establishWith = begun?.payload.establishWith as { recoveryCodesJson: string };
  const codes = JSON.parse(establishWith.recoveryCodesJson) as Record<string, unknown>[];

  expect(codes).toHaveLength(10);
  for (const code of codes) {
    expect(Object.keys(code)).toEqual(['codeBytesB64u']);
    expect(base64UrlDecode(String(code.codeBytesB64u))).toHaveLength(20);
  }
});

test('the wire payload carries no client signing material', async () => {
  const steps: Step[] = [];
  const established = await establishNearEd25519CustodyV1(establishArgs(steps));

  const keys = Object.keys(established.commitPayload);
  expect(keys).not.toContain('ed25519LocalMaterialB64u');
  expect(keys).not.toContain('ed25519LocalMaterialNonceB64u');
  expect(keys).not.toContain('ecdsaReadyStateBlobB64u');
  // What the commit actually needs still crosses.
  expect(established.commitPayload.walletId).toBe(WALLET_ID);
  expect(established.commitPayload.keySet).toBe('near_ed25519_v1');
  expect(established.commitPayload.establishedCustody).toBeTruthy();
});

test('the continuity cache is returned separately, not on the payload', async () => {
  /* Separate by type rather than by a caller remembering to strip it: the
     cache re-opens signing material, so "send the payload" must not be able to
     send it by accident. */
  const steps: Step[] = [];
  const fixture = buildWalletCustodyCommitPayloadFixture({
    walletId: WALLET_ID,
    keySet: 'near_ed25519_v1',
  });
  const withCache = {
    ...fixture,
    ed25519LocalMaterialB64u: 'bWF0ZXJpYWw',
    ed25519LocalMaterialNonceB64u: 'AQIDBAUGBwgJCgsM',
    ed25519ApplicationBindingDigestB64u: 'ZGlnZXN0',
  };
  const args = establishArgs(steps);
  const established = await establishNearEd25519CustodyV1({
    ...args,
    runStep: (async (type: string, payload: Record<string, unknown>) => {
      steps.push({ type, payload });
      if (type === 'beginWalletCustodyKeySetRun') {
        return { yaoExecuteRequestJson: '{"execute":"request"}' };
      }
      if (type === 'finishWalletCustodyKeySetRun') return withCache;
      return {};
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any,
  });

  expect(established.localMaterial).toEqual({
    b64u: 'bWF0ZXJpYWw',
    nonceB64u: 'AQIDBAUGBwgJCgsM',
    applicationBindingDigestB64u: 'ZGlnZXN0',
  });
  const keys = Object.keys(established.commitPayload);
  expect(keys).not.toContain('ed25519LocalMaterialB64u');
  // The digest is a field of the seal binding, so it stays client-side too.
  expect(keys).not.toContain('ed25519ApplicationBindingDigestB64u');
});

test('the projection drops material from any payload, including an EVM run', async () => {
  const projected = walletCustodyCommitPayloadForWire({
    ...buildWalletCustodyCommitPayloadFixture({ walletId: WALLET_ID }),
    ed25519LocalMaterialB64u: 'bWF0ZXJpYWw',
    ed25519LocalMaterialNonceB64u: 'AQIDBAUGBwgJCgsM',
  });

  const keys = Object.keys(projected);
  expect(keys).not.toContain('ecdsaReadyStateBlobB64u');
  expect(keys).not.toContain('ed25519LocalMaterialB64u');
  expect(keys).not.toContain('ed25519LocalMaterialNonceB64u');
  expect(projected.keyManifestDigestB64u).toBeTruthy();
});

test('the activation reference comes from the round this run performed', async () => {
  /* Route 4 claims the Yao result with this reference. The ceremony consumes
     the Router's result and returns only public facts, so if the run did not
     carry the session id out, the deferred leg would have nothing to present.
     It is parsed from the result rather than accepted as an argument, so it
     cannot name another ceremony's activation for the leg to burn. */
  const steps: Step[] = [];
  const established = await establishNearEd25519CustodyV1(establishArgs(steps));

  expect(established.activationReference).toEqual({
    kind: 'router_ab_ed25519_yao_activation_reference_v1',
    lifecycle_id: 'wrc_test',
    session_id: [1, 2, 3, 4],
  });
});

test('a Router result with no session id fails the run', async () => {
  const steps: Step[] = [];
  await expect(
    establishNearEd25519CustodyV1({
      ...establishArgs(steps),
      runRouterRound: async () => '{"binding":{}}',
    }),
  ).rejects.toThrow(/session id/);
});
