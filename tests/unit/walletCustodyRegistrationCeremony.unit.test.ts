import { expect, test } from '@playwright/test';
import {
  computeWalletCustodyEvmFamilyKeyManifestDigestB64u,
  establishNearEd25519CustodyV1,
  joinCustodyJsonFromEstablishedCommitPayload,
  joinNearEd25519CustodyV1,
  rejoinNearEd25519CustodyV1,
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

test('the EVM custody manifest digest matches the Rust canonical vector', async () => {
  await expect(
    computeWalletCustodyEvmFamilyKeyManifestDigestB64u({
      walletId: 'wallet-1',
      evmFamilySigningKeySlotId: 'evm-slot-1',
      clientRootPublicKey33B64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    }),
  ).resolves.toBe('oYYQddIgFfu_BhG0YNzHJe4k_M3g2PPx1h0DL31R7K4');
});

type Step = { type: string; payload: Record<string, unknown> };

function recordingRunner(steps: Step[]) {
  return (async (type: string, payload: Record<string, unknown>) => {
    steps.push({ type, payload });
    switch (type) {
      case 'beginWalletCustodyKeySetRun':
        return {
          ceremonyId: String(payload.ceremonyId),
          keySet: 'near_ed25519_v1',
          yaoExecuteRequestJson: '{"execute":"request"}',
        };
      case 'completeWalletCustodyKeySetRun':
        return { ceremonyId: String(payload.ceremonyId), keySet: 'near_ed25519_v1' };
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
        return {
          ceremonyId: String(payload.ceremonyId),
          keySet: 'near_ed25519_v1',
          yaoExecuteRequestJson: '{"execute":"request"}',
        };
      }
      if (type === 'finishWalletCustodyKeySetRun') return withCache;
      if (type === 'completeWalletCustodyKeySetRun') {
        return { ceremonyId: String(payload.ceremonyId), keySet: 'near_ed25519_v1' };
      }
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

test('a mixed-wallet NEAR key set joins the EVM-established envelope', async () => {
  const steps: Step[] = [];
  const { walletId: _walletId, factorJson: _factorJson, ...base } = establishArgs(steps);
  const joined = await joinNearEd25519CustodyV1({
    ...base,
    runStep: rejoinArgs(steps).runStep,
    custodyJson: joinCustodyJsonFromEstablishedCommitPayload(
      buildWalletCustodyCommitPayloadFixture({
        walletId: WALLET_ID,
        keySet: 'evm_family_ecdsa_v1',
      }),
    ),
  });

  const begun = steps.find((step) => step.type === 'beginWalletCustodyKeySetRun');
  expect((begun?.payload.custody as { origin: string }).origin).toBe('join');
  const inputs = JSON.parse(String(begun?.payload.protocolInputsJson)) as Record<string, unknown>;
  expect(inputs.continuityRegisteredPublicKeyB64u).toBeUndefined();
  expect(joined.commitPayload.establishedCustody).toBeUndefined();
});

test('the established-envelope projection emits the exact join wire', () => {
  const payload = buildWalletCustodyCommitPayloadFixture({
    walletId: WALLET_ID,
    keySet: 'evm_family_ecdsa_v1',
  });
  const wire = JSON.parse(joinCustodyJsonFromEstablishedCommitPayload(payload)) as Record<
    string,
    unknown
  >;

  expect(Object.keys(wire).sort()).toEqual([
    'aadHashB64u',
    'ciphertextDigestB64u',
    'envelopeBinding',
    'nonceB64u',
    'sealedCustodySecretB64u',
  ]);
});

/**
 * Synced-passkey cold unlock: a browser with empty IndexedDB reproduces the
 * wallet's key set from the server-held envelope and the same credential.
 *
 * The guarantees are all negatives — no new credential, no new envelope, no
 * recovery code consumed — so these check what the run does *not* do as much
 * as what it returns.
 */
function rejoinArgs(steps: Step[], overrides: Record<string, unknown> = {}) {
  const { runStep: _runStep, factorJson: _factorJson, ...rest } = establishArgs(steps);
  return {
    ...rest,
    runStep: (async (type: string, payload: Record<string, unknown>) => {
      steps.push({ type, payload });
      if (type === 'beginWalletCustodyKeySetRun') {
        return {
          ceremonyId: String(payload.ceremonyId),
          keySet: 'near_ed25519_v1',
          yaoExecuteRequestJson: '{"execute":"request"}',
        };
      }
      if (type === 'finishWalletCustodyKeySetRun') {
        return {
          walletId: WALLET_ID,
          keySet: 'near_ed25519_v1',
          keyManifestDigestB64u: 'ZGlnZXN0',
          registeredPublicKeyB64u: 'cHVibGlj',
          ed25519LocalMaterialB64u: 'bWF0ZXJpYWw',
          ed25519LocalMaterialNonceB64u: 'AQIDBAUGBwgJCgsM',
          ed25519ApplicationBindingDigestB64u: 'YmluZGluZw',
        };
      }
      if (type === 'completeWalletCustodyKeySetRun') {
        return { ceremonyId: String(payload.ceremonyId), keySet: 'near_ed25519_v1' };
      }
      return {};
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    }) as any,
    custodyJson: JSON.stringify({ envelopeBinding: {}, nonceB64u: 'AQIDBAUGBwgJCgsM' }),
    registeredPublicKeyB64u: 'cHVibGlj',
    ...overrides,
  };
}

test('a cold unlock joins existing custody and seals no envelope', async () => {
  const steps: Step[] = [];
  const rejoined = await rejoinNearEd25519CustodyV1(rejoinArgs(steps));

  const begun = steps.find((step) => step.type === 'beginWalletCustodyKeySetRun');
  expect((begun?.payload.custody as { origin: string }).origin).toBe('join');

  // `finish` is called with nothing to establish — the ceremony refuses to
  // combine that with a joining origin, which is what makes "no second
  // envelope, no new codes" structural rather than a promise.
  const finished = steps.find((step) => step.type === 'finishWalletCustodyKeySetRun');
  expect(finished?.payload.establishWith).toBeUndefined();
  expect(rejoined.commitPayload.establishedCustody).toBeUndefined();
});

test('a cold unlock reproduces the registered key rather than establishing one', async () => {
  const steps: Step[] = [];
  await rejoinNearEd25519CustodyV1(rejoinArgs(steps));

  const begun = steps.find((step) => step.type === 'beginWalletCustodyKeySetRun');
  const inputs = JSON.parse(String(begun?.payload.protocolInputsJson)) as Record<string, unknown>;
  // Present means reproduce; absent would register a second, different key for
  // a wallet that already has one.
  expect(inputs.continuityRegisteredPublicKeyB64u).toBe('cHVibGlj');
});

test('a cold unlock without the key it reproduces is refused before any step runs', async () => {
  const steps: Step[] = [];
  await expect(
    rejoinNearEd25519CustodyV1(rejoinArgs(steps, { registeredPublicKeyB64u: '  ' })),
  ).rejects.toThrow(/must name the key set/);
  expect(steps).toHaveLength(0);
});

test('a cold unlock that somehow established custody is refused', async () => {
  /* Unreachable through the ceremony, which refuses to seal on a joining run.
     Checked anyway: a second envelope and a second recovery set for one wallet
     is the failure this design exists to prevent. */
  const steps: Step[] = [];
  await expect(
    rejoinNearEd25519CustodyV1({
      ...rejoinArgs(steps),
      runStep: (async (type: string, payload: Record<string, unknown>) => {
        if (type === 'beginWalletCustodyKeySetRun') {
          return {
            ceremonyId: String(payload.ceremonyId),
            keySet: 'near_ed25519_v1',
            yaoExecuteRequestJson: '{"execute":"request"}',
          };
        }
        if (type === 'finishWalletCustodyKeySetRun') {
          return {
            ...buildWalletCustodyCommitPayloadFixture({
              walletId: WALLET_ID,
              keySet: 'near_ed25519_v1',
            }),
            ed25519LocalMaterialB64u: 'bWF0ZXJpYWw',
            ed25519LocalMaterialNonceB64u: 'AQIDBAUGBwgJCgsM',
            ed25519ApplicationBindingDigestB64u: 'YmluZGluZw',
          };
        }
        if (type === 'completeWalletCustodyKeySetRun') {
          return { ceremonyId: String(payload.ceremonyId), keySet: 'near_ed25519_v1' };
        }
        return {};
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      }) as any,
    }),
  ).rejects.toThrow(/must not establish custody/);
});
