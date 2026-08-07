import { expect, test } from '@playwright/test';
import {
  runWalletCustodyRegistrationCeremony,
  type WalletCustodyCeremonyRouterResponse,
  type WalletCustodyCeremonyStepRunner,
} from '../../packages/sdk-web/src/core/signingEngine/walletCustody/ceremonyDriver';

/**
 * The driver's job is ordering and cleanup. These own the property that is
 * easy to lose at a call site: a ceremony holds a seed in the worker until it
 * seals, so every exit that is not a completed seal must discard it — including
 * the one where the caller's own Router round-trip throws.
 */

const CEREMONY_ID = 'ceremony-1';

const BEGUN = {
  ceremonyId: CEREMONY_ID,
  yaoExecuteRequestJson: '{"yao":"execute"}',
  ecdsaContextBinding32B64u: 'context-binding',
  ecdsaClientSharePublicKey33B64u: 'client-share-key',
};

const SEALED = {
  walletId: 'alice.testnet',
  envelopeId: 'envelope-1',
  keyManifestDigestB64u: 'digest',
  envelopeBindingJson: '{}',
  envelopeNonceB64u: 'nonce',
  sealedCustodySecretB64u: 'ciphertext',
  envelopeAadHashB64u: 'aad',
  envelopeCiphertextDigestB64u: 'ciphertext-digest',
  recoveryManifestKekWraps: [],
  recoveryEntryNonceB64u: 'nonce',
  recoveryEntryCiphertextB64u: 'ciphertext',
  recoveryEntryAadHashB64u: 'aad',
  registeredPublicKeyB64u: 'registered',
  clientRootPublicKey33B64u: 'client-root',
  ecdsaReadyStateBlobB64u: 'ready-blob',
};

const ROUTER_RESPONSE: WalletCustodyCeremonyRouterResponse = {
  yaoResultJson: '{"yao":"result"}',
  relayerPublicIdentityJson: '{"relayerKeyId":"relayer-1"}',
  identitiesJson: '{"nearEd25519SigningKeyId":"key-1"}',
};

type Call = { type: string; payload: Record<string, unknown> };

function recordingRunner(overrides: Partial<Record<string, unknown>> = {}): {
  runStep: WalletCustodyCeremonyStepRunner;
  calls: Call[];
} {
  const calls: Call[] = [];
  const runStep = (async (type: string, payload: Record<string, unknown>) => {
    calls.push({ type, payload });
    if (type in overrides) {
      const override = overrides[type];
      if (override instanceof Error) throw override;
      return override;
    }
    switch (type) {
      case 'beginWalletCustodyRegistration':
        return BEGUN;
      case 'completeWalletCustodyRegistration':
        return { ceremonyId: CEREMONY_ID };
      case 'sealWalletCustodyRegistration':
        return SEALED;
      case 'discardWalletCustodyCeremony':
        return { ceremonyId: CEREMONY_ID, discarded: true };
      default:
        throw new Error(`unexpected step ${type}`);
    }
  }) as unknown as WalletCustodyCeremonyStepRunner;
  return { runStep, calls };
}

function input(
  runStep: WalletCustodyCeremonyStepRunner,
  runRouterRound: WalletCustodyRegistrationInput['runRouterRound'],
) {
  return {
    runStep,
    walletId: 'alice.testnet',
    protocolInputsJson: '{"clientParticipantId":1}',
    runRouterRound,
    factorJson: '{"envelopeId":"envelope-1"}',
    factorSecret: new ArrayBuffer(32),
    recoveryCodesJson: '[]',
    ceremonyId: CEREMONY_ID,
  };
}

type WalletCustodyRegistrationInput = Parameters<typeof runWalletCustodyRegistrationCeremony>[0];

test('a ceremony runs begin, the Router round, complete, then seal', async () => {
  const { runStep, calls } = recordingRunner();
  let sawRequest: unknown = null;

  const payload = await runWalletCustodyRegistrationCeremony(
    input(runStep, async (request) => {
      sawRequest = request;
      return ROUTER_RESPONSE;
    }),
  );

  expect(payload).toEqual(SEALED);
  expect(calls.map((call) => call.type)).toEqual([
    'beginWalletCustodyRegistration',
    'completeWalletCustodyRegistration',
    'sealWalletCustodyRegistration',
  ]);
  // A completed ceremony is not discarded: the seal already consumed it.
  expect(calls.some((call) => call.type === 'discardWalletCustodyCeremony')).toBe(false);

  // The Router round sees only the public protocol messages.
  expect(sawRequest).toEqual({
    yaoExecuteRequestJson: BEGUN.yaoExecuteRequestJson,
    ecdsaContextBinding32B64u: BEGUN.ecdsaContextBinding32B64u,
    ecdsaClientSharePublicKey33B64u: BEGUN.ecdsaClientSharePublicKey33B64u,
  });
  // Every step addresses the same ceremony.
  for (const call of calls) expect(call.payload.ceremonyId).toBe(CEREMONY_ID);
});

test('a failed Router round discards the ceremony and rethrows', async () => {
  const { runStep, calls } = recordingRunner();
  const relayerDown = new Error('relayer unavailable');

  await expect(
    runWalletCustodyRegistrationCeremony(
      input(runStep, async () => {
        throw relayerDown;
      }),
    ),
  ).rejects.toThrow('relayer unavailable');

  // This is the case the driver exists for: the worker never saw a failure, so
  // nothing there would have dropped the seed.
  expect(calls.map((call) => call.type)).toEqual([
    'beginWalletCustodyRegistration',
    'discardWalletCustodyCeremony',
  ]);
});

test('a failed step discards the ceremony and surfaces the original error', async () => {
  for (const failing of ['completeWalletCustodyRegistration', 'sealWalletCustodyRegistration']) {
    const { runStep, calls } = recordingRunner({ [failing]: new Error(`${failing} failed`) });

    await expect(
      runWalletCustodyRegistrationCeremony(input(runStep, async () => ROUTER_RESPONSE)),
    ).rejects.toThrow(`${failing} failed`);

    expect(calls.at(-1)?.type).toBe('discardWalletCustodyCeremony');
  }
});

test('a discard that itself fails does not mask the original error', async () => {
  const { runStep } = recordingRunner({
    sealWalletCustodyRegistration: new Error('seal rejected the recovery set'),
    discardWalletCustodyCeremony: new Error('worker is gone'),
  });

  // The caller must learn why the ceremony failed, not why cleanup failed.
  await expect(
    runWalletCustodyRegistrationCeremony(input(runStep, async () => ROUTER_RESPONSE)),
  ).rejects.toThrow('seal rejected the recovery set');
});

test('a failed begin needs no discard', async () => {
  const { runStep, calls } = recordingRunner({
    beginWalletCustodyRegistration: new Error('protocol inputs rejected'),
  });

  await expect(
    runWalletCustodyRegistrationCeremony(input(runStep, async () => ROUTER_RESPONSE)),
  ).rejects.toThrow('protocol inputs rejected');

  // Nothing was ever stored under this id, and the worker dropped the seed with
  // the failed transition.
  expect(calls.map((call) => call.type)).toEqual(['beginWalletCustodyRegistration']);
});

test('each ceremony gets its own id when none is supplied', async () => {
  const seen = new Set<string>();
  for (let index = 0; index < 3; index += 1) {
    const { runStep, calls } = recordingRunner();
    await runWalletCustodyRegistrationCeremony({
      ...input(runStep, async () => ROUTER_RESPONSE),
      ceremonyId: undefined,
    });
    seen.add(String(calls[0]?.payload.ceremonyId));
  }
  expect(seen.size).toBe(3);
});
