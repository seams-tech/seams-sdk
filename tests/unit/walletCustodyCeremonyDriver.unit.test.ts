import { expect, test } from '@playwright/test';
import {
  runWalletCustodyKeySetCeremony,
  type WalletCustodyCeremonyCustodyInput,
  type WalletCustodyCeremonyKeySetInput,
  type WalletCustodyCeremonyStepRunner,
} from '../../packages/sdk-web/src/core/signingEngine/walletCustody/ceremonyDriver';
import { buildRecoveredPasskeyCustodyEnvelopeRecord } from '../../packages/sdk-web/src/core/signingEngine/walletCustody/recoveryReplacementEnvelope';

/**
 * The driver's job is ordering, key-set dispatch, and cleanup.
 *
 * These own the properties that are easy to lose at a call site: a run holds a
 * seed in the worker until it finishes, so every exit that is not a completed
 * finish must discard it — including the one where the caller's own protocol
 * round-trip throws. And a joining run must never seal, which is why the
 * establish/join choice is a union rather than an optional field.
 */

const CEREMONY_ID = 'ceremony-1';
const WALLET_ID = 'alice.testnet';

const BEGUN_NEAR = {
  ceremonyId: CEREMONY_ID,
  keySet: 'near_ed25519_v1',
  yaoExecuteRequestJson: '{"yao":"execute"}',
};

const EVM_PREACTIVATION_PAYLOAD = {
  walletId: WALLET_ID,
  keySet: 'evm_family_ecdsa_v1',
  keyManifestDigestB64u: 'other-digest',
  clientRootPublicKey33B64u: 'client-root',
};

const BEGUN_EVM = {
  ceremonyId: CEREMONY_ID,
  keySet: 'evm_family_ecdsa_v1',
  ecdsaContextBinding32B64u: 'context-binding',
  ecdsaClientSharePublicKey33B64u: 'client-share-key',
  preActivationCommitPayload: EVM_PREACTIVATION_PAYLOAD,
};

const ESTABLISHED_PAYLOAD = {
  walletId: WALLET_ID,
  keySet: 'near_ed25519_v1',
  keyManifestDigestB64u: 'digest',
  registeredPublicKeyB64u: 'registered',
  establishedCustody: {
    envelopeId: 'envelope-1',
    envelopeBindingJson: '{}',
    envelopeNonceB64u: 'nonce',
    sealedCustodySecretB64u: 'ciphertext',
    envelopeAadHashB64u: 'aad',
    envelopeCiphertextDigestB64u: 'ciphertext-digest',
    recoveryManifestKekWraps: [],
    recoveryEntryNonceB64u: 'nonce',
    recoveryEntryCiphertextB64u: 'ciphertext',
    recoveryEntryAadHashB64u: 'aad',
  },
};

const JOINED_PAYLOAD = {
  ...EVM_PREACTIVATION_PAYLOAD,
  ecdsaReadyStateBlobB64u: 'ready-blob',
  ecdsaPublicFacts: {
    contextBinding32B64u: 'context-binding',
    derivationClientSharePublicKey33B64u: 'client-share-key',
    clientVerifyingShare33B64u: 'client-verifying-share',
    relayerPublicKey33B64u: 'relayer-public-key',
    groupPublicKey33B64u: 'group-public-key',
    ethereumAddress: '0x0000000000000000000000000000000000000001',
    clientShareRetryCounter: 0,
    relayerShareRetryCounter: 0,
  },
};

const EVM_COMPLETION = {
  ceremonyId: CEREMONY_ID,
  keySet: 'evm_family_ecdsa_v1',
  activation: {
    walletId: WALLET_ID,
    keyManifestDigestB64u: 'other-digest',
    clientRootPublicKey33B64u: 'client-root',
    ecdsaReadyStateBlobB64u: JOINED_PAYLOAD.ecdsaReadyStateBlobB64u,
    ecdsaPublicFacts: JOINED_PAYLOAD.ecdsaPublicFacts,
  },
};

type Call = { type: string; payload: Record<string, unknown> };

function recordingRunner(
  overrides: Partial<Record<string, unknown>> = {},
  begun: Record<string, unknown> = BEGUN_NEAR,
  finished: Record<string, unknown> = ESTABLISHED_PAYLOAD,
): { runStep: WalletCustodyCeremonyStepRunner; calls: Call[] } {
  const calls: Call[] = [];
  const runStep = (async (type: string, payload: Record<string, unknown>) => {
    calls.push({ type, payload });
    if (type in overrides) {
      const override = overrides[type];
      if (override instanceof Error) throw override;
      return override;
    }
    switch (type) {
      case 'beginWalletCustodyKeySetRun':
        return begun;
      case 'completeWalletCustodyKeySetRun':
        return begun.keySet === 'evm_family_ecdsa_v1'
          ? EVM_COMPLETION
          : { ceremonyId: CEREMONY_ID, keySet: 'near_ed25519_v1' };
      case 'finishWalletCustodyKeySetRun':
        return finished;
      case 'discardWalletCustodyCeremony':
        return { ceremonyId: CEREMONY_ID, discarded: true };
      default:
        throw new Error(`unexpected step ${type}`);
    }
  }) as unknown as WalletCustodyCeremonyStepRunner;
  return { runStep, calls };
}

function establishingCustody(): WalletCustodyCeremonyCustodyInput {
  return {
    origin: 'establish',
    walletId: WALLET_ID,
    factorJson: '{"envelopeId":"envelope-1"}',
    factorSecret: new ArrayBuffer(32),
    recoveryCodesJson: '[]',
  };
}

function joiningCustody(): WalletCustodyCeremonyCustodyInput {
  return {
    origin: 'join',
    custodyJson: '{"nonceB64u":"nonce"}',
    factorSecret: new ArrayBuffer(32),
  };
}

function recoveringAndResealingCustody(): WalletCustodyCeremonyCustodyInput {
  return {
    origin: 'recover_and_reseal',
    custodyJson: '{"walletId":"alice.testnet"}',
    recoveryCode: new ArrayBuffer(20),
    replacementFactorJson: '{"envelopeId":"replacement-envelope-1"}',
    replacementFactorSecret: new ArrayBuffer(32),
  };
}

function nearRun(
  runRouterRound: (request: string) => Promise<string>,
  afterRouterRoundCompleted?: (result: string) => Promise<void>,
): WalletCustodyCeremonyKeySetInput {
  return {
    keySet: 'near_ed25519_v1',
    protocolInputsJson: '{"clientParticipantId":1}',
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    runRouterRound,
    ...(afterRouterRoundCompleted ? { afterRouterRoundCompleted } : {}),
  };
}

function evmRun(
  runRelayerRound: (bootstrap: {
    contextBinding32B64u: string;
    clientSharePublicKey33B64u: string;
    preActivationCommitPayload: typeof EVM_PREACTIVATION_PAYLOAD;
  }) => Promise<string>,
  beforeRelayerRound: () => Promise<void> = async () => undefined,
): WalletCustodyCeremonyKeySetInput {
  return {
    keySet: 'evm_family_ecdsa_v1',
    protocolInputsJson: '{"applicationBindingDigestB64u":"digest"}',
    evmFamilySigningKeySlotId: 'wallet-key:evm-family:alice.testnet:root-1:v1',
    beforeRelayerRound,
    runRelayerRound,
  };
}

test('an establishing NEAR run: begin, the Router round, complete, then finish', async () => {
  const { runStep, calls } = recordingRunner();
  let sawRequest: unknown = null;

  const payload = await runWalletCustodyKeySetCeremony({
    runStep,
    custody: establishingCustody(),
    keySetRun: nearRun(async (request) => {
      sawRequest = request;
      return '{"yao":"result"}';
    }),
    ceremonyId: CEREMONY_ID,
  });

  expect(payload).toEqual(ESTABLISHED_PAYLOAD);
  expect(calls.map((call) => call.type)).toEqual([
    'beginWalletCustodyKeySetRun',
    'completeWalletCustodyKeySetRun',
    'finishWalletCustodyKeySetRun',
  ]);
  // A completed run is not discarded: the finish already consumed it.
  expect(calls.some((call) => call.type === 'discardWalletCustodyCeremony')).toBe(false);

  // The Router round sees only the public execution request.
  expect(sawRequest).toBe(BEGUN_NEAR.yaoExecuteRequestJson);

  const begin = calls[0]!.payload;
  expect(begin.keySet).toBe('near_ed25519_v1');
  expect(begin.custody).toEqual({ origin: 'establish', walletId: WALLET_ID });

  // The identity recorded is this key set's own field.
  expect(calls[1]!.payload.nearEd25519SigningKeyId).toBe('near-ed25519-key-1');

  // An establishing run must seal, so the finish carries the factor and codes.
  const finish = calls[2]!.payload.finish as Record<string, unknown>;
  expect(finish.kind).toBe('establish');
  expect(finish.factorJson).toBe('{"envelopeId":"envelope-1"}');
  expect(finish.recoveryCodesJson).toBe('[]');

  for (const call of calls) expect(call.payload.ceremonyId).toBe(CEREMONY_ID);
});

test('a NEAR recovery run opens with the code and finishes with only a replacement envelope', async () => {
  const recoveredPayload = {
    walletId: WALLET_ID,
    keySet: 'near_ed25519_v1',
    keyManifestDigestB64u: 'digest',
    registeredPublicKeyB64u: 'registered',
    recoveryReplacementEnvelope: {
      envelopeId: 'replacement-envelope-1',
      envelopeBindingJson: '{}',
      envelopeNonceB64u: 'nonce',
      sealedCustodySecretB64u: 'ciphertext',
      envelopeAadHashB64u: 'aad',
      envelopeCiphertextDigestB64u: 'digest',
    },
  };
  const { runStep, calls } = recordingRunner({}, BEGUN_NEAR, recoveredPayload);

  const payload = await runWalletCustodyKeySetCeremony({
    runStep,
    custody: recoveringAndResealingCustody(),
    keySetRun: nearRun(async () => '{"yao":"recovery-result"}'),
    recordedKeyManifestDigestB64u: 'registered-manifest-digest',
    ceremonyId: CEREMONY_ID,
  });

  expect(payload).toEqual(recoveredPayload);
  expect(calls[0]!.payload.custody).toMatchObject({
    origin: 'recover_and_reseal',
    custodyJson: '{"walletId":"alice.testnet"}',
  });
  expect(calls[1]!.payload.recordedKeyManifestDigestB64u).toBe('registered-manifest-digest');
  expect(calls[2]!.payload.finish).toMatchObject({
    kind: 'recover_reseal',
    replacementFactorJson: '{"envelopeId":"replacement-envelope-1"}',
  });
  expect(recoveredPayload.establishedCustody).toBeUndefined();
});

test('a NEAR recovery activates only after the worker verifies its transcript', async () => {
  const { runStep, calls } = recordingRunner();
  const order: string[] = [];
  const observingRunner = (async (type: string, payload: Record<string, unknown>) => {
    const result = await runStep(
      type as Parameters<WalletCustodyCeremonyStepRunner>[0],
      payload as never,
    );
    order.push(type);
    return result;
  }) as WalletCustodyCeremonyStepRunner;

  await runWalletCustodyKeySetCeremony({
    runStep: observingRunner,
    custody: recoveringAndResealingCustody(),
    keySetRun: nearRun(
      async () => '{"yao":"recovery-result"}',
      async (result) => {
        expect(result).toBe('{"yao":"recovery-result"}');
        order.push('activateRouterRecovery');
      },
    ),
    recordedKeyManifestDigestB64u: 'registered-manifest-digest',
    ceremonyId: CEREMONY_ID,
  });

  expect(order).toEqual([
    'beginWalletCustodyKeySetRun',
    'completeWalletCustodyKeySetRun',
    'activateRouterRecovery',
    'finishWalletCustodyKeySetRun',
  ]);
  expect(calls.some((call) => call.type === 'discardWalletCustodyCeremony')).toBe(false);
});

test('recovery replacement ciphertext becomes one exact active passkey envelope', () => {
  const envelopeId = 'wallet-custody-recovery-envelope-1';
  const binding = {
    walletId: WALLET_ID,
    envelopeId,
    factor: {
      kind: 'passkey',
      rpId: 'wallet.example',
      credentialIdB64u: 'credential-1',
      kekVersion: 'passkey_prf_kek_hkdf_sha256_v1',
    },
    envelopeRevision: 1,
    binding: {
      kind: 'wallet_custody_seed_v1',
      derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
    },
  };
  const replacement = {
    envelopeId,
    envelopeBindingJson: JSON.stringify(binding),
    envelopeNonceB64u: 'AAAAAAAAAAAAAAAA',
    sealedCustodySecretB64u: 'AAAAAAAAAAAAAAAAAAAAAAA',
    envelopeAadHashB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    envelopeCiphertextDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  };
  const record = buildRecoveredPasskeyCustodyEnvelopeRecord({
    expectedWalletId: WALLET_ID,
    replacement,
    activatedAtMs: 60_000,
  });
  expect(record).toMatchObject({
    envelopeId,
    walletId: WALLET_ID,
    factor: binding.factor,
    binding: binding.binding,
    envelopeRevision: 1,
    lifecycle: { state: 'active', activatedAtMs: 60_000 },
  });
  expect(() =>
    buildRecoveredPasskeyCustodyEnvelopeRecord({
      expectedWalletId: WALLET_ID,
      replacement: { ...replacement, envelopeId: 'another-envelope' },
      activatedAtMs: 60_000,
    }),
  ).toThrow(/envelope identity/);
});

test('a joining EVM run reaches the relayer and never seals', async () => {
  const { runStep, calls } = recordingRunner({}, BEGUN_EVM, JOINED_PAYLOAD);
  let sawBootstrap: unknown = null;

  const payload = await runWalletCustodyKeySetCeremony({
    runStep,
    custody: joiningCustody(),
    keySetRun: evmRun(async (bootstrap) => {
      sawBootstrap = bootstrap;
      return '{"relayerKeyId":"relayer-1"}';
    }),
    ceremonyId: CEREMONY_ID,
  });

  expect(payload).toEqual(JOINED_PAYLOAD);

  // The relayer round gets the bootstrap facts, not a Router request.
  expect(sawBootstrap).toEqual({
    contextBinding32B64u: BEGUN_EVM.ecdsaContextBinding32B64u,
    clientSharePublicKey33B64u: BEGUN_EVM.ecdsaClientSharePublicKey33B64u,
    preActivationCommitPayload: EVM_PREACTIVATION_PAYLOAD,
  });

  const begin = calls[0]!.payload;
  expect(begin.keySet).toBe('evm_family_ecdsa_v1');
  expect((begin.custody as Record<string, unknown>).origin).toBe('join');
  // The factor secret opens the existing envelope, at the begin rather than the
  // finish: a joining run has no seed of its own to seal.
  expect((begin.custody as Record<string, unknown>).custodyJson).toBe('{"nonceB64u":"nonce"}');

  expect(begin.evmFamilySigningKeySlotId).toBe('wallet-key:evm-family:alice.testnet:root-1:v1');
  expect(calls.map((call) => call.type)).toEqual([
    'beginWalletCustodyKeySetRun',
    'completeWalletCustodyKeySetRun',
  ]);
});

test('an EVM run requires local recovery backup before relayer activation', async () => {
  const { runStep } = recordingRunner({}, BEGUN_EVM, JOINED_PAYLOAD);
  const order: string[] = [];

  await runWalletCustodyKeySetCeremony({
    runStep,
    custody: joiningCustody(),
    keySetRun: evmRun(
      async () => {
        order.push('relayer');
        return '{"relayerKeyId":"relayer-1"}';
      },
      async () => {
        order.push('backup');
      },
    ),
    ceremonyId: CEREMONY_ID,
  });

  expect(order).toEqual(['backup', 'relayer']);
});

test('a recorded manifest digest reaches the completing step', async () => {
  const { runStep, calls } = recordingRunner();

  await runWalletCustodyKeySetCeremony({
    runStep,
    custody: establishingCustody(),
    keySetRun: nearRun(async () => '{"yao":"result"}'),
    recordedKeyManifestDigestB64u: 'recorded-digest',
    ceremonyId: CEREMONY_ID,
  });

  // Present means the run must reproduce that key set rather than replace it.
  expect(calls[1]!.payload.recordedKeyManifestDigestB64u).toBe('recorded-digest');
});

test('a failed protocol round discards the run and rethrows', async () => {
  const { runStep, calls } = recordingRunner();
  const relayerDown = new Error('relayer unavailable');

  await expect(
    runWalletCustodyKeySetCeremony({
      runStep,
      custody: establishingCustody(),
      keySetRun: nearRun(async () => {
        throw relayerDown;
      }),
      ceremonyId: CEREMONY_ID,
    }),
  ).rejects.toThrow('relayer unavailable');

  // This is the case the driver exists for: the worker never saw a failure, so
  // nothing there would have dropped the seed.
  expect(calls.map((call) => call.type)).toEqual([
    'beginWalletCustodyKeySetRun',
    'discardWalletCustodyCeremony',
  ]);
});

test('a worker key-set mismatch fails before completing', async () => {
  const { runStep, calls } = recordingRunner({}, BEGUN_EVM);

  await expect(
    runWalletCustodyKeySetCeremony({
      runStep,
      custody: establishingCustody(),
      keySetRun: nearRun(async () => '{"yao":"result"}'),
      ceremonyId: CEREMONY_ID,
    }),
  ).rejects.toThrow('began an EVM run for a NEAR request');

  expect(calls.map((call) => call.type)).toEqual([
    'beginWalletCustodyKeySetRun',
    'discardWalletCustodyCeremony',
  ]);
});

test('a failed step discards the run and surfaces the original error', async () => {
  for (const failing of ['completeWalletCustodyKeySetRun', 'finishWalletCustodyKeySetRun']) {
    const { runStep, calls } = recordingRunner({ [failing]: new Error(`${failing} failed`) });

    await expect(
      runWalletCustodyKeySetCeremony({
        runStep,
        custody: establishingCustody(),
        keySetRun: nearRun(async () => '{"yao":"result"}'),
        ceremonyId: CEREMONY_ID,
      }),
    ).rejects.toThrow(`${failing} failed`);

    expect(calls.at(-1)?.type).toBe('discardWalletCustodyCeremony');
  }
});

test('a discard that itself fails does not mask the original error', async () => {
  const { runStep } = recordingRunner({
    finishWalletCustodyKeySetRun: new Error('finish rejected the recovery set'),
    discardWalletCustodyCeremony: new Error('worker is gone'),
  });

  // The caller must learn why the run failed, not why cleanup failed.
  await expect(
    runWalletCustodyKeySetCeremony({
      runStep,
      custody: establishingCustody(),
      keySetRun: nearRun(async () => '{"yao":"result"}'),
      ceremonyId: CEREMONY_ID,
    }),
  ).rejects.toThrow('finish rejected the recovery set');
});

test('a failed begin needs no discard', async () => {
  const { runStep, calls } = recordingRunner({
    beginWalletCustodyKeySetRun: new Error('protocol inputs rejected'),
  });

  await expect(
    runWalletCustodyKeySetCeremony({
      runStep,
      custody: establishingCustody(),
      keySetRun: nearRun(async () => '{"yao":"result"}'),
      ceremonyId: CEREMONY_ID,
    }),
  ).rejects.toThrow('protocol inputs rejected');

  // Nothing was ever stored under this id, and the worker dropped the seed with
  // the failed transition.
  expect(calls.map((call) => call.type)).toEqual(['beginWalletCustodyKeySetRun']);
});

test('each run gets its own id when none is supplied', async () => {
  const seen = new Set<string>();
  for (let index = 0; index < 3; index += 1) {
    const { runStep, calls } = recordingRunner();
    await runWalletCustodyKeySetCeremony({
      runStep,
      custody: establishingCustody(),
      keySetRun: nearRun(async () => '{"yao":"result"}'),
    });
    seen.add(String(calls[0]?.payload.ceremonyId));
  }
  expect(seen.size).toBe(3);
});
