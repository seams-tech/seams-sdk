import { expect, test } from '@playwright/test';
import type { WalletCustodyCeremonyTransportPort } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
import {
  custodyEnvelopePasskeyAuthMethodIdV1,
  destroyUnlockedWalletCustodyTransferCapabilitiesV1,
  dropUnlockedWalletCustodyTransferCapabilityReferenceV1,
  establishUnlockedWalletCustodyTransferCapabilityV1,
  readUnlockedWalletCustodyTransferCapabilityV1,
} from '@/core/signingEngine/walletCustody/unlockedCustodyTransferCapability';
import { passkeyCustodyEnvelope } from './helpers/passkeyCustodyEnvelope.fixtures';
import { buildUnlockedCustodyCapabilityFixtureV1 } from './helpers/linkedDeviceCustodyTransfer.fixtures';

/**
 * R103 zero-prompt handoff — the main-thread registry's lifecycle contract.
 *
 * The registry is module-global on purpose (it mirrors the one signed-in
 * wallet), so every test starts by dropping whatever an earlier test left.
 * The worker itself is faked: these tests own what crosses the boundary and
 * when the local reference dies, not the wasm handle semantics.
 */

type WorkerCall = { readonly type: string; readonly payload: Record<string, unknown> };

function fakeWorker(handler?: (call: WorkerCall) => unknown): {
  readonly transport: WalletCustodyCeremonyTransportPort;
  readonly calls: WorkerCall[];
} {
  const calls: WorkerCall[] = [];
  return {
    calls,
    transport: {
      async requestOperation(args) {
        const request = args.request as { type: string; payload: Record<string, unknown> };
        const call = { type: request.type, payload: request.payload };
        calls.push(call);
        if (handler) return handler(call);
        return undefined;
      },
    },
  };
}

function establishedReference(overrides: Record<string, unknown> = {}) {
  return {
    ...buildUnlockedCustodyCapabilityFixtureV1({
      walletId: 'alice.testnet',
      walletSessionId: 'wallet-session:unlock',
      expiresAtMs: Date.now() + 60_000,
    }),
    ...overrides,
  };
}

test.beforeEach(() => {
  dropUnlockedWalletCustodyTransferCapabilityReferenceV1();
});

test('uses the canonical wallet auth-method identity for a passkey envelope', () => {
  const envelope = passkeyCustodyEnvelope();
  if (envelope.factor.kind !== 'passkey') throw new Error('fixture factor is not a passkey');
  expect(custodyEnvelopePasskeyAuthMethodIdV1(envelope.factor)).toBe(
    `passkey:${envelope.factor.rpId}:${envelope.factor.credentialIdB64u}`,
  );
});

test('establish forwards a copied factor secret, records the reference, and zeroizes its copy', async () => {
  const reference = establishedReference();
  let transferredBuffer: ArrayBuffer | null = null;
  const worker = fakeWorker((call) => {
    transferredBuffer = call.payload.existingFactorSecret as ArrayBuffer;
    return reference;
  });
  const factorSecret = new Uint8Array(32).fill(7);

  const established = await establishUnlockedWalletCustodyTransferCapabilityV1(worker.transport, {
    existingEnvelope: passkeyCustodyEnvelope(),
    existingFactorSecret: factorSecret,
    walletId: reference.walletId,
    walletAuthMethodId: reference.walletAuthMethodId,
    walletSessionId: reference.walletSessionId,
    expiresAtMs: reference.expiresAtMs,
  });

  expect(established).toEqual(reference);
  expect(readUnlockedWalletCustodyTransferCapabilityV1(reference.walletId)).toEqual(reference);
  // The worker received a copy, and the module wiped that copy after the
  // transfer; the caller's own buffer stays the caller's responsibility.
  expect(transferredBuffer).not.toBe(factorSecret.buffer);
  expect([...factorSecret]).toEqual(new Array(32).fill(7));
  expect(worker.calls[0]?.type).toBe('establishUnlockedWalletCustodyTransferCapability');
});

test('establish refuses a worker response that is not a capability reference', async () => {
  const worker = fakeWorker(() => ({ nonsense: true }));
  await expect(
    establishUnlockedWalletCustodyTransferCapabilityV1(worker.transport, {
      existingEnvelope: passkeyCustodyEnvelope(),
      existingFactorSecret: new Uint8Array(32).fill(7),
      walletId: 'alice.testnet',
      walletAuthMethodId: 'passkey:wallet.example.test:cred',
      walletSessionId: 'wallet-session:unlock',
      expiresAtMs: Date.now() + 60_000,
    }),
  ).rejects.toThrow('returned no reference');
  expect(readUnlockedWalletCustodyTransferCapabilityV1('alice.testnet')).toBeUndefined();
});

test('read is wallet-exact and expiry-aware, never a stale reference', async () => {
  const reference = establishedReference();
  const worker = fakeWorker(() => reference);
  await establishUnlockedWalletCustodyTransferCapabilityV1(worker.transport, {
    existingEnvelope: passkeyCustodyEnvelope(),
    existingFactorSecret: new Uint8Array(32).fill(7),
    walletId: reference.walletId,
    walletAuthMethodId: reference.walletAuthMethodId,
    walletSessionId: reference.walletSessionId,
    expiresAtMs: reference.expiresAtMs,
  });

  expect(readUnlockedWalletCustodyTransferCapabilityV1('wallet:other')).toBeUndefined();
  expect(readUnlockedWalletCustodyTransferCapabilityV1(reference.walletId)).toEqual(reference);

  // Expiry invalidates on read — and stays invalid afterwards.
  const expired = establishedReference({ expiresAtMs: Date.now() - 1 });
  const expiredWorker = fakeWorker(() => expired);
  await establishUnlockedWalletCustodyTransferCapabilitiesReplacement(expiredWorker.transport, expired);
  expect(readUnlockedWalletCustodyTransferCapabilityV1(expired.walletId)).toBeUndefined();
  expect(readUnlockedWalletCustodyTransferCapabilityV1(expired.walletId)).toBeUndefined();
});

test('expiry destroys the worker-held capability without a later read', async () => {
  const expired = establishedReference({ expiresAtMs: Date.now() - 1 });
  const worker = fakeWorker(() => expired);
  await establishUnlockedWalletCustodyTransferCapabilitiesReplacement(worker.transport, expired);

  await new Promise<void>((resolve) => setTimeout(resolve, 0));

  const destroyCall = worker.calls.find(
    (call) => call.type === 'destroyUnlockedWalletCustodyTransferCapabilities',
  );
  expect(destroyCall?.payload).toEqual({
    scope: {
      kind: 'capability',
      capabilityHandleId: expired.capabilityHandleId,
    },
  });
  expect(readUnlockedWalletCustodyTransferCapabilityV1(expired.walletId)).toBeUndefined();
});

async function establishUnlockedWalletCustodyTransferCapabilitiesReplacement(
  transport: WalletCustodyCeremonyTransportPort,
  reference: ReturnType<typeof establishedReference>,
) {
  await establishUnlockedWalletCustodyTransferCapabilityV1(transport, {
    existingEnvelope: passkeyCustodyEnvelope(),
    existingFactorSecret: new Uint8Array(32).fill(7),
    walletId: reference.walletId,
    walletAuthMethodId: reference.walletAuthMethodId,
    walletSessionId: reference.walletSessionId,
    expiresAtMs: reference.expiresAtMs,
  });
}

test('destroy scopes drop the matching local reference and always reach the worker', async () => {
  const scopes = [
    { kind: 'all' } as const,
    { kind: 'wallet', walletId: 'alice.testnet' } as const,
    { kind: 'wallet_session', walletSessionId: 'wallet-session:unlock' } as const,
    { kind: 'capability', capabilityHandleId: 'unlocked-custody-capability-fixture' } as const,
  ];
  for (const scope of scopes) {
    const reference = establishedReference();
    const worker = fakeWorker(() => reference);
    await establishUnlockedWalletCustodyTransferCapabilitiesReplacement(worker.transport, reference);
    await destroyUnlockedWalletCustodyTransferCapabilitiesV1(worker.transport, scope);
    expect(readUnlockedWalletCustodyTransferCapabilityV1(reference.walletId)).toBeUndefined();
    const destroyCall = worker.calls.at(-1);
    expect(destroyCall?.type).toBe('destroyUnlockedWalletCustodyTransferCapabilities');
    expect(destroyCall?.payload).toEqual({ scope });
  }
});

test('a non-matching destroy scope keeps the local reference but still reaches the worker', async () => {
  const reference = establishedReference();
  const worker = fakeWorker(() => reference);
  await establishUnlockedWalletCustodyTransferCapabilitiesReplacement(worker.transport, reference);
  await destroyUnlockedWalletCustodyTransferCapabilitiesV1(worker.transport, {
    kind: 'wallet',
    walletId: 'wallet:other',
  });
  expect(readUnlockedWalletCustodyTransferCapabilityV1(reference.walletId)).toEqual(reference);
});

test('destroy clears the local reference even when the worker is unreachable', async () => {
  const reference = establishedReference();
  const worker = fakeWorker(() => reference);
  await establishUnlockedWalletCustodyTransferCapabilitiesReplacement(worker.transport, reference);
  const deadWorker: WalletCustodyCeremonyTransportPort = {
    requestOperation: async () => {
      throw new Error('worker was reset');
    },
  };
  // A dead worker has already lost its handle memory; the local drop is the
  // part that must not depend on reaching it.
  await destroyUnlockedWalletCustodyTransferCapabilitiesV1(deadWorker, { kind: 'all' });
  expect(readUnlockedWalletCustodyTransferCapabilityV1(reference.walletId)).toBeUndefined();
});

test('the worker-reset drop invalidates the reference without a worker call', async () => {
  const reference = establishedReference();
  const worker = fakeWorker(() => reference);
  await establishUnlockedWalletCustodyTransferCapabilitiesReplacement(worker.transport, reference);
  const callsBefore = worker.calls.length;
  dropUnlockedWalletCustodyTransferCapabilityReferenceV1();
  expect(readUnlockedWalletCustodyTransferCapabilityV1(reference.walletId)).toBeUndefined();
  expect(worker.calls.length).toBe(callsBefore);
});
