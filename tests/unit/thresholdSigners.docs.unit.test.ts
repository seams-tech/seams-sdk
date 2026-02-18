import { expect, test } from '@playwright/test';
import type { TatchiPasskey } from '@tatchi-xyz/sdk/react';
import {
  provisionTempoAndEvmThresholdSigners,
  readCachedThresholdKeyRef,
  resolveThresholdKeyRef,
  writeCachedThresholdKeyRef,
  type ThresholdEcdsaKeyRef,
} from '../../examples/tatchi-site/src/utils/thresholdSigners';

type MockBootstrapArgs = {
  nearAccountId: string;
  options?: {
    chain?: 'evm' | 'tempo';
    ttlMs?: number;
    remainingUses?: number;
  };
};

type MockTatchi = {
  bootstrapThresholdEcdsaSession: (
    args: MockBootstrapArgs,
  ) => Promise<{ thresholdEcdsaKeyRef: ThresholdEcdsaKeyRef }>;
};

function createSessionStorageMock(): Storage {
  const data = new Map<string, string>();
  return {
    get length(): number {
      return data.size;
    },
    clear(): void {
      data.clear();
    },
    getItem(key: string): string | null {
      return data.has(key) ? (data.get(key) as string) : null;
    },
    key(index: number): string | null {
      const keys = Array.from(data.keys());
      return keys[index] || null;
    },
    removeItem(key: string): void {
      data.delete(key);
    },
    setItem(key: string, value: string): void {
      data.set(String(key), String(value));
    },
  };
}

function installWindowSessionStorage(storage: Storage): void {
  Object.defineProperty(globalThis, 'window', {
    value: { sessionStorage: storage },
    configurable: true,
    writable: true,
  });
}

function makeThresholdKeyRef(chain: 'evm' | 'tempo'): ThresholdEcdsaKeyRef {
  return {
    type: 'threshold-ecdsa-secp256k1',
    userId: 'alice.testnet',
    relayerUrl: 'https://relay.example',
    relayerKeyId: `${chain}-relayer-key-id`,
    clientVerifyingShareB64u: `${chain}-client-share`,
    participantIds: [1, 2],
    groupPublicKeyB64u: `${chain}-group-pk`,
    relayerVerifyingShareB64u: `${chain}-relayer-share`,
  };
}

let originalWindowDescriptor: PropertyDescriptor | undefined;

test.describe('docs threshold signer helpers', () => {
  test.beforeEach(() => {
    originalWindowDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'window');
    installWindowSessionStorage(createSessionStorageMock());
  });

  test.afterEach(() => {
    if (originalWindowDescriptor) {
      Object.defineProperty(globalThis, 'window', originalWindowDescriptor);
      return;
    }
    delete (globalThis as { window?: unknown }).window;
  });

  test('writes and reads threshold keyRefs from sessionStorage', () => {
    const keyRef = makeThresholdKeyRef('evm');
    writeCachedThresholdKeyRef('alice.testnet', 'evm', keyRef);
    const cached = readCachedThresholdKeyRef('alice.testnet', 'evm');
    expect(cached).toEqual(keyRef);
  });

  test('resolveThresholdKeyRef returns cached keyRef without bootstrap call', async () => {
    const keyRef = makeThresholdKeyRef('tempo');
    writeCachedThresholdKeyRef('alice.testnet', 'tempo', keyRef);

    let calls = 0;
    const mock: MockTatchi = {
      bootstrapThresholdEcdsaSession: async () => {
        calls += 1;
        return { thresholdEcdsaKeyRef: makeThresholdKeyRef('tempo') };
      },
    };

    const resolved = await resolveThresholdKeyRef({
      tatchi: mock as unknown as TatchiPasskey,
      nearAccountId: 'alice.testnet',
      chain: 'tempo',
    });

    expect(resolved).toEqual(keyRef);
    expect(calls).toBe(0);
  });

  test('resolveThresholdKeyRef bootstraps and caches when missing', async () => {
    let calls = 0;
    const keyRef = makeThresholdKeyRef('evm');
    const mock: MockTatchi = {
      bootstrapThresholdEcdsaSession: async () => {
        calls += 1;
        return { thresholdEcdsaKeyRef: keyRef };
      },
    };

    const resolved = await resolveThresholdKeyRef({
      tatchi: mock as unknown as TatchiPasskey,
      nearAccountId: 'alice.testnet',
      chain: 'evm',
    });

    expect(calls).toBe(1);
    expect(resolved).toEqual(keyRef);
    expect(readCachedThresholdKeyRef('alice.testnet', 'evm')).toEqual(keyRef);
  });

  test('provisionTempoAndEvmThresholdSigners reuses one bootstrap for both chains', async () => {
    const calls: MockBootstrapArgs[] = [];
    const sharedKeyRef = makeThresholdKeyRef('tempo');
    const mock: MockTatchi = {
      bootstrapThresholdEcdsaSession: async (args) => {
        calls.push(args);
        return { thresholdEcdsaKeyRef: sharedKeyRef };
      },
    };

    const provisioned = await provisionTempoAndEvmThresholdSigners({
      tatchi: mock as unknown as TatchiPasskey,
      nearAccountId: 'alice.testnet',
    });

    expect(calls).toHaveLength(1);
    expect(calls[0]?.options?.chain).toBe('tempo');
    expect(provisioned.evm.thresholdEcdsaKeyRef).toEqual(sharedKeyRef);
    expect(provisioned.tempo.thresholdEcdsaKeyRef).toEqual(sharedKeyRef);
    expect(readCachedThresholdKeyRef('alice.testnet', 'evm')).toEqual(sharedKeyRef);
    expect(readCachedThresholdKeyRef('alice.testnet', 'tempo')).not.toBeNull();
  });

  test('provisionTempoAndEvmThresholdSigners surfaces bootstrap failures', async () => {
    const mock: MockTatchi = {
      bootstrapThresholdEcdsaSession: async () => {
        throw new Error('bootstrap failed');
      },
    };

    await expect(
      provisionTempoAndEvmThresholdSigners({
        tatchi: mock as unknown as TatchiPasskey,
        nearAccountId: 'alice.testnet',
      }),
    ).rejects.toThrow(/bootstrap failed/i);
  });
});
