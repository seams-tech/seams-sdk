import { expect, test } from '@playwright/test';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import { toWalletId } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import { Ed25519YaoPageLifecycleOwner } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoPageLifecycleOwner';
import {
  ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1,
  IndexedDbEd25519YaoPublicCapabilityReferenceStore,
  parseEd25519YaoPublicCapabilityReferencesV1,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';

const APP_STATE_KEY = 'ed25519YaoPublicCapabilityReferencesV1';

class AppStateFixture {
  private readonly records = new Map<string, unknown>();

  isDisabled(): boolean {
    return false;
  }

  async getAppState<T>(key: string): Promise<T | undefined> {
    return this.records.get(key) as T | undefined;
  }

  async setAppState<T>(key: string, value: T): Promise<void> {
    this.records.set(key, value);
  }

  read(key: string): unknown {
    return this.records.get(key);
  }
}

function publicIdentityFixture() {
  return {
    walletId: toWalletId('wallet-yao-lifecycle'),
    nearAccountId: toAccountId('wallet-yao-lifecycle.testnet'),
    thresholdSessionId: 'threshold-session-yao-lifecycle',
  };
}

test.describe('Ed25519 Yao public capability lifecycle', () => {
  test('persists only the exact public capability identity projection', async () => {
    const appState = new AppStateFixture();
    const store = new IndexedDbEd25519YaoPublicCapabilityReferenceStore(appState);
    const identity = publicIdentityFixture();

    await store.upsert(identity);

    expect(appState.read(APP_STATE_KEY)).toEqual({
      kind: ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1,
      identities: [identity],
    });
    expect(await store.list()).toEqual([identity]);

    await store.clear();
    expect(await store.list()).toEqual([]);
  });

  test('rejects secret-bearing or package-bearing persistence fields', () => {
    const identity = publicIdentityFixture();
    const forbiddenFields = [
      'clientScalar',
      'prfFirst',
      'rootShare',
      'walletSessionJwt',
      'activationPackage',
    ];

    for (const forbiddenField of forbiddenFields) {
      expect(() =>
        parseEd25519YaoPublicCapabilityReferencesV1({
          kind: ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1,
          identities: [{ ...identity, [forbiddenField]: 'forbidden' }],
        }),
      ).toThrow('contains unexpected fields');
    }
  });

  test('pagehide disposes the live client owner exactly once', () => {
    const eventTarget = new EventTarget();
    let disposeCalls = 0;
    const owner = new Ed25519YaoPageLifecycleOwner(eventTarget, {
      dispose(): void {
        disposeCalls += 1;
      },
    });

    eventTarget.dispatchEvent(new Event('pagehide'));
    eventTarget.dispatchEvent(new Event('pagehide'));
    owner.dispose();

    expect(disposeCalls).toBe(1);
  });
});
