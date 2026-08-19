import { expect, test } from '@playwright/test';
import { toAccountId } from '../../packages/wallet/src/core/types/accountIds';
import { toWalletId } from '../../packages/wallet/src/core/signingEngine/interfaces/ecdsaChainTarget';
import { Ed25519YaoPageLifecycleOwner } from '../../packages/wallet/src/core/signingEngine/threshold/ed25519/yaoPageLifecycleOwner';
import {
  ED25519_YAO_PUBLIC_CAPABILITY_LANES_KIND_V1,
  ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1,
  IndexedDbEd25519YaoPublicCapabilityReferenceStore,
  parseEd25519YaoPublicCapabilityLanesV1,
  parseEd25519YaoPublicCapabilityReferencesV1,
} from '../../packages/wallet/src/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import {
  buildMpcMaterialActivationRefFixture,
  buildWalletAuthAuthorityRefFixture,
} from './helpers/ecdsaMaterialRef.fixtures';
import { nearEd25519SigningKeyIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseThresholdEd25519SessionId } from '../../packages/shared-ts/src/utils/domainIds';
import { toRpId } from '../../packages/wallet/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { nearEd25519PublicLocatorObservation } from '../../packages/wallet/src/SeamsWeb/signingSurface/BrowserSigningSurface';
import { passkeyEd25519YaoLaneReferenceFromRecovery } from '@/core/signingEngine/flows/recovery/passkeyEd25519YaoRecovery';
import {
  buildPasskeyEd25519AuthorizationProjectionFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import { rebindRouterAbEd25519WalletSessionStateFromExactRuntime } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { resolveNearEd25519YaoCapabilityHydrationV1 } from '../../packages/wallet/src/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import { buildRestorableMpcMaterialRefInternal } from '../../packages/wallet/src/core/signingEngine/session/material/restorableMpcMaterialRef.internal';

const APP_STATE_KEY = 'ed25519YaoPublicCapabilityReferencesV1';
const LANES_APP_STATE_KEY = 'ed25519YaoPublicCapabilityLanesV1';

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
  const thresholdSessionId = parseThresholdEd25519SessionId('threshold-ed25519-yao-lifecycle');
  if (!thresholdSessionId.ok) throw new Error(thresholdSessionId.error.message);
  return {
    walletId: toWalletId('wallet-yao-lifecycle'),
    nearAccountId: toAccountId('wallet-yao-lifecycle.testnet'),
    materialActivation: buildMpcMaterialActivationRefFixture(
      'activation-yao-lifecycle',
      'wallet-yao-lifecycle',
    ),
    thresholdSessionId: thresholdSessionId.value,
    runtimePolicyScope: {
      orgId: 'org-yao-lifecycle',
      projectId: 'project-yao-lifecycle',
      envId: 'test',
      signingRootVersion: 'root-v1',
    },
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

    await store.remove(identity);
    expect(await store.list()).toEqual([]);
  });

  test('persists the complete signing lane projection separately from material identity', async () => {
    const appState = new AppStateFixture();
    const store = new IndexedDbEd25519YaoPublicCapabilityReferenceStore(appState);
    const identity = publicIdentityFixture();
    const lane = {
      ...identity,
      auth: {
        kind: 'passkey' as const,
        rpId: toRpId('localhost'),
        credentialIdB64u: 'credential-yao-lifecycle',
      },
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString('scope-yao-lifecycle'),
      signerSlot: 1,
    };

    await store.upsertLane(lane);

    expect(appState.read(LANES_APP_STATE_KEY)).toEqual({
      kind: ED25519_YAO_PUBLIC_CAPABILITY_LANES_KIND_V1,
      lanes: [lane],
    });
    expect(await store.listLanes()).toEqual([lane]);
    expect(parseEd25519YaoPublicCapabilityLanesV1(appState.read(LANES_APP_STATE_KEY))).toEqual({
      kind: ED25519_YAO_PUBLIC_CAPABILITY_LANES_KIND_V1,
      lanes: [lane],
    });

    const replacement = {
      ...lane,
      materialActivation: buildMpcMaterialActivationRefFixture(
        'activation-yao-lifecycle-replacement',
        String(identity.walletId),
      ),
    };
    await store.upsertLane(replacement);

    expect(await store.listLanes()).toEqual([replacement]);
  });

  test('lane projection drives exact signing hydration lookup', async () => {
    const appState = new AppStateFixture();
    const store = new IndexedDbEd25519YaoPublicCapabilityReferenceStore(appState);
    const identity = publicIdentityFixture();
    const thresholdSessionId = parseThresholdEd25519SessionId(String(identity.thresholdSessionId));
    if (!thresholdSessionId.ok) throw new Error(thresholdSessionId.error.message);
    const lane = {
      ...identity,
      thresholdSessionId: thresholdSessionId.value,
      auth: {
        kind: 'passkey' as const,
        rpId: toRpId('localhost'),
        credentialIdB64u: 'credential-yao-lifecycle',
      },
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString('scope-yao-lifecycle'),
      signerSlot: 1,
    };

    await store.upsertLane(lane);

    const publicLocator = nearEd25519PublicLocatorObservation({
      references: await store.listLanes(),
      walletId: lane.walletId,
      nearAccountId: lane.nearAccountId,
      signerSlot: lane.signerSlot,
      thresholdSessionId: lane.thresholdSessionId,
    });
    expect(publicLocator).toMatchObject({
      kind: 'available',
      walletId: String(lane.walletId),
      nearAccountId: String(lane.nearAccountId),
      signerSlot: lane.signerSlot,
      materialActivation: lane.materialActivation,
    });
    if (publicLocator.kind !== 'available') {
      throw new Error('lane projection must resolve an exact public locator');
    }
    const authority = buildWalletAuthAuthorityRefFixture({
      walletId: String(lane.walletId),
      label: 'yao-lifecycle',
    });
    const hydration = resolveNearEd25519YaoCapabilityHydrationV1({
      publicLocator: {
        ...publicLocator,
        authority,
      },
      sealed: {
        kind: 'available',
        authority,
        materialActivation: lane.materialActivation,
        sealedMaterial: buildRestorableMpcMaterialRefInternal('sealed-yao-lifecycle'),
      },
      runtime: { kind: 'absent' },
      unlockSource: { kind: 'available', authority },
    });
    expect(hydration).toMatchObject({ kind: 'rehydrate_material_activation' });

    const wrongLane = nearEd25519PublicLocatorObservation({
      references: await store.listLanes(),
      walletId: lane.walletId,
      nearAccountId: lane.nearAccountId,
      signerSlot: 2,
      thresholdSessionId: lane.thresholdSessionId,
    });
    expect(wrongLane).toEqual({ kind: 'missing' });
    if (wrongLane.kind !== 'missing') throw new Error('expected a missing wrong-owner lane');
    expect(
      resolveNearEd25519YaoCapabilityHydrationV1({
        publicLocator: wrongLane,
        sealed: { kind: 'missing' },
        runtime: { kind: 'absent' },
        unlockSource: { kind: 'unavailable' },
      }),
    ).toMatchObject({ kind: 'blocked', reason: 'missing_capability' });
  });

  test('passkey unlock lane publication preserves the recovered signing identity', async () => {
    const record = buildPasskeyEd25519SealedSessionRecordFixture();
    const runtime = parseExactEd25519SealedSessionRuntime(record);
    if (!runtime) throw new Error('passkey sealed runtime fixture is invalid');
    const authorization = buildPasskeyEd25519AuthorizationProjectionFixture(record);
    const walletSessionState = await rebindRouterAbEd25519WalletSessionStateFromExactRuntime({
      runtime,
      authorization,
      nowMs: runtime.expiresAtMs - 1,
    });
    const lane = passkeyEd25519YaoLaneReferenceFromRecovery({
      walletSessionState,
      materialActivation: record.ed25519Restore.materialActivation,
    });

    expect(lane).toEqual({
      walletId: walletSessionState.signingLane.identity.signer.account.wallet.walletId,
      nearAccountId: walletSessionState.signingLane.identity.signer.account.nearAccountId,
      thresholdSessionId: walletSessionState.thresholdSessionId,
      runtimePolicyScope: walletSessionState.runtimePolicyScope,
      materialActivation: record.ed25519Restore.materialActivation,
      auth: walletSessionState.signingLane.auth,
      nearEd25519SigningKeyId:
        walletSessionState.signingLane.identity.signer.nearEd25519SigningKeyId,
      signerSlot: walletSessionState.signingLane.identity.signer.signerSlot,
    });
  });

  test('rejects secret-bearing or package-bearing persistence fields', () => {
    const identity = publicIdentityFixture();
    const forbiddenFields = [
      'clientScalar',
      'prfFirst',
      'rootShare',
      'walletSessionToken',
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
