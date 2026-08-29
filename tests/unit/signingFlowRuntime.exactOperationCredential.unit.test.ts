import { expect, test } from '@playwright/test';
import { IndexedDBManager } from '@/core/indexedDB';
import {
  walletSessionAuthorizations,
  type WalletSessionAuthorizationExactOperationCredentialReadResult,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { resolveExactEcdsaOperationCredential } from '@/core/signingEngine/flows/signEvmFamily/signingFlowRuntime';
import {
  buildLinkedDeviceUnlockRuntimeFixture,
  type LinkedDeviceUnlockRuntimeFixture,
} from './helpers/linkedDeviceUnlockRuntime.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

function resolvedSelection(fixture: LinkedDeviceUnlockRuntimeFixture) {
  return {
    kind: 'resolved' as const,
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: fixture.signerMaterials,
    exportRoot: null,
  };
}

class ExactCredentialReadHarness {
  exactRead: WalletSessionAuthorizationExactOperationCredentialReadResult;
  activeReadCalled = false;

  constructor(readonly fixture: LinkedDeviceUnlockRuntimeFixture) {
    this.exactRead = {
      kind: 'found',
      record: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    };
  }

  async resolveSelectedWalletAuthority() {
    return resolvedSelection(this.fixture);
  }

  async readExactWithOperationCredential(
    input: Parameters<typeof walletSessionAuthorizations.readExactWithOperationCredential>[0],
  ): Promise<WalletSessionAuthorizationExactOperationCredentialReadResult> {
    expect(input).toEqual({
      walletId: this.fixture.walletId,
      authorityId: this.fixture.authority.authorityId,
      authMethodId: this.fixture.authMethod.walletAuthMethodId,
    });
    return this.exactRead;
  }

  async rejectActiveWalletRead(): Promise<never> {
    this.activeReadCalled = true;
    throw new Error('wallet-wide session lookup must not run');
  }
}

test('ECDSA step-up resolves only the selected exact session primary credential', async () => {
  const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
  const ecdsaActivation = fixture.authority.signerActivations.ecdsa;
  if (!ecdsaActivation) throw new Error('fixture is missing its ECDSA activation');
  const originalResolveSelectedWalletAuthority = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalReadExact = walletSessionAuthorizations.readExactWithOperationCredential;
  const originalReadActive = walletSessionAuthorizations.readActiveForWallet;
  const harness = new ExactCredentialReadHarness(fixture);

  IndexedDBManager.resolveSelectedWalletAuthority =
    harness.resolveSelectedWalletAuthority.bind(harness);
  walletSessionAuthorizations.readExactWithOperationCredential =
    harness.readExactWithOperationCredential.bind(harness);
  walletSessionAuthorizations.readActiveForWallet = harness.rejectActiveWalletRead.bind(harness);

  try {
    await expect(
      resolveExactEcdsaOperationCredential({
        walletId: fixture.walletId,
        authority: fixture.factorAuthority,
        materialActivation: ecdsaActivation.materialActivation,
        nowMs: Date.now(),
      }),
    ).resolves.toEqual({
      kind: 'resolved',
      operationCredential: fixture.operationCredential,
    });
    expect(harness.activeReadCalled).toBe(false);

    harness.exactRead = {
      kind: 'found',
      record: fixture.activeWalletSession,
      operationCredential: { ...fixture.operationCredential, token: '   ' },
    };
    await expect(
      resolveExactEcdsaOperationCredential({
        walletId: fixture.walletId,
        authority: fixture.factorAuthority,
        materialActivation: ecdsaActivation.materialActivation,
        nowMs: Date.now(),
      }),
    ).resolves.toEqual({
      kind: 'unavailable',
      reason: 'wallet_session_identity_mismatch',
    });

    harness.exactRead = { kind: 'upgrade_required' };
    await expect(
      resolveExactEcdsaOperationCredential({
        walletId: fixture.walletId,
        authority: fixture.factorAuthority,
        materialActivation: ecdsaActivation.materialActivation,
        nowMs: Date.now(),
      }),
    ).resolves.toEqual({ kind: 'upgrade_required' });

    harness.exactRead = {
      kind: 'found',
      record: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    };
    await expect(
      resolveExactEcdsaOperationCredential({
        walletId: fixture.walletId,
        authority: fixture.factorAuthority,
        materialActivation: buildMpcMaterialActivationRefFixture(
          'other-exact-session',
          String(fixture.walletId),
          'worker:other-exact-session',
        ),
        nowMs: Date.now(),
      }),
    ).resolves.toEqual({
      kind: 'unavailable',
      reason: 'selected_authority_mismatch',
    });
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelectedWalletAuthority;
    walletSessionAuthorizations.readExactWithOperationCredential = originalReadExact;
    walletSessionAuthorizations.readActiveForWallet = originalReadActive;
  }
});
