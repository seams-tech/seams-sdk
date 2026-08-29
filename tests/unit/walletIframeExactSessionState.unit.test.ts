import { expect, test } from '@playwright/test';
import {
  readSelectedWalletIframeExactSessionState,
  type WalletIframeExactSessionReadDependencies,
  type WalletIframeExactSessionState,
  type WalletIframeExactSessionStatus,
} from '@/SeamsWeb/walletIframe/shared/exactSessionState';
import {
  buildLinkedDeviceUnlockRuntimeFixture,
  type LinkedDeviceUnlockRuntimeFixture,
} from './helpers/linkedDeviceUnlockRuntime.fixtures';

function activeStatus(fixture: LinkedDeviceUnlockRuntimeFixture): WalletIframeExactSessionStatus {
  return {
    status: 'active',
    walletSessionId: fixture.operationCredential.walletSessionId,
    quotaId: fixture.activeWalletSession.quotaId,
    remainingUses: 10,
    expiresAtMs: fixture.activeWalletSession.expiresAtMs,
    authorization: fixture.activeWalletSession,
  };
}

function exhaustedStatus(
  fixture: LinkedDeviceUnlockRuntimeFixture,
): WalletIframeExactSessionStatus {
  return {
    status: 'exhausted',
    walletSessionId: fixture.operationCredential.walletSessionId,
    quotaId: fixture.activeWalletSession.quotaId,
    remainingUses: 0,
    expiresAtMs: fixture.activeWalletSession.expiresAtMs,
    authorization: fixture.activeWalletSession,
  };
}

function expiredStatus(fixture: LinkedDeviceUnlockRuntimeFixture): WalletIframeExactSessionStatus {
  return {
    status: 'expired',
    walletSessionId: fixture.operationCredential.walletSessionId,
    quotaId: fixture.activeWalletSession.quotaId,
    expiresAtMs: fixture.activeWalletSession.expiresAtMs,
    authorization: fixture.activeWalletSession,
  };
}

function missingStatus(fixture: LinkedDeviceUnlockRuntimeFixture): WalletIframeExactSessionStatus {
  return {
    status: 'missing',
    walletSessionId: fixture.operationCredential.walletSessionId,
    quotaId: fixture.activeWalletSession.quotaId,
  };
}

function readDependencies(
  fixture: LinkedDeviceUnlockRuntimeFixture,
  status: WalletIframeExactSessionStatus,
  nowMs: number,
): WalletIframeExactSessionReadDependencies {
  return {
    resolveSelectedWalletAuthority: async () => ({
      kind: 'resolved',
      selection: fixture.selection,
      authMethod: fixture.authMethod,
      authority: fixture.authority,
      signerMaterials: fixture.signerMaterials,
      exportRoot: null,
    }),
    readExactActiveForWallet: async () => ({
      kind: 'found',
      record: fixture.activeWalletSession,
      operationCredential: fixture.operationCredential,
    }),
    readStatus: async () => status,
    nowMs: () => nowMs,
  };
}

async function readState(
  fixture: LinkedDeviceUnlockRuntimeFixture,
  status: WalletIframeExactSessionStatus,
  nowMs = 0,
): Promise<WalletIframeExactSessionState> {
  return await readSelectedWalletIframeExactSessionState(
    { walletId: fixture.walletId },
    readDependencies(fixture, status, nowMs),
  );
}

test.describe('wallet iframe exact V6 session state', () => {
  test('projects an active V6 record using its operation credential identity', async () => {
    const fixture = await buildLinkedDeviceUnlockRuntimeFixture();

    await expect(readState(fixture, activeStatus(fixture))).resolves.toEqual({
      kind: 'active_session',
      status: 'active',
      walletId: fixture.walletId,
      authorizationId: fixture.activeWalletSession.authorizationId,
      walletSessionId: fixture.operationCredential.walletSessionId,
      authMethod: fixture.authMethod.kind,
      expiresAtMs: fixture.activeWalletSession.expiresAtMs,
    });
  });

  test('retains the exact identity when the relayer reports an expired session', async () => {
    const fixture = await buildLinkedDeviceUnlockRuntimeFixture();

    await expect(readState(fixture, expiredStatus(fixture))).resolves.toMatchObject({
      kind: 'expired_session',
      walletId: fixture.walletId,
      authorizationId: fixture.activeWalletSession.authorizationId,
      walletSessionId: fixture.operationCredential.walletSessionId,
      authMethod: fixture.authMethod.kind,
      expiresAtMs: fixture.activeWalletSession.expiresAtMs,
    });
  });

  test('distinguishes a missing remote session from an exhausted quota', async () => {
    const fixture = await buildLinkedDeviceUnlockRuntimeFixture();

    await expect(readState(fixture, missingStatus(fixture))).resolves.toMatchObject({
      kind: 'wallet_unlocked_without_signing_session',
      reason: 'not_found',
      walletId: fixture.walletId,
      authorizationId: fixture.activeWalletSession.authorizationId,
      walletSessionId: fixture.operationCredential.walletSessionId,
      authMethod: fixture.authMethod.kind,
    });
    await expect(readState(fixture, exhaustedStatus(fixture))).resolves.toEqual({
      kind: 'wallet_unlocked_without_signing_session',
      reason: 'exhausted',
      walletId: fixture.walletId,
    });
  });

  test('fails closed when the status read is unavailable', async () => {
    const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
    const dependencies = readDependencies(fixture, activeStatus(fixture), 0);
    const unavailableDependencies: WalletIframeExactSessionReadDependencies = {
      ...dependencies,
      readStatus: async () => {
        throw new Error('relayer unavailable');
      },
    };

    await expect(
      readSelectedWalletIframeExactSessionState(
        { walletId: fixture.walletId },
        unavailableDependencies,
      ),
    ).resolves.toEqual({
      kind: 'wallet_unlocked_without_signing_session',
      reason: 'unavailable',
      walletId: fixture.walletId,
    });
  });
});
