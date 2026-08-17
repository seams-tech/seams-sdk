import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import {
  buildR103DeviceLinkFixture,
  buildR103LinkedWalletSessionDeliveryFixture,
} from './helpers/deviceLinkContracts.fixtures';

test('persists one exact linked Wallet Session delivery and resolves its approved key', async ({
  page,
}) => {
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  const delivery = buildR103LinkedWalletSessionDeliveryFixture(buildR103DeviceLinkFixture());
  const mismatchedRenewal = buildR103LinkedWalletSessionDeliveryFixture(
    buildR103DeviceLinkFixture({ deviceId: 'device:r103-renewal-mismatch' }),
    { sessionSuffix: 'renewal-mismatch' },
  );
  const result = await page.evaluate(async (input) => {
    const schema = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
    const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
    const storeModule =
      await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore.js');
    const dbName = schema.createSeamsTestWalletDbName(`linked_auth_${crypto.randomUUID()}`);
    const manager = new managerModule.SeamsWalletDBManager();
    manager.setDbName(dbName);
    const repository = new storeModule.LinkedDeviceWalletSessionRepositoryV1(manager);
    const token = input.delivery.orderedTokens[0];
    if (!token) throw new Error('linked Wallet Session fixture has no token');
    try {
      const persisted = await repository.putExactActiveDeliveryV1(input.delivery);
      const replayed = await repository.putExactActiveDeliveryV1(input.delivery);
      const found = await repository.readTokenForWalletKeyV1({
        enrollmentId: input.delivery.enrollmentId,
        walletKeyId: token.walletKeyId,
        keyFamily: token.keyFamily,
        nowMs: input.delivery.issuedAtMs,
      });
      const wrongFamily = await repository.readTokenForWalletKeyV1({
        enrollmentId: input.delivery.enrollmentId,
        walletKeyId: token.walletKeyId,
        keyFamily: token.keyFamily === 'ed25519' ? 'ecdsa_secp256k1' : 'ed25519',
        nowMs: input.delivery.issuedAtMs,
      });
      const expired = await repository.readActiveForEnrollmentV1({
        enrollmentId: input.delivery.enrollmentId,
        nowMs: input.delivery.expiresAtMs,
      });
      let replayMismatchRejected = false;
      try {
        await repository.putExactActiveDeliveryV1({
          ...input.delivery,
          orderedTokens: [
            {
              ...token,
              walletSessionJwt: `${token.walletSessionJwt.slice(0, -1)}x`,
            },
          ],
        });
      } catch {
        replayMismatchRejected = true;
      }
      let renewalIdentityMismatchRejected = false;
      try {
        await repository.replaceExactRenewedDeliveryV1(input.mismatchedRenewal);
      } catch {
        renewalIdentityMismatchRejected = true;
      }
      const renewalIdentityPreserved = await repository.readForEnrollmentV1(
        input.delivery.enrollmentId,
      );
      await repository.clearEnrollmentV1(input.delivery.enrollmentId);
      const cleared = await repository.readActiveForEnrollmentV1({
        enrollmentId: input.delivery.enrollmentId,
        nowMs: input.delivery.issuedAtMs,
      });
      return {
        persisted,
        replayed,
        found,
        wrongFamily,
        expired,
        replayMismatchRejected,
        renewalIdentityMismatchRejected,
        renewalIdentityPreserved,
        cleared,
      };
    } finally {
      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
    }
  }, { delivery, mismatchedRenewal });

  expect(result.persisted).toEqual(delivery);
  expect(result.replayed).toEqual(delivery);
  expect(result.found).toEqual({
    kind: 'found',
    delivery,
    token: delivery.orderedTokens[0],
  });
  expect(result.wrongFamily).toEqual({ kind: 'missing' });
  expect(result.expired).toEqual({ kind: 'expired' });
  expect(result.replayMismatchRejected).toBe(true);
  expect(result.renewalIdentityMismatchRejected).toBe(true);
  expect(result.renewalIdentityPreserved).toEqual({ kind: 'found', delivery });
  expect(result.cleared).toEqual({ kind: 'missing' });
});

test('keeps only the current linked-device enrollment for a wallet', async ({ page }) => {
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  const older = buildR103LinkedWalletSessionDeliveryFixture(buildR103DeviceLinkFixture(), {
    sessionSuffix: 'older',
  });
  const current = buildR103LinkedWalletSessionDeliveryFixture(
    buildR103DeviceLinkFixture({
      linkSessionId: 'link-session:r103:current',
      enrollmentId: 'enrollment:r103:current',
      deviceId: 'device:r103:current',
    }),
    { sessionSuffix: 'current' },
  );

  const result = await page.evaluate(async (input) => {
    const schema = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
    const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
    const storeModule =
      await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore.js');
    const dbName = schema.createSeamsTestWalletDbName(`linked_current_${crypto.randomUUID()}`);
    const manager = new managerModule.SeamsWalletDBManager();
    manager.setDbName(dbName);
    const repository = new storeModule.LinkedDeviceWalletSessionRepositoryV1(manager);
    try {
      await repository.putExactActiveDeliveryV1(input.older);
      await repository.putExactActiveDeliveryV1(input.current);
      return {
        older: await repository.readForEnrollmentV1(input.older.enrollmentId),
        current: await repository.readForEnrollmentV1(input.current.enrollmentId),
        unique: await repository.readUniqueActiveForWalletV1({
          walletId: input.current.walletId,
          nowMs: input.current.issuedAtMs,
        }),
      };
    } finally {
      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
    }
  }, { older, current });

  expect(result.older).toEqual({ kind: 'missing' });
  expect(result.current).toEqual({ kind: 'found', delivery: current });
  expect(result.unique).toEqual({ kind: 'found', delivery: current });
});

test('selects one active sealed refresh and clears superseded sealed refreshes', async ({ page }) => {
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  const older = buildR103LinkedWalletSessionDeliveryFixture(buildR103DeviceLinkFixture(), {
    sessionSuffix: 'sealed-older',
  });
  const current = buildR103LinkedWalletSessionDeliveryFixture(
    buildR103DeviceLinkFixture({
      linkSessionId: 'link-session:r103:sealed-current',
      enrollmentId: 'enrollment:r103:sealed-current',
      deviceId: 'device:r103:sealed-current',
    }),
    { sessionSuffix: 'sealed-current' },
  );

  const result = await page.evaluate(
    async ({ older, current }) => {
      const schema = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const storeModule =
        await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore.js');
      const dbName = schema.createSeamsTestWalletDbName(`linked_sealed_${crypto.randomUUID()}`);
      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const repository = new storeModule.LinkedDeviceWalletSessionRepositoryV1(manager);
      const sealedRefreshFor = (delivery: typeof older, sealedSecretB64u: string) => ({
        kind: 'linked_device_sealed_refresh_material_v1',
        algorithm: 'shamir3pass-v2',
        groupId: 'rfc2409-group2',
        walletId: delivery.walletId,
        enrollmentId: delivery.enrollmentId,
        deviceId: delivery.deviceId,
        walletSessionId: delivery.walletSessionId,
        credentialIdB64u: 'CQ',
        sealedSecretB64u,
        keyVersion: null,
        issuedAtMs: delivery.issuedAtMs,
        expiresAtMs: delivery.expiresAtMs,
        remainingUses: delivery.remainingUses,
      });
      const rowFor = (delivery: typeof older, sealedRefresh: unknown) => ({
        enrollment_id: delivery.enrollmentId,
        wallet_id: delivery.walletId,
        device_id: delivery.deviceId,
        expires_at_ms: delivery.expiresAtMs,
        delivery,
        sealed_refresh: sealedRefresh,
      });
      try {
        const db = await manager.getDB();
        await db.put(
          schema.SEAMS_WALLET_STORES.linkedDeviceWalletSessions,
          rowFor(older, sealedRefreshFor(older, 'AQ')),
        );
        await db.put(
          schema.SEAMS_WALLET_STORES.linkedDeviceWalletSessions,
          rowFor(current, sealedRefreshFor(current, 'Ag')),
        );
        const ambiguous = await repository.readUniqueActiveSealedRefreshForWalletV1({
          walletId: current.walletId,
          nowMs: current.issuedAtMs,
        });
        await repository.putSealedRefreshV1(sealedRefreshFor(current, 'Aw'));
        const unique = await repository.readUniqueActiveSealedRefreshForWalletV1({
          walletId: current.walletId,
          nowMs: current.issuedAtMs,
        });
        const olderRow = await db.get(
          schema.SEAMS_WALLET_STORES.linkedDeviceWalletSessions,
          older.enrollmentId,
        );
        const clearPromise = repository.clearSealedRefreshV1(current.enrollmentId);
        const duringClear = await repository.readUniqueActiveSealedRefreshForWalletV1({
          walletId: current.walletId,
          nowMs: current.issuedAtMs,
        });
        await clearPromise;
        const afterClear = await repository.readUniqueActiveSealedRefreshForWalletV1({
          walletId: current.walletId,
          nowMs: current.issuedAtMs,
        });
        await repository.putSealedRefreshV1(sealedRefreshFor(current, 'BA'));
        return {
          ambiguous,
          unique,
          olderSealedRefresh: olderRow?.sealed_refresh ?? null,
          duringClear,
          afterClear,
        };
      } finally {
        manager.close();
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase(dbName);
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
      }
    },
    { older, current },
  );

  expect(result.ambiguous).toEqual({ kind: 'ambiguous' });
  expect(result.unique).toMatchObject({
    kind: 'found',
    sealedRefresh: { enrollmentId: current.enrollmentId, sealedSecretB64u: 'Aw' },
  });
  expect(result.olderSealedRefresh).toBeNull();
  expect(result.duringClear).toEqual({ kind: 'missing' });
  expect(result.afterClear).toEqual({ kind: 'missing' });
});
