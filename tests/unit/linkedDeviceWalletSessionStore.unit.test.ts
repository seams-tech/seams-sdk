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
  const result = await page.evaluate(async (input) => {
    const schema = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
    const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
    const storeModule =
      await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore.js');
    const dbName = schema.createSeamsTestWalletDbName(`linked_auth_${crypto.randomUUID()}`);
    const manager = new managerModule.SeamsWalletDBManager();
    manager.setDbName(dbName);
    const repository = new storeModule.LinkedDeviceWalletSessionRepositoryV1(manager);
    const token = input.orderedTokens[0];
    if (!token) throw new Error('linked Wallet Session fixture has no token');
    try {
      const persisted = await repository.putExactActiveDeliveryV1(input);
      const replayed = await repository.putExactActiveDeliveryV1(input);
      const found = await repository.readTokenForWalletKeyV1({
        enrollmentId: input.enrollmentId,
        walletKeyId: token.walletKeyId,
        keyFamily: token.keyFamily,
        nowMs: input.issuedAtMs,
      });
      const wrongFamily = await repository.readTokenForWalletKeyV1({
        enrollmentId: input.enrollmentId,
        walletKeyId: token.walletKeyId,
        keyFamily: token.keyFamily === 'ed25519' ? 'ecdsa_secp256k1' : 'ed25519',
        nowMs: input.issuedAtMs,
      });
      const expired = await repository.readActiveForEnrollmentV1({
        enrollmentId: input.enrollmentId,
        nowMs: input.expiresAtMs,
      });
      let replayMismatchRejected = false;
      try {
        await repository.putExactActiveDeliveryV1({
          ...input,
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
      await repository.clearEnrollmentV1(input.enrollmentId);
      const cleared = await repository.readActiveForEnrollmentV1({
        enrollmentId: input.enrollmentId,
        nowMs: input.issuedAtMs,
      });
      return {
        persisted,
        replayed,
        found,
        wrongFamily,
        expired,
        replayMismatchRejected,
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
  }, delivery);

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
  expect(result.cleared).toEqual({ kind: 'missing' });
});
