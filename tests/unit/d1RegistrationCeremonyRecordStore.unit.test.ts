import { expect, test } from '@playwright/test';
import {
  D1RegistrationCeremonyRecordConflictError,
  D1RegistrationCeremonyRecordStore,
} from '../../packages/wallet-server/src/router/cloudflare/d1/registration/d1RegistrationCeremonyRecordStore';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';

const TENANT_SCOPE = {
  namespace: 'test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
};

test.describe('D1 registration ceremony record store', () => {
  let temporary: TemporaryD1Database;
  let store: D1RegistrationCeremonyRecordStore;

  test.beforeEach(async () => {
    temporary = createTemporaryD1Database();
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    store = new D1RegistrationCeremonyRecordStore({
      database: temporary.database,
      scope: TENANT_SCOPE,
      keyPrefix: 'gateway-registration:',
    });
  });

  test.afterEach(() => {
    cleanupTemporaryD1Database(temporary.tempDir);
  });

  test('consumes a one-time record exactly once under contention', async () => {
    await store.putExact(recordMutation('intent', 'grant-a', { grant: 'grant-a' }));

    const results = await Promise.all([
      store.take('intent', 'grant-a'),
      store.take('intent', 'grant-a'),
    ]);

    expect(results.filter((result) => result !== null)).toHaveLength(1);
    expect(await store.get('intent', 'grant-a')).toBeNull();
  });

  test('uses canonical JSON for exact replay and expected-value CAS', async () => {
    const expiresAtMs = futureExpiry();
    await store.putExact(
      recordMutation('ceremony', 'ceremony-a', { alpha: 1, beta: 2 }, expiresAtMs),
    );
    await store.putExact(
      recordMutation('ceremony', 'ceremony-a', { beta: 2, alpha: 1 }, expiresAtMs),
    );

    await store.updateExpected({
      scope: 'ceremony',
      id: 'ceremony-a',
      expected: { beta: 2, alpha: 1 },
      next: { alpha: 2, beta: 2 },
      expiresAtMs: futureExpiry(),
    });

    expect((await store.get('ceremony', 'ceremony-a'))?.value).toEqual({ alpha: 2, beta: 2 });
  });

  test('rejects stale updates instead of overwriting a newer transition', async () => {
    await store.putExact(recordMutation('ceremony', 'ceremony-a', { state: 'prepared' }));
    await store.updateExpected({
      scope: 'ceremony',
      id: 'ceremony-a',
      expected: { state: 'prepared' },
      next: { state: 'running' },
      expiresAtMs: futureExpiry(),
    });

    await expect(
      store.updateExpected({
        scope: 'ceremony',
        id: 'ceremony-a',
        expected: { state: 'prepared' },
        next: { state: 'failed' },
        expiresAtMs: futureExpiry(),
      }),
    ).rejects.toBeInstanceOf(D1RegistrationCeremonyRecordConflictError);
    expect((await store.get('ceremony', 'ceremony-a'))?.value).toEqual({ state: 'running' });
  });

  test('stores both add-signer replay indexes atomically and rejects partial replay state', async () => {
    const replay = { ceremonyId: 'add-a', idempotencyKey: 'request-a' };
    const mutations = [
      recordMutation('add-signer-finalize-replay', 'add-a:request-a', replay),
      recordMutation('add-signer-finalize-claim', 'add-a', replay),
    ];
    await store.putManyExact(mutations);
    await store.putManyExact(mutations);

    await store.putExact(
      recordMutation('add-signer-finalize-claim', 'add-b', {
        ceremonyId: 'add-b',
        idempotencyKey: 'different-request',
      }),
    );
    await expect(
      store.putManyExact([
        recordMutation('add-signer-finalize-replay', 'add-b:request-b', replay),
        recordMutation('add-signer-finalize-claim', 'add-b', replay),
      ]),
    ).rejects.toBeInstanceOf(D1RegistrationCeremonyRecordConflictError);
    expect(await store.get('add-signer-finalize-replay', 'add-b:request-b')).toBeNull();
  });
});

function recordMutation(
  scope: string,
  id: string,
  value: Record<string, unknown>,
  expiresAtMs = futureExpiry(),
) {
  return { scope, id, value, expiresAtMs };
}

function futureExpiry(): number {
  return Date.now() + 60_000;
}
