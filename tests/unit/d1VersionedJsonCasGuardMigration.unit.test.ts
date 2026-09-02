import { expect, test } from '@playwright/test';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';

test('signer migrations install the immutable versioned-json CAS sentinel', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
    const row = await temporary.database
      .prepare('SELECT guard_id FROM router_ab_yao_versioned_json_cas_guard WHERE guard_id = 1')
      .first<{ guard_id: number }>();

    expect(row).toEqual({ guard_id: 1 });
    await expect(
      temporary.database
        .prepare('DELETE FROM router_ab_yao_versioned_json_cas_guard WHERE guard_id = 1')
        .run(),
    ).rejects.toThrow(/immutable/u);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});
