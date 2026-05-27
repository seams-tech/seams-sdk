import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import {
  LEGACY_INDEXED_DB_NAMES,
  SEAMS_WALLET_DB_NAME,
  SEAMS_WALLET_INDEXES,
  SEAMS_WALLET_SCHEMA_MANIFEST,
  SEAMS_WALLET_STORES,
  assertCanonicalIndexedDBName,
  createSeamsTestWalletDbName,
} from '../../client/src/core/indexedDB/schemaNames';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const CANONICAL_NAME_PATTERN = /^seams_[a-z0-9]+(?:_[a-z0-9]+)*$/;
const SNAKE_CASE_PATTERN = /^[a-z0-9]+(?:_[a-z0-9]+)*$/;

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listSourceFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listSourceFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

test.describe('IndexedDB consolidation guards', () => {
  test('canonical wallet schema names are Seams-prefixed snake_case', () => {
    expect(SEAMS_WALLET_DB_NAME).toBe('seams_wallet');
    expect(Object.values(SEAMS_WALLET_STORES).every((name) => name.startsWith('seams_'))).toBe(
      true,
    );

    for (const name of [SEAMS_WALLET_DB_NAME, ...Object.values(SEAMS_WALLET_STORES)]) {
      expect(name, name).toMatch(CANONICAL_NAME_PATTERN);
      expect(() => assertCanonicalIndexedDBName(name)).not.toThrow();
    }
    for (const name of Object.values(SEAMS_WALLET_INDEXES)) {
      expect(name, name).toMatch(SNAKE_CASE_PATTERN);
    }
  });

  test('test wallet DB names normalize unsafe suffixes', () => {
    expect(createSeamsTestWalletDbName('Case-Heavy UUID 123')).toBe(
      'seams_test_wallet_case_heavy_uuid_123',
    );
    expect(() => createSeamsTestWalletDbName('---')).toThrow(
      'Test wallet IndexedDB name suffix is required',
    );
  });

  test('schema manifest defines every canonical store exactly once', () => {
    const manifestStores = SEAMS_WALLET_SCHEMA_MANIFEST.map((entry) => entry.store);
    expect([...new Set(manifestStores)].sort()).toEqual(Object.values(SEAMS_WALLET_STORES).sort());

    for (const entry of SEAMS_WALLET_SCHEMA_MANIFEST) {
      expect(entry.store, entry.store).toMatch(CANONICAL_NAME_PATTERN);
      for (const index of entry.indexes) {
        expect(index.name, `${entry.store}:${index.name}`).toMatch(SNAKE_CASE_PATTERN);
      }
    }
  });

  test('fresh seams wallet databases match the schema manifest', async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    const result = await page.evaluate(async () => {
      const schemaNames = await import('/sdk/esm/core/indexedDB/schemaNames.js');
      const managerModule = await import('/sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
      const manifest = schemaNames.SEAMS_WALLET_SCHEMA_MANIFEST as Array<{
        store: string;
        keyPath: string | string[];
        indexes: Array<{
          name: string;
          keyPath: string | string[];
          unique: boolean;
        }>;
      }>;
      const dbName = schemaNames.createSeamsTestWalletDbName(
        `manifest_${crypto.randomUUID()}`,
      );

      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });

      const manager = new managerModule.SeamsWalletDBManager();
      manager.setDbName(dbName);
      const db = await manager.getDB();
      const observed = manifest.map((definition) => {
        const storeNames = Array.from(db.objectStoreNames);
        const tx = db.transaction(definition.store, 'readonly');
        const store = tx.objectStore(definition.store);
        const indexes = definition.indexes.map((expectedIndex) => {
          const index = store.index(expectedIndex.name);
          return {
            name: index.name,
            keyPath: index.keyPath,
            unique: index.unique,
          };
        });
        return {
          storeNames,
          store: definition.store,
          keyPath: store.keyPath,
          indexNames: Array.from(store.indexNames),
          indexes,
        };
      });
      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
      return observed;
    });

    const manifestStoreNames = SEAMS_WALLET_SCHEMA_MANIFEST.map((definition) => definition.store);
    for (const observedStore of result) {
      const definition = SEAMS_WALLET_SCHEMA_MANIFEST.find(
        (entry) => entry.store === observedStore.store,
      );
      expect(definition, observedStore.store).toBeDefined();
      expect(observedStore.storeNames.sort()).toEqual([...manifestStoreNames].sort());
      expect(observedStore.keyPath).toEqual(definition!.keyPath);
      expect(observedStore.indexNames.sort()).toEqual(
        definition!.indexes.map((index) => index.name).sort(),
      );
      expect(observedStore.indexes).toEqual(
        definition!.indexes.map((index) => ({
          name: index.name,
          keyPath: index.keyPath,
          unique: index.unique,
        })),
      );
    }
  });

  test('legacy database name literals stay isolated to explicit boundary files', () => {
    const allowedLegacyReferences = new Set([
      'client/src/core/indexedDB/accountKeyMaterialDB/schema.ts',
      'client/src/core/indexedDB/index.ts',
      'client/src/core/indexedDB/passkeyClientDB/schema.ts',
      'client/src/core/indexedDB/schemaNames.ts',
      'client/src/core/signingEngine/session/persistence/sealedSessionStore.ts',
      'client/src/core/signingEngine/workerManager/workers/email-otp/deviceEnrollmentEscrowStore.ts',
      'shared/src/utils/signingSessionSeal.ts',
    ]);
    const sourceFiles = [
      ...listSourceFiles('client/src'),
      ...listSourceFiles('shared/src'),
    ].filter((relativePath) => !allowedLegacyReferences.has(relativePath));

    for (const legacyName of LEGACY_INDEXED_DB_NAMES) {
      const literalPattern = new RegExp(
        `['"\`]${legacyName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"\`]`,
      );
      const offenders = sourceFiles.filter((relativePath) =>
        literalPattern.test(readRepoSource(relativePath)),
      );
      expect(offenders, legacyName).toEqual([]);
    }
  });
});
