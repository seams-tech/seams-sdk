import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test, expect } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function sourceBetween(source: string, start: string, end: string): string {
  const startIndex = source.indexOf(start);
  expect(startIndex, `Missing source marker ${start}`).toBeGreaterThanOrEqual(0);
  const endIndex = source.indexOf(end, startIndex + start.length);
  expect(endIndex, `Missing source marker ${end}`).toBeGreaterThan(startIndex);
  return source.slice(startIndex, endIndex);
}

test('ECDSA derivation client worker rejects raw secret fields for every request', () => {
  const source = readRepoSource(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsa-derivation-client.worker.ts',
  );
  const fieldPolicy = sourceBetween(
    source,
    'function forbiddenSecretFieldsForEcdsaDerivationWorkerRequest',
    'function assertNoPrfSecretsInSignerPayload',
  );

  expect(fieldPolicy).not.toContain('switch');
  expect(fieldPolicy).toContain("'prfOutput'");
  expect(fieldPolicy).toContain("secretB64uField('prfFirst')");
  expect(fieldPolicy).toContain("secretB64uField('signingShare32')");
});
