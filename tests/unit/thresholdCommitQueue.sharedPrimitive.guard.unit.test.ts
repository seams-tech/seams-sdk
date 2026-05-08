import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function readRepoFile(relativePath: string): string {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const absolutePath = path.join(repoRoot, relativePath);
  return fs.readFileSync(absolutePath, 'utf8');
}

test.describe('threshold commit queue shared primitive guard', () => {
  test('ECDSA and Ed25519 queue wrappers both use the shared primitive', () => {
    const ecdsa = readRepoFile(
      'client/src/core/signingEngine/threshold/ecdsa/commitQueue.ts',
    );
    const ed25519 = readRepoFile(
      'client/src/core/signingEngine/threshold/ed25519/commitQueue.ts',
    );

    expect(ecdsa).toContain("from '../commitQueueShared'");
    expect(ed25519).toContain("from '../commitQueueShared'");
    expect(ecdsa).toContain('withThresholdCommitQueue({');
    expect(ed25519).toContain('withThresholdCommitQueue({');
    expect(ecdsa).toContain('clearThresholdCommitQueue(queueByKey);');
    expect(ed25519).toContain('clearThresholdCommitQueue(queueByKey);');
  });

  test('curve key domains stay separate while remaining session-scoped', () => {
    const ecdsa = readRepoFile(
      'client/src/core/signingEngine/threshold/ecdsa/commitQueue.ts',
    );
    const ed25519 = readRepoFile(
      'client/src/core/signingEngine/threshold/ed25519/commitQueue.ts',
    );

    expect(ecdsa).toContain('return `session:${targetKey}:${thresholdSessionId}`;');
    expect(ed25519).toContain("return `session:ed25519:${thresholdSessionId}`;");
  });
});
