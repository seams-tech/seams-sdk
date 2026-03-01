import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

function readNearSigningSource(): string {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const filePath = path.join(repoRoot, 'client/src/core/signingEngine/api/nearSigning.ts');
  return fs.readFileSync(filePath, 'utf8');
}

test.describe('threshold Ed25519 near signing queue guard', () => {
  test('threshold near signing routes through strict session-scoped queue wrapper', () => {
    const source = readNearSigningSource();
    const wrapperCalls = source.match(/withThresholdEd25519CommitQueue\(\{/g)?.length || 0;

    expect(source).toContain('resolveThresholdEd25519CommitQueueKey');
    expect(source).toContain("if (args.signerMode.mode !== 'threshold-signer')");
    expect(source).toContain('enabled: true,');
    expect(wrapperCalls).toBeGreaterThanOrEqual(3);
  });
});
