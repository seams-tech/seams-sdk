import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

test.describe('confirmation config normalization', () => {
  test('normalizer accepts raw silent config with either behavior and strips ignored fields', () => {
    const source = readSource('packages/sdk-web/src/core/types/confirmationConfig.ts');

    expect(source).toContain("if (input?.uiMode === 'none')");
    expect(source).toContain("kind: 'silent'");
    expect(source).not.toMatch(/kind:\s*'silent'[\s\S]{0,120}behavior:/);
    expect(source).not.toMatch(/kind:\s*'silent'[\s\S]{0,120}autoProceedDelay:/);
  });
});

