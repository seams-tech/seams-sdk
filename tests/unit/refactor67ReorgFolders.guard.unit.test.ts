import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listFiles(relativeDir: string, predicate: (fileName: string) => boolean): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];
  const entries = fs.readdirSync(absoluteDir, { withFileTypes: true });
  const files: string[] = [];
  const ignoredDirectories = new Set(['.vite', 'dist', 'node_modules']);
  for (const entry of entries) {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) {
      if (ignoredDirectories.has(entry.name)) continue;
      files.push(...listFiles(relativePath, predicate));
      continue;
    }
    if (entry.isFile() && predicate(entry.name)) files.push(relativePath);
  }
  return files;
}

function listSourceFiles(relativeDir: string): string[] {
  return listFiles(relativeDir, (fileName) => /\.(ts|tsx|mjs|js|json|yaml|yml)$/.test(fileName));
}

test.describe('refactor 67 folder reorg guards', () => {
  test('keeps deleted implementation roots from returning', () => {
    const forbiddenRoots = ['client', 'sdk', 'server', 'shared'];
    const existing = forbiddenRoots.filter((relativePath) =>
      fs.existsSync(path.join(repoRoot, relativePath)),
    );
    expect(existing, existing.join('\n')).toEqual([]);
  });

  test('keeps workspace package roots canonical', () => {
    const workspace = readRepoFile('pnpm-workspace.yaml');
    for (const required of [
      'packages/sdk-web',
      'packages/sdk-server-ts',
      'packages/shared-ts',
      'apps/web-client',
      'apps/web-server',
      'apps/docs',
    ]) {
      expect(workspace).toContain(required);
    }

    expect(workspace).not.toMatch(/^\s*-\s*sdk\s*$/m);
    expect(workspace).not.toContain('packages/sdk-runtime-ts');
    expect(workspace).not.toContain('examples/seams-site');
    expect(workspace).not.toContain('examples/relay-server');
    expect(workspace).not.toContain('examples/seams-docs');
  });

  test('keeps package type paths off deleted client and server roots', () => {
    const packageJson = readRepoFile('packages/sdk-web/package.json');
    expect(packageJson).not.toContain('dist/types/client/src');
    expect(packageJson).not.toContain('dist/types/server/src');
    expect(packageJson).toContain('dist/types/sdk-web/src');
    expect(packageJson).toContain('dist/types/sdk-server-ts/src');
  });

  test('keeps deployable apps from importing package implementation source', () => {
    const violations: string[] = [];
    for (const file of [...listSourceFiles('apps/web-client'), ...listSourceFiles('apps/web-server')]) {
      const source = readRepoFile(file);
      if (/\.\.\/(?:\.\.\/)*packages\/(?:sdk-web|sdk-server-ts|shared-ts)\/src/.test(source)) {
        violations.push(file);
      }
      if (/\.\.\/(?:\.\.\/)*(?:client|server|shared)\/src/.test(source)) {
        violations.push(file);
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps native roots from importing npm implementation source', () => {
    const violations: string[] = [];
    for (const file of [...listSourceFiles('clients/ios'), ...listSourceFiles('crates/seams-embedded')]) {
      const source = readRepoFile(file);
      if (/packages\/(?:sdk-web|sdk-server-ts|shared-ts)\/src/.test(source)) {
        violations.push(file);
      }
      if (/(?:client|server|shared)\/src/.test(source)) {
        violations.push(file);
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });
});
