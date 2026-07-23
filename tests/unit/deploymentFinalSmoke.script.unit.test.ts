import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

type SmokeManifest = {
  readonly releaseSetId: string;
  readonly buildIdentity: {
    readonly selectedComponents: readonly string[];
  };
};

type SmokeOptions = {
  readonly releaseSetId?: string;
  readonly selectedComponents?: string;
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const smokeScript = path.join(repoRoot, 'scripts/deployment-final-smoke.mjs');

test('final smoke accepts a manifest-only check for a role-only release', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'seams-deployment-smoke-'));
  try {
    const manifestPath = path.join(root, 'manifest.json');
    const manifest: SmokeManifest = {
      releaseSetId: 'rs_' + 'a'.repeat(64),
      buildIdentity: { selectedComponents: ['deriver-a'] },
    };
    writeFileSync(manifestPath, `${JSON.stringify(manifest)}\n`, 'utf8');

    const output = runSmoke(manifestPath, {
      selectedComponents: '["deriver-a"]',
      releaseSetId: manifest.releaseSetId,
    });

    expect(output).toContain(`"releaseSetId":"${manifest.releaseSetId}"`);
    expect(output).toContain('"results":[]');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('final smoke rejects a release-set identity mismatch before probing origins', () => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'seams-deployment-smoke-'));
  try {
    const manifestPath = path.join(root, 'manifest.json');
    writeFileSync(
      manifestPath,
      `${JSON.stringify({ releaseSetId: 'rs_' + 'a'.repeat(64) })}\n`,
      'utf8',
    );

    expect(() =>
      runSmoke(manifestPath, {
        selectedComponents: '[]',
        releaseSetId: 'rs_' + 'b'.repeat(64),
      }),
    ).toThrow();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

function runSmoke(manifestPath: string, options: SmokeOptions): string {
  return execFileSync(
    process.execPath,
    [
      smokeScript,
      '--manifest',
      manifestPath,
      '--release-set-id',
      options.releaseSetId ?? 'rs_' + 'a'.repeat(64),
      '--selected-components',
      options.selectedComponents ?? '[]',
    ],
    { cwd: repoRoot, encoding: 'utf8' },
  );
}
