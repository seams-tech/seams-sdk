import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

type ForbiddenPattern = {
  label: string;
  needle: string;
};

function collectSourceFiles(rootDir: string): string[] {
  const out: string[] = [];
  const stack = [rootDir];
  while (stack.length > 0) {
    const current = stack.pop()!;
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
        continue;
      }
      if (!entry.isFile()) continue;
      if (!/\.(ts|tsx|js|mjs)$/.test(entry.name)) continue;
      out.push(fullPath);
    }
  }
  return out;
}

test.describe('threshold ECDSA legacy-surface guard', () => {
  test('forbids removed APIs and fallback signatures in core source', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const coreRoot = path.join(repoRoot, 'client/src/core');
    const files = collectSourceFiles(coreRoot);

    const forbidden: ForbiddenPattern[] = [
      {
        label: 'removed Tempo threshold method',
        needle: 'signTempoWithThresholdEcdsa',
      },
      {
        label: 'removed provided-keyRef compatibility branch',
        needle: 'provided thresholdEcdsaKeyRef does not match canonical threshold session state',
      },
      {
        label: 'removed threshold trace instrumentation marker',
        needle: '[threshold-trace]',
      },
      {
        label: 'removed hardcoded 2p participant fallback',
        needle: 'participantIds: [1, 2] as const',
      },
      {
        label: 'removed full-flow threshold sign queue wrapper',
        needle: 'withThresholdEcdsaSignQueue',
      },
      {
        label: 'removed threshold sign queue clear API',
        needle: 'clearThresholdEcdsaSignQueue',
      },
      {
        label: 'removed threshold sign-in-flight gate module',
        needle: 'thresholdEcdsaSignInFlightGate',
      },
      {
        label: 'removed legacy queue_overflow signer code',
        needle: "code = 'queue_overflow'",
      },
      {
        label: 'removed legacy queue_timeout signer code',
        needle: "code = 'queue_timeout'",
      },
    ];

    const violations: string[] = [];
    for (const file of files) {
      const content = fs.readFileSync(file, 'utf8');
      for (const item of forbidden) {
        if (content.includes(item.needle)) {
          const rel = path.relative(repoRoot, file);
          violations.push(`${item.label}: ${rel}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('signTempo does not wrap the full flow with queueing', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const signingEnginePath = path.join(repoRoot, 'client/src/core/signingEngine/SigningEngine.ts');
    const secp256k1Path = path.join(repoRoot, 'client/src/core/signingEngine/signers/algorithms/secp256k1.ts');
    const signingEngineContent = fs.readFileSync(signingEnginePath, 'utf8');
    const secp256k1Content = fs.readFileSync(secp256k1Path, 'utf8');

    expect(signingEngineContent.includes('return await signTempoValue(this.orchestrationDeps.tempoSigningDeps, args);')).toBe(true);
    expect(signingEngineContent.includes('withThresholdEcdsaSignQueue({')).toBe(false);
    expect(secp256k1Content.includes('enqueueThresholdEcdsaCommit')).toBe(true);
  });
});
