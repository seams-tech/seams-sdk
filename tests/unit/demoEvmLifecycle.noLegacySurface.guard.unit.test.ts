import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

type ForbiddenNeedle = {
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
      if (!/\.(ts|tsx)$/.test(entry.name)) continue;
      out.push(fullPath);
    }
  }
  return out;
}

test.describe('demo EVM lifecycle no-legacy-surface guard', () => {
  test('forbids removed demo-local lifecycle helpers and modules', () => {
    const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
    const demoRoot = path.join(repoRoot, 'examples/tatchi-site/src/flows/demo');
    const files = collectSourceFiles(demoRoot);

    const removedFiles = [
      path.join(demoRoot, 'hooks/demoEvmTransactionHandling.ts'),
      path.join(demoRoot, 'hooks/reportTempoBroadcastFailure.ts'),
      path.join(demoRoot, 'hooks/reportEvmFinalizationDebugEvent.ts'),
    ];
    const existingRemovedFiles = removedFiles
      .filter((filePath) => fs.existsSync(filePath))
      .map((filePath) => path.relative(repoRoot, filePath));
    expect(existingRemovedFiles, existingRemovedFiles.join('\n')).toEqual([]);

    const forbiddenNeedles: ForbiddenNeedle[] = [
      {
        label: 'removed demo raw transaction broadcaster helper',
        needle: 'sendRawEvmTransaction(',
      },
      {
        label: 'removed demo finalization poll helper',
        needle: 'waitForEvmTransactionFinalization(',
      },
      {
        label: 'removed demo payload verifier helper',
        needle: 'verifyFinalizedEvmTxPayload(',
      },
      {
        label: 'removed demo broadcast-failure reporter helper',
        needle: 'reportTempoBroadcastFailure',
      },
      {
        label: 'removed demo finalization debug-event reporter helper',
        needle: 'reportEvmFinalizationDebugEvent',
      },
      {
        label: 'removed demo legacy transaction handling module',
        needle: 'demoEvmTransactionHandling',
      },
    ];

    const violations: string[] = [];
    for (const file of files) {
      const content = fs.readFileSync(file, 'utf8');
      for (const item of forbiddenNeedles) {
        if (!content.includes(item.needle)) continue;
        const rel = path.relative(repoRoot, file);
        violations.push(`${item.label}: ${rel}`);
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });
});

