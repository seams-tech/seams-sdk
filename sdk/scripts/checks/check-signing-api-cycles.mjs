#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findSigningApiCrossLayerCycles } from '../lib/signing-api-cycles.mjs';

function main() {
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(scriptDir, '../../..');

  const result = findSigningApiCrossLayerCycles(repoRoot);
  if (result.error) {
    console.error(result.error);
    process.exit(1);
  }

  if (!result.cycles.length) {
    console.log('[check-signing-api-cycles] OK: no api/lower-layer cycles detected');
    return;
  }

  console.error('[check-signing-api-cycles] failed: detected api/lower-layer cycles');
  for (let i = 0; i < result.cycles.length; i += 1) {
    const cycle = result.cycles[i];
    console.error(`  cycle-${i + 1}:`);
    for (const filePath of cycle) {
      console.error(`    - ${filePath}`);
    }
  }
  process.exit(1);
}

main();
