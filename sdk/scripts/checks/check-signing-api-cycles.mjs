#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  findForbiddenSignerToAdapterImports,
  findSigningApiCrossLayerCycles,
} from '../lib/signing-api-cycles.mjs';

function main() {
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(scriptDir, '../../..');

  const result = findSigningApiCrossLayerCycles(repoRoot);
  const signerBoundaryResult = findForbiddenSignerToAdapterImports(repoRoot);
  if (result.error) {
    console.error(result.error);
    process.exit(1);
  }
  if (signerBoundaryResult.error) {
    console.error(signerBoundaryResult.error);
    process.exit(1);
  }

  if (!result.cycles.length && !signerBoundaryResult.violations.length) {
    console.log(
      '[check-signing-api-cycles] OK: no api/lower-layer cycles and no signer->chainAdapter imports detected',
    );
    return;
  }

  if (result.cycles.length) {
    console.error('[check-signing-api-cycles] failed: detected api/lower-layer cycles');
    for (let i = 0; i < result.cycles.length; i += 1) {
      const cycle = result.cycles[i];
      console.error(`  cycle-${i + 1}:`);
      for (const filePath of cycle) {
        console.error(`    - ${filePath}`);
      }
    }
  }

  if (signerBoundaryResult.violations.length) {
    console.error(
      '[check-signing-api-cycles] failed: signers/algorithms must not import chainAdaptors',
    );
    for (const violation of signerBoundaryResult.violations) {
      const location = violation.line ? `${violation.file}:${violation.line}` : violation.file;
      console.error(`  - ${location} imports ${violation.specifier} -> ${violation.target}`);
    }
  }

  process.exit(1);
}

main();
