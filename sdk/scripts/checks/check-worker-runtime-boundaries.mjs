#!/usr/bin/env node
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findWorkerRuntimeBoundaryViolations } from '../lib/worker-runtime-boundaries.mjs';

function formatLocation(violation) {
  if (typeof violation.line === 'number' && Number.isFinite(violation.line)) {
    return `${violation.file}:${violation.line}`;
  }
  return String(violation.file);
}

function main() {
  const scriptDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(scriptDir, '../../..');

  const result = findWorkerRuntimeBoundaryViolations(repoRoot);
  if (result.error) {
    console.error(result.error);
    process.exit(1);
  }

  let total = 0;
  for (const check of result.checks) {
    if (!check.violations.length) continue;
    total += check.violations.length;
    console.error(
      `[check-worker-runtime-boundaries] ${check.id} failed (${check.violations.length}): ${check.description}`,
    );
    for (const violation of check.violations) {
      console.error(
        `  - ${formatLocation(violation)} matched "${violation.pattern}" (${violation.text})`,
      );
    }
  }

  if (total > 0) {
    process.exit(1);
  }

  console.log('[check-worker-runtime-boundaries] OK');
}

main();
