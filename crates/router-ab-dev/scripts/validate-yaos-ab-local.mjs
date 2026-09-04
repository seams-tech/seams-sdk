import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { collectLocalReadinessInputs } from '../../ed25519-yao-cloudflare-bench/scripts/local_readiness_inputs.mjs';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));
const receiptPath = join(
  repoRoot,
  'crates/router-ab-dev/target/phase9c-yaos-ab-local-evidence-v1.json',
);
const lifecycleReportPath = join(
  repoRoot,
  'crates/router-ab-dev/reports/ed25519-yao-local-latency-v1.json',
);
const completedChecks = [];

rmSync(receiptPath, { force: true });
runCheck('canonical Yao derivation', 'cargo', [
  'test',
  '--offline',
  '--manifest-path',
  'crates/signer-core/Cargo.toml',
  '--features',
  'ed25519-yao-derivation',
  '--test',
  'ed25519_yao_derivation',
]);
runCheck('transport-neutral Yao composition', 'cargo', [
  'test',
  '--offline',
  '--manifest-path',
  'crates/router-ab-ed25519-yao/Cargo.toml',
]);
runCheck('Client-owned activation and export boundary', 'cargo', [
  'test',
  '--offline',
  '--manifest-path',
  'crates/router-ab-ed25519-yao-client/Cargo.toml',
  '--all-targets',
]);
runCheck('Client-owned activation and export WASM boundary', 'cargo', [
  'check',
  '--offline',
  '--manifest-path',
  'crates/router-ab-ed25519-yao-client/Cargo.toml',
  '--target',
  'wasm32-unknown-unknown',
  '--lib',
]);
runCheck('SDK Router boundary guard', 'node', [
  'tests/scripts/check-ed25519-yao-near-signing-boundaries.mjs',
]);
runCheck('public Ed25519 export boundary guard', 'node', [
  'tests/scripts/check-key-export-boundaries.mjs',
]);
runCheck('SDK Yao local TypeScript gate', 'node', ['tests/scripts/check-yaos-local-types.mjs']);
runCheck(
  'SDK Router, WASM Client, wallet lifecycle, and process gates',
  './node_modules/.bin/playwright',
  ['test', '-c', 'tests/playwright.yaos-local.config.ts', '--reporter=dot'],
);
runCheck(
  'public local-product registration, NEAR readiness, signing, and export gates',
  './node_modules/.bin/playwright',
  ['test', '-c', 'tests/playwright.yaos-local-product.config.ts', '--reporter=dot'],
);
runCheck('local role boundaries and process lifecycle', 'cargo', [
  'test',
  '--offline',
  '--manifest-path',
  'crates/router-ab-dev/Cargo.toml',
  '--test',
  'ed25519_yao_api',
  '--test',
  'ed25519_yao_delivery',
  '--test',
  'ed25519_yao_input',
  '--test',
  'ed25519_yao_local_profiles',
  '--test',
  'ed25519_yao_router',
  '--test',
  'ed25519_yao_refresh',
  '--test',
  'ed25519_yao_stream',
  '--test',
  'local_worker_http',
]);
runCheck('untrusted Yao stream parser mutation smoke', 'cargo', [
  'test',
  '--offline',
  '--manifest-path',
  'crates/ed25519-yao/Cargo.toml',
  'deterministic_untrusted_stream_parser_fuzz_smoke',
]);
runCheck('recipient-package parser mutation smoke', 'cargo', [
  'test',
  '--offline',
  '--manifest-path',
  'crates/router-ab-ed25519-yao-protocol/Cargo.toml',
  'deterministic_recipient_package_parser_fuzz_smoke',
]);
runCheck('constant-time code-generation guard', 'node', [
  'crates/ed25519-yao/scripts/check_constant_time_codegen.mjs',
]);

writePhase9CReceipt();
console.log('validate:yaos-ab-local passed');

function runCheck(label, command, args) {
  console.log(`\n[validate:yaos-ab-local] ${label}`);
  const result = spawnCheck(command, args);
  if (result.status !== 0) {
    throw new Error(`${label} failed with status ${String(result.status)}`);
  }
  completedChecks.push(label);
}

function spawnCheck(command, args) {
  return spawnSync(command, args, {
    cwd: repoRoot,
    env: process.env,
    stdio: 'inherit',
  });
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function writePhase9CReceipt() {
  const receipt = {
    schema: 'seams-ed25519-yao-phase9c-validation-receipt-v2',
    gate: 'validate:yaos-ab-local',
    result: 'pass',
    production_eligible: false,
    generated_at: new Date().toISOString(),
    validated_inputs: collectLocalReadinessInputs(),
    completed_checks: completedChecks,
    lifecycle_report: {
      path: 'crates/router-ab-dev/reports/ed25519-yao-local-latency-v1.json',
      sha256: sha256(readFileSync(lifecycleReportPath)),
    },
  };
  mkdirSync(dirname(receiptPath), { recursive: true });
  const pendingPath = `${receiptPath}.pending`;
  writeFileSync(pendingPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  renameSync(pendingPath, receiptPath);
}
