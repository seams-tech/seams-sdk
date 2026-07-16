import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
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
const expectedProfiles = Object.freeze([
  'ed25519-yao-one-account',
  'ed25519-yao-two-administrator',
]);
const expectedLifecycleVectors = Object.freeze([
  'registration',
  'activation',
  'recovery',
  'refresh',
  'exact_export',
  'post_refresh_ordinary_signing',
]);
const completedChecks = [];
const lifecycleEvidenceDirectory = mkdtempSync(join(tmpdir(), 'seams-phase9c-evidence-'));

rmSync(receiptPath, { force: true });

try {
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
  runCheck('managed product contract boundary guard', 'node', [
    'tests/scripts/check-intended-behaviour-contract-boundaries.mjs',
  ]);
  runCheck('SDK Yao local TypeScript gate', 'node', ['tests/scripts/check-yaos-local-types.mjs']);
  runCheck(
    'SDK Router, WASM Client, wallet lifecycle, and process gates',
    './tests/node_modules/.bin/playwright',
    ['test', '-c', 'tests/playwright.yaos-local.config.ts', '--reporter=dot'],
  );
  runCheck(
    'public local-product registration, NEAR readiness, signing, and export gates',
    './tests/node_modules/.bin/playwright',
    ['test', '-c', 'tests/playwright.yaos-local-product.config.ts', '--reporter=dot'],
  );
  runCheck(
    'local role boundaries and process lifecycle',
    'cargo',
    [
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
    ],
    { SEAMS_YAOS_AB_PHASE9C_EVIDENCE_DIR: lifecycleEvidenceDirectory },
  );
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
} finally {
  rmSync(lifecycleEvidenceDirectory, { recursive: true, force: true });
}

function runCheck(label, command, args, env = {}) {
  console.log(`\n[validate:yaos-ab-local] ${label}`);
  const result = spawnCheck(command, args, env);
  if (result.status !== 0) {
    throw new Error(`${label} failed with status ${String(result.status)}`);
  }
  completedChecks.push(label);
}

function spawnCheck(command, args, env) {
  return spawnSync(command, args, {
    cwd: repoRoot,
    env: { ...process.env, ...env },
    stdio: 'inherit',
  });
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function requireObject(value, field) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`invalid Phase 9C lifecycle evidence object: ${field}`);
  }
  return value;
}

function requireExact(value, expected, field) {
  if (value !== expected) {
    throw new Error(`invalid Phase 9C lifecycle evidence field: ${field}`);
  }
}

function requireExactStringArray(value, expected, field) {
  if (!Array.isArray(value) || value.length !== expected.length) {
    throw new Error(`invalid Phase 9C lifecycle evidence array: ${field}`);
  }
  for (let index = 0; index < expected.length; index += 1) {
    requireExact(value[index], expected[index], `${field}.${index}`);
  }
}

function loadLifecycleEvidence(profile) {
  const path = join(lifecycleEvidenceDirectory, `${profile}.json`);
  const evidence = requireObject(JSON.parse(readFileSync(path, 'utf8')), profile);
  requireExact(
    evidence.schema,
    'seams-ed25519-yao-phase9c-lifecycle-evidence-v1',
    `${profile}.schema`,
  );
  requireExact(evidence.profile, profile, `${profile}.profile`);
  requireExactStringArray(
    evidence.lifecycle_vectors,
    expectedLifecycleVectors,
    `${profile}.vectors`,
  );
  for (const field of [
    'export_public_key_matches_registered',
    'export_standard_signature_verified',
    'recovery_preserved_identity',
    'refresh_preserved_identity',
    'deriver_processes_terminated_before_signing',
    'ordinary_signing_standard_signature_verified',
  ]) {
    requireExact(evidence[field], true, `${profile}.${field}`);
  }
  requireExact(
    evidence.exported_public_key_sha256,
    evidence.registered_public_key_sha256,
    `${profile}.public_key_sha256`,
  );
  for (const field of [
    'ordinary_signing_deriver_a_requests',
    'ordinary_signing_deriver_b_requests',
    'ordinary_signing_deriver_a_to_b_bytes',
    'ordinary_signing_deriver_b_to_a_bytes',
  ]) {
    requireExact(evidence[field], 0, `${profile}.${field}`);
  }
  return evidence;
}

function writePhase9CReceipt() {
  const lifecycleEvidence = [];
  for (const profile of expectedProfiles) {
    lifecycleEvidence.push(loadLifecycleEvidence(profile));
  }
  const receipt = {
    schema: 'seams-ed25519-yao-phase9c-validation-receipt-v1',
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
    lifecycle_evidence: lifecycleEvidence,
  };
  mkdirSync(dirname(receiptPath), { recursive: true });
  const pendingPath = `${receiptPath}.pending`;
  writeFileSync(pendingPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  renameSync(pendingPath, receiptPath);
}
