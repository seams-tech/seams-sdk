import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));
const manifestPath = 'crates/router-ab-dev/Cargo.toml';
const samplePrefix = 'YAOS_AB_LOCAL_SAMPLE ';
const sampleSchema = 'seams-ed25519-yao-local-latency-sample-v2';
const reportSchema = 'seams-ed25519-yao-local-latency-report-v2';
const profiles = Object.freeze([
  Object.freeze({
    label: 'ed25519-yao-product-topology',
    test: 'product_topology_completes_local_ed25519_yao_registration',
  }),
]);

const options = parseOptions(process.argv.slice(2));
const reportProfiles = [];

for (const profile of profiles) {
  process.stderr.write(`warming ${profile.label}: ${options.warmups} run(s)\n`);
  for (let warmup = 0; warmup < options.warmups; warmup += 1) {
    runSample(profile, options.buildProfile);
  }

  const samples = [];
  process.stderr.write(`measuring ${profile.label}: ${options.samples} run(s)\n`);
  for (let index = 0; index < options.samples; index += 1) {
    samples.push(runSample(profile, options.buildProfile));
    process.stderr.write(`  ${profile.label} ${index + 1}/${options.samples}\r`);
  }
  process.stderr.write('\n');
  reportProfiles.push(summarizeProfile(profile.label, samples));
}

const report = {
  schema: reportSchema,
  evidence_kind: 'nonproduction_local_process',
  production_eligible: false,
  deployed_evidence: false,
  generated_at: new Date().toISOString(),
  samples_per_profile: options.samples,
  warmups_per_profile: options.warmups,
  rust_build_profile: options.buildProfile,
  percentile_method: 'nearest_rank',
  statistically_sufficient_for_p99: options.samples >= 100,
  profiles: reportProfiles,
};
const encoded = `${JSON.stringify(report, null, 2)}\n`;

if (options.output === undefined) {
  process.stdout.write(encoded);
} else {
  const outputPath = workspaceOutputPath(options.output);
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, encoded, 'utf8');
  process.stdout.write(`${relative(repoRoot, outputPath)}\n`);
}

function parseOptions(args) {
  let samples = 100;
  let warmups = 1;
  let buildProfile = 'release';
  let output;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--samples') {
      samples = positiveInteger(requiredValue(args, ++index, arg), arg);
      continue;
    }
    if (arg === '--warmups') {
      warmups = nonnegativeInteger(requiredValue(args, ++index, arg), arg);
      continue;
    }
    if (arg === '--build-profile') {
      buildProfile = requiredValue(args, ++index, arg);
      if (!['release', 'dev'].includes(buildProfile)) {
        fail(`invalid --build-profile value: ${buildProfile}`);
      }
      continue;
    }
    if (arg === '--output') {
      output = requiredValue(args, ++index, arg);
      continue;
    }
    if (arg === '--help' || arg === '-h') {
      printUsage();
      process.exit(0);
    }
    fail(`unknown argument: ${arg}`);
  }

  return Object.freeze({ samples, warmups, buildProfile, output });
}

function requiredValue(args, index, flag) {
  const value = args[index];
  if (value === undefined || value.startsWith('--')) {
    fail(`${flag} requires a value`);
  }
  return value;
}

function positiveInteger(value, flag) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    fail(`${flag} must be a positive integer`);
  }
  return parsed;
}

function nonnegativeInteger(value, flag) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    fail(`${flag} must be a nonnegative integer`);
  }
  return parsed;
}

function runSample(profile, buildProfile) {
  const cargoArgs = [
    'test',
    '--offline',
    '--manifest-path',
    manifestPath,
    '--test',
    'local_worker_http',
    profile.test,
    '--',
    '--exact',
    '--nocapture',
  ];
  if (buildProfile === 'release') {
    cargoArgs.splice(1, 0, '--release');
  }
  const result = spawnSync(
    'cargo',
    cargoArgs,
    {
      cwd: repoRoot,
      encoding: 'utf8',
      env: process.env,
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  if (result.status !== 0) {
    process.stdout.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    fail(`measurement test failed for ${profile.label}`);
  }
  const sample = parseSample(result.stdout, profile.label);
  validateSample(sample, profile.label);
  return sample;
}

function parseSample(stdout, expectedProfile) {
  const lines = stdout.split(/\r?\n/u);
  const encodedSamples = [];
  for (const line of lines) {
    if (line.startsWith(samplePrefix)) {
      encodedSamples.push(line.slice(samplePrefix.length));
    }
  }
  if (encodedSamples.length !== 1) {
    fail(`expected one sample for ${expectedProfile}; received ${encodedSamples.length}`);
  }
  try {
    return JSON.parse(encodedSamples[0]);
  } catch (error) {
    fail(`invalid sample JSON for ${expectedProfile}: ${error.message}`);
  }
}

function validateSample(sample, expectedProfile) {
  if (
    sample.schema !== sampleSchema ||
    sample.profile !== expectedProfile ||
    !Number.isSafeInteger(sample.registration_microseconds) ||
    sample.registration_microseconds < 1
  ) {
    fail(`sample contract mismatch for ${expectedProfile}`);
  }
}

function summarizeProfile(profile, samples) {
  const registrationValues = [];
  for (const sample of samples) {
    registrationValues.push(sample.registration_microseconds);
  }
  return {
    profile,
    operations: {
      registration: summarizeMicroseconds(registrationValues),
    },
  };
}

function summarizeMicroseconds(values) {
  const sorted = [...values].sort(compareNumbers);
  return {
    p50_microseconds: nearestRank(sorted, 0.5),
    p95_microseconds: nearestRank(sorted, 0.95),
    p99_microseconds: nearestRank(sorted, 0.99),
    minimum_microseconds: sorted[0],
    maximum_microseconds: sorted[sorted.length - 1],
  };
}

function compareNumbers(left, right) {
  return left - right;
}

function nearestRank(sorted, percentile) {
  const index = Math.max(0, Math.ceil(percentile * sorted.length) - 1);
  return sorted[index];
}

function workspaceOutputPath(value) {
  const candidate = isAbsolute(value) ? resolve(value) : resolve(repoRoot, value);
  const pathFromRoot = relative(repoRoot, candidate);
  if (pathFromRoot.startsWith('..') || isAbsolute(pathFromRoot)) {
    fail('--output must stay inside the repository');
  }
  return candidate;
}

function printUsage() {
  process.stdout.write(`usage: node measure-ed25519-yao-local.mjs [options]\n\nOptions:\n  --samples N            measured registration samples (default: 100)\n  --warmups N            discarded warmups (default: 1)\n  --build-profile NAME   release or dev (default: release)\n  --output PATH          write the JSON report inside the repository\n`);
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
