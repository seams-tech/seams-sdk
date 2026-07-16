import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, readlinkSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const REPOSITORY_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const INPUT_ROOTS = Object.freeze([
  '.cargo/config.toml',
  '.github/workflows/ci.yml',
  'justfile',
  'pnpm-lock.yaml',
  'rustfmt.toml',
  'crates/ed25519-yao',
  'crates/ed25519-yao-cloudflare-bench',
  'crates/router-ab-core',
  'crates/router-ab-ecdsa-derivation',
  'crates/router-ab-ed25519-yao',
  'crates/router-ab-ed25519-yao-client',
  'crates/router-ab-ed25519-yao-protocol',
  'crates/router-ab-dev',
  'crates/signer-core',
  'packages/shared-ts/src',
  'packages/sdk-server-ts/src',
  'packages/sdk-web/tsconfig.json',
  'packages/sdk-web/src',
  'tests/playwright.config.ts',
  'tests/playwright.intended.ci.config.ts',
  'tests/playwright.intended.config.ts',
  'tests/playwright.yaos-local.config.ts',
  'tests/e2e/intended-behaviours',
  'tests/scripts/check-ed25519-yao-near-signing-boundaries.mjs',
  'tests/scripts/check-intended-behaviour-contract-boundaries.mjs',
  'tests/scripts/ensure-intended-google-token.mjs',
  'tests/scripts/intended-google-oidc-env.mjs',
  'tests/scripts/seed-intended-local-console.mjs',
  'tests/scripts/start-intended-services.mjs',
  'tests/scripts/check-yaos-local-types.mjs',
  'tests/unit',
  'tests/tsconfig.playwright.json',
  'tests/yaos-local-test-slice.json',
  'tests/yaos-local',
  'tools/ed25519-yao-generator',
  'tools/ed25519-yao-verifier',
]);
const EXCLUDED_DIRECTORY_NAMES = new Set([
  '.git',
  '.lake',
  '.tmp',
  '_build',
  '__pycache__',
  'build',
  'bundled',
  'node_modules',
  'pkg',
  'pkg-phase5',
  'target',
]);
const EXCLUDED_FILES = new Set([
  'crates/ed25519-yao-cloudflare-bench/docs/phase13a-local-preflight-evidence-v1.json',
]);
const EXCLUDED_PATH_PREFIXES = Object.freeze([
  'crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary/tools/',
]);
const MAX_INPUT_FILES = 4_096;
const MAX_TOTAL_BYTES = 128 * 1024 * 1024;

function repositoryPath(absolutePath) {
  const path = relative(REPOSITORY_ROOT, absolutePath).split(sep).join('/');
  if (path.length === 0 || path.startsWith('../') || path.includes('\0')) {
    throw new Error('local-readiness input escaped the repository root');
  }
  return path;
}

function isExcludedPath(path) {
  for (const prefix of EXCLUDED_PATH_PREFIXES) {
    if (path.startsWith(prefix)) return true;
  }
  return false;
}

function collectPath(absolutePath, entries) {
  const path = repositoryPath(absolutePath);
  if (isExcludedPath(path)) return;
  const metadata = lstatSync(absolutePath);
  if (metadata.isSymbolicLink()) {
    entries.push(
      Object.freeze({ path, kind: 'symlink', bytes: Buffer.from(readlinkSync(absolutePath)) }),
    );
    return;
  }
  if (metadata.isDirectory()) {
    if (EXCLUDED_DIRECTORY_NAMES.has(path.split('/').at(-1))) {
      return;
    }
    const children = readdirSync(absolutePath, { withFileTypes: true })
      .map((entry) => entry.name)
      .sort();
    for (const child of children) {
      collectPath(join(absolutePath, child), entries);
    }
    return;
  }
  if (!metadata.isFile()) {
    throw new Error(`unsupported local-readiness input type: ${path}`);
  }
  if (!EXCLUDED_FILES.has(path)) {
    entries.push(Object.freeze({ path, kind: 'file', bytes: readFileSync(absolutePath) }));
  }
}

export function collectLocalReadinessInputs() {
  const entries = [];
  for (const root of INPUT_ROOTS) {
    collectPath(join(REPOSITORY_ROOT, root), entries);
  }
  entries.sort((left, right) => left.path.localeCompare(right.path));
  if (entries.length === 0 || entries.length > MAX_INPUT_FILES) {
    throw new Error('local-readiness input file count is outside its fixed bound');
  }
  const aggregate = createHash('sha256');
  let totalBytes = 0;
  for (const entry of entries) {
    totalBytes += entry.bytes.length;
    if (totalBytes > MAX_TOTAL_BYTES) {
      throw new Error('local-readiness input bytes exceed the fixed bound');
    }
    const digest = createHash('sha256').update(entry.bytes).digest('hex');
    aggregate.update(entry.kind);
    aggregate.update('\0');
    aggregate.update(entry.path);
    aggregate.update('\0');
    aggregate.update(String(entry.bytes.length));
    aggregate.update('\0');
    aggregate.update(digest);
    aggregate.update('\0');
  }
  return Object.freeze({
    schema: 'ed25519_yao_local_readiness_inputs_v1',
    file_count: entries.length,
    total_bytes: totalBytes,
    sha256: aggregate.digest('hex'),
  });
}

function main() {
  process.stdout.write(`${JSON.stringify(collectLocalReadinessInputs(), null, 2)}\n`);
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
