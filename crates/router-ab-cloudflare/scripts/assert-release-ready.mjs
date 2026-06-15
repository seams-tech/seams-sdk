import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, '..', '..', '..');

const blockers = [];

const strictWorkerSource = readRepoFile('crates/router-ab-cloudflare/src/strict_worker.rs');
if (strictWorkerSource.includes('strict SigningWorker normal-signing handler is not configured')) {
  blockers.push('P1: strict SigningWorker normal-signing handler is still fail-closed');
}
if (
  strictWorkerSource.includes(
    'strict SigningWorker normal signing requires persisted server round-1 nonce material',
  )
) {
  blockers.push(
    'P1: strict SigningWorker normal-signing finalizer still lacks server round-1 nonce persistence',
  );
}

const p2Tests = [
  'durable_object_handler_stores_full_derivation_ceremony_lifecycle',
  'durable_object_handler_rejects_skipped_derivation_ceremony_activation',
  'durable_object_handler_rejects_derivation_ceremony_scope_change',
  'durable_object_handler_rejects_terminal_derivation_ceremony_rewrite',
];
const p2Result = runCargoTest(p2Tests);
if (p2Result.status !== 0) {
  blockers.push('P2: Cloudflare derivation ceremony lifecycle tests failed');
}

if (blockers.length > 0) {
  console.error('Router A/B release blockers remain:');
  for (const blocker of blockers) {
    console.error(`- ${blocker}`);
  }
  if (p2Result.status !== 0) {
    console.error('\nP2 ceremony lifecycle test output:');
    process.stderr.write(p2Result.output);
  }
  process.exit(1);
}

console.log('Router A/B release blockers clear.');

function readRepoFile(path) {
  return readFileSync(join(repoRoot, path), 'utf8');
}

function runCargoTest(testNames) {
  let output = '';
  for (const testName of testNames) {
    const args = [
      'test',
      '--manifest-path',
      'crates/router-ab-cloudflare/Cargo.toml',
      '--test',
      'bindings',
      testName,
      '--',
      '--exact',
    ];
    const result = spawnSync('cargo', args, {
      cwd: repoRoot,
      encoding: 'utf8',
    });
    output += `$ cargo ${args.join(' ')}\n`;
    output += `${result.stdout || ''}${result.stderr || ''}`;
    if ((result.status ?? 1) !== 0) {
      return {
        status: result.status ?? 1,
        output,
      };
    }
    if (!testOutputHasExactlyOnePassingTest(`${result.stdout || ''}${result.stderr || ''}`)) {
      output += `Expected exactly one passing test for ${testName}.\n`;
      return {
        status: 1,
        output,
      };
    }
  }
  return { status: 0, output };
}

function testOutputHasExactlyOnePassingTest(output) {
  return /\ntest result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out;/.test(
    output,
  );
}
