import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, '..', '..', '..');

const blockers = [];

const strictWorkerSource = readRepoFile('crates/router-ab-cloudflare/src/strict_worker.rs');
if (strictWorkerSource.includes('strict SigningWorker normal-signing handler is not configured')) {
  blockers.push('P1: strict SigningWorker normal-signing handler is still fail-closed');
}

const durableObjectSource = readRepoFile('crates/router-ab-cloudflare/src/durable_object.rs');
if (!durableObjectSource.includes('CloudflareDerivationCeremony')) {
  blockers.push(
    'P2: Cloudflare Durable Object storage has no dedicated derivation ceremony lifecycle record',
  );
}

if (blockers.length > 0) {
  console.error('Router A/B release blockers remain:');
  for (const blocker of blockers) {
    console.error(`- ${blocker}`);
  }
  process.exit(1);
}

console.log('Router A/B release blockers clear.');

function readRepoFile(path) {
  return readFileSync(join(repoRoot, path), 'utf8');
}
