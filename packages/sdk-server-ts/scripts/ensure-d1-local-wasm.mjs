import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));

const requiredArtifacts = [
  'wasm/near_signer/pkg/wasm_signer_worker.js',
  'wasm/near_signer/pkg/wasm_signer_worker.d.ts',
  'wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
  'wasm/near_signer/pkg-server/wasm_signer_worker.js',
  'wasm/near_signer/pkg-server/wasm_signer_worker.d.ts',
  'wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm',
  'wasm/threshold_prf/pkg/threshold_prf.js',
  'wasm/threshold_prf/pkg/threshold_prf.d.ts',
  'wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
  'wasm/eth_signer/pkg/eth_signer.js',
  'wasm/eth_signer/pkg/eth_signer.d.ts',
  'wasm/eth_signer/pkg/eth_signer_bg.wasm',
];

const missingArtifacts = requiredArtifacts.filter((artifact) => !existsSync(join(repoRoot, artifact)));

if (missingArtifacts.length === 0) {
  process.exit(0);
}

console.log('[d1-local] Missing generated WASM artifacts:');
for (const artifact of missingArtifacts) {
  console.log(`[d1-local] - ${artifact}`);
}
console.log('[d1-local] Building WASM artifacts with pnpm -C packages/sdk-web run build:wasm...');

const result = spawnSync('pnpm', ['-C', 'packages/sdk-web', 'run', 'build:wasm'], {
  cwd: repoRoot,
  env: process.env,
  stdio: 'inherit',
});

if (result.error) {
  console.error(`[d1-local] Failed to start WASM build: ${result.error.message}`);
  process.exit(1);
}

if (result.signal) {
  console.error(`[d1-local] WASM build stopped by signal ${result.signal}`);
  process.exit(1);
}

process.exit(result.status ?? 1);
