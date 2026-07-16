import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));

const requiredArtifacts = [
  'wasm/near_signer/pkg/wasm_signer_worker.js',
  'wasm/near_signer/pkg/wasm_signer_worker.d.ts',
  'wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
  'wasm/threshold_prf/pkg/threshold_prf.js',
  'wasm/threshold_prf/pkg/threshold_prf.d.ts',
  'wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
  'wasm/evm_crypto/pkg/evm_crypto.js',
  'wasm/evm_crypto/pkg/evm_crypto.d.ts',
  'wasm/evm_crypto/pkg/evm_crypto_bg.wasm',
  'wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker.js',
  'wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker.d.ts',
  'wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker_bg.wasm',
];

const missingArtifacts = requiredArtifacts.filter(
  (artifact) => !existsSync(join(repoRoot, artifact)),
);
const autoBuildMissingArtifacts = process.env.SEAMS_D1_LOCAL_WASM_AUTO_BUILD !== '0';

if (missingArtifacts.length === 0) {
  process.exit(0);
}

printMissingArtifacts();

if (!autoBuildMissingArtifacts) {
  console.error(
    '[d1-local] WASM auto-build is disabled; run pnpm -C packages/sdk-web run build:wasm.',
  );
  process.exit(1);
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

function printMissingArtifacts() {
  console.log('[d1-local] Missing generated WASM artifacts:');
  for (const artifact of missingArtifacts) {
    console.log(`[d1-local] - ${artifact}`);
  }
}
