import { existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

const require = createRequire(
  new URL('../../wallet-console-server-ts/package.json', import.meta.url),
);
const sdkServerRoot = dirname(require.resolve('@seams/sdk-server/package.json'));
const requiredArtifacts = [
  'dist/esm/wasm/near_signer/pkg/wasm_signer_worker.js',
  'dist/esm/wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
  'dist/esm/wasm/evm_crypto/pkg/evm_crypto.js',
  'dist/esm/wasm/evm_crypto/pkg/evm_crypto_bg.wasm',
  'dist/esm/wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker.js',
  'dist/esm/wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker_bg.wasm',
  'dist/esm/wasm/shamir3pass_runtime/pkg/shamir3pass_runtime.js',
  'dist/esm/wasm/shamir3pass_runtime/pkg/shamir3pass_runtime_bg.wasm',
];

const missingArtifacts = requiredArtifacts.filter(
  (artifact) => !existsSync(join(sdkServerRoot, artifact)),
);

if (missingArtifacts.length > 0) {
  console.error('[d1-local] The installed @seams/sdk-server package is missing WASM assets:');
  for (const artifact of missingArtifacts) {
    console.error(`[d1-local] - ${artifact}`);
  }
  process.exit(1);
}
