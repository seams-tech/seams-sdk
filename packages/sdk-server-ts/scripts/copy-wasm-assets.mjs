import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const serverRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = path.resolve(serverRoot, '../..');

const assets = [
  {
    source: 'wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
    target: 'dist/esm/wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
  },
  {
    source: 'wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
    target: 'dist/esm/wasm/threshold_prf/pkg/threshold_prf_bg.wasm',
  },
  {
    source: 'wasm/eth_signer/pkg/eth_signer_bg.wasm',
    target: 'dist/esm/wasm/eth_signer/pkg/eth_signer_bg.wasm',
  },
];

function copyAsset(asset) {
  const sourcePath = path.join(repoRoot, asset.source);
  const targetPath = path.join(serverRoot, asset.target);
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`Missing server package WASM asset: ${sourcePath}`);
  }
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.copyFileSync(sourcePath, targetPath);
}

for (const asset of assets) {
  copyAsset(asset);
}
