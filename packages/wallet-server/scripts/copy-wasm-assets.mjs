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
    source: 'wasm/evm_crypto/pkg/evm_crypto_bg.wasm',
    target: 'dist/esm/wasm/evm_crypto/pkg/evm_crypto_bg.wasm',
  },
  {
    source: 'wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker_bg.wasm',
    target:
      'dist/esm/wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker_bg.wasm',
  },
  {
    source: 'wasm/shamir3pass_runtime/pkg/shamir3pass_runtime_bg.wasm',
    target: 'dist/esm/wasm/shamir3pass_runtime/pkg/shamir3pass_runtime_bg.wasm',
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

rewriteBuiltWasmImports(path.join(serverRoot, 'dist', 'esm'));

function rewriteBuiltWasmImports(esmRoot) {
  for (const filePath of listJavaScriptFiles(esmRoot)) {
    const source = fs.readFileSync(filePath, 'utf8');
    const rewritten = rewriteWasmImportsInFile(source, filePath, esmRoot);
    if (rewritten !== source) fs.writeFileSync(filePath, rewritten);
  }
}

function rewriteWasmImportsInFile(source, filePath, esmRoot) {
  const pattern =
    /(?:\.\.\/)+wasm\/(near_signer|evm_crypto|router_ab_ecdsa_signing_worker|shamir3pass_runtime)\/pkg\/([A-Za-z0-9_]+\.wasm)/gu;
  let rewritten = '';
  let cursor = 0;
  for (const match of source.matchAll(pattern)) {
    rewritten += source.slice(cursor, match.index);
    rewritten += relativeModulePath(
      path.dirname(filePath),
      path.join(esmRoot, 'wasm', match[1], 'pkg', match[2]),
    );
    cursor = match.index + match[0].length;
  }
  return cursor === 0 ? source : rewritten + source.slice(cursor);
}

function listJavaScriptFiles(directory) {
  const files = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...listJavaScriptFiles(entryPath));
    if (entry.isFile() && entry.name.endsWith('.js')) files.push(entryPath);
  }
  return files;
}

function relativeModulePath(fromDirectory, targetPath) {
  const relativePath = path.relative(fromDirectory, targetPath).split(path.sep).join('/');
  return relativePath.startsWith('.') ? relativePath : `./${relativePath}`;
}
