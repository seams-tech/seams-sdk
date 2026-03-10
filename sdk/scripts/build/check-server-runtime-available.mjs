#!/usr/bin/env node
import { access } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const sdkRoot = path.resolve(scriptDir, '../..');
const requiredOutputs = [
  'dist/esm/server/index.js',
  'dist/esm/server/router/express.js',
  'dist/esm/server/router/cloudflare.js',
];

const missingOutputs = [];

for (const relativePath of requiredOutputs) {
  try {
    await access(path.join(sdkRoot, relativePath));
  } catch {
    missingOutputs.push(relativePath);
  }
}

if (missingOutputs.length > 0) {
  console.error('Missing SDK server runtime build outputs:');
  for (const relativePath of missingOutputs) {
    console.error(`- ${relativePath}`);
  }
  process.exit(1);
}

console.log('SDK server runtime build outputs are available');
