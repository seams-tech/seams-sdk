#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';

async function fileExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

function hasUnsupportedSideEffectsGlobs(sideEffects) {
  if (!Array.isArray(sideEffects)) return false;
  return sideEffects.some((value) => {
    return typeof value === 'string' && value.startsWith('./snippets/') && value.includes('*');
  });
}

async function fixPkgDir(pkgDir) {
  const packageJsonPath = path.join(pkgDir, 'package.json');
  if (!(await fileExists(packageJsonPath))) return;

  const raw = await fs.readFile(packageJsonPath, 'utf8');
  const parsed = JSON.parse(raw);

  if (!hasUnsupportedSideEffectsGlobs(parsed.sideEffects)) return;

  parsed.sideEffects = false;
  await fs.writeFile(packageJsonPath, `${JSON.stringify(parsed, null, 2)}\n`);
}

async function main() {
  const pkgDirs = process.argv.slice(2);
  if (pkgDirs.length === 0) {
    console.error('Usage: fix-wasm-pack-sideeffects.mjs <pkgDir...>');
    process.exit(1);
  }

  for (const pkgDir of pkgDirs) {
    await fixPkgDir(pkgDir);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
