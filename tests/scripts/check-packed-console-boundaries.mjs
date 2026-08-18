#!/usr/bin/env node

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const consoleCorePackages = [
  { dir: 'packages/console-shared-ts', name: '@seams-internal/console-shared' },
  { dir: 'packages/console-server-ts', name: '@seams-internal/console-server' },
];

const walletConsolePackages = [
  { dir: 'packages/wallet-console-shared-ts', name: '@seams-internal/wallet-console-shared' },
  { dir: 'packages/wallet-console-server-ts', name: '@seams-internal/wallet-console-server' },
];

const forbiddenInConsoleCore = [
  '@seams/sdk',
  '@seams/sdk-server',
  '@seams/wallet',
  '@seams/wallet-server',
  '@seams-internal/wallet-console-shared',
  '@seams-internal/wallet-console-server',
  'packages/sdk-web',
  'packages/sdk-server-ts',
  'packages/wallet-console-shared-ts',
  'packages/wallet-console-server-ts',
];

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: 'utf8', ...opts });
}

function listFilesRecursive(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const child = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listFilesRecursive(child));
    else out.push(child);
  }
  return out;
}

function packInto(packageDir, destination) {
  const output = run('npm', ['pack', '--pack-destination', destination, '--json'], {
    cwd: path.join(repoRoot, packageDir),
  });
  const parsed = JSON.parse(output);
  assert.equal(parsed.length, 1, `npm pack for ${packageDir} produced ${parsed.length} tarballs`);
  return path.join(destination, parsed[0].filename);
}

function unpackTarball(tarballPath, destination) {
  fs.mkdirSync(destination, { recursive: true });
  run('tar', ['-xzf', tarballPath, '-C', destination]);
  return path.join(destination, 'package');
}

function scanForForbiddenSpecifiers(rootDir, forbidden, label) {
  const offenders = [];
  for (const file of listFilesRecursive(rootDir)) {
    if (!/\.(?:js|mjs|cjs|d\.ts|json|map)$/.test(file)) continue;
    if (file.endsWith('package.json')) continue;
    const source = fs.readFileSync(file, 'utf8');
    for (const specifier of forbidden) {
      if (source.includes(specifier)) {
        offenders.push(`${label}: ${path.relative(rootDir, file)} references ${specifier}`);
      }
    }
  }
  return offenders;
}

function checkPackageJsonDependencies(unpackedDir, forbidden, label) {
  const manifest = JSON.parse(fs.readFileSync(path.join(unpackedDir, 'package.json'), 'utf8'));
  const offenders = [];
  for (const section of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
    for (const dep of Object.keys(manifest[section] || {})) {
      if (forbidden.includes(dep)) offenders.push(`${label}: ${section} declares ${dep}`);
    }
  }
  return offenders;
}

function linkIntoNodeModules(nodeModulesDir, name, targetDir) {
  const destination = path.join(nodeModulesDir, name);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.symlinkSync(targetDir, destination, 'dir');
}

// Node resolves bare specifiers from the importing file's realpath, so packed
// packages must physically live inside the workspace node_modules for their
// cross-package imports to resolve — a symlink to the unpacked dir would make
// resolution walk up from the unpack location instead.
function copyIntoNodeModules(nodeModulesDir, name, sourceDir) {
  const destination = path.join(nodeModulesDir, name);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.cpSync(sourceDir, destination, { recursive: true });
}

const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'r105-packed-'));
const tarballDir = path.join(workDir, 'tarballs');
fs.mkdirSync(tarballDir, { recursive: true });

const unpacked = new Map();
for (const pkg of [...consoleCorePackages, ...walletConsolePackages]) {
  const tarball = packInto(pkg.dir, tarballDir);
  const dir = unpackTarball(tarball, path.join(workDir, 'unpacked', path.basename(pkg.dir)));
  unpacked.set(pkg.name, dir);
  console.log(`[packed] ${pkg.name} -> ${path.basename(tarball)}`);
}

const offenders = [];
for (const pkg of consoleCorePackages) {
  const dir = unpacked.get(pkg.name);
  offenders.push(...scanForForbiddenSpecifiers(dir, forbiddenInConsoleCore, pkg.name));
  offenders.push(...checkPackageJsonDependencies(dir, forbiddenInConsoleCore, pkg.name));
}
assert.deepEqual(
  offenders,
  [],
  `packed Console core artifacts contain Wallet references:\n${offenders.join('\n')}`,
);
console.log('[packed] Console core tarballs contain no Wallet references');

// Core-only workspace: only the packed Console core packages plus tslib.
// Resolving and importing the server entry proves the runtime module graph
// never leaves the core boundary.
const coreWorkspace = path.join(workDir, 'core-only');
const coreNodeModules = path.join(coreWorkspace, 'node_modules');
fs.mkdirSync(coreNodeModules, { recursive: true });
for (const pkg of consoleCorePackages) {
  copyIntoNodeModules(coreNodeModules, pkg.name, unpacked.get(pkg.name));
}
linkIntoNodeModules(coreNodeModules, 'tslib', path.join(repoRoot, 'node_modules', 'tslib'));

// console-shared is a source-only TS package resolved by bundlers/tsc; its
// code ships inlined in console-server's dist. Verify its export map points at
// real files, and exercise the runtime graph through the console-server entry.
const consoleSharedDir = unpacked.get('@seams-internal/console-shared');
const consoleSharedManifest = JSON.parse(
  fs.readFileSync(path.join(consoleSharedDir, 'package.json'), 'utf8'),
);
for (const target of Object.values(consoleSharedManifest.exports)) {
  assert.ok(
    fs.existsSync(path.join(consoleSharedDir, target)),
    `console-shared export target missing from tarball: ${target}`,
  );
}

const coreSmoke = path.join(coreWorkspace, 'smoke.mjs');
fs.writeFileSync(
  coreSmoke,
  [
    "const consoleServer = await import('@seams-internal/console-server');",
    "if (typeof consoleServer.createInMemoryConsoleAccountService !== 'function') {",
    "  throw new Error('console-server entry missing account service factory');",
    '}',
    "console.log('[core-only] console-server imports cleanly without Wallet packages');",
  ].join('\n'),
);
run('node', [coreSmoke], { cwd: coreWorkspace });
console.log('[packed] Console core imports without any Wallet package installed');

// Composed workspace: Console core + Wallet Console from tarballs, Wallet
// server linked from the repo (the composition legitimately depends on both).
const composedWorkspace = path.join(workDir, 'composed');
const composedNodeModules = path.join(composedWorkspace, 'node_modules');
fs.mkdirSync(composedNodeModules, { recursive: true });
for (const pkg of [...consoleCorePackages, ...walletConsolePackages]) {
  copyIntoNodeModules(composedNodeModules, pkg.name, unpacked.get(pkg.name));
}
for (const dep of ['tslib', 'bs58', 'express', '@aws-sdk/client-sesv2']) {
  linkIntoNodeModules(composedNodeModules, dep, path.join(repoRoot, 'node_modules', dep));
}
linkIntoNodeModules(
  composedNodeModules,
  '@seams/sdk-server',
  path.join(repoRoot, 'packages', 'sdk-server-ts'),
);

const composedSmoke = path.join(composedWorkspace, 'smoke.mjs');
fs.writeFileSync(
  composedSmoke,
  [
    "const composition = await import('@seams-internal/wallet-console-server/router/consoleComposition');",
    "if (typeof composition.createWalletConsoleRouter !== 'function') {",
    "  throw new Error('wallet-console-server missing createWalletConsoleRouter');",
    '}',
    "if (typeof composition.createHostedWalletConsoleRouter !== 'function') {",
    "  throw new Error('wallet-console-server missing createHostedWalletConsoleRouter');",
    '}',
    "console.log('[composed] wallet console composition imports from packed artifacts');",
  ].join('\n'),
);
run('node', [composedSmoke], { cwd: composedWorkspace });
console.log('[packed] Wallet Console composition builds from packed artifacts');

fs.rmSync(workDir, { recursive: true, force: true });
console.log('[check-packed-console-boundaries] passed');
