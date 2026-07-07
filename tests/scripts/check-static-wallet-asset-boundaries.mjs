#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const VITE_HELPER_PATH = 'packages/sdk-web/src/plugins/vite.ts';

function readRepoSource(relativePath) {
  return fs.readFileSync(path.join(REPO_ROOT, relativePath), 'utf8');
}

function sourceRangeBetween(source, startNeedle, endNeedle) {
  const start = source.indexOf(startNeedle);
  if (start < 0) throw new Error(`missing source range start: ${startNeedle}`);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  if (end < 0) throw new Error(`missing source range end: ${endNeedle}`);
  return source.slice(start, end);
}

function assertNoMarkers(source, label, markers) {
  const offenders = markers.filter((marker) => source.includes(marker));
  if (offenders.length > 0) {
    throw new Error(`${label} contains forbidden marker(s): ${offenders.join(', ')}`);
  }
}

function assertContains(source, label, marker) {
  if (!source.includes(marker)) throw new Error(`${label} is missing required marker: ${marker}`);
}

function assertViteHelperBoundaries() {
  const source = readRepoSource(VITE_HELPER_PATH);
  assertNoMarkers(source, VITE_HELPER_PATH, ['export function seamsWasmMime']);

  const walletService = sourceRangeBetween(
    source,
    'export function seamsWalletService',
    '/**\n * Dev plugin: serve the RP ID related-origin helper',
  );
  assertNoMarkers(walletService, 'seamsWalletService', [
    'Cross-Origin-Opener-Policy',
    'Cross-Origin-Resource-Policy',
    'Content-Security-Policy',
    'Permissions-Policy',
  ]);

  const devHeaders = sourceRangeBetween(
    source,
    'export function seamsHeaders',
    'function createDevServerPlugin',
  );
  assertNoMarkers(devHeaders, 'seamsHeaders', [
    'Cross-Origin-Opener-Policy',
    'Content-Security-Policy',
    'Permissions-Policy',
    'buildWalletCsp',
    'buildPermissionsPolicy',
  ]);
  assertContains(devHeaders, 'seamsHeaders', "if (coepMode !== 'off')");

  const devServer = sourceRangeBetween(
    source,
    'function createDevServerPlugin',
    '// === Build-time helper',
  );
  assertContains(devServer, 'createDevServerPlugin', 'options.setDevHeaders === true');
  assertNoMarkers(devServer, 'createDevServerPlugin', [
    'options.setDevHeaders !== false',
    'seamsWasmMime',
    "devCSP: 'strict'",
  ]);

  const buildHeaders = sourceRangeBetween(
    source,
    'export function seamsBuildHeaders',
    'export function computeDevPermissionsPolicy',
  );
  assertNoMarkers(buildHeaders, 'seamsBuildHeaders', [
    'Cross-Origin-Opener-Policy',
    'Content-Security-Policy',
    'Permissions-Policy',
    'buildWalletCsp',
    'buildPermissionsPolicy',
  ]);
  assertContains(buildHeaders, 'seamsBuildHeaders', "coepMode === 'off'");
}

assertViteHelperBoundaries();
console.log('[check-static-wallet-asset-boundaries] OK');
