#!/usr/bin/env node
import path from 'node:path';

import {
  d1StagingHttpLines,
  executeD1StagingJsonEndpoint,
  isDirectInvocation,
  normalizeString,
  normalizeStagingMode,
  normalizeStagingOrigin,
  normalizeStagingTimeoutMs,
  packageRoot,
  parseFlagArgs,
  printD1StagingCliError,
  printStagingManifestResult,
  resolvePackagePath,
  writeD1StagingManifest,
} from './d1-staging-config.mjs';

const defaultManifestRoot = path.join(packageRoot, '.wrangler/d1-staging-smoke');
const smokeModes = Object.freeze(['dry-run', 'remote']);

export function buildD1StagingSmokePlan(input = {}) {
  const options = normalizeOptions(input);
  return {
    version: 'seams_d1_staging_smoke_v1',
    generatedAtIso: options.generatedAtIso,
    mode: options.mode,
    timeoutMs: options.timeoutMs,
    endpoints: smokeEndpoints(options),
  };
}

export async function runD1StagingSmoke(input = {}) {
  const options = normalizeOptions(input);
  const plan = buildD1StagingSmokePlan(options);
  const checks = [];

  if (options.mode === 'remote') {
    for (const endpoint of plan.endpoints) {
      checks.push(
        await executeD1StagingJsonEndpoint({
          endpoint,
          fetchImpl: options.fetchImpl,
          nonJsonBodyLabel: 'Staging smoke endpoint',
          timeoutMs: options.timeoutMs,
        }),
      );
    }
  }

  const manifest = {
    ...plan,
    checks,
  };
  return writeD1StagingManifest(options, defaultManifestRoot, manifest);
}

async function main() {
  try {
    const result = await runD1StagingSmoke(parseArgs(process.argv.slice(2)));
    printStagingManifestResult(result, 'D1 staging smoke manifest', 'Dry run endpoints:', d1StagingHttpLines(result.manifest.endpoints));
  } catch (error) {
    printD1StagingCliError(error);
  }
}

function parseArgs(args) {
  return parseFlagArgs(args, {
    consoleOrigin: '',
    generatedAtIso: '',
    manifestPath: '',
    mode: 'dry-run',
    gatewayOrigin: '',
    timeoutMs: '',
  }, {
    '--console-origin': 'consoleOrigin',
    '--generated-at': 'generatedAtIso',
    '--manifest': 'manifestPath',
    '--mode': 'mode',
    '--gateway-origin': 'gatewayOrigin',
    '--timeout-ms': 'timeoutMs',
  });
}

function normalizeOptions(input) {
  const mode = normalizeStagingMode(input.mode, smokeModes, 'staging smoke');
  return {
    consoleOrigin: normalizeStagingOrigin(input.consoleOrigin, '--console-origin', {
      allowHttpInDryRun: true,
      mode,
    }),
    gatewayOrigin: normalizeStagingOrigin(input.gatewayOrigin, '--gateway-origin', {
      allowHttpInDryRun: true,
      mode,
    }),
    generatedAtIso: normalizeString(input.generatedAtIso) || new Date().toISOString(),
    manifestPath: normalizeString(input.manifestPath),
    mode,
    timeoutMs: normalizeStagingTimeoutMs(input.timeoutMs),
    fetchImpl: input.fetchImpl || globalThis.fetch,
  };
}

function smokeEndpoints(options) {
  return [
    {
      id: 'console_readyz',
      method: 'GET',
      url: `${options.consoleOrigin}/console/readyz`,
      expectedStatus: 200,
      expectedJson: {
        ok: true,
        service: 'console',
      },
    },
    {
      id: 'router_api_readyz',
      method: 'GET',
      url: `${options.gatewayOrigin}/readyz`,
      expectedStatus: 200,
      expectedJson: {
        ok: true,
      },
    },
    {
      id: 'router_api_healthz',
      method: 'GET',
      url: `${options.gatewayOrigin}/healthz`,
      expectedStatus: 200,
      expectedJson: {
        ok: true,
      },
    },
    {
      id: 'signer_custody_ed25519_healthz',
      method: 'GET',
      url: `${options.gatewayOrigin}/router-ab/ed25519/healthz`,
      expectedStatus: 200,
      expectedJson: {
        ok: true,
        configured: true,
      },
    },
    {
      id: 'signer_custody_ecdsa_derivation_healthz',
      method: 'GET',
      url: `${options.gatewayOrigin}/router-ab/ecdsa-derivation/healthz`,
      expectedStatus: 200,
      expectedJson: {
        ok: true,
        configured: true,
      },
    },
  ];
}

if (isDirectInvocation(import.meta.url)) await main();
