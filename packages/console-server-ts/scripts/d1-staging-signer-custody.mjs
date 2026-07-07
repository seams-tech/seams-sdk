#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

import {
  d1StagingHttpLines,
  executeD1StagingJsonEndpoint,
  isDirectInvocation,
  isJsonRecord,
  normalizeString,
  normalizeStagingMode,
  normalizeStagingOrigin,
  normalizeStagingTimeoutMs,
  packageRoot,
  parseFlagArgs,
  printD1StagingCliError,
  printStagingManifestResult,
  relativeToRepo,
  resolvePackagePath,
  resolveRequiredPackagePath,
  sha256String,
  writeD1StagingManifest,
} from './d1-staging-config.mjs';

const defaultManifestRoot = path.join(packageRoot, '.wrangler/d1-staging-signer-custody');
const signerCustodyModes = Object.freeze(['dry-run', 'remote']);
const ecdsaExportSharePath = '/router-ab/ecdsa-hss/export/share';
const healthChecks = Object.freeze([
  {
    id: 'signer_custody_ed25519_healthz',
    method: 'GET',
    path: '/router-ab/ed25519/healthz',
    expectedStatus: 200,
    expectedJson: { ok: true, configured: true },
  },
  {
    id: 'signer_custody_ecdsa_hss_healthz',
    method: 'GET',
    path: '/router-ab/ecdsa-hss/healthz',
    expectedStatus: 200,
    expectedJson: { ok: true, configured: true },
  },
]);
const responseSecretFieldNames = new Set([
  'authorization',
  'jwt',
  'privateKeyHex',
  'private_key_hex',
  'server_export_share_32_b64u',
  'serverExportShare32B64u',
  'serverShare32B64u',
  'server_share_32_b64u',
  'signing_share_32_b64u',
  'signingShare32B64u',
  'token',
].map(responseSecretFieldKey));

export function buildD1StagingSignerCustodyPlan(input = {}) {
  const options = normalizeOptions(input);
  const exportShareFixture = readFixture(options.exportShareFixturePath, '--export-share-fixture');
  const missingKekFixture = options.missingKekFixturePath
    ? readFixture(options.missingKekFixturePath, '--missing-kek-fixture')
    : null;
  return {
    version: 'seams_d1_staging_signer_custody_v1',
    generatedAtIso: options.generatedAtIso,
    mode: options.mode,
    routerApiOrigin: options.routerApiOrigin,
    timeoutMs: options.timeoutMs,
    healthChecks: healthChecks.map((check) => ({
      ...check,
      url: `${options.routerApiOrigin}${check.path}`,
    })),
    checks: signerCustodyChecks({
      options,
      exportShareFixture,
      missingKekFixture,
    }),
  };
}

export async function runD1StagingSignerCustody(input = {}) {
  const options = normalizeOptions(input);
  const plan = buildD1StagingSignerCustodyPlan(options);
  const results = [];

  if (options.mode === 'remote') {
    for (const check of plan.healthChecks) {
      results.push(
        await executeD1StagingJsonEndpoint({
          endpoint: check,
          fetchImpl: options.fetchImpl,
          nonJsonBodyLabel: 'Signer custody endpoint',
          timeoutMs: options.timeoutMs,
        }),
      );
    }
    for (const check of plan.checks) {
      results.push(
        await executeSignerCustodyCheck({
          check,
          env: options.env,
          fetchImpl: options.fetchImpl,
          timeoutMs: options.timeoutMs,
        }),
      );
    }
  }

  const manifest = {
    ...plan,
    results,
  };
  return writeD1StagingManifest(options, defaultManifestRoot, manifest);
}

async function main() {
  try {
    const result = await runD1StagingSignerCustody(parseArgs(process.argv.slice(2)));
    printStagingManifestResult(
      result,
      'D1 staging signer custody manifest',
      'Dry run checks:',
      d1StagingHttpLines([...result.manifest.healthChecks, ...result.manifest.checks]),
    );
  } catch (error) {
    printD1StagingCliError(error);
  }
}

function parseArgs(args) {
  return parseFlagArgs(args, {
    exportShareFixturePath: '',
    generatedAtIso: '',
    manifestPath: '',
    missingKekExpectedCode: '',
    missingKekExpectedStatus: '',
    missingKekFixturePath: '',
    missingKekJwtEnvName: '',
    mode: 'dry-run',
    origin: '',
    routerApiOrigin: '',
    timeoutMs: '',
    walletSessionJwtEnvName: '',
  }, {
    '--export-share-fixture': 'exportShareFixturePath',
    '--generated-at': 'generatedAtIso',
    '--manifest': 'manifestPath',
    '--missing-kek-expected-code': 'missingKekExpectedCode',
    '--missing-kek-expected-status': 'missingKekExpectedStatus',
    '--missing-kek-fixture': 'missingKekFixturePath',
    '--missing-kek-wallet-session-jwt-env': 'missingKekJwtEnvName',
    '--mode': 'mode',
    '--origin': 'origin',
    '--router-api-origin': 'routerApiOrigin',
    '--timeout-ms': 'timeoutMs',
    '--wallet-session-jwt-env': 'walletSessionJwtEnvName',
  });
}

function normalizeOptions(input) {
  const missingKekFixturePath = resolvePackagePath(input.missingKekFixturePath, '');
  const missingKekExpectedCode = normalizeString(input.missingKekExpectedCode);
  const mode = normalizeStagingMode(input.mode, signerCustodyModes, 'staging signer custody');
  return {
    exportShareFixturePath: resolveRequiredPackagePath(
      input.exportShareFixturePath,
      '--export-share-fixture',
    ),
    fetchImpl: input.fetchImpl || globalThis.fetch,
    generatedAtIso: normalizeString(input.generatedAtIso) || new Date().toISOString(),
    manifestPath: normalizeString(input.manifestPath),
    missingKekExpectedCode,
    missingKekExpectedStatus: normalizeExpectedStatus(input.missingKekExpectedStatus, 500),
    missingKekFixturePath,
    missingKekJwtEnvName:
      normalizeString(input.missingKekJwtEnvName) || 'SEAMS_STAGING_MISSING_KEK_WALLET_SESSION_JWT',
    mode,
    origin: normalizeOptionalOrigin(input.origin, mode),
    routerApiOrigin: normalizeStagingOrigin(input.routerApiOrigin, '--router-api-origin', {
      allowHttpInDryRun: true,
      mode,
    }),
    timeoutMs: normalizeStagingTimeoutMs(input.timeoutMs),
    walletSessionJwtEnvName:
      normalizeString(input.walletSessionJwtEnvName) || 'SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT',
    env: input.env || process.env,
  };
}

function signerCustodyChecks(input) {
  const checks = [
    {
      id: 'ecdsa_export_share_success',
      method: 'POST',
      path: ecdsaExportSharePath,
      url: `${input.options.routerApiOrigin}${ecdsaExportSharePath}`,
      expectedStatus: 200,
      expectedJson: { ok: true },
      expectServerExportShare: true,
      fixture: fixtureSummary(input.exportShareFixture),
      walletSessionJwtEnvName: input.options.walletSessionJwtEnvName,
      origin: input.options.origin,
    },
  ];
  if (input.missingKekFixture) {
    checks.push({
      id: 'ecdsa_export_share_missing_kek_fail_closed',
      method: 'POST',
      path: ecdsaExportSharePath,
      url: `${input.options.routerApiOrigin}${ecdsaExportSharePath}`,
      expectedStatus: input.options.missingKekExpectedStatus,
      expectedJson: missingKekExpectedJson(input.options.missingKekExpectedCode),
      expectServerExportShare: false,
      fixture: fixtureSummary(input.missingKekFixture),
      walletSessionJwtEnvName: input.options.missingKekJwtEnvName,
      origin: input.options.origin,
    });
  }
  return checks;
}

function missingKekExpectedJson(expectedCode) {
  return expectedCode ? { ok: false, code: expectedCode } : { ok: false };
}

async function executeSignerCustodyCheck(input) {
  const token = readRequiredEnv(input.env, input.check.walletSessionJwtEnvName);
  const fixture = readFixture(input.check.fixture.path, '--export-share-fixture');
  const result = await executeD1StagingJsonEndpoint({
    endpoint: input.check,
    fetchImpl: input.fetchImpl,
    nonJsonBodyLabel: 'Signer custody endpoint',
    timeoutMs: input.timeoutMs,
    request: {
      url: input.check.url,
      method: input.check.method,
      headers: requestHeaders({
        token,
        origin: input.check.origin,
      }),
      body: JSON.stringify(fixture.body),
    },
  });
  if (input.check.expectServerExportShare) assertServerExportShare(input.check.id, result.body);
  return {
    ...result,
    body: redactResponseBody(result.body),
  };
}

function requestHeaders(input) {
  const headers = {
    accept: 'application/json',
    authorization: bearerHeader(input.token),
    'content-type': 'application/json',
  };
  if (input.origin) headers.origin = input.origin;
  return headers;
}

function bearerHeader(token) {
  const value = normalizeString(token);
  if (/^Bearer\s+/i.test(value)) return value;
  return `Bearer ${value}`;
}

function assertServerExportShare(endpointId, body) {
  const value = isJsonRecord(body.value) ? body.value : null;
  const serverExportShare32B64u = normalizeString(value?.serverExportShare32B64u);
  if (serverExportShare32B64u) return;
  throw new Error(`${endpointId} did not return value.serverExportShare32B64u`);
}

function readRequiredEnv(env, name) {
  const value = normalizeString(env?.[name]);
  if (!value) throw new Error(`${name} is required for remote signer custody checks`);
  return value;
}

function readFixture(fixturePath, label) {
  if (!existsSync(fixturePath)) {
    throw new Error(`${label} does not exist: ${relativeToRepo(fixturePath)}`);
  }
  const source = readFileSync(fixturePath, 'utf8');
  let body;
  try {
    body = JSON.parse(source);
  } catch {
    throw new Error(`${label} must contain JSON`);
  }
  if (!isJsonRecord(body)) throw new Error(`${label} must contain a JSON object`);
  return {
    path: fixturePath,
    sha256: sha256String(source),
    body,
  };
}

function fixtureSummary(fixture) {
  return {
    path: fixture.path,
    relativePath: relativeToRepo(fixture.path),
    sha256: fixture.sha256,
  };
}

function redactResponseBody(input) {
  if (Array.isArray(input)) return input.map(redactResponseBody);
  if (!isJsonRecord(input)) return input;
  const out = {};
  for (const entry of Object.entries(input)) {
    out[entry[0]] = responseSecretFieldNames.has(responseSecretFieldKey(entry[0]))
      ? '<redacted>'
      : redactResponseBody(entry[1]);
  }
  return out;
}

function responseSecretFieldKey(input) {
  return String(input).toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function normalizeOptionalOrigin(input, mode) {
  const value = normalizeString(input);
  return value
    ? normalizeStagingOrigin(value, '--origin', {
        allowHttpInDryRun: true,
        mode,
      })
    : '';
}

function normalizeExpectedStatus(input, fallback) {
  const value = normalizeString(input);
  if (!value) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 400 || parsed > 599) {
    throw new Error('--missing-kek-expected-status must be an integer between 400 and 599');
  }
  return parsed;
}

if (isDirectInvocation(import.meta.url)) await main();
