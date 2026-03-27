#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import initWasm, {
  WorkerRequestType,
  WorkerResponseType,
  handle_signer_message,
  init_wasm_signer_worker,
  threshold_ed25519_bootstrap_recovery_share,
  threshold_ed25519_keygen_from_master_secret_and_client_verifying_share,
  threshold_ed25519_recovery_client_share,
} from '../../../sdk/dist/esm/wasm/near_signer/pkg/wasm_signer_worker.js';
import {
  RECOVERY_SHARE_DOMAIN_MODULUS,
  decodeU256Le,
  generatePaillierKeyPair,
  paillierAddConst,
  paillierDecrypt,
  paillierEncrypt,
  serializePaillierCiphertextB64u,
  serializePaillierPublicKeyB64u,
} from '../../../shared/src/utils/paillier.ts';
import { base64UrlDecode, base64UrlEncode } from '../../../shared/src/utils/base64.ts';
import {
  buildMarkdown,
  buildStats,
  ensureDir,
  findLatestRunArtifact,
  loadJsonFile,
  roundMs,
  tsRunId,
  utf8ByteLength,
  type BrowserBenchmarkSummary,
  type NodeBenchmarkSummary,
} from './report.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const MODULE_ROOT = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(MODULE_ROOT, '..', '..');
const WASM_PATH = path.resolve(
  REPO_ROOT,
  'sdk',
  'dist',
  'esm',
  'wasm',
  'near_signer',
  'pkg',
  'wasm_signer_worker_bg.wasm',
);

const KEY_VERSION = 'option-b-v1';
const RP_ID = 'bench.localhost';

type Stats = {
  count: number;
  minMs: number;
  maxMs: number;
  meanMs: number;
  p50Ms: number;
  p95Ms: number;
};

type Summary = NodeBenchmarkSummary;

type Args = {
  registrationIterations: number;
  paillierIterations: number;
  outDir: string;
  docsOutput: string;
  syncDocs: boolean;
};

let wasmReady = false;

function parsePositiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(String(value || '').trim(), 10);
  if (!Number.isFinite(parsed) || parsed < 1) return fallback;
  return parsed;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    registrationIterations: 25,
    paillierIterations: 5,
    outDir: path.join(MODULE_ROOT, 'out'),
    docsOutput: path.join(REPO_ROOT, 'docs', 'benchmarks', 'threshold-ed25519-dual-key.md'),
    syncDocs: true,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--registration-iterations' && argv[i + 1]) {
      args.registrationIterations = parsePositiveInt(argv[++i], args.registrationIterations);
      continue;
    }
    if (token === '--paillier-iterations' && argv[i + 1]) {
      args.paillierIterations = parsePositiveInt(argv[++i], args.paillierIterations);
      continue;
    }
    if (token === '--out-dir' && argv[i + 1]) {
      args.outDir = path.resolve(String(argv[++i]));
      continue;
    }
    if (token === '--docs-output' && argv[i + 1]) {
      args.docsOutput = path.resolve(String(argv[++i]));
      continue;
    }
    if (token === '--skip-doc-sync') {
      args.syncDocs = false;
      continue;
    }
  }

  return args;
}

function filledBytes(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i += 1) {
    out[i] = (seed + i * 17) & 0xff;
  }
  return out;
}

async function ensureWasmReady(): Promise<void> {
  if (wasmReady) return;
  const wasmBytes = await fs.readFile(WASM_PATH);
  await initWasm({ module_or_path: wasmBytes });
  init_wasm_signer_worker();
  wasmReady = true;
}

async function measureAsync<T>(fn: () => Promise<T>): Promise<{ durationMs: number; result: T }> {
  const start = performance.now();
  const result = await fn();
  return { durationMs: performance.now() - start, result };
}

function measureSync<T>(fn: () => T): { durationMs: number; result: T } {
  const start = performance.now();
  const result = fn();
  return { durationMs: performance.now() - start, result };
}

async function deriveOperationalClientShare(input: {
  nearAccountId: string;
  prfFirstB64u: string;
  wrapKeySalt: string;
}): Promise<{ clientVerifyingShareB64u: string }> {
  const response = (await handle_signer_message({
    type: WorkerRequestType.DeriveThresholdEd25519ClientVerifyingShare,
    payload: {
      sessionId: `operational-${input.nearAccountId}`,
      nearAccountId: input.nearAccountId,
      prfFirstB64u: input.prfFirstB64u,
      wrapKeySalt: input.wrapKeySalt,
    },
  })) as {
    type: number;
    payload?: { clientVerifyingShareB64u?: string };
  };
  if (response.type !== WorkerResponseType.DeriveThresholdEd25519ClientVerifyingShareSuccess) {
    throw new Error('Operational client share derivation failed');
  }
  const clientVerifyingShareB64u = String(response.payload?.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('Operational client share derivation returned empty clientVerifyingShareB64u');
  }
  return { clientVerifyingShareB64u };
}

async function deriveDualKeyBootstrapPackage(input: {
  nearAccountId: string;
  prfFirstB64u: string;
  recoveryServerShareB64u: string;
}): Promise<{
  clientVerifyingShareB64u: string;
  recoveryPublicKey?: string;
}> {
  const response = (await handle_signer_message({
    type: WorkerRequestType.DeriveThresholdEd25519BootstrapPackage,
    payload: {
      sessionId: `dual-key-${input.nearAccountId}`,
      nearAccountId: input.nearAccountId,
      rpId: RP_ID,
      keyVersion: KEY_VERSION,
      prfFirstB64u: input.prfFirstB64u,
      recoveryServerShareB64u: input.recoveryServerShareB64u,
    },
  })) as {
    type: number;
    payload?: {
      clientVerifyingShareB64u?: string;
      recoveryPublicKey?: string;
    };
  };
  if (response.type !== WorkerResponseType.DeriveThresholdEd25519BootstrapPackageSuccess) {
    throw new Error('Dual-key bootstrap package derivation failed');
  }
  const clientVerifyingShareB64u = String(response.payload?.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('Dual-key bootstrap package returned empty clientVerifyingShareB64u');
  }
  return {
    clientVerifyingShareB64u,
    recoveryPublicKey: String(response.payload?.recoveryPublicKey || '').trim() || undefined,
  };
}

async function runRegistrationBenchmarks(iterations: number): Promise<Summary['registration']> {
  const operationalClientShareMs: number[] = [];
  const operationalRelayKeygenMs: number[] = [];
  const operationalTotalMs: number[] = [];
  const dualKeyRecoveryPreflightMs: number[] = [];
  const dualKeyBootstrapPackageMs: number[] = [];
  const dualKeyTotalMs: number[] = [];

  for (let i = 0; i < iterations; i += 1) {
    const nearAccountId = `bench-${String(i + 1).padStart(3, '0')}.test.near`;
    const prfFirstB64u = base64UrlEncode(filledBytes(32, 17 + i));
    const masterSecretB64u = base64UrlEncode(filledBytes(32, 91 + i));
    const wrapKeySalt = base64UrlEncode(filledBytes(16, 33 + i));

    const operationalClientShare = await measureAsync(() =>
      deriveOperationalClientShare({
        nearAccountId,
        prfFirstB64u,
        wrapKeySalt,
      }),
    );
    const relayKeygen = measureSync(() =>
      threshold_ed25519_keygen_from_master_secret_and_client_verifying_share({
        masterSecretB64u,
        nearAccountId,
        rpId: RP_ID,
        clientVerifyingShareB64u: operationalClientShare.result.clientVerifyingShareB64u,
      }),
    );

    const recoveryPreflight = measureSync(() =>
      threshold_ed25519_bootstrap_recovery_share({
        masterSecretB64u,
        nearAccountId,
        rpId: RP_ID,
        keyVersion: KEY_VERSION,
      }),
    );
    const bootstrapPackage = await measureAsync(() =>
      deriveDualKeyBootstrapPackage({
        nearAccountId,
        prfFirstB64u,
        recoveryServerShareB64u: recoveryPreflight.result.recoveryServerShareB64u,
      }),
    );

    operationalClientShareMs.push(operationalClientShare.durationMs);
    operationalRelayKeygenMs.push(relayKeygen.durationMs);
    operationalTotalMs.push(operationalClientShare.durationMs + relayKeygen.durationMs);
    dualKeyRecoveryPreflightMs.push(recoveryPreflight.durationMs);
    dualKeyBootstrapPackageMs.push(bootstrapPackage.durationMs);
    dualKeyTotalMs.push(recoveryPreflight.durationMs + bootstrapPackage.durationMs);
  }

  const operationalTotal = buildStats(operationalTotalMs);
  const dualKeyTotal = buildStats(dualKeyTotalMs);
  return {
    operationalEnrollment: {
      clientShareMs: buildStats(operationalClientShareMs),
      relayKeygenMs: buildStats(operationalRelayKeygenMs),
      totalMs: operationalTotal,
    },
    dualKeyBootstrap: {
      recoveryPreflightMs: buildStats(dualKeyRecoveryPreflightMs),
      bootstrapPackageMs: buildStats(dualKeyBootstrapPackageMs),
      totalMs: dualKeyTotal,
    },
    delta: {
      meanMs: roundMs(dualKeyTotal.meanMs - operationalTotal.meanMs),
      meanPercent:
        operationalTotal.meanMs > 0
          ? roundMs(((dualKeyTotal.meanMs - operationalTotal.meanMs) / operationalTotal.meanMs) * 100)
          : 0,
    },
  };
}

async function runExportBenchmarks(iterations: number): Promise<Summary['exportFlow']> {
  const keygenMs: number[] = [];
  const encryptMs: number[] = [];
  const addConstMs: number[] = [];
  const decryptMs: number[] = [];

  const sampleNearAccountId = 'bench-export.test.near';
  const samplePrfFirstB64u = base64UrlEncode(filledBytes(32, 141));
  const sampleMasterSecretB64u = base64UrlEncode(filledBytes(32, 207));
  const recoveryServerShare = threshold_ed25519_bootstrap_recovery_share({
    masterSecretB64u: sampleMasterSecretB64u,
    nearAccountId: sampleNearAccountId,
    rpId: RP_ID,
    keyVersion: KEY_VERSION,
  });
  const recoveryClientShare = threshold_ed25519_recovery_client_share({
    prfFirstB64u: samplePrfFirstB64u,
    nearAccountId: sampleNearAccountId,
    rpId: RP_ID,
    keyVersion: KEY_VERSION,
  });

  let samplePublicKeyB64u = '';
  let sampleClientCiphertextB64u = '';
  let sampleServerCiphertextB64u = '';

  for (let i = 0; i < iterations; i += 1) {
    const keygen = await measureAsync(() => generatePaillierKeyPair({ bits: 2048 }));
    const recoveryClientShareValue = decodeU256Le(
      base64UrlDecode(recoveryClientShare.recoveryClientShareB64u),
    );
    const recoveryServerShareValue = decodeU256Le(
      base64UrlDecode(recoveryServerShare.recoveryServerShareB64u),
    );

    const encrypt = measureSync(() => paillierEncrypt(keygen.result.publicKey, recoveryClientShareValue));
    const addConst = measureSync(() =>
      paillierAddConst(keygen.result.publicKey, encrypt.result, recoveryServerShareValue),
    );
    const decrypt = measureSync(() =>
      paillierDecrypt(keygen.result, addConst.result) % RECOVERY_SHARE_DOMAIN_MODULUS,
    );

    keygenMs.push(keygen.durationMs);
    encryptMs.push(encrypt.durationMs);
    addConstMs.push(addConst.durationMs);
    decryptMs.push(decrypt.durationMs);

    if (i === 0) {
      samplePublicKeyB64u = serializePaillierPublicKeyB64u(keygen.result.publicKey);
      sampleClientCiphertextB64u = serializePaillierCiphertextB64u(
        keygen.result.publicKey,
        encrypt.result,
      );
      sampleServerCiphertextB64u = serializePaillierCiphertextB64u(
        keygen.result.publicKey,
        addConst.result,
      );
    }
  }

  const publicKeyRawBytes = base64UrlDecode(samplePublicKeyB64u).length;
  const clientCiphertextRawBytes = base64UrlDecode(sampleClientCiphertextB64u).length;
  const serverCiphertextRawBytes = base64UrlDecode(sampleServerCiphertextB64u).length;
  const requestJsonBytes = utf8ByteLength(
    JSON.stringify({
      paillierPublicKeyB64u: samplePublicKeyB64u,
      clientCiphertextB64u: sampleClientCiphertextB64u,
    }),
  );
  const responseJsonBytes = utf8ByteLength(
    JSON.stringify({
      serverCiphertextB64u: sampleServerCiphertextB64u,
    }),
  );

  return {
    paillier: {
      keygenMs: buildStats(keygenMs),
      encryptMs: buildStats(encryptMs),
      addConstMs: buildStats(addConstMs),
      decryptMs: buildStats(decryptMs),
    },
    payloadSizes: {
      publicKeyRawBytes,
      publicKeyB64uChars: samplePublicKeyB64u.length,
      clientCiphertextRawBytes,
      clientCiphertextB64uChars: sampleClientCiphertextB64u.length,
      serverCiphertextRawBytes,
      serverCiphertextB64uChars: sampleServerCiphertextB64u.length,
      requestCryptoRawBytes: publicKeyRawBytes + clientCiphertextRawBytes,
      responseCryptoRawBytes: serverCiphertextRawBytes,
      requestJsonBytes,
      responseJsonBytes,
      roundTrips: 1,
    },
  };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  await ensureWasmReady();

  const registration = await runRegistrationBenchmarks(args.registrationIterations);
  const exportFlow = await runExportBenchmarks(args.paillierIterations);

  const summary: Summary = {
    generatedAt: new Date().toISOString(),
    runtime: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    config: {
      registrationIterations: args.registrationIterations,
      paillierIterations: args.paillierIterations,
      paillierBits: 2048,
    },
    registration,
    exportFlow,
  };

  const latestBrowserSummaryPath = await findLatestRunArtifact(args.outDir, 'browser-summary.json');
  const browserSummary = latestBrowserSummaryPath
    ? await loadJsonFile<BrowserBenchmarkSummary>(latestBrowserSummaryPath)
    : null;
  const markdown = buildMarkdown(summary, browserSummary);
  const runId = tsRunId();
  const runOutDir = path.join(args.outDir, runId);
  const rawSummaryPath = path.join(runOutDir, 'raw-summary.json');
  const markdownPath = path.join(runOutDir, 'summary.md');

  await ensureDir(runOutDir);
  await fs.writeFile(rawSummaryPath, `${JSON.stringify(summary, null, 2)}\n`, 'utf8');
  await fs.writeFile(markdownPath, `${markdown}\n`, 'utf8');
  if (args.syncDocs) {
    await ensureDir(path.dirname(args.docsOutput));
    await fs.writeFile(args.docsOutput, `${markdown}\n`, 'utf8');
  }

  console.log(`[benchmark] run_id=${runId}`);
  console.log(`[benchmark] output_dir=${runOutDir}`);
  console.log(`[benchmark] summary_json=${rawSummaryPath}`);
  console.log(`[benchmark] summary_markdown=${markdownPath}`);
  if (args.syncDocs) {
    console.log(`[benchmark] docs_synced=${args.docsOutput}`);
  }
  console.log(
    `[benchmark] registration_total_mean_ms=${summary.registration.dualKeyBootstrap.totalMs.meanMs}`,
  );
  console.log(
    `[benchmark] paillier_keygen_mean_ms=${summary.exportFlow.paillier.keygenMs.meanMs}`,
  );
  console.log(
    `[benchmark] export_request_json_bytes=${summary.exportFlow.payloadSizes.requestJsonBytes}`,
  );
  console.log(
    `[benchmark] export_response_json_bytes=${summary.exportFlow.payloadSizes.responseJsonBytes}`,
  );
}

main().catch((error: unknown) => {
  console.error('[benchmark] fatal', error);
  process.exitCode = 1;
});
