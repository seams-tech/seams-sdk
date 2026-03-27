#!/usr/bin/env node

import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
import { chromium, webkit } from '@playwright/test';
import {
  buildMarkdown,
  buildStats,
  ensureDir,
  findLatestRunArtifact,
  loadJsonFile,
  roundMs,
  tsRunId,
  type BrowserBenchmarkRun,
  type BrowserBenchmarkSummary,
  type NodeBenchmarkSummary,
} from './report.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const MODULE_ROOT = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(MODULE_ROOT, '..', '..');
const SDK_DIST_ROOT = path.resolve(REPO_ROOT, 'sdk', 'dist');

const KEY_VERSION = 'option-b-v1';
const RP_ID = 'bench.localhost';

type Args = {
  registrationIterations: number;
  paillierIterations: number;
  outDir: string;
  docsOutput: string;
  syncDocs: boolean;
};

type BrowserRawBenchmarkResult = {
  userAgent: string;
  platform: string;
  registration: {
    operationalClientShareMs: number[];
    operationalRelayKeygenMs: number[];
    operationalTotalMs: number[];
    dualKeyRecoveryPreflightMs: number[];
    dualKeyBootstrapPackageMs: number[];
    dualKeyTotalMs: number[];
  };
  exportFlow: {
    keygenMs: number[];
    encryptMs: number[];
    addConstMs: number[];
    decryptMs: number[];
    payloadSizes: {
      publicKeyRawBytes: number;
      publicKeyB64uChars: number;
      clientCiphertextRawBytes: number;
      clientCiphertextB64uChars: number;
      serverCiphertextRawBytes: number;
      serverCiphertextB64uChars: number;
      requestCryptoRawBytes: number;
      responseCryptoRawBytes: number;
      requestJsonBytes: number;
      responseJsonBytes: number;
      roundTrips: number;
    };
  };
};

function parsePositiveInt(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(String(value || '').trim(), 10);
  if (!Number.isFinite(parsed) || parsed < 1) return fallback;
  return parsed;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    registrationIterations: 10,
    paillierIterations: 3,
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

function contentType(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.html':
      return 'text/html; charset=utf-8';
    case '.js':
    case '.mjs':
      return 'text/javascript; charset=utf-8';
    case '.json':
    case '.map':
      return 'application/json; charset=utf-8';
    case '.wasm':
      return 'application/wasm';
    case '.css':
      return 'text/css; charset=utf-8';
    default:
      return 'application/octet-stream';
  }
}

function safeResolvedPath(root: string, requestPath: string): string | null {
  const candidate = path.resolve(root, `.${requestPath}`);
  if (!candidate.startsWith(root)) return null;
  return candidate;
}

async function createStaticSdkServer(): Promise<{
  origin: string;
  close: () => Promise<void>;
}> {
  const paillierBundle = await build({
    entryPoints: [path.resolve(REPO_ROOT, 'shared', 'src', 'utils', 'paillier.ts')],
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: ['es2022'],
    write: false,
  });
  const paillierBundleText = String(paillierBundle.outputFiles?.[0]?.text || '').trim();
  if (!paillierBundleText) {
    throw new Error('Failed to build browser Paillier bundle for benchmark runner');
  }

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url || '/', 'http://127.0.0.1');
      if (url.pathname === '/' || url.pathname === '/index.html') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<!DOCTYPE html><html><head><meta charset="utf-8"></head><body>bench</body></html>');
        return;
      }
      if (url.pathname === '/favicon.ico') {
        res.writeHead(204);
        res.end();
        return;
      }
      if (url.pathname === '/bench/paillier.js') {
        res.writeHead(200, {
          'Content-Type': 'text/javascript; charset=utf-8',
          'Cache-Control': 'no-store',
        });
        res.end(paillierBundleText);
        return;
      }
      if (!url.pathname.startsWith('/sdk/')) {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('not found');
        return;
      }
      const relativePath = url.pathname.slice('/sdk'.length);
      const filePath = safeResolvedPath(SDK_DIST_ROOT, relativePath);
      if (!filePath) {
        res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('forbidden');
        return;
      }
      const body = await fs.readFile(filePath);
      res.writeHead(200, {
        'Content-Type': contentType(filePath),
        'Cache-Control': 'no-store',
      });
      res.end(body);
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(error instanceof Error ? error.message : 'internal error');
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to determine static benchmark server address');
  }
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: async () =>
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}

async function runBrowserBench(page: any, args: Args): Promise<BrowserRawBenchmarkResult> {
  await page.evaluate(() => {
    if (typeof (globalThis as any).__name !== 'function') {
      (globalThis as any).__name = (target: unknown) => target;
    }
  });
  return await page.evaluate(
    async ({ registrationIterations, paillierIterations, keyVersion, rpId }) => {
      const wasm = await import('/sdk/esm/wasm/near_signer/pkg/wasm_signer_worker.js');
      const paillier = await import('/bench/paillier.js');
      const base64 = await import('/sdk/esm/shared/src/utils/base64.js');

      await wasm.default();
      wasm.init_wasm_signer_worker();

      function filledBytes(length: number, seed: number): Uint8Array {
        const out = new Uint8Array(length);
        for (let i = 0; i < length; i += 1) {
          out[i] = (seed + i * 17) & 0xff;
        }
        return out;
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
        const response = (await wasm.handle_signer_message({
          type: wasm.WorkerRequestType.DeriveThresholdEd25519ClientVerifyingShare,
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
        if (response.type !== wasm.WorkerResponseType.DeriveThresholdEd25519ClientVerifyingShareSuccess) {
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
      }): Promise<{ clientVerifyingShareB64u: string; recoveryPublicKey?: string }> {
        const response = (await wasm.handle_signer_message({
          type: wasm.WorkerRequestType.DeriveThresholdEd25519BootstrapPackage,
          payload: {
            sessionId: `dual-key-${input.nearAccountId}`,
            nearAccountId: input.nearAccountId,
            rpId,
            keyVersion,
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
        if (response.type !== wasm.WorkerResponseType.DeriveThresholdEd25519BootstrapPackageSuccess) {
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

      const operationalClientShareMs: number[] = [];
      const operationalRelayKeygenMs: number[] = [];
      const operationalTotalMs: number[] = [];
      const dualKeyRecoveryPreflightMs: number[] = [];
      const dualKeyBootstrapPackageMs: number[] = [];
      const dualKeyTotalMs: number[] = [];

      for (let i = 0; i < registrationIterations; i += 1) {
        const nearAccountId = `browser-bench-${String(i + 1).padStart(3, '0')}.test.near`;
        const prfFirstB64u = base64.base64UrlEncode(filledBytes(32, 17 + i));
        const masterSecretB64u = base64.base64UrlEncode(filledBytes(32, 91 + i));
        const wrapKeySalt = base64.base64UrlEncode(filledBytes(16, 33 + i));

        const operationalClientShare = await measureAsync(() =>
          deriveOperationalClientShare({
            nearAccountId,
            prfFirstB64u,
            wrapKeySalt,
          }),
        );
        const relayKeygen = measureSync(() =>
          wasm.threshold_ed25519_keygen_from_master_secret_and_client_verifying_share({
            masterSecretB64u,
            nearAccountId,
            rpId,
            clientVerifyingShareB64u: operationalClientShare.result.clientVerifyingShareB64u,
          }),
        );
        const recoveryPreflight = measureSync(() =>
          wasm.threshold_ed25519_bootstrap_recovery_share({
            masterSecretB64u,
            nearAccountId,
            rpId,
            keyVersion,
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

      const keygenMs: number[] = [];
      const encryptMs: number[] = [];
      const addConstMs: number[] = [];
      const decryptMs: number[] = [];

      const sampleNearAccountId = 'browser-bench-export.test.near';
      const samplePrfFirstB64u = base64.base64UrlEncode(filledBytes(32, 141));
      const sampleMasterSecretB64u = base64.base64UrlEncode(filledBytes(32, 207));
      const recoveryServerShare = wasm.threshold_ed25519_bootstrap_recovery_share({
        masterSecretB64u: sampleMasterSecretB64u,
        nearAccountId: sampleNearAccountId,
        rpId,
        keyVersion,
      });
      const recoveryClientShare = wasm.threshold_ed25519_recovery_client_share({
        prfFirstB64u: samplePrfFirstB64u,
        nearAccountId: sampleNearAccountId,
        rpId,
        keyVersion,
      });

      let samplePublicKeyB64u = '';
      let sampleClientCiphertextB64u = '';
      let sampleServerCiphertextB64u = '';

      for (let i = 0; i < paillierIterations; i += 1) {
        const keygen = await measureAsync(() => paillier.generatePaillierKeyPair({ bits: 2048 }));
        const recoveryClientShareValue = paillier.decodeU256Le(
          base64.base64UrlDecode(recoveryClientShare.recoveryClientShareB64u),
        );
        const recoveryServerShareValue = paillier.decodeU256Le(
          base64.base64UrlDecode(recoveryServerShare.recoveryServerShareB64u),
        );
        const encrypt = measureSync(() =>
          paillier.paillierEncrypt(keygen.result.publicKey, recoveryClientShareValue),
        );
        const addConst = measureSync(() =>
          paillier.paillierAddConst(keygen.result.publicKey, encrypt.result, recoveryServerShareValue),
        );
        const decrypt = measureSync(() =>
          paillier.paillierDecrypt(keygen.result, addConst.result) %
          paillier.RECOVERY_SHARE_DOMAIN_MODULUS,
        );

        keygenMs.push(keygen.durationMs);
        encryptMs.push(encrypt.durationMs);
        addConstMs.push(addConst.durationMs);
        decryptMs.push(decrypt.durationMs);

        if (i === 0) {
          samplePublicKeyB64u = paillier.serializePaillierPublicKeyB64u(keygen.result.publicKey);
          sampleClientCiphertextB64u = paillier.serializePaillierCiphertextB64u(
            keygen.result.publicKey,
            encrypt.result,
          );
          sampleServerCiphertextB64u = paillier.serializePaillierCiphertextB64u(
            keygen.result.publicKey,
            addConst.result,
          );
        }
      }

      const publicKeyRawBytes = base64.base64UrlDecode(samplePublicKeyB64u).length;
      const clientCiphertextRawBytes = base64.base64UrlDecode(sampleClientCiphertextB64u).length;
      const serverCiphertextRawBytes = base64.base64UrlDecode(sampleServerCiphertextB64u).length;
      const requestJsonBytes = new TextEncoder().encode(
        JSON.stringify({
          paillierPublicKeyB64u: samplePublicKeyB64u,
          clientCiphertextB64u: sampleClientCiphertextB64u,
        }),
      ).length;
      const responseJsonBytes = new TextEncoder().encode(
        JSON.stringify({
          serverCiphertextB64u: sampleServerCiphertextB64u,
        }),
      ).length;

      return {
        userAgent: navigator.userAgent,
        platform: navigator.platform || '',
        registration: {
          operationalClientShareMs,
          operationalRelayKeygenMs,
          operationalTotalMs,
          dualKeyRecoveryPreflightMs,
          dualKeyBootstrapPackageMs,
          dualKeyTotalMs,
        },
        exportFlow: {
          keygenMs,
          encryptMs,
          addConstMs,
          decryptMs,
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
        },
      };
    },
    {
      registrationIterations: args.registrationIterations,
      paillierIterations: args.paillierIterations,
      keyVersion: KEY_VERSION,
      rpId: RP_ID,
    },
  );
}

function toBrowserRun(args: Args, browserName: string, browserVersion: string, raw: BrowserRawBenchmarkResult): BrowserBenchmarkRun {
  const operationalTotal = buildStats(raw.registration.operationalTotalMs);
  const dualKeyTotal = buildStats(raw.registration.dualKeyTotalMs);
  return {
    browserName,
    browserVersion,
    userAgent: raw.userAgent,
    platform: raw.platform,
    config: {
      registrationIterations: args.registrationIterations,
      paillierIterations: args.paillierIterations,
      paillierBits: 2048,
    },
    registration: {
      operationalEnrollment: {
        clientShareMs: buildStats(raw.registration.operationalClientShareMs),
        relayKeygenMs: buildStats(raw.registration.operationalRelayKeygenMs),
        totalMs: operationalTotal,
      },
      dualKeyBootstrap: {
        recoveryPreflightMs: buildStats(raw.registration.dualKeyRecoveryPreflightMs),
        bootstrapPackageMs: buildStats(raw.registration.dualKeyBootstrapPackageMs),
        totalMs: dualKeyTotal,
      },
      delta: {
        meanMs: roundMs(dualKeyTotal.meanMs - operationalTotal.meanMs),
        meanPercent:
          operationalTotal.meanMs > 0
            ? roundMs(((dualKeyTotal.meanMs - operationalTotal.meanMs) / operationalTotal.meanMs) * 100)
            : 0,
      },
    },
    exportFlow: {
      paillier: {
        keygenMs: buildStats(raw.exportFlow.keygenMs),
        encryptMs: buildStats(raw.exportFlow.encryptMs),
        addConstMs: buildStats(raw.exportFlow.addConstMs),
        decryptMs: buildStats(raw.exportFlow.decryptMs),
      },
      payloadSizes: raw.exportFlow.payloadSizes,
    },
  };
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const server = await createStaticSdkServer();
  try {
    const runs: BrowserBenchmarkRun[] = [];
    for (const browserType of [chromium, webkit]) {
      const browser = await browserType.launch({ headless: true });
      try {
        const page = await browser.newPage();
        await page.goto(server.origin, { waitUntil: 'domcontentloaded' });
        const raw = await runBrowserBench(page, args);
        runs.push(toBrowserRun(args, browserType.name(), browser.version(), raw));
        await page.close();
      } finally {
        await browser.close();
      }
    }

    const browserSummary: BrowserBenchmarkSummary = {
      generatedAt: new Date().toISOString(),
      runs,
    };

    const latestNodeSummaryPath = await findLatestRunArtifact(args.outDir, 'raw-summary.json');
    const nodeSummary = latestNodeSummaryPath
      ? await loadJsonFile<NodeBenchmarkSummary>(latestNodeSummaryPath)
      : null;
    if (!nodeSummary) {
      throw new Error('Browser benchmark requires an existing node raw-summary.json; run pnpm benchmark:threshold-ed25519 first.');
    }

    const markdown = buildMarkdown(nodeSummary, browserSummary);
    const runId = tsRunId();
    const runOutDir = path.join(args.outDir, runId);
    const rawSummaryPath = path.join(runOutDir, 'browser-summary.json');
    const markdownPath = path.join(runOutDir, 'browser-summary.md');

    await ensureDir(runOutDir);
    await fs.writeFile(rawSummaryPath, `${JSON.stringify(browserSummary, null, 2)}\n`, 'utf8');
    await fs.writeFile(markdownPath, `${markdown}\n`, 'utf8');
    if (args.syncDocs) {
      await ensureDir(path.dirname(args.docsOutput));
      await fs.writeFile(args.docsOutput, `${markdown}\n`, 'utf8');
    }

    console.log(`[browser-benchmark] run_id=${runId}`);
    console.log(`[browser-benchmark] output_dir=${runOutDir}`);
    console.log(`[browser-benchmark] summary_json=${rawSummaryPath}`);
    console.log(`[browser-benchmark] summary_markdown=${markdownPath}`);
    if (args.syncDocs) {
      console.log(`[browser-benchmark] docs_synced=${args.docsOutput}`);
    }
    for (const run of browserSummary.runs) {
      console.log(
        `[browser-benchmark] ${run.browserName}_registration_total_mean_ms=${run.registration.dualKeyBootstrap.totalMs.meanMs}`,
      );
      console.log(
        `[browser-benchmark] ${run.browserName}_paillier_keygen_mean_ms=${run.exportFlow.paillier.keygenMs.meanMs}`,
      );
      console.log(
        `[browser-benchmark] ${run.browserName}_export_request_json_bytes=${run.exportFlow.payloadSizes.requestJsonBytes}`,
      );
    }
  } finally {
    await server.close();
  }
}

main().catch((error: unknown) => {
  console.error('[browser-benchmark] fatal', error);
  process.exitCode = 1;
});
