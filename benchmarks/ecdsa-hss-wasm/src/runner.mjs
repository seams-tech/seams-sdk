import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  initSync as initEthSignerSync,
  threshold_ecdsa_hss_role_local_relayer_bootstrap,
} from '../../../wasm/eth_signer/pkg/eth_signer.js';
import {
  initSync as initHssClientSignerSync,
  build_ecdsa_role_local_export_artifact_v1,
  finalize_ecdsa_client_bootstrap_v1,
  prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1,
} from '../../../wasm/hss_client_signer/pkg/hss_client_signer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../../..');
const OUT_ROOT = path.join(REPO_ROOT, 'benchmarks', 'ecdsa-hss-wasm', 'out');
const FIXTURE_PATH = path.join(REPO_ROOT, 'crates', 'ecdsa-hss', 'fixtures', 'role_local_v2.json');
const ETH_SIGNER_WASM_PATH = path.join(
  REPO_ROOT,
  'wasm',
  'eth_signer',
  'pkg',
  'eth_signer_bg.wasm',
);
const HSS_CLIENT_SIGNER_WASM_PATH = path.join(
  REPO_ROOT,
  'wasm',
  'hss_client_signer',
  'pkg',
  'hss_client_signer_bg.wasm',
);

let wasmReady = false;

function ensureWasm() {
  if (wasmReady) return;
  initEthSignerSync({ module: readFileSync(ETH_SIGNER_WASM_PATH) });
  initHssClientSignerSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_PATH) });
  wasmReady = true;
}

function hexToBytes(hex) {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function bytesToB64u(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function b64uToBytes(value) {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

function bytesToHexPrefixed(bytes) {
  return `0x${Buffer.from(bytes).toString('hex')}`;
}

function byteLengthJson(value) {
  return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

function readRepresentativeFixture() {
  const fixture = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'));
  const context = fixture.context;
  return {
    walletId: context.walletId,
    rpId: context.rpId,
    ecdsaThresholdKeyId: context.ecdsaThresholdKeyId,
    signingRootId: context.signingRootId,
    signingRootVersion: context.signingRootVersion,
    keyPurpose: context.keyPurpose,
    keyVersion: context.keyVersion,
    relayerKeyId: fixture.inputs.relayer_key_id,
    yClient32Le: hexToBytes(fixture.inputs.y_client32_le_hex),
    yRelayer32Le: hexToBytes(fixture.inputs.y_relayer32_le_hex),
    expected: {
      contextBinding32: hexToBytes(fixture.context_binding32_hex),
      clientPublicKey33: hexToBytes(fixture.identity.client_public_key33_hex),
      relayerPublicKey33: hexToBytes(fixture.identity.relayer_public_key33_hex),
      groupPublicKey33: hexToBytes(fixture.identity.threshold_public_key33_hex),
      ethereumAddress20: hexToBytes(fixture.identity.threshold_ethereum_address20_hex),
      clientShareRetryCounter: fixture.identity.client_share_retry_counter,
    },
  };
}

function contextPayload(fixture) {
  return {
    walletId: fixture.walletId,
    rpId: fixture.rpId,
    chainTarget: {
      kind: 'evm',
      namespace: 'eip155',
      chainId: 1,
      networkSlug: 'ethereum',
    },
    ecdsaThresholdKeyId: fixture.ecdsaThresholdKeyId,
    signingRootId: fixture.signingRootId,
    signingRootVersion: fixture.signingRootVersion,
    keyPurpose: 'evm-signing',
    keyVersion: 'v1',
  };
}

function clientBootstrapPayload(fixture) {
  return {
    kind: 'prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1',
    algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
    context: contextPayload(fixture),
    participants: {
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
    },
    resolvedEmailOtpRootShare32B64u: bytesToB64u(fixture.yClient32Le),
  };
}

function prepareClientBootstrap(payload) {
  return JSON.parse(
    prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1(JSON.stringify(payload)),
  );
}

function relayerContextPayload(fixture) {
  return {
    ...contextPayload(fixture),
  };
}

function relayerBootstrapPayload(fixture, clientBootstrap) {
  return {
    ...relayerContextPayload(fixture),
    relayerKeyId: fixture.relayerKeyId,
    yRelayer32Le: Array.from(fixture.yRelayer32Le),
    clientPublicKey33: Array.from(
      b64uToBytes(clientBootstrap.clientBootstrap.hssClientSharePublicKey33B64u),
    ),
    clientShareRetryCounter: Number(clientBootstrap.clientBootstrap.clientShareRetryCounter),
  };
}

function relayerPublicIdentityPayload(fixture, relayerBootstrap) {
  return {
    relayerKeyId: fixture.relayerKeyId,
    relayerPublicKey33B64u: bytesToB64u(relayerBootstrap.relayerPublicKey33),
    groupPublicKey33B64u: bytesToB64u(relayerBootstrap.groupPublicKey33),
    ethereumAddress: bytesToHexPrefixed(relayerBootstrap.ethereumAddress20),
  };
}

function finalizeClientBootstrapPayload(fixture, clientBootstrap, relayerBootstrap) {
  return {
    kind: 'finalize_ecdsa_client_bootstrap_v1',
    pendingStateBlob: clientBootstrap.pendingStateBlob,
    relayerPublicIdentity: relayerPublicIdentityPayload(fixture, relayerBootstrap),
  };
}

function finalizeClientBootstrap(payload) {
  return JSON.parse(finalize_ecdsa_client_bootstrap_v1(JSON.stringify(payload)));
}

function exportArtifactPayload(fixture, finalizedBootstrap, relayerBootstrap) {
  const context = contextPayload(fixture);
  return {
    kind: 'build_ecdsa_role_local_export_artifact_v1',
    algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
    stateBlob: finalizedBootstrap.stateBlob,
    publicFacts: {
      walletId: fixture.walletId,
      rpId: fixture.rpId,
      chainTarget: context.chainTarget,
      keyHandle: fixture.ecdsaThresholdKeyId,
      ecdsaThresholdKeyId: fixture.ecdsaThresholdKeyId,
      signingRootId: fixture.signingRootId,
      signingRootVersion: fixture.signingRootVersion,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      contextBinding32B64u: finalizedBootstrap.publicFacts.contextBinding32B64u,
      hssClientSharePublicKey33B64u:
        finalizedBootstrap.publicFacts.hssClientSharePublicKey33B64u,
      relayerPublicKey33B64u: finalizedBootstrap.publicFacts.relayerPublicKey33B64u,
      groupPublicKey33B64u: finalizedBootstrap.publicFacts.groupPublicKey33B64u,
      ethereumAddress: finalizedBootstrap.publicFacts.ethereumAddress,
    },
    authorization: {
      kind: 'passkey_export_authorized',
      walletId: fixture.walletId,
      rpId: fixture.rpId,
      credentialIdB64u: bytesToB64u(new Uint8Array([1])),
    },
    serverExportShare32B64u: bytesToB64u(relayerBootstrap.relayerShare32),
  };
}

function buildExportArtifact(payload) {
  return JSON.parse(build_ecdsa_role_local_export_artifact_v1(JSON.stringify(payload)));
}

function assertBytesEqual(label, actual, expected) {
  const actualHex = Buffer.from(actual).toString('hex');
  const expectedHex = Buffer.from(expected).toString('hex');
  if (actualHex !== expectedHex) {
    throw new Error(`${label} mismatch: got ${actualHex}, expected ${expectedHex}`);
  }
}

function assertByteLength(label, actual, expectedLength) {
  const actualLength = Buffer.from(actual).length;
  if (actualLength !== expectedLength) {
    throw new Error(`${label} must be ${expectedLength} bytes, got ${actualLength}`);
  }
}

function assertNonEmptyBytes(label, actual) {
  const actualLength = Buffer.from(actual).length;
  if (actualLength === 0) {
    throw new Error(`${label} must be non-empty`);
  }
}

function validateActivePath(clientBootstrap, relayerBootstrap, finalizedBootstrap) {
  assertBytesEqual(
    'context binding',
    b64uToBytes(clientBootstrap.clientBootstrap.contextBinding32B64u),
    relayerBootstrap.contextBinding32,
  );
  assertBytesEqual(
    'client public key public facts',
    b64uToBytes(clientBootstrap.publicFacts.hssClientSharePublicKey33B64u),
    b64uToBytes(clientBootstrap.clientBootstrap.hssClientSharePublicKey33B64u),
  );
  assertBytesEqual(
    'finalized context binding',
    b64uToBytes(finalizedBootstrap.publicFacts.contextBinding32B64u),
    relayerBootstrap.contextBinding32,
  );
  assertBytesEqual(
    'finalized client public key',
    b64uToBytes(finalizedBootstrap.publicFacts.hssClientSharePublicKey33B64u),
    b64uToBytes(clientBootstrap.clientBootstrap.hssClientSharePublicKey33B64u),
  );
  assertBytesEqual(
    'finalized relayer public key',
    b64uToBytes(finalizedBootstrap.publicFacts.relayerPublicKey33B64u),
    relayerBootstrap.relayerPublicKey33,
  );
  assertBytesEqual(
    'finalized group public key',
    b64uToBytes(finalizedBootstrap.publicFacts.groupPublicKey33B64u),
    relayerBootstrap.groupPublicKey33,
  );
  assertBytesEqual(
    'finalized ethereum address',
    Buffer.from(finalizedBootstrap.publicFacts.ethereumAddress.slice(2), 'hex'),
    relayerBootstrap.ethereumAddress20,
  );
  assertNonEmptyBytes(
    'pending state blob',
    b64uToBytes(clientBootstrap.pendingStateBlob.stateBlobB64u),
  );
  assertNonEmptyBytes(
    'ready state blob',
    b64uToBytes(finalizedBootstrap.stateBlob.stateBlobB64u),
  );
  assertByteLength('relayer share', relayerBootstrap.relayerShare32, 32);
  assertByteLength('relayer public key', relayerBootstrap.relayerPublicKey33, 33);
  assertByteLength('group public key', relayerBootstrap.groupPublicKey33, 33);
  assertByteLength('ethereum address', relayerBootstrap.ethereumAddress20, 20);
}

function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) return (sorted[mid - 1] + sorted[mid]) / 2;
  return sorted[mid];
}

function mean(values) {
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function measure(label, fn, { warmup = 5, iterations = 20 } = {}) {
  for (let i = 0; i < warmup; i += 1) fn();
  const samplesMs = [];
  for (let i = 0; i < iterations; i += 1) {
    const started = performance.now();
    fn();
    samplesMs.push(performance.now() - started);
  }
  return {
    label,
    warmup,
    iterations,
    medianMs: Number(median(samplesMs).toFixed(3)),
    meanMs: Number(mean(samplesMs).toFixed(3)),
    minMs: Number(Math.min(...samplesMs).toFixed(3)),
    maxMs: Number(Math.max(...samplesMs).toFixed(3)),
    samplesMs: samplesMs.map((value) => Number(value.toFixed(3))),
  };
}

function summarizeSamples(label, samplesMs, { warmup = 0, iterations = samplesMs.length } = {}) {
  return {
    label,
    warmup,
    iterations,
    medianMs: Number(median(samplesMs).toFixed(3)),
    meanMs: Number(mean(samplesMs).toFixed(3)),
    minMs: Number(Math.min(...samplesMs).toFixed(3)),
    maxMs: Number(Math.max(...samplesMs).toFixed(3)),
    samplesMs: samplesMs.map((value) => Number(value.toFixed(3))),
  };
}

function renderMarkdown(summary) {
  const lines = [];
  lines.push('# `ecdsa-hss` WASM Benchmark Summary');
  lines.push('');
  lines.push(`- Run ID: \`${summary.runId}\``);
  lines.push('- Runtime: Node-hosted wasm (`wasm/eth_signer/pkg` + `wasm/hss_client_signer/pkg`)');
  lines.push('- Scope: active role-local client/server/bootstrap/export boundary');
  lines.push('');
  lines.push('| Path | Median | Mean | Min | Max |');
  lines.push('| --- | ---: | ---: | ---: | ---: |');
  for (const bench of summary.benchmarks) {
    lines.push(
      `| \`${bench.label}\` | \`${bench.medianMs} ms\` | \`${bench.meanMs} ms\` | \`${bench.minMs} ms\` | \`${bench.maxMs} ms\` |`,
    );
  }
  lines.push('');
  lines.push('## Serialized Sizes');
  lines.push('');
  lines.push('| Payload | Bytes |');
  lines.push('| --- | ---: |');
  for (const size of summary.serializedSizes) {
    lines.push(`| \`${size.label}\` | \`${size.bytes}\` |`);
  }
  lines.push('');
  if (summary.signProfile) {
    lines.push('## Sign Breakdown');
    lines.push('');
    lines.push('| Bucket | Median | Mean | Min | Max |');
    lines.push('| --- | ---: | ---: | ---: | ---: |');
    for (const bucket of summary.signProfile) {
      lines.push(
        `| \`${bucket.label}\` | \`${bucket.medianMs} ms\` | \`${bucket.meanMs} ms\` | \`${bucket.minMs} ms\` | \`${bucket.maxMs} ms\` |`,
      );
    }
    lines.push('');
  }
  lines.push('Notes:');
  lines.push('- This is wasm runtime measurement, not native Criterion.');
  lines.push('- This is Cloudflare-worker-adjacent, not a full deployed worker benchmark.');
  return `${lines.join('\n')}\n`;
}

async function withStaticServer(fn) {
  const server = http.createServer((req, res) => {
    try {
      const url = new URL(req.url || '/', 'http://127.0.0.1');
      if (url.pathname === '/' || url.pathname === '/blank') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end('<!doctype html><meta charset="utf-8"><title>ecdsa-hss wasm bench</title>');
        return;
      }
      const filePath = path.resolve(REPO_ROOT, `.${url.pathname}`);
      if (!filePath.startsWith(REPO_ROOT)) {
        res.writeHead(403);
        res.end('forbidden');
        return;
      }
      const contentType = filePath.endsWith('.wasm')
        ? 'application/wasm'
        : filePath.endsWith('.js')
          ? 'text/javascript; charset=utf-8'
          : 'application/octet-stream';
      res.writeHead(200, { 'content-type': contentType });
      res.end(readFileSync(filePath));
    } catch (error) {
      res.writeHead(404);
      res.end(String(error?.message || error || 'not found'));
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('benchmark static server failed');
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    return await fn(origin);
  } finally {
    await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
}

async function measureBrowserClientBootstrap(fixture) {
  const { chromium } = await import('playwright');
  return await withStaticServer(async (origin) => {
    const browser = await chromium.launch({ headless: true });
    try {
      const page = await browser.newPage();
      await page.goto(`${origin}/blank`);
      const result = await page.evaluate(
        async ({ origin: pageOrigin, payload }) => {
          const mod = await import(
            `${pageOrigin}/wasm/hss_client_signer/pkg/hss_client_signer.js`
          );
          await mod.default(
            `${pageOrigin}/wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm`,
          );
          for (let i = 0; i < 20; i += 1) {
            mod.prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1(
              JSON.stringify(payload),
            );
          }
          const samplesMs = [];
          for (let i = 0; i < 120; i += 1) {
            const started = performance.now();
            mod.prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1(
              JSON.stringify(payload),
            );
            samplesMs.push(performance.now() - started);
          }
          return samplesMs;
        },
        {
          origin,
          payload: clientBootstrapPayload(fixture),
        },
      );
      return summarizeSamples('browser_role_local_client_prepare_resolved_email_otp_wasm', result, {
        warmup: 20,
        iterations: 120,
      });
    } finally {
      await browser.close();
    }
  });
}

async function main() {
  ensureWasm();
  const fixture = readRepresentativeFixture();
  const initialClientBootstrap = prepareClientBootstrap(clientBootstrapPayload(fixture));
  const initialRelayerBootstrap = threshold_ecdsa_hss_role_local_relayer_bootstrap(
    relayerBootstrapPayload(fixture, initialClientBootstrap),
  );
  const initialFinalizePayload = finalizeClientBootstrapPayload(
    fixture,
    initialClientBootstrap,
    initialRelayerBootstrap,
  );
  const initialFinalizedBootstrap = finalizeClientBootstrap(initialFinalizePayload);
  validateActivePath(initialClientBootstrap, initialRelayerBootstrap, initialFinalizedBootstrap);

  const clientPayload = clientBootstrapPayload(fixture);
  const relayerPayload = relayerBootstrapPayload(fixture, initialClientBootstrap);
  const artifactPayload = exportArtifactPayload(
    fixture,
    initialFinalizedBootstrap,
    initialRelayerBootstrap,
  );

  const benchmarks = [
    measure(
      'role_local_client_prepare_resolved_email_otp_wasm',
      () => prepareClientBootstrap(clientPayload),
      { warmup: 20, iterations: 200 },
    ),
    measure(
      'role_local_client_finalize_wasm',
      () => finalizeClientBootstrap(initialFinalizePayload),
      { warmup: 20, iterations: 200 },
    ),
    measure(
      'role_local_server_bootstrap_wasm',
      () => threshold_ecdsa_hss_role_local_relayer_bootstrap(relayerPayload),
      { warmup: 20, iterations: 200 },
    ),
    measure(
      'role_local_full_bootstrap_wasm',
      () => {
        const client = prepareClientBootstrap(clientPayload);
        const relayer = threshold_ecdsa_hss_role_local_relayer_bootstrap(
          relayerBootstrapPayload(fixture, client),
        );
        return finalizeClientBootstrap(finalizeClientBootstrapPayload(fixture, client, relayer));
      },
      { warmup: 20, iterations: 120 },
    ),
    measure(
      'role_local_export_artifact_wasm',
      () => buildExportArtifact(artifactPayload),
      { warmup: 20, iterations: 200 },
    ),
  ];
  benchmarks.push(await measureBrowserClientBootstrap(fixture));

  const serializedSizes = [
    { label: 'client_bootstrap_request_json', bytes: byteLengthJson(clientPayload) },
    {
      label: 'client_bootstrap_response_json',
      bytes: byteLengthJson(initialClientBootstrap),
    },
    { label: 'client_finalize_request_json', bytes: byteLengthJson(initialFinalizePayload) },
    {
      label: 'client_finalize_response_json',
      bytes: byteLengthJson(initialFinalizedBootstrap),
    },
    { label: 'server_bootstrap_request_json', bytes: byteLengthJson(relayerPayload) },
    {
      label: 'server_bootstrap_response_json',
      bytes: byteLengthJson(initialRelayerBootstrap),
    },
    { label: 'client_export_artifact_request_json', bytes: byteLengthJson(artifactPayload) },
    {
      label: 'role_local_client_state_json',
      bytes: byteLengthJson({
        stateBlob: initialFinalizedBootstrap.stateBlob,
        publicFacts: initialFinalizedBootstrap.publicFacts,
      }),
    },
    {
      label: 'role_local_server_record_json',
      bytes: byteLengthJson({
        contextBinding32B64u: bytesToB64u(initialRelayerBootstrap.contextBinding32),
        relayerShare32B64u: bytesToB64u(initialRelayerBootstrap.relayerShare32),
        relayerPublicKey33B64u: bytesToB64u(initialRelayerBootstrap.relayerPublicKey33),
        clientPublicKey33B64u:
          initialClientBootstrap.clientBootstrap.hssClientSharePublicKey33B64u,
        groupPublicKey33B64u: bytesToB64u(initialRelayerBootstrap.groupPublicKey33),
        ethereumAddress: bytesToHexPrefixed(initialRelayerBootstrap.ethereumAddress20),
        publicTranscriptDigest32B64u: bytesToB64u(initialRelayerBootstrap.publicTranscriptDigest32),
      }),
    },
  ];

  const runId = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = path.join(OUT_ROOT, runId);
  mkdirSync(outDir, { recursive: true });

  const summary = {
    runId,
    runtime: 'node-hosted-wasm-web-target',
    fixture: 'role_local_v2',
    benchmarks,
    serializedSizes,
  };

  const rawSummaryPath = path.join(outDir, 'raw-summary.json');
  const markdownPath = path.join(outDir, 'summary.md');
  writeFileSync(rawSummaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  writeFileSync(markdownPath, renderMarkdown(summary));

  console.log(`[benchmark] run_id=${runId}`);
  console.log(`[benchmark] summary_json=${rawSummaryPath}`);
  console.log(`[benchmark] summary_markdown=${markdownPath}`);
  for (const bench of benchmarks) {
    console.log(
      `[benchmark] ${bench.label} median_ms=${bench.medianMs} mean_ms=${bench.meanMs} min_ms=${bench.minMs} max_ms=${bench.maxMs}`,
    );
  }
  for (const size of serializedSizes) {
    console.log(`[benchmark] ${size.label} bytes=${size.bytes}`);
  }
}

await main();
