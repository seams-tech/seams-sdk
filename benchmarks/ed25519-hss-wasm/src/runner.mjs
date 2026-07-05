import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  derive_threshold_ed25519_hss_client_inputs,
  initSync as initHssClientSignerWasmSync,
  threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact,
  threshold_ed25519_hss_derive_client_output_mask,
  threshold_ed25519_hss_prepare_client_request,
} from '../../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import {
  initSync as initNearSignerWasmSync,
  init_worker,
  threshold_ed25519_hss_prepare_role_separated_server_input_delivery,
  threshold_ed25519_hss_prepare_server_session,
} from '../../../wasm/near_signer/pkg-server/wasm_signer_worker.js';
import {
  initSync as initThresholdPrfWasmSync,
  init_threshold_prf,
  threshold_prf_derive_ed25519_hss_server_inputs,
} from '../../../wasm/threshold_prf/pkg/threshold_prf.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../../..');
const requireFromRoot = createRequire(path.join(REPO_ROOT, 'package.json'));
const requireFromTests = createRequire(path.join(REPO_ROOT, 'tests', 'package.json'));
const OUT_ROOT = path.join(REPO_ROOT, 'benchmarks', 'ed25519-hss-wasm', 'out');
const HSS_CLIENT_SIGNER_WASM_PATH = path.join(
  REPO_ROOT,
  'wasm',
  'hss_client_signer',
  'pkg',
  'hss_client_signer_bg.wasm',
);
const NEAR_SIGNER_SERVER_WASM_PATH = path.join(
  REPO_ROOT,
  'wasm',
  'near_signer',
  'pkg-server',
  'wasm_signer_worker_bg.wasm',
);
const THRESHOLD_PRF_WASM_PATH = path.join(
  REPO_ROOT,
  'wasm',
  'threshold_prf',
  'pkg',
  'threshold_prf_bg.wasm',
);

const SDK_ED25519_HSS_APPLICATION_BINDING_DOMAIN_V1 =
  'seams-sdk:ed25519-hss:application-binding:v1';
const BINDING_FACTS = {
  nearEd25519SigningKeyId: 'near-ed25519:wasm-benchmark',
  signingRootId: 'project_single_key_hss:env_single_key_hss',
  signingRootVersion: 'root-v1',
};
const CONTEXT = {
  signingRootId: 'project_single_key_hss:env_single_key_hss',
  nearAccountId: 'single-key-hss-active.testnet',
  keyPurpose: 'near-ed25519-signing',
  keyVersion: 'root-v1',
  participantIds: [1, 2],
  derivationVersion: 1,
  applicationBindingDigestB64u: computeApplicationBindingDigestB64u(BINDING_FACTS),
};
const RELAYER_KEY_ID = 'ed25519:relayer-key-id';
const PRF_FIRST_B64U = Buffer.alloc(32, 11).toString('base64url');
const THRESHOLD_PRF_THRESHOLD = 2;
const THRESHOLD_PRF_SHARE_COUNT = 3;
const SIGNING_ROOT_SHARE_WIRE_HEX = [
  '0001d73847ea1a0888265782eb6998f3d905b8275fa4e5fda6556ddacc3b28741702',
  '0002b3ee4da8422ffeebb66bd0b55afb5d072f55aa324698a89c0a8b234042fd6c0f',
];
const IMPORTANT_TIMING_BUCKETS = [
  'hiddenEvalTotalMs',
  'hiddenEvalRoundCoreMs',
  'hiddenEvalRoundNewABitsMs',
  'hiddenEvalRoundNewEBitsMs',
  'hiddenEvalRoundChMs',
  'hiddenEvalRoundMajMs',
  'hiddenEvalMessageScheduleMs',
  'hiddenEvalMessageScheduleAccumulationMs',
  'hiddenEvalOutputProjectorMs',
  'hiddenEvalOutputProjectorCoreMs',
  'hiddenEvalOutputProjectorClampAMs',
  'hiddenEvalOutputProjectorReduceAMs',
  'hiddenEvalOutputProjectorTauMs',
  'hiddenEvalOutputProjectorMaskShareMs',
  'hiddenEvalOutputProjectorMaskAddMs',
  'hiddenEvalOutputProjectorClientBaseMs',
  'hiddenEvalOutputProjectorClientOutputMs',
  'hiddenEvalOutputProjectorTauDoubleMs',
  'hiddenEvalOutputProjectorRelayerOutputMs',
  'hiddenEvalOutputProjectorBundleBuildMs',
  'hiddenEvalOutputProjectorLocalWordMaterializations',
  'hiddenEvalLogicalLocalWordMaterializations',
  'hiddenEvalLogicalSharedWordMaterializations',
  'hiddenEvalLogicalTransportWordMaterializations',
  'hiddenEvalLogicalCommitmentMaterializations',
  'hiddenEvalLogicalProvenanceDigestMaterializations',
  'hiddenEvalLogicalCommitmentDerivations',
  'hiddenEvalLogicalProvenanceDigestDerivations',
  'hiddenEvalLogicalLabelWrites',
  'hiddenEvalLogicalLabelFormatAllocations',
  'buildArtifactMs',
  'materializeSessionMs',
  'encodeArtifactMs',
  'decodeEvaluatorDriverStateMs',
  'decodeEvaluatorOtStateMs',
  'decodeServerInputDeliveryMs',
  'decodeClientRequestMessageMs',
  'decodeClientOutputMaskMs',
];
const COUNT_TIMING_BUCKETS = new Set(
  IMPORTANT_TIMING_BUCKETS.filter((bucket) => !bucket.endsWith('Ms')),
);

let wasmReady = false;

function parseArgs(argv) {
  const out = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) continue;
    const [key, inlineValue] = arg.split('=', 2);
    if (inlineValue !== undefined) {
      out.set(key, inlineValue);
      continue;
    }
    const next = argv[index + 1];
    if (next && !next.startsWith('--')) {
      out.set(key, next);
      index += 1;
    } else {
      out.set(key, true);
    }
  }
  return out;
}

const CLI_ARGS = parseArgs(process.argv.slice(2));
const WARMUP = numberOption('--warmup', 2);
const ITERATIONS = numberOption('--iterations', 8);
const BROWSER_WARMUP = numberOption('--browser-warmup', 1);
const BROWSER_ITERATIONS = numberOption('--browser-iterations', 4);
const SKIP_BROWSER = Boolean(CLI_ARGS.get('--skip-browser'));

function numberOption(name, fallback) {
  const raw = CLI_ARGS.get(name);
  if (raw === undefined || raw === true) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : fallback;
}

function ensureWasm() {
  if (wasmReady) return;
  initHssClientSignerWasmSync({ module: readFileSync(HSS_CLIENT_SIGNER_WASM_PATH) });
  initNearSignerWasmSync({ module: readFileSync(NEAR_SIGNER_SERVER_WASM_PATH) });
  init_worker();
  initThresholdPrfWasmSync({ module: readFileSync(THRESHOLD_PRF_WASM_PATH) });
  init_threshold_prf();
  wasmReady = true;
}

function b64uToBytes(value) {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

function bytesToB64u(value) {
  return Buffer.from(value).toString('base64url');
}

function requireBytes(value, label) {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} must be bytes`);
  }
  return value;
}

function computeApplicationBindingDigestB64u(input) {
  return createHash('sha256').update(encodeApplicationBindingFacts(input)).digest('base64url');
}

function encodeApplicationBindingFacts(input) {
  const out = [];
  const domainBytes = new TextEncoder().encode(SDK_ED25519_HSS_APPLICATION_BINDING_DOMAIN_V1);
  pushU32(out, domainBytes.length);
  out.push(...domainBytes);
  pushLengthDelimitedField(out, 'nearEd25519SigningKeyId', input.nearEd25519SigningKeyId);
  pushLengthDelimitedField(out, 'signingRootId', input.signingRootId);
  pushLengthDelimitedField(out, 'signingRootVersion', input.signingRootVersion);
  return new Uint8Array(out);
}

function pushLengthDelimitedField(out, label, value) {
  const labelBytes = new TextEncoder().encode(label);
  const valueBytes = new TextEncoder().encode(requireNonEmptyString(value, label));
  pushU32(out, labelBytes.length);
  out.push(...labelBytes);
  pushU32(out, valueBytes.length);
  out.push(...valueBytes);
}

function pushU32(out, value) {
  out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function requireNonEmptyString(value, field) {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function loadPlaywright() {
  try {
    return requireFromRoot('playwright');
  } catch (rootError) {
    try {
      return requireFromTests('playwright');
    } catch (testsPlaywrightError) {
      try {
        return requireFromTests('@playwright/test');
      } catch (testsPackageError) {
        throw new Error(
          `playwright is not resolvable from the root or tests workspace: ${rootError.message}; ${testsPlaywrightError.message}; ${testsPackageError.message}`,
        );
      }
    }
  }
}

function hexToBytes(value) {
  return new Uint8Array(Buffer.from(value, 'hex'));
}

function shareWireSetBytes(hexValues) {
  const chunks = hexValues.map(hexToBytes);
  const out = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function byteLengthJson(value) {
  return Buffer.byteLength(JSON.stringify(value), 'utf8');
}

function b64uByteLength(value) {
  return Buffer.byteLength(Buffer.from(String(value || ''), 'base64url'));
}

function stats(values) {
  const finite = values.filter((value) => Number.isFinite(value));
  if (finite.length === 0) {
    return {
      median: 0,
      p95: 0,
      mean: 0,
      min: 0,
      max: 0,
    };
  }
  const sorted = [...finite].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
  const p95Index = Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1);
  const mean = sorted.reduce((sum, value) => sum + value, 0) / sorted.length;
  return {
    median: Number(median.toFixed(3)),
    p95: Number(sorted[p95Index].toFixed(3)),
    mean: Number(mean.toFixed(3)),
    min: Number(sorted[0].toFixed(3)),
    max: Number(sorted[sorted.length - 1].toFixed(3)),
  };
}

function sanitizeTimings(timings) {
  const out = {};
  for (const [key, value] of Object.entries(timings || {})) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) out[key] = numeric;
  }
  return out;
}

function summarizeTimedSamples(label, samples, { warmup, iterations }) {
  const timingKeys = new Set();
  for (const sample of samples) {
    for (const key of Object.keys(sample.timings || {})) {
      timingKeys.add(key);
    }
  }
  const orderedTimingKeys = [
    ...IMPORTANT_TIMING_BUCKETS.filter((key) => timingKeys.has(key)),
    ...[...timingKeys].filter((key) => !IMPORTANT_TIMING_BUCKETS.includes(key)).sort(),
  ];
  return {
    label,
    warmup,
    iterations,
    wall: stats(samples.map((sample) => sample.wallMs)),
    artifactBytes: stats(samples.map((sample) => sample.artifactBytes)),
    timingBuckets: orderedTimingKeys.map((key) => ({
      label: key,
      ...stats(samples.map((sample) => sample.timings?.[key])),
    })),
    samples: samples.map((sample) => ({
      wallMs: Number(sample.wallMs.toFixed(3)),
      artifactBytes: sample.artifactBytes,
      timings: Object.fromEntries(
        Object.entries(sample.timings || {}).map(([key, value]) => [key, Number(value.toFixed(3))]),
      ),
    })),
  };
}

function assertContextBinding(label, actual, expected) {
  if (actual !== expected) {
    throw new Error(`${label} context binding mismatch`);
  }
}

function createBenchmarkState() {
  const preparedServerSession = threshold_ed25519_hss_prepare_server_session(CONTEXT);
  const preparedSession = {
    contextBindingB64u: preparedServerSession.contextBindingB64u,
    evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
  };
  const clientInputs = derive_threshold_ed25519_hss_client_inputs({
    ...CONTEXT,
    prfFirstB64u: PRF_FIRST_B64U,
  });
  const serverInputs = threshold_prf_derive_ed25519_hss_server_inputs(
    THRESHOLD_PRF_THRESHOLD,
    THRESHOLD_PRF_SHARE_COUNT,
    shareWireSetBytes(SIGNING_ROOT_SHARE_WIRE_HEX),
    b64uToBytes(CONTEXT.applicationBindingDigestB64u),
  );
  const clientOutputMask = threshold_ed25519_hss_derive_client_output_mask({
    ...CONTEXT,
    contextBindingB64u: preparedSession.contextBindingB64u,
    operation: 'registration',
    relayerKeyId: RELAYER_KEY_ID,
    clientRecoverableSecretB64u: PRF_FIRST_B64U,
  });
  assertContextBinding(
    'client inputs',
    String(clientInputs.contextBindingB64u || ''),
    preparedSession.contextBindingB64u,
  );
  assertContextBinding(
    'server inputs',
    bytesToB64u(serverInputs.contextBinding),
    preparedSession.contextBindingB64u,
  );

  const state = {
    context: CONTEXT,
    relayerKeyId: RELAYER_KEY_ID,
    prfFirstB64u: PRF_FIRST_B64U,
    shareWireHex: SIGNING_ROOT_SHARE_WIRE_HEX,
    thresholdPrfThreshold: THRESHOLD_PRF_THRESHOLD,
    thresholdPrfShareCount: THRESHOLD_PRF_SHARE_COUNT,
    preparedServerSession,
    preparedSession,
    storedPreparedServerSession: {
      preparedSessionHandle: preparedServerSession.preparedSessionHandle,
      garblerDriverStateBytes: b64uToBytes(preparedServerSession.garblerDriverStateB64u),
    },
    clientInputs,
    serverInputs: {
      yRelayerBytes: requireBytes(serverInputs.yRelayer, 'serverInputs.yRelayer'),
      tauRelayerBytes: requireBytes(serverInputs.tauRelayer, 'serverInputs.tauRelayer'),
    },
    clientOutputMaskB64u: clientOutputMask.clientOutputMaskB64u,
  };
  const fixedClientRequest = prepareClientRequest(state);
  const fixedServerInputDelivery = prepareServerInputDelivery(state, fixedClientRequest);
  state.serializedArtifactPayload = {
    sessionSource: 'serialized_state',
    evaluatorDriverStateB64u: preparedSession.evaluatorDriverStateB64u,
    clientRequestMessageB64u: fixedClientRequest.clientRequestMessageB64u,
    evaluatorOtStateB64u: fixedClientRequest.evaluatorOtStateB64u,
    serverInputDeliveryB64u: fixedServerInputDelivery.serverInputDeliveryB64u,
    clientOutputMaskB64u: clientOutputMask.clientOutputMaskB64u,
  };
  return state;
}

function prepareClientRequest(state) {
  return threshold_ed25519_hss_prepare_client_request({
    evaluatorDriverStateB64u: state.preparedSession.evaluatorDriverStateB64u,
    clientOtOfferMessageB64u: state.preparedServerSession.clientOtOfferMessageB64u,
    yClientB64u: state.clientInputs.yClientB64u,
    tauClientB64u: state.clientInputs.tauClientB64u,
  });
}

function prepareServerInputDelivery(state, clientRequest) {
  const delivery = threshold_ed25519_hss_prepare_role_separated_server_input_delivery({
    operation: 'registration',
    preparedSessionHandle: state.storedPreparedServerSession.preparedSessionHandle,
    garblerDriverStateBytes: state.storedPreparedServerSession.garblerDriverStateBytes,
    clientRequestMessageBytes: b64uToBytes(clientRequest.clientRequestMessageB64u),
    yRelayerBytes: state.serverInputs.yRelayerBytes,
    tauRelayerBytes: state.serverInputs.tauRelayerBytes,
  });
  assertContextBinding(
    'server input delivery',
    String(delivery.contextBindingB64u || ''),
    state.preparedSession.contextBindingB64u,
  );
  return delivery;
}

function makeWorkerHandleArtifactPayload(state) {
  const clientRequest = prepareClientRequest(state);
  const delivery = prepareServerInputDelivery(state, clientRequest);
  return {
    sessionSource: 'worker_handle',
    workerSessionHandle: clientRequest.workerSessionHandle,
    clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
    evaluatorOtStateB64u: clientRequest.evaluatorOtStateB64u,
    serverInputDeliveryB64u: delivery.serverInputDeliveryB64u,
    clientOutputMaskB64u: state.clientOutputMaskB64u,
  };
}

function measureArtifact(label, payloadFactory, { warmup, iterations }) {
  for (let index = 0; index < warmup; index += 1) {
    threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact(payloadFactory());
  }
  const samples = [];
  for (let index = 0; index < iterations; index += 1) {
    const payload = payloadFactory();
    const started = performance.now();
    const artifact = threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact(payload);
    const wallMs = performance.now() - started;
    samples.push({
      wallMs,
      artifactBytes: b64uByteLength(artifact.stagedEvaluatorArtifactB64u),
      timings: sanitizeTimings(artifact.timings),
    });
  }
  return summarizeTimedSamples(label, samples, { warmup, iterations });
}

async function withStaticServer(fn) {
  const server = http.createServer((req, res) => {
    try {
      const url = new URL(req.url || '/', 'http://127.0.0.1');
      if (url.pathname === '/' || url.pathname === '/blank') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        res.end('<!doctype html><meta charset="utf-8"><title>ed25519-hss wasm bench</title>');
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

async function measureBrowserWorkerHandleArtifact(state) {
  const { chromium } = loadPlaywright();
  return await withStaticServer(async (origin) => {
    const browser = await chromium.launch({ headless: true });
    try {
      const page = await browser.newPage();
      await page.goto(`${origin}/blank`);
      const samples = await page.evaluate(
        async ({
          origin: pageOrigin,
          context,
          relayerKeyId,
          prfFirstB64u,
          shareWireHex,
          thresholdPrfThreshold,
          thresholdPrfShareCount,
          options,
        }) => {
          const hss = await import(`${pageOrigin}/wasm/hss_client_signer/pkg/hss_client_signer.js`);
          const near = await import(
            `${pageOrigin}/wasm/near_signer/pkg-server/wasm_signer_worker.js`
          );
          const prf = await import(`${pageOrigin}/wasm/threshold_prf/pkg/threshold_prf.js`);
          await hss.default(`${pageOrigin}/wasm/hss_client_signer/pkg/hss_client_signer_bg.wasm`);
          await near.default(
            `${pageOrigin}/wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm`,
          );
          near.init_worker();
          await prf.default(`${pageOrigin}/wasm/threshold_prf/pkg/threshold_prf_bg.wasm`);
          prf.init_threshold_prf();

          const b64uToBytes = (value) => {
            const base64 = String(value || '')
              .replace(/-/g, '+')
              .replace(/_/g, '/');
            const padded = `${base64}${'='.repeat((4 - (base64.length % 4)) % 4)}`;
            const binary = atob(padded);
            const out = new Uint8Array(binary.length);
            for (let index = 0; index < binary.length; index += 1) {
              out[index] = binary.charCodeAt(index);
            }
            return out;
          };
          const hexToBytes = (value) => {
            const out = new Uint8Array(value.length / 2);
            for (let index = 0; index < out.length; index += 1) {
              out[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
            }
            return out;
          };
          const shareWireSetBytes = (hexValues) => {
            const chunks = hexValues.map(hexToBytes);
            const out = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
            let offset = 0;
            for (const chunk of chunks) {
              out.set(chunk, offset);
              offset += chunk.length;
            }
            return out;
          };
          const b64uByteLength = (value) => b64uToBytes(value).length;
          const sanitizeTimings = (timings) => {
            const out = {};
            for (const [key, value] of Object.entries(timings || {})) {
              const numeric = Number(value);
              if (Number.isFinite(numeric)) out[key] = numeric;
            }
            return out;
          };

          const preparedServerSession = near.threshold_ed25519_hss_prepare_server_session(context);
          const clientInputs = hss.derive_threshold_ed25519_hss_client_inputs({
            ...context,
            prfFirstB64u,
          });
          const serverInputs = prf.threshold_prf_derive_ed25519_hss_server_inputs(
            thresholdPrfThreshold,
            thresholdPrfShareCount,
            shareWireSetBytes(shareWireHex),
            b64uToBytes(context.applicationBindingDigestB64u),
          );
          const clientOutputMask = hss.threshold_ed25519_hss_derive_client_output_mask({
            ...context,
            contextBindingB64u: preparedServerSession.contextBindingB64u,
            operation: 'registration',
            relayerKeyId,
            clientRecoverableSecretB64u: prfFirstB64u,
          });

          const makePayload = () => {
            const clientRequest = hss.threshold_ed25519_hss_prepare_client_request({
              evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
              clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
              yClientB64u: clientInputs.yClientB64u,
              tauClientB64u: clientInputs.tauClientB64u,
            });
            const delivery =
              near.threshold_ed25519_hss_prepare_role_separated_server_input_delivery({
                operation: 'registration',
                preparedSessionHandle: preparedServerSession.preparedSessionHandle,
                garblerDriverStateBytes: b64uToBytes(preparedServerSession.garblerDriverStateB64u),
                clientRequestMessageBytes: b64uToBytes(clientRequest.clientRequestMessageB64u),
                yRelayerBytes: serverInputs.yRelayer,
                tauRelayerBytes: serverInputs.tauRelayer,
              });
            return {
              sessionSource: 'worker_handle',
              workerSessionHandle: clientRequest.workerSessionHandle,
              clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
              evaluatorOtStateB64u: clientRequest.evaluatorOtStateB64u,
              serverInputDeliveryB64u: delivery.serverInputDeliveryB64u,
              clientOutputMaskB64u: clientOutputMask.clientOutputMaskB64u,
            };
          };

          for (let index = 0; index < options.warmup; index += 1) {
            hss.threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact(makePayload());
          }
          const samples = [];
          for (let index = 0; index < options.iterations; index += 1) {
            const payload = makePayload();
            const started = performance.now();
            const artifact =
              hss.threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact(payload);
            samples.push({
              wallMs: performance.now() - started,
              artifactBytes: b64uByteLength(artifact.stagedEvaluatorArtifactB64u),
              timings: sanitizeTimings(artifact.timings),
            });
          }
          near.threshold_ed25519_hss_release_prepared_server_session(
            preparedServerSession.preparedSessionHandle,
          );
          return samples;
        },
        {
          origin,
          context: state.context,
	          relayerKeyId: state.relayerKeyId,
	          prfFirstB64u: state.prfFirstB64u,
	          shareWireHex: state.shareWireHex,
	          thresholdPrfThreshold: state.thresholdPrfThreshold,
	          thresholdPrfShareCount: state.thresholdPrfShareCount,
	          options: {
            warmup: BROWSER_WARMUP,
            iterations: BROWSER_ITERATIONS,
          },
        },
      );
      return summarizeTimedSamples('browser_client_artifact_worker_handle_wasm', samples, {
        warmup: BROWSER_WARMUP,
        iterations: BROWSER_ITERATIONS,
      });
    } finally {
      await browser.close();
    }
  });
}

function renderBenchmarkTable(benchmarks) {
  const lines = [];
  lines.push('| Path | Median | p95 | Mean | Min | Max | Artifact bytes |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: | ---: |');
  for (const bench of benchmarks) {
    lines.push(
      `| \`${bench.label}\` | \`${bench.wall.median} ms\` | \`${bench.wall.p95} ms\` | \`${bench.wall.mean} ms\` | \`${bench.wall.min} ms\` | \`${bench.wall.max} ms\` | \`${bench.artifactBytes.median}\` |`,
    );
  }
  return lines;
}

function renderTimingTables(benchmarks) {
  const lines = [];
  for (const bench of benchmarks) {
    lines.push(`### \`${bench.label}\``);
    lines.push('');
    lines.push('| Bucket | Median | p95 | Mean | Min | Max |');
    lines.push('| --- | ---: | ---: | ---: | ---: | ---: |');
    for (const bucket of bench.timingBuckets) {
      if (!IMPORTANT_TIMING_BUCKETS.includes(bucket.label)) continue;
      const unit = COUNT_TIMING_BUCKETS.has(bucket.label) ? '' : ' ms';
      lines.push(
        `| \`${bucket.label}\` | \`${bucket.median}${unit}\` | \`${bucket.p95}${unit}\` | \`${bucket.mean}${unit}\` | \`${bucket.min}${unit}\` | \`${bucket.max}${unit}\` |`,
      );
    }
    lines.push('');
  }
  return lines;
}

function renderMarkdown(summary) {
  const lines = [];
  lines.push('# Ed25519 HSS WASM Benchmark Summary');
  lines.push('');
  lines.push(`- Run ID: \`${summary.runId}\``);
  lines.push('- Runtime: direct WASM exports for Ed25519 HSS client/server ceremony pieces');
  lines.push(
    `- Node samples: ${summary.options.iterations} iterations after ${summary.options.warmup} warmups`,
  );
  lines.push(
    `- Browser samples: ${
      summary.options.skipBrowser
        ? 'skipped'
        : `${summary.options.browserIterations} iterations after ${summary.options.browserWarmup} warmups`
    }`,
  );
  lines.push('');
  lines.push('## Wall Time');
  lines.push('');
  lines.push(...renderBenchmarkTable(summary.benchmarks));
  lines.push('');
  lines.push('## Hidden-Eval Buckets');
  lines.push('');
  lines.push(...renderTimingTables(summary.benchmarks));
  lines.push('## Serialized Sizes');
  lines.push('');
  lines.push('| Payload | Bytes |');
  lines.push('| --- | ---: |');
  for (const size of summary.serializedSizes) {
    lines.push(`| \`${size.label}\` | \`${size.bytes}\` |`);
  }
  lines.push('');
  lines.push('Notes:');
  lines.push(
    '- The worker-handle paths exclude client request and server delivery setup from wall time.',
  );
  lines.push('- Internal timings come from the `hss_client_signer` staged-artifact export.');
  lines.push('- This benchmark is diagnostic-only and does not alter crypto control flow.');
  return `${lines.join('\n')}\n`;
}

async function main() {
  ensureWasm();
  const state = createBenchmarkState();
  const initialArtifact = threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact(
    state.serializedArtifactPayload,
  );
  assertContextBinding(
    'initial artifact',
    String(initialArtifact.contextBindingB64u || ''),
    state.preparedSession.contextBindingB64u,
  );

  const benchmarks = [
    measureArtifact(
      'node_client_artifact_serialized_state_wasm',
      () => state.serializedArtifactPayload,
      {
        warmup: WARMUP,
        iterations: ITERATIONS,
      },
    ),
    measureArtifact(
      'node_client_artifact_worker_handle_wasm',
      () => makeWorkerHandleArtifactPayload(state),
      {
        warmup: WARMUP,
        iterations: ITERATIONS,
      },
    ),
  ];
  if (!SKIP_BROWSER) {
    benchmarks.push(await measureBrowserWorkerHandleArtifact(state));
  }

  const serializedSizes = [
    { label: 'prepared_session_json', bytes: byteLengthJson(state.preparedSession) },
    {
      label: 'prepared_server_session_json',
      bytes: byteLengthJson(state.preparedServerSession),
    },
    {
      label: 'serialized_artifact_payload_json',
      bytes: byteLengthJson(state.serializedArtifactPayload),
    },
    {
      label: 'staged_evaluator_artifact_bytes',
      bytes: b64uByteLength(initialArtifact.stagedEvaluatorArtifactB64u),
    },
  ];

  const runId = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = path.join(OUT_ROOT, runId);
  mkdirSync(outDir, { recursive: true });

  const summary = {
    runId,
    runtime: 'node-and-browser-hosted-wasm-web-target',
    context: CONTEXT,
    options: {
      warmup: WARMUP,
      iterations: ITERATIONS,
      browserWarmup: BROWSER_WARMUP,
      browserIterations: BROWSER_ITERATIONS,
      skipBrowser: SKIP_BROWSER,
    },
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
    const hiddenEvalTotal = bench.timingBuckets.find(
      (bucket) => bucket.label === 'hiddenEvalTotalMs',
    );
    const roundCore = bench.timingBuckets.find(
      (bucket) => bucket.label === 'hiddenEvalRoundCoreMs',
    );
    console.log(
      `[benchmark] ${bench.label} wall_median_ms=${bench.wall.median} wall_p95_ms=${bench.wall.p95} hidden_eval_median_ms=${hiddenEvalTotal?.median ?? 0} round_core_median_ms=${roundCore?.median ?? 0}`,
    );
  }
}

await main();
