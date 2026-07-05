import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  derive_threshold_ed25519_hss_client_inputs,
  initSync as initHssClientSignerWasmSync,
  threshold_ed25519_hss_prepare_add_stage_request_message,
  threshold_ed25519_hss_prepare_client_request,
} from '../../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import {
  initSync as initNearSignerWasmSync,
  init_worker,
  threshold_ed25519_hss_advance_server_eval_state,
  threshold_ed25519_hss_prepare_role_separated_server_input_delivery,
  threshold_ed25519_hss_prepare_server_session,
} from '../../../wasm/near_signer/pkg-server/wasm_signer_worker.js';
import {
  init_threshold_prf,
  initSync as initThresholdPrfWasmSync,
  threshold_prf_derive_ed25519_hss_server_inputs,
} from '../../../wasm/threshold_prf/pkg/threshold_prf.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../../..');
const OUT_ROOT = path.join(REPO_ROOT, 'benchmarks', 'ed25519-hss-advance-sources', 'out');
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

// Every probe result is only comparable when each WASM artifact was built from
// the sources currently on disk. Each entry lists the crate roots whose edits
// require a rebuild of that artifact (own crate plus path dependencies).
const WASM_ARTIFACTS = [
  {
    name: 'near_signer_server',
    wasmPath: NEAR_SIGNER_SERVER_WASM_PATH,
    sourceRoots: [
      'wasm/near_signer/src',
      'wasm/near_signer/Cargo.toml',
      'crates/ed25519-hss/src',
      'crates/ed25519-hss/Cargo.toml',
      'crates/signer-core/src',
      'crates/signer-core/Cargo.toml',
    ],
  },
  {
    name: 'hss_client_signer',
    wasmPath: HSS_CLIENT_SIGNER_WASM_PATH,
    sourceRoots: [
      'wasm/hss_client_signer/src',
      'wasm/hss_client_signer/Cargo.toml',
      'crates/ed25519-hss/src',
      'crates/ed25519-hss/Cargo.toml',
      'crates/ecdsa-hss/src',
      'crates/ecdsa-hss/Cargo.toml',
      'crates/signer-core/src',
      'crates/signer-core/Cargo.toml',
    ],
  },
  {
    name: 'threshold_prf',
    wasmPath: THRESHOLD_PRF_WASM_PATH,
    sourceRoots: [
      'wasm/threshold_prf/src',
      'wasm/threshold_prf/Cargo.toml',
      'crates/threshold-prf/src',
      'crates/threshold-prf/Cargo.toml',
    ],
  },
];
const PRUNED_DIR_NAMES = new Set(['target', 'pkg', 'pkg-server', 'node_modules', '.git', 'dist']);

const SDK_ED25519_HSS_APPLICATION_BINDING_DOMAIN_V1 =
  'seams-sdk:ed25519-hss:application-binding:v1';
const BINDING_FACTS = {
  nearEd25519SigningKeyId: 'near-ed25519:advance-probe',
  signingRootId: 'project_single_key_hss:env_single_key_hss',
  signingRootVersion: 'root-v1',
};
const CANONICAL_CONTEXT = {
  applicationBindingDigestB64u: computeApplicationBindingDigestB64u(BINDING_FACTS),
  participantIds: [1, 2],
};
const PRF_FIRST_B64U = Buffer.alloc(32, 11).toString('base64url');
const THRESHOLD_PRF_THRESHOLD = 2;
const THRESHOLD_PRF_SHARE_COUNT = 3;
const SIGNING_ROOT_SHARE_WIRE_HEX = [
  '0001d73847ea1a0888265782eb6998f3d905b8275fa4e5fda6556ddacc3b28741702',
  '0002b3ee4da8422ffeebb66bd0b55afb5d072f55aa324698a89c0a8b234042fd6c0f',
];

const CLI_ARGS = parseArgs(process.argv.slice(2));
const WARMUP = numberOption('--warmup', 1);
const ITERATIONS = numberOption('--iterations', 3);
const NATIVE_URL = stringOption('--native-url');
const NATIVE_WARMUP_URL = stringOption('--native-warmup-url');
const WORKERD_URL = stringOption('--workerd-url');
const WORKERD_WARMUP_URL = stringOption('--workerd-warmup-url');
const SKIP_OPTIONAL = Boolean(CLI_ARGS.get('--skip-optional'));
const ALLOW_STALE_ARTIFACT = Boolean(CLI_ARGS.get('--allow-stale-artifact'));

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
      continue;
    }
    out.set(key, true);
  }
  return out;
}

function numberOption(name, fallback) {
  const raw = CLI_ARGS.get(name);
  if (raw === undefined || raw === true) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : fallback;
}

function stringOption(name) {
  const raw = CLI_ARGS.get(name);
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  return trimmed || null;
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

function b64uToBytes(value) {
  return new Uint8Array(Buffer.from(value, 'base64url'));
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

function createAdvanceFixture() {
  const preparedServerSession = threshold_ed25519_hss_prepare_server_session(CANONICAL_CONTEXT);
  const clientInputs = derive_threshold_ed25519_hss_client_inputs({
    ...CANONICAL_CONTEXT,
    prfFirstB64u: PRF_FIRST_B64U,
  });
  const serverInputs = threshold_prf_derive_ed25519_hss_server_inputs(
    THRESHOLD_PRF_THRESHOLD,
    THRESHOLD_PRF_SHARE_COUNT,
    shareWireSetBytes(SIGNING_ROOT_SHARE_WIRE_HEX),
    b64uToBytes(CANONICAL_CONTEXT.applicationBindingDigestB64u),
  );
  assertContextBinding('client inputs', clientInputs.contextBindingB64u, preparedServerSession.contextBindingB64u);
  assertContextBinding(
    'server inputs',
    bytesToB64u(serverInputs.contextBinding),
    preparedServerSession.contextBindingB64u,
  );

  const clientRequest = threshold_ed25519_hss_prepare_client_request({
    evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
    clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
    yClientB64u: clientInputs.yClientB64u,
    tauClientB64u: clientInputs.tauClientB64u,
  });
  const delivery = threshold_ed25519_hss_prepare_role_separated_server_input_delivery({
    operation: 'registration',
    preparedSessionHandle: preparedServerSession.preparedSessionHandle,
    garblerDriverStateBytes: b64uToBytes(preparedServerSession.garblerDriverStateB64u),
    clientRequestMessageBytes: b64uToBytes(clientRequest.clientRequestMessageB64u),
    yRelayerBytes: requireBytes(serverInputs.yRelayer, 'serverInputs.yRelayer'),
    tauRelayerBytes: requireBytes(serverInputs.tauRelayer, 'serverInputs.tauRelayer'),
  });
  assertContextBinding('server delivery', delivery.contextBindingB64u, preparedServerSession.contextBindingB64u);

  const addStage = threshold_ed25519_hss_prepare_add_stage_request_message({
    sessionSource: 'serialized_state',
    evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
    clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
    evaluatorOtStateB64u: clientRequest.evaluatorOtStateB64u,
    serverInputDeliveryB64u: delivery.serverInputDeliveryB64u,
  });
  assertContextBinding('add-stage request', addStage.contextBindingB64u, preparedServerSession.contextBindingB64u);

  return {
    kind: 'ed25519_hss_registration_advance_probe_fixture_v1',
    bindingFacts: BINDING_FACTS,
    context: CANONICAL_CONTEXT,
    projectionMode: 'registration_seed_and_output',
    expectedContextBindingB64u: preparedServerSession.contextBindingB64u,
    preparedSessionHandle: preparedServerSession.preparedSessionHandle,
    evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
    garblerDriverStateB64u: preparedServerSession.garblerDriverStateB64u,
    serverEvalStateB64u: delivery.serverEvalStateB64u,
    addStageRequestMessageB64u: addStage.addStageRequestMessageB64u,
  };
}

function assertContextBinding(label, actual, expected) {
  if (String(actual || '') !== String(expected || '')) {
    throw new Error(`${label} context binding mismatch`);
  }
}

function newestPathMtime(targetPath) {
  const entry = statSync(targetPath);
  if (!entry.isDirectory()) {
    return { mtimeMs: entry.mtimeMs, path: targetPath };
  }
  let newest = { mtimeMs: entry.mtimeMs, path: targetPath };
  for (const child of readdirSync(targetPath, { withFileTypes: true })) {
    if (child.isDirectory() && PRUNED_DIR_NAMES.has(child.name)) continue;
    const candidate = newestPathMtime(path.join(targetPath, child.name));
    if (candidate.mtimeMs > newest.mtimeMs) newest = candidate;
  }
  return newest;
}

function collectArtifactProvenance() {
  return WASM_ARTIFACTS.map((artifact) => {
    const wasmStat = statSync(artifact.wasmPath);
    const sha256 = createHash('sha256').update(readFileSync(artifact.wasmPath)).digest('hex');
    let newestSource = { mtimeMs: 0, path: '' };
    for (const root of artifact.sourceRoots) {
      const absolute = path.join(REPO_ROOT, root);
      let candidate;
      try {
        candidate = newestPathMtime(absolute);
      } catch {
        continue;
      }
      if (candidate.mtimeMs > newestSource.mtimeMs) newestSource = candidate;
    }
    return {
      name: artifact.name,
      wasmPath: path.relative(REPO_ROOT, artifact.wasmPath),
      sha256,
      builtAtMs: Math.round(wasmStat.mtimeMs),
      builtAtIso: new Date(wasmStat.mtimeMs).toISOString(),
      newestSourceMtimeMs: Math.round(newestSource.mtimeMs),
      newestSourceIso: new Date(newestSource.mtimeMs).toISOString(),
      newestSourcePath: newestSource.path ? path.relative(REPO_ROOT, newestSource.path) : '',
      stale: newestSource.mtimeMs > wasmStat.mtimeMs,
    };
  });
}

function assertArtifactsFresh(artifacts) {
  const stale = artifacts.filter((artifact) => artifact.stale);
  if (stale.length === 0) return;
  const details = stale
    .map(
      (artifact) =>
        `${artifact.name}: ${artifact.wasmPath} built ${artifact.builtAtIso}, but ${artifact.newestSourcePath} changed ${artifact.newestSourceIso}`,
    )
    .join('\n  ');
  if (ALLOW_STALE_ARTIFACT) {
    console.warn(
      `[benchmark] WARNING: measuring STALE artifacts (results are not comparable across sources):\n  ${details}`,
    );
    return;
  }
  throw new Error(
    `Refusing to benchmark stale WASM artifacts:\n  ${details}\nRun \`pnpm -C packages/sdk-web run build:wasm\` first, or pass --allow-stale-artifact to measure anyway (results will be marked stale).`,
  );
}

function bytesToB64u(value) {
  return Buffer.from(requireBytes(value, 'bytes')).toString('base64url');
}

function requireBytes(value, field) {
  if (value instanceof Uint8Array) return value;
  throw new Error(`${field} must be Uint8Array`);
}

function runNodeServerWasmProbe(fixture) {
  const result = threshold_ed25519_hss_advance_server_eval_state({
    preparedSessionHandle: fixture.preparedSessionHandle,
    evaluatorDriverStateBytes: b64uToBytes(fixture.evaluatorDriverStateB64u),
    garblerDriverStateBytes: b64uToBytes(fixture.garblerDriverStateB64u),
    serverEvalStateBytes: b64uToBytes(fixture.serverEvalStateB64u),
    addStageRequestMessageBytes: b64uToBytes(fixture.addStageRequestMessageB64u),
    projectionMode: fixture.projectionMode,
  });
  assertContextBinding('node server WASM advance', result.contextBindingB64u, fixture.expectedContextBindingB64u);
  return result;
}

async function runHttpProbe(source, url, fixture) {
  const response = await postJson(url, fixture);
  assertContextBinding(`${source} advance`, response.contextBindingB64u, fixture.expectedContextBindingB64u);
  return response;
}

async function runHttpWarmup(source, url, fixture) {
  const response = await postJson(url, fixture);
  if (response?.ok !== true) {
    throw new Error(`${source} warmup did not return ok=true`);
  }
  assertContextBinding(`${source} warmup`, response.contextBindingB64u, fixture.expectedContextBindingB64u);
  return response;
}

function postJson(urlString, payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  const url = new URL(urlString);
  const transport = url.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = transport.request(
      url,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': String(body.byteLength),
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`${urlString} returned ${res.statusCode}: ${text.slice(0, 500)}`));
            return;
          }
          try {
            resolve(JSON.parse(text));
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

async function measureProbe(source, run, fixture) {
  for (let index = 0; index < WARMUP; index += 1) {
    await run(fixture);
  }
  const samples = [];
  for (let index = 0; index < ITERATIONS; index += 1) {
    const startedAt = performance.now();
    const result = await run(fixture);
    const wallMs = performance.now() - startedAt;
    samples.push({
      wallMs: Number(wallMs.toFixed(3)),
      preparedSessionSource: result.preparedSessionSource ?? null,
      fingerprint: responseFingerprint(result),
      timings: sanitizeTimings(result.timings),
    });
  }
  return {
    source,
    status: 'measured',
    warmup: WARMUP,
    iterations: ITERATIONS,
    wall: stats(samples.map((sample) => sample.wallMs)),
    timingBuckets: summarizeTimingBuckets(samples),
    samples,
    fingerprint: samples[0]?.fingerprint ?? null,
  };
}

function skippedProbe(source, reason) {
  return {
    source,
    status: 'skipped',
    reason,
  };
}

function sanitizeTimings(timings) {
  const out = {};
  for (const [key, value] of Object.entries(timings || {})) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) out[key] = Number(numeric.toFixed(3));
  }
  return out;
}

function responseFingerprint(result) {
  return {
    contextBindingB64u: String(result.contextBindingB64u || ''),
    addStageRequestDigestB64u: String(result.addStageRequestDigestB64u || ''),
    projectionMode: String(result.projectionMode || ''),
    advancedServerEvalStateDigestB64u: digestB64uField(
      result.advancedServerEvalStateB64u,
      'advancedServerEvalStateB64u',
    ),
    priorStageResponseMessageDigestB64u: digestB64uField(
      result.priorStageResponseMessageB64u,
      'priorStageResponseMessageB64u',
    ),
  };
}

function digestB64uField(value, field) {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${field} is required`);
  return createHash('sha256').update(Buffer.from(normalized, 'base64url')).digest('base64url');
}

function assertMeasuredFingerprintsMatch(probes) {
  const measured = probes.filter((probe) => probe.status === 'measured');
  const baseline = measured.find((probe) => probe.source === 'node_server_wasm_probe');
  if (!baseline?.fingerprint) return;
  for (const probe of measured) {
    if (!probe.fingerprint) {
      throw new Error(`${probe.source} did not record a response fingerprint`);
    }
    const baselineJson = JSON.stringify(baseline.fingerprint);
    const probeJson = JSON.stringify(probe.fingerprint);
    if (probeJson !== baselineJson) {
      throw new Error(`${probe.source} response fingerprint does not match node_server_wasm_probe`);
    }
  }
}

function summarizeTimingBuckets(samples) {
  const keys = new Set();
  for (const sample of samples) {
    for (const key of Object.keys(sample.timings || {})) {
      keys.add(key);
    }
  }
  return [...keys].sort().map((key) => ({
    label: key,
    ...stats(samples.map((sample) => sample.timings?.[key])),
  }));
}

function stats(values) {
  const finite = values.filter((value) => Number.isFinite(value));
  if (finite.length === 0) {
    return { median: 0, p95: 0, mean: 0, min: 0, max: 0 };
  }
  const sorted = [...finite].sort((left, right) => left - right);
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

function renderMarkdown(summary) {
  const lines = [];
  lines.push(`# Ed25519 HSS Advance Source Probe ${summary.runId}`);
  lines.push('');
  lines.push(`Fixture: \`${summary.fixture.kind}\``);
  lines.push('');
  lines.push('| Source | Status | Median | P95 | Max |');
  lines.push('| --- | --- | ---: | ---: | ---: |');
  for (const probe of summary.probes) {
    if (probe.status !== 'measured') {
      lines.push(`| \`${probe.source}\` | ${probe.reason} | - | - | - |`);
      continue;
    }
    lines.push(
      `| \`${probe.source}\` | measured | \`${probe.wall.median}ms\` | \`${probe.wall.p95}ms\` | \`${probe.wall.max}ms\` |`,
    );
  }
  lines.push('');
  lines.push('Artifacts:');
  lines.push('');
  lines.push('| Artifact | Built | SHA-256 (12) | Freshness |');
  lines.push('| --- | --- | --- | --- |');
  for (const artifact of summary.artifacts) {
    const freshness = artifact.stale
      ? `**STALE** (\`${artifact.newestSourcePath}\` changed ${artifact.newestSourceIso})`
      : 'fresh';
    lines.push(
      `| \`${artifact.name}\` | ${artifact.builtAtIso} | \`${artifact.sha256.slice(0, 12)}\` | ${freshness} |`,
    );
  }
  lines.push('');
  lines.push('Notes:');
  lines.push('- Every measured source consumes the same deterministic advance fixture.');
  lines.push('- Optional endpoint probes are skipped unless their URLs are passed.');
  if (summary.artifacts.some((artifact) => artifact.stale)) {
    lines.push(
      '- WARNING: one or more WASM artifacts were STALE for this run; cross-source comparisons are not valid.',
    );
  }
  return `${lines.join('\n')}\n`;
}

async function main() {
  const artifacts = collectArtifactProvenance();
  assertArtifactsFresh(artifacts);
  ensureWasm();
  const fixture = createAdvanceFixture();
  const probes = [
    await measureProbe('node_server_wasm_probe', runNodeServerWasmProbe, fixture),
  ];
  if (NATIVE_URL) {
    if (NATIVE_WARMUP_URL) {
      await runHttpWarmup('native release', NATIVE_WARMUP_URL, fixture);
    }
    probes.push(
      await measureProbe(
        'native_release_probe',
        (input) => runHttpProbe('native release', NATIVE_URL, input),
        fixture,
      ),
    );
  } else if (SKIP_OPTIONAL) {
    probes.push(skippedProbe('native_release_probe', 'endpoint not configured'));
  }
  if (WORKERD_URL) {
    if (WORKERD_WARMUP_URL) {
      await runHttpWarmup('workerd WASM', WORKERD_WARMUP_URL, fixture);
    }
    probes.push(
      await measureProbe(
        'workerd_wasm_probe',
        (input) => runHttpProbe('workerd WASM', WORKERD_URL, input),
        fixture,
      ),
    );
  } else if (SKIP_OPTIONAL) {
    probes.push(skippedProbe('workerd_wasm_probe', 'endpoint not configured'));
  }
  assertMeasuredFingerprintsMatch(probes);

  const runId = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = path.join(OUT_ROOT, runId);
  mkdirSync(outDir, { recursive: true });
  const summary = {
    kind: 'ed25519_hss_advance_source_probe_summary_v1',
    runId,
    options: {
      warmup: WARMUP,
      iterations: ITERATIONS,
      nativeUrlConfigured: Boolean(NATIVE_URL),
      nativeWarmupUrlConfigured: Boolean(NATIVE_WARMUP_URL),
      workerdUrlConfigured: Boolean(WORKERD_URL),
      workerdWarmupUrlConfigured: Boolean(WORKERD_WARMUP_URL),
      allowStaleArtifact: ALLOW_STALE_ARTIFACT,
    },
    artifacts,
    fixture: {
      kind: fixture.kind,
      bindingFacts: fixture.bindingFacts,
      context: fixture.context,
      projectionMode: fixture.projectionMode,
      expectedContextBindingB64u: fixture.expectedContextBindingB64u,
    },
    probes,
  };
  const rawSummaryPath = path.join(outDir, 'raw-summary.json');
  const markdownPath = path.join(outDir, 'summary.md');
  writeFileSync(rawSummaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  writeFileSync(markdownPath, renderMarkdown(summary));

  console.log(`[benchmark] run_id=${runId}`);
  console.log(`[benchmark] summary_json=${rawSummaryPath}`);
  console.log(`[benchmark] summary_markdown=${markdownPath}`);
  for (const artifact of artifacts) {
    console.log(
      `[benchmark] artifact ${artifact.name} sha256=${artifact.sha256.slice(0, 12)} built=${artifact.builtAtIso}${artifact.stale ? ' STALE' : ''}`,
    );
  }
  for (const probe of probes) {
    if (probe.status !== 'measured') {
      console.log(`[benchmark] ${probe.source} skipped reason="${probe.reason}"`);
      continue;
    }
    console.log(
      `[benchmark] ${probe.source} median_ms=${probe.wall.median} p95_ms=${probe.wall.p95} max_ms=${probe.wall.max}`,
    );
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
