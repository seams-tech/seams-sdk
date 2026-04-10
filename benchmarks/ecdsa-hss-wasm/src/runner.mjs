import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  initSync as initEthSignerSync,
  ecdsa_hss_bootstrap_non_export_sign,
  ecdsa_hss_derive_additive_shares,
  ecdsa_hss_derive_canonical_secret,
  ecdsa_hss_explicit_export,
  ecdsa_hss_sign_non_export,
  ecdsa_hss_sign_non_export_profiled,
} from '../../../wasm/eth_signer/pkg/eth_signer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../../..');
const OUT_ROOT = path.join(REPO_ROOT, 'benchmarks', 'ecdsa-hss-wasm', 'out');
const FIXTURE_PATH = path.join(REPO_ROOT, 'crates', 'ecdsa-hss', 'fixtures', 'phase1_v1.json');
const WASM_PATH = path.join(REPO_ROOT, 'wasm', 'eth_signer', 'pkg', 'eth_signer_bg.wasm');

let wasmReady = false;

function ensureWasm() {
  if (wasmReady) return;
  const wasmBytes = readFileSync(WASM_PATH);
  initEthSignerSync({ module: wasmBytes });
  wasmReady = true;
}

function readRepresentativeFixture() {
  const parsed = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'));
  const fixture = parsed.fixtures.find((entry) => entry.name === 'derived-beta');
  if (!fixture) throw new Error('Missing derived-beta fixture');
  return {
    nearAccountId: fixture.context.near_account_id,
    keyPurpose: fixture.context.key_purpose,
    keyVersion: fixture.context.key_version,
    yClient32Le: Buffer.from(fixture.inputs.y_client32_le_hex, 'hex'),
    yRelayer32Le: Buffer.from(fixture.inputs.y_relayer32_le_hex, 'hex'),
  };
}

function fixedDigest32(label) {
  const bytes = new TextEncoder().encode(label);
  const out = new Uint8Array(32);
  const hash = createHash('sha256').update(bytes).digest();
  out.set(hash.subarray(0, 32));
  return out;
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

function toByteArray(bufferLike) {
  const u8 = bufferLike instanceof Uint8Array ? bufferLike : new Uint8Array(bufferLike);
  return Array.from(u8);
}

function makeRootPayload(fixture) {
  return {
    nearAccountId: fixture.nearAccountId,
    keyPurpose: fixture.keyPurpose,
    keyVersion: fixture.keyVersion,
    yClient32Le: toByteArray(fixture.yClient32Le),
    yRelayer32Le: toByteArray(fixture.yRelayer32Le),
  };
}

function makeSignPayload(fixture) {
  return {
    ...makeRootPayload(fixture),
    digest32: toByteArray(fixedDigest32('ecdsa-hss/wasm-bench/digest')),
    entropy32: toByteArray(fixedDigest32('ecdsa-hss/wasm-bench/entropy')),
  };
}

function renderMarkdown(summary) {
  const lines = [];
  lines.push('# `ecdsa-hss` WASM Benchmark Summary');
  lines.push('');
  lines.push(`- Run ID: \`${summary.runId}\``);
  lines.push('- Runtime: Node-hosted wasm (`wasm/eth_signer/pkg`, web target)');
  lines.push('- Scope: crate lifecycle through wasm boundary');
  lines.push('');
  lines.push('| Path | Median | Mean | Min | Max |');
  lines.push('| --- | ---: | ---: | ---: | ---: |');
  for (const bench of summary.benchmarks) {
    lines.push(
      `| \`${bench.label}\` | \`${bench.medianMs} ms\` | \`${bench.meanMs} ms\` | \`${bench.minMs} ms\` | \`${bench.maxMs} ms\` |`,
    );
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

function summarizeSeries(label, values) {
  return {
    label,
    medianMs: Number(median(values).toFixed(3)),
    meanMs: Number(mean(values).toFixed(3)),
    minMs: Number(Math.min(...values).toFixed(3)),
    maxMs: Number(Math.max(...values).toFixed(3)),
    samplesMs: values.map((value) => Number(value.toFixed(3))),
  };
}

function main() {
  ensureWasm();
  const fixture = readRepresentativeFixture();
  const rootPayload = makeRootPayload(fixture);
  const signPayload = makeSignPayload(fixture);

  const benchmarks = [
    measure('canonical_derivation_wasm', () => ecdsa_hss_derive_canonical_secret(rootPayload), {
      warmup: 10,
      iterations: 120,
    }),
    measure('share_derivation_wasm', () => ecdsa_hss_derive_additive_shares(rootPayload), {
      warmup: 10,
      iterations: 80,
    }),
    measure('bootstrap_non_export_wasm', () => ecdsa_hss_bootstrap_non_export_sign(rootPayload), {
      warmup: 8,
      iterations: 60,
    }),
    measure('sign_non_export_wasm', () => ecdsa_hss_sign_non_export(signPayload), {
      warmup: 5,
      iterations: 20,
    }),
    measure('explicit_export_wasm', () => ecdsa_hss_explicit_export(rootPayload), {
      warmup: 8,
      iterations: 60,
    }),
  ];

  const profiledSamples = [];
  for (let i = 0; i < 5; i += 1) ecdsa_hss_sign_non_export_profiled(signPayload);
  for (let i = 0; i < 20; i += 1) {
    profiledSamples.push(ecdsa_hss_sign_non_export_profiled(signPayload));
  }
  const signProfile = [
    summarizeSeries(
      'sign_parse_input_wasm',
      profiledSamples.map((sample) => sample.parseInputMs),
    ),
    summarizeSeries(
      'sign_prepare_session_wasm',
      profiledSamples.map((sample) => sample.prepareSessionMs),
    ),
    summarizeSeries(
      'sign_presign_roundtrip_wasm',
      profiledSamples.map((sample) => sample.presignRoundtripMs),
    ),
    summarizeSeries(
      'sign_client_signature_share_wasm',
      profiledSamples.map((sample) => sample.clientSignatureShareMs),
    ),
    summarizeSeries(
      'sign_finalize_signature_wasm',
      profiledSamples.map((sample) => sample.finalizeSignatureMs),
    ),
    summarizeSeries(
      'sign_total_core_wasm',
      profiledSamples.map((sample) => sample.totalCoreMs),
    ),
  ];

  const runId = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = path.join(OUT_ROOT, runId);
  mkdirSync(outDir, { recursive: true });

  const summary = {
    runId,
    runtime: 'node-hosted-wasm-web-target',
    fixture: 'derived-beta',
    benchmarks,
    signProfile,
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
  for (const bucket of signProfile) {
    console.log(
      `[benchmark] ${bucket.label} median_ms=${bucket.medianMs} mean_ms=${bucket.meanMs} min_ms=${bucket.minMs} max_ms=${bucket.maxMs}`,
    );
  }
}

main();
