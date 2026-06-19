import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  initSync,
  init_threshold_prf,
  threshold_prf_combine_verified_partials,
  threshold_prf_evaluate_partial_with_dleq_proof,
} from '../../../wasm/threshold_prf/pkg/threshold_prf.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../../..');
const OUT_ROOT = path.join(REPO_ROOT, 'benchmarks', 'router-ab-threshold-prf-wasm', 'out');
const WASM_PATH = path.join(REPO_ROOT, 'wasm', 'threshold_prf', 'pkg', 'threshold_prf_bg.wasm');
const FIXTURE_PATH = path.join(
  REPO_ROOT,
  'crates',
  'threshold-prf',
  'fixtures',
  'protocol-t-of-n.json',
);

const ROUTER_AB_PURPOSE = 'router-ab/x_client_base/v1';
const ROUTER_AB_CONTEXT = new TextEncoder().encode('router-ab-threshold-prf-wasm-benchmark/v1');

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
const WARMUP = numberOption('--warmup', 5);
const ITERATIONS = numberOption('--iterations', 30);

function numberOption(name, fallback) {
  const raw = CLI_ARGS.get(name);
  if (raw === undefined || raw === true) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : fallback;
}

function hexToBytes(value) {
  return new Uint8Array(Buffer.from(value, 'hex'));
}

function concatBytes(chunks) {
  const out = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function stats(values) {
  const finite = values.filter((value) => Number.isFinite(value));
  if (finite.length === 0) {
    return { median: 0, p95: 0, mean: 0, min: 0, max: 0 };
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

function loadShareWires() {
  const fixture = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'));
  const vector = fixture.vectors.find(
    (candidate) =>
      candidate.policy?.threshold === 2 &&
      candidate.policy?.share_count === 3 &&
      Array.isArray(candidate.shares) &&
      candidate.shares.length >= 2,
  );
  if (!vector) throw new Error('missing threshold-prf 2-of-3 fixture');
  return {
    threshold: vector.policy.threshold,
    shareCount: vector.policy.share_count,
    shares: vector.shares.slice(0, 2).map((share) => hexToBytes(share.wire_hex)),
  };
}

function buildProofBundleWires(shares) {
  return concatBytes(
    shares.map((share) =>
      threshold_prf_evaluate_partial_with_dleq_proof(share, ROUTER_AB_PURPOSE, ROUTER_AB_CONTEXT),
    ),
  );
}

function measure(label, fn) {
  for (let index = 0; index < WARMUP; index += 1) {
    fn();
  }
  const samples = [];
  for (let index = 0; index < ITERATIONS; index += 1) {
    const started = performance.now();
    const output = fn();
    const wallMs = performance.now() - started;
    samples.push({
      wallMs,
      outputBytes: output?.byteLength ?? output?.length ?? 0,
    });
  }
  return {
    label,
    warmup: WARMUP,
    iterations: ITERATIONS,
    wall: stats(samples.map((sample) => sample.wallMs)),
    outputBytes: stats(samples.map((sample) => sample.outputBytes)),
    samples: samples.map((sample) => ({
      wallMs: Number(sample.wallMs.toFixed(3)),
      outputBytes: sample.outputBytes,
    })),
  };
}

function renderSummary(summary) {
  const lines = [];
  lines.push('# Router A/B Threshold-PRF WASM Benchmark Summary');
  lines.push('');
  lines.push(`- Run ID: \`${summary.runId}\``);
  lines.push('- Runtime: Node-hosted `wasm/threshold_prf`');
  lines.push('- Scope: selected `mpc_threshold_prf_v1` proof-bundle generation and verified combine');
  lines.push(`- Warmup / iterations: ${WARMUP} / ${ITERATIONS}`);
  lines.push('');
  lines.push('| Path | Median | p95 | Mean | Min | Max | Output bytes |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: | ---: |');
  for (const bench of summary.benchmarks) {
    lines.push(
      `| \`${bench.label}\` | \`${bench.wall.median} ms\` | \`${bench.wall.p95} ms\` | \`${bench.wall.mean} ms\` | \`${bench.wall.min} ms\` | \`${bench.wall.max} ms\` | \`${bench.outputBytes.median}\` |`,
    );
  }
  lines.push('');
  lines.push('Notes:');
  lines.push('- Proof generation uses secure randomness from the WASM `getrandom` path.');
  lines.push('- The benchmark excludes HPKE, JSON, HTTP, Service Binding, and Cloudflare runtime latency.');
  return lines.join('\n');
}

function main() {
  initSync({ module: readFileSync(WASM_PATH) });
  init_threshold_prf();
  const fixture = loadShareWires();
  const fixedProofBundleWires = buildProofBundleWires(fixture.shares);

  const benchmarks = [
    measure('router_ab_mpc_threshold_prf_two_proofs_wasm', () =>
      buildProofBundleWires(fixture.shares),
    ),
    measure('router_ab_mpc_threshold_prf_verified_combine_wasm', () =>
      threshold_prf_combine_verified_partials(
        fixture.threshold,
        fixture.shareCount,
        fixedProofBundleWires,
        ROUTER_AB_PURPOSE,
        ROUTER_AB_CONTEXT,
      ),
    ),
    measure('router_ab_mpc_threshold_prf_two_proofs_plus_combine_wasm', () => {
      const proofBundleWires = buildProofBundleWires(fixture.shares);
      return threshold_prf_combine_verified_partials(
        fixture.threshold,
        fixture.shareCount,
        proofBundleWires,
        ROUTER_AB_PURPOSE,
        ROUTER_AB_CONTEXT,
      );
    }),
  ];

  const runId = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = path.join(OUT_ROOT, runId);
  mkdirSync(outDir, { recursive: true });
  const summary = {
    runId,
    runtime: 'node-hosted wasm/threshold_prf',
    purpose: ROUTER_AB_PURPOSE,
    contextUtf8: 'router-ab-threshold-prf-wasm-benchmark/v1',
    threshold: fixture.threshold,
    shareCount: fixture.shareCount,
    proofBundleBytes: fixedProofBundleWires.byteLength,
    benchmarks,
  };
  const rawSummaryPath = path.join(outDir, 'raw-summary.json');
  const markdownPath = path.join(outDir, 'summary.md');
  writeFileSync(rawSummaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  writeFileSync(markdownPath, `${renderSummary(summary)}\n`);

  console.log(`[benchmark] run_id=${runId}`);
  console.log(`[benchmark] summary_json=${rawSummaryPath}`);
  console.log(`[benchmark] summary_markdown=${markdownPath}`);
  for (const bench of benchmarks) {
    console.log(
      `[benchmark] ${bench.label} median_ms=${bench.wall.median} p95_ms=${bench.wall.p95} mean_ms=${bench.wall.mean}`,
    );
  }
}

main();
