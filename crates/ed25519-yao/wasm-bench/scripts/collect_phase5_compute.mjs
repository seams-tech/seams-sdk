import { exercise } from "./run_phase5_streaming.mjs";

const SAMPLE_COUNT = 21;
const CEREMONY_P95_LIMIT_MS = 250;
const COMBINED_ROLE_P95_LIMIT_MS = 150;
const MEMORY_LIMIT_BYTES = 96 * 1024 * 1024;
const CASES = Object.freeze([
  Object.freeze({ family: "activation", profile: "128kib" }),
  Object.freeze({ family: "export", profile: "128kib" }),
]);

function compareNumbers(left, right) {
  return left - right;
}

function percentile(values, numerator, denominator) {
  const sorted = [...values].sort(compareNumbers);
  const rank = Math.max(0, Math.ceil((numerator * sorted.length) / denominator) - 1);
  return sorted[rank];
}

function summarize(values) {
  return Object.freeze({
    min: Math.min(...values),
    p50: percentile(values, 50, 100),
    p95: percentile(values, 95, 100),
    p99: percentile(values, 99, 100),
    max: Math.max(...values),
  });
}

function select(samples, selector) {
  const values = [];
  for (const sample of samples) {
    values.push(selector(sample));
  }
  return values;
}

function selectConstruction(sample) {
  return sample.timing.synchronous.session_construction_ms;
}

function selectDeriverA(sample) {
  return sample.timing.synchronous.deriver_a_ms;
}

function selectDeriverB(sample) {
  return sample.timing.synchronous.deriver_b_ms;
}

function selectTerminal(sample) {
  return sample.timing.synchronous.terminal_ms;
}

function selectTotal(sample) {
  return sample.timing.total_ms;
}

function selectLinearPeak(sample) {
  return sample.timing.wasm_linear_memory_peak_bytes;
}

function fixedMemory(first) {
  return Object.freeze({
    deriver_a_peak_arena_bytes: first.deriver_a_peak_arena_bytes,
    deriver_b_peak_arena_bytes: first.deriver_b_peak_arena_bytes,
    deriver_a_peak_table_buffer_bytes: first.deriver_a_peak_table_buffer_bytes,
    deriver_b_peak_table_buffer_bytes: first.deriver_b_peak_table_buffer_bytes,
    peak_rust_frame_allocation_bytes:
      first.rust_wasm_boundary.peak_rust_frame_allocation_bytes,
    peak_js_live_wire_bytes: first.js.peak_js_live_wire_bytes,
  });
}

function requireFixedMemory(samples, expected) {
  for (const sample of samples) {
    const observed = fixedMemory(sample);
    for (const field of Object.keys(expected)) {
      if (observed[field] !== expected[field]) {
        throw new Error(`non-deterministic memory evidence: ${field}`);
      }
    }
  }
}

function buildCaseReport(definition, samples) {
  const warm = samples.slice(1);
  const memory = fixedMemory(samples[0]);
  requireFixedMemory(samples, memory);
  return Object.freeze({
    family: definition.family,
    profile: definition.profile,
    sample_count: samples.length,
    warm_sample_count: warm.length,
    synchronous_ms: Object.freeze({
      session_construction: summarize(select(warm, selectConstruction)),
      deriver_a_garbling_and_stream: summarize(select(warm, selectDeriverA)),
      deriver_b_evaluation_and_stream: summarize(select(warm, selectDeriverB)),
      terminal_output: summarize(select(warm, selectTerminal)),
    }),
    total_wall_ms: summarize(select(warm, selectTotal)),
    fixed_live_allocations: memory,
    wasm_linear_memory_peak_bytes: summarize(select(samples, selectLinearPeak)),
  });
}

async function collectCase(definition) {
  const samples = [];
  for (let index = 0; index < SAMPLE_COUNT; index += 1) {
    samples.push(await exercise(definition.family, definition.profile));
  }
  return buildCaseReport(definition, samples);
}

function validateActivationBudget(report) {
  const combinedRoleP95 =
    report.synchronous_ms.deriver_a_garbling_and_stream.p95 +
    report.synchronous_ms.deriver_b_evaluation_and_stream.p95;
  if (
    report.total_wall_ms.p95 > CEREMONY_P95_LIMIT_MS ||
    combinedRoleP95 > COMBINED_ROLE_P95_LIMIT_MS ||
    report.wasm_linear_memory_peak_bytes.max >= MEMORY_LIMIT_BYTES ||
    report.fixed_live_allocations.deriver_a_peak_table_buffer_bytes !== 131_072 ||
    report.fixed_live_allocations.deriver_b_peak_table_buffer_bytes !== 131_072
  ) {
    throw new Error("local activation WASM compute budget exceeded");
  }
}

async function main() {
  const cases = [];
  for (const definition of CASES) {
    cases.push(await collectCase(definition));
  }
  validateActivationBudget(cases[0]);
  const report = Object.freeze({
    schema: "ed25519_yao_phase5_local_wasm_compute_v1",
    recorded_at: new Date().toISOString(),
    runtime: process.version,
    sample_policy: "one warmup followed by twenty measured sequential ceremonies",
    timing_scope:
      "host-observed synchronous wasm calls; excludes event-loop yields and transport waits",
    memory_scope:
      "wasm linear-memory high-water plus exact protocol-owned live allocations; excludes JS engine and process RSS",
    cases,
  });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

function handleFatal(error) {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
}

main().catch(handleFatal);
