import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { performance } from "node:perf_hooks";
import { TransformStream } from "node:stream/web";
import { pathToFileURL } from "node:url";

const require = createRequire(import.meta.url);
const wasm = require("../pkg-phase5/ed25519_yao_wasm_bench.js");

const producerDelayMs = parseDelay("PHASE5_SLOW_PRODUCER_MS");
const consumerDelayMs = parseDelay("PHASE5_SLOW_CONSUMER_MS");
const families = ["activation", "export"];
const profiles = ["64kib", "128kib", "256kib"];

export async function collectEvidence() {
  const results = [];
  for (const family of families) {
    for (const profile of profiles) {
      results.push(await exercise(family, profile));
    }
  }
  return {
    schema: "ed25519_yao_phase5_node_stream_evidence_v1",
    producer_delay_ms: producerDelayMs,
    consumer_delay_ms: consumerDelayMs,
    results,
  };
}

export async function exercise(family, profile) {
  const linearMemoryBeforeBytes = wasm.wasm_linear_memory_bytes();
  const constructionStarted = performance.now();
  const session = new wasm.Phase5StreamBenchmark(family, profile);
  const synchronous = {
    session_construction_ms: performance.now() - constructionStarted,
    deriver_a_ms: 0,
    deriver_b_ms: 0,
    terminal_ms: 0,
  };
  let linearMemoryPeakBytes = Math.max(
    linearMemoryBeforeBytes,
    wasm.wasm_linear_memory_bytes(),
  );
  const expectedFrames = session.expected_frame_count();
  const expectedBodyBytes = Number(session.expected_body_bytes());
  const counters = newJsCounters();
  const started = performance.now();

  let synchronousStarted = performance.now();
  let outboundManifest = session.take_opening_manifest();
  synchronous.deriver_a_ms += performance.now() - synchronousStarted;
  linearMemoryPeakBytes = Math.max(linearMemoryPeakBytes, wasm.wasm_linear_memory_bytes());
  assert.equal(outboundManifest.byteLength, 248);
  counters.wasm_generated_manifest_bytes += outboundManifest.byteLength;
  await producerYield(producerDelayMs, counters);
  let transportedManifest = copyTransportChunk(outboundManifest, counters, "manifest");
  outboundManifest.fill(0);
  outboundManifest = null;
  await consumerYield(consumerDelayMs, counters);
  synchronousStarted = performance.now();
  session.accept_opening_manifest(transportedManifest);
  synchronous.deriver_b_ms += performance.now() - synchronousStarted;
  linearMemoryPeakBytes = Math.max(linearMemoryPeakBytes, wasm.wasm_linear_memory_bytes());
  counters.wasm_ingress_manifest_bytes += transportedManifest.byteLength;
  transportedManifest.fill(0);
  transportedManifest = null;

  const tableTransport = new TransformStream(
    undefined,
    { highWaterMark: 1 },
    { highWaterMark: 1 },
  );
  const tableWriter = tableTransport.writable.getWriter();
  const tableReader = tableTransport.readable.getReader();
  let firstFrameMs = null;
  let finalFrameMs = null;
  for (let sequence = 0; sequence < expectedFrames; sequence += 1) {
    await producerYield(producerDelayMs, counters);
    synchronousStarted = performance.now();
    let outboundFrame = session.next_table_frame();
    synchronous.deriver_a_ms += performance.now() - synchronousStarted;
    linearMemoryPeakBytes = Math.max(linearMemoryPeakBytes, wasm.wasm_linear_memory_bytes());
    if (firstFrameMs === null) {
      firstFrameMs = performance.now() - started;
    }
    finalFrameMs = performance.now() - started;
    counters.wasm_generated_frame_bytes += outboundFrame.byteLength;
    counters.peak_js_live_wire_bytes = Math.max(
      counters.peak_js_live_wire_bytes,
      outboundFrame.byteLength,
    );
    let transportedFrame = copyTransportChunk(outboundFrame, counters, "frame");
    counters.peak_js_live_wire_bytes = Math.max(
      counters.peak_js_live_wire_bytes,
      outboundFrame.byteLength + transportedFrame.byteLength,
    );
    outboundFrame.fill(0);
    outboundFrame = null;
    const consumer = consumeNextFrame(
      session,
      tableReader,
      consumerDelayMs,
      counters,
      synchronous,
    );
    await tableWriter.write(transportedFrame);
    transportedFrame = null;
    await consumer;
    linearMemoryPeakBytes = Math.max(linearMemoryPeakBytes, wasm.wasm_linear_memory_bytes());
  }
  const evaluationCompleteMs = performance.now() - started;
  await tableWriter.close();
  const exactEof = await tableReader.read();
  assert.equal(exactEof.done, true);
  tableReader.releaseLock();
  tableWriter.releaseLock();
  synchronousStarted = performance.now();
  session.confirm_outbound_body_closed();
  synchronous.deriver_a_ms += performance.now() - synchronousStarted;
  synchronousStarted = performance.now();
  session.confirm_inbound_exact_eof();
  synchronous.deriver_b_ms += performance.now() - synchronousStarted;
  linearMemoryPeakBytes = Math.max(linearMemoryPeakBytes, wasm.wasm_linear_memory_bytes());
  const transcriptFinalizedMs = performance.now() - started;
  synchronousStarted = performance.now();
  const report = session.finish();
  synchronous.terminal_ms += performance.now() - synchronousStarted;
  linearMemoryPeakBytes = Math.max(linearMemoryPeakBytes, wasm.wasm_linear_memory_bytes());

  const result = readReport(report, counters, {
    first_frame_ms: firstFrameMs,
    final_frame_ms: finalFrameMs,
    evaluation_complete_ms: evaluationCompleteMs,
    transcript_finalized_ms: transcriptFinalizedMs,
    total_ms: performance.now() - started,
    synchronous,
    wasm_linear_memory_before_bytes: linearMemoryBeforeBytes,
    wasm_linear_memory_peak_bytes: linearMemoryPeakBytes,
    wasm_linear_memory_growth_bytes: linearMemoryPeakBytes - linearMemoryBeforeBytes,
  });
  report.free();
  session.free();
  assertReport(result, expectedFrames, expectedBodyBytes);
  return result;
}

function newJsCounters() {
  return {
    wasm_generated_manifest_bytes: 0,
    wasm_ingress_manifest_bytes: 0,
    wasm_generated_frame_bytes: 0,
    wasm_ingress_frame_bytes: 0,
    js_transport_manifest_allocations: 0,
    js_transport_manifest_copy_bytes: 0,
    js_transport_frame_allocations: 0,
    js_transport_frame_copy_bytes: 0,
    peak_js_live_wire_bytes: 0,
    producer_yields: 0,
    consumer_yields: 0,
  };
}

function copyTransportChunk(source, counters, kind) {
  const copy = new Uint8Array(source);
  if (kind === "manifest") {
    counters.js_transport_manifest_allocations += 1;
    counters.js_transport_manifest_copy_bytes += copy.byteLength;
  } else {
    counters.js_transport_frame_allocations += 1;
    counters.js_transport_frame_copy_bytes += copy.byteLength;
  }
  return copy;
}

async function producerYield(delayMs, counters) {
  counters.producer_yields += 1;
  await eventLoopYield(delayMs);
}

async function consumerYield(delayMs, counters) {
  counters.consumer_yields += 1;
  await eventLoopYield(delayMs);
}

async function consumeNextFrame(session, reader, delayMs, counters, synchronous) {
  await consumerYield(delayMs, counters);
  const next = await reader.read();
  assert.equal(next.done, false);
  const synchronousStarted = performance.now();
  session.accept_table_frame(next.value);
  synchronous.deriver_b_ms += performance.now() - synchronousStarted;
  counters.wasm_ingress_frame_bytes += next.value.byteLength;
  next.value.fill(0);
}

async function main() {
  process.stdout.write(`${JSON.stringify(await collectEvidence())}\n`);
}

function handleFatal(error) {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
  main().catch(handleFatal);
}

function eventLoopYield(delayMs) {
  if (delayMs > 0) {
    return new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  return new Promise((resolve) => setImmediate(resolve));
}

function readReport(report, js, timing) {
  return {
    family: report.family(),
    profile: report.profile(),
    table_payload_bytes: report.table_payload_bytes(),
    body_bytes: Number(report.body_bytes()),
    frame_count: report.frame_count(),
    deriver_a_peak_table_buffer_bytes: report.deriver_a_peak_table_buffer_bytes(),
    deriver_b_peak_table_buffer_bytes: report.deriver_b_peak_table_buffer_bytes(),
    deriver_a_peak_arena_bytes: report.deriver_a_peak_arena_bytes(),
    deriver_b_peak_arena_bytes: report.deriver_b_peak_arena_bytes(),
    runtime_host_boundary_copy_bytes: report.runtime_host_boundary_copy_bytes(),
    runtime_chunk_to_wire_copy_bytes: Number(report.runtime_chunk_to_wire_copy_bytes()),
    table_buffer_write_bytes: report.table_buffer_write_bytes(),
    and_records_decoded: report.and_records_decoded(),
    rust_wasm_boundary: {
      wasm_to_host_manifest_copy_bytes: Number(report.wasm_to_host_manifest_copy_bytes()),
      host_to_wasm_manifest_copy_bytes: Number(report.host_to_wasm_manifest_copy_bytes()),
      wasm_to_host_frame_copy_bytes: Number(report.wasm_to_host_frame_copy_bytes()),
      host_to_wasm_frame_copy_bytes: Number(report.host_to_wasm_frame_copy_bytes()),
      rust_frame_allocations: report.rust_frame_allocations(),
      rust_frame_allocation_bytes: Number(report.rust_frame_allocation_bytes()),
      peak_rust_frame_allocation_bytes: report.peak_rust_frame_allocation_bytes(),
    },
    js,
    timing,
  };
}

function assertReport(result, expectedFrames, expectedBodyBytes) {
  assert.equal(result.frame_count, expectedFrames);
  assert.equal(result.body_bytes, expectedBodyBytes);
  assert.equal(result.runtime_host_boundary_copy_bytes, 0);
  assert.equal(result.runtime_chunk_to_wire_copy_bytes, result.table_payload_bytes);
  assert.equal(result.table_buffer_write_bytes, result.table_payload_bytes);
  assert.equal(result.rust_wasm_boundary.wasm_to_host_manifest_copy_bytes, 248);
  assert.equal(result.rust_wasm_boundary.host_to_wasm_manifest_copy_bytes, 248);
  assert.equal(result.rust_wasm_boundary.wasm_to_host_frame_copy_bytes, expectedBodyBytes);
  assert.equal(result.rust_wasm_boundary.host_to_wasm_frame_copy_bytes, expectedBodyBytes);
  assert.equal(result.rust_wasm_boundary.rust_frame_allocations, expectedFrames);
  assert.equal(result.js.wasm_generated_manifest_bytes, 248);
  assert.equal(result.js.wasm_ingress_manifest_bytes, 248);
  assert.equal(result.js.wasm_generated_frame_bytes, expectedBodyBytes);
  assert.equal(result.js.wasm_ingress_frame_bytes, expectedBodyBytes);
  assert.equal(result.js.js_transport_manifest_allocations, 1);
  assert.equal(result.js.js_transport_manifest_copy_bytes, 248);
  assert.equal(result.js.js_transport_frame_allocations, expectedFrames);
  assert.equal(result.js.js_transport_frame_copy_bytes, expectedBodyBytes);
  assert.ok(result.js.producer_yields >= expectedFrames + 1);
  assert.ok(result.js.consumer_yields >= expectedFrames + 1);
  assert.ok(result.js.peak_js_live_wire_bytes < expectedBodyBytes || expectedFrames === 1);
  assert.ok(result.timing.synchronous.session_construction_ms >= 0);
  assert.ok(result.timing.synchronous.deriver_a_ms > 0);
  assert.ok(result.timing.synchronous.deriver_b_ms > 0);
  assert.ok(result.timing.wasm_linear_memory_peak_bytes >= result.timing.wasm_linear_memory_before_bytes);
  assert.equal(
    result.timing.wasm_linear_memory_growth_bytes,
    result.timing.wasm_linear_memory_peak_bytes - result.timing.wasm_linear_memory_before_bytes,
  );
}

function parseDelay(name) {
  const raw = process.env[name] ?? "0";
  if (!/^\d+$/.test(raw)) {
    throw new Error(`${name} must be a nonnegative integer`);
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value > 1000) {
    throw new Error(`${name} must be at most 1000`);
  }
  return value;
}
