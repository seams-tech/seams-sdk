import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { buildReport, validateResult } from "./run_same_account_benchmark.mjs";

function fixtureResult() {
  const fixtureUrl = new URL("./fixtures/deployed-success.json", import.meta.url);
  const result = JSON.parse(readFileSync(fixtureUrl, "utf8"));
  result.topology = "same-account-service-binding";
  result.deriver_b_colo = null;
  return result;
}

function fixtureSample(index, clientWallMs) {
  return {
    index,
    client_wall_ms: clientWallMs,
    ...fixtureResult(),
  };
}

function assertInvalid(mutator) {
  const result = fixtureResult();
  mutator(result);
  assert.throws(validateResult.bind(null, result));
}

function corruptTimingOrder(result) {
  result.offer_received_ms = result.extension_received_ms + 1;
}

function corruptTimingDuration(result) {
  result.table_stream_duration_ms += 1;
}

function corruptTimingBoundary(result) {
  result.table_timing_boundary = "caller-asserted";
}

function corruptBodyByteTimingBoundary(result) {
  result.body_byte_timing_boundary = "decoded-envelope";
}

function removeFirstResponseBodyByte(result) {
  delete result.b_to_a_first_body_byte_received_ms;
}

function enableProductionEligibility(result) {
  result.production_eligible = true;
}

function claimZeroizedIncomingBuffers(result) {
  result.incoming_secret_buffer_disposal = "zeroized";
}

function corruptIncomingCopyPasses(result) {
  result.adapter_secret_ingress_rust_copy_passes = 2;
}

function corruptIncomingCopyBytes(result) {
  result.adapter_secret_ingress_rust_copy_bytes += 1;
}

function corruptJsOverwriteBytes(result) {
  result.adapter_secret_ingress_js_overwrite_bytes -= 1;
}

function corruptWireAccounting(result) {
  result.ot_payload_bytes -= 1;
}

function run() {
  const valid = fixtureResult();
  validateResult(valid);

  assertInvalid(corruptTimingOrder);
  assertInvalid(corruptTimingDuration);
  assertInvalid(corruptTimingBoundary);
  assertInvalid(corruptBodyByteTimingBoundary);
  assertInvalid(removeFirstResponseBodyByte);
  assertInvalid(enableProductionEligibility);
  assertInvalid(claimZeroizedIncomingBuffers);
  assertInvalid(corruptIncomingCopyPasses);
  assertInvalid(corruptIncomingCopyBytes);
  assertInvalid(corruptJsOverwriteBytes);
  assertInvalid(corruptWireAccounting);

  const report = buildReport("http://127.0.0.1:8787/benchmark/activation", [
    fixtureSample(0, 120),
    fixtureSample(1, 100),
    fixtureSample(2, 110),
  ]);
  assert.equal(report.warm.client_wall_ms.p95, 110);
  assert.equal(report.warm.transport_timing_ms.table_stream_duration_ms.p95, 40);
  assert.equal(report.invariants.table_timing_boundary, "outbound-stream-backpressure-acceptance");
  assert.equal(
    report.invariants.body_byte_timing_boundary,
    "raw-stream-chunk-emission-and-receipt",
  );
  assert.equal(report.invariants.total_ab_transport_bytes, 2_222_584);
}

run();
process.stdout.write("local benchmark tooling fixtures passed\n");
