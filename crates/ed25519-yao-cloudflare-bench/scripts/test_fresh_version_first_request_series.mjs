import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { assembleFreshVersionFirstRequestSeries } from "./assemble_fresh_version_first_request_series.mjs";

const REPORT_COUNT = 20;
const A_ARTIFACT = "a".repeat(64);
const B_ARTIFACT = "b".repeat(64);
const A_WASM = "c".repeat(64);
const B_WASM = "d".repeat(64);
const LOCAL_READINESS_BUNDLE = "e".repeat(64);

let fixturePaths = [];

function hexadecimalId(index) {
  return index.toString(16).padStart(32, "0");
}

function versionId(role, index) {
  return `${role}-version-${index.toString().padStart(4, "0")}`;
}

function rawSample(index, deploymentId, clientWallMs, tableStreamDurationMs) {
  const lastTable = tableStreamDurationMs + 6;
  const responseEof = tableStreamDurationMs + 12;
  return {
    index,
    started_at: "2026-07-13T00:00:00.000Z",
    client_wall_ms: clientWallMs,
    observation: {},
    result: {
      benchmark: "phase9b-cloudflare-activation-128kib",
      benchmark_only: true,
      production_eligible: false,
      incoming_secret_buffer_disposal:
        "rust-wasm-copy-zeroized-js-view-overwritten-platform-copies-uncontrolled",
      role: "deriver-a",
      topology: "cross-account-https",
      deployment_id: deploymentId,
      body_byte_timing_boundary: "raw-stream-chunk-emission-and-receipt",
      table_payload_bytes: 2_104_960,
      total_ab_transport_bytes: 2_222_584,
      ot_message_count: 4,
      ot_sequential_round_count: 4,
      total_incoming_body_bytes: 37_164,
      adapter_secret_ingress_rust_copy_passes: 1,
      adapter_secret_ingress_rust_copy_bytes: 37_164,
      adapter_secret_ingress_js_overwrite_bytes: 37_164,
      total_outgoing_envelope_bytes: 2_185_420,
      workers_rs_outgoing_stream_body_copy_passes: 1,
      workers_rs_outgoing_stream_body_copy_bytes: 2_185_420,
      b_response_headers_received_ms: 1,
      b_to_a_first_body_byte_received_ms: 2,
      offer_received_ms: 3,
      a_to_b_first_body_byte_emitted_ms: 4,
      extension_received_ms: 5,
      first_table_frame_accepted_ms: 6,
      last_table_frame_accepted_ms: lastTable,
      translation_accepted_ms: tableStreamDurationMs + 7,
      a_to_b_final_body_byte_emitted_ms: tableStreamDurationMs + 8,
      request_direction_closed_ms: tableStreamDurationMs + 9,
      b_to_a_final_body_byte_received_ms: tableStreamDurationMs + 10,
      returned_received_ms: tableStreamDurationMs + 11,
      response_eof_complete_ms: responseEof,
      table_stream_duration_ms: tableStreamDurationMs,
      total_protocol_duration_ms: responseEof,
    },
  };
}

function fixtureReport(index) {
  const deploymentId = hexadecimalId(index + 1);
  return {
    benchmark: "phase9b-cloudflare-activation-128kib",
    benchmark_only: true,
    security_claim: "none",
    topology: "cross-account-https",
    requested_topology: "two-account",
    region_label: "tokyo-runner-1",
    deployment: {
      schema: "ed25519_yao_phase9b_deployment_receipt_v4",
      deployment_id: deploymentId,
      local_readiness_bundle_sha256: LOCAL_READINESS_BUNDLE,
      topology: "cross-account-https",
      topology_binding: {
        schema: "ed25519_yao_phase9b_topology_binding_v1",
        kind: "cross-account-https",
        a_account_sha256: "1".repeat(64),
        b_account_sha256: "2".repeat(64),
        a_public_hostname: "a-benchmark.example.com",
        b_public_hostname: "b-benchmark.example.com",
      },
      recorded_at: "2026-07-13T00:00:00.000Z",
      constant_time_codegen: {
        schema: "ed25519_yao_worker_constant_time_codegen_v1",
        inspector: "llvm-objdump-secret-bit-branch-gate-v1",
        result: "pass",
        roles: {
          a: { artifact_sha256: A_ARTIFACT, wasm_sha256: A_WASM },
          b: { artifact_sha256: B_ARTIFACT, wasm_sha256: B_WASM },
        },
      },
      a: {
        script_name: "ed25519-yao-ab-benchmark-a-cross-account",
        wrangler_version: "4.105.0",
        worker_tag: versionId("a-tag", index),
        version_id: versionId("a", index),
        deployed_at: "2026-07-12T23:59:58.000Z",
        artifact_sha256: A_ARTIFACT,
      },
      b: {
        script_name: "ed25519-yao-ab-benchmark-b-cross-account",
        wrangler_version: "4.105.0",
        worker_tag: versionId("b-tag", index),
        version_id: versionId("b", index),
        deployed_at: "2026-07-12T23:59:59.000Z",
        artifact_sha256: B_ARTIFACT,
      },
    },
    requested_samples: 2,
    completed_samples: 2,
    success_count: 2,
    failure_count: 0,
    failures: [],
    first_observation: rawSample(0, deploymentId, 201 + index, 101 + index),
    samples: [
      rawSample(1, deploymentId, 10_000 + index, 20_000 + index),
      rawSample(0, deploymentId, 201 + index, 101 + index),
    ],
  };
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function writeReports(directory, reports) {
  const paths = [];
  for (let index = 0; index < reports.length; index += 1) {
    const path = join(directory, `report-${index}.json`);
    writeFileSync(path, `${JSON.stringify(reports[index])}\n`);
    paths.push(path);
  }
  return paths;
}

function fixtureReports() {
  const reports = [];
  for (let index = 0; index < REPORT_COUNT; index += 1) {
    reports.push(fixtureReport(index));
  }
  return reports;
}

function assembleFixtureReports(reports) {
  const directory = mkdtempSync(join(tmpdir(), "yaos-ab-cold-series-test-"));
  fixturePaths.push(directory);
  return assembleFreshVersionFirstRequestSeries(writeReports(directory, reports));
}

function assembleTooFewReports() {
  assembleFixtureReports(fixtureReports().slice(0, REPORT_COUNT - 1));
}

function assembleFailedReport() {
  const reports = fixtureReports();
  reports[3].failure_count = 1;
  reports[3].success_count = 1;
  reports[3].failures.push({ error_code: "CLIENT_TIMEOUT" });
  assembleFixtureReports(reports);
}

function assembleMixedTopology() {
  const reports = fixtureReports();
  reports[5].topology = "same-account-service-binding";
  reports[5].requested_topology = "one-account";
  reports[5].deployment.topology = "same-account-service-binding";
  reports[5].deployment.a.script_name = "ed25519-yao-ab-benchmark-a";
  reports[5].deployment.b.script_name = "ed25519-yao-ab-benchmark-b";
  reports[5].first_observation.result.topology = "same-account-service-binding";
  for (const sample of reports[5].samples) {
    sample.result.topology = "same-account-service-binding";
  }
  assembleFixtureReports(reports);
}

function assembleMixedRegion() {
  const reports = fixtureReports();
  reports[7].region_label = "osaka-runner-1";
  assembleFixtureReports(reports);
}

function assembleDuplicateDeployment() {
  const reports = fixtureReports();
  reports[8].deployment.deployment_id = reports[0].deployment.deployment_id;
  for (const sample of reports[8].samples) {
    sample.result.deployment_id = reports[8].deployment.deployment_id;
  }
  assembleFixtureReports(reports);
}

function assembleDuplicateVersion() {
  const reports = fixtureReports();
  reports[9].deployment.a.version_id = reports[0].deployment.a.version_id;
  assembleFixtureReports(reports);
}

function assembleCrossRoleDuplicateVersion() {
  const reports = fixtureReports();
  reports[10].deployment.b.version_id = reports[0].deployment.a.version_id;
  assembleFixtureReports(reports);
}

function assembleArtifactDrift() {
  const reports = fixtureReports();
  reports[11].deployment.b.artifact_sha256 = "c".repeat(64);
  assembleFixtureReports(reports);
}

function assembleLocalReadinessBundleDrift() {
  const reports = fixtureReports();
  reports[11].deployment.local_readiness_bundle_sha256 = "f".repeat(64);
  assembleFixtureReports(reports);
}

function assembleTopologyBindingDrift() {
  const reports = fixtureReports();
  reports[11].deployment.topology_binding.b_account_sha256 = "3".repeat(64);
  assembleFixtureReports(reports);
}

function assembleMissingIndexZero() {
  const reports = fixtureReports();
  reports[12].samples[1].index = 1;
  assembleFixtureReports(reports);
}

function assembleSampleBeforeDeployment() {
  const reports = fixtureReports();
  reports[13].samples[1].started_at = "2026-07-12T23:59:57.000Z";
  assembleFixtureReports(reports);
}

function assembleProductionEligibleSample() {
  const reports = fixtureReports();
  reports[14].samples[1].result.production_eligible = true;
  assembleFixtureReports(reports);
}

function assembleInvalidSecretCopyAccounting() {
  const reports = fixtureReports();
  reports[14].samples[1].result.adapter_secret_ingress_rust_copy_bytes += 1;
  assembleFixtureReports(reports);
}

function assembleLateOfferSample() {
  const reports = fixtureReports();
  reports[15].samples[1].result.offer_received_ms =
    reports[15].samples[1].result.request_direction_closed_ms;
  assembleFixtureReports(reports);
}

function assembleRelativePaths() {
  const reports = fixtureReports();
  const directory = mkdtempSync(join(tmpdir(), "yaos-ab-cold-series-test-"));
  fixturePaths.push(directory);
  writeReports(directory, reports);
  const relativePaths = [];
  for (let index = 0; index < REPORT_COUNT; index += 1) {
    relativePaths.push(`report-${index}.json`);
  }
  assembleFreshVersionFirstRequestSeries(relativePaths);
}

function cleanFixtures() {
  for (const directory of fixturePaths) {
    rmSync(directory, { recursive: true, force: true });
  }
  fixturePaths = [];
}

function run() {
  try {
    const reports = fixtureReports();
    const output = assembleFixtureReports(reports);
    assert.equal(output.schema, "ed25519_yao_phase9b_fresh_version_first_request_series_v1");
    assert.equal(output.benchmark_only, true);
    assert.equal(output.topology, "cross-account-https");
    assert.equal(output.region_label, "tokyo-runner-1");
    assert.equal(output.sample_count, REPORT_COUNT);
    assert.equal(output.classification, "fresh-version-first-request-operational-cold-proxy");
    assert.equal(output.physical_isolate_cold_proven, false);
    assert.deepEqual(output.metrics.client_wall_ms, { p50: 210, p95: 219, p99: 220 });
    assert.deepEqual(output.metrics.table_stream_duration_ms, {
      p50: 110,
      p95: 119,
      p99: 120,
    });
    assert.equal(output.samples.length, REPORT_COUNT);
    assert.equal(output.samples[0].first_raw_sample.index, 0);
    assert.deepEqual(output.samples[0].deployment, reports[0].deployment);
    assert.ok(output.samples[0].source_report.startsWith("/"));

    assert.throws(assembleTooFewReports);
    assert.throws(assembleFailedReport);
    assert.throws(assembleMixedTopology);
    assert.throws(assembleMixedRegion);
    assert.throws(assembleDuplicateDeployment);
    assert.throws(assembleDuplicateVersion);
    assert.throws(assembleCrossRoleDuplicateVersion);
    assert.throws(assembleArtifactDrift);
    assert.throws(assembleLocalReadinessBundleDrift);
    assert.throws(assembleTopologyBindingDrift);
    assert.throws(assembleMissingIndexZero);
    assert.throws(assembleSampleBeforeDeployment);
    assert.throws(assembleProductionEligibleSample);
    assert.throws(assembleInvalidSecretCopyAccounting);
    assert.throws(assembleLateOfferSample);
    assert.throws(assembleRelativePaths);
  } finally {
    cleanFixtures();
  }
}

run();
process.stdout.write("fresh-version first-request series fixtures passed\n");
