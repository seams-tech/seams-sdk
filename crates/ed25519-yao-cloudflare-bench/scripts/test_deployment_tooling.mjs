import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  BoundaryError,
  parseAnalyticsWindow,
  parseDeploymentEnvironment,
} from './deployment_boundary.mjs';
import {
  MEMORY_EVIDENCE_CLASSIFICATION,
  PLATFORM_COPY_ACCOUNTING,
  WORKERS_CORE_QUERY,
  WORKERS_MEMORY_QUERY,
  buildSampledMemoryGate,
  collectWorkersAnalytics,
} from './collect_workers_analytics.mjs';
import {
  calculateCost,
  costEvidenceMetadata,
  parseCostEnvironment,
} from './calculate_deployed_cost.mjs';
import { collectDeployedBenchmark } from './run_deployed_benchmark.mjs';
import {
  bindPrebuiltArtifact,
  buildDeploymentPlan,
  parseWhoamiAccountIds,
  renderDeploymentConfigs,
} from './plan_cloudflare_benchmark.mjs';
import {
  assertArtifactEvidenceEqual,
  attachConstantTimeCodegen,
  attachRoleDeployment,
  attachRoleArtifact,
  completeDeploymentReceipt,
  collectArtifactEvidence,
  deploymentReceiptEvidence,
  initialDeploymentReceipt,
  parseWranglerDeploymentOutput,
  readDeploymentReceipt,
  validateDeploymentReceipt,
  writeDeploymentReceipt,
} from './deployment_receipt.mjs';
import {
  EvidenceError,
  PHASE13A_THRESHOLDS,
  evaluatePhase13A,
} from './evaluate_phase13a_viability.mjs';
import { ACTIVATION_128KIB_WIRE_PROFILE } from './activation_wire_profile.mjs';
import { loadLocalReadinessBundle } from './local_readiness_bundle.mjs';

const FIXTURE_ROOT = new URL('./fixtures/', import.meta.url);
const PHASE13A_EVALUATOR = fileURLToPath(
  new URL('./evaluate_phase13a_viability.mjs', import.meta.url),
);
const DEPLOYED_SUCCESS = fixture('deployed-success.json');
const GRAPHQL_CORE_SUCCESS = fixture('graphql-core-success.json');
const GRAPHQL_MEMORY_EQUAL = fixture('graphql-memory-equal-threshold.json');
const GRAPHQL_MEMORY_BELOW = fixture('graphql-memory-below-threshold.json');
const GRAPHQL_MEMORY_ABOVE = fixture('graphql-memory-above-threshold.json');
const GRAPHQL_MEMORY_UNAVAILABLE = fixture('graphql-memory-unavailable.json');
const GRAPHQL_CORE_EXCEEDED_MEMORY = fixture('graphql-core-exceeded-memory.json');
const PHASE13A_SAME_BENCHMARK = fixture('phase13a-same-benchmark-go.json');
const PHASE13A_CROSS_BENCHMARK = fixture('phase13a-cross-benchmark-go.json');
const PHASE13A_SAME_ANALYTICS = fixture('phase13a-same-analytics-go.json');
const PHASE13A_CROSS_ANALYTICS = fixture('phase13a-cross-analytics-go.json');
const DELAYED_BODY_MS = 25;
const FIXTURE_DEPLOYMENT_ID = 'ab'.repeat(16);
const LOCAL_READINESS_BUNDLE_SHA256 = loadLocalReadinessBundle().sha256;

class DelayedSuccessBodySource {
  constructor() {
    this.bytes = new TextEncoder().encode(JSON.stringify(clonedDeployedSuccess()));
  }

  start(controller) {
    this.controller = controller;
    setTimeout(this.finish.bind(this), DELAYED_BODY_MS);
  }

  finish() {
    this.controller.enqueue(this.bytes);
    this.controller.close();
  }
}

function fixture(name) {
  return JSON.parse(readFileSync(new URL(name, FIXTURE_ROOT), 'utf8'));
}

function envExample(name) {
  const text = readFileSync(new URL(`../deployment-env/${name}`, import.meta.url), 'utf8');
  const environment = {};
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.length === 0 || trimmed.startsWith('#')) {
      continue;
    }
    const separator = trimmed.indexOf('=');
    if (separator <= 0) {
      continue;
    }
    environment[trimmed.slice(0, separator)] = trimmed.slice(separator + 1);
  }
  return environment;
}

function twoAccountEnvironment() {
  return {
    YAOS_AB_TOPOLOGY: 'two-account',
    YAOS_AB_A_ACCOUNT_ID: 'a'.repeat(32),
    YAOS_AB_B_ACCOUNT_ID: 'b'.repeat(32),
    YAOS_AB_A_PROFILE: 'yaos-a',
    YAOS_AB_B_PROFILE: 'yaos-b',
    YAOS_AB_A_SCRIPT_NAME: 'ed25519-yao-ab-benchmark-a-cross-account',
    YAOS_AB_B_SCRIPT_NAME: 'ed25519-yao-ab-benchmark-b-cross-account',
    YAOS_AB_A_PUBLIC_ENDPOINT: 'https://a-benchmark.example.com/benchmark/activation',
    YAOS_AB_B_HOSTNAME: 'b-benchmark.example.com',
    YAOS_AB_B_HTTPS_ENDPOINT: 'https://b-benchmark.example.com/benchmark/activation',
    YAOS_AB_SAMPLE_COUNT: '3',
    YAOS_AB_REGION_LABEL: 'tokyo-runner-1',
  };
}

function oneAccountEnvironment() {
  const environment = twoAccountEnvironment();
  environment.YAOS_AB_TOPOLOGY = 'one-account';
  environment.YAOS_AB_B_ACCOUNT_ID = environment.YAOS_AB_A_ACCOUNT_ID;
  environment.YAOS_AB_B_PROFILE = environment.YAOS_AB_A_PROFILE;
  environment.YAOS_AB_A_SCRIPT_NAME = 'ed25519-yao-ab-benchmark-a';
  environment.YAOS_AB_B_SCRIPT_NAME = 'ed25519-yao-ab-benchmark-b';
  delete environment.YAOS_AB_B_HOSTNAME;
  delete environment.YAOS_AB_B_HTTPS_ENDPOINT;
  return environment;
}

function analyticsWindowEnvironment() {
  return {
    YAOS_AB_ANALYTICS_START: '2026-07-12T00:00:00.000Z',
    YAOS_AB_ANALYTICS_END: '2026-07-12T01:00:00.000Z',
  };
}

function clonedDeployedSuccess() {
  return JSON.parse(JSON.stringify(DEPLOYED_SUCCESS));
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function phase13aInput() {
  const input = {
    same_benchmark: cloneJson(PHASE13A_SAME_BENCHMARK),
    cross_benchmark: cloneJson(PHASE13A_CROSS_BENCHMARK),
    same_analytics: cloneJson(PHASE13A_SAME_ANALYTICS),
    cross_analytics: cloneJson(PHASE13A_CROSS_ANALYTICS),
  };
  attachRawSamples(input.same_benchmark);
  attachRawSamples(input.cross_benchmark);
  const sameReceipt = completeReceipt(
    parseDeploymentEnvironment(oneAccountEnvironment()),
    'cd'.repeat(16),
  );
  const crossReceipt = completeReceipt(
    parseDeploymentEnvironment(twoAccountEnvironment()),
    FIXTURE_DEPLOYMENT_ID,
  );
  input.same_benchmark.deployment = cloneJson(deploymentReceiptEvidence(sameReceipt));
  input.same_analytics.deployment = cloneJson(deploymentReceiptEvidence(sameReceipt));
  input.cross_benchmark.deployment = cloneJson(deploymentReceiptEvidence(crossReceipt));
  input.cross_analytics.deployment = cloneJson(deploymentReceiptEvidence(crossReceipt));
  for (const sample of input.same_benchmark.samples) {
    sample.result.deployment_id = sameReceipt.deployment_id;
  }
  for (const sample of input.cross_benchmark.samples) {
    sample.result.deployment_id = crossReceipt.deployment_id;
  }
  input.same_cold_proxy = coldProxySeries(
    input.same_benchmark,
    deploymentReceiptEvidence(sameReceipt),
    'same',
  );
  input.cross_cold_proxy = coldProxySeries(
    input.cross_benchmark,
    deploymentReceiptEvidence(crossReceipt),
    'cross',
  );
  input.same_cost = phase13CostReport(oneAccountEnvironment(), sameReceipt);
  input.cross_cost = phase13CostReport(twoAccountEnvironment(), crossReceipt);
  input.operational_acceptance = operationalAcceptance();
  return input;
}

function sampleMetricValue(report, metric, index) {
  const summary = report.warm.metrics[metric];
  if (summary === undefined) {
    return 1;
  }
  return index >= 49 ? (summary.p99 ?? summary.p95) : summary.p95;
}

function rawPhase13aSample(report, index) {
  const tableDuration = sampleMetricValue(report, 'table_stream_duration_ms', index);
  const responseEof = tableDuration + 12;
  return {
    index,
    started_at: new Date(Date.parse(report.measurement_window.start) + index * 1_000).toISOString(),
    client_wall_ms: sampleMetricValue(report, 'client_wall_ms', index),
    result: {
      ...ACTIVATION_128KIB_WIRE_PROFILE,
      benchmark: report.benchmark,
      benchmark_only: true,
      production_eligible: false,
      incoming_secret_buffer_disposal:
        'rust-wasm-copy-zeroized-js-view-overwritten-platform-copies-uncontrolled',
      role: 'deriver-a',
      topology: report.topology,
      body_byte_timing_boundary: 'raw-stream-chunk-emission-and-receipt',
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
      last_table_frame_accepted_ms: tableDuration + 6,
      translation_accepted_ms: tableDuration + 7,
      a_to_b_final_body_byte_emitted_ms: tableDuration + 8,
      request_direction_closed_ms: tableDuration + 9,
      b_to_a_final_body_byte_received_ms: tableDuration + 10,
      returned_received_ms: tableDuration + 11,
      response_eof_complete_ms: responseEof,
      table_stream_duration_ms: tableDuration,
      total_protocol_duration_ms: responseEof,
    },
  };
}

function attachRawSamples(report) {
  report.security_claim = 'none';
  report.failures = [];
  report.samples = [];
  for (let index = 0; index < report.requested_samples; index += 1) {
    report.samples.push(rawPhase13aSample(report, index));
  }
}

function setWarmMetricQuantiles(report, metric, p95, p99) {
  report.warm.metrics[metric].p95 = p95;
  report.warm.metrics[metric].p99 = p99;
  for (const sample of report.samples) {
    if (sample.index === 0) {
      continue;
    }
    const value = sample.index >= 49 ? p99 : p95;
    if (metric === 'client_wall_ms') {
      sample.client_wall_ms = value;
    } else {
      sample.result[metric] = value;
      sample.result.last_table_frame_accepted_ms = value + 6;
      sample.result.translation_accepted_ms = value + 7;
      sample.result.a_to_b_final_body_byte_emitted_ms = value + 8;
      sample.result.request_direction_closed_ms = value + 9;
      sample.result.b_to_a_final_body_byte_received_ms = value + 10;
      sample.result.returned_received_ms = value + 11;
      sample.result.response_eof_complete_ms = value + 12;
      sample.result.total_protocol_duration_ms = value + 12;
    }
  }
}

function setTablePayloadBytes(report, value) {
  report.fixed_profile_ranges.table_payload_bytes.min = value;
  report.fixed_profile_ranges.table_payload_bytes.max = value;
  for (const sample of report.samples) {
    sample.result.table_payload_bytes = value;
  }
}

async function fakeDeployedFetch() {
  return new Response(JSON.stringify(clonedDeployedSuccess()), {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cf-ray': '0123456789abcdef-NRT',
      server: 'cloudflare',
    },
  });
}

async function fakeDelayedBodyFetch() {
  return new Response(new ReadableStream(new DelayedSuccessBodySource()), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

async function fakeWrongColoFieldFetch() {
  const body = clonedDeployedSuccess();
  body.a_colo = body.deriver_a_colo;
  body.b_colo = body.deriver_b_colo;
  delete body.deriver_a_colo;
  delete body.deriver_b_colo;
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

async function fakeProductionEligibleFetch() {
  const body = clonedDeployedSuccess();
  body.production_eligible = true;
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

async function fakeWireMismatchFetch() {
  const body = clonedDeployedSuccess();
  body.total_ab_transport_bytes -= 1;
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

async function fakeDeploymentMismatchFetch() {
  const body = clonedDeployedSuccess();
  body.deployment_id = 'cd'.repeat(16);
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function graphqlRequestQuery(options) {
  return JSON.parse(options.body).query;
}

function jsonResponse(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

async function fakeGraphqlFetch(_url, options) {
  const query = graphqlRequestQuery(options);
  return query.includes('YaosAbWorkersMemory')
    ? jsonResponse(GRAPHQL_MEMORY_EQUAL)
    : jsonResponse(GRAPHQL_CORE_SUCCESS);
}

async function fakeMemoryUnavailableFetch(_url, options) {
  const query = graphqlRequestQuery(options);
  return query.includes('YaosAbWorkersMemory')
    ? jsonResponse(GRAPHQL_MEMORY_UNAVAILABLE)
    : jsonResponse(GRAPHQL_CORE_SUCCESS);
}

async function fakeBelowThresholdFetch(_url, options) {
  const query = graphqlRequestQuery(options);
  return query.includes('YaosAbWorkersMemory')
    ? jsonResponse(GRAPHQL_MEMORY_BELOW)
    : jsonResponse(GRAPHQL_CORE_SUCCESS);
}

async function fakeAboveThresholdFetch(_url, options) {
  const query = graphqlRequestQuery(options);
  return query.includes('YaosAbWorkersMemory')
    ? jsonResponse(GRAPHQL_MEMORY_ABOVE)
    : jsonResponse(GRAPHQL_CORE_SUCCESS);
}

async function fakeExceededMemoryFetch(_url, options) {
  const query = graphqlRequestQuery(options);
  return query.includes('YaosAbWorkersMemory')
    ? jsonResponse(GRAPHQL_MEMORY_BELOW)
    : jsonResponse(GRAPHQL_CORE_EXCEEDED_MEMORY);
}

function parseRejectedEnvironment(environment) {
  parseDeploymentEnvironment(environment);
}

function assertEnvironmentRejected(environment) {
  assert.throws(parseRejectedEnvironment.bind(null, environment), BoundaryError);
}

function costEnvironment() {
  return {
    YAOS_AB_TOPOLOGY: 'two-account',
    YAOS_AB_COST_CEREMONIES: '1000000',
    YAOS_AB_MEASURED_REQUESTS_A_PER_CEREMONY: '1',
    YAOS_AB_MEASURED_REQUESTS_B_PER_CEREMONY: '1',
    YAOS_AB_MEASURED_CPU_A_MS_PER_CEREMONY: '80',
    YAOS_AB_MEASURED_CPU_B_MS_PER_CEREMONY: '60',
    YAOS_AB_MEASURED_NETWORK_BYTES_PER_CEREMONY: '2222584',
    YAOS_AB_MEASURED_CPU_STATISTIC: 'GraphQL mean CPU from sum.cpuTimeUs/requests',
    YAOS_AB_PRICE_REQUESTS_USD_PER_MILLION_A: '0.30',
    YAOS_AB_PRICE_USAGE_MODEL: 'standard',
    YAOS_AB_PRICE_CPU_USD_PER_MILLION_MS_A: '0.02',
    YAOS_AB_INCLUDED_REQUESTS_A: '0',
    YAOS_AB_INCLUDED_CPU_MS_A: '0',
    YAOS_AB_PRICE_REQUESTS_USD_PER_MILLION_B: '0.30',
    YAOS_AB_PRICE_CPU_USD_PER_MILLION_MS_B: '0.02',
    YAOS_AB_INCLUDED_REQUESTS_B: '0',
    YAOS_AB_INCLUDED_CPU_MS_B: '0',
    YAOS_AB_PRICE_NETWORK_USD_PER_GB: '0',
    YAOS_AB_PRICE_EFFECTIVE_DATE: '2026-07-12',
    YAOS_AB_PRICE_SOURCE: 'https://developers.cloudflare.com/workers/platform/pricing/',
  };
}

function parseRejectedCostEnvironment(environment) {
  parseCostEnvironment(environment);
}

function assertCostEnvironmentRejected(environment) {
  assert.throws(parseRejectedCostEnvironment.bind(null, environment), BoundaryError);
}

function parseInvalidWhoami() {
  parseWhoamiAccountIds('{"loggedIn":true,"accounts":[{"id":"invalid"}]}');
}

function wranglerDeploymentOutput(scriptName, roleSuffix) {
  return `${JSON.stringify({
    type: 'wrangler-session',
    version: 1,
    wrangler_version: '4.110.0',
    timestamp: '2026-07-13T00:00:00.000Z',
  })}\n${JSON.stringify({
    type: 'deploy',
    version: 1,
    worker_name: scriptName,
    worker_tag: `benchmark-tag-${roleSuffix}`,
    version_id: `benchmark-version-${roleSuffix}`,
    targets: [`https://${scriptName}.example.com`],
    worker_name_overridden: false,
    wrangler_environment: 'production',
    timestamp: '2026-07-13T00:00:01.000Z',
  })}\n`;
}

function completeReceipt(configuration, deploymentId = FIXTURE_DEPLOYMENT_ID) {
  const receipt = initialDeploymentReceipt(
    configuration,
    deploymentId,
    '2026-07-13T00:00:00.000Z',
    LOCAL_READINESS_BUNDLE_SHA256,
  );
  const bArtifact = fixtureArtifactEvidence('b');
  const aArtifact = fixtureArtifactEvidence('a');
  attachRoleArtifact(receipt, 'b', bArtifact);
  attachRoleArtifact(receipt, 'a', aArtifact);
  attachConstantTimeCodegen(receipt, fixtureConstantTimeInspection(aArtifact, bArtifact));
  attachRoleDeployment(
    receipt,
    'b',
    wranglerDeploymentOutput(configuration.b.scriptName, 'bbbbbbbb'),
  );
  attachRoleDeployment(
    receipt,
    'a',
    wranglerDeploymentOutput(configuration.a.scriptName, 'aaaaaaaa'),
  );
  completeDeploymentReceipt(receipt);
  return receipt;
}

function coldDeploymentId(prefix, index) {
  return createHash('sha256').update(`${prefix}:${index}`).digest('hex').slice(0, 32);
}

function coldVersionId(prefix, role, index) {
  return `cold-${prefix}-${role}-${String(index).padStart(4, '0')}`;
}

function constantMetricSummary(value) {
  return { p50: value, p95: value, p99: value };
}

function coldProxySeries(report, receiptEvidence, prefix) {
  const samples = [];
  const first = report.samples[0];
  for (let index = 0; index < 20; index += 1) {
    const deployment = cloneJson(receiptEvidence);
    const deploymentId = coldDeploymentId(prefix, index);
    deployment.deployment_id = deploymentId;
    deployment.a.version_id = coldVersionId(prefix, 'a', index);
    deployment.b.version_id = coldVersionId(prefix, 'b', index);
    const sample = cloneJson(first);
    sample.index = 0;
    sample.started_at = new Date(
      Date.parse('2026-07-13T00:10:00.000Z') + index * 1_000,
    ).toISOString();
    sample.result.deployment_id = deploymentId;
    samples.push({
      source_report: `/tmp/${prefix}-${index}.json`,
      deployment,
      first_raw_sample: sample,
    });
  }
  return {
    schema: 'ed25519_yao_phase9b_fresh_version_first_request_series_v1',
    benchmark: report.benchmark,
    benchmark_only: true,
    topology: report.topology,
    region_label: report.region_label,
    sample_count: samples.length,
    classification: 'fresh-version-first-request-operational-cold-proxy',
    physical_isolate_cold_proven: false,
    metrics: {
      client_wall_ms: constantMetricSummary(first.client_wall_ms),
      table_stream_duration_ms: constantMetricSummary(first.result.table_stream_duration_ms),
    },
    samples,
  };
}

function phase13CostReport(deploymentEnvironment, receipt) {
  const environment = costEnvironment();
  environment.YAOS_AB_TOPOLOGY = deploymentEnvironment.YAOS_AB_TOPOLOGY;
  environment.YAOS_AB_MEASURED_REQUESTS_B_PER_CEREMONY =
    deploymentEnvironment.YAOS_AB_TOPOLOGY === 'one-account' ? '0' : '1';
  const configuration = parseCostEnvironment(environment);
  const deploymentConfiguration = parseDeploymentEnvironment(deploymentEnvironment);
  const metadata = costEvidenceMetadata(
    deploymentConfiguration,
    receipt,
    '2026-07-13T00:30:00.000Z',
  );
  return cloneJson(calculateCost(configuration, metadata));
}

function operationalAcceptance() {
  return {
    schema: 'ed25519_yao_phase13a_operational_acceptance_v1',
    decision: 'accept',
    accepted_at: '2026-07-13T00:05:00.000Z',
    accepted_by: 'phase13a-fixture-owner',
    independent_two_account_administration_accepted: true,
    pricing_source_reviewed: true,
    pricing_effective_date: '2026-07-12',
    maximum_same_account_usd_per_million: 10,
    maximum_cross_account_usd_per_million: 10,
  };
}

function fixtureArtifactEvidence(role) {
  const paths = ['index.js', 'index_bg.wasm', 'package.json', 'worker/shim.mjs'];
  const files = [];
  const aggregate = createHash('sha256');
  for (let index = 0; index < paths.length; index += 1) {
    const path = paths[index];
    const bytes = index + 1;
    const digest = createHash('sha256').update(`${role}-${path}`).digest('hex');
    files.push({ path, bytes, sha256: digest });
    aggregate.update(path);
    aggregate.update('\0');
    aggregate.update(String(bytes));
    aggregate.update('\0');
    aggregate.update(digest);
    aggregate.update('\0');
  }
  return {
    schema: 'ed25519_yao_worker_artifact_digest_v1',
    sha256: aggregate.digest('hex'),
    files,
  };
}

function fixtureConstantTimeInspection(aArtifact, bArtifact) {
  return {
    schema: 'ed25519_yao_worker_constant_time_codegen_v1',
    inspector: 'llvm-objdump-secret-bit-branch-gate-v1',
    result: 'pass',
    roles: {
      a: { wasm_sha256: aArtifact.files[1].sha256 },
      b: { wasm_sha256: bArtifact.files[1].sha256 },
    },
  };
}

function selectAction(operation) {
  return operation.action;
}

function selectRole(operation) {
  return operation.role;
}

function reasonCodes(result) {
  const codes = [];
  for (const reason of result.reasons) {
    codes.push(reason.code);
  }
  return codes;
}

function evaluateMissingTableTiming() {
  const input = phase13aInput();
  delete input.cross_benchmark.warm.metrics.table_stream_duration_ms;
  evaluatePhase13A(input);
}

function evaluateMissingRawSamples() {
  const input = phase13aInput();
  delete input.cross_benchmark.samples;
  evaluatePhase13A(input);
}

function evaluateMissingFirstResponseBodyByte() {
  const input = phase13aInput();
  delete input.cross_benchmark.samples[0].result.b_to_a_first_body_byte_received_ms;
  evaluatePhase13A(input);
}

function evaluateWrongOtRoundCount() {
  const input = phase13aInput();
  input.cross_benchmark.samples[0].result.ot_sequential_round_count = 3;
  evaluatePhase13A(input);
}

function evaluateForgedTableStreamDuration() {
  const input = phase13aInput();
  input.cross_benchmark.warm.metrics.table_stream_duration_ms.p95 = 1;
  for (const sample of input.cross_benchmark.samples) {
    sample.result.table_stream_duration_ms = 1;
  }
  evaluatePhase13A(input);
}

function evaluateForgedTransportBytes() {
  const input = phase13aInput();
  for (const sample of input.cross_benchmark.samples) {
    sample.result.total_ab_transport_bytes = 100;
  }
  evaluatePhase13A(input);
}

function evaluateTablePayloadDrift() {
  const input = phase13aInput();
  setTablePayloadBytes(input.cross_benchmark, 2_202_010);
  evaluatePhase13A(input);
}

function evaluateColdWireProfileDrift() {
  const input = phase13aInput();
  input.cross_cold_proxy.samples[0].first_raw_sample.result.ot_message_count = 3;
  evaluatePhase13A(input);
}

function evaluateColdArtifactDriftFromWarmCampaign() {
  const input = phase13aInput();
  for (const sample of input.cross_cold_proxy.samples) {
    sample.deployment.a.artifact_sha256 = 'f'.repeat(64);
    sample.deployment.constant_time_codegen.roles.a.artifact_sha256 = 'f'.repeat(64);
  }
  evaluatePhase13A(input);
}

function evaluateMissingColdProxy() {
  const input = phase13aInput();
  delete input.cross_cold_proxy;
  evaluatePhase13A(input);
}

function evaluateMissingCost() {
  const input = phase13aInput();
  delete input.cross_cost;
  evaluatePhase13A(input);
}

function evaluateMissingOperationalAcceptance() {
  const input = phase13aInput();
  delete input.operational_acceptance;
  evaluatePhase13A(input);
}

function evaluateInsufficientWarmSamples() {
  const input = phase13aInput();
  input.cross_benchmark.requested_samples = 2;
  input.cross_benchmark.completed_samples = 2;
  input.cross_benchmark.success_count = 2;
  input.cross_benchmark.warm.success_count = 1;
  input.cross_benchmark.samples = input.cross_benchmark.samples.slice(0, 2);
  evaluatePhase13A(input);
}

function evaluateReusedColdVersion() {
  const input = phase13aInput();
  input.cross_cold_proxy.samples[1].deployment.a.version_id =
    input.cross_cold_proxy.samples[0].deployment.a.version_id;
  evaluatePhase13A(input);
}

function evaluatePostmeasurementAcceptance() {
  const input = phase13aInput();
  input.operational_acceptance.accepted_at = '2026-07-13T00:11:00.000Z';
  evaluatePhase13A(input);
}

function evaluatePredeploymentBenchmarkWindow() {
  const input = phase13aInput();
  input.cross_benchmark.measurement_window.start = '2026-07-13T00:00:00.500Z';
  evaluatePhase13A(input);
}

function evaluateForgedMemoryP999Gate() {
  const input = phase13aInput();
  input.cross_analytics.a.memory.quantiles_bytes.memoryUsageBytesP999 = 100663296;
  evaluatePhase13A(input);
}

function evaluateForgedExceededMemoryGate() {
  const input = phase13aInput();
  input.cross_analytics.a.core.by_colo[0].dimensions.status = 'exceededMemory';
  evaluatePhase13A(input);
}

function evaluateMissingMemoryClassification() {
  const input = phase13aInput();
  delete input.cross_analytics.memory_evidence_classification;
  evaluatePhase13A(input);
}

function evaluateExactPeakClaim() {
  const input = phase13aInput();
  input.cross_analytics.exact_peak_proven = true;
  evaluatePhase13A(input);
}

function evaluateInventedPlatformCopyAccounting() {
  const input = phase13aInput();
  input.cross_analytics.platform_copy_accounting = 'complete';
  evaluatePhase13A(input);
}

function evaluateStaleLocalReadinessBundle() {
  const input = phase13aInput();
  input.cross_benchmark.deployment.local_readiness_bundle_sha256 = 'f'.repeat(64);
  evaluatePhase13A(input);
}

function evaluateCrossAccountCommitmentEquality() {
  const input = phase13aInput();
  input.cross_benchmark.deployment.topology_binding.b_account_sha256 =
    input.cross_benchmark.deployment.topology_binding.a_account_sha256;
  evaluatePhase13A(input);
}

function evaluateCrossAccountHostnameEquality() {
  const input = phase13aInput();
  input.cross_benchmark.deployment.topology_binding.b_public_hostname =
    input.cross_benchmark.deployment.topology_binding.a_public_hostname;
  evaluatePhase13A(input);
}

function evaluateColdTopologyBindingDrift() {
  const input = phase13aInput();
  for (const sample of input.cross_cold_proxy.samples) {
    sample.deployment.topology_binding.a_account_sha256 = '3'.repeat(64);
    sample.deployment.topology_binding.b_account_sha256 = '4'.repeat(64);
  }
  evaluatePhase13A(input);
}

function assertEvidenceErrorCode(action, expectedCode) {
  let observed = null;
  try {
    action();
  } catch (error) {
    if (error instanceof EvidenceError) {
      observed = error.code;
    } else {
      throw error;
    }
  }
  assert.equal(observed, expectedCode);
}

function testEnvironmentBoundaries() {
  const two = parseDeploymentEnvironment(twoAccountEnvironment());
  assert.equal(two.expectedTopologyLabel, 'cross-account-https');
  assert.equal(two.a.publicHostname, 'a-benchmark.example.com');
  assert.equal(two.b.publicHostname, 'b-benchmark.example.com');
  assert.equal(two.sampleCount, 3);

  const one = parseDeploymentEnvironment(oneAccountEnvironment());
  assert.equal(one.expectedTopologyLabel, 'same-account-service-binding');
  assert.equal(one.b.publicEndpoint, undefined);

  const equalAccounts = twoAccountEnvironment();
  equalAccounts.YAOS_AB_B_ACCOUNT_ID = equalAccounts.YAOS_AB_A_ACCOUNT_ID;
  assertEnvironmentRejected(equalAccounts);

  const wrongBEndpoint = twoAccountEnvironment();
  wrongBEndpoint.YAOS_AB_B_HTTPS_ENDPOINT = 'https://other.example.com/benchmark/activation';
  assertEnvironmentRejected(wrongBEndpoint);

  const queryEndpoint = twoAccountEnvironment();
  queryEndpoint.YAOS_AB_A_PUBLIC_ENDPOINT += '?profile=other';
  assertEnvironmentRejected(queryEndpoint);

  const unrelatedScript = twoAccountEnvironment();
  unrelatedScript.YAOS_AB_A_SCRIPT_NAME = 'production-router';
  assertEnvironmentRejected(unrelatedScript);
}

function testWhoamiBoundary() {
  const accountId = 'a'.repeat(32);
  const ids = parseWhoamiAccountIds(
    JSON.stringify({ loggedIn: true, accounts: [{ id: accountId, name: 'A' }] }),
  );
  assert.deepEqual([...ids], [accountId]);
  assert.throws(parseInvalidWhoami, BoundaryError);
}

function testDeploymentReceipt() {
  const configuration = parseDeploymentEnvironment(twoAccountEnvironment());
  const deploymentId = 'ab'.repeat(16);
  const receipt = initialDeploymentReceipt(
    configuration,
    deploymentId,
    '2026-07-13T00:00:00.000Z',
    LOCAL_READINESS_BUNDLE_SHA256,
  );
  const bArtifact = fixtureArtifactEvidence('b');
  const aArtifact = fixtureArtifactEvidence('a');
  attachRoleArtifact(receipt, 'b', bArtifact);
  attachRoleArtifact(receipt, 'a', aArtifact);
  attachConstantTimeCodegen(receipt, fixtureConstantTimeInspection(aArtifact, bArtifact));
  attachRoleDeployment(
    receipt,
    'b',
    wranglerDeploymentOutput(configuration.b.scriptName, 'bbbbbbbb'),
  );
  attachRoleDeployment(
    receipt,
    'a',
    wranglerDeploymentOutput(configuration.a.scriptName, 'aaaaaaaa'),
  );
  completeDeploymentReceipt(receipt);
  validateDeploymentReceipt(receipt, configuration, true);
  assert.equal(receipt.deployment_id, deploymentId);
  assert.equal(receipt.roles.a.deployment.wrangler_version, '4.110.0');
  assert.equal(receipt.constant_time_codegen.result, 'pass');
  assert.equal(receipt.local_readiness_bundle_sha256, LOCAL_READINESS_BUNDLE_SHA256);
  assert.equal(JSON.stringify(receipt).includes(configuration.a.accountId), false);
  assert.equal(JSON.stringify(receipt).includes(configuration.b.accountId), false);
  assert.notEqual(
    receipt.topology_binding.a_account_sha256,
    receipt.topology_binding.b_account_sha256,
  );

  const mismatchedTopologyBinding = cloneJson(receipt);
  mismatchedTopologyBinding.topology_binding.a_account_sha256 = 'f'.repeat(64);
  assert.throws(
    validateDeploymentReceipt.bind(null, mismatchedTopologyBinding, configuration, true),
    BoundaryError,
  );

  const missingLocalReadinessBundle = cloneJson(receipt);
  delete missingLocalReadinessBundle.local_readiness_bundle_sha256;
  assert.throws(
    validateDeploymentReceipt.bind(null, missingLocalReadinessBundle, configuration, true),
    BoundaryError,
  );

  const missingInspection = cloneJson(receipt);
  missingInspection.constant_time_codegen = null;
  assert.throws(
    validateDeploymentReceipt.bind(null, missingInspection, configuration, true),
    BoundaryError,
  );
  const mismatchedInspection = cloneJson(receipt);
  mismatchedInspection.constant_time_codegen.roles.a.wasm_sha256 = 'f'.repeat(64);
  assert.throws(
    validateDeploymentReceipt.bind(null, mismatchedInspection, configuration, true),
    BoundaryError,
  );

  const directory = mkdtempSync(join(tmpdir(), 'ed25519-yao-receipt-test-'));
  try {
    const path = join(directory, 'receipt.json');
    writeDeploymentReceipt(path, receipt, true);
    const loaded = readDeploymentReceipt(path, configuration, true);
    assert.equal(loaded.roles.b.deployment.version_id, 'benchmark-version-bbbbbbbb');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }

  assert.throws(
    parseWranglerDeploymentOutput.bind(
      null,
      wranglerDeploymentOutput('production-router', 'aaaaaaaa'),
      configuration.a.scriptName,
    ),
    BoundaryError,
  );
}

function writeArtifactFixture(directory) {
  mkdirSync(join(directory, 'worker'), { recursive: true });
  writeFileSync(join(directory, 'index.js'), 'export default {};\n');
  writeFileSync(join(directory, 'index_bg.wasm'), Buffer.from([0, 97, 115, 109]));
  writeFileSync(join(directory, 'package.json'), '{"type":"module"}\n');
  writeFileSync(join(directory, 'worker/shim.mjs'), 'export {};\n');
}

function testArtifactMutationDetection() {
  const directory = mkdtempSync(join(tmpdir(), 'ed25519-yao-artifact-mutation-'));
  try {
    writeArtifactFixture(directory);
    const expected = collectArtifactEvidence(directory);
    assertArtifactEvidenceEqual(expected, collectArtifactEvidence(directory), 'fixture artifact');

    writeFileSync(join(directory, 'index_bg.wasm'), Buffer.from([0, 97, 115, 109, 1]));
    assert.throws(
      assertArtifactEvidenceEqual.bind(
        null,
        expected,
        collectArtifactEvidence(directory),
        'fixture artifact',
      ),
      BoundaryError,
    );

    writeArtifactFixture(directory);
    writeFileSync(join(directory, 'index.js'), 'export default { changed: true };\n');
    assert.throws(
      assertArtifactEvidenceEqual.bind(
        null,
        expected,
        collectArtifactEvidence(directory),
        'fixture artifact',
      ),
      BoundaryError,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

async function testDeployedCollector() {
  const configuration = parseDeploymentEnvironment(twoAccountEnvironment());
  const receipt = completeReceipt(configuration);
  const report = await collectDeployedBenchmark(configuration, receipt, fakeDeployedFetch);
  assert.equal(report.success_count, 3);
  assert.equal(report.failure_count, 0);
  assert.equal(report.warm.success_count, 2);
  assert.equal(report.warm.metrics.elapsed_ms.p50, 123.5);
  assert.deepEqual(report.colo.a.values, ['NRT']);
  assert.deepEqual(report.colo.b.values, ['KIX']);
  assert.deepEqual(report.colo.client_edge_cross_check.values, ['NRT']);
  assert.equal(report.connection_reuse.directly_observable_from_fetch, false);

  const delayedBodyEnvironment = twoAccountEnvironment();
  delayedBodyEnvironment.YAOS_AB_SAMPLE_COUNT = '2';
  const delayedBodyConfiguration = parseDeploymentEnvironment(delayedBodyEnvironment);
  const delayedBodyReport = await collectDeployedBenchmark(
    delayedBodyConfiguration,
    completeReceipt(delayedBodyConfiguration),
    fakeDelayedBodyFetch,
  );
  assert.equal(delayedBodyReport.failure_count, 0);
  assert.equal(delayedBodyReport.samples.every(sampleIncludesDelayedBody), true);

  const wrongFieldReport = await collectDeployedBenchmark(
    configuration,
    receipt,
    fakeWrongColoFieldFetch,
  );
  assert.equal(wrongFieldReport.success_count, 0);
  assert.equal(wrongFieldReport.failure_count, 3);
  assert.equal(wrongFieldReport.failures[0].error_code, 'INVALID_BENCHMARK_RESPONSE');

  const productionEligibleReport = await collectDeployedBenchmark(
    configuration,
    receipt,
    fakeProductionEligibleFetch,
  );
  assert.equal(productionEligibleReport.success_count, 0);
  assert.equal(productionEligibleReport.failure_count, 3);
  assert.equal(productionEligibleReport.failures[0].error_code, 'INVALID_BENCHMARK_RESPONSE');

  const wireMismatchReport = await collectDeployedBenchmark(
    configuration,
    receipt,
    fakeWireMismatchFetch,
  );
  assert.equal(wireMismatchReport.success_count, 0);
  assert.equal(wireMismatchReport.failure_count, 3);
  assert.equal(wireMismatchReport.failures[0].error_code, 'INVALID_BENCHMARK_RESPONSE');

  const deploymentMismatchReport = await collectDeployedBenchmark(
    configuration,
    receipt,
    fakeDeploymentMismatchFetch,
  );
  assert.equal(deploymentMismatchReport.success_count, 0);
  assert.equal(deploymentMismatchReport.failure_count, 3);
  assert.equal(deploymentMismatchReport.failures[0].error_code, 'INVALID_BENCHMARK_RESPONSE');
}

function sampleIncludesDelayedBody(sample) {
  return sample.client_wall_ms >= DELAYED_BODY_MS - 5;
}

async function testGraphqlCollector() {
  const configuration = parseDeploymentEnvironment(twoAccountEnvironment());
  const receipt = completeReceipt(configuration);
  const window = parseAnalyticsWindow(analyticsWindowEnvironment());
  const tokens = { a: 'fixture-token-a-123456', b: 'fixture-token-b-123456' };
  const report = await collectWorkersAnalytics(
    configuration,
    receipt,
    window,
    tokens,
    fakeGraphqlFetch,
  );
  assert.equal(report.a.core.available, true);
  assert.equal(report.a.core.sum.requests, 51);
  assert.equal(report.a.core.quantiles.milliseconds.cpuTimeP99, 120);
  assert.equal(report.b.memory.available, true);
  assert.equal(report.b.memory.quantiles_bytes.memoryUsageBytesP999, 100663296);
  assert.equal(report.a.sampled_memory_gate.result, 'fail');
  assert.equal(report.a.sampled_memory_gate.threshold_bytes, 100663296);
  assert.equal(report.memory_evidence_classification, MEMORY_EVIDENCE_CLASSIFICATION);
  assert.equal(report.exact_peak_proven, false);
  assert.equal(report.platform_copy_accounting, PLATFORM_COPY_ACCOUNTING);
  assert.equal(JSON.stringify(report).includes(configuration.a.accountId), false);
  assert.equal(JSON.stringify(report).includes(tokens.a), false);

  const malformedCore = cloneJson(report.a.core);
  malformedCore.by_colo[0].sum.requests = '51';
  const malformedGate = buildSampledMemoryGate(malformedCore, report.a.memory);
  assert.equal(malformedGate.result, 'unavailable');
  assert.equal(malformedGate.exceeded_memory_status_count, null);

  const partial = await collectWorkersAnalytics(
    configuration,
    receipt,
    window,
    tokens,
    fakeMemoryUnavailableFetch,
  );
  assert.equal(partial.a.core.available, true);
  assert.equal(partial.a.memory.available, false);
  assert.equal(partial.a.memory.failure.kind, 'graphql-schema-or-plan');
  assert.equal(partial.a.memory.failure.errors[0].code, 'GRAPHQL_VALIDATION_FAILED');
  assert.equal(partial.a.sampled_memory_gate.result, 'unavailable');
  assert.equal(JSON.stringify(partial).includes('Cannot query field'), false);

  const below = await collectWorkersAnalytics(
    configuration,
    receipt,
    window,
    tokens,
    fakeBelowThresholdFetch,
  );
  assert.equal(below.a.sampled_memory_gate.result, 'pass');
  assert.equal(below.a.sampled_memory_gate.memory_usage_bytes_p999, 100663295);

  const above = await collectWorkersAnalytics(
    configuration,
    receipt,
    window,
    tokens,
    fakeAboveThresholdFetch,
  );
  assert.equal(above.a.sampled_memory_gate.result, 'fail');
  assert.equal(above.a.sampled_memory_gate.memory_usage_bytes_p999, 100663297);

  const exceeded = await collectWorkersAnalytics(
    configuration,
    receipt,
    window,
    tokens,
    fakeExceededMemoryFetch,
  );
  assert.equal(exceeded.a.sampled_memory_gate.result, 'fail');
  assert.equal(exceeded.a.sampled_memory_gate.exceeded_memory_status_observed, true);
  assert.equal(exceeded.a.sampled_memory_gate.exceeded_memory_status_count, 1);
}

function testQueryFixtures() {
  for (const expected of [
    'cpuTimeP50',
    'cpuTimeP99',
    'requestDurationP99',
    'wallTimeP99',
    'coloCode',
  ]) {
    assert.equal(WORKERS_CORE_QUERY.includes(expected), true);
  }
  for (const expected of [
    'memoryUsageBytesP50',
    'memoryUsageBytesP90',
    'memoryUsageBytesP99',
    'memoryUsageBytesP999',
  ]) {
    assert.equal(WORKERS_MEMORY_QUERY.includes(expected), true);
  }
}

function testCostCalculator() {
  const environment = costEnvironment();
  const configuration = parseCostEnvironment(environment);
  const deploymentConfiguration = parseDeploymentEnvironment(twoAccountEnvironment());
  const receipt = completeReceipt(deploymentConfiguration);
  const metadata = costEvidenceMetadata(
    deploymentConfiguration,
    receipt,
    '2026-07-13T00:30:00.000Z',
  );
  const report = calculateCost(configuration, metadata);
  assert.equal(report.request_model.matches_expected, true);
  assert.equal(report.account_costs.a_account_combined.measured_requests, 1_000_000);
  assert.equal(report.account_costs.b_account.measured_requests, 1_000_000);
  assert.equal(Number.isFinite(report.usd_per_ceremony), true);

  const zero = costEnvironment();
  zero.YAOS_AB_COST_CEREMONIES = '0';
  assertCostEnvironmentRejected(zero);

  const fractional = costEnvironment();
  fractional.YAOS_AB_COST_CEREMONIES = '1.5';
  assertCostEnvironmentRejected(fractional);
}

function testDeploymentPlan() {
  const two = parseDeploymentEnvironment(twoAccountEnvironment());
  const plan = buildDeploymentPlan(two, 'deploy-plan');
  assert.equal(plan.mode, 'deploy-plan');
  assert.equal(plan.external_state_changed, false);
  assert.equal(plan.external_state_change_requested, false);
  assert.equal(JSON.stringify(plan).includes(two.a.accountId), false);
  assert.equal(JSON.stringify(plan).includes(two.b.accountId), false);
  const twoConfigs = renderDeploymentConfigs(two);
  assert.equal(twoConfigs.a.account_id, two.a.accountId);
  assert.equal(twoConfigs.b.account_id, two.b.accountId);
  assert.equal(twoConfigs.a.vars.DERIVER_B_HTTPS_ENDPOINT, two.b.publicEndpoint);
  assert.equal(twoConfigs.a.routes[0].pattern, two.a.publicHostname);
  assert.equal(twoConfigs.b.routes[0].pattern, two.b.publicHostname);
  assert.equal(twoConfigs.a.main.startsWith('/'), true);
  assert.equal(twoConfigs.b.main.startsWith('/'), true);
  assert.equal(twoConfigs.a.build.watch_dir.startsWith('/'), true);
  assert.equal(twoConfigs.b.build.watch_dir.startsWith('/'), true);
  assert.equal(twoConfigs.a.build.command.includes('worker-build --release'), true);
  assert.equal(twoConfigs.a.build.command.includes(' --features deriver-a-cross-account'), true);
  const boundConfigs = renderDeploymentConfigs(two, FIXTURE_DEPLOYMENT_ID);
  assert.equal(boundConfigs.a.vars.BENCHMARK_DEPLOYMENT_ID, FIXTURE_DEPLOYMENT_ID);
  assert.equal(boundConfigs.b.vars.BENCHMARK_DEPLOYMENT_ID, FIXTURE_DEPLOYMENT_ID);
  const prebuiltA = bindPrebuiltArtifact(boundConfigs.a, '/tmp/prebuilt-a');
  assert.equal(prebuiltA.main, '/tmp/prebuilt-a/index.js');
  assert.equal(prebuiltA.no_bundle, true);
  assert.equal(prebuiltA.build, undefined);
  assert.deepEqual(plan.operations.map(selectAction), [
    'wrangler whoami --json',
    'wrangler whoami --json',
    'wrangler deploy --strict',
    'wrangler deploy --strict',
  ]);

  const cleanup = buildDeploymentPlan(two, 'cleanup-plan');
  assert.deepEqual(cleanup.operations.map(selectRole), [
    'deriver-a',
    'deriver-b',
    'deriver-a',
    'deriver-b',
  ]);
  assert.equal(cleanup.operations[2].action, 'wrangler delete --force');

  const one = parseDeploymentEnvironment(oneAccountEnvironment());
  const oneConfigs = renderDeploymentConfigs(one);
  assert.equal(oneConfigs.a.services[0].service, one.b.scriptName);
  assert.equal(oneConfigs.b.routes, undefined);
}

function testCheckedInExamplesAreNonExecuting() {
  for (const name of ['one-account.env.example', 'two-account.env.example']) {
    const environment = envExample(name);
    assert.notEqual(environment.YAOS_AB_CONFIRM_NON_PRODUCTION, 'YES');
    assert.notEqual(environment.YAOS_AB_CONFIRM_NO_AUTH_CLAIM, 'YES');
    assert.notEqual(environment.YAOS_AB_CONFIRM_DELETE_BENCHMARK, 'YES');
  }
  assertCostEnvironmentRejected(envExample('cost.env.example'));
}

function testPhase13aEvaluator() {
  const passing = evaluatePhase13A(phase13aInput());
  assert.equal(passing.decision, 'go');
  assert.equal(passing.reasons.length, 0);
  assert.equal(passing.evidence.cross_account.table_payload_bytes.exact_known_bytes, 2104960);
  assert.equal(PHASE13A_THRESHOLDS.table_payload_bytes_max_floor, 2202009);
  assert.equal(passing.evidence.combined_cross_account_cpu_p95_upper_bound_ms, 150);

  const transferEquality = phase13aInput();
  setWarmMetricQuantiles(transferEquality.cross_benchmark, 'table_stream_duration_ms', 75, 75);
  assert.deepEqual(reasonCodes(evaluatePhase13A(transferEquality)), [
    'PHASE13A_CROSS_TABLE_STREAM_P95_EXCEEDED',
  ]);

  const ceremonyTooSlow = phase13aInput();
  setWarmMetricQuantiles(ceremonyTooSlow.cross_benchmark, 'client_wall_ms', 250.001, 500.001);
  assert.deepEqual(reasonCodes(evaluatePhase13A(ceremonyTooSlow)), [
    'PHASE13A_CROSS_CEREMONY_P95_EXCEEDED',
    'PHASE13A_CROSS_CEREMONY_P99_EXCEEDED',
  ]);

  const cpuTooHigh = phase13aInput();
  cpuTooHigh.cross_analytics.a.core.quantiles.milliseconds.cpuTimeP99 = 86;
  assert.deepEqual(reasonCodes(evaluatePhase13A(cpuTooHigh)), [
    'PHASE13A_COMBINED_CPU_P95_EXCEEDED',
  ]);

  const contaminatedWindow = phase13aInput();
  contaminatedWindow.cross_analytics.b.core.sum.requests = 52;
  contaminatedWindow.cross_analytics.b.core.by_colo[0].sum.requests = 52;
  assert.deepEqual(reasonCodes(evaluatePhase13A(contaminatedWindow)), [
    'PHASE13A_CROSS_B_REQUEST_COUNT_MISMATCH',
    'PHASE13A_CROSS_COST_EVIDENCE_MISMATCH',
  ]);

  const staleAnalyticsDeployment = phase13aInput();
  staleAnalyticsDeployment.cross_analytics.deployment.b.version_id = 'benchmark-version-stale-b';
  assert.deepEqual(reasonCodes(evaluatePhase13A(staleAnalyticsDeployment)), [
    'PHASE13A_CROSS_DEPLOYMENT_MISMATCH',
    'PHASE13A_CROSS_COST_EVIDENCE_MISMATCH',
  ]);

  const unavailable = phase13aInput();
  unavailable.cross_analytics.a.core.available = false;
  unavailable.cross_analytics.a.sampled_memory_gate.result = 'unavailable';
  unavailable.cross_analytics.a.sampled_memory_gate.exceeded_memory_status_count = null;
  unavailable.cross_analytics.a.sampled_memory_gate.exceeded_memory_status_observed = null;
  const unavailableCodes = reasonCodes(evaluatePhase13A(unavailable));
  assert.equal(unavailableCodes.includes('PHASE13A_CROSS_A_CORE_UNAVAILABLE'), true);
  assert.equal(unavailableCodes.includes('PHASE13A_COMBINED_CPU_P95_UNAVAILABLE'), true);
  assert.equal(unavailableCodes.includes('PHASE13A_CROSS_A_MEMORY_GATE_FAILED'), true);

  const memoryEquality = phase13aInput();
  memoryEquality.cross_analytics.b.memory.quantiles_bytes.memoryUsageBytesP999 = 100663296;
  memoryEquality.cross_analytics.b.sampled_memory_gate.memory_usage_bytes_p999 = 100663296;
  memoryEquality.cross_analytics.b.sampled_memory_gate.result = 'fail';
  assert.deepEqual(reasonCodes(evaluatePhase13A(memoryEquality)), [
    'PHASE13A_CROSS_B_MEMORY_GATE_FAILED',
  ]);

  const exceededMemory = phase13aInput();
  exceededMemory.cross_analytics.b.core.by_colo[0].dimensions.status = 'exceededMemory';
  exceededMemory.cross_analytics.b.sampled_memory_gate.exceeded_memory_status_count = 51;
  exceededMemory.cross_analytics.b.sampled_memory_gate.exceeded_memory_status_observed = true;
  exceededMemory.cross_analytics.b.sampled_memory_gate.result = 'fail';
  assert.deepEqual(reasonCodes(evaluatePhase13A(exceededMemory)), [
    'PHASE13A_CROSS_B_MEMORY_GATE_FAILED',
  ]);

  const unacceptableCost = phase13aInput();
  unacceptableCost.operational_acceptance.maximum_cross_account_usd_per_million = 1;
  assert.deepEqual(reasonCodes(evaluatePhase13A(unacceptableCost)), [
    'PHASE13A_CROSS_COST_EXCEEDED',
  ]);

  assert.throws(evaluateMissingTableTiming, EvidenceError);
  assert.throws(evaluateMissingRawSamples, EvidenceError);
  assert.throws(evaluateMissingFirstResponseBodyByte, EvidenceError);
  assert.throws(evaluateWrongOtRoundCount, EvidenceError);
  assertEvidenceErrorCode(
    evaluateForgedTableStreamDuration,
    'PHASE13A_REPORT_IDENTITY_MISMATCH',
  );
  assertEvidenceErrorCode(evaluateForgedTransportBytes, 'PHASE13A_RAW_SAMPLE_WIRE_PROFILE');
  assertEvidenceErrorCode(evaluateTablePayloadDrift, 'PHASE13A_RAW_SAMPLE_WIRE_PROFILE');
  assertEvidenceErrorCode(evaluateColdWireProfileDrift, 'PHASE13A_RAW_SAMPLE_WIRE_PROFILE');
  assertEvidenceErrorCode(
    evaluateColdArtifactDriftFromWarmCampaign,
    'PHASE13A_REPORT_IDENTITY_MISMATCH',
  );
  assert.throws(evaluateMissingColdProxy, EvidenceError);
  assert.throws(evaluateMissingCost, EvidenceError);
  assert.throws(evaluateMissingOperationalAcceptance, EvidenceError);
  assertEvidenceErrorCode(
    evaluateInsufficientWarmSamples,
    'PHASE13A_WARM_SAMPLE_COUNT_INSUFFICIENT',
  );
  assertEvidenceErrorCode(evaluateReusedColdVersion, 'PHASE13A_COLD_PROXY_IDENTITY_REUSED');
  assertEvidenceErrorCode(
    evaluatePostmeasurementAcceptance,
    'PHASE13A_OPERATIONAL_ACCEPTANCE_POSTMEASUREMENT',
  );
  assertEvidenceErrorCode(
    evaluatePredeploymentBenchmarkWindow,
    'PHASE13A_MEASUREMENT_PREDEPLOYMENT',
  );
  assertEvidenceErrorCode(
    evaluateForgedMemoryP999Gate,
    'PHASE13A_REPORT_IDENTITY_MISMATCH',
  );
  assertEvidenceErrorCode(
    evaluateForgedExceededMemoryGate,
    'PHASE13A_REPORT_IDENTITY_MISMATCH',
  );
  assertEvidenceErrorCode(
    evaluateMissingMemoryClassification,
    'PHASE13A_REPORT_IDENTITY_MISMATCH',
  );
  assertEvidenceErrorCode(evaluateExactPeakClaim, 'PHASE13A_REPORT_IDENTITY_MISMATCH');
  assertEvidenceErrorCode(
    evaluateInventedPlatformCopyAccounting,
    'PHASE13A_REPORT_IDENTITY_MISMATCH',
  );
  assertEvidenceErrorCode(
    evaluateStaleLocalReadinessBundle,
    'PHASE13A_DEPLOYMENT_IDENTITY',
  );
  assertEvidenceErrorCode(
    evaluateCrossAccountCommitmentEquality,
    'PHASE13A_DEPLOYMENT_IDENTITY',
  );
  assertEvidenceErrorCode(
    evaluateCrossAccountHostnameEquality,
    'PHASE13A_DEPLOYMENT_IDENTITY',
  );
  assertEvidenceErrorCode(
    evaluateColdTopologyBindingDrift,
    'PHASE13A_REPORT_IDENTITY_MISMATCH',
  );
}

function testPhase13aCliEvidenceIncomplete() {
  const environment = { ...process.env };
  for (const name of Object.keys(environment)) {
    if (name.startsWith('YAOS_AB_PHASE13A_')) {
      delete environment[name];
    }
  }
  const execution = spawnSync(process.execPath, [PHASE13A_EVALUATOR], {
    env: environment,
    encoding: 'utf8',
  });
  assert.equal(execution.status, 2);
  const report = JSON.parse(execution.stdout);
  assert.equal(report.decision, 'evidence-incomplete');
  assert.equal(report.reasons[0].code, 'PHASE13A_REPORT_PATH_INVALID');
}

async function main() {
  testEnvironmentBoundaries();
  testWhoamiBoundary();
  testDeploymentReceipt();
  testArtifactMutationDetection();
  testQueryFixtures();
  testCostCalculator();
  testDeploymentPlan();
  testCheckedInExamplesAreNonExecuting();
  testPhase13aEvaluator();
  testPhase13aCliEvidenceIncomplete();
  await testDeployedCollector();
  await testGraphqlCollector();
  process.stdout.write('deployment tooling fixtures passed\n');
}

main().catch(handleFatal);

function handleFatal(error) {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
}
