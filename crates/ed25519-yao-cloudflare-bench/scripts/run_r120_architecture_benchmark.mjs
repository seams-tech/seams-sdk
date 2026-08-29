import { pathToFileURL } from "node:url";

import {
  BoundaryError,
  parseDeploymentEnvironment,
} from "./deployment_boundary.mjs";
import {
  deploymentReceiptEvidence,
  deploymentReceiptPath,
  readDeploymentReceipt,
} from "./deployment_receipt.mjs";

const DEFAULT_SAMPLES = 101;
const DEFAULT_ENDPOINT = "http://127.0.0.1:8787/benchmark/activation";
const DEFAULT_TOPOLOGY = "same-account-service-binding-websocket";
const REQUEST_TIMEOUT_MS = 120_000;
const MAX_RESPONSE_BYTES = 65_536;
const MAX_WARM_P95_DELTA_MS = 10;
const MINIMUM_WARM_SAMPLES = 100;
const PROOF_BUNDLE_BYTES = 342;
const TOTAL_PREFACE_BYTES = 684;
const MAX_PREFACE_BYTES = 4_096;
const LOCAL_DEPLOYMENT_ID = "0123456789abcdef0123456789abcdef";
const PROFILES = Object.freeze(["current", "threshold-prf-v1"]);
const CAMPAIGNS = Object.freeze([
  "paired-latency",
  "resource-current",
  "resource-candidate",
]);
const ALLOWED_TOPOLOGIES = Object.freeze([
  "same-account-service-binding-websocket",
  "cross-account-websocket",
]);
const CEREMONIES = Object.freeze([
  Object.freeze({
    id: "activation",
    benchmark: "phase9b-cloudflare-activation-128kib",
    circuitDigest: "65b001c2f94de27ee8cb9f0c0773fbe54258ceab43d183174bee710ee8aa546d",
    scheduleDigest: "fb04a139dec15e9d52e496dc4fc011cf885c8f3f6f2d18bf3860e46071f0e69a",
  }),
  Object.freeze({
    id: "export",
    benchmark: "r120-cloudflare-export-128kib",
    circuitDigest: "31b03d13e41a728342aedce7af40f5405dc598d28e784de44d8044db9c601a0c",
    scheduleDigest: "66ddc20f8407e369b74f2a210287d2131e78c7525f47fc829c57f6418b0d97d0",
  }),
  Object.freeze({
    id: "lane-materialization",
    benchmark: "r120-cloudflare-lane-materialization-128kib",
    circuitDigest: "b82d95991e0d3f91f2d31009cb1558f73abd1d0a667fec99e02ddb751f652d06",
    scheduleDigest: "3bbae3843bab644b3b7e7ed6dd379b6b40b7c32133c5094e4b1fc4e966fd57d4",
  }),
]);
const YAO_PARITY_FIELDS = Object.freeze([
  "table_payload_bytes",
  "body_bytes",
  "frame_count",
  "table_framing_payload_bytes",
  "table_protocol_bytes",
  "ot_payload_bytes",
  "other_control_payload_bytes",
  "envelope_header_bytes",
  "table_transport_bytes",
  "control_transport_bytes",
  "deriver_a_to_b_transport_bytes",
  "deriver_b_to_a_transport_bytes",
  "total_ab_transport_bytes",
  "ot_message_count",
  "ot_sequential_round_count",
  "transport_message_count",
  "peak_outgoing_envelope_bytes",
  "max_incoming_platform_fragment_bytes",
  "client_package_bytes",
  "signing_worker_package_bytes",
]);

function compareNumbers(left, right) {
  return left - right;
}

function percentile(values, percentileValue) {
  if (values.length === 0) {
    throw new Error("cannot compute a percentile without samples");
  }
  const sorted = [...values].sort(compareNumbers);
  const rank = Math.max(0, Math.ceil(percentileValue * sorted.length) - 1);
  return sorted[rank];
}

function summarize(values) {
  return Object.freeze({
    min: Math.min(...values),
    p50: percentile(values, 0.5),
    p95: percentile(values, 0.95),
    p99: percentile(values, 0.99),
    max: Math.max(...values),
  });
}

function parseSampleCount(raw) {
  if (raw === undefined) {
    return DEFAULT_SAMPLES;
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isSafeInteger(parsed) || parsed < 2 || parsed > 1_000) {
    throw new Error("sample count must be an integer from 2 through 1000");
  }
  return parsed;
}

function parseTopology(raw) {
  const topology = raw ?? DEFAULT_TOPOLOGY;
  if (!ALLOWED_TOPOLOGIES.includes(topology)) {
    throw new Error(`unsupported topology: ${topology}`);
  }
  return topology;
}

function parseCampaign(raw) {
  const campaign = raw ?? "paired-latency";
  if (!CAMPAIGNS.includes(campaign)) {
    throw new Error(`unsupported R120 campaign: ${campaign}`);
  }
  return campaign;
}

function isFiniteNonnegative(value) {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function requireFiniteNonnegative(result, field) {
  if (!isFiniteNonnegative(result[field])) {
    throw new Error(`invalid numeric benchmark field: ${field}`);
  }
}

function requireZero(result, field) {
  if (result[field] !== 0) {
    throw new Error(`baseline-only work appeared in ${field}`);
  }
}

function validateCommonResult(
  result,
  ceremony,
  profile,
  expectedTopology,
  expectedDeploymentId,
) {
  if (
    result === null ||
    typeof result !== "object" ||
    result.ok !== true ||
    result.benchmark_only !== true ||
    result.production_eligible !== false ||
    result.role !== "deriver-a" ||
    result.topology !== expectedTopology ||
    result.deployment_id !== expectedDeploymentId ||
    result.family !== ceremony.id ||
    result.benchmark !== ceremony.benchmark ||
    result.profile !== "128KiB" ||
    result.r120_profile !== profile ||
    result.yao_circuit_digest !== ceremony.circuitDigest ||
    result.yao_schedule_digest !== ceremony.scheduleDigest
  ) {
    throw new Error(`unexpected R120 benchmark response: ${JSON.stringify(result)}`);
  }
  for (const field of YAO_PARITY_FIELDS) {
    requireFiniteNonnegative(result, field);
  }
  for (const field of [
    "elapsed_ms",
    "r120_preface_wall_ms",
    "r120_preface_peer_exchange_ms",
    "r120_preface_a_to_b_bytes",
    "r120_preface_b_to_a_bytes",
    "r120_preface_total_bytes",
    "r120_proof_bundle_flights",
    "r120_added_connection_count",
    "r120_added_http_request_count",
    "r120_added_websocket_count",
    "r120_added_client_round_trip_count",
    "r120_standalone_readiness_message_flights",
  ]) {
    requireFiniteNonnegative(result, field);
  }
  if (
    result.total_outgoing_envelope_bytes !== result.deriver_a_to_b_transport_bytes ||
    result.total_incoming_body_bytes !== result.deriver_b_to_a_transport_bytes
  ) {
    throw new Error("Yao directional wire accounting does not match the transport");
  }
  for (const field of [
    "r120_added_connection_count",
    "r120_added_http_request_count",
    "r120_added_websocket_count",
    "r120_added_client_round_trip_count",
    "r120_standalone_readiness_message_flights",
  ]) {
    requireZero(result, field);
  }
}

function validatePrefaceResult(result, profile) {
  if (profile === "current") {
    for (const field of [
      "r120_preface_wall_ms",
      "r120_preface_peer_exchange_ms",
      "r120_preface_a_to_b_bytes",
      "r120_preface_b_to_a_bytes",
      "r120_preface_total_bytes",
      "r120_proof_bundle_flights",
    ]) {
      requireZero(result, field);
    }
    return;
  }
  if (
    result.r120_preface_a_to_b_bytes !== PROOF_BUNDLE_BYTES ||
    result.r120_preface_b_to_a_bytes !== PROOF_BUNDLE_BYTES ||
    result.r120_preface_total_bytes !== TOTAL_PREFACE_BYTES ||
    result.r120_preface_total_bytes > MAX_PREFACE_BYTES ||
    result.r120_proof_bundle_flights !== 1 ||
    result.r120_preface_peer_exchange_ms > result.r120_preface_wall_ms
  ) {
    throw new Error(`candidate preface accounting is invalid: ${JSON.stringify(result)}`);
  }
}

export function validateR120Result(
  result,
  ceremony,
  profile,
  expectedTopology,
  expectedDeploymentId,
) {
  validateCommonResult(
    result,
    ceremony,
    profile,
    expectedTopology,
    expectedDeploymentId,
  );
  validatePrefaceResult(result, profile);
}

function yaoParitySignature(sample) {
  const identity = {
    circuit_digest: sample.yao_circuit_digest,
    schedule_digest: sample.yao_schedule_digest,
  };
  for (const field of YAO_PARITY_FIELDS) {
    identity[field] = sample[field];
  }
  return JSON.stringify(identity);
}

function samplesFor(samples, ceremonyId, profile) {
  return samples.filter(function matchesCohort(sample) {
    return sample.family === ceremonyId && sample.r120_profile === profile;
  });
}

function valuesFor(samples, field) {
  return samples.map(function selectValue(sample) {
    return sample[field];
  });
}

function buildCohort(samples) {
  const coldFirst = samples[0];
  const warm = samples.slice(1);
  return Object.freeze({
    sample_count: samples.length,
    cold_first: coldFirst,
    warm: Object.freeze({
      sample_count: warm.length,
      client_wall_ms: summarize(valuesFor(warm, "client_wall_ms")),
      worker_elapsed_ms: summarize(valuesFor(warm, "elapsed_ms")),
      preface_wall_ms: summarize(valuesFor(warm, "r120_preface_wall_ms")),
      preface_peer_exchange_ms: summarize(
        valuesFor(warm, "r120_preface_peer_exchange_ms"),
      ),
    }),
  });
}

function validateYaoParity(current, candidate, ceremonyId) {
  const signatures = new Set();
  for (const sample of [...current, ...candidate]) {
    signatures.add(yaoParitySignature(sample));
  }
  if (signatures.size !== 1) {
    throw new Error(`current/candidate Yao artifacts diverged for ${ceremonyId}`);
  }
}

function buildCeremonyReport(samples, ceremony, samplesPerCohort) {
  const currentSamples = samplesFor(samples, ceremony.id, "current");
  const candidateSamples = samplesFor(samples, ceremony.id, "threshold-prf-v1");
  if (
    currentSamples.length !== samplesPerCohort ||
    candidateSamples.length !== samplesPerCohort
  ) {
    throw new Error(`incomplete R120 cohorts for ${ceremony.id}`);
  }
  validateYaoParity(currentSamples, candidateSamples, ceremony.id);
  const current = buildCohort(currentSamples);
  const candidate = buildCohort(candidateSamples);
  const clientWallP95DeltaMs =
    candidate.warm.client_wall_ms.p95 - current.warm.client_wall_ms.p95;
  const workerElapsedP95DeltaMs =
    candidate.warm.worker_elapsed_ms.p95 - current.warm.worker_elapsed_ms.p95;
  return Object.freeze({
    benchmark: ceremony.benchmark,
    artifact_identity: Object.freeze({
      circuit_digest: ceremony.circuitDigest,
      schedule_digest: ceremony.scheduleDigest,
    }),
    current,
    candidate,
    warm_p95_delta_ms: Object.freeze({
      client_wall: clientWallP95DeltaMs,
      worker_elapsed: workerElapsedP95DeltaMs,
    }),
    latency_gate_passed:
      clientWallP95DeltaMs <= MAX_WARM_P95_DELTA_MS &&
      workerElapsedP95DeltaMs <= MAX_WARM_P95_DELTA_MS,
  });
}

function ceremonyReports(samples, samplesPerCohort) {
  const reports = {};
  for (const ceremony of CEREMONIES) {
    reports[ceremony.id] = buildCeremonyReport(samples, ceremony, samplesPerCohort);
  }
  return Object.freeze(reports);
}

function resourceProfile(campaign) {
  switch (campaign) {
    case "resource-current":
      return "current";
    case "resource-candidate":
      return "threshold-prf-v1";
    case "paired-latency":
      throw new Error("paired latency has no single resource profile");
    default:
      throw new Error(`unsupported R120 campaign: ${campaign}`);
  }
}

function resourceCeremonyReports(samples, profile, samplesPerCohort) {
  const reports = {};
  for (const ceremony of CEREMONIES) {
    const cohortSamples = samplesFor(samples, ceremony.id, profile);
    if (cohortSamples.length !== samplesPerCohort) {
      throw new Error(`incomplete R120 resource cohort for ${ceremony.id}`);
    }
    const signatures = new Set(cohortSamples.map(yaoParitySignature));
    if (signatures.size !== 1) {
      throw new Error(`R120 resource cohort drifted for ${ceremony.id}`);
    }
    reports[ceremony.id] = Object.freeze({
      benchmark: ceremony.benchmark,
      artifact_identity: Object.freeze({
        circuit_digest: ceremony.circuitDigest,
        schedule_digest: ceremony.scheduleDigest,
      }),
      cohort: buildCohort(cohortSamples),
    });
  }
  return Object.freeze(reports);
}

function everyLatencyGatePassed(reports) {
  return Object.values(reports).every(function ceremonyPassed(report) {
    return report.latency_gate_passed;
  });
}

function feasibilityStatus(latencyGatePassed, sampleCountGatePassed) {
  if (!latencyGatePassed) {
    return "rejected-by-latency";
  }
  if (!sampleCountGatePassed) {
    return "provisionally-feasible";
  }
  return "latency-wire-and-sample-gates-passed";
}

function validateEvidenceScope(evidenceScope, expectedTopology) {
  if (evidenceScope?.kind === "local-diagnostic") {
    if (evidenceScope.deployment_id !== LOCAL_DEPLOYMENT_ID) {
      throw new Error("local evidence has an unexpected deployment ID");
    }
    return evidenceScope;
  }
  if (
    evidenceScope?.kind === "deployed-selection" &&
    evidenceScope.deployment?.deployment_id === evidenceScope.deployment_id &&
    evidenceScope.deployment?.topology === expectedTopology
  ) {
    return evidenceScope;
  }
  throw new Error("R120 evidence scope is invalid");
}

function validateReportSamples(
  samples,
  profiles,
  samplesPerCohort,
  expectedTopology,
  expectedDeploymentId,
) {
  if (
    !Array.isArray(samples) ||
    samples.length !== CEREMONIES.length * profiles.length * samplesPerCohort
  ) {
    throw new Error("R120 report has an invalid raw sample count");
  }
  const observed = new Set();
  for (const sample of samples) {
    const ceremony = CEREMONIES.find(function matchingCeremony(value) {
      return value.id === sample?.family;
    });
    if (
      ceremony === undefined ||
      !profiles.includes(sample.r120_profile) ||
      !Number.isSafeInteger(sample.cohort_index) ||
      sample.cohort_index < 0 ||
      sample.cohort_index >= samplesPerCohort ||
      !isFiniteNonnegative(sample.client_wall_ms)
    ) {
      throw new Error("R120 report contains an invalid raw sample");
    }
    validateR120Result(
      sample,
      ceremony,
      sample.r120_profile,
      expectedTopology,
      expectedDeploymentId,
    );
    const key = `${sample.family}:${sample.r120_profile}:${sample.cohort_index}`;
    if (observed.has(key)) {
      throw new Error("R120 report contains a duplicate raw sample");
    }
    observed.add(key);
  }
}

export function buildR120Report({
  endpoint,
  expectedTopology,
  samples,
  samplesPerCohort,
  evidenceScope,
  startedAt,
  endedAt,
}) {
  const validatedEvidenceScope = validateEvidenceScope(evidenceScope, expectedTopology);
  validateReportSamples(
    samples,
    PROFILES,
    samplesPerCohort,
    expectedTopology,
    validatedEvidenceScope.deployment_id,
  );
  const ceremonies = ceremonyReports(samples, samplesPerCohort);
  const warmSamplesPerCohort = samplesPerCohort - 1;
  const sampleCountGatePassed = warmSamplesPerCohort >= MINIMUM_WARM_SAMPLES;
  const latencyGatePassed = everyLatencyGatePassed(ceremonies);
  return Object.freeze({
    benchmark: "r120-threshold-prf-architecture-selection-v1",
    benchmark_only: true,
    generated_at: endedAt,
    measurement_window: Object.freeze({ start: startedAt, end: endedAt }),
    evidence_scope: validatedEvidenceScope,
    endpoint,
    topology: expectedTopology,
    samples_per_cohort: samplesPerCohort,
    warm_samples_per_cohort: warmSamplesPerCohort,
    attempt_count: samples.length,
    success_count: samples.length,
    failure_count: 0,
    retry_count: 0,
    frozen_limits: Object.freeze({
      maximum_warm_p95_delta_ms: MAX_WARM_P95_DELTA_MS,
      minimum_warm_samples_per_cohort: MINIMUM_WARM_SAMPLES,
      maximum_preface_wire_bytes: MAX_PREFACE_BYTES,
      exact_proof_bundle_flights: 1,
      added_connections: 0,
      added_http_requests: 0,
      added_websockets: 0,
      added_client_round_trips: 0,
      standalone_readiness_message_flights: 0,
    }),
    ceremonies,
    acceptance: Object.freeze({
      feasibility_status: feasibilityStatus(latencyGatePassed, sampleCountGatePassed),
      sample_count_gate_passed: sampleCountGatePassed,
      latency_gate_passed: latencyGatePassed,
      artifact_and_wire_parity_passed: true,
      preface_resource_budget_passed: true,
      deployed_cpu_memory_and_headroom: "requires-workers-analytics",
      signed_selection_record: "requires-release-signing",
      selection_ready: false,
    }),
    samples,
  });
}

export function buildR120ResourceCampaignReport({
  endpoint,
  expectedTopology,
  samples,
  samplesPerCohort,
  evidenceScope,
  campaign,
  startedAt,
  endedAt,
}) {
  const validatedEvidenceScope = validateEvidenceScope(evidenceScope, expectedTopology);
  if (validatedEvidenceScope.kind !== "deployed-selection") {
    throw new Error("R120 resource campaigns require deployment-bound evidence");
  }
  const profile = resourceProfile(campaign);
  validateReportSamples(
    samples,
    [profile],
    samplesPerCohort,
    expectedTopology,
    validatedEvidenceScope.deployment_id,
  );
  const warmSamplesPerCohort = samplesPerCohort - 1;
  return Object.freeze({
    benchmark: "r120-threshold-prf-resource-campaign-v1",
    benchmark_only: true,
    generated_at: endedAt,
    measurement_window: Object.freeze({ start: startedAt, end: endedAt }),
    evidence_scope: validatedEvidenceScope,
    endpoint,
    topology: expectedTopology,
    campaign: Object.freeze({ kind: "resource-profile", profile }),
    samples_per_cohort: samplesPerCohort,
    warm_samples_per_cohort: warmSamplesPerCohort,
    attempt_count: samples.length,
    success_count: samples.length,
    failure_count: 0,
    retry_count: 0,
    ceremonies: resourceCeremonyReports(samples, profile, samplesPerCohort),
    acceptance: Object.freeze({
      sample_count_gate_passed: warmSamplesPerCohort >= MINIMUM_WARM_SAMPLES,
      artifact_and_wire_consistency_passed: true,
      workers_analytics: "required-for-resource-comparison",
      selection_ready: false,
    }),
    samples,
  });
}

async function readBoundedText(response) {
  const declared = response.headers.get("content-length");
  if (declared !== null && Number(declared) > MAX_RESPONSE_BYTES) {
    throw new Error("R120 benchmark response exceeded the fixed size limit");
  }
  if (response.body === null) {
    throw new Error("R120 benchmark response has no body");
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const next = await reader.read();
    if (next.done) {
      break;
    }
    total += next.value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel("bounded R120 response exceeded");
      throw new Error("R120 benchmark response exceeded the fixed size limit");
    }
    chunks.push(next.value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

async function fetchResult(endpoint, ceremony, profile) {
  const started = performance.now();
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      accept: "application/json",
      "x-ed25519-yao-r120-ceremony": ceremony.id,
      "x-ed25519-yao-r120-profile": profile,
    },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const clientWallMs = performance.now() - started;
  const body = await readBoundedText(response);
  let result;
  try {
    result = JSON.parse(body);
  } catch {
    throw new Error(`R120 benchmark returned non-JSON status ${response.status}`);
  }
  if (!response.ok) {
    throw new Error(`R120 benchmark failed with ${response.status}: ${body}`);
  }
  return { clientWallMs, result };
}

async function runSample(
  endpoint,
  expectedTopology,
  expectedDeploymentId,
  ceremony,
  profile,
  cohortIndex,
) {
  const fetched = await fetchResult(endpoint, ceremony, profile);
  validateR120Result(
    fetched.result,
    ceremony,
    profile,
    expectedTopology,
    expectedDeploymentId,
  );
  return Object.freeze({
    cohort_index: cohortIndex,
    client_wall_ms: fetched.clientWallMs,
    ...fetched.result,
  });
}

function orderedProfiles(index) {
  return index % 2 === 0 ? PROFILES : [...PROFILES].reverse();
}

function campaignProfiles(campaign, index) {
  return campaign === "paired-latency"
    ? orderedProfiles(index)
    : [resourceProfile(campaign)];
}

async function collectSamples(
  endpoint,
  expectedTopology,
  expectedDeploymentId,
  samplesPerCohort,
  campaign,
) {
  const samples = [];
  const failures = [];
  for (const ceremony of CEREMONIES) {
    for (let index = 0; index < samplesPerCohort; index += 1) {
      for (const profile of campaignProfiles(campaign, index)) {
        try {
          samples.push(
            await runSample(
              endpoint,
              expectedTopology,
              expectedDeploymentId,
              ceremony,
              profile,
              index,
            ),
          );
        } catch (error) {
          failures.push(
            Object.freeze({
              family: ceremony.id,
              profile,
              cohort_index: index,
              kind: failureKind(error),
            }),
          );
        }
      }
    }
  }
  return Object.freeze({ samples, failures });
}

function failureKind(error) {
  if (error?.name === "TimeoutError") {
    return "timeout";
  }
  if (error instanceof TypeError) {
    return "transport";
  }
  if (error instanceof Error) {
    return "invalid-response";
  }
  return "unexpected";
}

export function buildR120FailedCampaignReport(
  configuration,
  collection,
  startedAt,
  endedAt,
) {
  return Object.freeze({
    benchmark: "r120-threshold-prf-campaign-failure-v1",
    benchmark_only: true,
    generated_at: endedAt,
    measurement_window: Object.freeze({ start: startedAt, end: endedAt }),
    evidence_scope: configuration.evidenceScope,
    endpoint: configuration.endpoint,
    topology: configuration.expectedTopology,
    campaign: configuration.campaign,
    samples_per_cohort: configuration.samplesPerCohort,
    attempt_count: collection.samples.length + collection.failures.length,
    success_count: collection.samples.length,
    failure_count: collection.failures.length,
    retry_count: 0,
    acceptance: Object.freeze({
      feasibility_status: "rejected-by-failed-observation",
      selection_ready: false,
    }),
    failures: collection.failures,
    samples: collection.samples,
  });
}

function localEndpoint(raw) {
  const endpoint = raw ?? DEFAULT_ENDPOINT;
  let parsed;
  try {
    parsed = new URL(endpoint);
  } catch {
    throw new BoundaryError("local R120 endpoint must be an absolute URL");
  }
  if (
    !["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname) ||
    parsed.pathname !== "/benchmark/activation" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new BoundaryError("local R120 evidence accepts only a loopback benchmark endpoint");
  }
  return parsed.href;
}

function localRunConfiguration() {
  const samplesPerCohort = parseSampleCount(process.argv[2]);
  const endpoint = localEndpoint(process.argv[3]);
  const expectedTopology = parseTopology(process.argv[4]);
  const campaign = parseCampaign(process.env.YAOS_AB_R120_CAMPAIGN);
  if (campaign !== "paired-latency") {
    throw new BoundaryError("R120 resource campaigns require a deployed benchmark receipt");
  }
  return Object.freeze({
    samplesPerCohort,
    endpoint,
    expectedTopology,
    expectedDeploymentId: LOCAL_DEPLOYMENT_ID,
    campaign,
    evidenceScope: Object.freeze({
      kind: "local-diagnostic",
      deployment_id: LOCAL_DEPLOYMENT_ID,
    }),
  });
}

function deployedRunConfiguration() {
  if (process.argv.length > 2) {
    throw new BoundaryError(
      "deployed R120 evidence is configured only through the validated deployment environment",
    );
  }
  const configuration = parseDeploymentEnvironment(process.env);
  const receipt = readDeploymentReceipt(
    deploymentReceiptPath(process.env),
    configuration,
    true,
  );
  return Object.freeze({
    samplesPerCohort: configuration.sampleCount,
    endpoint: configuration.a.publicEndpoint,
    expectedTopology: configuration.expectedTopologyLabel,
    expectedDeploymentId: receipt.deployment_id,
    campaign: parseCampaign(process.env.YAOS_AB_R120_CAMPAIGN),
    evidenceScope: Object.freeze({
      kind: "deployed-selection",
      deployment_id: receipt.deployment_id,
      deployment: deploymentReceiptEvidence(receipt),
    }),
  });
}

function runConfiguration() {
  return process.env.YAOS_AB_DEPLOYMENT_RECEIPT_PATH === undefined
    ? localRunConfiguration()
    : deployedRunConfiguration();
}

async function main() {
  const configuration = runConfiguration();
  const startedAt = new Date().toISOString();
  const collection = await collectSamples(
    configuration.endpoint,
    configuration.expectedTopology,
    configuration.expectedDeploymentId,
    configuration.samplesPerCohort,
    configuration.campaign,
  );
  const endedAt = new Date().toISOString();
  if (collection.failures.length > 0) {
    const failedReport = buildR120FailedCampaignReport(
      configuration,
      collection,
      startedAt,
      endedAt,
    );
    process.stdout.write(`${JSON.stringify(failedReport, null, 2)}\n`);
    process.exitCode = 2;
    return;
  }
  const report =
    configuration.campaign === "paired-latency"
      ? buildR120Report({
          ...configuration,
          samples: collection.samples,
          startedAt,
          endedAt,
        })
      : buildR120ResourceCampaignReport({
          ...configuration,
          samples: collection.samples,
          startedAt,
          endedAt,
        });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (
    report.benchmark === "r120-threshold-prf-architecture-selection-v1" &&
    !report.acceptance.latency_gate_passed
  ) {
    process.exitCode = 2;
  }
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
