import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { isAbsolute } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { pathToFileURL } from "node:url";

import {
  BoundaryError,
  parseDeploymentEnvironment,
  requireAnalyticsToken,
} from "./deployment_boundary.mjs";
import {
  deploymentReceiptEvidence,
  deploymentReceiptPath,
  readDeploymentReceipt,
} from "./deployment_receipt.mjs";
import {
  collectRoleAnalytics,
  MEMORY_EVIDENCE_CLASSIFICATION,
  PLATFORM_COPY_ACCOUNTING,
} from "./collect_workers_analytics.mjs";

const MAX_CAMPAIGN_BYTES = 32 * 1024 * 1024;
const MINIMUM_WARM_SAMPLES = 100;
const WEBSOCKET_MESSAGE_LIMIT_BYTES = 32 * 1024 * 1024;
const WEBSOCKET_HEADROOM_THRESHOLD_BYTES = 24 * 1024 * 1024;
const CEREMONIES = Object.freeze(["activation", "export", "lane-materialization"]);

function fail(message) {
  throw new BoundaryError(message);
}

function campaignPath(environment) {
  const path = environment.YAOS_AB_R120_RESOURCE_CAMPAIGN_PATH;
  if (
    typeof path !== "string" ||
    !isAbsolute(path) ||
    !path.endsWith(".json") ||
    /[\r\n\0]/.test(path)
  ) {
    fail("YAOS_AB_R120_RESOURCE_CAMPAIGN_PATH must be an absolute JSON path");
  }
  return path;
}

function canonicalInstant(value, field) {
  if (
    typeof value !== "string" ||
    !Number.isFinite(Date.parse(value)) ||
    new Date(Date.parse(value)).toISOString() !== value
  ) {
    fail(`${field} must be a canonical UTC instant`);
  }
  return value;
}

function readCampaignFile(path) {
  let size;
  try {
    size = statSync(path).size;
  } catch {
    fail("R120 resource campaign is unavailable");
  }
  if (size <= 0 || size > MAX_CAMPAIGN_BYTES) {
    fail("R120 resource campaign has an invalid size");
  }
  let bytes;
  let report;
  try {
    bytes = readFileSync(path);
    report = JSON.parse(bytes.toString("utf8"));
  } catch {
    fail("R120 resource campaign is not valid JSON");
  }
  return Object.freeze({
    report,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  });
}

function campaignProfile(report) {
  const profile = report.campaign?.profile;
  if (
    report.campaign?.kind !== "resource-profile" ||
    !["current", "threshold-prf-v1"].includes(profile)
  ) {
    fail("R120 resource campaign has an invalid profile");
  }
  return profile;
}

function validateMeasurementWindow(report) {
  const start = canonicalInstant(
    report.measurement_window?.start,
    "measurement_window.start",
  );
  const end = canonicalInstant(
    report.measurement_window?.end,
    "measurement_window.end",
  );
  if (Date.parse(start) >= Date.parse(end)) {
    fail("R120 resource campaign measurement window is invalid");
  }
  return Object.freeze({ start, end });
}

function validateSamples(report, profile, deploymentId) {
  const samplesPerCohort = report.samples_per_cohort;
  if (
    !Number.isSafeInteger(samplesPerCohort) ||
    samplesPerCohort - 1 < MINIMUM_WARM_SAMPLES ||
    report.warm_samples_per_cohort !== samplesPerCohort - 1 ||
    !Array.isArray(report.samples) ||
    report.samples.length !== samplesPerCohort * CEREMONIES.length
  ) {
    fail("R120 resource campaign has an incomplete sample set");
  }
  const observed = new Set();
  for (const sample of report.samples) {
    if (
      sample?.deployment_id !== deploymentId ||
      sample.topology !== report.topology ||
      sample.r120_profile !== profile ||
      !CEREMONIES.includes(sample.family) ||
      !Number.isSafeInteger(sample.cohort_index) ||
      sample.cohort_index < 0 ||
      sample.cohort_index >= samplesPerCohort
    ) {
      fail("R120 resource campaign contains an invalid sample");
    }
    const key = `${sample.family}:${sample.cohort_index}`;
    if (observed.has(key)) {
      fail("R120 resource campaign contains a duplicate sample");
    }
    observed.add(key);
  }
  return samplesPerCohort * CEREMONIES.length;
}

function maximumSampleField(samples, field) {
  let maximum = 0;
  for (const sample of samples) {
    const value = sample[field];
    if (!Number.isFinite(value) || value < 0) {
      fail(`R120 resource campaign contains invalid ${field}`);
    }
    maximum = Math.max(maximum, value);
  }
  return maximum;
}

function wireHeadroom(samples) {
  const maximumOutgoingEnvelopeBytes = maximumSampleField(
    samples,
    "peak_outgoing_envelope_bytes",
  );
  const maximumIncomingFragmentBytes = maximumSampleField(
    samples,
    "max_incoming_platform_fragment_bytes",
  );
  return Object.freeze({
    websocket_message_limit_bytes: WEBSOCKET_MESSAGE_LIMIT_BYTES,
    headroom_threshold_bytes: WEBSOCKET_HEADROOM_THRESHOLD_BYTES,
    maximum_outgoing_envelope_bytes: maximumOutgoingEnvelopeBytes,
    maximum_incoming_platform_fragment_bytes: maximumIncomingFragmentBytes,
    result:
      maximumOutgoingEnvelopeBytes <= WEBSOCKET_HEADROOM_THRESHOLD_BYTES &&
      maximumIncomingFragmentBytes <= WEBSOCKET_HEADROOM_THRESHOLD_BYTES
        ? "pass"
        : "fail",
  });
}

export function validateR120ResourceCampaign(
  report,
  sha256,
  configuration,
  receipt,
) {
  const deployment = deploymentReceiptEvidence(receipt);
  if (
    report === null ||
    typeof report !== "object" ||
    Array.isArray(report) ||
    report.benchmark !== "r120-threshold-prf-resource-campaign-v1" ||
    report.benchmark_only !== true ||
    report.topology !== configuration.expectedTopologyLabel ||
    report.evidence_scope?.kind !== "deployed-selection" ||
    report.evidence_scope.deployment_id !== receipt.deployment_id ||
    !isDeepStrictEqual(report.evidence_scope.deployment, deployment) ||
    report.acceptance?.sample_count_gate_passed !== true ||
    report.acceptance?.artifact_and_wire_consistency_passed !== true
  ) {
    fail("R120 resource campaign identity does not match the deployment");
  }
  const profile = campaignProfile(report);
  const window = validateMeasurementWindow(report);
  const expectedRequestsPerRole = validateSamples(report, profile, receipt.deployment_id);
  return Object.freeze({
    sha256,
    profile,
    window,
    expectedRequestsPerRole,
    wireHeadroom: wireHeadroom(report.samples),
  });
}

export async function collectR120WorkersAnalytics(
  configuration,
  receipt,
  campaign,
  tokens,
  fetchImplementation = fetch,
) {
  const a = await collectRoleAnalytics(
    "deriver-a",
    configuration.a.accountId,
    configuration.a.scriptName,
    tokens.a,
    campaign.window,
    fetchImplementation,
  );
  const b = await collectRoleAnalytics(
    "deriver-b",
    configuration.b.accountId,
    configuration.b.scriptName,
    tokens.b,
    campaign.window,
    fetchImplementation,
  );
  return Object.freeze({
    benchmark: "r120-threshold-prf-workers-resource-v1",
    benchmark_only: true,
    generated_at: new Date().toISOString(),
    topology: configuration.expectedTopologyLabel,
    profile: campaign.profile,
    deployment: deploymentReceiptEvidence(receipt),
    campaign_sha256: campaign.sha256,
    measurement_window: campaign.window,
    expected_requests_per_role: campaign.expectedRequestsPerRole,
    cpu_limit_ms: 300,
    cpu_headroom_threshold_ms: 225,
    memory_limit_bytes: 128 * 1024 * 1024,
    memory_headroom_threshold_bytes: 96 * 1024 * 1024,
    websocket_headroom: campaign.wireHeadroom,
    http_duration_limit: "unbounded-while-client-connected",
    cold_start_incidence: "not-observable-from-workers-invocations-adaptive",
    memory_evidence_classification: MEMORY_EVIDENCE_CLASSIFICATION,
    exact_peak_proven: false,
    platform_copy_accounting: PLATFORM_COPY_ACCOUNTING,
    a,
    b,
  });
}

async function main() {
  const configuration = parseDeploymentEnvironment(process.env);
  const receipt = readDeploymentReceipt(
    deploymentReceiptPath(process.env),
    configuration,
    true,
  );
  const file = readCampaignFile(campaignPath(process.env));
  const campaign = validateR120ResourceCampaign(
    file.report,
    file.sha256,
    configuration,
    receipt,
  );
  const tokens = Object.freeze({
    a: requireAnalyticsToken(process.env, "a", false),
    b: requireAnalyticsToken(process.env, "b", configuration.topology === "one-account"),
  });
  const report = await collectR120WorkersAnalytics(
    configuration,
    receipt,
    campaign,
    tokens,
  );
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

function handleFatal(error) {
  const message =
    error instanceof BoundaryError
      ? error.message
      : "R120 Workers resource analytics collection failed";
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
  main().catch(handleFatal);
}
