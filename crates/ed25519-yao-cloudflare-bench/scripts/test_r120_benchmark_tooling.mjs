import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as signEd25519 } from 'node:crypto';
import { readFileSync } from 'node:fs';

import {
  buildR120Report,
  buildR120FailedCampaignReport,
  buildR120ResourceCampaignReport,
  validateR120Result,
} from './run_r120_architecture_benchmark.mjs';
import {
  buildR120SelectionInputChecklist,
  evaluateR120ArchitectureSelection,
} from './evaluate_r120_architecture_selection.mjs';
import {
  collectR120WorkersAnalytics,
  validateR120ResourceCampaign,
} from './collect_r120_workers_analytics.mjs';
import { deploymentReceiptEvidence } from './deployment_receipt.mjs';
import {
  r120ArchitectureSelectionSignedBytes,
  r120ReleaseAuthorityKeyDigest,
  verifyR120ArchitectureSelection,
} from './verify_r120_architecture_selection.mjs';

const TOPOLOGY = 'same-account-service-binding-websocket';
const DEPLOYMENT_ID = '0123456789abcdef0123456789abcdef';
const STARTED_AT = '2026-08-29T00:00:00.000Z';
const ENDED_AT = '2026-08-29T00:10:00.000Z';
const GRAPHQL_CORE_SUCCESS = fixture('graphql-core-success.json');
const GRAPHQL_MEMORY_BELOW = fixture('graphql-memory-below-threshold.json');
const GRAPHQL_MEMORY_UNAVAILABLE = fixture('graphql-memory-unavailable.json');
const CEREMONIES = Object.freeze([
  Object.freeze({
    id: 'activation',
    benchmark: 'phase9b-cloudflare-activation-128kib',
    circuitDigest: '65b001c2f94de27ee8cb9f0c0773fbe54258ceab43d183174bee710ee8aa546d',
    scheduleDigest: 'fb04a139dec15e9d52e496dc4fc011cf885c8f3f6f2d18bf3860e46071f0e69a',
  }),
  Object.freeze({
    id: 'export',
    benchmark: 'r120-cloudflare-export-128kib',
    circuitDigest: '31b03d13e41a728342aedce7af40f5405dc598d28e784de44d8044db9c601a0c',
    scheduleDigest: '66ddc20f8407e369b74f2a210287d2131e78c7525f47fc829c57f6418b0d97d0',
  }),
  Object.freeze({
    id: 'lane-materialization',
    benchmark: 'r120-cloudflare-lane-materialization-128kib',
    circuitDigest: 'b82d95991e0d3f91f2d31009cb1558f73abd1d0a667fec99e02ddb751f652d06',
    scheduleDigest: '3bbae3843bab644b3b7e7ed6dd379b6b40b7c32133c5094e4b1fc4e966fd57d4',
  }),
]);

function fixture(name) {
  return JSON.parse(readFileSync(new URL(`./fixtures/${name}`, import.meta.url), 'utf8'));
}

function jsonResponse(body) {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function r120CoreSuccess() {
  const payload = JSON.parse(JSON.stringify(GRAPHQL_CORE_SUCCESS));
  const account = payload.data.viewer.accounts[0];
  account.aggregate[0].sum.requests = 303;
  account.byColo[0].sum.requests = 303;
  return payload;
}

async function fakeR120GraphqlFetch(_url, options) {
  const query = JSON.parse(options.body).query;
  return query.includes('YaosAbWorkersMemory')
    ? jsonResponse(GRAPHQL_MEMORY_BELOW)
    : jsonResponse(r120CoreSuccess());
}

async function fakeR120MemoryUnavailableFetch(_url, options) {
  const query = JSON.parse(options.body).query;
  return query.includes('YaosAbWorkersMemory')
    ? jsonResponse(GRAPHQL_MEMORY_UNAVAILABLE)
    : jsonResponse(r120CoreSuccess());
}

function fixtureResult(ceremony, profile, elapsedMs) {
  const preface = profile === 'current' ? 0 : 1;
  const bundleBytes = profile === 'current' ? 0 : 342;
  return {
    ok: true,
    benchmark_only: true,
    production_eligible: false,
    role: 'deriver-a',
    topology: TOPOLOGY,
    deployment_id: DEPLOYMENT_ID,
    family: ceremony.id,
    benchmark: ceremony.benchmark,
    profile: '128KiB',
    r120_profile: profile,
    yao_circuit_digest: ceremony.circuitDigest,
    yao_schedule_digest: ceremony.scheduleDigest,
    elapsed_ms: elapsedMs,
    r120_preface_wall_ms: preface,
    r120_preface_peer_exchange_ms: preface,
    r120_preface_a_to_b_bytes: bundleBytes,
    r120_preface_b_to_a_bytes: bundleBytes,
    r120_preface_total_bytes: bundleBytes * 2,
    r120_proof_bundle_flights: preface,
    r120_added_connection_count: 0,
    r120_added_http_request_count: 0,
    r120_added_websocket_count: 0,
    r120_added_client_round_trip_count: 0,
    r120_standalone_readiness_message_flights: 0,
    table_payload_bytes: 100,
    body_bytes: 110,
    frame_count: 1,
    table_framing_payload_bytes: 10,
    table_protocol_bytes: 120,
    ot_payload_bytes: 20,
    other_control_payload_bytes: 30,
    envelope_header_bytes: 40,
    table_transport_bytes: 140,
    control_transport_bytes: 90,
    deriver_a_to_b_transport_bytes: 150,
    deriver_b_to_a_transport_bytes: 80,
    total_ab_transport_bytes: 230,
    ot_message_count: 4,
    ot_sequential_round_count: 4,
    transport_message_count: 8,
    peak_outgoing_envelope_bytes: 140,
    max_incoming_platform_fragment_bytes: 80,
    client_package_bytes: 32,
    signing_worker_package_bytes: 32,
    total_outgoing_envelope_bytes: 150,
    total_incoming_body_bytes: 80,
  };
}

function fixtureSamples(samplesPerCohort) {
  const samples = [];
  for (const ceremony of CEREMONIES) {
    for (const profile of ['current', 'threshold-prf-v1']) {
      for (let index = 0; index < samplesPerCohort; index += 1) {
        const elapsedMs = 100 + index + (profile === 'current' ? 0 : 5);
        samples.push({
          cohort_index: index,
          client_wall_ms: elapsedMs + 1,
          ...fixtureResult(ceremony, profile, elapsedMs),
        });
      }
    }
  }
  return samples;
}

function fixtureResourceSamples(samplesPerCohort, profile) {
  return fixtureSamples(samplesPerCohort).filter(function selectedProfile(sample) {
    return sample.r120_profile === profile;
  });
}

function deployedEvidenceScope() {
  return Object.freeze({
    kind: 'deployed-selection',
    deployment_id: DEPLOYMENT_ID,
    deployment: Object.freeze({
      deployment_id: DEPLOYMENT_ID,
      topology: TOPOLOGY,
    }),
  });
}

function completeReceipt() {
  function role(scriptName, suffix) {
    return {
      script_name: scriptName,
      deployment: {
        wrangler_version: '4.111.0',
        worker_tag: `worker-tag-${suffix}`,
        version_id: `version-id-${suffix}`,
        deployed_at: STARTED_AT,
      },
      artifact: { sha256: suffix.repeat(64) },
    };
  }
  return {
    status: 'deployed',
    schema: 'ed25519_yao_phase9b_deployment_receipt_v4',
    deployment_id: DEPLOYMENT_ID,
    topology: TOPOLOGY,
    recorded_at: STARTED_AT,
    local_readiness_bundle_sha256: 'ab'.repeat(32),
    topology_binding: { kind: 'same-account-service-binding' },
    constant_time_codegen: { result: 'pass' },
    roles: {
      a: role('ed25519-yao-ab-benchmark-a', 'a'),
      b: role('ed25519-yao-ab-benchmark-b', 'b'),
    },
  };
}

function deployedLatencyReport(topology) {
  const deploymentId = topology === TOPOLOGY ? DEPLOYMENT_ID : 'abcdef0123456789abcdef0123456789';
  const deployment = Object.freeze({ deployment_id: deploymentId, topology });
  const samples = fixtureSamples(101).map(function bindTopology(sample) {
    return { ...sample, topology, deployment_id: deploymentId };
  });
  return buildR120Report({
    endpoint: `https://${topology}.example.com/benchmark/activation`,
    expectedTopology: topology,
    samples,
    samplesPerCohort: 101,
    evidenceScope: Object.freeze({
      kind: 'deployed-selection',
      deployment_id: deploymentId,
      deployment,
    }),
    startedAt: STARTED_AT,
    endedAt: ENDED_AT,
  });
}

function analyticsRole(cpuP95Ms, memoryP999Bytes) {
  return {
    core: {
      available: true,
      sum: { requests: 303, errors: 0 },
      quantiles: {
        microseconds: { cpuTimeP95: cpuP95Ms * 1_000 },
        milliseconds: { cpuTimeP95: cpuP95Ms },
      },
    },
    memory: {
      available: true,
      quantiles_bytes: { memoryUsageBytesP999: memoryP999Bytes },
    },
    sampled_memory_gate: {
      threshold_bytes: 96 * 1024 * 1024,
      memory_usage_bytes_p999: memoryP999Bytes,
      exceeded_memory_status_count: 0,
      exceeded_memory_status_observed: false,
      result: 'pass',
    },
  };
}

function resourceAnalytics(latency, profile, start, end) {
  const candidate = profile === 'threshold-prf-v1';
  return {
    benchmark: 'r120-threshold-prf-workers-resource-v1',
    benchmark_only: true,
    topology: latency.topology,
    profile,
    deployment: latency.evidence_scope.deployment,
    campaign_sha256: (profile === 'current' ? '44' : '55').repeat(32),
    measurement_window: { start, end },
    expected_requests_per_role: 303,
    cpu_limit_ms: 300,
    cpu_headroom_threshold_ms: 225,
    memory_limit_bytes: 128 * 1024 * 1024,
    memory_headroom_threshold_bytes: 96 * 1024 * 1024,
    websocket_headroom: {
      websocket_message_limit_bytes: 32 * 1024 * 1024,
      headroom_threshold_bytes: 24 * 1024 * 1024,
      maximum_outgoing_envelope_bytes: 131_180,
      maximum_incoming_platform_fragment_bytes: 131_180,
      result: 'pass',
    },
    http_duration_limit: 'unbounded-while-client-connected',
    cold_start_incidence: 'not-observable-from-workers-invocations-adaptive',
    memory_evidence_classification: 'cloudflare-reservoir-sampled-shared-isolate-operational-proxy',
    exact_peak_proven: false,
    platform_copy_accounting: 'unavailable',
    a: analyticsRole(candidate ? 84 : 80, candidate ? 84_000_000 : 80_000_000),
    b: analyticsRole(candidate ? 64 : 60, candidate ? 84_000_000 : 80_000_000),
  };
}

function selectionTopologyInput(topology) {
  const latency = deployedLatencyReport(topology);
  return {
    latency: { report: latency, sha256: '11'.repeat(32) },
    currentResources: {
      report: resourceAnalytics(
        latency,
        'current',
        '2026-08-29T00:20:00.000Z',
        '2026-08-29T00:30:00.000Z',
      ),
      sha256: '22'.repeat(32),
    },
    candidateResources: {
      report: resourceAnalytics(
        latency,
        'threshold-prf-v1',
        '2026-08-29T00:40:00.000Z',
        '2026-08-29T00:50:00.000Z',
      ),
      sha256: '33'.repeat(32),
    },
  };
}

function selectionInput() {
  return {
    'same-account-service-binding-websocket': selectionTopologyInput(TOPOLOGY),
    'cross-account-websocket': selectionTopologyInput('cross-account-websocket'),
  };
}

function selectionInputWithPaths() {
  const input = selectionInput();
  let index = 0;
  for (const topology of Object.values(input)) {
    for (const artifact of [
      topology.latency,
      topology.currentResources,
      topology.candidateResources,
    ]) {
      index += 1;
      artifact.path = `/absolute/r120-selection-artifact-${index}.json`;
    }
  }
  return input;
}

function jsonArtifact(value) {
  return Object.freeze({
    value,
    sha256: createHash('sha256').update(JSON.stringify(value)).digest('hex'),
  });
}

function reviewerFixture() {
  const keys = generateKeyPairSync('ed25519');
  const publicJwk = keys.publicKey.export({ format: 'jwk' });
  const reviewer = {
    role: 'architecture_selection_reviewer',
    authority_id: 'r120-release-reviewer',
    key_epoch: 7,
    verifying_key_hex: Buffer.from(publicJwk.x, 'base64url').toString('hex'),
    authority_key_digest: '',
  };
  reviewer.authority_key_digest = r120ReleaseAuthorityKeyDigest(reviewer);
  return Object.freeze({ keys, reviewer: Object.freeze(reviewer) });
}

function releasePolicy(reviewer, minimumSequence = 9) {
  return {
    schema: 'r120-threshold-prf-release-authority-policy-v1',
    policy_scope: 'r120_threshold_prf_architecture_selection_v1',
    minimum_approval_sequence: minimumSequence,
    reviewer,
  };
}

function signedSelection(candidate, reviewer, privateKey, sequence = 9) {
  const record = {
    schema: 'r120-threshold-prf-signed-architecture-selection-v1',
    approval_payload_sha256: candidate.approval_payload_sha256,
    approval_sequence: sequence,
    reviewer_authority_id: reviewer.authority_id,
    reviewer_key_epoch: reviewer.key_epoch,
    reviewer_authority_key_digest: reviewer.authority_key_digest,
    signature_algorithm: 'ed25519',
    signature_hex: '',
  };
  record.signature_hex = signEd25519(
    null,
    r120ArchitectureSelectionSignedBytes(record),
    privateKey,
  ).toString('hex');
  return record;
}

function verificationInput(candidate, policy, signedSelectionValue) {
  return {
    candidate: jsonArtifact(candidate),
    policy: jsonArtifact(policy),
    signedSelection: jsonArtifact(signedSelectionValue),
  };
}

function r120CollectorConfiguration() {
  return Object.freeze({
    expectedTopologyLabel: TOPOLOGY,
    a: Object.freeze({
      accountId: 'a'.repeat(32),
      scriptName: 'ed25519-yao-ab-benchmark-a',
    }),
    b: Object.freeze({
      accountId: 'a'.repeat(32),
      scriptName: 'ed25519-yao-ab-benchmark-b',
    }),
  });
}

function fixtureReport(samplesPerCohort, samples = fixtureSamples(samplesPerCohort)) {
  return buildR120Report({
    endpoint: 'http://127.0.0.1:8787/benchmark/activation',
    expectedTopology: TOPOLOGY,
    samples,
    samplesPerCohort,
    evidenceScope: Object.freeze({
      kind: 'local-diagnostic',
      deployment_id: DEPLOYMENT_ID,
    }),
    startedAt: STARTED_AT,
    endedAt: ENDED_AT,
  });
}

async function run() {
  const current = fixtureResult(CEREMONIES[0], 'current', 100);
  const candidate = fixtureResult(CEREMONIES[0], 'threshold-prf-v1', 105);
  validateR120Result(current, CEREMONIES[0], 'current', TOPOLOGY, DEPLOYMENT_ID);
  validateR120Result(candidate, CEREMONIES[0], 'threshold-prf-v1', TOPOLOGY, DEPLOYMENT_ID);

  const invalidPreface = { ...current, r120_proof_bundle_flights: 1 };
  assert.throws(function rejectBaselinePreface() {
    validateR120Result(invalidPreface, CEREMONIES[0], 'current', TOPOLOGY, DEPLOYMENT_ID);
  });

  const invalidArtifact = { ...candidate, yao_circuit_digest: '00'.repeat(32) };
  assert.throws(function rejectArtifactDrift() {
    validateR120Result(invalidArtifact, CEREMONIES[0], 'threshold-prf-v1', TOPOLOGY, DEPLOYMENT_ID);
  });

  const report = fixtureReport(3);
  assert.equal(report.ceremonies.activation.warm_p95_delta_ms.client_wall, 5);
  assert.equal(report.ceremonies.activation.warm_p95_delta_ms.worker_elapsed, 5);
  assert.equal(report.acceptance.feasibility_status, 'provisionally-feasible');
  assert.equal(report.acceptance.latency_gate_passed, true);
  assert.equal(report.acceptance.sample_count_gate_passed, false);
  assert.equal(report.acceptance.selection_ready, false);

  const fullCohortReport = fixtureReport(101);
  assert.equal(
    fullCohortReport.acceptance.feasibility_status,
    'latency-wire-and-sample-gates-passed',
  );
  assert.equal(fullCohortReport.acceptance.sample_count_gate_passed, true);
  assert.equal(fullCohortReport.acceptance.selection_ready, false);

  const slowCandidateSamples = fixtureSamples(3).map(function slowCandidate(sample) {
    if (sample.r120_profile === 'current') {
      return sample;
    }
    return {
      ...sample,
      client_wall_ms: sample.client_wall_ms + 16,
      elapsed_ms: sample.elapsed_ms + 16,
    };
  });
  const rejectedReport = fixtureReport(3, slowCandidateSamples);
  assert.equal(rejectedReport.acceptance.feasibility_status, 'rejected-by-latency');
  assert.equal(rejectedReport.acceptance.latency_gate_passed, false);

  const drifted = fixtureSamples(3);
  drifted[9].table_payload_bytes += 1;
  assert.throws(function rejectYaoWireDrift() {
    fixtureReport(3, drifted);
  });

  const staleDeployment = fixtureResult(CEREMONIES[0], 'current', 100);
  staleDeployment.deployment_id = 'fedcba9876543210fedcba9876543210';
  assert.throws(function rejectStaleDeployment() {
    validateR120Result(staleDeployment, CEREMONIES[0], 'current', TOPOLOGY, DEPLOYMENT_ID);
  });

  assert.throws(function rejectUnboundDeployedEvidence() {
    buildR120Report({
      endpoint: 'https://r120-benchmark.example.com/benchmark/activation',
      expectedTopology: TOPOLOGY,
      samples: fixtureSamples(3),
      samplesPerCohort: 3,
      evidenceScope: Object.freeze({
        kind: 'deployed-selection',
        deployment_id: DEPLOYMENT_ID,
        deployment: Object.freeze({
          deployment_id: 'fedcba9876543210fedcba9876543210',
          topology: TOPOLOGY,
        }),
      }),
      startedAt: STARTED_AT,
      endedAt: ENDED_AT,
    });
  });

  const resourceReport = buildR120ResourceCampaignReport({
    endpoint: 'https://r120-benchmark.example.com/benchmark/activation',
    expectedTopology: TOPOLOGY,
    samples: fixtureResourceSamples(101, 'threshold-prf-v1'),
    samplesPerCohort: 101,
    evidenceScope: deployedEvidenceScope(),
    campaign: 'resource-candidate',
    startedAt: STARTED_AT,
    endedAt: ENDED_AT,
  });
  assert.equal(resourceReport.campaign.profile, 'threshold-prf-v1');
  assert.equal(resourceReport.warm_samples_per_cohort, 100);
  assert.equal(resourceReport.acceptance.sample_count_gate_passed, true);
  assert.equal(resourceReport.ceremonies.activation.cohort.warm.sample_count, 100);

  assert.throws(function rejectResourceCampaignWithoutReceipt() {
    buildR120ResourceCampaignReport({
      endpoint: 'http://127.0.0.1:8787/benchmark/activation',
      expectedTopology: TOPOLOGY,
      samples: fixtureResourceSamples(3, 'current'),
      samplesPerCohort: 3,
      evidenceScope: Object.freeze({
        kind: 'local-diagnostic',
        deployment_id: DEPLOYMENT_ID,
      }),
      campaign: 'resource-current',
      startedAt: STARTED_AT,
      endedAt: ENDED_AT,
    });
  });

  const receipt = completeReceipt();
  const boundResourceCampaign = buildR120ResourceCampaignReport({
    endpoint: 'https://r120-benchmark.example.com/benchmark/activation',
    expectedTopology: TOPOLOGY,
    samples: fixtureResourceSamples(101, 'current'),
    samplesPerCohort: 101,
    evidenceScope: Object.freeze({
      kind: 'deployed-selection',
      deployment_id: DEPLOYMENT_ID,
      deployment: deploymentReceiptEvidence(receipt),
    }),
    campaign: 'resource-current',
    startedAt: STARTED_AT,
    endedAt: ENDED_AT,
  });
  const validatedCampaign = validateR120ResourceCampaign(
    boundResourceCampaign,
    '44'.repeat(32),
    { expectedTopologyLabel: TOPOLOGY },
    receipt,
  );
  assert.equal(validatedCampaign.profile, 'current');
  assert.equal(validatedCampaign.expectedRequestsPerRole, 303);
  assert.equal(validatedCampaign.wireHeadroom.result, 'pass');

  const resourceAnalyticsReport = await collectR120WorkersAnalytics(
    r120CollectorConfiguration(),
    receipt,
    validatedCampaign,
    { a: 'fixture-token-a', b: 'fixture-token-b' },
    fakeR120GraphqlFetch,
  );
  assert.equal(resourceAnalyticsReport.profile, 'current');
  assert.equal(resourceAnalyticsReport.a.core.sum.requests, 303);
  assert.equal(resourceAnalyticsReport.b.memory.available, true);
  assert.equal(resourceAnalyticsReport.a.sampled_memory_gate.result, 'pass');

  const unavailableMemoryReport = await collectR120WorkersAnalytics(
    r120CollectorConfiguration(),
    receipt,
    validatedCampaign,
    { a: 'fixture-token-a', b: 'fixture-token-b' },
    fakeR120MemoryUnavailableFetch,
  );
  assert.equal(unavailableMemoryReport.a.memory.available, false);
  assert.equal(unavailableMemoryReport.a.sampled_memory_gate.result, 'unavailable');

  const wrongCampaignDeployment = JSON.parse(JSON.stringify(boundResourceCampaign));
  wrongCampaignDeployment.evidence_scope.deployment_id = 'ff'.repeat(16);
  assert.throws(function rejectWrongResourceCampaignDeployment() {
    validateR120ResourceCampaign(
      wrongCampaignDeployment,
      '44'.repeat(32),
      { expectedTopologyLabel: TOPOLOGY },
      receipt,
    );
  });

  const wrongCampaignProfile = JSON.parse(JSON.stringify(boundResourceCampaign));
  wrongCampaignProfile.campaign.profile = 'threshold-prf-v1';
  assert.throws(function rejectResourceCampaignProfileMismatch() {
    validateR120ResourceCampaign(
      wrongCampaignProfile,
      '44'.repeat(32),
      { expectedTopologyLabel: TOPOLOGY },
      receipt,
    );
  });

  const failedCampaign = buildR120FailedCampaignReport(
    {
      endpoint: 'http://127.0.0.1:8787/benchmark/activation',
      expectedTopology: TOPOLOGY,
      campaign: 'paired-latency',
      samplesPerCohort: 2,
      evidenceScope: { kind: 'local-diagnostic', deployment_id: DEPLOYMENT_ID },
    },
    {
      samples: [fixtureResult(CEREMONIES[0], 'current', 100)],
      failures: [
        {
          family: 'activation',
          profile: 'threshold-prf-v1',
          cohort_index: 0,
          kind: 'timeout',
        },
      ],
    },
    STARTED_AT,
    ENDED_AT,
  );
  assert.equal(failedCampaign.failure_count, 1);
  assert.equal(failedCampaign.retry_count, 0);
  assert.equal(failedCampaign.acceptance.selection_ready, false);

  const selection = evaluateR120ArchitectureSelection(selectionInput());
  assert.equal(selection.decision, 'ready-for-release-signature');
  assert.equal(selection.reasons.length, 0);
  assert.match(selection.approval_payload_sha256, /^[0-9a-f]{64}$/);
  assert.equal(selection.signature.selection_ready, false);

  const slowCpu = selectionInput();
  slowCpu[TOPOLOGY].candidateResources.report.a.core.quantiles.microseconds.cpuTimeP95 = 86_000;
  slowCpu[TOPOLOGY].candidateResources.report.a.core.quantiles.milliseconds.cpuTimeP95 = 86;
  const rejectedSelection = evaluateR120ArchitectureSelection(slowCpu);
  assert.deepEqual(rejectedSelection.reasons, [`${TOPOLOGY}:a:cpu-p95-delta-exceeded`]);

  const overlappingWindows = selectionInput();
  overlappingWindows[TOPOLOGY].candidateResources.report.measurement_window.start =
    '2026-08-29T00:25:00.000Z';
  const overlapResult = evaluateR120ArchitectureSelection(overlappingWindows);
  assert.deepEqual(overlapResult.reasons, [`${TOPOLOGY}:resource-windows-overlap`]);

  const wrongResourceDeployment = selectionInput();
  wrongResourceDeployment[TOPOLOGY].currentResources.report.deployment = {
    deployment_id: 'ff'.repeat(16),
    topology: TOPOLOGY,
  };
  assert.throws(function rejectWrongResourceDeployment() {
    evaluateR120ArchitectureSelection(wrongResourceDeployment);
  });

  const wrongResourceProfile = selectionInput();
  wrongResourceProfile[TOPOLOGY].currentResources.report.profile = 'threshold-prf-v1';
  assert.throws(function rejectWrongResourceProfile() {
    evaluateR120ArchitectureSelection(wrongResourceProfile);
  });

  const contaminatedRequests = selectionInput();
  contaminatedRequests[TOPOLOGY].candidateResources.report.a.core.sum.requests = 304;
  const contaminatedResult = evaluateR120ArchitectureSelection(contaminatedRequests);
  assert.deepEqual(contaminatedResult.reasons, [
    `${TOPOLOGY}:a:exclusive-window-request-accounting-failed`,
  ]);

  const unavailableMemory = selectionInput();
  unavailableMemory[TOPOLOGY].candidateResources.report.a.memory = {
    available: false,
    failure: { kind: 'graphql-schema-or-plan' },
  };
  unavailableMemory[TOPOLOGY].candidateResources.report.a.sampled_memory_gate = {
    threshold_bytes: 96 * 1024 * 1024,
    memory_usage_bytes_p999: null,
    exceeded_memory_status_count: 0,
    exceeded_memory_status_observed: false,
    result: 'unavailable',
  };
  assert.throws(function rejectUnavailableMemoryEvidence() {
    evaluateR120ArchitectureSelection(unavailableMemory);
  });

  const tamperedLatency = selectionInput();
  tamperedLatency[TOPOLOGY].latency.report = JSON.parse(
    JSON.stringify(tamperedLatency[TOPOLOGY].latency.report),
  );
  tamperedLatency[TOPOLOGY].latency.report.samples[0].elapsed_ms += 1;
  assert.throws(function rejectTamperedLatencySamples() {
    evaluateR120ArchitectureSelection(tamperedLatency);
  });

  const checklistInput = selectionInputWithPaths();
  const checklist = buildR120SelectionInputChecklist(checklistInput);
  assert.equal(checklist.status, 'ready-for-evaluation');
  assert.equal(checklist.artifact_count, 6);
  assert.equal(checklist.selection_ready, false);

  const duplicateChecklistPath = selectionInputWithPaths();
  duplicateChecklistPath[TOPOLOGY].currentResources.path =
    duplicateChecklistPath[TOPOLOGY].latency.path;
  assert.throws(function rejectDuplicateChecklistArtifact() {
    buildR120SelectionInputChecklist(duplicateChecklistPath);
  });

  const checklistProfileMismatch = selectionInputWithPaths();
  checklistProfileMismatch[TOPOLOGY].candidateResources.report.profile = 'current';
  assert.throws(function rejectChecklistProfileMismatch() {
    buildR120SelectionInputChecklist(checklistProfileMismatch);
  });

  const signedCandidate = evaluateR120ArchitectureSelection(selectionInput());
  const authority = reviewerFixture();
  const policy = releasePolicy(authority.reviewer);
  const approval = signedSelection(signedCandidate, authority.reviewer, authority.keys.privateKey);
  const verified = verifyR120ArchitectureSelection(
    verificationInput(signedCandidate, policy, approval),
  );
  assert.equal(verified.selection_ready, true);
  assert.equal(verified.approval_payload_sha256, signedCandidate.approval_payload_sha256);
  assert.equal(verified.approval_sequence, 9);

  const staleApproval = signedSelection(
    signedCandidate,
    authority.reviewer,
    authority.keys.privateKey,
    8,
  );
  assert.throws(function rejectStaleApprovalSequence() {
    verifyR120ArchitectureSelection(verificationInput(signedCandidate, policy, staleApproval));
  });

  const wrongAuthority = reviewerFixture();
  const wrongKeyApproval = signedSelection(
    signedCandidate,
    authority.reviewer,
    wrongAuthority.keys.privateKey,
  );
  assert.throws(function rejectWrongSigningKey() {
    verifyR120ArchitectureSelection(verificationInput(signedCandidate, policy, wrongKeyApproval));
  });

  const mutatedCandidate = JSON.parse(JSON.stringify(signedCandidate));
  mutatedCandidate.approval_payload.evidence[TOPOLOGY].roles.a.current_cpu_p95_microseconds += 1;
  assert.throws(function rejectMutatedApprovalEvidence() {
    verifyR120ArchitectureSelection(verificationInput(mutatedCandidate, policy, approval));
  });

  const invalidSignature = { ...approval };
  const invalidSignatureBytes = Buffer.from(approval.signature_hex, 'hex');
  invalidSignatureBytes[63] ^= 1;
  invalidSignature.signature_hex = invalidSignatureBytes.toString('hex');
  assert.throws(function rejectInvalidSignature() {
    verifyR120ArchitectureSelection(verificationInput(signedCandidate, policy, invalidSignature));
  });
}

await run();
process.stdout.write('R120 benchmark tooling fixtures passed\n');
