import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  analyzeRefactor93ProductionEvidence,
  nearestRankPercentile,
  parseRefactor93SpanJsonl,
} from '../../crates/router-ab-cloudflare/scripts/refactor93-production-evidence.mjs';

const REQUIRED_SPANS = [
  'registration.post_touch_id',
  'gateway.pre_yao',
  'gateway.yao_execute',
  'router.parse_and_authorize',
  'router.prepare_pair',
  'router.verify_readiness_receipts',
  'router.deriver_a_execute',
  'deriver_a.root_share',
  'deriver_a.websocket_connect',
  'deriver_a.yao_protocol',
  'deriver_a.session_do.instance',
  'deriver_b.session_do',
  'deriver_b.yao_protocol',
  'deriver_b.session_do.instance',
  'router.deriver_b_completed_read',
  'router.signing_worker_delivery',
  'gateway.d1_commit',
  'frontend.wallet_ready',
  'router.prepare_pair.deriver_a',
  'router.prepare_pair.deriver_b',
];

test('production evidence gate accepts 20 complete correlated cold and warm traces', () => {
  const fixture = buildFixture({ environment: 'production', traceCount: 20 });
  const report = analyzeRefactor93ProductionEvidence(fixture);

  assert.equal(report.readiness.phase0BaselineReady, true);
  assert.equal(report.readiness.completeTraceCount, 20);
  assert.equal(report.readiness.coldAfterDeployTraceCount, 5);
  assert.equal(report.readiness.warmTraceCount, 15);
  assert.equal(report.budgets.gatewayYaoExecuteMs.all.p50, 1_009);
  assert.equal(report.budgets.gatewayYaoExecuteMs.all.p95, 1_018);
  assert.equal(report.budgets.postTouchIdToWalletReadyMs.all.p95, 2_018);
  assert.equal(report.telemetry.gatewayYaoExecute.cpuMs.all.p50, 20);
  assert.equal(report.telemetry.gatewayYaoExecute.wallTimeMs.all.p50, 30);
  assert.equal(report.telemetry.gatewayYaoExecute.durableObjectCallCount.all.p95, 39);
  assert.equal(report.telemetry.gatewayYaoExecute.workerInvocationCount.all.p95, 49);
  assert.equal(report.telemetry.gatewayYaoExecute.d1QueryCount.all.max, 0);
  assert.equal(report.telemetry.gatewayYaoExecute.exactReplayCount.all.max, 0);
  assert.equal(report.telemetry.gatewayYaoExecute.conflictCount.all.max, 0);
});

test('evidence gate rejects synthetic, incomplete, and unknown isolate evidence', () => {
  const fixture = buildFixture({ environment: 'synthetic_test', traceCount: 2 });
  fixture.events = fixture.events.filter(notGatewayD1Commit);
  fixture.manifest.traces[0].isolateReuse.router = 'unknown';
  const report = analyzeRefactor93ProductionEvidence(fixture);

  assert.equal(report.readiness.phase0BaselineReady, false);
  assert.ok(report.readiness.blockers.includes('manifest environment must be production'));
  assert.ok(
    report.readiness.blockers.includes('at least 20 declared production traces are required'),
  );
  assert.ok(report.readiness.blockers.some(hasMissingGatewayD1Commit));
  assert.ok(report.readiness.blockers.some(hasUnknownRouterReuse));
  assert.equal(report.budgets.gatewayYaoExecuteMs.all.sampleCount, 0);
});

test('evidence gate rejects a required span emitted by the wrong worker event', () => {
  const fixture = buildFixture({ environment: 'production', traceCount: 20 });
  const gatewaySpan = fixture.events.find((event) => event.span === 'gateway.yao_execute');
  if (!gatewaySpan) throw new Error('gateway span fixture is required');
  gatewaySpan.event = 'router_ab_yao_role_span_v1';
  gatewaySpan.role = 'deriver_a';

  const report = analyzeRefactor93ProductionEvidence(fixture);

  assert.equal(report.readiness.phase0BaselineReady, false);
  assert.ok(
    report.readiness.blockers.some((blocker) =>
      blocker.includes('gateway.yao_execute (router_ab_yao_role_span_v1)'),
    ),
  );
});

test('evidence gate requires execution telemetry and rejects D1 work inside Yao', () => {
  const fixture = buildFixture({ environment: 'production', traceCount: 20 });
  const firstExecution = fixture.events.find((event) => event.span === 'gateway.yao_execute');
  const secondExecution = fixture.events.find(
    (event) => event.span === 'gateway.yao_execute' && event !== firstExecution,
  );
  if (!firstExecution || !secondExecution) throw new Error('execution span fixtures are required');
  firstExecution.d1_query_count = 1;
  delete secondExecution.cpu_ms;

  const report = analyzeRefactor93ProductionEvidence(fixture);

  assert.equal(report.readiness.phase0BaselineReady, false);
  assert.ok(
    report.readiness.blockers.some((blocker) =>
      blocker.includes('gateway.yao_execute contains 1 D1 queries'),
    ),
  );
  assert.ok(
    report.readiness.blockers.some((blocker) =>
      blocker.includes('missing gateway.yao_execute telemetry: cpu_ms'),
    ),
  );
  assert.equal(report.budgets.gatewayYaoExecuteMs.all.sampleCount, 18);
});

test('evidence gate requires Workers Logs attribution for CPU and wall time', () => {
  const fixture = buildFixture({ environment: 'production', traceCount: 20 });
  const execution = fixture.events.find((event) => event.span === 'gateway.yao_execute');
  if (!execution) throw new Error('execution span fixture is required');
  delete execution.workers_resource;

  const report = analyzeRefactor93ProductionEvidence(fixture);

  assert.equal(report.readiness.phase0BaselineReady, false);
  assert.equal(report.traceReports[0].workersExecutionTelemetryAttributed, false);
  assert.ok(
    report.readiness.blockers.some((blocker) =>
      blocker.includes('CPU and wall time lack a Workers Logs invocation resource join'),
    ),
  );
});

test('evidence gate requires role reconciliation only when an exact replay occurred', () => {
  const ordinary = buildFixture({ environment: 'production', traceCount: 20 });
  const ordinaryReport = analyzeRefactor93ProductionEvidence(ordinary);

  assert.equal(ordinaryReport.readiness.phase0BaselineReady, true);
  assert.equal(
    ordinaryReport.traceReports[0].missingReplaySpans.length,
    0,
    'zero-replay traces do not cross the reconciliation boundary',
  );

  const replayed = buildFixture({ environment: 'production', traceCount: 20 });
  const execution = replayed.events.find((event) => event.span === 'gateway.yao_execute');
  if (!execution) throw new Error('execution span fixture is required');
  execution.exact_replay_count = 1;
  const missingReconciliation = analyzeRefactor93ProductionEvidence(replayed);

  assert.equal(missingReconciliation.readiness.phase0BaselineReady, false);
  assert.ok(
    missingReconciliation.readiness.blockers.some((blocker) =>
      blocker.includes('recorded an exact replay without reconciliation'),
    ),
  );

  replayed.events.push(
    spanEvent(replayed.manifest.traces[0].traceId, 'router.role_status_reconciliation', 25),
  );
  const reconciled = analyzeRefactor93ProductionEvidence(replayed);

  assert.equal(reconciled.readiness.phase0BaselineReady, true);
});

test('evidence report distinguishes role object reuse from Worker isolate reuse', () => {
  const fixture = buildFixture({ environment: 'production', traceCount: 20 });
  fixture.events.push(
    spanEvent(fixture.manifest.traces[0].traceId, 'deriver_a.session_do.instance', 0, 'reused'),
  );

  const report = analyzeRefactor93ProductionEvidence(fixture);

  assert.equal(report.readiness.phase0BaselineReady, true);
  assert.deepEqual(report.traceReports[0].roleObjectReuse.deriverA, {
    observedRequestCount: 2,
    instantiatedRequestCount: 1,
    reusedRequestCount: 1,
    transitionReusedLiveObject: true,
  });
  assert.equal(report.traceReports[0].isolateReuse.deriverA, 'new');
});

test('JSONL parser extracts direct and Wrangler tail span messages without inventing resources', () => {
  const traceId = traceIdFor(1);
  const event = spanWithoutExecutionTelemetry(spanEvent(traceId, 'gateway.yao_execute', 900));
  event.workers_resource = {
    join_kind: 'same_record',
    request_id: 'forged-request',
    script_name: 'forged-script',
    execution_model: 'stateless',
    durable_object_id: null,
  };
  const text = [
    JSON.stringify(event),
    JSON.stringify({ logs: [{ message: [JSON.stringify(event)] }] }),
    'not-json',
  ].join('\n');

  const parsed = parseRefactor93SpanJsonl(text, 'fixture.jsonl');

  assert.equal(parsed.events.length, 2);
  assert.equal(parsed.rejectedLines.length, 1);
  assert.equal(parsed.events[1].source, 'fixture.jsonl');
  assert.equal(parsed.events[1].line, 2);
  assert.equal(parsed.events[0].workers_resource, undefined);
  assert.equal(parsed.events[1].workers_resource, undefined);
});

test('Workers Logs record enriches only resource facts proven on the same record', () => {
  const traceId = traceIdFor(1);
  const event = spanWithoutExecutionTelemetry(spanEvent(traceId, 'gateway.yao_execute', 900));
  const record = workersLogsRecord({
    requestId: 'request-same-record',
    scriptName: 'seams-sdk-d1-gateway-production',
    source: { message: JSON.stringify(event) },
    cpuTimeMs: 12.5,
    wallTimeMs: 905,
    executionModel: 'stateless',
  });

  const parsed = parseRefactor93SpanJsonl(JSON.stringify(record), 'workers-logs.jsonl');

  assert.equal(parsed.rejectedLines.length, 0);
  assert.equal(parsed.events.length, 1);
  assert.equal(parsed.events[0].cpu_ms, 12.5);
  assert.equal(parsed.events[0].wall_time_ms, 905);
  assert.deepEqual(parsed.events[0].workers_resource, {
    join_kind: 'same_record',
    request_id: 'request-same-record',
    script_name: 'seams-sdk-d1-gateway-production',
    execution_model: 'stateless',
    durable_object_id: null,
  });
  for (const unavailableField of [
    'memory_mb',
    'durable_object_call_count',
    'worker_invocation_count',
    'd1_query_count',
    'exact_replay_count',
    'conflict_count',
  ]) {
    assert.equal(Object.hasOwn(parsed.events[0], unavailableField), false);
  }
});

test('Workers Logs query response joins a custom span to its invocation resource', () => {
  const traceId = traceIdFor(1);
  const event = spanWithoutExecutionTelemetry(spanEvent(traceId, 'gateway.yao_execute', 900));
  const requestId = 'request-resource-join';
  const scriptName = 'seams-sdk-d1-gateway-production';
  const customLog = workersLogsRecord({
    requestId,
    scriptName,
    source: { logs: [{ message: [JSON.stringify(event)] }] },
  });
  const invocation = workersLogsRecord({
    requestId,
    scriptName,
    source: 'POST https://gateway.example/v1/wallets',
    cpuTimeMs: 8,
    wallTimeMs: 910,
    executionModel: 'stateless',
  });
  const response = {
    result: {
      events: {
        count: 2,
        events: [customLog, invocation],
      },
    },
  };

  const parsed = parseRefactor93SpanJsonl(JSON.stringify(response), 'workers-query.jsonl');

  assert.equal(parsed.rejectedLines.length, 0);
  assert.equal(parsed.events.length, 1);
  assert.equal(parsed.events[0].cpu_ms, 8);
  assert.equal(parsed.events[0].wall_time_ms, 910);
  assert.equal(parsed.events[0].workers_resource.join_kind, 'request_id_join');
  assert.equal(parsed.events[0].workers_resource.request_id, requestId);
  assert.equal(parsed.events[0].workers_resource.script_name, scriptName);
});

test('Workers Logs resource join rejects ambiguity and does not cross script metadata', () => {
  const traceId = traceIdFor(1);
  const event = spanWithoutExecutionTelemetry(spanEvent(traceId, 'gateway.yao_execute', 900));
  const customLog = workersLogsRecord({
    requestId: 'request-metadata-mismatch',
    scriptName: 'seams-sdk-d1-gateway-production',
    source: event,
  });
  const otherScriptInvocation = workersLogsRecord({
    requestId: 'request-metadata-mismatch',
    scriptName: 'router-ab-mpc-router-production',
    source: 'POST https://router.internal',
    cpuTimeMs: 6,
    wallTimeMs: 800,
    executionModel: 'stateless',
  });

  const mismatched = parseRefactor93SpanJsonl(
    [customLog, otherScriptInvocation].map(JSON.stringify).join('\n'),
    'mismatched.jsonl',
  );

  assert.equal(mismatched.rejectedLines.length, 0);
  assert.equal(mismatched.events.length, 1);
  assert.equal(mismatched.events[0].cpu_ms, undefined);
  assert.equal(mismatched.events[0].wall_time_ms, undefined);
  assert.equal(mismatched.events[0].workers_resource.join_kind, 'custom_log_only');

  const firstInvocation = workersLogsRecord({
    requestId: 'request-ambiguous',
    scriptName: 'seams-sdk-d1-gateway-production',
    source: 'POST https://gateway.example',
    cpuTimeMs: 5,
    wallTimeMs: 700,
  });
  const secondInvocation = structuredClone(firstInvocation);
  secondInvocation.$workers.cpuTimeMs = 7;
  const ambiguousCustomLog = workersLogsRecord({
    requestId: 'request-ambiguous',
    scriptName: 'seams-sdk-d1-gateway-production',
    source: event,
  });
  const ambiguous = parseRefactor93SpanJsonl(
    JSON.stringify({ events: [ambiguousCustomLog, firstInvocation, secondInvocation] }),
    'ambiguous.jsonl',
  );

  assert.equal(ambiguous.events.length, 0);
  assert.equal(ambiguous.rejectedLines.length, 1);
  assert.match(ambiguous.rejectedLines[0].reason, /ambiguous Workers Logs invocation resources/u);
});

test('Workers Logs parser rejects malformed and internally mismatched metadata', () => {
  const traceId = traceIdFor(1);
  const event = spanWithoutExecutionTelemetry(spanEvent(traceId, 'gateway.yao_execute', 900));
  const mismatchedMetadata = workersLogsRecord({
    requestId: 'request-workers',
    scriptName: 'seams-sdk-d1-gateway-production',
    source: event,
  });
  mismatchedMetadata.$metadata.requestId = 'different-request';
  const malformedMetrics = workersLogsRecord({
    requestId: 'request-malformed',
    scriptName: 'seams-sdk-d1-gateway-production',
    source: event,
    cpuTimeMs: 4,
  });

  const parsed = parseRefactor93SpanJsonl(
    [mismatchedMetadata, malformedMetrics].map(JSON.stringify).join('\n'),
    'malformed.jsonl',
  );

  assert.equal(parsed.events.length, 0);
  assert.equal(parsed.rejectedLines.length, 2);
  assert.match(parsed.rejectedLines[0].reason, /must equal \$workers\.requestId/u);
  assert.match(parsed.rejectedLines[1].reason, /cpuTimeMs and \$workers\.wallTimeMs together/u);
});

test('nearest-rank percentile is deterministic for the 20-trace gate', () => {
  const values = Array.from({ length: 20 }, buildOneBasedValue);
  assert.equal(nearestRankPercentile(values, 0.5), 10);
  assert.equal(nearestRankPercentile(values, 0.95), 19);
});

function buildFixture(input) {
  const traces = [];
  const events = [];
  for (let index = 0; index < input.traceCount; index += 1) {
    const traceId = traceIdFor(index + 1);
    traces.push({
      traceId,
      cohort: index < 5 ? 'cold_after_deploy' : 'warm',
      isolateReuse: {
        gateway: index < 5 ? 'new' : 'reused',
        router: index < 5 ? 'new' : 'reused',
        deriverA: index < 5 ? 'new' : 'reused',
        deriverB: index < 5 ? 'new' : 'reused',
        signingWorker: index < 5 ? 'new' : 'reused',
      },
    });
    for (const span of REQUIRED_SPANS) {
      const base = span === 'registration.post_touch_id' ? 2_000 : 1_000;
      events.push(spanEvent(traceId, span, base + index));
    }
  }
  const synthetic = input.environment === 'synthetic_test';
  return {
    manifest: {
      schemaVersion: 1,
      environment: input.environment,
      capturedAt: '2026-07-24T00:00:00.000Z',
      captureMethod: synthetic ? 'synthetic_test' : 'cloudflare_workers_logs_export',
      release: {
        sourceSha: 'a'.repeat(40),
        gatewayVersionId: 'gateway-v1',
        routerVersionId: 'router-v1',
        deriverAVersionId: 'deriver-a-v1',
        deriverBVersionId: 'deriver-b-v1',
        signingWorkerVersionId: 'signing-worker-v1',
      },
      traces,
    },
    events,
    inputFiles: [
      {
        path: '/evidence/workers-logs.jsonl',
        sha256: 'b'.repeat(64),
        rejectedJsonLineCount: 0,
      },
    ],
  };
}

function spanEvent(traceId, span, durationMs, forcedInstanceDisposition) {
  const event = eventForSpan(span);
  const instanceDisposition = span.endsWith('.session_do.instance')
    ? (forcedInstanceDisposition ??
      (Number.parseInt(traceId.slice(-2), 16) <= 5 ? 'new' : 'reused'))
    : undefined;
  return {
    event: event.event,
    span,
    operation: event.operation,
    ...(event.role ? { role: event.role } : {}),
    outcome: 'success',
    duration_ms: durationMs,
    trace_id: traceId,
    ...(instanceDisposition
      ? {
          instance_disposition: instanceDisposition,
          instance_request_sequence: instanceDisposition === 'new' ? 1 : 2,
        }
      : {}),
    ...(span === 'gateway.yao_execute'
      ? {
          cpu_ms: 10 + Number.parseInt(traceId.slice(-2), 16),
          wall_time_ms: 20 + Number.parseInt(traceId.slice(-2), 16),
          memory_mb: 30 + Number.parseInt(traceId.slice(-2), 16),
          durable_object_call_count: 20 + Number.parseInt(traceId.slice(-2), 16),
          worker_invocation_count: 30 + Number.parseInt(traceId.slice(-2), 16),
          d1_query_count: 0,
          exact_replay_count: 0,
          conflict_count: 0,
          workers_resource: {
            join_kind: 'same_record',
            request_id: `workers-request-${traceId}`,
            script_name: 'seams-sdk-d1-gateway-production',
            execution_model: 'stateless',
            durable_object_id: null,
          },
        }
      : {}),
    source: '/evidence/workers-logs.jsonl',
    line: 1,
  };
}

function spanWithoutExecutionTelemetry(event) {
  const copy = { ...event };
  for (const field of [
    'cpu_ms',
    'wall_time_ms',
    'memory_mb',
    'durable_object_call_count',
    'worker_invocation_count',
    'd1_query_count',
    'exact_replay_count',
    'conflict_count',
    'workers_resource',
  ]) {
    delete copy[field];
  }
  return copy;
}

function workersLogsRecord(input) {
  const workers = {
    eventType: 'fetch',
    requestId: input.requestId,
    scriptName: input.scriptName,
    ...(input.cpuTimeMs === undefined ? {} : { cpuTimeMs: input.cpuTimeMs }),
    ...(input.wallTimeMs === undefined ? {} : { wallTimeMs: input.wallTimeMs }),
    ...(input.executionModel === undefined ? {} : { executionModel: input.executionModel }),
  };
  return {
    $metadata: {
      id: `event-${input.requestId}`,
      requestId: input.requestId,
      service: input.scriptName,
    },
    $workers: workers,
    dataset: 'cloudflare-workers',
    source: input.source,
    timestamp: 1_753_440_000_000,
  };
}

function eventForSpan(span) {
  if (span.startsWith('deriver_a.')) {
    return { event: 'router_ab_yao_role_span_v1', operation: 'activation', role: 'deriver_a' };
  }
  if (span.startsWith('deriver_b.')) {
    return { event: 'router_ab_yao_role_span_v1', operation: 'begin_pair', role: 'deriver_b' };
  }
  if (span.startsWith('router.')) {
    return { event: 'router_ab_yao_coordinator_span_v1', operation: 'registration' };
  }
  if (span.startsWith('gateway.')) {
    return { event: 'router_ab_yao_gateway_span_v1', operation: 'registration' };
  }
  return { event: 'seams_registration_timing_span_v1', operation: 'registration' };
}

function traceIdFor(value) {
  return value.toString(16).padStart(32, '0');
}

function notGatewayD1Commit(event) {
  return event.span !== 'gateway.d1_commit';
}

function hasMissingGatewayD1Commit(blocker) {
  return blocker.includes('missing required spans: gateway.d1_commit');
}

function hasUnknownRouterReuse(blocker) {
  return blocker.includes('unknown isolate reuse: router');
}

function buildOneBasedValue(_value, index) {
  return index + 1;
}
