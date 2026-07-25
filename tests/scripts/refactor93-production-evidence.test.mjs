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

test('JSONL parser extracts direct, Wrangler tail, and Workers Logs span messages', () => {
  const traceId = traceIdFor(1);
  const event = spanEvent(traceId, 'gateway.yao_execute', 900);
  const text = [
    JSON.stringify(event),
    JSON.stringify({ logs: [{ message: [JSON.stringify(event)] }] }),
    JSON.stringify({ message: [JSON.stringify(event)] }),
    'not-json',
  ].join('\n');

  const parsed = parseRefactor93SpanJsonl(text, 'fixture.jsonl');

  assert.equal(parsed.events.length, 3);
  assert.equal(parsed.rejectedLines.length, 1);
  assert.equal(parsed.events[1].source, 'fixture.jsonl');
  assert.equal(parsed.events[1].line, 2);
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
      captureMethod: synthetic ? 'synthetic_test' : 'wrangler_tail_json',
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
        path: '/evidence/worker-tail.jsonl',
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
          active_duration_ms: 20 + Number.parseInt(traceId.slice(-2), 16),
          memory_mb: 30 + Number.parseInt(traceId.slice(-2), 16),
          durable_object_call_count: 20 + Number.parseInt(traceId.slice(-2), 16),
          worker_invocation_count: 30 + Number.parseInt(traceId.slice(-2), 16),
          d1_query_count: 0,
          exact_replay_count: 0,
          conflict_count: 0,
        }
      : {}),
    source: '/evidence/worker-tail.jsonl',
    line: 1,
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
