import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const TRACE_ID_PATTERN = /^[0-9a-f]{32}$/u;
const SOURCE_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const MINIMUM_PRODUCTION_TRACES = 20;
const REQUIRED_RELEASE_COMPONENTS = [
  'gatewayVersionId',
  'routerVersionId',
  'deriverAVersionId',
  'deriverBVersionId',
  'signingWorkerVersionId',
];
const REQUIRED_ISOLATE_REUSE_COMPONENTS = [
  'gateway',
  'router',
  'deriverA',
  'deriverB',
  'signingWorker',
];
const REQUIRED_TRACE_SPANS = [
  'registration.post_touch_id',
  'gateway.pre_yao',
  'gateway.yao_execute',
  'router.parse_and_authorize',
  'router.role_status_reconciliation',
  'router.prepare_pair',
  'router.verify_readiness_receipts',
  'router.deriver_a_execute',
  'deriver_a.root_share',
  'deriver_a.websocket_connect',
  'deriver_a.yao_protocol',
  'deriver_b.session_do',
  'deriver_b.yao_protocol',
  'router.deriver_b_completed_read',
  'router.signing_worker_delivery',
  'gateway.d1_commit',
  'frontend.wallet_ready',
];
const REQUIRED_PREPARATION_SPANS = [
  'router.prepare_pair.deriver_a',
  'router.prepare_pair.deriver_b',
];
const UNIQUE_BUDGET_SPANS = ['registration.post_touch_id', 'gateway.yao_execute'];
const ENVIRONMENTS = new Set(['production', 'staging', 'local', 'synthetic_test']);
const CAPTURE_METHODS = new Set([
  'wrangler_tail_json',
  'cloudflare_workers_logs_export',
  'synthetic_test',
]);
const COHORTS = new Set(['cold_after_deploy', 'warm']);
const ISOLATE_REUSE_STATES = new Set(['new', 'reused', 'unknown']);

export function parseRefactor93EvidenceManifest(value) {
  const record = requireRecord(value, 'evidence manifest');
  requireExactKeys(record, 'evidence manifest', [
    'schemaVersion',
    'environment',
    'capturedAt',
    'captureMethod',
    'release',
    'traces',
  ]);
  if (record.schemaVersion !== 1) {
    throw new Error('evidence manifest schemaVersion must be 1');
  }
  const environment = requireEnum(record.environment, ENVIRONMENTS, 'manifest environment');
  const captureMethod = requireEnum(
    record.captureMethod,
    CAPTURE_METHODS,
    'manifest captureMethod',
  );
  if (environment === 'production' && captureMethod === 'synthetic_test') {
    throw new Error('production evidence cannot use the synthetic_test capture method');
  }
  if (environment === 'synthetic_test' && captureMethod !== 'synthetic_test') {
    throw new Error('synthetic_test evidence must use the synthetic_test capture method');
  }
  const traces = requireArray(record.traces, 'manifest traces');
  return {
    schemaVersion: 1,
    environment,
    capturedAt: requireIsoTimestamp(record.capturedAt, 'manifest capturedAt'),
    captureMethod,
    release: parseRelease(record.release),
    traces: traces.map(parseTraceManifestEntry),
  };
}

export function parseRefactor93SpanJsonl(text, sourceLabel = '<input>') {
  const events = [];
  const rejectedLines = [];
  const lines = text.split(/\r?\n/u);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    if (line.length === 0) continue;
    let value;
    try {
      value = JSON.parse(line);
    } catch (error) {
      rejectedLines.push({
        source: sourceLabel,
        line: index + 1,
        reason: error instanceof Error ? error.message : String(error),
      });
      continue;
    }
    collectSpanCandidates(value, events, sourceLabel, index + 1);
  }
  return { events, rejectedLines };
}

export function analyzeRefactor93ProductionEvidence(input) {
  const manifest = parseRefactor93EvidenceManifest(input.manifest);
  const inputFiles = parseInputFiles(input.inputFiles);
  const events = input.events.map(parseSpanEvent);
  const eventsByTrace = groupEventsByTrace(events);
  const traceReports = [];
  for (const trace of manifest.traces) {
    traceReports.push(analyzeTrace(trace, eventsByTrace.get(trace.traceId) ?? []));
  }
  const blockers = [];
  addManifestBlockers(blockers, manifest, traceReports, inputFiles);
  const eligibleTraceReports = traceReports.filter(isBudgetEligibleTrace);
  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    provenance: {
      environment: manifest.environment,
      capturedAt: manifest.capturedAt,
      captureMethod: manifest.captureMethod,
      release: manifest.release,
      inputs: inputFiles,
    },
    readiness: {
      phase0BaselineReady: blockers.length === 0,
      minimumProductionTraceCount: MINIMUM_PRODUCTION_TRACES,
      declaredTraceCount: traceReports.length,
      completeTraceCount: eligibleTraceReports.length,
      coldAfterDeployTraceCount: countCohort(eligibleTraceReports, 'cold_after_deploy'),
      warmTraceCount: countCohort(eligibleTraceReports, 'warm'),
      blockers,
    },
    budgets: {
      gatewayYaoExecuteMs: cohortMetrics(eligibleTraceReports, 'gateway.yao_execute'),
      postTouchIdToWalletReadyMs: cohortMetrics(eligibleTraceReports, 'registration.post_touch_id'),
      productTarget: {
        p50Ms: 3_000,
        p95Ms: 4_000,
      },
    },
    traceReports,
    ignoredEventCount: countIgnoredEvents(eventsByTrace, manifest.traces),
  };
  return report;
}

export function nearestRankPercentile(values, percentile) {
  if (!Array.isArray(values) || values.length === 0) return null;
  if (typeof percentile !== 'number' || percentile <= 0 || percentile > 1) {
    throw new Error('percentile must be greater than 0 and at most 1');
  }
  const sorted = [...values].sort(compareNumbers);
  const index = Math.ceil(percentile * sorted.length) - 1;
  return sorted[index];
}

function parseRelease(value) {
  const record = requireRecord(value, 'manifest release');
  requireExactKeys(record, 'manifest release', ['sourceSha', ...REQUIRED_RELEASE_COMPONENTS]);
  const sourceSha = requireString(record.sourceSha, 'manifest release sourceSha');
  if (!SOURCE_SHA_PATTERN.test(sourceSha)) {
    throw new Error('manifest release sourceSha must be a full lowercase Git SHA');
  }
  const release = { sourceSha };
  for (const component of REQUIRED_RELEASE_COMPONENTS) {
    release[component] = requireString(record[component], `manifest release ${component}`);
  }
  return release;
}

function parseTraceManifestEntry(value, index) {
  const label = `manifest traces[${index}]`;
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['traceId', 'cohort', 'isolateReuse']);
  const traceId = requireTraceId(record.traceId, `${label} traceId`);
  const cohort = requireEnum(record.cohort, COHORTS, `${label} cohort`);
  const isolateReuseRecord = requireRecord(record.isolateReuse, `${label} isolateReuse`);
  requireExactKeys(isolateReuseRecord, `${label} isolateReuse`, REQUIRED_ISOLATE_REUSE_COMPONENTS);
  const isolateReuse = {};
  for (const component of REQUIRED_ISOLATE_REUSE_COMPONENTS) {
    isolateReuse[component] = requireEnum(
      isolateReuseRecord[component],
      ISOLATE_REUSE_STATES,
      `${label} isolateReuse ${component}`,
    );
  }
  return { traceId, cohort, isolateReuse };
}

function collectSpanCandidates(value, events, source, line) {
  if (isRecord(value) && looksLikeSpanEvent(value)) {
    events.push({ ...value, source, line });
    return;
  }
  if (!isRecord(value)) return;
  collectMessageCandidates(value.message, events, source, line);
  collectMessageCandidates(value.logs, events, source, line);
  collectMessageCandidates(value.Logs, events, source, line);
}

function collectMessageCandidates(value, events, source, line) {
  if (Array.isArray(value)) {
    for (const child of value) collectMessageCandidates(child, events, source, line);
    return;
  }
  if (isRecord(value)) {
    collectSpanCandidates(value, events, source, line);
    return;
  }
  if (typeof value !== 'string') return;
  let decoded;
  try {
    decoded = JSON.parse(value);
  } catch {
    return;
  }
  collectSpanCandidates(decoded, events, source, line);
}

function looksLikeSpanEvent(value) {
  return (
    typeof value.event === 'string' &&
    value.event.endsWith('_span_v1') &&
    typeof value.span === 'string' &&
    Object.hasOwn(value, 'trace_id') &&
    Object.hasOwn(value, 'duration_ms')
  );
}

function parseSpanEvent(value, index) {
  const label = `span events[${index}]`;
  const record = requireRecord(value, label);
  const event = requireString(record.event, `${label} event`);
  if (!event.endsWith('_span_v1')) {
    throw new Error(`${label} event must be a versioned span event`);
  }
  const outcome = requireString(record.outcome, `${label} outcome`);
  const durationMs = requireNonNegativeSafeInteger(record.duration_ms, `${label} duration_ms`);
  return {
    event,
    span: requireString(record.span, `${label} span`),
    operation: requireString(record.operation, `${label} operation`),
    outcome,
    durationMs,
    traceId: requireTraceId(record.trace_id, `${label} trace_id`),
    source: requireString(record.source, `${label} source`),
    line: requirePositiveSafeInteger(record.line, `${label} line`),
  };
}

function parseInputFiles(value) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('at least one evidence input file is required');
  }
  const inputs = [];
  for (let index = 0; index < value.length; index += 1) {
    const record = requireRecord(value[index], `inputFiles[${index}]`);
    inputs.push({
      path: requireString(record.path, `inputFiles[${index}] path`),
      sha256: requireSha256(record.sha256, `inputFiles[${index}] sha256`),
      rejectedJsonLineCount: requireNonNegativeSafeInteger(
        record.rejectedJsonLineCount,
        `inputFiles[${index}] rejectedJsonLineCount`,
      ),
    });
  }
  return inputs;
}

function groupEventsByTrace(events) {
  const grouped = new Map();
  for (const event of events) {
    const current = grouped.get(event.traceId);
    if (current) current.push(event);
    else grouped.set(event.traceId, [event]);
  }
  return grouped;
}

function analyzeTrace(trace, events) {
  const registrationEvents = [];
  const wrongOperationEvents = [];
  for (const event of events) {
    if (event.operation === 'registration') registrationEvents.push(event);
    else wrongOperationEvents.push(event);
  }
  const missingSpans = [];
  const failedSpans = [];
  const spanDurationsMs = {};
  for (const span of REQUIRED_TRACE_SPANS) {
    const spanEvents = eventsForSpan(registrationEvents, span);
    const successful = spanEvents.filter(isSuccessfulEvent);
    if (successful.length === 0) missingSpans.push(span);
    if (spanEvents.some(isFailedEvent)) failedSpans.push(span);
    spanDurationsMs[span] = successful.map(eventDuration);
  }
  const missingPreparationSpans = [];
  for (const span of REQUIRED_PREPARATION_SPANS) {
    if (!registrationEvents.some(matchesSuccessfulSpan(span))) {
      missingPreparationSpans.push(span);
    }
  }
  const duplicateBudgetSpans = [];
  for (const span of UNIQUE_BUDGET_SPANS) {
    if (spanDurationsMs[span].length !== 1) duplicateBudgetSpans.push(span);
  }
  const unknownIsolateReuse = [];
  for (const component of REQUIRED_ISOLATE_REUSE_COMPONENTS) {
    if (trace.isolateReuse[component] === 'unknown') unknownIsolateReuse.push(component);
  }
  return {
    traceId: trace.traceId,
    cohort: trace.cohort,
    complete:
      missingSpans.length === 0 &&
      missingPreparationSpans.length === 0 &&
      failedSpans.length === 0 &&
      duplicateBudgetSpans.length === 0 &&
      wrongOperationEvents.length === 0 &&
      unknownIsolateReuse.length === 0,
    isolateReuse: trace.isolateReuse,
    eventCount: registrationEvents.length,
    missingSpans,
    missingPreparationSpans,
    failedSpans,
    duplicateBudgetSpans,
    unexpectedOperationCount: wrongOperationEvents.length,
    spanDurationsMs,
  };
}

function addManifestBlockers(blockers, manifest, traceReports, inputFiles) {
  if (manifest.environment !== 'production') {
    blockers.push('manifest environment must be production');
  }
  if (inputFiles.some(hasRejectedJsonLines)) {
    blockers.push('evidence log inputs must contain no rejected JSONL lines');
  }
  if (traceReports.length < MINIMUM_PRODUCTION_TRACES) {
    blockers.push(`at least ${MINIMUM_PRODUCTION_TRACES} declared production traces are required`);
  }
  if (hasDuplicateTraceIds(manifest.traces)) {
    blockers.push('manifest trace IDs must be unique');
  }
  if (Object.values(manifest.release).some(isUnknownValue)) {
    blockers.push('all coherent release component version IDs must be known');
  }
  const complete = traceReports.filter(isBudgetEligibleTrace);
  if (!complete.some(matchesCohort('cold_after_deploy'))) {
    blockers.push('at least one complete cold-after-deploy trace is required');
  }
  if (!complete.some(matchesCohort('warm'))) {
    blockers.push('at least one complete warm trace is required');
  }
  for (const report of traceReports) {
    addTraceBlockers(blockers, report);
  }
}

function addTraceBlockers(blockers, report) {
  if (report.missingSpans.length > 0) {
    blockers.push(`${report.traceId} missing required spans: ${report.missingSpans.join(', ')}`);
  }
  if (report.missingPreparationSpans.length > 0) {
    blockers.push(
      `${report.traceId} cannot measure overlapped A/B preparation; missing: ${report.missingPreparationSpans.join(', ')}`,
    );
  }
  if (report.failedSpans.length > 0) {
    blockers.push(
      `${report.traceId} contains failed required spans: ${report.failedSpans.join(', ')}`,
    );
  }
  if (report.duplicateBudgetSpans.length > 0) {
    blockers.push(
      `${report.traceId} must contain exactly one successful budget span: ${report.duplicateBudgetSpans.join(', ')}`,
    );
  }
  if (report.unexpectedOperationCount > 0) {
    blockers.push(`${report.traceId} contains non-registration span events`);
  }
  const unknown = [];
  for (const component of REQUIRED_ISOLATE_REUSE_COMPONENTS) {
    if (report.isolateReuse[component] === 'unknown') unknown.push(component);
  }
  if (unknown.length > 0) {
    blockers.push(`${report.traceId} has unknown isolate reuse: ${unknown.join(', ')}`);
  }
}

function cohortMetrics(traceReports, span) {
  return {
    all: metricsForReports(traceReports, span),
    coldAfterDeploy: metricsForReports(
      traceReports.filter(matchesCohort('cold_after_deploy')),
      span,
    ),
    warm: metricsForReports(traceReports.filter(matchesCohort('warm')), span),
  };
}

function metricsForReports(traceReports, span) {
  const values = [];
  for (const report of traceReports) {
    const duration = report.spanDurationsMs[span];
    if (duration.length === 1) values.push(duration[0]);
  }
  return {
    sampleCount: values.length,
    p50: nearestRankPercentile(values, 0.5),
    p95: nearestRankPercentile(values, 0.95),
    min: values.length === 0 ? null : Math.min(...values),
    max: values.length === 0 ? null : Math.max(...values),
  };
}

function countCohort(reports, cohort) {
  return reports.filter(matchesCohort(cohort)).length;
}

function countIgnoredEvents(eventsByTrace, traces) {
  const declared = new Set();
  for (const trace of traces) declared.add(trace.traceId);
  let count = 0;
  for (const [traceId, events] of eventsByTrace.entries()) {
    if (!declared.has(traceId)) count += events.length;
  }
  return count;
}

function hasDuplicateTraceIds(traces) {
  const ids = new Set();
  for (const trace of traces) {
    if (ids.has(trace.traceId)) return true;
    ids.add(trace.traceId);
  }
  return false;
}

function isBudgetEligibleTrace(report) {
  return report.complete;
}

function matchesCohort(cohort) {
  return function matchReportCohort(report) {
    return report.cohort === cohort;
  };
}

function matchesSuccessfulSpan(span) {
  return function matchEventSpan(event) {
    return event.span === span && isSuccessfulEvent(event);
  };
}

function eventsForSpan(events, span) {
  const matched = [];
  for (const event of events) {
    if (event.span === span) matched.push(event);
  }
  return matched;
}

function isSuccessfulEvent(event) {
  return event.outcome === 'success';
}

function isFailedEvent(event) {
  return event.outcome !== 'success';
}

function eventDuration(event) {
  return event.durationMs;
}

function compareNumbers(left, right) {
  return left - right;
}

function isUnknownValue(value) {
  return value === 'unknown';
}

function hasRejectedJsonLines(inputFile) {
  return inputFile.rejectedJsonLineCount > 0;
}

function requireRecord(value, label) {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value;
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireExactKeys(record, label, keys) {
  const expected = new Set(keys);
  for (const key of Object.keys(record)) {
    if (!expected.has(key)) throw new Error(`${label}.${key} is not supported`);
  }
  for (const key of keys) {
    if (!Object.hasOwn(record, key)) throw new Error(`${label}.${key} is required`);
  }
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function requireTraceId(value, label) {
  const traceId = requireString(value, label);
  if (!TRACE_ID_PATTERN.test(traceId)) {
    throw new Error(`${label} must be canonical 128-bit lowercase hex`);
  }
  return traceId;
}

function requireSha256(value, label) {
  const sha256 = requireString(value, label);
  if (!/^[0-9a-f]{64}$/u.test(sha256)) {
    throw new Error(`${label} must be lowercase SHA-256`);
  }
  return sha256;
}

function requireIsoTimestamp(value, label) {
  const timestamp = requireString(value, label);
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString() !== timestamp) {
    throw new Error(`${label} must be a canonical ISO timestamp`);
  }
  return timestamp;
}

function requireEnum(value, values, label) {
  if (typeof value !== 'string' || !values.has(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function requireArray(value, label) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function requireNonNegativeSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function requirePositiveSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function parseCliArgs(argv) {
  if (argv[0] !== 'analyze') {
    throw new Error(
      'usage: refactor93-production-evidence.mjs analyze --manifest <file> --logs <file> [--logs <file> ...] [--out <file>]',
    );
  }
  let manifestPath = null;
  let outPath = null;
  const logPaths = [];
  for (let index = 1; index < argv.length; index += 2) {
    const option = argv[index];
    const value = argv[index + 1];
    if (!option?.startsWith('--') || value === undefined) {
      throw new Error(`invalid evidence argument: ${option ?? '<missing>'}`);
    }
    switch (option) {
      case '--manifest':
        if (manifestPath !== null) throw new Error('--manifest may be provided once');
        manifestPath = resolve(value);
        break;
      case '--logs':
        logPaths.push(resolve(value));
        break;
      case '--out':
        if (outPath !== null) throw new Error('--out may be provided once');
        outPath = resolve(value);
        break;
      default:
        throw new Error(`unsupported evidence option: ${option}`);
    }
  }
  if (manifestPath === null) throw new Error('--manifest is required');
  if (logPaths.length === 0) throw new Error('at least one --logs file is required');
  return { manifestPath, logPaths, outPath };
}

async function loadEvidenceInputs(options) {
  const manifestText = await readFile(options.manifestPath, 'utf8');
  const manifest = JSON.parse(manifestText);
  const events = [];
  const inputFiles = [];
  for (const path of options.logPaths) {
    const text = await readFile(path, 'utf8');
    const parsed = parseRefactor93SpanJsonl(text, path);
    events.push(...parsed.events);
    inputFiles.push({
      path,
      sha256: createHash('sha256').update(text).digest('hex'),
      rejectedJsonLineCount: parsed.rejectedLines.length,
    });
  }
  return { manifest, events, inputFiles };
}

async function runCli() {
  const options = parseCliArgs(process.argv.slice(2));
  const input = await loadEvidenceInputs(options);
  const report = analyzeRefactor93ProductionEvidence(input);
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  if (options.outPath) await writeFile(options.outPath, serialized);
  process.stdout.write(serialized);
  if (!report.readiness.phase0BaselineReady) process.exitCode = 1;
}

function isMainModule() {
  return (
    process.argv[1] !== undefined &&
    import.meta.url === pathToFileURL(resolve(process.argv[1])).href
  );
}

if (isMainModule()) await runCli();
