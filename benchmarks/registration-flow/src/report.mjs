import { SCENARIOS } from './scenarios.mjs';

function fmtNum(value, decimals = 1) {
  if (value == null || !Number.isFinite(value)) return 'n/a';
  return Number(value).toFixed(decimals);
}

function scenarioDescription(id) {
  return SCENARIOS.find((entry) => entry.id === id)?.description || id;
}

function appendStatsTable(lines, title, statsByName) {
  const entries = Object.entries(statsByName || {}).filter(([, stats]) => stats?.count > 0);
  if (!entries.length) return;
  lines.push(`### ${title}`);
  lines.push('');
  lines.push('| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |');
  lines.push('|---|---:|---:|---:|---:|---:|---:|');
  for (const [name, stats] of entries.sort(([left], [right]) => left.localeCompare(right))) {
    lines.push(
      `| \`${name}\` | ${fmtNum(stats.count, 0)} | ${fmtNum(stats.p50)} | ${fmtNum(stats.p95)} | ${fmtNum(stats.p99)} | ${fmtNum(stats.mean)} | ${fmtNum(stats.max)} |`,
    );
  }
  lines.push('');
}

function appendHssWorkerTable(lines, diagnosticsByOperation) {
  const entries = Object.entries(diagnosticsByOperation || {}).filter(
    ([, entry]) => entry?.totalMs?.count > 0,
  );
  if (!entries.length) return;
  lines.push('### HSS Worker Diagnostics');
  lines.push('');
  lines.push(
    '| Operation | Count | total p50 | total p95 | wasm p50 | wasm p95 | queue p95 | request bytes p50 | response bytes p50 |',
  );
  lines.push('|---|---:|---:|---:|---:|---:|---:|---:|---:|');
  for (const [operation, entry] of entries.sort(([left], [right]) => left.localeCompare(right))) {
    lines.push(
      `| \`${operation}\` | ${fmtNum(entry.totalMs?.count, 0)} | ${fmtNum(entry.totalMs?.p50)} | ${fmtNum(entry.totalMs?.p95)} | ${fmtNum(entry.wasmCallMs?.p50)} | ${fmtNum(entry.wasmCallMs?.p95)} | ${fmtNum(entry.queueWaitMs?.p95)} | ${fmtNum(entry.requestPayloadBytes?.p50, 0)} | ${fmtNum(entry.responsePayloadBytes?.p50, 0)} |`,
    );
  }
  lines.push('');

  const wasmTimingRows = [];
  for (const [operation, entry] of entries) {
    for (const [name, stats] of Object.entries(entry || {})) {
      if (!name.startsWith('wasm.') || stats?.count <= 0) continue;
      wasmTimingRows.push({
        operation,
        name: name.slice('wasm.'.length),
        stats,
      });
    }
  }
  if (!wasmTimingRows.length) return;
  lines.push('### HSS Worker WASM Substep Timings');
  lines.push('');
  lines.push('| Operation | Substep | Count | p50 (ms) | p95 (ms) | Mean (ms) | Max (ms) |');
  lines.push('|---|---|---:|---:|---:|---:|---:|');
  for (const row of wasmTimingRows.sort((left, right) => {
    const operationOrder = left.operation.localeCompare(right.operation);
    return operationOrder || left.name.localeCompare(right.name);
  })) {
    lines.push(
      `| \`${row.operation}\` | \`${row.name}\` | ${fmtNum(row.stats.count, 0)} | ${fmtNum(row.stats.p50)} | ${fmtNum(row.stats.p95)} | ${fmtNum(row.stats.mean)} | ${fmtNum(row.stats.max)} |`,
    );
  }
  lines.push('');
}

function appendRelayRouteTables(lines, statsByRoute) {
  const routes = Object.entries(statsByRoute || {}).filter(
    ([, statsByName]) => Object.keys(statsByName || {}).length > 0,
  );
  if (!routes.length) return;
  for (const [route, statsByName] of routes.sort(([left], [right]) => left.localeCompare(right))) {
    lines.push(`### Relay Route Diagnostics: ${route}`);
    lines.push('');
    lines.push('| Bucket | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |');
    lines.push('|---|---:|---:|---:|---:|---:|---:|');
    for (const [name, stats] of Object.entries(statsByName).sort(([left], [right]) =>
      left.localeCompare(right),
    )) {
      lines.push(
        `| \`${name}\` | ${fmtNum(stats.count, 0)} | ${fmtNum(stats.p50)} | ${fmtNum(stats.p95)} | ${fmtNum(stats.p99)} | ${fmtNum(stats.mean)} | ${fmtNum(stats.max)} |`,
      );
    }
    lines.push('');
  }
}

function appendHssClientTable(lines, diagnosticsByOperation) {
  const entries = Object.entries(diagnosticsByOperation || {}).filter(
    ([, entry]) => entry?.totalMs?.count > 0,
  );
  if (!entries.length) return;
  lines.push('### HSS Client Timings');
  lines.push('');
  lines.push(
    '| Operation | Count | total p50 | total p95 | fetch p50 | fetch p95 | request bytes p50 | response bytes p50 |',
  );
  lines.push('|---|---:|---:|---:|---:|---:|---:|---:|');
  for (const [operation, entry] of entries.sort(([left], [right]) => left.localeCompare(right))) {
    lines.push(
      `| \`${operation}\` | ${fmtNum(entry.totalMs?.count, 0)} | ${fmtNum(entry.totalMs?.p50)} | ${fmtNum(entry.totalMs?.p95)} | ${fmtNum(entry.fetchMs?.p50)} | ${fmtNum(entry.fetchMs?.p95)} | ${fmtNum(entry.requestBytes?.p50, 0)} | ${fmtNum(entry.responseBytes?.p50, 0)} |`,
    );
  }
  lines.push('');
}

export function buildMarkdownReport(input) {
  const lines = [];
  lines.push('# Registration Flow Benchmark Report');
  lines.push('');
  lines.push(`Generated: ${input.generatedAtIso}`);
  lines.push(`Run ID: \`${input.runId}\``);
  lines.push('');
  lines.push('## Scenario Summary');
  lines.push('');
  lines.push(
    '| Scenario | Description | Status | Successful Runs | browser p50 (ms) | browser p95 (ms) | SDK p50 (ms) | SDK p95 (ms) | Relay diagnostics | HSS client timings | HSS worker diagnostics |',
  );
  lines.push('|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|');
  for (const result of input.results || []) {
    const summary = result.summary;
    lines.push(
      `| \`${result.id}\` | ${scenarioDescription(result.id)} | ${result.status} | ${fmtNum(summary?.successfulRuns, 0)} / ${fmtNum(summary?.runsRequested, 0)} | ${fmtNum(summary?.timingStats?.totalMs?.p50)} | ${fmtNum(summary?.timingStats?.totalMs?.p95)} | ${fmtNum(summary?.timingStats?.sdkTotalMs?.p50)} | ${fmtNum(summary?.timingStats?.sdkTotalMs?.p95)} | ${fmtNum(summary?.relayDiagnosticsCount, 0)} | ${fmtNum(summary?.hssClientTimingCount, 0)} | ${fmtNum(summary?.hssWorkerDiagnosticsCount, 0)} |`,
    );
  }
  lines.push('');

  for (const result of input.results || []) {
    lines.push(`## ${result.id}`);
    lines.push('');
    lines.push(`- Description: ${scenarioDescription(result.id)}`);
    lines.push(`- Status: ${result.status}`);
    if (result.command) lines.push(`- Command: \`${result.command}\``);
    if (result.error) lines.push(`- Error: ${result.error}`);
    const summary = result.summary;
    if (!summary) {
      lines.push('');
      continue;
    }
    lines.push(`- Scenario mode: ${summary.signerMode} / ${summary.walletIframeMode}`);
    lines.push(`- Runs requested: ${fmtNum(summary.runsRequested, 0)}`);
    lines.push(`- Successful runs: ${fmtNum(summary.successfulRuns, 0)}`);
    lines.push(`- Failed runs: ${fmtNum(summary.failedRuns, 0)}`);
    lines.push(`- Relay diagnostics captured: ${fmtNum(summary.relayDiagnosticsCount, 0)}`);
    lines.push(`- HSS client timings captured: ${fmtNum(summary.hssClientTimingCount, 0)}`);
    lines.push(`- HSS worker diagnostics captured: ${fmtNum(summary.hssWorkerDiagnosticsCount, 0)}`);
    lines.push('');
    appendStatsTable(lines, 'Registration Timing Buckets', summary.timingStats || {});
    appendRelayRouteTables(lines, summary.relayStatsByRoute || {});
    appendHssClientTable(lines, summary.hssClientStatsByOperation || {});
    appendHssWorkerTable(lines, summary.hssWorkerStatsByOperation || {});
  }

  lines.push('## Notes');
  lines.push('');
  lines.push('- This benchmark uses browser Playwright flows, WebAuthn mocks, IndexedDB, and real HSS relay messages from the local managed-registration harness.');
  lines.push('- Relay route diagnostics are observational response metadata and contain bucket durations only.');
  lines.push('- HSS worker diagnostics are observational and contain durations plus field sizes, not payload values.');

  return lines.join('\n');
}
