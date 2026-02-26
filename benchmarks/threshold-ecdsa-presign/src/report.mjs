import { SCENARIOS } from './scenarios.mjs';

function fmtNum(value, decimals = 0) {
  if (value == null || !Number.isFinite(value)) return 'n/a';
  return Number(value).toFixed(decimals);
}

function fmtPct(value) {
  if (value == null || !Number.isFinite(value)) return 'n/a';
  return `${(value * 100).toFixed(1)}%`;
}

function scenarioDescription(id) {
  const found = SCENARIOS.find((scenario) => scenario.id === id);
  return found?.description || id;
}

function fmtValue(value, decimals = 0) {
  if (value == null || !Number.isFinite(value)) return 'n/a';
  return Number(value).toFixed(decimals);
}

function appendRouteTable(lines, routeDurations) {
  lines.push('| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |');
  lines.push('|---|---:|---:|---:|---:|---:|');
  const routes = Object.keys(routeDurations).sort();
  for (const route of routes) {
    const stats = routeDurations[route];
    lines.push(
      `| \`${route}\` | ${fmtNum(stats?.count)} | ${fmtNum(stats?.p50)} | ${fmtNum(stats?.p95)} | ${fmtNum(stats?.p99)} | ${fmtNum(stats?.mean, 1)} |`,
    );
  }
}

function computeRecommendation(results) {
  const recommended = {
    targetDepth: 3,
    lowWatermark: 1,
    maxRefillInFlight: 1,
  };
  const reasons = [];

  const presignStepP95 = Math.max(
    ...results.map(
      (entry) => entry.metrics?.routeDurations?.['/threshold-ecdsa/presign/step']?.p95 || 0,
    ),
    0,
  );
  const poolEmptyTotal = results.reduce(
    (acc, entry) => acc + (entry.metrics?.poolEmptyResponses || 0),
    0,
  );
  const backgroundRatioMax = Math.max(
    ...results.map((entry) => entry.metrics?.backgroundPresignTraffic?.ratio || 0),
    0,
  );

  if (poolEmptyTotal > 0) {
    recommended.targetDepth = 4;
    recommended.lowWatermark = 2;
    reasons.push(
      `Observed ${poolEmptyTotal} pool_empty responses; raise depth to reduce cold misses.`,
    );
  }

  if (presignStepP95 > 1500) {
    recommended.maxRefillInFlight = 1;
    recommended.targetDepth = Math.min(recommended.targetDepth, 3);
    recommended.lowWatermark = Math.min(recommended.lowWatermark, 1);
    reasons.push(
      `p95(/presign/step)=${fmtNum(presignStepP95)}ms; keep refill conservative and prioritize foreground.`,
    );
  }

  if (backgroundRatioMax > 0.4 && presignStepP95 > 1200) {
    recommended.targetDepth = Math.min(recommended.targetDepth, 3);
    recommended.maxRefillInFlight = 1;
    reasons.push(
      `High background presign ratio (${fmtPct(backgroundRatioMax)}) under elevated step latency; avoid aggressive refill.`,
    );
  }

  if (reasons.length === 0) {
    reasons.push(
      'Current data supports keeping defaults (targetDepth=3, lowWatermark=1, maxRefillInFlight=1).',
    );
  }

  return { recommended, reasons };
}

export function buildMarkdownReport(input) {
  const lines = [];
  lines.push('# Threshold ECDSA Presign Benchmark Report');
  lines.push('');
  lines.push(`Generated: ${input.generatedAtIso}`);
  lines.push(`Run ID: \`${input.runId}\``);
  lines.push('');

  lines.push('## Scenario Results');
  lines.push('');
  for (const result of input.results) {
    lines.push(`### ${result.id}`);
    lines.push('');
    lines.push(`- Description: ${scenarioDescription(result.id)}`);
    lines.push(`- Status: ${result.status}`);
    if (result.command) lines.push(`- Command: \`${result.command}\``);
    if (result.error) lines.push(`- Error: ${result.error}`);
    lines.push('');
    if (result.status === 'ok') {
      if (result.metrics.scenarioTotalMs) {
        lines.push(
          '| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |',
        );
        lines.push('|---|---:|---:|---:|---:|---:|');
        lines.push(
          `| \`${result.id}\` | ${fmtNum(result.metrics.scenarioTotalMs?.count)} | ${fmtNum(result.metrics.scenarioTotalMs?.p50)} | ${fmtNum(result.metrics.scenarioTotalMs?.p95)} | ${fmtNum(result.metrics.scenarioTotalMs?.p99)} | ${fmtNum(result.metrics.scenarioTotalMs?.mean, 1)} |`,
        );
        lines.push('');
      }
      appendRouteTable(lines, result.metrics.routeDurations || {});
      lines.push('');
      lines.push('| Presign Perf | Value |');
      lines.push('|---|---:|');
      lines.push(
        `| presign_live_cache_hit | ${fmtNum(result.metrics.presignStepPerf?.counters?.presign_live_cache_hit)} |`,
      );
      lines.push(
        `| presign_live_cache_miss | ${fmtNum(result.metrics.presignStepPerf?.counters?.presign_live_cache_miss)} |`,
      );
      lines.push(
        `| presign_stale_session_state | ${fmtNum(result.metrics.presignStepPerf?.counters?.presign_stale_session_state)} |`,
      );
      lines.push(`| liveCacheHitRatio | ${fmtPct(result.metrics.presignStepPerf?.liveHitRatio)} |`);
      lines.push(
        `| staleSessionRatio | ${fmtPct(result.metrics.presignStepPerf?.staleSessionRatio)} |`,
      );
      lines.push(
        `| gateWaitP95ForegroundMs | ${fmtNum(result.metrics.presignGateWait?.foreground?.p95)} |`,
      );
      lines.push(
        `| gateWaitP95BackgroundMs | ${fmtNum(result.metrics.presignGateWait?.background?.p95)} |`,
      );
      lines.push(
        `| backgroundPresignRequestRatio | ${fmtPct(result.metrics.backgroundPresignTraffic?.ratio)} |`,
      );
      lines.push(`| poolEmptyResponses | ${fmtNum(result.metrics.poolEmptyResponses)} |`);
      lines.push('');
    }
  }

  if (input.slo) {
    lines.push('## SLO Gates');
    lines.push('');
    lines.push(`- Enabled: ${input.slo.enabled ? 'yes' : 'no'}`);
    lines.push(`- Passed: ${fmtNum(input.slo.passedCount)}`);
    lines.push(`- Failed: ${fmtNum(input.slo.failedCount)}`);
    lines.push(`- Skipped: ${fmtNum(input.slo.skippedCount)}`);
    lines.push('');
    lines.push('| Gate | Status | Actual | Comparator | Threshold | Reason |');
    lines.push('|---|---|---:|---|---:|---|');
    for (const check of input.slo.checks || []) {
      lines.push(
        `| ${check.name} | ${check.status} | ${fmtValue(check.actual, 2)} | ${check.comparator || 'n/a'} | ${fmtValue(check.threshold, 2)} | ${check.reason || ''} |`,
      );
    }
    lines.push('');
  }

  const recommendation = computeRecommendation(
    input.results.filter((entry) => entry.status === 'ok'),
  );
  lines.push('## Presign Pool Configuration Recommendation');
  lines.push('');
  lines.push('| Setting | Recommended |');
  lines.push('|---|---:|');
  lines.push(`| targetDepth | ${recommendation.recommended.targetDepth} |`);
  lines.push(`| lowWatermark | ${recommendation.recommended.lowWatermark} |`);
  lines.push(`| maxRefillInFlight | ${recommendation.recommended.maxRefillInFlight} |`);
  lines.push('');
  lines.push('Rationale:');
  lines.push('');
  for (const reason of recommendation.reasons) {
    lines.push(`- ${reason}`);
  }

  lines.push('');
  lines.push('## Notes');
  lines.push('');
  lines.push('- Use this report to justify changes in `client/src/core/config/defaultConfigs.ts`.');
  lines.push('- Keep route-level and presign-step perf logs enabled in benchmark runs.');
  lines.push('- Re-run benchmarks after any live-cache/store-path change.');

  return lines.join('\n');
}
