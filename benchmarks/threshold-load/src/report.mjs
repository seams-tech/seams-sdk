import { SCENARIOS } from './scenarios.mjs';

function fmtNum(value, decimals = 2) {
  if (value == null || !Number.isFinite(value)) return 'n/a';
  return Number(value).toFixed(decimals);
}

function fmtPct(value) {
  if (value == null || !Number.isFinite(value)) return 'n/a';
  return `${(Number(value) * 100).toFixed(1)}%`;
}

function scenarioDescription(id) {
  return SCENARIOS.find((entry) => entry.id === id)?.description || id;
}

function appendStatsTable(lines, title, stats) {
  if (!stats || !Number.isFinite(stats.count) || stats.count <= 0) return;
  lines.push(`#### ${title}`);
  lines.push('');
  lines.push('| Metric | Count | p50 | p95 | p99 | Mean | Max |');
  lines.push('|---|---:|---:|---:|---:|---:|---:|');
  lines.push(
    `| ${title} | ${fmtNum(stats.count, 0)} | ${fmtNum(stats.p50)} | ${fmtNum(stats.p95)} | ${fmtNum(stats.p99)} | ${fmtNum(stats.mean)} | ${fmtNum(stats.max)} |`,
  );
  lines.push('');
}

function appendRouteTable(lines, routeDurations) {
  const routes = Object.keys(routeDurations || {}).sort();
  if (!routes.length) return;
  lines.push('| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |');
  lines.push('|---|---:|---:|---:|---:|---:|---:|');
  for (const route of routes) {
    const stats = routeDurations[route];
    lines.push(
      `| \`${route}\` | ${fmtNum(stats?.count, 0)} | ${fmtNum(stats?.p50)} | ${fmtNum(stats?.p95)} | ${fmtNum(stats?.p99)} | ${fmtNum(stats?.mean)} | ${fmtNum(stats?.max)} |`,
    );
  }
  lines.push('');
}

function appendCountMap(lines, title, values) {
  const entries = Object.entries(values || {}).sort(([left], [right]) => left.localeCompare(right));
  if (!entries.length) return;
  lines.push(`#### ${title}`);
  lines.push('');
  lines.push('| Value | Count |');
  lines.push('|---|---:|');
  for (const [value, count] of entries) {
    lines.push(`| \`${value}\` | ${fmtNum(count, 0)} |`);
  }
  lines.push('');
}

export function buildMarkdownReport(input) {
  const lines = [];
  lines.push('# Threshold Load Report');
  lines.push('');
  lines.push(`Generated: ${input.generatedAtIso}`);
  lines.push(`Run ID: \`${input.runId}\``);
  lines.push('');
  lines.push('## Scenario Summary');
  lines.push('');
  lines.push('| Scenario | Description | Status | Success Rate | Signs/sec | Sign p95 (ms) |');
  lines.push('|---|---|---|---:|---:|---:|');
  for (const result of input.results) {
    const summary = result.summary;
    lines.push(
      `| \`${result.id}\` | ${scenarioDescription(result.id)} | ${result.status} | ${fmtPct(summary?.signing?.successRate)} | ${fmtNum(summary?.signing?.throughputSignsPerSec)} | ${fmtNum(summary?.signing?.endToEndMs?.p95)} |`,
    );
  }
  lines.push('');

  for (const result of input.results) {
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
    lines.push(`- Profile: ${summary.profile}`);
    lines.push(`- Wallets: ${summary.wallets}`);
    lines.push(`- Signs per wallet: ${summary.signsPerWallet}`);
    lines.push(`- Max concurrency: ${summary.maxConcurrency}`);
    lines.push(`- Bootstrap duration (ms): ${fmtNum(summary.bootstrap?.durationMs)}`);
    lines.push(`- Signing duration (ms): ${fmtNum(summary.signing?.durationMs)}`);
    lines.push(`- Total attempts: ${fmtNum(summary.signing?.totalAttempts, 0)}`);
    lines.push(`- Total success: ${fmtNum(summary.signing?.totalSuccess, 0)}`);
    lines.push(`- Total failure: ${fmtNum(summary.signing?.totalFailure, 0)}`);
    lines.push(`- Success rate: ${fmtPct(summary.signing?.successRate)}`);
    lines.push(`- Throughput (signs/sec): ${fmtNum(summary.signing?.throughputSignsPerSec)}`);
    if (summary.presign) {
      lines.push(`- Presign mode: ${summary.presign.mode}`);
      lines.push(
        `- Presign accepted during measured run: ${fmtNum(summary.presign.acceptedDuringMeasuredRun, 0)}`,
      );
      lines.push(
        `- Presign rejected during measured run: ${fmtNum(summary.presign.rejectedDuringMeasuredRun, 0)}`,
      );
      lines.push(`- Presign pool hits: ${fmtNum(summary.presign.poolHits, 0)}`);
      if (summary.presign.setup) {
        lines.push(`- Presign setup accepted: ${fmtNum(summary.presign.setup.accepted, 0)}`);
        lines.push(`- Presign setup rejected: ${fmtNum(summary.presign.setup.rejected, 0)}`);
      }
    }
    lines.push('');

    appendStatsTable(lines, 'Bootstrap Session Mint', summary.bootstrap?.sessionMintMs);
    appendStatsTable(lines, 'Presign Setup', summary.presign?.setup?.endToEndMs);
    appendStatsTable(lines, 'End-to-End Sign', summary.signing?.endToEndMs);

    lines.push('### Bootstrap Routes');
    lines.push('');
    appendRouteTable(lines, summary.bootstrap?.routeDurations || {});

    if (summary.presign?.setup) {
      lines.push('### Presign Setup Routes');
      lines.push('');
      appendRouteTable(lines, summary.presign.setup.routeDurations || {});
    }

    lines.push('### Signing Routes');
    lines.push('');
    appendRouteTable(lines, summary.signing?.routeDurations || {});

    appendCountMap(
      lines,
      'Presign Double-Consume Rejection Codes',
      summary.presign?.doubleConsumeRejectedCodes,
    );

    lines.push('### System');
    lines.push('');
    lines.push('| Metric | Value |');
    lines.push('|---|---:|');
    lines.push(`| cpuUserMsTotal | ${fmtNum(summary.system?.cpuUserMsTotal)} |`);
    lines.push(`| cpuSystemMsTotal | ${fmtNum(summary.system?.cpuSystemMsTotal)} |`);
    lines.push(`| rssMb p95 | ${fmtNum(summary.system?.rssMb?.p95)} |`);
    lines.push(`| rssMb max | ${fmtNum(summary.system?.rssMb?.max)} |`);
    lines.push(`| heapUsedMb p95 | ${fmtNum(summary.system?.heapUsedMb?.p95)} |`);
    lines.push(`| heapUsedMb max | ${fmtNum(summary.system?.heapUsedMb?.max)} |`);
    lines.push(`| eventLoopDelayMs p95 | ${fmtNum(summary.system?.eventLoopDelayMs?.p95)} |`);
    lines.push(`| eventLoopDelayMs max | ${fmtNum(summary.system?.eventLoopDelayMs?.max)} |`);
    lines.push('');
  }

  lines.push('## Notes');
  lines.push('');
  lines.push('- Current coverage is threshold-ed25519 warm-session local 2-party only.');
  lines.push(
    '- The actor provisions canonical single-key material directly, then measures the kept warm signing and presign paths.',
  );
  lines.push(
    '- ECDSA, multi-node routing, backend comparison, and relayer-cosigner topologies remain follow-on work.',
  );

  return lines.join('\n');
}
