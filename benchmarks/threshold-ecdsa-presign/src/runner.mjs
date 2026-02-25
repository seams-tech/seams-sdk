#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { collectMetricsFromLog } from './collectors.mjs';
import { buildMarkdownReport } from './report.mjs';
import { SCENARIOS, resolveScenarioById, resolveScenarioCommand } from './scenarios.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const MODULE_ROOT = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(MODULE_ROOT, '..', '..');

function readFiniteEnvNumber(name, fallback, min = -Infinity, max = Infinity, env = process.env) {
  const raw = String(env[name] || '').trim();
  if (!raw) return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return fallback;
  if (parsed < min || parsed > max) return fallback;
  return parsed;
}

function buildSloConfig(env = process.env) {
  return {
    enabled: String(env.BENCH_SLO_DISABLE || '').trim() !== '1',
    firstSignP95Ms: readFiniteEnvNumber('BENCH_SLO_FIRST_SIGN_P95_MS', 4000, 1, 120_000, env),
    warmSignP95Ms: readFiniteEnvNumber('BENCH_SLO_WARM_SIGN_P95_MS', 1500, 1, 120_000, env),
    presignStepP95Ms: readFiniteEnvNumber('BENCH_SLO_PRESIGN_STEP_P95_MS', 900, 1, 60_000, env),
    presignStepP99Ms: readFiniteEnvNumber('BENCH_SLO_PRESIGN_STEP_P99_MS', 1300, 1, 60_000, env),
    replayFallbackRatioMax: readFiniteEnvNumber('BENCH_SLO_REPLAY_FALLBACK_RATIO_MAX', 0.01, 0, 1, env),
  };
}

function maxFinite(values) {
  const nums = values.filter((value) => Number.isFinite(value));
  if (nums.length === 0) return null;
  return Math.max(...nums);
}

function evaluateSlo(results, config) {
  const checks = [];
  const okResults = results.filter((entry) => entry.status === 'ok');
  const byId = new Map(okResults.map((entry) => [entry.id, entry]));

  const pushCheck = (input) => {
    if (!config.enabled) {
      checks.push({
        name: input.name,
        status: 'skipped',
        actual: null,
        threshold: input.threshold,
        comparator: input.comparator,
        reason: 'SLO gate disabled',
      });
      return;
    }
    if (!Number.isFinite(input.actual)) {
      checks.push({
        name: input.name,
        status: 'skipped',
        actual: null,
        threshold: input.threshold,
        comparator: input.comparator,
        reason: input.missingReason || 'Metric unavailable for this run',
      });
      return;
    }
    const pass = input.comparator === '<='
      ? input.actual <= input.threshold
      : input.actual >= input.threshold;
    checks.push({
      name: input.name,
      status: pass ? 'pass' : 'fail',
      actual: input.actual,
      threshold: input.threshold,
      comparator: input.comparator,
      reason: pass ? undefined : input.failReason,
    });
  };

  const coldScenario = byId.get('cold_first_sign_no_pool');
  pushCheck({
    name: 'first_sign_p95_ms',
    actual: coldScenario?.metrics?.scenarioTotalMs?.p95,
    threshold: config.firstSignP95Ms,
    comparator: '<=',
    missingReason: '`cold_first_sign_no_pool` was not executed',
    failReason: 'Cold first-sign p95 exceeded threshold',
  });

  const warmScenario = byId.get('warm_sign_pool_hit');
  pushCheck({
    name: 'warm_sign_p95_ms',
    actual: warmScenario?.metrics?.scenarioTotalMs?.p95,
    threshold: config.warmSignP95Ms,
    comparator: '<=',
    missingReason: '`warm_sign_pool_hit` was not executed',
    failReason: 'Warm-sign p95 exceeded threshold',
  });

  const nonFallbackScenarios = okResults.filter((entry) => entry.id !== 'replay_fallback_path');
  pushCheck({
    name: 'presign_step_p95_ms',
    actual: maxFinite(nonFallbackScenarios.map((entry) => entry.metrics?.routeDurations?.['/threshold-ecdsa/presign/step']?.p95)),
    threshold: config.presignStepP95Ms,
    comparator: '<=',
    missingReason: 'No `/threshold-ecdsa/presign/step` p95 values were collected',
    failReason: 'Max `/threshold-ecdsa/presign/step` p95 exceeded threshold',
  });

  pushCheck({
    name: 'presign_step_p99_ms',
    actual: maxFinite(nonFallbackScenarios.map((entry) => entry.metrics?.routeDurations?.['/threshold-ecdsa/presign/step']?.p99)),
    threshold: config.presignStepP99Ms,
    comparator: '<=',
    missingReason: 'No `/threshold-ecdsa/presign/step` p99 values were collected',
    failReason: 'Max `/threshold-ecdsa/presign/step` p99 exceeded threshold',
  });

  pushCheck({
    name: 'replay_fallback_ratio_nonfallback_max',
    actual: maxFinite(nonFallbackScenarios.map((entry) => entry.metrics?.presignStepPerf?.replayFallbackRatio)),
    threshold: config.replayFallbackRatioMax,
    comparator: '<=',
    missingReason: 'No replay fallback ratios were collected',
    failReason: 'Replay fallback ratio appeared in non-fallback scenarios',
  });

  const failedCount = checks.filter((entry) => entry.status === 'fail').length;
  const passedCount = checks.filter((entry) => entry.status === 'pass').length;
  const skippedCount = checks.filter((entry) => entry.status === 'skipped').length;
  return {
    enabled: config.enabled,
    config,
    checks,
    failedCount,
    passedCount,
    skippedCount,
  };
}

function parseArgs(argv) {
  const args = {
    scenarios: [],
    inputs: [],
    outDir: path.join(MODULE_ROOT, 'out'),
    docsOutput: path.join(REPO_ROOT, 'docs', 'benchmarks', 'threshold-ecdsa-presign.md'),
    syncDocs: true,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--scenario' && argv[i + 1]) {
      args.scenarios.push(String(argv[++i]));
      continue;
    }
    if (token === '--input' && argv[i + 1]) {
      args.inputs.push(String(argv[++i]));
      continue;
    }
    if (token === '--out-dir' && argv[i + 1]) {
      args.outDir = path.resolve(String(argv[++i]));
      continue;
    }
    if (token === '--docs-output' && argv[i + 1]) {
      args.docsOutput = path.resolve(String(argv[++i]));
      continue;
    }
    if (token === '--skip-doc-sync') {
      args.syncDocs = false;
      continue;
    }
  }
  return args;
}

function tsRunId() {
  const d = new Date();
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const min = String(d.getUTCMinutes()).padStart(2, '0');
  const ss = String(d.getUTCSeconds()).padStart(2, '0');
  return `${yyyy}${mm}${dd}-${hh}${min}${ss}Z`;
}

function parseInputArg(rawInput) {
  const token = String(rawInput || '').trim();
  if (!token) return null;
  const idx = token.indexOf('=');
  if (idx <= 0) {
    const basename = path.basename(token).replace(/\.[^.]+$/, '') || 'manual_input';
    return { id: basename, file: path.resolve(token) };
  }
  const id = token.slice(0, idx).trim();
  const file = token.slice(idx + 1).trim();
  if (!id || !file) return null;
  return { id, file: path.resolve(file) };
}

async function runCommand(command, cwd) {
  return await new Promise((resolve) => {
    const child = spawn(command, {
      cwd,
      shell: true,
      env: process.env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
    });
    child.on('close', (code) => {
      resolve({ code: Number(code || 0), stdout, stderr });
    });
  });
}

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const selectedScenarioIds = args.scenarios.length > 0
    ? args.scenarios
    : SCENARIOS.map((entry) => entry.id);
  const runId = tsRunId();
  const runOutDir = path.join(args.outDir, runId);
  await ensureDir(runOutDir);

  const results = [];

  for (const scenarioId of selectedScenarioIds) {
    const scenario = resolveScenarioById(scenarioId);
    if (!scenario) {
      results.push({
        id: scenarioId,
        status: 'error',
        error: `Unknown scenario id: ${scenarioId}`,
      });
      continue;
    }
    const command = resolveScenarioCommand(scenario);
    if (!command) {
      results.push({
        id: scenario.id,
        status: 'skipped',
        error: `Missing scenario command env: ${scenario.commandEnv}`,
      });
      continue;
    }

    const executed = await runCommand(command, REPO_ROOT);
    const combined = `${executed.stdout}\n${executed.stderr}`.trim();
    const logPath = path.join(runOutDir, `${scenario.id}.log`);
    await fs.writeFile(logPath, `${combined}\n`, 'utf8');

    if (executed.code !== 0) {
      results.push({
        id: scenario.id,
        status: 'error',
        command,
        logPath,
        error: `Scenario command exited with code ${executed.code}`,
      });
      continue;
    }

    results.push({
      id: scenario.id,
      status: 'ok',
      command,
      logPath,
      metrics: collectMetricsFromLog(combined),
    });
  }

  for (const inputToken of args.inputs) {
    const parsed = parseInputArg(inputToken);
    if (!parsed) {
      results.push({
        id: 'manual_input',
        status: 'error',
        error: `Invalid --input format: ${inputToken}`,
      });
      continue;
    }
    try {
      const logText = await fs.readFile(parsed.file, 'utf8');
      results.push({
        id: parsed.id,
        status: 'ok',
        command: `ingest:${parsed.file}`,
        logPath: parsed.file,
        metrics: collectMetricsFromLog(logText),
      });
    } catch (error) {
      results.push({
        id: parsed.id,
        status: 'error',
        error: `Failed to read input log: ${String(error instanceof Error ? error.message : error)}`,
      });
    }
  }

  const generatedAtIso = new Date().toISOString();
  const sloConfig = buildSloConfig();
  const slo = evaluateSlo(results, sloConfig);
  const summary = {
    runId,
    generatedAtIso,
    results,
    slo,
  };
  const markdown = buildMarkdownReport(summary);

  const rawSummaryPath = path.join(runOutDir, 'raw-summary.json');
  const markdownPath = path.join(runOutDir, 'summary.md');
  await fs.writeFile(rawSummaryPath, JSON.stringify(summary, null, 2), 'utf8');
  await fs.writeFile(markdownPath, `${markdown}\n`, 'utf8');

  if (args.syncDocs) {
    await ensureDir(path.dirname(args.docsOutput));
    await fs.writeFile(args.docsOutput, `${markdown}\n`, 'utf8');
  }

  const okCount = results.filter((entry) => entry.status === 'ok').length;
  const errCount = results.filter((entry) => entry.status === 'error').length;
  const skipCount = results.filter((entry) => entry.status === 'skipped').length;

  console.log(`[benchmark] run_id=${runId}`);
  console.log(`[benchmark] output_dir=${runOutDir}`);
  console.log(`[benchmark] summary_json=${rawSummaryPath}`);
  console.log(`[benchmark] summary_markdown=${markdownPath}`);
  if (args.syncDocs) console.log(`[benchmark] docs_synced=${args.docsOutput}`);
  console.log(`[benchmark] scenarios_ok=${okCount} scenarios_error=${errCount} scenarios_skipped=${skipCount}`);
  console.log(`[benchmark] slo_enabled=${slo.enabled} slo_passed=${slo.passedCount} slo_failed=${slo.failedCount} slo_skipped=${slo.skippedCount}`);
  if (slo.enabled && slo.failedCount > 0) {
    for (const check of slo.checks.filter((entry) => entry.status === 'fail')) {
      console.error(`[benchmark][slo][fail] ${check.name}: actual=${check.actual} ${check.comparator} threshold=${check.threshold} (${check.reason || 'failed'})`);
    }
  }

  if (errCount > 0 || (slo.enabled && slo.failedCount > 0)) process.exitCode = 1;
}

main().catch((error) => {
  console.error('[benchmark] fatal', error);
  process.exitCode = 1;
});
