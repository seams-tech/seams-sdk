#!/usr/bin/env node
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { buildMarkdownReport } from './report.mjs';
import {
  SCENARIOS,
  resolveScenarioById,
  resolveScenarioCommand,
  resolveScenarioIdsByGroup,
} from './scenarios.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const MODULE_ROOT = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(MODULE_ROOT, '..', '..');
const SUMMARY_MARKER = '@@REGISTRATION_FLOW_SUMMARY@@';

function parseArgs(argv) {
  const args = {
    scenarios: [],
    groups: [],
    outDir: path.join(MODULE_ROOT, 'out'),
    docsOutput: path.join(REPO_ROOT, 'docs', 'benchmarks', 'registration-flow.md'),
    syncDocs: true,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--scenario' && argv[index + 1]) {
      args.scenarios.push(String(argv[++index]));
      continue;
    }
    if (token === '--group' && argv[index + 1]) {
      args.groups.push(String(argv[++index]));
      continue;
    }
    if (token === '--out-dir' && argv[index + 1]) {
      args.outDir = path.resolve(String(argv[++index]));
      continue;
    }
    if (token === '--docs-output' && argv[index + 1]) {
      args.docsOutput = path.resolve(String(argv[++index]));
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
  const now = new Date();
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(now.getUTCDate()).padStart(2, '0');
  const hh = String(now.getUTCHours()).padStart(2, '0');
  const min = String(now.getUTCMinutes()).padStart(2, '0');
  const ss = String(now.getUTCSeconds()).padStart(2, '0');
  return `${yyyy}${mm}${dd}-${hh}${min}${ss}Z`;
}

async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
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

function extractScenarioSummary(stdout) {
  const lines = String(stdout || '')
    .split(/\r?\n/)
    .reverse();
  for (const line of lines) {
    const markerIndex = line.indexOf(SUMMARY_MARKER);
    if (markerIndex < 0) continue;
    return JSON.parse(line.slice(markerIndex + SUMMARY_MARKER.length));
  }
  return null;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const selectedScenarioIds = Array.from(
    new Set(
      args.scenarios.length > 0
        ? args.scenarios
        : args.groups.length > 0
          ? args.groups.flatMap((group) => resolveScenarioIdsByGroup(group))
          : SCENARIOS.map((entry) => entry.id),
    ),
  );
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
        id: scenarioId,
        status: 'error',
        error: `No command configured for scenario ${scenarioId}`,
      });
      continue;
    }

    const execution = await runCommand(command, REPO_ROOT);
    const logPath = path.join(runOutDir, `${scenarioId}.log`);
    await fs.writeFile(
      logPath,
      [execution.stdout.trimEnd(), execution.stderr.trimEnd()].filter(Boolean).join('\n'),
      'utf8',
    );

    let summary = null;
    try {
      summary = extractScenarioSummary(execution.stdout);
    } catch (error) {
      results.push({
        id: scenarioId,
        status: 'error',
        command,
        logPath,
        error: `Failed to parse scenario summary: ${String(error?.message || error)}`,
      });
      continue;
    }

    if (execution.code !== 0 && summary) {
      results.push({
        id: scenarioId,
        status: 'failed',
        command,
        logPath,
        summary,
        error: `Scenario command exited with code ${execution.code}`,
      });
      continue;
    }

    if (execution.code !== 0) {
      results.push({
        id: scenarioId,
        status: 'error',
        command,
        logPath,
        error: `Scenario command exited with code ${execution.code}`,
      });
      continue;
    }

    if (!summary) {
      results.push({
        id: scenarioId,
        status: 'error',
        command,
        logPath,
        error: 'Scenario completed without a summary marker',
      });
      continue;
    }

    results.push({
      id: scenarioId,
      status: 'ok',
      command,
      logPath,
      summary,
    });
  }

  const rawSummary = {
    reportVersion: 'registration_flow_benchmark_v1',
    runId,
    generatedAtIso: new Date().toISOString(),
    results,
  };
  const summaryJsonPath = path.join(runOutDir, 'raw-summary.json');
  const summaryMarkdownPath = path.join(runOutDir, 'summary.md');
  await fs.writeFile(summaryJsonPath, JSON.stringify(rawSummary, null, 2), 'utf8');

  const markdown = buildMarkdownReport(rawSummary);
  await fs.writeFile(summaryMarkdownPath, `${markdown}\n`, 'utf8');
  if (args.syncDocs) {
    await ensureDir(path.dirname(args.docsOutput));
    await fs.writeFile(args.docsOutput, `${markdown}\n`, 'utf8');
  }

  const okCount = results.filter((entry) => entry.status === 'ok').length;
  const failedCount = results.filter((entry) => entry.status === 'failed').length;
  const errorCount = results.filter((entry) => entry.status === 'error').length;
  console.log(`[benchmark] run_id=${runId}`);
  console.log(`[benchmark] output_dir=${runOutDir}`);
  console.log(`[benchmark] summary_json=${summaryJsonPath}`);
  console.log(`[benchmark] summary_markdown=${summaryMarkdownPath}`);
  if (args.syncDocs) {
    console.log(`[benchmark] docs_synced=${args.docsOutput}`);
  }
  console.log(
    `[benchmark] scenarios_ok=${okCount} scenarios_failed=${failedCount} scenarios_error=${errorCount}`,
  );

  if (failedCount > 0 || errorCount > 0) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
