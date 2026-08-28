#!/usr/bin/env node
import { rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const testsRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const listCasesOnly = process.argv.includes('--list-cases');
const selectionArgs = process.argv
  .slice(2)
  .filter((arg) => arg !== '--' && arg !== '--list-cases');
const childEnvironment = {
  ...process.env,
  SEAMS_LINKED_DEVICE_E2E: '1',
};

const listed = runPnpmCapture([
  'exec',
  'playwright',
  'test',
  '-c',
  'playwright.intended.config.ts',
  '--list',
  '--reporter=json',
  ...selectionArgs,
]);
const report = parseJsonReport(listed);
const cases = collectCases(report.suites);
if (cases.length === 0) throw new Error('The intended E2E selection did not match any cases');

if (listCasesOnly) {
  console.log(`[intended-isolated] selected ${cases.length} isolated case(s)`);
  for (const testCase of cases) {
    console.log(`${testCase.file}:${String(testCase.line)} ${testCase.title}`);
  }
} else {
  console.log(`[intended-isolated] running ${cases.length} case(s) with fresh managed D1 state`);
  for (const [index, testCase] of cases.entries()) {
    runCase(testCase, index, cases.length);
  }
}

function runCase(testCase, index, total) {
  runPnpmInherited(['run', 'ensure:intended-google-token'], childEnvironment);
  const caseNumber = index + 1;
  const caseRoot = path.join(
    tmpdir(),
    `seams-sdk-intended-${String(process.pid)}-${String(caseNumber)}`,
  );
  const viteCacheDir = path.join(caseRoot, 'vite-cache');
  const environment = {
    ...childEnvironment,
    SEAMS_INTENDED_ROUTER_AB_ROOT: caseRoot,
    SEAMS_INTENDED_SITE_VITE_CACHE_DIR: viteCacheDir,
    ...(index > 0 ? { SEAMS_INTENDED_SKIP_BUILD: '1' } : {}),
  };
  const exactTitle = `${escapeRegex(testCase.title)}$`;
  console.log(
    `[intended-isolated] ${String(caseNumber)}/${String(total)} ${testCase.file}:${String(testCase.line)} ${testCase.title}`,
  );
  try {
    runPnpmInherited(
      [
        'exec',
        'playwright',
        'test',
        '-c',
        'playwright.intended.ci.config.ts',
        testCase.file,
        '--grep',
        exactTitle,
        '--reporter=line',
      ],
      environment,
    );
  } finally {
    rmSync(caseRoot, { recursive: true, force: true });
  }
}

function collectCases(suites, parentTitles = [], depth = 0) {
  if (!Array.isArray(suites)) return [];
  const cases = [];
  for (const suite of suites) {
    const suiteTitle = typeof suite?.title === 'string' ? suite.title.trim() : '';
    const titles = depth === 0 || !suiteTitle ? parentTitles : [...parentTitles, suiteTitle];
    if (Array.isArray(suite?.specs)) {
      for (const spec of suite.specs) {
        const title = typeof spec?.title === 'string' ? spec.title.trim() : '';
        const file = typeof spec?.file === 'string' ? spec.file.trim() : '';
        const line = Number(spec?.line);
        if (!title || !file || !Number.isSafeInteger(line) || line <= 0) continue;
        cases.push({
          file,
          line,
          title: [...titles, title].join(' '),
        });
      }
    }
    cases.push(...collectCases(suite?.suites, titles, depth + 1));
  }
  return cases;
}

function parseJsonReport(stdout) {
  try {
    return JSON.parse(stdout);
  } catch (error) {
    throw new Error('Playwright --list did not return a valid JSON report', { cause: error });
  }
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function runPnpmCapture(args) {
  const result = spawnSync('pnpm', args, {
    cwd: testsRoot,
    env: childEnvironment,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.status === 0) return result.stdout;
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  throw new Error(`pnpm ${args.join(' ')} exited with ${String(result.status ?? 'unknown')}`);
}

function runPnpmInherited(args, environment) {
  const result = spawnSync('pnpm', args, {
    cwd: testsRoot,
    env: environment,
    stdio: 'inherit',
  });
  if (result.status === 0) return;
  throw new Error(`pnpm ${args.join(' ')} exited with ${String(result.status ?? 'unknown')}`);
}
