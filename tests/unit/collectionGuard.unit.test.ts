import { expect, test } from '@playwright/test';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Regression guard for the unit suite's own failure mode.
 *
 * A test file that fails to load (missing export, top-level throw in a fixture)
 * aborts Playwright's collection phase: no tests run at all. Historically that
 * surfaced only as a bare `SyntaxError` line, which reads like a warning and is
 * trivial to scroll past. `reporters/failOnCollectionErrors.ts` is wired into
 * playwright.unit.config.ts to make that outcome an explicit failure; this test
 * pins the behaviour by running the guard over a two-file fixture suite.
 */

const TESTS_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURE_CONFIG = 'reporters/fixtures/collection-guard/playwright.fixture.config.ts';

type FixtureRun = { exitCode: number | null; output: string };

function runFixtureSuite(args: readonly string[]): Promise<FixtureRun> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      'npx',
      ['playwright', 'test', '-c', FIXTURE_CONFIG, ...args],
      { cwd: TESTS_ROOT, timeout: 120_000, maxBuffer: 8 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const output = `${stdout}${stderr}`;
        // execFile reports a non-zero exit through `error`; that is the expected path here.
        if (error && typeof error.code !== 'number') {
          reject(new Error(`failed to spawn playwright: ${error.message}\n${output}`));
          return;
        }
        resolve({ exitCode: child.exitCode, output });
      },
    );
  });
}

test.describe('unit suite collection guard', () => {
  test.setTimeout(180_000);

  test('a test file that fails to load fails the run instead of reporting success', async () => {
    const run = await runFixtureSuite([]);

    expect(run.exitCode).not.toBe(0);
    expect(run.output).toContain('[collection-guard]');
    expect(run.output).toContain('error(s) outside of any test');
    expect(run.output).toContain('refusing to report success');
    // The importer hint is what turns a bare link error into an actionable one.
    expect(run.output).toContain('grep -rn "absentExport" tests/');
  });

  test('a healthy file on its own passes without tripping the guard', async () => {
    const run = await runFixtureSuite(['healthy.spec.ts']);

    expect(run.exitCode).toBe(0);
    expect(run.output).not.toContain('[collection-guard]');
    expect(run.output).toContain('1 passed');
  });
});
