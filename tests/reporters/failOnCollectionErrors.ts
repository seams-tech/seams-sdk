import type { FullConfig, FullResult, Reporter, Suite, TestError } from '@playwright/test/reporter';

/**
 * Guard reporter: a test file that fails to load must never be reported as a pass.
 *
 * Playwright surfaces module-load failures (missing exports, top-level throws in
 * fixtures) through `onError` and then aborts collection, so the run ends with
 * zero executed tests. Printed on their own those errors read like warnings, and
 * a suite that ran nothing looks indistinguishable from a suite that ran clean.
 * This reporter forces `status: 'failed'` and prints an explicit banner naming
 * every file that failed to load.
 *
 * NOTE: a CLI `--reporter=...` override replaces the reporters declared in the
 * config, which drops this guard. Keep unit-suite invocations reporter-free (or
 * append this reporter explicitly) so the guard stays wired in.
 */

const BANNER = '='.repeat(78);

function errorLocation(error: TestError): string | null {
  if (error.location?.file) {
    const line = error.location.line ? `:${error.location.line}` : '';
    return `${error.location.file}${line}`;
  }
  const stackFrame = String(error.stack || '')
    .split('\n')
    .map((line) => line.trim())
    .find((line) => line.startsWith('at ') && line.includes('/tests/'));
  return stackFrame ? stackFrame.replace(/^at\s+/, '') : null;
}

/**
 * ESM link errors ("does not provide an export named 'x'") carry no stack and no
 * location, so Playwright cannot say which file imported the missing symbol.
 * Hand the reader the grep that finds it.
 */
function importerHint(message: string): string | null {
  const missingExport = /does not provide an export named '([^']+)'/.exec(message);
  if (!missingExport) return null;
  return `importer: grep -rn "${missingExport[1]}" tests/`;
}

function errorSummary(error: TestError): string {
  const message = String(error.message || error.value || 'unknown error').split('\n')[0];
  const details = [errorLocation(error), importerHint(message)].filter((detail): detail is string =>
    Boolean(detail),
  );
  return [message, ...details.map((detail) => `      ${detail}`)].join('\n');
}

export default class FailOnCollectionErrors implements Reporter {
  private readonly collectionErrors: TestError[] = [];
  private collectedTests = 0;
  private label = 'test run';

  printsToStdio(): boolean {
    return true;
  }

  onBegin(config: FullConfig, suite: Suite): void {
    this.collectedTests = suite.allTests().length;
    const configFile = config.configFile ? config.configFile.split('/').pop() : null;
    if (configFile) this.label = configFile;
  }

  onError(error: TestError): void {
    this.collectionErrors.push(error);
  }

  async onEnd(result: FullResult): Promise<{ status: FullResult['status'] } | void> {
    const hasCollectionErrors = this.collectionErrors.length > 0;
    const ranNothing = this.collectedTests === 0;
    if (!hasCollectionErrors && !ranNothing) return;

    const lines: string[] = ['', BANNER];
    if (hasCollectionErrors) {
      lines.push(
        `[collection-guard] ${this.collectionErrors.length} error(s) outside of any test while loading ${this.label}.`,
        '[collection-guard] Playwright aborts the run when a test file fails to load, so the',
        '[collection-guard] tests in every matched file were skipped, not passed.',
        '',
      );
      this.collectionErrors.forEach((error, index) => {
        lines.push(`  ${index + 1}. ${errorSummary(error)}`);
      });
      lines.push('');
    }
    if (ranNothing) {
      lines.push(
        `[collection-guard] 0 tests were collected for ${this.label}; refusing to report success.`,
        '',
      );
    }
    lines.push(
      `[collection-guard] Failing the run (reported status: ${result.status}).`,
      BANNER,
      '',
    );
    process.stdout.write(lines.join('\n'));

    return { status: 'failed' };
  }
}
