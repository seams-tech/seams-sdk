import baseConfig from './playwright.config';

const unitSourceGuardIgnorePatterns = [
  '**/unit/**/*.guard.unit.test.ts',
  '**/unit/**/*.behavior.guard.unit.test.ts',
  '**/unit/**/*.domain.guard.unit.test.ts',
  '**/unit/**/*.guards.test.ts',
  '**/unit/**/*.guardrails.unit.test.ts',
  '**/unit/**/*.script.unit.test.ts',
  '**/unit/**/*.source.script.unit.test.ts',
];

function isExplicitUnitGuardTestArg(arg: string): boolean {
  const normalized = arg.replace(/\\/g, '/');
  const isUnitFile =
    normalized.startsWith('unit/') ||
    normalized.startsWith('./unit/') ||
    normalized.includes('/unit/');
  if (!isUnitFile) return false;
  return [
    '.guard.unit.test.ts',
    '.behavior.guard.unit.test.ts',
    '.domain.guard.unit.test.ts',
    '.guards.test.ts',
    '.guardrails.unit.test.ts',
    '.script.unit.test.ts',
    '.source.script.unit.test.ts',
  ].some((suffix) => normalized.endsWith(suffix));
}

function hasExplicitUnitGuardTestArg(argv: readonly string[]): boolean {
  return argv.some(isExplicitUnitGuardTestArg);
}

// A module-load failure in any unit test file aborts Playwright's collection
// phase: nothing runs, and the only output is a bare `SyntaxError` that is easy
// to mistake for a warning. `./reporters/failOnCollectionErrors` turns that into
// an explicit failure naming the broken files, and refuses to report success for
// a run that collected zero tests. Keep it last so it prints after `line`'s
// summary.
//
// Playwright's CLI `--reporter=...` REPLACES this list rather than extending it,
// which would silently drop the guard. `line` is declared here precisely so that
// unit-suite commands no longer need to pass `--reporter=line`.
const unitReporters: Array<[string]> = [['line'], ['./reporters/failOnCollectionErrors.ts']];

export default {
  ...baseConfig,
  reporter: unitReporters,
  testMatch: ['**/unit/**/*.test.ts'],
  testIgnore: hasExplicitUnitGuardTestArg(process.argv)
    ? ['**/unit/**/*.integration.test.ts']
    : [...unitSourceGuardIgnorePatterns, '**/unit/**/*.integration.test.ts'],
};
