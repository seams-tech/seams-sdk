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

export default {
  ...baseConfig,
  testMatch: ['**/unit/**/*.test.ts'],
  testIgnore: hasExplicitUnitGuardTestArg(process.argv)
    ? ['**/unit/**/*.integration.test.ts']
    : [...unitSourceGuardIgnorePatterns, '**/unit/**/*.integration.test.ts'],
};
