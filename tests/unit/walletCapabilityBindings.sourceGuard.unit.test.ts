import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

type ForbiddenPattern = {
  id: string;
  regex: RegExp;
};

type SourceGuardAllowEntry = {
  file: string;
  pattern: string;
  reason: string;
  disposition: string;
};

type SourceGuardAllowlist = {
  allow: SourceGuardAllowEntry[];
};

const FORBIDDEN_PATTERNS: ForbiddenPattern[] = [
  { id: 'wallet-near-fallback', regex: /\bwalletId\s*(?:\|\||\?\?)\s*nearAccountId\b/g },
  {
    id: 'record-wallet-near-fallback',
    regex: /\brecord\.walletId\s*\?\?\s*record\.nearAccountId\b/g,
  },
  { id: 'to-wallet-id-from-near-account', regex: /\btoWalletId\(nearAccountId\)/g },
  {
    id: 'to-wallet-id-from-near-account-expression',
    regex: /\btoWalletId\([^)]*nearAccountId[^)]*\)/g,
  },
  { id: 'wallet-id-from-near-account', regex: /\bwalletId:\s*nearAccountId\b/g },
  { id: 'wallet-id-from-account-id', regex: /\bwalletId:\s*accountId\b/g },
  { id: 'account-id-from-wallet-id', regex: /\baccountId:\s*walletId\b/g },
  {
    id: 'ed25519-scope-near-fallback',
    regex: /\bnearEd25519SigningKeyId\s*(?:\|\||\?\?)\s*nearAccountId\b/g,
  },
  {
    id: 'ed25519-scope-from-near-account',
    regex: /\bnearEd25519SigningKeyId:\s*nearAccountId\b/g,
  },
  {
    id: 'ed25519-scope-from-wallet-id',
    regex: /\bnearEd25519SigningKeyId:\s*walletId\b/g,
  },
  {
    id: 'legacy-ed25519-key-scope-id',
    regex: /\bed25519KeyScopeId\b/g,
  },
  {
    id: 'legacy-ed25519-key-scope-type',
    regex: /\bEd25519KeyScopeId\b/g,
  },
  {
    id: 'legacy-ed25519-key-scope-snake',
    regex: /\bed25519_key_scope\b/g,
  },
  { id: 'args-wallet-near-fallback', regex: /\bargs\.walletId\s*\|\|\s*nearAccountId\b/g },
  {
    id: 'wallet-session-near-fallback',
    regex: /\bwalletSession\.walletId\s*\|\|\s*nearAccountId\b/g,
  },
  {
    id: 'get-wallet-session-by-account-id',
    regex: /\bgetWalletSession\([^)]*(?:nearAccountId|accountId)[^)]*\)/g,
  },
  {
    id: 'inline-current-auth-method-none',
    regex: /\bcurrentAuthMethod:\s*\{\s*kind:\s*['"]none['"]\s*\},/g,
  },
  {
    id: 'inline-current-auth-method-selected',
    regex: /\bcurrentAuthMethod:\s*\{\s*kind:\s*['"]selected['"][\s\S]*?\},/g,
  },
  {
    id: 'inline-near-account-binding',
    regex:
      /\{\s*(?:readonly\s+)?kind:\s*['"](?:implicit_near_account|named_near_account)['"][\s\S]*?\bnearAccountId:/g,
  },
  { id: 'as-wallet-id', regex: /\bas WalletId\b/g },
  { id: 'as-ed25519-key-scope', regex: /\bas NearEd25519SigningKeyId\b/g },
];

const FORBIDDEN_UNIT_FIXTURE_PATTERNS: ForbiddenPattern[] = [
  {
    id: 'unit-get-wallet-session-by-account-id',
    regex: /\bgetWalletSession\([^)]*(?:nearAccountId|accountId)[^)]*\)/g,
  },
];

const CORE_COMMAND_IDENTITY_GUARD_DIRS = [
  'packages/sdk-web/src/core/signingEngine/flows/signNear',
  'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily',
  'packages/sdk-web/src/core/signingEngine/flows/recovery',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp',
  'packages/sdk-web/src/core/signingEngine/session/passkey',
  'packages/sdk-web/src/core/signingEngine/interfaces',
] as const;

const OPTIONAL_CORE_IDENTITY_FIELD_PATTERN: ForbiddenPattern = {
  id: 'core-optional-identity-field',
  regex: /\b(?:walletId|nearAccountId|nearEd25519SigningKeyId|walletSession)\?:/g,
};

function repoRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
}

function toPosixRelative(root: string, filePath: string): string {
  return path.relative(root, filePath).split(path.sep).join('/');
}

function listSourceFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    if (entry.name === 'dist' || entry.name === 'node_modules') continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listSourceFiles(fullPath));
      continue;
    }
    if (!entry.name.endsWith('.ts') && !entry.name.endsWith('.tsx')) continue;
    if (entry.name.endsWith('.typecheck.ts')) continue;
    files.push(fullPath);
  }
  return files;
}

function loadAllowlist(root: string): SourceGuardAllowlist {
  const allowlistPath = path.join(
    root,
    'tests/unit/walletCapabilityBindings.sourceGuard.allowlist.json',
  );
  return JSON.parse(fs.readFileSync(allowlistPath, 'utf8')) as SourceGuardAllowlist;
}

function assertAllowlistEntriesAreDocumented(allowlist: SourceGuardAllowlist): void {
  for (const entry of allowlist.allow) {
    expect(entry.file, 'allowlist file is required').toBeTruthy();
    expect(entry.pattern, `allowlist pattern is required for ${entry.file}`).toBeTruthy();
    expect(entry.reason, `allowlist reason is required for ${entry.file}:${entry.pattern}`)
      .toBeTruthy();
    expect(
      /^(permanent-boundary|remove-with[^:]*|owned-by-refactor-79):/.test(entry.disposition),
      `allowlist disposition must describe retention/removal ownership for ${entry.file}:${entry.pattern}`,
    ).toBe(true);
  }
}

function isAllowed(
  allowlist: SourceGuardAllowlist,
  file: string,
  pattern: ForbiddenPattern,
): boolean {
  return allowlist.allow.some((entry) => entry.file === file && entry.pattern === pattern.id);
}

function collectPatternViolations(args: {
  root: string;
  files: string[];
  patterns: readonly ForbiddenPattern[];
  allowlist?: SourceGuardAllowlist;
}): string[] {
  const violations: string[] = [];
  for (const sourceFile of args.files) {
    const relativePath = toPosixRelative(args.root, sourceFile);
    const source = fs.readFileSync(sourceFile, 'utf8');
    for (const pattern of args.patterns) {
      const regex = new RegExp(pattern.regex.source, 'g');
      if (!regex.test(source)) continue;
      if (args.allowlist && isAllowed(args.allowlist, relativePath, pattern)) continue;
      violations.push(`${relativePath}: ${pattern.id}`);
    }
  }
  return violations;
}

function collectOptionalCoreIdentityFieldViolations(args: {
  root: string;
  files: string[];
  allowlist: SourceGuardAllowlist;
}): string[] {
  const violations: string[] = [];
  for (const sourceFile of args.files) {
    const relativePath = toPosixRelative(args.root, sourceFile);
    const source = fs.readFileSync(sourceFile, 'utf8');
    const lines = source.split(/\r?\n/);
    lines.forEach((line, index) => {
      if (!OPTIONAL_CORE_IDENTITY_FIELD_PATTERN.regex.test(line)) return;
      OPTIONAL_CORE_IDENTITY_FIELD_PATTERN.regex.lastIndex = 0;
      if (line.includes('?: never')) return;
      if (isAllowed(args.allowlist, relativePath, OPTIONAL_CORE_IDENTITY_FIELD_PATTERN)) return;
      violations.push(
        `${relativePath}:${index + 1}: ${OPTIONAL_CORE_IDENTITY_FIELD_PATTERN.id}`,
      );
    });
  }
  return violations;
}

test('wallet capability binding source guard blocks identity fallback patterns', () => {
  const root = repoRoot();
  const allowlist = loadAllowlist(root);
  assertAllowlistEntriesAreDocumented(allowlist);
  const sourceFiles = [
    path.join(root, 'packages/shared-ts/src'),
    path.join(root, 'packages/sdk-server-ts/src'),
    path.join(root, 'packages/sdk-web/src'),
  ].flatMap(listSourceFiles);

  const violations = collectPatternViolations({
    root,
    files: sourceFiles,
    patterns: FORBIDDEN_PATTERNS,
    allowlist,
  });

  expect(violations).toEqual([]);
});

test('wallet capability binding source guard blocks stale unit session fixtures', () => {
  const root = repoRoot();
  const unitFiles = listSourceFiles(path.join(root, 'tests/unit')).filter(
    (file) =>
      toPosixRelative(root, file) !== 'tests/unit/walletCapabilityBindings.sourceGuard.unit.test.ts',
  );

  const violations = collectPatternViolations({
    root,
    files: unitFiles,
    patterns: FORBIDDEN_UNIT_FIXTURE_PATTERNS,
  });

  expect(violations).toEqual([]);
});

test('wallet capability binding source guard blocks optional identity in core commands', () => {
  const root = repoRoot();
  const allowlist = loadAllowlist(root);
  assertAllowlistEntriesAreDocumented(allowlist);
  const sourceFiles = CORE_COMMAND_IDENTITY_GUARD_DIRS.flatMap((dir) =>
    listSourceFiles(path.join(root, dir)),
  );

  const violations = collectOptionalCoreIdentityFieldViolations({
    root,
    files: sourceFiles,
    allowlist,
  });

  expect(violations).toEqual([]);
});
