#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function check(_label, callback) {
  callback();
}

function expect(received, message = '') {
  return {
    toBe(expected) {
      assert.equal(received, expected, message);
    },
    toBeTruthy() {
      assert.ok(received, message || `Expected value to be truthy`);
    },
    toEqual(expected) {
      assert.deepEqual(received, expected, message);
    },
  };
}

const FORBIDDEN_PATTERNS = [
  {
    id: 'wallet-near-fallback',
    regex: /\bwalletId[ \t]*(?:\|\||\?\?)[ \t]*nearAccountId\b/g,
  },
  {
    id: 'record-wallet-near-fallback',
    regex: /\brecord\.walletId\s*\?\?\s*record\.nearAccountId\b/g,
  },
  {
    id: 'wallet-id-from-near-profile-fallback',
    regex: /\binput\.walletId\s*\|\|\s*buildNearProfileId\(/g,
  },
  {
    id: 'login-challenge-user-id-from-near-account',
    regex: /\buserId:\s*String\(nearAccountId\)/g,
  },
  {
    id: 'wallet-id-from-to-account-id',
    regex: /\bwalletId:\s*String\(toAccountId\(/g,
  },
  {
    id: 'ed25519-session-wallet-id-legacy-migration',
    regex: /\bmigratedWalletIdRaw\b/g,
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

const FORBIDDEN_UNIT_FIXTURE_PATTERNS = [
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
];

const OPTIONAL_CORE_IDENTITY_FIELD_PATTERN = {
  id: 'core-optional-identity-field',
  regex: /\b(?:walletId|nearAccountId|nearEd25519SigningKeyId|walletSession)\?:/g,
};

const BOUNDARY_EXEMPTIONS = [
  {
    file: 'packages/shared-ts/src/utils/registrationIntent.ts',
    pattern: 'as-ed25519-key-scope',
    reason: 'shared domain parser constructs NearEd25519SigningKeyId after validation',
  },
  {
    file: 'packages/shared-ts/src/utils/walletCapabilityBindings.ts',
    pattern: 'inline-near-account-binding',
    reason: 'shared capability builder constructs NearAccountBinding branches from typed inputs',
  },
  {
    file: 'packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget.ts',
    pattern: 'core-optional-identity-field',
    reason: 'boundary parser accepts raw wallet-session values before normalizing to WalletSessionRef',
  },
];

function currentRepoRoot() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
}

function toPosixRelative(root, filePath) {
  return path.relative(root, filePath).split(path.sep).join('/');
}

function listSourceFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
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

function loadAllowlist(root) {
  const allowlistPath = path.join(
    root,
    'tests/unit/walletCapabilityBindings.sourceGuard.allowlist.json',
  );
  if (fs.existsSync(allowlistPath)) {
    throw new Error(
      'walletCapabilityBindings.sourceGuard.allowlist.json is retired; use typed boundaries or built-in boundary exemptions',
    );
  }
  return { allow: [] };
}

function assertAllowlistEntriesAreDocumented(allowlist) {
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
  allowlist,
  file,
  pattern,
) {
  return [...allowlist.allow, ...BOUNDARY_EXEMPTIONS].some(
    (entry) => entry.file === file && entry.pattern === pattern.id,
  );
}

function allowlistEntryKey(entry) {
  return `${entry.file}\0${entry.pattern}`;
}

function allowlistPatternKey(file, pattern) {
  return `${file}\0${pattern.id}`;
}

function collectPatternMatchKeys(args) {
  const matches = new Set();
  for (const sourceFile of args.files) {
    const relativePath = toPosixRelative(args.root, sourceFile);
    const source = fs.readFileSync(sourceFile, 'utf8');
    for (const pattern of args.patterns) {
      const regex = new RegExp(pattern.regex.source, 'g');
      if (regex.test(source)) {
        matches.add(allowlistPatternKey(relativePath, pattern));
      }
    }
  }
  return matches;
}

function collectPatternViolations(args) {
  const violations = [];
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

function collectOptionalCoreIdentityFieldMatchKeys(args) {
  const matches = new Set();
  for (const sourceFile of args.files) {
    const relativePath = toPosixRelative(args.root, sourceFile);
    const source = fs.readFileSync(sourceFile, 'utf8');
    const lines = source.split(/\r?\n/);
    for (const line of lines) {
      if (!OPTIONAL_CORE_IDENTITY_FIELD_PATTERN.regex.test(line)) continue;
      OPTIONAL_CORE_IDENTITY_FIELD_PATTERN.regex.lastIndex = 0;
      if (line.includes('?: never')) continue;
      matches.add(allowlistPatternKey(relativePath, OPTIONAL_CORE_IDENTITY_FIELD_PATTERN));
      break;
    }
  }
  return matches;
}

function collectOptionalCoreIdentityFieldViolations(args) {
  const violations = [];
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

check('wallet capability binding source guard blocks identity fallback patterns', () => {
  const root = currentRepoRoot();
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

check('wallet capability binding source guard rejects stale allowlist entries', () => {
  const root = currentRepoRoot();
  const allowlist = loadAllowlist(root);
  assertAllowlistEntriesAreDocumented(allowlist);
  const sourceFiles = [
    path.join(root, 'packages/shared-ts/src'),
    path.join(root, 'packages/sdk-server-ts/src'),
    path.join(root, 'packages/sdk-web/src'),
  ].flatMap(listSourceFiles);
  const coreSourceFiles = CORE_COMMAND_IDENTITY_GUARD_DIRS.flatMap((dir) =>
    listSourceFiles(path.join(root, dir)),
  );

  const usedAllowlistKeys = new Set([
    ...collectPatternMatchKeys({
      root,
      files: sourceFiles,
      patterns: FORBIDDEN_PATTERNS,
    }),
    ...collectOptionalCoreIdentityFieldMatchKeys({
      root,
      files: coreSourceFiles,
    }),
  ]);
  const staleEntries = allowlist.allow
    .filter((entry) => !usedAllowlistKeys.has(allowlistEntryKey(entry)))
    .map((entry) => `${entry.file}: ${entry.pattern}`);

  expect(staleEntries).toEqual([]);
});

check('wallet capability binding source guard uses every built-in boundary exemption', () => {
  const root = currentRepoRoot();
  const sourceFiles = [
    path.join(root, 'packages/shared-ts/src'),
    path.join(root, 'packages/sdk-server-ts/src'),
    path.join(root, 'packages/sdk-web/src'),
  ].flatMap(listSourceFiles);
  const coreSourceFiles = CORE_COMMAND_IDENTITY_GUARD_DIRS.flatMap((dir) =>
    listSourceFiles(path.join(root, dir)),
  );

  const usedExemptionKeys = new Set([
    ...collectPatternMatchKeys({
      root,
      files: sourceFiles,
      patterns: FORBIDDEN_PATTERNS,
    }),
    ...collectOptionalCoreIdentityFieldMatchKeys({
      root,
      files: coreSourceFiles,
    }),
  ]);
  const staleExemptions = BOUNDARY_EXEMPTIONS.filter(
    (entry) => !usedExemptionKeys.has(allowlistEntryKey(entry)),
  ).map((entry) => `${entry.file}: ${entry.pattern}`);

  expect(staleExemptions).toEqual([]);
});

check('wallet capability binding source guard blocks stale unit session fixtures', () => {
  const root = currentRepoRoot();
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

check('wallet capability binding source guard blocks optional identity in core commands', () => {
  const root = currentRepoRoot();
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

console.log('[check-wallet-capability-bindings-source-guard] passed');
