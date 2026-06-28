import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ts from 'typescript';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const cloudflareRuntimeRoots = [
  'packages/sdk-server-ts/src/router/cloudflare-adaptor.ts',
  ...listTypeScriptFiles('packages/sdk-server-ts/src/router/cloudflare'),
].filter(isRuntimeSourceFile);

const routerAbLocalDevScriptRoot = 'crates/router-ab-dev/scripts';
const ciWorkflowPath = '.github/workflows/ci.yml';
const sdkServerTsconfigPath = 'packages/sdk-server-ts/tsconfig.json';

const forbiddenCloudflarePostgresEnvTokens = [
  'POSTGRES_URL',
  'CONSOLE_POSTGRES_URL',
  'POSTGRES_MIGRATION_URL',
  'CONSOLE_POSTGRES_MIGRATION_URL',
  'BILLING_POSTGRES_URL',
  'RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL',
  'WEBHOOK_RETRY_POSTGRES_URL',
] as const;

const legacyRouteCapabilityFlagPatterns = [
  {
    pattern: /\bemailRecovery\s*:\s*\{\s*enabled\b/,
    message: 'uses the old emailRecovery enabled flag instead of structural route services',
  },
  {
    pattern: /\bed25519RegistrationPrepare\s*:\s*\{\s*enabled\b/,
    message:
      'uses the old ed25519RegistrationPrepare enabled flag instead of structural route services',
  },
  {
    pattern: /\bsigningSessionSeal\s*:\s*\{[^}]*\benabled\b/s,
    message: 'uses the old signingSessionSeal enabled flag instead of structural route services',
  },
] as const;

const forbiddenRouterAbLocalPostgresPatterns = [
  {
    pattern: /\bPOSTGRES_URL\b/,
    message: 'uses POSTGRES_URL instead of current SQLite/D1/DO local seed tooling',
  },
  {
    pattern: /\bthreshold_ed25519_keys\b/,
    message: 'writes the removed partial Postgres Ed25519 key-store table',
  },
  {
    pattern: /\bthreshold_wallet_session_(?:budget_reservations|consumptions)\b/,
    message: 'writes the removed partial Postgres wallet-session tables',
  },
] as const;

const forbiddenCiPostgresPatterns = [
  {
    pattern: /\brelay-server-postgres-split-smoke\b/,
    message: 'defines the removed split-domain Postgres smoke job',
  },
  {
    pattern: /\bpostgres:setup:split\b/,
    message: 'runs the removed web-server Postgres setup script',
  },
  {
    pattern: /\bpostgres:down\b/,
    message: 'runs the removed web-server Postgres teardown script',
  },
  {
    pattern: /\bPOSTGRES_URL\b/,
    message: 'exports Postgres env for current CI jobs',
  },
  {
    pattern: /\bCONSOLE_POSTGRES_URL\b/,
    message: 'exports console Postgres env for current CI jobs',
  },
  {
    pattern: /\bpostgres:\s*\n\s*image:\s*postgres:/,
    message: 'starts a Postgres service for current CI jobs',
  },
] as const;

const forbiddenSdkServerTsconfigPostgresPatterns = [
  {
    pattern: /"pg"/,
    message: 'adds pg to sdk-server TypeScript ambient types or path aliases',
  },
  {
    pattern: /@types\/pg/,
    message: 'resolves the removed pg type package from sdk-server TypeScript config',
  },
] as const;

const sharedD1HelperPath = 'packages/sdk-server-ts/src/storage/d1Sql.ts';
const sharedSqliteD1TestHelperPath = 'tests/helpers/sqliteD1.ts';
const cloudflareD1ConsoleServicesPath =
  'packages/sdk-server-ts/src/router/cloudflare/d1ConsoleServices.ts';
const cloudflareD1ConsoleStagingWorkerPath =
  'packages/sdk-server-ts/src/router/cloudflare/d1ConsoleStagingWorker.ts';
const cloudflareD1RelayStagingWorkerPath =
  'packages/sdk-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts';
const oldCloudflareD1RouterApiStagingWorkerPath =
  'packages/sdk-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts';
const activeRouterApiDocPaths = [
  'packages/sdk-server-ts/src/README.md',
  'packages/sdk-server-ts/README.md',
  'docs/saas/bring-you-own-auth.md',
] as const;

const forbiddenLocalD1HelperPatterns = [
  {
    pattern: /\bfunction\s+parseD1RecordJson\b/,
    message: 'defines a local D1 JSON record parser instead of parseD1JsonColumn',
  },
  {
    pattern: /\bfunction\s+(?:d1Changes|toD1Changes|runChanges|changedRows)\b/,
    message: 'defines a local D1 mutation-count helper instead of d1ChangedRows',
  },
  {
    pattern: /\bfunction\s+(?:isD1DatabaseLike|resolveD1DatabaseFromConfig)\b/,
    message: 'defines a local D1 database resolver instead of the shared d1Sql helper',
  },
] as const;

const forbiddenSqliteD1HarnessDuplicationPatterns = [
  {
    pattern: /\bclass\s+SqliteCliD1Database\b/,
    message: 'defines a local SQLite-D1 database harness instead of tests/helpers/sqliteD1',
  },
  {
    pattern: /\bclass\s+SqliteCliD1PreparedStatement\b/,
    message: 'defines a local SQLite-D1 statement harness instead of tests/helpers/sqliteD1',
  },
  {
    pattern: /\bfunction\s+createTemporaryD1Database\b/,
    message: 'defines a local temporary D1 database helper instead of tests/helpers/sqliteD1',
  },
  {
    pattern: /\bfunction\s+cleanupTemporaryD1Database\b/,
    message: 'defines a local temporary D1 cleanup helper instead of tests/helpers/sqliteD1',
  },
  {
    pattern: /\bfunction\s+interpolateSql\b/,
    message: 'defines local D1 SQL interpolation instead of tests/helpers/sqliteD1',
  },
  {
    pattern: /\bspawnSync\(\s*['"]sqlite3['"]/,
    message: 'shells out to sqlite3 instead of using tests/helpers/sqliteD1',
  },
  {
    pattern: /\bfunction\s+applyMigrations\b/,
    message: 'defines a local D1 migration applicator instead of tests/helpers/sqliteD1',
  },
  {
    pattern: /packages\/sdk-server-ts\/migrations\/d1-/,
    message: 'hard-codes D1 migration paths instead of using tests/helpers/sqliteD1',
  },
] as const;

const forbiddenSdkServerPostgresRuntimePatterns = [
  {
    pattern: /\bfrom\s+['"]pg['"]/,
    message: 'imports pg at runtime',
  },
  {
    pattern: /\bimport\s*\(\s*['"]pg['"]\s*\)/,
    message: 'imports pg dynamically at runtime',
  },
  {
    pattern: /\bnew\s+Pool\b/,
    message: 'constructs a Postgres pool',
  },
  {
    pattern: /\bgetPostgresPool\b/,
    message: 'uses the removed Postgres pool helper',
  },
  {
    pattern: /\bcreatePostgres[A-Za-z0-9_]*Service\b/,
    message: 'exposes a live partial Postgres service factory',
  },
  {
    pattern: /\bpostgresRecords\b/,
    message: 'uses removed Postgres record helpers',
  },
] as const;

const coreOrchestrationPortOnlyFiles = [
  'packages/sdk-server-ts/src/core/AuthService.ts',
  'packages/sdk-server-ts/src/core/SessionService.ts',
  'packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts',
  'packages/sdk-server-ts/src/core/ThresholdService/createThresholdSigningService.ts',
  'packages/sdk-server-ts/src/core/ThresholdService/signingHandlers.ts',
  'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPoolFillHandlers.ts',
  'packages/sdk-server-ts/src/core/ThresholdService/routerAb/ecdsaHssPresignBridge.ts',
] as const;

const forbiddenCoreOrchestrationPersistencePatterns = [
  {
    pattern: /\bfrom\s+['"](?:\.\.\/)+storage\//,
    message: 'imports storage-layer modules instead of domain-store ports',
  },
  {
    pattern: /\bD1(?:Database|PreparedStatement|Result)Like\b/,
    message: 'mentions raw D1 binding or statement types',
  },
  {
    pattern: /\bCloudflareDurableObject(?:Namespace|Stub)Like\b/,
    message: 'mentions raw Durable Object binding or stub types',
  },
  {
    pattern: /\bTenantStorageRoute\b/,
    message: 'depends on tenant-route resolution instead of injected domain stores',
  },
  {
    pattern: /\bresolveD1DatabaseFromConfig\b/,
    message: 'resolves D1 databases inside core orchestration',
  },
  {
    pattern: /\b(?:CONSOLE_DB|SIGNER_DB|THRESHOLD_STORE)\b/,
    message: 'mentions Cloudflare binding names inside core orchestration',
  },
  {
    pattern: /\.\s*(?:prepare|batch|exec)\s*\(/,
    message: 'calls raw database methods inside core orchestration',
  },
] as const;

function isRuntimeSourceFile(relativePath: string): boolean {
  return !relativePath.endsWith('.typecheck.ts');
}

function toRepoPath(absolutePath: string): string {
  return path.relative(repoRoot, absolutePath).split(path.sep).join('/');
}

function toAbsolutePath(relativePath: string): string {
  return path.join(repoRoot, relativePath);
}

function listTypeScriptFiles(relativeDir: string): string[] {
  const absoluteDir = toAbsolutePath(relativeDir);
  const files: string[] = [];
  for (const entry of fs.readdirSync(absoluteDir, { withFileTypes: true })) {
    const relativePath = `${relativeDir}/${entry.name}`;
    if (entry.isDirectory()) {
      files.push(...listTypeScriptFiles(relativePath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.ts')) files.push(relativePath);
  }
  return files.sort();
}

function listJavaScriptFiles(relativeDir: string): string[] {
  const absoluteDir = toAbsolutePath(relativeDir);
  const files: string[] = [];
  for (const entry of fs.readdirSync(absoluteDir, { withFileTypes: true })) {
    const relativePath = `${relativeDir}/${entry.name}`;
    if (entry.isDirectory()) {
      files.push(...listJavaScriptFiles(relativePath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.mjs')) files.push(relativePath);
  }
  return files.sort();
}

function listRouterRuntimeFiles(): string[] {
  return listTypeScriptFiles('packages/sdk-server-ts/src/router').filter(isRuntimeSourceFile);
}

function readSource(relativePath: string): string {
  return fs.readFileSync(toAbsolutePath(relativePath), 'utf8');
}

function parseSource(relativePath: string): ts.SourceFile {
  return ts.createSourceFile(relativePath, readSource(relativePath), ts.ScriptTarget.Latest, true);
}

function lineNumber(sourceFile: ts.SourceFile, node: ts.Node): number {
  return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
}

function importHasRuntimeBinding(node: ts.ImportDeclaration): boolean {
  const clause = node.importClause;
  if (!clause) return true;
  if (clause.isTypeOnly) return false;
  if (clause.name) return true;
  const namedBindings = clause.namedBindings;
  if (!namedBindings) return true;
  if (ts.isNamespaceImport(namedBindings)) return true;
  for (const element of namedBindings.elements) {
    if (!element.isTypeOnly) return true;
  }
  return false;
}

function exportHasRuntimeBinding(node: ts.ExportDeclaration): boolean {
  if (node.isTypeOnly) return false;
  const clause = node.exportClause;
  if (!clause) return true;
  if (ts.isNamespaceExport(clause)) return true;
  for (const element of clause.elements) {
    if (!element.isTypeOnly) return true;
  }
  return false;
}

function moduleSpecifierText(node: ts.ImportDeclaration | ts.ExportDeclaration): string | null {
  const specifier = node.moduleSpecifier;
  if (!specifier || !ts.isStringLiteral(specifier)) return null;
  return specifier.text;
}

function dynamicImportSpecifierText(node: ts.Node): string | null {
  if (!ts.isCallExpression(node)) return null;
  if (node.expression.kind !== ts.SyntaxKind.ImportKeyword) return null;
  const [specifier] = node.arguments;
  if (!specifier || !ts.isStringLiteral(specifier)) return null;
  return specifier.text;
}

type RuntimeDependency = {
  importer: string;
  line: number;
  specifier: string;
  resolved: string | null;
};

function runtimeDependencies(relativePath: string): RuntimeDependency[] {
  const sourceFile = parseSource(relativePath);
  const deps: RuntimeDependency[] = [];
  for (const statement of sourceFile.statements) {
    if (ts.isImportDeclaration(statement)) {
      if (!importHasRuntimeBinding(statement)) continue;
      const specifier = moduleSpecifierText(statement);
      if (!specifier) continue;
      deps.push({
        importer: relativePath,
        line: lineNumber(sourceFile, statement),
        specifier,
        resolved: resolveRelativeModule(relativePath, specifier),
      });
      continue;
    }
    if (ts.isExportDeclaration(statement)) {
      if (!exportHasRuntimeBinding(statement)) continue;
      const specifier = moduleSpecifierText(statement);
      if (!specifier) continue;
      deps.push({
        importer: relativePath,
        line: lineNumber(sourceFile, statement),
        specifier,
        resolved: resolveRelativeModule(relativePath, specifier),
      });
    }
  }
  deps.push(...dynamicImportDependencies(sourceFile, relativePath));
  return deps;
}

function dynamicImportDependencies(
  sourceFile: ts.SourceFile,
  relativePath: string,
): RuntimeDependency[] {
  const deps: RuntimeDependency[] = [];
  const stack: ts.Node[] = [sourceFile];
  while (stack.length > 0) {
    const node = stack.pop();
    if (!node) continue;
    const specifier = dynamicImportSpecifierText(node);
    if (specifier) {
      deps.push({
        importer: relativePath,
        line: lineNumber(sourceFile, node),
        specifier,
        resolved: resolveRelativeModule(relativePath, specifier),
      });
    }
    const children = node.getChildren(sourceFile);
    for (let i = children.length - 1; i >= 0; i -= 1) {
      stack.push(children[i]);
    }
  }
  return deps;
}

function resolveRelativeModule(importer: string, specifier: string): string | null {
  if (!specifier.startsWith('.')) return null;
  const importerDir = path.dirname(toAbsolutePath(importer));
  const basePath = path.resolve(importerDir, specifier);
  const candidates = [
    `${basePath}.ts`,
    `${basePath}.tsx`,
    path.join(basePath, 'index.ts'),
    path.join(basePath, 'index.tsx'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return toRepoPath(candidate);
  }
  return null;
}

function forbiddenRuntimeReason(resolvedPath: string): string | null {
  if (resolvedPath === 'packages/sdk-server-ts/src/storage/postgres.ts') {
    return 'imports the Postgres storage driver';
  }
  if (/^packages\/sdk-server-ts\/src\/console\/shared\/postgres.*\.ts$/.test(resolvedPath)) {
    return 'imports a console Postgres shared helper';
  }
  if (resolvedPath === 'packages/sdk-server-ts/src/threshold/session/signingSessionSeal/index.ts') {
    return 'imports the mixed session-seal barrel instead of Cloudflare runtime leaf modules';
  }
  if (/^packages\/sdk-server-ts\/src\/console\/[^/]+\/index\.ts$/.test(resolvedPath)) {
    return 'imports a mixed console barrel instead of leaf modules';
  }
  if (/^packages\/sdk-server-ts\/src\/console\/.*\/postgres\.ts$/.test(resolvedPath)) {
    return 'imports a console Postgres adapter';
  }
  return null;
}

function cloudflareRuntimeDependencyViolations(): string[] {
  const pending = [...cloudflareRuntimeRoots];
  const seen = new Set<string>();
  const violations: string[] = [];

  while (pending.length > 0) {
    const current = pending.pop();
    if (!current || seen.has(current)) continue;
    seen.add(current);

    for (const dependency of runtimeDependencies(current)) {
      const resolved = dependency.resolved;
      if (!resolved) continue;
      const reason = forbiddenRuntimeReason(resolved);
      if (reason) {
        violations.push(
          `${dependency.importer}:${dependency.line} ${dependency.specifier} -> ${resolved}: ${reason}`,
        );
      }
      if (resolved.startsWith('packages/sdk-server-ts/src/')) pending.push(resolved);
    }
  }

  return violations.sort();
}

function cloudflarePostgresEnvTokenViolations(): string[] {
  const violations: string[] = [];
  for (const relativePath of cloudflareRuntimeRoots) {
    const source = readSource(relativePath);
    for (const token of forbiddenCloudflarePostgresEnvTokens) {
      if (source.includes(token)) violations.push(`${relativePath} contains ${token}`);
    }
  }
  return violations.sort();
}

function legacyRouteCapabilityFlagViolations(): string[] {
  const violations: string[] = [];
  for (const relativePath of listRouterRuntimeFiles()) {
    const source = readSource(relativePath);
    for (const { pattern, message } of legacyRouteCapabilityFlagPatterns) {
      if (pattern.test(source)) violations.push(`${relativePath}: ${message}`);
    }
  }
  return violations.sort();
}

function routerAbLocalPostgresToolingViolations(): string[] {
  const violations: string[] = [];
  for (const relativePath of listJavaScriptFiles(routerAbLocalDevScriptRoot)) {
    const source = readSource(relativePath);
    for (const { pattern, message } of forbiddenRouterAbLocalPostgresPatterns) {
      if (pattern.test(source)) violations.push(`${relativePath}: ${message}`);
    }
  }
  return violations.sort();
}

function ciWorkflowPostgresSmokeViolations(): string[] {
  const violations: string[] = [];
  const source = readSource(ciWorkflowPath);
  for (const { pattern, message } of forbiddenCiPostgresPatterns) {
    if (pattern.test(source)) violations.push(`${ciWorkflowPath}: ${message}`);
  }
  return violations.sort();
}

function sdkServerTsconfigPostgresScaffoldingViolations(): string[] {
  const violations: string[] = [];
  const source = readSource(sdkServerTsconfigPath);
  for (const { pattern, message } of forbiddenSdkServerTsconfigPostgresPatterns) {
    if (pattern.test(source)) violations.push(`${sdkServerTsconfigPath}: ${message}`);
  }
  return violations.sort();
}

function staleRefactor82NameViolations(): string[] {
  const violations: string[] = [];
  if (fs.existsSync(toAbsolutePath(oldCloudflareD1RouterApiStagingWorkerPath))) {
    violations.push(`${oldCloudflareD1RouterApiStagingWorkerPath}: old relay staging Worker filename exists`);
  }
  for (const relativePath of [
    ...listTypeScriptFiles('packages/sdk-server-ts/src'),
    ...listTypeScriptFiles('packages/sdk-web/src'),
    ...listTypeScriptFiles('tests'),
    ...activeRouterApiDocPaths,
  ]) {
    if (relativePath === 'tests/unit/refactor82CloudflareD1Runtime.guard.unit.test.ts') {
      continue;
    }
    const source = readSource(relativePath);
    if (source.includes('d1RouterApiStagingWorker')) {
      violations.push(`${relativePath}: references old relay staging Worker filename`);
    }
    if (source.includes('routerApier')) {
      violations.push(`${relativePath}: references old routerApier typo path`);
    }
    if (source.includes('createRelayRouter')) {
      violations.push(`${relativePath}: references old createRelayRouter export name`);
    }
  }
  return violations.sort();
}

function localD1HelperDuplicationViolations(): string[] {
  const violations: string[] = [];
  for (const relativePath of listTypeScriptFiles('packages/sdk-server-ts/src')) {
    if (!isRuntimeSourceFile(relativePath) || relativePath === sharedD1HelperPath) continue;
    const source = readSource(relativePath);
    for (const { pattern, message } of forbiddenLocalD1HelperPatterns) {
      if (pattern.test(source)) violations.push(`${relativePath}: ${message}`);
    }
  }
  return violations.sort();
}

function sqliteD1HarnessDuplicationViolations(): string[] {
  const violations: string[] = [];
  for (const relativePath of listTypeScriptFiles('tests')) {
    if (relativePath === sharedSqliteD1TestHelperPath) continue;
    const source = readSource(relativePath);
    for (const { pattern, message } of forbiddenSqliteD1HarnessDuplicationPatterns) {
      if (pattern.test(source)) violations.push(`${relativePath}: ${message}`);
    }
  }
  return violations.sort();
}

function sdkServerRuntimePostgresImplementationViolations(): string[] {
  const violations: string[] = [];
  for (const relativePath of listTypeScriptFiles('packages/sdk-server-ts/src')) {
    if (!isRuntimeSourceFile(relativePath)) continue;
    if (path.basename(relativePath).toLowerCase().includes('postgres')) {
      violations.push(`${relativePath}: Postgres runtime implementation file exists`);
      continue;
    }
    const source = readSource(relativePath);
    for (const { pattern, message } of forbiddenSdkServerPostgresRuntimePatterns) {
      if (pattern.test(source)) violations.push(`${relativePath}: ${message}`);
    }
  }
  return violations.sort();
}

function coreOrchestrationPersistenceBoundaryViolations(): string[] {
  const violations: string[] = [];
  for (const relativePath of coreOrchestrationPortOnlyFiles) {
    const source = readSource(relativePath);
    for (const { pattern, message } of forbiddenCoreOrchestrationPersistencePatterns) {
      if (pattern.test(source)) violations.push(`${relativePath}: ${message}`);
    }
  }
  return violations.sort();
}

function sourceFunctionBody(relativePath: string, functionName: string): string | null {
  const source = readSource(relativePath);
  const startPattern = new RegExp(`export\\s+async\\s+function\\s+${functionName}\\s*\\(`);
  const startMatch = startPattern.exec(source);
  if (!startMatch) return null;
  const startIndex = startMatch.index;
  let braceIndex = source.indexOf('{', startIndex);
  if (braceIndex < 0) return null;
  let depth = 0;
  for (let index = braceIndex; index < source.length; index += 1) {
    const char = source[index];
    if (char === '{') depth += 1;
    if (char === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(startIndex, index + 1);
    }
  }
  return null;
}

function consoleOnlyStagingSignerCustodyViolations(): string[] {
  const functionName = 'createCloudflareD1ConsoleOnlyServiceBundle';
  const body = sourceFunctionBody(cloudflareD1ConsoleServicesPath, functionName);
  if (!body) return [`${cloudflareD1ConsoleServicesPath}: missing ${functionName}`];
  const forbidden = [
    'kekProvider',
    'signerMetadataDatabase',
    'thresholdStore',
    'createCloudflareD1TenantRouteResolver',
    'createCloudflareD1SigningRootSecretAdapters',
  ] as const;
  const violations: string[] = [];
  for (const token of forbidden) {
    if (body.includes(token)) {
      violations.push(`${cloudflareD1ConsoleServicesPath}: ${functionName} references ${token}`);
    }
  }
  return violations.sort();
}

function consoleStagingWorkerSignerCustodyViolations(): string[] {
  const source = readSource(cloudflareD1ConsoleStagingWorkerPath);
  const forbidden = [
    'SIGNER_DB',
    'THRESHOLD_STORE',
    'kekProvider',
    'createCloudflareD1ConsoleServiceBundle',
    'createCloudflareSecretsStoreKekProviderFromEnv',
  ] as const;
  const violations: string[] = [];
  for (const token of forbidden) {
    if (source.includes(token)) {
      violations.push(`${cloudflareD1ConsoleStagingWorkerPath}: references ${token}`);
    }
  }
  return violations.sort();
}

function relayStagingWorkerSignerCustodyViolations(): string[] {
  const source = readSource(cloudflareD1RelayStagingWorkerPath);
  const required = [
    'SIGNER_DB',
    'THRESHOLD_STORE',
    'createCloudflareSecretsStoreKekProviderFromEnv',
    'resolveSponsoredEvmWorkerExecutionAdapter',
  ] as const;
  const violations: string[] = [];
  for (const token of required) {
    if (!source.includes(token)) {
      violations.push(`${cloudflareD1RelayStagingWorkerPath}: missing ${token}`);
    }
  }
  return violations.sort();
}

test('Cloudflare router runtime graph stays D1/DO-only at persistence boundaries', () => {
  const violations = cloudflareRuntimeDependencyViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('Cloudflare Worker env shape does not expose Postgres cron fallbacks', () => {
  const violations = cloudflarePostgresEnvTokenViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('Router API route capabilities are selected by structural services, not enabled flags', () => {
  const violations = legacyRouteCapabilityFlagViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('router-ab local dev scripts do not revive partial Postgres seed tooling', () => {
  const violations = routerAbLocalPostgresToolingViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('CI does not revive removed Postgres staging smoke jobs', () => {
  const violations = ciWorkflowPostgresSmokeViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('sdk-server TypeScript config does not revive pg compiler scaffolding', () => {
  const violations = sdkServerTsconfigPostgresScaffoldingViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 82 stale staging and relayer names stay deleted', () => {
  const violations = staleRefactor82NameViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('D1 persistence helpers stay centralized at the storage boundary', () => {
  const violations = localD1HelperDuplicationViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('SQLite-backed D1 test harness stays centralized', () => {
  const violations = sqliteD1HarnessDuplicationViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('Postgres escape hatch remains a typed contract without sdk-server runtime adapters', () => {
  const violations = sdkServerRuntimePostgresImplementationViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('core orchestration receives domain-store ports instead of raw persistence bindings', () => {
  const violations = coreOrchestrationPersistenceBoundaryViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('console-only Cloudflare D1 staging factory does not receive signer custody bindings', () => {
  const violations = consoleOnlyStagingSignerCustodyViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('console staging Worker stays isolated from signer custody bindings', () => {
  const violations = consoleStagingWorkerSignerCustodyViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('relay staging Worker owns signer custody and sponsored EVM bindings', () => {
  const violations = relayStagingWorkerSignerCustodyViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});
