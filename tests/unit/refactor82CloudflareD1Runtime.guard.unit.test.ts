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

const forbiddenCloudflarePostgresEnvTokens = [
  'BILLING_POSTGRES_URL',
  'RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL',
  'WEBHOOK_RETRY_POSTGRES_URL',
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
  if (resolvedPath === 'packages/sdk-server-ts/src/console/shared/postgresTenantContext.ts') {
    return 'imports Postgres tenant transaction context';
  }
  if (resolvedPath === 'packages/sdk-server-ts/src/threshold/session/signingSessionSeal/index.ts') {
    return 'imports the session-seal barrel that re-exports Postgres idempotency backends';
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

test('Cloudflare router runtime graph stays D1/DO-only at persistence boundaries', () => {
  const violations = cloudflareRuntimeDependencyViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});

test('Cloudflare Worker env shape does not expose Postgres cron fallbacks', () => {
  const violations = cloudflarePostgresEnvTokenViolations();
  expect(violations, violations.join('\n')).toEqual([]);
});
