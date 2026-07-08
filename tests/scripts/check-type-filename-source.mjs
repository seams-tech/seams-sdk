#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ts from 'typescript';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');

const sourceRoots = [
  'packages/sdk-server-ts/src',
  'packages/sdk-web/src',
  'packages/shared-ts/src',
  'tests',
];

const allowedTypesTsFiles = new Set([
  'packages/console-server-ts/src/account/types.ts',
  'packages/console-server-ts/src/apiKeys/types.ts',
  'packages/console-server-ts/src/approvals/types.ts',
  'packages/console-server-ts/src/audit/types.ts',
  'packages/console-server-ts/src/auditExports/types.ts',
  'packages/console-server-ts/src/billing/types.ts',
  'packages/console-server-ts/src/billingPrepaidReservations/types.ts',
  'packages/console-server-ts/src/bootstrapTokens/types.ts',
  'packages/console-server-ts/src/enterpriseIsolation/types.ts',
  'packages/console-server-ts/src/gasSponsorship/types.ts',
  'packages/console-server-ts/src/keyExports/types.ts',
  'packages/console-server-ts/src/observability/types.ts',
  'packages/console-server-ts/src/onboarding/types.ts',
  'packages/console-server-ts/src/orgProjectEnv/types.ts',
  'packages/console-server-ts/src/policies/types.ts',
  'packages/console-server-ts/src/runtimeSnapshots/types.ts',
  'packages/console-server-ts/src/sponsoredCalls/types.ts',
  'packages/console-server-ts/src/sponsorshipSpendCaps/types.ts',
  'packages/console-server-ts/src/teamRbac/types.ts',
  'packages/console-server-ts/src/wallets/types.ts',
  'packages/console-server-ts/src/webhooks/types.ts',
  'packages/sdk-server-ts/src/core/types.ts',
  'packages/sdk-server-ts/src/email-recovery/types.ts',
  'packages/sdk-web/src/SeamsWeb/publicApi/types.ts',
  'packages/sdk-web/src/SeamsWeb/signingSurface/types.ts',
  'packages/sdk-web/src/core/platform/types.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/types.ts',
  'packages/sdk-web/src/core/signingEngine/session/operationState/types.ts',
  'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.ts',
  'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types.ts',
  'packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/TxTree/renderers/types.ts',
  'packages/sdk-web/src/react/components/AccountMenuButton/types.ts',
  'packages/sdk-web/src/react/components/SeamsAuthMenu/types.ts',
  'packages/sdk-web/src/react/types.ts',
  'tests/setup/types.ts',
]);

function isSourceFile(relativePath) {
  return /\.(ts|tsx)$/.test(relativePath);
}

function shouldSkipDirectory(name) {
  return name === 'node_modules' || name === 'dist' || name === 'test-results';
}

function listSourceFiles(relativePath) {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) return isSourceFile(relativePath) ? [relativePath] : [];

  const files = [];
  for (const entry of fs.readdirSync(absolutePath, { withFileTypes: true })) {
    const childPath = path.join(relativePath, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) {
      if (shouldSkipDirectory(entry.name)) continue;
      files.push(...listSourceFiles(childPath));
      continue;
    }
    if (isSourceFile(childPath)) files.push(childPath);
  }
  return files;
}

function activeSourceFiles() {
  return sourceRoots.flatMap((root) => listSourceFiles(root)).sort();
}

function readSource(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function typeOnlyModuleViolationMessage(relativePath, source) {
  const sourceFile = ts.createSourceFile(relativePath, source, ts.ScriptTarget.Latest, true);
  for (const statement of sourceFile.statements) {
    const message = statementViolationMessage(sourceFile, statement);
    if (message) return `${relativePath}:${lineNumber(sourceFile, statement)} ${message}`;
  }
  return null;
}

function statementViolationMessage(sourceFile, statement) {
  if (ts.isImportDeclaration(statement)) return importDeclarationViolationMessage(statement);
  if (ts.isExportDeclaration(statement)) return exportDeclarationViolationMessage(statement);
  if (ts.isTypeAliasDeclaration(statement) || ts.isInterfaceDeclaration(statement)) return null;
  if (statement.kind === ts.SyntaxKind.EmptyStatement) return null;

  const text = statement.getText(sourceFile).split('\n')[0]?.trim() ?? '';
  return `contains executable or runtime statement ${statementKindName(statement)}: ${text}`;
}

function importDeclarationViolationMessage(statement) {
  if (!statement.importClause) return 'contains a side-effect import';
  if (!statement.importClause.isTypeOnly) return 'contains a value import';
  return null;
}

function exportDeclarationViolationMessage(statement) {
  if (exportDeclarationIsTypeOnly(statement)) return null;
  return 'contains a value export';
}

function exportDeclarationIsTypeOnly(statement) {
  if (statement.isTypeOnly) return true;
  if (allNamedExportsAreTypeOnly(statement)) return true;
  return false;
}

function allNamedExportsAreTypeOnly(statement) {
  if (!statement.exportClause || !ts.isNamedExports(statement.exportClause)) return false;
  for (const element of statement.exportClause.elements) {
    if (!element.isTypeOnly) return false;
  }
  return true;
}

function lineNumber(sourceFile, statement) {
  return sourceFile.getLineAndCharacterOfPosition(statement.getStart(sourceFile)).line + 1;
}

function statementKindName(statement) {
  if (ts.isVariableStatement(statement)) return 'VariableStatement';
  if (ts.isFunctionDeclaration(statement)) return 'FunctionDeclaration';
  if (ts.isClassDeclaration(statement)) return 'ClassDeclaration';
  if (ts.isEnumDeclaration(statement)) return 'EnumDeclaration';
  return ts.SyntaxKind[statement.kind];
}

function valueTypesReexportMessage(relativePath, source) {
  const sourceFile = ts.createSourceFile(relativePath, source, ts.ScriptTarget.Latest, true);
  for (const statement of sourceFile.statements) {
    if (!ts.isExportDeclaration(statement)) continue;
    if (!exportsTypesModule(statement)) continue;
    if (!exportDeclarationIsTypeOnly(statement)) {
      return `${relativePath} value-reexports a .types module`;
    }
  }
  return null;
}

function exportsTypesModule(statement) {
  const moduleSpecifier = statement.moduleSpecifier;
  if (!moduleSpecifier || !ts.isStringLiteral(moduleSpecifier)) return false;
  return moduleSpecifier.text.includes('.types');
}

function expectEqual(actual, expected, label) {
  if (actual === expected) return;
  throw new Error(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function runSelfCheck() {
  expectEqual(
    typeOnlyModuleViolationMessage('fixture.types.ts', 'const x = 1;\nexport type X = string;'),
    'fixture.types.ts:1 contains executable or runtime statement VariableStatement: const x = 1;',
    'type-only runtime statement self-check',
  );
  expectEqual(
    typeOnlyModuleViolationMessage('fixture.types.ts', 'import { Foo } from "./foo";'),
    'fixture.types.ts:1 contains a value import',
    'type-only value import self-check',
  );
  expectEqual(
    typeOnlyModuleViolationMessage(
      'fixture.types.ts',
      'export interface X {\n  value: string;\n}\n',
    ),
    null,
    'type-only interface self-check',
  );
  expectEqual(
    valueTypesReexportMessage('fixture.ts', "export type { Foo } from './foo.types';"),
    null,
    'type-only reexport self-check',
  );
  expectEqual(
    valueTypesReexportMessage('fixture.ts', "export { Foo } from './foo.types';"),
    'fixture.ts value-reexports a .types module',
    'value reexport self-check',
  );
}

function collectViolations() {
  const offenders = [];
  const files = activeSourceFiles();

  for (const file of files) {
    if (file.endsWith('.typings.ts')) offenders.push(`${file}: deprecated .typings.ts suffix`);
  }

  for (const file of files) {
    if (file.endsWith('/types.ts') && !allowedTypesTsFiles.has(file)) {
      offenders.push(`${file}: types.ts file is not in the approved inventory`);
    }
  }

  for (const file of allowedTypesTsFiles) {
    if (!fs.existsSync(path.join(repoRoot, file))) {
      offenders.push(`${file}: approved types.ts inventory entry no longer exists`);
    }
  }

  for (const file of files) {
    if (!file.endsWith('.types.ts')) continue;
    const message = typeOnlyModuleViolationMessage(file, readSource(file));
    if (message) offenders.push(message);
  }

  for (const file of files) {
    const message = valueTypesReexportMessage(file, readSource(file));
    if (message) offenders.push(message);
  }

  return offenders;
}

runSelfCheck();
const violations = collectViolations();
if (violations.length > 0) {
  console.error(`[type-filename-source] ${violations.length} violation(s)`);
  for (const violation of violations) console.error(violation);
  process.exitCode = 1;
} else {
  console.log('[type-filename-source] ok');
}
