import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import * as ts from 'typescript';

type TypesTsClassification =
  | 'public-barrel'
  | 'mixed-runtime'
  | 'external-contract';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sourceRoots = [
  'packages/sdk-server-ts/src',
  'packages/sdk-web/src',
  'packages/shared-ts/src',
  'tests',
] as const;

const allowedTypesTsFiles: Record<string, TypesTsClassification> = {
  'packages/sdk-server-ts/src/console/account/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/apiKeys/types.ts': 'mixed-runtime',
  'packages/sdk-server-ts/src/console/approvals/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/audit/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/auditExports/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/billing/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/billingPrepaidReservations/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/bootstrapTokens/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/enterpriseIsolation/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/gasSponsorship/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/keyExports/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/observability/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/onboarding/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/orgProjectEnv/types.ts': 'mixed-runtime',
  'packages/sdk-server-ts/src/console/policies/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/runtimeSnapshots/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/sponsoredCalls/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/sponsorshipSpendCaps/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/teamRbac/types.ts': 'mixed-runtime',
  'packages/sdk-server-ts/src/console/wallets/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/console/webhooks/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/core/types.ts': 'mixed-runtime',
  'packages/sdk-server-ts/src/email-recovery/types.ts': 'external-contract',
  'packages/sdk-web/src/SeamsWeb/publicApi/types.ts': 'public-barrel',
  'packages/sdk-web/src/SeamsWeb/signingSurface/types.ts': 'public-barrel',
  'packages/sdk-web/src/core/platform/types.ts': 'mixed-runtime',
  'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/types.ts': 'mixed-runtime',
  'packages/sdk-web/src/core/signingEngine/session/operationState/types.ts': 'mixed-runtime',
  'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.ts': 'mixed-runtime',
  'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types.ts': 'mixed-runtime',
  'packages/sdk-web/src/core/signingEngine/uiConfirm/ui/lit-components/TxTree/renderers/types.ts':
    'mixed-runtime',
  'packages/sdk-web/src/react/components/AccountMenuButton/types.ts': 'mixed-runtime',
  'packages/sdk-web/src/react/components/PasskeyAuthMenu/types.ts': 'mixed-runtime',
  'packages/sdk-web/src/react/types.ts': 'public-barrel',
  'tests/setup/types.ts': 'external-contract',
};

function isSourceFile(relativePath: string): boolean {
  return /\.(ts|tsx)$/.test(relativePath);
}

function shouldSkipDirectory(name: string): boolean {
  return name === 'node_modules' || name === 'dist' || name === 'test-results';
}

function listSourceFiles(relativePath: string): string[] {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) return isSourceFile(relativePath) ? [relativePath] : [];

  const files: string[] = [];
  for (const entry of fs.readdirSync(absolutePath, { withFileTypes: true })) {
    const childPath = path.join(relativePath, entry.name);
    if (entry.isDirectory()) {
      if (shouldSkipDirectory(entry.name)) continue;
      files.push(...listSourceFiles(childPath));
      continue;
    }
    if (isSourceFile(childPath)) files.push(childPath);
  }
  return files;
}

function activeSourceFiles(): string[] {
  const files: string[] = [];
  for (const root of sourceRoots) files.push(...listSourceFiles(root));
  return files.sort();
}

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function isAllowedTypesTsFile(relativePath: string): boolean {
  return Object.prototype.hasOwnProperty.call(allowedTypesTsFiles, relativePath);
}

function typeOnlyModuleViolationMessage(relativePath: string, source: string): string | null {
  const sourceFile = ts.createSourceFile(relativePath, source, ts.ScriptTarget.Latest, true);
  for (const statement of sourceFile.statements) {
    const message = statementViolationMessage(sourceFile, statement);
    if (message) return `${relativePath}:${lineNumber(sourceFile, statement)} ${message}`;
  }
  return null;
}

function statementViolationMessage(
  sourceFile: ts.SourceFile,
  statement: ts.Statement,
): string | null {
  if (ts.isImportDeclaration(statement)) return importDeclarationViolationMessage(statement);
  if (ts.isExportDeclaration(statement)) return exportDeclarationViolationMessage(statement);
  if (ts.isTypeAliasDeclaration(statement) || ts.isInterfaceDeclaration(statement)) return null;
  if (statement.kind === ts.SyntaxKind.EmptyStatement) return null;

  const text = statement.getText(sourceFile).split('\n')[0]?.trim() ?? '';
  return `contains executable or runtime statement ${statementKindName(statement)}: ${text}`;
}

function importDeclarationViolationMessage(statement: ts.ImportDeclaration): string | null {
  if (!statement.importClause) return 'contains a side-effect import';
  if (!statement.importClause.isTypeOnly) return 'contains a value import';
  return null;
}

function exportDeclarationViolationMessage(statement: ts.ExportDeclaration): string | null {
  if (exportDeclarationIsTypeOnly(statement)) return null;
  return 'contains a value export';
}

function exportDeclarationIsTypeOnly(statement: ts.ExportDeclaration): boolean {
  if (statement.isTypeOnly) return true;
  if (allNamedExportsAreTypeOnly(statement)) return true;
  return false;
}

function allNamedExportsAreTypeOnly(statement: ts.ExportDeclaration): boolean {
  if (!statement.exportClause || !ts.isNamedExports(statement.exportClause)) return false;
  for (const element of statement.exportClause.elements) {
    if (!element.isTypeOnly) return false;
  }
  return true;
}

function lineNumber(sourceFile: ts.SourceFile, statement: ts.Statement): number {
  return sourceFile.getLineAndCharacterOfPosition(statement.getStart(sourceFile)).line + 1;
}

function statementKindName(statement: ts.Statement): string {
  if (ts.isVariableStatement(statement)) return 'VariableStatement';
  if (ts.isFunctionDeclaration(statement)) return 'FunctionDeclaration';
  if (ts.isClassDeclaration(statement)) return 'ClassDeclaration';
  if (ts.isEnumDeclaration(statement)) return 'EnumDeclaration';
  return ts.SyntaxKind[statement.kind];
}

function valueTypesReexportMessage(relativePath: string, source: string): string | null {
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

function exportsTypesModule(statement: ts.ExportDeclaration): boolean {
  const moduleSpecifier = statement.moduleSpecifier;
  if (!moduleSpecifier || !ts.isStringLiteral(moduleSpecifier)) return false;
  return moduleSpecifier.text.includes('.types');
}

test.describe('Refactor 73 type filename source guards', () => {
  test('the type-only module guard rejects runtime statements', () => {
    expect(
      typeOnlyModuleViolationMessage('fixture.types.ts', 'const x = 1;\nexport type X = string;'),
    ).toBe(
      'fixture.types.ts:1 contains executable or runtime statement VariableStatement: const x = 1;',
    );
    expect(
      typeOnlyModuleViolationMessage(
        'fixture.types.ts',
        'console.log("x");\nexport type X = string;',
      ),
    ).toBe(
      'fixture.types.ts:1 contains executable or runtime statement ExpressionStatement: console.log("x");',
    );
    expect(
      typeOnlyModuleViolationMessage('fixture.types.ts', 'if (true) {}\nexport type X = string;'),
    ).toBe('fixture.types.ts:1 contains executable or runtime statement IfStatement: if (true) {}');
    expect(typeOnlyModuleViolationMessage('fixture.types.ts', 'import { Foo } from "./foo";')).toBe(
      'fixture.types.ts:1 contains a value import',
    );
    expect(
      typeOnlyModuleViolationMessage(
        'fixture.types.ts',
        'export interface X {\n  value: string;\n}\n',
      ),
    ).toBeNull();
    expect(
      typeOnlyModuleViolationMessage('fixture.types.ts', 'interface X {\n  value: string;\n}\n'),
    ).toBeNull();
  });

  test('the runtime barrel guard distinguishes type-only .types reexports', () => {
    expect(
      valueTypesReexportMessage('fixture.ts', "export type { Foo } from './foo.types';"),
    ).toBeNull();
    expect(valueTypesReexportMessage('fixture.ts', "export type * from './foo.types';")).toBeNull();
    expect(
      valueTypesReexportMessage('fixture.ts', "export { type Foo } from './foo.types';"),
    ).toBeNull();
    expect(valueTypesReexportMessage('fixture.ts', "export { Foo } from './foo.types';")).toBe(
      'fixture.ts value-reexports a .types module',
    );
    expect(valueTypesReexportMessage('fixture.ts', "export * from './foo.types';")).toBe(
      'fixture.ts value-reexports a .types module',
    );
    expect(
      valueTypesReexportMessage('fixture.ts', "export { type Foo, Bar } from './foo.types';"),
    ).toBe('fixture.ts value-reexports a .types module');
  });

  test('source files do not use the deprecated .typings.ts suffix', () => {
    const offenders: string[] = [];
    for (const file of activeSourceFiles()) {
      if (file.endsWith('.typings.ts')) offenders.push(file);
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('types.ts files stay explicit in the approved inventory', () => {
    const offenders: string[] = [];
    for (const file of activeSourceFiles()) {
      if (file.endsWith('/types.ts') && !isAllowedTypesTsFile(file)) offenders.push(file);
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('types.ts inventory does not contain removed files', () => {
    const offenders: string[] = [];
    for (const file of Object.keys(allowedTypesTsFiles)) {
      if (!fs.existsSync(path.join(repoRoot, file))) offenders.push(file);
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('.types.ts modules remain type-only', () => {
    const offenders: string[] = [];
    for (const file of activeSourceFiles()) {
      if (!file.endsWith('.types.ts')) continue;
      const message = typeOnlyModuleViolationMessage(file, readSource(file));
      if (message) offenders.push(message);
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('runtime barrels do not value-reexport .types modules', () => {
    const offenders: string[] = [];
    for (const file of activeSourceFiles()) {
      const message = valueTypesReexportMessage(file, readSource(file));
      if (message) offenders.push(message);
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});
