import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

type TypesTsClassification =
  | 'public-barrel'
  | 'mixed-runtime'
  | 'external-contract'
  | `rename-later:${string}`;

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
  'packages/sdk-server-ts/src/core/ThresholdService/schemes/types.ts':
    'rename-later:thresholdServiceSchemes.types.ts',
  'packages/sdk-server-ts/src/core/types.ts': 'mixed-runtime',
  'packages/sdk-server-ts/src/email-recovery/types.ts': 'external-contract',
  'packages/sdk-server-ts/src/router/cloudflare/types.ts': 'rename-later:cloudflare.types.ts',
  'packages/sdk-server-ts/src/threshold/session/signingSessionSeal/types.ts':
    'rename-later:signingSessionSeal.types.ts',
  'packages/sdk-web/src/SeamsWeb/publicApi/types.ts': 'public-barrel',
  'packages/sdk-web/src/SeamsWeb/signingSurface/types.ts': 'public-barrel',
  'packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/types.ts':
    'rename-later:walletIframeHandler.types.ts',
  'packages/sdk-web/src/core/accountData/near/types.ts': 'rename-later:nearAccountData.types.ts',
  'packages/sdk-web/src/core/platform/types.ts': 'rename-later:platform.types.ts',
  'packages/sdk-web/src/core/runtime/types.ts': 'rename-later:runtime.types.ts',
  'packages/sdk-web/src/core/signingEngine/chains/evm/types.ts':
    'rename-later:evmSigning.types.ts',
  'packages/sdk-web/src/core/signingEngine/chains/tempo/types.ts':
    'rename-later:tempoSigning.types.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/types.ts': 'mixed-runtime',
  'packages/sdk-web/src/core/signingEngine/session/operationState/types.ts': 'mixed-runtime',
  'packages/sdk-web/src/core/signingEngine/session/sealedRecovery/types.ts':
    'rename-later:sealedRecovery.types.ts',
  'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.ts': 'mixed-runtime',
  'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types.ts': 'mixed-runtime',
  'packages/sdk-web/src/core/signingEngine/uiConfirm/types.ts':
    'rename-later:uiConfirm.types.ts',
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

function runtimeExportMessage(relativePath: string, source: string): string | null {
  const runtimeExport = /^\s*export\s+(const|let|var|function|class|enum)\b/m.exec(source);
  if (runtimeExport) return `${relativePath} exports runtime ${runtimeExport[1]}`;

  const sideEffectImport = /^\s*import\s+['"][^'"]+['"];?\s*$/m.exec(source);
  if (sideEffectImport) return `${relativePath} contains a side-effect import`;

  const runtimeImport = /^\s*import\s+(?!type\b)/m.exec(source);
  if (runtimeImport) return `${relativePath} contains a value import`;

  return null;
}

function valueTypesReexportMessage(relativePath: string, source: string): string | null {
  for (const statement of exportStatements(source)) {
    if (!statement.includes('.types')) continue;
    if (/^\s*export\s+type\b/.test(statement)) continue;
    if (/^\s*export\s+(?:\*|\{)/.test(statement)) {
      return `${relativePath} value-reexports a .types module`;
    }
  }
  return null;
}

function exportStatements(source: string): string[] {
  const statements: string[] = [];
  let current = '';
  for (const line of source.split('\n')) {
    if (current.length === 0 && !/^\s*export\b/.test(line)) continue;
    current = current.length === 0 ? line : `${current}\n${line}`;
    if (line.includes(';')) {
      statements.push(current);
      current = '';
    }
  }
  if (current.length > 0) statements.push(current);
  return statements;
}

test.describe('Refactor 73 type filename source guards', () => {
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
      const message = runtimeExportMessage(file, readSource(file));
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
