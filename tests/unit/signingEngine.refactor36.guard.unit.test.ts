import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import {
  reduceNearAccountIdForbiddenPathNearOwnedAllowlist,
  reduceNearAccountIdAccountToSubjectAllowlist,
  refactor36EcdsaActivationConstructionAllowlist,
} from './signingEngine.refactor36.allowlists';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTsFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listTsFiles(relativePath);
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

function listSourceFiles(relativePath: string): string[] {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) {
    return /\.(ts|tsx|rs)$/.test(relativePath) ? [relativePath] : [];
  }
  return fs.readdirSync(absolutePath, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(relativePath, entry.name);
    if (entry.isDirectory()) return listSourceFiles(entryPath);
    return /\.(ts|tsx|rs)$/.test(entry.name) ? [entryPath] : [];
  });
}

function findCallObjects(source: string, callName: string): string[] {
  const objects: string[] = [];
  let searchFrom = 0;
  const needle = `${callName}({`;

  while (true) {
    const callStart = source.indexOf(needle, searchFrom);
    if (callStart < 0) break;

    let depth = 0;
    let end = -1;
    for (let i = callStart + callName.length + 1; i < source.length; i += 1) {
      const char = source[i];
      if (char === '{') depth += 1;
      if (char === '}') {
        depth -= 1;
        if (depth === 0) {
          end = i + 1;
          break;
        }
      }
    }

    if (end < 0) break;
    objects.push(source.slice(callStart, end));
    searchFrom = end;
  }

  return objects;
}

function findLoggerCalls(source: string): string[] {
  const calls: string[] = [];
  const pattern = /(?:^|[^\w])(?:this|ctx|options|input)?\.?logger\.(?:info|warn|error|debug)\(/g;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(source))) {
    const openParenIndex = source.indexOf('(', match.index);
    if (openParenIndex < 0) continue;
    let depth = 0;
    let end = -1;
    for (let i = openParenIndex; i < source.length; i += 1) {
      const char = source[i];
      if (char === '(') depth += 1;
      if (char === ')') {
        depth -= 1;
        if (depth === 0) {
          end = i + 1;
          break;
        }
      }
    }
    if (end < 0) break;
    calls.push(source.slice(match.index, end));
    pattern.lastIndex = end;
  }
  return calls;
}

function lineNumberForIndex(source: string, index: number): number {
  return source.slice(0, index).split(/\r?\n/).length;
}

function findBalancedBlock(source: string, openBraceIndex: number): string | null {
  if (openBraceIndex < 0) return null;
  let depth = 0;
  for (let i = openBraceIndex; i < source.length; i += 1) {
    const char = source[i];
    if (char === '{') depth += 1;
    if (char === '}') {
      depth -= 1;
      if (depth === 0) return source.slice(openBraceIndex, i + 1);
    }
  }
  return null;
}

function findTypeDeclaration(source: string, name: string): string {
  const declarationPattern = new RegExp(`\\b(?:export\\s+)?(type|interface)\\s+${name}\\b`);
  const match = declarationPattern.exec(source);
  if (!match) throw new Error(`Missing declaration ${name}`);

  if (match[1] === 'interface') {
    const openBraceIndex = source.indexOf('{', match.index);
    const block = findBalancedBlock(source, openBraceIndex);
    if (!block) throw new Error(`Could not parse interface ${name}`);
    return block;
  }

  let curlyDepth = 0;
  let parenDepth = 0;
  let bracketDepth = 0;
  for (let i = match.index; i < source.length; i += 1) {
    const char = source[i];
    if (char === '{') curlyDepth += 1;
    if (char === '}') curlyDepth -= 1;
    if (char === '(') parenDepth += 1;
    if (char === ')') parenDepth -= 1;
    if (char === '[') bracketDepth += 1;
    if (char === ']') bracketDepth -= 1;
    if (char === ';' && curlyDepth === 0 && parenDepth === 0 && bracketDepth === 0) {
      return source.slice(match.index, i + 1);
    }
  }

  throw new Error(`Could not parse type ${name}`);
}

function findObjectBlockAfter(source: string, needle: string): string {
  const start = source.indexOf(needle);
  if (start < 0) throw new Error(`Missing object block after ${needle}`);
  const openBraceIndex = source.indexOf('{', start);
  const block = findBalancedBlock(source, openBraceIndex);
  if (!block) throw new Error(`Could not parse object block after ${needle}`);
  return block;
}

function findChainedMethodCallObjects(
  source: string,
  methodNames: string[],
  receiverPattern = '\\b\\w+',
): Array<{ methodName: string; line: number; block: string }> {
  const calls: Array<{ methodName: string; line: number; block: string }> = [];
  const pattern = new RegExp(
    `(?:${receiverPattern})\\s*\\.(?:${methodNames.join('|')})\\s*\\(\\s*{`,
    'g',
  );
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(source))) {
    const dottedNames = [...match[0].matchAll(/\.(\w+)/g)];
    const methodName = dottedNames[dottedNames.length - 1]?.[1];
    if (!methodName) continue;
    const openBraceIndex = source.indexOf('{', match.index);
    const block = findBalancedBlock(source, openBraceIndex);
    if (!block) continue;
    calls.push({
      methodName,
      line: lineNumberForIndex(source, match.index),
      block,
    });
    pattern.lastIndex = openBraceIndex + block.length;
  }
  return calls;
}

function findMethodDeclarationAndBody(source: string, methodName: string): string | null {
  const methodStart = source.indexOf(`async ${methodName}(`);
  if (methodStart < 0) return null;
  const openParenIndex = source.indexOf('(', methodStart);
  let parenDepth = 0;
  let closeParenIndex = -1;
  for (let i = openParenIndex; i < source.length; i += 1) {
    const char = source[i];
    if (char === '(') parenDepth += 1;
    if (char === ')') {
      parenDepth -= 1;
      if (parenDepth === 0) {
        closeParenIndex = i;
        break;
      }
    }
  }
  if (closeParenIndex < 0) return null;
  const bodyOpenIndex = source.indexOf('{', closeParenIndex);
  const bodyBlock = findBalancedBlock(source, bodyOpenIndex);
  return bodyBlock ? source.slice(methodStart, bodyOpenIndex) + bodyBlock : null;
}

function expectRequiredFields(block: string, fields: string[], context: string): string[] {
  return fields
    .filter((field) => !new RegExp(`\\b${field}\\s*(?::|,)`).test(block))
    .map((field) => `${context} is missing required ${field}`);
}

function expectDeclaredFields(block: string, fields: string[], context: string): string[] {
  return fields
    .filter((field) => !new RegExp(`\\b${field}\\??\\s*:`).test(block))
    .map((field) => `${context} does not declare ${field}`);
}

function expectAnyDeclaredField(block: string, fields: string[], context: string): string[] {
  return fields.some((field) => new RegExp(`\\b${field}\\??\\s*:`).test(block))
    ? []
    : [`${context} does not declare any of: ${fields.join(', ')}`];
}

function expectNoField(block: string, field: string, context: string): string[] {
  const searchable = block.replace(new RegExp(`\\b${field}\\?:\\s*never\\b`, 'g'), '');
  return new RegExp(`\\b${field}\\s*(?::|\\?:|,)`).test(searchable)
    ? [`${context} exposes ${field}`]
    : [];
}

function expectNoNearAccountId(
  block: string,
  context: string,
  options: { allowNeverTripwire?: boolean } = {},
): string[] {
  const searchable = options.allowNeverTripwire
    ? block.replace(/\bnearAccountId\?:\s*never\b/g, '')
    : block;
  return /\bnearAccountId\b/.test(searchable) ? [`${context} exposes nearAccountId`] : [];
}

test.describe('signing engine refactor 36 guards', () => {
  test('persistent allowlists stay explicit and finite', () => {
    for (const entry of [
      ...refactor36EcdsaActivationConstructionAllowlist,
      ...reduceNearAccountIdForbiddenPathNearOwnedAllowlist,
    ]) {
      expect(entry.file).toMatch(/\.(ts|tsx|rs)$/);
      expect(String(entry.ownerPhase || '')).toMatch(/^\d+$/);
      expect(String(entry.reason || '').trim().length).toBeGreaterThan(0);
      expect(fs.existsSync(path.join(repoRoot, entry.file)), entry.file).toBe(true);
    }
  });

  test('new optional lifecycle fields stay behind the finite allowlist', () => {
    const searchRoots = [
      'client/src/core/signingEngine/session/warmCapabilities',
      'client/src/core/signingEngine/session/passkey',
      'client/src/core/signingEngine/session/emailOtp',
      'client/src/core/signingEngine/session/budget',
      'client/src/core/signingEngine/flows/signEvmFamily',
    ];
    const offenders: string[] = [];
    const pattern =
      /sessionId\?: string|walletSigningSessionId\?: string|thresholdSessionId\?: string|thresholdSessionAuth\?:(?!\s*never\b)|webauthnAuthentication\?:(?!\s*never\b)|clientRootShare32B64u\?:(?!\s*never\b)|warmRecord\?:|warmKeyRef\?:|reauthRecord\?:|emailOtpAuthContext\?:(?!\s*never\b)/;
    for (const root of searchRoots) {
      for (const relativePath of listTsFiles(root)) {
        const source = readRepoFile(relativePath);
        if (!pattern.test(source)) continue;
        offenders.push(relativePath);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('old warm ECDSA lifecycle symbols stay deleted', () => {
    const offenders: string[] = [];
    const pattern =
      /\bEnsureWarmEcdsaCapabilityReadyArgs\b|\bResolveWarmEcdsaBootstrapRequestArgs\b|\bWarmEcdsaBootstrapRequest\b|\bProvisionWarmEcdsaCapabilityArgs\b|\bbuildProvisionWarmEcdsaCapabilityArgs\b/;
    for (const relativePath of listTsFiles('client/src/core/signingEngine')) {
      const source = readRepoFile(relativePath);
      if (!pattern.test(source)) continue;
      offenders.push(relativePath);
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('ECDSA provision plans only come from builder modules', () => {
    const provisionPlanConstructionPatterns = [
      /return\s*{\s*kind:\s*'passkey_ecdsa_session_provision'/,
      /return\s*{\s*kind:\s*'threshold_session_auth_ecdsa_reconnect'/,
      /return\s*{\s*kind:\s*'cookie_ecdsa_reconnect'/,
      /return\s*{\s*kind:\s*'email_otp_ecdsa_session_provision'/,
    ];
    const builderCalls = [
      'buildPasskeyEcdsaSessionProvision',
      'buildThresholdSessionAuthEcdsaReconnect',
      'buildEmailOtpEcdsaSessionProvision',
      'buildEcdsaSessionProvisionPlan',
    ];
    const offenders: string[] = [];
    for (const relativePath of listTsFiles('client/src/core/signingEngine')) {
      if (
        relativePath ===
          'client/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts' ||
        relativePath.endsWith('.typecheck.ts')
      ) {
        continue;
      }
      const source = readRepoFile(relativePath);
      for (const pattern of provisionPlanConstructionPatterns) {
        const match = source.match(pattern);
        if (match?.[0]) {
          offenders.push(`${relativePath} directly constructs ${match[0]}`);
        }
      }
      if (source.includes('as EcdsaSessionProvisionPlan')) {
        offenders.push(`${relativePath} casts to EcdsaSessionProvisionPlan`);
      }
      for (const callName of builderCalls) {
        for (const callObject of findCallObjects(source, callName)) {
          if (callObject.includes('...')) {
            offenders.push(`${relativePath} uses object spread in ${callName}()`);
          }
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('server budget-status routes stay parser-owned', () => {
    const routeFiles = [
      'server/src/router/express/routes/sessions.ts',
      'server/src/router/cloudflare/routes/sessions.ts',
    ];
    const offenders: string[] = [];
    for (const relativePath of routeFiles) {
      const source = readRepoFile(relativePath);
      if (!source.includes('parseWalletSigningBudgetStatusRequest')) {
        offenders.push(`${relativePath} does not import the shared budget-status parser`);
      }
      for (const forbidden of [
        'parseThresholdEcdsaSessionClaims',
        'parseThresholdEd25519SessionClaims',
        'body.walletSigningSessionId',
        'body.thresholdSessionId',
      ]) {
        if (source.includes(forbidden)) {
          offenders.push(`${relativePath} contains forbidden route-local parsing token ${forbidden}`);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('raw ECDSA identity parsing stays out of guarded internals', () => {
    const searchRoots = [
      'client/src/core/signingEngine/flows/signEvmFamily',
      'client/src/core/signingEngine/session/passkey',
      'client/src/core/signingEngine/session/warmCapabilities',
    ];
    const offenders: string[] = [];
    const patterns = [
      {
        name: 'object field identity parsing',
        pattern:
          /(thresholdSessionId|walletSigningSessionId)\s*:\s*String\((?:[^)\n]*)(?:thresholdSessionId|walletSigningSessionId)(?:[^)\n]*)\)\.trim\(/g,
      },
      {
        name: 'raw identity comparison',
        pattern:
          /String\([^;\n]*(?:thresholdSessionId|walletSigningSessionId)[^;\n]*\)\.trim\(\)\s*(?:={2,3}|!={1,2})\s*String\([^;\n]*(?:thresholdSessionId|walletSigningSessionId)[^;\n]*\)\.trim\(\)/g,
      },
      {
        name: 'paired local identity parsing',
        pattern:
          /\b(?:const|let)\s+\w*(?:ThresholdSessionId|SessionId)\s*=\s*String\([^;\n]*thresholdSessionId[^;\n]*\)\.trim\(\)[\s\S]{0,240}\b(?:const|let)\s+\w*WalletSigningSessionId\s*=\s*String\([^;\n]*walletSigningSessionId[^;\n]*\)\.trim\(\)/g,
      },
      {
        name: 'paired local identity parsing',
        pattern:
          /\b(?:const|let)\s+\w*WalletSigningSessionId\s*=\s*String\([^;\n]*walletSigningSessionId[^;\n]*\)\.trim\(\)[\s\S]{0,240}\b(?:const|let)\s+\w*(?:ThresholdSessionId|SessionId)\s*=\s*String\([^;\n]*thresholdSessionId[^;\n]*\)\.trim\(\)/g,
      },
    ];
    for (const root of searchRoots) {
      for (const relativePath of listTsFiles(root)) {
        const source = readRepoFile(relativePath);
        for (const { name, pattern } of patterns) {
          if (!pattern.test(source)) continue;
          pattern.lastIndex = 0;
          offenders.push(`${relativePath} (${name})`);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('near account to ECDSA subject derivations stay finite', () => {
    const guardedRoots = ['client/src/core/signingEngine', 'client/src/core/SeamsPasskey'];
    const accountToSubjectPattern =
      /toWalletSubjectId\(\s*(?:(?:args|input|request)\.)?(?:nearAccountId|accountId)\s*\)/;
    const actual = new Map<string, number>();
    for (const relativePath of guardedRoots.flatMap((root) => listTsFiles(root))) {
      if (relativePath.endsWith('.typecheck.ts')) continue;
      const source = readRepoFile(relativePath);
      const count = source
        .split(/\r?\n/)
        .filter((line) => accountToSubjectPattern.test(line)).length;
      if (count > 0) actual.set(relativePath, count);
    }

    const expected = new Map(
      reduceNearAccountIdAccountToSubjectAllowlist.map((entry) => [
        entry.file,
        entry.occurrences,
      ]),
    );
    const format = (entries: Map<string, number>) =>
      [...entries.entries()].sort(([a], [b]) => a.localeCompare(b));

    expect(format(actual)).toEqual(format(expected));
  });

  test('nearAccountId residue in ECDSA-forbidden paths stays finite', () => {
    const forbiddenPaths = [
      'client/src/core/SeamsPasskey/evm',
      'client/src/core/SeamsPasskey/tempo',
      'client/src/core/signingEngine/flows/signEvmFamily',
      'client/src/core/signingEngine/nonce',
      'client/src/core/signingEngine/session/budget',
      'client/src/core/signingEngine/session/warmCapabilities',
      'client/src/core/signingEngine/chains/evm',
      'client/src/core/signingEngine/threshold/ecdsa',
      'client/src/core/signingEngine/workerManager/workers',
      'client/src/core/signingEngine/workerManager/workerTypes.ts',
      'client/src/core/rpcClients/evm',
      'server/src/core/ThresholdService/ethSignerWasm.ts',
      'wasm/hss_client_signer',
    ];
    const actual = new Map<string, number>();
    for (const relativePath of forbiddenPaths.flatMap((entry) => listSourceFiles(entry))) {
      const source = readRepoFile(relativePath);
      const count = source.match(/\bnearAccountId\b/g)?.length || 0;
      if (count > 0) actual.set(relativePath, count);
    }

    const expected = new Map(
      reduceNearAccountIdForbiddenPathNearOwnedAllowlist.map((entry) => [
        entry.file,
        entry.occurrences,
      ]),
    );
    const format = (entries: Map<string, number>) =>
      [...entries.entries()].sort(([a], [b]) => a.localeCompare(b));

    expect(format(actual)).toEqual(format(expected));
  });

  test('threshold/server logs do not emit raw secret material', () => {
    const roots = [
      'server/src/core/ThresholdService',
      'server/src/threshold/session/signingSessionSeal',
    ];
    const forbiddenFields = [
      'ciphertext',
      'wrappedCiphertext',
      'clientSignatureShareB64u',
      'cosignerShareB64u',
      'clientVerifyingShareB64u',
      'relayerSigningShareB64u',
      'secretBytes',
      'privateKey',
      'privateKeyHex',
      'token',
      'authorizationHeader',
      'cookieHeader',
      'claims',
    ];
    const offenders: string[] = [];
    for (const root of roots) {
      for (const relativePath of listTsFiles(root)) {
        const source = readRepoFile(relativePath);
        for (const call of findLoggerCalls(source)) {
          for (const field of forbiddenFields) {
            const fieldPattern = new RegExp(`\\b${field}\\b\\s*:`);
            if (fieldPattern.test(call)) {
              offenders.push(`${relativePath} logs forbidden field ${field}`);
            }
          }
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('strict ECDSA activation branches only come from activation builder modules', () => {
    const allowedFiles = new Set<string>(
      refactor36EcdsaActivationConstructionAllowlist.map((entry) => entry.file),
    );
    const offenders: string[] = [];
    const pattern =
      /kind:\s*'(passkey_ecdsa_activation|email_otp_ecdsa_activation|threshold_session_auth_reconnect|cookie_reconnect)'/;
    for (const relativePath of listTsFiles('client/src/core/signingEngine')) {
      if (relativePath.endsWith('.typecheck.ts')) continue;
      const source = readRepoFile(relativePath);
      if (!pattern.test(source)) continue;
      if (!allowedFiles.has(relativePath)) {
        offenders.push(relativePath);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('strict activation/session state avoids cast escape hatches', () => {
    const offenders: string[] = [];
    const pattern =
      /\bas (?:ThresholdEcdsaActivationRequest|ThresholdEcdsaPasskeyActivationRequest|ThresholdEcdsaEmailOtpActivationRequest|ThresholdEcdsaThresholdSessionAuthReconnectRequest|ThresholdEcdsaCookieReconnectRequest|PasskeyEcdsaActivation|EmailOtpEcdsaActivation|ThresholdSessionAuthEcdsaActivation|CookieEcdsaActivation|PreparedEvmFamilyEcdsaSigningSession|EcdsaSessionProvisionPlan)\b/;
    for (const relativePath of [
      ...listTsFiles('client/src/core/signingEngine/session/passkey'),
      ...listTsFiles('client/src/core/signingEngine/flows/signEvmFamily'),
    ]) {
      const source = readRepoFile(relativePath);
      if (pattern.test(source)) {
        offenders.push(relativePath);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('strict activation/session builders avoid broad spread shortcuts', () => {
    const offenders: string[] = [];
    const pattern = /\.\.\.(?:baseArgs|args\.signingAuthPlan|activation|effectivePlan)\b/;
    for (const relativePath of [
      'client/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts',
      'client/src/core/signingEngine/session/passkey/ecdsaProvisioner.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/requireEvmFamilyStepUpAuth.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    ]) {
      const source = readRepoFile(relativePath);
      if (pattern.test(source)) {
        offenders.push(relativePath);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('public SDK ECDSA inputs stay wallet-session shaped', () => {
    const source = readRepoFile('client/src/core/SeamsPasskey/interfaces.ts');
    const namedDeclarations = [
      {
        name: 'SignTempoArgs',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId'],
        allowNeverTripwire: true,
      },
      {
        name: 'ReportTempoNonceLifecycleBaseArgs',
        required: ['walletSession', 'signedResult'],
        allowNeverTripwire: true,
      },
      {
        name: 'ExecuteEvmFamilyTransactionArgs',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId'],
        allowNeverTripwire: true,
      },
      {
        name: 'BootstrapThresholdEcdsaSessionArgs',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId'],
        allowNeverTripwire: true,
      },
      {
        name: 'EmailOtpEcdsaCapabilityArgs',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId'],
        allowNeverTripwire: true,
      },
      {
        name: 'ExportKeypairWithUIInput',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId'],
        allowNeverTripwire: true,
      },
    ];
    const inlineArgBlocks = [
      {
        context: 'AuthCapability.prefillThresholdEcdsaPresignPool',
        block: findObjectBlockAfter(source, 'prefillThresholdEcdsaPresignPool(args: {'),
        required: ['walletSession', 'chainTarget'],
      },
      {
        context: 'AuthCapability.requestEmailOtpSigningSessionChallenge',
        block: findObjectBlockAfter(source, 'requestEmailOtpSigningSessionChallenge(args: {'),
        required: ['walletSession', 'chainTarget'],
      },
      {
        context: 'AuthCapability.refreshEmailOtpSigningSession',
        block: findObjectBlockAfter(source, 'refreshEmailOtpSigningSession(args: {'),
        required: ['walletSession', 'chainTarget'],
      },
    ];
    const offenders: string[] = [];

    for (const declaration of namedDeclarations) {
      const block = findTypeDeclaration(source, declaration.name);
      offenders.push(
        ...expectRequiredFields(block, declaration.required, declaration.name),
        ...(declaration.forbidden || []).flatMap((field) =>
          expectNoField(block, field, declaration.name),
        ),
        ...expectNoNearAccountId(block, declaration.name, {
          allowNeverTripwire: declaration.allowNeverTripwire,
        }),
      );
    }

    for (const { context, block, required } of inlineArgBlocks) {
      offenders.push(
        ...expectRequiredFields(block, required, context),
        ...expectNoNearAccountId(block, context, { allowNeverTripwire: true }),
      );
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('ECDSA iframe payloads stay wallet-session shaped', () => {
    const source = readRepoFile('client/src/core/WalletIframe/shared/messages.ts');
    const namedDeclarations = [
      {
        name: 'PMSignTempoPayload',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId'],
      },
      {
        name: 'PMTempoNonceLifecyclePayloadBase',
        required: ['walletSession', 'signedResult'],
      },
      {
        name: 'PMExportKeypairUiPayload',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId'],
      },
      {
        name: 'PMEmailOtpSigningSessionChallengePayload',
        required: ['walletSession', 'chainTarget'],
      },
      {
        name: 'PMEmailOtpEcdsaCapabilityPayload',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId'],
      },
      {
        name: 'PMRefreshEmailOtpSigningSessionPayload',
        required: ['walletSession', 'chainTarget'],
      },
      {
        name: 'PMPrefillThresholdEcdsaPresignPoolPayload',
        required: ['walletSession', 'chainTarget'],
        forbidden: ['subjectId'],
      },
    ];
    const offenders: string[] = [];

    if (
      !source.includes(
        'export type PMBootstrapThresholdEcdsaSessionPayload = BootstrapThresholdEcdsaSessionArgs;',
      )
    ) {
      offenders.push(
        'PMBootstrapThresholdEcdsaSessionPayload must reuse BootstrapThresholdEcdsaSessionArgs',
      );
    }
    if (
      !source.includes(
        'export interface PMEmailOtpEcdsaEnrollmentCapabilityPayload extends PMEmailOtpEcdsaCapabilityPayload {}',
      )
    ) {
      offenders.push(
        'PMEmailOtpEcdsaEnrollmentCapabilityPayload must reuse PMEmailOtpEcdsaCapabilityPayload',
      );
    }

    for (const declaration of namedDeclarations) {
      const block = findTypeDeclaration(source, declaration.name);
      offenders.push(
        ...expectRequiredFields(block, declaration.required, declaration.name),
        ...(declaration.forbidden || []).flatMap((field) =>
          expectNoField(block, field, declaration.name),
        ),
        ...expectNoNearAccountId(block, declaration.name),
      );
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('ECDSA HSS role-local bootstrap types keep lane identity explicit', () => {
    const clientSource = readRepoFile('client/src/core/rpcClients/relayer/thresholdEcdsa.ts');
    const clientSessionPolicySource = readRepoFile(
      'client/src/core/signingEngine/threshold/sessionPolicy.ts',
    );
    const serverSource = readRepoFile('server/src/core/types.ts');
    const thresholdPrfSource = readRepoFile(
      'server/src/core/ThresholdService/thresholdPrfWasm.ts',
    );
    const hssClientSource = readRepoFile(
      'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
    );
    const offenders: string[] = [];
    const requiredRoleLocalBootstrapFields = [
      'walletSessionUserId',
      'rpId',
      'subjectId',
      'ecdsaThresholdKeyId',
      'signingRootId',
      'signingRootVersion',
      'keyScope',
      'relayerKeyId',
      'clientPublicKey33B64u',
      'contextBinding32B64u',
      'sessionId',
      'walletSigningSessionId',
      'participantIds',
    ];

    for (const { source, file, typeName } of [
      {
        source: clientSource,
        file: 'client/src/core/rpcClients/relayer/thresholdEcdsa.ts',
        typeName: 'ThresholdEcdsaHssRoleLocalBootstrapRequest',
      },
      {
        source: clientSource,
        file: 'client/src/core/rpcClients/relayer/thresholdEcdsa.ts',
        typeName: 'ThresholdEcdsaHssRoleLocalBootstrapBody',
      },
      {
        source: serverSource,
        file: 'server/src/core/types.ts',
        typeName: 'EcdsaHssClientBootstrapRequestBase',
      },
    ]) {
      const block = findTypeDeclaration(source, typeName);
      offenders.push(
        ...expectRequiredFields(block, requiredRoleLocalBootstrapFields, `${file} ${typeName}`),
        ...expectNoField(block, 'chainTarget', `${file} ${typeName}`),
        ...expectNoField(block, 'keyHandle', `${file} ${typeName}`),
        ...expectNoNearAccountId(block, `${file} ${typeName}`, {
          allowNeverTripwire: true,
        }),
      );
    }

    const serverRoleLocalRecordBlock = findTypeDeclaration(serverSource, 'EcdsaHssRoleLocalKeyRecord');
    offenders.push(
      ...expectRequiredFields(
        serverRoleLocalRecordBlock,
        [
          'version',
          'keyHandle',
          'walletSessionUserId',
          'subjectId',
          'ecdsaThresholdKeyId',
          'relayerKeyId',
          'clientPublicKey33B64u',
          'relayerPublicKey33B64u',
          'groupPublicKey33B64u',
          'relayerShare32B64u',
          'relayerCaitSithInput',
        ],
        'server/src/core/types.ts EcdsaHssRoleLocalKeyRecord',
      ),
      ...expectNoField(
        serverRoleLocalRecordBlock,
        'chainTarget',
        'server/src/core/types.ts EcdsaHssRoleLocalKeyRecord',
      ),
      ...expectNoNearAccountId(
        serverRoleLocalRecordBlock,
        'server/src/core/types.ts EcdsaHssRoleLocalKeyRecord',
      ),
    );

    const clientEcdsaPolicyBlock = findTypeDeclaration(
      clientSessionPolicySource,
      'EcdsaHssSessionPolicy',
    );
    offenders.push(
      ...expectRequiredFields(
        clientEcdsaPolicyBlock,
        ['walletSessionUserId', 'subjectId', 'chainTarget', 'sessionId'],
        'client/src/core/signingEngine/threshold/sessionPolicy.ts EcdsaHssSessionPolicy',
      ),
      ...expectNoField(
        clientEcdsaPolicyBlock,
        'userId',
        'client/src/core/signingEngine/threshold/sessionPolicy.ts EcdsaHssSessionPolicy',
      ),
      ...expectNoNearAccountId(
        clientEcdsaPolicyBlock,
        'client/src/core/signingEngine/threshold/sessionPolicy.ts EcdsaHssSessionPolicy',
      ),
    );

    const signingRootContextBlock = findTypeDeclaration(
      thresholdPrfSource,
      'EcdsaHssStableKeyPrfContext',
    );
    offenders.push(
      ...expectRequiredFields(
        signingRootContextBlock,
        ['signingRootId', 'walletSessionUserId', 'keyPurpose', 'keyVersion'],
        'server/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaHssStableKeyPrfContext',
      ),
      ...expectNoNearAccountId(
        signingRootContextBlock,
        'server/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaHssStableKeyPrfContext',
      ),
    );

    const ecdsaClientContextBlock = findTypeDeclaration(
      hssClientSource,
      'ThresholdEcdsaHssStableKeyContext',
    );
    offenders.push(
      ...expectRequiredFields(
        ecdsaClientContextBlock,
        ['walletSessionUserId', 'subjectId', 'chainTarget', 'keyPurpose', 'keyVersion'],
        'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts ThresholdEcdsaHssStableKeyContext',
      ),
      ...expectNoNearAccountId(
        ecdsaClientContextBlock,
        'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts ThresholdEcdsaHssStableKeyContext',
      ),
    );

    for (const [block, context] of [
      [
        signingRootContextBlock,
        'server/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaHssStableKeyPrfContext',
      ],
      [
        ecdsaClientContextBlock,
        'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts ThresholdEcdsaHssStableKeyContext',
      ],
    ] as const) {
      for (const field of ['walletSigningSessionId', 'thresholdSessionId']) {
        if (new RegExp(`\\b${field}\\s*:`).test(block)) {
          offenders.push(`${context} carries concrete ${field}`);
        }
        if (!new RegExp(`\\b${field}\\?:\\s*never\\b`).test(block)) {
          offenders.push(`${context} must reject ${field} with never`);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('ECDSA HSS WASM package exports stay role-local', () => {
    const clientDts = readRepoFile('wasm/hss_client_signer/pkg/hss_client_signer.d.ts');
    const serverDts = readRepoFile('wasm/eth_signer/pkg/eth_signer.d.ts');
    const nearWorkerDts = readRepoFile('wasm/near_signer/pkg/wasm_signer_worker.d.ts');
    const offenders: string[] = [];

    for (const symbol of [
      'threshold_ecdsa_hss_prepare_session',
      'threshold_ecdsa_hss_prepare_client_request',
      'threshold_ecdsa_hss_finalize_client_request',
      'threshold_ecdsa_hss_prepare_server_session',
      'threshold_ecdsa_hss_prepare_server_ceremony',
      'threshold_ecdsa_hss_finalize_server_report',
      'threshold_ecdsa_hss_open_server_output',
    ]) {
      if (clientDts.includes(symbol)) offenders.push(`client WASM still exports ${symbol}`);
      if (serverDts.includes(symbol)) offenders.push(`server WASM still exports ${symbol}`);
    }

    for (const symbol of [
      'PrepareThresholdEcdsaHssSession',
      'PrepareThresholdEcdsaHssClientRequest',
      'FinalizeThresholdEcdsaHssClientRequest',
    ]) {
      if (nearWorkerDts.includes(symbol)) offenders.push(`near worker still exposes ${symbol}`);
    }

    for (const symbol of [
      'threshold_ecdsa_hss_role_local_client_bootstrap',
      'threshold_ecdsa_hss_role_local_export_artifact',
    ]) {
      if (!clientDts.includes(symbol)) offenders.push(`client WASM is missing ${symbol}`);
    }

    if (clientDts.includes('threshold_ecdsa_hss_role_local_relayer_bootstrap')) {
      offenders.push('client WASM exposes relayer bootstrap helper');
    }
    if (!serverDts.includes('threshold_ecdsa_hss_role_local_relayer_bootstrap')) {
      offenders.push('server WASM is missing role-local relayer bootstrap helper');
    }

    for (const line of [
      'BuildThresholdEcdsaHssRoleLocalClientBootstrap = 13',
      'BuildThresholdEcdsaHssRoleLocalExportArtifact = 14',
      'BuildThresholdEcdsaHssRoleLocalClientBootstrapSuccess = 30',
      'BuildThresholdEcdsaHssRoleLocalExportArtifactSuccess = 32',
    ]) {
      if (!nearWorkerDts.includes(line)) offenders.push(`near worker is missing ${line}`);
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('Email OTP ECDSA export authorization uses wallet-session identity', () => {
    const confirmationSource = readRepoFile(
      'client/src/core/signingEngine/flows/recovery/keyExportConfirmation.ts',
    );
    const ecdsaExportSource = readRepoFile(
      'client/src/core/signingEngine/flows/recovery/ecdsaExportFlow.ts',
    );
    const nearAccountBranchIndex = confirmationSource.indexOf("kind: 'near_account_export_auth'");
    const nearAccountBranch = confirmationSource.slice(
      nearAccountBranchIndex,
      nearAccountBranchIndex + 350,
    );
    const offenders: string[] = [];

    if (nearAccountBranchIndex < 0) {
      offenders.push('near_account_export_auth branch is missing for NEAR export');
    }
    if (!nearAccountBranch.includes("chain: 'near'")) {
      offenders.push('near_account_export_auth must be NEAR-chain only');
    }
    if (!nearAccountBranch.includes("curve: 'ed25519'")) {
      offenders.push('near_account_export_auth must be Ed25519-only');
    }
    if (/ThresholdEcdsaChainTarget|WalletAuthCurve/.test(nearAccountBranch)) {
      offenders.push('near_account_export_auth still accepts broad ECDSA-capable fields');
    }
    if (ecdsaExportSource.includes("kind: 'near_account_export_auth'")) {
      offenders.push('ECDSA export flow still requests near_account_export_auth');
    }
    if (!ecdsaExportSource.includes("kind: 'wallet_session_export_auth'")) {
      offenders.push('ECDSA export flow must request wallet_session_export_auth');
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('budget status lookup avoids subject-wide ECDSA scan fallback', () => {
    const source = readRepoFile(
      'client/src/core/signingEngine/session/budget/budgetStatusReader.ts',
    );
    const offenders: string[] = [];
    for (const forbidden of [
      'listThresholdEcdsaRuntimeLanesForSubject',
      'toWalletSubjectId(walletId)',
    ]) {
      if (source.includes(forbidden)) {
        offenders.push(`budgetStatusReader contains forbidden ECDSA fallback ${forbidden}`);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('SigningEngine public ECDSA methods do not derive subject identity from accounts', () => {
    const source = readRepoFile('client/src/core/signingEngine/SigningEngine.ts');
    const methodNames = [
      'signTempo',
      'bootstrapEcdsaSession',
      'requestEmailOtpSigningSessionChallenge',
      'refreshEmailOtpSigningSession',
      'loginWithEmailOtpEcdsaCapabilityInternal',
      'enrollAndLoginWithEmailOtpEcdsaCapabilityInternal',
    ];
    const offenders: string[] = [];

    for (const methodName of methodNames) {
      const methodSource = findMethodDeclarationAndBody(source, methodName);
      if (!methodSource) {
        offenders.push(`Missing SigningEngine.${methodName}`);
        continue;
      }
      if (/\btoWalletSubjectId\(/.test(methodSource)) {
        offenders.push(`SigningEngine.${methodName} derives subject identity`);
      }
      if (/\bnearAccountId\b/.test(methodSource)) {
        offenders.push(`SigningEngine.${methodName} exposes nearAccountId`);
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('public SDK signer fixtures use domain-shaped NEAR and ECDSA calls', () => {
    const ecdsaSigningMethods = ['signTempo', 'executeEvmFamilyTransaction'];
    const ecdsaLifecycleMethods = [
      'reportBroadcastAccepted',
      'reportBroadcastRejected',
      'reportFinalized',
      'reportDroppedOrReplaced',
      'reconcileNonceLane',
    ];
    const nearMethods = [
      'executeAction',
      'signAndSendTransactions',
      'signAndSendTransaction',
      'signTransactionsWithActions',
      'signDelegateAction',
      'signAndSendDelegateAction',
      'signNEP413Message',
    ];
    const offenders: string[] = [];

    for (const root of ['tests/helpers', 'tests/e2e', 'tests/unit']) {
      for (const relativePath of listTsFiles(root)) {
        const source = readRepoFile(relativePath);
        for (const call of findChainedMethodCallObjects(
          source,
          ecdsaSigningMethods,
          '\\b(?:pm|seams)\\.tempo|\\bsigner',
        )) {
          offenders.push(
            ...expectRequiredFields(
              call.block,
              ['walletSession', 'chainTarget'],
              `${relativePath}:${call.line} ${call.methodName}`,
            ),
            ...expectNoField(
              call.block,
              'subjectId',
              `${relativePath}:${call.line} ${call.methodName}`,
            ),
            ...expectNoNearAccountId(
              call.block,
              `${relativePath}:${call.line} ${call.methodName}`,
            ),
          );
        }
        for (const call of findChainedMethodCallObjects(
          source,
          ecdsaLifecycleMethods,
          '\\b(?:pm|seams)\\.tempo|\\bsigner',
        )) {
          offenders.push(
            ...expectRequiredFields(
              call.block,
              ['walletSession'],
              `${relativePath}:${call.line} ${call.methodName}`,
            ),
            ...expectNoNearAccountId(
              call.block,
              `${relativePath}:${call.line} ${call.methodName}`,
            ),
          );
        }
        for (const call of findChainedMethodCallObjects(
          source,
          nearMethods,
          '\\b(?:pm|seams)\\.near|\\bsigner',
        )) {
          offenders.push(
            ...expectRequiredFields(
              call.block,
              ['nearAccount'],
              `${relativePath}:${call.line} ${call.methodName}`,
            ),
          );
          if (/\bnearAccountId\s*:/.test(call.block)) {
            offenders.push(`${relativePath}:${call.line} ${call.methodName} uses nearAccountId`);
          }
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});
