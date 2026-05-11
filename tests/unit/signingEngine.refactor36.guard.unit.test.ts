import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import {
  refactor36EcdsaActivationConstructionAllowlist,
  refactor36RawIdentityParseAllowlist,
  refactor36TransitionalLifecycleOptionals,
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

test.describe('signing engine refactor 36 guards', () => {
  test('transitional lifecycle allowlists stay explicit and finite', () => {
    expect(refactor36TransitionalLifecycleOptionals.length).toBeGreaterThanOrEqual(0);
    expect(refactor36RawIdentityParseAllowlist).toEqual([]);
    for (const entry of [
      ...refactor36TransitionalLifecycleOptionals,
      ...refactor36RawIdentityParseAllowlist,
      ...refactor36EcdsaActivationConstructionAllowlist,
    ]) {
      expect(entry.file).toMatch(/\.(ts|tsx)$/);
      expect(String(entry.ownerPhase || '')).toMatch(/^\d+$/);
      expect(String(entry.reason || '').trim().length).toBeGreaterThan(0);
      expect(fs.existsSync(path.join(repoRoot, entry.file)), entry.file).toBe(true);
    }
  });

  test('new optional lifecycle fields stay behind the finite allowlist', () => {
    const allowedFiles = new Set(
      refactor36TransitionalLifecycleOptionals.map((entry) => entry.file),
    );
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
        if (!allowedFiles.has(relativePath)) {
          offenders.push(relativePath);
        }
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
    const allowedFiles = new Set(refactor36RawIdentityParseAllowlist.map((entry) => entry.file));
    const searchRoots = [
      'client/src/core/signingEngine/flows/signEvmFamily',
      'client/src/core/signingEngine/session/passkey',
      'client/src/core/signingEngine/session/warmCapabilities',
    ];
    const offenders: string[] = [];
    const pattern =
      /(thresholdSessionId|walletSigningSessionId)\s*:\s*String\((?:[^)\n]*)(?:thresholdSessionId|walletSigningSessionId)(?:[^)\n]*)\)\.trim\(/g;
    for (const root of searchRoots) {
      for (const relativePath of listTsFiles(root)) {
        const source = readRepoFile(relativePath);
        if (!pattern.test(source)) continue;
        pattern.lastIndex = 0;
        if (!allowedFiles.has(relativePath)) {
          offenders.push(relativePath);
        }
      }
    }

    expect(offenders, offenders.join('\n')).toEqual([]);
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
    const allowedFiles = new Set(
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
});
