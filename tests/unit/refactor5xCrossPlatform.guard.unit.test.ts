import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const guardedRoots = [
  'client/src/core/signingEngine/session',
  'client/src/core/signingEngine/flows',
  'client/src/core/signingEngine/threshold',
  'client/src/core/signingEngine/interfaces',
];

function listTypeScriptFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  const entries = fs.readdirSync(absoluteDir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listTypeScriptFiles(relativePath));
      continue;
    }
    if (entry.isFile() && /\.tsx?$/.test(entry.name)) {
      files.push(relativePath);
    }
  }
  return files;
}

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

const platformLeakageAllowlist = new Set([
  'client/src/core/signingEngine/flows/signEvmFamily/events.ts',
  'client/src/core/signingEngine/flows/signEvmFamily/accountAuth.ts',
  'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
  'client/src/core/signingEngine/flows/signEvmFamily/signers/webauthnP256.ts',
  'client/src/core/signingEngine/flows/signEvmFamily/webauthnP256KeyRef.ts',
  'client/src/core/signingEngine/interfaces/operationDeps.ts',
  'client/src/core/signingEngine/interfaces/runtime.ts',
  'client/src/core/signingEngine/interfaces/signing.ts',
  'client/src/core/signingEngine/session/availability/availableSigningLanes.ts',
  'client/src/core/signingEngine/session/budget/budgetFinalizer.ts',
  'client/src/core/signingEngine/session/operationState/trace.ts',
  'client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
  'client/src/core/signingEngine/session/passkey/ecdsaClientRoot.ts',
  'client/src/core/signingEngine/session/userPreferences.ts',
]);

const rawHssAllowlist = new Set([
  'client/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts',
  'client/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts',
  'client/src/core/signingEngine/flows/signEvmFamily/signers/secp256k1.ts',
  'client/src/core/signingEngine/interfaces/signing.ts',
  'client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts',
  'client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.typecheck.ts',
  'client/src/core/signingEngine/session/passkey/ecdsaProvisioner.ts',
  'client/src/core/signingEngine/session/persistence/records.ts',
  'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
  'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.typecheck.ts',
  'client/src/core/signingEngine/threshold/ecdsa/activation.ts',
  'client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
  'client/src/core/signingEngine/threshold/ecdsa/keygen.ts',
]);

const platformLeakagePatterns = [
  /\bIndexedDBManager\b/,
  /\bUnifiedIndexedDBManager\b/,
  /\bnavigator\.credentials\b/,
  /\bnew\s+Worker\b/,
  /\bMessageChannel\b/,
  /\bwindow\b/,
  /\bdocument\b/,
  /\blocalStorage\b/,
  /\bcrypto\.subtle\b/,
];

const rawHssPatterns = [
  /\bclientShare32B64u\b/,
  /\bclientAdditiveShare32B64u\b/,
  /\bmappedPrivateShare32B64u\b/,
  /\bverifyingShare33B64u\b/,
  /\bclientCaitSithInput\b/,
  /\bclientPublicKey33B64u\b/,
];

const secretSourceCastAllowlist = new Set([
  'client/src/core/platform/types.typecheck.ts',
]);

const secretSourceCastPatterns = [
  /\bas\s+ClientSecretSource\b/,
  /\bas\s+WebAuthnPrfFirstSecretSource\b/,
  /\bas\s+EmailOtpWorkerSessionSecretSource\b/,
  /\bas\s+EmailOtpWorkerIssuedSessionHandle\b/,
  /\bas\s+SecureEnclaveWrappedSecretSource\b/,
  /\bas\s+Fido2HmacSecretSource\b/,
];

test.describe('refactor 5x cross-platform guards', () => {
  test('keeps platform APIs behind known adapter boundaries', () => {
    const violations: string[] = [];
    for (const file of guardedRoots.flatMap(listTypeScriptFiles)) {
      if (platformLeakageAllowlist.has(file)) continue;
      const source = readRepoFile(file);
      for (const pattern of platformLeakagePatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps raw ECDSA HSS share fields confined to the tracked migration set', () => {
    const violations: string[] = [];
    for (const file of guardedRoots.flatMap(listTypeScriptFiles)) {
      if (rawHssAllowlist.has(file)) continue;
      const source = readRepoFile(file);
      for (const pattern of rawHssPatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps client secret sources builder-only', () => {
    const violations: string[] = [];
    for (const file of ['client/src/core/platform', ...guardedRoots].flatMap(listTypeScriptFiles)) {
      if (secretSourceCastAllowlist.has(file)) continue;
      const source = readRepoFile(file);
      for (const pattern of secretSourceCastPatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });
});
