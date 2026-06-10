import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

const guardedRoots = [
  'packages/sdk-web/src/core/signingEngine/session',
  'packages/sdk-web/src/core/signingEngine/flows',
  'packages/sdk-web/src/core/signingEngine/threshold',
  'packages/sdk-web/src/core/signingEngine/interfaces',
  'packages/sdk-web/src/core/signingEngine/useCases',
];

const activeCoreSigningRoots = [
  ...guardedRoots,
  'packages/sdk-web/src/core/signingEngine/chains',
];

function listFiles(relativeDir: string, predicate: (fileName: string) => boolean): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!fs.existsSync(absoluteDir)) {
    return [];
  }
  const entries = fs.readdirSync(absoluteDir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFiles(relativePath, predicate));
      continue;
    }
    if (entry.isFile() && predicate(entry.name)) {
      files.push(relativePath);
    }
  }
  return files;
}

function listTypeScriptFiles(relativeDir: string): string[] {
  return listFiles(relativeDir, (fileName) => /\.tsx?$/.test(fileName));
}

function listTypeScriptFilesInRoots(relativeRoots: readonly string[]): string[] {
  const files = new Set<string>();
  for (const relativeRoot of relativeRoots) {
    const absoluteRoot = path.join(repoRoot, relativeRoot);
    if (!fs.existsSync(absoluteRoot)) {
      continue;
    }
    const stat = fs.statSync(absoluteRoot);
    if (stat.isDirectory()) {
      for (const file of listTypeScriptFiles(relativeRoot)) {
        files.add(file);
      }
      continue;
    }
    if (stat.isFile() && /\.tsx?$/.test(relativeRoot)) {
      files.add(relativeRoot);
    }
  }
  return [...files].sort();
}

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

type GuardBoundaryEntry = {
  file: string;
  owner: string;
  reason: string;
};

function guardBoundaryFiles(entries: readonly GuardBoundaryEntry[]): ReadonlySet<string> {
  const seen = new Set<string>();
  for (const entry of entries) {
    if (seen.has(entry.file)) {
      throw new Error(`Duplicate guard boundary entry: ${entry.file}`);
    }
    seen.add(entry.file);
    if (!entry.owner.trim() || !entry.reason.trim()) {
      throw new Error(`Incomplete guard boundary entry: ${entry.file}`);
    }
  }
  return seen;
}

const platformBoundaryFiles = guardBoundaryFiles([
  {
    file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/events.ts',
    owner: 'EVM-family diagnostics boundary',
    reason: 'reads browser diagnostics storage for signing event traces',
  },
  {
    file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/accountAuth.ts',
    owner: 'EVM-family auth boundary',
    reason: 'checks browser credential availability before WebAuthn authentication',
  },
  {
    file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    owner: 'EVM-family public signing boundary',
    reason: 'coordinates browser diagnostics and runtime signing checks at the public flow edge',
  },
  {
    file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/webauthnP256.ts',
    owner: 'WebAuthn P-256 signer boundary',
    reason: 'performs direct WebAuthn P-256 assertions',
  },
  {
    file: 'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/webauthnP256KeyRef.ts',
    owner: 'WebAuthn P-256 key-ref boundary',
    reason: 'reads browser credential state for P-256 key references',
  },
  {
    file: 'packages/sdk-web/src/core/signingEngine/interfaces/operationDeps.ts',
    owner: 'operation dependency port boundary',
    reason: 'types runtime dependencies injected at signing operation edges',
  },
  {
    file: 'packages/sdk-web/src/core/signingEngine/interfaces/runtime.ts',
    owner: 'runtime dependency port boundary',
    reason: 'types platform runtime dependencies injected by assembly',
  },
  {
    file: 'packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts',
    owner: 'signing lane availability boundary',
    reason: 'checks browser persistence availability before reading lane state',
  },
  {
    file: 'packages/sdk-web/src/core/signingEngine/session/budget/budgetFinalizer.ts',
    owner: 'budget finalization diagnostics boundary',
    reason: 'reads browser diagnostics storage while finalizing signing budgets',
  },
  {
    file: 'packages/sdk-web/src/core/signingEngine/session/operationState/trace.ts',
    owner: 'operation trace diagnostics boundary',
    reason: 'reads browser diagnostics storage for operation traces',
  },
  {
    file: 'packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
    owner: 'passkey ECDSA bootstrap boundary',
    reason: 'receives browser storage and prompt ports for ECDSA bootstrap',
  },
  {
    file: 'packages/sdk-web/src/core/signingEngine/session/userPreferences.ts',
    owner: 'session preference persistence boundary',
    reason: 'reads browser local storage for user preferences',
  },
]);

const rawHssBoundaryFiles = guardBoundaryFiles([]);

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

const rawClientRootSharePatterns = [
  /\bclientRootShare32\b/,
  /\bclientRootShare32B64u\b/,
];

const secretSourceCastBoundaryFiles = new Set(['packages/sdk-web/src/core/platform/types.typecheck.ts']);

const secretSourceCastPatterns = [
  /\bas\s+ClientSecretSource\b/,
  /\bas\s+WebAuthnPrfFirstSecretSource\b/,
  /\bas\s+EmailOtpWorkerSessionSecretSource\b/,
  /\bas\s+EmailOtpWorkerIssuedSessionHandle\b/,
  /\bas\s+SecureEnclaveWrappedSecretSource\b/,
  /\bas\s+Fido2HmacSecretSource\b/,
];

function isRuntimePortsAssemblyFile(file: string): boolean {
  return (
    file === 'packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts' ||
    file.startsWith('packages/sdk-web/src/core/signingEngine/assembly/')
  );
}

const rawDbRecordBoundaryFiles = guardBoundaryFiles([]);

const rawDbRecordPatterns = [
  /\bEcdsaRoleLocalBoundaryRecord\b/,
  /\becdsa_role_local_ready_record_v1\b/,
  /\blegacy_raw_role_local_v1\b/,
  /\bcurrent_unbranched_ready_record_v1\b/,
];

const hssClientWorkerConstructionBoundaryFiles = guardBoundaryFiles([]);

const hssClientWorkerConstructionPatterns = [
  /\bWorkerRequestType\.BuildThresholdEcdsaHssRoleLocalClientBootstrap\b/,
  /\bbuildThresholdEcdsaHssRoleLocalClientBootstrapWasm\b/,
  /\bThresholdEcdsaHssRoleLocalClientBootstrap\b/,
];

const signerCommandSchemaBoundaryFiles = guardBoundaryFiles([
  {
    file: 'packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts',
    owner: 'generated signer-core schemas',
    reason: 'this is the committed Rust-generated command schema file',
  },
  {
    file: 'packages/sdk-web/src/core/platform/signerCoreCommandAdapters.ts',
    owner: 'signer-core schema adapter',
    reason: 'this module is the only TypeScript wrapper layer for generated command schemas',
  },
  {
    file: 'packages/sdk-web/src/core/platform/signerCoreCommandAdapters.typecheck.ts',
    owner: 'signer-core schema type fixtures',
    reason: 'type fixtures intentionally reference generated command schema names',
  },
]);

const signerCommandSchemaRoots = [
  'packages/sdk-web/src/core/platform',
  'packages/sdk-web/src/core/signingEngine/threshold',
  'packages/sdk-web/src/core/signingEngine/workerManager',
];

const handWrittenSignerCommandSchemaPatterns = [
  /\b(?:export\s+)?type\s+PrepareEcdsaClientBootstrapCommand\b/,
  /\b(?:export\s+)?interface\s+PrepareEcdsaClientBootstrapCommand\b/,
  /\b(?:export\s+)?type\s+FinalizeEcdsaClientBootstrapCommand\b/,
  /\b(?:export\s+)?interface\s+FinalizeEcdsaClientBootstrapCommand\b/,
];

test.describe('cross-platform boundary guards', () => {
  test('keeps platform APIs behind known adapter boundaries', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(guardedRoots)) {
      if (platformBoundaryFiles.has(file)) continue;
      const source = readRepoFile(file);
      for (const pattern of platformLeakagePatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps raw ECDSA HSS share fields out of active core signing roots', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(activeCoreSigningRoots)) {
      if (rawHssBoundaryFiles.has(file)) continue;
      const source = readRepoFile(file);
      for (const pattern of rawHssPatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps passkey ECDSA PRF material from being modeled as client-root shares', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(activeCoreSigningRoots)) {
      const source = readRepoFile(file);
      for (const pattern of rawClientRootSharePatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps client secret sources builder-only', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(['packages/sdk-web/src/core/platform', ...guardedRoots])) {
      if (secretSourceCastBoundaryFiles.has(file)) continue;
      const source = readRepoFile(file);
      for (const pattern of secretSourceCastPatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps RuntimePorts as an assembly-only aggregate', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFiles('packages/sdk-web/src/core/signingEngine')) {
      if (isRuntimePortsAssemblyFile(file)) continue;
      const source = readRepoFile(file);
      if (/\bRuntimePorts\b/.test(source) || /\bcreateBrowserPlatformRuntime\b/.test(source)) {
        violations.push(file);
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps use-case services from depending on RuntimePorts', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFiles('packages/sdk-web/src/core/signingEngine/useCases')) {
      const source = readRepoFile(file);
      if (/\bRuntimePorts\b/.test(source) || /\bcreateBrowserPlatformRuntime\b/.test(source)) {
        violations.push(file);
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps raw ECDSA role-local record shapes inside persistence boundaries', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots([
      ...activeCoreSigningRoots,
      'packages/sdk-web/src/core/platform',
      'packages/sdk-web/src/SeamsWeb',
    ])) {
      if (rawDbRecordBoundaryFiles.has(file)) continue;
      const source = readRepoFile(file);
      for (const pattern of rawDbRecordPatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps the ECDSA role-local parser on the canonical persistence path', () => {
    const platformTypes = 'packages/sdk-web/src/core/platform/ecdsaRoleLocalRecords.ts';
    const violations: string[] = [];
    if (fs.existsSync(path.join(repoRoot, platformTypes))) {
      const source = readRepoFile(platformTypes);
      if (/\bexport function parse|\bfunction parseRaw|\bfrom ['"].*\/persistence\/records['"]/.test(source)) {
        violations.push(`${platformTypes}: parser implementation belongs in the persistence boundary`);
      }
    }
    for (const file of listTypeScriptFilesInRoots(['packages/sdk-web/src/core'])) {
      if (file.startsWith('packages/sdk-web/src/core/platform/')) continue;
      const source = readRepoFile(file);
      if (/platform\/ecdsaRoleLocalRecords/.test(source)) {
        violations.push(`${file}: imports platform role-local types outside the platform barrel`);
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps hss-client bootstrap worker construction behind signer adapters', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(activeCoreSigningRoots)) {
      if (hssClientWorkerConstructionBoundaryFiles.has(file)) continue;
      const source = readRepoFile(file);
      for (const pattern of hssClientWorkerConstructionPatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps the legacy root-share ECDSA prepare FFI out of production surfaces', () => {
    const emailOtpWorkerSource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    );
    const clientDts = readRepoFile('wasm/hss_client_signer/pkg/hss_client_signer.d.ts');

    expect(emailOtpWorkerSource).not.toContain(
      'threshold_ecdsa_hss_role_local_prepare_client_bootstrap',
    );
    expect(clientDts).not.toContain('threshold_ecdsa_hss_role_local_prepare_client_bootstrap');
  });

  test('rejects hand-written signer-core command schema copies', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(signerCommandSchemaRoots)) {
      if (signerCommandSchemaBoundaryFiles.has(file)) continue;
      const source = readRepoFile(file);
      for (const pattern of handWrittenSignerCommandSchemaPatterns) {
        if (pattern.test(source)) {
          violations.push(`${file}: ${pattern}`);
        }
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps Email OTP registration ECDSA prep behind worker-issued handles', () => {
    const registrationSource = readRepoFile(
      'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
    );
    const emailOtpSource = readRepoFile(
      'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/enrollment.ts',
    );
    const workerTypesSource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
    );

    expect(registrationSource).not.toContain('enrollment.clientRootShare32B64u');
    expect(emailOtpSource).not.toContain('clientRootShare32B64u: string;');
    expect(workerTypesSource).not.toContain('clientRootShare32B64u: string;');
  });

  test('keeps ECDSA export flow from transporting client-root share strings', () => {
    const exportFlowSource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportFlow.ts',
    );
    const exportBoundarySource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts',
    );

    expect(exportFlowSource).not.toContain('clientRootShare32B64u');
    expect(exportBoundarySource).not.toContain('clientRootShare32B64u: string');
  });

  test('keeps Email OTP Ed25519 export material inside the Email OTP worker', () => {
    const workerTypesSource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
    );
    const exportRecoverySource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.ts',
    );
    const nearExportSource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/recovery/nearEd25519ExportFlow.ts',
    );

    expect(workerTypesSource).not.toContain('recoverEmailOtpEd25519ExportPrfFirst');
    expect(exportRecoverySource).not.toContain('thresholdEd25519PrfFirstB64u');
    expect(exportRecoverySource).not.toContain('prfFirstB64u: string');
    expect(nearExportSource).not.toContain('recoverEd25519ExportPrfFirst');
  });

  test('keeps lifecycle worker results out of boolean success bags', () => {
    const workerTypesSource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
    );

    expect(workerTypesSource).not.toContain('result: { ok: boolean }');
  });
});
