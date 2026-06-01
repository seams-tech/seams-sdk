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
  'client/src/core/signingEngine/useCases',
];

const activeCoreSigningRoots = [
  'client/src/core/signingEngine/SigningEngine.ts',
  ...guardedRoots,
  'client/src/core/signingEngine/chains',
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

type GuardAllowlistEntry = {
  file: string;
  ownerPhase: string;
  deletionTrigger: string;
  reason: string;
};

function guardAllowlist(entries: readonly GuardAllowlistEntry[]): ReadonlySet<string> {
  const seen = new Set<string>();
  for (const entry of entries) {
    if (seen.has(entry.file)) {
      throw new Error(`Duplicate guard allowlist entry: ${entry.file}`);
    }
    seen.add(entry.file);
    if (!entry.ownerPhase.trim() || !entry.deletionTrigger.trim() || !entry.reason.trim()) {
      throw new Error(`Incomplete guard allowlist entry: ${entry.file}`);
    }
  }
  return seen;
}

const platformLeakageAllowlist = guardAllowlist([
  {
    file: 'client/src/core/signingEngine/flows/signEvmFamily/events.ts',
    ownerPhase: 'Phase 9',
    deletionTrigger:
      'legacy EVM-family flow compatibility path is deleted after use-case routing owns signing diagnostics.',
    reason: 'legacy flow-level event diagnostics read browser globals until compatibility deletion',
  },
  {
    file: 'client/src/core/signingEngine/flows/signEvmFamily/accountAuth.ts',
    ownerPhase: 'Phase 9',
    deletionTrigger:
      'legacy EVM-family auth compatibility path is deleted after use-case routing owns auth ports.',
    reason: 'legacy flow-level auth helper still touches browser capability checks',
  },
  {
    file: 'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    ownerPhase: 'Phase 9',
    deletionTrigger:
      'legacy EVM-family signing compatibility path is deleted after use-case service orchestration owns the public flow.',
    reason: 'legacy public flow still performs browser diagnostics and runtime checks',
  },
  {
    file: 'client/src/core/signingEngine/flows/signEvmFamily/signers/webauthnP256.ts',
    ownerPhase: 'Phase 9',
    deletionTrigger:
      'legacy WebAuthn P-256 signer compatibility path is deleted after AuthenticatorPort or a signer adapter owns P-256 signing.',
    reason: 'legacy signer helper performs direct WebAuthn calls',
  },
  {
    file: 'client/src/core/signingEngine/flows/signEvmFamily/webauthnP256KeyRef.ts',
    ownerPhase: 'Phase 9',
    deletionTrigger:
      'legacy WebAuthn key-ref compatibility path is deleted after browser adapter boundary parsing owns key-ref lookup.',
    reason: 'legacy key-ref helper reads browser credential state',
  },
  {
    file: 'client/src/core/signingEngine/interfaces/operationDeps.ts',
    ownerPhase: 'Phase 9',
    deletionTrigger:
      'legacy operation-deps aggregate is deleted after all public flows route through narrow use-case ports.',
    reason: 'legacy shared dependency type still exposes browser runtime dependencies',
  },
  {
    file: 'client/src/core/signingEngine/interfaces/runtime.ts',
    ownerPhase: 'Phase 9',
    deletionTrigger:
      'legacy runtime aggregate is deleted after assembly-owned narrow ports cover remaining public flows.',
    reason: 'legacy runtime type is the migration source for platform adapter extraction',
  },
  {
    file: 'client/src/core/signingEngine/session/availability/availableSigningLanes.ts',
    ownerPhase: 'Phase 8',
    deletionTrigger:
      'activation and restore use cases own lane availability without direct browser storage checks.',
    reason: 'current availability reader still checks browser persistence availability',
  },
  {
    file: 'client/src/core/signingEngine/session/budget/budgetFinalizer.ts',
    ownerPhase: 'Phase 8',
    deletionTrigger: 'budget finalization runs through signing-session activation use-case ports.',
    reason: 'current budget finalizer still reads browser diagnostics state',
  },
  {
    file: 'client/src/core/signingEngine/session/operationState/trace.ts',
    ownerPhase: 'Phase 8',
    deletionTrigger: 'operation tracing receives diagnostics storage through a platform port.',
    reason: 'current trace helper reads browser diagnostics storage directly',
  },
  {
    file: 'client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
    ownerPhase: 'Phase 8',
    deletionTrigger: 'activation use case owns ECDSA bootstrap without browser storage or prompt deps.',
    reason: 'current activation bridge still receives browser storage and prompt ports',
  },
  {
    file: 'client/src/core/signingEngine/session/userPreferences.ts',
    ownerPhase: 'Phase 8',
    deletionTrigger: 'session preference persistence is routed through the storage port.',
    reason: 'current preference helper reads browser local storage directly',
  },
]);

const rawHssAllowlist = guardAllowlist([]);

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

const secretSourceCastAllowlist = new Set(['client/src/core/platform/types.typecheck.ts']);

const secretSourceCastPatterns = [
  /\bas\s+ClientSecretSource\b/,
  /\bas\s+WebAuthnPrfFirstSecretSource\b/,
  /\bas\s+EmailOtpWorkerSessionSecretSource\b/,
  /\bas\s+EmailOtpWorkerIssuedSessionHandle\b/,
  /\bas\s+SecureEnclaveWrappedSecretSource\b/,
  /\bas\s+Fido2HmacSecretSource\b/,
];

function isPlatformRuntimeAssemblyFile(file: string): boolean {
  return (
    file === 'client/src/core/signingEngine/SigningEngine.ts' ||
    file.startsWith('client/src/core/signingEngine/assembly/')
  );
}

const rawDbRecordBoundaryAllowlist = guardAllowlist([]);

const rawDbRecordPatterns = [
  /\bEcdsaRoleLocalBoundaryRecord\b/,
  /\becdsa_role_local_ready_record_v1\b/,
  /\blegacy_raw_role_local_v1\b/,
  /\bcurrent_unbranched_ready_record_v1\b/,
];

const hssClientWorkerConstructionAllowlist = guardAllowlist([]);

const hssClientWorkerConstructionPatterns = [
  /\bWorkerRequestType\.BuildThresholdEcdsaHssRoleLocalClientBootstrap\b/,
  /\bbuildThresholdEcdsaHssRoleLocalClientBootstrapWasm\b/,
  /\bThresholdEcdsaHssRoleLocalClientBootstrap\b/,
];

const signerCommandSchemaAllowlist = guardAllowlist([
  {
    file: 'client/src/core/platform/generated/signerCoreCommands.ts',
    ownerPhase: 'Phase 2',
    deletionTrigger: 'generated signer-core command schemas move to a new canonical path.',
    reason: 'this is the committed Rust-generated command schema file',
  },
  {
    file: 'client/src/core/platform/signerCoreCommandAdapters.ts',
    ownerPhase: 'Phase 2',
    deletionTrigger: 'schema wrapper ownership moves to a new canonical adapter module.',
    reason: 'this module is the only TypeScript wrapper layer for generated command schemas',
  },
  {
    file: 'client/src/core/platform/signerCoreCommandAdapters.typecheck.ts',
    ownerPhase: 'Phase 2',
    deletionTrigger: 'wrapper/generated parity fixtures move with the schema wrapper module.',
    reason: 'type fixtures intentionally reference generated command schema names',
  },
]);

const signerCommandSchemaRoots = [
  'client/src/core/platform',
  'client/src/core/signingEngine/threshold',
  'client/src/core/signingEngine/workerManager',
];

const handWrittenSignerCommandSchemaPatterns = [
  /\b(?:export\s+)?type\s+PrepareEcdsaClientBootstrapCommand\b/,
  /\b(?:export\s+)?interface\s+PrepareEcdsaClientBootstrapCommand\b/,
  /\b(?:export\s+)?type\s+FinalizeEcdsaClientBootstrapCommand\b/,
  /\b(?:export\s+)?interface\s+FinalizeEcdsaClientBootstrapCommand\b/,
];

test.describe('refactor 5x cross-platform guards', () => {
  test('keeps platform APIs behind known adapter boundaries', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(guardedRoots)) {
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
    for (const file of listTypeScriptFilesInRoots(activeCoreSigningRoots)) {
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
    for (const file of listTypeScriptFilesInRoots(['client/src/core/platform', ...guardedRoots])) {
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

  test('keeps PlatformRuntime as an assembly-only aggregate', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFiles('client/src/core/signingEngine')) {
      if (isPlatformRuntimeAssemblyFile(file)) continue;
      const source = readRepoFile(file);
      if (/\bPlatformRuntime\b/.test(source) || /\bcreateBrowserPlatformRuntime\b/.test(source)) {
        violations.push(file);
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps use-case services from depending on PlatformRuntime', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFiles('client/src/core/signingEngine/useCases')) {
      const source = readRepoFile(file);
      if (/\bPlatformRuntime\b/.test(source) || /\bcreateBrowserPlatformRuntime\b/.test(source)) {
        violations.push(file);
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps raw ECDSA role-local record shapes inside persistence boundaries', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots([
      ...activeCoreSigningRoots,
      'client/src/core/platform',
      'client/src/core/SeamsPasskey',
    ])) {
      if (rawDbRecordBoundaryAllowlist.has(file)) continue;
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
    const temporaryReexport = 'client/src/core/platform/ecdsaRoleLocalRecords.ts';
    const violations: string[] = [];
    if (fs.existsSync(path.join(repoRoot, temporaryReexport))) {
      violations.push(`${temporaryReexport}: temporary re-export still exists`);
    }
    for (const file of listTypeScriptFilesInRoots(['client/src/core'])) {
      const source = readRepoFile(file);
      if (/platform\/ecdsaRoleLocalRecords/.test(source)) {
        violations.push(`${file}: imports temporary platform parser re-export`);
      }
    }
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('keeps hss-client bootstrap worker construction behind signer adapters', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(activeCoreSigningRoots)) {
      if (hssClientWorkerConstructionAllowlist.has(file)) continue;
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
      'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
    );
    const clientDts = readRepoFile('wasm/hss_client_signer/pkg/hss_client_signer.d.ts');

    expect(emailOtpWorkerSource).not.toContain(
      'threshold_ecdsa_hss_role_local_prepare_client_bootstrap',
    );
    expect(clientDts).not.toContain('threshold_ecdsa_hss_role_local_prepare_client_bootstrap');
    expect(emailOtpWorkerSource).toContain(
      'prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1',
    );
    expect(clientDts).toContain(
      'prepare_ecdsa_client_bootstrap_from_resolved_email_otp_root_v1',
    );
  });

  test('keeps signer-core command schemas generated from Rust', () => {
    const source = readRepoFile('client/src/core/platform/generated/signerCoreCommands.ts');

    expect(source).toContain('generated by `pnpm generate:signer-core-types`');
    expect(source).toContain('export type PrepareEcdsaClientBootstrapCommand');
    expect(source).toContain('export type FinalizeEcdsaClientBootstrapCommand');
    expect(source).toContain('export type PrepareEcdsaClientBootstrapErrorCode');
    expect(source).toContain('export type FinalizeEcdsaClientBootstrapErrorCode');
  });

  test('rejects hand-written signer-core command schema copies', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots(signerCommandSchemaRoots)) {
      if (signerCommandSchemaAllowlist.has(file)) continue;
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
    const registrationSource = readRepoFile('client/src/core/SeamsPasskey/registration.ts');
    const emailOtpSource = readRepoFile('client/src/core/SeamsPasskey/emailOtp.ts');
    const workerTypesSource = readRepoFile(
      'client/src/core/signingEngine/workerManager/workerTypes.ts',
    );

    expect(registrationSource).not.toContain('enrollment.clientRootShare32B64u');
    expect(emailOtpSource).not.toContain('clientRootShare32B64u: string;');
    expect(workerTypesSource).toContain('wallet_registration_ecdsa_prepare');
    expect(workerTypesSource).toContain(
      'prepareWalletRegistrationEcdsaPreparedClientBootstrapFromEmailOtpHandle',
    );
  });

  test('keeps ECDSA export flow from transporting client-root share strings', () => {
    const exportFlowSource = readRepoFile(
      'client/src/core/signingEngine/flows/recovery/ecdsaExportFlow.ts',
    );
    const exportBoundarySource = readRepoFile(
      'client/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts',
    );

    expect(exportFlowSource).not.toContain('clientRootShare32B64u');
    expect(exportBoundarySource).not.toContain('clientRootShare32B64u: string');
  });

  test('keeps cached passkey ECDSA export from collecting PRF material', () => {
    const exportFlowSource = readRepoFile(
      'client/src/core/signingEngine/flows/recovery/ecdsaExportFlow.ts',
    );
    const exportFunctionStart = exportFlowSource.indexOf(
      'export async function exportThresholdEcdsaKeyWithAuthorization',
    );
    expect(exportFunctionStart).toBeGreaterThanOrEqual(0);
    const exportFunctionSource = exportFlowSource.slice(exportFunctionStart);
    const cachedBranch = exportFunctionSource.indexOf('if (cachedArtifact)');
    const passkeyPrfAuthorization = exportFunctionSource.indexOf(
      'requestThresholdEcdsaExportAuthorization',
    );

    expect(cachedBranch).toBeGreaterThanOrEqual(0);
    expect(passkeyPrfAuthorization).toBeGreaterThanOrEqual(0);
    expect(cachedBranch).toBeLessThan(passkeyPrfAuthorization);
  });

  test('keeps Email OTP Ed25519 export material inside the Email OTP worker', () => {
    const workerTypesSource = readRepoFile(
      'client/src/core/signingEngine/workerManager/workerTypes.ts',
    );
    const exportRecoverySource = readRepoFile(
      'client/src/core/signingEngine/session/emailOtp/exportRecovery.ts',
    );
    const nearExportSource = readRepoFile(
      'client/src/core/signingEngine/flows/recovery/nearEd25519ExportFlow.ts',
    );

    expect(workerTypesSource).not.toContain('recoverEmailOtpEd25519ExportPrfFirst');
    expect(exportRecoverySource).not.toContain('thresholdEd25519PrfFirstB64u');
    expect(exportRecoverySource).not.toContain('prfFirstB64u: string');
    expect(nearExportSource).not.toContain('recoverEd25519ExportPrfFirst');
    expect(nearExportSource).toContain('exportEd25519SeedWithAuthorization');
  });

  test('keeps lifecycle worker results out of boolean success bags', () => {
    const workerTypesSource = readRepoFile(
      'client/src/core/signingEngine/workerManager/workerTypes.ts',
    );

    expect(workerTypesSource).not.toContain('result: { ok: boolean }');
    expect(workerTypesSource).toContain('ThresholdEcdsaPresignAbortResult');
    expect(workerTypesSource).toContain('threshold_ecdsa_presign_session_aborted');
  });
});
