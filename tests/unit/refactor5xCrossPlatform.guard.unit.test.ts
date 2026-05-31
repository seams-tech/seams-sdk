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
    ownerPhase: 'Phase 5',
    deletionTrigger:
      'EVM-family signing flow is routed through use-case services and browser-only diagnostics move behind a port.',
    reason: 'current flow-level event diagnostics read browser globals',
  },
  {
    file: 'client/src/core/signingEngine/flows/signEvmFamily/accountAuth.ts',
    ownerPhase: 'Phase 5',
    deletionTrigger: 'EVM-family auth flow receives browser capabilities through narrow ports.',
    reason: 'current flow-level auth helper still touches browser capability checks',
  },
  {
    file: 'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    ownerPhase: 'Phase 5',
    deletionTrigger: 'EVM-family signing flow is replaced by use-case service orchestration.',
    reason: 'current public flow still performs browser diagnostics and runtime checks',
  },
  {
    file: 'client/src/core/signingEngine/flows/signEvmFamily/signers/webauthnP256.ts',
    ownerPhase: 'Phase 5',
    deletionTrigger:
      'WebAuthn P-256 signing is accessed through AuthenticatorPort or a signer adapter.',
    reason: 'current signer helper performs direct WebAuthn calls',
  },
  {
    file: 'client/src/core/signingEngine/flows/signEvmFamily/webauthnP256KeyRef.ts',
    ownerPhase: 'Phase 5',
    deletionTrigger: 'WebAuthn key-ref lookup is parsed at the browser adapter boundary.',
    reason: 'current key-ref helper reads browser credential state',
  },
  {
    file: 'client/src/core/signingEngine/interfaces/operationDeps.ts',
    ownerPhase: 'Phase 5',
    deletionTrigger: 'operation deps are decomposed into narrow use-case ports.',
    reason: 'current shared dependency type still exposes browser runtime dependencies',
  },
  {
    file: 'client/src/core/signingEngine/interfaces/runtime.ts',
    ownerPhase: 'Phase 5',
    deletionTrigger: 'legacy runtime aggregate is replaced by assembly-owned narrow ports.',
    reason: 'current runtime type is the migration source for platform adapter extraction',
  },
  {
    file: 'client/src/core/signingEngine/interfaces/signing.ts',
    ownerPhase: 'Phase 6',
    deletionTrigger:
      'ECDSA signing schemas are generated from signer-core and raw HSS fields leave TypeScript domain types.',
    reason: 'current signing interfaces expose legacy browser signer material',
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
    ownerPhase: 'Phase 6',
    deletionTrigger: 'passkey ECDSA bootstrap moves onto signer-core command wrappers.',
    reason: 'current passkey bootstrap derives browser PRF-backed ECDSA material directly',
  },
  {
    file: 'client/src/core/signingEngine/session/passkey/ecdsaClientRoot.ts',
    ownerPhase: 'Phase 6',
    deletionTrigger: 'client-root derivation is isolated behind the browser signer crypto adapter.',
    reason: 'current helper derives ECDSA client-root material with browser crypto',
  },
  {
    file: 'client/src/core/signingEngine/session/userPreferences.ts',
    ownerPhase: 'Phase 8',
    deletionTrigger: 'session preference persistence is routed through the storage port.',
    reason: 'current preference helper reads browser local storage directly',
  },
]);

const rawHssAllowlist = guardAllowlist([
  {
    file: 'client/src/core/signingEngine/SigningEngine.ts',
    ownerPhase: 'Phase 5',
    deletionTrigger:
      'SigningEngine delegates ECDSA provisioning to ProvisionEcdsaUseCase and narrow signer ports.',
    reason: 'current assembly still prepares ECDSA bootstrap facts inline',
  },
  {
    file: 'client/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts',
    ownerPhase: 'Phase 7',
    deletionTrigger: 'ECDSA export moves onto ready blobs and signer-core export commands.',
    reason: 'current export boundary still consumes legacy HSS material',
  },
  {
    file: 'client/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts',
    ownerPhase: 'Phase 4',
    deletionTrigger:
      'ECDSA material state reads normalized ready records from the persistence parser.',
    reason: 'current material state bridges legacy signing-session records',
  },
  {
    file: 'client/src/core/signingEngine/flows/signEvmFamily/signers/secp256k1.ts',
    ownerPhase: 'Phase 8',
    deletionTrigger:
      'EVM signing session activation consumes ready records and signer command outputs.',
    reason: 'current signer path reads legacy backend client-share material',
  },
  {
    file: 'client/src/core/signingEngine/interfaces/signing.ts',
    ownerPhase: 'Phase 6',
    deletionTrigger: 'signer-core command schemas replace hand-written HSS field interfaces.',
    reason: 'current signing interfaces define legacy HSS field shapes',
  },
  {
    file: 'client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts',
    ownerPhase: 'Phase 3',
    deletionTrigger: 'ECDSA public facts use branded signer-core-owned public key domains.',
    reason: 'current identity helper validates legacy HSS public key strings',
  },
  {
    file: 'client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.typecheck.ts',
    ownerPhase: 'Phase 3',
    deletionTrigger: 'type fixtures move to the branded public-facts contract.',
    reason: 'current type fixture covers legacy HSS identity fields',
  },
  {
    file: 'client/src/core/signingEngine/session/passkey/ecdsaProvisioner.ts',
    ownerPhase: 'Phase 5',
    deletionTrigger: 'passkey ECDSA provisioning moves to ProvisionEcdsaUseCase.',
    reason: 'current provisioner still bridges raw bootstrap shares into signing-session state',
  },
  {
    file: 'client/src/core/signingEngine/session/persistence/records.ts',
    ownerPhase: 'Phase 4',
    deletionTrigger: 'ECDSA role-local records move to the canonical persistence parser.',
    reason: 'current persistence boundary parses legacy raw HSS records',
  },
  {
    file: 'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
    ownerPhase: 'Phase 6',
    deletionTrigger: 'signer-core ECDSA bootstrap command replaces helper-level HSS worker output.',
    reason: 'current browser signer crypto helper owns legacy HSS worker result parsing',
  },
  {
    file: 'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.typecheck.ts',
    ownerPhase: 'Phase 6',
    deletionTrigger: 'type fixtures move to generated signer-core command wrappers.',
    reason: 'current type fixture covers legacy HSS worker output',
  },
  {
    file: 'client/src/core/signingEngine/threshold/ecdsa/activation.ts',
    ownerPhase: 'Phase 8',
    deletionTrigger: 'activation use case consumes normalized ECDSA ready records.',
    reason: 'current activation path still references legacy HSS public facts',
  },
  {
    file: 'client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
    ownerPhase: 'Phase 6',
    deletionTrigger: 'ECDSA bootstrap internals move into signer-core command modules.',
    reason: 'current bootstrap session consumes helper-level HSS bootstrap output',
  },
  {
    file: 'client/src/core/signingEngine/threshold/ecdsa/keygen.ts',
    ownerPhase: 'Phase 6',
    deletionTrigger: 'ECDSA keygen consumes signer-core public facts and opaque ready blobs.',
    reason: 'current keygen path still maps legacy HSS public fields',
  },
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

const rawDbRecordBoundaryAllowlist = guardAllowlist([
  {
    file: 'client/src/core/signingEngine/session/persistence/records.ts',
    ownerPhase: 'Phase 4',
    deletionTrigger:
      'ECDSA role-local raw record parsing moves to client/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords.ts.',
    reason: 'current persistence parser accepts live raw ECDSA role-local records',
  },
]);

const rawDbRecordPatterns = [
  /\bEcdsaRoleLocalBoundaryRecord\b/,
  /\bEcdsaRoleLocalSessionRecordState\b/,
  /\bEcdsaRoleLocalRecordParseResult\b/,
  /\bparseRawEcdsaRoleLocalRecord\b/,
  /\becdsa_role_local_ready_record_v1\b/,
  /\blegacy_raw_role_local_v1\b/,
  /\bcurrent_unbranched_ready_record_v1\b/,
];

const hssClientWorkerConstructionAllowlist = guardAllowlist([
  {
    file: 'client/src/core/signingEngine/SigningEngine.ts',
    ownerPhase: 'Phase 5',
    deletionTrigger:
      'SigningEngine calls ProvisionEcdsaUseCase instead of the hss-client worker helper directly.',
    reason: 'current assembly prepares passkey ECDSA bootstrap via the legacy helper',
  },
  {
    file: 'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts',
    ownerPhase: 'Phase 6',
    deletionTrigger: 'browser signer crypto adapter calls generated signer-core command bindings.',
    reason: 'current helper constructs the hss-client bootstrap worker request',
  },
  {
    file: 'client/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.typecheck.ts',
    ownerPhase: 'Phase 6',
    deletionTrigger: 'type fixtures move to generated signer-core command wrappers.',
    reason: 'current fixture exercises the legacy hss-client bootstrap helper',
  },
  {
    file: 'client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
    ownerPhase: 'Phase 6',
    deletionTrigger:
      'ECDSA bootstrap session consumes signer-core command wrappers and opaque blobs.',
    reason: 'current bootstrap session consumes legacy hss-client bootstrap output',
  },
]);

const hssClientWorkerConstructionPatterns = [
  /\bWorkerRequestType\.BuildThresholdEcdsaHssRoleLocalClientBootstrap\b/,
  /\bbuildThresholdEcdsaHssRoleLocalClientBootstrapWasm\b/,
  /\bThresholdEcdsaHssRoleLocalClientBootstrap\b/,
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

  test('keeps raw ECDSA role-local record shapes inside persistence boundaries', () => {
    const violations: string[] = [];
    for (const file of listTypeScriptFilesInRoots([
      ...activeCoreSigningRoots,
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
