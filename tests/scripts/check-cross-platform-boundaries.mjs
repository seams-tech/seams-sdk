#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');

const guardedRoots = [
  'packages/sdk-web/src/core/signingEngine/session',
  'packages/sdk-web/src/core/signingEngine/flows',
  'packages/sdk-web/src/core/signingEngine/threshold',
  'packages/sdk-web/src/core/signingEngine/interfaces',
  'packages/sdk-web/src/core/signingEngine/useCases',
];

const activeCoreSigningRoots = [...guardedRoots, 'packages/sdk-web/src/core/signingEngine/chains'];

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
const rawDbRecordBoundaryFiles = guardBoundaryFiles([]);
const ecdsaDerivationClientWorkerConstructionBoundaryFiles = guardBoundaryFiles([]);
const secretSourceCastBoundaryFiles = new Set([
  'packages/sdk-web/src/core/platform/types.typecheck.ts',
]);

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

const rawClientRootSharePatterns = [/\bclientRootShare32\b/, /\bclientRootShare32B64u\b/];

const secretSourceCastPatterns = [
  /\bas\s+ClientSecretSource\b/,
  /\bas\s+WebAuthnPrfFirstSecretSource\b/,
  /\bas\s+EmailOtpWorkerSessionSecretSource\b/,
  /\bas\s+EmailOtpWorkerIssuedSessionHandle\b/,
  /\bas\s+SecureEnclaveWrappedSecretSource\b/,
  /\bas\s+Fido2HmacSecretSource\b/,
];

const rawDbRecordPatterns = [
  /\bEcdsaRoleLocalBoundaryRecord\b/,
  /\becdsa_role_local_ready_record_v1\b/,
  /\blegacy_raw_role_local_v1\b/,
  /\bcurrent_unbranched_ready_record_v1\b/,
];

const ecdsaDerivationClientWorkerConstructionPatterns = [
  /\bWorkerRequestType\.BuildThresholdEcdsaDerivationRoleLocalClientBootstrap\b/,
  /\bbuildThresholdEcdsaDerivationRoleLocalClientBootstrapWasm\b/,
  /\bThresholdEcdsaDerivationRoleLocalClientBootstrap\b/,
];

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

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function pathExists(relativePath) {
  return fs.existsSync(absolutePath(relativePath));
}

function readRepoFile(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function isTypeScriptFileName(fileName) {
  return /\.tsx?$/.test(fileName);
}

function listFiles(relativeDir, files) {
  const absoluteDir = absolutePath(relativeDir);
  if (!fs.existsSync(absoluteDir)) {
    return;
  }

  const entries = fs.readdirSync(absoluteDir, { withFileTypes: true });
  for (const entry of entries) {
    const relativePath = path.join(relativeDir, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) {
      listFiles(relativePath, files);
      continue;
    }
    if (entry.isFile() && isTypeScriptFileName(entry.name)) {
      files.push(relativePath);
    }
  }
}

function listTypeScriptFiles(relativeDir) {
  const files = [];
  listFiles(relativeDir, files);
  return files;
}

function listTypeScriptFilesInRoots(relativeRoots) {
  const files = new Set();

  for (const relativeRoot of relativeRoots) {
    const absoluteRoot = absolutePath(relativeRoot);
    if (!fs.existsSync(absoluteRoot)) {
      continue;
    }

    const stat = fs.statSync(absoluteRoot);
    if (stat.isDirectory()) {
      const rootFiles = listTypeScriptFiles(relativeRoot);
      for (const file of rootFiles) {
        files.add(file);
      }
      continue;
    }
    if (stat.isFile() && isTypeScriptFileName(relativeRoot)) {
      files.add(relativeRoot);
    }
  }

  return [...files].sort();
}

function guardBoundaryFiles(entries) {
  const seen = new Set();
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

function isRuntimePortsAssemblyFile(file) {
  return (
    file === 'packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts' ||
    file.startsWith('packages/sdk-web/src/core/signingEngine/assembly/')
  );
}

function collectPatternViolations(files, boundaryFiles, patterns, suffix) {
  const violations = [];
  for (const file of files) {
    if (boundaryFiles.has(file)) {
      continue;
    }
    const source = readRepoFile(file);
    for (const pattern of patterns) {
      if (pattern.test(source)) {
        violations.push(`${file}: ${suffix}: ${pattern}`);
      }
    }
  }
  return violations;
}

function collectPlatformApiViolations() {
  return collectPatternViolations(
    listTypeScriptFilesInRoots(guardedRoots),
    platformBoundaryFiles,
    platformLeakagePatterns,
    'platform API outside known adapter boundary',
  );
}

function collectRawHssViolations() {
  return collectPatternViolations(
    listTypeScriptFilesInRoots(activeCoreSigningRoots),
    rawHssBoundaryFiles,
    rawHssPatterns,
    'raw Router A/B ECDSA derivation share field in active core signing root',
  );
}

function collectClientRootShareViolations() {
  return collectPatternViolations(
    listTypeScriptFilesInRoots(activeCoreSigningRoots),
    new Set(),
    rawClientRootSharePatterns,
    'passkey ECDSA PRF material modeled as client-root share',
  );
}

function collectSecretSourceCastViolations() {
  return collectPatternViolations(
    listTypeScriptFilesInRoots(['packages/sdk-web/src/core/platform', ...guardedRoots]),
    secretSourceCastBoundaryFiles,
    secretSourceCastPatterns,
    'client secret source cast outside builder boundary',
  );
}

function collectRuntimePortsAggregateViolations() {
  const violations = [];
  const files = listTypeScriptFiles('packages/sdk-web/src/core/signingEngine');

  for (const file of files) {
    if (isRuntimePortsAssemblyFile(file)) {
      continue;
    }
    const source = readRepoFile(file);
    if (/\bRuntimePorts\b/.test(source) || /\bcreateBrowserPlatformRuntime\b/.test(source)) {
      violations.push(`${file}: RuntimePorts or createBrowserPlatformRuntime outside assembly`);
    }
  }

  return violations;
}

function collectUseCaseRuntimePortsViolations() {
  const violations = [];
  const files = listTypeScriptFiles('packages/sdk-web/src/core/signingEngine/useCases');

  for (const file of files) {
    const source = readRepoFile(file);
    if (/\bRuntimePorts\b/.test(source) || /\bcreateBrowserPlatformRuntime\b/.test(source)) {
      violations.push(`${file}: use-case service depends on RuntimePorts`);
    }
  }

  return violations;
}

function collectRawDbRecordViolations() {
  return collectPatternViolations(
    listTypeScriptFilesInRoots([
      ...activeCoreSigningRoots,
      'packages/sdk-web/src/core/platform',
      'packages/sdk-web/src/SeamsWeb',
    ]),
    rawDbRecordBoundaryFiles,
    rawDbRecordPatterns,
    'raw ECDSA role-local record shape outside persistence boundary',
  );
}

function collectRoleLocalParserViolations() {
  const violations = [];
  const platformTypes = 'packages/sdk-web/src/core/platform/ecdsaRoleLocalRecords.ts';

  if (pathExists(platformTypes)) {
    const source = readRepoFile(platformTypes);
    if (
      /\bexport function parse|\bfunction parseRaw|\bfrom ['"].*\/persistence\/records['"]/.test(
        source,
      )
    ) {
      violations.push(
        `${platformTypes}: parser implementation belongs in the persistence boundary`,
      );
    }
  }

  const files = listTypeScriptFilesInRoots(['packages/sdk-web/src/core']);
  for (const file of files) {
    if (file.startsWith('packages/sdk-web/src/core/platform/')) {
      continue;
    }
    const source = readRepoFile(file);
    if (/platform\/ecdsaRoleLocalRecords/.test(source)) {
      violations.push(`${file}: imports platform role-local types outside the platform barrel`);
    }
  }

  return violations;
}

function collectEcdsaDerivationClientWorkerConstructionViolations() {
  return collectPatternViolations(
    listTypeScriptFilesInRoots(activeCoreSigningRoots),
    ecdsaDerivationClientWorkerConstructionBoundaryFiles,
    ecdsaDerivationClientWorkerConstructionPatterns,
    'ECDSA derivation client bootstrap worker construction outside signer adapter',
  );
}

function collectLegacyRootShareFfiViolations() {
  const violations = [];
  const emailOtpWorkerSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  );
  const clientDts = readRepoFile('wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client.d.ts');
  const legacyFfi = 'threshold_ecdsa_derivation_role_local_prepare_client_bootstrap';

  if (emailOtpWorkerSource.includes(legacyFfi)) {
    violations.push('email-otp.worker.ts contains legacy root-share ECDSA prepare FFI');
  }
  if (clientDts.includes(legacyFfi)) {
    violations.push('router_ab_ecdsa_derivation_client.d.ts contains legacy root-share ECDSA prepare FFI');
  }

  return violations;
}

function collectHandWrittenSignerCommandSchemaViolations() {
  return collectPatternViolations(
    listTypeScriptFilesInRoots(signerCommandSchemaRoots),
    signerCommandSchemaBoundaryFiles,
    handWrittenSignerCommandSchemaPatterns,
    'hand-written signer-core command schema copy',
  );
}

function collectEmailOtpRegistrationPrepViolations() {
  const violations = [];
  const registrationSource = readRepoFile(
    'packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts',
  );
  const emailOtpSource = readRepoFile(
    'packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/prewarmedRegistrationMaterial.ts',
  );
  const workerTypesSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
  );

  if (registrationSource.includes('enrollment.clientRootShare32B64u')) {
    violations.push('registration.ts transports enrollment.clientRootShare32B64u');
  }
  if (emailOtpSource.includes('clientRootShare32B64u: string;')) {
    violations.push(
      'emailOtp/prewarmedRegistrationMaterial.ts exposes clientRootShare32B64u as a string',
    );
  }
  if (workerTypesSource.includes('clientRootShare32B64u: string;')) {
    violations.push('workerTypes.ts exposes clientRootShare32B64u as a string');
  }

  return violations;
}

function collectEcdsaExportClientRootShareViolations() {
  const violations = [];
  const exportFlowSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportFlow.ts',
  );
  const exportBoundarySource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaDerivationExport.ts',
  );

  if (exportFlowSource.includes('clientRootShare32B64u')) {
    violations.push('ecdsaExportFlow.ts transports clientRootShare32B64u');
  }
  if (exportBoundarySource.includes('clientRootShare32B64u: string')) {
    violations.push('ecdsaDerivationExport.ts exposes clientRootShare32B64u as a string');
  }

  return violations;
}

function collectEmailOtpEd25519ExportMaterialViolations() {
  const violations = [];
  const workerTypesSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
  );
  const exportRecoverySource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.ts',
  );

  if (workerTypesSource.includes('recoverEmailOtpEd25519ExportPrfFirst')) {
    violations.push('workerTypes.ts exposes recoverEmailOtpEd25519ExportPrfFirst');
  }
  if (exportRecoverySource.includes('thresholdEd25519PrfFirstB64u')) {
    violations.push('emailOtp/exportRecovery.ts exposes thresholdEd25519PrfFirstB64u');
  }
  if (exportRecoverySource.includes('prfFirstB64u: string')) {
    violations.push('emailOtp/exportRecovery.ts exposes prfFirstB64u as a string');
  }
  return violations;
}

function collectLifecycleWorkerResultViolations() {
  const workerTypesSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts',
  );
  if (workerTypesSource.includes('result: { ok: boolean }')) {
    return ['workerTypes.ts exposes lifecycle worker result as boolean success bag'];
  }
  return [];
}

function main() {
  const violations = [
    ...collectPlatformApiViolations(),
    ...collectRawHssViolations(),
    ...collectClientRootShareViolations(),
    ...collectSecretSourceCastViolations(),
    ...collectRuntimePortsAggregateViolations(),
    ...collectUseCaseRuntimePortsViolations(),
    ...collectRawDbRecordViolations(),
    ...collectRoleLocalParserViolations(),
    ...collectEcdsaDerivationClientWorkerConstructionViolations(),
    ...collectLegacyRootShareFfiViolations(),
    ...collectHandWrittenSignerCommandSchemaViolations(),
    ...collectEmailOtpRegistrationPrepViolations(),
    ...collectEcdsaExportClientRootShareViolations(),
    ...collectEmailOtpEd25519ExportMaterialViolations(),
    ...collectLifecycleWorkerResultViolations(),
  ];

  if (violations.length > 0) {
    console.error('[check-cross-platform-boundaries] failed');
    for (const violation of violations) {
      console.error(`- ${violation}`);
    }
    process.exitCode = 1;
    return;
  }

  console.log('[check-cross-platform-boundaries] passed');
}

main();
