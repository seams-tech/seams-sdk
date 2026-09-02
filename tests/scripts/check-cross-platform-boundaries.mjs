#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');

const guardedRoots = [
  'packages/wallet/src/core/signingEngine/session',
  'packages/wallet/src/core/signingEngine/flows',
  'packages/wallet/src/core/signingEngine/threshold',
  'packages/wallet/src/core/signingEngine/interfaces',
  'packages/wallet/src/core/signingEngine/useCases',
];

const activeCoreSigningRoots = [...guardedRoots, 'packages/wallet/src/core/signingEngine/chains'];

const platformBoundaryFiles = guardBoundaryFiles([
  {
    file: 'packages/wallet/src/core/signingEngine/flows/signEvmFamily/events.ts',
    owner: 'EVM-family diagnostics boundary',
    reason: 'reads browser diagnostics storage for signing event traces',
  },
  {
    file: 'packages/wallet/src/core/signingEngine/flows/signEvmFamily/accountAuth.ts',
    owner: 'EVM-family auth boundary',
    reason: 'checks browser credential availability before WebAuthn authentication',
  },
  {
    file: 'packages/wallet/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    owner: 'EVM-family public signing boundary',
    reason: 'coordinates browser diagnostics and runtime signing checks at the public flow edge',
  },
  {
    file: 'packages/wallet/src/core/signingEngine/flows/signEvmFamily/signers/webauthnP256.ts',
    owner: 'WebAuthn P-256 signer boundary',
    reason: 'performs direct WebAuthn P-256 assertions',
  },
  {
    file: 'packages/wallet/src/core/signingEngine/flows/signEvmFamily/webauthnP256KeyRef.ts',
    owner: 'WebAuthn P-256 key-ref boundary',
    reason: 'reads browser credential state for P-256 key references',
  },
  {
    file: 'packages/wallet/src/core/signingEngine/interfaces/operationDeps.ts',
    owner: 'operation dependency port boundary',
    reason: 'types runtime dependencies injected at signing operation edges',
  },
  {
    file: 'packages/wallet/src/core/signingEngine/interfaces/runtime.ts',
    owner: 'runtime dependency port boundary',
    reason: 'types platform runtime dependencies injected by assembly',
  },
  {
    file: 'packages/wallet/src/core/signingEngine/session/availability/availableSigningLanes.ts',
    owner: 'signing lane availability boundary',
    reason: 'checks browser persistence availability before reading lane state',
  },
  {
    file: 'packages/wallet/src/core/signingEngine/session/operationState/trace.ts',
    owner: 'operation trace diagnostics boundary',
    reason: 'reads browser diagnostics storage for operation traces',
  },
  {
    file: 'packages/wallet/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
    owner: 'passkey ECDSA bootstrap boundary',
    reason: 'receives browser storage and prompt ports for ECDSA bootstrap',
  },
  {
    file: 'packages/wallet/src/core/signingEngine/flows/recovery/passkeyEd25519YaoRecovery.ts',
    owner: 'passkey Ed25519 Yao recovery boundary',
    reason: 'coordinates exact-owner recovery persistence at the browser recovery edge',
  },
  {
    file: 'packages/wallet/src/core/signingEngine/session/passkey/ed25519YaoRecoverySource.ts',
    owner: 'passkey Ed25519 Yao recovery source boundary',
    reason: 'seals recovery source material with the browser WebCrypto boundary',
  },
  {
    file: 'packages/wallet/src/core/signingEngine/session/userPreferences.ts',
    owner: 'session preference persistence boundary',
    reason: 'reads browser local storage for user preferences',
  },
]);

const secretSourceCastBoundaryFiles = new Set([
  'packages/wallet/src/core/platform/types.typecheck.ts',
]);

const signerCommandSchemaBoundaryFiles = guardBoundaryFiles([
  {
    file: 'packages/wallet/src/core/platform/generated/signerCoreCommands.ts',
    owner: 'generated signer-core schemas',
    reason: 'this is the committed Rust-generated command schema file',
  },
  {
    file: 'packages/wallet/src/core/platform/signerCoreCommandAdapters.ts',
    owner: 'signer-core schema adapter',
    reason: 'this module is the only TypeScript wrapper layer for generated command schemas',
  },
  {
    file: 'packages/wallet/src/core/platform/signerCoreCommandAdapters.typecheck.ts',
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

const secretSourceCastPatterns = [
  /\bas\s+ClientSecretSource\b/,
  /\bas\s+WebAuthnPrfFirstSecretSource\b/,
  /\bas\s+EmailOtpWorkerSessionSecretSource\b/,
  /\bas\s+EmailOtpWorkerIssuedSessionHandle\b/,
  /\bas\s+SecureEnclaveWrappedSecretSource\b/,
  /\bas\s+Fido2HmacSecretSource\b/,
];

const signerCommandSchemaRoots = [
  'packages/wallet/src/core/platform',
  'packages/wallet/src/core/signingEngine/threshold',
  'packages/wallet/src/core/signingEngine/workerManager',
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
    file === 'packages/wallet/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts' ||
    file.startsWith('packages/wallet/src/core/signingEngine/assembly/')
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

function collectSecretSourceCastViolations() {
  return collectPatternViolations(
    listTypeScriptFilesInRoots(['packages/wallet/src/core/platform', ...guardedRoots]),
    secretSourceCastBoundaryFiles,
    secretSourceCastPatterns,
    'client secret source cast outside builder boundary',
  );
}

function collectRuntimePortsAggregateViolations() {
  const violations = [];
  const files = listTypeScriptFiles('packages/wallet/src/core/signingEngine');

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
  const files = listTypeScriptFiles('packages/wallet/src/core/signingEngine/useCases');

  for (const file of files) {
    const source = readRepoFile(file);
    if (/\bRuntimePorts\b/.test(source) || /\bcreateBrowserPlatformRuntime\b/.test(source)) {
      violations.push(`${file}: use-case service depends on RuntimePorts`);
    }
  }

  return violations;
}

function collectRoleLocalParserViolations() {
  const violations = [];
  const platformTypes = 'packages/wallet/src/core/platform/ecdsaRoleLocalRecords.ts';

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

  const files = listTypeScriptFilesInRoots(['packages/wallet/src/core']);
  for (const file of files) {
    if (file.startsWith('packages/wallet/src/core/platform/')) {
      continue;
    }
    const source = readRepoFile(file);
    if (/platform\/ecdsaRoleLocalRecords/.test(source)) {
      violations.push(`${file}: imports platform role-local types outside the platform barrel`);
    }
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
    'packages/wallet/src/SeamsWeb/operations/registration/registration.ts',
  );
  const workerTypesSource = readRepoFile(
    'packages/wallet/src/core/signingEngine/workerManager/workerTypes.ts',
  );

  if (registrationSource.includes('enrollment.clientRootShare32B64u')) {
    violations.push('registration.ts transports enrollment.clientRootShare32B64u');
  }
  if (workerTypesSource.includes('clientRootShare32B64u: string;')) {
    violations.push('workerTypes.ts exposes clientRootShare32B64u as a string');
  }

  return violations;
}

function collectEmailOtpEd25519ExportMaterialViolations() {
  const violations = [];
  const workerTypesSource = readRepoFile(
    'packages/wallet/src/core/signingEngine/workerManager/workerTypes.ts',
  );
  const exportRecoverySource = readRepoFile(
    'packages/wallet/src/core/signingEngine/session/emailOtp/exportRecovery.ts',
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
    'packages/wallet/src/core/signingEngine/workerManager/workerTypes.ts',
  );
  if (workerTypesSource.includes('result: { ok: boolean }')) {
    return ['workerTypes.ts exposes lifecycle worker result as boolean success bag'];
  }
  return [];
}

function main() {
  const violations = [
    ...collectPlatformApiViolations(),
    ...collectSecretSourceCastViolations(),
    ...collectRuntimePortsAggregateViolations(),
    ...collectUseCaseRuntimePortsViolations(),
    ...collectRoleLocalParserViolations(),
    ...collectHandWrittenSignerCommandSchemaViolations(),
    ...collectEmailOtpRegistrationPrepViolations(),
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
