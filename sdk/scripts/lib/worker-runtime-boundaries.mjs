import fs from 'node:fs';
import path from 'node:path';

function toPosixPath(filePath) {
  return filePath.split(path.sep).join('/');
}

function findSubstringLineMatches(absolutePath, substring, repoRoot) {
  if (!fs.existsSync(absolutePath) || !fs.statSync(absolutePath).isFile()) {
    return [];
  }
  const source = fs.readFileSync(absolutePath, 'utf8');
  const lines = source.split(/\r?\n/);
  const matches = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.includes(substring)) continue;
    matches.push({
      file: toPosixPath(path.relative(repoRoot, absolutePath)),
      line: index + 1,
      pattern: substring,
      text: line.trim(),
    });
  }
  return matches;
}

function firstExistingLineMatch(paths, substring, repoRoot) {
  for (const relativePath of paths) {
    const absolutePath = path.join(repoRoot, relativePath);
    const matches = findSubstringLineMatches(absolutePath, substring, repoRoot);
    if (matches.length) return matches[0];
  }
  return null;
}

function collectSourceFiles(dir) {
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) return [];
  const out = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const absolute = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectSourceFiles(absolute));
      continue;
    }
    if (!entry.isFile()) continue;
    if (!absolute.endsWith('.ts') && !absolute.endsWith('.tsx')) continue;
    if (absolute.endsWith('.d.ts')) continue;
    out.push(absolute);
  }
  return out;
}

function findExistingPathViolations(paths, repoRoot) {
  const violations = [];
  for (const relativePath of paths) {
    const absolutePath = path.join(repoRoot, relativePath);
    if (!fs.existsSync(absolutePath)) continue;
    violations.push({
      file: toPosixPath(path.relative(repoRoot, absolutePath)),
      line: null,
      pattern: relativePath,
      text: 'legacy artifact exists and must be removed',
    });
  }
  return violations;
}

export function findWorkerRuntimeBoundaryViolations(repoRoot) {
  const executeHelperFile = 'client/src/core/signingEngine/workerManager/executeWorkerOperation.ts';
  const signingEngineRoot = path.join(repoRoot, 'client/src/core/signingEngine');
  const legacyWorkerRoot = 'client/src/core/workers';
  const workerTransportFiles = [
    'client/src/core/signingEngine/workerManager/workerTransport.ts',
  ];
  const workerRuntimeFiles = [
    'client/src/core/signingEngine/workerManager/workers/eth-signer.worker.ts',
    'client/src/core/signingEngine/workerManager/workers/tempo-signer.worker.ts',
  ];
  const forbiddenLegacyNearFiles = [
    'client/src/core/signingEngine/workerManager/backends/multichainWorkerBackend.ts',
    'client/src/core/signingEngine/workerManager/backends/nearWorkerBackend.ts',
    'client/src/core/signingEngine/workerManager/backends/multichainSignerWorkerTransport.ts',
    'client/src/core/signingEngine/workerManager/backends/nearSignerWorkerTransport.ts',
    'client/src/core/signingEngine/workerManager/nearKeyOpsService.ts',
    'client/src/core/signingEngine/workerManager/gateway.ts',
  ];
  const forbiddenLegacyWorkerRoots = [
    'client/src/core/signingEngine/workers',
  ];
  const exportRecoveryFile = 'client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts';
  const forbiddenLegacyExportFiles = [
    'client/src/core/signingEngine/workerManager/nearKeyOps/exportNearKeypairUi.ts',
  ];

  const checks = [];

  const executeHelperAbsolute = path.join(repoRoot, executeHelperFile);
  const executeHelperMatches = findSubstringLineMatches(
    executeHelperAbsolute,
    'requestMultichainWorkerOperation',
    repoRoot,
  );
  checks.push({
    id: 'execute-helper-context-enforcement',
    description: 'execute helper must dispatch through runtime context only',
    violations: executeHelperMatches,
  });

  const legacyWorkerRootAbsolute = path.join(repoRoot, legacyWorkerRoot);
  const legacyWorkerRootViolations = [];
  if (fs.existsSync(legacyWorkerRootAbsolute) && fs.statSync(legacyWorkerRootAbsolute).isDirectory()) {
    legacyWorkerRootViolations.push({
      file: toPosixPath(path.relative(repoRoot, legacyWorkerRootAbsolute)),
      line: null,
      pattern: legacyWorkerRoot,
      text: 'legacy worker root directory exists',
    });
  }
  checks.push({
    id: 'single-canonical-worker-runtime-root',
    description: 'legacy worker root client/src/core/workers must remain removed',
    violations: legacyWorkerRootViolations,
  });

  checks.push({
    id: 'legacy-near-worker-artifacts-removed',
    description: 'legacy NEAR worker transport/service shims must stay removed',
    violations: findExistingPathViolations(forbiddenLegacyNearFiles, repoRoot),
  });

  checks.push({
    id: 'no-top-level-signing-workers-root',
    description: 'worker runtimes must stay nested under workerManager/workers',
    violations: findExistingPathViolations(forbiddenLegacyWorkerRoots, repoRoot),
  });

  const typedErrorMatch = firstExistingLineMatch(
    workerTransportFiles,
    'SignerWorkerOperationError',
    repoRoot,
  );
  checks.push({
    id: 'typed-worker-error-propagation',
    description: 'worker transports must preserve typed error-code objects',
    violations: typedErrorMatch
      ? []
      : [
          {
            file: workerTransportFiles.join(','),
            line: null,
            pattern: 'SignerWorkerOperationError',
            text: 'missing in expected worker transport files',
          },
        ],
  });

  const runtimeCoreCodeMatch = firstExistingLineMatch(workerRuntimeFiles, 'coreCode', repoRoot);
  checks.push({
    id: 'worker-runtime-corecode-propagation',
    description: 'multichain workers must forward structured wasm error codes',
    violations: runtimeCoreCodeMatch
      ? []
      : [
          {
            file: workerRuntimeFiles.join(','),
            line: null,
            pattern: 'coreCode',
            text: 'missing in expected worker runtime files',
          },
        ],
  });

  const legacyExecutionRequestViolations = [];
  const signingEngineFiles = collectSourceFiles(signingEngineRoot);
  for (const filePath of signingEngineFiles) {
    legacyExecutionRequestViolations.push(
      ...findSubstringLineMatches(filePath, 'NearEd25519ExecutionRequest', repoRoot),
    );
  }
  checks.push({
    id: 'no-near-execution-closure-request-type',
    description: 'legacy NearEd25519ExecutionRequest type must not be reintroduced',
    violations: legacyExecutionRequestViolations,
  });

  const legacyTransportSymbolPatterns = [
    'requestMultichainWorkerOperation',
    'NearSignerWorkerTransport',
    'MultichainSignerWorkerTransport',
    'preWarmWorkerPool',
  ];
  const legacyTransportSymbolViolations = [];
  for (const filePath of signingEngineFiles) {
    for (const pattern of legacyTransportSymbolPatterns) {
      legacyTransportSymbolViolations.push(
        ...findSubstringLineMatches(filePath, pattern, repoRoot),
      );
    }
  }
  checks.push({
    id: 'no-legacy-signer-transport-symbols',
    description: 'legacy split transport and worker-pool symbols must stay removed',
    violations: legacyTransportSymbolViolations,
  });

  const touchConfirmDirectUsageAllowlist = new Set([
    'client/src/core/signingEngine/bootstrap/managerAssembly.ts',
    'client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts',
    'client/src/core/signingEngine/touchConfirm/types.ts',
  ]);
  const touchConfirmDirectUsagePatterns = [
    'touchConfirmManager',
    'TouchConfirmManager',
    'createTouchConfirmManager',
  ];
  const touchConfirmDirectUsageViolations = [];
  for (const filePath of signingEngineFiles) {
    const relativePath = toPosixPath(path.relative(repoRoot, filePath));
    if (touchConfirmDirectUsageAllowlist.has(relativePath)) continue;
    for (const pattern of touchConfirmDirectUsagePatterns) {
      touchConfirmDirectUsageViolations.push(
        ...findSubstringLineMatches(filePath, pattern, repoRoot),
      );
    }
  }
  checks.push({
    id: 'touchconfirm-manager-single-bridge-boundary',
    description: 'TouchConfirmManager direct usage must stay limited to manager assembly and manager-definition files',
    violations: touchConfirmDirectUsageViolations,
  });

  const awaitUserConfirmationAllowlist = new Set([
    'client/src/core/signingEngine/touchConfirm/awaitUserConfirmation.ts',
    'client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts',
  ]);
  const awaitUserConfirmationPatterns = [
    'awaitUserConfirmationV2(',
    'awaitUserConfirmationV2 = awaitUserConfirmationV2',
  ];
  const awaitUserConfirmationViolations = [];
  for (const filePath of signingEngineFiles) {
    const relativePath = toPosixPath(path.relative(repoRoot, filePath));
    if (awaitUserConfirmationAllowlist.has(relativePath)) continue;
    for (const pattern of awaitUserConfirmationPatterns) {
      awaitUserConfirmationViolations.push(
        ...findSubstringLineMatches(filePath, pattern, repoRoot),
      );
    }
  }
  checks.push({
    id: 'touchconfirm-await-user-confirmation-worker-owned',
    description: 'awaitUserConfirmationV2 usage must stay limited to passkey-confirm worker runtime and its bridge helper',
    violations: awaitUserConfirmationViolations,
  });

  checks.push({
    id: 'legacy-export-shortcut-artifacts-removed',
    description: 'legacy export shortcut wrapper modules must stay removed',
    violations: findExistingPathViolations(forbiddenLegacyExportFiles, repoRoot),
  });

  const exportRecoveryAbsolute = path.join(repoRoot, exportRecoveryFile);
  const exportShortcutForbiddenPatterns = [
    'touchConfirmManager',
    'getContext().requestUserConfirmation',
    'getPrfResultsFromCredential',
    'UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI',
  ];
  const exportShortcutPatternViolations = [];
  for (const pattern of exportShortcutForbiddenPatterns) {
    exportShortcutPatternViolations.push(
      ...findSubstringLineMatches(exportRecoveryAbsolute, pattern, repoRoot),
    );
  }
  checks.push({
    id: 'no-mainthread-export-confirmation-shortcuts',
    description: 'private key export API must not orchestrate confirmations or parse PRF in main thread',
    violations: exportShortcutPatternViolations,
  });

  const exportHardeningGuardMatch = firstExistingLineMatch(
    [exportRecoveryFile],
    'SIGNER_EXPORT_TEMP_DISABLED_LEGACY_SHORTCUT',
    repoRoot,
  );
  checks.push({
    id: 'export-hardening-typed-disable-code',
    description: 'export flow must provide typed fail-closed code for blocked legacy shortcut paths',
    violations: exportHardeningGuardMatch
      ? []
      : [
          {
            file: exportRecoveryFile,
            line: null,
            pattern: 'SIGNER_EXPORT_TEMP_DISABLED_LEGACY_SHORTCUT',
            text: 'missing typed fail-closed code in export orchestration',
          },
        ],
  });

  return {
    checks,
    error: null,
  };
}
