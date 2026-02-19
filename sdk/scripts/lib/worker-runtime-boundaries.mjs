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

export function findWorkerRuntimeBoundaryViolations(repoRoot) {
  const executeHelperFile = 'client/src/core/signing/workers/operations/executeSignerWorkerOperation.ts';
  const legacyWorkerRoot = 'client/src/core/workers';
  const workerBoundaryFiles = [
    'client/src/core/signing/workers/signerWorkerManager/backends/multichainWorkerBackend.ts',
    'client/src/core/signing/workers/signerWorkerManager/backends/nearWorkerBackend.ts',
    'client/src/core/signing/workers/eth-signer.worker.ts',
    'client/src/core/signing/workers/tempo-signer.worker.ts',
  ];
  const workerTransportFiles = [
    'client/src/core/signing/workers/signerWorkerManager/backends/multichainWorkerBackend.ts',
    'client/src/core/signing/workers/signerWorkerManager/backends/nearWorkerBackend.ts',
  ];
  const workerRuntimeFiles = [
    'client/src/core/signing/workers/eth-signer.worker.ts',
    'client/src/core/signing/workers/tempo-signer.worker.ts',
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

  const contractVersionMatch = firstExistingLineMatch(
    workerBoundaryFiles,
    'resolveSignerWorkerContractVersion',
    repoRoot,
  );
  checks.push({
    id: 'worker-contract-version-guardrails',
    description: 'signer worker backends/workers must enforce contract version guardrails',
    violations: contractVersionMatch
      ? []
      : [
          {
            file: workerBoundaryFiles.join(','),
            line: null,
            pattern: 'resolveSignerWorkerContractVersion',
            text: 'missing in expected worker boundary files',
          },
        ],
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

  return {
    checks,
    error: null,
  };
}
