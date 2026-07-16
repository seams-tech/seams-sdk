#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import zlib from 'node:zlib';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const sdkRoot = path.resolve(scriptDirectory, '../..');
const repoRoot = path.resolve(sdkRoot, '../..');
const iterations = 9;
const reportOutputPath = process.argv[2]
  ? path.resolve(process.cwd(), process.argv[2])
  : null;

const workerBundles = [
  {
    id: 'ed25519Signer',
    path: 'packages/sdk-web/dist/workers/near-signer.worker.js',
    ownedWasmArtifacts: ['wasm_signer_worker_bg.wasm'],
  },
  {
    id: 'ecdsaDerivationClient',
    path: 'packages/sdk-web/dist/workers/ecdsa-derivation-client.worker.js',
    ownedWasmArtifacts: ['router_ab_ecdsa_derivation_client_bg.wasm'],
  },
  {
    id: 'ecdsaPresignClient',
    path: 'packages/sdk-web/dist/workers/ecdsa-presign-client.worker.js',
    ownedWasmArtifacts: ['router_ab_ecdsa_presign_client_bg.wasm'],
  },
  {
    id: 'ecdsaOnlineClient',
    path: 'packages/sdk-web/dist/workers/ecdsa-online-client.worker.js',
    ownedWasmArtifacts: ['router_ab_ecdsa_online_client_bg.wasm'],
  },
  {
    id: 'emailOtp',
    path: 'packages/sdk-web/dist/workers/email-otp.worker.js',
    ownedWasmArtifacts: [
      'email_otp_runtime_bg.wasm',
      'router_ab_ecdsa_derivation_client_bg.wasm',
      'router_ab_ed25519_yao_client_bg.wasm',
    ],
  },
];

const targets = [
  {
    id: 'ed25519YaoClient',
    packageDirectory: 'crates/router-ab-ed25519-yao-client/pkg',
    moduleName: 'router_ab_ed25519_yao_client',
    wasmBudget: { raw: 556_435, gzip: 223_677 },
    firstOperation: 'initialization_only',
  },
  {
    id: 'ecdsaDerivationClient',
    packageDirectory: 'wasm/router_ab_ecdsa_derivation_client/pkg',
    moduleName: 'router_ab_ecdsa_derivation_client',
    wasmBudget: { raw: 630_000, gzip: 250_000 },
    firstOperation: 'client_ceremony_public_key',
  },
  {
    id: 'ecdsaPresignClient',
    packageDirectory: 'wasm/router_ab_ecdsa_presign_client/pkg',
    moduleName: 'router_ab_ecdsa_presign_client',
    wasmBudget: null,
    firstOperation: 'map_fixed_2p_additive_share',
  },
  {
    id: 'ecdsaOnlineClient',
    packageDirectory: 'wasm/router_ab_ecdsa_online_client/pkg',
    moduleName: 'router_ab_ecdsa_online_client',
    wasmBudget: null,
    firstOperation: 'online_client_init_marker',
  },
];

const operationLazyProfiles = [
  {
    operation: 'ed25519_registration_recovery_refresh_export',
    workerBundles: ['ed25519Signer', 'emailOtp'],
    requiredArtifacts: ['router_ab_ed25519_yao_client_bg.wasm'],
  },
  {
    operation: 'ecdsa_registration_recovery_refresh_export',
    workerBundles: ['ecdsaDerivationClient', 'emailOtp'],
    requiredArtifacts: ['router_ab_ecdsa_derivation_client_bg.wasm'],
  },
  {
    operation: 'ed25519_normal_signing',
    workerBundles: ['ed25519Signer'],
    requiredArtifacts: ['wasm_signer_worker_bg.wasm'],
  },
  {
    operation: 'ecdsa_normal_signing_role_local',
    workerBundles: ['ecdsaDerivationClient', 'ecdsaPresignClient', 'ecdsaOnlineClient'],
    requiredArtifacts: [
      'router_ab_ecdsa_derivation_client_bg.wasm',
      'router_ab_ecdsa_presign_client_bg.wasm',
      'router_ab_ecdsa_online_client_bg.wasm',
    ],
  },
  {
    operation: 'ecdsa_normal_signing_email_otp',
    workerBundles: ['emailOtp', 'ecdsaPresignClient', 'ecdsaOnlineClient'],
    requiredArtifacts: [
      'email_otp_runtime_bg.wasm',
      'router_ab_ecdsa_presign_client_bg.wasm',
      'router_ab_ecdsa_online_client_bg.wasm',
    ],
  },
];

function readBytes(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath));
}

function compressedSizes(bytes) {
  return {
    raw: bytes.length,
    gzip: zlib.gzipSync(bytes, { level: 9 }).length,
    brotli: zlib.brotliCompressSync(bytes, {
      params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11 },
    }).length,
  };
}

function directoryFiles(relativeDirectory) {
  const directory = path.join(repoRoot, relativeDirectory);
  return fs
    .readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(relativeDirectory, entry.name))
    .sort();
}

function directoryRawBytes(relativeDirectory) {
  return directoryFiles(relativeDirectory).reduce(
    (total, relativePath) => total + fs.statSync(path.join(repoRoot, relativePath)).size,
    0,
  );
}

function recursiveRawBytes(relativeDirectory) {
  const root = path.join(repoRoot, relativeDirectory);
  let total = 0;
  const pending = [root];
  while (pending.length > 0) {
    const current = pending.pop();
    if (!current) continue;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const child = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(child);
      if (entry.isFile()) total += fs.statSync(child).size;
    }
  }
  return total;
}

function percentile(samples, quantile) {
  const sorted = [...samples].sort((left, right) => left - right);
  const index = Math.min(sorted.length - 1, Math.floor(sorted.length * quantile));
  return Number(sorted[index].toFixed(3));
}

function measureSync(operation) {
  const samples = [];
  for (let index = 0; index < iterations; index += 1) {
    const startedAt = performance.now();
    operation();
    samples.push(performance.now() - startedAt);
  }
  return {
    iterations,
    medianMs: percentile(samples, 0.5),
    p95Ms: percentile(samples, 0.95),
    maxMs: Number(Math.max(...samples).toFixed(3)),
  };
}

function wasmMemoryBytes(initializationOutput) {
  return initializationOutput.memory instanceof WebAssembly.Memory
    ? initializationOutput.memory.buffer.byteLength
    : null;
}

function firstOperation(target, importedModule) {
  switch (target.firstOperation) {
    case 'initialization_only':
      return { kind: target.firstOperation, latency: null };
    case 'client_ceremony_public_key': {
      const latency = measureSync(() => {
        const ceremony = new importedModule.RouterAbEcdsaClientCeremonyV1();
        ceremony.public_key();
        ceremony.close();
        ceremony.free();
      });
      return { kind: target.firstOperation, latency };
    }
    case 'map_fixed_2p_additive_share': {
      importedModule.init_router_ab_ecdsa_presign_client();
      const additiveShare32 = new Uint8Array(32);
      additiveShare32[31] = 1;
      const latency = measureSync(() => {
        const mapped = importedModule.map_client_additive_share_2p(additiveShare32);
        mapped.fill(0);
      });
      additiveShare32.fill(0);
      return { kind: target.firstOperation, latency };
    }
    case 'online_client_init_marker': {
      const latency = measureSync(() => importedModule.init_router_ab_ecdsa_online_client());
      return { kind: target.firstOperation, latency };
    }
    default:
      throw new Error(`Unknown first operation: ${target.firstOperation}`);
  }
}

async function measureTarget(target) {
  const wasmRelativePath = `${target.packageDirectory}/${target.moduleName}_bg.wasm`;
  const glueRelativePath = `${target.packageDirectory}/${target.moduleName}.js`;
  const declarationRelativePath = `${target.packageDirectory}/${target.moduleName}.d.ts`;
  const wasmBytes = readBytes(wasmRelativePath);
  const wasmSizes = compressedSizes(wasmBytes);
  const validate = measureSync(() => {
    if (!WebAssembly.validate(wasmBytes)) throw new Error(`${target.id} WASM validation failed`);
  });
  const compile = measureSync(() => new WebAssembly.Module(wasmBytes));
  const importedModule = await import(
    `${pathToFileURL(path.join(repoRoot, glueRelativePath)).href}?evidence=${Date.now()}-${target.id}`
  );
  const rssBeforeInit = process.memoryUsage().rss;
  const initStartedAt = performance.now();
  const initializationOutput = importedModule.initSync({ module: wasmBytes });
  const initializationMs = Number((performance.now() - initStartedAt).toFixed(3));
  const rssAfterInit = process.memoryUsage().rss;
  const operation = firstOperation(target, importedModule);
  const rssAfterFirstOperation = process.memoryUsage().rss;
  const budget = target.wasmBudget;
  const budgetResult = budget
    ? {
        rawPass: wasmSizes.raw <= budget.raw,
        gzipPass: wasmSizes.gzip <= budget.gzip,
        pass: wasmSizes.raw <= budget.raw && wasmSizes.gzip <= budget.gzip,
      }
    : null;
  return {
    id: target.id,
    files: {
      wasm: { path: wasmRelativePath, ...wasmSizes },
      javascriptGlue: {
        path: glueRelativePath,
        ...compressedSizes(readBytes(glueRelativePath)),
      },
      declarations: {
        path: declarationRelativePath,
        ...compressedSizes(readBytes(declarationRelativePath)),
      },
      sourceMaps: directoryFiles(target.packageDirectory)
        .filter((relativePath) => relativePath.endsWith('.map'))
        .map((relativePath) => ({ path: relativePath, ...compressedSizes(readBytes(relativePath)) })),
      packageRawBytes: directoryRawBytes(target.packageDirectory),
    },
    runtime: {
      validate,
      compile,
      initializationMs,
      wasmLinearMemoryBytesAfterInit: wasmMemoryBytes(initializationOutput),
      processRssBytes: {
        beforeInit: rssBeforeInit,
        afterInit: rssAfterInit,
        afterFirstOperation: rssAfterFirstOperation,
        observedMaximum: Math.max(rssBeforeInit, rssAfterInit, rssAfterFirstOperation),
      },
      firstOperation: operation,
    },
    budget,
    budgetResult,
  };
}

function sha256(relativePath) {
  return crypto.createHash('sha256').update(readBytes(relativePath)).digest('hex');
}

function measureWorkerBundle(bundle) {
  const source = readBytes(bundle.path).toString('utf8');
  const artifactEvidence = bundle.ownedWasmArtifacts.map((artifact) => ({
    artifact,
    referencedByGeneratedBundle: source.includes(artifact),
  }));
  return {
    id: bundle.id,
    path: bundle.path,
    sizes: compressedSizes(Buffer.from(source)),
    artifactEvidence,
    pass: artifactEvidence.every((entry) => entry.referencedByGeneratedBundle),
  };
}

function verifyLazyProfile(profile, measuredWorkerBundles) {
  const selectedBundles = measuredWorkerBundles.filter((bundle) =>
    profile.workerBundles.includes(bundle.id),
  );
  const referencedArtifacts = new Set(
    selectedBundles.flatMap((bundle) =>
      bundle.artifactEvidence
        .filter((entry) => entry.referencedByGeneratedBundle)
        .map((entry) => entry.artifact),
    ),
  );
  const missingArtifacts = profile.requiredArtifacts.filter(
    (artifact) => !referencedArtifacts.has(artifact),
  );
  return {
    ...profile,
    missingArtifacts,
    pass: selectedBundles.length === profile.workerBundles.length && missingArtifacts.length === 0,
  };
}

const measuredTargets = [];
for (const target of targets) measuredTargets.push(await measureTarget(target));
const measuredWorkerBundles = workerBundles.map(measureWorkerBundle);
const measuredLazyProfiles = operationLazyProfiles.map((profile) =>
  verifyLazyProfile(profile, measuredWorkerBundles),
);
const failedBudgets = measuredTargets.filter((target) => target.budgetResult?.pass === false);
const failedWorkerBundles = measuredWorkerBundles.filter((bundle) => !bundle.pass);
const failedLazyProfiles = measuredLazyProfiles.filter((profile) => !profile.pass);
const report = {
  schema: 'yaos_ab_phase14b_local_artifact_evidence_v1',
  generatedAt: new Date().toISOString(),
  environment: {
    runtime: process.version,
    platform: process.platform,
    architecture: process.arch,
    pnpmLockSha256: sha256('pnpm-lock.yaml'),
  },
  measurements: measuredTargets,
  generatedWorkerBundleEvidence: measuredWorkerBundles,
  operationLazyProfiles: measuredLazyProfiles,
  totals: {
    sdkDistributionRawBytes: recursiveRawBytes('packages/sdk-web/dist'),
  },
  gates: {
    frozenWasmBudgetsPass: failedBudgets.length === 0,
    failedBudgetArtifacts: failedBudgets.map((target) => target.id),
    generatedWorkerOwnershipPass: failedWorkerBundles.length === 0,
    failedWorkerBundles: failedWorkerBundles.map((bundle) => bundle.id),
    operationLazyProfilesPass: failedLazyProfiles.length === 0,
    failedOperationLazyProfiles: failedLazyProfiles.map((profile) => profile.operation),
  },
};

const serializedReport = `${JSON.stringify(report, null, 2)}\n`;
if (reportOutputPath) {
  fs.mkdirSync(path.dirname(reportOutputPath), { recursive: true });
  fs.writeFileSync(reportOutputPath, serializedReport, { mode: 0o600 });
}
console.log(serializedReport);
if (failedBudgets.length > 0 || failedWorkerBundles.length > 0 || failedLazyProfiles.length > 0) {
  process.exitCode = 1;
}
