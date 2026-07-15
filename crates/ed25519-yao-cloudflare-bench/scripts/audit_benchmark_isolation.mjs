import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, extname, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const CORE_MANIFEST = "crates/ed25519-yao/Cargo.toml";
const CORE_SOURCE = "crates/ed25519-yao/src/lib.rs";
const BENCH_MANIFEST = "crates/ed25519-yao-cloudflare-bench/Cargo.toml";
const BENCH_SOURCE = "crates/ed25519-yao-cloudflare-bench/src/lib.rs";
const PRODUCT_ROOTS = Object.freeze([
  "apps",
  "clients",
  "examples",
  "packages",
  "tests",
  "voiceId",
  "crates/ecdsa-hss",
  "crates/router-ab-cloudflare",
  "crates/router-ab-core",
  "crates/router-ab-dev",
  "crates/seams-embedded",
  "crates/signer-core",
  "crates/signer-embedded-linux",
  "crates/threshold-prf",
]);
const SKIPPED_DIRECTORIES = new Set([
  ".git",
  "build",
  "bundled",
  "coverage",
  "dist",
  "node_modules",
  "pkg",
  "pkg-phase5",
  "target",
]);
const TEXT_EXTENSIONS = new Set([
  ".cjs",
  ".css",
  ".html",
  ".js",
  ".json",
  ".jsonc",
  ".jsx",
  ".mjs",
  ".rs",
  ".sh",
  ".toml",
  ".ts",
  ".tsx",
  ".yaml",
  ".yml",
]);
const FORBIDDEN_PRODUCT_TOKENS = Object.freeze([
  "ed25519-yao-cloudflare-bench",
  "ed25519_yao_cloudflare_bench",
  "phase9-role-benchmark",
  "phase9_role_benchmark",
  "passive-wasm-benchmark",
  "phase5_benchmark",
  "benchmark/activation",
  "phase9b-cloudflare-activation-128kib",
  "ed25519-yao-ab-benchmark",
]);
const AUTHORIZED_CORE_DEPENDENCIES = Object.freeze([
  Object.freeze({
    manifest: "crates/ed25519-yao-cloudflare-bench/Cargo.toml",
    kind: "normal",
    features: "phase9-role-benchmark",
  }),
  Object.freeze({
    manifest: "crates/ed25519-yao/formal-verification/verus/Cargo.toml",
    kind: "dev",
    features: "",
  }),
  Object.freeze({
    manifest: "crates/ed25519-yao/wasm-bench/Cargo.toml",
    kind: "normal",
    features: "passive-wasm-benchmark",
  }),
  Object.freeze({
    manifest: "crates/router-ab-ed25519-yao/Cargo.toml",
    kind: "normal",
    features: "local-protocol",
  }),
  Object.freeze({
    manifest: "tools/ed25519-yao-generator/Cargo.toml",
    kind: "normal",
    features: "",
  }),
]);

export class IsolationAuditError extends Error {
  constructor(code, field) {
    super(`${code}: ${field}`);
    this.name = "IsolationAuditError";
    this.code = code;
    this.field = field;
  }
}

function fail(code, field) {
  throw new IsolationAuditError(code, field);
}

function workspacePath(path) {
  return resolve(ROOT, path);
}

function normalizedRelative(path) {
  return relative(ROOT, path).split(sep).join("/");
}

function walkFiles(path, output) {
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    if (entry.isDirectory() && SKIPPED_DIRECTORIES.has(entry.name)) {
      continue;
    }
    const child = resolve(path, entry.name);
    if (entry.isDirectory()) {
      walkFiles(child, output);
    } else if (entry.isFile()) {
      output.push(child);
    }
  }
}

function collectManifestPaths() {
  const files = [];
  walkFiles(workspacePath("crates"), files);
  walkFiles(workspacePath("tools"), files);
  const manifests = [];
  for (const path of files) {
    if (path.endsWith(`${sep}Cargo.toml`)) {
      manifests.push(path);
    }
  }
  manifests.sort();
  return manifests;
}

function cargoMetadata(manifest) {
  const result = spawnSync(
    "cargo",
    ["metadata", "--offline", "--format-version", "1", "--no-deps", "--manifest-path", manifest],
    { cwd: ROOT, encoding: "utf8" },
  );
  if (result.error !== undefined || result.status !== 0) {
    fail("YAOS_ISOLATION_METADATA", normalizedRelative(manifest));
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    fail("YAOS_ISOLATION_METADATA_JSON", normalizedRelative(manifest));
  }
}

function dependencyKind(kind) {
  return kind === null ? "normal" : kind;
}

function collectDependencyRecords() {
  const core = [];
  const benchmark = [];
  const seen = new Set();
  for (const manifest of collectManifestPaths()) {
    const metadata = cargoMetadata(manifest);
    for (const packageRecord of metadata.packages) {
      const packageManifest = normalizedRelative(packageRecord.manifest_path);
      for (const dependency of packageRecord.dependencies) {
        if (dependency.name !== "ed25519-yao" && dependency.name !== "ed25519-yao-cloudflare-bench") {
          continue;
        }
        const features = [...dependency.features].sort().join(",");
        const record = Object.freeze({
          manifest: packageManifest,
          kind: dependencyKind(dependency.kind),
          features,
        });
        const identity = `${dependency.name}|${record.manifest}|${record.kind}|${record.features}`;
        if (seen.has(identity)) {
          continue;
        }
        seen.add(identity);
        if (dependency.name === "ed25519-yao") {
          core.push(record);
        } else {
          benchmark.push(record);
        }
      }
    }
  }
  core.sort(compareDependencyRecords);
  benchmark.sort(compareDependencyRecords);
  return Object.freeze({ core, benchmark });
}

function compareDependencyRecords(left, right) {
  return `${left.manifest}|${left.kind}|${left.features}`.localeCompare(
    `${right.manifest}|${right.kind}|${right.features}`,
  );
}

function collectProductReferences() {
  const references = [];
  let filesScanned = 0;
  for (const root of PRODUCT_ROOTS) {
    const files = [];
    walkFiles(workspacePath(root), files);
    for (const path of files) {
      if (!TEXT_EXTENSIONS.has(extname(path))) {
        continue;
      }
      filesScanned += 1;
      const source = readFileSync(path, "utf8");
      for (const token of FORBIDDEN_PRODUCT_TOKENS) {
        if (source.includes(token)) {
          references.push(Object.freeze({ path: normalizedRelative(path), token }));
        }
      }
    }
  }
  return Object.freeze({ filesScanned, references });
}

function collectWranglerConfigs() {
  const directory = workspacePath("crates/ed25519-yao-cloudflare-bench");
  const configs = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.startsWith("wrangler") || !entry.name.endsWith(".jsonc")) {
      continue;
    }
    const path = resolve(directory, entry.name);
    const parsed = JSON.parse(readFileSync(path, "utf8"));
    const classification = parsed.vars?.BENCHMARK_CLASSIFICATION;
    configs.push(Object.freeze({
      path: normalizedRelative(path),
      name: parsed.name,
      main: parsed.main,
      classification,
      hasProductionRoute: Object.hasOwn(parsed, "route") || Object.hasOwn(parsed, "routes"),
    }));
  }
  configs.sort(compareWranglerConfigs);
  return configs;
}

function compareWranglerConfigs(left, right) {
  return left.path.localeCompare(right.path);
}

function collectCoreBoundary() {
  const metadata = cargoMetadata(workspacePath(CORE_MANIFEST));
  const packageRecord = metadata.packages[0];
  const library = packageRecord.targets.find(findLibraryTarget);
  const manifest = readFileSync(workspacePath(CORE_MANIFEST), "utf8");
  const source = readFileSync(workspacePath(CORE_SOURCE), "utf8");
  return Object.freeze({
    publishRegistries: packageRecord.publish,
    defaultFeatures: packageRecord.features.default,
    featureNames: Object.keys(packageRecord.features).sort(),
    libraryCrateTypes: library?.crate_types ?? [],
    benchmarkBinaryRequiresPassiveFeature:
      manifest.includes('name = "benchmark_phase5_role"') &&
      manifest.includes('required-features = ["passive-benchmark"]'),
    phase9ExportIsCfgGated:
      source.includes('#[cfg(feature = "phase9-role-benchmark")]') &&
      source.includes("pub use passive::role_protocol::benchmark as phase9_role_benchmark;"),
    localExportIsCfgGated:
      source.includes('#[cfg(feature = "local-protocol")]') &&
      source.includes("pub use passive::role_protocol::benchmark as local_protocol;"),
    passiveModuleIsCfgGated:
      source.includes('feature = "passive-benchmark"') &&
      source.includes('feature = "passive-wasm-benchmark"') &&
      source.includes('feature = "phase9-role-benchmark"'),
  });
}

function findLibraryTarget(target) {
  return target.crate_types.includes("rlib");
}

function collectBenchmarkBoundary() {
  const metadata = cargoMetadata(workspacePath(BENCH_MANIFEST));
  const packageRecord = metadata.packages[0];
  const source = readFileSync(workspacePath(BENCH_SOURCE), "utf8");
  return Object.freeze({
    publishRegistries: packageRecord.publish,
    defaultFeatures: packageRecord.features.default,
    productionEligibleFalse:
      source.includes("pub(super) const PRODUCTION_ELIGIBLE: bool = false;"),
    fixedBenchmarkEndpoint:
      source.includes('pub(super) const BENCHMARK_PATH: &str = "/benchmark/activation";'),
  });
}

export function collectWorkspaceSnapshot() {
  const dependencies = collectDependencyRecords();
  const product = collectProductReferences();
  return {
    coreDependencies: dependencies.core,
    benchmarkDependencies: dependencies.benchmark,
    productFilesScanned: product.filesScanned,
    productReferences: product.references,
    wranglerConfigs: collectWranglerConfigs(),
    coreBoundary: collectCoreBoundary(),
    benchmarkBoundary: collectBenchmarkBoundary(),
  };
}

function dependencyIdentity(record) {
  return `${record.manifest}|${record.kind}|${record.features}`;
}

function requireAuthorizedDependencies(records) {
  if (records.length !== AUTHORIZED_CORE_DEPENDENCIES.length) {
    fail("YAOS_ISOLATION_CORE_DEPENDENCY_SET", "coreDependencies");
  }
  for (let index = 0; index < AUTHORIZED_CORE_DEPENDENCIES.length; index += 1) {
    if (dependencyIdentity(records[index]) !== dependencyIdentity(AUTHORIZED_CORE_DEPENDENCIES[index])) {
      fail("YAOS_ISOLATION_CORE_DEPENDENCY", records[index]?.manifest ?? String(index));
    }
  }
}

function requireWranglerIsolation(configs) {
  if (configs.length !== 19) {
    fail("YAOS_ISOLATION_WRANGLER_SET", "wranglerConfigs");
  }
  for (const config of configs) {
    if (
      typeof config.name !== "string" ||
      !config.name.includes("benchmark") ||
      typeof config.main !== "string" ||
      config.hasProductionRoute ||
      typeof config.classification !== "string" ||
      !config.classification.startsWith("NON_PRODUCTION")
    ) {
      fail("YAOS_ISOLATION_WRANGLER_CONFIG", config.path);
    }
  }
}

export function evaluateIsolation(snapshot) {
  requireAuthorizedDependencies(snapshot.coreDependencies);
  if (snapshot.benchmarkDependencies.length !== 0) {
    fail("YAOS_ISOLATION_BENCHMARK_DEPENDENT", snapshot.benchmarkDependencies[0].manifest);
  }
  if (snapshot.productFilesScanned < 100 || snapshot.productReferences.length !== 0) {
    fail("YAOS_ISOLATION_PRODUCT_REFERENCE", snapshot.productReferences[0]?.path ?? "scan");
  }
  requireWranglerIsolation(snapshot.wranglerConfigs);
  const core = snapshot.coreBoundary;
  if (
    core.publishRegistries.length !== 0 ||
    core.defaultFeatures.length !== 0 ||
    core.featureNames.join(",") !==
      "default,local-protocol,passive-benchmark,passive-wasm-benchmark,phase9-role-benchmark" ||
    core.libraryCrateTypes.join(",") !== "rlib" ||
    !core.benchmarkBinaryRequiresPassiveFeature ||
    !core.phase9ExportIsCfgGated ||
    !core.localExportIsCfgGated ||
    !core.passiveModuleIsCfgGated
  ) {
    fail("YAOS_ISOLATION_CORE_BOUNDARY", "coreBoundary");
  }
  const benchmark = snapshot.benchmarkBoundary;
  if (
    benchmark.publishRegistries.length !== 0 ||
    benchmark.defaultFeatures.length !== 0 ||
    !benchmark.productionEligibleFalse ||
    !benchmark.fixedBenchmarkEndpoint
  ) {
    fail("YAOS_ISOLATION_BENCHMARK_BOUNDARY", "benchmarkBoundary");
  }
  return Object.freeze({
    schema: "ed25519_yao_benchmark_isolation_audit_v1",
    status: "pass",
    production_reachable: false,
    authorized_core_dependents: snapshot.coreDependencies.length,
    benchmark_dependents: snapshot.benchmarkDependencies.length,
    product_files_scanned: snapshot.productFilesScanned,
    product_references: snapshot.productReferences.length,
    benchmark_wrangler_configs: snapshot.wranglerConfigs.length,
    production_routes: 0,
  });
}

function main() {
  process.stdout.write(`${JSON.stringify(evaluateIsolation(collectWorkspaceSnapshot()), null, 2)}\n`);
}

function handleFatal(error) {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

if (isMainModule()) {
  try {
    main();
  } catch (error) {
    handleFatal(error);
  }
}
