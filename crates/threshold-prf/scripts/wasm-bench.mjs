import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const crateDir = join(scriptDir, "..");
const benchCrateDir = join(crateDir, "wasm-bench");
const pkgDir = join(benchCrateDir, "pkg");
const resultsDir = join(crateDir, "target", "wasm-bench");
const resultsPath = join(resultsDir, "results.json");

run("wasm-pack", [
  "build",
  benchCrateDir,
  "--target",
  "nodejs",
  "--release",
  "--out-dir",
  "pkg",
]);

const wasmModule = await import(pathToFileURL(join(pkgDir, "threshold_prf_wasm_bench.js")));
const wasm = wasmModule.default?.benchmark_one_runtime_2_of_3 ? wasmModule.default : wasmModule;

const benches = [
  {
    name: "one_runtime_2_of_3_evaluate_partials_and_combine",
    iterations: 20_000,
    fn: wasm.benchmark_one_runtime_2_of_3,
  },
  {
    name: "one_runtime_3_of_5_evaluate_partials_and_combine",
    iterations: 10_000,
    fn: wasm.benchmark_one_runtime_3_of_5,
  },
  {
    name: "evaluate_partial_with_dleq_proof",
    iterations: 10_000,
    fn: wasm.benchmark_dleq_prove,
  },
  {
    name: "verify_partial_dleq_proof",
    iterations: 10_000,
    fn: wasm.benchmark_dleq_verify,
  },
  {
    name: "combine_verified_partials_3_of_5",
    iterations: 3_000,
    fn: wasm.benchmark_dleq_combine_verified_3_of_5,
  },
];

const results = [];
for (const bench of benches) {
  bench.fn(100);
  const start = performance.now();
  const checksum = bench.fn(bench.iterations);
  const elapsedMs = performance.now() - start;
  const nsPerOp = (elapsedMs * 1_000_000) / bench.iterations;
  results.push({
    name: bench.name,
    iterations: bench.iterations,
    elapsed_ms: elapsedMs,
    ns_per_op: nsPerOp,
    checksum,
  });
}

const payload = {
  date: new Date().toISOString(),
  runtime: `node ${process.version}`,
  target: "wasm32-unknown-unknown via wasm-pack --target nodejs --release",
  git: {
    revision: commandOutput("git", ["rev-parse", "HEAD"]),
    dirty_status: commandOutput("git", ["status", "--short"]),
  },
  results,
};

mkdirSync(resultsDir, { recursive: true });
writeFileSync(resultsPath, `${JSON.stringify(payload, null, 2)}\n`);

console.table(
  results.map((result) => ({
    benchmark: result.name,
    iterations: result.iterations,
    "time/op": formatNs(result.ns_per_op),
    checksum: result.checksum,
  })),
);
console.log(`wrote ${resultsPath}`);

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: crateDir,
    stdio: "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function commandOutput(command, args) {
  const result = spawnSync(command, args, {
    cwd: crateDir,
    encoding: "utf8",
  });
  if (result.error || result.status !== 0) {
    return null;
  }
  return result.stdout.trim();
}

function formatNs(ns) {
  if (ns >= 1_000_000) {
    return `${(ns / 1_000_000).toFixed(3)} ms`;
  }
  if (ns >= 1_000) {
    return `${(ns / 1_000).toFixed(3)} us`;
  }
  return `${ns.toFixed(3)} ns`;
}
