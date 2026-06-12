import { spawnSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(scriptDir, "..", "..", "..");
const wasmCrateDir = join(repoRoot, "wasm", "threshold_prf");
const workerBenchDir = join(repoRoot, "crates", "threshold-prf", "worker-bench");
const outDir = join(workerBenchDir, "vendor", "threshold_prf");

rmSync(outDir, { recursive: true, force: true });
run("wasm-pack", [
  "build",
  wasmCrateDir,
  "--target",
  "web",
  "--release",
  "--out-dir",
  outDir,
  "--out-name",
  "threshold_prf",
]);

for (const path of [
  join(outDir, "threshold_prf.js"),
  join(outDir, "threshold_prf_bg.wasm"),
]) {
  if (!existsSync(path)) {
    throw new Error(`wasm-pack did not produce ${path}`);
  }
}

console.log(`built Worker benchmark WASM package at ${outDir}`);

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
