import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const REPOSITORY_ROOT = resolve(process.cwd(), "../..");

const WASM_FEATURE_SETS = Object.freeze([
  "deriver-a",
  "deriver-a-cross-account",
  "deriver-b",
  "deriver-b-cross-account",
  "deriver-a,fault-fragmentation",
  "deriver-b,fault-fragmentation",
  "deriver-a,fault-request-disconnect-after-base-choices",
  "deriver-b,fault-response-disconnect-after-offer",
  "deriver-b,fault-trailing-after-terminal",
  "deriver-a,fault-short-timeout",
  "deriver-b,fault-stall-after-offer",
  "deriver-b,fault-wrong-role-offer-tag",
  "deriver-b,fault-session-mismatch",
]);

const WORKER_BUILD_SCRIPTS = Object.freeze([
  "build:a",
  "build:a:cross-account",
  "build:b",
  "build:b:cross-account",
  "build:fault:fragmentation:a",
  "build:fault:fragmentation:b",
  "build:fault:request-disconnect:a",
  "build:fault:response-disconnect:b",
  "build:fault:trailing:b",
  "build:fault:timeout:a",
  "build:fault:stall:b",
  "build:fault:wrong-role:b",
  "build:fault:session-mismatch:b",
]);

const WRANGLER_DRY_RUN_SCRIPTS = Object.freeze([
  "dry-run:a",
  "dry-run:a:cross-account",
  "dry-run:b",
  "dry-run:b:cross-account",
]);

function execute(command, args, environment, workingDirectory) {
  const result = spawnSync(command, args, {
    cwd: workingDirectory,
    env: environment,
    stdio: "inherit",
  });
  if (result.error !== undefined) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with status ${result.status}`);
  }
}

function run(command, args) {
  execute(command, args, process.env, process.cwd());
}

function runAtRepositoryRoot(command, args) {
  execute(command, args, process.env, REPOSITORY_ROOT);
}

function runAtRepositoryRootWithEnvironment(command, args, environment) {
  execute(command, args, environment, REPOSITORY_ROOT);
}

function runWranglerScript(script) {
  execute(
    "npm",
    ["run", script],
    {
      ...process.env,
      WRANGLER_LOG_PATH: "/tmp/ed25519-yao-wrangler.log",
    },
    process.cwd(),
  );
}

function runCargoChecks() {
  run("cargo", ["fmt", "--check"]);
  run("cargo", ["test", "--no-default-features"]);
  run("cargo", ["clippy", "--all-targets", "--no-default-features", "--", "-D", "warnings"]);
  for (const features of WASM_FEATURE_SETS) {
    run("cargo", [
      "clippy",
      "--target",
      "wasm32-unknown-unknown",
      "--no-default-features",
      "--features",
      features,
      "--",
      "-D",
      "warnings",
    ]);
  }
}

function runCoreCorrectnessChecks() {
  runAtRepositoryRoot("cargo", [
    "fmt",
    "--manifest-path",
    "crates/ed25519-yao/Cargo.toml",
    "--",
    "--check",
  ]);
  runAtRepositoryRoot("cargo", [
    "test",
    "--manifest-path",
    "crates/ed25519-yao/Cargo.toml",
    "--features",
    "passive-benchmark",
  ]);
  runAtRepositoryRoot("cargo", [
    "clippy",
    "--manifest-path",
    "crates/ed25519-yao/Cargo.toml",
    "--all-targets",
    "--features",
    "passive-benchmark",
    "--",
    "-D",
    "warnings",
  ]);
  runAtRepositoryRoot("cargo", [
    "clippy",
    "--manifest-path",
    "crates/ed25519-yao/Cargo.toml",
    "--features",
    "passive-wasm-benchmark",
    "--target",
    "wasm32-unknown-unknown",
    "--",
    "-D",
    "warnings",
  ]);
  runAtRepositoryRoot("cargo", [
    "clippy",
    "--manifest-path",
    "crates/ed25519-yao/wasm-bench/Cargo.toml",
    "--target",
    "wasm32-unknown-unknown",
    "--",
    "-D",
    "warnings",
  ]);
  runAtRepositoryRoot("python3", ["tools/ed25519-yao-verifier/test_phase5_stream_kats.py"]);
  runAtRepositoryRoot("cargo", ["yao-fv", "cross-language-check"]);
  runAtRepositoryRoot("cargo", ["yao-fv", "parity"]);
}

function runCoreWasmStreamingChecks() {
  runAtRepositoryRoot("wasm-pack", [
    "build",
    "crates/ed25519-yao/wasm-bench",
    "--target",
    "nodejs",
    "--release",
    "--out-dir",
    "pkg-phase5",
  ]);
  const harness = "crates/ed25519-yao/wasm-bench/scripts/run_phase5_streaming.mjs";
  runAtRepositoryRoot("node", [harness]);
  runAtRepositoryRootWithEnvironment("node", [harness], {
    ...process.env,
    PHASE5_SLOW_PRODUCER_MS: "1",
    PHASE5_SLOW_CONSUMER_MS: "1",
  });
}

function runLocalComputeChecks() {
  run("npm", ["run", "compute:native"]);
  run("npm", ["run", "compute:wasm"]);
}

function runToolingChecks() {
  run("npm", ["run", "test:constant-time-codegen"]);
  run("npm", ["run", "audit:isolation"]);
  run("npm", ["run", "test:isolation"]);
  run("npm", ["run", "test:local-benchmark-tooling"]);
  run("npm", ["run", "test:deployment-tooling"]);
  run("npm", ["run", "test:cost-report-integrity"]);
  run("npm", ["run", "test:fresh-version-first-request-series"]);
  run("npm", ["run", "test:rendered-deployment-configs"]);
  run("npm", ["run", "test:phase13a-local-preflight"]);
  run("npm", ["run", "phase13a:local-preflight"]);
}

function runWorkerBuilds() {
  for (const script of WORKER_BUILD_SCRIPTS) {
    run("npm", ["run", script]);
  }
}

function runWranglerDryRuns() {
  for (const script of WRANGLER_DRY_RUN_SCRIPTS) {
    runWranglerScript(script);
  }
}

function main() {
  runCargoChecks();
  runCoreCorrectnessChecks();
  runCoreWasmStreamingChecks();
  runLocalComputeChecks();
  runToolingChecks();
  runWorkerBuilds();
  runWranglerDryRuns();
  process.stdout.write("local readiness artifact matrix passed\n");
}

try {
  main();
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
