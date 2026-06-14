import { mkdirSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));
const argv = process.argv.slice(2);
const reportPath = resolveReportPath(
  readOption("--out") ??
    join(
      "crates",
      "router-ab-dev",
      "reports",
      "local-smoke-timings",
      `local-smoke-timings-${new Date().toISOString().replace(/[:.]/g, "-")}.json`,
    ),
);
const keepEphemeralRoot = argv.includes("--keep-ephemeral-root");

mkdirSync(dirname(reportPath), { recursive: true });
run("cargo", [
  "build",
  "--manifest-path",
  "crates/router-ab-dev/Cargo.toml",
  "--bin",
  "router_ab_local_worker",
  "--bin",
  "router_ab_local_smoke",
]);

const smokeArgs = [
  "run",
  "--manifest-path",
  "crates/router-ab-dev/Cargo.toml",
  "--bin",
  "router_ab_local_smoke",
  "--",
  "--ephemeral",
  "--out",
  reportPath,
];
if (keepEphemeralRoot) {
  smokeArgs.push("--keep-ephemeral-root");
}
run("cargo", smokeArgs);
console.log(`\nWrote ${reportPath}`);

function run(command, args) {
  const child = spawnSync(command, args, {
    cwd: repoRoot,
    stdio: "inherit",
    env: process.env,
  });
  if (child.status !== 0) {
    process.exit(child.status ?? 1);
  }
}

function readOption(name) {
  const index = argv.indexOf(name);
  if (index === -1) {
    return undefined;
  }
  const value = argv[index + 1];
  if (!value || value.startsWith("--")) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function resolveReportPath(path) {
  return isAbsolute(path) ? path : join(repoRoot, path);
}
