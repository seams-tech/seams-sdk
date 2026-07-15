import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { parseDeploymentEnvironment } from "./deployment_boundary.mjs";
import {
  bindPrebuiltArtifact,
  renderDeploymentConfigs,
} from "./plan_cloudflare_benchmark.mjs";

const PACKAGE_ROOT = fileURLToPath(new URL("../", import.meta.url));
const WRANGLER = fileURLToPath(
  new URL("../../../packages/console-server-ts/node_modules/.bin/wrangler", import.meta.url),
);
const DEPLOYMENT_ID = "0123456789abcdef0123456789abcdef";

function fixtureEnvironment() {
  return {
    YAOS_AB_TOPOLOGY: "two-account",
    YAOS_AB_A_ACCOUNT_ID: "a".repeat(32),
    YAOS_AB_B_ACCOUNT_ID: "b".repeat(32),
    YAOS_AB_A_PROFILE: "yaos-a",
    YAOS_AB_B_PROFILE: "yaos-b",
    YAOS_AB_A_SCRIPT_NAME: "ed25519-yao-ab-benchmark-a-cross-account",
    YAOS_AB_B_SCRIPT_NAME: "ed25519-yao-ab-benchmark-b-cross-account",
    YAOS_AB_A_PUBLIC_ENDPOINT: "https://a-benchmark.example.com/benchmark/activation",
    YAOS_AB_B_HOSTNAME: "b-benchmark.example.com",
    YAOS_AB_B_HTTPS_ENDPOINT: "https://b-benchmark.example.com/benchmark/activation",
    YAOS_AB_SAMPLE_COUNT: "2",
    YAOS_AB_REGION_LABEL: "rendered-config-fixture",
  };
}

function childEnvironment(directory) {
  const environment = { ...process.env, WRANGLER_LOG_PATH: join(directory, "wrangler.log") };
  for (const name of [
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_API_KEY",
    "CLOUDFLARE_ACCOUNT_ID",
    "CF_API_TOKEN",
  ]) {
    delete environment[name];
  }
  return environment;
}

function writeConfig(directory, role, config) {
  const path = join(directory, `wrangler.${role}.json`);
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  return path;
}

function dryRun(directory, role, config) {
  const configPath = writeConfig(directory, role, config);
  const argumentsList = [
    "deploy",
    "--dry-run",
    "--config",
    configPath,
    "--outdir",
    join(directory, `bundle-${role}`),
  ];
  if (config.no_bundle === true) {
    argumentsList.push("--no-bundle");
  }
  const result = spawnSync(
    WRANGLER,
    argumentsList,
    {
      cwd: PACKAGE_ROOT,
      env: childEnvironment(directory),
      encoding: "utf8",
    },
  );
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    throw new Error(`rendered ${role} Wrangler dry run failed`);
  }
}

function main() {
  const configuration = parseDeploymentEnvironment(fixtureEnvironment());
  const configs = renderDeploymentConfigs(configuration, DEPLOYMENT_ID);
  const directory = mkdtempSync(join(tmpdir(), "ed25519-yao-rendered-wrangler-"));
  try {
    dryRun(directory, "a", configs.a);
    dryRun(directory, "b", configs.b);
    dryRun(
      directory,
      "a-prebuilt",
      bindPrebuiltArtifact(configs.a, dirname(configs.a.main)),
    );
    dryRun(
      directory,
      "b-prebuilt",
      bindPrebuiltArtifact(configs.b, dirname(configs.b.main)),
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  process.stdout.write("rendered deployment config dry runs passed\n");
}

main();
