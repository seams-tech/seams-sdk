import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

import {
  BoundaryError,
  parseDeploymentEnvironment,
} from "./deployment_boundary.mjs";
import {
  calculateCost,
  costEvidenceMetadata,
  parseCostEnvironment,
} from "./calculate_deployed_cost.mjs";
import {
  attachConstantTimeCodegen,
  attachRoleArtifact,
  attachRoleDeployment,
  completeDeploymentReceipt,
  deploymentReceiptEvidence,
  initialDeploymentReceipt,
  writeDeploymentReceipt,
} from "./deployment_receipt.mjs";
import { loadLocalReadinessBundle } from "./local_readiness_bundle.mjs";

const SCRIPT_PATH = fileURLToPath(new URL("./calculate_deployed_cost.mjs", import.meta.url));
const BENCH_ROOT = fileURLToPath(new URL("../", import.meta.url));
const DEPLOYMENT_ID = "ab".repeat(16);
const GENERATED_AT = "2026-07-13T12:00:00.000Z";
const LOCAL_READINESS_BUNDLE_SHA256 = loadLocalReadinessBundle().sha256;
const ARTIFACT_PATHS = Object.freeze([
  "index.js",
  "index_bg.wasm",
  "package.json",
  "worker/shim.mjs",
]);

function testEnvironment(receiptPath) {
  return {
    YAOS_AB_TOPOLOGY: "two-account",
    YAOS_AB_A_ACCOUNT_ID: "a".repeat(32),
    YAOS_AB_B_ACCOUNT_ID: "b".repeat(32),
    YAOS_AB_A_PROFILE: "benchmark-a",
    YAOS_AB_B_PROFILE: "benchmark-b",
    YAOS_AB_A_SCRIPT_NAME: "ed25519-yao-ab-benchmark-a-cross-account",
    YAOS_AB_B_SCRIPT_NAME: "ed25519-yao-ab-benchmark-b-cross-account",
    YAOS_AB_A_PUBLIC_ENDPOINT: "https://a.yao-bench.example/benchmark/activation",
    YAOS_AB_B_HOSTNAME: "b.yao-bench.example",
    YAOS_AB_B_HTTPS_ENDPOINT: "https://b.yao-bench.example/benchmark/activation",
    YAOS_AB_SAMPLE_COUNT: "51",
    YAOS_AB_REGION_LABEL: "tokyo-runner-1",
    YAOS_AB_DEPLOYMENT_RECEIPT_PATH: receiptPath,
    YAOS_AB_COST_CEREMONIES: "1000000",
    YAOS_AB_MEASURED_REQUESTS_A_PER_CEREMONY: "1",
    YAOS_AB_MEASURED_REQUESTS_B_PER_CEREMONY: "1",
    YAOS_AB_MEASURED_CPU_A_MS_PER_CEREMONY: "80",
    YAOS_AB_MEASURED_CPU_B_MS_PER_CEREMONY: "40",
    YAOS_AB_MEASURED_NETWORK_BYTES_PER_CEREMONY: "2222584",
    YAOS_AB_MEASURED_CPU_STATISTIC: "GraphQL CPU P50",
    YAOS_AB_PRICE_USAGE_MODEL: "standard",
    YAOS_AB_PRICE_REQUESTS_USD_PER_MILLION_A: "0.30",
    YAOS_AB_PRICE_CPU_USD_PER_MILLION_MS_A: "0.02",
    YAOS_AB_INCLUDED_REQUESTS_A: "0",
    YAOS_AB_INCLUDED_CPU_MS_A: "0",
    YAOS_AB_PRICE_REQUESTS_USD_PER_MILLION_B: "0.30",
    YAOS_AB_PRICE_CPU_USD_PER_MILLION_MS_B: "0.02",
    YAOS_AB_INCLUDED_REQUESTS_B: "0",
    YAOS_AB_INCLUDED_CPU_MS_B: "0",
    YAOS_AB_PRICE_NETWORK_USD_PER_GB: "0",
    YAOS_AB_PRICE_EFFECTIVE_DATE: "2026-07-13",
    YAOS_AB_PRICE_SOURCE: "https://developers.cloudflare.com/workers/platform/pricing/",
  };
}

function artifactEvidence(seed) {
  const files = [];
  const aggregate = createHash("sha256");
  for (let index = 0; index < ARTIFACT_PATHS.length; index += 1) {
    const path = ARTIFACT_PATHS[index];
    const bytes = seed.length + index + 1;
    const sha256 = createHash("sha256").update(`${seed}:${path}`).digest("hex");
    files.push(Object.freeze({ path, bytes, sha256 }));
    aggregate.update(path);
    aggregate.update("\0");
    aggregate.update(String(bytes));
    aggregate.update("\0");
    aggregate.update(sha256);
    aggregate.update("\0");
  }
  return Object.freeze({
    schema: "ed25519_yao_worker_artifact_digest_v1",
    sha256: aggregate.digest("hex"),
    files: Object.freeze(files),
  });
}

function wranglerDeploymentOutput(scriptName, role) {
  const session = {
    type: "wrangler-session",
    wrangler_version: "4.105.0",
  };
  const deployment = {
    type: "deploy",
    worker_name: scriptName,
    worker_name_overridden: false,
    worker_tag: `benchmark-worker-tag-${role}`,
    version_id: `benchmark-version-id-${role}`,
    targets: [`https://${role}.yao-bench.example/`],
    timestamp: `2026-07-13T00:00:0${role === "a" ? "2" : "1"}.000Z`,
  };
  return `${JSON.stringify(session)}\n${JSON.stringify(deployment)}\n`;
}

function completeReceipt(configuration) {
  const receipt = initialDeploymentReceipt(
    configuration,
    DEPLOYMENT_ID,
    "2026-07-13T00:00:00.000Z",
    LOCAL_READINESS_BUNDLE_SHA256,
  );
  const bArtifact = artifactEvidence("b");
  const aArtifact = artifactEvidence("a");
  attachRoleArtifact(receipt, "b", bArtifact);
  attachRoleArtifact(receipt, "a", aArtifact);
  attachConstantTimeCodegen(receipt, {
    schema: "ed25519_yao_worker_constant_time_codegen_v1",
    inspector: "llvm-objdump-secret-bit-branch-gate-v1",
    result: "pass",
    roles: {
      a: { wasm_sha256: aArtifact.files[1].sha256 },
      b: { wasm_sha256: bArtifact.files[1].sha256 },
    },
  });
  attachRoleDeployment(
    receipt,
    "b",
    wranglerDeploymentOutput(configuration.b.scriptName, "b"),
  );
  attachRoleDeployment(
    receipt,
    "a",
    wranglerDeploymentOutput(configuration.a.scriptName, "a"),
  );
  completeDeploymentReceipt(receipt);
  return receipt;
}

function calculateWithWrongTopology(configuration, metadata) {
  calculateCost(Object.freeze({ ...configuration, topology: "one-account" }), metadata);
}

function testPureCostReportBinding(environment, receipt) {
  const deploymentConfiguration = parseDeploymentEnvironment(environment);
  const costConfiguration = parseCostEnvironment(environment);
  const metadata = costEvidenceMetadata(
    deploymentConfiguration,
    receipt,
    GENERATED_AT,
  );
  const report = calculateCost(costConfiguration, metadata);
  assert.equal(report.benchmark, "phase9b-cloudflare-cost-model");
  assert.equal(report.topology, "two-account");
  assert.deepEqual(report.deployment, deploymentReceiptEvidence(receipt));
  assert.equal(report.region_label, deploymentConfiguration.regionLabel);
  assert.equal(report.generated_at, GENERATED_AT);
  assert.deepEqual(report.measured, costConfiguration.measured);
  assert.deepEqual(report.pricing.accounts.a, costConfiguration.rates.a);
  assert.deepEqual(report.pricing.accounts.b, costConfiguration.rates.b);
  assert.throws(
    calculateWithWrongTopology.bind(null, costConfiguration, metadata),
    BoundaryError,
  );
}

function testCliLoadsCompleteReceipt(environment, receipt, receiptPath) {
  writeDeploymentReceipt(receiptPath, receipt, true);
  const execution = spawnSync(process.execPath, [SCRIPT_PATH], {
    cwd: BENCH_ROOT,
    env: { ...process.env, ...environment },
    encoding: "utf8",
  });
  assert.equal(execution.status, 0, execution.stderr);
  const report = JSON.parse(execution.stdout);
  assert.deepEqual(report.deployment, deploymentReceiptEvidence(receipt));
  assert.equal(report.region_label, environment.YAOS_AB_REGION_LABEL);
  assert.equal(new Date(report.generated_at).toISOString(), report.generated_at);
  assert.deepEqual(report.measured, parseCostEnvironment(environment).measured);
}

function main() {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "ed25519-yao-cost-report-"));
  const receiptPath = join(temporaryDirectory, "deployment-receipt.json");
  try {
    const environment = testEnvironment(receiptPath);
    const deploymentConfiguration = parseDeploymentEnvironment(environment);
    const receipt = completeReceipt(deploymentConfiguration);
    testPureCostReportBinding(environment, receipt);
    testCliLoadsCompleteReceipt(environment, receipt, receiptPath);
    process.stdout.write("cost report integrity fixtures passed\n");
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

main();
