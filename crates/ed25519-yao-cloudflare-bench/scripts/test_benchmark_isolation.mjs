import assert from "node:assert/strict";

import {
  IsolationAuditError,
  collectWorkspaceSnapshot,
  evaluateIsolation,
} from "./audit_benchmark_isolation.mjs";

function cloneSnapshot(snapshot) {
  return JSON.parse(JSON.stringify(snapshot));
}

function addProductReference(snapshot) {
  snapshot.productReferences.push({
    path: "packages/sdk/src/signing.ts",
    token: "phase9_role_benchmark",
  });
}

function addUnauthorizedCoreDependency(snapshot) {
  snapshot.coreDependencies.push({
    manifest: "crates/signer-core/Cargo.toml",
    kind: "normal",
    features: "phase9-role-benchmark",
  });
}

function addBenchmarkDependent(snapshot) {
  snapshot.benchmarkDependencies.push({
    manifest: "crates/router-ab-core/Cargo.toml",
    kind: "normal",
    features: "",
  });
}

function enableCoreDefaultFeature(snapshot) {
  snapshot.coreBoundary.defaultFeatures.push("passive-benchmark");
}

function addProductionRoute(snapshot) {
  snapshot.wranglerConfigs[0].hasProductionRoute = true;
}

function promoteWranglerClassification(snapshot) {
  snapshot.wranglerConfigs[0].classification = "PRODUCTION";
}

function enableBenchmarkProduction(snapshot) {
  snapshot.benchmarkBoundary.productionEligibleFalse = false;
}

function assertMutationRejected(snapshot, mutator) {
  const mutated = cloneSnapshot(snapshot);
  mutator(mutated);
  assert.throws(evaluateIsolation.bind(null, mutated), IsolationAuditError);
}

function run() {
  const snapshot = collectWorkspaceSnapshot();
  const result = evaluateIsolation(snapshot);
  assert.equal(result.status, "pass");
  assert.equal(result.production_reachable, false);
  assert.equal(result.authorized_core_dependents, 5);
  assert.equal(result.benchmark_dependents, 0);
  assert.equal(result.product_references, 0);
  assert.equal(result.benchmark_wrangler_configs, 19);
  assert.equal(result.production_routes, 0);

  assertMutationRejected(snapshot, addProductReference);
  assertMutationRejected(snapshot, addUnauthorizedCoreDependency);
  assertMutationRejected(snapshot, addBenchmarkDependent);
  assertMutationRejected(snapshot, enableCoreDefaultFeature);
  assertMutationRejected(snapshot, addProductionRoute);
  assertMutationRejected(snapshot, promoteWranglerClassification);
  assertMutationRejected(snapshot, enableBenchmarkProduction);
}

run();
process.stdout.write("benchmark isolation mutation fixtures passed\n");
