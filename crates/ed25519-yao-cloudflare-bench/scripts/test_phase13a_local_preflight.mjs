import assert from 'node:assert/strict';

import {
  LocalPreflightError,
  evaluateLocalPreflight,
  loadLocalEvidence,
  loadWorkspaceArtifact,
} from './evaluate_phase13a_local_preflight.mjs';

const PHASE9C_RECEIPT_PATH = 'crates/router-ab-dev/target/phase9c-yaos-ab-local-evidence-v1.json';

function cloneEvidence() {
  return JSON.parse(JSON.stringify(loadLocalEvidence()));
}

function evaluateEvidence(evidence) {
  return evaluateLocalPreflight(evidence, loadWorkspaceArtifact);
}

function evaluateEvidenceWithReceipt(evidence, receipt) {
  return evaluateLocalPreflight(evidence, loadMutatedReceipt.bind(null, receipt));
}

function loadMutatedReceipt(receipt, path) {
  if (path === PHASE9C_RECEIPT_PATH) {
    return Buffer.from(`${JSON.stringify(receipt)}\n`);
  }
  return loadWorkspaceArtifact(path);
}

function clonePhase9CReceipt() {
  return JSON.parse(loadWorkspaceArtifact(PHASE9C_RECEIPT_PATH).toString('utf8'));
}

function corruptArtifactDigest(evidence) {
  evidence.artifacts[0].sha256 = '0'.repeat(64);
}

function corruptValidatedInputTree(evidence) {
  evidence.validated_inputs.sha256 = '0'.repeat(64);
}

function corruptTableFormula(evidence) {
  evidence.stream_kat_cases[0].table_bytes += 32;
}

function enableProduction(evidence) {
  evidence.production_eligible = true;
}

function broadenSecretDisposalClaim(evidence) {
  evidence.incoming_secret_buffer_disposal = 'zeroized';
}

function removeDeploymentGate(evidence) {
  evidence.deployed_evidence_unavailable.pop();
}

function corruptFormalParityEvidence(evidence) {
  evidence.validation.formal_parity_generator_rust_tests -= 1;
}

function corruptSourceGuardCount(evidence) {
  evidence.validation.source_guard_tests -= 1;
}

function corruptWireEvidence(evidence) {
  evidence.activation_128kib_wire_profile.total_ab_transport_bytes -= 1;
}

function exceedLocalComputeLimit(evidence) {
  evidence.local_compute.wasm_activation_128kib.combined_role_synchronous_p95_ms = 151;
}

function exposeBenchmarkToProduction(evidence) {
  evidence.benchmark_isolation.production_reachable = true;
}

function corruptPhase9CBinding(evidence) {
  evidence.phase9c_validation.profile_count -= 1;
}

function failPhase9CGate(receipt) {
  receipt.result = 'failed';
}

function removePhase9CProfile(receipt) {
  receipt.lifecycle_evidence.pop();
}

function removePhase9CLifecycleVector(receipt) {
  receipt.lifecycle_evidence[0].lifecycle_vectors.pop();
}

function breakPhase9CExportContinuity(receipt) {
  receipt.lifecycle_evidence[0].export_public_key_matches_registered = false;
}

function breakPhase9CExportSignature(receipt) {
  receipt.lifecycle_evidence[0].export_standard_signature_verified = false;
}

function substitutePhase9CExportedPublicKey(receipt) {
  receipt.lifecycle_evidence[0].exported_public_key_sha256 = '0'.repeat(64);
}

function addPhase9CSigningDeriverCall(receipt) {
  receipt.lifecycle_evidence[0].ordinary_signing_deriver_a_requests = 1;
}

function addPhase9CSigningDeriverBytes(receipt) {
  receipt.lifecycle_evidence[0].ordinary_signing_deriver_a_to_b_bytes = 1;
}

function corruptPhase9CSourceDigest(receipt) {
  receipt.validated_inputs.sha256 = '0'.repeat(64);
}

function removePhase9CCompletedCheck(receipt) {
  receipt.completed_checks.splice(5, 1);
}

function assertMutationRejected(mutator) {
  const evidence = cloneEvidence();
  mutator(evidence);
  assert.throws(evaluateEvidence.bind(null, evidence), LocalPreflightError);
}

function assertReceiptMutationRejected(mutator) {
  const evidence = cloneEvidence();
  const receipt = clonePhase9CReceipt();
  mutator(receipt);
  assert.throws(evaluateEvidenceWithReceipt.bind(null, evidence, receipt), LocalPreflightError);
}

function run() {
  const result = evaluateEvidence(cloneEvidence());
  assert.equal(result.status, 'deployment-required');
  assert.equal(result.phase13a_decision, 'unavailable');
  assert.equal(result.production_eligible, false);
  assert.equal(result.local_checks.length, 13);
  assert.equal(result.deployed_evidence_unavailable.length, 11);

  assertMutationRejected(corruptArtifactDigest);
  assertMutationRejected(corruptValidatedInputTree);
  assertMutationRejected(corruptTableFormula);
  assertMutationRejected(enableProduction);
  assertMutationRejected(broadenSecretDisposalClaim);
  assertMutationRejected(removeDeploymentGate);
  assertMutationRejected(corruptFormalParityEvidence);
  assertMutationRejected(corruptSourceGuardCount);
  assertMutationRejected(corruptWireEvidence);
  assertMutationRejected(exceedLocalComputeLimit);
  assertMutationRejected(exposeBenchmarkToProduction);
  assertMutationRejected(corruptPhase9CBinding);
  assertReceiptMutationRejected(failPhase9CGate);
  assertReceiptMutationRejected(removePhase9CProfile);
  assertReceiptMutationRejected(removePhase9CLifecycleVector);
  assertReceiptMutationRejected(breakPhase9CExportContinuity);
  assertReceiptMutationRejected(breakPhase9CExportSignature);
  assertReceiptMutationRejected(substitutePhase9CExportedPublicKey);
  assertReceiptMutationRejected(addPhase9CSigningDeriverCall);
  assertReceiptMutationRejected(addPhase9CSigningDeriverBytes);
  assertReceiptMutationRejected(corruptPhase9CSourceDigest);
  assertReceiptMutationRejected(removePhase9CCompletedCheck);
}

run();
process.stdout.write('Phase 13A local preflight fixtures passed\n');
