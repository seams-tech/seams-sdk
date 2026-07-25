import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  inventoryRefactor93LegacyKeys,
  validateRefactor93DrainReceipt,
} from '../../crates/router-ab-cloudflare/scripts/refactor93-deployment-drain.mjs';

test('drain receipt stays blocked until all five deployment gates are evidenced', () => {
  const result = validateRefactor93DrainReceipt(validReceipt());
  assert.equal(result.ready, true);
  assert.equal(result.requiredDrainMs, 105_000);

  const blocked = validReceipt();
  blocked.environment = 'production';
  blocked.coherentDeployment.noLegacyGatewayCalls = false;
  blocked.stagingRuns.recovery.exactReplay = 'missing';
  blocked.lifetime.observedDrainMs = 1;
  blocked.rollback.rehearsalPassed = false;
  blocked.postDrain.sourceOwners = ['legacy Stage route'];
  const blockedResult = validateRefactor93DrainReceipt(blocked);
  assert.equal(blockedResult.ready, false);
  assert.equal(blockedResult.blockers.length, 6);
});

test('legacy key inventory reports references without authorizing deletion', () => {
  const inventory = inventoryRefactor93LegacyKeys([
    { path: 'gateway.json', text: 'DERIVER_A DERIVER_B SIGNING_WORKER ROUTER_API_RUNTIME' },
    { path: 'backend.ts', text: 'MPC_ROUTER SIGNING_WORKER' },
  ]);
  const deriverA = inventory.find((entry) => entry.key === 'DERIVER_A');
  const signingWorker = inventory.find((entry) => entry.key === 'SIGNING_WORKER');
  const mpcRouter = inventory.find((entry) => entry.key === 'MPC_ROUTER');
  if (!deriverA || !signingWorker || !mpcRouter) throw new Error('inventory entries are required');
  assert.equal(deriverA.decision, 'drain_or_follow_up');
  assert.equal(signingWorker.decision, 'retain_non_yao_owner');
  assert.equal(mpcRouter.decision, 'retain_yao_owner');
  assert.equal(deriverA.references[0].count, 1);
  assert.equal(signingWorker.references.length, 2);
});

function validReceipt() {
  const release = {
    sourceSha: 'a'.repeat(40),
    gatewayVersionId: 'gateway-v2',
    routerVersionId: 'router-v2',
    deriverAVersionId: 'deriver-a-v2',
    deriverBVersionId: 'deriver-b-v2',
    signingWorkerVersionId: 'signing-worker-v2',
  };
  return {
    schemaVersion: 1,
    environment: 'staging',
    capturedAt: '2026-07-25T00:00:00.000Z',
    release,
    coherentDeployment: {
      gatewayVersionId: release.gatewayVersionId,
      routerVersionId: release.routerVersionId,
      deriverAVersionId: release.deriverAVersionId,
      deriverBVersionId: release.deriverBVersionId,
      signingWorkerVersionId: release.signingWorkerVersionId,
      noLegacyGatewayCalls: true,
    },
    stagingRuns: {
      registration: { status: 'success', exactReplay: 'verified', conflict: 'verified' },
      recovery: { status: 'success', exactReplay: 'verified', conflict: 'verified' },
      export: { status: 'success', exactReplay: 'verified', conflict: 'verified' },
    },
    lifetime: {
      stagedLifetimeMs: 60_000,
      runningLifetimeMs: 20_000,
      transportFailureBudgetMs: 10_000,
      rollbackBudgetMs: 15_000,
      observedDrainMs: 105_000,
    },
    rollback: {
      previousGatewayVersionId: 'gateway-v1',
      rehearsalPassed: true,
      previousVersionDeployable: true,
    },
    postDrain: { generatedConfigOwners: [], sourceOwners: [] },
  };
}
