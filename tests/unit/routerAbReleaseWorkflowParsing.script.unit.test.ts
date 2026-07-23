import { readFileSync } from 'node:fs';
import { expect, test } from '@playwright/test';
import { parseWorkflowYaml } from '../../crates/router-ab-cloudflare/scripts/assert-release-ready.mjs';

const workflowSource = readFileSync(
  new URL(
    '../../scripts/deployment-workflow-templates/deploy-cloudflare-stack.yml',
    import.meta.url,
  ),
  'utf8',
);

test('Router A/B release guard parses accepted-artifact topology from YAML', () => {
  const workflow = parseWorkflowYaml(workflowSource, 'deploy-cloudflare-stack-template.yml');

  expect(workflow.on.workflow_call.inputs.artifact_run_id).toMatchObject({
    required: true,
    type: 'string',
  });
  expect(workflow.env.DEPLOY_SHA).toBe('${{ inputs.deploy_sha }}');
  expect(workflow.on.workflow_dispatch).toBeUndefined();
  expect(workflow.jobs.deploy_signing_worker.needs).toEqual(['preflight_release']);
  expect(workflow.jobs.deploy_deriver_a.needs).toEqual(['preflight_release']);
  expect(workflow.jobs.deploy_deriver_b.needs).toEqual(['preflight_release']);
  expect(workflow.jobs.deploy_mpc_router.needs).toEqual([
    'preflight_release',
    'deploy_signing_worker',
    'deploy_deriver_a',
    'deploy_deriver_b',
  ]);

  const signingWorkerDownload = workflow.jobs.deploy_signing_worker.steps.find(
    (step: { uses?: string }) => step.uses === 'actions/download-artifact@v8',
  );
  expect(signingWorkerDownload?.with).toMatchObject({
    name: 'release-${{ env.DEPLOY_TARGET }}-${{ env.DEPLOY_SHA }}-signing-worker',
    'run-id': '${{ env.ARTIFACT_RUN_ID }}',
  });
});

test('Router A/B release guard rejects malformed YAML instead of accepting partial input', () => {
  expect(() => parseWorkflowYaml('jobs: [', 'broken-workflow.yml')).toThrow(/not valid YAML/);
  expect(() => parseWorkflowYaml('- only-a-sequence', 'wrong-root.yml')).toThrow(/mapping/);
});
