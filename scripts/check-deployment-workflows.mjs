#!/usr/bin/env node

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';

const workflowRoot = '.github/workflows';

export const WORKFLOW_NAMES = Object.freeze({
  'validate-repository.yml': 'Validate / repository',
  'validate-cloudflare-mpc-router-ab.yml': 'Validate / cloudflare-mpc-router-ab',
  'deploy-staging-cloudflare-stack.yml': 'Deploy / staging / cloudflare-stack',
  'deploy-production-cloudflare-stack.yml': 'Deploy / production / cloudflare-stack',
  'deploy-staging-frontend.yml': 'Deploy / staging / frontend',
  'deploy-production-frontend.yml': 'Deploy / production / frontend',
});

export const DEPLOYMENT_WORKFLOWS = Object.freeze([
  Object.freeze({
    filename: 'deploy-staging-cloudflare-stack.yml',
    environment: 'staging',
    branch: 'dev',
    lane: 'backend',
    surface: 'cloudflare-stack',
    upstreamWorkflow: 'Validate / repository',
    requiredInputs: Object.freeze(['source_sha', 'artifact_run_id', 'release_set_id']),
  }),
  Object.freeze({
    filename: 'deploy-production-cloudflare-stack.yml',
    environment: 'production',
    branch: 'main',
    lane: 'backend',
    surface: 'cloudflare-stack',
    upstreamWorkflow: 'Validate / repository',
    requiredInputs: Object.freeze(['source_sha', 'artifact_run_id', 'release_set_id']),
  }),
  Object.freeze({
    filename: 'deploy-staging-frontend.yml',
    environment: 'staging',
    branch: 'dev',
    lane: 'frontend',
    surface: 'frontend',
    upstreamWorkflow: 'Deploy / staging / cloudflare-stack',
    requiredInputs: Object.freeze([
      'source_sha',
      'artifact_run_id',
      'release_set_id',
      'backend_receipt_run_id',
    ]),
  }),
  Object.freeze({
    filename: 'deploy-production-frontend.yml',
    environment: 'production',
    branch: 'main',
    lane: 'frontend',
    surface: 'frontend',
    upstreamWorkflow: 'Deploy / production / cloudflare-stack',
    requiredInputs: Object.freeze([
      'source_sha',
      'artifact_run_id',
      'release_set_id',
      'backend_receipt_run_id',
    ]),
  }),
]);

const expectedDeploymentByFilename = new Map(
  DEPLOYMENT_WORKFLOWS.map((workflow) => [workflow.filename, workflow]),
);

export function validateDeploymentWorkflowPolicy(workflows, workflowSources) {
  const failures = [];

  for (const [filename, source] of workflowSources) {
    if (source.includes('secrets: inherit')) {
      failures.push(`${filename}: secrets: inherit is forbidden`);
    }
    if (source.includes('workflow_call') || source.includes('INTERNAL /')) {
      failures.push(`${filename}: reusable/internal workflows do not belong in .github/workflows`);
    }
    if (source.includes('./.github/workflows/')) {
      failures.push(`${filename}: local reusable-workflow references are forbidden`);
    }
  }

  for (const [filename, workflow] of workflows) {
    const source = workflowSources.get(filename) ?? '';
    const expectedName = WORKFLOW_NAMES[filename];
    if (expectedName === undefined) {
      failures.push(`unexpected workflow: ${filename}`);
    } else if (workflow.name !== expectedName) {
      failures.push(`${filename}: expected name ${JSON.stringify(expectedName)}`);
    }

    for (const [jobId, job] of Object.entries(workflow.jobs ?? {})) {
      if (!job || typeof job !== 'object') continue;
      const jobName = typeof job.name === 'string' ? job.name : '';
      if (jobName.startsWith('Deploy / ') && !job.environment) {
        failures.push(`${filename}:${jobId}: deployment job must declare a GitHub environment`);
      }

      const mutationSurface = mutationSurfaceForJob(jobName);
      if (mutationSurface !== undefined && !expectedDeploymentByFilename.has(filename)) {
        failures.push(`${filename}:${jobId}: mutation job is outside a deployment workflow`);
      }
    }
  }

  for (const filename of Object.keys(WORKFLOW_NAMES)) {
    if (!workflows.has(filename)) failures.push(`missing workflow: ${filename}`);
  }

  for (const [filename, descriptor] of expectedDeploymentByFilename) {
    const workflow = workflows.get(filename);
    if (!workflow) continue;
    const source = workflowSources.get(filename) ?? '';
    validateDeploymentWorkflow(workflow, source, descriptor, failures);
  }

  return failures;
}

function validateDeploymentWorkflow(workflow, source, descriptor, failures) {
  if (!workflow.name.startsWith(`Deploy / ${descriptor.environment} / ${descriptor.surface}`)) {
    failures.push(
      `${descriptor.filename}: deployment environment and surface are not visible in the workflow name`,
    );
  }

  const workflowRun = workflow.on?.workflow_run;
  if (!workflowRun?.workflows?.includes(descriptor.upstreamWorkflow)) {
    failures.push(
      `${descriptor.filename}: automatic deployment is not gated by ${descriptor.upstreamWorkflow}`,
    );
  }
  if (!workflowRun?.branches?.includes(descriptor.branch)) {
    failures.push(`${descriptor.filename}: automatic deployment has the wrong protected branch`);
  }
  if (
    descriptor.lane === 'backend' &&
    !source.includes("github.event.workflow_run.event == 'push'")
  ) {
    failures.push(
      `${descriptor.filename}: automatic backend deployment must accept push validation runs only`,
    );
  }
  if (
    descriptor.lane === 'frontend' &&
    !source.includes("github.event.workflow_run.conclusion == 'success'")
  ) {
    failures.push(
      `${descriptor.filename}: automatic frontend deployment must require a successful backend run`,
    );
  }

  const dispatchInputs = workflow.on?.workflow_dispatch?.inputs ?? {};
  for (const inputName of descriptor.requiredInputs) {
    if (!dispatchInputs[inputName]) {
      failures.push(`${descriptor.filename}: manual promotion is missing ${inputName} input`);
    }
  }
  if (dispatchInputs.target) {
    failures.push(`${descriptor.filename}: deployment target must be fixed by the workflow file`);
  }
  if (workflow.env?.DEPLOY_TARGET !== descriptor.environment) {
    failures.push(
      `${descriptor.filename}: DEPLOY_TARGET must be fixed to ${descriptor.environment}`,
    );
  }
  if (workflow.concurrency?.group !== `deployment-${descriptor.environment}-${descriptor.lane}`) {
    failures.push(
      `${descriptor.filename}: concurrency must use deployment-${descriptor.environment}-${descriptor.lane}`,
    );
  }

  const mutationJobs = Object.entries(workflow.jobs ?? {})
    .map(([jobId, job]) => ({ jobId, job, surface: mutationSurfaceForJob(job?.name) }))
    .filter((entry) => entry.surface !== undefined);
  const backendMutationJobs = mutationJobs.filter((entry) => entry.surface === 'backend');
  const frontendMutationJobs = mutationJobs.filter((entry) => entry.surface === 'frontend');

  if (descriptor.lane === 'backend' && frontendMutationJobs.length > 0) {
    for (const entry of frontendMutationJobs) {
      failures.push(
        `${descriptor.filename}:${entry.jobId}: frontend mutation belongs in the frontend lane`,
      );
    }
  }
  if (descriptor.lane === 'frontend' && backendMutationJobs.length > 0) {
    for (const entry of backendMutationJobs) {
      failures.push(
        `${descriptor.filename}:${entry.jobId}: backend mutation belongs in the backend lane`,
      );
    }
  }
  if (descriptor.lane === 'backend' && backendMutationJobs.length === 0) {
    failures.push(`${descriptor.filename}: backend deployment must contain a backend mutation job`);
  }
  if (descriptor.lane === 'frontend' && frontendMutationJobs.length === 0) {
    failures.push(`${descriptor.filename}: frontend deployment must contain a Pages mutation job`);
  }

  if (descriptor.lane === 'backend' && containsFrontendMutationSource(source)) {
    failures.push(
      `${descriptor.filename}: frontend mutation source is forbidden in the backend lane`,
    );
  }
  if (descriptor.lane === 'frontend' && containsBackendMutationSource(source)) {
    failures.push(
      `${descriptor.filename}: backend mutation source is forbidden in the frontend lane`,
    );
  }
  if (descriptor.environment === 'production' && !source.includes('"$EVENT_BRANCH" != \'main\'')) {
    failures.push(`${descriptor.filename}: production authority guard is missing`);
  }
  if (source.includes('secrets: inherit')) {
    failures.push(`${descriptor.filename}: deployment secrets must be explicit`);
  }
}

function mutationSurfaceForJob(jobName) {
  if (typeof jobName !== 'string' || !jobName.startsWith('Deploy / ')) return undefined;
  if (jobName.includes('/ cloudflare-pages')) return 'frontend';
  if (
    jobName.includes('/ cloudflare-api-gateway') ||
    jobName.includes('/ cloudflare-mpc-router-ab')
  ) {
    return 'backend';
  }
  return undefined;
}

function containsFrontendMutationSource(source) {
  return source.includes('deploy-cloudflare-pages.yml') || source.includes('wrangler pages deploy');
}

function containsBackendMutationSource(source) {
  return (
    source.includes('deploy-cloudflare-gateway.yml') ||
    source.includes('wrangler deploy') ||
    source.includes('cloudflare-mpc-router-ab')
  );
}

function readWorkflowSet(root) {
  const workflows = new Map();
  const workflowSources = new Map();

  for (const filename of readdirSync(root).filter((value) => value.endsWith('.yml'))) {
    const source = readFileSync(join(root, filename), 'utf8');
    workflowSources.set(filename, source);
    let workflow;
    try {
      workflow = parseYaml(source, { version: '1.2' });
    } catch (error) {
      console.error(`${filename}: invalid YAML: ${error instanceof Error ? error.message : error}`);
      continue;
    }
    if (!workflow || typeof workflow !== 'object' || Array.isArray(workflow)) {
      console.error(`${filename}: workflow root must be a mapping`);
      continue;
    }
    workflows.set(filename, workflow);
  }
  return { workflows, workflowSources };
}

function isMainModule() {
  return (
    process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])
  );
}

if (isMainModule()) {
  const { workflows, workflowSources } = readWorkflowSet(workflowRoot);
  const failures = validateDeploymentWorkflowPolicy(workflows, workflowSources);
  if (failures.length > 0) {
    console.error('Deployment workflow policy failed:');
    for (const failure of failures) console.error(`- ${failure}`);
    process.exit(1);
  }
  console.log(`Deployment workflow policy passed for ${workflows.size} workflows.`);
}
