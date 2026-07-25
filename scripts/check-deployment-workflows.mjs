#!/usr/bin/env node

import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, resolve } from 'node:path';
import { parse as parseYaml } from 'yaml';

const repositoryRoot = resolve(fileURLToPath(import.meta.url), '../..');
const workflowRoot = join(repositoryRoot, '.github/workflows');
const deploymentTemplateRoot = join(repositoryRoot, 'scripts/deployment-workflow-templates');
const codeownersPath = join(repositoryRoot, '.github/CODEOWNERS');

export const REQUIRED_CODEOWNER_PATTERNS = Object.freeze([
  '/.github/workflows/**',
  '/.github/actions/**',
  '/scripts/deployment-*.mjs',
  '/scripts/check-deployment-workflows.mjs',
  '/scripts/generate-deployment-workflows.mjs',
  '/scripts/deployment-workflow-templates/**',
  '/docs/deployment/**',
]);

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

const FRONTEND_ALLOWED_SECRET_NAMES = new Set([
  'GITHUB_TOKEN',
  'CLOUDFLARE_API_TOKEN',
  'CLOUDFLARE_ACCOUNT_ID',
  'CF_PAGES_PROJECT_VITE',
  'CF_PAGES_PROJECT_WALLET',
]);

const GATEWAY_FORBIDDEN_SECRET_NAMES = new Set([
  'CF_PAGES_PROJECT_VITE',
  'CF_PAGES_PROJECT_WALLET',
  'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
  'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
  'DERIVER_A_PEER_SIGNING_KEY',
  'DERIVER_B_ROOT_SHARE_WIRE_SECRET',
  'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY',
  'DERIVER_B_PEER_SIGNING_KEY',
  'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY',
]);

const expectedDeploymentByFilename = new Map(
  DEPLOYMENT_WORKFLOWS.map((workflow) => [workflow.filename, workflow]),
);

export function validateDeploymentWorkflowPolicy(workflows, workflowSources) {
  const failures = [];

  for (const [filename, source] of workflowSources) {
    if (source.includes('pull_request_target') && /\b(?:secrets|vars)\./u.test(source)) {
      failures.push(
        `${filename}: pull_request_target workflows cannot receive deployment credentials`,
      );
    }
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
    validateCredentialBoundaries(workflow, filename, descriptor, failures);
  }

  for (const [filename, source] of workflowSources) {
    if (expectedDeploymentByFilename.get(filename)?.lane === 'backend') {
      for (const forbidden of [
        'CF_PAGES_PROJECT_VITE',
        'CF_PAGES_PROJECT_WALLET',
        'wrangler pages deploy',
        'deploy-cloudflare-pages.yml',
      ]) {
        if (source.includes(forbidden)) {
          failures.push(
            `${filename}: backend lane contains frontend-only credential or mutation ${forbidden}`,
          );
        }
      }
    }
    if (expectedDeploymentByFilename.get(filename)?.lane === 'frontend') {
      for (const forbidden of [
        'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
        'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK',
        'RELAY_SESSION_HMAC_SECRET',
        'ACCOUNT_ID_DERIVATION_SECRET',
        'deploy-cloudflare-gateway.yml',
        'deploy-cloudflare-stack.yml',
        'wrangler deploy',
      ]) {
        if (source.includes(forbidden)) {
          failures.push(
            `${filename}: frontend lane contains backend-only credential or mutation ${forbidden}`,
          );
        }
      }
    }
  }

  return failures;
}

export function validateCodeowners(source) {
  const lines = String(source)
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
  return REQUIRED_CODEOWNER_PATTERNS.filter(
    (pattern) => !lines.some((line) => line.split(/\s+/u)[0] === pattern && line.includes('@')),
  ).map((pattern) => `CODEOWNERS is missing an owner rule for ${pattern}`);
}

export function validateDeploymentWorkflowTemplates(templates) {
  const failures = [];
  for (const [filename, template] of templates) {
    if (template.source.includes('workflow_call')) {
      failures.push(`${filename}: deployment templates must not declare workflow_call`);
    }
    if (template.source.includes('secrets: inherit')) {
      failures.push(`${filename}: deployment templates must not inherit secrets`);
    }
    if (!template.value || typeof template.value !== 'object' || Array.isArray(template.value)) {
      failures.push(`${filename}: deployment template root must be a mapping`);
      continue;
    }
    if (!template.value.jobs || typeof template.value.jobs !== 'object') {
      failures.push(`${filename}: deployment template must contain job fragments`);
    }
    if (template.value.on !== undefined) {
      failures.push(`${filename}: deployment job fragments must not declare workflow triggers`);
    }
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
    (!source.includes("github.event.workflow_run.event == 'push'") ||
      !source.includes("github.event.workflow_run.conclusion == 'success'"))
  ) {
    failures.push(
      `${descriptor.filename}: automatic backend deployment must require a successful push validation run`,
    );
  }
  if (
    descriptor.lane === 'frontend' &&
    (!source.includes("github.event.workflow_run.event == 'workflow_run'") ||
      !source.includes("github.event.workflow_run.conclusion == 'success'"))
  ) {
    failures.push(
      `${descriptor.filename}: automatic frontend deployment must require a successful automatic backend run`,
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
  if (workflow.env?.DEPLOY_SOURCE_BRANCH !== descriptor.branch) {
    failures.push(
      `${descriptor.filename}: DEPLOY_SOURCE_BRANCH must be fixed to ${descriptor.branch}`,
    );
  }
  if (source.includes('inputs.target') || source.includes('inputs.deploy_environment')) {
    failures.push(`${descriptor.filename}: deployment target must not be selected by an input`);
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

  for (const [jobId, job] of Object.entries(workflow.jobs ?? {})) {
    if (!job || typeof job !== 'object' || job.environment === undefined) continue;
    const environmentText = JSON.stringify(job.environment);
    const otherEnvironment = descriptor.environment === 'staging' ? 'production' : 'staging';
    if (environmentText.includes(otherEnvironment)) {
      failures.push(
        `${descriptor.filename}:${jobId}: deployment job references the ${otherEnvironment} environment`,
      );
    } else if (!environmentText.includes(descriptor.environment)) {
      failures.push(
        `${descriptor.filename}:${jobId}: deployment job environment is not bound to ${descriptor.environment}`,
      );
    }
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
  if (
    descriptor.environment === 'production' &&
    !source.includes('"$EVENT_BRANCH" != \'main\'') &&
    !source.includes('"$EVENT_BRANCH" != "$DEPLOY_SOURCE_BRANCH"')
  ) {
    failures.push(`${descriptor.filename}: production authority guard is missing`);
  }
  if (source.includes('secrets: inherit')) {
    failures.push(`${descriptor.filename}: deployment secrets must be explicit`);
  }
}

function validateCredentialBoundaries(workflow, filename, descriptor, failures) {
  for (const [jobId, job] of Object.entries(workflow.jobs ?? {})) {
    const secretNames = collectSecretNames(job);
    const hasEnvironment = job?.environment !== undefined;
    if (hasEnvironment === false && collectVariableNames(job).size > 0) {
      failures.push(
        `${filename}:${jobId}: jobs that read environment variables must declare a GitHub environment`,
      );
    }
    const unscopedSecretNames = [...secretNames].filter(
      (secretName) => secretName !== 'GITHUB_TOKEN',
    );
    if (hasEnvironment === false && unscopedSecretNames.length > 0) {
      failures.push(
        `${filename}:${jobId}: jobs that read deployment secrets must declare a GitHub environment (${unscopedSecretNames.join(', ')})`,
      );
    }
    if (descriptor.lane === 'frontend') {
      for (const secretName of secretNames) {
        if (!FRONTEND_ALLOWED_SECRET_NAMES.has(secretName)) {
          failures.push(
            `${filename}:${jobId}: frontend job reads backend or unapproved secret ${secretName}`,
          );
        }
      }
      continue;
    }

    const jobName = typeof job?.name === 'string' ? job.name : '';
    if (!jobName.includes('cloudflare-api-gateway')) continue;
    for (const secretName of secretNames) {
      if (GATEWAY_FORBIDDEN_SECRET_NAMES.has(secretName)) {
        failures.push(
          `${filename}:${jobId}: Gateway job reads Pages-only or Router-only secret ${secretName}`,
        );
      }
    }
  }
}

function collectSecretNames(value) {
  const names = new Set();
  visitSecretNames(value, names);
  return names;
}

function collectVariableNames(value) {
  const names = new Set();
  visitVariableNames(value, names);
  return names;
}

function visitVariableNames(value, names) {
  if (typeof value === 'string') {
    for (const match of value.matchAll(/\bvars\.([A-Z][A-Z0-9_]*)/gu)) {
      names.add(match[1]);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const child of value) visitVariableNames(child, names);
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const child of Object.values(value)) visitVariableNames(child, names);
}

function visitSecretNames(value, names) {
  if (typeof value === 'string') {
    for (const match of value.matchAll(/\bsecrets\.([A-Z][A-Z0-9_]*)/gu)) {
      names.add(match[1]);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const child of value) visitSecretNames(child, names);
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const child of Object.values(value)) visitSecretNames(child, names);
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

function readDeploymentTemplateSet(root) {
  const templates = new Map();
  for (const filename of readdirSync(root).filter((value) => value.endsWith('.yml'))) {
    const source = readFileSync(join(root, filename), 'utf8');
    let value;
    try {
      value = parseYaml(source, { version: '1.2' });
    } catch (error) {
      console.error(
        `${filename}: invalid deployment template YAML: ${error instanceof Error ? error.message : error}`,
      );
      continue;
    }
    templates.set(filename, { source, value });
  }
  return templates;
}

function isMainModule() {
  return (
    process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolve(process.argv[1])
  );
}

if (isMainModule()) {
  const { workflows, workflowSources } = readWorkflowSet(workflowRoot);
  const failures = validateDeploymentWorkflowPolicy(workflows, workflowSources);
  failures.push(
    ...validateDeploymentWorkflowTemplates(readDeploymentTemplateSet(deploymentTemplateRoot)),
  );
  let codeownersSource = '';
  try {
    codeownersSource = readFileSync(codeownersPath, 'utf8');
  } catch {
    failures.push(`missing CODEOWNERS: ${codeownersPath}`);
  }
  failures.push(...validateCodeowners(codeownersSource));
  if (failures.length > 0) {
    console.error('Deployment workflow policy failed:');
    for (const failure of failures) console.error(`- ${failure}`);
    process.exit(1);
  }
  console.log(`Deployment workflow policy passed for ${workflows.size} workflows.`);
}
