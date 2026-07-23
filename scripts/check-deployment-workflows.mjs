#!/usr/bin/env node

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse as parseYaml } from 'yaml';

const workflowRoot = '.github/workflows';
const workflowNames = {
  'validate-repository.yml': 'Validate / repository',
  'validate-cloudflare-router-ab.yml': 'Validate / cloudflare-router-ab',
  'deploy-staging-cloudflare-stack.yml': 'Deploy / staging / cloudflare-stack',
  'deploy-production-cloudflare-stack.yml': 'Deploy / production / cloudflare-stack',
  'internal-release-cloudflare-stack.yml': 'INTERNAL / release / cloudflare-stack',
  'internal-deploy-cloudflare-stack.yml': 'INTERNAL / deploy / cloudflare-stack',
  'internal-deploy-cloudflare-gateway.yml': 'INTERNAL / deploy / cloudflare-gateway',
  'internal-deploy-cloudflare-pages.yml': 'INTERNAL / deploy / cloudflare-pages',
};

const failures = [];
const workflows = new Map();

for (const filename of readdirSync(workflowRoot).filter((value) => value.endsWith('.yml'))) {
  const source = readFileSync(join(workflowRoot, filename), 'utf8');
  if (source.includes('secrets: inherit')) {
    failures.push(`${filename}: secrets: inherit is forbidden`);
  }
  let workflow;
  try {
    workflow = parseYaml(source, { version: '1.2' });
  } catch (error) {
    failures.push(`${filename}: invalid YAML: ${error instanceof Error ? error.message : error}`);
    continue;
  }
  if (!workflow || typeof workflow !== 'object' || Array.isArray(workflow)) {
    failures.push(`${filename}: workflow root must be a mapping`);
    continue;
  }
  workflows.set(filename, workflow);
  if (workflow.name !== workflowNames[filename]) {
    failures.push(`${filename}: expected name ${JSON.stringify(workflowNames[filename])}`);
  }
  for (const [jobId, job] of Object.entries(workflow.jobs ?? {})) {
    if (!job || typeof job !== 'object') continue;
    const jobName = typeof job.name === 'string' ? job.name : '';
    if (jobName.startsWith('Deploy / ') && typeof job.uses !== 'string') {
      if (!job.environment || typeof job.environment !== 'object') {
        failures.push(`${filename}:${jobId}: deployment job must declare a GitHub environment`);
      } else if (
        typeof job.environment.name === 'string' &&
        !job.environment.name.includes('inputs.') &&
        !job.environment.name.includes('needs.') &&
        !['staging', 'production'].includes(job.environment.name)
      ) {
        failures.push(`${filename}:${jobId}: deployment environment is outside staging/production`);
      }
    }
  }
}

for (const filename of Object.keys(workflowNames)) {
  if (!workflows.has(filename)) failures.push(`missing workflow: ${filename}`);
}
for (const filename of workflows.keys()) {
  if (!Object.hasOwn(workflowNames, filename)) failures.push(`unexpected workflow: ${filename}`);
}

for (const filename of [
  'internal-release-cloudflare-stack.yml',
  'internal-deploy-cloudflare-stack.yml',
  'internal-deploy-cloudflare-gateway.yml',
  'internal-deploy-cloudflare-pages.yml',
]) {
  const workflow = workflows.get(filename);
  if (!workflow) continue;
  const triggerNames = Object.keys(workflow.on ?? {});
  if (triggerNames.length !== 1 || triggerNames[0] !== 'workflow_call') {
    failures.push(`${filename}: internal workflows must expose workflow_call only`);
  }
}

for (const [filename, environment] of [
  ['deploy-staging-cloudflare-stack.yml', 'staging'],
  ['deploy-production-cloudflare-stack.yml', 'production'],
]) {
  const workflow = workflows.get(filename);
  if (!workflow) continue;
  if (!workflow.name.startsWith(`Deploy / ${environment} / `)) {
    failures.push(`${filename}: deployment environment is not visible in the workflow name`);
  }
  if (!workflow.on?.workflow_run?.workflows?.includes('Validate / repository')) {
    failures.push(`${filename}: automatic deployment is not gated by Validate / repository`);
  }
  if (!workflow.on?.workflow_run?.branches?.includes(environment === 'staging' ? 'dev' : 'main')) {
    failures.push(`${filename}: automatic deployment has the wrong protected branch`);
  }
  const automatic = workflow.jobs?.automatic_release;
  const manual = workflow.jobs?.manual_promotion;
  if (automatic?.uses !== './.github/workflows/internal-release-cloudflare-stack.yml') {
    failures.push(`${filename}: automatic_release must call internal-release-cloudflare-stack`);
  }
  if (manual?.uses !== './.github/workflows/internal-deploy-cloudflare-stack.yml') {
    failures.push(`${filename}: manual_promotion must call internal-deploy-cloudflare-stack`);
  }
  if (
    manual?.with?.target !== environment ||
    manual?.with?.source_branch !== (environment === 'staging' ? 'dev' : 'main')
  ) {
    failures.push(`${filename}: manual promotion target and branch must be constants`);
  }
}

const stack = workflows.get('internal-deploy-cloudflare-stack.yml');
if (stack) {
  const stackCalls = Object.values(stack.jobs ?? {})
    .filter((job) => job && typeof job === 'object' && typeof job.uses === 'string')
    .map((job) => job.uses);
  for (const expected of [
    './.github/workflows/internal-deploy-cloudflare-gateway.yml',
    './.github/workflows/internal-deploy-cloudflare-pages.yml',
  ]) {
    if (!stackCalls.includes(expected)) failures.push(`stack workflow must call ${expected}`);
  }
  const sourceValidationScript = stack.jobs?.preflight_release?.steps?.find(
    (step) => step?.name === 'Validate source branch and target',
  )?.run;
  if (
    typeof sourceValidationScript !== 'string' ||
    !sourceValidationScript.includes(
      `"$DEPLOY_TARGET" == 'production' && "$GITHUB_REF" != 'refs/heads/main'`,
    )
  ) {
    failures.push('stack workflow must reject production authority outside refs/heads/main');
  }
}

const release = workflows.get('internal-release-cloudflare-stack.yml');
if (release) {
  const releaseCalls = Object.values(release.jobs ?? {})
    .filter((job) => job && typeof job === 'object' && typeof job.uses === 'string')
    .map((job) => job.uses);
  if (!releaseCalls.includes('./.github/workflows/internal-deploy-cloudflare-stack.yml')) {
    failures.push('internal release workflow must call internal-deploy-cloudflare-stack');
  }
  const releaseIdentityScript = release.jobs?.prepare?.steps?.find(
    (step) => step?.name === 'Resolve release identity',
  )?.run;
  if (
    typeof releaseIdentityScript !== 'string' ||
    !releaseIdentityScript.includes('"$validation_branch" == "$source_branch"') ||
    releaseIdentityScript.includes('$expected_branch') ||
    !releaseIdentityScript.includes(
      `"$target" == 'production' && "$GITHUB_REF" != 'refs/heads/main'`,
    )
  ) {
    failures.push(
      'internal release workflow must validate source_branch and main-rooted production authority',
    );
  }
}

if (failures.length > 0) {
  console.error('Deployment workflow policy failed:');
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Deployment workflow policy passed for ${workflows.size} workflows.`);
