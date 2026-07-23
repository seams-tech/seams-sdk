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
};

const deploymentWorkflows = [
  ['deploy-staging-cloudflare-stack.yml', 'staging', 'dev'],
  ['deploy-production-cloudflare-stack.yml', 'production', 'main'],
];

const failures = [];
const workflows = new Map();

for (const filename of readdirSync(workflowRoot).filter((value) => value.endsWith('.yml'))) {
  const source = readFileSync(join(workflowRoot, filename), 'utf8');
  if (source.includes('secrets: inherit')) {
    failures.push(`${filename}: secrets: inherit is forbidden`);
  }
  if (source.includes('workflow_call') || source.includes('INTERNAL /')) {
    failures.push(`${filename}: reusable/internal workflows do not belong in .github/workflows`);
  }
  if (source.includes('./.github/workflows/')) {
    failures.push(`${filename}: local reusable-workflow references are forbidden`);
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
    if (jobName.startsWith('Deploy / ') && !job.environment) {
      failures.push(`${filename}:${jobId}: deployment job must declare a GitHub environment`);
    }
  }
}

for (const filename of Object.keys(workflowNames)) {
  if (!workflows.has(filename)) failures.push(`missing workflow: ${filename}`);
}
for (const filename of workflows.keys()) {
  if (!Object.hasOwn(workflowNames, filename)) failures.push(`unexpected workflow: ${filename}`);
}

for (const [filename, environment, branch] of deploymentWorkflows) {
  const workflow = workflows.get(filename);
  if (!workflow) continue;

  if (!workflow.name.startsWith(`Deploy / ${environment} / cloudflare-stack`)) {
    failures.push(`${filename}: deployment environment is not visible in the workflow name`);
  }
  if (!workflow.on?.workflow_run?.workflows?.includes('Validate / repository')) {
    failures.push(`${filename}: automatic deployment is not gated by Validate / repository`);
  }
  if (!workflow.on?.workflow_run?.branches?.includes(branch)) {
    failures.push(`${filename}: automatic deployment has the wrong protected branch`);
  }
  if (!workflow.on?.workflow_dispatch?.inputs?.source_sha) {
    failures.push(`${filename}: manual promotion is missing source_sha input`);
  }
  if (!workflow.on?.workflow_dispatch?.inputs?.artifact_run_id) {
    failures.push(`${filename}: manual promotion is missing artifact_run_id input`);
  }
  if (!workflow.on?.workflow_dispatch?.inputs?.release_set_id) {
    failures.push(`${filename}: manual promotion is missing release_set_id input`);
  }
  if (workflow.on?.workflow_dispatch?.inputs?.target) {
    failures.push(`${filename}: deployment target must be fixed by the workflow file`);
  }

  const requiredJobFragments = [
    ['auto_prepare', 'Select accepted release'],
    ['auto_create_release_set', 'Create release-set manifest'],
    ['auto_preflight_release', 'Verify /'],
    ['manual_preflight_release', 'Verify /'],
    ['auto_deploy_mpc_router', 'cloudflare-router-ab'],
    ['auto_deploy_gateway', 'cloudflare-gateway'],
    ['auto_deploy_app', 'cloudflare-pages'],
    ['auto_deploy_wallet', 'cloudflare-pages'],
    ['auto_final_smoke', 'Verify /'],
    ['manual_deploy_mpc_router', 'cloudflare-router-ab'],
    ['manual_deploy_gateway', 'cloudflare-gateway'],
    ['manual_deploy_app', 'cloudflare-pages'],
    ['manual_deploy_wallet', 'cloudflare-pages'],
    ['manual_final_smoke', 'Verify /'],
  ];
  for (const [jobId, nameFragment] of requiredJobFragments) {
    const job = workflow.jobs?.[jobId];
    if (!job) {
      failures.push(`${filename}: missing ${jobId} deployment job`);
    } else if (typeof job.name !== 'string' || !job.name.includes(nameFragment)) {
      failures.push(`${filename}:${jobId}: job name must include ${JSON.stringify(nameFragment)}`);
    }
  }

  const productionGuard = `"$GITHUB_REF" != 'refs/heads/main'`;
  const workflowSource = readFileSync(join(workflowRoot, filename), 'utf8');
  if (!workflowSource.includes(productionGuard)) {
    failures.push(`${filename}: production authority guard is missing`);
  }
  if (workflowSource.includes('secrets: inherit')) {
    failures.push(`${filename}: deployment secrets must be explicit`);
  }
}

const staging = workflows.get('deploy-staging-cloudflare-stack.yml');
const production = workflows.get('deploy-production-cloudflare-stack.yml');
for (const [workflow, environment] of [
  [staging, 'staging'],
  [production, 'production'],
]) {
  if (!workflow) continue;
  if (workflow.env?.DEPLOY_TARGET !== environment) {
    failures.push(`${workflow.name}: DEPLOY_TARGET must be fixed to ${environment}`);
  }
}

if (failures.length > 0) {
  console.error('Deployment workflow policy failed:');
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(`Deployment workflow policy passed for ${workflows.size} workflows.`);
