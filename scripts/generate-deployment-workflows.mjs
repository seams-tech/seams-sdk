#!/usr/bin/env node

import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import prettier from 'prettier';
import { parse as parseYaml, Scalar, stringify as stringifyYaml } from 'yaml';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = dirname(scriptDirectory);
const workflowDirectory = join(repositoryRoot, '.github/workflows');
const templateDirectory = join(repositoryRoot, 'scripts/deployment-workflow-templates');

const workflowTargets = Object.freeze([
  Object.freeze({
    environment: 'staging',
    branch: 'dev',
    filename: 'deploy-staging-cloudflare-stack.yml',
    gatewayOrigin: 'https://seams-sdk-d1-gateway-staging.n6378056.workers.dev',
  }),
  Object.freeze({
    environment: 'production',
    branch: 'main',
    filename: 'deploy-production-cloudflare-stack.yml',
    gatewayOrigin: 'https://seams-sdk-d1-gateway.n6378056.workers.dev',
  }),
]);

const templateFiles = Object.freeze({
  release: 'release-cloudflare-stack.yml',
  stack: 'deploy-cloudflare-stack.yml',
  gateway: 'deploy-cloudflare-gateway.yml',
  pages: 'deploy-cloudflare-pages.yml',
});

function clone(value) {
  return structuredClone(value);
}

function mapStrings(value, mapper) {
  if (typeof value === 'string') return mapper(value);
  if (Array.isArray(value)) return value.map((item) => mapStrings(item, mapper));
  if (!value || typeof value !== 'object') return value;

  const mapped = {};
  for (const [key, child] of Object.entries(value)) {
    mapped[key] = mapStrings(child, mapper);
  }
  return mapped;
}

function stripExpression(value) {
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  if (trimmed.startsWith('${{') && trimmed.endsWith('}}')) {
    return trimmed.slice(3, -2).trim();
  }
  return trimmed;
}

function addEventGuard(original, eventName) {
  const expression = stripExpression(original);
  if (!expression) return eventName;
  return `${eventName} && (${expression})`;
}

function prefixNeeds(value, prefix, knownJobIds) {
  if (typeof value === 'string') {
    let result = value;
    for (const jobId of knownJobIds) {
      result = result.replaceAll(`needs.${jobId}`, `needs.${prefix}${jobId}`);
      result = result.replaceAll(`steps.${jobId}`, `steps.${prefix}${jobId}`);
    }
    if (knownJobIds.includes(value)) return `${prefix}${value}`;
    return result;
  }
  if (Array.isArray(value)) return value.map((item) => prefixNeeds(item, prefix, knownJobIds));
  return value;
}

function transformJobMap(sourceJobs, options) {
  const sourceJobIds = Object.keys(sourceJobs ?? {});
  const transformed = {};

  for (const [jobId, sourceJob] of Object.entries(sourceJobs ?? {})) {
    if (options.skip?.includes(jobId)) continue;

    let job = clone(sourceJob);
    job = mapStrings(job, (value) => options.mapValue(value));
    job = mapStrings(job, (value) => prefixNeeds(value, options.prefix, sourceJobIds));

    if (job.needs) job.needs = prefixNeeds(job.needs, options.prefix, sourceJobIds);
    job.if = addEventGuard(job.if, options.eventName);
    job.env = { ...options.sharedEnv, ...(job.env ?? {}) };

    transformed[`${options.prefix}${jobId}`] = job;
  }
  return transformed;
}

function replaceInputs(value, replacements) {
  let result = value;
  for (const [inputName, replacement] of Object.entries(replacements)) {
    result = result.replaceAll(`inputs.${inputName}`, replacement);
  }
  return result;
}

function mergeNeeds(job, additionalNeeds) {
  const existing = job.needs ? (Array.isArray(job.needs) ? job.needs : [job.needs]) : [];
  job.needs = [...new Set([...existing, ...additionalNeeds])];
}

function expression(body) {
  return '${{ ' + body + ' }}';
}

function sourceShaExpressionBody() {
  return "github.event_name == 'workflow_run' && github.event.workflow_run.head_sha || inputs.source_sha";
}

function automaticEventExpression() {
  return "github.event_name == 'workflow_run' && github.event.workflow_run.event == 'push'";
}

function sourceShaExpression() {
  return expression(sourceShaExpressionBody());
}

function targetExpression(target) {
  return `'${target.environment}'`;
}

function branchExpression(target) {
  return `'${target.branch}'`;
}

function makeSharedEnvironment(target, mode, releasePrefix) {
  const automatic = mode === 'automatic';
  return {
    DEPLOY_TARGET: target.environment,
    DEPLOY_SHA: sourceShaExpression(),
    ARTIFACT_RUN_ID: automatic ? expression('github.run_id') : expression('inputs.artifact_run_id'),
    RELEASE_SET_ID: automatic
      ? expression(`needs.${releasePrefix}create_release_set.outputs.release_set_id`)
      : expression('inputs.release_set_id'),
    DEPLOY_SOURCE_BRANCH: target.branch,
    ENFORCE_CURRENT_BRANCH: automatic ? 'true' : 'false',
    STAGING_GATEWAY_ORIGIN: 'https://seams-sdk-d1-gateway-staging.n6378056.workers.dev',
    PRODUCTION_GATEWAY_ORIGIN: 'https://seams-sdk-d1-gateway.n6378056.workers.dev',
    RUST_TOOLCHAIN: '1.96.0',
  };
}

function normalizeObject(value) {
  if (value instanceof Scalar) return value;
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(normalizeObject);
  if (!value || typeof value !== 'object') return value;

  const result = {};
  for (const [key, child] of Object.entries(value)) result[key] = normalizeObject(child);
  return result;
}

function literalizeMultilineStrings(value) {
  if (value instanceof Scalar) return value;
  if (typeof value === 'string') {
    if (!value.includes('\n')) return value;
    const scalar = new Scalar(value);
    scalar.type = 'BLOCK_LITERAL';
    return scalar;
  }
  if (Array.isArray(value)) return value.map(literalizeMultilineStrings);
  if (!value || typeof value !== 'object') return value;

  for (const [key, child] of Object.entries(value)) {
    value[key] = literalizeMultilineStrings(child);
  }
  return value;
}

async function readWorkflowTemplate(filename) {
  const templatePath = join(templateDirectory, filename);
  const source = await readFile(templatePath, 'utf8');
  return parseYaml(source, { version: '1.2' });
}

function transformReleaseJobs(template, target) {
  return transformJobMap(template.jobs, {
    prefix: 'auto_',
    eventName: automaticEventExpression(),
    skip: ['deploy'],
    sharedEnv: {},
    mapValue: (value) =>
      replaceInputs(value, {
        target: 'env.DEPLOY_TARGET',
        source_sha: 'env.SOURCE_SHA',
        validation_run_id: 'env.VALIDATION_RUN_ID',
      }).replaceAll('internal-release-cloudflare-stack', 'deploy-cloudflare-stack'),
  });
}

function transformStackJobs(template, target, mode) {
  const automatic = mode === 'automatic';
  const prefix = automatic ? 'auto_' : 'manual_';
  const releasePrefix = 'auto_';
  const replacements = automatic
    ? {
        target: targetExpression(target),
        deploy_sha: sourceShaExpressionBody(),
        artifact_run_id: 'github.run_id',
        release_set_id: `needs.${releasePrefix}create_release_set.outputs.release_set_id`,
        source_branch: branchExpression(target),
      }
    : {
        target: targetExpression(target),
        deploy_sha: sourceShaExpressionBody(),
        artifact_run_id: 'inputs.artifact_run_id',
        release_set_id: 'inputs.release_set_id',
        source_branch: branchExpression(target),
      };
  const sharedEnv = makeSharedEnvironment(target, mode, releasePrefix);
  const jobs = transformJobMap(template.jobs, {
    prefix,
    eventName: automatic
      ? automaticEventExpression()
      : "github.event_name == 'workflow_dispatch'",
    skip: ['deploy_gateway', 'deploy_pages'],
    sharedEnv,
    mapValue: (value) => replaceInputs(value, replacements),
  });
  for (const job of Object.values(jobs)) {
    if (typeof job.name === 'string') {
      job.name = job.name
        .replace('${{ env.DEPLOY_TARGET }}', target.environment)
        .replace(expression(targetExpression(target)), target.environment);
    }
  }

  const preflight = jobs[`${prefix}preflight_release`];
  if (automatic) {
    mergeNeeds(preflight, ['auto_create_release_set']);
    preflight.if = addEventGuard(
      "needs.auto_create_release_set.result == 'success'",
      "github.event_name == 'workflow_run'",
    );
    for (const job of Object.values(jobs)) {
      mergeNeeds(job, ['auto_create_release_set']);
    }
  }

  return jobs;
}

function transformGatewayJobs(template, target, mode) {
  const automatic = mode === 'automatic';
  const prefix = automatic ? 'auto_' : 'manual_';
  const sharedEnv = {
    ...makeSharedEnvironment(target, mode, 'auto_'),
    GATEWAY_ARTIFACT_NAME: `release-${target.environment}-${sourceShaExpression()}-gateway`,
    GATEWAY_ARTIFACT_IDENTITY: '{"wasmPackageSet":"gateway-v1"}',
  };
  const replacements = automatic
    ? {
        target: targetExpression(target),
        source_sha: sourceShaExpressionBody(),
        artifact_run_id: 'github.run_id',
        release_set_id: 'needs.auto_create_release_set.outputs.release_set_id',
      }
    : {
        target: targetExpression(target),
        source_sha: sourceShaExpressionBody(),
        artifact_run_id: 'inputs.artifact_run_id',
        release_set_id: 'inputs.release_set_id',
      };
  const jobs = transformJobMap(template.jobs, {
    prefix,
    eventName: automatic
      ? automaticEventExpression()
      : "github.event_name == 'workflow_dispatch'",
    sharedEnv,
    mapValue: (value) => replaceInputs(value, replacements),
  });
  const gateway = jobs[`${prefix}deploy`];
  gateway.name = `Deploy / ${target.environment} / cloudflare-gateway`;
  mergeNeeds(gateway, [`${prefix}preflight_release`]);
  if (automatic) mergeNeeds(gateway, ['auto_create_release_set']);
  gateway.if = addEventGuard(
    'needs.' +
      `${prefix}preflight_release.result == 'success' && contains(fromJSON(needs.${prefix}preflight_release.outputs.selected_components), 'gateway')`,
    automatic ? "github.event_name == 'workflow_run'" : "github.event_name == 'workflow_dispatch'",
  );
  return { [`${prefix}deploy_gateway`]: gateway };
}

function transformPagesJobs(template, target, mode) {
  const automatic = mode === 'automatic';
  const prefix = automatic ? 'auto_' : 'manual_';
  const sharedEnv = {
    ...makeSharedEnvironment(target, mode, 'auto_'),
    DEPLOY_ENVIRONMENT: target.environment,
    PAGES_BRANCH: target.branch,
    PAGES_ARTIFACT_NAME: `release-${target.environment}-${sourceShaExpression()}-pages`,
    PAGES_ARTIFACT_IDENTITY: '{"pagesBuild":"app-wallet-v1"}',
  };
  const replacements = automatic
    ? {
        target: "'all'",
        deploy_environment: targetExpression(target),
        source_sha: sourceShaExpressionBody(),
        artifact_run_id: 'github.run_id',
        release_set_id: 'needs.auto_create_release_set.outputs.release_set_id',
      }
    : {
        target: "'all'",
        deploy_environment: targetExpression(target),
        source_sha: sourceShaExpressionBody(),
        artifact_run_id: 'inputs.artifact_run_id',
        release_set_id: 'inputs.release_set_id',
      };
  const jobs = transformJobMap(template.jobs, {
    prefix,
    eventName: automatic
      ? "github.event_name == 'workflow_run'"
      : "github.event_name == 'workflow_dispatch'",
    sharedEnv,
    mapValue: (value) => replaceInputs(value, replacements),
  });
  jobs[`${prefix}deploy_app`].name = `Deploy / ${target.environment} / cloudflare-pages / app`;
  jobs[`${prefix}deploy_wallet`].name =
    `Deploy / ${target.environment} / cloudflare-pages / wallet`;
  const pageSelection = `contains(fromJSON(needs.${prefix}preflight_release.outputs.selected_components), 'site') || contains(fromJSON(needs.${prefix}preflight_release.outputs.selected_components), 'signer-iframe')`;
  for (const jobId of [`${prefix}deploy_app`, `${prefix}deploy_wallet`]) {
    const job = jobs[jobId];
    mergeNeeds(job, [`${prefix}preflight_release`, `${prefix}deploy_gateway`]);
    if (automatic) mergeNeeds(job, ['auto_create_release_set']);
    job.if = `always() && ${automatic ? "github.event_name == 'workflow_run'" : "github.event_name == 'workflow_dispatch'"} && needs.${prefix}preflight_release.result == 'success' && (${pageSelection}) && (!contains(fromJSON(needs.${prefix}preflight_release.outputs.selected_components), 'gateway') || needs.${prefix}deploy_gateway.result == 'success')`;
  }
  return jobs;
}

function makePagesBarrier(target, mode) {
  const automatic = mode === 'automatic';
  const prefix = automatic ? 'auto_' : 'manual_';
  const pageBarrierId = `${prefix}deploy_pages`;
  const eventName = automatic
    ? automaticEventExpression()
    : "github.event_name == 'workflow_dispatch'";
  const pageSelection = `contains(fromJSON(needs.${prefix}preflight_release.outputs.selected_components), 'site') || contains(fromJSON(needs.${prefix}preflight_release.outputs.selected_components), 'signer-iframe')`;
  return {
    [pageBarrierId]: {
      name: `Verify / ${target.environment} / cloudflare-pages`,
      if: `always() && ${eventName} && needs.${prefix}preflight_release.result == 'success' && (${pageSelection}) && (!contains(fromJSON(needs.${prefix}preflight_release.outputs.selected_components), 'gateway') || needs.${prefix}deploy_gateway.result == 'success')`,
      needs: [
        `${prefix}preflight_release`,
        `${prefix}deploy_gateway`,
        `${prefix}deploy_app`,
        `${prefix}deploy_wallet`,
      ],
      'runs-on': 'ubuntu-latest',
      'timeout-minutes': 2,
      steps: [
        {
          name: 'Require Pages deployments to succeed',
          env: {
            APP_RESULT: expression(`needs.${prefix}deploy_app.result`),
            WALLET_RESULT: expression(`needs.${prefix}deploy_wallet.result`),
          },
          run: 'test "$APP_RESULT" = success && test "$WALLET_RESULT" = success',
        },
      ],
    },
  };
}

function rewriteFinalSmoke(jobMap, target, mode) {
  const prefix = mode === 'automatic' ? 'auto_' : 'manual_';
  const finalSmoke = jobMap[`${prefix}final_smoke`];
  if (!finalSmoke) throw new Error(`missing ${prefix}final_smoke job`);
  finalSmoke.needs = finalSmoke.needs.map((jobId) =>
    jobId === `${prefix}deploy_pages` ? jobId : jobId,
  );
  finalSmoke.name = `Verify / ${target.environment} / cloudflare-stack`;
  return finalSmoke;
}

function makeWorkflowRoot(target, jobs) {
  const runName = new Scalar(
    `deploy / ${target.environment} / cloudflare-stack /\n` +
      `${sourceShaExpression()} /\n` +
      "${{ github.event_name == 'workflow_run' && 'automatic' || 'manual-promotion' }}",
  );
  runName.type = 'BLOCK_FOLDED';
  const workflow = {
    name: `Deploy / ${target.environment} / cloudflare-stack`,
    'run-name': runName,
    on: {
      workflow_run: {
        workflows: ['Validate / repository'],
        types: ['completed'],
        branches: [target.branch],
      },
      workflow_dispatch: {
        inputs: {
          source_sha: {
            description: `Exact accepted ${target.environment} source SHA`,
            required: true,
            type: 'string',
          },
          artifact_run_id: {
            description: 'Accepted release artifact workflow run ID',
            required: true,
            type: 'string',
          },
          release_set_id: {
            description: 'Content-addressed release-set ID',
            required: true,
            type: 'string',
          },
        },
      },
    },
    permissions: { actions: 'read', contents: 'read' },
    env: {
      DEPLOY_TARGET: target.environment,
      DEPLOY_SOURCE_BRANCH: target.branch,
      SOURCE_SHA: sourceShaExpression(),
      VALIDATION_RUN_ID:
        "${{ github.event_name == 'workflow_run' && github.event.workflow_run.id || '' }}",
      MANUAL_ARTIFACT_RUN_ID: '${{ inputs.artifact_run_id }}',
      MANUAL_RELEASE_SET_ID: '${{ inputs.release_set_id }}',
      STAGING_GATEWAY_ORIGIN: 'https://seams-sdk-d1-gateway-staging.n6378056.workers.dev',
      PRODUCTION_GATEWAY_ORIGIN: 'https://seams-sdk-d1-gateway.n6378056.workers.dev',
      RUST_TOOLCHAIN: '1.96.0',
    },
    concurrency: {
      group: `deployment-${target.environment}`,
      'cancel-in-progress': false,
    },
    jobs,
  };
  return normalizeObject(workflow);
}

async function generateWorkflow(target, templates) {
  const automaticReleaseJobs = transformReleaseJobs(templates.release, target);
  const automaticStackJobs = transformStackJobs(templates.stack, target, 'automatic');
  const automaticGatewayJobs = transformGatewayJobs(templates.gateway, target, 'automatic');
  const automaticPagesJobs = transformPagesJobs(templates.pages, target, 'automatic');
  const manualStackJobs = transformStackJobs(templates.stack, target, 'manual');
  const manualGatewayJobs = transformGatewayJobs(templates.gateway, target, 'manual');
  const manualPagesJobs = transformPagesJobs(templates.pages, target, 'manual');

  const automaticJobs = {
    ...automaticReleaseJobs,
    ...automaticStackJobs,
    ...automaticGatewayJobs,
    ...automaticPagesJobs,
    ...makePagesBarrier(target, 'automatic'),
  };
  const manualJobs = {
    ...manualStackJobs,
    ...manualGatewayJobs,
    ...manualPagesJobs,
    ...makePagesBarrier(target, 'manual'),
  };

  rewriteFinalSmoke(automaticJobs, target, 'automatic');
  rewriteFinalSmoke(manualJobs, target, 'manual');

  const jobs = { ...automaticJobs, ...manualJobs };
  const yaml = stringifyYaml(literalizeMultilineStrings(makeWorkflowRoot(target, jobs)), {
    lineWidth: 120,
  });
  const outputPath = join(workflowDirectory, target.filename);
  const prettierOptions = (await prettier.resolveConfig(outputPath)) ?? {};
  return prettier.format(yaml, {
    ...prettierOptions,
    filepath: outputPath,
  });
}

async function main() {
  const templates = {};
  for (const [key, filename] of Object.entries(templateFiles)) {
    templates[key] = await readWorkflowTemplate(filename);
  }

  for (const target of workflowTargets) {
    const generated = await generateWorkflow(target, templates);
    const outputPath = join(workflowDirectory, target.filename);
    if (process.argv.includes('--check')) {
      const current = await readFile(outputPath, 'utf8');
      if (current !== generated) {
        throw new Error(`${target.filename} is stale; run pnpm generate:deployment-workflows`);
      }
    } else {
      await writeFile(outputPath, generated);
    }
  }
}

await main();
