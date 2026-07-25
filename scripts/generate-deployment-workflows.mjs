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
    frontendFilename: 'deploy-staging-frontend.yml',
    gatewayOrigin: 'https://seams-sdk-d1-gateway-staging.n6378056.workers.dev',
  }),
  Object.freeze({
    environment: 'production',
    branch: 'main',
    filename: 'deploy-production-cloudflare-stack.yml',
    frontendFilename: 'deploy-production-frontend.yml',
    gatewayOrigin: 'https://seams-sdk-d1-gateway.n6378056.workers.dev',
  }),
]);

const templateFiles = Object.freeze({
  release: 'release-cloudflare-stack.yml',
  frontendRelease: 'release-cloudflare-frontend.yml',
  stack: 'deploy-cloudflare-stack.yml',
  frontend: 'deploy-cloudflare-frontend.yml',
  gateway: 'deploy-cloudflare-gateway.yml',
});

const DEPLOYMENT_ENVIRONMENT_SUFFIXES = Object.freeze([
  'frontend',
  'gateway',
  'mpc-router',
  'deriver-a',
  'deriver-b',
  'signing-worker',
]);

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

function bindJobEnvironment(job, target) {
  const environment = job.environment;
  const environmentName =
    typeof environment === 'string'
      ? environment
      : environment && typeof environment === 'object' && typeof environment.name === 'string'
        ? environment.name
        : undefined;
  if (environmentName === undefined) return job;

  const suffix = DEPLOYMENT_ENVIRONMENT_SUFFIXES.find((value) => environmentName.includes(value));
  if (suffix === undefined) return job;
  const boundName = `${target.environment}-${suffix}`;
  job.environment =
    typeof environment === 'string' ? boundName : { ...environment, name: boundName };
  return job;
}

function transformJobMap(sourceJobs, options) {
  const sourceJobIds = Object.keys(sourceJobs ?? {});
  const transformed = {};

  for (const [jobId, sourceJob] of Object.entries(sourceJobs ?? {})) {
    if (options.skip?.includes(jobId)) continue;

    let job = clone(sourceJob);
    job = mapStrings(job, (value) => options.mapValue(value));
    job = mapStrings(job, (value) => prefixNeeds(value, options.prefix, sourceJobIds));
    job = bindJobEnvironment(job, options.target);

    if (job.needs) job.needs = prefixNeeds(job.needs, options.prefix, sourceJobIds);
    job.if = addEventGuard(job.if, options.eventName);
    job.env = { ...options.sharedEnv, ...(job.env ?? {}) };

    transformed[`${options.prefix}${jobId}`] = job;
  }
  return transformed;
}

function mapJobMap(sourceJobs, options) {
  const transformed = {};
  for (const [jobId, sourceJob] of Object.entries(sourceJobs ?? {})) {
    if (options.skip?.includes(jobId)) continue;
    let job = clone(sourceJob);
    job = mapStrings(job, (value) => options.mapValue(value));
    if (job.needs) job.needs = mapStrings(job.needs, (value) => options.mapValue(value));
    job = bindJobEnvironment(job, options.target);
    job.env = { ...options.sharedEnv, ...(job.env ?? {}) };
    transformed[jobId] = job;
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
  return "github.event_name == 'workflow_run' && github.event.workflow_run.event == 'push' && github.event.workflow_run.conclusion == 'success'";
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
    target,
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
    eventName: automatic ? automaticEventExpression() : "github.event_name == 'workflow_dispatch'",
    skip: ['deploy_gateway', 'deploy_pages'],
    sharedEnv,
    target,
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
      automaticEventExpression(),
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
    eventName: automatic ? automaticEventExpression() : "github.event_name == 'workflow_dispatch'",
    sharedEnv,
    target,
    mapValue: (value) => replaceInputs(value, replacements),
  });
  const gateway = jobs[`${prefix}deploy`];
  gateway.name = `Deploy / ${target.environment} / cloudflare-api-gateway`;
  mergeNeeds(gateway, [`${prefix}preflight_release`]);
  if (automatic) mergeNeeds(gateway, ['auto_create_release_set']);
  gateway.if = addEventGuard(
    'needs.' +
      `${prefix}preflight_release.result == 'success' && contains(fromJSON(needs.${prefix}preflight_release.outputs.selected_components), 'gateway')`,
    automatic ? automaticEventExpression() : "github.event_name == 'workflow_dispatch'",
  );
  return { [`${prefix}deploy_gateway`]: gateway };
}

function rewriteFinalSmoke(jobMap, target, mode) {
  const prefix = mode === 'automatic' ? 'auto_' : 'manual_';
  const finalSmoke = jobMap[`${prefix}final_smoke`];
  if (!finalSmoke) throw new Error(`missing ${prefix}final_smoke job`);
  finalSmoke.name = `Verify / ${target.environment} / cloudflare-stack`;
  return finalSmoke;
}

function frontendInputReplacements(target) {
  return {
    target: targetExpression(target),
    deploy_environment: targetExpression(target),
    source_sha: sourceShaExpressionBody(),
    deploy_sha: sourceShaExpressionBody(),
    validation_run_id: "''",
    artifact_run_id:
      "github.event_name == 'workflow_run' && github.run_id || inputs.artifact_run_id",
    release_set_id:
      "github.event_name == 'workflow_run' && needs.create_release_set.outputs.release_set_id || inputs.release_set_id",
    backend_receipt_run_id:
      "github.event_name == 'workflow_run' && github.event.workflow_run.id || inputs.backend_receipt_run_id",
    source_branch: branchExpression(target),
    enforce_current_branch: "github.event_name == 'workflow_run'",
  };
}

function transformFrontendJobs(templates, target) {
  const replacements = frontendInputReplacements(target);
  const sharedEnv = {
    DEPLOY_TARGET: target.environment,
    DEPLOY_ENVIRONMENT: target.environment,
    DEPLOY_SOURCE_BRANCH: target.branch,
    DEPLOY_SHA: sourceShaExpression(),
    ARTIFACT_RUN_ID: expression(
      "github.event_name == 'workflow_run' && github.run_id || inputs.artifact_run_id",
    ),
    RELEASE_SET_ID: expression(
      "github.event_name == 'workflow_run' && needs.create_release_set.outputs.release_set_id || inputs.release_set_id",
    ),
    BACKEND_RECEIPT_RUN_ID: expression(
      "github.event_name == 'workflow_run' && github.event.workflow_run.id || inputs.backend_receipt_run_id",
    ),
    ENFORCE_CURRENT_BRANCH: expression("github.event_name == 'workflow_run'"),
    STAGING_GATEWAY_ORIGIN: 'https://seams-sdk-d1-gateway-staging.n6378056.workers.dev',
    PRODUCTION_GATEWAY_ORIGIN: 'https://seams-sdk-d1-gateway.n6378056.workers.dev',
    RUST_TOOLCHAIN: '1.96.0',
  };
  const jobs = {
    ...mapJobMap(templates.frontendRelease.jobs, {
      skip: ['deploy'],
      sharedEnv,
      target,
      mapValue: (value) => replaceInputs(value, replacements),
    }),
    ...mapJobMap(templates.frontend.jobs, {
      sharedEnv,
      target,
      mapValue: (value) => replaceInputs(value, replacements),
    }),
  };

  const automaticOnly =
    "github.event_name == 'workflow_run' && github.event.workflow_run.event == 'workflow_run' && github.event.workflow_run.conclusion == 'success'";
  jobs.prepare.if = "github.event_name == 'workflow_dispatch' || (" + automaticOnly + ')';
  jobs.select_components.if = automaticOnly;
  jobs.build_pages.if = `${automaticOnly} && needs.select_components.result == 'success' && needs.select_components.outputs.frontend_components != '[]'`;
  jobs.create_release_set.if = `always() && ${automaticOnly} && needs.prepare.result == 'success' && needs.select_components.result == 'success' && needs.select_components.outputs.frontend_components != '[]' && needs.build_pages.result == 'success'`;
  jobs.preflight_release.if = `always() && ((github.event_name == 'workflow_dispatch') || (${automaticOnly} && needs.select_components.result == 'success' && needs.select_components.outputs.frontend_components != '[]' && needs.create_release_set.result == 'success'))`;
  mergeNeeds(jobs.preflight_release, ['select_components', 'create_release_set']);
  for (const jobId of ['deploy_app', 'deploy_wallet', 'frontend_smoke']) {
    jobs[jobId].name = jobs[jobId].name.replace(
      '${{ inputs.deploy_environment }}',
      target.environment,
    );
  }
  jobs.frontend_smoke.name = `Verify / ${target.environment} / frontend`;
  return jobs;
}

function backendSelectionExpression(prefix) {
  const selected = `needs.${prefix}preflight_release.outputs.selected_components`;
  return ['gateway', 'router', 'deriver-a', 'deriver-b', 'signing-worker']
    .map((component) => `contains(fromJSON(${selected}), '${component}')`)
    .join(' || ');
}

function makeBackendReceiptJob(target, prefix, mode) {
  const automatic = mode === 'automatic';
  const eventName = automatic
    ? automaticEventExpression()
    : "github.event_name == 'workflow_dispatch'";
  const artifactRunId = automatic ? 'github.run_id' : 'inputs.artifact_run_id';
  const releaseSetId = automatic
    ? `needs.${prefix}create_release_set.outputs.release_set_id`
    : 'inputs.release_set_id';
  const selectedComponents = `needs.${prefix}preflight_release.outputs.selected_components`;
  const receiptInputFile = '.release-artifacts/backend-coordination-receipt/input.json';
  return {
    [`${prefix}emit_backend_coordination_receipt`]: {
      name: `Emit / ${target.environment} / backend coordination receipt`,
      if: `always() && ${eventName} && needs.${prefix}preflight_release.result == 'success' && needs.${prefix}final_smoke.result == 'success' && (${backendSelectionExpression(prefix)})`,
      needs: [
        `${prefix}preflight_release`,
        `${prefix}final_smoke`,
        ...(automatic ? [`${prefix}create_release_set`] : []),
      ],
      'runs-on': 'ubuntu-latest',
      'timeout-minutes': 5,
      environment: {
        name: `${target.environment}-gateway`,
      },
      env: {
        DEPLOY_TARGET: target.environment,
        DEPLOY_SHA: automatic ? sourceShaExpression() : expression('inputs.source_sha'),
        ARTIFACT_RUN_ID: expression(artifactRunId),
        RELEASE_SET_ID: expression(releaseSetId),
        SELECTED_BACKEND_COMPONENTS: expression(selectedComponents),
      },
      steps: [
        {
          name: 'Checkout selected revision',
          uses: 'actions/checkout@v6',
          with: { 'fetch-depth': 0, ref: '${{ env.DEPLOY_SHA }}' },
        },
        {
          name: 'Setup Node',
          uses: 'actions/setup-node@v6',
          with: { 'node-version': '24' },
        },
        {
          name: 'Download backend release-set manifest',
          uses: 'actions/download-artifact@v8',
          with: {
            name: 'release-set-${{ env.RELEASE_SET_ID }}',
            path: '.release-artifacts/release-set',
            'github-token': '${{ secrets.GITHUB_TOKEN }}',
            repository: '${{ github.repository }}',
            'run-id': '${{ env.ARTIFACT_RUN_ID }}',
          },
        },
        {
          name: 'Verify backend release-set manifest',
          run: [
            'set -euo pipefail',
            'node scripts/deployment-release.mjs verify \\',
            '  --manifest .release-artifacts/release-set/manifest.json \\',
            '  --lane backend \\',
            '  --target "$DEPLOY_TARGET" \\',
            '  --source-sha "$DEPLOY_SHA" \\',
            '  --artifact-run-id "$ARTIFACT_RUN_ID" \\',
            '  --release-set-id "$RELEASE_SET_ID"',
          ].join('\n'),
        },
        {
          name: 'Assemble backend coordination receipt input',
          env: { RECEIPT_INPUT_FILE: receiptInputFile },
          run: [
            'set -euo pipefail',
            'mkdir -p "$(dirname "$RECEIPT_INPUT_FILE")"',
            "node --input-type=module <<'NODE'",
            "import { readFile, writeFile } from 'node:fs/promises';",
            "const manifest = JSON.parse(await readFile('.release-artifacts/release-set/manifest.json', 'utf8'));",
            "const backendNames = new Set(['gateway', 'router', 'deriver-a', 'deriver-b', 'signing-worker']);",
            'const selected = JSON.parse(process.env.SELECTED_BACKEND_COMPONENTS).filter((name) => backendNames.has(name)).sort();',
            'const digests = manifest.components.filter((component) => selected.includes(component.name)).map((component) => ({ component: component.name, digestSha256: component.contentDigestSha256 }));',
            "const input = { mode: 'backend-deployment', target: process.env.DEPLOY_TARGET, receiptRunId: process.env.GITHUB_RUN_ID, acceptedSourceSha: process.env.DEPLOY_SHA, acceptedValidationRunId: manifest.acceptedValidationRunId, backendArtifactRunId: process.env.ARTIFACT_RUN_ID, backendReleaseSetId: process.env.RELEASE_SET_ID, backendReleaseSetManifest: manifest, selectedBackendComponents: selected, deployedComponentDigests: digests, smokeResult: { status: 'passed', completedAt: new Date().toISOString(), checks: [{ name: 'backend-final-smoke', status: 200 }] }, createdAt: new Date().toISOString() };",
            'await writeFile(process.env.RECEIPT_INPUT_FILE, `${JSON.stringify(input, null, 2)}\\n`);',
            'NODE',
          ].join('\n'),
        },
        {
          name: 'Create backend coordination receipt',
          run: `node scripts/deployment-coordination-receipt.mjs --command create --input-file ${receiptInputFile} --output .release-artifacts/backend-coordination-receipt/manifest.json`,
        },
        {
          name: 'Upload backend coordination receipt',
          uses: 'actions/upload-artifact@v7',
          with: {
            name: 'backend-coordination-receipt-${{ env.DEPLOY_TARGET }}',
            path: '.release-artifacts/backend-coordination-receipt/manifest.json',
            'include-hidden-files': true,
            'retention-days': 30,
          },
        },
      ],
    },
  };
}

function makeNoOpCoordinationReceiptJob(target) {
  const backendSelection = ['gateway', 'router', 'deriver-a', 'deriver-b', 'signing-worker']
    .map(
      (component) =>
        `contains(fromJSON(needs.auto_select_components.outputs.components), '${component}')`,
    )
    .join(' || ');
  return {
    auto_emit_frontend_only_noop_receipt: {
      name: `Emit / ${target.environment} / backend coordination receipt / frontend-only no-op`,
      if: `always() && ${automaticEventExpression()} && needs.auto_select_components.result == 'success' && !(${backendSelection})`,
      needs: ['auto_select_components'],
      'runs-on': 'ubuntu-latest',
      'timeout-minutes': 1,
      env: {
        DEPLOY_TARGET: target.environment,
        DEPLOY_SOURCE_BRANCH: target.branch,
        DEPLOY_SHA: sourceShaExpression(),
        VALIDATION_RUN_ID: expression('github.event.workflow_run.id'),
      },
      steps: [
        {
          name: 'Checkout selected revision',
          uses: 'actions/checkout@v6',
          with: { ref: '${{ env.DEPLOY_SHA }}' },
        },
        {
          name: 'Resolve active backend receipt',
          id: 'resolve_active',
          env: {
            GH_TOKEN: '${{ secrets.GITHUB_TOKEN }}',
            RECEIPT_ARTIFACT_NAME: `backend-coordination-receipt-${target.environment}`,
          },
          run: [
            'set -euo pipefail',
            'workflow_file="deploy-${DEPLOY_TARGET}-cloudflare-stack.yml"',
            'active_run_id="$(gh api --paginate "repos/$GITHUB_REPOSITORY/actions/workflows/$workflow_file/runs?branch=$DEPLOY_SOURCE_BRANCH&status=success&per_page=100" --jq \' .workflow_runs[].id\' | while read -r candidate; do [[ "$candidate" == "$GITHUB_RUN_ID" ]] && continue; if gh api "repos/$GITHUB_REPOSITORY/actions/runs/$candidate/artifacts?per_page=100" --jq \' .artifacts[].name\' | grep -Fxq "$RECEIPT_ARTIFACT_NAME"; then echo "$candidate"; break; fi; done)"',
            'test -n "$active_run_id" || { echo "::error title=No active backend receipt::A frontend-only release requires an existing backend coordination receipt"; exit 1; }',
            'echo "run_id=$active_run_id" >> "$GITHUB_OUTPUT"',
          ].join('\n'),
        },
        {
          name: 'Download active backend receipt',
          uses: 'actions/download-artifact@v8',
          with: {
            name: `backend-coordination-receipt-${target.environment}`,
            path: '.active-backend-receipt',
            'github-token': '${{ secrets.GITHUB_TOKEN }}',
            repository: '${{ github.repository }}',
            'run-id': '${{ steps.resolve_active.outputs.run_id }}',
          },
        },
        {
          name: 'Verify active backend receipt',
          run: 'node scripts/deployment-coordination-receipt.mjs --command verify --receipt-file .active-backend-receipt/manifest.json',
        },
        {
          name: 'Create frontend-only no-op receipt',
          run: [
            'set -euo pipefail',
            'echo "selected_components=[]" >> "$GITHUB_STEP_SUMMARY"',
            'mkdir -p .release-artifacts/backend-coordination-receipt',
            "node --input-type=module <<'NODE'",
            "import { readFile, writeFile } from 'node:fs/promises';",
            "const previousActiveReceipt = JSON.parse(await readFile('.active-backend-receipt/manifest.json', 'utf8'));",
            "const input = { mode: 'frontend-only-no-op', target: process.env.DEPLOY_TARGET, receiptRunId: process.env.GITHUB_RUN_ID, acceptedSourceSha: process.env.DEPLOY_SHA, acceptedValidationRunId: process.env.VALIDATION_RUN_ID, selectedBackendComponents: [], previousActiveReceipt, createdAt: new Date().toISOString() };",
            "await writeFile('.release-artifacts/backend-coordination-receipt/input.json', `${JSON.stringify(input, null, 2)}\\n`);",
            'NODE',
            'node scripts/deployment-coordination-receipt.mjs --command create --input-file .release-artifacts/backend-coordination-receipt/input.json --output .release-artifacts/backend-coordination-receipt/manifest.json',
          ].join('\n'),
        },
        {
          name: 'Upload frontend-only no-op receipt',
          uses: 'actions/upload-artifact@v7',
          with: {
            name: `backend-coordination-receipt-${target.environment}`,
            path: '.release-artifacts/backend-coordination-receipt/manifest.json',
            'include-hidden-files': true,
            'retention-days': 30,
          },
        },
      ],
    },
  };
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
      EVENT_BRANCH: expression(
        "github.event_name == 'workflow_run' && github.event.workflow_run.head_branch || github.ref_name",
      ),
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
      group: `deployment-${target.environment}-backend`,
      'cancel-in-progress': false,
    },
    jobs,
  };
  return normalizeObject(workflow);
}

function makeFrontendWorkflowRoot(target, jobs) {
  const runName = new Scalar(
    `deploy / ${target.environment} / frontend /\n` +
      `${sourceShaExpression()} /\n` +
      "${{ github.event_name == 'workflow_run' && 'automatic' || 'manual-promotion' }}",
  );
  runName.type = 'BLOCK_FOLDED';
  return normalizeObject({
    name: `Deploy / ${target.environment} / frontend`,
    'run-name': runName,
    on: {
      workflow_run: {
        workflows: [`Deploy / ${target.environment} / cloudflare-stack`],
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
            description: 'Accepted frontend release artifact workflow run ID',
            required: true,
            type: 'string',
          },
          release_set_id: {
            description: 'Content-addressed frontend release-set ID',
            required: true,
            type: 'string',
          },
          backend_receipt_run_id: {
            description: 'Accepted backend coordination receipt workflow run ID',
            required: true,
            type: 'string',
          },
        },
      },
    },
    permissions: { actions: 'read', contents: 'read' },
    env: {
      DEPLOY_TARGET: target.environment,
      DEPLOY_ENVIRONMENT: target.environment,
      DEPLOY_SOURCE_BRANCH: target.branch,
      EVENT_BRANCH: expression(
        "github.event_name == 'workflow_run' && github.event.workflow_run.head_branch || github.ref_name",
      ),
      SOURCE_SHA: sourceShaExpression(),
      ARTIFACT_RUN_ID: expression(
        "github.event_name == 'workflow_run' && github.run_id || inputs.artifact_run_id",
      ),
      RELEASE_SET_ID: expression("inputs.release_set_id || ''"),
      BACKEND_RECEIPT_RUN_ID: expression(
        "github.event_name == 'workflow_run' && github.event.workflow_run.id || inputs.backend_receipt_run_id",
      ),
      PAGES_BRANCH: target.environment === 'production' ? 'main' : 'dev',
      PAGES_ARTIFACT_IDENTITY: '{"pagesBuild":"app-wallet-v1"}',
      SIGNER_IFRAME_ARTIFACT_IDENTITY: '{"pagesBuild":"app-wallet-v1"}',
      RELEASE_MANIFEST: '.release-artifacts/release-set/manifest.json',
      STAGING_GATEWAY_ORIGIN: 'https://seams-sdk-d1-gateway-staging.n6378056.workers.dev',
      PRODUCTION_GATEWAY_ORIGIN: 'https://seams-sdk-d1-gateway.n6378056.workers.dev',
      RUST_TOOLCHAIN: '1.96.0',
    },
    concurrency: {
      group: `deployment-${target.environment}-frontend`,
      'cancel-in-progress': false,
    },
    jobs,
  });
}

async function generateWorkflow(target, templates) {
  const automaticReleaseJobs = transformReleaseJobs(templates.release, target);
  const automaticStackJobs = transformStackJobs(templates.stack, target, 'automatic');
  const automaticGatewayJobs = transformGatewayJobs(templates.gateway, target, 'automatic');
  const manualStackJobs = transformStackJobs(templates.stack, target, 'manual');
  const manualGatewayJobs = transformGatewayJobs(templates.gateway, target, 'manual');

  const automaticJobs = {
    ...automaticReleaseJobs,
    ...automaticStackJobs,
    ...automaticGatewayJobs,
    ...makeBackendReceiptJob(target, 'auto_', 'automatic'),
    ...makeNoOpCoordinationReceiptJob(target),
  };
  const manualJobs = {
    ...manualStackJobs,
    ...manualGatewayJobs,
    ...makeBackendReceiptJob(target, 'manual_', 'manual'),
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

async function generateFrontendWorkflow(target, templates) {
  const jobs = transformFrontendJobs(templates, target);
  const workflow = makeFrontendWorkflowRoot(target, jobs);
  const outputPath = join(workflowDirectory, target.frontendFilename);
  const yaml = stringifyYaml(literalizeMultilineStrings(workflow), { lineWidth: 120 });
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
    const frontendGenerated = await generateFrontendWorkflow(target, {
      frontendRelease: templates.frontendRelease,
      frontend: templates.frontend,
    });
    const frontendOutputPath = join(workflowDirectory, target.frontendFilename);
    if (process.argv.includes('--check')) {
      const currentFrontend = await readFile(frontendOutputPath, 'utf8');
      if (currentFrontend !== frontendGenerated) {
        throw new Error(
          `${target.frontendFilename} is stale; run pnpm generate:deployment-workflows`,
        );
      }
    } else {
      await writeFile(frontendOutputPath, frontendGenerated);
    }
  }
}

await main();
