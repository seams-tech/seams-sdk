import { expect, test } from '@playwright/test';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

type RecordValue = Record<string, unknown>;

type FrontendTarget = {
  readonly environment: 'staging' | 'production';
  readonly branch: 'dev' | 'main';
  readonly filename: string;
  readonly backendWorkflowName: string;
  readonly workflowName: string;
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const workflowRoot = path.join(repoRoot, '.github/workflows');
const frontendTargets: readonly FrontendTarget[] = [
  {
    environment: 'staging',
    branch: 'dev',
    filename: 'deploy-staging-frontend.yml',
    backendWorkflowName: 'Deploy / staging / cloudflare-stack',
    workflowName: 'Deploy / staging / frontend',
  },
  {
    environment: 'production',
    branch: 'main',
    filename: 'deploy-production-frontend.yml',
    backendWorkflowName: 'Deploy / production / cloudflare-stack',
    workflowName: 'Deploy / production / frontend',
  },
];

function isRecord(value: unknown): value is RecordValue {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireRecord(value: unknown, label: string): RecordValue {
  if (!isRecord(value)) throw new Error(`${label} must be a mapping`);
  return value;
}

function requireString(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  return value;
}

function requireArray(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  return value;
}

function readWorkflow(filename: string): RecordValue {
  const source = readFileSync(path.join(workflowRoot, filename), 'utf8');
  return requireRecord(parseYaml(source, { version: '1.2' }), filename);
}

function readWorkflowSource(filename: string): string {
  return readFileSync(path.join(workflowRoot, filename), 'utf8');
}

function readWorkflowJobs(workflow: RecordValue): RecordValue {
  return requireRecord(workflow.jobs, 'workflow jobs');
}

function readWorkflowTriggers(workflow: RecordValue): RecordValue {
  return requireRecord(workflow.on, 'workflow triggers');
}

function readJobSteps(job: RecordValue): readonly RecordValue[] {
  return requireArray(job.steps, 'job steps')
    .filter(isRecord)
    .map((step) => step);
}

function collectArtifactDownloadNames(workflow: RecordValue): readonly string[] {
  const names: string[] = [];
  for (const job of Object.values(readWorkflowJobs(workflow))) {
    if (!isRecord(job)) continue;
    for (const step of readJobSteps(job)) {
      if (step.uses !== 'actions/download-artifact@v8') continue;
      const options = requireRecord(step.with, 'download-artifact options');
      names.push(requireString(options.name, 'download-artifact name'));
    }
  }
  return names;
}

function collectWorkflowFiles(): readonly string[] {
  return readdirSync(workflowRoot)
    .filter((filename) => filename.endsWith('.yml'))
    .sort()
    .map((filename) => path.join(workflowRoot, filename));
}

function findNoOpReceiptJob(workflow: RecordValue): [string, RecordValue] {
  const candidate = Object.entries(readWorkflowJobs(workflow)).find(([jobId, job]) => {
    if (!isRecord(job)) return false;
    return /no[- ]?op[\s\S]*coordination receipt|coordination receipt[\s\S]*no[- ]?op/iu.test(
      `${jobId} ${JSON.stringify(job)}`,
    );
  });
  if (!candidate || !isRecord(candidate[1])) {
    throw new Error('backend workflow is missing a no-op coordination receipt job');
  }
  return [candidate[0], candidate[1]];
}

function workflowJobText(jobId: string, job: RecordValue): string {
  return `${jobId} ${JSON.stringify(job)}`;
}

test('frontend workflows use one trigger-agnostic graph for automatic and manual promotion', () => {
  for (const target of frontendTargets) {
    const workflow = readWorkflow(target.filename);
    const triggers = readWorkflowTriggers(workflow);
    const workflowRun = requireRecord(triggers.workflow_run, `${target.filename} workflow_run`);
    const dispatch = requireRecord(
      triggers.workflow_dispatch,
      `${target.filename} workflow_dispatch`,
    );

    expect(workflow.name).toBe(target.workflowName);
    expect(workflowRun.workflows).toEqual([target.backendWorkflowName]);
    expect(workflowRun.types).toContain('completed');
    expect(workflowRun.branches).toEqual([target.branch]);
    expect(dispatch.inputs).toEqual(
      expect.objectContaining({
        source_sha: expect.any(Object),
        artifact_run_id: expect.any(Object),
        release_set_id: expect.any(Object),
        backend_receipt_run_id: expect.any(Object),
      }),
    );

    const jobIds = Object.keys(readWorkflowJobs(workflow));
    expect(jobIds.filter((jobId) => /^(auto|manual)_/u.test(jobId))).toEqual([]);

    const source = readWorkflowSource(target.filename);
    expect(source).toContain("github.event_name == 'workflow_run'");
    expect(source).toContain("github.event_name == 'workflow_dispatch'");
    expect(source).toContain('github.event.workflow_run');
    expect(source).toContain('inputs.source_sha');
  }
});

test('frontend workflows download only scoped frontend artifacts and their coordination receipt', () => {
  for (const target of frontendTargets) {
    const workflow = readWorkflow(target.filename);
    const downloadNames = collectArtifactDownloadNames(workflow);

    expect(downloadNames.length).toBeGreaterThan(0);
    expect(downloadNames.every((name) => !name.includes('*'))).toBe(true);
    expect(downloadNames.some((name) => name.includes('release-set'))).toBe(true);
    expect(downloadNames.some((name) => name.includes('pages'))).toBe(true);
    expect(downloadNames.some((name) => name.includes('signer-iframe'))).toBe(true);
    expect(downloadNames.some((name) => /receipt/iu.test(name))).toBe(true);
    for (const backendArtifact of [
      'gateway',
      'router',
      'deriver-a',
      'deriver-b',
      'signing-worker',
    ]) {
      expect(downloadNames.some((name) => name.endsWith(`-${backendArtifact}`))).toBe(false);
    }

    const source = readWorkflowSource(target.filename);
    expect(source).not.toContain('Download all release component artifacts');
  }
});

test('frontend workflows are terminal workflow_run deployment levels', () => {
  const frontendWorkflowNames = new Set(frontendTargets.map((target) => target.workflowName));

  for (const workflowPath of collectWorkflowFiles()) {
    const workflow = readWorkflow(path.basename(workflowPath));
    const workflowRun =
      workflow.on === undefined ? undefined : readWorkflowTriggers(workflow).workflow_run;
    if (!isRecord(workflowRun)) continue;

    const downstreamNames = requireArray(
      workflowRun.workflows,
      `${workflowPath} workflow_run workflows`,
    ).filter((name): name is string => typeof name === 'string');
    expect(downstreamNames.filter((name) => frontendWorkflowNames.has(name))).toEqual([]);
  }
});

test('backend and frontend deployment workflows have independent non-canceling concurrency', () => {
  const expected = [
    ['deploy-staging-cloudflare-stack.yml', 'deployment-staging-backend'],
    ['deploy-production-cloudflare-stack.yml', 'deployment-production-backend'],
    ['deploy-staging-frontend.yml', 'deployment-staging-frontend'],
    ['deploy-production-frontend.yml', 'deployment-production-frontend'],
  ] as const;

  for (const [filename, group] of expected) {
    const concurrency = requireRecord(
      readWorkflow(filename).concurrency,
      `${filename} concurrency`,
    );
    expect(concurrency.group).toBe(group);
    expect(concurrency['cancel-in-progress']).toBe(false);
  }
});

test('no-op backend receipt creation is bounded and has no mutation or build path', () => {
  for (const target of frontendTargets) {
    const backendFilename = target.backendWorkflowName.includes('staging')
      ? 'deploy-staging-cloudflare-stack.yml'
      : 'deploy-production-cloudflare-stack.yml';
    const [jobId, job] = findNoOpReceiptJob(readWorkflow(backendFilename));
    const text = workflowJobText(jobId, job);
    const timeoutMinutes = job['timeout-minutes'];

    expect(timeoutMinutes).toBe(1);
    expect(text).toMatch(/selected[_ -]components/iu);
    expect(text).toMatch(/gateway/iu);
    expect(text).toMatch(/router|deriver-a|deriver-b|signing-worker/iu);
    expect(text).not.toMatch(/pnpm\s+(?:install|build|exec)|cargo\s+(?:build|install)/iu);
    expect(text).not.toMatch(
      /wrangler\s+deploy|actions\/setup-node|pnpm\/action-setup|dtolnay\/rust-toolchain/iu,
    );
    expect(text).toContain('"retention-days":30');
    expect(text).toContain('actions/upload-artifact@v7');
  }
});
