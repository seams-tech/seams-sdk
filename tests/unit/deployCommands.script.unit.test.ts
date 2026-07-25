import { expect, test } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';

type CommandResult = {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const backendScript = path.join(repoRoot, 'scripts/deploy-backend.mjs');
const frontendScript = path.join(repoRoot, 'scripts/deploy-frontend.mjs');
const deploymentSecretNames = [
  'STRIPE_API_SK',
  'RELAYER_PRIVATE_KEY',
  'SPONSORED_EVM_EXECUTORS_JSON',
  'SIGNING_SESSION_SEAL_KEY_VERSION',
  'SIGNING_SESSION_SHAMIR_P_B64U',
  'SIGNING_SESSION_SEAL_E_S_B64U',
  'SIGNING_SESSION_SEAL_D_S_B64U',
];

function runCommand(
  script: string,
  args: readonly string[],
  env?: NodeJS.ProcessEnv,
): CommandResult {
  const result = spawnSync(process.execPath, [script, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    env,
  });
  return {
    status: result.status,
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
  };
}

function environmentWithoutDeploymentSecrets(): NodeJS.ProcessEnv {
  const env = { ...process.env };
  for (const name of deploymentSecretNames) delete env[name];
  return env;
}

function expectFailure(result: CommandResult, message: RegExp): void {
  expect(result.status).not.toBe(0);
  expect(`${result.stdout}\n${result.stderr}`).toMatch(message);
}

function expectOrdered(output: string, labels: readonly string[]): void {
  const orderStart = output.indexOf('\nOrder:\n');
  expect(orderStart, 'plan is missing an Order section').toBeGreaterThanOrEqual(0);
  const order = output.slice(orderStart);
  let previousIndex = -1;
  for (const label of labels) {
    const index = order.indexOf(label);
    expect(index, `missing plan step ${label}`).toBeGreaterThanOrEqual(0);
    expect(index, `plan step ${label} is out of order`).toBeGreaterThan(previousIndex);
    previousIndex = index;
  }
}

test('backend plan runs without deployment secrets and prints the complete lane order', () => {
  const result = runCommand(
    backendScript,
    ['plan', '--target', 'staging'],
    environmentWithoutDeploymentSecrets(),
  );

  expect(result.status).toBe(0);
  expect(result.stdout).not.toContain('plan-secret-value');
  expectOrdered(result.stdout, [
    'preflight',
    'build',
    'migrate',
    'signing-worker',
    'deriver-a',
    'deriver-b',
    'router',
    'gateway',
    'smoke',
  ]);
});

test('frontend plan runs without deployment secrets', () => {
  const result = runCommand(
    frontendScript,
    ['plan', '--target', 'staging'],
    environmentWithoutDeploymentSecrets(),
  );

  expect(result.status).toBe(0);
  expectOrdered(result.stdout, ['build', 'deploy', 'smoke']);
});

test('backend commands reject missing, unknown, and misplaced arguments', () => {
  expectFailure(runCommand(backendScript, []), /usage:.*deploy-backend/u);
  expectFailure(runCommand(backendScript, ['unknown', '--target', 'staging']), /usage:/u);
  expectFailure(runCommand(backendScript, ['plan']), /--target.*required/u);
  expectFailure(
    runCommand(backendScript, ['plan', '--target', 'staging', '--component', 'gateway']),
    /--component.*not allowed|unexpected.*component/u,
  );
  expectFailure(
    runCommand(backendScript, ['preflight', '--target', 'staging']),
    /--component.*required/u,
  );
  expectFailure(
    runCommand(backendScript, ['preflight', '--target', 'staging', '--component', 'unknown']),
    /unknown component/u,
  );
  expectFailure(
    runCommand(backendScript, ['deploy', '--target', 'staging', '--component', 'frontend']),
    /unknown component|backend component/u,
  );
});

test('frontend commands reject backend-only operations and extra component arguments', () => {
  expectFailure(runCommand(frontendScript, ['migrate', '--target', 'staging']), /usage:/u);
  expectFailure(runCommand(frontendScript, ['plan']), /--target.*required/u);
  expectFailure(
    runCommand(frontendScript, ['plan', '--target', 'staging', '--component', 'gateway']),
    /--component.*not allowed|unexpected.*component/u,
  );
  expectFailure(runCommand(frontendScript, ['plan', '--target', 'development']), /target/u);
});

test('backend workflow needs chain matches the backend command plan', () => {
  const workflowOrder = [
    'preflight',
    'build',
    'migrate',
    'deploy_signing_worker',
    'deploy_deriver_a',
    'deploy_deriver_b',
    'deploy_router',
    'deploy_gateway',
    'smoke',
  ];
  const planLabels = [
    'preflight',
    'build',
    'migrate',
    'signing-worker',
    'deriver-a',
    'deriver-b',
    'router',
    'gateway',
    'smoke',
  ];

  for (const target of ['staging', 'production']) {
    const result = runCommand(
      backendScript,
      ['plan', '--target', target],
      environmentWithoutDeploymentSecrets(),
    );
    expect(result.status).toBe(0);
    expectOrdered(result.stdout, planLabels);

    const workflow = parseYaml(
      readFileSync(path.join(repoRoot, `.github/workflows/deploy-${target}-backend.yml`), 'utf8'),
    ) as {
      jobs: Record<string, { needs?: string | readonly string[] }>;
    };
    const needsOf = (jobName: string): readonly string[] => {
      const job = workflow.jobs[jobName];
      expect(job, `missing workflow job ${jobName}`).toBeTruthy();
      return Array.isArray(job.needs) ? job.needs : job.needs ? [job.needs] : [];
    };

    expect(needsOf('preflight')).toContain('branch_guard');
    expect(needsOf('build')).toContain('branch_guard');
    expect(needsOf('migrate')).toEqual(expect.arrayContaining(['preflight', 'build']));
    for (let index = 3; index < workflowOrder.length; index += 1) {
      expect(needsOf(workflowOrder[index])).toContain(workflowOrder[index - 1]);
    }
  }
});
