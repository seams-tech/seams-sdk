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
const gatewayCutoverWorkerVarNames = [
  'ROUTER_AB_YAO_GATEWAY_REGISTRATION_ADMISSION_CUTOFF_MS',
  'ROUTER_AB_YAO_GATEWAY_REGISTRATION_DRAIN_UNTIL_MS',
  'ROUTER_AB_YAO_GATEWAY_RECOVERY_ADMISSION_CUTOFF_MS',
  'ROUTER_AB_YAO_GATEWAY_RECOVERY_DRAIN_UNTIL_MS',
  'ROUTER_AB_YAO_GATEWAY_EXPORT_ADMISSION_CUTOFF_MS',
  'ROUTER_AB_YAO_GATEWAY_EXPORT_DRAIN_UNTIL_MS',
] as const;

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
    'build',
    'preflight',
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

test('backend preflight validates one custody environment from JSON inventories', () => {
  const secretValue = 'inventory-secret-value';
  const result = runCommand(
    backendScript,
    ['preflight', '--target', 'staging', '--component', 'signing-worker'],
    {
      ...environmentWithoutDeploymentSecrets(),
      DEPLOYMENT_SECRETS_JSON: JSON.stringify({
        CLOUDFLARE_API_TOKEN: secretValue,
        CLOUDFLARE_ACCOUNT_ID: secretValue,
        ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: secretValue,
        SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY: secretValue,
      }),
      DEPLOYMENT_VARS_JSON: JSON.stringify({
        ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: 'inventory-public-value',
      }),
    },
  );

  expect(result.status).toBe(0);
  expect(result.stdout).toContain('Preflight passed: staging/signing-worker');
  expect(`${result.stdout}${result.stderr}`).not.toContain(secretValue);
});

test('backend preflight rejects a missing required secret without printing values', () => {
  const secretValue = 'inventory-secret-value';
  const result = runCommand(
    backendScript,
    ['preflight', '--target', 'staging', '--component', 'signing-worker'],
    {
      ...environmentWithoutDeploymentSecrets(),
      DEPLOYMENT_SECRETS_JSON: JSON.stringify({
        CLOUDFLARE_API_TOKEN: secretValue,
        CLOUDFLARE_ACCOUNT_ID: secretValue,
        ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: secretValue,
      }),
      DEPLOYMENT_VARS_JSON: JSON.stringify({
        ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: 'inventory-public-value',
      }),
    },
  );

  expectFailure(result, /SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY is required/u);
  expect(`${result.stdout}${result.stderr}`).not.toContain(secretValue);
});

test('Gateway preflight rejects an incomplete family cutover window', () => {
  const result = runCommand(
    backendScript,
    ['preflight', '--target', 'staging', '--component', 'gateway'],
    {
      ...environmentWithoutDeploymentSecrets(),
      DEPLOYMENT_SECRETS_JSON: '{}',
      DEPLOYMENT_VARS_JSON: JSON.stringify({
        ROUTER_AB_YAO_GATEWAY_REGISTRATION_ADMISSION_CUTOFF_MS: '1000',
      }),
    },
  );

  expectFailure(result, /must be set together/u);
});

test('Gateway preflight rejects capability consumer cutovers before recovery drains', () => {
  const result = runCommand(
    backendScript,
    ['preflight', '--target', 'production', '--component', 'gateway'],
    {
      ...environmentWithoutDeploymentSecrets(),
      DEPLOYMENT_SECRETS_JSON: '{}',
      DEPLOYMENT_VARS_JSON: JSON.stringify({
        ROUTER_AB_YAO_GATEWAY_RECOVERY_ADMISSION_CUTOFF_MS: '1000',
        ROUTER_AB_YAO_GATEWAY_RECOVERY_DRAIN_UNTIL_MS: '3000',
        ROUTER_AB_YAO_GATEWAY_EXPORT_ADMISSION_CUTOFF_MS: '1500',
        ROUTER_AB_YAO_GATEWAY_EXPORT_DRAIN_UNTIL_MS: '2000',
      }),
    },
  );

  expectFailure(result, /RECOVERY must finish draining no later than EXPORT/u);
});

test('Gateway preflight rejects an obsolete tenant-wide cutover window', () => {
  const result = runCommand(
    backendScript,
    ['preflight', '--target', 'production', '--component', 'gateway'],
    {
      ...environmentWithoutDeploymentSecrets(),
      DEPLOYMENT_SECRETS_JSON: '{}',
      DEPLOYMENT_VARS_JSON: JSON.stringify({
        ROUTER_AB_YAO_GATEWAY_ADMISSION_CUTOFF_MS: '',
      }),
    },
  );

  expectFailure(result, /is obsolete/u);
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

test('backend workflows deploy independent workers concurrently before router', () => {
  const workflowOrder = [
    'build',
    'preflight',
    'migrate',
    'deploy_signing_worker',
    'deploy_deriver_a',
    'deploy_deriver_b',
    'deploy_router',
    'deploy_gateway',
  ];
  const planLabels = [
    'build',
    'preflight',
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
      jobs: Record<
        string,
        { needs?: string | readonly string[]; env?: Readonly<Record<string, string>> }
      >;
    };
    const needsOf = (jobName: string): readonly string[] => {
      const job = workflow.jobs[jobName];
      expect(job, `missing workflow job ${jobName}`).toBeTruthy();
      return Array.isArray(job.needs) ? job.needs : job.needs ? [job.needs] : [];
    };

    expect(Object.keys(workflow.jobs)).toEqual(workflowOrder);
    expect(needsOf('build')).toEqual([]);
    expect(needsOf('preflight')).toContain('build');
    expect(needsOf('migrate')).toEqual(expect.arrayContaining(['preflight', 'build']));
    expect(needsOf('deploy_signing_worker')).toEqual(['migrate']);
    expect(needsOf('deploy_deriver_a')).toEqual(['migrate']);
    expect(needsOf('deploy_deriver_b')).toEqual(['migrate']);
    expect(needsOf('deploy_router')).toEqual([
      'deploy_signing_worker',
      'deploy_deriver_a',
      'deploy_deriver_b',
    ]);
    expect(needsOf('deploy_gateway')).toEqual(['deploy_router']);
    for (const jobName of ['migrate', 'deploy_gateway']) {
      const environment = workflow.jobs[jobName]?.env;
      expect(environment, `${target}/${jobName} is missing its environment`).toBeTruthy();
      for (const name of gatewayCutoverWorkerVarNames) {
        expect(environment?.[name]).toBe(`\${{ vars.${name} }}`);
      }
    }
  }
});

test('frontend workflows contain one environment-bound deployment job', () => {
  for (const target of ['staging', 'production']) {
    const workflow = parseYaml(
      readFileSync(path.join(repoRoot, `.github/workflows/deploy-${target}-frontend.yml`), 'utf8'),
    ) as {
      jobs: Record<string, { environment?: string }>;
    };

    expect(Object.keys(workflow.jobs)).toEqual(['deploy']);
    expect(workflow.jobs.deploy.environment).toBe(target);
  }
});
