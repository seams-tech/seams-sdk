import { expect, test } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { assertExpectedWorkerServices } from '../../scripts/deploy-backend.mjs';

type CommandResult = {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const backendScript = path.join(repoRoot, 'scripts/deploy-backend.mjs');
const frontendScript = path.join(repoRoot, 'scripts/deploy-frontend.mjs');
const environmentGeneratorScript = path.join(
  repoRoot,
  'crates/router-ab-cloudflare/scripts/generate-github-env-values.mjs',
);
const deploymentSecretNames = [
  'STRIPE_API_SK',
  'RELAYER_PRIVATE_KEY',
  'SPONSORED_EVM_EXECUTORS_JSON',
  'SIGNING_SESSION_SEAL_ROOT_SECRET_B64U',
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
    ['plan', '--lane', 'staging-testnet'],
    environmentWithoutDeploymentSecrets(),
  );

  expect(result.status).toBe(0);
  expect(result.stdout).toContain('Backend deployment plan: staging-testnet');
  expect(result.stdout).toContain('Release: staging');
  expect(result.stdout).toContain('Network: testnet');
  expect(result.stdout).toContain('Runtime profile: testnet_live_demo');
  expect(result.stdout).toContain('Gateway origin: https://staging.api.seams.sh');
  expect(result.stdout).toContain('Wallet origin: https://staging.sign.seams.sh');
  expect(result.stdout).not.toContain('plan-secret-value');
  expect(result.stdout).not.toContain('bootstrap Gateway tenant');
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

test('production-mainnet plan reports pending provisioning and blocks operations', () => {
  const plan = runCommand(
    backendScript,
    ['plan', '--lane', 'production-mainnet'],
    environmentWithoutDeploymentSecrets(),
  );

  expect(plan.status).toBe(0);
  expect(plan.stdout).toContain('Backend deployment plan: production-mainnet');
  expect(plan.stdout).toContain('Provisioning: pending');
  expect(plan.stdout).toContain('Runtime profile: mainnet_service');
  expect(plan.stdout).toContain('Required values:');

  const preflight = runCommand(
    backendScript,
    ['preflight', '--lane', 'production-mainnet', '--component', 'gateway'],
    environmentWithoutDeploymentSecrets(),
  );
  expectFailure(preflight, /pending provisioning/u);
  expect(`${preflight.stdout}${preflight.stderr}`).not.toContain(
    'CLOUDFLARE_API_TOKEN is required',
  );
});

test('environment generation lets a pending production lane reach resource discovery', () => {
  const result = runCommand(
    environmentGeneratorScript,
    ['--lane', 'production-mainnet', '--json'],
    {
      ...environmentWithoutDeploymentSecrets(),
      GATEWAY_RUNTIME_PROFILE: 'mainnet_service',
    },
  );

  expectFailure(result, /resources\.consoleD1\.id has an invalid format/u);
  expect(`${result.stdout}\n${result.stderr}`).not.toContain('pending provisioning');
});

test('production-shaped project policy uses the canonical Seams environment id', () => {
  const source = readFileSync(environmentGeneratorScript, 'utf8');
  const policyBuilder = source.match(
    /function buildProjectPolicy\(configuration\) \{[\s\S]*?\n\}/u,
  )?.[0];
  const registrationValidator = source.match(
    /function validateGatewayRegistrationDocuments\(outputDocument\) \{[\s\S]*?\n\}/u,
  )?.[0];

  expect(policyBuilder).toBeTruthy();
  expect(registrationValidator).toBeTruthy();
  expect(source).toContain("'SEAMS_ENV_ID'");
  expect(policyBuilder).toContain('environment: configuration.environmentId,');
  expect(policyBuilder).not.toContain('environment: targetName,');
  expect(registrationValidator).toMatch(
    /policy\.environment,\s*deploymentConfig\.tenant\.environmentId,/u,
  );

  const lanePrefix = 'production';
  const seamsEnvironmentId = 'seams-production-mainnet';
  expect(seamsEnvironmentId).not.toBe(lanePrefix);
});

test('frontend plan runs without deployment secrets', () => {
  const result = runCommand(
    frontendScript,
    ['plan', '--site', 'staging'],
    environmentWithoutDeploymentSecrets(),
  );

  expect(result.status).toBe(0);
  expectOrdered(result.stdout, ['build', 'deploy', 'smoke']);
});

test('backend commands reject missing, unknown, and misplaced arguments', () => {
  expectFailure(runCommand(backendScript, []), /usage:.*deploy-backend/u);
  expectFailure(runCommand(backendScript, ['unknown', '--lane', 'staging-testnet']), /usage:/u);
  expectFailure(runCommand(backendScript, ['plan']), /--lane.*required/u);
  expectFailure(runCommand(backendScript, ['plan', '--target', 'staging']), /usage:/u);
  expectFailure(runCommand(backendScript, ['plan', '--lane', 'production']), /lane/u);
  expectFailure(
    runCommand(backendScript, ['plan', '--lane', 'staging-testnet', '--component', 'gateway']),
    /--component.*not allowed|unexpected.*component/u,
  );
  expectFailure(
    runCommand(backendScript, ['preflight', '--lane', 'staging-testnet']),
    /--component.*required/u,
  );
  expectFailure(
    runCommand(backendScript, ['preflight', '--lane', 'staging-testnet', '--component', 'unknown']),
    /unknown component/u,
  );
  expectFailure(
    runCommand(backendScript, ['deploy', '--lane', 'staging-testnet', '--component', 'frontend']),
    /unknown component|backend component/u,
  );
});

test('backend commands reject a lane branch mismatch before deployment work', () => {
  const result = runCommand(backendScript, ['smoke', '--lane', 'staging-testnet'], {
    ...environmentWithoutDeploymentSecrets(),
    GITHUB_REF: 'refs/heads/main',
  });

  expectFailure(result, /lane staging-testnet requires branch dev/u);
});

test('backend preflight validates one custody environment from JSON inventories', () => {
  const secretValue = 'inventory-secret-value';
  const result = runCommand(
    backendScript,
    ['preflight', '--lane', 'staging-testnet', '--component', 'signing-worker'],
    {
      ...environmentWithoutDeploymentSecrets(),
      DEPLOYMENT_SECRETS_JSON: JSON.stringify({
        CLOUDFLARE_API_TOKEN: secretValue,
        CLOUDFLARE_ACCOUNT_ID: secretValue,
        ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: secretValue,
        SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY: secretValue,
        SIGNING_WORKER_PRIVATE_D1_KEK: secretValue,
      }),
      DEPLOYMENT_VARS_JSON: JSON.stringify({
        ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: 'inventory-public-value',
        ROUTER_AB_SIGNING_WORKER_PRIVATE_D1_ID: 'inventory-database-id',
        ROUTER_AB_SIGNING_WORKER_PRIVATE_D1_KEK_PUBLIC_KEY: 'inventory-kek-public-key',
        ROUTER_AB_SIGNING_WORKER_PRIVATE_D1_KEK_VERSION: 'inventory-kek-version',
      }),
    },
  );

  expect(result.status).toBe(0);
  expect(result.stdout).toContain('Preflight passed: staging-testnet/signing-worker');
  expect(`${result.stdout}${result.stderr}`).not.toContain(secretValue);
});

test('backend preflight rejects a missing required secret without printing values', () => {
  const secretValue = 'inventory-secret-value';
  const result = runCommand(
    backendScript,
    ['preflight', '--lane', 'staging-testnet', '--component', 'signing-worker'],
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

test('backend service binding validation rejects a wrong service hidden by a later block', () => {
  const lane = {
    id: 'production-testnet',
    resources: {
      deriverA: { workerName: 'router-ab-deriver-a-testnet' },
      deriverB: { workerName: 'router-ab-deriver-b-testnet' },
      signingWorker: { workerName: 'router-ab-signing-worker-testnet' },
    },
  };
  const section = `
[[env.production-testnet.services]]
binding = "DERIVER_B"
service = "router-ab-deriver-a-testnet"

[[env.production-testnet.services]]
binding = "UNRELATED"
service = "router-ab-deriver-b-testnet"
`;

  expect(() => assertExpectedWorkerServices(lane, 'deriver-a', section)).toThrow(
    /production-testnet\/deriver-a must bind DERIVER_B to router-ab-deriver-b-testnet/u,
  );
});

test('frontend commands reject backend-only operations and extra component arguments', () => {
  expectFailure(runCommand(frontendScript, ['migrate', '--site', 'staging']), /usage:/u);
  expectFailure(runCommand(frontendScript, ['plan']), /--site.*required/u);
  expectFailure(
    runCommand(frontendScript, ['plan', '--site', 'staging', '--component', 'gateway']),
    /--component.*not allowed|unexpected.*component/u,
  );
  expectFailure(runCommand(frontendScript, ['plan', '--site', 'development']), /site/u);
});

test('frontend commands reject a site branch mismatch before deployment work', () => {
  const result = runCommand(frontendScript, ['smoke', '--site', 'staging'], {
    ...environmentWithoutDeploymentSecrets(),
    GITHUB_REF: 'refs/heads/main',
  });

  expectFailure(result, /site staging requires branch dev/u);
});

test('frontend commands reject a site with pending lane provisioning before branch checks', () => {
  const result = runCommand(frontendScript, ['smoke', '--site', 'production'], {
    ...environmentWithoutDeploymentSecrets(),
    GITHUB_REF: 'refs/heads/dev',
  });

  expectFailure(result, /pending lane provisioning.*production-mainnet/u);
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

  const lanes = [
    { id: 'staging-testnet', workflow: 'deploy-staging-backend.yml' },
    { id: 'production-testnet', workflow: 'deploy-production-testnet-backend.yml' },
    { id: 'production-mainnet', workflow: 'deploy-production-mainnet-backend.yml' },
  ] as const;

  for (const lane of lanes) {
    const result = runCommand(
      backendScript,
      ['plan', '--lane', lane.id],
      environmentWithoutDeploymentSecrets(),
    );
    expect(result.status).toBe(0);
    expectOrdered(result.stdout, planLabels);

    const workflowSource = readFileSync(
      path.join(repoRoot, `.github/workflows/${lane.workflow}`),
      'utf8',
    );
    const workflow = parseYaml(workflowSource) as {
      env?: Readonly<Record<string, string>>;
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
    expect(workflow.env?.DEPLOY_LANE).toBe(lane.id);
    expect(workflowSource).toContain(`--lane "$DEPLOY_LANE"`);
    expect(workflowSource).not.toContain('--target');
    expect(workflowSource).toContain(
      `test "$GITHUB_REF" = refs/heads/${lane.id === 'staging-testnet' ? 'dev' : 'main'}`,
    );
    const custodyPrefix =
      lane.id === 'staging-testnet'
        ? 'staging-'
        : lane.id === 'production-testnet'
          ? 'production-testnet-'
          : 'production-';
    for (const component of ['signing-worker', 'deriver-a', 'deriver-b', 'mpc-router', 'gateway']) {
      expect(workflowSource).toContain(`${custodyPrefix}${component}`);
    }
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
  }

  expect(existsSync(path.join(repoRoot, '.github/workflows/deploy-production-backend.yml'))).toBe(
    false,
  );
});

test('frontend workflows contain one environment-bound deployment job', () => {
  for (const site of ['staging', 'production']) {
    const workflowSource = readFileSync(
      path.join(repoRoot, `.github/workflows/deploy-${site}-frontend.yml`),
      'utf8',
    );
    const workflow = parseYaml(workflowSource) as {
      env?: Readonly<Record<string, string>>;
      jobs: Record<string, { environment?: string }>;
    };

    expect(Object.keys(workflow.jobs)).toEqual(['deploy']);
    expect(workflow.jobs.deploy.environment).toBe(site);
    expect(workflow.env?.DEPLOY_SITE).toBe(site);
    expect(workflowSource).toContain('--site "$DEPLOY_SITE"');
    expect(workflowSource).not.toContain('--target');
    if (site === 'staging') {
      expect(workflowSource).toContain('CF_PAGES_PROJECT_WALLET:');
      expect(workflowSource).not.toContain('CF_PAGES_PROJECT_WALLET_TESTNET:');
    } else {
      expect(workflowSource).toContain('CF_PAGES_PROJECT_WALLET_TESTNET:');
      expect(workflowSource).toContain('CF_PAGES_PROJECT_WALLET_MAINNET:');
    }
  }
});
