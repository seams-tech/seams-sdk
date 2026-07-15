import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const argv = process.argv.slice(2).filter((arg) => arg !== '--');
const json = argv.includes('--json');
const envNames = readEnvironmentNames();
const scriptDir = dirname(fileURLToPath(import.meta.url));

if (argv.includes('--help')) {
  console.log(`Usage:
  pnpm router:deploy:env-keygen
  pnpm router:deploy:env-keygen -- --env staging
  pnpm router:deploy:env-keygen -- --env staging --json

Without --env, this generates the split staging GitHub Environment values.
Production generation remains unavailable until Phase 6A selects the strict
security and deployment profile.

Each output block is self-contained and includes every variable/secret that the
GitHub Environment must define. Manual placeholders are included for Cloudflare
API credentials. Router JWT issuer/JWKS values assume staging.seams.sh and seams.sh.`);
  process.exit(0);
}

const output = {
  generatedAt: new Date().toISOString(),
  environments: Object.fromEntries(envNames.flatMap(generateEnvironmentEntries)),
};

if (json) {
  console.log(JSON.stringify(output, null, 2));
} else {
  printHumanOutput(output);
}

function generateEnvironmentEntries(envName) {
  const deployment = runJsonScript('generate-deployment-keys.mjs', [
    '--env',
    envName,
    '--show-secrets',
    '--json',
  ]);
  const rootShares = runJsonScript('generate-root-share-keys.mjs', ['--json']);
  const internalServiceAuthSecret = generateInternalServiceAuthSecret();

  return [
    buildRouterEnvironment(envName, deployment, internalServiceAuthSecret),
    buildDeriverAEnvironment(envName, deployment, rootShares, internalServiceAuthSecret),
    buildDeriverBEnvironment(envName, deployment, rootShares, internalServiceAuthSecret),
    buildSigningWorkerEnvironment(envName, deployment, internalServiceAuthSecret),
  ];
}

function buildRouterEnvironment(envName, deployment, internalServiceAuthSecret) {
  return [
    `${envName}-router`,
    {
      variables: {
        ROUTER_AB_JWT_ISSUER: routerJwtIssuerForEnv(envName),
        ROUTER_AB_JWT_AUDIENCE: `router-ab:${envName}`,
        ROUTER_AB_JWT_JWKS_URL: `${routerJwtIssuerForEnv(envName)}/.well-known/router-ab/jwks.json`,
        ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY:
          deployment.variables.ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY,
        ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY:
          deployment.variables.ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY,
        ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY:
          deployment.variables.ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
        ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX:
          deployment.variables.ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX,
        ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX:
          deployment.variables.ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX,
      },
      secrets: buildBaseSecrets(internalServiceAuthSecret),
    },
  ];
}

function buildDeriverAEnvironment(envName, deployment, rootShares, internalServiceAuthSecret) {
  return [
    `${envName}-deriver-a`,
    {
      variables: {
        ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY:
          deployment.variables.ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY,
        ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX:
          deployment.variables.ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX,
        ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX:
          deployment.variables.ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX,
      },
      secrets: {
        ...buildBaseSecrets(internalServiceAuthSecret),
        DERIVER_A_ROOT_SHARE_WIRE_SECRET:
          rootShares.secrets.account1DeriverA.DERIVER_A_ROOT_SHARE_WIRE_SECRET,
        DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY: deployment.secrets.DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY,
        DERIVER_A_PEER_SIGNING_KEY: deployment.secrets.DERIVER_A_PEER_SIGNING_KEY,
      },
    },
  ];
}

function buildDeriverBEnvironment(envName, deployment, rootShares, internalServiceAuthSecret) {
  return [
    `${envName}-deriver-b`,
    {
      variables: {
        ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY:
          deployment.variables.ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY,
        ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX:
          deployment.variables.ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX,
        ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX:
          deployment.variables.ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX,
      },
      secrets: {
        ...buildBaseSecrets(internalServiceAuthSecret),
        DERIVER_B_ROOT_SHARE_WIRE_SECRET:
          rootShares.secrets.account2DeriverB.DERIVER_B_ROOT_SHARE_WIRE_SECRET,
        DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY: deployment.secrets.DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY,
        DERIVER_B_PEER_SIGNING_KEY: deployment.secrets.DERIVER_B_PEER_SIGNING_KEY,
      },
    },
  ];
}

function buildSigningWorkerEnvironment(envName, deployment, internalServiceAuthSecret) {
  return [
    `${envName}-signing-worker`,
    {
      variables: {
        ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY:
          deployment.variables.ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
      },
      secrets: {
        ...buildBaseSecrets(internalServiceAuthSecret),
        SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY:
          deployment.secrets.SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY,
      },
    },
  ];
}

function buildBaseSecrets(internalServiceAuthSecret) {
  return {
    CLOUDFLARE_ACCOUNT_ID: '<manual:cloudflare-account-id>',
    CLOUDFLARE_API_TOKEN: '<manual:cloudflare-api-token>',
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: internalServiceAuthSecret,
  };
}

function runJsonScript(scriptName, args) {
  const scriptPath = join(scriptDir, scriptName);
  const child = spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: resolve(scriptDir, '../../..'),
    encoding: 'utf8',
  });
  if (child.status !== 0) {
    process.stderr.write(child.stderr || child.stdout || `${scriptName} failed\n`);
    process.exit(child.status ?? 1);
  }
  return JSON.parse(child.stdout);
}

function generateInternalServiceAuthSecret() {
  return `router-ab-internal-service-auth-v1:${randomBytes(32).toString('base64url')}`;
}

function routerJwtIssuerForEnv(envName) {
  switch (envName) {
    case 'staging':
      return 'https://staging.seams.sh';
    default:
      return `https://${envName}.seams.sh`;
  }
}

function printHumanOutput(data) {
  console.log('Router A/B split GitHub Environment values');
  console.log(`Generated at: ${data.generatedAt}`);

  for (const [environmentName, environment] of Object.entries(data.environments)) {
    console.log(`\n[${environmentName}] variables`);
    printAssignments(environment.variables);
    console.log(`\n[${environmentName}] secrets`);
    printAssignments(environment.secrets);
  }
}

function printAssignments(values) {
  for (const [name, value] of Object.entries(values)) {
    console.log(`${name}=${value}`);
  }
}

function readEnvironmentNames() {
  const envName = readOption('--env');
  if (envName && envName !== 'staging') {
    throw new Error('only the staging deployment environment is available before Phase 6A');
  }
  return ['staging'];
}

function readOption(name) {
  const index = argv.indexOf(name);
  if (index === -1) {
    return undefined;
  }
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}
