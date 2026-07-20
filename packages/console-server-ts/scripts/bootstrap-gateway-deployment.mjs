import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { parseGatewayDeploymentPlan } from './gateway-deployment-config.mjs';

function main() {
  const options = parseArguments(process.argv.slice(2));
  const plan = parseGatewayDeploymentPlan(fs.readFileSync(options.plan, 'utf8'));
  const sql = buildBootstrapSql(plan);
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'seams-gateway-bootstrap-'), {
    encoding: 'utf8',
  });
  const sqlPath = path.join(temporaryDirectory, 'bootstrap.sql');
  try {
    fs.writeFileSync(sqlPath, sql, { mode: 0o600 });
    executeRemoteD1({
      databaseName: plan.consoleD1.name,
      wranglerConfig: options.wranglerConfig,
      sqlPath,
    });
  } finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
  process.stdout.write(
    `Seeded ${plan.target} tenant ${plan.d1Bootstrap.orgId}/${plan.d1Bootstrap.projectId}/${plan.d1Bootstrap.environmentId}\n`,
  );
}

function parseArguments(args) {
  let plan = '';
  let wranglerConfig = '';
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--plan') {
      plan = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    if (argument === '--wrangler-config') {
      wranglerConfig = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${argument}`);
  }
  if (!plan) throw new Error('--plan is required');
  if (!wranglerConfig) throw new Error('--wrangler-config is required');
  return {
    plan: path.resolve(process.cwd(), plan),
    wranglerConfig: path.resolve(process.cwd(), wranglerConfig),
  };
}

function requireArgumentValue(args, index, name) {
  const value = String(args[index + 1] || '').trim();
  if (!value) throw new Error(`${name} requires a value`);
  return value;
}

function buildBootstrapSql(plan) {
  const bootstrap = plan.d1Bootstrap;
  const nowMs = Date.now();
  const orgName = `${titleCaseTarget(plan.target)} Organization`;
  const projectName = `${titleCaseTarget(plan.target)} Project`;
  const environmentName = titleCaseTarget(bootstrap.environmentKey);
  const orgSlug = `seams-${plan.target}`;
  const projectSlug = `seams-${plan.target}-project`;
  const apiKeyId = deterministicApiKeyId(bootstrap);
  const secretHash = sha256ApiKeySecret(bootstrap.publishableKey);
  const keyPrefix = bootstrap.publishableKey.slice(0, 24);
  const secretPreview = `${bootstrap.publishableKey.slice(0, 10)}...`;
  const allowedOriginsJson = JSON.stringify(bootstrap.allowedOrigins);

  return [
    'PRAGMA foreign_keys = ON;',
    organizationUpsertSql({
      namespace: bootstrap.namespace,
      id: bootstrap.orgId,
      name: orgName,
      slug: orgSlug,
      nowMs,
    }),
    projectUpsertSql({
      namespace: bootstrap.namespace,
      id: bootstrap.projectId,
      orgId: bootstrap.orgId,
      name: projectName,
      slug: projectSlug,
      nowMs,
    }),
    environmentUpsertSql({
      namespace: bootstrap.namespace,
      id: bootstrap.environmentId,
      orgId: bootstrap.orgId,
      projectId: bootstrap.projectId,
      environmentKey: bootstrap.environmentKey,
      name: environmentName,
      nowMs,
    }),
    publishableKeyUpsertSql({
      namespace: bootstrap.namespace,
      orgId: bootstrap.orgId,
      id: apiKeyId,
      environmentId: bootstrap.environmentId,
      keyPrefix,
      allowedOriginsJson,
      secretHash,
      secretPreview,
      nowMs,
    }),
    verificationSql(bootstrap, apiKeyId, secretHash, allowedOriginsJson),
    '',
  ].join('\n');
}

function organizationUpsertSql(input) {
  return `INSERT INTO organizations
  (namespace, id, name, slug, created_by_user_id, status, created_at_ms, updated_at_ms)
VALUES
  (${sqlText(input.namespace)}, ${sqlText(input.id)}, ${sqlText(input.name)}, ${sqlText(input.slug)}, NULL, 'ACTIVE', ${input.nowMs}, ${input.nowMs})
ON CONFLICT DO NOTHING;`;
}

function projectUpsertSql(input) {
  return `INSERT INTO projects
  (namespace, id, org_id, name, slug, status, created_at_ms, updated_at_ms)
VALUES
  (${sqlText(input.namespace)}, ${sqlText(input.id)}, ${sqlText(input.orgId)}, ${sqlText(input.name)}, ${sqlText(input.slug)}, 'ACTIVE', ${input.nowMs}, ${input.nowMs})
ON CONFLICT DO NOTHING;`;
}

function environmentUpsertSql(input) {
  return `INSERT INTO environments
  (namespace, id, org_id, project_id, env_key, signing_root_version, name, status, created_at_ms, updated_at_ms)
VALUES
  (${sqlText(input.namespace)}, ${sqlText(input.id)}, ${sqlText(input.orgId)}, ${sqlText(input.projectId)}, ${sqlText(input.environmentKey)}, 'default', ${sqlText(input.name)}, 'ACTIVE', ${input.nowMs}, ${input.nowMs})
ON CONFLICT DO NOTHING;`;
}

function publishableKeyUpsertSql(input) {
  return `INSERT INTO api_keys
  (namespace, org_id, id, kind, name, environment_id, key_prefix,
   scopes_json, ip_allowlist_json, allowed_origins_json, rate_limit_bucket,
   quota_bucket, risk_policy_json, payment_policy_json, status, secret_hash,
   secret_version, secret_preview, last_used_at_ms, expires_at_ms,
   revoked_reason, endpoint_usage_counts_json, anomaly_flags_json,
   created_at_ms, updated_at_ms)
VALUES
  (${sqlText(input.namespace)}, ${sqlText(input.orgId)}, ${sqlText(input.id)}, 'publishable_key',
   'Deployment publishable key', ${sqlText(input.environmentId)}, ${sqlText(input.keyPrefix)},
   '[]', '[]', ${sqlText(input.allowedOriginsJson)}, 'default', 'default', '{}', '{}',
   'ACTIVE', ${sqlText(input.secretHash)}, 1, ${sqlText(input.secretPreview)}, NULL, NULL,
   NULL, '{}', '[]', ${input.nowMs}, ${input.nowMs})
ON CONFLICT DO NOTHING;`;
}

function verificationSql(bootstrap, apiKeyId, secretHash, allowedOriginsJson) {
  return `CREATE TEMP TABLE deployment_bootstrap_assert (
  value INTEGER NOT NULL CHECK (value = 1)
);
INSERT INTO deployment_bootstrap_assert VALUES (
  (SELECT COUNT(*) FROM organizations
   WHERE namespace = ${sqlText(bootstrap.namespace)}
     AND id = ${sqlText(bootstrap.orgId)}
     AND status = 'ACTIVE')
);
INSERT INTO deployment_bootstrap_assert VALUES (
  (SELECT COUNT(*) FROM projects
   WHERE namespace = ${sqlText(bootstrap.namespace)}
     AND id = ${sqlText(bootstrap.projectId)}
     AND org_id = ${sqlText(bootstrap.orgId)}
     AND status = 'ACTIVE')
);
INSERT INTO deployment_bootstrap_assert VALUES (
  (SELECT COUNT(*) FROM environments
   WHERE namespace = ${sqlText(bootstrap.namespace)}
     AND id = ${sqlText(bootstrap.environmentId)}
     AND project_id = ${sqlText(bootstrap.projectId)}
     AND env_key = ${sqlText(bootstrap.environmentKey)}
     AND status = 'ACTIVE')
);
INSERT INTO deployment_bootstrap_assert VALUES (
  (SELECT COUNT(*) FROM api_keys
   WHERE namespace = ${sqlText(bootstrap.namespace)}
     AND org_id = ${sqlText(bootstrap.orgId)}
     AND id = ${sqlText(apiKeyId)}
     AND environment_id = ${sqlText(bootstrap.environmentId)}
     AND kind = 'publishable_key'
     AND status = 'ACTIVE'
     AND secret_hash = ${sqlText(secretHash)}
     AND allowed_origins_json = ${sqlText(allowedOriginsJson)})
);
DROP TABLE deployment_bootstrap_assert;`;
}

function executeRemoteD1(input) {
  const child = spawnSync(
    'pnpm',
    [
      'exec',
      'wrangler',
      'd1',
      'execute',
      input.databaseName,
      '--remote',
      '--yes',
      '--file',
      input.sqlPath,
      '--config',
      input.wranglerConfig,
    ],
    {
      cwd: process.cwd(),
      env: process.env,
      encoding: 'utf8',
      stdio: ['ignore', 'inherit', 'inherit'],
    },
  );
  if (child.error) throw child.error;
  if (child.status !== 0) {
    throw new Error(`wrangler d1 execute failed with status ${child.status}`);
  }
}

function deterministicApiKeyId(bootstrap) {
  const identity = [
    bootstrap.namespace,
    bootstrap.orgId,
    bootstrap.projectId,
    bootstrap.environmentId,
  ].join('\0');
  return `ak_bootstrap_${createHash('sha256').update(identity).digest('hex').slice(0, 20)}`;
}

function sha256ApiKeySecret(secret) {
  return `sha256:${createHash('sha256').update(secret, 'utf8').digest('hex')}`;
}

function sqlText(value) {
  if (/[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error('SQL text values must not contain control characters');
  }
  return `'${value.replaceAll("'", "''")}'`;
}

function titleCaseTarget(value) {
  return `${value.charAt(0).toUpperCase()}${value.slice(1)}`;
}

main();
