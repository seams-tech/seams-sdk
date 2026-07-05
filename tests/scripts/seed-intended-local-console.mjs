#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import dotenv from 'dotenv';

import {
  defaultEnvFile,
  firstNonEmptyString,
  readEnvFile,
  repoRoot,
  resolveRepoPath,
  updateEnvFile,
} from './intended-google-oidc-env.mjs';

const envFilePath = resolveRepoPath(defaultEnvFile);
dotenv.config({ path: envFilePath, override: true });

const envFile = readEnvFile(envFilePath);
const seedConfig = resolveSeedConfig(envFile);
const d1LocalPersistPath =
  process.env.SEAMS_D1_LOCAL_PERSIST_TO || '.wrangler/state/seams-d1';
const d1LocalWranglerConfig =
  process.env.SEAMS_D1_LOCAL_WRANGLER_CONFIG || 'wrangler.d1-local.toml';

updateEnvFile(envFilePath, {
  SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID: seedConfig.environmentId,
  SEAMS_INTENDED_PUBLISHABLE_KEY: seedConfig.publishableKey,
  SEAMS_TENANT_STORAGE_NAMESPACE: seedConfig.namespace,
});

runWranglerSeed(seedConfig);

console.log(
  [
    '[intended-local-console] seeded',
    `namespace=${seedConfig.namespace}`,
    `org=${seedConfig.orgId}`,
    `project=${seedConfig.projectId}`,
    `environment=${seedConfig.environmentId}`,
    `publishableKeyPrefix=${seedConfig.keyPrefix}`,
  ].join(' '),
);

function resolveSeedConfig(localEnv) {
  const appOrigin = originFromUrl(
    firstNonEmptyString([
      process.env.SEAMS_INTENDED_APP_URL,
      localEnv.SEAMS_INTENDED_APP_URL,
      'https://localhost',
    ]),
  );
  const walletOrigin = originFromUrl(
    firstNonEmptyString([
      process.env.SEAMS_INTENDED_WALLET_ORIGIN,
      localEnv.SEAMS_INTENDED_WALLET_ORIGIN,
      'https://localhost:8443',
    ]),
  );
  const docsOrigin = originFromUrl(
    firstNonEmptyString([
      process.env.SEAMS_INTENDED_DOCS_ORIGIN,
      localEnv.SEAMS_INTENDED_DOCS_ORIGIN,
      'https://docs.localhost',
    ]),
  );
  const publishableKey = firstNonEmptyString([
    process.env.SEAMS_INTENDED_PUBLISHABLE_KEY,
    localEnv.SEAMS_INTENDED_PUBLISHABLE_KEY,
    'pk_local',
  ]);
  const nowMs = Date.now();

  const baseConfig = {
    namespace: firstNonEmptyString([
      process.env.SEAMS_TENANT_STORAGE_NAMESPACE,
      localEnv.SEAMS_TENANT_STORAGE_NAMESPACE,
      'seams-local',
    ]),
    orgId: firstNonEmptyString([
      process.env.SEAMS_INTENDED_CONSOLE_ORG_ID,
      localEnv.SEAMS_INTENDED_CONSOLE_ORG_ID,
      process.env.SEAMS_LOCAL_CONSOLE_ORG_ID,
      localEnv.SEAMS_LOCAL_CONSOLE_ORG_ID,
      'local-smoke-org',
    ]),
    projectId: firstNonEmptyString([
      process.env.SEAMS_INTENDED_PROJECT_ID,
      localEnv.SEAMS_INTENDED_PROJECT_ID,
      process.env.SEAMS_LOCAL_CONSOLE_PROJECT_ID,
      localEnv.SEAMS_LOCAL_CONSOLE_PROJECT_ID,
      'local-smoke-project',
    ]),
    environmentId: firstNonEmptyString([
      process.env.SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID,
      localEnv.SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID,
      process.env.SEAMS_LOCAL_CONSOLE_ENVIRONMENT_ID,
      localEnv.SEAMS_LOCAL_CONSOLE_ENVIRONMENT_ID,
      'local-env',
    ]),
    environmentKey: firstNonEmptyString([
      process.env.SEAMS_INTENDED_ENVIRONMENT_KEY,
      localEnv.SEAMS_INTENDED_ENVIRONMENT_KEY,
      'dev',
    ]),
    publishableKey,
    allowedOrigins: uniqueNonEmpty([
      appOrigin,
      walletOrigin,
      docsOrigin,
      'https://localhost',
      'https://localhost:8443',
    ]),
    keyPrefix: publishableKey.trim().slice(0, 24),
    secretHash: hashApiKeySecret(publishableKey),
    secretPreview: `${publishableKey.trim().slice(0, 10)}...`,
    nowMs,
  };
  return {
    ...baseConfig,
    ...buildTempoSponsorshipRuntimeFields(baseConfig),
  };
}

function runWranglerSeed(config) {
  const sql = buildSeedSql(config);
  const result = spawnSync(
    'pnpm',
    [
      '-C',
      'packages/sdk-server-ts',
      'exec',
      'wrangler',
      'd1',
      'execute',
      'seams-console',
      '--local',
      '--persist-to',
      d1LocalPersistPath,
      '--config',
      d1LocalWranglerConfig,
      '--command',
      sql,
    ],
    {
      cwd: repoRoot,
      env: process.env,
      stdio: 'inherit',
    },
  );
  if (result.error) {
    throw new Error(`wrangler D1 seed failed to start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`wrangler D1 seed exited with ${String(result.status ?? 'unknown')}`);
  }
}

function buildSeedSql(config) {
  return [
    buildOrganizationStatement(config),
    buildProjectStatement(config),
    buildEnvironmentStatement(config),
    buildBillingAccountStatement(config),
    buildRetireTempoPricingStatement(config),
    buildTempoPricingStatement(config),
    buildRuntimeSnapshotStatement(config),
    buildRuntimeSnapshotOutboxStatement(config),
    buildApiKeyStatement(config),
  ].join('\n');
}

function buildOrganizationStatement(config) {
  return `INSERT INTO organizations
  (namespace, id, name, slug, created_by_user_id, status, created_at_ms, updated_at_ms)
VALUES
  (${sqlString(config.namespace)}, ${sqlString(config.orgId)}, 'Intended Local Org',
   'intended-local-org', 'intended-local-seed', 'ACTIVE', ${config.nowMs}, ${config.nowMs})
ON CONFLICT(namespace, id) DO UPDATE SET
  name = excluded.name,
  slug = excluded.slug,
  status = excluded.status,
  updated_at_ms = excluded.updated_at_ms;`;
}

function buildProjectStatement(config) {
  return `INSERT INTO projects
  (namespace, id, org_id, name, slug, status, created_at_ms, updated_at_ms)
VALUES
  (${sqlString(config.namespace)}, ${sqlString(config.projectId)}, ${sqlString(config.orgId)},
   'Intended Local Project', 'intended-local-project', 'ACTIVE', ${config.nowMs}, ${config.nowMs})
ON CONFLICT(namespace, id) DO UPDATE SET
  org_id = excluded.org_id,
  name = excluded.name,
  slug = excluded.slug,
  status = excluded.status,
  updated_at_ms = excluded.updated_at_ms;`;
}

function buildEnvironmentStatement(config) {
  return `INSERT INTO environments
  (namespace, id, org_id, project_id, env_key, signing_root_version, name, status, created_at_ms, updated_at_ms)
VALUES
  (${sqlString(config.namespace)}, ${sqlString(config.environmentId)}, ${sqlString(config.orgId)},
   ${sqlString(config.projectId)}, ${sqlString(config.environmentKey)}, 'default',
   'Intended Local Dev', 'ACTIVE', ${config.nowMs}, ${config.nowMs})
ON CONFLICT(namespace, id) DO UPDATE SET
  org_id = excluded.org_id,
  project_id = excluded.project_id,
  env_key = excluded.env_key,
  signing_root_version = excluded.signing_root_version,
  name = excluded.name,
  status = excluded.status,
  updated_at_ms = excluded.updated_at_ms;`;
}

function buildApiKeyStatement(config) {
  return `INSERT INTO api_keys
  (namespace, org_id, id, kind, name, environment_id, key_prefix,
   scopes_json, ip_allowlist_json, allowed_origins_json, rate_limit_bucket,
   quota_bucket, risk_policy_json, payment_policy_json, status, secret_hash,
   secret_version, secret_preview, last_used_at_ms, expires_at_ms, revoked_reason,
   endpoint_usage_counts_json, anomaly_flags_json, created_at_ms, updated_at_ms)
VALUES
  (${sqlString(config.namespace)}, ${sqlString(config.orgId)}, 'ak_intended_local_publishable',
   'publishable_key', 'Intended local publishable key', ${sqlString(config.environmentId)},
   ${sqlString(config.keyPrefix)}, '[]', '[]', ${jsonSql(config.allowedOrigins)},
   'intended-local', 'intended-local', '{}', '{}', 'ACTIVE', ${sqlString(config.secretHash)},
   1, ${sqlString(config.secretPreview)}, NULL, NULL, NULL, '{}', '[]',
   ${config.nowMs}, ${config.nowMs})
ON CONFLICT(namespace, org_id, id) DO UPDATE SET
  kind = excluded.kind,
  name = excluded.name,
  environment_id = excluded.environment_id,
  key_prefix = excluded.key_prefix,
  scopes_json = excluded.scopes_json,
  ip_allowlist_json = excluded.ip_allowlist_json,
  allowed_origins_json = excluded.allowed_origins_json,
  rate_limit_bucket = excluded.rate_limit_bucket,
  quota_bucket = excluded.quota_bucket,
  risk_policy_json = excluded.risk_policy_json,
  payment_policy_json = excluded.payment_policy_json,
  status = excluded.status,
  secret_hash = excluded.secret_hash,
  secret_version = excluded.secret_version,
  secret_preview = excluded.secret_preview,
  expires_at_ms = excluded.expires_at_ms,
  revoked_reason = excluded.revoked_reason,
  updated_at_ms = excluded.updated_at_ms;`;
}

function buildBillingAccountStatement(config) {
  return `INSERT INTO billing_accounts
  (namespace, org_id, credit_balance_minor, low_balance_threshold_minor, created_at_ms, updated_at_ms)
VALUES
  (${sqlString(config.namespace)}, ${sqlString(config.orgId)}, ${config.prepaidCreditMinor}, 2000,
   ${config.nowMs}, ${config.nowMs})
ON CONFLICT(namespace, org_id) DO UPDATE SET
  credit_balance_minor = max(billing_accounts.credit_balance_minor, excluded.credit_balance_minor),
  low_balance_threshold_minor = excluded.low_balance_threshold_minor,
  updated_at_ms = excluded.updated_at_ms;`;
}

function buildRetireTempoPricingStatement(config) {
  return `UPDATE sponsorship_pricing_rules
SET status = 'retired',
    effective_until_ms = ${config.nowMs},
    updated_at_ms = ${config.nowMs}
WHERE namespace = ${sqlString(config.namespace)}
  AND org_id = ${sqlString(config.orgId)}
  AND project_id = ${sqlString(config.projectId)}
  AND environment_id = ${sqlString(config.environmentId)}
  AND policy_id = ${sqlString(config.tempoPolicyId)}
  AND chain_family = 'evm'
  AND chain_id = ${config.tempoChainId}
  AND intent_kind = 'evm_call'
  AND executor_kind = 'evm_eoa'
  AND status = 'active'
  AND pricing_version <> ${sqlString(config.tempoPricingVersion)};`;
}

function buildTempoPricingStatement(config) {
  return `INSERT INTO sponsorship_pricing_rules
  (namespace, org_id, project_id, environment_id, policy_id, chain_family, chain_id,
   intent_kind, executor_kind, model_kind, pricing_version, estimate_fee_per_gas_wei,
   minor_per_wei_numerator, minor_per_wei_denominator, min_spend_minor, rounding_mode,
   status, effective_from_ms, effective_until_ms, created_by, created_at_ms, updated_at_ms)
VALUES
  (${sqlString(config.namespace)}, ${sqlString(config.orgId)}, ${sqlString(config.projectId)},
   ${sqlString(config.environmentId)}, ${sqlString(config.tempoPolicyId)}, 'evm',
   ${config.tempoChainId}, 'evm_call', 'evm_eoa', 'evm_static_gas_v1',
   ${sqlString(config.tempoPricingVersion)}, '40000000000', '1', '1000000000000000',
   1, 'ceil', 'active', ${config.nowMs}, NULL, 'intended-local-seed',
   ${config.nowMs}, ${config.nowMs})
ON CONFLICT(namespace, pricing_version) DO UPDATE SET
  org_id = excluded.org_id,
  project_id = excluded.project_id,
  environment_id = excluded.environment_id,
  policy_id = excluded.policy_id,
  estimate_fee_per_gas_wei = excluded.estimate_fee_per_gas_wei,
  minor_per_wei_numerator = excluded.minor_per_wei_numerator,
  minor_per_wei_denominator = excluded.minor_per_wei_denominator,
  min_spend_minor = excluded.min_spend_minor,
  status = excluded.status,
  effective_until_ms = excluded.effective_until_ms,
  updated_at_ms = excluded.updated_at_ms;`;
}

function buildRuntimeSnapshotStatement(config) {
  return `INSERT INTO runtime_snapshots
  (namespace, org_id, project_id, environment_id, snapshot_id, version, effective_at_ms,
   checksum, payload_json, created_at_ms, created_by)
VALUES
  (${sqlString(config.namespace)}, ${sqlString(config.orgId)}, ${sqlString(config.projectId)},
   ${sqlString(config.environmentId)}, ${sqlString(config.runtimeSnapshotId)},
   ${config.runtimeSnapshotVersion}, ${config.nowMs}, ${sqlString(config.runtimeSnapshotChecksum)},
   ${jsonSql(config.runtimeSnapshotPayload)}, ${config.nowMs}, 'intended-local-seed')
ON CONFLICT(namespace, org_id, snapshot_id) DO UPDATE SET
  payload_json = excluded.payload_json,
  checksum = excluded.checksum,
  created_at_ms = excluded.created_at_ms,
  created_by = excluded.created_by;`;
}

function buildRuntimeSnapshotOutboxStatement(config) {
  return `INSERT INTO runtime_snapshot_outbox
  (namespace, org_id, project_id, environment_id, event_id, event_type, snapshot_id,
   snapshot_version, payload_json, status, attempt_count, available_at_ms, claimed_by,
   claim_expires_at_ms, last_error, created_at_ms, updated_at_ms, dispatched_at_ms)
VALUES
  (${sqlString(config.namespace)}, ${sqlString(config.orgId)}, ${sqlString(config.projectId)},
   ${sqlString(config.environmentId)}, ${sqlString(config.runtimeSnapshotOutboxEventId)},
   'RUNTIME_SNAPSHOT_PUBLISHED_V1', ${sqlString(config.runtimeSnapshotId)},
   ${config.runtimeSnapshotVersion}, ${jsonSql(config.runtimeSnapshotOutboxPayload)},
   'PENDING', 0, ${config.nowMs}, NULL, NULL, NULL, ${config.nowMs}, ${config.nowMs}, NULL)
ON CONFLICT(namespace, org_id, snapshot_id, snapshot_version, event_type) DO UPDATE SET
  payload_json = excluded.payload_json,
  status = 'PENDING',
  attempt_count = 0,
  available_at_ms = excluded.available_at_ms,
  claimed_by = NULL,
  claim_expires_at_ms = NULL,
  last_error = NULL,
  updated_at_ms = excluded.updated_at_ms,
  dispatched_at_ms = NULL;`;
}

function hashApiKeySecret(secret) {
  const hex = createHash('sha256').update(secret.trim()).digest('hex');
  return `sha256:${hex}`;
}

function buildTempoSponsorshipRuntimeFields(config) {
  const effectiveAt = new Date(config.nowMs).toISOString();
  const tempoPolicyId = `policy_intended_local_tempo_${hashStableId(
    `${config.namespace}:${config.orgId}:${config.projectId}:${config.environmentId}`,
  )}`;
  const runtimeSnapshotVersion = config.nowMs;
  const runtimeSnapshotId = `runtime_snapshot_intended_${hashStableId(
    `${config.namespace}:${config.orgId}:${config.environmentId}:${config.nowMs}`,
  )}`;
  const runtimeSnapshotOutboxEventId = `runtime_snapshot_event_intended_${hashStableId(
    `${runtimeSnapshotId}:${runtimeSnapshotVersion}`,
  )}`;
  const tempoFaucetContract = '0xBB442B54c85efBa2D7B81eA52990ad638cDbA483';
  const tempoPricingVersion = `tempo-testnet-static-v1:${tempoPolicyId}`;
  const runtimeSnapshotPayload = buildTempoRuntimeSnapshotPayload({
    ...config,
    effectiveAt,
    tempoPolicyId,
    tempoFaucetContract,
  });
  const runtimeSnapshotChecksum = computeRuntimeSnapshotChecksum({
    orgId: config.orgId,
    projectId: config.projectId,
    environmentId: config.environmentId,
    snapshotId: runtimeSnapshotId,
    version: runtimeSnapshotVersion,
    effectiveAt,
    payload: runtimeSnapshotPayload,
  });
  const runtimeSnapshotOutboxPayload = {
    eventType: 'runtime_snapshot.published.v1',
    snapshot: {
      orgId: config.orgId,
      projectId: config.projectId,
      environmentId: config.environmentId,
      snapshotId: runtimeSnapshotId,
      version: runtimeSnapshotVersion,
      effectiveAt,
      checksum: runtimeSnapshotChecksum,
      createdAt: effectiveAt,
      createdBy: 'intended-local-seed',
    },
  };
  return {
    tempoChainId: 42_431,
    tempoPolicyId,
    tempoPricingVersion,
    tempoFaucetContract,
    prepaidCreditMinor: 1_000_000,
    runtimeSnapshotVersion,
    runtimeSnapshotId,
    runtimeSnapshotOutboxEventId,
    runtimeSnapshotPayload,
    runtimeSnapshotChecksum,
    runtimeSnapshotOutboxPayload,
  };
}

function buildTempoRuntimeSnapshotPayload(input) {
  const resolvedPolicy = {
    kind: 'evm_call',
    policyId: input.tempoPolicyId,
    policyName: 'Tempo Testnet Onboarding',
    scopePolicyId: null,
    scopePolicyName: null,
    templateId: 'tempo_testnet_onboarding',
    networkClass: 'TESTNET',
    executionMode: 'evm_eoa',
    spendCap: {
      mode: 'NONE',
      period: 'MONTHLY',
      capsByChain: [],
    },
    scopeType: 'ENVIRONMENT',
    projectId: input.projectId,
    environmentId: input.environmentId,
    allowedChainIds: [42_431],
    allowedCalls: [
      {
        chainId: 42_431,
        to: input.tempoFaucetContract,
        functionSignature: 'dripTo(address,address[])',
        selector: '0x867ae9d4',
        maxGasLimit: '1000000',
        maxValueWei: '0',
      },
    ],
  };
  return {
    policy: {
      status: 'resolved',
      policyCount: 0,
      assignmentCount: 0,
      policies: [],
      assignments: [],
    },
    gasSponsorship: {
      status: 'resolved',
      policyCount: 1,
      policies: [resolvedPolicy],
      resolvedPolicies: [resolvedPolicy],
    },
    metadata: {
      source: 'intended_local_seed_v1',
      generatedAt: input.effectiveAt,
      environmentId: input.environmentId,
      projectId: input.projectId,
    },
  };
}

function computeRuntimeSnapshotChecksum(input) {
  return hashFNV1A32(
    stableJsonStringify({
      orgId: input.orgId,
      projectId: input.projectId,
      environmentId: input.environmentId,
      snapshotId: input.snapshotId,
      version: input.version,
      effectiveAt: input.effectiveAt,
      payload: input.payload,
    }),
  );
}

function stableJsonStringify(value) {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(stableJsonStringify).join(',')}]`;
  }
  if (typeof value === 'object') {
    const row = value;
    const entries = Object.keys(row)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stableJsonStringify(row[key])}`);
    return `{${entries.join(',')}}`;
  }
  return 'null';
}

function hashFNV1A32(input) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return `fnv1a32:${(hash >>> 0).toString(16).padStart(8, '0')}`;
}

function hashStableId(input) {
  return createHash('sha256').update(String(input)).digest('hex').slice(0, 16);
}

function originFromUrl(value) {
  return new URL(value).origin;
}

function uniqueNonEmpty(values) {
  return Array.from(new Set(values.map(normalizeString).filter(Boolean)));
}

function normalizeString(value) {
  return String(value || '').trim();
}

function jsonSql(value) {
  return sqlString(JSON.stringify(value));
}

function sqlString(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}
