#!/usr/bin/env node

import {
  defaultD1StagingGatewayConfigPath,
  isDirectInvocation,
  isJsonRecord,
  normalizeGeneratedAtIso,
  normalizeGatewayD1StagingConfig,
  normalizeStagingMode,
  normalizeString,
  parseFlagArgs,
  printD1StagingCliError,
  relativeToRepo,
  runShellCommand,
  shellArg,
  wranglerCommand,
} from './d1-staging-config.mjs';
import { requireGatewayD1StagingReadiness } from './d1-staging-readiness-check.mjs';

const signerD1DatabaseName = 'seams-signer-staging-nrt';
const inventoryModes = Object.freeze(['dry-run', 'remote']);
const credentialBearingCompletionPredicate = `
  EXISTS (
    SELECT 1 FROM json_tree(record_json) AS credential
     WHERE credential.value IS NOT NULL
       AND credential.key IN (
         'walletSessionToken',
         'operationCredential',
         'primaryCredential',
         'childCredential',
         'primaryOperationCredential',
         'childOperationCredential',
         'clientRootProof',
         'passkeyBootstrapAuthorization'
       )
  )
`;
const inventoryColumns = Object.freeze([
  Object.freeze({ column: 'active_v1', property: 'activeV1' }),
  Object.freeze({ column: 'active_usable_v2', property: 'activeUsableV2' }),
  Object.freeze({ column: 'active_v2_without_credential', property: 'activeV2WithoutCredential' }),
  Object.freeze({
    column: 'pending_v1_authorized_operations',
    property: 'pendingV1AuthorizedOperations',
  }),
  Object.freeze({
    column: 'unconsumed_hosted_exchange_codes',
    property: 'unconsumedHostedExchangeCodes',
  }),
  Object.freeze({ column: 'v1_only_quotas', property: 'v1OnlyQuotas' }),
  Object.freeze({ column: 'activation_credential_rows', property: 'activationCredentialRows' }),
  Object.freeze({
    column: 'provisioning_credential_rows',
    property: 'provisioningCredentialRows',
  }),
]);

export function buildSignerD1Phase1InventoryQuery(nowMs) {
  const nowExpression = nowMs === undefined ? '(unixepoch() * 1000)' : sqlInteger(nowMs);
  return compactSql(`
    SELECT
      (SELECT COUNT(*) FROM reusable_wallet_sessions
        WHERE lifecycle_kind = 'active' AND expires_at_ms > ${nowExpression}) AS active_v1,
      (SELECT COUNT(*) FROM wallet_session_authorizations_v2
        WHERE retired_at_ms IS NULL
          AND operation_credential_hash IS NOT NULL
          AND expires_at_ms > ${nowExpression}) AS active_usable_v2,
      (SELECT COUNT(*) FROM wallet_session_authorizations_v2
        WHERE retired_at_ms IS NULL
          AND operation_credential_hash IS NULL
          AND expires_at_ms > ${nowExpression}) AS active_v2_without_credential,
      (SELECT COUNT(*) FROM authorized_operations
        WHERE lifecycle_kind = 'claimed'
          AND authorization_source_kind = 'authorization_grant'
          AND authorization_grant_kind = 'wallet_session_authorization'
          AND linked_scope_org_id IS NULL
          AND linked_scope_project_id IS NULL
          AND linked_scope_env_id IS NULL) AS pending_v1_authorized_operations,
      (SELECT COUNT(*) FROM hosted_wallet_session_exchange_codes
        WHERE lifecycle_kind = 'issued' AND expires_at_ms > ${nowExpression})
        AS unconsumed_hosted_exchange_codes,
      (SELECT COUNT(*) FROM authorization_wallet_session_quotas AS quota
        WHERE NOT EXISTS (
          SELECT 1 FROM wallet_session_authorizations_v2 AS session
           WHERE session.namespace = quota.namespace
             AND session.tenant_id = quota.tenant_id
             AND session.quota_id = quota.quota_id
        )) AS v1_only_quotas,
      (SELECT COUNT(*) FROM router_ab_yao_versioned_json_records
        WHERE record_key LIKE 'wallet-registration-activate:%'
          AND ${credentialBearingCompletionPredicate})
        AS activation_credential_rows,
      (SELECT COUNT(*) FROM router_ab_yao_versioned_json_records
        WHERE record_key LIKE 'wallet-registration-near-provisioning:%'
          AND ${credentialBearingCompletionPredicate})
        AS provisioning_credential_rows;
  `);
}

export function normalizeSignerD1Phase1InventoryRow(row) {
  if (!isJsonRecord(row)) throw new Error('Signer D1 inventory returned no count row');
  const counts = {};
  for (const entry of inventoryColumns) {
    counts[entry.property] = countValue(row[entry.column], entry.column);
  }
  return counts;
}

export function parseSignerD1Phase1InventoryOutput(stdout) {
  const source = normalizeString(stdout);
  if (!source) throw new Error('Signer D1 inventory returned empty JSON output');
  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error('Signer D1 inventory returned non-JSON output');
  }
  const rows = extractResultRows(parsed);
  if (rows.length !== 1) {
    throw new Error('Signer D1 inventory must return exactly one count row');
  }
  return normalizeSignerD1Phase1InventoryRow(rows[0]);
}

export function buildD1StagingSignerPhase1InventoryPlan(input = {}) {
  const options = normalizeOptions(input);
  requireGatewayD1StagingReadiness({
    label: 'signer Phase 1 inventory',
    gatewayConfigPath: options.gatewayConfigPath,
    environmentName: options.environmentName,
  });
  const query = buildSignerD1Phase1InventoryQuery(options.nowMs);
  return {
    version: 'seams_d1_signer_r103f_phase1_inventory_v1',
    generatedAtIso: options.generatedAtIso,
    mode: options.mode,
    environmentName: options.environmentName,
    gatewayConfigPath: relativeToRepo(options.gatewayConfigPath),
    target: 'signer_d1',
    databaseName: signerD1DatabaseName,
    query,
    command: wranglerCommand(
      ['d1 execute', signerD1DatabaseName, '--remote', '--json', '--command', shellArg(query)].join(
        ' ',
      ),
      options.gatewayConfigPath,
    ),
  };
}

export function runD1StagingSignerPhase1Inventory(input = {}) {
  const options = normalizeOptions(input);
  const plan = buildD1StagingSignerPhase1InventoryPlan(options);
  if (options.mode === 'dry-run') return { ...plan, counts: null };

  let commandResult;
  try {
    commandResult = options.commandRunner(plan.command);
  } catch {
    throw new Error('Signer D1 Phase 1 inventory command failed');
  }
  if (!commandResult || commandResult.status !== 0) {
    throw new Error('Signer D1 Phase 1 inventory command failed');
  }
  return {
    ...plan,
    counts: parseSignerD1Phase1InventoryOutput(commandResult.stdout),
  };
}

function normalizeOptions(input) {
  const config = normalizeGatewayD1StagingConfig(input, {
    gatewayConfigPath: defaultD1StagingGatewayConfigPath,
  });
  return {
    ...config,
    generatedAtIso: normalizeGeneratedAtIso(input.generatedAtIso),
    mode: normalizeStagingMode(input.mode, inventoryModes, 'signer Phase 1 inventory'),
    nowMs: input.nowMs,
    commandRunner: input.commandRunner || runShellCommand,
  };
}

function extractResultRows(parsed) {
  if (Array.isArray(parsed)) {
    for (const value of parsed) {
      if (isJsonRecord(value) && Array.isArray(value.results)) return value.results;
    }
    throw new Error('Signer D1 inventory returned no result rows');
  }
  if (isJsonRecord(parsed)) {
    if (Array.isArray(parsed.results)) return parsed.results;
    if (Array.isArray(parsed.rows)) return parsed.rows;
  }
  throw new Error('Signer D1 inventory returned unsupported JSON output');
}

function countValue(value, column) {
  const count =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && /^\d+$/.test(value.trim())
        ? Number(value)
        : Number.NaN;
  if (!Number.isSafeInteger(count) || count < 0) {
    throw new Error(`Signer D1 inventory returned an invalid ${column} count`);
  }
  return count;
}

function sqlInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('Signer D1 inventory nowMs must be a non-negative safe integer');
  }
  return String(value);
}

function compactSql(source) {
  return source.replace(/\s+/g, ' ').trim();
}

function parseArgs(args) {
  return parseFlagArgs(
    args,
    {
      gatewayConfigPath: '',
      environmentName: 'staging',
      generatedAtIso: '',
      mode: 'dry-run',
    },
    {
      '--config': 'gatewayConfigPath',
      '--environment': 'environmentName',
      '--generated-at': 'generatedAtIso',
      '--mode': 'mode',
    },
  );
}

function main() {
  try {
    const result = runD1StagingSignerPhase1Inventory(parseArgs(process.argv.slice(2)));
    if (result.counts) {
      process.stdout.write(`${JSON.stringify(result.counts)}\n`);
      return;
    }
    process.stdout.write(`Dry-run command: ${result.command}\n`);
  } catch (error) {
    printD1StagingCliError(error);
  }
}

if (isDirectInvocation(import.meta.url)) main();
