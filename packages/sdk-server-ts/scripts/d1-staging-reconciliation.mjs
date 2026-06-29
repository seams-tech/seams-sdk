#!/usr/bin/env node
import path from 'node:path';

import {
  d1StagingConfigManifestArgDefaults,
  d1StagingConfigManifestFlagFields,
  d1StagingCommandLines,
  isDirectInvocation,
  isJsonRecord,
  commaList,
  normalizeConsoleRouterApiD1StagingOptions,
  normalizeString,
  packageRoot,
  parseFlagArgs,
  printD1StagingCliError,
  printStagingManifestResult,
  readSelectedWranglerConfig,
  readString,
  relativeToRepo,
  requireSuccessfulCommandResult,
  shellArg,
  sqlString,
  sqlStringList,
  tableBody,
  writeD1StagingManifest,
  wranglerCommand,
} from './d1-staging-config.mjs';
import { requireConsoleAndRouterApiD1StagingReadiness } from './d1-staging-readiness-check.mjs';

const defaultManifestRoot = path.join(packageRoot, '.wrangler/d1-staging-reconciliation');
const reconciliationModes = Object.freeze(['dry-run', 'remote']);

export function buildD1StagingReconciliationPlan(input = {}) {
  const options = normalizeOptions(input);
  requireConsoleAndRouterApiD1StagingReadiness({
    label: 'reconciliation',
    consoleConfigPath: options.consoleConfigPath,
    routerApiConfigPath: options.routerApiConfigPath,
    environmentName: options.environmentName,
  });
  const stagingVars = readRouterApiStagingVars({
    configPath: options.routerApiConfigPath,
    environmentName: options.environmentName,
  });
  const checks = reconciliationChecks({
    consoleConfigPath: options.consoleConfigPath,
    routerApiConfigPath: options.routerApiConfigPath,
    stagingVars,
  });
  return {
    version: 'seams_d1_staging_reconciliation_v1',
    generatedAtIso: options.generatedAtIso,
    mode: options.mode,
    environmentName: options.environmentName,
    consoleConfigPath: relativeToRepo(options.consoleConfigPath),
    routerApiConfigPath: relativeToRepo(options.routerApiConfigPath),
    tenant: {
      namespace: stagingVars.namespace,
      orgId: stagingVars.orgId,
      projectId: stagingVars.projectId,
      envId: stagingVars.envId,
    },
    checks,
  };
}

export function runD1StagingReconciliation(input = {}) {
  const options = normalizeOptions(input);
  const plan = buildD1StagingReconciliationPlan(options);
  const executed = [];

  if (options.mode === 'remote') {
    for (const check of plan.checks) {
      const result = requireSuccessfulCommandResult(check.command, options.commandRunner(check.command));
      const rows = parseRowsFromWranglerJson(result.stdout, check.id);
      executed.push({
        id: check.id,
        target: check.target,
        description: check.description,
        status: result.status,
        rowCount: rows.length,
        rows,
        command: result.command,
        stderr: result.stderr,
      });
    }
    assertNoReconciliationFailures(executed);
  }

  const manifest = {
    ...plan,
    executed,
  };
  return writeD1StagingManifest(options, defaultManifestRoot, manifest);
}

function main() {
  try {
    const result = runD1StagingReconciliation(parseArgs(process.argv.slice(2)));
    printStagingManifestResult(result, 'D1 staging reconciliation manifest', 'Dry run commands:', d1StagingCommandLines(result.manifest.checks));
  } catch (error) {
    printD1StagingCliError(error);
  }
}

function parseArgs(args) {
  return parseFlagArgs(args, d1StagingConfigManifestArgDefaults, d1StagingConfigManifestFlagFields);
}

function normalizeOptions(input) {
  return normalizeConsoleRouterApiD1StagingOptions(input, {
    modes: reconciliationModes,
    modeLabel: 'staging reconciliation',
  });
}

function readRouterApiStagingVars(input) {
  const source = readSelectedWranglerConfig({
    configPath: input.configPath,
    environmentName: input.environmentName,
    label: 'Router API',
  });
  const vars = tableBody(source, 'vars');
  const stagingVars = {
    namespace: readRequiredVar(vars, 'SEAMS_TENANT_STORAGE_NAMESPACE'),
    orgId: readRequiredVar(vars, 'SEAMS_STAGING_ORG_ID'),
    projectId: readRequiredVar(vars, 'SEAMS_STAGING_PROJECT_ID'),
    envId: readRequiredVar(vars, 'SEAMS_STAGING_ENV_ID'),
    kekIds: commaList(readString(vars, 'SIGNING_ROOT_KEK_IDS')),
  };
  if (stagingVars.kekIds.length === 0) throw new Error('SIGNING_ROOT_KEK_IDS must list at least one KEK id');
  return stagingVars;
}

function readRequiredVar(source, key) {
  const value = readString(source, key);
  if (!value) throw new Error(`${key} is required under router-api [vars]`);
  return value;
}

function reconciliationChecks(input) {
  return [
    consoleCheck({
      id: 'billing_account_balance_mismatch',
      description: 'Billing account balances must equal the sum of ledger entries.',
      configPath: input.consoleConfigPath,
      sql: billingAccountBalanceMismatchSql(input.stagingVars),
    }),
    consoleCheck({
      id: 'prepaid_reservation_summary_mismatch',
      description: 'Prepaid reservation summaries must equal active RESERVED reservations.',
      configPath: input.consoleConfigPath,
      sql: prepaidReservationSummaryMismatchSql(input.stagingVars),
    }),
    consoleCheck({
      id: 'sponsored_call_missing_billing_links',
      description: 'Charged sponsored EVM calls must link to billing ledger and prepaid reservation records.',
      configPath: input.consoleConfigPath,
      sql: sponsoredCallMissingBillingLinksSql(input.stagingVars),
    }),
    consoleCheck({
      id: 'sponsored_call_settlement_amount_mismatch',
      description: 'Sponsored EVM call settled spend must match the linked ledger debit amount.',
      configPath: input.consoleConfigPath,
      sql: sponsoredCallSettlementAmountMismatchSql(input.stagingVars),
    }),
    signerCheck({
      id: 'signer_share_unknown_kek',
      description: 'Signer sealed-share rows must use a KEK configured in the Router API staging profile.',
      configPath: input.routerApiConfigPath,
      sql: signerShareUnknownKekSql(input.stagingVars),
    }),
    signerCheck({
      id: 'signer_share_invalid_rotation_state',
      description: 'Signer sealed-share rotation fields must match the selected lifecycle state.',
      configPath: input.routerApiConfigPath,
      sql: signerShareInvalidRotationStateSql(input.stagingVars),
    }),
  ];
}

function consoleCheck(input) {
  return readOnlyD1Check({
    ...input,
    target: 'console',
    databaseName: 'seams-console-staging',
  });
}

function signerCheck(input) {
  return readOnlyD1Check({
    ...input,
    target: 'signer',
    databaseName: 'seams-signer-staging',
  });
}

function readOnlyD1Check(input) {
  return {
    id: input.id,
    target: input.target,
    databaseName: input.databaseName,
    description: input.description,
    sql: input.sql,
    command: wranglerCommand(
      [
        'd1 execute',
        input.databaseName,
        '--remote',
        '--json',
        '--command',
        shellArg(input.sql),
      ].join(' '),
      input.configPath,
    ),
  };
}

function billingAccountBalanceMismatchSql(vars) {
  return compactSql(`
    SELECT
      a.namespace,
      a.org_id,
      a.credit_balance_minor,
      COALESCE(SUM(e.amount_minor), 0) AS ledger_balance_minor
    FROM billing_accounts a
    LEFT JOIN billing_ledger_entries e
      ON e.namespace = a.namespace
     AND e.org_id = a.org_id
    WHERE a.namespace = ${sqlString(vars.namespace)}
      AND a.org_id = ${sqlString(vars.orgId)}
    GROUP BY a.namespace, a.org_id, a.credit_balance_minor
    HAVING a.credit_balance_minor != COALESCE(SUM(e.amount_minor), 0)
    LIMIT 50
  `);
}

function prepaidReservationSummaryMismatchSql(vars) {
  return compactSql(`
    SELECT
      s.namespace,
      s.org_id,
      s.reserved_minor AS summary_reserved_minor,
      COALESCE(SUM(r.requested_minor), 0) AS active_reserved_minor,
      s.active_reservation_count AS summary_active_count,
      COUNT(r.id) AS active_count
    FROM billing_prepaid_reservation_summaries s
    LEFT JOIN billing_prepaid_reservations r
      ON r.namespace = s.namespace
     AND r.org_id = s.org_id
     AND r.status = 'RESERVED'
    WHERE s.namespace = ${sqlString(vars.namespace)}
      AND s.org_id = ${sqlString(vars.orgId)}
    GROUP BY s.namespace, s.org_id, s.reserved_minor, s.active_reservation_count
    HAVING s.reserved_minor != COALESCE(SUM(r.requested_minor), 0)
        OR s.active_reservation_count != COUNT(r.id)
    LIMIT 50
  `);
}

function sponsoredCallMissingBillingLinksSql(vars) {
  return compactSql(`
    SELECT
      c.namespace,
      c.org_id,
      c.id,
      c.billing_ledger_entry_id,
      c.prepaid_reservation_id
    FROM sponsored_call_records c
    LEFT JOIN billing_ledger_entries e
      ON e.namespace = c.namespace
     AND e.org_id = c.org_id
     AND e.id = c.billing_ledger_entry_id
    LEFT JOIN billing_prepaid_reservations r
      ON r.namespace = c.namespace
     AND r.org_id = c.org_id
     AND r.id = c.prepaid_reservation_id
    WHERE c.namespace = ${sqlString(vars.namespace)}
      AND c.org_id = ${sqlString(vars.orgId)}
      AND c.intent_kind = 'evm_call'
      AND c.charged = 1
      AND (
        c.billing_ledger_entry_id IS NULL
        OR c.prepaid_reservation_id IS NULL
        OR e.id IS NULL
        OR r.id IS NULL
      )
    LIMIT 50
  `);
}

function sponsoredCallSettlementAmountMismatchSql(vars) {
  return compactSql(`
    SELECT
      c.namespace,
      c.org_id,
      c.id,
      c.settled_spend_minor,
      e.amount_minor AS ledger_amount_minor
    FROM sponsored_call_records c
    JOIN billing_ledger_entries e
      ON e.namespace = c.namespace
     AND e.org_id = c.org_id
     AND e.id = c.billing_ledger_entry_id
    WHERE c.namespace = ${sqlString(vars.namespace)}
      AND c.org_id = ${sqlString(vars.orgId)}
      AND c.intent_kind = 'evm_call'
      AND c.charged = 1
      AND COALESCE(c.settled_spend_minor, -1) != ABS(e.amount_minor)
    LIMIT 50
  `);
}

function signerShareUnknownKekSql(vars) {
  return compactSql(`
    SELECT
      namespace,
      org_id,
      project_id,
      env_id,
      signing_root_id,
      signing_root_version,
      share_id,
      kek_id
    FROM signing_root_secret_shares
    WHERE namespace = ${sqlString(vars.namespace)}
      AND org_id = ${sqlString(vars.orgId)}
      AND project_id = ${sqlString(vars.projectId)}
      AND env_id = ${sqlString(vars.envId)}
      AND kek_id NOT IN (${sqlStringList(vars.kekIds)})
    LIMIT 50
  `);
}

function signerShareInvalidRotationStateSql(vars) {
  return compactSql(`
    SELECT
      namespace,
      org_id,
      project_id,
      env_id,
      signing_root_id,
      signing_root_version,
      share_id,
      rotation_state,
      rotated_from_kek_id,
      rotated_at_ms,
      retired_at_ms
    FROM signing_root_secret_shares
    WHERE namespace = ${sqlString(vars.namespace)}
      AND org_id = ${sqlString(vars.orgId)}
      AND project_id = ${sqlString(vars.projectId)}
      AND env_id = ${sqlString(vars.envId)}
      AND (
        (rotation_state = 'active' AND (rotated_at_ms IS NOT NULL OR retired_at_ms IS NOT NULL))
        OR (rotation_state = 'rotation_pending' AND retired_at_ms IS NOT NULL)
        OR (rotation_state = 'rotated' AND (rotated_from_kek_id IS NULL OR rotated_at_ms IS NULL))
        OR (rotation_state = 'retired' AND retired_at_ms IS NULL)
      )
    LIMIT 50
  `);
}

function parseRowsFromWranglerJson(stdout, checkId) {
  const source = normalizeString(stdout);
  if (!source) throw new Error(`${checkId} returned empty Wrangler JSON output`);
  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error(`${checkId} returned non-JSON Wrangler output`);
  }
  return extractRows(parsed, checkId);
}

function extractRows(parsed, checkId) {
  if (Array.isArray(parsed)) return extractRowsFromArray(parsed, checkId);
  if (isJsonRecord(parsed)) return extractRowsFromObject(parsed, checkId);
  throw new Error(`${checkId} returned unsupported Wrangler JSON output`);
}

function extractRowsFromArray(values, checkId) {
  for (const value of values) {
    if (!isJsonRecord(value)) continue;
    if (Array.isArray(value.results)) return value.results;
  }
  if (values.length === 0) return [];
  if (isJsonRecord(values[0])) return values;
  throw new Error(`${checkId} returned array output without result rows`);
}

function extractRowsFromObject(value, checkId) {
  if (Array.isArray(value.results)) return value.results;
  if (Array.isArray(value.rows)) return value.rows;
  throw new Error(`${checkId} returned object output without result rows`);
}

function assertNoReconciliationFailures(executed) {
  const failures = [];
  for (const check of executed) {
    if (check.rowCount > 0) failures.push(`${check.id}: ${check.rowCount} mismatch row(s)`);
  }
  if (failures.length === 0) return;
  const lines = ['D1 staging reconciliation found mismatches:'];
  for (const failure of failures) lines.push(`- ${failure}`);
  throw new Error(lines.join('\n'));
}

function compactSql(source) {
  return source.replace(/\s+/g, ' ').trim();
}

if (isDirectInvocation(import.meta.url)) main();
