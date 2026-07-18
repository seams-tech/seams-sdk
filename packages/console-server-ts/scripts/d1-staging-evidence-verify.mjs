#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

import {
  d1IntegrityCheckValues,
  d1TimeTravelBookmarkValue,
  isDirectInvocation,
  isJsonRecord,
  normalizeGeneratedAtIso,
  normalizeString,
  packageRoot,
  printD1StagingCliError,
  relativeToRepo,
  parseFlagArgs,
  resolvePackagePath,
  resolveRequiredPackagePath,
  writeJsonManifest,
} from './d1-staging-config.mjs';

const defaultOutputPath = path.join(
  packageRoot,
  '.wrangler/d1-staging-evidence/verification.json',
);

const evidenceSpecs = Object.freeze([
  Object.freeze({
    id: 'resource_inventory',
    flag: 'resources',
    version: 'seams_d1_staging_resource_inventory_v1',
    validate: validateResourceInventory,
  }),
  Object.freeze({
    id: 'hosted_signer_kek_metadata',
    flag: 'kekCheck',
    version: 'seams_d1_staging_kek_check_v1',
    validate: validateKekCheck,
  }),
  Object.freeze({
    id: 'remote_d1_migrations',
    flag: 'migrations',
    version: 'seams_d1_staging_migration_v1',
    validate: validateMigration,
  }),
  Object.freeze({
    id: 'time_travel_before_fixture_import',
    flag: 'bookmarkBeforeFixtureImport',
    version: 'seams_d1_staging_time_travel_bookmark_v1',
    validate: validateBookmarkBeforeFixtureImport,
  }),
  Object.freeze({
    id: 'fixture_import',
    flag: 'fixtureImport',
    version: 'seams_d1_staging_fixture_import_v1',
    validate: validateFixtureImport,
  }),
  Object.freeze({
    id: 'time_travel_before_route_switch',
    flag: 'bookmarkBeforeRouteSwitch',
    version: 'seams_d1_staging_time_travel_bookmark_v1',
    validate: validateBookmarkBeforeRouteSwitch,
  }),
  Object.freeze({
    id: 'staging_smoke',
    flag: 'smoke',
    version: 'seams_d1_staging_smoke_v1',
    validate: validateSmoke,
  }),
  Object.freeze({
    id: 'd1_reconciliation',
    flag: 'reconciliation',
    version: 'seams_d1_staging_reconciliation_v1',
    validate: validateReconciliation,
  }),
  Object.freeze({
    id: 'signer_custody',
    flag: 'signerCustody',
    version: 'seams_d1_staging_signer_custody_v1',
    validate: validateSignerCustody,
  }),
  Object.freeze({
    id: 'r2_restore_drill',
    flag: 'r2RestoreDrill',
    version: 'seams_d1_staging_r2_restore_drill_v1',
    validate: validateR2RestoreDrill,
  }),
]);

const environmentEvidenceIds = Object.freeze([
  'resource_inventory',
  'hosted_signer_kek_metadata',
  'remote_d1_migrations',
  'fixture_import',
  'd1_reconciliation',
]);

const consoleConfigEvidenceIds = Object.freeze([
  'resource_inventory',
  'remote_d1_migrations',
  'time_travel_before_fixture_import',
  'fixture_import',
  'time_travel_before_route_switch',
  'd1_reconciliation',
  'r2_restore_drill',
]);

const gatewayConfigEvidenceIds = Object.freeze([
  'resource_inventory',
  'hosted_signer_kek_metadata',
  'remote_d1_migrations',
  'time_travel_before_fixture_import',
  'fixture_import',
  'time_travel_before_route_switch',
  'd1_reconciliation',
  'r2_restore_drill',
]);

const orderedRunEvidenceIds = Object.freeze([
  'resource_inventory',
  'hosted_signer_kek_metadata',
  'remote_d1_migrations',
  'time_travel_before_fixture_import',
  'fixture_import',
  'time_travel_before_route_switch',
  'staging_smoke',
  'd1_reconciliation',
  'signer_custody',
  'r2_restore_drill',
]);

const evidenceFlagFields = Object.freeze({
  ...Object.fromEntries(evidenceSpecs.map((spec) => [`--${cliFlag(spec)}`, spec.flag])),
  '--generated-at': 'generatedAtIso',
  '--output': 'outputPath',
});

const tenantFieldNames = Object.freeze(['namespace', 'orgId', 'projectId', 'envId']);
const requiredResourceInventoryCheckIds = Object.freeze([
  'console_d1_info',
  'signer_d1_info',
  'console_worker_deployment_status',
  'router_api_worker_deployment_status',
]);
const signerOnlyConsoleD1Bindings = Object.freeze(['SIGNER_DB']);
const signerOnlyConsoleDurableObjectBindings = Object.freeze([
  'THRESHOLD_STORE',
  'ROUTER_API_RUNTIME',
]);
const requiredGatewayDurableObjectBindings = Object.freeze([
  'THRESHOLD_STORE',
  'ROUTER_API_RUNTIME',
]);
const requiredMigrationTargetActionPairs = Object.freeze([
  'console:list_before',
  'console:apply',
  'console:list_after',
  'signer:list_before',
  'signer:apply',
  'signer:list_after',
]);
const requiredFixtureLogicalNames = Object.freeze(['console', 'signer']);
const requiredBookmarkLogicalNames = Object.freeze(['console', 'signer']);
const requiredSmokeCheckIds = Object.freeze([
  'console_readyz',
  'router_api_readyz',
  'router_api_healthz',
  'signer_custody_ed25519_healthz',
  'signer_custody_ecdsa_derivation_healthz',
]);
const smokeExpectedPathsById = Object.freeze({
  console_readyz: '/console/readyz',
  router_api_readyz: '/readyz',
  router_api_healthz: '/healthz',
  signer_custody_ed25519_healthz: '/router-ab/ed25519/healthz',
  signer_custody_ecdsa_derivation_healthz: '/router-ab/ecdsa-derivation/healthz',
});
const smokeExpectedStatusesById = Object.freeze({
  console_readyz: 200,
  router_api_readyz: 200,
  router_api_healthz: 200,
  signer_custody_ed25519_healthz: 200,
  signer_custody_ecdsa_derivation_healthz: 200,
});
const gatewaySmokeCheckIds = Object.freeze([
  'router_api_readyz',
  'router_api_healthz',
  'signer_custody_ed25519_healthz',
  'signer_custody_ecdsa_derivation_healthz',
]);
const signerCustodyMissingKekResultId = 'ecdsa_export_share_missing_kek_fail_closed';
const signerCustodyMissingKekCode = 'missing_signing_root_kek';
const requiredSignerCustodyResultIds = Object.freeze([
  'signer_custody_ed25519_healthz',
  'signer_custody_ecdsa_derivation_healthz',
  'ecdsa_export_share_success',
  signerCustodyMissingKekResultId,
]);
const signerCustodyExpectedPathsById = Object.freeze({
  signer_custody_ed25519_healthz: '/router-ab/ed25519/healthz',
  signer_custody_ecdsa_derivation_healthz: '/router-ab/ecdsa-derivation/healthz',
  ecdsa_export_share_success: '/router-ab/ecdsa-derivation/export/share',
  [signerCustodyMissingKekResultId]: '/router-ab/ecdsa-derivation/export/share',
});
const signerCustodyExpectedStatusesById = Object.freeze({
  signer_custody_ed25519_healthz: 200,
  signer_custody_ecdsa_derivation_healthz: 200,
  ecdsa_export_share_success: 200,
});
const signerCustodySensitiveBodyFieldNames = new Set([
  'authorization',
  'jwt',
  'privateKeyHex',
  'private_key_hex',
  'server_export_share_32_b64u',
  'serverExportShare32B64u',
  'serverShare32B64u',
  'server_share_32_b64u',
  'signing_share_32_b64u',
  'signingShare32B64u',
  'token',
].map(sensitiveBodyFieldKey));
const requiredReconciliationCheckIds = Object.freeze([
  'billing_account_balance_mismatch',
  'prepaid_reservation_summary_mismatch',
  'sponsored_call_missing_billing_links',
  'sponsored_call_settlement_amount_mismatch',
  'signer_share_unknown_kek',
  'signer_share_invalid_rotation_state',
]);

export function verifyD1StagingEvidence(input = {}) {
  const options = normalizeOptions(input);
  const evidence = [];
  const errors = [];
  const manifestsById = new Map();

  for (const spec of evidenceSpecs) {
    const manifestPath = options[spec.flag];
    const manifest = readManifest({ id: spec.id, path: manifestPath, errors });
    if (!manifest) continue;
    manifestsById.set(spec.id, manifest);
    validateVersionMode({ spec, manifest, errors });
    spec.validate({ manifest, errors, id: spec.id });
    evidence.push(evidenceSummary({ spec, manifestPath, manifest }));
  }
  validateManifestConsistency({ manifestsById, errors });

  if (errors.length > 0) {
    throw new Error(evidenceFailureMessage(errors));
  }

  const summary = {
    version: 'seams_d1_staging_evidence_verification_v1',
    generatedAtIso: options.generatedAtIso,
    ok: true,
    evidence,
  };
  writeJsonManifest(options.outputPath, summary);
  return {
    outputPath: options.outputPath,
    summary,
  };
}

function main() {
  try {
    const result = verifyD1StagingEvidence(parseArgs(process.argv.slice(2)));
    console.log(`D1 staging evidence verification: ${relativeToRepo(result.outputPath)}`);
  } catch (error) {
    printD1StagingCliError(error);
  }
}

function parseArgs(args) {
  return parseFlagArgs(args, {
    bookmarkBeforeFixtureImport: '',
    bookmarkBeforeRouteSwitch: '',
    fixtureImport: '',
    generatedAtIso: '',
    kekCheck: '',
    migrations: '',
    outputPath: '',
    r2RestoreDrill: '',
    reconciliation: '',
    resources: '',
    signerCustody: '',
    smoke: '',
  }, evidenceFlagFields);
}

function normalizeOptions(input) {
  const options = {
    generatedAtIso: normalizeGeneratedAtIso(input.generatedAtIso),
    outputPath: resolvePackagePath(input.outputPath, defaultOutputPath),
  };
  for (const spec of evidenceSpecs) {
    options[spec.flag] = resolveRequiredPackagePath(input[spec.flag], `--${cliFlag(spec)}`);
  }
  return options;
}

function readManifest(input) {
  if (!existsSync(input.path)) {
    input.errors.push(`${input.id}: manifest does not exist at ${relativeToRepo(input.path)}`);
    return null;
  }
  const source = readFileSync(input.path, 'utf8');
  try {
    const parsed = JSON.parse(source);
    if (isJsonRecord(parsed)) return parsed;
  } catch {
    input.errors.push(`${input.id}: manifest is not valid JSON`);
    return null;
  }
  input.errors.push(`${input.id}: manifest root must be a JSON object`);
  return null;
}

function validateVersionMode(input) {
  if (input.manifest.version !== input.spec.version) {
    input.errors.push(
      `${input.spec.id}: expected version ${input.spec.version}, got ${String(input.manifest.version)}`,
    );
  }
  if (input.manifest.mode !== 'remote') {
    input.errors.push(`${input.spec.id}: evidence must come from mode=remote`);
  }
}

function validateResourceInventory(input) {
  const checks = readArray(input.manifest.checks);
  requireNonEmpty(input, checks, 'checks');
  validateUniqueFieldValues({
    id: input.id,
    errors: input.errors,
    values: checks,
    fieldName: 'checks',
  });
  validateResourceInventoryCommandCoverage(input, checks);
  validateRequiredIds({
    id: input.id,
    errors: input.errors,
    values: checks,
    fieldName: 'checks',
    requiredIds: requiredResourceInventoryCheckIds,
  });
  for (const check of checks) {
    requireStatusZero(input, check, `checks.${String(check?.id || check?.target || 'unknown')}`);
    if (!isJsonRecord(check.json)) {
      input.errors.push(`${input.id}: remote inventory check ${String(check?.id || '')} lacks JSON metadata`);
    }
  }
  validateResourceInventoryD1Metadata(input, checks);
  validateResourceInventorySignerIsolation(input);
  validateResourceInventoryGatewaySignerBindings(input);
}

function validateResourceInventoryCommandCoverage(input, checks) {
  const commands = readArray(input.manifest.commands);
  if (commands.length === 0) {
    input.errors.push(`${input.id}: commands must be non-empty`);
    return;
  }
  if (checks.length !== commands.length) {
    input.errors.push(
      `${input.id}: check command count ${checks.length} does not match planned command count ${commands.length}`,
    );
  }
  validateUniqueFieldValues({
    id: input.id,
    errors: input.errors,
    values: commands,
    fieldName: 'commands',
  });
  validateRequiredIds({
    id: input.id,
    errors: input.errors,
    values: commands,
    fieldName: 'commands',
    requiredIds: requiredResourceInventoryCheckIds,
  });
  const plannedCommands = new Map();
  for (const command of commands) {
    const commandId = normalizeString(command?.id);
    if (!commandId) {
      input.errors.push(`${input.id}: commands entry is missing id`);
      continue;
    }
    const commandText = normalizeString(command?.command);
    if (!commandText) {
      input.errors.push(`${input.id}: commands.${commandId}.command must be present`);
      continue;
    }
    plannedCommands.set(commandId, commandText);
  }

  for (const check of checks) {
    const checkId = normalizeString(check?.id);
    if (!checkId) {
      input.errors.push(`${input.id}: checks entry is missing id`);
      continue;
    }
    if (!plannedCommands.has(checkId)) {
      input.errors.push(`${input.id}: missing planned command for check ${checkId}`);
      continue;
    }
    validateExecutedCommandMatchesPlan({
      id: input.id,
      errors: input.errors,
      index: checkId,
      plannedCommand: plannedCommands.get(checkId),
      executedCommand: normalizeString(check?.command),
    });
  }
}

function validateResourceInventoryD1Metadata(input, checks) {
  const consoleDatabaseId = requireResourceD1DatabaseId({
    input,
    workerFieldName: 'consoleWorker',
    binding: 'CONSOLE_DB',
  });
  const relayConsoleDatabaseId = requireResourceD1DatabaseId({
    input,
    workerFieldName: 'gatewayWorker',
    binding: 'CONSOLE_DB',
  });
  const signerDatabaseId = requireResourceD1DatabaseId({
    input,
    workerFieldName: 'gatewayWorker',
    binding: 'SIGNER_DB',
  });

  if (consoleDatabaseId && relayConsoleDatabaseId && consoleDatabaseId !== relayConsoleDatabaseId) {
    input.errors.push(
      `resource_inventory: gatewayWorker CONSOLE_DB databaseId ${relayConsoleDatabaseId} must match consoleWorker CONSOLE_DB ${consoleDatabaseId}`,
    );
  }

  validateRemoteD1InfoDatabaseId({
    input,
    checks,
    checkId: 'console_d1_info',
    binding: 'CONSOLE_DB',
    expectedDatabaseId: consoleDatabaseId,
  });
  validateRemoteD1InfoDatabaseId({
    input,
    checks,
    checkId: 'signer_d1_info',
    binding: 'SIGNER_DB',
    expectedDatabaseId: signerDatabaseId,
  });
}

function validateResourceInventorySignerIsolation(input) {
  const consoleWorker = resourceInventoryWorker(input.manifest, 'consoleWorker');
  if (!consoleWorker) return;
  validateForbiddenResourceBindings({
    id: input.id,
    errors: input.errors,
    workerFieldName: 'consoleWorker',
    resourceFieldName: 'd1Databases',
    bindingFieldName: 'binding',
    bindings: readArray(consoleWorker.d1Databases),
    forbiddenBindings: signerOnlyConsoleD1Bindings,
  });
  validateForbiddenResourceBindings({
    id: input.id,
    errors: input.errors,
    workerFieldName: 'consoleWorker',
    resourceFieldName: 'durableObjects',
    bindingFieldName: 'name',
    bindings: readArray(consoleWorker.durableObjects),
    forbiddenBindings: signerOnlyConsoleDurableObjectBindings,
  });
  validateConsoleDoesNotReceiveSignerKeks(input, consoleWorker);
}

function validateResourceInventoryGatewaySignerBindings(input) {
  const gatewayWorker = resourceInventoryWorker(input.manifest, 'gatewayWorker');
  if (!gatewayWorker) return;
  validateRequiredResourceBindings({
    id: input.id,
    errors: input.errors,
    workerFieldName: 'gatewayWorker',
    resourceFieldName: 'durableObjects',
    bindingFieldName: 'name',
    bindings: readArray(gatewayWorker.durableObjects),
    requiredBindings: requiredGatewayDurableObjectBindings,
  });
  validateGatewayReceivesConfiguredSignerKeks(input, gatewayWorker);
}

function validateForbiddenResourceBindings(input) {
  const forbidden = new Set(input.forbiddenBindings);
  for (const binding of input.bindings) {
    const name = normalizeString(binding?.[input.bindingFieldName]);
    if (!forbidden.has(name)) continue;
    input.errors.push(
      `${input.id}: resources.${input.workerFieldName}.${input.resourceFieldName} must not include signer-only binding ${name}`,
    );
  }
}

function validateRequiredResourceBindings(input) {
  const present = new Set();
  for (const binding of input.bindings) {
    const name = normalizeString(binding?.[input.bindingFieldName]);
    if (name) present.add(name);
  }
  for (const required of input.requiredBindings) {
    if (present.has(required)) continue;
    input.errors.push(
      `${input.id}: resources.${input.workerFieldName}.${input.resourceFieldName} missing ${required}`,
    );
  }
}

function validateConsoleDoesNotReceiveSignerKeks(input, consoleWorker) {
  const signerKekIds = resourceInventorySignerKekIds(input.manifest);
  for (const secret of readArray(consoleWorker.secretsStoreSecrets)) {
    const binding = normalizeString(secret?.binding);
    const secretName = normalizeString(secret?.secretName);
    if (binding.startsWith('SIGNING_ROOT_KEK')) {
      input.errors.push(
        `${input.id}: resources.consoleWorker.secretsStoreSecrets must not include signer KEK binding ${binding}`,
      );
    }
    if (signerKekIds.has(secretName)) {
      input.errors.push(
        `${input.id}: resources.consoleWorker.secretsStoreSecrets must not include signer KEK secret ${secretName}`,
      );
    }
  }
}

function validateGatewayReceivesConfiguredSignerKeks(input, gatewayWorker) {
  const signerKekIds = resourceInventorySignerKekIds(input.manifest);
  const gatewaySecretNames = new Set();
  for (const secret of readArray(gatewayWorker.secretsStoreSecrets)) {
    const secretName = normalizeString(secret?.secretName);
    if (secretName) gatewaySecretNames.add(secretName);
  }
  for (const kekId of signerKekIds) {
    if (gatewaySecretNames.has(kekId)) continue;
    input.errors.push(
      `${input.id}: resources.gatewayWorker.secretsStoreSecrets missing signer KEK secret ${kekId}`,
    );
  }
}

function resourceInventorySignerKekIds(manifest) {
  const tenant = resourceInventoryTenant(manifest);
  const ids = new Set();
  for (const id of readArray(tenant?.signingRootKekIds)) {
    const normalized = normalizeString(id);
    if (normalized) ids.add(normalized);
  }
  return ids;
}

function requireResourceD1DatabaseId(input) {
  const worker = resourceInventoryWorker(input.input.manifest, input.workerFieldName);
  if (!worker) {
    input.input.errors.push(`resource_inventory: resources.${input.workerFieldName} must be present`);
    return '';
  }

  const database = resourceD1DatabaseByBinding(worker, input.binding);
  if (!database) {
    input.input.errors.push(
      `resource_inventory: resources.${input.workerFieldName}.d1Databases missing ${input.binding}`,
    );
    return '';
  }

  const databaseId = normalizeString(database.databaseId);
  if (!databaseId) {
    input.input.errors.push(
      `resource_inventory: resources.${input.workerFieldName}.d1Databases.${input.binding}.databaseId must be present`,
    );
  }
  return databaseId;
}

function validateRemoteD1InfoDatabaseId(input) {
  if (!input.expectedDatabaseId) return;
  const check = findResultById(input.checks, input.checkId);
  if (!check) return;
  const actualDatabaseId = d1InfoDatabaseId(check.json);
  if (!actualDatabaseId) {
    input.input.errors.push(
      `resource_inventory: checks.${input.checkId}.json must include a D1 database id for ${input.binding}`,
    );
    return;
  }
  if (actualDatabaseId === input.expectedDatabaseId) return;
  input.input.errors.push(
    `resource_inventory: checks.${input.checkId}.json database id ${actualDatabaseId} must match ${input.binding} ${input.expectedDatabaseId}`,
  );
}

function resourceInventoryWorker(manifest, workerFieldName) {
  const resources = recordOrNull(manifest.resources);
  return recordOrNull(resources?.[workerFieldName]);
}

function resourceD1DatabaseByBinding(worker, binding) {
  for (const database of readArray(worker.d1Databases)) {
    if (normalizeString(database?.binding) === binding) return database;
  }
  return null;
}

function d1InfoDatabaseId(json) {
  const record = recordOrNull(json);
  if (!record) return '';
  return (
    normalizeString(record.uuid) ||
    normalizeString(record.databaseId) ||
    normalizeString(record.database_id) ||
    normalizeString(record.id)
  );
}

function validateKekCheck(input) {
  const checks = readArray(input.manifest.checks);
  requireNonEmpty(input, checks, 'checks');
  const configuredKeks = readArray(input.manifest.keks);
  requireNonEmpty(input, configuredKeks, 'keks');
  validateKekCheckCommandCoverage(input, checks, configuredKeks);
  const presentSecretNames = new Set();
  for (const check of checks) {
    requireStatusZero(input, check, `checks.${String(check?.storeId || 'unknown')}`);
    const checkSecretNames = readArray(check?.presentSecretNames);
    if (checkSecretNames.length === 0) {
      input.errors.push(`${input.id}: KEK metadata check for ${String(check?.storeId || '')} found no secrets`);
    }
    for (const secretName of checkSecretNames) presentSecretNames.add(String(secretName || ''));
  }
  for (const kek of configuredKeks) {
    const secretName = normalizeString(kek?.secretName);
    if (!secretName) {
      input.errors.push(`${input.id}: configured KEK is missing secretName`);
      continue;
    }
    if (!presentSecretNames.has(secretName)) {
      input.errors.push(`${input.id}: configured KEK ${secretName} was not found in Secrets Store evidence`);
    }
  }
}

function validateKekCheckCommandCoverage(input, checks, configuredKeks) {
  const commands = readArray(input.manifest.commands);
  if (commands.length === 0) {
    input.errors.push(`${input.id}: commands must be non-empty`);
    return;
  }
  if (commands.length !== checks.length) {
    input.errors.push(
      `${input.id}: check command count ${checks.length} does not match planned command count ${commands.length}`,
    );
  }

  const expectedStoreIds = new Set();
  for (const kek of configuredKeks) {
    const storeId = normalizeString(kek?.storeId);
    if (!storeId) {
      input.errors.push(`${input.id}: configured KEK is missing storeId`);
      continue;
    }
    expectedStoreIds.add(storeId);
  }

  const checkedStoreIds = new Set();
  const commandCount = Math.min(commands.length, checks.length);
  for (let index = 0; index < commandCount; index += 1) {
    const check = checks[index];
    const storeId = normalizeString(check?.storeId);
    if (!storeId) {
      input.errors.push(`${input.id}: checks[${index}].storeId must be present`);
      continue;
    }
    checkedStoreIds.add(storeId);
    if (!expectedStoreIds.has(storeId)) {
      input.errors.push(`${input.id}: checks[${index}].storeId ${storeId} is not configured`);
    }
    validatePlannedCommandMatchesEvidence({
      id: input.id,
      errors: input.errors,
      label: `checks[${index}]`,
      plannedCommand: plannedCommandText(commands[index]),
      evidenceCommand: normalizeString(check?.command),
    });
    validateCommandMentionsStoreId({
      id: input.id,
      errors: input.errors,
      label: `checks[${index}].command`,
      command: check?.command,
      storeId,
    });
  }

  for (const storeId of expectedStoreIds) {
    if (checkedStoreIds.has(storeId)) continue;
    input.errors.push(`${input.id}: missing Secrets Store check evidence for ${storeId}`);
  }
}

function validateCommandMentionsStoreId(input) {
  const command = normalizeString(input.command);
  if (!command) return;
  if (command.includes(input.storeId)) return;
  input.errors.push(`${input.id}: ${input.label} must reference store ${input.storeId}`);
}

function validateExecutedStatuses(input) {
  const executed = readArray(input.manifest.executed);
  requireNonEmpty(input, executed, 'executed');
  for (const result of executed) {
    requireStatusZero(input, result, executedLabel(result));
  }
}

function validateMigration(input) {
  validateExecutedStatuses(input);
  validateExecutedCommandCoverage(input);
  validateUniquePairKeys({
    id: input.id,
    errors: input.errors,
    values: readArray(input.manifest.commands),
    fieldName: 'commands',
  });
  validateUniquePairKeys({
    id: input.id,
    errors: input.errors,
    values: readArray(input.manifest.executed),
    fieldName: 'executed',
  });
  validateRequiredPairKeys({
    id: input.id,
    errors: input.errors,
    values: readArray(input.manifest.executed),
    fieldName: 'executed',
    requiredKeys: requiredMigrationTargetActionPairs,
  });
}

function validateFixtureImport(input) {
  validateExecutedStatuses(input);
  validateUniqueFieldValues({
    id: input.id,
    errors: input.errors,
    values: readArray(input.manifest.fixtures),
    fieldName: 'fixtures',
    valueFieldName: 'logicalName',
  });
  validateRequiredIds({
    id: input.id,
    errors: input.errors,
    values: readArray(input.manifest.fixtures),
    fieldName: 'fixtures',
    requiredIds: requiredFixtureLogicalNames,
    idFieldName: 'logicalName',
  });
  validateExecutedCommandCoverage(input);
}

function executedLabel(result) {
  return `executed.${String(result?.action || result?.command || 'unknown')}`;
}

function validateBookmarkBeforeFixtureImport(input) {
  validateBookmark(input, 'before_fixture_import');
}

function validateBookmarkBeforeRouteSwitch(input) {
  validateBookmark(input, 'before_route_switch');
}

function validateBookmark(input, expectedPurpose) {
  if (input.manifest.purpose !== expectedPurpose) {
    input.errors.push(`${input.id}: expected purpose ${expectedPurpose}, got ${String(input.manifest.purpose)}`);
  }
  validateExecutedStatuses(input);
  validateExecutedCommandCoverage(input);
  const evidence = readArray(input.manifest.bookmarkEvidence);
  requireNonEmpty(input, evidence, 'bookmarkEvidence');
  validateUniqueFieldValues({
    id: input.id,
    errors: input.errors,
    values: evidence,
    fieldName: 'bookmarkEvidence',
    valueFieldName: 'logicalName',
  });
  validateRequiredIds({
    id: input.id,
    errors: input.errors,
    values: evidence,
    fieldName: 'bookmarkEvidence',
    requiredIds: requiredBookmarkLogicalNames,
    idFieldName: 'logicalName',
  });
  validateBookmarkEvidencePayloads(input, evidence);
}

function validateBookmarkEvidencePayloads(input, evidence) {
  for (const logicalName of requiredBookmarkLogicalNames) {
    const item = findRecordByField(evidence, 'logicalName', logicalName);
    if (!item) continue;
    validateBookmarkEvidencePath({
      id: input.id,
      errors: input.errors,
      manifest: input.manifest,
      logicalName,
      path: item.path,
    });
    validateBookmarkEvidenceJson({
      id: input.id,
      errors: input.errors,
      logicalName,
      json: item.json,
    });
  }
}

function validateBookmarkEvidencePath(input) {
  const actualPath = normalizeString(input.path);
  const expectedPath = expectedBookmarkArtifactPath(input.manifest, input.logicalName);
  if (!actualPath) {
    input.errors.push(`${input.id}: bookmarkEvidence.${input.logicalName}.path must be present`);
    return;
  }
  if (!expectedPath) {
    input.errors.push(`${input.id}: artifacts.${input.logicalName}BookmarkPath must be present`);
    return;
  }
  if (actualPath === expectedPath) return;
  input.errors.push(
    `${input.id}: bookmarkEvidence.${input.logicalName}.path is ${actualPath}, expected ${expectedPath}`,
  );
}

function expectedBookmarkArtifactPath(manifest, logicalName) {
  const artifacts = recordOrNull(manifest.artifacts);
  if (logicalName === 'console') return normalizeString(artifacts?.consoleBookmarkPath);
  if (logicalName === 'signer') return normalizeString(artifacts?.signerBookmarkPath);
  return '';
}

function validateBookmarkEvidenceJson(input) {
  const json = recordOrNull(input.json);
  if (!json) {
    input.errors.push(`${input.id}: bookmarkEvidence.${input.logicalName}.json must be a JSON object`);
    return;
  }
  const bookmark = d1TimeTravelBookmarkValue(json);
  if (bookmark) return;
  input.errors.push(`${input.id}: bookmarkEvidence.${input.logicalName}.json must include a bookmark`);
}

function validateOkResults(input, fieldName) {
  const results = readArray(input.manifest[fieldName]);
  requireNonEmpty(input, results, fieldName);
  for (const result of results) {
    if (result?.ok !== true) {
      input.errors.push(`${input.id}: ${fieldName}.${String(result?.id || 'unknown')} is not ok`);
    }
  }
}

function validateSmoke(input) {
  const endpoints = readArray(input.manifest.endpoints);
  const checks = readArray(input.manifest.checks);
  validateHttpPlanCoverage({
    id: input.id,
    errors: input.errors,
    planValues: endpoints,
    planFieldName: 'endpoints',
    resultValues: checks,
    resultFieldName: 'checks',
    requiredIds: requiredSmokeCheckIds,
  });
  validateOkResults(input, 'checks');
  validateRequiredOkResultIds({
    id: input.id,
    manifest: input.manifest,
    errors: input.errors,
    fieldName: 'checks',
    requiredIds: requiredSmokeCheckIds,
  });
  validateHttpsResultUrls(input, 'checks');
  validateExpectedResultPaths({
    id: input.id,
    manifest: input.manifest,
    errors: input.errors,
    fieldName: 'checks',
    expectedPathsById: smokeExpectedPathsById,
  });
  validateExpectedResultStatuses({
    id: input.id,
    manifest: input.manifest,
    errors: input.errors,
    fieldName: 'checks',
    expectedStatusesById: smokeExpectedStatusesById,
  });
  validateSmokeWorkerOriginSeparation(input);
}

function validateSmokeWorkerOriginSeparation(input) {
  const checks = readArray(input.manifest.checks);
  const consoleOrigin = resultOrigin(checks, 'console_readyz');
  const gatewayOrigin = resultOrigin(checks, 'router_api_readyz');
  if (!consoleOrigin || !gatewayOrigin || consoleOrigin !== gatewayOrigin) return;
  input.errors.push(
    `${input.id}: console_readyz and router_api_readyz must use distinct Worker origins, got ${consoleOrigin}`,
  );
}

function validateReconciliation(input) {
  const checks = readArray(input.manifest.checks);
  const executed = readArray(input.manifest.executed);
  requireNonEmpty(input, checks, 'checks');
  requireNonEmpty(input, executed, 'executed');
  validateUniqueFieldValues({
    id: input.id,
    errors: input.errors,
    values: checks,
    fieldName: 'checks',
  });
  validateUniqueFieldValues({
    id: input.id,
    errors: input.errors,
    values: executed,
    fieldName: 'executed',
  });
  validateRequiredIds({
    id: input.id,
    errors: input.errors,
    values: checks,
    fieldName: 'checks',
    requiredIds: requiredReconciliationCheckIds,
  });
  validateRequiredIds({
    id: input.id,
    errors: input.errors,
    values: executed,
    fieldName: 'executed',
    requiredIds: requiredReconciliationCheckIds,
  });
  validateReconciliationCommandCoverage(input, checks, executed);
  for (const check of executed) {
    requireStatusZero(input, check, `executed.${String(check?.id || 'unknown')}`);
    if (Number(check?.rowCount) !== 0) {
      input.errors.push(`${input.id}: ${String(check?.id || 'unknown')} returned ${String(check?.rowCount)} mismatch rows`);
    }
  }
}

function validateReconciliationCommandCoverage(input, checks, executed) {
  const checksById = new Map();
  for (const check of checks) {
    const id = normalizeString(check?.id);
    if (!id) {
      input.errors.push(`${input.id}: checks entry is missing id`);
      continue;
    }
    checksById.set(id, check);
  }

  for (const result of executed) {
    const id = normalizeString(result?.id);
    if (!id) {
      input.errors.push(`${input.id}: executed entry is missing id`);
      continue;
    }
    const check = checksById.get(id);
    if (!check) continue;
    validatePlannedCommandMatchesEvidence({
      id: input.id,
      errors: input.errors,
      label: `executed[${id}]`,
      plannedCommand: normalizeString(check.command),
      evidenceCommand: normalizeString(result?.command),
    });
  }
}

function validateSignerCustody(input) {
  const healthChecks = readArray(input.manifest.healthChecks);
  const checks = readArray(input.manifest.checks);
  validateHttpPlanCoverage({
    id: input.id,
    errors: input.errors,
    planValues: signerCustodyPlannedChecks(input.manifest),
    planFieldName: 'plannedChecks',
    resultValues: readArray(input.manifest.results),
    resultFieldName: 'results',
    requiredIds: requiredSignerCustodyResultIds,
  });
  requireNonEmpty(input, healthChecks, 'healthChecks');
  requireNonEmpty(input, checks, 'checks');
  validateOkResults(input, 'results');
  validateRequiredOkResultIds({
    id: input.id,
    manifest: input.manifest,
    errors: input.errors,
    fieldName: 'results',
    requiredIds: requiredSignerCustodyResultIds,
  });
  validateHttpsResultUrls(input, 'results');
  validateExpectedResultPaths({
    id: input.id,
    manifest: input.manifest,
    errors: input.errors,
    fieldName: 'results',
    expectedPathsById: signerCustodyExpectedPathsById,
  });
  validateExpectedResultStatuses({
    id: input.id,
    manifest: input.manifest,
    errors: input.errors,
    fieldName: 'results',
    expectedStatusesById: signerCustodyExpectedStatusesById,
  });
  validateMissingKekFailClosedResult(input);
  validateSignerCustodyBodyRedaction(input);
}

function signerCustodyPlannedChecks(manifest) {
  const checks = [];
  for (const check of readArray(manifest.healthChecks)) checks.push(check);
  for (const check of readArray(manifest.checks)) checks.push(check);
  return checks;
}

function validateHttpPlanCoverage(input) {
  requireNonEmpty({ id: input.id, errors: input.errors }, input.planValues, input.planFieldName);
  if (input.planValues.length !== input.resultValues.length) {
    input.errors.push(
      `${input.id}: ${input.resultFieldName} count ${input.resultValues.length} does not match planned ${input.planFieldName} count ${input.planValues.length}`,
    );
  }
  validateUniqueFieldValues({
    id: input.id,
    errors: input.errors,
    values: input.planValues,
    fieldName: input.planFieldName,
  });
  validateUniqueFieldValues({
    id: input.id,
    errors: input.errors,
    values: input.resultValues,
    fieldName: input.resultFieldName,
  });
  validateRequiredIds({
    id: input.id,
    errors: input.errors,
    values: input.planValues,
    fieldName: input.planFieldName,
    requiredIds: input.requiredIds,
  });

  const planById = new Map();
  for (const plan of input.planValues) {
    const id = normalizeString(plan?.id);
    if (!id) {
      input.errors.push(`${input.id}: ${input.planFieldName} entry is missing id`);
      continue;
    }
    if (planById.has(id)) {
      input.errors.push(`${input.id}: ${input.planFieldName}.${id} is duplicated`);
      continue;
    }
    planById.set(id, plan);
  }

  for (const result of input.resultValues) {
    const resultId = normalizeString(result?.id);
    if (!resultId) {
      input.errors.push(`${input.id}: ${input.resultFieldName} entry is missing id`);
      continue;
    }
    const plan = planById.get(resultId);
    if (!plan) {
      input.errors.push(`${input.id}: missing planned ${input.planFieldName} evidence for ${resultId}`);
      continue;
    }
    validateHttpResultMatchesPlan({
      id: input.id,
      errors: input.errors,
      plan,
      planFieldName: input.planFieldName,
      result,
      resultFieldName: input.resultFieldName,
      resultId,
    });
  }
}

function validateHttpResultMatchesPlan(input) {
  const plannedUrl = normalizeString(input.plan?.url);
  const resultUrl = normalizeString(input.result?.url);
  if (!plannedUrl) {
    input.errors.push(`${input.id}: ${input.planFieldName}.${input.resultId}.url must be present`);
  } else if (!resultUrl) {
    input.errors.push(`${input.id}: ${input.resultFieldName}.${input.resultId}.url must be present`);
  } else if (plannedUrl !== resultUrl) {
    input.errors.push(
      `${input.id}: ${input.resultFieldName}.${input.resultId}.url does not match planned ${input.planFieldName}.${input.resultId}.url`,
    );
  }

  const expectedStatus = Number(input.plan?.expectedStatus);
  const actualStatus = Number(input.result?.status);
  if (!Number.isInteger(expectedStatus)) {
    input.errors.push(`${input.id}: ${input.planFieldName}.${input.resultId}.expectedStatus must be present`);
  } else if (actualStatus !== expectedStatus) {
    input.errors.push(
      `${input.id}: ${input.resultFieldName}.${input.resultId}.status ${String(input.result?.status)} does not match planned ${input.planFieldName}.${input.resultId}.expectedStatus ${expectedStatus}`,
    );
  }
}

function validateMissingKekFailClosedResult(input) {
  const result = findResultById(readArray(input.manifest.results), signerCustodyMissingKekResultId);
  if (!result) return;

  const actualStatus = Number(result.status);
  if (!Number.isInteger(actualStatus) || actualStatus < 400 || actualStatus > 599) {
    input.errors.push(
      `${input.id}: results.${signerCustodyMissingKekResultId}.status must be a 4xx/5xx fail-closed status, got ${String(result.status)}`,
    );
  }

  const body = recordOrNull(result.body);
  if (!body) {
    input.errors.push(`${input.id}: results.${signerCustodyMissingKekResultId}.body must be a JSON object`);
    return;
  }
  if (body.ok !== false) {
    input.errors.push(`${input.id}: results.${signerCustodyMissingKekResultId}.body.ok must be false`);
  }
  if (body.code === signerCustodyMissingKekCode) return;
  input.errors.push(
    `${input.id}: results.${signerCustodyMissingKekResultId}.body.code must be ${signerCustodyMissingKekCode}`,
  );
}

function findResultById(results, id) {
  for (const result of results) {
    if (result?.id === id) return result;
  }
  return null;
}

function findRecordByField(values, fieldName, expectedValue) {
  for (const value of values) {
    if (normalizeString(value?.[fieldName]) === expectedValue) return value;
  }
  return null;
}

function validateSignerCustodyBodyRedaction(input) {
  for (const result of readArray(input.manifest.results)) {
    const resultId = String(result?.id || 'unknown');
    validateSignerCustodyRedactedValue({
      id: input.id,
      errors: input.errors,
      value: result?.body,
      path: `results.${resultId}.body`,
    });
  }
}

function validateSignerCustodyRedactedValue(input) {
  if (Array.isArray(input.value)) {
    for (let index = 0; index < input.value.length; index += 1) {
      validateSignerCustodyRedactedValue({
        id: input.id,
        errors: input.errors,
        value: input.value[index],
        path: `${input.path}[${index}]`,
      });
    }
    return;
  }
  if (!isJsonRecord(input.value)) return;

  for (const [fieldName, value] of Object.entries(input.value)) {
    const childPath = `${input.path}.${fieldName}`;
    if (signerCustodySensitiveBodyFieldNames.has(sensitiveBodyFieldKey(fieldName))) {
      if (value === '<redacted>') continue;
      input.errors.push(`${input.id}: ${childPath} must be redacted`);
      continue;
    }
    validateSignerCustodyRedactedValue({
      id: input.id,
      errors: input.errors,
      value,
      path: childPath,
    });
  }
}

function sensitiveBodyFieldKey(input) {
  return String(input).toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function validateHttpsResultUrls(input, fieldName) {
  for (const result of readArray(input.manifest[fieldName])) {
    const label = `${fieldName}.${String(result?.id || 'unknown')}.url`;
    const value = normalizeString(result?.url);
    if (!value) {
      input.errors.push(`${input.id}: ${label} must be present`);
      continue;
    }
    if (isHttpsUrl(value)) continue;
    input.errors.push(`${input.id}: ${label} must be an HTTPS URL`);
  }
}

function validateExpectedResultPaths(input) {
  for (const result of readArray(input.manifest[input.fieldName])) {
    const resultId = String(result?.id || 'unknown');
    const expectedPath = input.expectedPathsById[resultId] || '';
    if (!expectedPath) continue;
    validateEvidenceUrlPath({
      id: input.id,
      errors: input.errors,
      label: `${input.fieldName}.${resultId}.url`,
      value: result?.url,
      expectedPath,
    });
  }
}

function validateEvidenceUrlPath(input) {
  const value = normalizeString(input.value);
  if (!value) return;
  const parsed = urlOrNull(value);
  if (!parsed) return;
  if (parsed.pathname === input.expectedPath && !parsed.search && !parsed.hash) return;
  const actualPath = `${parsed.pathname}${parsed.search}${parsed.hash}`;
  input.errors.push(
    `${input.id}: ${input.label} uses path ${actualPath}, expected ${input.expectedPath}`,
  );
}

function validateExpectedResultStatuses(input) {
  for (const result of readArray(input.manifest[input.fieldName])) {
    const resultId = String(result?.id || 'unknown');
    const expectedStatus = input.expectedStatusesById[resultId];
    if (expectedStatus === undefined) continue;
    const actualStatus = Number(result?.status);
    if (actualStatus === expectedStatus) continue;
    input.errors.push(
      `${input.id}: ${input.fieldName}.${resultId}.status is ${String(result?.status)}, expected ${expectedStatus}`,
    );
  }
}

function validateRequiredOkResultIds(input) {
  validateRequiredIds({
    id: input.id,
    errors: input.errors,
    values: readArray(input.manifest[input.fieldName]),
    fieldName: input.fieldName,
    requiredIds: input.requiredIds,
  });
}

function validateR2RestoreDrill(input) {
  validateExecutedStatuses(input);
  validateExecutedCommandCoverage(input);
  validateR2RestoreIntegrityChecks(input);
  const artifactEvidence = readArray(input.manifest.artifactEvidence);
  requireNonEmpty(input, artifactEvidence, 'artifactEvidence');
  validateUniqueArtifactEvidencePaths(input, artifactEvidence);
  const artifacts = recordOrNull(input.manifest.artifacts);
  const requiredPaths = [
    normalizeString(artifacts?.consoleExportPath),
    normalizeString(artifacts?.signerExportPath),
    normalizeString(artifacts?.consoleRestorePath),
    normalizeString(artifacts?.signerRestorePath),
  ];
  const paths = artifactPathSet(artifactEvidence);
  for (const requiredPath of requiredPaths) {
    if (!requiredPath) {
      input.errors.push(`${input.id}: artifacts must include console/signer export and restore paths`);
      continue;
    }
    if (paths.has(requiredPath)) {
      validateR2ArtifactMetadata({
        id: input.id,
        errors: input.errors,
        artifact: findRecordByField(artifactEvidence, 'path', requiredPath),
        path: requiredPath,
      });
      continue;
    }
    input.errors.push(`${input.id}: missing artifact evidence for ${requiredPath}`);
  }
  validateR2ArtifactPairHashMatch({
    id: input.id,
    errors: input.errors,
    artifactEvidence,
    sourcePath: normalizeString(artifacts?.consoleExportPath),
    restorePath: normalizeString(artifacts?.consoleRestorePath),
    label: 'console',
  });
  validateR2ArtifactPairHashMatch({
    id: input.id,
    errors: input.errors,
    artifactEvidence,
    sourcePath: normalizeString(artifacts?.signerExportPath),
    restorePath: normalizeString(artifacts?.signerRestorePath),
    label: 'signer',
  });
}

function validateR2ArtifactMetadata(input) {
  if (!input.artifact) return;
  const bytes = Number(input.artifact.bytes);
  if (!Number.isSafeInteger(bytes) || bytes <= 0) {
    input.errors.push(`${input.id}: artifactEvidence.${input.path}.bytes must be greater than zero`);
  }
  const sha256 = normalizeString(input.artifact.sha256);
  if (isSha256Hex(sha256)) return;
  input.errors.push(`${input.id}: artifactEvidence.${input.path}.sha256 must be a SHA-256 hex digest`);
}

function validateUniqueArtifactEvidencePaths(input, artifactEvidence) {
  const paths = new Set();
  for (const artifact of artifactEvidence) {
    const path = normalizeString(artifact?.path);
    if (!path) {
      input.errors.push(`${input.id}: artifactEvidence entry is missing path`);
      continue;
    }
    if (paths.has(path)) {
      input.errors.push(`${input.id}: artifactEvidence.${path} is duplicated`);
      continue;
    }
    paths.add(path);
  }
}

function validateR2ArtifactPairHashMatch(input) {
  if (!input.sourcePath || !input.restorePath) return;
  const sourceArtifact = findRecordByField(input.artifactEvidence, 'path', input.sourcePath);
  const restoreArtifact = findRecordByField(input.artifactEvidence, 'path', input.restorePath);
  if (!sourceArtifact || !restoreArtifact) return;
  const sourceHash = normalizeString(sourceArtifact.sha256);
  const restoreHash = normalizeString(restoreArtifact.sha256);
  if (!isSha256Hex(sourceHash) || !isSha256Hex(restoreHash)) return;
  if (sourceHash === restoreHash) return;
  input.errors.push(
    `${input.id}: ${input.label} restore artifact hash ${restoreHash} must match export artifact hash ${sourceHash}`,
  );
}

function isSha256Hex(value) {
  return /^[a-f0-9]{64}$/i.test(value);
}

function validateR2RestoreIntegrityChecks(input) {
  const artifacts = recordOrNull(input.manifest.artifacts);
  const consoleRestoreDatabaseName = requiredManifestString({
    id: input.id,
    errors: input.errors,
    fieldName: 'artifacts.consoleRestoreDatabaseName',
    value: artifacts?.consoleRestoreDatabaseName,
  });
  const signerRestoreDatabaseName = requiredManifestString({
    id: input.id,
    errors: input.errors,
    fieldName: 'artifacts.signerRestoreDatabaseName',
    value: artifacts?.signerRestoreDatabaseName,
  });
  const integrityTargets = {
    console: false,
    signer: false,
  };
  const executed = readArray(input.manifest.executed);
  for (let index = 0; index < executed.length; index += 1) {
    const result = executed[index];
    if (!isIntegrityCheckCommand(result?.command)) continue;
    const target = restoreIntegrityCheckTarget({
      command: result?.command,
      consoleRestoreDatabaseName,
      signerRestoreDatabaseName,
    });
    if (!target) {
      input.errors.push(
        `${input.id}: executed[${index}].command must target console or signer restore database for integrity_check`,
      );
      continue;
    }
    integrityTargets[target] = true;
    validateIntegrityCheckStdout({
      id: input.id,
      errors: input.errors,
      label: `executed[${index}]`,
      stdout: result?.stdout,
    });
  }
  if (!integrityTargets.console) {
    input.errors.push(`${input.id}: missing console restore integrity-check command evidence`);
  }
  if (!integrityTargets.signer) {
    input.errors.push(`${input.id}: missing signer restore integrity-check command evidence`);
  }
}

function isIntegrityCheckCommand(command) {
  return normalizeString(command).includes('PRAGMA integrity_check');
}

function restoreIntegrityCheckTarget(input) {
  const command = normalizeString(input.command);
  if (input.consoleRestoreDatabaseName && command.includes(input.consoleRestoreDatabaseName)) {
    return 'console';
  }
  if (input.signerRestoreDatabaseName && command.includes(input.signerRestoreDatabaseName)) {
    return 'signer';
  }
  return '';
}

function requiredManifestString(input) {
  const value = normalizeString(input.value);
  if (value) return value;
  input.errors.push(`${input.id}: ${input.fieldName} must be present`);
  return '';
}

function validateIntegrityCheckStdout(input) {
  const source = normalizeString(input.stdout);
  if (!source) {
    input.errors.push(`${input.id}: ${input.label}.stdout must include JSON integrity_check output`);
    return;
  }

  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch {
    input.errors.push(`${input.id}: ${input.label}.stdout must be JSON integrity_check output`);
    return;
  }

  const values = d1IntegrityCheckValues(parsed);
  if (values.length === 0) {
    input.errors.push(`${input.id}: ${input.label}.stdout must include an integrity_check result`);
    return;
  }
  for (const value of values) {
    if (value === 'ok') continue;
    input.errors.push(`${input.id}: ${input.label}.integrity_check is ${value}, expected ok`);
  }
}

function validateExecutedCommandCoverage(input) {
  const commands = readArray(input.manifest.commands);
  const executed = readArray(input.manifest.executed);
  if (commands.length === 0) {
    input.errors.push(`${input.id}: commands must be non-empty`);
    return;
  }
  if (executed.length !== commands.length) {
    input.errors.push(
      `${input.id}: executed command count ${executed.length} does not match planned command count ${commands.length}`,
    );
  }
  const commandCount = Math.min(commands.length, executed.length);
  for (let index = 0; index < commandCount; index += 1) {
    validateExecutedCommandMatchesPlan({
      id: input.id,
      errors: input.errors,
      index,
      plannedCommand: plannedCommandText(commands[index]),
      executedCommand: normalizeString(executed[index]?.command),
    });
  }
}

function validateExecutedCommandMatchesPlan(input) {
  validatePlannedCommandMatchesEvidence({
    id: input.id,
    errors: input.errors,
    label: `executed[${input.index}]`,
    plannedCommand: input.plannedCommand,
    evidenceCommand: input.executedCommand,
  });
}

function validatePlannedCommandMatchesEvidence(input) {
  if (!input.plannedCommand) {
    input.errors.push(`${input.id}: ${input.label} planned command must be present`);
    return;
  }
  if (!input.evidenceCommand) {
    input.errors.push(`${input.id}: ${input.label}.command must be present`);
    return;
  }
  if (input.evidenceCommand === input.plannedCommand) return;
  input.errors.push(`${input.id}: ${input.label}.command does not match planned command`);
}

function plannedCommandText(input) {
  if (typeof input === 'string') return normalizeString(input);
  const record = recordOrNull(input);
  return normalizeString(record?.command);
}

function validateRequiredIds(input) {
  const actualIds = new Set();
  const idFieldName = input.idFieldName || 'id';
  for (const value of input.values) actualIds.add(String(value?.[idFieldName] || ''));
  for (const requiredId of input.requiredIds) {
    if (actualIds.has(requiredId)) continue;
    input.errors.push(`${input.id}: missing ${requiredId} evidence in ${input.fieldName}`);
  }
}

function validateUniqueFieldValues(input) {
  const fieldName = input.valueFieldName || 'id';
  const seen = new Set();
  for (const value of input.values) {
    const fieldValue = normalizeString(value?.[fieldName]);
    if (!fieldValue) continue;
    if (!seen.has(fieldValue)) {
      seen.add(fieldValue);
      continue;
    }
    input.errors.push(`${input.id}: ${input.fieldName}.${fieldValue} is duplicated`);
  }
}

function validateRequiredPairKeys(input) {
  const actualKeys = new Set();
  for (const value of input.values) {
    actualKeys.add(`${String(value?.target || '')}:${String(value?.action || '')}`);
  }
  for (const requiredKey of input.requiredKeys) {
    if (actualKeys.has(requiredKey)) continue;
    input.errors.push(`${input.id}: missing ${requiredKey} evidence in ${input.fieldName}`);
  }
}

function validateUniquePairKeys(input) {
  const seen = new Set();
  for (const value of input.values) {
    const target = normalizeString(value?.target);
    const action = normalizeString(value?.action);
    if (!target || !action) continue;
    const key = `${target}:${action}`;
    if (!seen.has(key)) {
      seen.add(key);
      continue;
    }
    input.errors.push(`${input.id}: ${input.fieldName}.${key} is duplicated`);
  }
}

function artifactPathSet(artifactEvidence) {
  const paths = new Set();
  for (const artifact of artifactEvidence) paths.add(String(artifact?.path || ''));
  return paths;
}

function validateManifestConsistency(input) {
  validateSharedFieldConsistency({
    manifestsById: input.manifestsById,
    errors: input.errors,
    ids: environmentEvidenceIds,
    fieldName: 'environmentName',
  });
  validateSharedFieldConsistency({
    manifestsById: input.manifestsById,
    errors: input.errors,
    ids: consoleConfigEvidenceIds,
    fieldName: 'consoleConfigPath',
  });
  validateSharedFieldConsistency({
    manifestsById: input.manifestsById,
    errors: input.errors,
    ids: gatewayConfigEvidenceIds,
    fieldName: 'gatewayConfigPath',
  });
  validateTenantConsistency(input);
  validateKekConfigConsistency(input);
  validateGatewayOriginConsistency(input);
  validateRunOrder(input);
}

function validateSharedFieldConsistency(input) {
  let expectedValue = '';
  let expectedId = '';
  for (const id of input.ids) {
    const manifest = input.manifestsById.get(id);
    if (!manifest) continue;
    const value = normalizeString(manifest[input.fieldName]);
    if (!value) {
      input.errors.push(`${id}: ${input.fieldName} must be present`);
      continue;
    }
    if (!expectedValue) {
      expectedValue = value;
      expectedId = id;
      continue;
    }
    if (value !== expectedValue) {
      input.errors.push(
        `${input.fieldName} mismatch: ${id} uses ${value}, expected ${expectedValue} from ${expectedId}`,
      );
    }
  }
}

function validateTenantConsistency(input) {
  const resourceInventory = input.manifestsById.get('resource_inventory');
  const reconciliation = input.manifestsById.get('d1_reconciliation');
  if (!resourceInventory || !reconciliation) return;

  const resourceTenant = resourceInventoryTenant(resourceInventory);
  const reconciliationTenant = recordOrNull(reconciliation.tenant);
  for (const fieldName of tenantFieldNames) {
    const resourceValue = normalizeString(resourceTenant?.[fieldName]);
    const reconciliationValue = normalizeString(reconciliationTenant?.[fieldName]);
    if (!resourceValue) {
      input.errors.push(`resource_inventory: resources.gatewayWorker.stagingVars.${fieldName} must be present`);
      continue;
    }
    if (!reconciliationValue) {
      input.errors.push(`d1_reconciliation: tenant.${fieldName} must be present`);
      continue;
    }
    if (resourceValue !== reconciliationValue) {
      input.errors.push(
        `tenant ${fieldName} mismatch: d1_reconciliation uses ${reconciliationValue}, expected ${resourceValue} from resource_inventory`,
      );
    }
  }
}

function validateKekConfigConsistency(input) {
  const resourceInventory = input.manifestsById.get('resource_inventory');
  const kekCheck = input.manifestsById.get('hosted_signer_kek_metadata');
  if (!resourceInventory || !kekCheck) return;

  const resourceTenant = resourceInventoryTenant(resourceInventory);
  const provider = normalizeString(resourceTenant?.signingRootKekProvider);
  const configuredKekIds = readArray(resourceTenant?.signingRootKekIds).map(String).filter(Boolean);
  if (!provider) {
    input.errors.push('resource_inventory: resources.gatewayWorker.stagingVars.signingRootKekProvider must be present');
  }
  if (configuredKekIds.length === 0) {
    input.errors.push('resource_inventory: resources.gatewayWorker.stagingVars.signingRootKekIds must be non-empty');
  }

  const presentSecretNames = new Set();
  for (const check of readArray(kekCheck.checks)) {
    for (const secretName of readArray(check?.presentSecretNames)) {
      presentSecretNames.add(String(secretName || ''));
    }
  }
  for (const kekId of configuredKekIds) {
    if (!presentSecretNames.has(kekId)) {
      input.errors.push(`hosted_signer_kek_metadata: missing Secrets Store evidence for configured KEK ${kekId}`);
    }
  }
}

function validateGatewayOriginConsistency(input) {
  const smoke = input.manifestsById.get('staging_smoke');
  const signerCustody = input.manifestsById.get('signer_custody');
  if (!smoke) return;

  const expectedOrigin = gatewayOriginFromSmoke(smoke);
  if (!expectedOrigin) return;

  for (const check of readArray(smoke.checks)) {
    const checkId = String(check?.id || '');
    if (!gatewaySmokeCheckIds.includes(checkId)) continue;
    validateEvidenceUrlOrigin({
      id: 'staging_smoke',
      errors: input.errors,
      label: `checks.${checkId}.url`,
      value: check?.url,
      expectedOrigin,
      expectedSource: 'staging_smoke router_api_readyz',
    });
  }

  if (!signerCustody) return;
  for (const result of readArray(signerCustody.results)) {
    const resultId = String(result?.id || 'unknown');
    validateEvidenceUrlOrigin({
      id: 'signer_custody',
      errors: input.errors,
      label: `results.${resultId}.url`,
      value: result?.url,
      expectedOrigin,
      expectedSource: 'staging_smoke router_api_readyz',
    });
  }
}

function gatewayOriginFromSmoke(manifest) {
  for (const check of readArray(manifest.checks)) {
    if (check?.id !== 'router_api_readyz') continue;
    return urlOrigin(normalizeString(check?.url));
  }
  return '';
}

function resultOrigin(results, id) {
  const result = findResultById(results, id);
  return result ? urlOrigin(normalizeString(result.url)) : '';
}

function validateEvidenceUrlOrigin(input) {
  const value = normalizeString(input.value);
  if (!value) return;
  const actualOrigin = urlOrigin(value);
  if (!actualOrigin || actualOrigin === input.expectedOrigin) return;
  input.errors.push(
    `${input.id}: ${input.label} uses ${actualOrigin}, expected ${input.expectedOrigin} from ${input.expectedSource}`,
  );
}

function urlOrigin(input) {
  const parsed = urlOrNull(input);
  return parsed ? parsed.origin : '';
}

function urlOrNull(input) {
  try {
    return new URL(input);
  } catch {
    return null;
  }
}

function validateRunOrder(input) {
  let previous = null;
  for (const id of orderedRunEvidenceIds) {
    const manifest = input.manifestsById.get(id);
    if (!manifest) continue;
    const current = orderedTimestamp({ id, manifest, errors: input.errors });
    if (!current) continue;
    if (previous && current.epochMs < previous.epochMs) {
      input.errors.push(
        `evidence order mismatch: ${id} at ${current.iso} is before ${previous.id} at ${previous.iso}`,
      );
    }
    previous = current;
  }
}

function orderedTimestamp(input) {
  const fieldName = orderedTimestampField(input.id);
  const value = normalizeString(input.manifest[fieldName]);
  if (!value) {
    input.errors.push(`${input.id}: ${fieldName} must be an ISO timestamp`);
    return null;
  }
  const epochMs = Date.parse(value);
  if (Number.isNaN(epochMs)) {
    input.errors.push(`${input.id}: ${fieldName} must be an ISO timestamp`);
    return null;
  }
  return {
    id: input.id,
    epochMs,
    iso: new Date(epochMs).toISOString(),
  };
}

function orderedTimestampField(id) {
  if (id === 'time_travel_before_fixture_import') return 'timestampIso';
  if (id === 'time_travel_before_route_switch') return 'timestampIso';
  return 'generatedAtIso';
}

function resourceInventoryTenant(manifest) {
  const resources = recordOrNull(manifest.resources);
  const gatewayWorker = recordOrNull(resources?.gatewayWorker);
  return recordOrNull(gatewayWorker?.stagingVars);
}

function requireNonEmpty(input, values, fieldName) {
  if (values.length > 0) return;
  input.errors.push(`${input.id}: ${fieldName} must be non-empty`);
}

function requireStatusZero(input, result, label) {
  if (Number(result?.status) === 0) return;
  input.errors.push(`${input.id}: ${label} has non-zero status ${String(result?.status)}`);
}

function evidenceSummary(input) {
  return {
    id: input.spec.id,
    path: relativeToRepo(input.manifestPath),
    version: input.manifest.version,
    generatedAtIso: normalizeString(input.manifest.generatedAtIso),
  };
}

function evidenceFailureMessage(errors) {
  const lines = ['D1 staging evidence verification failed:'];
  for (const error of errors) lines.push(`- ${error}`);
  return lines.join('\n');
}

function cliFlag(spec) {
  let out = '';
  for (const letter of spec.flag) {
    out += isUppercaseAscii(letter) ? `-${letter.toLowerCase()}` : letter;
  }
  return out;
}

function isUppercaseAscii(letter) {
  return letter >= 'A' && letter <= 'Z';
}

function readArray(input) {
  return Array.isArray(input) ? input : [];
}

function isHttpsUrl(input) {
  let url;
  try {
    url = new URL(input);
  } catch {
    return false;
  }
  return url.protocol === 'https:';
}

function recordOrNull(input) {
  return isJsonRecord(input) ? input : null;
}

if (isDirectInvocation(import.meta.url)) main();
