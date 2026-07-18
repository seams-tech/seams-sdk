#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import {
  isDirectInvocation,
  normalizeConsoleGatewayD1StagingConfig,
  normalizeGeneratedAtIso,
  normalizeString,
  normalizeR2BucketName,
  normalizeStagingOrigin,
  packageRoot,
  parseFlagArgs,
  printD1StagingCliError,
  relativeToRepo,
  repoRoot,
  resolvePackagePath,
  shellArg,
  wranglerCommand,
} from './d1-staging-config.mjs';
import { requireConsoleAndGatewayD1StagingReadiness } from './d1-staging-readiness-check.mjs';

const defaultOutputPath = path.join(repoRoot, 'docs/deployment/refactor-82-staging-log.md');

export function buildD1StagingRunbook(input = {}) {
  const options = normalizeOptions(input);
  const checks = requireConsoleAndGatewayD1StagingReadiness({
    label: 'runbook generation',
    errorFormat: 'profile_config',
    consoleConfigPath: options.consoleConfigPath,
    gatewayConfigPath: options.gatewayConfigPath,
    environmentName: options.environmentName,
  });
  return renderRunbook({
    options,
    checks,
  });
}

export function writeD1StagingRunbook(input = {}) {
  const options = normalizeOptions(input);
  const markdown = buildD1StagingRunbook(options);
  mkdirSync(path.dirname(options.outputPath), { recursive: true });
  writeFileSync(options.outputPath, markdown);
  return {
    outputPath: options.outputPath,
    markdown,
  };
}

function main() {
  try {
    const result = writeD1StagingRunbook(parseArgs(process.argv.slice(2)));
    console.log(`D1 staging runbook written: ${relativeToRepo(result.outputPath)}`);
  } catch (error) {
    printD1StagingCliError(error);
  }
}

function parseArgs(args) {
  return parseFlagArgs(args, {
    consoleConfigPath: '',
    environmentName: 'staging',
    generatedAtIso: '',
    operator: '',
    outputPath: '',
    gatewayConfigPath: '',
    r2Bucket: '',
    consoleOrigin: '',
    gatewayOrigin: '',
  }, {
    '--console-config': 'consoleConfigPath',
    '--console-origin': 'consoleOrigin',
    '--environment': 'environmentName',
    '--generated-at': 'generatedAtIso',
    '--operator': 'operator',
    '--output': 'outputPath',
    '--r2-bucket': 'r2Bucket',
    '--gateway-config': 'gatewayConfigPath',
    '--gateway-origin': 'gatewayOrigin',
  });
}

function normalizeOptions(input) {
  return {
    ...normalizeConsoleGatewayD1StagingConfig(input),
    outputPath: resolvePackagePath(input.outputPath, defaultOutputPath),
    generatedAtIso: normalizeGeneratedAtIso(input.generatedAtIso),
    operator: normalizeString(input.operator) || '<operator>',
    r2Bucket: normalizeR2BucketName(input.r2Bucket),
    consoleOrigin: normalizeStagingOrigin(input.consoleOrigin, '--console-origin'),
    gatewayOrigin: normalizeStagingOrigin(input.gatewayOrigin, '--gateway-origin'),
  };
}

function renderRunbook(input) {
  const lines = [];
  lines.push('# Refactor 82 D1/DO Staging Deployment Log');
  lines.push('');
  lines.push(`Generated: ${input.options.generatedAtIso}`);
  lines.push(`Operator: ${input.options.operator}`);
  lines.push(`Environment: ${input.options.environmentName}`);
  lines.push(`Console config: ${relativeToRepo(input.options.consoleConfigPath)}`);
  lines.push(`Gateway config: ${relativeToRepo(input.options.gatewayConfigPath)}`);
  lines.push('');
  lines.push('Do not record secret values in this file. Record secret names, binding names,');
  lines.push('Cloudflare resource IDs, command output summaries, object keys, bookmarks,');
  lines.push('and pass/fail evidence only.');
  lines.push('');
  appendReadiness(lines, input.checks);
  appendResourceInventory(lines);
  appendCommandSection(lines, 'Preflight', preflightCommands(input.options));
  appendCommandSection(lines, 'Resource Inventory Capture', resourceInventoryCommands());
  appendCommandSection(lines, 'Hosted Signer KEK Metadata Check', kekCheckCommands());
  appendCommandSection(lines, 'Remote D1 Migrations', migrationCommands(input.options));
  appendCommandSection(lines, 'Time Travel Bookmark Before Fixture Import', timeTravelCommands(input.options, 'before_fixture_import'));
  appendCommandSection(lines, 'Fixture Import', fixtureImportCommands(input.options));
  appendCommandSection(lines, 'Time Travel Bookmark Before Route Switch', timeTravelCommands(input.options, 'before_route_switch'));
  appendCommandSection(lines, 'Worker Deploy', deployCommands(input.options));
  appendCommandSection(lines, 'Staging Smoke', smokeCommands(input.options));
  appendCommandSection(lines, 'D1 Data Reconciliation', reconciliationCommands());
  appendCommandSection(lines, 'Signer Custody Route Drill', signerCustodyCommands(input.options));
  appendCommandSection(lines, 'Remote R2 Export And Restore Drill', r2ExportRestoreCommands(input.options));
  appendCommandSection(lines, 'Final Evidence Verification', evidenceVerificationCommands());
  appendEvidenceTable(lines);
  appendSignOff(lines);
  return `${lines.join('\n')}\n`;
}

function appendReadiness(lines, checks) {
  lines.push('## Readiness Gate');
  lines.push('');
  for (const check of checks) {
    lines.push(`- [x] ${check.profile} readiness passed for ${relativeToRepo(check.configPath)}`);
  }
  lines.push('');
}

function appendResourceInventory(lines) {
  lines.push('## Resource Inventory');
  lines.push('');
  lines.push('| Resource | Value | Evidence |');
  lines.push('| --- | --- | --- |');
  lines.push('| Cloudflare account ID |  |  |');
  lines.push('| Console D1 database ID |  | `wrangler d1 info seams-console-staging` |');
  lines.push('| Signer D1 database ID |  | `wrangler d1 info seams-signer-staging` |');
  lines.push('| Threshold Durable Object namespace |  | gateway Wrangler config |');
  lines.push('| Secrets Store ID |  | gateway Wrangler config |');
  lines.push('| Signer KEK secret names |  | gateway Wrangler config, secret metadata only |');
  lines.push('| R2 backup bucket |  | bucket metadata |');
  lines.push('| Console Worker version |  | deploy output |');
  lines.push('| Gateway Worker version |  | deploy output |');
  lines.push('');
}

function appendCommandSection(lines, title, commands) {
  lines.push(`## ${title}`);
  lines.push('');
  lines.push('```sh');
  for (const command of commands) lines.push(command);
  lines.push('```');
  lines.push('');
}

function preflightCommands(options) {
  return [
    'pnpm --dir packages/console-server-ts run d1:staging:check',
    [
      'pnpm --dir packages/console-server-ts run d1:staging:runbook --',
      '--output',
      shellArg(path.relative(packageRoot, options.outputPath)),
      '--r2-bucket',
      shellArg(options.r2Bucket),
      '--console-origin',
      shellArg(options.consoleOrigin),
      '--gateway-origin',
      shellArg(options.gatewayOrigin),
    ].join(' '),
  ];
}

function resourceInventoryCommands() {
  return [
    'pnpm --dir packages/console-server-ts run d1:staging:resources -- --mode dry-run',
    'pnpm --dir packages/console-server-ts run d1:staging:resources -- --mode remote',
  ];
}

function migrationCommands(options) {
  return [
    'pnpm --dir packages/console-server-ts run d1:staging:migrate -- --mode dry-run',
    'pnpm --dir packages/console-server-ts run d1:staging:migrate -- --mode remote',
  ];
}

function kekCheckCommands() {
  return [
    'pnpm --dir packages/console-server-ts run d1:staging:kek-check -- --mode dry-run',
    'pnpm --dir packages/console-server-ts run d1:staging:kek-check -- --mode remote',
  ];
}

function timeTravelCommands(options, label) {
  return [
    [
      'pnpm --dir packages/console-server-ts run d1:staging:bookmark --',
      '--mode dry-run',
      '--purpose',
      label,
    ].join(' '),
    [
      'pnpm --dir packages/console-server-ts run d1:staging:bookmark --',
      '--mode remote',
      '--purpose',
      label,
    ].join(' '),
  ];
}

function fixtureImportCommands(options) {
  return [
    'CONSOLE_FIXTURE_SQL="./staging/fixtures/console.sql"',
    'SIGNER_FIXTURE_SQL="./staging/fixtures/signer.sql"',
    [
      'pnpm --dir packages/console-server-ts run d1:staging:import-fixtures --',
      '--mode dry-run',
      '--console-fixture "$CONSOLE_FIXTURE_SQL"',
      '--signer-fixture "$SIGNER_FIXTURE_SQL"',
    ].join(' '),
    [
      'pnpm --dir packages/console-server-ts run d1:staging:import-fixtures --',
      '--mode remote',
      '--console-fixture "$CONSOLE_FIXTURE_SQL"',
      '--signer-fixture "$SIGNER_FIXTURE_SQL"',
    ].join(' '),
    '# Import Durable Object fixture state only through the gateway Worker route or typed admin tool chosen for staging.',
  ];
}

function deployCommands(options) {
  return [
    wranglerCommand('deploy --message "refactor-82 console D1 staging"', options.consoleConfigPath),
    wranglerCommand('deploy --message "refactor-82 gateway D1/DO staging"', options.gatewayConfigPath),
  ];
}

function smokeCommands(options) {
  return [
    [
      'pnpm --dir packages/console-server-ts run d1:staging:smoke --',
      '--mode dry-run',
      '--console-origin',
      shellArg(options.consoleOrigin),
      '--gateway-origin',
      shellArg(options.gatewayOrigin),
    ].join(' '),
    [
      'pnpm --dir packages/console-server-ts run d1:staging:smoke --',
      '--mode remote',
      '--console-origin',
      shellArg(options.consoleOrigin),
      '--gateway-origin',
      shellArg(options.gatewayOrigin),
    ].join(' '),
  ];
}

function reconciliationCommands() {
  return [
    'pnpm --dir packages/console-server-ts run d1:staging:reconcile -- --mode dry-run',
    'pnpm --dir packages/console-server-ts run d1:staging:reconcile -- --mode remote',
  ];
}

function signerCustodyCommands(options) {
  return [
    'ECDSA_EXPORT_SHARE_FIXTURE="./staging/fixtures/ecdsa-export-share.json"',
    'ECDSA_MISSING_KEK_EXPORT_SHARE_FIXTURE="./staging/fixtures/ecdsa-export-share-missing-kek.json"',
    'export SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT="<fixture-wallet-session-jwt>"',
    'export SEAMS_STAGING_MISSING_KEK_WALLET_SESSION_JWT="<missing-kek-fixture-wallet-session-jwt>"',
    [
      'pnpm --dir packages/console-server-ts run d1:staging:signer-custody --',
      '--mode dry-run',
      '--gateway-origin',
      shellArg(options.gatewayOrigin),
      '--origin',
      shellArg(options.consoleOrigin),
      '--export-share-fixture "$ECDSA_EXPORT_SHARE_FIXTURE"',
      '--wallet-session-jwt-env SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT',
      '--missing-kek-fixture "$ECDSA_MISSING_KEK_EXPORT_SHARE_FIXTURE"',
      '--missing-kek-wallet-session-jwt-env SEAMS_STAGING_MISSING_KEK_WALLET_SESSION_JWT',
      '--missing-kek-expected-status 503',
      '--missing-kek-expected-code missing_signing_root_kek',
    ].join(' '),
    [
      'pnpm --dir packages/console-server-ts run d1:staging:signer-custody --',
      '--mode remote',
      '--gateway-origin',
      shellArg(options.gatewayOrigin),
      '--origin',
      shellArg(options.consoleOrigin),
      '--export-share-fixture "$ECDSA_EXPORT_SHARE_FIXTURE"',
      '--wallet-session-jwt-env SEAMS_STAGING_ECDSA_WALLET_SESSION_JWT',
      '--missing-kek-fixture "$ECDSA_MISSING_KEK_EXPORT_SHARE_FIXTURE"',
      '--missing-kek-wallet-session-jwt-env SEAMS_STAGING_MISSING_KEK_WALLET_SESSION_JWT',
      '--missing-kek-expected-status 503',
      '--missing-kek-expected-code missing_signing_root_kek',
    ].join(' '),
    '# The final evidence verifier requires ecdsa_export_share_missing_kek_fail_closed in the signer custody manifest.',
  ];
}

function r2ExportRestoreCommands(options) {
  return [
    [
      'pnpm --dir packages/console-server-ts run d1:staging:r2-restore-drill --',
      '--mode dry-run',
      '--r2-bucket',
      shellArg(options.r2Bucket),
    ].join(' '),
    [
      'pnpm --dir packages/console-server-ts run d1:staging:r2-restore-drill --',
      '--mode remote',
      '--r2-bucket',
      shellArg(options.r2Bucket),
    ].join(' '),
  ];
}

function evidenceVerificationCommands() {
  return [
    'RESOURCE_INVENTORY_MANIFEST="<resource-inventory-remote-manifest.json>"',
    'KEK_CHECK_MANIFEST="<kek-check-remote-manifest.json>"',
    'MIGRATIONS_MANIFEST="<migrations-remote-manifest.json>"',
    'BOOKMARK_BEFORE_FIXTURE_IMPORT_MANIFEST="<before-fixture-import-bookmark-manifest.json>"',
    'FIXTURE_IMPORT_MANIFEST="<fixture-import-remote-manifest.json>"',
    'BOOKMARK_BEFORE_ROUTE_SWITCH_MANIFEST="<before-route-switch-bookmark-manifest.json>"',
    'SMOKE_MANIFEST="<smoke-remote-manifest.json>"',
    'RECONCILIATION_MANIFEST="<reconciliation-remote-manifest.json>"',
    'SIGNER_CUSTODY_MANIFEST="<signer-custody-remote-manifest.json>"',
    'R2_RESTORE_DRILL_MANIFEST="<r2-restore-drill-remote-manifest.json>"',
    [
      'pnpm --dir packages/console-server-ts run d1:staging:evidence --',
      '--resources "$RESOURCE_INVENTORY_MANIFEST"',
      '--kek-check "$KEK_CHECK_MANIFEST"',
      '--migrations "$MIGRATIONS_MANIFEST"',
      '--bookmark-before-fixture-import "$BOOKMARK_BEFORE_FIXTURE_IMPORT_MANIFEST"',
      '--fixture-import "$FIXTURE_IMPORT_MANIFEST"',
      '--bookmark-before-route-switch "$BOOKMARK_BEFORE_ROUTE_SWITCH_MANIFEST"',
      '--smoke "$SMOKE_MANIFEST"',
      '--reconciliation "$RECONCILIATION_MANIFEST"',
      '--signer-custody "$SIGNER_CUSTODY_MANIFEST"',
      '--r2-restore-drill "$R2_RESTORE_DRILL_MANIFEST"',
      '--output .wrangler/d1-staging-evidence/verification.json',
    ].join(' '),
  ];
}

function appendEvidenceTable(lines) {
  lines.push('## Evidence');
  lines.push('');
  lines.push('| Check | Result | Evidence location |');
  lines.push('| --- | --- | --- |');
  lines.push('| Staging readiness |  |  |');
  lines.push('| Console migrations |  |  |');
  lines.push('| Signer migrations |  |  |');
  lines.push('| Time Travel before fixture import |  |  |');
  lines.push('| Fixture import |  |  |');
  lines.push('| Time Travel before route switch |  |  |');
  lines.push('| Console `/readyz` |  |  |');
  lines.push('| Gateway `/readyz` |  |  |');
  lines.push('| Gateway `/router-ab/ed25519/healthz` configured |  |  |');
  lines.push('| Gateway `/router-ab/ecdsa-derivation/healthz` configured |  |  |');
  lines.push('| Dashboard reconciliation |  |  |');
  lines.push('| Sponsored gas settlement and prepaid billing |  |  |');
  lines.push('| Fixture-backed signer custody, KEK isolation, and missing-KEK fail-closed |  |  |');
  lines.push('| R2 export object keys |  |  |');
  lines.push('| Restore drill integrity checks |  |  |');
  lines.push('| Final evidence verification |  |  |');
  lines.push('');
}

function appendSignOff(lines) {
  lines.push('## Sign-Off');
  lines.push('');
  lines.push('- [ ] Staging starts on D1/DO.');
  lines.push('- [ ] No request path mixes D1/DO and Postgres.');
  lines.push('- [ ] Console Worker has no signer D1, Durable Object, or KEK bindings.');
  lines.push('- [ ] Time Travel bookmarks are captured before fixture import and before route traffic switch.');
  lines.push('- [ ] R2 export and restore drill evidence is recorded.');
  lines.push('- [ ] Final evidence verification passes.');
  lines.push('- [ ] Dashboard reconciliation, sponsored gas settlement, signer route health, fixture-backed custody, and missing-KEK fail-closed checks pass.');
  lines.push('');
}

if (isDirectInvocation(import.meta.url)) main();
