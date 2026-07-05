#!/usr/bin/env node
import dotenv from 'dotenv';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
dotenv.config({ path: path.join(repoRoot, '.env.intended.local'), override: true });
const manifestPath = path.join(
  repoRoot,
  'tests/e2e/intended-behaviours/mutation-self-check.manifest.json',
);
const intendedRoot = path.join(repoRoot, 'tests/e2e/intended-behaviours');
const harnessPath = path.join(intendedRoot, 'harness.ts');
const expectedManifestVersion = 'refactor-88-2026-07-04';
const googleTokenEnsureCommand = 'pnpm -C tests run ensure:intended-google-token';

const expectedMutationIds = [
  'cross_chain_ecdsa_material_reuse',
  'email_otp_reroll_bootstrap_token_request_mismatch',
  'export_provider_user_mismatch_after_app_session_refresh',
  'first_post_step_up_transaction_failure',
];

const expectedFailureOraclesByMutationId = {
  cross_chain_ecdsa_material_reuse: 'Arc/EVM recovered signer mismatch',
  email_otp_reroll_bootstrap_token_request_mismatch: 'bootstrap_token_request_mismatch',
  export_provider_user_mismatch_after_app_session_refresh: 'fresh Email OTP export authorization',
  first_post_step_up_transaction_failure: 'post-step-up transaction failed',
};

const allowedPhase3bProofStatuses = new Set([
  'blocked_email_otp_token',
  'blocked_product_identity',
  'detected',
]);

const fixedCiPorts = [
  { label: 'app https', port: 443 },
  { label: 'wallet https', port: 8443 },
  { label: 'router https', port: 9444 },
  { label: 'site vite', port: 3600 },
  { label: 'router worker', port: 9090 },
];

await main().catch(handleFatalError);

async function main() {
  const args = parseCliArgs(process.argv.slice(2));
  const manifest = readJsonRecord(manifestPath);
  const allMutations = validateManifest(manifest);
  const mutations = selectMutations({
    mutations: allMutations,
    selectedMutationIds: args.selectedMutationIds,
  });
  if (!args.preflight) {
    printManifestCheckSummary({
      selectedCount: mutations.length,
      totalCount: allMutations.length,
      mutations,
    });
    if (!enforceDetectedProofRequirement({ mutations, requireDetected: args.requireDetected })) {
      process.exitCode = 1;
    }
    return;
  }

  const result = args.ci ? await ciPreflight(mutations) : await localPreflight(mutations);
  printPreflight(result);
  if (!enforceDetectedProofRequirement({ mutations, requireDetected: args.requireDetected })) {
    process.exitCode = 1;
  }
  if (result.blockedRows.length > 0) {
    process.exitCode = 1;
  }
}

function handleFatalError(error) {
  console.error(
    `[intended-mutation-self-check] ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
}

function printManifestCheckSummary(input) {
  console.log(
    `[intended-mutation-self-check] manifest ok: ${input.selectedCount} of ${input.totalCount} seeded regressions`,
  );
  console.log(`[intended-mutation-self-check] proof status: ${formatProofStatusCounts(input.mutations)}`);
}

function formatProofStatusCounts(mutations) {
  const counts = countProofStatuses(mutations);
  const labels = [];
  for (const status of allowedPhase3bProofStatuses) {
    labels.push(`${status}=${counts.get(status) || 0}`);
  }
  return labels.join(' ');
}

function countProofStatuses(mutations) {
  const counts = new Map();
  for (const mutation of mutations) {
    const proof = requireRecordField(mutation, 'phase3bProof');
    const status = requireStringField(proof, 'status');
    counts.set(status, (counts.get(status) || 0) + 1);
  }
  return counts;
}

function enforceDetectedProofRequirement(input) {
  if (!input.requireDetected) return true;
  const incompleteRows = incompleteDetectedProofRows(input.mutations);
  if (incompleteRows.length === 0) {
    console.log('[intended-mutation-self-check] proof completion ok: all selected rows detected');
    for (const row of detectedProofRows(input.mutations)) {
      printDetectedProofRow(row);
    }
    return true;
  }
  console.log(
    `[intended-mutation-self-check] proof completion incomplete: ${incompleteRows.length} of ${input.mutations.length} selected rows are not detected`,
  );
  for (const row of incompleteRows) {
    printIncompleteDetectedProofRow(row);
  }
  return false;
}

function incompleteDetectedProofRows(mutations) {
  const rows = [];
  for (const mutation of mutations) {
    const proof = requireRecordField(mutation, 'phase3bProof');
    const status = requireStringField(proof, 'status');
    if (status === 'detected') continue;
    rows.push({
      id: requireStringField(mutation, 'id'),
      status,
      unblockRequirement: optionalStringField(proof, 'unblockRequirement'),
    });
  }
  return rows;
}

function detectedProofRows(mutations) {
  const rows = [];
  for (const mutation of mutations) {
    const proof = requireRecordField(mutation, 'phase3bProof');
    const status = requireStringField(proof, 'status');
    if (status !== 'detected') continue;
    rows.push({
      id: requireStringField(mutation, 'id'),
      observedAt: requireStringField(proof, 'observedAt'),
      observedFailureOracle: requireStringField(proof, 'observedFailureOracle'),
      observedFailureCommand: requireStringField(proof, 'observedFailureCommand'),
      restoredValidationCommand: requireStringField(proof, 'restoredValidationCommand'),
    });
  }
  return rows;
}

function printDetectedProofRow(row) {
  console.log(`[intended-mutation-self-check]   detected ${row.id} observedAt=${row.observedAt}`);
  console.log(`[intended-mutation-self-check]     oracle: ${row.observedFailureOracle}`);
  console.log(`[intended-mutation-self-check]     failure: ${row.observedFailureCommand}`);
  console.log(`[intended-mutation-self-check]     restored: ${row.restoredValidationCommand}`);
}

function printIncompleteDetectedProofRow(row) {
  console.log(`[intended-mutation-self-check]   incomplete ${row.id} status=${row.status}`);
  if (row.unblockRequirement) {
    console.log(`[intended-mutation-self-check]     unblock: ${row.unblockRequirement}`);
  }
}

function validateManifest(manifest) {
  const version = requireStringField(manifest, 'version');
  if (version !== expectedManifestVersion) {
    throw new Error(`manifest version must be ${expectedManifestVersion}, received ${version}`);
  }
  const instruction = requireStringField(manifest, 'instruction');
  requireInstructionToken(instruction, 'fresh SDK build');
  requireInstructionToken(instruction, 'restarted site/router services');
  requireInstructionToken(instruction, 'CI-managed intended startup');

  const mutations = manifest.mutations;
  if (!Array.isArray(mutations)) {
    throw new Error('manifest mutations must be an array');
  }

  const ids = mutations.map(readMutationId).sort();
  const expectedIds = [...expectedMutationIds].sort();
  if (JSON.stringify(ids) !== JSON.stringify(expectedIds)) {
    throw new Error(`manifest mutation ids mismatch: ${ids.join(', ')}`);
  }

  const harnessSource = fs.readFileSync(harnessPath, 'utf8');
  for (const mutation of mutations) {
    validateMutationRow({ mutation, harnessSource });
  }

  return mutations;
}

function requireInstructionToken(instruction, token) {
  if (!instruction.includes(token)) {
    throw new Error(`manifest instruction must include ${token}`);
  }
}

function parseCliArgs(argv) {
  const selectedMutationIds = [];
  let preflight = false;
  let ci = false;
  let requireDetected = false;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--') {
      continue;
    }
    if (arg === '--preflight') {
      preflight = true;
      continue;
    }
    if (arg === '--ci') {
      ci = true;
      continue;
    }
    if (arg === '--require-detected') {
      requireDetected = true;
      continue;
    }
    if (arg === '--mutation') {
      selectedMutationIds.push(requireNextCliValue(argv, index, '--mutation'));
      index += 1;
      continue;
    }
    if (arg.startsWith('--mutation=')) {
      selectedMutationIds.push(requireInlineCliValue(arg, '--mutation='));
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }
  return {
    preflight,
    ci,
    requireDetected,
    selectedMutationIds: uniqueCliValues(selectedMutationIds),
  };
}

function requireNextCliValue(argv, index, optionName) {
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) {
    throw new Error(`${optionName} requires a mutation id`);
  }
  return value;
}

function requireInlineCliValue(arg, prefix) {
  const value = arg.slice(prefix.length).trim();
  if (!value) {
    throw new Error(`${prefix.slice(0, -1)} requires a mutation id`);
  }
  return value;
}

function uniqueCliValues(values) {
  return [...new Set(values.map(requireNonEmptyCliValue))];
}

function requireNonEmptyCliValue(value) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error('mutation id must be non-empty');
  }
  return normalized;
}

function selectMutations(input) {
  if (input.selectedMutationIds.length === 0) return input.mutations;
  const byId = new Map(input.mutations.map((mutation) => [readMutationId(mutation), mutation]));
  const selected = [];
  const unknown = [];
  for (const id of input.selectedMutationIds) {
    const mutation = byId.get(id);
    if (mutation) {
      selected.push(mutation);
    } else {
      unknown.push(id);
    }
  }
  if (unknown.length > 0) {
    throw new Error(`unknown mutation id(s): ${unknown.join(', ')}`);
  }
  return selected;
}

function validateMutationRow(input) {
  const id = requireStringField(input.mutation, 'id');
  requireStringField(input.mutation, 'seededRegression');
  validateExpectedFailureOracle({
    id,
    expectedFailureOracle: requireStringField(input.mutation, 'expectedFailureOracle'),
  });
  const contractFiles = requireStringArrayField(input.mutation, 'contractFiles');
  validateContractFiles({ id, contractFiles });
  validateHarnessEvidence({
    id,
    harnessSource: input.harnessSource,
    evidenceTokens: requireStringArrayField(input.mutation, 'requiredHarnessEvidence'),
  });
  validateProof({ id, contractFiles, proof: requireRecordField(input.mutation, 'phase3bProof') });
}

function validateExpectedFailureOracle(input) {
  const expected = expectedFailureOraclesByMutationId[input.id];
  if (!expected) {
    throw new Error(`${input.id} has no expected failure oracle policy`);
  }
  if (input.expectedFailureOracle !== expected) {
    throw new Error(
      `${input.id} expectedFailureOracle must be "${expected}", received "${input.expectedFailureOracle}"`,
    );
  }
}

function validateContractFiles(input) {
  for (const contractFile of input.contractFiles) {
    const absolutePath = path.join(intendedRoot, contractFile);
    if (!fs.existsSync(absolutePath)) {
      throw new Error(`${input.id} references missing contract file: ${contractFile}`);
    }
  }
}

function validateHarnessEvidence(input) {
  for (const token of input.evidenceTokens) {
    if (!input.harnessSource.includes(token)) {
      throw new Error(`${input.id} missing required harness evidence token: ${token}`);
    }
  }
}

function validateProof(input) {
  if (input.proof.requiresFreshStartup !== true) {
    throw new Error(`${input.id} phase3bProof.requiresFreshStartup must be true`);
  }
  if (typeof input.proof.requiresEmailOtpGoogleIdToken !== 'boolean') {
    throw new Error(`${input.id} phase3bProof.requiresEmailOtpGoogleIdToken must be boolean`);
  }
  validateProofStatusPolicy({
    id: input.id,
    contractFiles: input.contractFiles,
    expectedFailureOracle: expectedFailureOraclesByMutationId[input.id],
    proof: input.proof,
  });
  validateKnownProductBlockerPolicy(input.id, input.proof);
  const localCommand = requireStringField(input.proof, 'localCommand');
  const ciCommand = requireStringField(input.proof, 'ciCommand');
  validateProofTokenPolicy({
    id: input.id,
    requiresEmailOtpGoogleIdToken: input.proof.requiresEmailOtpGoogleIdToken,
    localCommand,
    ciCommand,
  });
  if (!localCommand.includes('playwright.intended.config.ts')) {
    throw new Error(`${input.id} localCommand must use playwright.intended.config.ts`);
  }
  if (!ciCommand.includes('playwright.intended.ci.config.ts')) {
    throw new Error(`${input.id} ciCommand must use playwright.intended.ci.config.ts`);
  }
  if (!proofCommandsMentionTargetedContracts(input.contractFiles, localCommand, ciCommand)) {
    throw new Error(`${input.id} proof commands must mention a targeted contract`);
  }
  validateProofCommandContractScope({
    id: input.id,
    contractFiles: input.contractFiles,
    localCommand,
    ciCommand,
  });
}

function validateProofStatusPolicy(input) {
  const status = requireStringField(input.proof, 'status');
  if (!allowedPhase3bProofStatuses.has(status)) {
    throw new Error(`${input.id} phase3bProof.status is invalid: ${status}`);
  }
  const observedFailureOracle = optionalStringField(input.proof, 'observedFailureOracle');
  const unblockRequirement = optionalStringField(input.proof, 'unblockRequirement');
  if (status === 'detected') {
    if (observedFailureOracle !== input.expectedFailureOracle) {
      throw new Error(
        `${input.id} phase3bProof.observedFailureOracle must match expectedFailureOracle`,
      );
    }
    if (unblockRequirement !== undefined) {
      throw new Error(
        `${input.id} phase3bProof.unblockRequirement is only allowed while proof is blocked`,
      );
    }
    validateDetectedProofEvidence(input);
    return;
  }
  if (observedFailureOracle !== undefined) {
    throw new Error(
      `${input.id} phase3bProof.observedFailureOracle is only allowed when status is detected`,
    );
  }
  validateBlockedProofOmitsDetectedEvidence(input);
  if (!unblockRequirement) {
    throw new Error(`${input.id} blocked proof rows must explain phase3bProof.unblockRequirement`);
  }
  if (status === 'blocked_email_otp_token' && input.proof.requiresEmailOtpGoogleIdToken !== true) {
    throw new Error(`${input.id} blocked_email_otp_token rows must require the Google ID token`);
  }
  if (
    status === 'blocked_email_otp_token' &&
    !unblockRequirement.includes('SEAMS_INTENDED_GOOGLE_ID_TOKEN')
  ) {
    throw new Error(`${input.id} blocked_email_otp_token rows must name the Google ID token`);
  }
  if (status === 'blocked_product_identity' && input.id !== 'cross_chain_ecdsa_material_reuse') {
    throw new Error(`${input.id} blocked_product_identity is only allowed on cross-chain ECDSA`);
  }
  if (
    status === 'blocked_product_identity' &&
    !unblockRequirement.includes('target-specific Tempo and Arc/EVM ECDSA owner/public-key facts')
  ) {
    throw new Error(`${input.id} blocked_product_identity rows must name target-specific ECDSA facts`);
  }
}

function validateDetectedProofEvidence(input) {
  const observedAt = requireStringField(input.proof, 'observedAt');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(observedAt)) {
    throw new Error(`${input.id} phase3bProof.observedAt must use YYYY-MM-DD`);
  }
  validateDetectedProofCommand({
    id: input.id,
    label: 'observedFailureCommand',
    command: requireStringField(input.proof, 'observedFailureCommand'),
    contractFiles: input.contractFiles,
  });
  validateDetectedProofCommand({
    id: input.id,
    label: 'restoredValidationCommand',
    command: requireStringField(input.proof, 'restoredValidationCommand'),
    contractFiles: input.contractFiles,
  });
}

function validateDetectedProofCommand(input) {
  if (!usesIntendedPlaywrightConfig(input.command)) {
    throw new Error(
      `${input.id} phase3bProof.${input.label} must use an intended Playwright config`,
    );
  }
  if (!proofCommandsMentionTargetedContracts(input.contractFiles, input.command, input.command)) {
    throw new Error(`${input.id} phase3bProof.${input.label} must mention a targeted contract`);
  }
}

function usesIntendedPlaywrightConfig(command) {
  return (
    command.includes('playwright.intended.config.ts') ||
    command.includes('playwright.intended.ci.config.ts')
  );
}

function validateBlockedProofOmitsDetectedEvidence(input) {
  const detectedFields = [
    'observedAt',
    'observedFailureCommand',
    'restoredValidationCommand',
  ];
  for (const fieldName of detectedFields) {
    if (optionalStringField(input.proof, fieldName) === undefined) continue;
    throw new Error(`${input.id} phase3bProof.${fieldName} is only allowed when status is detected`);
  }
}

function proofCommandsMentionTargetedContracts(contractFiles, localCommand, ciCommand) {
  return contractFiles.some(
    (contractFile) => localCommand.includes(contractFile) || ciCommand.includes(contractFile),
  );
}

function validateKnownProductBlockerPolicy(id, proof) {
  const knownProductBlocker = optionalStringField(proof, 'knownProductBlocker');
  const status = requireStringField(proof, 'status');
  if (status === 'blocked_product_identity' && id === 'cross_chain_ecdsa_material_reuse') {
    if (!knownProductBlocker) {
      throw new Error(`${id} phase3bProof.knownProductBlocker must document target identity separation`);
    }
    if (!knownProductBlocker.includes('target-specific ECDSA owner/public-key facts')) {
      throw new Error(`${id} phase3bProof.knownProductBlocker must mention target-specific ECDSA owner/public-key facts`);
    }
    if (!knownProductBlocker.includes('shared evm-family key scope')) {
      throw new Error(`${id} phase3bProof.knownProductBlocker must mention the shared evm-family key scope`);
    }
    return;
  }
  if (knownProductBlocker !== undefined) {
    throw new Error(
      `${id} phase3bProof.knownProductBlocker is only allowed on blocked cross-chain ECDSA material reuse`,
    );
  }
}

function validateProofTokenPolicy(input) {
  const commands = [
    { label: 'localCommand', command: input.localCommand },
    { label: 'ciCommand', command: input.ciCommand },
  ];
  for (const command of commands) {
    const hasTokenEnsure = command.command.includes(googleTokenEnsureCommand);
    if (command.command.includes('SEAMS_INTENDED_GOOGLE_ID_TOKEN=')) {
      throw new Error(`${input.id} ${command.label} must not inline a Google ID token`);
    }
    if (input.requiresEmailOtpGoogleIdToken && !hasTokenEnsure) {
      throw new Error(`${input.id} ${command.label} must include ${googleTokenEnsureCommand}`);
    }
    if (!input.requiresEmailOtpGoogleIdToken && hasTokenEnsure) {
      throw new Error(`${input.id} ${command.label} must not require ${googleTokenEnsureCommand}`);
    }
  }
}

function validateProofCommandContractScope(input) {
  const allowedContracts = new Set(input.contractFiles);
  const commandContracts = [
    ...extractContractFilesFromCommand(input.localCommand),
    ...extractContractFilesFromCommand(input.ciCommand),
  ];
  for (const contractFile of commandContracts) {
    if (allowedContracts.has(contractFile)) continue;
    throw new Error(`${input.id} proof command references non-target contract: ${contractFile}`);
  }
}

function extractContractFilesFromCommand(command) {
  const matches = command.matchAll(/e2e\/intended-behaviours\/([a-z0-9.-]+\.contract\.test\.ts)/g);
  return [...matches].map(readContractFileMatch);
}

function readContractFileMatch(match) {
  return match[1];
}

function readMutationId(mutation) {
  return requireStringField(mutation, 'id');
}

async function localPreflight(mutations) {
  const appUrl = process.env.SEAMS_INTENDED_APP_URL || 'https://localhost';
  const routerUrl = process.env.SEAMS_INTENDED_ROUTER_URL || 'https://localhost:9444';
  const serviceChecks = [
    await httpsOk(appUrl, 'site root'),
    await httpsOk(intendedPageSmokeUrl(appUrl), 'intended page'),
    await httpsOk(`${routerUrl}/healthz`, 'router healthz'),
    await httpsOk(`${routerUrl}/readyz`, 'router readyz'),
  ];
  const sharedBlocks = localSharedBlocks(serviceChecks);
  if (process.env.SEAMS_INTENDED_MUTATION_FRESH_STARTUP !== '1') {
    sharedBlocks.push(
      'SEAMS_INTENDED_MUTATION_FRESH_STARTUP=1 is required after a fresh SDK build and restarted site/router services',
    );
  }
  return preflightRows({
    mode: 'local',
    mutations,
    sharedBlocks,
    serviceChecks,
  });
}

function intendedPageSmokeUrl(appUrl) {
  const url = new URL('/__intended-e2e', appUrl);
  url.searchParams.set('flow', 'passkey.registration');
  url.searchParams.set('walletId', 'intended-preflight-smoke');
  return url.href;
}

function localSharedBlocks(serviceChecks) {
  return serviceChecks
    .filter(isServiceBlocked)
    .map(formatBlockedService);
}

function isServiceBlocked(check) {
  return !check.ok;
}

function formatBlockedService(check) {
  return `${check.label} is not ready at ${check.url}`;
}

async function ciPreflight(mutations) {
  const portChecks = await Promise.all(fixedCiPorts.map(checkPortOccupied));
  const sharedBlocks = portChecks.filter(isPortOccupied).map(formatOccupiedPort);
  return preflightRows({
    mode: 'ci',
    mutations,
    sharedBlocks,
    serviceChecks: portChecks,
  });
}

function isPortOccupied(check) {
  return check.occupied;
}

function formatOccupiedPort(check) {
  return `${check.label} port ${check.port} is already occupied`;
}

function preflightRows(input) {
  const googleIdTokenPreflight = validateGoogleIdTokenPreflight(
    process.env.SEAMS_INTENDED_GOOGLE_ID_TOKEN,
  );
  const rows = input.mutations.map((mutation) =>
    preflightRow({
      mutation,
      mode: input.mode,
      sharedBlocks: input.sharedBlocks,
      googleIdTokenPreflight,
    }),
  );
  return {
    mode: input.mode,
    googleIdTokenPreflight,
    serviceChecks: input.serviceChecks,
    rows,
    blockedRows: rows.filter(isRowBlocked),
  };
}

function preflightRow(input) {
  const proof = requireRecordField(input.mutation, 'phase3bProof');
  const status = requireStringField(proof, 'status');
  const unblockRequirement = optionalStringField(proof, 'unblockRequirement');
  const blocks = [...input.sharedBlocks];
  if (proof.requiresEmailOtpGoogleIdToken && input.googleIdTokenPreflight.block) {
    blocks.push(input.googleIdTokenPreflight.block);
  }
  const knownProductBlocker = optionalStringField(proof, 'knownProductBlocker');
  if (knownProductBlocker) {
    blocks.push(knownProductBlocker);
  }
  return {
    id: requireStringField(input.mutation, 'id'),
    status,
    unblockRequirement,
    ready: blocks.length === 0,
    blocks,
    command: input.mode === 'ci' ? proof.ciCommand : proof.localCommand,
  };
}

function isRowBlocked(row) {
  return !row.ready;
}

function printPreflight(result) {
  console.log(`[intended-mutation-self-check] mode=${result.mode}`);
  console.log(
    `[intended-mutation-self-check] SEAMS_INTENDED_GOOGLE_ID_TOKEN=${result.googleIdTokenPreflight.label}`,
  );
  console.log(
    `[intended-mutation-self-check] SEAMS_INTENDED_MUTATION_FRESH_STARTUP=${process.env.SEAMS_INTENDED_MUTATION_FRESH_STARTUP === '1' ? 'acknowledged' : 'missing'}`,
  );
  for (const check of result.serviceChecks) {
    printServiceCheck(check);
  }
  for (const row of result.rows) {
    printPreflightRow(row);
  }
}

function printServiceCheck(check) {
  if ('url' in check) {
    const status = check.ok ? 'ready' : `blocked (${check.error || check.status || 'unknown'})`;
    console.log(`[intended-mutation-self-check] ${check.label}: ${status}`);
    return;
  }
  console.log(
    `[intended-mutation-self-check] ${check.label}: ${check.occupied ? 'occupied' : 'available'}`,
  );
}

function printPreflightRow(row) {
  console.log(
    `[intended-mutation-self-check] ${row.ready ? 'ready' : 'blocked'} ${row.id} status=${row.status}`,
  );
  for (const block of row.blocks) {
    console.log(`  - ${block}`);
  }
  if (row.unblockRequirement) {
    console.log(`  unblock: ${row.unblockRequirement}`);
  }
  console.log(`  command: ${row.command}`);
}

function validateGoogleIdTokenPreflight(rawToken) {
  const token = typeof rawToken === 'string' ? rawToken.trim() : '';
  if (!token) {
    return {
      label: 'missing',
      block: 'SEAMS_INTENDED_GOOGLE_ID_TOKEN is required for this seeded regression',
    };
  }
  if (isGoogleIdTokenPlaceholder(token)) {
    return {
      label: 'placeholder',
      block:
        'SEAMS_INTENDED_GOOGLE_ID_TOKEN must be a real Google ID token, not <local-google-id-token>',
    };
  }
  if (!isCompactJwtShape(token)) {
    return {
      label: 'malformed',
      block: 'SEAMS_INTENDED_GOOGLE_ID_TOKEN must be a compact JWT: header.payload.signature',
    };
  }
  return {
    label: 'jwt-shaped',
    block: '',
  };
}

function isGoogleIdTokenPlaceholder(token) {
  return token === '<local-google-id-token>' || token.includes('local-google-id-token');
}

function isCompactJwtShape(token) {
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  return parts.every(isBase64UrlJwtSegment);
}

function isBase64UrlJwtSegment(segment) {
  return /^[A-Za-z0-9_-]+={0,2}$/.test(segment);
}

function httpsOk(url, label) {
  return new Promise((resolve) => {
    const request = https.get(
      url,
      {
        rejectUnauthorized: false,
        timeout: 2_000,
      },
      handleHttpsResponse({ resolve, label, url }),
    );
    request.on('timeout', handleHttpsTimeout(request));
    request.on('error', handleHttpsError({ resolve, label, url }));
  });
}

function handleHttpsResponse(input) {
  return function onResponse(response) {
    response.resume();
    const ok = response.statusCode >= 200 && response.statusCode < 300;
    input.resolve({ label: input.label, url: input.url, ok, status: response.statusCode });
  };
}

function handleHttpsTimeout(request) {
  return function onTimeout() {
    request.destroy(new Error('timeout'));
  };
}

function handleHttpsError(input) {
  return function onError(error) {
    input.resolve({ label: input.label, url: input.url, ok: false, error: error.message });
  };
}

function checkPortOccupied(input) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port: input.port });
    socket.once('connect', handlePortConnect({ socket, resolve, input }));
    socket.once('error', handlePortError({ resolve, input }));
    socket.setTimeout(500, handlePortTimeout({ socket, resolve, input }));
  });
}

function handlePortConnect(args) {
  return function onConnect() {
    args.socket.destroy();
    args.resolve({ ...args.input, occupied: true });
  };
}

function handlePortError(args) {
  return function onError() {
    args.resolve({ ...args.input, occupied: false });
  };
}

function handlePortTimeout(args) {
  return function onTimeout() {
    args.socket.destroy();
    args.resolve({ ...args.input, occupied: false });
  };
}

function readJsonRecord(filePath) {
  const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!isRecord(parsed)) {
    throw new Error(`${filePath} must contain a JSON object`);
  }
  return parsed;
}

function requireStringField(value, fieldName) {
  if (!isRecord(value)) {
    throw new Error(`field ${fieldName} owner must be an object`);
  }
  const field = value[fieldName];
  if (typeof field !== 'string' || field.trim() === '') {
    throw new Error(`field ${fieldName} must be a non-empty string`);
  }
  return field;
}

function requireStringArrayField(value, fieldName) {
  if (!isRecord(value)) {
    throw new Error(`field ${fieldName} owner must be an object`);
  }
  const field = value[fieldName];
  if (!Array.isArray(field) || field.length === 0) {
    throw new Error(`field ${fieldName} must be a non-empty array`);
  }
  return field.map(validateStringArrayEntry(fieldName));
}

function validateStringArrayEntry(fieldName) {
  return function validateEntry(entry) {
    if (typeof entry !== 'string' || entry.trim() === '') {
      throw new Error(`field ${fieldName} entries must be non-empty strings`);
    }
    return entry;
  };
}

function requireRecordField(value, fieldName) {
  if (!isRecord(value)) {
    throw new Error(`field ${fieldName} owner must be an object`);
  }
  const field = value[fieldName];
  if (!isRecord(field)) {
    throw new Error(`field ${fieldName} must be an object`);
  }
  return field;
}

function validateOptionalStringField(value, fieldName, id) {
  const field = optionalStringField(value, fieldName);
  if (field === undefined) return;
  if (field.length > 0) return;
  throw new Error(`${id} phase3bProof.${fieldName} must be non-empty when present`);
}

function optionalStringField(value, fieldName) {
  if (!isRecord(value)) {
    throw new Error(`field ${fieldName} owner must be an object`);
  }
  const field = value[fieldName];
  if (field === undefined) return undefined;
  if (typeof field !== 'string') {
    throw new Error(`field ${fieldName} must be a string when present`);
  }
  return field.trim();
}

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}
