#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listTypeScriptFiles(relativeDir) {
  const absoluteDir = path.join(repoRoot, relativeDir);
  if (!fs.existsSync(absoluteDir)) return [];

  const files = [];
  for (const entry of fs.readdirSync(absoluteDir, { withFileTypes: true })) {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listTypeScriptFiles(relativePath));
      continue;
    }
    if (/\.(ts|tsx)$/.test(entry.name)) files.push(relativePath);
  }
  return files;
}

function assertDoesNotMatch(source, pattern, label) {
  assert.ok(!pattern.test(source), `${label}: matched ${pattern}`);
}

function assertNoOffenders(label, offenders) {
  assert.deepEqual(offenders, [], `${label}\n${offenders.join('\n')}`);
}

function checkReactUiDoesNotBranchOnRelayGoogleEmailOtpResolution() {
  const offenders = [];
  for (const relativePath of listTypeScriptFiles('packages/wallet/src/react')) {
    if (/\bgoogleEmailOtpResolution\b/.test(readRepoFile(relativePath))) offenders.push(relativePath);
  }

  assertNoOffenders('React UI code must not branch on relay Google Email OTP resolution', offenders);
}

function checkHeadlessFlowOperationDependsOnNarrowPorts() {
  const source = readRepoFile(
    'packages/wallet/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts',
  );
  const forbiddenPatterns = [
    /\bSeamsWebContext\b/,
    /\bSeamsWebSigningSurface\b/,
    /\bBrowserSigningSurface\b/,
    /from\s+['"]@\/SeamsWeb\/SeamsWeb['"]/,
  ];

  for (const pattern of forbiddenPatterns) {
    assertDoesNotMatch(source, pattern, 'headless Google Email OTP operation must depend on narrow ports');
  }
}

function checkStandardRegistrationBranchCannotIssueOtpChallenges() {
  const source = readRepoFile(
    'packages/wallet/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts',
  );
  const start = source.indexOf('function createGoogleEmailOtpWalletRegistrationFlow');
  const end = source.indexOf('function createGoogleEmailOtpWalletLoginFlow');
  assert.ok(start >= 0 && end > start, 'Missing Google Email OTP registration flow block');

  const registrationFlow = source.slice(start, end);
  const forbiddenPatterns = [
    /\brequestLoginChallenge\b/,
    /\brequestEmailOtpChallenge\b/,
    /\bcreateGoogleEmailOtpWalletLoginFlow\b/,
    /\bchallenge_sent\b/,
  ];
  for (const pattern of forbiddenPatterns) {
    assertDoesNotMatch(
      registrationFlow,
      pattern,
      'standard Google Email OTP registration branch must not issue OTP challenges',
    );
  }
}

function checkPublicApiLayerDoesNotOwnWalletIframeFlowHandles() {
  const offenders = [];
  for (const relativePath of listTypeScriptFiles('packages/wallet/src/SeamsWeb/publicApi')) {
    if (/\bflowHandleId\b|googleEmailOtpWalletAuthFlows\b/.test(readRepoFile(relativePath))) {
      offenders.push(relativePath);
    }
  }

  assertNoOffenders('public API layer must not own wallet iframe flow handles', offenders);
}

function checkWalletIframeEmailOtpFlowHandlesAreBoundBeforeConsume() {
  const hostSource = readRepoFile('packages/wallet/src/SeamsWeb/walletIframe/host/handlers/emailOtp.ts');
  const messagesSource = readRepoFile('packages/wallet/src/SeamsWeb/walletIframe/shared/messages.ts');
  const clientSource = readRepoFile('packages/wallet/src/SeamsWeb/walletIframe/client/router.ts');

  assert.match(messagesSource, /flowId: string/);
  assert.match(messagesSource, /walletId: string/);
  assert.match(messagesSource, /mode: GoogleEmailOtpWalletAuthResolvedMode/);
  assert.ok(
    hostSource.includes('assertFlowHandleMatchesPayload(record.flow, payload)'),
    'wallet iframe host must bind flow handle to the consumed payload',
  );
  assert.match(clientSource, /flowId: wire\.flowId/);
  assert.match(clientSource, /walletId: wire\.walletId/);
  assert.match(clientSource, /mode: wire\.mode/);
}

checkReactUiDoesNotBranchOnRelayGoogleEmailOtpResolution();
checkHeadlessFlowOperationDependsOnNarrowPorts();
checkStandardRegistrationBranchCannotIssueOtpChallenges();
checkPublicApiLayerDoesNotOwnWalletIframeFlowHandles();
checkWalletIframeEmailOtpFlowHandlesAreBoundBeforeConsume();

console.log('[check-headless-google-email-otp-flow-boundaries] passed');
