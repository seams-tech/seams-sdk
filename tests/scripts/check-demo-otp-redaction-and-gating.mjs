#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function linesContaining(source, pattern) {
  return source.split(/\r?\n/).filter((line) => pattern.test(line));
}

function checkGoogleEmailOtpObservableSurfaces() {
  const source = readRepoFile('apps/seams-site/src/flows/demo/PasskeyLoginMenu.tsx');
  const flowStart = source.indexOf('const onGoogleSsoEmailOtp = async');
  assert.notEqual(flowStart, -1, 'Missing demo Google Email OTP flow');
  const flowEnd = source.indexOf('\n  const onSyncAccount', flowStart);
  assert.ok(flowEnd > flowStart, 'Could not isolate demo Google Email OTP flow');
  const flow = source.slice(flowStart, flowEnd);
  const observableLines = linesContaining(flow, /\b(?:toast|console)\./);

  assert.doesNotMatch(flow, /Session JWT minted|JWT returned|result\.jwt/);
  assert.deepEqual(
    observableLines.filter((line) => /\b(?:idToken|jwt|otpCode|challengeId|token)\b/i.test(line)),
    [],
    'demo Google Email OTP flow must not emit credential or token fields',
  );
}

function checkEmailOtpSessionGating() {
  const source = readRepoFile('apps/seams-site/src/flows/demo/hooks/useDemoSigningSession.ts');
  const otpBranchStart = source.indexOf("if (authMethod === 'email_otp')");
  const ordinaryUnlock = source.indexOf('await seams.auth.unlock(walletId', otpBranchStart);
  assert.notEqual(otpBranchStart, -1, 'Missing demo Email OTP session branch');
  assert.notEqual(ordinaryUnlock, -1, 'Missing ordinary demo session unlock path');

  const otpBranch = source.slice(otpBranchStart, ordinaryUnlock);
  assert.match(otpBranch, /currentSession\.retention === 'single_use'/);
  assert.match(otpBranch, /Email OTP per-operation policy does not support reusable sessions/);
  assert.match(otpBranch, /requestEmailOtpSigningSessionChallenge/);
  assert.match(otpBranch, /refreshEmailOtpSigningSession/);
  assert.ok(otpBranchStart < ordinaryUnlock, 'Email OTP gating must precede ordinary unlock');

  const observableLines = linesContaining(source, /\b(?:toast|console)\./);
  assert.deepEqual(
    observableLines.filter((line) => /\b(?:otpCode|challengeId|jwt|token)\b/i.test(line)),
    [],
    'demo signing-session UI must not emit credential or token fields',
  );
}

checkGoogleEmailOtpObservableSurfaces();
checkEmailOtpSessionGating();

console.log('[check-demo-otp-redaction-and-gating] passed');
