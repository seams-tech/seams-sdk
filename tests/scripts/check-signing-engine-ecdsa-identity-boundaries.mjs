#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');

function absolutePath(relativePath) {
  return path.join(repoRoot, relativePath);
}

function readRepoFile(relativePath) {
  return fs.readFileSync(absolutePath(relativePath), 'utf8');
}

function listTsFiles(relativeDir) {
  const absoluteDir = absolutePath(relativeDir);
  return fs.readdirSync(absoluteDir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) {
      return listTsFiles(relativePath);
    }
    return /\.(ts|tsx)$/.test(entry.name) ? [relativePath] : [];
  });
}

function listSourceFiles(relativePath) {
  const absolute = absolutePath(relativePath);
  const stat = fs.statSync(absolute);
  if (stat.isFile()) {
    return /\.(ts|tsx|rs)$/.test(relativePath) ? [relativePath] : [];
  }
  return fs.readdirSync(absolute, { withFileTypes: true }).flatMap((entry) => {
    const entryPath = path.join(relativePath, entry.name).split(path.sep).join('/');
    if (entry.isDirectory()) {
      return listSourceFiles(entryPath);
    }
    return /\.(ts|tsx|rs)$/.test(entry.name) ? [entryPath] : [];
  });
}

function findCallObjects(source, callName) {
  const objects = [];
  let searchFrom = 0;
  const needle = `${callName}({`;

  while (true) {
    const callStart = source.indexOf(needle, searchFrom);
    if (callStart < 0) {
      break;
    }

    let depth = 0;
    let end = -1;
    for (let i = callStart + callName.length + 1; i < source.length; i += 1) {
      const char = source[i];
      if (char === '{') {
        depth += 1;
      }
      if (char === '}') {
        depth -= 1;
        if (depth === 0) {
          end = i + 1;
          break;
        }
      }
    }

    if (end < 0) {
      break;
    }
    objects.push(source.slice(callStart, end));
    searchFrom = end;
  }

  return objects;
}

function findLoggerCalls(source) {
  const calls = [];
  const pattern = /(?:^|[^\w])(?:this|ctx|options|input)?\.?logger\.(?:info|warn|error|debug)\(/g;
  let match;
  while ((match = pattern.exec(source))) {
    const openParenIndex = source.indexOf('(', match.index);
    if (openParenIndex < 0) {
      continue;
    }
    let depth = 0;
    let end = -1;
    for (let i = openParenIndex; i < source.length; i += 1) {
      const char = source[i];
      if (char === '(') {
        depth += 1;
      }
      if (char === ')') {
        depth -= 1;
        if (depth === 0) {
          end = i + 1;
          break;
        }
      }
    }
    if (end < 0) {
      break;
    }
    calls.push(source.slice(match.index, end));
    pattern.lastIndex = end;
  }
  return calls;
}

function lineNumberForIndex(source, index) {
  return source.slice(0, index).split(/\r?\n/).length;
}

function findBalancedBlock(source, openBraceIndex) {
  if (openBraceIndex < 0) {
    return null;
  }
  let depth = 0;
  for (let i = openBraceIndex; i < source.length; i += 1) {
    const char = source[i];
    if (char === '{') {
      depth += 1;
    }
    if (char === '}') {
      depth -= 1;
      if (depth === 0) {
        return source.slice(openBraceIndex, i + 1);
      }
    }
  }
  return null;
}

function findTypeDeclaration(source, name) {
  const declarationPattern = new RegExp(`\\b(?:export\\s+)?(type|interface)\\s+${name}\\b`);
  const match = declarationPattern.exec(source);
  if (!match) {
    throw new Error(`Missing declaration ${name}`);
  }

  if (match[1] === 'interface') {
    const openBraceIndex = source.indexOf('{', match.index);
    const block = findBalancedBlock(source, openBraceIndex);
    if (!block) {
      throw new Error(`Could not parse interface ${name}`);
    }
    return block;
  }

  let curlyDepth = 0;
  let parenDepth = 0;
  let bracketDepth = 0;
  for (let i = match.index; i < source.length; i += 1) {
    const char = source[i];
    if (char === '{') {
      curlyDepth += 1;
    }
    if (char === '}') {
      curlyDepth -= 1;
    }
    if (char === '(') {
      parenDepth += 1;
    }
    if (char === ')') {
      parenDepth -= 1;
    }
    if (char === '[') {
      bracketDepth += 1;
    }
    if (char === ']') {
      bracketDepth -= 1;
    }
    if (char === ';' && curlyDepth === 0 && parenDepth === 0 && bracketDepth === 0) {
      return source.slice(match.index, i + 1);
    }
  }

  throw new Error(`Could not parse type ${name}`);
}

function findObjectBlockAfter(source, needle) {
  const start = source.indexOf(needle);
  if (start < 0) {
    throw new Error(`Missing object block after ${needle}`);
  }
  const openBraceIndex = source.indexOf('{', start);
  const block = findBalancedBlock(source, openBraceIndex);
  if (!block) {
    throw new Error(`Could not parse object block after ${needle}`);
  }
  return block;
}

function findChainedMethodCallObjects(source, methodNames, receiverPattern = '\\b\\w+') {
  const calls = [];
  const pattern = new RegExp(
    `(?:${receiverPattern})\\s*\\.(?:${methodNames.join('|')})\\s*\\(\\s*{`,
    'g',
  );
  let match;
  while ((match = pattern.exec(source))) {
    const dottedNames = [...match[0].matchAll(/\.(\w+)/g)];
    const methodName = dottedNames[dottedNames.length - 1]?.[1];
    if (!methodName) {
      continue;
    }
    const openBraceIndex = source.indexOf('{', match.index);
    const block = findBalancedBlock(source, openBraceIndex);
    if (!block) {
      continue;
    }
    calls.push({
      methodName,
      line: lineNumberForIndex(source, match.index),
      block,
    });
    pattern.lastIndex = openBraceIndex + block.length;
  }
  return calls;
}

function findMethodDeclarationAndBody(source, methodName) {
  const methodStart = source.indexOf(`async ${methodName}(`);
  if (methodStart < 0) {
    return null;
  }
  const openParenIndex = source.indexOf('(', methodStart);
  let parenDepth = 0;
  let closeParenIndex = -1;
  for (let i = openParenIndex; i < source.length; i += 1) {
    const char = source[i];
    if (char === '(') {
      parenDepth += 1;
    }
    if (char === ')') {
      parenDepth -= 1;
      if (parenDepth === 0) {
        closeParenIndex = i;
        break;
      }
    }
  }
  if (closeParenIndex < 0) {
    return null;
  }
  const bodyOpenIndex = source.indexOf('{', closeParenIndex);
  const bodyBlock = findBalancedBlock(source, bodyOpenIndex);
  return bodyBlock ? source.slice(methodStart, bodyOpenIndex) + bodyBlock : null;
}

function expectRequiredFields(block, fields, context) {
  return fields
    .filter((field) => !new RegExp(`\\b${field}\\s*(?::|,)`).test(block))
    .map((field) => `${context} is missing required ${field}`);
}

function expectNoField(block, field, context) {
  const searchable = block.replace(new RegExp(`\\b${field}\\?:\\s*never\\b`, 'g'), '');
  return new RegExp(`\\b${field}\\s*(?::|\\?:|,)`).test(searchable)
    ? [`${context} exposes ${field}`]
    : [];
}

function expectNoNearAccountId(block, context, options = {}) {
  const searchable = options.allowNeverTripwire
    ? block.replace(/\bnearAccountId\?:\s*never\b/g, '')
    : block;
  return /\bnearAccountId\b/.test(searchable) ? [`${context} exposes nearAccountId`] : [];
}

function assertNoOffenders(offenders, context) {
  if (offenders.length > 0) {
    throw new Error(`${context}:\n${offenders.join('\n')}`);
  }
}

function isRefactor84LinkDeviceStub(relativePath, source) {
  return (
    relativePath === 'packages/sdk-web/src/SeamsWeb/operations/devices/linkDevice.ts' &&
    source.includes('LINK_DEVICE_REFACTOR_84_MESSAGE') &&
    source.includes('Linked-device lane creation is disabled until refactor 84 lands')
  );
}

function checkEmailOtpEcdsaExportAuthorizationUsesWalletSessionIdentity() {
  const confirmationSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/flows/recovery/keyExportConfirmation.ts',
  );
  const emailOtpExportPromptSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/otpPrompt/exportAuthorization.ts',
  );
  const ecdsaExportSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportFlow.ts',
  );
  const nearAccountBranchIndex = confirmationSource.indexOf("kind: 'near_account_export_auth'");
  const nearAccountBranch =
    nearAccountBranchIndex < 0
      ? ''
      : confirmationSource.slice(nearAccountBranchIndex, nearAccountBranchIndex + 350);
  const offenders = [];

  if (/ThresholdEcdsaChainTarget|WalletAuthCurve/.test(nearAccountBranch)) {
    offenders.push('near_account_export_auth still accepts broad ECDSA-capable fields');
  }
  if (ecdsaExportSource.includes("kind: 'near_account_export_auth'")) {
    offenders.push('ECDSA export flow still requests near_account_export_auth');
  }
  if (/toAccountId\([^)]*(?:walletId|walletSessionUserId)[^)]*\)/.test(confirmationSource)) {
    offenders.push('ECDSA export confirmation coerces wallet identity through toAccountId');
  }
  if (/toAccountId\([^)]*(?:walletId|walletSessionUserId)[^)]*\)/.test(ecdsaExportSource)) {
    offenders.push('ECDSA export flow coerces wallet identity through toAccountId');
  }
  if (/\bnearAccountId:\s*toAccountId\([^)]*walletId[^)]*\)/.test(ecdsaExportSource)) {
    offenders.push('ECDSA export viewer receives wallet id through nearAccountId conversion');
  }
  if (
    /requestEmailOtpExportAuthorization\(args:\s*\{\s*nearAccountId:/m.test(
      emailOtpExportPromptSource,
    )
  ) {
    offenders.push('Email OTP export prompt helper still accepts only nearAccountId identity');
  }
  if (/requestEmailOtpExportAuthorizationValue\(\{\s*nearAccountId:/m.test(confirmationSource)) {
    offenders.push('Email OTP ECDSA export still passes wallet identity as nearAccountId');
  }

  assertNoOffenders(offenders, 'Email OTP ECDSA export authorization identity');
}

function checkEcdsaDerivationExportConfirmationDigestBindsSlot() {
  const passkeyExportSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaDerivationExport.ts',
  );
  const emailOtpWorkerSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  );
  const passkeyDigest = findObjectBlockAfter(
    passkeyExportSource,
    'const confirmationDigest32B64u = await digestB64u(',
  );
  const emailOtpDigest = findObjectBlockAfter(
    emailOtpWorkerSource,
    'const confirmationDigest32B64u = await digestB64u(',
  );
  const offenders = [];

  for (const [block, context] of [
    [passkeyDigest, 'passkey export digest'],
    [emailOtpDigest, 'Email OTP export digest'],
  ]) {
    if (!block.includes('evmFamilySigningKeySlotId')) {
      offenders.push(`${context} does not bind evmFamilySigningKeySlotId`);
    }
  }

  assertNoOffenders(offenders, 'Router A/B ECDSA derivation export confirmation digest');
}

function checkBudgetStatusLookupAvoidsSubjectWideEcdsaScanFallback() {
  const source = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts',
  );
  const offenders = [];
  for (const forbidden of ['listThresholdEcdsaRuntimeLanesForSubject', 'toWalletId(walletId)']) {
    if (source.includes(forbidden)) {
      offenders.push(`budgetStatusReader contains forbidden ECDSA fallback ${forbidden}`);
    }
  }

  assertNoOffenders(offenders, 'budget status lookup fallback');
}

function checkBrowserSigningSurfaceDoesNotDeriveEcdsaSubjectFromAccounts() {
  const source = readRepoFile(
    'packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts',
  );
  const methodNames = [
    'signEvmFamily',
    'bootstrapEcdsaSession',
    'requestEmailOtpSigningSessionChallenge',
    'refreshEmailOtpSigningSession',
    'loginWithEmailOtpEcdsaCapabilityInternal',
    'enrollAndLoginWithEmailOtpEcdsaCapabilityInternal',
  ];
  const offenders = [];

  for (const methodName of methodNames) {
    const methodSource = findMethodDeclarationAndBody(source, methodName);
    if (!methodSource) {
      continue;
    }
    if (/\btoWalletId\(/.test(methodSource)) {
      offenders.push(`BrowserSigningSurface.${methodName} derives subject identity`);
    }
    if (/\bnearAccountId\b/.test(methodSource)) {
      offenders.push(`BrowserSigningSurface.${methodName} exposes nearAccountId`);
    }
  }

  assertNoOffenders(offenders, 'browser signing surface ECDSA identity');
}

function checkPublicSdkSignerFixturesUseDomainShapedCalls() {
  const ecdsaSigningMethods = ['signTempo', 'executeEvmFamilyTransaction'];
  const ecdsaLifecycleMethods = [
    'reportBroadcastAccepted',
    'reportBroadcastRejected',
    'reportFinalized',
    'reportDroppedOrReplaced',
    'reconcileNonceLane',
  ];
  const nearMethods = [
    'executeAction',
    'signAndSendTransaction',
    'signTransactionWithActions',
    'signDelegateAction',
    'signAndSendDelegateAction',
    'signNEP413Message',
  ];
  const offenders = [];

  for (const root of ['tests/helpers', 'tests/e2e', 'tests/unit']) {
    for (const relativePath of listTsFiles(root)) {
      const source = readRepoFile(relativePath);
      for (const call of findChainedMethodCallObjects(
        source,
        ecdsaSigningMethods,
        '\\b(?:pm|seams)\\.tempo|\\bsigner',
      )) {
        offenders.push(
          ...expectRequiredFields(
            call.block,
            ['walletSession', 'chainTarget'],
            `${relativePath}:${call.line} ${call.methodName}`,
          ),
          ...expectNoField(
            call.block,
            'subjectId',
            `${relativePath}:${call.line} ${call.methodName}`,
          ),
          ...expectNoNearAccountId(call.block, `${relativePath}:${call.line} ${call.methodName}`),
        );
      }
      for (const call of findChainedMethodCallObjects(
        source,
        ecdsaLifecycleMethods,
        '\\b(?:pm|seams)\\.tempo|\\bsigner',
      )) {
        offenders.push(
          ...expectRequiredFields(
            call.block,
            ['walletSession'],
            `${relativePath}:${call.line} ${call.methodName}`,
          ),
          ...expectNoNearAccountId(call.block, `${relativePath}:${call.line} ${call.methodName}`),
        );
      }
      for (const call of findChainedMethodCallObjects(
        source,
        nearMethods,
        '\\b(?:pm|seams)\\.near|\\bsigner',
      )) {
        offenders.push(
          ...expectRequiredFields(
            call.block,
            ['nearAccount'],
            `${relativePath}:${call.line} ${call.methodName}`,
          ),
        );
        if (/\bnearAccountId\s*:/.test(call.block)) {
          offenders.push(`${relativePath}:${call.line} ${call.methodName} uses nearAccountId`);
        }
      }
    }
  }

  assertNoOffenders(offenders, 'public SDK signer fixtures');
}

function checkOptionalLifecycleFieldsStayBehindNarrowBoundaries() {
  const searchRoots = [
    'packages/sdk-web/src/core/signingEngine/session/warmCapabilities',
    'packages/sdk-web/src/core/signingEngine/session/passkey',
    'packages/sdk-web/src/core/signingEngine/session/emailOtp',
    'packages/sdk-web/src/core/signingEngine/session/budget',
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily',
  ];
  const optionalLifecycleFieldAllowlist = new Set([
    'packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
  ]);
  const offenders = [];
  const pattern =
    /sessionId\?: string|signingGrantId\?: string|thresholdSessionId\?: string|walletSessionRouteAuth\?:(?!\s*never\b)|webauthnAuthentication\?:(?!\s*never\b)|clientRootShare32B64u\?:(?!\s*never\b)|warmRecord\?:|warmKeyRef\?:|reauthRecord\?:|emailOtpAuthContext\?:(?!\s*never\b)/;

  for (const root of searchRoots) {
    for (const relativePath of listTsFiles(root)) {
      const source = readRepoFile(relativePath);
      if (!pattern.test(source)) {
        continue;
      }
      if (optionalLifecycleFieldAllowlist.has(relativePath)) {
        continue;
      }
      offenders.push(relativePath);
    }
  }

  assertNoOffenders(offenders, 'optional lifecycle field boundaries');
}

function checkOldWarmEcdsaLifecycleSymbolsStayDeleted() {
  const offenders = [];
  const pattern =
    /\bEnsureWarmEcdsaCapabilityReadyArgs\b|\bResolveWarmEcdsaBootstrapRequestArgs\b|\bWarmEcdsaBootstrapRequest\b|\bProvisionWarmEcdsaCapabilityArgs\b|\bbuildProvisionWarmEcdsaCapabilityArgs\b/;
  for (const relativePath of listTsFiles('packages/sdk-web/src/core/signingEngine')) {
    const source = readRepoFile(relativePath);
    if (pattern.test(source)) {
      offenders.push(relativePath);
    }
  }

  assertNoOffenders(offenders, 'old warm ECDSA lifecycle symbols');
}

function checkEcdsaProvisionPlansOnlyComeFromBuilders() {
  const provisionPlanConstructionPatterns = [
    /return\s*{\s*kind:\s*'passkey_ecdsa_session_provision'/,
    /return\s*{\s*kind:\s*'wallet_session_ecdsa_reconnect'/,
    /return\s*{\s*kind:\s*'email_otp_ecdsa_session_provision'/,
  ];
  const builderCalls = [
    'buildPasskeyEcdsaSessionProvision',
    'buildWalletSessionEcdsaReconnect',
    'buildEmailOtpEcdsaSessionProvision',
    'buildEcdsaSessionProvisionPlan',
  ];
  const offenders = [];

  for (const relativePath of listTsFiles('packages/sdk-web/src/core/signingEngine')) {
    if (
      relativePath ===
        'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts' ||
      relativePath.endsWith('.typecheck.ts')
    ) {
      continue;
    }
    const source = readRepoFile(relativePath);
    for (const pattern of provisionPlanConstructionPatterns) {
      const match = source.match(pattern);
      if (match?.[0]) {
        offenders.push(`${relativePath} directly constructs ${match[0]}`);
      }
    }
    if (source.includes('as EcdsaSessionProvisionPlan')) {
      offenders.push(`${relativePath} casts to EcdsaSessionProvisionPlan`);
    }
    for (const callName of builderCalls) {
      for (const callObject of findCallObjects(source, callName)) {
        if (callObject.includes('...')) {
          offenders.push(`${relativePath} uses object spread in ${callName}()`);
        }
      }
    }
  }

  assertNoOffenders(offenders, 'ECDSA provision plan construction');
}

function checkServerBudgetStatusRoutesStayParserOwned() {
  const routeFiles = ['packages/sdk-server-ts/src/router/cloudflare/routes/sessions.ts'];
  const offenders = [];
  for (const relativePath of routeFiles) {
    const source = readRepoFile(relativePath);
    for (const forbidden of [
      'parseThresholdEcdsaSessionClaims',
      'parseThresholdEd25519SessionClaims',
      'body.signingGrantId',
      'body.thresholdSessionId',
    ]) {
      if (source.includes(forbidden)) {
        offenders.push(`${relativePath} contains forbidden route-local parsing token ${forbidden}`);
      }
    }
  }

  assertNoOffenders(offenders, 'server budget-status routes');
}

function checkRawEcdsaIdentityParsingStaysOutOfInternals() {
  const searchRoots = [
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily',
    'packages/sdk-web/src/core/signingEngine/session/passkey',
    'packages/sdk-web/src/core/signingEngine/session/warmCapabilities',
  ];
  const rawIdentityParsingAllowlist = new Set([
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
  ]);
  const offenders = [];
  const patterns = [
    {
      name: 'object field identity parsing',
      pattern:
        /(thresholdSessionId|signingGrantId)\s*:\s*String\((?:[^)\n]*)(?:thresholdSessionId|signingGrantId)(?:[^)\n]*)\)\.trim\(/g,
    },
    {
      name: 'raw identity comparison',
      pattern:
        /String\([^;\n]*(?:thresholdSessionId|signingGrantId)[^;\n]*\)\.trim\(\)\s*(?:={2,3}|!={1,2})\s*String\([^;\n]*(?:thresholdSessionId|signingGrantId)[^;\n]*\)\.trim\(\)/g,
    },
    {
      name: 'paired local identity parsing',
      pattern:
        /\b(?:const|let)\s+\w*(?:ThresholdSessionId|SessionId)\s*=\s*String\([^;\n]*thresholdSessionId[^;\n]*\)\.trim\(\)[\s\S]{0,240}\b(?:const|let)\s+\w*SigningGrantId\s*=\s*String\([^;\n]*signingGrantId[^;\n]*\)\.trim\(\)/g,
    },
    {
      name: 'paired local identity parsing',
      pattern:
        /\b(?:const|let)\s+\w*SigningGrantId\s*=\s*String\([^;\n]*signingGrantId[^;\n]*\)\.trim\(\)[\s\S]{0,240}\b(?:const|let)\s+\w*(?:ThresholdSessionId|SessionId)\s*=\s*String\([^;\n]*thresholdSessionId[^;\n]*\)\.trim\(\)/g,
    },
  ];

  for (const root of searchRoots) {
    for (const relativePath of listTsFiles(root)) {
      const source = readRepoFile(relativePath);
      for (const { name, pattern } of patterns) {
        pattern.lastIndex = 0;
        if (!pattern.test(source)) {
          continue;
        }
        pattern.lastIndex = 0;
        if (rawIdentityParsingAllowlist.has(relativePath)) {
          continue;
        }
        offenders.push(`${relativePath} (${name})`);
      }
    }
  }

  assertNoOffenders(offenders, 'raw ECDSA identity parsing');
}

function checkWalletUnlockKeepsRawEcdsaParsingAtBoundaries() {
  const loginSource = readRepoFile('packages/sdk-web/src/SeamsWeb/operations/auth/login.ts');
  const offenders = [];
  for (const forbidden of [
    'metadata.sharedEvmFamilyKey',
    'metadata.keyHandle',
    'metadata.ecdsaThresholdKeyId',
    'metadata.signingRootId',
    'metadata.signingRootVersion',
    'metadata.participantIds',
    'metadata.thresholdOwnerAddress',
    'metadata.ownerAddress',
    'const records = inventory.records',
    '/router-ab/ecdsa-derivation/key-identities',
  ]) {
    if (loginSource.includes(forbidden)) {
      offenders.push(`login unlock path contains raw boundary token ${forbidden}`);
    }
  }

  assertNoOffenders(offenders, 'wallet unlock ECDSA raw parsing');
}

function checkPrepareParsersDeriveSigningRootFromRuntimePolicyScope() {
  const parserTargets = [
    {
      relativePath: 'packages/sdk-web/src/SeamsWeb/operations/devices/linkDevice.ts',
      functionName: 'parseLinkDeviceEcdsaPrepare',
    },
  ];
  const offenders = [];

  for (const { relativePath, functionName } of parserTargets) {
    const source = readRepoFile(relativePath);
    if (isRefactor84LinkDeviceStub(relativePath, source)) {
      continue;
    }
    const functionStart = source.indexOf(`function ${functionName}(`);
    const openBraceIndex = source.indexOf('{', functionStart);
    const block = findBalancedBlock(source, openBraceIndex);
    if (!block) {
      offenders.push(`${relativePath} missing ${functionName}`);
      continue;
    }
    if (!block.includes('signingRootScopeFromRuntimePolicyScope(runtimePolicyScope)')) {
      offenders.push(`${relativePath} ${functionName} does not derive signing root from scope`);
    }
    if (/\bvalue\.signingRoot(?:Id|Version)\b/.test(block)) {
      offenders.push(`${relativePath} ${functionName} reads signing root from payload`);
    }
    if (!/\bruntimePolicyScope\s*,/.test(block)) {
      offenders.push(`${relativePath} ${functionName} does not return runtimePolicyScope`);
    }
  }

  assertNoOffenders(offenders, 'ECDSA prepare parser signing-root derivation');
}

function checkNearAccountToEcdsaSubjectDerivationsStayOutOfSigningPaths() {
  const guardedRoots = [
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily',
    'packages/sdk-web/src/core/signingEngine/session/passkey',
    'packages/sdk-web/src/core/signingEngine/session/warmCapabilities',
    'packages/sdk-web/src/core/signingEngine/threshold/ecdsa',
    'packages/sdk-web/src/core/rpcClients/evm',
  ];
  const accountToSubjectPattern =
    /toWalletId\(\s*(?:(?:args|input|request)\.)?(?:nearAccountId|accountId)\s*\)/;
  const offenders = [];
  for (const relativePath of guardedRoots.flatMap((root) => listTsFiles(root))) {
    if (relativePath.endsWith('.typecheck.ts')) {
      continue;
    }
    const source = readRepoFile(relativePath);
    const lines = source.split(/\r?\n/);
    lines.forEach((line, index) => {
      if (accountToSubjectPattern.test(line)) {
        offenders.push(`${relativePath}:${index + 1}`);
      }
    });
  }

  assertNoOffenders(offenders, 'near account to ECDSA subject derivations');
}

function checkNearAccountIdResidueStaysOutOfEcdsaOnlyPaths() {
  const forbiddenPaths = [
    'packages/sdk-web/src/SeamsWeb/operations/evm',
    'packages/sdk-web/src/SeamsWeb/operations/tempo',
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily',
    'packages/sdk-web/src/core/signingEngine/nonce/evmNonceLane.ts',
    'packages/sdk-web/src/core/signingEngine/session/budget',
    'packages/sdk-web/src/core/signingEngine/chains/evm',
    'packages/sdk-web/src/core/signingEngine/threshold/ecdsa',
    'packages/sdk-web/src/core/rpcClients/evm',
    'packages/sdk-server-ts/src/core/ThresholdService/evmCryptoWasm.ts',
  ];
  const offenders = [];
  for (const relativePath of forbiddenPaths.flatMap((entry) => listSourceFiles(entry))) {
    const source = readRepoFile(relativePath);
    if (/\bnearAccountId\b/.test(source)) {
      offenders.push(relativePath);
    }
  }

  assertNoOffenders(offenders, 'nearAccountId residue in ECDSA-only paths');
}

function checkThresholdServerLogsDoNotEmitRawSecretMaterial() {
  const roots = [
    'packages/sdk-server-ts/src/core/ThresholdService',
    'packages/sdk-server-ts/src/threshold/session/signingSessionSeal',
  ];
  const forbiddenFields = [
    'ciphertext',
    'wrappedCiphertext',
    'clientSignatureShareB64u',
    'cosignerShareB64u',
    'clientVerifyingShareB64u',
    'relayerSigningShareB64u',
    'secretBytes',
    'privateKey',
    'privateKeyHex',
    'token',
    'authorizationHeader',
    'cookieHeader',
    'claims',
  ];
  const offenders = [];
  for (const root of roots) {
    for (const relativePath of listTsFiles(root)) {
      const source = readRepoFile(relativePath);
      for (const call of findLoggerCalls(source)) {
        for (const field of forbiddenFields) {
          const fieldPattern = new RegExp(`\\b${field}\\b\\s*:`);
          if (fieldPattern.test(call)) {
            offenders.push(`${relativePath} logs forbidden field ${field}`);
          }
        }
      }
    }
  }

  assertNoOffenders(offenders, 'threshold/server log material');
}

function checkStrictEcdsaActivationBranchesOnlyComeFromBuilders() {
  const allowedFiles = new Set([
    'packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts',
    'packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsaSession.ts',
  ]);
  const offenders = [];
  const pattern =
    /kind:\s*'(passkey_ecdsa_activation|email_otp_ecdsa_activation|wallet_session_reconnect)'/;
  for (const relativePath of listTsFiles('packages/sdk-web/src/core/signingEngine')) {
    if (relativePath.endsWith('.typecheck.ts')) {
      continue;
    }
    const source = readRepoFile(relativePath);
    if (!pattern.test(source)) {
      continue;
    }
    if (!allowedFiles.has(relativePath)) {
      offenders.push(relativePath);
    }
  }

  assertNoOffenders(offenders, 'strict ECDSA activation branches');
}

function checkStrictActivationSessionStateAvoidsCastEscapes() {
  const offenders = [];
  const pattern =
    /\bas (?:ThresholdEcdsaActivationRequest|ThresholdEcdsaPasskeyActivationRequest|ThresholdEcdsaEmailOtpActivationRequest|ThresholdEcdsaWalletSessionReconnectRequest|PasskeyEcdsaActivation|EmailOtpEcdsaActivation|WalletSessionEcdsaActivation|PreparedEvmFamilyEcdsaSigningSession|EcdsaSessionProvisionPlan)\b/;
  for (const relativePath of [
    ...listTsFiles('packages/sdk-web/src/core/signingEngine/session/passkey'),
    ...listTsFiles('packages/sdk-web/src/core/signingEngine/flows/signEvmFamily'),
  ]) {
    const source = readRepoFile(relativePath);
    if (pattern.test(source)) {
      offenders.push(relativePath);
    }
  }

  assertNoOffenders(offenders, 'strict activation/session cast escapes');
}

function checkStrictActivationSessionBuildersAvoidBroadSpreadShortcuts() {
  const offenders = [];
  const pattern = /\.\.\.(?:baseArgs|args\.signingAuthPlan|activation|effectivePlan)\b/;
  for (const relativePath of [
    'packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts',
    'packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsaSession.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/requireEvmFamilyStepUpAuth.ts',
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
  ]) {
    const source = readRepoFile(relativePath);
    if (pattern.test(source)) {
      offenders.push(relativePath);
    }
  }

  assertNoOffenders(offenders, 'strict activation/session broad spread shortcuts');
}

function checkPublicSdkEcdsaInputsStayWalletSessionShaped() {
  const source = readRepoFile('packages/sdk-web/src/SeamsWeb/publicApi/types.ts');
  const namedDeclarations = [
    {
      name: 'SignTempoArgs',
      required: ['walletSession', 'chainTarget'],
      forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      allowNeverTripwire: true,
    },
    {
      name: 'ReportTempoNonceLifecycleBaseArgs',
      required: ['walletSession', 'signedResult'],
      forbidden: ['runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      allowNeverTripwire: true,
    },
    {
      name: 'ExecuteEvmFamilyTransactionArgs',
      declarationNames: ['ExecuteEvmFamilyTransactionBaseArgs', 'ExecuteEvmFamilyTransactionArgs'],
      required: ['walletSession', 'chainTarget'],
      forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      allowNeverTripwire: true,
    },
    {
      name: 'BootstrapThresholdEcdsaSessionArgs',
      required: ['walletSession', 'chainTarget'],
      forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      allowNeverTripwire: true,
    },
    {
      name: 'EmailOtpEcdsaCapabilityArgs',
      required: ['walletSession', 'chainTarget'],
      forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      allowNeverTripwire: true,
    },
    {
      name: 'ExportKeypairWithUIInput',
      sourcePath: 'packages/sdk-web/src/core/signingEngine/flows/recovery/keyExportFlow.ts',
      declarationNames: ['SigningEngineExportKeypairWithUIInput'],
      required: ['walletSession', 'chainTarget'],
      forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
      allowNeverTripwire: true,
    },
  ];
  const inlineArgBlocks = [
    {
      context: 'AuthCapability.prefillRouterAbEcdsaDerivationPresignaturePool',
      block: findObjectBlockAfter(source, 'prefillRouterAbEcdsaDerivationPresignaturePool(args: {'),
      required: ['walletSession', 'chainTarget'],
    },
    {
      context: 'AuthCapability.requestEmailOtpSigningSessionChallenge',
      block: findObjectBlockAfter(source, 'requestEmailOtpSigningSessionChallenge(args: {'),
      required: ['walletSession', 'chainTarget'],
    },
    {
      context: 'AuthCapability.refreshEmailOtpSigningSession',
      block: findObjectBlockAfter(source, 'refreshEmailOtpSigningSession(args: {'),
      required: ['walletSession', 'chainTarget'],
    },
  ];
  const offenders = [];

  for (const declaration of namedDeclarations) {
    const declarationSource = declaration.sourcePath
      ? readRepoFile(declaration.sourcePath)
      : source;
    const declarationNames = declaration.declarationNames || [declaration.name];
    const block = declarationNames
      .map((name) => findTypeDeclaration(declarationSource, name))
      .join('\n');
    offenders.push(
      ...expectRequiredFields(block, declaration.required, declaration.name),
      ...declaration.forbidden.flatMap((field) => expectNoField(block, field, declaration.name)),
      ...expectNoNearAccountId(block, declaration.name, {
        allowNeverTripwire: declaration.allowNeverTripwire,
      }),
    );
  }

  for (const { context, block, required } of inlineArgBlocks) {
    offenders.push(
      ...expectRequiredFields(block, required, context),
      ...expectNoNearAccountId(block, context, { allowNeverTripwire: true }),
    );
  }

  assertNoOffenders(offenders, 'public SDK ECDSA inputs');
}

function checkEcdsaIframePayloadsStayWalletSessionShaped() {
  const source = readRepoFile('packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts');
  const namedDeclarations = [
    {
      name: 'PMSignTempoPayload',
      required: ['walletSession', 'chainTarget'],
      forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
    },
    {
      name: 'PMTempoNonceLifecyclePayloadBase',
      required: ['walletSession', 'signedResult'],
      forbidden: ['runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
    },
    {
      name: 'PMExportKeypairUiPayload',
      required: ['walletSession', 'chainTarget'],
      forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
    },
    {
      name: 'PMEmailOtpSigningSessionChallengePayload',
      required: ['walletSession', 'chainTarget'],
      forbidden: ['runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
    },
    {
      name: 'PMEmailOtpEcdsaCapabilityPayload',
      required: ['walletSession', 'chainTarget'],
      forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
    },
    {
      name: 'PMRefreshEmailOtpSigningSessionPayload',
      required: ['walletSession', 'chainTarget'],
      forbidden: ['runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
    },
    {
      name: 'PMPrefillRouterAbEcdsaDerivationPresignaturePoolPayload',
      required: ['walletSession', 'chainTarget'],
      forbidden: ['subjectId', 'runtimePolicyScope', 'signingRootId', 'signingRootVersion'],
    },
  ];
  const offenders = [];

  for (const declaration of namedDeclarations) {
    const block = findTypeDeclaration(source, declaration.name);
    offenders.push(
      ...expectRequiredFields(block, declaration.required, declaration.name),
      ...declaration.forbidden.flatMap((field) => expectNoField(block, field, declaration.name)),
      ...expectNoNearAccountId(block, declaration.name),
    );
  }

  assertNoOffenders(offenders, 'ECDSA iframe payloads');
}

function checkActiveSdkEcdsaKeyRefsRejectSigningRootIdentityFields() {
  const source = readRepoFile('packages/sdk-web/src/core/signingEngine/interfaces/signing.ts');
  const keyRefBlock = findTypeDeclaration(source, 'KeyRef');
  const offenders = [];

  for (const field of ['signingRootId', 'signingRootVersion']) {
    const neverFieldPattern = new RegExp(`\\b${field}\\?:\\s*never\\b`);
    if (!neverFieldPattern.test(keyRefBlock)) {
      offenders.push(`KeyRef does not reject ${field} with a never field`);
    }
  }

  const searchable = keyRefBlock
    .replace(/\bsigningRootId\?:\s*never\b/g, '')
    .replace(/\bsigningRootVersion\?:\s*never\b/g, '');
  if (/\bsigningRoot(?:Id|Version)\??\s*:/.test(searchable)) {
    offenders.push('KeyRef exposes signing-root identity outside never tripwires');
  }

  assertNoOffenders(offenders, 'active SDK ECDSA key refs');
}

function checkEcdsaDerivationRoleLocalBootstrapTypesKeepLaneIdentityExplicit() {
  const clientSource = readRepoFile(
    'packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts',
  );
  const clientSessionPolicySource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts',
  );
  const serverSource = readRepoFile('packages/sdk-server-ts/src/core/types.ts');
  const thresholdPrfSource = readRepoFile(
    'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts',
  );
  const ecdsaDerivationClientSource = readRepoFile(
    'packages/sdk-web/src/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm.ts',
  );
  const offenders = [];
  const requiredRoleLocalBootstrapFields = [
    'walletId',
    'evmFamilySigningKeySlotId',
    'ecdsaThresholdKeyId',
    'signingRootId',
    'signingRootVersion',
    'keyScope',
    'relayerKeyId',
    'derivationClientSharePublicKey33B64u',
    'contextBinding32B64u',
    'sessionId',
    'signingGrantId',
    'participantIds',
  ];

  for (const { source, file, typeName } of [
    {
      source: clientSource,
      file: 'packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts',
      typeName: 'ThresholdEcdsaDerivationRoleLocalBootstrapRequest',
    },
    {
      source: clientSource,
      file: 'packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts',
      typeName: 'ThresholdEcdsaDerivationRoleLocalBootstrapBodyBase',
    },
    {
      source: serverSource,
      file: 'packages/sdk-server-ts/src/core/types.ts',
      typeName: 'EcdsaDerivationClientBootstrapRequestBase',
    },
  ]) {
    const block = findTypeDeclaration(source, typeName);
    offenders.push(
      ...expectRequiredFields(block, requiredRoleLocalBootstrapFields, `${file} ${typeName}`),
      ...expectNoField(block, 'rpId', `${file} ${typeName}`),
      ...expectNoField(block, 'chainTarget', `${file} ${typeName}`),
      ...expectNoField(block, 'keyHandle', `${file} ${typeName}`),
      ...expectNoNearAccountId(block, `${file} ${typeName}`, {
        allowNeverTripwire: true,
      }),
    );
  }

  const serverRoleLocalRecordBlock = findTypeDeclaration(
    serverSource,
    'EcdsaDerivationRoleLocalKeyRecord',
  );
  offenders.push(
    ...expectRequiredFields(
      serverRoleLocalRecordBlock,
      [
        'version',
        'keyHandle',
        'walletId',
        'evmFamilySigningKeySlotId',
        'ecdsaThresholdKeyId',
        'signingRootId',
        'signingRootVersion',
        'keyScope',
        'relayerKeyId',
        'contextBinding32B64u',
        'clientPublicKey33B64u',
        'relayerPublicKey33B64u',
        'groupPublicKey33B64u',
        'relayerShare32B64u',
        'publicTranscriptDigest32B64u',
      ],
      'packages/sdk-server-ts/src/core/types.ts EcdsaDerivationRoleLocalKeyRecord',
    ),
    ...expectNoField(
      serverRoleLocalRecordBlock,
      'relayerCaitSithInput',
      'packages/sdk-server-ts/src/core/types.ts EcdsaDerivationRoleLocalKeyRecord',
    ),
    ...expectNoField(
      serverRoleLocalRecordBlock,
      'rpId',
      'packages/sdk-server-ts/src/core/types.ts EcdsaDerivationRoleLocalKeyRecord',
    ),
    ...expectNoField(
      serverRoleLocalRecordBlock,
      'chainTarget',
      'packages/sdk-server-ts/src/core/types.ts EcdsaDerivationRoleLocalKeyRecord',
    ),
    ...expectNoNearAccountId(
      serverRoleLocalRecordBlock,
      'packages/sdk-server-ts/src/core/types.ts EcdsaDerivationRoleLocalKeyRecord',
    ),
  );

  const clientEcdsaPolicyBlock = findTypeDeclaration(
    clientSessionPolicySource,
    'EcdsaDerivationSessionPolicy',
  );
  offenders.push(
    ...expectRequiredFields(
      clientEcdsaPolicyBlock,
      ['walletId', 'evmFamilySigningKeySlotId', 'chainTarget', 'sessionId', 'signingGrantId'],
      'packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts EcdsaDerivationSessionPolicy',
    ),
    ...expectNoField(
      clientEcdsaPolicyBlock,
      'rpId',
      'packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts EcdsaDerivationSessionPolicy',
    ),
    ...expectNoField(
      clientEcdsaPolicyBlock,
      'userId',
      'packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts EcdsaDerivationSessionPolicy',
    ),
    ...expectNoNearAccountId(
      clientEcdsaPolicyBlock,
      'packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts EcdsaDerivationSessionPolicy',
    ),
  );

  const signingRootContextBlock = findTypeDeclaration(
    thresholdPrfSource,
    'EcdsaDerivationStableKeyPrfContext',
  );
  offenders.push(
    ...expectRequiredFields(
      signingRootContextBlock,
      ['applicationBindingDigest'],
      'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaDerivationStableKeyPrfContext',
    ),
    ...expectNoField(
      signingRootContextBlock,
      'walletId',
      'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaDerivationStableKeyPrfContext',
    ),
    ...expectNoField(
      signingRootContextBlock,
      'rpId',
      'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaDerivationStableKeyPrfContext',
    ),
    ...expectNoField(
      signingRootContextBlock,
      'signingRootId',
      'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaDerivationStableKeyPrfContext',
    ),
    ...expectNoField(
      signingRootContextBlock,
      'keyPurpose',
      'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaDerivationStableKeyPrfContext',
    ),
    ...expectNoField(
      signingRootContextBlock,
      'keyVersion',
      'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaDerivationStableKeyPrfContext',
    ),
    ...expectNoNearAccountId(
      signingRootContextBlock,
      'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaDerivationStableKeyPrfContext',
    ),
  );

  const ecdsaClientContextBlock = findTypeDeclaration(
    ecdsaDerivationClientSource,
    'ThresholdEcdsaDerivationStableKeyContext',
  );
  offenders.push(
    ...expectRequiredFields(
      ecdsaClientContextBlock,
      ['walletId', 'ecdsaThresholdKeyId', 'signingRootId', 'signingRootVersion'],
      'packages/sdk-web/src/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm.ts ThresholdEcdsaDerivationStableKeyContext',
    ),
    ...expectNoField(
      ecdsaClientContextBlock,
      'rpId',
      'packages/sdk-web/src/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm.ts ThresholdEcdsaDerivationStableKeyContext',
    ),
    ...expectNoField(
      ecdsaClientContextBlock,
      'chainTarget',
      'packages/sdk-web/src/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm.ts ThresholdEcdsaDerivationStableKeyContext',
    ),
    ...expectNoField(
      ecdsaClientContextBlock,
      'keyPurpose',
      'packages/sdk-web/src/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm.ts ThresholdEcdsaDerivationStableKeyContext',
    ),
    ...expectNoField(
      ecdsaClientContextBlock,
      'keyVersion',
      'packages/sdk-web/src/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm.ts ThresholdEcdsaDerivationStableKeyContext',
    ),
    ...expectNoNearAccountId(
      ecdsaClientContextBlock,
      'packages/sdk-web/src/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm.ts ThresholdEcdsaDerivationStableKeyContext',
    ),
  );

  for (const [block, context] of [
    [
      signingRootContextBlock,
      'packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts EcdsaDerivationStableKeyPrfContext',
    ],
    [
      ecdsaClientContextBlock,
      'packages/sdk-web/src/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm.ts ThresholdEcdsaDerivationStableKeyContext',
    ],
  ]) {
    for (const field of ['signingGrantId', 'thresholdSessionId']) {
      if (new RegExp(`\\b${field}\\s*:`).test(block)) {
        offenders.push(`${context} carries concrete ${field}`);
      }
      if (!new RegExp(`\\b${field}\\?:\\s*never\\b`).test(block)) {
        offenders.push(`${context} must reject ${field} with never`);
      }
    }
  }

  assertNoOffenders(offenders, 'Router A/B ECDSA derivation role-local bootstrap identity');
}

function checkEcdsaDerivationWasmPackageExportsStayRoleLocal() {
  const clientDts = readRepoFile(
    'wasm/router_ab_ecdsa_derivation_client/pkg/router_ab_ecdsa_derivation_client.d.ts',
  );
  const serverDts = readRepoFile(
    'wasm/router_ab_ecdsa_signing_worker/pkg/router_ab_ecdsa_signing_worker.d.ts',
  );
  const nearWorkerDts = readRepoFile('wasm/near_signer/pkg/wasm_signer_worker.d.ts');
  const offenders = [];

  for (const symbol of [
    'threshold_ecdsa_derivation_prepare_session',
    'threshold_ecdsa_derivation_prepare_client_request',
    'threshold_ecdsa_derivation_finalize_client_request',
    'threshold_ecdsa_derivation_prepare_server_session',
    'threshold_ecdsa_derivation_prepare_server_ceremony',
    'threshold_ecdsa_derivation_finalize_server_report',
    'threshold_ecdsa_derivation_open_server_output',
  ]) {
    if (clientDts.includes(symbol)) {
      offenders.push(`client WASM still exports ${symbol}`);
    }
    if (serverDts.includes(symbol)) {
      offenders.push(`server WASM still exports ${symbol}`);
    }
  }

  for (const symbol of [
    'PrepareThresholdEcdsaDerivationSession',
    'PrepareThresholdEcdsaDerivationClientRequest',
    'FinalizeThresholdEcdsaDerivationClientRequest',
  ]) {
    if (nearWorkerDts.includes(symbol)) {
      offenders.push(`near worker still exposes ${symbol}`);
    }
  }

  if (clientDts.includes('threshold_ecdsa_derivation_role_local_prepare_client_bootstrap')) {
    offenders.push('client WASM still exports legacy root-share ECDSA prepare helper');
  }
  if (clientDts.includes('threshold_ecdsa_derivation_role_local_export_artifact')) {
    offenders.push('client WASM still exports root-share ECDSA export helper');
  }
  if (clientDts.includes('threshold_ecdsa_derivation_role_local_client_bootstrap')) {
    offenders.push('client WASM still exports single-call role-local client bootstrap');
  }
  if (clientDts.includes('threshold_ecdsa_derivation_role_local_relayer_bootstrap')) {
    offenders.push('client WASM exposes relayer bootstrap helper');
  }

  assertNoOffenders(offenders, 'Router A/B ECDSA derivation WASM package exports');
}

function runChecks() {
  checkEmailOtpEcdsaExportAuthorizationUsesWalletSessionIdentity();
  checkEcdsaDerivationExportConfirmationDigestBindsSlot();
  checkBudgetStatusLookupAvoidsSubjectWideEcdsaScanFallback();
  checkBrowserSigningSurfaceDoesNotDeriveEcdsaSubjectFromAccounts();
  checkPublicSdkSignerFixturesUseDomainShapedCalls();
  checkOptionalLifecycleFieldsStayBehindNarrowBoundaries();
  checkOldWarmEcdsaLifecycleSymbolsStayDeleted();
  checkEcdsaProvisionPlansOnlyComeFromBuilders();
  checkServerBudgetStatusRoutesStayParserOwned();
  checkRawEcdsaIdentityParsingStaysOutOfInternals();
  checkWalletUnlockKeepsRawEcdsaParsingAtBoundaries();
  checkPrepareParsersDeriveSigningRootFromRuntimePolicyScope();
  checkNearAccountToEcdsaSubjectDerivationsStayOutOfSigningPaths();
  checkNearAccountIdResidueStaysOutOfEcdsaOnlyPaths();
  checkThresholdServerLogsDoNotEmitRawSecretMaterial();
  checkStrictEcdsaActivationBranchesOnlyComeFromBuilders();
  checkStrictActivationSessionStateAvoidsCastEscapes();
  checkStrictActivationSessionBuildersAvoidBroadSpreadShortcuts();
  checkPublicSdkEcdsaInputsStayWalletSessionShaped();
  checkEcdsaIframePayloadsStayWalletSessionShaped();
  checkActiveSdkEcdsaKeyRefsRejectSigningRootIdentityFields();
  checkEcdsaDerivationRoleLocalBootstrapTypesKeepLaneIdentityExplicit();
  checkEcdsaDerivationWasmPackageExportsStayRoleLocal();
}

runChecks();
console.log('[check-signing-engine-ecdsa-identity-boundaries] passed');
