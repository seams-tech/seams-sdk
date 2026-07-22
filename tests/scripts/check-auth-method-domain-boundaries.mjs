#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sourceRoots = [
  'packages/shared-ts/src',
  'packages/sdk-web/src',
  'packages/sdk-server-ts/src',
];

// Temporary Refactor 91 inventory. New occurrences fail; removals must shrink this list.
const approvedBinaryFallbacks = new Map([
  ['packages/sdk-web/src/SeamsWeb/assembly/browserSigningSurfaceAssembly.ts', 1],
  ['packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts', 1],
  ['packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts', 3],
  ['packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts', 1],
  ['packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit.ts', 1],
  ['packages/sdk-web/src/core/signingEngine/session/operationState/lanes.ts', 1],
  ['packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord.ts', 1],
  ['packages/sdk-web/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts', 1],
  ['packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts', 1],
]);
const approvedLiteralUnions = new Map([
  ['packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts', 1],
  ['packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportMaterial.ts', 1],
  [
    'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/requireEvmFamilyStepUpAuth.ts',
    1,
  ],
  ['packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget.ts', 1],
  [
    'packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts',
    9,
  ],
  ['packages/sdk-web/src/core/signingEngine/session/emailOtp/persistedSnapshot.ts', 1],
  [
    'packages/sdk-web/src/core/signingEngine/session/persistence/durableSealedSessionCommands.ts',
    4,
  ],
  ['packages/sdk-web/src/core/signingEngine/session/persistence/records.ts', 1],
  ['packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts', 11],
  [
    'packages/sdk-web/src/core/signingEngine/session/postconditions/runtimePostconditions.ts',
    0,
  ],
  ['packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord.ts', 1],
  [
    'packages/sdk-web/src/core/signingEngine/session/sealedRecovery/sealedRecovery.types.ts',
    4,
  ],
  ['packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.ts', 0],
  ['packages/sdk-web/src/core/signingEngine/stepUpConfirmation/methodRunners.ts', 1],
  ['packages/sdk-web/src/core/signingEngine/stepUpConfirmation/methodSelection.ts', 1],
  ['packages/sdk-web/src/core/signingEngine/stepUpConfirmation/requireStepUpAuth.ts', 1],
  ['packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts', 0],
]);

function listTypeScriptFiles(relativeDirectory) {
  const absoluteDirectory = path.join(repoRoot, relativeDirectory);
  const files = [];
  for (const entry of fs.readdirSync(absoluteDirectory, { withFileTypes: true })) {
    if (entry.name === 'dist' || entry.name === 'node_modules') continue;
    const relativePath = path.join(relativeDirectory, entry.name);
    if (entry.isDirectory()) {
      files.push(...listTypeScriptFiles(relativePath));
      continue;
    }
    if (!entry.isFile() || !/\.(?:ts|tsx)$/.test(entry.name)) continue;
    if (entry.name.endsWith('.d.ts') || entry.name.endsWith('.typecheck.ts')) continue;
    files.push(relativePath.replaceAll(path.sep, '/'));
  }
  return files;
}

function sourceFileFor(relativePath) {
  const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
  const scriptKind = relativePath.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  return ts.createSourceFile(relativePath, source, ts.ScriptTarget.Latest, true, scriptKind);
}

function stringLiteralValue(node) {
  if (!ts.isLiteralTypeNode(node) || !ts.isStringLiteral(node.literal)) return null;
  return node.literal.text;
}

function isExactBinaryAuthLiteralUnion(node) {
  if (!ts.isUnionTypeNode(node) || node.types.length !== 2) return false;
  const values = node.types.map(stringLiteralValue).filter((value) => value !== null).sort();
  return values.length === 2 && values[0] === 'email_otp' && values[1] === 'passkey';
}

function declarationName(node) {
  if (!node?.name) return null;
  if (ts.isIdentifier(node.name) || ts.isStringLiteral(node.name)) return node.name.text;
  return node.name.getText();
}

function enclosingFunction(node) {
  let current = node.parent;
  while (current) {
    if (ts.isFunctionLike(current)) return current;
    current = current.parent;
  }
  return null;
}

function functionName(node) {
  const directName = declarationName(node);
  if (directName) return directName;
  if (ts.isArrowFunction(node) || ts.isFunctionExpression(node)) {
    const parent = node.parent;
    if (ts.isVariableDeclaration(parent)) return declarationName(parent);
    if (ts.isPropertyAssignment(parent)) return declarationName(parent);
  }
  return null;
}

function isWithinBoundaryParser(node) {
  const fn = enclosingFunction(node);
  if (!fn) return false;
  const name = functionName(fn);
  return Boolean(name && /^(?:parse|normalize|decode|read)[A-Z0-9_]/.test(name));
}

function unionContext(node) {
  const parent = node.parent;
  if (ts.isTypeAliasDeclaration(parent)) return `type ${parent.name.text}`;
  if (ts.isPropertySignature(parent) || ts.isPropertyDeclaration(parent)) {
    return `property ${declarationName(parent) || '<anonymous>'}`;
  }
  if (ts.isParameter(parent)) return `parameter ${declarationName(parent) || '<anonymous>'}`;
  const fn = enclosingFunction(node);
  if (fn?.type === node) return `return ${functionName(fn) || '<anonymous>'}`;
  return ts.SyntaxKind[parent.kind];
}

function authTokenKinds(node) {
  const kinds = new Set();
  collectAuthTokenKinds(node, kinds);
  return kinds;
}

function collectAuthTokenKinds(node, kinds) {
  if (ts.isStringLiteral(node)) {
    if (node.text === 'passkey') kinds.add('passkey');
    if (node.text === 'email_otp') kinds.add('email_otp');
  }
  if (ts.isIdentifier(node)) {
    if (/passkey/i.test(node.text)) kinds.add('passkey');
    if (/emailOtp/i.test(node.text)) kinds.add('email_otp');
  }
  ts.forEachChild(node, (child) => collectAuthTokenKinds(child, kinds));
}

function hasOnlyAuthToken(kinds, expected) {
  return kinds.size === 1 && kinds.has(expected);
}

function isBinaryAuthFallbackConditional(node) {
  if (!ts.isConditionalExpression(node)) return false;
  if (ts.isConditionalExpression(node.whenTrue) || ts.isConditionalExpression(node.whenFalse)) {
    return false;
  }
  const trueKinds = authTokenKinds(node.whenTrue);
  const falseKinds = authTokenKinds(node.whenFalse);
  return (
    (hasOnlyAuthToken(trueKinds, 'email_otp') && hasOnlyAuthToken(falseKinds, 'passkey')) ||
    (hasOnlyAuthToken(trueKinds, 'passkey') && hasOnlyAuthToken(falseKinds, 'email_otp'))
  );
}

function isAuthRelatedExpression(node) {
  return /(?:authMethod|method|source|kind|auth)\b/i.test(node.getText());
}

function comparedAuthToken(node) {
  const kinds = authTokenKinds(node);
  if (hasOnlyAuthToken(kinds, 'passkey')) return 'passkey';
  if (hasOnlyAuthToken(kinds, 'email_otp')) return 'email_otp';
  return null;
}

function isDirectNegativeAuthFallback(node) {
  if (!ts.isBinaryExpression(node)) return false;
  if (
    node.operatorToken.kind !== ts.SyntaxKind.ExclamationEqualsToken &&
    node.operatorToken.kind !== ts.SyntaxKind.ExclamationEqualsEqualsToken
  ) {
    return false;
  }
  const leftToken = comparedAuthToken(node.left);
  const rightToken = comparedAuthToken(node.right);
  const comparesAuthMethod =
    (leftToken && isAuthRelatedExpression(node.right)) ||
    (rightToken && isAuthRelatedExpression(node.left));
  if (!comparesAuthMethod) return false;

  let current = node.parent;
  while (ts.isParenthesizedExpression(current)) current = current.parent;
  if (ts.isReturnStatement(current) && current.expression === node) return true;
  return ts.isArrowFunction(current) && current.body === node;
}

function normalizedSource(node) {
  return node.getText().replace(/\s+/g, ' ').trim();
}

function collectNodeOccurrences(node, state) {
  if (isExactBinaryAuthLiteralUnion(node) && !isWithinBoundaryParser(node)) {
    state.literalUnions.push({
      context: unionContext(node),
      relativePath: state.relativePath,
      sourceFile: state.sourceFile,
      node,
    });
  }
  if (isBinaryAuthFallbackConditional(node)) {
    state.binaryFallbacks.push({
      context: 'conditional-fallback',
      relativePath: state.relativePath,
      sourceFile: state.sourceFile,
      node,
    });
  }
  if (isDirectNegativeAuthFallback(node)) {
    state.binaryFallbacks.push({
      context: 'negative-fallback',
      relativePath: state.relativePath,
      sourceFile: state.sourceFile,
      node,
    });
  }
  ts.forEachChild(node, (child) => collectNodeOccurrences(child, state));
}

function collectSourceFileOccurrences(relativePath, sourceFile) {
  const state = {
    binaryFallbacks: [],
    literalUnions: [],
    relativePath,
    sourceFile,
  };
  collectNodeOccurrences(sourceFile, state);
  return state;
}

function collectOccurrences() {
  const occurrences = { binaryFallbacks: [], literalUnions: [] };
  for (const relativePath of sourceRoots.flatMap(listTypeScriptFiles)) {
    const current = collectSourceFileOccurrences(relativePath, sourceFileFor(relativePath));
    occurrences.binaryFallbacks.push(...current.binaryFallbacks);
    occurrences.literalUnions.push(...current.literalUnions);
  }
  return occurrences;
}

function fixtureOccurrences(source) {
  const relativePath = '<auth-method-domain-boundary-fixture>.ts';
  const sourceFile = ts.createSourceFile(
    relativePath,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  return collectSourceFileOccurrences(relativePath, sourceFile);
}

function checkClassifierFixtures() {
  assert.equal(
    fixtureOccurrences("type AdHocAuthMethod = 'passkey' | 'email_otp';").literalUnions.length,
    1,
  );
  assert.equal(
    fixtureOccurrences(
      "const authMethod = input.kind === 'email_otp' ? 'email_otp' : 'passkey';",
    ).binaryFallbacks.length,
    1,
  );
  assert.equal(
    fixtureOccurrences(
      "function parseAuthMethod(input: unknown): 'passkey' | 'email_otp' { if (input === 'passkey') return 'passkey'; if (input === 'email_otp') return 'email_otp'; throw new Error('invalid auth method'); }",
    ).literalUnions.length,
    0,
  );
  assert.equal(
    fixtureOccurrences(
      "type AuthAuthority = { kind: 'passkey'; credentialId: string } | { kind: 'email_otp'; subjectId: string };",
    ).literalUnions.length,
    0,
  );
}

function formatOccurrence(occurrence) {
  const line = occurrence.sourceFile.getLineAndCharacterOfPosition(occurrence.node.getStart()).line + 1;
  return `${occurrence.relativePath}:${line} [${occurrence.context}]: ${normalizedSource(occurrence.node)}`;
}

function assertMatchesAllowlist(label, occurrences, allowlist) {
  const counts = new Map();
  for (const occurrence of occurrences) {
    counts.set(occurrence.relativePath, (counts.get(occurrence.relativePath) || 0) + 1);
  }
  const violations = [];
  for (const [relativePath, actualCount] of counts) {
    const allowedCount = allowlist.get(relativePath) || 0;
    if (actualCount > allowedCount) {
      violations.push(
        `${relativePath}: found ${actualCount}, allowlisted ${allowedCount}`,
        ...occurrences
          .filter((occurrence) => occurrence.relativePath === relativePath)
          .map(formatOccurrence),
      );
    }
  }
  for (const [relativePath, allowedCount] of allowlist) {
    const actualCount = counts.get(relativePath) || 0;
    if (actualCount < allowedCount) {
      violations.push(
        `stale allowlist: ${relativePath}: expected ${allowedCount}, found ${actualCount}`,
      );
    }
  }
  assert.deepEqual(violations, [], `${label}\n${violations.join('\n')}`);
}

export function checkAuthMethodDomainBoundaries() {
  checkClassifierFixtures();
  const occurrences = collectOccurrences();
  assertMatchesAllowlist(
    'new binary auth-method fallbacks must use exhaustive canonical-domain control flow',
    occurrences.binaryFallbacks,
    approvedBinaryFallbacks,
  );
  assertMatchesAllowlist(
    "new ad hoc 'passkey' | 'email_otp' unions require a named canonical or protocol domain",
    occurrences.literalUnions,
    approvedLiteralUnions,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  checkAuthMethodDomainBoundaries();
  console.log('[check-auth-method-domain-boundaries] passed');
}
