#!/usr/bin/env node

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ts from 'typescript';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sourceRoots = [
  'packages/sdk-server-ts/src',
  'packages/sdk-web/src',
  'packages/shared-ts/src',
  'crates/router-ab-dev/src',
  'tests',
];
const activeDocPaths = [
  'apps/docs/src/concepts/sessions/wallet-sessions.md',
  'docs/intended-behaviours.md',
  'docs/ml-dsa-threshold.md',
  'docs/otp/email-otp.md',
  'docs/refactor-68-wallet-session-v2.md',
  'docs/router-a-b-cleanup.md',
  'docs/router-a-b-SPEC.md',
  'docs/refactor-74-login-no-hss.md',
  'docs/signing-session-architecture/README.md',
  'docs/signing-session-architecture/sealed-refresh.md',
  'docs/threshold-ecdsa/ecdsa-hss-v2-integration.md',
];
const activeSigningPaths = [
  'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/readySecp256k1Material.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signers/secp256k1.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlowRuntime.ts',
  'packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts',
  'packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts',
];
const selfPaths = new Set([
  'tests/unit/walletSessionVocabularyBoundaries.guard.unit.test.ts',
  'tests/scripts/check-wallet-session-vocabulary-boundaries.mjs',
]);

const sessionIdPublicSurfaceRoots = [
  'packages/sdk-server-ts/src',
  'packages/sdk-web/src',
  'packages/shared-ts/src',
  'apps/seams-site/src/flows/demo',
];
const sessionIdBoundaryRoots = [
  'apps/docs/src/concepts',
  'crates/signer-core/src/commands',
  'wasm/near_signer/src',
];
const classifiedSessionIdPublicSurfaceFiles = {
  'apps/seams-site/src/flows/demo/hooks/useDemoSigningSession.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-server-ts/src/core/RecoveryExecutionStore.ts':
    'keep_app_device_or_recovery_session',
  'packages/sdk-server-ts/src/core/RecoverySessionStore.ts': 'keep_app_device_or_recovery_session',
  'packages/sdk-server-ts/src/core/types.ts': 'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-server-ts/src/router/authServicePort.ts': 'keep_app_device_or_recovery_session',
  'packages/sdk-server-ts/src/router/recoveryExecutionTracking.ts':
    'keep_app_device_or_recovery_session',
  'packages/sdk-web/src/SeamsWeb/signingSurface/ports.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/platform/ports.ts': 'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/platform/secretSources.ts': 'keep_email_otp_worker_session',
  'packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/assembly/ports/shared.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/interfaces/near.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/interfaces/nearKeyOps.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/interfaces/operationDeps.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/interfaces/signing.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/routerAb/ecdsaHss/presignaturePool.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/availability/readiness.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/ports.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/recoveryCodeWarmSessionHydration.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/workerRequests.ts':
    'keep_email_otp_worker_session',
  'packages/sdk-web/src/core/signingEngine/session/emailOtp/warmSessionRuntime.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/identity/emailOtpHssIdentity.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts':
    'keep_email_otp_worker_session',
  'packages/sdk-web/src/core/signingEngine/session/passkey/prfCache.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/passkey/warmSessionMaterialWriter.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/passkey/warmSessionHydration.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ed25519Authorization.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/public.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/confirmOperation.ts':
    'keep_ui_or_operation_session',
  'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/threshold/crypto/webauthn.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/threshold/ed25519/connectSession.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/uiConfirm/uiConfirm.types.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/uiConfirm/ui/export-viewer-host.ts':
    'keep_ui_or_operation_session',
  'packages/sdk-web/src/core/signingEngine/uiConfirm/warmSessionUiConfirm.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsa.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/types/linkDevice.ts': 'keep_app_device_or_recovery_session',
  'packages/sdk-web/src/core/types/seams.ts': 'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/types/secure-confirm-worker.ts': 'keep_secureconfirm_session',
  'packages/sdk-web/src/core/types/signer-worker.ts': 'rename_later_agent_b_signing_or_wasm',
  'packages/shared-ts/src/threshold/ecdsaHssRoleLocalBootstrap.ts':
    'rename_later_agent_b_signing_or_wasm',
};
const classifiedSessionIdBoundaryFiles = {
  'apps/docs/src/concepts/security-model.md': 'keep_secureconfirm_session',
  'crates/signer-core/src/commands/ecdsa_bootstrap.rs':
    'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/handlers/handle_sign_delegate_action.rs':
    'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/handlers/handle_sign_nep413_message.rs':
    'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/handlers/handle_sign_transactions_with_actions.rs':
    'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_client_verifying_share.rs':
    'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/threshold/coordinator.rs': 'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/threshold/relayer_http.rs': 'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/threshold/signer_backend.rs': 'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/threshold/transport.rs': 'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/types/signing.rs': 'rename_later_agent_b_signing_or_wasm',
};
const forbiddenWalletSigningSessionMarkers = [
  joined(['wallet', 'SigningSessionId']),
  joined(['Wallet', 'SigningSessionId']),
  joined(['wallet_', 'signing_', 'session_id']),
  joined(['wallet-', 'signing-', 'session']),
  'wallet signing session',
  'Wallet signing session',
  'wallet signing-session',
  'Wallet signing-session',
  'wallet-signing session',
];

function joined(parts) {
  return parts.join('');
}

function readSource(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listFilesMatching(relativePath, extensionPattern) {
  const absolutePath = path.join(repoRoot, relativePath);
  const stat = fs.statSync(absolutePath);
  if (stat.isFile()) return extensionPattern.test(relativePath) ? [relativePath] : [];
  return fs.readdirSync(absolutePath, { withFileTypes: true }).flatMap((entry) => {
    const childPath = path.join(relativePath, entry.name);
    if (entry.isDirectory()) {
      if (
        entry.name === 'node_modules' ||
        entry.name === 'dist' ||
        entry.name === 'target' ||
        entry.name === 'test-results'
      ) {
        return [];
      }
      return listFilesMatching(childPath, extensionPattern);
    }
    return extensionPattern.test(entry.name) ? [childPath] : [];
  });
}

function listSourceFiles(relativePath) {
  return listFilesMatching(relativePath, /\.(ts|tsx|rs)$/);
}

function listBoundaryFiles(relativePath) {
  return listFilesMatching(relativePath, /\.(ts|tsx|rs|md)$/);
}

function activeSourceFiles() {
  return sourceRoots.flatMap((root) => listSourceFiles(root)).filter((file) => !selfPaths.has(file));
}

function publicSurfaceFiles() {
  return sessionIdPublicSurfaceRoots
    .flatMap((root) => listSourceFiles(root))
    .filter((file) => !selfPaths.has(file));
}

function boundaryFiles() {
  return sessionIdBoundaryRoots.flatMap((root) => listBoundaryFiles(root));
}

function sourceContainsSessionIdMarker(source) {
  return /\bsessionId\b|session_id/.test(source);
}

function hasExportModifier(node) {
  if (!ts.canHaveModifiers(node)) return false;
  return ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) === true;
}

function propertyNameText(name) {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) {
    return name.text;
  }
  return '';
}

function nodeHasSessionIdProperty(node) {
  if (ts.isPropertySignature(node) && propertyNameText(node.name) === 'sessionId') return true;
  return ts.forEachChild(node, nodeHasSessionIdProperty) === true;
}

function fileHasExportedSessionIdSurface(relativePath) {
  if (!/\.(ts|tsx)$/.test(relativePath)) return false;
  const source = readSource(relativePath);
  if (!source.includes('sessionId')) return false;
  const sourceFile = ts.createSourceFile(relativePath, source, ts.ScriptTarget.Latest, true);
  for (const statement of sourceFile.statements) {
    if (!hasExportModifier(statement)) continue;
    if (ts.isInterfaceDeclaration(statement) && nodeHasSessionIdProperty(statement)) return true;
    if (ts.isTypeAliasDeclaration(statement) && nodeHasSessionIdProperty(statement)) return true;
  }
  return false;
}

function assertNoViolations(label, violations) {
  assert.deepEqual(violations, [], `${label}\n${violations.join('\n')}`);
}

function collectOldSigningGrantNameViolations(files) {
  const offenders = [];
  for (const file of files) {
    const source = readSource(file);
    for (const marker of forbiddenWalletSigningSessionMarkers) {
      if (source.includes(marker)) offenders.push(`${file} contains ${marker}`);
    }
  }
  return offenders;
}

function checkActiveSourcesAvoidOldSigningGrantNames() {
  assertNoViolations(
    'active package and test sources do not expose the old signing-grant names',
    collectOldSigningGrantNameViolations(activeSourceFiles()),
  );
}

function checkRouterAbWalletSessionJwtPayloadsUseThresholdSessionId() {
  const jwtKindMarkers = [
    'ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND',
    'ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND',
    'router_ab_ed25519_wallet_session_v1',
    'router_ab_ecdsa_hss_wallet_session_v1',
  ];
  const offenders = [];
  for (const file of activeSourceFiles()) {
    const source = readSource(file);
    for (const kind of jwtKindMarkers) {
      const pattern = new RegExp(`${kind}[\\s\\S]{0,420}["']?sessionId["']?\\s*:`);
      if (pattern.test(source)) offenders.push(`${file} uses sessionId near ${kind}`);
    }
  }
  assertNoViolations('Router A/B Wallet Session JWT payloads use thresholdSessionId claims', offenders);
}

function checkDocsAvoidOldSigningGrantNames() {
  assertNoViolations(
    'current docs do not present the old signing-grant names as live terminology',
    collectOldSigningGrantNameViolations(activeDocPaths),
  );
}

function checkActiveSigningPathsAvoidThresholdSessionAuthTokenNaming() {
  const offenders = [];
  for (const file of activeSigningPaths) {
    const source = readSource(file);
    if (source.includes('thresholdSessionAuthToken')) {
      offenders.push(`${file} contains thresholdSessionAuthToken`);
    }
  }
  assertNoViolations('active signing paths do not use threshold-session auth token naming', offenders);
}

function checkExportedSessionIdPublicSurfacesAreClassified() {
  const offenders = [];
  for (const file of publicSurfaceFiles()) {
    if (!fileHasExportedSessionIdSurface(file)) continue;
    if (classifiedSessionIdPublicSurfaceFiles[file]) continue;
    offenders.push(`${file} exposes an unclassified exported sessionId field`);
  }
  assertNoViolations('exported sessionId public surfaces have explicit classifications', offenders);
}

function checkBoundarySessionIdMarkersAreClassified() {
  const offenders = [];
  for (const file of boundaryFiles()) {
    if (!sourceContainsSessionIdMarker(readSource(file))) continue;
    if (classifiedSessionIdBoundaryFiles[file]) continue;
    offenders.push(`${file} contains an unclassified sessionId/session_id marker`);
  }
  assertNoViolations('non-package sessionId boundary files have explicit classifications', offenders);
}

checkActiveSourcesAvoidOldSigningGrantNames();
checkRouterAbWalletSessionJwtPayloadsUseThresholdSessionId();
checkDocsAvoidOldSigningGrantNames();
checkActiveSigningPathsAvoidThresholdSessionAuthTokenNaming();
checkExportedSessionIdPublicSurfacesAreClassified();
checkBoundarySessionIdMarkersAreClassified();

console.log('[wallet-session-vocabulary-boundaries] ok');
