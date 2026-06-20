import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import * as ts from 'typescript';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const sourceRoots = [
  'packages/sdk-server-ts/src',
  'packages/sdk-web/src',
  'packages/shared-ts/src',
  'crates/router-ab-dev/src',
  'tests',
] as const;
const activeDocPaths = [
  'apps/docs/src/concepts/sessions/wallet-sessions.md',
  'docs/intended-behaviours.md',
  'docs/ml-dsa-threshold.md',
  'docs/otp/email-otp.md',
  'docs/refactor-68-wallet-session-v2.md',
  'docs/router-a-b-cleanup.md',
  'docs/router-a-b-single-session.md',
  'docs/router-A-B-signer.md',
  'docs/router-A-B-signer-SPEC.md',
  'docs/refactor-74-login-no-hss.md',
  'docs/signing-session-architecture/README.md',
  'docs/signing-session-architecture/sealed-refresh.md',
  'docs/threshold-ecdsa/ecdsa-hss-v2-integration.md',
] as const;
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
] as const;
const selfPath = 'tests/unit/refactor71WalletSessionNaming.guard.unit.test.ts';

type SessionIdSurfaceClassification =
  | 'keep_app_device_or_recovery_session'
  | 'keep_email_otp_worker_session'
  | 'keep_secureconfirm_session'
  | 'keep_ui_or_operation_session'
  | 'rename_later_agent_b_signing_or_wasm';

const sessionIdPublicSurfaceRoots = [
  'packages/sdk-server-ts/src',
  'packages/sdk-web/src',
  'packages/shared-ts/src',
  'apps/web-client/src/flows/demo',
] as const;
const sessionIdBoundaryRoots = [
  'apps/docs/src/concepts',
  'crates/signer-core/src/commands',
  'wasm/near_signer/src',
] as const;
const classifiedSessionIdPublicSurfaceFiles: Record<string, SessionIdSurfaceClassification> = {
  'apps/web-client/src/flows/demo/hooks/useDemoSigningSession.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-server-ts/src/core/DeviceLinkingSessionStore.ts':
    'keep_app_device_or_recovery_session',
  'packages/sdk-server-ts/src/core/RecoveryExecutionStore.ts':
    'keep_app_device_or_recovery_session',
  'packages/sdk-server-ts/src/core/RecoverySessionStore.ts': 'keep_app_device_or_recovery_session',
  'packages/sdk-server-ts/src/core/types.ts': 'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-server-ts/src/router/recoveryExecutionTracking.ts':
    'keep_app_device_or_recovery_session',
  'packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/platform/generated/signerCoreCommands.ts':
    'keep_email_otp_worker_session',
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
  'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/walletAuthModeResolver.ts':
    'rename_later_agent_b_signing_or_wasm',
  'packages/sdk-web/src/core/signingEngine/threshold/crypto/webauthn.ts':
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
const classifiedSessionIdBoundaryFiles: Record<string, SessionIdSurfaceClassification> = {
  'apps/docs/src/concepts/security-model.md': 'keep_secureconfirm_session',
  'crates/signer-core/src/commands/ecdsa_bootstrap.rs': 'keep_email_otp_worker_session',
  'crates/signer-core/src/commands/ed25519_worker_material.rs':
    'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/handlers/handle_sign_delegate_action.rs':
    'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/handlers/handle_sign_nep413_message.rs':
    'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/handlers/handle_sign_transactions_with_actions.rs':
    'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_client_verifying_share.rs':
    'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_hss_client_inputs.rs':
    'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/threshold/coordinator.rs': 'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/threshold/relayer_http.rs': 'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/threshold/signer_backend.rs': 'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/threshold/transport.rs': 'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/threshold/worker_material.rs': 'rename_later_agent_b_signing_or_wasm',
  'wasm/near_signer/src/types/signing.rs': 'rename_later_agent_b_signing_or_wasm',
};

function joined(parts: readonly string[]): string {
  return parts.join('');
}

function listFilesMatching(relativePath: string, extensionPattern: RegExp): string[] {
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

function listSourceFiles(relativePath: string): string[] {
  return listFilesMatching(relativePath, /\.(ts|tsx|rs)$/);
}

function listBoundaryFiles(relativePath: string): string[] {
  return listFilesMatching(relativePath, /\.(ts|tsx|rs|md)$/);
}

function activeSourceFiles(): string[] {
  return sourceRoots.flatMap((root) => listSourceFiles(root)).filter((file) => file !== selfPath);
}

function readSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function publicSurfaceFiles(): string[] {
  return sessionIdPublicSurfaceRoots
    .flatMap((root) => listSourceFiles(root))
    .filter((file) => file !== selfPath);
}

function boundaryFiles(): string[] {
  return sessionIdBoundaryRoots.flatMap((root) => listBoundaryFiles(root));
}

function sourceContainsSessionIdMarker(source: string): boolean {
  return /\bsessionId\b|session_id/.test(source);
}

function hasExportModifier(node: ts.Node): boolean {
  if (!ts.canHaveModifiers(node)) return false;
  return (
    ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) ===
    true
  );
}

function propertyNameText(name: ts.PropertyName): string {
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) {
    return name.text;
  }
  return '';
}

function fileHasExportedSessionIdSurface(relativePath: string): boolean {
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

function nodeHasSessionIdProperty(node: ts.Node): boolean {
  if (ts.isPropertySignature(node) && propertyNameText(node.name) === 'sessionId') return true;
  return ts.forEachChild(node, nodeHasSessionIdProperty) === true;
}

test.describe('Refactor 71 wallet-session naming source guards', () => {
  test('active package and test sources do not expose the old signing-grant names', () => {
    const forbiddenIdentifierMarkers = [
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
    const offenders: string[] = [];
    for (const file of activeSourceFiles()) {
      const source = readSource(file);
      for (const marker of forbiddenIdentifierMarkers) {
        if (source.includes(marker)) offenders.push(`${file} contains ${marker}`);
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('Router A/B Wallet Session JWT payloads use thresholdSessionId claims', () => {
    const jwtKindMarkers = [
      'ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND',
      'ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND',
      'router_ab_ed25519_wallet_session_v1',
      'router_ab_ecdsa_hss_wallet_session_v1',
    ];
    const offenders: string[] = [];
    for (const file of activeSourceFiles()) {
      const source = readSource(file);
      for (const kind of jwtKindMarkers) {
        const pattern = new RegExp(`${kind}[\\s\\S]{0,420}["']?sessionId["']?\\s*:`);
        if (pattern.test(source)) offenders.push(`${file} uses sessionId near ${kind}`);
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('current docs do not present the old signing-grant names as live terminology', () => {
    const forbiddenTerminologyMarkers = [
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
    const offenders: string[] = [];
    for (const file of activeDocPaths) {
      const source = readSource(file);
      for (const marker of forbiddenTerminologyMarkers) {
        if (source.includes(marker)) offenders.push(`${file} contains ${marker}`);
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('active signing paths do not use threshold-session auth token naming', () => {
    const offenders: string[] = [];
    for (const file of activeSigningPaths) {
      const source = readSource(file);
      if (source.includes('thresholdSessionAuthToken')) {
        offenders.push(`${file} contains thresholdSessionAuthToken`);
      }
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('exported sessionId public surfaces have explicit classifications', () => {
    const offenders: string[] = [];
    for (const file of publicSurfaceFiles()) {
      if (!fileHasExportedSessionIdSurface(file)) continue;
      if (classifiedSessionIdPublicSurfaceFiles[file]) continue;
      offenders.push(`${file} exposes an unclassified exported sessionId field`);
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });

  test('non-package sessionId boundary files have explicit classifications', () => {
    const offenders: string[] = [];
    for (const file of boundaryFiles()) {
      if (!sourceContainsSessionIdMarker(readSource(file))) continue;
      if (classifiedSessionIdBoundaryFiles[file]) continue;
      offenders.push(`${file} contains an unclassified sessionId/session_id marker`);
    }
    expect(offenders, offenders.join('\n')).toEqual([]);
  });
});
