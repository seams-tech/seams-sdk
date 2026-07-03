import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listRepoFiles(relativeDir: string): string[] {
  const absoluteDir = path.join(repoRoot, relativeDir);
  const entries = fs.readdirSync(absoluteDir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listRepoFiles(relativePath));
    } else if (entry.isFile() && relativePath.endsWith('.ts')) {
      files.push(relativePath);
    }
  }
  return files;
}

test.describe('Email OTP operation split guard', () => {
  test('transaction signing APIs cannot request export challenges', () => {
    const transactionApiFiles = [
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts',
      'packages/sdk-web/src/core/signingEngine/assembly/ports/evmFamily.ts',
    ];
    const forbidden = [
      'requestEmailOtpChallengeForSigning',
      'requestChallengeForSigning',
      'WALLET_EMAIL_OTP_EXPORT_OPERATION',
      "'export_key'",
      '"export_key"',
      "operation?: 'transaction_sign' | 'export_key'",
      'operation?: "transaction_sign" | "export_key"',
    ];

    const violations: string[] = [];
    for (const relativePath of transactionApiFiles) {
      const source = readRepoFile(relativePath);
      for (const token of forbidden) {
        if (source.includes(token)) {
          violations.push(`${relativePath} contains ${token}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('Email OTP coordinator keeps export challenge issuance separate from signing challenge issuance', () => {
    const source = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator.ts',
    );
    const forbidden = [
      'requestEmailOtpChallengeForSigning',
      'requestChallengeForSigning',
      'createPasskeyWalletAuthAdapter',
      'createWalletAuthModeResolver',
      'WalletAuthPolicyError',
      'requestExportAuthorization',
      'requestUserConfirmation',
      'UserConfirmationType',
      "operation?: 'transaction_sign' | 'export_key'",
      'operation?: "transaction_sign" | "export_key"',
    ];
    const violations = forbidden
      .filter((token) => source.includes(token))
      .map((token) => `EmailOtpWalletSessionCoordinator.ts contains ${token}`);

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('Email OTP coordinator stays a thin runtime facade', () => {
    const source = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator.ts',
    );
    const lineCount = source.split(/\r?\n/).length;
    const forbidden = [
      'fetch(',
      'requestWorkerOperation',
      'sealEmailOtpWarmSessionMaterial',
      'requestEmailOtpTransactionSigningChallenge',
      'requestEmailOtpExportChallenge',
      'requestExportAuthorization',
      'requestUserConfirmation',
    ];
    const violations = forbidden
      .filter((token) => source.includes(token))
      .map((token) => `EmailOtpWalletSessionCoordinator.ts contains ${token}`);

    expect(lineCount).toBeLessThanOrEqual(250);
    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('obsolete wallet auth mode proof resolver stays deleted', () => {
    const obsoletePath =
      'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/walletAuthModeResolver.ts';
    const checkedFiles = [
      'packages/sdk-web/src/core/signingEngine/stepUpConfirmation/walletAuthPolicyError.ts',
      'packages/sdk-web/src/core/signingEngine/session/operationState/postSignPolicy.ts',
      'packages/sdk-web/src/core/signingEngine/flows/recovery/keyExportConfirmation.ts',
    ];
    const forbidden = [
      'WalletAuthProof',
      'PasskeyWalletAuthProof',
      'EmailOtpWalletAuthProof',
      'WalletAuthPlan',
      'createPasskeyWalletAuthAdapter',
      'createEmailOtpWalletAuthAdapter',
      'createWalletAuthModeResolver',
    ];
    const violations: string[] = [];

    if (fs.existsSync(path.join(repoRoot, obsoletePath))) {
      violations.push(`${obsoletePath} still exists`);
    }
    for (const relativePath of checkedFiles) {
      const source = readRepoFile(relativePath);
      for (const token of forbidden) {
        if (source.includes(token)) {
          violations.push(`${relativePath} contains ${token}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('SDK signing code reads Email OTP authority identity through accessors', () => {
    const checkedFiles = [
      ...listRepoFiles('packages/sdk-web/src/core/signingEngine'),
      'packages/sdk-web/src/SeamsWeb/operations/auth/login.ts',
    ];
    const forbidden = ['.authority.provider', '.authority.providerUserId'];
    const violations: string[] = [];

    for (const relativePath of checkedFiles) {
      const source = readRepoFile(relativePath);
      for (const token of forbidden) {
        if (source.includes(token)) {
          violations.push(`${relativePath} contains ${token}`);
        }
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('ECDSA fresh Email OTP decisions stay planner-owned, not pre-sign guard-owned', () => {
    const source = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    );
    const executorSource = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
    );

    expect(source).not.toContain('const assertEcdsaOperationAllowedForAttempt');
    expect(source).not.toContain('assertEcdsaOperationAllowedForSource');
    expect(executorSource).not.toContain('assertOperationAllowed');
  });

  test('ECDSA transaction signing selects an exact lane before material lookup', () => {
    const selectionModule = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
    );
    const selectionModuleResolver = selectionModule.indexOf(
      'export async function resolveEvmFamilyEcdsaSigningSelection',
    );
    const selectionSource = selectionModule.slice(selectionModuleResolver);

    expect(selectionModule).not.toContain('findExactEcdsaKeyRefForSelectedLane');
    expect(selectionModule).not.toContain('tryGetEmailOtpThresholdEcdsaKeyRefForSigning');
    expect(selectionModule).not.toContain('tryGetPasskeyThresholdEcdsaKeyRefForSigning');
    expect(selectionSource).not.toContain('genericRecord');
    expect(selectionSource).not.toContain('genericKeyRef');
  });

  test('Email OTP ECDSA helpers require the Email OTP source lane', () => {
    const evmSigning = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    );
    const authPlanning = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts',
    );
    const ecdsaSelection = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
    );
    const ecdsaLanes = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts',
    );
    const preparedSigning = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
    );

    expect(preparedSigning).not.toContain('getThresholdEcdsaKeyRefForLookup');
    expect(preparedSigning).not.toContain('getThresholdEcdsaSessionRecordForLookup');
    expect(preparedSigning).not.toContain('getEmailOtpThresholdEcdsaKeyRefForSigning');
    expect(preparedSigning).not.toContain('getPasskeyThresholdEcdsaKeyRefForSigning');
    expect(evmSigning).not.toContain('type EcdsaSigningLaneContext');
    expect(authPlanning).not.toContain('ecdsaSigningLane: ResolvedEvmFamilyEcdsaSigningLane');
    expect(ecdsaSelection).not.toContain('findExactEcdsaKeyRefForSelectedLane');
    expect(ecdsaSelection).not.toContain('tryGetEmailOtpThresholdEcdsaKeyRefForSigning');
    expect(ecdsaSelection).not.toContain('tryGetPasskeyThresholdEcdsaKeyRefForSigning');
    expect(ecdsaLanes).not.toContain('function emailOtpEcdsaAuthLaneFromRecord');
    expect(ecdsaLanes).toContain('function resolveEmailOtpEcdsaAuthLaneFromRecord');
  });

  test('Email OTP ECDSA export route auth consumes committed lanes', () => {
    const exportMaterial = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportMaterial.ts',
    );
    const exportFlow = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportFlow.ts',
    );
    const exportRuntime = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecoveryRuntime.ts',
    );
    const exportRecovery = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.ts',
    );
    const recoveryPortAdapter = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/assembly/ports/recovery.ts',
    );
    const routeAuthTypeStart = exportMaterial.indexOf(
      'export type FreshEmailOtpEcdsaExportMaterialRouteAuthReady',
    );
    const routeAuthType = exportMaterial.slice(
      routeAuthTypeStart,
      exportMaterial.indexOf('export type FreshEmailOtpEcdsaExportMaterial =', routeAuthTypeStart),
    );
    const routeAuthFlowStart = exportFlow.indexOf(
      'export async function exportThresholdEcdsaKeyWithFreshEmailOtpRouteAuth',
    );
    const routeAuthFlow = exportFlow.slice(
      routeAuthFlowStart,
      exportFlow.indexOf(
        'export async function exportThresholdEcdsaKeyWithAuthorization',
        routeAuthFlowStart,
      ),
    );
    const readyEmailOtpBranchStart = exportFlow.indexOf(
      "if (args.material.authMethod === 'email_otp')",
    );
    const readyEmailOtpBranch = exportFlow.slice(
      readyEmailOtpBranchStart,
      exportFlow.indexOf('\n  try {', readyEmailOtpBranchStart),
    );
    const flowDepsStart = exportFlow.indexOf('export type EcdsaExportFlowDeps');
    const flowDeps = exportFlow.slice(
      flowDepsStart,
      exportFlow.indexOf('type EcdsaExportOptions', flowDepsStart),
    );
    const readyPasskeyExportStart = exportMaterial.indexOf(
      'export type ReadyPasskeyThresholdEcdsaExportMaterial',
    );
    const readyPasskeyExportType = exportMaterial.slice(
      readyPasskeyExportStart,
      exportMaterial.indexOf('export type ReadyEmailOtpThresholdEcdsaExportMaterial'),
    );
    const runtimeEcdsaExportArgsStart = exportRuntime.indexOf(
      'export type ExportEcdsaKeyWithAuthorizationArgs',
    );
    const runtimeEcdsaExportArgs = exportRuntime.slice(
      runtimeEcdsaExportArgsStart,
      exportRuntime.indexOf(
        'export type ExportEcdsaKeyWithFreshEmailOtpLaneArgs',
        runtimeEcdsaExportArgsStart,
      ),
    );
    const emailOtpEcdsaExportFunctionStart = exportRecovery.indexOf(
      'export async function exportEcdsaKeyWithAuthorization',
    );
    const emailOtpEcdsaExportFunction = exportRecovery.slice(
      emailOtpEcdsaExportFunctionStart,
      exportRecovery.indexOf(
        'export async function exportEcdsaKeyWithFreshEmailOtpLane',
        emailOtpEcdsaExportFunctionStart,
      ),
    );

    expect(routeAuthType).toContain('committedLane');
    expect(routeAuthType).toContain('committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>');
    expect(routeAuthType).not.toContain('record: ThresholdEcdsaSessionRecord');
    expect(routeAuthType).not.toContain('authLane: EmailOtpAuthLane');
    expect(readyPasskeyExportType).toContain(
      'committedLane: ReadyEcdsaExportLane<PasskeyWalletAuthAuthority>',
    );
    expect(exportMaterial).toContain(
      'export type EcdsaExportLane<A extends WalletAuthAuthority = WalletAuthAuthority>',
    );
    expect(exportMaterial).toContain('RecordBackedEcdsaCommittedLane<A>');
    expect(readyPasskeyExportType).not.toContain('committedLane?: never');
    expect(exportMaterial).toContain('record?: never');
    expect(flowDeps).toContain('committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>');
    expect(flowDeps).not.toContain('RecordBackedEmailOtpEcdsaExportCommittedLane');
    expect(flowDeps).not.toContain('record: ThresholdEcdsaSessionRecord');
    expect(flowDeps).not.toContain('authLane: EmailOtpAuthLane');
    expect(runtimeEcdsaExportArgs).toContain(
      'committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>',
    );
    expect(runtimeEcdsaExportArgs).not.toContain('RecordBackedEmailOtpEcdsaCommittedLane');
    expect(runtimeEcdsaExportArgs).not.toContain('record: ThresholdEcdsaSessionRecord');
    expect(runtimeEcdsaExportArgs).not.toContain('routeAuth?: AppOrWalletSessionAuth');
    expect(runtimeEcdsaExportArgs).not.toContain('authLane?: EmailOtpAuthLane');
    expect(routeAuthFlow).toContain('const committedLane = args.material.committedLane');
    expect(routeAuthFlow).not.toContain('args.material.authLane');
    expect(routeAuthFlow).not.toContain('args.material.record');
    expect(readyEmailOtpBranch).toContain('const committedLane = args.material.committedLane');
    expect(readyEmailOtpBranch).not.toContain('const exportSigningSessionAuthLane');
    expect(readyEmailOtpBranch).not.toContain('toAuthorizingSigningGrantId');
    expect(exportMaterial).not.toContain('resolveRouterAbEcdsaWalletSessionAuthFromRecord');
    expect(exportMaterial).toContain('commitReadyRecordBackedEcdsaExportLane');
    expect(exportMaterial).toContain('tryCommitRecordBackedEmailOtpEcdsaExportLane');
    expect(emailOtpEcdsaExportFunction).toContain(
      'const walletSessionAuthority = args.committedLane.walletSessionAuthority',
    );
    expect(emailOtpEcdsaExportFunction).toContain(
      'walletSessionJwt: walletSessionAuthority.walletSessionJwt',
    );
    expect(emailOtpEcdsaExportFunction).not.toContain(
      'resolveRouterAbEcdsaWalletSessionAuthFromRecord',
    );
    expect(recoveryPortAdapter).not.toContain('record: request.committedLane.record');
    expect(recoveryPortAdapter).not.toContain('authLane: request.committedLane.authLane');
  });

  test('Email OTP Ed25519 export consumes committed lanes', () => {
    const exportRuntime = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecoveryRuntime.ts',
    );
    const exportRecovery = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.ts',
    );
    const nearExportFlow = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/recovery/nearEd25519ExportFlow.ts',
    );
    const typecheck = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecoveryRuntime.typecheck.ts',
    );
    const ed25519ExportArgsStart = exportRuntime.indexOf(
      'export type ExportEd25519SeedWithAuthorizationArgs',
    );
    const ed25519ExportArgs = exportRuntime.slice(
      ed25519ExportArgsStart,
      exportRuntime.indexOf(
        'export type ExportEcdsaKeyWithAuthorizationArgs',
        ed25519ExportArgsStart,
      ),
    );
    const ed25519ExportFunctionStart = exportRecovery.indexOf(
      'export async function exportEd25519SeedWithAuthorization',
    );
    const ed25519ExportFunction = exportRecovery.slice(
      ed25519ExportFunctionStart,
      exportRecovery.indexOf(
        'export async function exportEcdsaKeyWithAuthorization',
        ed25519ExportFunctionStart,
      ),
    );

    expect(exportRuntime).toContain('Ed25519ExportLane');
    expect(exportRuntime).toContain('RecordBackedEd25519CommittedLane');
    expect(exportRuntime).not.toContain('RecordBackedEmailOtpEd25519ExportCommittedLane');
    expect(exportRuntime).not.toContain("kind: 'email_otp_ed25519_export_committed_lane'");
    expect(nearExportFlow).not.toContain("kind: 'email_otp_ed25519_export_committed_lane'");
    expect(ed25519ExportArgs).toContain('committedLane: Ed25519ExportLane');
    expect(ed25519ExportArgs).not.toContain('record: ThresholdEd25519SessionRecord');
    expect(ed25519ExportArgs).not.toContain('participantIds: number[]');
    expect(ed25519ExportArgs).not.toContain('walletSessionJwt: string');
    expect(ed25519ExportArgs).not.toContain('authLane?: EmailOtpAuthLane');
    expect(nearExportFlow).toContain('function buildEd25519ExportLane');
    expect(nearExportFlow).toContain('const committedLane = buildEd25519ExportLane');
    expect(nearExportFlow).not.toContain('const walletSessionJwt = nonEmptyString(record.walletSessionJwt)');
    expect(nearExportFlow).not.toContain(
      'args.walletSessionAuth.walletSessionJwt !== record.walletSessionJwt',
    );
    expect(nearExportFlow).toContain('committedLane,');
    expect(nearExportFlow).not.toContain('exportSigningSessionAuthLane');
    expect(ed25519ExportFunction).toContain('const record = args.committedLane.record');
    expect(ed25519ExportFunction).toContain(
      'const walletSessionAuthority = args.committedLane.walletSessionAuthority',
    );
    expect(ed25519ExportFunction).not.toContain('args.record');
    expect(ed25519ExportFunction).not.toContain('args.routeAuth');
    expect(typecheck).toContain('Ed25519 Email OTP export carries records through the committed lane');
    expect(typecheck).toContain(
      'Ed25519 Email OTP export carries wallet-session authority through the committed lane',
    );
  });

  test('Email OTP Ed25519 NEAR step-up consumes committed lanes', () => {
    const signNear = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts',
    );
    const operationDeps = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/interfaces/operationDeps.ts',
    );
    const nearPort = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/assembly/ports/near.ts',
    );
    const browserSigningSurfaceAssembly = readRepoFile(
      'packages/sdk-web/src/SeamsWeb/assembly/browserSigningSurfaceAssembly.ts',
    );
    const coordinatorRuntime = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/coordinatorRuntime.ts',
    );
    const ed25519Warmup = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts',
    );
    const warmCapabilityReader = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/warmCapabilities/capabilityReaderCore.ts',
    );
    const routerAbEd25519WalletSessionState = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbEd25519WalletSessionState.ts',
    );
    const companionSessions = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.ts',
    );
    const typecheck = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Warmup.typecheck.ts',
    );
    const companionLaneTypeStart = companionSessions.indexOf(
      'export type EmailOtpEcdsaCompanionLaneForEd25519Signing',
    );
    const companionLaneType = companionSessions.slice(
      companionLaneTypeStart,
      companionSessions.indexOf('export type ChainDistinctEmailOtpEcdsaCompanionLanes'),
    );
    const operationLoginStart = operationDeps.indexOf(
      'loginWithEmailOtpEd25519CapabilityForSigning?:',
    );
    const operationLoginInput = operationDeps.slice(
      operationLoginStart,
      operationDeps.indexOf('restorePersistedSessionForSigning?', operationLoginStart),
    );
    const runtimeLoginStart = coordinatorRuntime.indexOf(
      'async loginWithEd25519CapabilityForSigning',
    );
    const runtimeLoginInput = coordinatorRuntime.slice(
      runtimeLoginStart,
      coordinatorRuntime.indexOf('async reconstructEd25519Session', runtimeLoginStart),
    );
    const warmupLoginStart = ed25519Warmup.indexOf('async loginForSigning');
    const warmupLoginInput = ed25519Warmup.slice(
      warmupLoginStart,
      ed25519Warmup.indexOf(
        '): Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }>',
        warmupLoginStart,
      ),
    );

    expect(signNear).toContain('function resolveEd25519SigningLane');
    expect(signNear).toContain('resolveEmailOtpEd25519SigningSessionAuthority');
    expect(signNear).not.toContain('resolveEmailOtpSigningSessionAuthLane');
    expect(signNear).not.toContain('emailOtpEd25519AuthLaneFromRecord');
    expect(warmCapabilityReader).toContain(
      'function resolveEmailOtpEd25519SigningSessionAuthority',
    );
    expect(warmCapabilityReader).not.toContain('resolveEmailOtpSigningSessionAuthLane');
    expect(routerAbEd25519WalletSessionState).not.toContain('emailOtpEd25519AuthLaneFromRecord');
    expect(signNear).not.toContain('resolveRecordBackedEmailOtpEd25519SigningCommittedLane');
    expect(ed25519Warmup).not.toContain("kind: 'email_otp_ed25519_signing_committed_lane'");
    expect(ed25519Warmup).not.toContain('RecordBackedEmailOtpEd25519SigningCommittedLane');
    expect(signNear).toContain('committedLane: Ed25519SigningLane');
    expect(signNear).toContain('walletSessionJwtForPreparedNearExecution');
    expect(signNear).toContain('committedLane,');
    expect(signNear).not.toContain('walletSessionJwtFromPersistedEd25519Record(thresholdSessionRecord)');
    expect(signNear).not.toContain('authLane: committedLane.authLane');
    expect(nearPort).toContain('committedLane,');
    expect(nearPort).not.toContain('authLane: committedLane.authLane');
    expect(browserSigningSurfaceAssembly).toContain('authLane: challengeArgs.committedLane.authLane');
    expect(signNear).toContain('committedLane,');
    expect(operationLoginInput).toContain('committedLane: Ed25519SigningLane');
    expect(operationLoginInput).toContain('record?: never');
    expect(operationLoginInput).toContain('authLane?: never');
    expect(runtimeLoginInput).toContain('committedLane: Ed25519SigningLane');
    expect(runtimeLoginInput).toContain('routeAuth?: never');
    expect(runtimeLoginInput).toContain('authLane?: never');
    expect(warmupLoginInput).toContain('committedLane: Ed25519SigningLane');
    expect(warmupLoginInput).toContain('record?: never');
    expect(warmupLoginInput).toContain('routeAuth?: never');
    expect(warmupLoginInput).toContain('authLane?: never');
    expect(companionLaneType).toContain(
      'committedLane: RecordBackedEcdsaCommittedLane<EmailOtpWalletAuthAuthority>',
    );
    expect(companionLaneType).not.toContain('RecordBackedEmailOtpEcdsaCommittedLane');
    expect(companionLaneType).toContain('record?: never');
    expect(companionLaneType).toContain('walletSessionAuthority?: never');
    expect(companionLaneType).not.toContain('record: EmailOtpEcdsaSessionRecord');
    expect(ed25519Warmup).toContain('const authLane = companionLane.committedLane.authLane');
    expect(ed25519Warmup).toContain(
      'const ecdsaCompanionRecord = ecdsaCompanionLane.committedLane.record',
    );
    expect(ed25519Warmup).not.toContain('companionLane.walletSessionAuthority');
    expect(ed25519Warmup).not.toContain('companionLane.record');
    expect(typecheck).toContain(
      'Email OTP Ed25519 signing carries records through the committed lane',
    );
    expect(typecheck).toContain(
      'Email OTP Ed25519 signing carries wallet-session auth through the committed lane',
    );
  });

  test('EVM-family ECDSA reauth carries committed lanes for every auth branch', () => {
    const ecdsaSelection = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
    );
    const ecdsaSelectionTypecheck = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.typecheck.ts',
    );
    const authPlanning = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts',
    );
    const evmSigning = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    );
    const emailOtpSigningBridge = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession.ts',
    );
    const ecdsaLogin = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts',
    );
    const reauthSelectionStart = ecdsaSelection.indexOf(
      'export type ReauthRequiredEvmFamilyEcdsaSigningSelection',
    );
    const reauthSelectionType = ecdsaSelection.slice(
      reauthSelectionStart,
      ecdsaSelection.indexOf(
        'export type BudgetBlockedEvmFamilyEcdsaSigningSelection',
        reauthSelectionStart,
      ),
    );
    const ecdsaSigningInputStart = ecdsaLogin.indexOf(
      'export type LoginEmailOtpEcdsaCapabilityForSigningArgs',
    );
    const ecdsaSigningInput = ecdsaLogin.slice(
      ecdsaSigningInputStart,
      ecdsaLogin.indexOf(
        'export type EmailOtpEcdsaTransactionStepUpInput',
        ecdsaSigningInputStart,
      ),
    );

    expect(reauthSelectionType).toContain('committedLane: EmailOtpEcdsaCommittedLane');
    expect(reauthSelectionType).toContain('committedLane: PasskeyEcdsaCommittedLane');
    expect(reauthSelectionType).not.toContain('committedLane?: PasskeyEcdsaCommittedLane');
    expect(reauthSelectionType).not.toContain('reauthAuthority');
    expect(ecdsaSelection).toContain('function requirePasskeyCommittedLaneForReauth');
    expect(ecdsaSelection).toContain('committedLane: reauthLane');
    expect(ecdsaSelectionTypecheck).toContain(
      'passkey reauth selections require committed lane authority',
    );
    expect(authPlanning).toContain('preparedSelection.committedLane');
    expect(authPlanning).toContain('committedLane: emailOtpCommittedLane');
    expect(authPlanning).not.toContain('reauthAuthLane');
    expect(authPlanning).not.toContain('signingSessionRecord');
    expect(emailOtpSigningBridge).toContain('committedLane: EmailOtpEcdsaCommittedLane');
    expect(emailOtpSigningBridge).not.toContain(
      'signingSessionRecord: ThresholdEcdsaSessionRecord',
    );
    expect(emailOtpSigningBridge).not.toContain('reauthAuthLane');
    expect(emailOtpSigningBridge).not.toContain('resolveEmailOtpSigningSessionAuthLane');
    expect(ecdsaSigningInput).toContain('committedLane: EmailOtpEcdsaCommittedLane');
    expect(ecdsaSigningInput).not.toContain('committedLane?: EmailOtpEcdsaCommittedLane');
    expect(ecdsaSigningInput).not.toContain('record?: ThresholdEcdsaSessionRecord');
    expect(ecdsaSigningInput).not.toContain('authLane?: EmailOtpAuthLane');
    expect(ecdsaLogin).not.toContain('EmailOtpEcdsaLoginReconnectInput');
    expect(ecdsaLogin).not.toContain('resolveEmailOtpEcdsaSigningInput');
    expect(authPlanning).not.toContain('preparedSelection.reauthAuthority');
    expect(evmSigning).toContain('prepared.selection.committedLane');
    expect(evmSigning).not.toContain('prepared.selection.reauthAuthority');
  });

  test('EVM-family ECDSA ready selections use committed lanes for every auth branch', () => {
    const ecdsaSelection = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
    );
    const preparedSigning = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
    );
    const ecdsaSelectionTypecheck = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.typecheck.ts',
    );
    const readySelectionStart = ecdsaSelection.indexOf(
      'export type ReadyEvmFamilyEcdsaSigningSelection',
    );
    const readySelectionType = ecdsaSelection.slice(
      readySelectionStart,
      ecdsaSelection.indexOf(
        'type ReauthRequiredEvmFamilyEcdsaSigningSelectionBase',
        readySelectionStart,
      ),
    );
    const committedLaneTypeStart = ecdsaSelection.indexOf(
      'export type EcdsaCommittedLane<A extends WalletAuthAuthority = WalletAuthAuthority>',
    );
    const committedLaneType = ecdsaSelection.slice(
      committedLaneTypeStart,
      ecdsaSelection.indexOf('export type EmailOtpEcdsaCommittedLane', committedLaneTypeStart),
    );

    expect(ecdsaSelection).toContain(
      'export type EcdsaCommittedLane<A extends WalletAuthAuthority = WalletAuthAuthority>',
    );
    expect(ecdsaSelection).toContain('A extends PasskeyWalletAuthAuthority');
    expect(ecdsaSelection).toContain('A extends EmailOtpWalletAuthAuthority');
    expect(ecdsaSelection).not.toContain("kind: 'passkey_ecdsa_committed_lane'");
    expect(ecdsaSelection).not.toContain("kind: 'email_otp_ecdsa_committed_lane'");
    expect(committedLaneType).not.toContain('walletId:');
    expect(ecdsaSelection).not.toContain('function passkeyAuthorityFromCandidate');
    expect(ecdsaSelection).toContain('function passkeyAuthorityFromRecord');
    expect(ecdsaSelection).toContain(
      'parseThresholdEcdsaSessionRecordAsRoleLocalReadyRecord(record)',
    );
    expect(ecdsaSelection).toContain(
      'function assertEcdsaCommittedLaneAuthorityMatchesWallet',
    );
    expect(ecdsaSelection).toContain(
      'committed lane authority wallet mismatch',
    );
    expect(ecdsaSelection).toContain("kind: 'resolver_backed'");
    expect(ecdsaSelection).toContain("source: 'resolver_backed'");
    expect(ecdsaSelection).toContain(
      'resolveEmailOtpEcdsaSigningSessionAuthority',
    );
    expect(ecdsaSelectionTypecheck).toContain(
      'resolver-backed lanes cannot satisfy record-backed committed-lane consumers',
    );
    expect(ecdsaSelectionTypecheck).toContain(
      'resolver-backed Email OTP ECDSA lanes require wallet-bound authority',
    );
    expect(readySelectionType).toContain('committedLane: ReadyPasskeyEcdsaCommittedLane');
    expect(readySelectionType).toContain('committedLane: ReadyEmailOtpEcdsaCommittedLane');
    expect(readySelectionType).not.toContain('committedLane?: never');
    expect(ecdsaSelectionTypecheck).toContain(
      'passkey ready selections require a committed lane',
    );
    const budgetAuthStart = preparedSigning.indexOf(
      'function budgetStatusAuthFromReadyEcdsaMaterial',
    );
    const budgetAuthSource = preparedSigning.slice(
      budgetAuthStart,
      preparedSigning.indexOf('function assertPreparedMaterialBindingMatchesOperation', budgetAuthStart),
    );
    expect(budgetAuthSource).toContain('args.selection.committedLane.walletSessionAuthority');
    expect(budgetAuthSource).not.toContain(
      'signerSession.routerAbEcdsaHssNormalSigning.credential.walletSessionJwt',
    );
  });

  test('EVM-family ECDSA signing does not use legacy read-side restore fallback paths', () => {
    const preparedSigning = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
    );
    const depsStart = preparedSigning.indexOf('export type PrepareEvmFamilyEcdsaSigningDeps');

    expect(preparedSigning.slice(depsStart)).not.toContain(
      'restorePersistedEmailOtpSessionsForRead',
    );
    expect(preparedSigning).not.toContain("(['email_otp', 'passkey'] as const)");
  });

  test('Email OTP seal transport requires explicit wallet-session authority', () => {
    const workerTypes = readRepoFile('packages/sdk-web/src/core/types/secure-confirm-worker.ts');
    const uiConfirmManager = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts',
    );
    const restoreStart = uiConfirmManager.indexOf(
      'private async restorePasskeySealedRecordForWallet',
    );
    const restoreBlock = uiConfirmManager.slice(
      restoreStart,
      uiConfirmManager.indexOf('putWarmSessionMaterial = async', restoreStart),
    );

    expect(workerTypes).toContain('type EmailOtpWarmSessionSealTransportCommon');
    expect(workerTypes).toContain('walletSessionJwt: string');
    expect(uiConfirmManager).toContain('function sealTransportWalletSessionAuthoritySource');
    expect(uiConfirmManager).toContain("transport?.authMethod === 'email_otp'");
    expect(uiConfirmManager).toContain("explicitTransport?.authMethod === 'email_otp'");
    expect(uiConfirmManager).toContain('const requiresExplicitWalletSessionJwt =');
    expect(uiConfirmManager).toContain('!requiresExplicitWalletSessionJwt');
    expect(uiConfirmManager).toContain(
      'if (requiresExplicitWalletSessionJwt && !explicitWalletSessionJwt)',
    );
    expect(restoreBlock).not.toContain("args.record.authMethod === 'email_otp'");
  });

  test('EVM-family exhausted ECDSA lanes defer ready-material requirements until reauth', () => {
    const evmSigning = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    );
    const evmFamilyEcdsaIdentity = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts',
    );
    const executorStart = evmSigning.indexOf('const preparedExecutorSession =');
    const executorEnd = evmSigning.indexOf('const executePayload =', executorStart);
    const executorPreparation = evmSigning.slice(executorStart, executorEnd);

    expect(evmSigning).not.toContain('readSelectedEcdsaKeyRefForLane({');
    expect(executorPreparation).not.toContain(
      "requireReadyEcdsaMaterial(\n        preparedExecutorSession.material,\n        'prepared executor signer session'",
    );
    expect(executorPreparation).not.toContain('prepared executor requires ready signer material');
    expect(executorPreparation).not.toContain(
      'toVerifiedEcdsaPublicFactsFromPairedRecordAndKeyRef({',
    );
    expect(executorPreparation).not.toContain(
      'preparedExecutorSession.signingLane.key.thresholdOwnerAddress',
    );
    expect(evmFamilyEcdsaIdentity).not.toContain(
      '!hasReadyThresholdEcdsaClientShare(input.keyRef)',
    );
  });

  test('EVM-family selection diagnostics remain observational', () => {
    const files = [
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    ];
    const violations: string[] = [];
    for (const file of files) {
      const source = readRepoFile(file);
      const lines = source.split(/\r?\n/);
      lines.forEach((line, index) => {
        if (/\b(if|while)\s*\(.*diagnostics/.test(line)) {
          violations.push(`${file}:${index + 1}: ${line.trim()}`);
        }
      });
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });
});
