import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function check(_label, callback) {
  callback();
}

function describeChecks(_label, callback) {
  callback();
}

function expect(received, message = '') {
  return {
    toContain(expected) {
      assert.ok(
        received.includes(expected),
        message || `Expected value to contain \`${expected}\``,
      );
    },
    toEqual(expected) {
      assert.deepEqual(received, expected, message);
    },
    toBeLessThanOrEqual(expected) {
      assert.ok(received <= expected, message || `Expected ${received} <= ${expected}`);
    },
    toBeGreaterThan(expected) {
      assert.ok(received > expected, message || `Expected ${received} > ${expected}`);
    },
    toBeGreaterThanOrEqual(expected) {
      assert.ok(received >= expected, message || `Expected ${received} >= ${expected}`);
    },
    not: {
      toContain(expected) {
        assert.ok(
          !received.includes(expected),
          message || `Expected value not to contain \`${expected}\``,
        );
      },
    },
  };
}

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function listRepoFiles(relativeDir) {
  const absoluteDir = path.join(repoRoot, relativeDir);
  const entries = fs.readdirSync(absoluteDir, { withFileTypes: true });
  const files = [];
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

describeChecks('Email OTP operation split guard', () => {
  check('transaction signing APIs cannot request export challenges', () => {
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

    const violations = [];
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

  check(
    'Email OTP coordinator keeps export challenge issuance separate from signing challenge issuance',
    () => {
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
    },
  );

  check('Email OTP coordinator stays a thin runtime facade', () => {
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

  check('obsolete wallet auth mode proof resolver stays deleted', () => {
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
    const violations = [];

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

  check('SDK signing code reads Email OTP authority identity through accessors', () => {
    const checkedFiles = [
      ...listRepoFiles('packages/sdk-web/src/core/signingEngine'),
      'packages/sdk-web/src/SeamsWeb/operations/auth/login.ts',
    ];
    const forbidden = [/\.authority\.provider\b/g, /\.authority\.providerUserId\b/g];
    const violations = [];

    for (const relativePath of checkedFiles) {
      const source = readRepoFile(relativePath);
      for (const pattern of forbidden) {
        if (pattern.test(source)) {
          violations.push(`${relativePath} contains ${pattern.source}`);
        }
        pattern.lastIndex = 0;
      }
    }

    expect(violations, violations.join('\n')).toEqual([]);
  });

  check('ECDSA fresh Email OTP decisions stay planner-owned, not pre-sign guard-owned', () => {
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

  check('ECDSA transaction signing selects an exact lane before material lookup', () => {
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

  check('Email OTP ECDSA helpers require the Email OTP source lane', () => {
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
    expect(ecdsaLanes).not.toContain('function resolveEmailOtpEcdsaAuthLaneFromRecord');
  });

  check('Email OTP ECDSA export uses exact current or public reauth authority', () => {
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
    expect(exportMaterial).toContain("kind: 'record_backed'");
    expect(exportMaterial).toContain("kind: 'durable_authority_backed'");
    expect(exportMaterial).toContain("kind: 'public_reauth_authority_backed'");
    expect(exportMaterial).toContain('signingSessionAuthority: EmailOtpEcdsaSigningSessionAuthority');
    expect(exportMaterial).toContain('emailOtpEcdsaSigningSessionAuthorityFromSealedRecord');
    expect(exportMaterial).not.toContain('fresh_email_otp_needs_challenge');
    expect(exportFlow).toContain('emailOtpEcdsaExportChallengeAuthority');
    expect(exportFlow).toContain("case 'durable_authority_backed':");
    expect(exportFlow).toContain("case 'public_reauth_authority_backed':");
    expect(exportFlow).toContain('exportEcdsaKeyWithDurableAuthorization');
    expect(exportFlow).toContain('exportEcdsaKeyWithPublicReauthAuthorization');
    expect(exportRuntime).toContain('export type ExportEcdsaKeyWithDurableAuthorizationArgs');
    expect(exportRuntime).toContain('export type ExportEcdsaKeyWithPublicReauthAuthorizationArgs');
    expect(exportRecovery).toContain('export async function exportEcdsaKeyWithDurableAuthorization');
    expect(exportRecovery).toContain(
      'export async function exportEcdsaKeyWithPublicReauthAuthorization',
    );
    expect(exportRecovery).toContain('buildSigningSessionRoutePlan');
    expect(exportRecovery).not.toContain('export async function exportEcdsaKeyWithFreshEmailOtpLane');
    expect(recoveryPortAdapter).toContain('exportEcdsaKeyWithDurableAuthorization');
    expect(recoveryPortAdapter).toContain('exportEcdsaKeyWithPublicReauthAuthorization');
  });

  check('Email OTP Ed25519 NEAR step-up consumes committed lanes', () => {
    const signNear = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts',
    );
    const operationDeps = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/interfaces/operationDeps.ts',
    );
    const budgetRecovery = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoBudgetRecovery.ts',
    );

    expect(signNear).toContain('function buildNearEmailOtpEd25519Reconnect');
    expect(signNear).toContain('const committedLane = args.committedLane;');
    expect(signNear).toContain('committedLane,');
    expect(operationDeps).toContain('recoverEmailOtpEd25519CapabilityForSigning?: (args: {');
    expect(operationDeps).toContain('committedLane: Ed25519SigningLane;');
    expect(budgetRecovery).toContain('committedLane: Ed25519SigningLane;');
    expect(budgetRecovery).toContain('walletAuthAuthoritiesMatch(');
    expect(budgetRecovery).toContain('args.committedLane.authority');
    expect(budgetRecovery).not.toContain('RecordBackedEmailOtpEd25519SigningCommittedLane');
  });

  check('EVM-family ECDSA reauth carries committed lanes for every auth branch', () => {
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
      ecdsaLogin.indexOf('export type EmailOtpEcdsaTransactionStepUpInput', ecdsaSigningInputStart),
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
    expect(authPlanning).toContain('emailOtpStepUpAuthority(preparedSelection)');
    expect(authPlanning).toContain('committedLane: selection.committedLane');
    expect(authPlanning).toContain(
      "return { kind: 'public_reauth_anchor', reauthLane: selection.reauthLane }",
    );
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

  check('EVM-family ECDSA ready selections use committed lanes for every auth branch', () => {
    const ecdsaSelection = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
    );
    const ecdsaIdentity = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts',
    );
    const sessionRecords = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/session/persistence/records.ts',
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
    expect(ecdsaSelection).toContain('function assertEcdsaCommittedLaneAuthorityMatchesWallet');
    expect(ecdsaSelection).toContain('committed lane authority wallet mismatch');
    expect(readySelectionType).toContain('committedLane: ReadyPasskeyEcdsaCommittedLane');
    expect(readySelectionType).toContain('committedLane: ReadyEmailOtpEcdsaCommittedLane');
    expect(readySelectionType).not.toContain('committedLane?: never');
    expect(ecdsaSelectionTypecheck).toContain('passkey ready selections require a committed lane');
    const budgetAuthStart = preparedSigning.indexOf(
      'function budgetStatusAuthFromReadyEcdsaMaterial',
    );
    const budgetAuthSource = preparedSigning.slice(
      budgetAuthStart,
      preparedSigning.indexOf(
        'function assertPreparedMaterialBindingMatchesOperation',
        budgetAuthStart,
      ),
    );
    expect(budgetAuthSource).toContain('args.selection.committedLane.walletSessionAuthority');
    expect(budgetAuthSource).not.toContain(
      'signerSession.routerAbEcdsaDerivationNormalSigning.credential.walletSessionJwt',
    );
    expect(ecdsaIdentity).not.toContain('walletSessionAuthInputFromPersistedThresholdSession');
    expect(sessionRecords).toContain('resolveRouterAbEcdsaWalletSessionAuthFromRecord(record)');
    expect(sessionRecords).not.toContain('keyRef.walletSessionJwt || args.bootstrap.session.jwt');
  });

  check('EVM-family ECDSA signing does not use legacy read-side restore fallback paths', () => {
    const preparedSigning = readRepoFile(
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
    );
    const depsStart = preparedSigning.indexOf('export type PrepareEvmFamilyEcdsaSigningDeps');

    expect(preparedSigning.slice(depsStart)).not.toContain(
      'restorePersistedEmailOtpSessionsForRead',
    );
    expect(preparedSigning).not.toContain("(['email_otp', 'passkey'] as const)");
  });

  check('Email OTP seal transport requires explicit wallet-session authority', () => {
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
    expect(uiConfirmManager).toContain('const walletSessionJwt = explicitWalletSessionJwt;');
    expect(uiConfirmManager).not.toContain('function sealTransportWalletSessionAuthoritySource');
    expect(uiConfirmManager).not.toContain('const requiresExplicitWalletSessionJwt =');
    expect(uiConfirmManager).not.toContain('!requiresExplicitWalletSessionJwt');
    expect(uiConfirmManager).not.toContain('function persistedSealTransportWalletSessionJwt');
    expect(uiConfirmManager).not.toContain('walletSessionJwtFromPersistedSealedRestore');
    expect(uiConfirmManager).not.toContain('walletSessionJwtFromPersistedSessionAuthRecord');
    expect(uiConfirmManager).toContain(
      'parseRouterAbEd25519WalletSessionAuthorityFromRecord(record)',
    );
    expect(uiConfirmManager).toContain('resolveRouterAbEcdsaWalletSessionAuthFromRecord(record)');
    expect(uiConfirmManager).not.toContain(
      'walletSessionJwtFromPersistedSessionAuthRecord(ed25519Record) ||\n              walletSessionJwtFromPersistedSessionAuthRecord(ecdsaRecord)',
    );
    expect(uiConfirmManager).toContain(
      "if (authMethod === 'email_otp' && !explicitWalletSessionJwt)",
    );
    expect(restoreBlock).not.toContain("args.record.authMethod === 'email_otp'");
  });

  check('EVM-family exhausted ECDSA lanes defer ready-material requirements until reauth', () => {
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
    expect(evmFamilyEcdsaIdentity).not.toContain(
      '!hasReadyThresholdEcdsaClientShare(input.keyRef)',
    );
  });

  check('EVM-family selection diagnostics remain observational', () => {
    const files = [
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
      'packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    ];
    const violations = [];
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

console.log('[check-email-otp-operation-split] passed');
