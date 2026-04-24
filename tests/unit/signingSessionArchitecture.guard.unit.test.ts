import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

function readRepoFile(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function repoFileExists(relativePath: string): boolean {
  return fs.existsSync(path.join(repoRoot, relativePath));
}

function collectTokenViolations(args: {
  files: readonly string[];
  forbiddenTokens: readonly string[];
}): string[] {
  const violations: string[] = [];
  for (const relativePath of args.files) {
    const source = readRepoFile(relativePath);
    for (const token of args.forbiddenTokens) {
      if (source.includes(token)) {
        violations.push(`${relativePath} contains ${token}`);
      }
    }
  }
  return violations;
}

function collectRepoFiles(relativeRoot: string, predicate: (relativePath: string) => boolean): string[] {
  const root = path.join(repoRoot, relativeRoot);
  const files: string[] = [];
  const visit = (absolutePath: string): void => {
    for (const entry of fs.readdirSync(absolutePath, { withFileTypes: true })) {
      const child = path.join(absolutePath, entry.name);
      if (entry.isDirectory()) {
        visit(child);
        continue;
      }
      const relativePath = path.relative(repoRoot, child);
      if (predicate(relativePath)) files.push(relativePath);
    }
  };
  visit(root);
  return files.sort();
}

test.describe('signing session architecture boundary guard', () => {
  test('planner and lane modules stay free of auth side-effect dependencies', () => {
    const purePlanningFiles = [
      'client/src/core/signingEngine/session/SigningSessionPlanner.ts',
      'client/src/core/signingEngine/session/SigningExecutionMachine.ts',
      'client/src/core/signingEngine/session/SigningLaneBuilders.ts',
      'client/src/core/signingEngine/session/SigningCapabilityReader.ts',
    ];
    const forbidden = [
      'touchIdPrompt',
      'navigator.credentials',
      'getAuthenticationCredentialsSerializedForChallengeB64u',
      'requestEmailOtpTransactionSigningChallenge',
      'loginWithEmailOtp',
      'reconnectPasskey',
      'provisionThreshold',
      'bootstrapThreshold',
      'consumeWalletSigningSessionUse',
    ];

    const violations = collectTokenViolations({
      files: purePlanningFiles,
      forbiddenTokens: forbidden,
    });

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('warm-session services do not own transaction auth-plan policy', () => {
    const productionFiles = [
      'client/src/core/signingEngine/session/WarmSessionCapabilityReader.ts',
      'client/src/core/signingEngine/session/WarmSessionCapabilityResolver.ts',
      'client/src/core/signingEngine/session/WarmSessionStatusReader.ts',
      'client/src/core/signingEngine/session/WarmSessionEcdsaProvisioner.ts',
      'client/src/core/signingEngine/session/WarmSessionEd25519Provisioner.ts',
      'client/src/core/signingEngine/orchestration/near/shared/thresholdAuthMode.ts',
      'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
      'client/src/core/signingEngine/api/evmSigning.ts',
      'client/src/core/signingEngine/api/tempoSigning.ts',
      'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
    ];
    const forbidden = [
      'resolveEd25519SigningAuthPlan',
      'WarmSessionEd25519SigningAuthPlan',
    ];

    const violations = collectTokenViolations({
      files: productionFiles,
      forbiddenTokens: forbidden,
    });

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('WarmSessionStore remains a focused storage helper', () => {
    const storePath = 'client/src/core/signingEngine/session/WarmSessionStore.ts';
    const storeSource = readRepoFile(storePath);

    expect(repoFileExists(storePath)).toBe(true);
    expect(storeSource).toContain('readWarmSessionCapabilityRecordsForAccount');
    expect(storeSource).toContain('readWarmSessionEd25519RecordByThresholdSessionId');
    expect(storeSource).toContain('readWarmSessionEcdsaRecordByThresholdSessionId');
    expect(
      collectTokenViolations({
        files: [storePath],
        forbiddenTokens: [
          'SigningSessionPlanner',
          'SigningExecutionMachine',
          'WalletSigningBudgetLedger',
          'orchestrateSigningConfirmation',
          'ensureEcdsaCapabilityReady',
          'applyEcdsaPostSignPolicy',
          'createWarmSessionStore',
          'export type WarmSessionStore =',
        ],
      }),
    ).toEqual([]);
  });

  test('warm-session service boundary types stay in WarmSessionServiceTypes', () => {
    const serviceTypesSource = readRepoFile(
      'client/src/core/signingEngine/session/WarmSessionServiceTypes.ts',
    );

    expect(serviceTypesSource).toContain('export type WarmSessionCapabilityReader');
    expect(serviceTypesSource).toContain('export type ThresholdWarmSessionStatusReader');
    expect(serviceTypesSource).toContain('export type WarmSessionProvisioner');
    expect(serviceTypesSource).toContain('export type WarmSessionPostSignPolicy');
  });

  test('focused warm-session services stay split by responsibility', () => {
    const requiredFocusedServiceFiles = [
      'client/src/core/signingEngine/session/WarmSessionStore.ts',
      'client/src/core/signingEngine/session/WarmSessionCapabilityReader.ts',
      'client/src/core/signingEngine/session/WarmSessionCapabilityResolver.ts',
      'client/src/core/signingEngine/session/WarmSessionStatusReader.ts',
      'client/src/core/signingEngine/session/WarmSessionSealedRefreshRestorer.ts',
      'client/src/core/signingEngine/session/WarmSessionEd25519Provisioner.ts',
      'client/src/core/signingEngine/session/WarmSessionEcdsaProvisioner.ts',
      'client/src/core/signingEngine/session/WarmSessionPostSignPolicyAdapter.ts',
    ];
    const forbiddenImplementationTokens = [
      'createWarmSessionStore',
      'export type WarmSessionStore =',
    ];

    const missingFiles = requiredFocusedServiceFiles.filter(
      (relativePath) => !repoFileExists(relativePath),
    );
    expect(missingFiles, missingFiles.join('\n')).toEqual([]);
    expect(
      collectTokenViolations({
        files: requiredFocusedServiceFiles,
        forbiddenTokens: forbiddenImplementationTokens,
      }),
    ).toEqual([]);
  });

  test('WarmSession provisioners and restorers stay out of transaction prompt policy', () => {
    const provisionerFiles = [
      'client/src/core/signingEngine/session/WarmSessionEd25519Provisioner.ts',
      'client/src/core/signingEngine/session/WarmSessionEcdsaProvisioner.ts',
    ];
    const restorerFiles = [
      'client/src/core/signingEngine/session/WarmSessionSealedRefreshRestorer.ts',
    ];
    const forbiddenPromptPolicy = [
      'SigningSessionPlanner',
      'WalletAuthModeResolver',
      'signingAuthPlan',
      'passkeySigningAuthPlan',
      'emailOtpSigningAuthPlan',
      'requestEmailOtpTransactionSigningChallenge',
      'loginWithEmailOtp',
      'navigator.credentials',
      'getAuthenticationCredentialsSerializedForChallengeB64u',
    ];

    expect(
      collectTokenViolations({
        files: provisionerFiles,
        forbiddenTokens: [...forbiddenPromptPolicy, 'WalletSigningBudgetLedger'],
      }),
    ).toEqual([]);
    expect(
      collectTokenViolations({
        files: restorerFiles,
        forbiddenTokens: forbiddenPromptPolicy,
      }),
    ).toEqual([]);
  });

  test('warm-session readers and provisioners do not own ECDSA sensitive-operation policy', () => {
    const focusedServiceFiles = [
      'client/src/core/signingEngine/session/WarmSessionCapabilityReader.ts',
      'client/src/core/signingEngine/session/WarmSessionCapabilityResolver.ts',
      'client/src/core/signingEngine/session/WarmSessionStatusReader.ts',
      'client/src/core/signingEngine/session/WarmSessionEcdsaProvisioner.ts',
      'client/src/core/signingEngine/session/WarmSessionEd25519Provisioner.ts',
    ];
    const policySource = readRepoFile('client/src/core/signingEngine/session/SigningPostSignPolicy.ts');
    const forbidden = collectTokenViolations({
      files: focusedServiceFiles,
      forbiddenTokens: [
        'WalletAuthPolicyError',
        'SENSITIVE_OPERATION_POLICIES',
        'export function assertEcdsaOperationAllowed',
        'function assertEcdsaOperationAllowed',
      ],
    });

    expect(forbidden, forbidden.join('\n')).toEqual([]);
    expect(policySource).toContain('export function assertEcdsaOperationAllowed');
    expect(policySource).toContain('WalletAuthPolicyError');
    expect(policySource).toContain('SENSITIVE_OPERATION_POLICIES');
  });

  test('new capability reader keeps signing-session reads tied to selected lanes', () => {
    const source = readRepoFile('client/src/core/signingEngine/session/SigningCapabilityReader.ts');
    const depsStart = source.indexOf('export type SigningCapabilityReaderDeps');
    const depsEnd = source.indexOf('export type SigningCapabilityReadErrorCode', depsStart);
    const depsSource = source.slice(depsStart, depsEnd);

    expect(depsStart).toBeGreaterThanOrEqual(0);
    expect(depsEnd).toBeGreaterThan(depsStart);
    expect(depsSource).toContain('readEmailOtpEcdsaSessionRecord');
    expect(depsSource).toContain('readPasskeyEcdsaSessionRecord');
    expect(depsSource).toContain('readEmailOtpEcdsaKeyRef');
    expect(depsSource).toContain('readPasskeyEcdsaKeyRef');
    expect(depsSource).toContain('readEd25519SessionRecordByThresholdSessionId');
    expect(depsSource).not.toContain('readEd25519SessionRecordForAccount');
    expect(depsSource).not.toContain('readEcdsaSessionRecord');
    expect(depsSource).not.toContain('readEcdsaKeyRef');
    expect(depsSource).not.toContain('source?:');
  });

  test('pre-confirm wallet transaction entrypoints stay out of confirmed auth side effects', () => {
    const preConfirmEntrypoints = [
      'client/src/core/TatchiPasskey/near/actions.ts',
      'client/src/core/TatchiPasskey/near/index.ts',
      'client/src/core/TatchiPasskey/tempo/index.ts',
      'client/src/core/TatchiPasskey/tempo/executeEvmFamilyTransaction.ts',
      'client/src/core/TatchiPasskey/evm/index.ts',
    ];
    const forbidden = [
      'touchIdPrompt',
      'navigator.credentials',
      'getAuthenticationCredentialsSerializedForChallengeB64u',
      'loginWithEmailOtpEd25519CapabilityForSigning',
      'loginWithEmailOtpEcdsaCapabilityForSigning',
      'reconnectPasskeyEd25519CapabilityForSigning',
      'provisionThresholdEcdsaSession',
      'bootstrapThresholdEcdsaSession',
      'consumeWalletSigningSessionUse',
      'getThresholdEcdsaSessionRecordForLookup',
      'getThresholdEcdsaKeyRefForLookup',
    ];

    const violations = collectTokenViolations({
      files: preConfirmEntrypoints,
      forbiddenTokens: forbidden,
    });

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('EVM-family auth planning separates pre-confirm and confirmed auth deps', () => {
    const source = readRepoFile('client/src/core/signingEngine/api/evmFamily/authPlanning.ts');
    const preConfirmStart = source.indexOf('export type EvmFamilyPreConfirmSigningDeps');
    const confirmedEmailOtpStart = source.indexOf('export type EvmFamilyConfirmedEmailOtpDeps');
    const confirmedStart = source.indexOf('export type EvmFamilyConfirmedSigningDeps');
    const transactionDepsStart = source.indexOf('export type EvmFamilyTransactionWalletAuthDeps');
    const baseArgsStart = source.indexOf('type ResolveEvmFamilyTransactionWalletAuthBaseArgs');
    const baseArgsEnd = source.indexOf('export type ResolveEvmFamilyTransactionWalletAuthArgs', baseArgsStart);

    expect(preConfirmStart).toBeGreaterThanOrEqual(0);
    expect(confirmedEmailOtpStart).toBeGreaterThan(preConfirmStart);
    expect(confirmedStart).toBeGreaterThan(preConfirmStart);
    expect(transactionDepsStart).toBeGreaterThan(confirmedStart);
    expect(baseArgsEnd).toBeGreaterThan(baseArgsStart);

    const preConfirmSource = source.slice(preConfirmStart, confirmedEmailOtpStart);
    expect(preConfirmSource).toContain('touchConfirm: WarmSessionStatusReader');
    expect(preConfirmSource).toContain('getEmailOtpWarmSessionStatus?');
    expect(preConfirmSource).not.toContain('EvmFamilySigningSessionCoordinatorDeps');
    expect(preConfirmSource).not.toContain('requestEmailOtpTransactionSigningChallenge');
    expect(preConfirmSource).not.toContain('loginWithEmailOtpEcdsaCapabilityForSigning');
    expect(preConfirmSource).not.toContain('provisionThresholdEcdsaSession');
    expect(preConfirmSource).not.toContain('rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord');

    const transactionDepsSource = source.slice(transactionDepsStart, baseArgsStart);
    expect(transactionDepsSource).toContain('EvmFamilyPreConfirmSigningDeps');
    expect(transactionDepsSource).not.toContain('EvmFamilyConfirmedEmailOtpDeps');
    expect(transactionDepsSource).not.toContain('requestEmailOtpTransactionSigningChallenge');
    expect(transactionDepsSource).not.toContain('loginWithEmailOtpEcdsaCapabilityForSigning');

    const baseArgsSource = source.slice(baseArgsStart, baseArgsEnd);
    expect(baseArgsSource).toContain('deps: EvmFamilyTransactionWalletAuthDeps');
    expect(baseArgsSource).toContain('confirmedDeps: EvmFamilyConfirmedSigningDeps');
  });

  test('NEAR transaction auth planning separates pre-confirm status from confirmed OTP deps', () => {
    const source = readRepoFile('client/src/core/signingEngine/api/nearSigning.ts');
    const preConfirmStart = source.indexOf('type NearTransactionPreConfirmSigningDeps');
    const confirmedStart = source.indexOf('type NearTransactionConfirmedSigningDeps');
    const resolverStart = source.indexOf('async function resolveNearTransactionWalletAuth');
    const resolverArgsEnd = source.indexOf('}): Promise', resolverStart);

    expect(preConfirmStart).toBeGreaterThanOrEqual(0);
    expect(confirmedStart).toBeGreaterThan(preConfirmStart);
    expect(resolverStart).toBeGreaterThan(confirmedStart);
    expect(resolverArgsEnd).toBeGreaterThan(resolverStart);

    const preConfirmSource = source.slice(preConfirmStart, confirmedStart);
    expect(preConfirmSource).toContain('getWarmThresholdEd25519SessionStatusForSession?');
    expect(preConfirmSource).toContain('hasTouchConfirm');
    expect(preConfirmSource).not.toContain('requestEmailOtpTransactionSigningChallenge');
    expect(preConfirmSource).not.toContain('loginWithEmailOtpEd25519CapabilityForSigning');
    expect(preConfirmSource).not.toContain('reconnectPasskeyEd25519CapabilityForSigning');
    expect(preConfirmSource).not.toContain('restoreEmailOtpEcdsaSigningSessionForNearTransaction');
    expect(preConfirmSource).not.toContain('getSignerWorkerContext');

    const resolverArgsSource = source.slice(resolverStart, resolverArgsEnd);
    expect(resolverArgsSource).toContain('preConfirmDeps: NearTransactionPreConfirmSigningDeps');
    expect(resolverArgsSource).toContain('confirmedDeps: NearTransactionConfirmedSigningDeps');
    expect(resolverArgsSource).not.toContain('deps: NearSigningApiDeps');
    expect(source).toContain('prepare: prepareEmailOtpChallenge');
    expect(source).not.toContain('const challenge = await walletAuthPlan.challenge();');
  });

  test('transaction flows keep auth side effects behind confirmation display', () => {
    const flows = [
      {
        name: 'EVM',
        source: readRepoFile('client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts'),
      },
      {
        name: 'Tempo',
        source: readRepoFile(
          'client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts',
        ),
      },
      {
        name: 'NEAR',
        source: readRepoFile(
          'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
        ),
      },
    ];

    for (const flow of flows) {
      const displayIndex = flow.source.indexOf('STEP_05_CONFIRMATION_DISPLAYED');
      const prepareIndex = flow.source.indexOf('emailOtpSigning.prepare()');
      const confirmIndex = flow.source.indexOf('orchestrateSigningConfirmation({');
      const completeIndex = flow.source.indexOf('emailOtpSigning.complete');
      const reconnectIndex = Math.max(
        flow.source.indexOf("notifyAuthSideEffectStarted('threshold_reconnect'"),
        flow.source.indexOf("emitConfirmedAuthSideEffectStarted('threshold_reconnect'"),
      );

      expect(displayIndex, `${flow.name} confirmation display`).toBeGreaterThanOrEqual(0);
      expect(prepareIndex, `${flow.name} OTP prepare`).toBeGreaterThan(displayIndex);
      expect(confirmIndex, `${flow.name} confirmation orchestration`).toBeGreaterThan(prepareIndex);
      expect(completeIndex, `${flow.name} OTP completion`).toBeGreaterThan(confirmIndex);
      expect(reconnectIndex, `${flow.name} threshold reconnect`).toBeGreaterThan(displayIndex);
    }
  });

  test('EVM-family nonce lifecycle modules stay out of signing-session policy', () => {
    const nonceFiles = [
      'client/src/core/signingEngine/api/evmFamily/nonceLifecycle.ts',
      'client/src/core/signingEngine/api/evmFamily/nonceResolution.ts',
      'client/src/core/signingEngine/api/evmFamily/evmNonceLifecycle.ts',
      'client/src/core/signingEngine/api/evmFamily/tempoNonceLifecycle.ts',
    ];
    const forbidden = [
      'SigningSessionPlanner',
      'SigningCapabilityReader',
      'requestEmailOtpTransactionSigningChallenge',
      'loginWithEmailOtp',
      'EmailOtp',
      'emailOtp',
      'touchIdPrompt',
      'navigator.credentials',
      'getAuthenticationCredentialsSerializedForChallengeB64u',
      'getThresholdEcdsaSessionRecord',
      'thresholdSessionStore',
      'WalletSigningBudgetLedger',
      'consumeWalletSigningSessionUse',
    ];

    const violations = collectTokenViolations({
      files: nonceFiles,
      forbiddenTokens: forbidden,
    });

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('EVM-family smart-account readiness stays out of auth policy and budget spending', () => {
    const smartAccountFiles = ['client/src/core/signingEngine/api/evmFamily/smartAccount.ts'];
    const forbidden = [
      'SigningSessionPlanner',
      'SigningCapabilityReader',
      'requestEmailOtpTransactionSigningChallenge',
      'loginWithEmailOtp',
      'EmailOtp',
      'emailOtp',
      'touchIdPrompt',
      'navigator.credentials',
      'getAuthenticationCredentialsSerializedForChallengeB64u',
      'getThresholdEcdsaSessionRecord',
      'thresholdSessionStore',
      'WalletSigningBudgetLedger',
      'consumeWalletSigningSessionUse',
    ];

    const violations = collectTokenViolations({
      files: smartAccountFiles,
      forbiddenTokens: forbidden,
    });

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('EVM-family transaction signing cannot use source-less ECDSA lookup helpers', () => {
    const transactionSigningFiles = [
      'client/src/core/signingEngine/api/evmSigning.ts',
      'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
      'client/src/core/signingEngine/api/evmFamily/budgetSpending.ts',
      'client/src/core/signingEngine/api/evmFamily/ecdsaReadiness.ts',
      'client/src/core/signingEngine/api/evmFamily/ecdsaSelection.ts',
      'client/src/core/signingEngine/api/evmFamily/emailOtpRefresh.ts',
      'client/src/core/signingEngine/api/evmFamily/freshEmailOtpRetry.ts',
      'client/src/core/signingEngine/api/evmFamily/postSignPolicy.ts',
      'client/src/core/signingEngine/api/evmFamily/signingFlowRuntime.ts',
      'client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts',
    ];
    const forbidden = [
      'getThresholdEcdsaSessionRecordForLookup',
      'getThresholdEcdsaKeyRefForLookup',
    ];

    const violations = collectTokenViolations({
      files: transactionSigningFiles,
      forbiddenTokens: forbidden,
    });

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('EVM-family transaction modules stay behind planner and ledger boundaries', () => {
    const evmFamilyTransactionFiles = [
      'client/src/core/signingEngine/api/evmSigning.ts',
      'client/src/core/signingEngine/api/evmFamily/accountAuth.ts',
      'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
      'client/src/core/signingEngine/api/evmFamily/budgetSpending.ts',
      'client/src/core/signingEngine/api/evmFamily/ecdsaReadiness.ts',
      'client/src/core/signingEngine/api/evmFamily/ecdsaSelection.ts',
      'client/src/core/signingEngine/api/evmFamily/emailOtpRefresh.ts',
      'client/src/core/signingEngine/api/evmFamily/freshEmailOtpRetry.ts',
      'client/src/core/signingEngine/api/evmFamily/postSignPolicy.ts',
      'client/src/core/signingEngine/api/evmFamily/signingFlowRuntime.ts',
      'client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts',
      'client/src/core/signingEngine/api/evmFamily/signingSessionCoordinator.ts',
    ];
    const forbidden = [
      'getStoredThresholdEcdsa',
      'setStoredThresholdEcdsa',
      'deleteStoredThresholdEcdsa',
      'getAuthenticationCredentialsSerializedForChallengeB64u',
      'navigator.credentials',
      'createWalletSigningSessionCoordinator',
      'WalletSigningSessionCoordinator',
      'consumeWalletSigningSessionUse',
      '.consumeUse({',
    ];

    const violations = collectTokenViolations({
      files: evmFamilyTransactionFiles,
      forbiddenTokens: forbidden,
    });

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('TatchiPasskey login and prefill helpers avoid source-less ECDSA reads', () => {
    const authSessions = readRepoFile('client/src/core/TatchiPasskey/authSessions.ts');
    const login = readRepoFile('client/src/core/TatchiPasskey/login.ts');
    const orchestrationDependencyFactory = readRepoFile(
      'client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts',
    );
    const warmSessionStatusReader = readRepoFile(
      'client/src/core/signingEngine/session/WarmSessionStatusReader.ts',
    );
    const warmSessionEcdsaProvisioner = readRepoFile(
      'client/src/core/signingEngine/session/WarmSessionEcdsaProvisioner.ts',
    );

    expect(authSessions).toContain("source: 'login'");
    expect(login).toContain('readonly ThresholdEcdsaSessionStoreSource[]');
    expect(login).toContain('source,');
    expect(login).not.toContain('ThresholdEcdsaSessionStoreSource | undefined');
    expect(login).not.toContain("['email_otp', undefined");
    expect(login).not.toContain('getRecord({ nearAccountId, chain })');
    expect(orchestrationDependencyFactory).toContain(
      'THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES',
    );
    expect(orchestrationDependencyFactory).not.toContain(
      'getThresholdEcdsaKeyRefForLookup({ nearAccountId, chain })',
    );
    expect(warmSessionStatusReader).not.toContain('const genericRecord = readCandidate()');
    expect(warmSessionStatusReader).not.toContain('readCandidate()');
    expect(warmSessionEcdsaProvisioner).toContain('listThresholdEcdsaKeyRefsForLookup');
    expect(warmSessionEcdsaProvisioner).toContain('readEcdsaKeyRefCandidates');
    expect(warmSessionEcdsaProvisioner).not.toContain(
      'getThresholdEcdsaKeyRefForLookup({\n        nearAccountId,\n        chain: args.chain,\n        ...(args.source ? { source: args.source } : {}),',
    );
  });

  test('EVM-family ECDSA readiness passes explicit source to warm-session APIs', () => {
    const serviceTypes = readRepoFile(
      'client/src/core/signingEngine/session/WarmSessionServiceTypes.ts',
    );
    const readiness = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/ecdsaReadiness.ts',
    );
    const signingSessionCoordinator = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/signingSessionCoordinator.ts',
    );

    expect(serviceTypes).not.toContain('SourceScopedWarmEcdsaCapabilityReadyArgs');
    expect(serviceTypes).not.toContain('ensureEcdsaCapabilityReadyForSource');
    expect(serviceTypes).not.toContain('tryReuseReadyEcdsaBootstrapForSource');
    expect(readiness).toContain('ensureEcdsaCapabilityReady({');
    expect(readiness).toContain('source,');
    expect(signingSessionCoordinator).toContain('export type EvmFamilySigningSessionCoordinator = Pick');
    expect(signingSessionCoordinator).toContain("'ensureEcdsaCapabilityReady'");
    expect(signingSessionCoordinator).toContain("'applyEcdsaPostSignPolicy'");
    expect(signingSessionCoordinator).toContain("'assertEcdsaOperationAllowed'");
    expect(signingSessionCoordinator).not.toContain("'ensureEcdsaCapabilityReadyForSource'");
    expect(signingSessionCoordinator).not.toContain("'applyEcdsaPostSignPolicyForSource'");
    expect(signingSessionCoordinator).not.toContain("'assertEcdsaOperationAllowedForSource'");
    expect(signingSessionCoordinator).not.toContain('createWarmSessionStore');
    expect(signingSessionCoordinator).toContain('createWarmSessionCapabilityReader');
    expect(signingSessionCoordinator).toContain('createWarmSessionStatusReader');
    expect(signingSessionCoordinator).toContain('ensureWarmEcdsaCapabilityReady');
    expect(signingSessionCoordinator).toContain(
      'throw new Error(\'[SigningEngine] ECDSA signing source is required for signing-artifact cleanup\')',
    );
    expect(signingSessionCoordinator).toContain('listThresholdEcdsaSessionRecordsForLookup');
    expect(signingSessionCoordinator).toContain('for (const source of THRESHOLD_ECDSA_SESSION_STORE_SOURCES)');
    expect(signingSessionCoordinator).toContain('listThresholdEcdsaKeyRefsForLookup');
    expect(signingSessionCoordinator).toContain('source ? [source] : THRESHOLD_ECDSA_SESSION_STORE_SOURCES');
  });

  test('source-less ECDSA status reads return multi-lane status, not a selected lane', () => {
    const serviceTypes = readRepoFile(
      'client/src/core/signingEngine/session/WarmSessionServiceTypes.ts',
    );
    const statusReader = readRepoFile(
      'client/src/core/signingEngine/session/WarmSessionStatusReader.ts',
    );
    const signingEngine = readRepoFile('client/src/core/signingEngine/SigningEngine.ts');
    const login = readRepoFile('client/src/core/TatchiPasskey/login.ts');

    expect(serviceTypes).toContain('listEcdsaSigningSessionStatuses');
    expect(serviceTypes).toContain('thresholdSessionId: string;');
    expect(statusReader).toContain('listEcdsaSigningSessionStatuses');
    expect(statusReader).toContain(
      "throw new Error('[WarmSessionStatusReader] thresholdSessionId is required for ECDSA status')",
    );
    expect(signingEngine).toContain('listWarmThresholdEcdsaSessionStatuses');
    expect(signingEngine).toContain(
      '}).listEcdsaSigningSessionStatuses({ nearAccountId, chain });',
    );
    expect(login).toContain('listWarmThresholdEcdsaSessionStatuses');
    expect(login).not.toContain('getWarmThresholdEcdsaSessionStatus(nearAccountId,');
  });

  test('NEAR planner-readiness status uses an exact Ed25519 threshold session id', () => {
    const serviceTypes = readRepoFile(
      'client/src/core/signingEngine/session/WarmSessionServiceTypes.ts',
    );
    const statusReader = readRepoFile(
      'client/src/core/signingEngine/session/WarmSessionStatusReader.ts',
    );
    const thresholdAuthMode = readRepoFile(
      'client/src/core/signingEngine/orchestration/near/shared/thresholdAuthMode.ts',
    );

    expect(serviceTypes).toContain('getEd25519SigningSessionStatusForSession');
    expect(statusReader).toContain(
      "throw new Error('[WarmSessionStatusReader] thresholdSessionId is required for Ed25519 status')",
    );
    expect(thresholdAuthMode).toContain('getEd25519SigningSessionStatusForSession({');
    expect(thresholdAuthMode).not.toContain(
      'getEd25519SigningSessionStatus(args.nearAccountId)',
    );
  });

  test('EVM-family ECDSA cleanup requires the selected lane and has no pre-sign policy guard', () => {
    const evmSigning = readRepoFile('client/src/core/signingEngine/api/evmSigning.ts');
    const postSignPolicy = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/postSignPolicy.ts',
    );
    const serviceTypes = readRepoFile(
      'client/src/core/signingEngine/session/WarmSessionServiceTypes.ts',
    );

    expect(serviceTypes).not.toContain('SourceScopedWarmEcdsaPostSignPolicyArgs');
    expect(serviceTypes).not.toContain('SourceScopedWarmEcdsaOperationAllowedArgs');
    expect(postSignPolicy).toContain('applyEcdsaPostSignPolicy');
    expect(postSignPolicy).not.toContain('applyEcdsaPostSignPolicyForSource');
    expect(postSignPolicy).toContain(
      'throw new Error(\'[SigningEngine] ECDSA signing lane is required for post-sign cleanup\')',
    );
    expect(postSignPolicy).toContain(
      'throw new Error(\'[SigningEngine] ECDSA signing source is required for post-sign cleanup\')',
    );
    expect(postSignPolicy).toContain('readSelectedEcdsaRecordForLane');
    expect(postSignPolicy).toContain('source: selectedEcdsaSource');
    expect(postSignPolicy).not.toContain(
      '...(args.selectedEcdsaSource ? { source: args.selectedEcdsaSource } : {})',
    );
    expect(evmSigning).toContain('const selectedSource = resolveSelectedEcdsaSource();');
    expect(evmSigning).toContain(
      'throw new Error(\'[SigningEngine] ECDSA signing source is required for post-sign cleanup\')',
    );
    expect(evmSigning).toContain('...(ecdsaSigningLane ? { ecdsaSigningLane } : {})');
    expect(evmSigning).not.toContain(
      'throw new Error(\'[SigningEngine] ECDSA signing source is required for operation policy\')',
    );
    expect(evmSigning).not.toContain('assertEcdsaOperationAllowedForSource({');
    expect(evmSigning).not.toContain(
      '...(resolveSelectedEcdsaSource() ? { source: resolveSelectedEcdsaSource()! } : {})',
    );
  });

  test('post-sign cleanup policy stays out of wallet-budget spending', () => {
    const source = readRepoFile(
      'client/src/core/signingEngine/session/SigningPostSignPolicy.ts',
    );

    expect(source).toContain('clearEcdsaEphemeralMaterial');
    expect(source).toContain('markEmailOtpSessionConsumed');
    expect(source).not.toContain('WalletSigningBudgetLedger');
    expect(source).not.toContain('createWalletSigningBudgetLedger');
    expect(source).not.toContain('consumeWalletSigningSessionUse');
    expect(source).not.toContain('.recordSuccess({');
  });

  test('transaction signing records wallet budget through the ledger only', () => {
    const nearTransactionsFlow = readRepoFile(
      'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
    );
    const evmSigning = readRepoFile('client/src/core/signingEngine/api/evmSigning.ts');
    const evmBudgetSpending = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/budgetSpending.ts',
    );

    expect(nearTransactionsFlow).toContain('WalletSigningBudgetLedger');
    expect(nearTransactionsFlow).toContain('.recordSuccess({');
    expect(nearTransactionsFlow).not.toContain('consumeWalletSigningSessionUse');

    expect(evmSigning).toContain('createWalletSigningBudgetLedger');
    expect(evmSigning).toContain('recordSuccessfulEvmFamilyWalletSigningSessionSpend');
    expect(evmBudgetSpending).toContain('.recordSuccess({');
    expect(evmSigning).not.toContain('consumeWalletSigningSessionUse');
    expect(evmSigning).not.toContain('.consumeWalletSigningSessionUse({');
    expect(evmBudgetSpending).toContain(
      "throw new Error('[SigningEngine][ecdsa] missing selected signing lane for budget finalizer')",
    );
    expect(evmBudgetSpending).toContain('readSelectedEcdsaRecordForLane');
    expect(evmBudgetSpending).not.toContain('buildEvmFamilyEcdsaSigningLaneContext');
    expect(evmBudgetSpending).not.toContain('consumeWalletSigningSessionUse');
    expect(evmBudgetSpending).not.toContain('.consumeWalletSigningSessionUse({');
  });

  test('EVM-family transaction runtime receives the planner output', () => {
    const authPlanning = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
    );
    const evmSigning = readRepoFile('client/src/core/signingEngine/api/evmSigning.ts');
    const transactionExecutor = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts',
    );
    const signingFlowRuntime = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/signingFlowRuntime.ts',
    );

    expect(authPlanning).toContain('signingSessionPlan?: SigningSessionPlan');
    expect(authPlanning).toContain('plannedSigningSessionPlan = signingSessionPlan');
    expect(evmSigning).toContain('const { signingAuthPlan, signingSessionPlan, emailOtpSigning }');
    expect(evmSigning).toContain('...(signingSessionPlan ? { signingSessionPlan } : {})');
    expect(transactionExecutor).toContain('signingSessionPlan?: SigningSessionPlan');
    expect(signingFlowRuntime).toContain('signingSessionPlan?: SigningSessionPlan');
    expect(signingFlowRuntime).toContain('executeEvmFamilyRuntimeCommand');
  });

  test('EVM-family transaction side effects run through execution commands', () => {
    const transactionExecutor = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts',
    );
    const signingFlowRuntime = readRepoFile(
      'client/src/core/signingEngine/api/evmFamily/signingFlowRuntime.ts',
    );
    const events = readRepoFile('client/src/core/signingEngine/api/evmFamily/events.ts');

    expect(transactionExecutor).toContain('runSuccessfulEvmFamilyPostSignCommands');
    expect(transactionExecutor).toContain('buildSigningPostSignExecutionSteps');
    expect(transactionExecutor).toContain('runSigningExecutionSteps');
    expect(transactionExecutor).toContain('onTransition: emitEvmFamilySigningExecutionTrace');
    expect(transactionExecutor).toContain(
      'command.kind === SigningExecutionCommandKind.SpendBudget',
    );
    expect(transactionExecutor).toContain(
      'command.kind === SigningExecutionCommandKind.Cleanup',
    );
    expect(signingFlowRuntime).toContain(
      'commandKind: SigningExecutionCommandKind.RequestOtp',
    );
    expect(signingFlowRuntime).toContain(
      'commandKind: SigningExecutionCommandKind.ReconnectThreshold',
    );
    expect(signingFlowRuntime).toContain('createSigningExecutionCommandTraceEvent');
    expect(events).toContain('SigningExecutionTransitionEvent');
    expect(events).toContain('tatchi:debug:signing-execution');
  });

  test('production signing code uses named discriminants for high-risk auth and session plans', () => {
    const files = [
      'client/src/core/signingEngine/SigningEngine.ts',
      'client/src/core/signingEngine/auth/walletAuthModeResolver.ts',
      'client/src/core/signingEngine/session/SigningSessionPlanner.ts',
      'client/src/core/signingEngine/session/SigningExecutionMachine.ts',
      'client/src/core/signingEngine/orchestration/shared/touchConfirmSigning.ts',
      'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
      'client/src/core/signingEngine/api/evmFamily/signingFlowRuntime.ts',
      'client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts',
      'client/src/core/signingEngine/api/nearSigning.ts',
      'client/src/core/signingEngine/orchestration/near/shared/thresholdAuthMode.ts',
      'client/src/core/signingEngine/threshold/workflows/connectEd25519Session.ts',
    ];
    const allowedDefinitionFiles = new Set([
      'client/src/core/signingEngine/auth/walletAuthModeResolver.ts',
      'client/src/core/signingEngine/session/signingSessionTypes.ts',
      'client/src/core/signingEngine/session/SigningExecutionMachine.ts',
      'client/src/core/signingEngine/touchConfirm/shared/confirmTypes.ts',
    ]);
    const forbiddenTokens = [
      ".kind === 'warmSession'",
      ".kind !== 'warmSession'",
      ".kind === 'passkeyReauth'",
      ".kind !== 'passkeyReauth'",
      ".kind === 'emailOtpReauth'",
      ".kind !== 'emailOtpReauth'",
      ".kind === 'warm_session'",
      ".kind !== 'warm_session'",
      ".kind === 'email_otp_reauth'",
      ".kind !== 'email_otp_reauth'",
      ".kind === 'passkey_reauth'",
      ".kind !== 'passkey_reauth'",
      ".kind === 'not_ready'",
      ".kind !== 'not_ready'",
      "command.kind === 'spendBudget'",
      "command.kind === 'cleanup'",
      "commandKind: 'requestOtp'",
      "commandKind: 'reconnectThreshold'",
    ];

    const violations = files.flatMap((relativePath) => {
      if (allowedDefinitionFiles.has(relativePath)) return [];
      return collectTokenViolations({
        files: [relativePath],
        forbiddenTokens,
      });
    });

    expect(violations).toEqual([]);
  });

  test('EVM and Tempo signing flows share touch-confirm auth progress mapping', () => {
    const shared = readRepoFile(
      'client/src/core/signingEngine/orchestration/shared/touchConfirmSigning.ts',
    );
    const evmFlow = readRepoFile(
      'client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts',
    );
    const tempoFlow = readRepoFile(
      'client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts',
    );

    expect(shared).toContain('export function resolveTouchConfirmSigningAuthMethod');
    expect(shared).toContain('export function mapTouchConfirmSigningProgress');
    expect(evmFlow).toContain('resolveTouchConfirmSigningAuthMethod');
    expect(evmFlow).toContain('mapTouchConfirmSigningProgress');
    expect(tempoFlow).toContain('resolveTouchConfirmSigningAuthMethod');
    expect(tempoFlow).toContain('mapTouchConfirmSigningProgress');
    expect(evmFlow).not.toContain('function resolveSigningAuthMethod');
    expect(evmFlow).not.toContain('function mapTouchConfirmSigningProgress');
    expect(tempoFlow).not.toContain('function resolveSigningAuthMethod');
    expect(tempoFlow).not.toContain('function mapTouchConfirmSigningProgress');
  });

  test('export, add-signer, and link-device flows cannot use the transaction budget ledger', () => {
    const nonTransactionSigningFiles = [
      'client/src/core/TatchiPasskey/near/linkDevice.ts',
      'client/src/core/TatchiPasskey/near/linkDevicePreparedEcdsa.ts',
      'client/src/core/TatchiPasskey/near/linkDeviceOwnerManagement.ts',
      'client/src/core/TatchiPasskey/near/delegateAction.ts',
      'client/src/core/TatchiPasskey/evm/linkDeviceThresholdEcdsa.ts',
      'client/src/core/TatchiPasskey/scanDevice.ts',
      'client/src/core/signingEngine/orchestration/near/delegateFlow.ts',
      'client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts',
      'client/src/core/signingEngine/touchConfirm/ui/export-viewer-host.ts',
      'client/src/core/signingEngine/touchConfirm/ui/lit-components/ExportPrivateKey/iframe-export-bootstrap-script.ts',
    ];
    const forbidden = [
      'WalletSigningBudgetLedger',
      'createWalletSigningBudgetLedger',
      'buildWalletSigningSpendPlan',
      'consumeWalletSigningSessionUse',
      '.recordSuccess({',
    ];

    const violations = collectTokenViolations({
      files: nonTransactionSigningFiles,
      forbiddenTokens: forbidden,
    });

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('wallet signing-session ids are never synthesized from threshold session ids', () => {
    const files = [
      'client/src/core/signingEngine/api/session/signingSessionSealedStore.ts',
      'client/src/core/signingEngine/threshold/session/sessionPolicy.ts',
      'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
      'client/src/core/signingEngine/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
      'client/src/core/signingEngine/session/WalletSigningSessionCoordinator.ts',
    ];
    const fallbackPattern =
      /walletSigningSessionId[\s\S]{0,140}\|\|\s*(?:thresholdSessionId|sessionId)/g;
    const violations = files.flatMap((relativePath) => {
      const source = readRepoFile(relativePath);
      return Array.from(source.matchAll(fallbackPattern), (match) => {
        const line = source.slice(0, match.index || 0).split('\n').length;
        return `${relativePath}:${line} ${match[0].replace(/\s+/g, ' ')}`;
      });
    });

    expect(violations, violations.join('\n')).toEqual([]);
  });

  test('EVM-family implementation files stay under the evmFamily folder', () => {
    const apiDir = path.join(repoRoot, 'client/src/core/signingEngine/api');
    const rootEvmFamilyFiles = fs
      .readdirSync(apiDir)
      .filter((name) => /^evmFamily[A-Z].*\.ts$/.test(name));

    expect(rootEvmFamilyFiles, rootEvmFamilyFiles.join('\n')).toEqual([]);
  });
});
