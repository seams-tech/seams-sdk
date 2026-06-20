import { expect, test, type ConsoleMessage, type Page, type TestInfo } from '@playwright/test';
import {
  readWebAuthnGetCallCount,
  setupThresholdEcdsaSealedRefreshHarness,
  TEST_KEY_VERSION,
  TEST_SHAMIR_PRIME_B64U,
  type SealedRefreshHarness,
} from '../helpers/thresholdEcdsaSealedRefreshHarness';
import { autoConfirmWalletIframeUntil } from '../setup/flows';

type BudgetEvidenceResult = {
  ok: boolean;
  accountId: string;
  consoleMessages?: string[];
  stages: Array<{
    label: string;
    ok: boolean;
    chain?: string;
    kind?: string;
    sessionStatus?: string;
    remainingUses?: number | null;
    signingGrantId?: string;
    thresholdSessionId?: string;
    ed25519State?: string;
    ed25519Reason?: string;
    hasMaterialHandle?: boolean;
    hasMaterialBindingDigest?: boolean;
    hasClientVerifier?: boolean;
    ed25519VisibleRecordCount?: number;
    ed25519VisibleRecordAccounts?: string[];
    ed25519VisibleRecordSessions?: string[];
    error?: string;
  }>;
  webauthnGetCounts: {
    before: number;
    afterUnlock: number;
    afterFirstThreeSigns: number;
    afterFourthSign: number;
  };
  error?: string;
};

test.describe('Router A/B shared server-budget local evidence', () => {
  test.skip(
    process.env.RUN_ROUTER_AB_BUDGET_EVIDENCE !== '1',
    'Set RUN_ROUTER_AB_BUDGET_EVIDENCE=1 to run local browser budget evidence.',
  );

  test('one unlock provisions three shared uses across NEAR, Tempo, and EVM, then step-up resets budget', async (
    { page },
    testInfo,
  ) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const result = await runSharedBudgetEvidence(page, harness, {
        accountId: `budget-evidence-${Date.now()}.w3a-v1.testnet`,
      });

      await attachBudgetEvidenceTrace(testInfo, result);
      const signingStages = result.stages.filter((stage) => stage.chain);
      const budgetEvidence = validateSharedBudgetEvidenceResult(result);
      expect(result.ok, result.error || JSON.stringify(result, null, 2)).toBe(true);
      expect(
        budgetEvidence.ok,
        budgetEvidence.ok ? JSON.stringify(result, null, 2) : budgetEvidence.error,
      ).toBe(true);
      expect(signingStages.slice(0, 3).map((stage) => stage.chain)).toEqual([
        'near',
        'tempo',
        'evm',
      ]);
      expect(signingStages.slice(0, 3).every((stage) => stage.ok)).toBe(true);
      expect(result.webauthnGetCounts.afterFirstThreeSigns).toBe(
        result.webauthnGetCounts.afterUnlock,
      );
      expect(signingStages[3]?.ok, JSON.stringify(signingStages[3])).toBe(true);
      expect(result.webauthnGetCounts.afterFourthSign).toBe(
        result.webauthnGetCounts.afterFirstThreeSigns + 1,
      );
    } finally {
      await harness.close();
    }
  });
});

async function attachBudgetEvidenceTrace(
  testInfo: TestInfo,
  result: BudgetEvidenceResult,
): Promise<void> {
  await testInfo.attach('router-ab-server-budget-evidence.json', {
    body: JSON.stringify(result, null, 2),
    contentType: 'application/json',
  });
}

async function runSharedBudgetEvidence(
  page: Page,
  harness: SealedRefreshHarness,
  args: {
    accountId: string;
  },
): Promise<BudgetEvidenceResult> {
  const before = await readWebAuthnGetCallCount(page);
  const consoleMessages: string[] = [];
  const onConsole = (message: ConsoleMessage): void => {
    if (message.type() !== 'error' && message.type() !== 'warning') return;
    consoleMessages.push(`[${message.type()}] ${message.text()}`);
  };
  page.on('console', onConsole);
  const setupResult = await autoConfirmWalletIframeUntil(
    page,
    runSharedBudgetSetup(page, harness, args),
    {
      timeoutMs: 180_000,
      intervalMs: 250,
    },
  );
  if (!setupResult.ok) {
    return {
      ok: false,
      accountId: args.accountId,
      consoleMessages,
      stages: setupResult.stages,
      webauthnGetCounts: {
        before,
        afterUnlock: await readWebAuthnGetCallCount(page),
        afterFirstThreeSigns: await readWebAuthnGetCallCount(page),
        afterFourthSign: await readWebAuthnGetCallCount(page),
      },
      error: setupResult.error,
    };
  }
  const afterUnlock = await readWebAuthnGetCallCount(page);

  const firstThree = await runEvidenceSigns(page, {
    accountId: args.accountId,
    labels: ['near-1', 'tempo-1', 'evm-1'],
  });
  const afterFirstThreeSigns = await readWebAuthnGetCallCount(page);

  const fourth = await autoConfirmWalletIframeUntil(
    page,
    runEvidenceSigns(page, {
      accountId: args.accountId,
      labels: ['near-2'],
    }),
    {
      timeoutMs: 180_000,
      intervalMs: 250,
    },
  );
  const afterFourthSign = await readWebAuthnGetCallCount(page);
  const stages = [...setupResult.stages, ...firstThree.stages, ...fourth.stages];
  const baseOk =
    setupResult.ok &&
    firstThree.ok &&
    fourth.ok &&
    afterFirstThreeSigns === afterUnlock &&
    afterFourthSign === afterFirstThreeSigns + 1;
  const baseResult: BudgetEvidenceResult = {
    ok: baseOk,
    accountId: args.accountId,
    consoleMessages,
    stages,
    webauthnGetCounts: {
      before,
      afterUnlock,
      afterFirstThreeSigns,
      afterFourthSign,
    },
  };
  const evidenceValidation = validateSharedBudgetEvidenceResult(baseResult);
  const ok = baseOk && evidenceValidation.ok;

  return {
    ok,
    accountId: args.accountId,
    consoleMessages,
    stages,
    webauthnGetCounts: {
      before,
      afterUnlock,
      afterFirstThreeSigns,
      afterFourthSign,
    },
    ...(!ok
      ? {
          error: `Budget evidence failed: ${JSON.stringify({
            setupResult,
            firstThree,
            fourth,
            consoleMessages,
            before,
            afterUnlock,
            afterFirstThreeSigns,
            afterFourthSign,
            evidenceError: evidenceValidation.ok ? '' : evidenceValidation.error,
          })}`,
        }
      : {}),
  };
}

function findEvidenceStage(
  stages: BudgetEvidenceResult['stages'],
  label: string,
): BudgetEvidenceResult['stages'][number] | null {
  return stages.find((stage) => stage.label === label) || null;
}

function requireStageRemainingUses(
  stage: BudgetEvidenceResult['stages'][number] | null,
  label: string,
  expected: number,
): string | null {
  if (!stage) return `Missing evidence stage ${label}`;
  if (stage.remainingUses !== expected) {
    return `Expected ${label} remainingUses=${expected}, got ${String(stage.remainingUses)}`;
  }
  return null;
}

function validateSharedBudgetEvidenceResult(
  result: BudgetEvidenceResult,
): { ok: true } | { ok: false; error: string } {
  const setup = findEvidenceStage(result.stages, 'evm_bootstrapped');
  const near1 = findEvidenceStage(result.stages, 'near-1');
  const tempo1 = findEvidenceStage(result.stages, 'tempo-1');
  const evm1 = findEvidenceStage(result.stages, 'evm-1');
  const near2 = findEvidenceStage(result.stages, 'near-2');
  const failures = [
    requireStageRemainingUses(setup, 'evm_bootstrapped', 3),
    requireStageRemainingUses(near1, 'near-1', 2),
    requireStageRemainingUses(tempo1, 'tempo-1', 1),
    requireStageRemainingUses(evm1, 'evm-1', 0),
    requireStageRemainingUses(near2, 'near-2', 0),
  ].filter(Boolean);
  if (!evm1?.signingGrantId || !near2?.signingGrantId) {
    failures.push('Budget evidence is missing signingGrantId values');
  } else if (evm1.signingGrantId === near2.signingGrantId) {
    failures.push('Fourth sign did not mint a new signingGrantId after exhaustion');
  }
  if (failures.length) {
    return { ok: false, error: failures.join('; ') };
  }
  return { ok: true };
}

function runSharedBudgetSetup(
  page: Page,
  harness: SealedRefreshHarness,
  args: {
    accountId: string;
  },
): Promise<{ ok: boolean; stages: BudgetEvidenceResult['stages']; error?: string }> {
  return page.evaluate(
    async ({ accountId, keyVersion, relayerUrl, shamirPrimeB64u }) => {
      const stages: BudgetEvidenceResult['stages'] = [];
      const formatEvidenceError = (error: unknown, fallback: string): string => {
        if (error instanceof Error) return error.stack || error.message;
        if (error && typeof error === 'object' && 'message' in error) {
          return String((error as { message?: unknown }).message || fallback);
        }
        return String(error || fallback);
      };
      try {
        const sdkMod = await import('/sdk/esm/SeamsWeb/index.js');
        const { SeamsWeb } = sdkMod as any;
        const confirmationConfig = (): Record<string, unknown> => ({
          uiMode: 'none',
          behavior: 'skipClick',
          autoProceedDelay: 0,
        });
        const labelHex = (label: string): string => {
          const hex = Array.from(new TextEncoder().encode(label))
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('');
          return `0x${hex || '00'}`;
        };
        const sessionStage = async (
          seamsForStage: any,
          stageAccountId: string,
          label: string,
          chain?: string,
          kind?: string,
        ): Promise<BudgetEvidenceResult['stages'][number]> => {
          const session = await seamsForStage.auth.getWalletSession(stageAccountId).catch(() => null);
          const remainingUses = Number(session?.signingSession?.remainingUses);
          const ed25519Diagnostics = await readEd25519Diagnostics(stageAccountId).catch(
            (error: unknown) => ({
              ed25519State: 'diagnostic_error',
              ed25519Reason:
                error && typeof error === 'object' && 'message' in error
                  ? String((error as { message?: unknown }).message || '')
                  : String(error || 'diagnostic failed'),
            }),
          );
          return {
            label,
            ok: true,
            ...(chain ? { chain } : {}),
            ...(kind ? { kind } : {}),
            sessionStatus: String(session?.signingSession?.status || ''),
            remainingUses: Number.isFinite(remainingUses) ? Math.floor(remainingUses) : null,
            signingGrantId: String(
              (session?.signingSession as Record<string, unknown> | null | undefined)
                ?.signingGrantId || '',
            ),
            ...ed25519Diagnostics,
          };
        };
        const readEd25519Diagnostics = async (
          stageAccountId: string,
        ): Promise<Partial<BudgetEvidenceResult['stages'][number]>> => {
          const recordsMod = (await import(
            '/sdk/esm/core/signingEngine/session/persistence/records.js'
          )) as any;
          const stateMod = (await import(
            '/sdk/esm/core/signingEngine/session/routerAbSigningWalletSession.js'
          )) as any;
          const record = recordsMod.getStoredThresholdEd25519SessionRecordForAccount(
            stageAccountId,
          );
          const visibleRecords = recordsMod.listStoredThresholdEd25519SessionRecordsForAccount
            ? recordsMod.listStoredThresholdEd25519SessionRecordsForAccount(stageAccountId)
            : [];
          const state = stateMod.classifyRouterAbEd25519PersistedSigningRecord(record);
          return {
            thresholdSessionId: String(record?.thresholdSessionId || ''),
            signingGrantId: String(record?.signingGrantId || ''),
            ed25519State: String(state?.kind || ''),
            ed25519Reason: String(state?.reason || ''),
            hasMaterialHandle: Boolean(String(record?.ed25519HssMaterialHandle || '').trim()),
            hasMaterialBindingDigest: Boolean(
              String(record?.ed25519HssMaterialBindingDigest || '').trim(),
            ),
            hasClientVerifier: Boolean(String(record?.clientVerifyingShareB64u || '').trim()),
            ed25519VisibleRecordCount: Array.isArray(visibleRecords) ? visibleRecords.length : 0,
            ed25519VisibleRecordAccounts: Array.isArray(visibleRecords)
              ? visibleRecords.map((visibleRecord: Record<string, unknown>) =>
                  String(visibleRecord.nearAccountId || ''),
                )
              : [],
            ed25519VisibleRecordSessions: Array.isArray(visibleRecords)
              ? visibleRecords.map((visibleRecord: Record<string, unknown>) =>
                  String(visibleRecord.thresholdSessionId || ''),
                )
              : [],
          };
        };
        const bootstrapTempo = async (seamsForBootstrap: any): Promise<void> => {
          const bootstrap = await seamsForBootstrap.tempo.bootstrapEcdsaSession({
            kind: 'reuse_warm_ecdsa_bootstrap',
            walletSession: {
              walletId: accountId,
              walletSessionUserId: accountId,
            },
            chainTarget: {
              kind: 'tempo',
              chainId: 42431,
              networkSlug: 'tempo-moderato',
            },
            relayerUrl,
            ttlMs: 120_000,
            remainingUses: 3,
          });
          if (!bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
            throw new Error('Tempo ECDSA bootstrap did not return ecdsaThresholdKeyId');
          }
        };
        const bootstrapEvm = async (seamsForBootstrap: any): Promise<void> => {
          const bootstrap = await seamsForBootstrap.evm.bootstrapEcdsaSession({
            kind: 'reuse_warm_ecdsa_bootstrap',
            walletSession: {
              walletId: accountId,
              walletSessionUserId: accountId,
            },
            subjectId: accountId,
            chainTarget: {
              kind: 'evm',
              namespace: 'eip155',
              chainId: 11155111,
              networkSlug: 'ethereum-sepolia',
            },
            relayerUrl,
            ttlMs: 120_000,
            remainingUses: 3,
          });
          if (!bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
            throw new Error('EVM ECDSA bootstrap did not return ecdsaThresholdKeyId');
          }
        };
        const signNear = async (seamsForSign: any, label: string): Promise<void> => {
          const signed = await seamsForSign.near.executeAction({
            nearAccount: { accountId },
            receiverId: 'w3a-v1.testnet',
            actionArgs: {
              type: 'FunctionCall',
              methodName: 'set_greeting',
              args: { greeting: `budget-evidence-${label}-${Date.now()}` },
              gas: '30000000000000',
              deposit: '0',
            },
            options: {
              waitUntil: 'EXECUTED_OPTIMISTIC',
              confirmationConfig: confirmationConfig(),
            },
          });
          if (!signed?.success) throw new Error(String(signed?.error || 'NEAR sign failed'));
        };
        const signTempo = async (seamsForSign: any, label: string): Promise<void> => {
          const signed = await seamsForSign.tempo.signTempo({
            walletSession: {
              walletId: accountId,
              walletSessionUserId: accountId,
            },
            chainTarget: {
              kind: 'tempo',
              chainId: 42431,
              networkSlug: 'tempo-moderato',
            },
            request: {
              chain: 'tempo',
              kind: 'tempoTransaction',
              senderSignatureAlgorithm: 'secp256k1',
              tx: {
                chainId: 42431,
                maxPriorityFeePerGas: 1n,
                maxFeePerGas: 2n,
                gasLimit: 21_000n,
                calls: [{ to: `0x${'11'.repeat(20)}`, value: 0n, input: labelHex(label) }],
                accessList: [],
                nonceKey: 0n,
                validBefore: null,
                validAfter: null,
                feePayerSignature: { kind: 'none' },
                aaAuthorizationList: [],
              },
            },
            options: { confirmationConfig: confirmationConfig() },
          });
          if (!signed || signed.kind !== 'tempoTransaction') {
            throw new Error('Tempo sign failed');
          }
        };
        const signEvm = async (seamsForSign: any, label: string): Promise<void> => {
          const signed = await seamsForSign.tempo.signTempo({
            walletSession: {
              walletId: accountId,
              walletSessionUserId: accountId,
            },
            chainTarget: {
              kind: 'evm',
              namespace: 'eip155',
              chainId: 11155111,
              networkSlug: 'ethereum-sepolia',
            },
            request: {
              chain: 'evm',
              kind: 'eip1559',
              senderSignatureAlgorithm: 'secp256k1',
              tx: {
                chainId: 11155111,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: `0x${'22'.repeat(20)}`,
                value: 0n,
                data: labelHex(label),
                accessList: [],
              },
            },
            options: { confirmationConfig: confirmationConfig() },
          });
          if (!signed || signed.kind !== 'eip1559' || signed.chain !== 'evm') {
            throw new Error('EVM sign failed');
          }
        };
        const seams = new SeamsWeb({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayerAccount: 'web3-authn-v4.testnet',
          relayer: { url: relayerUrl },
          registration: {
            mode: 'managed',
            environmentId: String(
              (globalThis as any).__w3aManagedRegistration?.environmentId || '',
            ),
            publishableKey: String(
              (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
            ),
          },
          signingSessionDefaults: {
            ttlMs: 120_000,
            remainingUses: 3,
          },
          routerAb: {
            normalSigning: {
              mode: 'enabled',
              signingWorkerId: 'local-signing-worker',
            },
          },
          signingSessionPersistenceMode: 'sealed_refresh_v1',
          signingSessionSeal: {
            keyVersion,
            shamirPrimeB64u,
          },
          iframeWallet: {
            walletOrigin: 'https://wallet.example.localhost',
            servicePath: '/wallet-service',
            sdkBasePath: '/sdk',
            rpIdOverride: 'example.localhost',
          },
        });
        seams.preferences.setConfirmationConfig(confirmationConfig());
        (globalThis as any).__routerAbBudgetEvidence = {
          sign: async (labels: string[]): Promise<{ ok: boolean; stages: BudgetEvidenceResult['stages']; error?: string }> => {
            const signStages: BudgetEvidenceResult['stages'] = [];
            try {
              for (const label of labels) {
                if (label.startsWith('near')) {
                  await signNear(seams, label);
                  signStages.push(await sessionStage(seams, accountId, label, 'near', 'nearAction'));
                  continue;
                }
                if (label.startsWith('tempo')) {
                  await signTempo(seams, label);
                  signStages.push(
                    await sessionStage(seams, accountId, label, 'tempo', 'tempoTransaction'),
                  );
                  continue;
                }
                if (label.startsWith('evm')) {
                  await signEvm(seams, label);
                  signStages.push(await sessionStage(seams, accountId, label, 'evm', 'eip1559'));
                  continue;
                }
                throw new Error(`unknown evidence sign label: ${label}`);
              }
              return { ok: true, stages: signStages };
            } catch (error: unknown) {
              signStages.push(
                await sessionStage(seams, accountId, 'sign_failure_diagnostic').catch(
                  (diagnosticError: unknown) => ({
                    label: 'sign_failure_diagnostic',
                    ok: false,
                    error:
                      diagnosticError &&
                      typeof diagnosticError === 'object' &&
                      'message' in diagnosticError
                        ? String((diagnosticError as { message?: unknown }).message || '')
                        : String(diagnosticError || 'diagnostic failed'),
                  }),
                ),
              );
              return {
                ok: false,
                stages: signStages,
                error: formatEvidenceError(error, 'budget evidence sign failed'),
              };
            }
          },
        };

        const registration = await seams.registration.registerPasskey(accountId, {
          confirmationConfig: confirmationConfig(),
        });
        if (!registration?.success) {
          throw new Error(String(registration?.error || 'registration failed'));
        }
        stages.push(await sessionStage(seams, accountId, 'registered'));

        const login = await seams.auth.unlock(accountId, {
          unlockSelection: { mode: 'ed25519_only', ed25519: true },
          session: {
            kind: 'jwt',
            relayUrl: relayerUrl,
            exchange: { type: 'passkey_assertion' },
          },
          signingSession: { ttlMs: 120_000, remainingUses: 3 },
        });
        if (!login?.success) {
          throw new Error(String(login?.error || 'unlock failed'));
        }
        stages.push(await sessionStage(seams, accountId, 'unlocked'));

        await bootstrapTempo(seams);
        stages.push(await sessionStage(seams, accountId, 'tempo_bootstrapped'));
        await bootstrapEvm(seams);
        stages.push(await sessionStage(seams, accountId, 'evm_bootstrapped'));

        return { ok: true, stages };
      } catch (error: unknown) {
        return {
          ok: false,
          stages,
          error: formatEvidenceError(error, 'budget evidence setup failed'),
        };
      }
    },
    {
      accountId: args.accountId,
      keyVersion: TEST_KEY_VERSION,
      relayerUrl: harness.relayerUrl,
      shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
    },
  );
}

function runEvidenceSigns(
  page: Page,
  args: {
    accountId: string;
    labels: string[];
  },
): Promise<{ ok: boolean; stages: BudgetEvidenceResult['stages']; error?: string }> {
  return page.evaluate(async ({ accountId, labels }) => {
    const harness = (globalThis as any).__routerAbBudgetEvidence;
    if (!harness || typeof harness.sign !== 'function') {
      return {
        ok: false,
        stages: [],
        error: `missing budget evidence SeamsWeb instance for ${accountId}`,
      };
    }
    return await harness.sign(labels);
  }, args);
}
