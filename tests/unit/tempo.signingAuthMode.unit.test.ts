import { expect, test, type Page } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  tempoSigningApi: '/sdk/esm/core/signingEngine/api/tempoSigning.js',
  thresholdSessionStore:
    '/sdk/esm/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.js',
  walletSigningBudgetLedger: '/sdk/esm/core/signingEngine/session/WalletSigningBudgetLedger.js',
  signEvmWithTouchConfirm: '/sdk/esm/core/signingEngine/orchestration/evm/evmSigningFlow.js',
  signTempoWithTouchConfirm: '/sdk/esm/core/signingEngine/orchestration/tempo/tempoSigningFlow.js',
  evmFamilyAuthPlanning: '/sdk/esm/core/signingEngine/api/evmFamily/authPlanning.js',
  evmFamilyBudgetSpending: '/sdk/esm/core/signingEngine/api/evmFamily/budgetSpending.js',
} as const;

async function routeEvmFamilySigningFlowStubs(page: Page): Promise<void> {
  const evmFlowStub = `
    export async function signEvmWithTouchConfirm(args) {
      globalThis.__tatchiStubConfirmationDisplayedCalls =
        (globalThis.__tatchiStubConfirmationDisplayedCalls || 0) + 1;
      args.onConfirmationDisplayed?.();
      const emailOtpChallenge = args.emailOtpSigning
        ? await args.emailOtpSigning.prepare()
        : undefined;
      const confirmation = await args.touchConfirm.orchestrateSigningConfirmation({
        signingAuthPlan: args.signingAuthPlan,
        emailOtpPrompt: emailOtpChallenge
          ? {
              challengeId: emailOtpChallenge.challengeId,
              emailHint: emailOtpChallenge.emailHint,
              onResend: args.emailOtpSigning.resend,
            }
          : undefined,
      });
      let keyRef = args.keyRefsByAlgorithm?.secp256k1;
      if (args.emailOtpSigning) {
        keyRef = await args.emailOtpSigning.complete(
          String(confirmation?.otpCode || '123456'),
          confirmation?.emailOtpChallengeId,
        );
      }
      globalThis.__tatchiStubSignedKeyRefs = globalThis.__tatchiStubSignedKeyRefs || [];
      globalThis.__tatchiStubSignedKeyRefs.push({
        chain: 'evm',
        thresholdSessionId: String(keyRef?.thresholdSessionId || ''),
        walletSigningSessionId: String(keyRef?.walletSigningSessionId || ''),
      });
      return {
        chain: 'evm',
        kind: args.request?.kind || 'eip1559',
        signedTxHex: '0x02aa',
        txHashHex: '0x' + '11'.repeat(32),
      };
    }
  `;
  const tempoFlowStub = `
    export async function signTempoWithTouchConfirm(args) {
      globalThis.__tatchiStubConfirmationDisplayedCalls =
        (globalThis.__tatchiStubConfirmationDisplayedCalls || 0) + 1;
      args.onConfirmationDisplayed?.();
      const emailOtpChallenge = args.emailOtpSigning
        ? await args.emailOtpSigning.prepare()
        : undefined;
      const confirmation = await args.touchConfirm.orchestrateSigningConfirmation({
        signingAuthPlan: args.signingAuthPlan,
        emailOtpPrompt: emailOtpChallenge
          ? {
              challengeId: emailOtpChallenge.challengeId,
              emailHint: emailOtpChallenge.emailHint,
              onResend: args.emailOtpSigning.resend,
            }
          : undefined,
      });
      let keyRef = args.keyRefsByAlgorithm?.secp256k1;
      if (args.emailOtpSigning) {
        keyRef = await args.emailOtpSigning.complete(
          String(confirmation?.otpCode || '123456'),
          confirmation?.emailOtpChallengeId,
        );
      }
      globalThis.__tatchiStubSignedKeyRefs = globalThis.__tatchiStubSignedKeyRefs || [];
      globalThis.__tatchiStubSignedKeyRefs.push({
        chain: 'tempo',
        thresholdSessionId: String(keyRef?.thresholdSessionId || ''),
        walletSigningSessionId: String(keyRef?.walletSigningSessionId || ''),
      });
      return {
        chain: 'tempo',
        kind: args.request?.kind || 'tempoTransaction',
        signedTxBytes: new Uint8Array([0x76, 0xaa]),
      };
    }
  `;
  const signerStub = `
    export class Secp256k1Engine {
      constructor(opts) {
        this.opts = opts || {};
        this.algorithm = 'secp256k1';
      }
      async sign() {
        const sig = new Uint8Array(65);
        sig[64] = 0;
        return sig;
      }
    }
  `;
  const webauthnStub = `
    export class WebAuthnP256Engine {
      constructor() {
        this.algorithm = 'webauthnP256';
      }
      async sign() {
        return new Uint8Array(64);
      }
    }
  `;
  await page.route('**/core/signingEngine/orchestration/evm/evmSigningFlow.js*', (route) =>
    route.fulfill({ contentType: 'application/javascript', body: evmFlowStub }),
  );
  await page.route('**/core/signingEngine/orchestration/tempo/tempoSigningFlow.js*', (route) =>
    route.fulfill({ contentType: 'application/javascript', body: tempoFlowStub }),
  );
  await page.route('**/core/signingEngine/signers/algorithms/secp256k1.js*', (route) =>
    route.fulfill({ contentType: 'application/javascript', body: signerStub }),
  );
  await page.route('**/core/signingEngine/signers/algorithms/webauthnP256.js*', (route) =>
    route.fulfill({ contentType: 'application/javascript', body: webauthnStub }),
  );
}

test.describe('tempo signing auth-mode resolution', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('EVM-family auth planning does not execute Email OTP side effects before confirmation', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { resolveEvmFamilyTransactionWalletAuth } = await import(paths.evmFamilyAuthPlanning);
        let challengeCalls = 0;
        let completeCalls = 0;
        let preConfirmSideEffectCalls = 0;
        const failPreConfirmSideEffect = () => {
          preConfirmSideEffectCalls += 1;
          throw new Error('pre-confirm deps must not expose or execute auth side effects');
        };

        const plan = await resolveEvmFamilyTransactionWalletAuth({
          deps: {
            touchConfirm: {
              getWarmSessionStatus: async () => {
                throw new Error(
                  'pre-confirm readiness should not need warm status for missing lane record',
                );
              },
            },
            requestEmailOtpTransactionSigningChallenge: failPreConfirmSideEffect,
            loginWithEmailOtpEcdsaCapabilityForSigning: failPreConfirmSideEffect,
            provisionThresholdEcdsaSession: failPreConfirmSideEffect,
            rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord: failPreConfirmSideEffect,
          } as any,
          confirmedDeps: {
            requestEmailOtpTransactionSigningChallenge: async () => {
              challengeCalls += 1;
              return { challengeId: 'otp-challenge-1', emailHint: 'o***p@example.com' };
            },
            loginWithEmailOtpEcdsaCapabilityForSigning: async () => {
              completeCalls += 1;
              throw new Error('OTP completion should not run during planning or challenge prepare');
            },
          },
          nearAccountId: 'otp-planning-boundary.testnet',
          chain: 'tempo',
          accountAuth: {
            primaryAuthMethod: 'email_otp',
            linkedAuthMethods: ['email_otp'],
          },
          senderSignatureAlgorithm: 'secp256k1',
          ecdsaAuthMethod: 'email_otp',
          ecdsaSigningLane: {
            operationId: 'op-otp-planning-boundary',
            accountId: 'otp-planning-boundary.testnet',
            authMethod: 'email_otp',
            curve: 'ecdsa',
            keyKind: 'threshold_ecdsa_secp256k1',
            chainFamily: 'tempo',
            walletSigningSessionId: 'wallet-otp-planning-boundary',
            thresholdSessionId: 'threshold-otp-planning-boundary',
            sessionOrigin: 'per_operation',
            storageSource: 'email_otp',
            retention: 'single_use',
          },
        });

        const afterPlanning = { challengeCalls, completeCalls };
        const prepared = await plan.emailOtpSigning?.prepare();

        return {
          signingAuthPlanKind: plan.signingAuthPlan.kind,
          signingSessionPlanKind: plan.signingSessionPlan?.kind || '',
          afterPlanning,
          afterPrepare: { challengeCalls, completeCalls },
          preConfirmSideEffectCalls,
          preparedChallengeId: prepared?.challengeId || '',
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.signingAuthPlanKind).toBe('emailOtpReauth');
    expect(result.signingSessionPlanKind).toBe('email_otp_reauth');
    expect(result.afterPlanning).toEqual({ challengeCalls: 0, completeCalls: 0 });
    expect(result.afterPrepare).toEqual({ challengeCalls: 1, completeCalls: 0 });
    expect(result.preConfirmSideEffectCalls).toBe(0);
    expect(result.preparedChallengeId).toBe('otp-challenge-1');
  });

  test('EVM-family auth planning treats in-flight wallet budget reservations as spent', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { resolveEvmFamilyTransactionWalletAuth } = await import(paths.evmFamilyAuthPlanning);
        const expiresAtMs = Date.now() + 60_000;

        const plan = await resolveEvmFamilyTransactionWalletAuth({
          deps: {
            touchConfirm: {
              getWarmSessionStatus: async () => {
                throw new Error('passkey ECDSA readiness should use the wallet budget ledger');
              },
            },
            walletSigningBudgetLedger: {
              getAvailableStatus: async () => ({
                sessionId: 'wallet-budget-inflight',
                status: 'active',
                remainingUses: 0,
                expiresAtMs,
              }),
            },
          } as any,
          confirmedDeps: {},
          nearAccountId: 'budget-planning.testnet',
          chain: 'tempo',
          accountAuth: {
            primaryAuthMethod: 'passkey',
            linkedAuthMethods: ['passkey'],
          },
          senderSignatureAlgorithm: 'secp256k1',
          ecdsaAuthMethod: 'passkey',
          ecdsaSigningLane: {
            accountId: 'budget-planning.testnet',
            authMethod: 'passkey',
            curve: 'ecdsa',
            keyKind: 'threshold_ecdsa_secp256k1',
            chainFamily: 'tempo',
            walletSigningSessionId: 'wallet-budget-inflight',
            thresholdSessionId: 'threshold-budget-inflight',
            sessionOrigin: 'login',
            storageSource: 'login',
            retention: 'session',
            signingRootId: 'proj_budget:dev',
            signingRootVersion: 'default',
          },
          ecdsaWarmRecord: {
            source: 'login',
            thresholdSessionId: 'threshold-budget-inflight',
            walletSigningSessionId: 'wallet-budget-inflight',
            expiresAtMs,
            remainingUses: 2,
          },
        });

        return {
          signingAuthPlanKind: plan.signingAuthPlan.kind,
          signingSessionPlanKind: plan.signingSessionPlan?.kind || '',
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.signingAuthPlanKind).toBe('passkeyReauth');
    expect(result.signingSessionPlanKind).toBe('passkey_reauth');
  });

  test('does not fail before confirmer when threshold warm session cache is unavailable (EVM)', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
        let confirmCalls = 0;
        let capturedAuthMode: string | null = null;
        let capturedAuthPlanKind: string | null = null;
        const events: any[] = [];
        const authSideEffects: string[] = [];

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
            if (type === 'encodeEip1559SignedTxFromSignature65')
              return new Uint8Array([0x02, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        try {
          await signEvmWithTouchConfirm({
            ctx: { indexedDB: {} } as any,
            workerCtx: workerCtx as any,
            touchConfirm: {
              getWarmSessionStatus: async () => ({
                ok: false,
                code: 'expired',
                message: 'expired',
              }),
              orchestrateSigningConfirmation: async (params: any) => {
                confirmCalls += 1;
                capturedAuthMode = String(params?.signingAuthMode || '');
                capturedAuthPlanKind = String(params?.signingAuthPlan?.kind || '');
                params?.onProgress?.({
                  phase: 'auth.passkey.prompt.started',
                  status: 'running',
                });
                params?.onProgress?.({
                  phase: 'auth.passkey.prompt.succeeded',
                  status: 'succeeded',
                });
                return {
                  sessionId: 'intent',
                  intentDigest: '0x' + '11'.repeat(32),
                };
              },
            } as any,
            nearAccountId: 'alice.testnet',
            request: {
              chain: 'evm',
              kind: 'eip1559',
              senderSignatureAlgorithm: 'secp256k1',
              tx: {
                chainId: 11155111,
                nonce: 7n,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: '0x' + '22'.repeat(20),
                value: 12_345n,
                data: '0x',
                accessList: [],
              },
            } as any,
            engines: {
              secp256k1: {
                algorithm: 'secp256k1',
                sign: async () => {
                  const sig = new Uint8Array(65);
                  sig[64] = 0;
                  return sig;
                },
              },
            } as any,
            keyRefsByAlgorithm: {
              secp256k1: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relayer.example',
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
                thresholdSessionId: 'session-1',
              },
            } as any,
            onEvent: (event: any) => events.push(event),
            onAuthSideEffectStarted: (sideEffect: string) => authSideEffects.push(sideEffect),
          });
          return {
            ok: true,
            confirmCalls,
            capturedAuthMode,
            capturedAuthPlanKind,
            authSideEffects,
            eventPhases: events.map((event) => event.phase),
            passkeyInteractions: events
              .filter((event) => String(event.phase || '').includes('passkey.prompt'))
              .map((event) => event.interaction),
          };
        } catch (error: any) {
          return {
            ok: false,
            confirmCalls,
            capturedAuthMode,
            capturedAuthPlanKind,
            authSideEffects,
            message: String(error?.message || error),
          };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(true);
    expect(result.confirmCalls).toBe(1);
    expect(result.capturedAuthMode).toBe('');
    expect(result.capturedAuthPlanKind).toBe('passkeyReauth');
    expect(result.authSideEffects).toEqual(['passkey_reauth']);
    expect(result.eventPhases).toEqual([
      'signing.confirmation.displayed',
      'signing.auth.passkey.prompt.started',
      'signing.auth.passkey.prompt.succeeded',
      'signing.confirmation.approved',
      'signing.commit.started',
      'signing.transaction.signed',
      'signing.completed',
    ]);
    expect(result.passkeyInteractions).toEqual([
      { kind: 'passkey_assert', overlay: 'show' },
      { kind: 'passkey_assert', overlay: 'hide' },
    ]);
  });

  test('uses Email OTP prompt and refreshed keyRef for EVM per-operation signing', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
        let capturedAuthMode = '';
        let capturedAuthPlanKind = '';
        let capturedChallengeId = '';
        let capturedPlanChallengeId = '';
        let completedOtpCode = '';
        let signedWithSessionId = '';
        const events: any[] = [];

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
            if (type === 'encodeEip1559SignedTxFromSignature65')
              return new Uint8Array([0x02, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        const signed = await signEvmWithTouchConfirm({
          ctx: { indexedDB: {} } as any,
          workerCtx: workerCtx as any,
          touchConfirm: {
            getWarmSessionStatus: async () => {
              throw new Error('warm-session status should not be read for emailOtp mode');
            },
            orchestrateSigningConfirmation: async (params: any) => {
              capturedAuthMode = String(params?.signingAuthMode || '');
              capturedAuthPlanKind = String(params?.signingAuthPlan?.kind || '');
              capturedChallengeId = String(params?.emailOtpPrompt?.challengeId || '');
              capturedPlanChallengeId = String(
                params?.signingAuthPlan?.emailOtpPrompt?.challengeId || '',
              );
              params?.onProgress?.({
                phase: 'confirmation.complete',
                status: 'succeeded',
              });
              return {
                sessionId: 'intent',
                intentDigest: '0x' + '11'.repeat(32),
                otpCode: '654321',
              };
            },
          } as any,
          nearAccountId: 'alice.testnet',
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              nonce: 7n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 21_000n,
              to: '0x' + '22'.repeat(20),
              value: 12_345n,
              data: '0x',
              accessList: [],
            },
          } as any,
          emailOtpSigning: {
            prepare: async () => ({
              challengeId: 'evm-email-otp-challenge',
              emailHint: 'a***e@example.com',
            }),
            complete: async (otpCode: string) => {
              completedOtpCode = otpCode;
              return {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relayer.example',
                relayerKeyId: 'rk-email-otp',
                clientVerifyingShareB64u: 'AQ',
                thresholdSessionId: 'email-otp-refreshed-session',
              } as any;
            },
          },
          ensureThresholdEcdsaKeyRefReady: async () => {
            throw new Error('stale per-operation Email OTP session should not be reconnected');
          },
          engines: {
            secp256k1: {
              algorithm: 'secp256k1',
              sign: async (_signReq: unknown, keyRef: any) => {
                signedWithSessionId = String(keyRef?.thresholdSessionId || '');
                const sig = new Uint8Array(65);
                sig[64] = 0;
                return sig;
              },
            },
          } as any,
          onEvent: (event: any) => events.push(event),
        });

        return {
          capturedAuthMode,
          capturedAuthPlanKind,
          capturedChallengeId,
          capturedPlanChallengeId,
          completedOtpCode,
          signedWithSessionId,
          chain: signed.chain,
          kind: signed.kind,
          eventPhases: events.map((event) => event.phase),
          emailOtpInteractions: events
            .filter((event) => String(event.phase || '').includes('email_otp'))
            .map((event) => event.interaction),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.capturedAuthMode).toBe('');
    expect(result.capturedAuthPlanKind).toBe('emailOtpReauth');
    expect(result.capturedChallengeId).toBe('evm-email-otp-challenge');
    expect(result.capturedPlanChallengeId).toBe('evm-email-otp-challenge');
    expect(result.completedOtpCode).toBe('654321');
    expect(result.signedWithSessionId).toBe('email-otp-refreshed-session');
    expect(result.chain).toBe('evm');
    expect(result.kind).toBe('eip1559');
    expect(result.eventPhases).toEqual([
      'signing.confirmation.displayed',
      'signing.auth.email_otp.verify.succeeded',
      'signing.confirmation.approved',
      'signing.commit.started',
      'signing.transaction.signed',
      'signing.completed',
    ]);
    expect(result.emailOtpInteractions).toEqual([{ kind: 'otp_input', overlay: 'hide' }]);
  });

  test('EVM per-operation Email OTP resend uses the resent challenge for completion', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
        let capturedInitialChallengeId = '';
        let capturedResentChallengeId = '';
        let completedOtpCode = '';
        let completedChallengeId = '';
        let signedWithSessionId = '';

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
            if (type === 'encodeEip1559SignedTxFromSignature65')
              return new Uint8Array([0x02, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        const signed = await signEvmWithTouchConfirm({
          ctx: { indexedDB: {} } as any,
          workerCtx: workerCtx as any,
          touchConfirm: {
            getWarmSessionStatus: async () => {
              throw new Error('warm-session status should not be read for emailOtp mode');
            },
            orchestrateSigningConfirmation: async (params: any) => {
              capturedInitialChallengeId = String(params?.emailOtpPrompt?.challengeId || '');
              const resent = await params.emailOtpPrompt.onResend();
              capturedResentChallengeId = String(resent?.challengeId || '');
              return {
                sessionId: 'intent',
                intentDigest: '0x' + '11'.repeat(32),
                otpCode: '246810',
                emailOtpChallengeId: capturedResentChallengeId,
              };
            },
          } as any,
          nearAccountId: 'alice.testnet',
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              nonce: 7n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 21_000n,
              to: '0x' + '22'.repeat(20),
              value: 12_345n,
              data: '0x',
              accessList: [],
            },
          } as any,
          emailOtpSigning: {
            prepare: async () => ({
              challengeId: 'evm-email-otp-challenge-1',
              emailHint: 'a***e@example.com',
            }),
            resend: async () => ({
              challengeId: 'evm-email-otp-challenge-2',
              emailHint: 'a***e@example.com',
            }),
            complete: async (otpCode: string, challengeId?: string) => {
              completedOtpCode = otpCode;
              completedChallengeId = String(challengeId || '');
              return {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relayer.example',
                relayerKeyId: 'rk-email-otp',
                clientVerifyingShareB64u: 'AQ',
                thresholdSessionId: 'email-otp-resent-session',
              } as any;
            },
          },
          ensureThresholdEcdsaKeyRefReady: async () => {
            throw new Error('stale per-operation Email OTP session should not be reconnected');
          },
          engines: {
            secp256k1: {
              algorithm: 'secp256k1',
              sign: async (_signReq: unknown, keyRef: any) => {
                signedWithSessionId = String(keyRef?.thresholdSessionId || '');
                const sig = new Uint8Array(65);
                sig[64] = 0;
                return sig;
              },
            },
          } as any,
        });

        return {
          capturedInitialChallengeId,
          capturedResentChallengeId,
          completedOtpCode,
          completedChallengeId,
          signedWithSessionId,
          chain: signed.chain,
          kind: signed.kind,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.capturedInitialChallengeId).toBe('evm-email-otp-challenge-1');
    expect(result.capturedResentChallengeId).toBe('evm-email-otp-challenge-2');
    expect(result.completedOtpCode).toBe('246810');
    expect(result.completedChallengeId).toBe('evm-email-otp-challenge-2');
    expect(result.signedWithSessionId).toBe('email-otp-resent-session');
    expect(result.chain).toBe('evm');
    expect(result.kind).toBe('eip1559');
  });

  test('abandons EVM Email OTP challenge on cancellation without completing or signing', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
        let completeCalls = 0;
        let signCalls = 0;

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
            if (type === 'encodeEip1559SignedTxFromSignature65')
              return new Uint8Array([0x02, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        try {
          await signEvmWithTouchConfirm({
            ctx: { indexedDB: {} } as any,
            workerCtx: workerCtx as any,
            touchConfirm: {
              getWarmSessionStatus: async () => {
                throw new Error('warm-session status should not be read for emailOtp mode');
              },
              orchestrateSigningConfirmation: async () => {
                throw new Error('User rejected signing request');
              },
            } as any,
            nearAccountId: 'alice.testnet',
            request: {
              chain: 'evm',
              kind: 'eip1559',
              senderSignatureAlgorithm: 'secp256k1',
              tx: {
                chainId: 11155111,
                nonce: 7n,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: '0x' + '22'.repeat(20),
                value: 12_345n,
                data: '0x',
                accessList: [],
              },
            } as any,
            emailOtpSigning: {
              prepare: async () => ({
                challengeId: 'evm-email-otp-challenge',
              }),
              complete: async () => {
                completeCalls += 1;
                throw new Error('complete should not be called after cancellation');
              },
            },
            engines: {
              secp256k1: {
                algorithm: 'secp256k1',
                sign: async () => {
                  signCalls += 1;
                  const sig = new Uint8Array(65);
                  sig[64] = 0;
                  return sig;
                },
              },
            } as any,
          });
          return { ok: true, completeCalls, signCalls, error: '' };
        } catch (error) {
          return {
            ok: false,
            completeCalls,
            signCalls,
            error: error instanceof Error ? error.message : String(error),
          };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(false);
    expect(result.error).toContain('User rejected signing request');
    expect(result.completeCalls).toBe(0);
    expect(result.signCalls).toBe(0);
  });

  test('does not sign after invalid or expired EVM Email OTP completion failure', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
        let completeCalls = 0;
        let signCalls = 0;

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
            if (type === 'encodeEip1559SignedTxFromSignature65')
              return new Uint8Array([0x02, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        try {
          await signEvmWithTouchConfirm({
            ctx: { indexedDB: {} } as any,
            workerCtx: workerCtx as any,
            touchConfirm: {
              getWarmSessionStatus: async () => {
                throw new Error('warm-session status should not be read for emailOtp mode');
              },
              orchestrateSigningConfirmation: async () => ({
                sessionId: 'intent',
                intentDigest: '0x' + '11'.repeat(32),
                otpCode: '000000',
              }),
            } as any,
            nearAccountId: 'alice.testnet',
            request: {
              chain: 'evm',
              kind: 'eip1559',
              senderSignatureAlgorithm: 'secp256k1',
              tx: {
                chainId: 11155111,
                nonce: 7n,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: '0x' + '22'.repeat(20),
                value: 12_345n,
                data: '0x',
                accessList: [],
              },
            } as any,
            emailOtpSigning: {
              prepare: async () => ({
                challengeId: 'evm-email-otp-challenge',
              }),
              complete: async () => {
                completeCalls += 1;
                throw new Error('Email OTP challenge expired or invalid');
              },
            },
            engines: {
              secp256k1: {
                algorithm: 'secp256k1',
                sign: async () => {
                  signCalls += 1;
                  const sig = new Uint8Array(65);
                  sig[64] = 0;
                  return sig;
                },
              },
            } as any,
          });
          return { ok: true, completeCalls, signCalls, error: '' };
        } catch (error) {
          return {
            ok: false,
            completeCalls,
            signCalls,
            error: error instanceof Error ? error.message : String(error),
          };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(false);
    expect(result.error).toContain('Email OTP challenge expired or invalid');
    expect(result.completeCalls).toBe(1);
    expect(result.signCalls).toBe(0);
  });

  test('retries EVM Email OTP signing with a fresh challenge after expiry', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
        const capturedChallengeIds: string[] = [];
        const completedOtpCodes: string[] = [];
        let signCalls = 0;

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
            if (type === 'encodeEip1559SignedTxFromSignature65')
              return new Uint8Array([0x02, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };
        const request = {
          chain: 'evm',
          kind: 'eip1559',
          senderSignatureAlgorithm: 'secp256k1',
          tx: {
            chainId: 11155111,
            nonce: 7n,
            maxPriorityFeePerGas: 1_500_000_000n,
            maxFeePerGas: 3_000_000_000n,
            gasLimit: 21_000n,
            to: '0x' + '22'.repeat(20),
            value: 12_345n,
            data: '0x',
            accessList: [],
          },
        } as any;

        const attempt = async (challengeId: string, shouldExpire: boolean) =>
          await signEvmWithTouchConfirm({
            ctx: { indexedDB: {} } as any,
            workerCtx: workerCtx as any,
            touchConfirm: {
              getWarmSessionStatus: async () => {
                throw new Error('warm-session status should not be read for emailOtp mode');
              },
              orchestrateSigningConfirmation: async (params: any) => {
                capturedChallengeIds.push(String(params?.emailOtpPrompt?.challengeId || ''));
                return {
                  sessionId: 'intent',
                  intentDigest: '0x' + '11'.repeat(32),
                  otpCode: shouldExpire ? '000000' : '654321',
                };
              },
            } as any,
            nearAccountId: 'alice.testnet',
            request,
            emailOtpSigning: {
              prepare: async () => ({
                challengeId,
              }),
              complete: async (otpCode: string) => {
                completedOtpCodes.push(otpCode);
                if (shouldExpire) {
                  throw new Error('Email OTP challenge expired or invalid');
                }
                return {
                  type: 'threshold-ecdsa-secp256k1',
                  userId: 'alice.testnet',
                  relayerUrl: 'https://relayer.example',
                  relayerKeyId: 'rk-email-otp',
                  clientVerifyingShareB64u: 'AQ',
                  thresholdSessionId: 'email-otp-refreshed-session',
                } as any;
              },
            },
            engines: {
              secp256k1: {
                algorithm: 'secp256k1',
                sign: async (_signReq: unknown, keyRef: any) => {
                  signCalls += 1;
                  if (String(keyRef?.thresholdSessionId || '') !== 'email-otp-refreshed-session') {
                    throw new Error('signer did not receive refreshed Email OTP keyRef');
                  }
                  const sig = new Uint8Array(65);
                  sig[64] = 0;
                  return sig;
                },
              },
            } as any,
          });

        let firstError = '';
        try {
          await attempt('expired-challenge', true);
        } catch (error) {
          firstError = error instanceof Error ? error.message : String(error);
        }
        const signed = await attempt('fresh-challenge', false);

        return {
          firstError,
          capturedChallengeIds,
          completedOtpCodes,
          signCalls,
          chain: signed.chain,
          kind: signed.kind,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.firstError).toContain('Email OTP challenge expired or invalid');
    expect(result.capturedChallengeIds).toEqual(['expired-challenge', 'fresh-challenge']);
    expect(result.completedOtpCodes).toEqual(['000000', '654321']);
    expect(result.signCalls).toBe(1);
    expect(result.chain).toBe('evm');
    expect(result.kind).toBe('eip1559');
  });

  test('uses warmSession mode when threshold warm-session material is available', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
        let capturedAuthMode: string | null = null;
        let capturedAuthPlanKind: string | null = null;
        const ordering: string[] = [];

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
            if (type === 'encodeEip1559SignedTxFromSignature65')
              return new Uint8Array([0x02, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        const signed = await signEvmWithTouchConfirm({
          ctx: { indexedDB: {} } as any,
          workerCtx: workerCtx as any,
          touchConfirm: {
            getWarmSessionStatus: async () => ({
              ok: true,
              remainingUses: 2,
              expiresAtMs: Date.now() + 10_000,
            }),
            orchestrateSigningConfirmation: async (params: any) => {
              ordering.push('confirm');
              capturedAuthMode = String(params?.signingAuthMode || '');
              capturedAuthPlanKind = String(params?.signingAuthPlan?.kind || '');
              return {
                sessionId: 'intent',
                intentDigest: String(params?.intentDigest || ''),
              };
            },
          } as any,
          nearAccountId: 'alice.testnet',
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              nonce: 7n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 21_000n,
              to: '0x' + '22'.repeat(20),
              value: 12_345n,
              data: '0x',
              accessList: [],
            },
          } as any,
          engines: {
            secp256k1: {
              algorithm: 'secp256k1',
              sign: async () => {
                const sig = new Uint8Array(65);
                sig[64] = 0;
                return sig;
              },
            },
          } as any,
          keyRefsByAlgorithm: {
            secp256k1: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relayer.example',
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              thresholdSessionId: 'session-1',
            },
          } as any,
          signingAuthPlan: {
            kind: 'warmSession',
            method: 'passkey',
            accountId: 'alice.testnet',
            intent: 'transaction_sign',
            curve: 'ecdsa',
            sessionId: 'session-1',
            expiresAtMs: Date.now() + 10_000,
            remainingUses: 2,
          },
          reserveWalletSigningSessionBudget: async () => {
            ordering.push('reserve');
            return null;
          },
        });

        return {
          capturedAuthMode,
          capturedAuthPlanKind,
          ordering,
          kind: signed.kind,
          chain: signed.chain,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.capturedAuthMode).toBe('');
    expect(result.capturedAuthPlanKind).toBe('warmSession');
    expect(result.ordering).toEqual(['reserve', 'confirm']);
    expect(result.chain).toBe('evm');
    expect(result.kind).toBe('eip1559');
  });

  test('passkey ECDSA reauth reuses the confirmation credential for a one-use reconnect', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
        const ordering: string[] = [];
        let capturedSessionPolicyDigest = '';
        let genericEnsureCalls = 0;
        let reconnectArgs: Record<string, unknown> = {};

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
            if (type === 'encodeEip1559SignedTxFromSignature65')
              return new Uint8Array([0x02, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };
        const credential = {
          id: 'cred-passkey-reauth',
          rawId: 'cred-passkey-reauth',
          type: 'public-key',
          authenticatorAttachment: 'platform',
          response: {
            clientDataJSON: 'client-data-json',
            authenticatorData: 'authenticator-data',
            signature: 'signature',
            userHandle: '',
          },
          clientExtensionResults: {
            prf: {
              results: {
                first: 'client-root-share-b64u',
              },
            },
          },
        };

        const signed = await signEvmWithTouchConfirm({
          ctx: { indexedDB: {} } as any,
          workerCtx: workerCtx as any,
          touchConfirm: {
            getWarmSessionStatus: async () => {
              throw new Error('warm-session status should not be read during passkey reauth');
            },
            orchestrateSigningConfirmation: async (params: any) => {
              ordering.push('confirm');
              capturedSessionPolicyDigest = String(params?.sessionPolicyDigest32 || '');
              return {
                sessionId: 'intent',
                intentDigest: String(params?.intentDigest || ''),
                credential,
              };
            },
          } as any,
          nearAccountId: 'alice.testnet',
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              nonce: 8n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 21_000n,
              to: '0x' + '33'.repeat(20),
              value: 12_345n,
              data: '0x',
              accessList: [],
            },
          } as any,
          engines: {
            secp256k1: {
              algorithm: 'secp256k1',
              sign: async () => {
                ordering.push('sign');
                const sig = new Uint8Array(65);
                sig[64] = 0;
                return sig;
              },
            },
          } as any,
          signingAuthPlan: {
            kind: 'passkeyReauth',
            method: 'passkey',
          },
          passkeyEcdsaReconnect: {
            prepare: async ({ usesNeeded }: { usesNeeded: number }) => {
              ordering.push(`prepare:${usesNeeded}`);
              return {
                sessionId: 'threshold-one-use',
                walletSigningSessionId: 'wallet-one-use',
                sessionPolicyDigest32: 'session-policy-digest-one-use',
              };
            },
            reconnect: async (args: any) => {
              ordering.push(`reconnect:${args.usesNeeded}`);
              reconnectArgs = {
                credentialId: String(args.credential?.id || ''),
                usesNeeded: args.usesNeeded,
                sessionId: args.sessionId,
                walletSigningSessionId: args.walletSigningSessionId,
              };
              return {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relayer.example',
                ecdsaThresholdKeyId: 'ecdsa-key-1',
                signingRootId: 'root-1',
                thresholdSessionId: args.sessionId,
                walletSigningSessionId: args.walletSigningSessionId,
              };
            },
          },
          ensureThresholdEcdsaKeyRefReady: async () => {
            genericEnsureCalls += 1;
            throw new Error('generic reconnect must not run after passkey reconnect');
          },
        });

        return {
          ordering,
          capturedSessionPolicyDigest,
          genericEnsureCalls,
          reconnectArgs,
          chain: signed.chain,
          kind: signed.kind,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ordering).toEqual(['prepare:1', 'confirm', 'reconnect:1', 'sign']);
    expect(result.capturedSessionPolicyDigest).toBe('session-policy-digest-one-use');
    expect(result.genericEnsureCalls).toBe(0);
    expect(result.reconnectArgs).toEqual({
      credentialId: 'cred-passkey-reauth',
      usesNeeded: 1,
      sessionId: 'threshold-one-use',
      walletSigningSessionId: 'wallet-one-use',
    });
    expect(result.chain).toBe('evm');
    expect(result.kind).toBe('eip1559');
  });

  test('uses WebAuthn mode only for fresh WebAuthnP256 Tempo signing', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signTempoWithTouchConfirm } = await import(paths.signTempoWithTouchConfirm);
        let capturedAuthMode: string | null = null;
        let capturedAuthPlanKind: string | null = null;

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeTempoSenderHash') return new Uint8Array(32).buffer;
            if (type === 'encodeTempoSignedTx') return new Uint8Array([0x76, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        try {
          await signTempoWithTouchConfirm({
            ctx: {
              indexedDB: {
                clientDB: {
                  resolveProfileAccountContext: async () => null,
                  listProfileAuthenticators: async () => [],
                  selectProfileAuthenticatorsForPrompt: async () => ({
                    authenticatorsForPrompt: [],
                  }),
                },
              },
            } as any,
            workerCtx: workerCtx as any,
            touchConfirm: {
              getWarmSessionStatus: async () => {
                throw new Error('warm-session status should not be read for WebAuthnP256 mode');
              },
              orchestrateSigningConfirmation: async (params: any) => {
                capturedAuthMode = String(params?.signingAuthMode || '');
                capturedAuthPlanKind = String(params?.signingAuthPlan?.kind || '');
                return {
                  sessionId: 'intent',
                  intentDigest: '0x' + '11'.repeat(32),
                  credential: {
                    id: 'cred-id',
                    rawId: 'cred-rawid-b64u',
                    type: 'public-key',
                    authenticatorAttachment: 'platform',
                    response: {
                      clientDataJSON: 'clientDataJSON-b64u',
                      authenticatorData: 'authenticatorData-b64u',
                      signature: 'signature-b64u',
                      userHandle: '',
                    },
                    clientExtensionResults: {},
                  },
                };
              },
            } as any,
            nearAccountId: 'alice.testnet',
            request: {
              chain: 'tempo',
              kind: 'tempoTransaction',
              senderSignatureAlgorithm: 'webauthnP256',
              tx: {
                chainId: 11155111,
                maxPriorityFeePerGas: 1n,
                maxFeePerGas: 2n,
                gasLimit: 21_000n,
                calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
                accessList: [],
                nonceKey: 1n,
                nonce: 1n,
                validBefore: null,
                validAfter: null,
                feePayerSignature: { kind: 'none' },
              },
            } as any,
            engines: {
              webauthnP256: {
                algorithm: 'webauthnP256',
                sign: async () => new Uint8Array(64),
              },
            } as any,
          });
          return { ok: true, capturedAuthMode, capturedAuthPlanKind, error: '' };
        } catch (error) {
          return {
            ok: false,
            capturedAuthMode,
            capturedAuthPlanKind,
            error: error instanceof Error ? error.message : String(error),
          };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(false);
    expect(result.capturedAuthMode).toBe('');
    expect(result.capturedAuthPlanKind).toBe('passkeyReauth');
    expect(result.error).toContain('no profile/account mapping');
  });

  test('runs reconnect hook after confirmer and before signing (EVM)', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
        const order: string[] = [];
        const authSideEffects: string[] = [];

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
            if (type === 'encodeEip1559SignedTxFromSignature65')
              return new Uint8Array([0x02, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        const signed = await signEvmWithTouchConfirm({
          ctx: { indexedDB: {} } as any,
          workerCtx: workerCtx as any,
          touchConfirm: {
            getWarmSessionStatus: async () => ({
              ok: false,
              code: 'not_found',
              message: 'missing',
            }),
            orchestrateSigningConfirmation: async () => {
              order.push('confirm');
              return {
                sessionId: 'intent',
                intentDigest: '0x' + '11'.repeat(32),
              };
            },
          } as any,
          nearAccountId: 'alice.testnet',
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              nonce: 7n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 21_000n,
              to: '0x' + '22'.repeat(20),
              value: 12_345n,
              data: '0x',
              accessList: [],
            },
          } as any,
          ensureThresholdEcdsaKeyRefReady: async () => {
            order.push('reconnect');
            return {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relayer.example',
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              thresholdSessionId: 'session-1',
            } as any;
          },
          reserveWalletSigningSessionBudget: async () => {
            order.push('reserve');
            return null;
          },
          engines: {
            secp256k1: {
              algorithm: 'secp256k1',
              sign: async () => {
                order.push('sign');
                const sig = new Uint8Array(65);
                sig[64] = 0;
                return sig;
              },
            },
          } as any,
          onAuthSideEffectStarted: (sideEffect: string) => {
            order.push(`trace:${sideEffect}`);
            authSideEffects.push(sideEffect);
          },
        });

        return {
          chain: signed.chain,
          kind: signed.kind,
          order,
          authSideEffects,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.chain).toBe('evm');
    expect(result.kind).toBe('eip1559');
    expect(result.order).toEqual([
      'confirm',
      'trace:threshold_reconnect',
      'reconnect',
      'reserve',
      'sign',
    ]);
    expect(result.authSideEffects).toEqual(['threshold_reconnect']);
  });

  test('budget reservation follows refreshed ECDSA keyRef after passkey reconnect', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { reserveEvmFamilyWalletSigningSessionBudget } = await import(
          paths.evmFamilyBudgetSpending
        );
        const { createWalletSigningBudgetLedger } = await import(paths.walletSigningBudgetLedger);
        const statusReads: any[] = [];
        const walletSigningBudgetLedger = createWalletSigningBudgetLedger({
          getStatus: async (args: any) => {
            statusReads.push(args);
            return {
              status: 'active',
              remainingUses: 5,
              expiresAtMs: Date.now() + 120_000,
            };
          },
        });
        const oldLane = {
          accountId: 'alice.testnet',
          authMethod: 'passkey',
          curve: 'ecdsa',
          keyKind: 'threshold_ecdsa_secp256k1',
          chainFamily: 'tempo',
          walletSigningSessionId: 'wallet-old-exhausted',
          thresholdSessionId: 'ecdsa-old-exhausted',
          sessionOrigin: 'login',
          storageSource: 'login',
          retention: 'session',
        };

        await reserveEvmFamilyWalletSigningSessionBudget({
          deps: {},
          walletSigningBudgetLedger,
          senderSignatureAlgorithm: 'secp256k1',
          nearAccountId: 'alice.testnet',
          chain: 'tempo',
          confirmationOperationId: 'op-refreshed-keyref',
          operationFingerprint: 'fingerprint-refreshed-keyref',
          ecdsaSigningLane: oldLane,
          thresholdEcdsaRecord: {
            nearAccountId: 'alice.testnet',
            chain: 'tempo',
            walletSigningSessionId: 'wallet-old-exhausted',
            thresholdSessionId: 'ecdsa-old-exhausted',
            source: 'login',
          },
          thresholdEcdsaKeyRef: {
            type: 'threshold-ecdsa-secp256k1',
            userId: 'alice.testnet',
            relayerUrl: 'https://relayer.example',
            ecdsaThresholdKeyId: 'ecdsa-key',
            signingRootId: 'root',
            walletSigningSessionId: 'wallet-refreshed',
            thresholdSessionId: 'ecdsa-refreshed',
          },
        });

        return { statusReads };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.statusReads).toEqual([
      {
        nearAccountId: 'alice.testnet',
        walletSigningSessionId: 'wallet-refreshed',
      },
    ]);
  });

  test('ignores confirmation behavior for auth-mode and still uses warmSession when cache is available (EVM)', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
        let capturedAuthMode: string | null = null;
        let capturedAuthPlanKind: string | null = null;

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
            if (type === 'encodeEip1559SignedTxFromSignature65')
              return new Uint8Array([0x02, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        const signed = await signEvmWithTouchConfirm({
          ctx: { indexedDB: {} } as any,
          workerCtx: workerCtx as any,
          touchConfirm: {
            getWarmSessionStatus: async () => ({
              ok: true,
              remainingUses: 2,
              expiresAtMs: Date.now() + 10_000,
            }),
            orchestrateSigningConfirmation: async (params: any) => {
              capturedAuthMode = String(params?.signingAuthMode || '');
              capturedAuthPlanKind = String(params?.signingAuthPlan?.kind || '');
              return {
                sessionId: 'intent',
                intentDigest: String(params?.intentDigest || ''),
              };
            },
          } as any,
          nearAccountId: 'alice.testnet',
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              nonce: 7n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 21_000n,
              to: '0x' + '22'.repeat(20),
              value: 12_345n,
              data: '0x',
              accessList: [],
            },
          } as any,
          confirmationConfigOverride: { behavior: 'requireClick' },
          engines: {
            secp256k1: {
              algorithm: 'secp256k1',
              sign: async () => {
                const sig = new Uint8Array(65);
                sig[64] = 0;
                return sig;
              },
            },
          } as any,
          keyRefsByAlgorithm: {
            secp256k1: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relayer.example',
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              thresholdSessionId: 'session-1',
            },
          } as any,
          signingAuthPlan: {
            kind: 'warmSession',
            method: 'passkey',
            accountId: 'alice.testnet',
            intent: 'transaction_sign',
            curve: 'ecdsa',
            sessionId: 'session-1',
            expiresAtMs: Date.now() + 10_000,
            remainingUses: 2,
          },
        });

        return {
          capturedAuthMode,
          capturedAuthPlanKind,
          kind: signed.kind,
          chain: signed.chain,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.capturedAuthMode).toBe('');
    expect(result.capturedAuthPlanKind).toBe('warmSession');
    expect(result.chain).toBe('evm');
    expect(result.kind).toBe('eip1559');
  });

  test('does not fail before confirmer when threshold warm session cache is unavailable (Tempo)', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signTempoWithTouchConfirm } = await import(paths.signTempoWithTouchConfirm);
        let confirmCalls = 0;

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeTempoSenderHash') return new Uint8Array(32).buffer;
            if (type === 'encodeTempoSignedTx') return new Uint8Array([0x76, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        try {
          await signTempoWithTouchConfirm({
            ctx: { indexedDB: {} } as any,
            workerCtx: workerCtx as any,
            touchConfirm: {
              getWarmSessionStatus: async () => ({
                ok: false,
                code: 'expired',
                message: 'expired',
              }),
              orchestrateSigningConfirmation: async () => {
                confirmCalls += 1;
                return {
                  sessionId: 'intent',
                  intentDigest: '0x' + '11'.repeat(32),
                };
              },
            } as any,
            nearAccountId: 'alice.testnet',
            request: {
              chain: 'tempo',
              kind: 'tempoTransaction',
              senderSignatureAlgorithm: 'secp256k1',
              tx: {
                chainId: 11155111,
                maxPriorityFeePerGas: 1n,
                maxFeePerGas: 2n,
                gasLimit: 21_000n,
                calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
                accessList: [],
                nonceKey: 1n,
                nonce: 1n,
                validBefore: null,
                validAfter: null,
                feePayerSignature: { kind: 'none' },
              },
            } as any,
            engines: {
              secp256k1: {
                algorithm: 'secp256k1',
                sign: async () => {
                  const sig = new Uint8Array(65);
                  sig[64] = 0;
                  return sig;
                },
              },
            } as any,
            keyRefsByAlgorithm: {
              secp256k1: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relayer.example',
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
                thresholdSessionId: 'session-1',
              },
            } as any,
          });
          return { ok: true, confirmCalls };
        } catch (error: any) {
          return {
            ok: false,
            confirmCalls,
            message: String(error?.message || error),
          };
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(true);
    expect(result.confirmCalls).toBe(1);
  });

  test('uses Email OTP prompt and refreshed keyRef for Tempo per-operation signing', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signTempoWithTouchConfirm } = await import(paths.signTempoWithTouchConfirm);
        let capturedAuthMode = '';
        let capturedChallengeId = '';
        let capturedAuthPlanKind = '';
        let completedOtpCode = '';
        let signedWithSessionId = '';

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeTempoSenderHash') return new Uint8Array(32).buffer;
            if (type === 'encodeTempoSignedTx') return new Uint8Array([0x76, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        const signed = await signTempoWithTouchConfirm({
          ctx: { indexedDB: {} } as any,
          workerCtx: workerCtx as any,
          touchConfirm: {
            getWarmSessionStatus: async () => {
              throw new Error('warm-session status should not be read for emailOtp mode');
            },
            orchestrateSigningConfirmation: async (params: any) => {
              capturedAuthMode = String(params?.signingAuthMode || '');
              capturedAuthPlanKind = String(params?.signingAuthPlan?.kind || '');
              capturedChallengeId = String(params?.emailOtpPrompt?.challengeId || '');
              return {
                sessionId: 'intent',
                intentDigest: '0x' + '11'.repeat(32),
                otpCode: '123456',
              };
            },
          } as any,
          nearAccountId: 'alice.testnet',
          request: {
            chain: 'tempo',
            kind: 'tempoTransaction',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21_000n,
              calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
              accessList: [],
              nonceKey: 1n,
              nonce: 1n,
              validBefore: null,
              validAfter: null,
              feePayerSignature: { kind: 'none' },
            },
          } as any,
          emailOtpSigning: {
            prepare: async () => ({
              challengeId: 'tempo-email-otp-challenge',
              emailHint: 'a***e@example.com',
            }),
            complete: async (otpCode: string) => {
              completedOtpCode = otpCode;
              return {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relayer.example',
                relayerKeyId: 'rk-email-otp',
                clientVerifyingShareB64u: 'AQ',
                thresholdSessionId: 'tempo-email-otp-refreshed-session',
              } as any;
            },
          },
          engines: {
            secp256k1: {
              algorithm: 'secp256k1',
              sign: async (_signReq: unknown, keyRef: any) => {
                signedWithSessionId = String(keyRef?.thresholdSessionId || '');
                const sig = new Uint8Array(65);
                sig[64] = 0;
                return sig;
              },
            },
          } as any,
        });

        return {
          capturedAuthMode,
          capturedAuthPlanKind,
          capturedChallengeId,
          completedOtpCode,
          signedWithSessionId,
          chain: signed.chain,
          kind: signed.kind,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.capturedAuthMode).toBe('');
    expect(result.capturedAuthPlanKind).toBe('emailOtpReauth');
    expect(result.capturedChallengeId).toBe('tempo-email-otp-challenge');
    expect(result.completedOtpCode).toBe('123456');
    expect(result.signedWithSessionId).toBe('tempo-email-otp-refreshed-session');
    expect(result.chain).toBe('tempo');
    expect(result.kind).toBe('tempoTransaction');
  });

  test('core Tempo signing uses OTP for exhausted Email OTP lane even when generic lookup sees passkey', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signTempo } = await import(paths.tempoSigningApi);
        const store = await import(paths.thresholdSessionStore);
        const accountId = 'otp-tempo.testnet';
        const chain = 'tempo';
        const now = Date.now();
        const walletSigningSessionId = 'wallet-email-otp-session';
        store.clearAllStoredThresholdEd25519SessionRecords();
        store.upsertStoredThresholdEd25519SessionRecord({
          nearAccountId: accountId,
          rpId: 'localhost',
          relayerUrl: 'https://relayer.example',
          relayerKeyId: 'rk-ed25519',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'ed25519-email-session',
          walletSigningSessionId,
          thresholdSessionJwt: 'jwt:ed25519-email-session',
          expiresAtMs: now + 120_000,
          remainingUses: 1,
          emailOtpAuthContext: {
            policy: 'per_operation',
            retention: 'single_use',
            reason: 'sign',
            authMethod: 'email_otp',
          },
          updatedAtMs: now,
          source: 'email_otp',
        });

        const passkeyRecord = {
          nearAccountId: accountId,
          chain,
          relayerUrl: 'https://relayer.example',
          ecdsaThresholdKeyId: 'ecdsa-passkey',
          signingRootId: 'proj_test:dev',
          relayerKeyId: 'rk-passkey',
          clientVerifyingShareB64u: 'AQ',
          clientAdditiveShare32B64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'passkey-session',
          thresholdSessionJwt: 'jwt:passkey-session',
          expiresAtMs: now + 120_000,
          remainingUses: 5,
          updatedAtMs: now + 1_000,
          source: 'login',
        };
        const emailOtpRecord = {
          nearAccountId: accountId,
          chain,
          relayerUrl: 'https://relayer.example',
          ecdsaThresholdKeyId: 'ecdsa-email',
          signingRootId: 'proj_test:dev',
          relayerKeyId: 'rk-email',
          clientVerifyingShareB64u: 'AQ',
          clientAdditiveShareHandle: {
            kind: 'email_otp_worker_session',
            sessionId: 'email-worker-session',
          },
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'email-threshold-session',
          walletSigningSessionId,
          thresholdSessionJwt: 'jwt:email-threshold-session',
          expiresAtMs: now + 120_000,
          remainingUses: 0,
          emailOtpAuthContext: {
            policy: 'per_operation',
            retention: 'single_use',
            reason: 'sign',
            authMethod: 'email_otp',
            consumedAtMs: now - 1_000,
          },
          updatedAtMs: now,
          source: 'email_otp',
        };
        const toKeyRef = (record: any) => ({
          type: 'threshold-ecdsa-secp256k1',
          userId: accountId,
          relayerUrl: record.relayerUrl,
          ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
          signingRootId: record.signingRootId,
          backendBinding: {
            relayerKeyId: record.relayerKeyId,
            clientVerifyingShareB64u: record.clientVerifyingShareB64u,
            ...(record.clientAdditiveShare32B64u
              ? { clientAdditiveShare32B64u: record.clientAdditiveShare32B64u }
              : {}),
            ...(record.clientAdditiveShareHandle
              ? { clientAdditiveShareHandle: record.clientAdditiveShareHandle }
              : {}),
          },
          participantIds: record.participantIds,
          thresholdSessionKind: record.thresholdSessionKind,
          thresholdSessionId: record.thresholdSessionId,
          thresholdSessionJwt: record.thresholdSessionJwt,
          ...(record.walletSigningSessionId
            ? { walletSigningSessionId: record.walletSigningSessionId }
            : {}),
        });
        let requestedChallengeAuthLane: any = null;
        let capturedAuthPlanKind = '';
        let capturedEmailOtpChallengeId = '';
        let capturedPasskeyPrompt = false;

        const deps = {
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async () => ({
                profileId: 'profile:otp-tempo',
                accountRef: { chainIdKey: 'near:testnet', accountAddress: accountId },
              }),
              getProfile: async () => ({ profileId: 'profile:otp-tempo', defaultSignerSlot: 1 }),
              listAccountSigners: async () => [
                {
                  signerSlot: 1,
                  signerAuthMethod: 'passkey',
                  signerKind: 'threshold_ed25519',
                  status: 'active',
                },
                {
                  signerSlot: 2,
                  signerAuthMethod: 'email_otp',
                  signerKind: 'threshold_ed25519',
                  status: 'active',
                },
              ],
              getLastProfileState: async () => ({
                profileId: 'profile:otp-tempo',
                activeSignerSlot: 2,
              }),
              listChainAccountsByProfile: async () => [
                {
                  profileId: 'profile:otp-tempo',
                  chainIdKey: 'tempo:11155111',
                  accountAddress: '0x' + '12'.repeat(20),
                  accountModel: 'tempo-native',
                  isPrimary: true,
                },
              ],
            },
          },
          tatchiPasskeyConfigs: {
            registration: { mode: 'manual' },
            network: { chains: [{ network: 'tempo-testnet', chainId: 11155111, rpcUrl: '' }] },
            signing: { thresholdEcdsa: { presignPool: { enabled: false } } },
          },
          evmNonceManager: {
            reserveNextNonce: async () => 1n,
            reconcileLane: async () => ({
              blocked: false,
              chainNextNonce: 1n,
              unresolvedInFlightNonces: [],
            }),
            markBroadcastRejected: () => undefined,
          },
          getSignerWorkerContext: () => ({
            requestWorkerOperation: async ({ request }: { request: any }) => {
              const type = String(request?.type || '');
              if (type === 'computeTempoSenderHash') return new Uint8Array(32).buffer;
              if (type === 'encodeTempoSignedTx') return new Uint8Array([0x76, 0xaa]).buffer;
              throw new Error(`Unexpected worker operation: ${type}`);
            },
          }),
          withThresholdEcdsaCommitQueue: async ({ task }: any) => await task(),
          getEmailOtpThresholdEcdsaSessionRecordForSigning: () => emailOtpRecord,
          getEmailOtpThresholdEcdsaKeyRefForSigning: () => {
            throw new Error('Consumed Email OTP lane has no reusable keyRef before OTP');
          },
          getPasskeyThresholdEcdsaSessionRecordForSigning: () => passkeyRecord,
          getPasskeyThresholdEcdsaKeyRefForSigning: () => toKeyRef(passkeyRecord),
          requestEmailOtpTransactionSigningChallenge: async ({ authLane }: any) => {
            requestedChallengeAuthLane = authLane;
            return { challengeId: 'email-otp-challenge', emailHint: 'o***p@example.com' };
          },
          loginWithEmailOtpEcdsaCapabilityForSigning: async () => toKeyRef(emailOtpRecord),
          getEmailOtpWarmSessionStatus: async () => ({
            ok: false,
            code: 'exhausted',
            message: 'exhausted',
          }),
          resolveEmailOtpSigningSessionAuthLane: () => null,
          clearThresholdEcdsaSessionRecordForLane: () => undefined,
          provisionThresholdEcdsaSession: async () => {
            throw new Error('passkey ECDSA provisioning should not run');
          },
          touchConfirm: {
            getContext: () => ({ touchIdPrompt: { getRpId: () => 'localhost' } }),
            getWarmSessionStatus: async () => ({
              ok: false,
              code: 'exhausted',
              message: 'exhausted',
            }),
            orchestrateSigningConfirmation: async (params: any) => {
              capturedAuthPlanKind = String(params?.signingAuthPlan?.kind || '');
              capturedEmailOtpChallengeId = String(params?.emailOtpPrompt?.challengeId || '');
              capturedPasskeyPrompt = params?.signingAuthPlan?.kind === 'passkeyReauth';
              throw new Error('STOP_AFTER_AUTH_PLAN');
            },
          },
        };

        try {
          await signTempo(deps as any, {
            nearAccountId: accountId,
            request: {
              chain: 'tempo',
              kind: 'tempoTransaction',
              senderSignatureAlgorithm: 'secp256k1',
              tx: {
                chainId: 11155111,
                maxPriorityFeePerGas: 1n,
                maxFeePerGas: 2n,
                gasLimit: 21_000n,
                calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
                accessList: [],
                nonceKey: 1n,
                nonce: 1n,
                validBefore: null,
                validAfter: null,
                feePayerSignature: { kind: 'none' },
              },
            } as any,
          });
        } catch (error: any) {
          if (!String(error?.message || error).includes('STOP_AFTER_AUTH_PLAN')) {
            return {
              ok: false,
              message: String(error?.message || error),
              capturedAuthPlanKind,
              capturedEmailOtpChallengeId,
              capturedPasskeyPrompt,
              requestedChallengeAuthLane,
            };
          }
        } finally {
          store.clearAllStoredThresholdEd25519SessionRecords();
        }

        return {
          ok: true,
          capturedAuthPlanKind,
          capturedEmailOtpChallengeId,
          capturedPasskeyPrompt,
          requestedChallengeAuthLane,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(true);
    expect(result.capturedAuthPlanKind).toBe('emailOtpReauth');
    expect(result.capturedEmailOtpChallengeId).toBe('email-otp-challenge');
    expect(result.capturedPasskeyPrompt).toBe(false);
    expect(result.requestedChallengeAuthLane?.kind).toBe('signing_session');
    expect(result.requestedChallengeAuthLane?.thresholdSessionId).toBe('email-threshold-session');
  });

  test('core Tempo signing keeps selected warm passkey lane when Email OTP local record counter is stale', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signTempo } = await import(paths.tempoSigningApi);
        const store = await import(paths.thresholdSessionStore);
        const accountId = 'otp-tempo-stale-counter.testnet';
        const chain = 'tempo';
        const now = Date.now();
        const walletSigningSessionId = 'wallet-email-otp-stale-counter';
        store.clearAllStoredThresholdEd25519SessionRecords();
        store.upsertStoredThresholdEd25519SessionRecord({
          nearAccountId: accountId,
          rpId: 'localhost',
          relayerUrl: 'https://relayer.example',
          relayerKeyId: 'rk-ed25519',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'ed25519-email-session',
          walletSigningSessionId,
          thresholdSessionJwt: 'jwt:ed25519-email-session',
          expiresAtMs: now + 120_000,
          remainingUses: 5,
          emailOtpAuthContext: {
            policy: 'session',
            retention: 'session',
            reason: 'login',
            authMethod: 'email_otp',
          },
          updatedAtMs: now,
          source: 'email_otp',
        });

        const passkeyRecord = {
          nearAccountId: accountId,
          chain,
          relayerUrl: 'https://relayer.example',
          ecdsaThresholdKeyId: 'ecdsa-passkey',
          signingRootId: 'proj_test:dev',
          relayerKeyId: 'rk-passkey',
          clientVerifyingShareB64u: 'AQ',
          clientAdditiveShare32B64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'passkey-session',
          walletSigningSessionId: 'wallet-passkey-stale-counter',
          thresholdSessionJwt: 'jwt:passkey-session',
          expiresAtMs: now + 120_000,
          remainingUses: 5,
          updatedAtMs: now + 1_000,
          source: 'login',
        };
        const emailOtpRecord = {
          nearAccountId: accountId,
          chain,
          relayerUrl: 'https://relayer.example',
          ecdsaThresholdKeyId: 'ecdsa-email',
          signingRootId: 'proj_test:dev',
          relayerKeyId: 'rk-email',
          clientVerifyingShareB64u: 'AQ',
          clientAdditiveShareHandle: {
            kind: 'email_otp_worker_session',
            sessionId: 'email-worker-session',
          },
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'email-threshold-session',
          walletSigningSessionId,
          thresholdSessionJwt: 'jwt:email-threshold-session',
          expiresAtMs: now + 120_000,
          remainingUses: 0,
          emailOtpAuthContext: {
            policy: 'session',
            retention: 'session',
            reason: 'login',
            authMethod: 'email_otp',
          },
          updatedAtMs: now,
          source: 'email_otp',
        };
        const toKeyRef = (record: any) => ({
          type: 'threshold-ecdsa-secp256k1',
          userId: accountId,
          relayerUrl: record.relayerUrl,
          ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
          signingRootId: record.signingRootId,
          backendBinding: {
            relayerKeyId: record.relayerKeyId,
            clientVerifyingShareB64u: record.clientVerifyingShareB64u,
            ...(record.clientAdditiveShare32B64u
              ? { clientAdditiveShare32B64u: record.clientAdditiveShare32B64u }
              : {}),
            ...(record.clientAdditiveShareHandle
              ? { clientAdditiveShareHandle: record.clientAdditiveShareHandle }
              : {}),
          },
          participantIds: record.participantIds,
          thresholdSessionKind: record.thresholdSessionKind,
          thresholdSessionId: record.thresholdSessionId,
          thresholdSessionJwt: record.thresholdSessionJwt,
          ...(record.walletSigningSessionId
            ? { walletSigningSessionId: record.walletSigningSessionId }
            : {}),
        });
        let capturedAuthPlanKind = '';
        let capturedPasskeyPrompt = false;
        let challengeCalls = 0;

        const deps = {
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async () => ({
                profileId: 'profile:otp-tempo-stale',
                accountRef: { chainIdKey: 'near:testnet', accountAddress: accountId },
              }),
              getProfile: async () => ({
                profileId: 'profile:otp-tempo-stale',
                defaultSignerSlot: 1,
              }),
              listAccountSigners: async () => [
                {
                  signerSlot: 1,
                  signerAuthMethod: 'passkey',
                  signerKind: 'threshold_ed25519',
                  status: 'active',
                },
              ],
              getLastProfileState: async () => ({
                profileId: 'profile:otp-tempo-stale',
                activeSignerSlot: 1,
              }),
              listChainAccountsByProfile: async () => [
                {
                  profileId: 'profile:otp-tempo-stale',
                  chainIdKey: 'tempo:11155111',
                  accountAddress: '0x' + '12'.repeat(20),
                  accountModel: 'tempo-native',
                  isPrimary: true,
                },
              ],
            },
          },
          tatchiPasskeyConfigs: {
            registration: { mode: 'manual' },
            network: { chains: [{ network: 'tempo-testnet', chainId: 11155111, rpcUrl: '' }] },
            signing: { thresholdEcdsa: { presignPool: { enabled: false } } },
          },
          evmNonceManager: {
            reserveNextNonce: async () => 1n,
            reconcileLane: async () => ({
              blocked: false,
              chainNextNonce: 1n,
              unresolvedInFlightNonces: [],
            }),
            markBroadcastRejected: () => undefined,
          },
          getSignerWorkerContext: () => ({
            requestWorkerOperation: async ({ request }: { request: any }) => {
              const type = String(request?.type || '');
              if (type === 'computeTempoSenderHash') return new Uint8Array(32).buffer;
              if (type === 'encodeTempoSignedTx') return new Uint8Array([0x76, 0xaa]).buffer;
              throw new Error(`Unexpected worker operation: ${type}`);
            },
          }),
          withThresholdEcdsaCommitQueue: async ({ task }: any) => await task(),
          getEmailOtpThresholdEcdsaSessionRecordForSigning: () => emailOtpRecord,
          getEmailOtpThresholdEcdsaKeyRefForSigning: () => toKeyRef(emailOtpRecord),
          getPasskeyThresholdEcdsaSessionRecordForSigning: () => passkeyRecord,
          getPasskeyThresholdEcdsaKeyRefForSigning: () => toKeyRef(passkeyRecord),
          requestEmailOtpTransactionSigningChallenge: async () => {
            challengeCalls += 1;
            return { challengeId: 'unexpected-email-otp-challenge' };
          },
          loginWithEmailOtpEcdsaCapabilityForSigning: async () => toKeyRef(emailOtpRecord),
          getEmailOtpWarmSessionStatus: async () => ({
            ok: true,
            remainingUses: 5,
            expiresAtMs: now + 120_000,
          }),
          resolveEmailOtpSigningSessionAuthLane: () => null,
          clearThresholdEcdsaSessionRecordForLane: () => undefined,
          provisionThresholdEcdsaSession: async () => {
            throw new Error('warm Email OTP ECDSA should not reconnect');
          },
          touchConfirm: {
            getContext: () => ({ touchIdPrompt: { getRpId: () => 'localhost' } }),
            getWarmSessionStatus: async () => ({
              ok: false,
              code: 'not_found',
              message: 'not found',
            }),
            orchestrateSigningConfirmation: async (params: any) => {
              capturedAuthPlanKind = String(params?.signingAuthPlan?.kind || '');
              capturedPasskeyPrompt = params?.signingAuthPlan?.kind === 'passkeyReauth';
              throw new Error('STOP_AFTER_AUTH_PLAN');
            },
          },
        };

        try {
          await signTempo(deps as any, {
            nearAccountId: accountId,
            request: {
              chain: 'tempo',
              kind: 'tempoTransaction',
              senderSignatureAlgorithm: 'secp256k1',
              tx: {
                chainId: 11155111,
                maxPriorityFeePerGas: 1n,
                maxFeePerGas: 2n,
                gasLimit: 21_000n,
                calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
                accessList: [],
                nonceKey: 1n,
                nonce: 1n,
                validBefore: null,
                validAfter: null,
                feePayerSignature: { kind: 'none' },
              },
            } as any,
          });
        } catch (error: any) {
          if (!String(error?.message || error).includes('STOP_AFTER_AUTH_PLAN')) {
            return {
              ok: false,
              message: String(error?.message || error),
              capturedAuthPlanKind,
              capturedPasskeyPrompt,
              challengeCalls,
            };
          }
        } finally {
          store.clearAllStoredThresholdEd25519SessionRecords();
        }

        return {
          ok: true,
          capturedAuthPlanKind,
          capturedPasskeyPrompt,
          challengeCalls,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(true);
    expect(result.capturedAuthPlanKind).toBe('warmSession');
    expect(result.capturedPasskeyPrompt).toBe(false);
    expect(result.challengeCalls).toBe(0);
  });

  for (const chain of ['tempo', 'evm'] as const) {
    test(`core ${chain.toUpperCase()} signing prompts Email OTP for two exhausted Email OTP ECDSA transactions`, async ({
      page,
    }) => {
      await routeEvmFamilySigningFlowStubs(page);
      const result = await page.evaluate(
        async ({ paths, chain }) => {
          const { signTempo } = await import(paths.tempoSigningApi);
          const store = await import(paths.thresholdSessionStore);
          const { createWalletSigningBudgetLedger } = await import(paths.walletSigningBudgetLedger);
          const accountId = `otp-${chain}-two-tx.testnet`;
          const now = Date.now();
          const chainId = 11155111;
          const walletSigningSessionId = `wallet-email-otp-${chain}`;
          const senderAddress = '0x' + '12'.repeat(20);
          const passkeyThresholdSessionId = `passkey-${chain}-session`;
          const initialEmailThresholdSessionId = `email-${chain}-initial-session`;
          const authPlanKinds: string[] = [];
          const emailOtpChallengeIds: string[] = [];
          const passkeyPlanCount: string[] = [];
          const challengeAuthSessionIds: string[] = [];
          const completedOtpCodes: string[] = [];
          const signedResults: any[] = [];
          const spendCalls: any[] = [];
          const markConsumedCalls: any[] = [];

          store.clearAllStoredThresholdEd25519SessionRecords();
          store.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId: accountId,
            rpId: 'localhost',
            relayerUrl: 'https://relayer.example',
            relayerKeyId: 'rk-ed25519',
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId: `ed25519-email-${chain}`,
            walletSigningSessionId,
            thresholdSessionJwt: `jwt:ed25519-email-${chain}`,
            expiresAtMs: now + 120_000,
            remainingUses: 0,
            emailOtpAuthContext: {
              policy: 'session',
              retention: 'session',
              reason: 'login',
              authMethod: 'email_otp',
            },
            updatedAtMs: now,
            source: 'email_otp',
          });

          const makeEmailOtpRecord = (thresholdSessionId: string, updatedAtMs: number) => ({
            nearAccountId: accountId,
            chain,
            relayerUrl: 'https://relayer.example',
            ecdsaThresholdKeyId: `ecdsa-email-${chain}`,
            signingRootId: 'proj_test:dev',
            relayerKeyId: `rk-email-${chain}`,
            clientVerifyingShareB64u: 'AQ',
            clientAdditiveShareHandle: {
              kind: 'email_otp_worker_session',
              sessionId: `worker-${thresholdSessionId}`,
            },
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId,
            walletSigningSessionId,
            thresholdSessionJwt: `jwt:${thresholdSessionId}`,
            expiresAtMs: now + 120_000,
            remainingUses: 0,
            ethereumAddress: senderAddress,
            emailOtpAuthContext: {
              policy: 'per_operation',
              retention: 'single_use',
              reason: 'sign',
              authMethod: 'email_otp',
              consumedAtMs: updatedAtMs - 1,
            },
            updatedAtMs,
            source: 'email_otp',
          });
          const passkeyRecord = {
            nearAccountId: accountId,
            chain,
            relayerUrl: 'https://relayer.example',
            ecdsaThresholdKeyId: `ecdsa-passkey-${chain}`,
            signingRootId: 'proj_test:dev',
            relayerKeyId: `rk-passkey-${chain}`,
            clientVerifyingShareB64u: 'AQ',
            clientAdditiveShare32B64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId: passkeyThresholdSessionId,
            walletSigningSessionId: `wallet-passkey-${chain}`,
            thresholdSessionJwt: `jwt:${passkeyThresholdSessionId}`,
            expiresAtMs: now + 120_000,
            remainingUses: 5,
            ethereumAddress: senderAddress,
            updatedAtMs: now + 10_000,
            source: 'login',
          };
          let emailOtpRecord: any = makeEmailOtpRecord(initialEmailThresholdSessionId, now);

          const toKeyRef = (record: any) => ({
            type: 'threshold-ecdsa-secp256k1',
            userId: accountId,
            relayerUrl: record.relayerUrl,
            ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
            signingRootId: record.signingRootId,
            backendBinding: {
              relayerKeyId: record.relayerKeyId,
              clientVerifyingShareB64u: record.clientVerifyingShareB64u,
              ...(record.clientAdditiveShare32B64u
                ? { clientAdditiveShare32B64u: record.clientAdditiveShare32B64u }
                : {}),
              ...(record.clientAdditiveShareHandle
                ? { clientAdditiveShareHandle: record.clientAdditiveShareHandle }
                : {}),
            },
            participantIds: record.participantIds,
            thresholdSessionKind: record.thresholdSessionKind,
            thresholdSessionId: record.thresholdSessionId,
            thresholdSessionJwt: record.thresholdSessionJwt,
            walletSigningSessionId: record.walletSigningSessionId,
            ...(record.ethereumAddress ? { ethereumAddress: record.ethereumAddress } : {}),
          });
          const chainIdKey = `${chain}:${chainId}`;
          const accountModel = chain === 'tempo' ? 'tempo-native' : 'erc4337';
          const chainAccount = {
            profileId: `profile:${chain}:otp-two-tx`,
            chainIdKey,
            accountAddress: senderAddress,
            accountModel,
            isPrimary: true,
            deployed: true,
            deploymentTxHash: null,
            lastDeploymentCheckAt: now,
          };
          const requestForNonce = (nonce: bigint) =>
            chain === 'tempo'
              ? ({
                  chain: 'tempo',
                  kind: 'tempoTransaction',
                  senderSignatureAlgorithm: 'secp256k1',
                  tx: {
                    chainId,
                    maxPriorityFeePerGas: 1n,
                    maxFeePerGas: 2n,
                    gasLimit: 21_000n,
                    calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
                    accessList: [],
                    nonceKey: 1n,
                    nonce,
                    validBefore: null,
                    validAfter: null,
                    feePayerSignature: { kind: 'none' },
                  },
                } as any)
              : ({
                  chain: 'evm',
                  kind: 'eip1559',
                  senderSignatureAlgorithm: 'secp256k1',
                  tx: {
                    chainId,
                    nonce,
                    maxPriorityFeePerGas: 1_500_000_000n,
                    maxFeePerGas: 3_000_000_000n,
                    gasLimit: 21_000n,
                    to: '0x' + '22'.repeat(20),
                    value: 0n,
                    data: '0x',
                    accessList: [],
                  },
                } as any);

          const deps = {
            indexedDB: {
              clientDB: {
                resolveProfileAccountContext: async () => ({
                  profileId: chainAccount.profileId,
                  accountRef: { chainIdKey: 'near:testnet', accountAddress: accountId },
                }),
                getProfile: async () => ({
                  profileId: chainAccount.profileId,
                  defaultSignerSlot: 1,
                }),
                listAccountSigners: async () => [
                  {
                    signerSlot: 1,
                    signerAuthMethod: 'email_otp',
                    signerKind: 'threshold_ed25519',
                    status: 'active',
                  },
                  {
                    signerSlot: 2,
                    signerAuthMethod: 'passkey',
                    signerKind: 'threshold_ed25519',
                    status: 'active',
                  },
                ],
                getLastProfileState: async () => ({
                  profileId: chainAccount.profileId,
                  activeSignerSlot: 1,
                }),
                listChainAccountsByProfile: async () => [chainAccount],
                listChainAccountsByProfileAndChain: async (
                  _profileId: string,
                  requested: string,
                ) => (requested === chainIdKey ? [chainAccount] : []),
                upsertChainAccount: async (input: any) => ({ ...chainAccount, ...input }),
              },
            },
            tatchiPasskeyConfigs: {
              registration: { mode: 'manual' },
              network: {
                chains: [
                  { network: 'tempo-testnet', chainId, rpcUrl: '' },
                  { network: 'ethereum-sepolia', chainId, rpcUrl: '' },
                ],
              },
              signing: {
                thresholdEcdsa: { presignPool: { enabled: false } },
                smartAccountDeployment: { mode: 'off' },
              },
            },
            evmNonceManager: {
              reserveNextNonce: async () => 1n,
              reconcileLane: async () => ({
                blocked: false,
                chainNextNonce: 1n,
                unresolvedInFlightNonces: [],
              }),
              markBroadcastRejected: () => undefined,
            },
            getSignerWorkerContext: () => ({
              requestWorkerOperation: async () => new Uint8Array([0x76, 0xaa]).buffer,
            }),
            withThresholdEcdsaCommitQueue: async ({ task }: any) => await task(),
            getEmailOtpThresholdEcdsaSessionRecordForSigning: () => emailOtpRecord,
            getEmailOtpThresholdEcdsaKeyRefForSigning: () => {
              throw new Error('exhausted Email OTP lane should require a fresh OTP');
            },
            getPasskeyThresholdEcdsaSessionRecordForSigning: () => passkeyRecord,
            getPasskeyThresholdEcdsaKeyRefForSigning: () => toKeyRef(passkeyRecord),
            requestEmailOtpTransactionSigningChallenge: async ({ authLane }: any) => {
              challengeAuthSessionIds.push(String(authLane?.thresholdSessionId || ''));
              const challengeId = `challenge-${challengeAuthSessionIds.length}`;
              return { challengeId, emailHint: 'o***p@example.com' };
            },
            loginWithEmailOtpEcdsaCapabilityForSigning: async ({
              otpCode,
            }: {
              otpCode: string;
            }) => {
              completedOtpCodes.push(otpCode);
              emailOtpRecord = makeEmailOtpRecord(
                `email-${chain}-fresh-session-${completedOtpCodes.length}`,
                now + completedOtpCodes.length,
              );
              return toKeyRef(emailOtpRecord);
            },
            getEmailOtpWarmSessionStatus: async () => ({
              ok: false,
              code: 'exhausted',
              message: 'exhausted',
            }),
            resolveEmailOtpSigningSessionAuthLane: () => null,
            markThresholdEcdsaEmailOtpSessionConsumedForAccount: (args: any) => {
              markConsumedCalls.push(args);
            },
            walletSigningBudgetLedger: createWalletSigningBudgetLedger({
              consumeUse: async (args: any) => {
                spendCalls.push({
                  nearAccountId: String(args.nearAccountId || ''),
                  walletSigningSessionId: String(args.walletSigningSessionId || ''),
                  uses: args.uses,
                  reason: args.reason,
                  alreadyConsumedThresholdSessionIds: args.alreadyConsumedThresholdSessionIds || [],
                });
                return {
                  status: 'active',
                  remainingUses: 1,
                  expiresAtMs: Date.now() + 120_000,
                };
              },
            }),
            clearThresholdEcdsaSessionRecordForLane: () => undefined,
            provisionThresholdEcdsaSession: async () => {
              throw new Error('exhausted Email OTP ECDSA should not use passkey reconnect');
            },
            touchConfirm: {
              getContext: () => ({ touchIdPrompt: { getRpId: () => 'localhost' } }),
              getWarmSessionStatus: async () => ({
                ok: false,
                code: 'exhausted',
                message: 'exhausted',
              }),
              orchestrateSigningConfirmation: async (params: any) => {
                const planKind = String(params?.signingAuthPlan?.kind || '');
                authPlanKinds.push(planKind);
                emailOtpChallengeIds.push(String(params?.emailOtpPrompt?.challengeId || ''));
                if (planKind === 'passkeyReauth') passkeyPlanCount.push(planKind);
                return {
                  sessionId: 'intent',
                  intentDigest: '0x' + '11'.repeat(32),
                  otpCode: '123456',
                };
              },
            },
          };

          (globalThis as any).__tatchiStubConfirmationDisplayedCalls = 0;
          try {
            signedResults.push(
              await signTempo(deps as any, {
                nearAccountId: accountId,
                request: requestForNonce(1n),
              }),
            );
            signedResults.push(
              await signTempo(deps as any, {
                nearAccountId: accountId,
                request: requestForNonce(2n),
              }),
            );
          } catch (error: any) {
            return {
              ok: false,
              message: String(error?.message || error),
              authPlanKinds,
              emailOtpChallengeIds,
              passkeyPlanCount,
              challengeAuthSessionIds,
              completedOtpCodes,
              spendCalls,
              markConsumedCalls,
            };
          } finally {
            store.clearAllStoredThresholdEd25519SessionRecords();
          }

          return {
            ok: true,
            resultKinds: signedResults.map((signed) => signed.kind),
            authPlanKinds,
            emailOtpChallengeIds,
            passkeyPlanCount,
            challengeAuthSessionIds,
            completedOtpCodes,
            spendCalls,
            markConsumedCalls,
            signedKeyRefs: (globalThis as any).__tatchiStubSignedKeyRefs || [],
          };
        },
        { paths: IMPORT_PATHS, chain },
      );

      expect(result.ok).toBe(true);
      expect(result.resultKinds).toEqual([
        chain === 'tempo' ? 'tempoTransaction' : 'eip1559',
        chain === 'tempo' ? 'tempoTransaction' : 'eip1559',
      ]);
      expect(result.authPlanKinds).toEqual(['emailOtpReauth', 'emailOtpReauth']);
      expect(result.emailOtpChallengeIds).toEqual(['challenge-1', 'challenge-2']);
      expect(result.passkeyPlanCount).toEqual([]);
      expect(result.challengeAuthSessionIds).toEqual([
        `email-${chain}-initial-session`,
        `email-${chain}-fresh-session-1`,
      ]);
      expect(result.completedOtpCodes).toEqual(['123456', '123456']);
      expect(result.spendCalls).toEqual([
        {
          nearAccountId: `otp-${chain}-two-tx.testnet`,
          walletSigningSessionId: `wallet-email-otp-${chain}`,
          uses: 1,
          reason: 'transaction_sign',
          alreadyConsumedThresholdSessionIds: [`email-${chain}-fresh-session-1`],
        },
        {
          nearAccountId: `otp-${chain}-two-tx.testnet`,
          walletSigningSessionId: `wallet-email-otp-${chain}`,
          uses: 1,
          reason: 'transaction_sign',
          alreadyConsumedThresholdSessionIds: [`email-${chain}-fresh-session-2`],
        },
      ]);
      expect(result.markConsumedCalls).toHaveLength(2);
      expect(result.signedKeyRefs.map((entry: any) => entry.thresholdSessionId)).toEqual([
        `email-${chain}-fresh-session-1`,
        `email-${chain}-fresh-session-2`,
      ]);
    });
  }

  for (const chain of ['tempo', 'evm'] as const) {
    test(`core ${chain.toUpperCase()} signing spends once when the same ECDSA operation completes twice`, async ({
      page,
    }) => {
      await routeEvmFamilySigningFlowStubs(page);
      const result = await page.evaluate(
        async ({ paths, chain }) => {
          const { signTempo } = await import(paths.tempoSigningApi);
          const store = await import(paths.thresholdSessionStore);
          const { createWalletSigningBudgetLedger } = await import(paths.walletSigningBudgetLedger);
          const accountId = `otp-${chain}-duplicate-budget.testnet`;
          const now = Date.now();
          const chainId = 11155111;
          const walletSigningSessionId = `wallet-email-otp-${chain}-duplicate-budget`;
          const thresholdSessionId = `email-${chain}-duplicate-budget-session`;
          const senderAddress = '0x' + '78'.repeat(20);
          const authPlanKinds: string[] = [];
          const spendCalls: any[] = [];
          const ledgerTrace: any[] = [];
          const signedResults: any[] = [];

          store.clearAllStoredThresholdEd25519SessionRecords();
          store.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId: accountId,
            rpId: 'localhost',
            relayerUrl: 'https://relayer.example',
            relayerKeyId: 'rk-ed25519',
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId: `ed25519-email-${chain}-duplicate-budget`,
            walletSigningSessionId,
            thresholdSessionJwt: `jwt:ed25519-email-${chain}-duplicate-budget`,
            expiresAtMs: now + 120_000,
            remainingUses: 5,
            emailOtpAuthContext: {
              policy: 'session',
              retention: 'session',
              reason: 'login',
              authMethod: 'email_otp',
            },
            updatedAtMs: now,
            source: 'email_otp',
          });

          const emailOtpRecord = {
            nearAccountId: accountId,
            chain,
            relayerUrl: 'https://relayer.example',
            ecdsaThresholdKeyId: `ecdsa-email-${chain}-duplicate-budget`,
            signingRootId: 'proj_test:dev',
            relayerKeyId: `rk-email-${chain}-duplicate-budget`,
            clientVerifyingShareB64u: 'AQ',
            clientAdditiveShareHandle: {
              kind: 'email_otp_worker_session',
              sessionId: `worker-${thresholdSessionId}`,
            },
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId,
            walletSigningSessionId,
            thresholdSessionJwt: `jwt:${thresholdSessionId}`,
            expiresAtMs: now + 120_000,
            remainingUses: 5,
            ethereumAddress: senderAddress,
            emailOtpAuthContext: {
              policy: 'session',
              retention: 'session',
              reason: 'login',
              authMethod: 'email_otp',
            },
            updatedAtMs: now,
            source: 'email_otp',
          };
          const toKeyRef = (record: any) => ({
            type: 'threshold-ecdsa-secp256k1',
            userId: accountId,
            relayerUrl: record.relayerUrl,
            ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
            signingRootId: record.signingRootId,
            backendBinding: {
              relayerKeyId: record.relayerKeyId,
              clientVerifyingShareB64u: record.clientVerifyingShareB64u,
              ...(record.clientAdditiveShareHandle
                ? { clientAdditiveShareHandle: record.clientAdditiveShareHandle }
                : {}),
            },
            participantIds: record.participantIds,
            thresholdSessionKind: record.thresholdSessionKind,
            thresholdSessionId: record.thresholdSessionId,
            thresholdSessionJwt: record.thresholdSessionJwt,
            walletSigningSessionId: record.walletSigningSessionId,
            ethereumAddress: record.ethereumAddress,
          });
          const chainIdKey = `${chain}:${chainId}`;
          const chainAccount = {
            profileId: `profile:${chain}:duplicate-budget`,
            chainIdKey,
            accountAddress: senderAddress,
            accountModel: chain === 'tempo' ? 'tempo-native' : 'erc4337',
            isPrimary: true,
            deployed: true,
            deploymentTxHash: null,
            lastDeploymentCheckAt: now,
          };
          const request =
            chain === 'tempo'
              ? ({
                  chain: 'tempo',
                  kind: 'tempoTransaction',
                  senderSignatureAlgorithm: 'secp256k1',
                  tx: {
                    chainId,
                    maxPriorityFeePerGas: 1n,
                    maxFeePerGas: 2n,
                    gasLimit: 21_000n,
                    calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
                    accessList: [],
                    nonceKey: 1n,
                    nonce: 1n,
                    validBefore: null,
                    validAfter: null,
                    feePayerSignature: { kind: 'none' },
                  },
                } as any)
              : ({
                  chain: 'evm',
                  kind: 'eip1559',
                  senderSignatureAlgorithm: 'secp256k1',
                  tx: {
                    chainId,
                    nonce: 1n,
                    maxPriorityFeePerGas: 1_500_000_000n,
                    maxFeePerGas: 3_000_000_000n,
                    gasLimit: 21_000n,
                    to: '0x' + '22'.repeat(20),
                    value: 0n,
                    data: '0x',
                    accessList: [],
                  },
                } as any);
          const walletSigningBudgetLedger = createWalletSigningBudgetLedger({
            onTrace: (event: any) => ledgerTrace.push(event),
            consumeUse: async (args: any) => {
              spendCalls.push({
                nearAccountId: String(args.nearAccountId || ''),
                walletSigningSessionId: String(args.walletSigningSessionId || ''),
                uses: args.uses,
                reason: args.reason,
                alreadyConsumedThresholdSessionIds: args.alreadyConsumedThresholdSessionIds || [],
              });
              return {
                status: 'active',
                remainingUses: 1,
                expiresAtMs: Date.now() + 120_000,
              };
            },
          });
          const deps = {
            indexedDB: {
              clientDB: {
                resolveProfileAccountContext: async () => ({
                  profileId: chainAccount.profileId,
                  accountRef: { chainIdKey: 'near:testnet', accountAddress: accountId },
                }),
                getProfile: async () => ({
                  profileId: chainAccount.profileId,
                  defaultSignerSlot: 1,
                }),
                listAccountSigners: async () => [
                  {
                    signerSlot: 1,
                    signerAuthMethod: 'email_otp',
                    signerKind: 'threshold_ed25519',
                    status: 'active',
                  },
                ],
                getLastProfileState: async () => ({
                  profileId: chainAccount.profileId,
                  activeSignerSlot: 1,
                }),
                listChainAccountsByProfile: async () => [chainAccount],
                listChainAccountsByProfileAndChain: async (
                  _profileId: string,
                  requested: string,
                ) => (requested === chainIdKey ? [chainAccount] : []),
                upsertChainAccount: async (input: any) => ({ ...chainAccount, ...input }),
              },
            },
            tatchiPasskeyConfigs: {
              registration: { mode: 'manual' },
              network: {
                chains: [
                  { network: 'tempo-testnet', chainId, rpcUrl: '' },
                  { network: 'ethereum-sepolia', chainId, rpcUrl: '' },
                ],
              },
              signing: {
                thresholdEcdsa: { presignPool: { enabled: false } },
                smartAccountDeployment: { mode: 'off' },
              },
            },
            evmNonceManager: {
              reserveNextNonce: async () => 1n,
              reconcileLane: async () => ({
                blocked: false,
                chainNextNonce: 1n,
                unresolvedInFlightNonces: [],
              }),
              markBroadcastRejected: () => undefined,
            },
            getSignerWorkerContext: () => ({
              requestWorkerOperation: async () => new Uint8Array([0x76, 0xaa]).buffer,
            }),
            withThresholdEcdsaCommitQueue: async ({ task }: any) => await task(),
            getEmailOtpThresholdEcdsaSessionRecordForSigning: () => emailOtpRecord,
            getEmailOtpThresholdEcdsaKeyRefForSigning: () => toKeyRef(emailOtpRecord),
            getPasskeyThresholdEcdsaSessionRecordForSigning: () => {
              throw new Error('duplicate Email OTP operation should not read passkey lane');
            },
            getPasskeyThresholdEcdsaKeyRefForSigning: () => {
              throw new Error('duplicate Email OTP operation should not read passkey keyRef');
            },
            requestEmailOtpTransactionSigningChallenge: async () => {
              throw new Error('warm Email OTP lane should not request a challenge');
            },
            loginWithEmailOtpEcdsaCapabilityForSigning: async () => {
              throw new Error('warm Email OTP lane should not complete OTP');
            },
            getEmailOtpWarmSessionStatus: async () => ({
              ok: true,
              remainingUses: 5,
              expiresAtMs: now + 120_000,
            }),
            resolveEmailOtpSigningSessionAuthLane: () => null,
            markThresholdEcdsaEmailOtpSessionConsumedForAccount: () => undefined,
            walletSigningBudgetLedger,
            clearThresholdEcdsaSessionRecordForLane: () => undefined,
            provisionThresholdEcdsaSession: async () => {
              throw new Error('warm Email OTP lane should not use passkey reconnect');
            },
            touchConfirm: {
              getContext: () => ({ touchIdPrompt: { getRpId: () => 'localhost' } }),
              getWarmSessionStatus: async () => ({
                ok: true,
                remainingUses: 5,
                expiresAtMs: now + 120_000,
              }),
              orchestrateSigningConfirmation: async (params: any) => {
                authPlanKinds.push(String(params?.signingAuthPlan?.kind || ''));
                return {
                  sessionId: 'intent',
                  intentDigest: '0x' + '11'.repeat(32),
                };
              },
            },
          };

          try {
            signedResults.push(
              await signTempo(deps as any, {
                nearAccountId: accountId,
                request,
                signingOperationId: `${chain}-duplicate-budget-operation`,
              }),
            );
            signedResults.push(
              await signTempo(deps as any, {
                nearAccountId: accountId,
                request,
                signingOperationId: `${chain}-duplicate-budget-operation`,
              }),
            );
          } catch (error: any) {
            return {
              ok: false,
              message: String(error?.message || error),
              authPlanKinds,
              spendCalls,
              ledgerTrace,
              confirmationDisplayedCalls:
                (globalThis as any).__tatchiStubConfirmationDisplayedCalls || 0,
            };
          } finally {
            store.clearAllStoredThresholdEd25519SessionRecords();
          }

          return {
            ok: true,
            resultKinds: signedResults.map((signed) => signed.kind),
            authPlanKinds,
            spendCalls,
            ledgerTrace,
            confirmationDisplayedCalls:
              (globalThis as any).__tatchiStubConfirmationDisplayedCalls || 0,
          };
        },
        { paths: IMPORT_PATHS, chain },
      );

      expect(result.ok).toBe(true);
      expect(result.resultKinds).toEqual([
        chain === 'tempo' ? 'tempoTransaction' : 'eip1559',
        chain === 'tempo' ? 'tempoTransaction' : 'eip1559',
      ]);
      expect(result.authPlanKinds).toEqual(['warmSession', 'warmSession']);
      expect(result.confirmationDisplayedCalls).toBe(2);
      expect(result.ledgerTrace.map((event: any) => event.event)).toEqual([
        'wallet_signing_budget_spend_started',
        'wallet_signing_budget_spend_succeeded',
        'wallet_signing_budget_spend_deduped',
      ]);
      expect(result.spendCalls).toEqual([
        {
          nearAccountId: `otp-${chain}-duplicate-budget.testnet`,
          walletSigningSessionId: `wallet-email-otp-${chain}-duplicate-budget`,
          uses: 1,
          reason: 'transaction_sign',
          alreadyConsumedThresholdSessionIds: [`email-${chain}-duplicate-budget-session`],
        },
      ]);
    });
  }

  for (const chain of ['tempo', 'evm'] as const) {
    test(`core ${chain.toUpperCase()} signing cancellation after Email OTP planning does not spend budget`, async ({
      page,
    }) => {
      await routeEvmFamilySigningFlowStubs(page);
      const result = await page.evaluate(
        async ({ paths, chain }) => {
          const { signTempo } = await import(paths.tempoSigningApi);
          const store = await import(paths.thresholdSessionStore);
          const { createWalletSigningBudgetLedger } = await import(paths.walletSigningBudgetLedger);
          const accountId = `otp-${chain}-cancelled.testnet`;
          const now = Date.now();
          const chainId = 11155111;
          const walletSigningSessionId = `wallet-email-otp-${chain}-cancelled`;
          const senderAddress = '0x' + '56'.repeat(20);
          const authPlanKinds: string[] = [];
          const challengeChains: string[] = [];
          const challengeDisplayCounts: number[] = [];
          const completedOtpCodes: string[] = [];
          const spendCalls: any[] = [];
          const markConsumedCalls: any[] = [];

          store.clearAllStoredThresholdEd25519SessionRecords();
          store.upsertStoredThresholdEd25519SessionRecord({
            nearAccountId: accountId,
            rpId: 'localhost',
            relayerUrl: 'https://relayer.example',
            relayerKeyId: 'rk-ed25519',
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId: `ed25519-email-${chain}-cancelled`,
            walletSigningSessionId,
            thresholdSessionJwt: `jwt:ed25519-email-${chain}-cancelled`,
            expiresAtMs: now + 120_000,
            remainingUses: 0,
            emailOtpAuthContext: {
              policy: 'session',
              retention: 'session',
              reason: 'login',
              authMethod: 'email_otp',
            },
            updatedAtMs: now,
            source: 'email_otp',
          });

          const emailOtpRecord = {
            nearAccountId: accountId,
            chain,
            relayerUrl: 'https://relayer.example',
            ecdsaThresholdKeyId: `ecdsa-email-${chain}-cancelled`,
            signingRootId: 'proj_test:dev',
            relayerKeyId: `rk-email-${chain}-cancelled`,
            clientVerifyingShareB64u: 'AQ',
            clientAdditiveShareHandle: {
              kind: 'email_otp_worker_session',
              sessionId: `worker-email-${chain}-cancelled`,
            },
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId: `email-${chain}-cancelled-session`,
            walletSigningSessionId,
            thresholdSessionJwt: `jwt:email-${chain}-cancelled-session`,
            expiresAtMs: now + 120_000,
            remainingUses: 0,
            ethereumAddress: senderAddress,
            emailOtpAuthContext: {
              policy: 'per_operation',
              retention: 'single_use',
              reason: 'sign',
              authMethod: 'email_otp',
              consumedAtMs: now - 1_000,
            },
            updatedAtMs: now,
            source: 'email_otp',
          };
          const chainIdKey = `${chain}:${chainId}`;
          const chainAccount = {
            profileId: `profile:${chain}:otp-cancelled`,
            chainIdKey,
            accountAddress: senderAddress,
            accountModel: chain === 'tempo' ? 'tempo-native' : 'erc4337',
            isPrimary: true,
            deployed: true,
            deploymentTxHash: null,
            lastDeploymentCheckAt: now,
          };
          const request =
            chain === 'tempo'
              ? ({
                  chain: 'tempo',
                  kind: 'tempoTransaction',
                  senderSignatureAlgorithm: 'secp256k1',
                  tx: {
                    chainId,
                    maxPriorityFeePerGas: 1n,
                    maxFeePerGas: 2n,
                    gasLimit: 21_000n,
                    calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
                    accessList: [],
                    nonceKey: 1n,
                    nonce: 1n,
                    validBefore: null,
                    validAfter: null,
                    feePayerSignature: { kind: 'none' },
                  },
                } as any)
              : ({
                  chain: 'evm',
                  kind: 'eip1559',
                  senderSignatureAlgorithm: 'secp256k1',
                  tx: {
                    chainId,
                    nonce: 1n,
                    maxPriorityFeePerGas: 1_500_000_000n,
                    maxFeePerGas: 3_000_000_000n,
                    gasLimit: 21_000n,
                    to: '0x' + '22'.repeat(20),
                    value: 0n,
                    data: '0x',
                    accessList: [],
                  },
                } as any);

          const deps = {
            indexedDB: {
              clientDB: {
                resolveProfileAccountContext: async () => ({
                  profileId: chainAccount.profileId,
                  accountRef: { chainIdKey: 'near:testnet', accountAddress: accountId },
                }),
                getProfile: async () => ({
                  profileId: chainAccount.profileId,
                  defaultSignerSlot: 1,
                }),
                listAccountSigners: async () => [
                  {
                    signerSlot: 1,
                    signerAuthMethod: 'email_otp',
                    signerKind: 'threshold_ed25519',
                    status: 'active',
                  },
                ],
                getLastProfileState: async () => ({
                  profileId: chainAccount.profileId,
                  activeSignerSlot: 1,
                }),
                listChainAccountsByProfile: async () => [chainAccount],
                listChainAccountsByProfileAndChain: async (
                  _profileId: string,
                  requested: string,
                ) => (requested === chainIdKey ? [chainAccount] : []),
                upsertChainAccount: async (input: any) => ({ ...chainAccount, ...input }),
              },
            },
            tatchiPasskeyConfigs: {
              registration: { mode: 'manual' },
              network: {
                chains: [
                  { network: 'tempo-testnet', chainId, rpcUrl: '' },
                  { network: 'ethereum-sepolia', chainId, rpcUrl: '' },
                ],
              },
              signing: {
                thresholdEcdsa: { presignPool: { enabled: false } },
                smartAccountDeployment: { mode: 'off' },
              },
            },
            evmNonceManager: {
              reserveNextNonce: async () => 1n,
              reconcileLane: async () => ({
                blocked: false,
                chainNextNonce: 1n,
                unresolvedInFlightNonces: [],
              }),
              markBroadcastRejected: () => undefined,
            },
            getSignerWorkerContext: () => ({
              requestWorkerOperation: async () => {
                throw new Error('signing worker should not run after cancellation');
              },
            }),
            withThresholdEcdsaCommitQueue: async ({ task }: any) => await task(),
            getEmailOtpThresholdEcdsaSessionRecordForSigning: () => emailOtpRecord,
            getEmailOtpThresholdEcdsaKeyRefForSigning: () => {
              throw new Error('cancelled exhausted Email OTP lane should not use stale keyRef');
            },
            getPasskeyThresholdEcdsaSessionRecordForSigning: () => {
              throw new Error('cancelled Email OTP signing should not read passkey lane');
            },
            getPasskeyThresholdEcdsaKeyRefForSigning: () => {
              throw new Error('cancelled Email OTP signing should not read passkey keyRef');
            },
            requestEmailOtpTransactionSigningChallenge: async ({ chain }: any) => {
              challengeChains.push(String(chain || ''));
              challengeDisplayCounts.push(
                (globalThis as any).__tatchiStubConfirmationDisplayedCalls || 0,
              );
              return {
                challengeId: `${chain}-cancelled-challenge`,
                emailHint: 'o***p@example.com',
              };
            },
            loginWithEmailOtpEcdsaCapabilityForSigning: async ({ otpCode }: any) => {
              completedOtpCodes.push(String(otpCode || ''));
              throw new Error('cancelled Email OTP signing should not complete OTP');
            },
            getEmailOtpWarmSessionStatus: async () => ({
              ok: false,
              code: 'exhausted',
              message: 'exhausted',
            }),
            resolveEmailOtpSigningSessionAuthLane: () => null,
            markThresholdEcdsaEmailOtpSessionConsumedForAccount: (args: any) => {
              markConsumedCalls.push(args);
            },
            walletSigningBudgetLedger: createWalletSigningBudgetLedger({
              consumeUse: async (args: any) => {
                spendCalls.push(args);
                return {
                  status: 'active',
                  remainingUses: 1,
                  expiresAtMs: Date.now() + 120_000,
                };
              },
            }),
            clearThresholdEcdsaSessionRecordForLane: () => undefined,
            provisionThresholdEcdsaSession: async () => {
              throw new Error('cancelled Email OTP signing should not use passkey reconnect');
            },
            touchConfirm: {
              getContext: () => ({ touchIdPrompt: { getRpId: () => 'localhost' } }),
              getWarmSessionStatus: async () => ({
                ok: false,
                code: 'exhausted',
                message: 'exhausted',
              }),
              orchestrateSigningConfirmation: async (params: any) => {
                authPlanKinds.push(String(params?.signingAuthPlan?.kind || ''));
                throw new Error('User rejected signing request');
              },
            },
          };

          (globalThis as any).__tatchiStubConfirmationDisplayedCalls = 0;
          try {
            await signTempo(deps as any, {
              nearAccountId: accountId,
              request,
            });
          } catch (error: any) {
            return {
              ok: String(error?.message || error).includes('User rejected signing request'),
              message: String(error?.message || error),
              authPlanKinds,
              challengeChains,
              challengeDisplayCounts,
              completedOtpCodes,
              spendCalls,
              markConsumedCalls,
              confirmationDisplayedCalls:
                (globalThis as any).__tatchiStubConfirmationDisplayedCalls || 0,
            };
          } finally {
            store.clearAllStoredThresholdEd25519SessionRecords();
          }

          return {
            ok: false,
            message: 'signing unexpectedly succeeded',
            authPlanKinds,
            challengeChains,
            challengeDisplayCounts,
            completedOtpCodes,
            spendCalls,
            markConsumedCalls,
            confirmationDisplayedCalls:
              (globalThis as any).__tatchiStubConfirmationDisplayedCalls || 0,
          };
        },
        { paths: IMPORT_PATHS, chain },
      );

      expect(result.ok).toBe(true);
      expect(result.authPlanKinds).toEqual(['emailOtpReauth']);
      expect(result.challengeChains).toEqual([chain]);
      expect(result.challengeDisplayCounts).toEqual([1]);
      expect(result.confirmationDisplayedCalls).toBe(1);
      expect(result.completedOtpCodes).toEqual([]);
      expect(result.spendCalls).toEqual([]);
      expect(result.markConsumedCalls).toEqual([]);
    });
  }

  test('active passkey signer ignores stale Email OTP lane and spends passkey budget after ECDSA exhaustion', async ({
    page,
  }) => {
    await routeEvmFamilySigningFlowStubs(page);
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signTempo } = await import(paths.tempoSigningApi);
        const store = await import(paths.thresholdSessionStore);
        const { createWalletSigningBudgetLedger } = await import(paths.walletSigningBudgetLedger);
        const chains = ['tempo', 'evm'] as const;
        const now = Date.now();
        const accountId = 'dual-auth-passkey.testnet';
        const senderAddress = '0x' + '34'.repeat(20);
        const chainId = 11155111;
        const authPlanKinds: string[] = [];
        const emailChallengeCalls: string[] = [];
        const spendCalls: any[] = [];
        const results: any[] = [];

        store.clearAllStoredThresholdEd25519SessionRecords();

        const toKeyRef = (record: any) => ({
          type: 'threshold-ecdsa-secp256k1',
          userId: accountId,
          relayerUrl: record.relayerUrl,
          ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
          signingRootId: record.signingRootId,
          backendBinding: {
            relayerKeyId: record.relayerKeyId,
            clientVerifyingShareB64u: record.clientVerifyingShareB64u,
            ...(record.clientAdditiveShare32B64u
              ? { clientAdditiveShare32B64u: record.clientAdditiveShare32B64u }
              : {}),
            ...(record.clientAdditiveShareHandle
              ? { clientAdditiveShareHandle: record.clientAdditiveShareHandle }
              : {}),
          },
          participantIds: record.participantIds,
          thresholdSessionKind: record.thresholdSessionKind,
          thresholdSessionId: record.thresholdSessionId,
          thresholdSessionJwt: record.thresholdSessionJwt,
          walletSigningSessionId: record.walletSigningSessionId,
          ...(record.ethereumAddress ? { ethereumAddress: record.ethereumAddress } : {}),
        });
        const makePasskeyRecord = (chain: 'tempo' | 'evm') => ({
          nearAccountId: accountId,
          chain,
          relayerUrl: 'https://relayer.example',
          ecdsaThresholdKeyId: `ecdsa-passkey-${chain}`,
          signingRootId: 'proj_test:dev',
          relayerKeyId: `rk-passkey-${chain}`,
          clientVerifyingShareB64u: 'AQ',
          clientAdditiveShare32B64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: `passkey-${chain}-exhausted-session`,
          walletSigningSessionId: `wallet-passkey-${chain}`,
          thresholdSessionJwt: `jwt:passkey-${chain}`,
          expiresAtMs: now + 120_000,
          remainingUses: 0,
          ethereumAddress: senderAddress,
          updatedAtMs: now,
          source: 'login',
        });
        const makeEmailOtpRecord = (chain: 'tempo' | 'evm') => ({
          nearAccountId: accountId,
          chain,
          relayerUrl: 'https://relayer.example',
          ecdsaThresholdKeyId: `ecdsa-email-${chain}`,
          signingRootId: 'proj_test:dev',
          relayerKeyId: `rk-email-${chain}`,
          clientVerifyingShareB64u: 'AQ',
          clientAdditiveShareHandle: {
            kind: 'email_otp_worker_session',
            sessionId: `stale-email-worker-${chain}`,
          },
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: `stale-email-${chain}-session`,
          walletSigningSessionId: `wallet-email-otp-${chain}`,
          thresholdSessionJwt: `jwt:stale-email-${chain}`,
          expiresAtMs: now - 1_000,
          remainingUses: 0,
          ethereumAddress: senderAddress,
          emailOtpAuthContext: {
            policy: 'per_operation',
            retention: 'single_use',
            reason: 'sign',
            authMethod: 'email_otp',
            consumedAtMs: now - 500,
          },
          updatedAtMs: now + 1_000,
          source: 'email_otp',
        });
        const passkeyRecords = Object.fromEntries(
          chains.map((chain) => [chain, makePasskeyRecord(chain)]),
        ) as Record<'tempo' | 'evm', any>;
        const emailOtpRecords = Object.fromEntries(
          chains.map((chain) => [chain, makeEmailOtpRecord(chain)]),
        ) as Record<'tempo' | 'evm', any>;
        const accountRows = Object.fromEntries(
          chains.map((chain) => [
            `${chain}:${chainId}`,
            {
              profileId: 'profile:dual-auth-passkey',
              chainIdKey: `${chain}:${chainId}`,
              accountAddress: senderAddress,
              accountModel: chain === 'tempo' ? 'tempo-native' : 'erc4337',
              isPrimary: true,
              deployed: true,
              deploymentTxHash: null,
              lastDeploymentCheckAt: now,
            },
          ]),
        ) as Record<string, any>;
        const requestForChain = (chain: 'tempo' | 'evm') =>
          chain === 'tempo'
            ? ({
                chain: 'tempo',
                kind: 'tempoTransaction',
                senderSignatureAlgorithm: 'secp256k1',
                tx: {
                  chainId,
                  maxPriorityFeePerGas: 1n,
                  maxFeePerGas: 2n,
                  gasLimit: 21_000n,
                  calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
                  accessList: [],
                  nonceKey: 1n,
                  nonce: 1n,
                  validBefore: null,
                  validAfter: null,
                  feePayerSignature: { kind: 'none' },
                },
              } as any)
            : ({
                chain: 'evm',
                kind: 'eip1559',
                senderSignatureAlgorithm: 'secp256k1',
                tx: {
                  chainId,
                  nonce: 1n,
                  maxPriorityFeePerGas: 1_500_000_000n,
                  maxFeePerGas: 3_000_000_000n,
                  gasLimit: 21_000n,
                  to: '0x' + '22'.repeat(20),
                  value: 0n,
                  data: '0x',
                  accessList: [],
                },
              } as any);
        const deps = {
          indexedDB: {
            clientDB: {
              resolveProfileAccountContext: async () => ({
                profileId: 'profile:dual-auth-passkey',
                accountRef: { chainIdKey: 'near:testnet', accountAddress: accountId },
              }),
              getProfile: async () => ({
                profileId: 'profile:dual-auth-passkey',
                defaultSignerSlot: 1,
              }),
              listAccountSigners: async () => [
                {
                  signerSlot: 1,
                  signerAuthMethod: 'passkey',
                  signerKind: 'threshold_ed25519',
                  status: 'active',
                },
                {
                  signerSlot: 2,
                  signerAuthMethod: 'email_otp',
                  signerKind: 'threshold_ed25519',
                  status: 'active',
                },
              ],
              getLastProfileState: async () => ({
                profileId: 'profile:dual-auth-passkey',
                activeSignerSlot: 1,
              }),
              listChainAccountsByProfile: async () => Object.values(accountRows),
              listChainAccountsByProfileAndChain: async (_profileId: string, chainIdKey: string) =>
                accountRows[chainIdKey] ? [accountRows[chainIdKey]] : [],
              upsertChainAccount: async (input: any) => ({
                ...(accountRows[input.chainIdKey] || {}),
                ...input,
              }),
            },
          },
          tatchiPasskeyConfigs: {
            registration: { mode: 'manual' },
            network: {
              chains: [
                { network: 'tempo-testnet', chainId, rpcUrl: '' },
                { network: 'ethereum-sepolia', chainId, rpcUrl: '' },
              ],
            },
            signing: {
              thresholdEcdsa: { presignPool: { enabled: false } },
              smartAccountDeployment: { mode: 'off' },
            },
          },
          evmNonceManager: {
            reserveNextNonce: async () => 1n,
            reconcileLane: async () => ({
              blocked: false,
              chainNextNonce: 1n,
              unresolvedInFlightNonces: [],
            }),
            markBroadcastRejected: () => undefined,
          },
          getSignerWorkerContext: () => ({
            requestWorkerOperation: async () => new Uint8Array([0x76, 0xaa]).buffer,
          }),
          withThresholdEcdsaCommitQueue: async ({ task }: any) => await task(),
          getEmailOtpThresholdEcdsaSessionRecordForSigning: ({ chain }: any) =>
            emailOtpRecords[chain as 'tempo' | 'evm'],
          getEmailOtpThresholdEcdsaKeyRefForSigning: () => {
            throw new Error('stale Email OTP lane must not be selected for passkey account');
          },
          getPasskeyThresholdEcdsaSessionRecordForSigning: ({ chain }: any) =>
            passkeyRecords[chain as 'tempo' | 'evm'],
          getPasskeyThresholdEcdsaKeyRefForSigning: ({ chain }: any) =>
            toKeyRef(passkeyRecords[chain as 'tempo' | 'evm']),
          requestEmailOtpTransactionSigningChallenge: async ({ chain }: any) => {
            emailChallengeCalls.push(String(chain || ''));
            return { challengeId: 'unexpected-email-otp-challenge' };
          },
          loginWithEmailOtpEcdsaCapabilityForSigning: async () => {
            throw new Error('Email OTP login should not run for active passkey signer');
          },
          getEmailOtpWarmSessionStatus: async () => ({
            ok: false,
            code: 'exhausted',
            message: 'exhausted',
          }),
          resolveEmailOtpSigningSessionAuthLane: () => null,
          walletSigningBudgetLedger: createWalletSigningBudgetLedger({
            consumeUse: async (args: any) => {
              spendCalls.push({
                nearAccountId: String(args.nearAccountId || ''),
                walletSigningSessionId: String(args.walletSigningSessionId || ''),
                uses: args.uses,
                reason: args.reason,
                alreadyConsumedThresholdSessionIds: args.alreadyConsumedThresholdSessionIds || [],
              });
              return {
                status: 'active',
                remainingUses: 1,
                expiresAtMs: Date.now() + 120_000,
              };
            },
          }),
          clearThresholdEcdsaSessionRecordForLane: () => undefined,
          provisionThresholdEcdsaSession: async ({ chain }: any) => ({
            ok: true,
            sessionId: `passkey-${chain}-refreshed-session`,
            thresholdEcdsaKeyRef: toKeyRef(passkeyRecords[chain as 'tempo' | 'evm']),
          }),
          touchConfirm: {
            getContext: () => ({ touchIdPrompt: { getRpId: () => 'localhost' } }),
            getWarmSessionStatus: async () => ({
              ok: false,
              code: 'exhausted',
              message: 'exhausted',
            }),
            orchestrateSigningConfirmation: async (params: any) => {
              authPlanKinds.push(String(params?.signingAuthPlan?.kind || ''));
              return {
                sessionId: 'intent',
                intentDigest: '0x' + '11'.repeat(32),
              };
            },
          },
        };

        try {
          for (const chain of chains) {
            results.push(
              await signTempo(deps as any, {
                nearAccountId: accountId,
                request: requestForChain(chain),
              }),
            );
          }
        } catch (error: any) {
          return {
            ok: false,
            message: String(error?.message || error),
            authPlanKinds,
            emailChallengeCalls,
            spendCalls,
          };
        } finally {
          store.clearAllStoredThresholdEd25519SessionRecords();
        }

        return {
          ok: true,
          resultChains: results.map((result) => result.chain),
          authPlanKinds,
          emailChallengeCalls,
          spendCalls,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(true);
    expect(result.resultChains).toEqual(['tempo', 'evm']);
    expect(result.authPlanKinds).toEqual(['passkeyReauth', 'passkeyReauth']);
    expect(result.emailChallengeCalls).toEqual([]);
    expect(result.spendCalls).toEqual([
      {
        nearAccountId: 'dual-auth-passkey.testnet',
        walletSigningSessionId: 'wallet-passkey-tempo',
        uses: 1,
        reason: 'transaction_sign',
        alreadyConsumedThresholdSessionIds: [],
      },
      {
        nearAccountId: 'dual-auth-passkey.testnet',
        walletSigningSessionId: 'wallet-passkey-evm',
        uses: 1,
        reason: 'transaction_sign',
        alreadyConsumedThresholdSessionIds: [],
      },
    ]);
  });

  test('Tempo per-operation Email OTP resend uses the resent challenge for completion', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signTempoWithTouchConfirm } = await import(paths.signTempoWithTouchConfirm);
        let capturedInitialChallengeId = '';
        let capturedResentChallengeId = '';
        let completedOtpCode = '';
        let completedChallengeId = '';
        let signedWithSessionId = '';

        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeTempoSenderHash') return new Uint8Array(32).buffer;
            if (type === 'encodeTempoSignedTx') return new Uint8Array([0x76, 0xaa]).buffer;
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        const signed = await signTempoWithTouchConfirm({
          ctx: { indexedDB: {} } as any,
          workerCtx: workerCtx as any,
          touchConfirm: {
            getWarmSessionStatus: async () => {
              throw new Error('warm-session status should not be read for emailOtp mode');
            },
            orchestrateSigningConfirmation: async (params: any) => {
              capturedInitialChallengeId = String(params?.emailOtpPrompt?.challengeId || '');
              const resent = await params.emailOtpPrompt.onResend();
              capturedResentChallengeId = String(resent?.challengeId || '');
              return {
                sessionId: 'intent',
                intentDigest: '0x' + '11'.repeat(32),
                otpCode: '135791',
                emailOtpChallengeId: capturedResentChallengeId,
              };
            },
          } as any,
          nearAccountId: 'alice.testnet',
          request: {
            chain: 'tempo',
            kind: 'tempoTransaction',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21_000n,
              calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
              accessList: [],
              nonceKey: 1n,
              nonce: 1n,
              validBefore: null,
              validAfter: null,
              feePayerSignature: { kind: 'none' },
            },
          } as any,
          emailOtpSigning: {
            prepare: async () => ({
              challengeId: 'tempo-email-otp-challenge-1',
              emailHint: 'a***e@example.com',
            }),
            resend: async () => ({
              challengeId: 'tempo-email-otp-challenge-2',
              emailHint: 'a***e@example.com',
            }),
            complete: async (otpCode: string, challengeId?: string) => {
              completedOtpCode = otpCode;
              completedChallengeId = String(challengeId || '');
              return {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relayer.example',
                relayerKeyId: 'rk-email-otp',
                clientVerifyingShareB64u: 'AQ',
                thresholdSessionId: 'tempo-email-otp-resent-session',
              } as any;
            },
          },
          engines: {
            secp256k1: {
              algorithm: 'secp256k1',
              sign: async (_signReq: unknown, keyRef: any) => {
                signedWithSessionId = String(keyRef?.thresholdSessionId || '');
                const sig = new Uint8Array(65);
                sig[64] = 0;
                return sig;
              },
            },
          } as any,
        });

        return {
          capturedInitialChallengeId,
          capturedResentChallengeId,
          completedOtpCode,
          completedChallengeId,
          signedWithSessionId,
          chain: signed.chain,
          kind: signed.kind,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.capturedInitialChallengeId).toBe('tempo-email-otp-challenge-1');
    expect(result.capturedResentChallengeId).toBe('tempo-email-otp-challenge-2');
    expect(result.completedOtpCode).toBe('135791');
    expect(result.completedChallengeId).toBe('tempo-email-otp-challenge-2');
    expect(result.signedWithSessionId).toBe('tempo-email-otp-resent-session');
    expect(result.chain).toBe('tempo');
    expect(result.kind).toBe('tempoTransaction');
  });
});
