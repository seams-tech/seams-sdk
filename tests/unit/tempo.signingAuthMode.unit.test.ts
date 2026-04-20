import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  signEvmWithTouchConfirm: '/sdk/esm/core/signingEngine/orchestration/evm/evmSigningFlow.js',
  signTempoWithTouchConfirm: '/sdk/esm/core/signingEngine/orchestration/tempo/tempoSigningFlow.js',
} as const;

test.describe('tempo signing auth-mode resolution', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
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
          });
          return {
            ok: true,
            confirmCalls,
            capturedAuthMode,
            capturedAuthPlanKind,
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
            challengeId: 'evm-email-otp-challenge',
            emailHint: 'a***e@example.com',
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
            challengeId: 'evm-email-otp-challenge-1',
            emailHint: 'a***e@example.com',
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
              challengeId: 'evm-email-otp-challenge',
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
              challengeId: 'evm-email-otp-challenge',
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
              challengeId,
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
          walletAuthPlan: {
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
        });

        return {
          chain: signed.chain,
          kind: signed.kind,
          order,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.chain).toBe('evm');
    expect(result.kind).toBe('eip1559');
    expect(result.order).toEqual(['confirm', 'reconnect', 'sign']);
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
          walletAuthPlan: {
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
            challengeId: 'tempo-email-otp-challenge',
            emailHint: 'a***e@example.com',
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
            challengeId: 'tempo-email-otp-challenge-1',
            emailHint: 'a***e@example.com',
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
