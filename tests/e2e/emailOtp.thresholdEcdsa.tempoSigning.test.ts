import { expect, test } from '@playwright/test';
import {
  type EmailOtpEcdsaTempoHarness,
  runEmailOtpEcdsaTempoFlow,
  setupEmailOtpEcdsaTempoHarness,
} from '../helpers/emailOtpEcdsaTempoFlow';

type ReloadSignKind = 'near' | 'tempo' | 'evm' | 'exportNear' | 'exportEcdsa';

async function runEmailOtpReloadPhase(
  page: import('@playwright/test').Page,
  args: {
    harness: EmailOtpEcdsaTempoHarness;
    accountId: string;
    appSessionJwt: string;
    signKinds: ReloadSignKind[];
    signAfterExports?: 'tempo' | 'evm';
    rememberAppSessionJwt?: boolean;
  },
): Promise<{
  ok: boolean;
  sessionStatus?: string;
  results?: Array<{ kind: string; ok: boolean; chain?: string; error?: string }>;
  emailOtpPromptCount?: number;
  webauthnGetCount?: number;
  promptCountBeforeExports?: number;
  promptCountAfterExports?: number;
  promptCountAfterFinalSign?: number;
  error?: string;
}> {
  return await page.evaluate(
    async ({
      relayerUrl,
      shamirPrimeB64u,
      signingSessionSealKeyVersion,
      accountId,
      appSessionJwt,
      signKinds,
      signAfterExports,
      rememberAppSessionJwt,
    }) => {
      const sdkMod = await import('/sdk/esm/index.js');
      const actionsMod = await import('/sdk/esm/core/types/actions.js');
      const { TatchiPasskey } = sdkMod as any;
      const { ActionType } = actionsMod as any;

      const joinUrl = (base: string, path: string): string =>
        `${String(base || '').replace(/\/+$/, '')}/${String(path || '').replace(/^\/+/, '')}`;
      const readEmailOtpOutbox = async (challengeIdRaw: string): Promise<string> => {
        const challengeId = String(challengeIdRaw || '').trim();
        if (!challengeId) throw new Error('missing Email OTP challengeId for reload phase');
        const outbox = await fetch(
          `${joinUrl(relayerUrl, '/wallet/email-otp/dev/otp-outbox')}?challengeId=${encodeURIComponent(challengeId)}&walletId=${encodeURIComponent(accountId)}`,
          {
            headers: appSessionJwt ? { Authorization: `Bearer ${appSessionJwt}` } : undefined,
          },
        );
        const outboxJson = await outbox.json().catch(() => ({}));
        const otpCode = String(outboxJson?.otpCode || '').trim();
        if (!otpCode) throw new Error(`missing Email OTP test outbox entry for ${challengeId}`);
        return otpCode;
      };

      const confirmationConfig = {
        uiMode: 'none' as const,
        behavior: 'skipClick' as const,
        autoProceedDelay: 0,
      };
      const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;
      const webauthnState = { getCount: 0 };
      const originalCredentialsGet = globalThis.navigator?.credentials?.get?.bind(
        globalThis.navigator.credentials,
      );
      if (globalThis.navigator?.credentials && originalCredentialsGet) {
        globalThis.navigator.credentials.get = (async (...credentialArgs: unknown[]) => {
          webauthnState.getCount += 1;
          return await originalCredentialsGet(...(credentialArgs as [CredentialRequestOptions]));
        }) as CredentialsContainer['get'];
      }

      try {
        const pm = new TatchiPasskey({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayerAccount: 'web3-authn-v4.testnet',
          relayer: {
            url: relayerUrl,
            smartAccountDeploymentMode: 'observe',
          },
          ...(managedRegistration
            ? {
                registration: {
                  mode: 'managed' as const,
                  environmentId: String(managedRegistration.environmentId || ''),
                  publishableKey: String(managedRegistration.publishableKey || ''),
                },
              }
            : {}),
          emailOtpAuthPolicy: 'session' as const,
          signingSessionPersistenceMode: 'sealed_refresh_v1' as const,
          signingSessionSeal: {
            keyVersion: signingSessionSealKeyVersion,
            shamirPrimeB64u,
          },
          iframeWallet: {
            walletOrigin: '',
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
            rpIdOverride: 'example.localhost',
          },
        });
        pm.setConfirmationConfig(confirmationConfig as any);

        const signingEngine = pm.getContext().signingEngine as any;
        if (
          rememberAppSessionJwt !== false &&
          appSessionJwt &&
          typeof signingEngine?.emailOtpSessions?.rememberAppSessionJwt === 'function'
        ) {
          signingEngine.emailOtpSessions.rememberAppSessionJwt({
            nearAccountId: accountId,
            appSessionJwt,
          });
        }
        const originalRequestUserConfirmation =
          typeof signingEngine?.touchConfirm?.requestUserConfirmation === 'function'
            ? signingEngine.touchConfirm.requestUserConfirmation.bind(signingEngine.touchConfirm)
            : null;
        let emailOtpPromptCount = 0;
        if (originalRequestUserConfirmation) {
          signingEngine.touchConfirm.requestUserConfirmation = async (
            request: Record<string, any>,
            requestOptions?: Record<string, any>,
          ) => {
            const requestType = String(request?.type || '');
            if (requestType === 'showSecurePrivateKeyUi') {
              return { confirmed: true };
            }
            const prompt =
              request?.payload?.signingAuthPlan?.emailOtpPrompt || request?.payload?.emailOtpPrompt;
            if (prompt) {
              emailOtpPromptCount += 1;
              const challengeId = String(prompt.challengeId || '').trim();
              const otpCode = await readEmailOtpOutbox(challengeId);
              return {
                requestId: String(request?.requestId || ''),
                confirmed: true,
                otpCode,
                emailOtpChallengeId: challengeId,
                ...(request?.intentDigest ? { intentDigest: request.intentDigest } : {}),
              };
            }
            return await originalRequestUserConfirmation(request as any, requestOptions as any);
          };
        }

        const tempoRequest = (tag: string) => ({
          chain: 'tempo' as const,
          kind: 'tempoTransaction' as const,
          senderSignatureAlgorithm: 'secp256k1' as const,
          tx: {
            chainId: 42431,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 21_000n,
            calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: `0x${tag}` }],
            accessList: [],
            nonceKey: 0n,
            validBefore: null,
            validAfter: null,
            feePayerSignature: { kind: 'none' as const },
            aaAuthorizationList: [],
          },
        });
        const evmRequest = (tag: string) => ({
          chain: 'evm' as const,
          kind: 'eip1559' as const,
          senderSignatureAlgorithm: 'secp256k1' as const,
          tx: {
            chainId: 11155111,
            maxPriorityFeePerGas: 1_500_000_000n,
            maxFeePerGas: 3_000_000_000n,
            gasLimit: 21_000n,
            to: '0x' + '22'.repeat(20),
            value: BigInt(`1234${tag.length}`),
            data: `0x${tag}`,
            accessList: [],
          },
        });

        const results: Array<{ kind: string; ok: boolean; chain?: string; error?: string }> = [];
        const signOne = async (kind: ReloadSignKind, tag: string) => {
          try {
            if (kind === 'near') {
              const signed = await pm.near.signTransactionsWithActions({
                nearAccountId: accountId,
                transactions: [
                  {
                    receiverId: 'w3a-v1.testnet',
                    actions: [{ type: ActionType.Transfer, amount: '1' }],
                  },
                ],
                options: { confirmationConfig },
              });
              results.push({
                kind,
                ok: Array.isArray(signed) && signed.length === 1,
                chain: 'near',
              });
              return;
            }
            if (kind === 'tempo') {
              const signed = await pm.tempo.signTempo({
                nearAccountId: accountId,
                request: tempoRequest(tag),
                options: { confirmationConfig },
              });
              results.push({ kind, ok: signed?.kind === 'tempoTransaction', chain: signed?.chain });
              return;
            }
            if (kind === 'evm') {
              const signed = await pm.tempo.signTempo({
                nearAccountId: accountId,
                request: evmRequest(tag),
                options: { confirmationConfig },
              });
              results.push({ kind, ok: signed?.kind === 'eip1559', chain: signed?.chain });
              return;
            }
            if (kind === 'exportNear') {
              const exported = await pm.keys.exportKeypairWithUI(accountId, {
                chain: 'near',
                variant: 'drawer',
              });
              results.push({
                kind,
                ok: Array.isArray(exported?.exportedSchemes)
                  ? exported.exportedSchemes.includes('ed25519')
                  : true,
                chain: 'near',
              });
              return;
            }
            if (kind === 'exportEcdsa') {
              const exported = await pm.keys.exportKeypairWithUI(accountId, {
                chain: 'tempo',
                variant: 'drawer',
              });
              results.push({
                kind,
                ok: Array.isArray(exported?.exportedSchemes)
                  ? exported.exportedSchemes.includes('secp256k1')
                  : true,
                chain: 'tempo',
              });
            }
          } catch (error: unknown) {
            results.push({
              kind,
              ok: false,
              error:
                error && typeof error === 'object' && 'message' in error
                  ? String((error as { message?: unknown }).message || '')
                  : String(error || `${kind} failed`),
            });
          }
        };

        let promptCountBeforeExports: number | null = null;
        for (const [index, kind] of signKinds.entries()) {
          if (
            promptCountBeforeExports == null &&
            (kind === 'exportNear' || kind === 'exportEcdsa')
          ) {
            promptCountBeforeExports = emailOtpPromptCount;
          }
          await signOne(kind as ReloadSignKind, `a${index + 1}`);
        }
        const promptCountAfterExports = emailOtpPromptCount;
        if (signAfterExports === 'tempo') {
          await signOne('tempo', 'af');
        } else if (signAfterExports === 'evm') {
          await signOne('evm', 'af');
        }

        const session = await pm.auth.getWalletSession(accountId);
        return {
          ok: results.every((result) => result.ok),
          sessionStatus: String(session?.signingSession?.status || ''),
          results,
          emailOtpPromptCount,
          webauthnGetCount: webauthnState.getCount,
          promptCountBeforeExports: promptCountBeforeExports ?? emailOtpPromptCount,
          promptCountAfterExports,
          promptCountAfterFinalSign: emailOtpPromptCount,
        };
      } catch (error: unknown) {
        return {
          ok: false,
          error:
            error && typeof error === 'object' && 'message' in error
              ? String((error as { message?: unknown }).message || '')
              : String(error || 'reload phase failed'),
        };
      }
    },
    {
      relayerUrl: args.harness.baseUrl,
      shamirPrimeB64u: args.harness.shamirPrimeB64u,
      signingSessionSealKeyVersion: args.harness.signingSessionSealKeyVersion,
      accountId: args.accountId,
      appSessionJwt: args.appSessionJwt,
      signKinds: args.signKinds,
      signAfterExports: args.signAfterExports,
      rememberAppSessionJwt: args.rememberAppSessionJwt,
    },
  );
}

test.describe('Email OTP threshold-ecdsa tempo signing', () => {
  test.setTimeout(180_000);

  test('session-mode Email OTP login bootstraps warm ECDSA capability and signs twice', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpsession${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-enroll-device',
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signTwice: true,
        signNearAfterLogin: true,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.registration?.success).toBe(true);
      expect(result.ecdsaKeyBinding?.ecdsaThresholdKeyId).toBeTruthy();
      expect(result.ecdsaKeyBinding?.participantIds).toEqual([1, 2]);
      expect(result.emailOtpEnrollment?.challengeId).toBeTruthy();
      expect(result.emailOtpEnrollment?.emailOtpKeyVersion).toBeTruthy();
      expect(result.emailOtpLogin?.policy).toBe('session');
      expect(result.emailOtpLogin?.retention).toBe('session');
      expect(result.emailOtpLogin?.warmState).toBe('ready');
      expect(result.otpCounters?.enrollChallengeCount).toBe(1);
      expect(result.otpCounters?.loginChallengeCount).toBe(1);
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('tempo');
      expect(result.firstSign?.kind).toBe('tempoTransaction');
      expect(result.firstSign?.rawTxHex?.startsWith('0x')).toBe(true);
      expect(result.secondSign?.ok, result.secondSign?.error || '').toBe(true);
      expect(result.secondSign?.chain).toBe('tempo');
      expect(result.secondSign?.kind).toBe('tempoTransaction');
      expect(result.secondSign?.rawTxHex?.startsWith('0x')).toBe(true);
      expect(result.nearSign?.ok, result.nearSign?.error || '').toBe(true);
      expect(result.nearSign?.signedCount).toBe(1);
      expect(result.nearSign?.signerId).toBe(accountId);
      expect(result.nearSign?.receiverId).toBe('w3a-v1.testnet');
    } finally {
      await harness.close();
    }
  });

  test('session-mode Email OTP reload signs NEAR and Tempo without another OTP, while export stays fresh-OTP scoped', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpreloadnt${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-reload-near-tempo-device',
      });

      const firstPhase = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signTwice: false,
        signNearAfterLogin: true,
      });

      expect(firstPhase.ok, `${firstPhase.error || ''}\n${JSON.stringify(firstPhase)}`).toBe(true);
      expect(firstPhase.emailOtpLogin?.retention).toBe('session');
      expect(firstPhase.firstSign?.ok, firstPhase.firstSign?.error || '').toBe(true);
      expect(firstPhase.nearSign?.ok, firstPhase.nearSign?.error || '').toBe(true);

      await page.reload();
      await page.waitForTimeout(300);

      const reloadPhase = await runEmailOtpReloadPhase(page, {
        harness,
        accountId,
        appSessionJwt,
        signKinds: ['near', 'tempo', 'exportNear', 'exportEcdsa'],
        signAfterExports: 'tempo',
        rememberAppSessionJwt: false,
      });

      expect(reloadPhase.ok, `${reloadPhase.error || ''}\n${JSON.stringify(reloadPhase)}`).toBe(
        true,
      );
      expect(reloadPhase.sessionStatus).toBe('active');
      expect(reloadPhase.results?.map((result) => [result.kind, result.ok, result.chain])).toEqual([
        ['near', true, 'near'],
        ['tempo', true, 'tempo'],
        ['exportNear', true, 'near'],
        ['exportEcdsa', true, 'tempo'],
        ['tempo', true, 'tempo'],
      ]);
      expect(reloadPhase.promptCountBeforeExports).toBe(0);
      expect(reloadPhase.promptCountAfterExports).toBeGreaterThan(0);
      expect(reloadPhase.promptCountAfterFinalSign).toBe(reloadPhase.promptCountAfterExports);
      expect(reloadPhase.webauthnGetCount).toBe(0);
    } finally {
      await harness.close();
    }
  });

  test('Google SSO Email OTP reload signs normal EVM transactions without another OTP', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const nonce = Date.now();
    const accountId = `emailotpreloadevm${nonce}.w3a-v1.testnet`;
    const googleSubject = `google:e2e-email-otp-reload-evm-${nonce}`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: googleSubject,
        walletId: accountId,
        email: `email-otp-reload-evm-${nonce}@example.com`,
        deviceId: 'google-sso-email-otp-reload-evm-device',
      });

      const firstPhase = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signingKind: 'eip1559',
        signTwice: false,
      });

      expect(firstPhase.ok, `${firstPhase.error || ''}\n${JSON.stringify(firstPhase)}`).toBe(true);
      expect(firstPhase.emailOtpLogin?.retention).toBe('session');
      expect(firstPhase.firstSign?.ok, firstPhase.firstSign?.error || '').toBe(true);
      expect(firstPhase.firstSign?.chain).toBe('evm');

      await page.reload();
      await page.waitForTimeout(300);

      const reloadPhase = await runEmailOtpReloadPhase(page, {
        harness,
        accountId,
        appSessionJwt,
        signKinds: ['evm'],
      });

      expect(reloadPhase.ok, `${reloadPhase.error || ''}\n${JSON.stringify(reloadPhase)}`).toBe(
        true,
      );
      expect(reloadPhase.sessionStatus).toBe('active');
      expect(reloadPhase.results).toEqual([{ kind: 'evm', ok: true, chain: 'evm' }]);
      expect(reloadPhase.emailOtpPromptCount).toBe(0);
      expect(reloadPhase.webauthnGetCount).toBe(0);
    } finally {
      await harness.close();
    }
  });

  test('Email OTP reload prompts OTP after restored session exhaustion', async ({ page }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpexhaustreload${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-reload-exhaustion-device',
      });

      const firstPhase = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signingSessionRemainingUses: 2,
        signTwice: false,
      });

      expect(firstPhase.ok, `${firstPhase.error || ''}\n${JSON.stringify(firstPhase)}`).toBe(true);
      expect(firstPhase.emailOtpLogin?.retention).toBe('session');
      expect(firstPhase.firstSign?.ok, firstPhase.firstSign?.error || '').toBe(true);

      await page.reload();
      await page.waitForTimeout(300);

      const reloadPhase = await runEmailOtpReloadPhase(page, {
        harness,
        accountId,
        appSessionJwt,
        signKinds: ['tempo', 'tempo'],
      });

      expect(reloadPhase.ok, `${reloadPhase.error || ''}\n${JSON.stringify(reloadPhase)}`).toBe(
        true,
      );
      expect(reloadPhase.results?.map((result) => [result.kind, result.ok, result.chain])).toEqual([
        ['tempo', true, 'tempo'],
        ['tempo', true, 'tempo'],
      ]);
      expect(reloadPhase.emailOtpPromptCount).toBeGreaterThan(0);
      expect(reloadPhase.webauthnGetCount).toBe(0);
    } finally {
      await harness.close();
    }
  });

  test('session-mode Email OTP login accepts a resent unlock code before signing', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpresend${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-resend-device',
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signTwice: false,
        resendLoginOtpBeforeSubmit: true,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('session');
      expect(result.emailOtpLogin?.retention).toBe('session');
      expect(result.emailOtpLogin?.warmState).toBe('ready');
      expect(result.otpCounters?.enrollChallengeCount).toBe(1);
      expect(result.otpCounters?.loginChallengeCount).toBe(2);
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('tempo');
    } finally {
      await harness.close();
    }
  });

  test('Google SSO Email OTP lifecycle signs and exports Ed25519/ECDSA with resend', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const nonce = Date.now();
    const accountId = `googlessootp${nonce}.w3a-v1.testnet`;
    const googleSubject = `google:e2e-email-otp-${nonce}`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: googleSubject,
        walletId: accountId,
        email: `email-otp-e2e-${nonce}@example.com`,
        deviceId: 'google-sso-email-otp-device',
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signingKind: 'eip1559',
        signTwice: true,
        signNearAfterLogin: true,
        exportNearWithResend: true,
        exportEcdsaWithResend: true,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.registration?.success).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('session');
      expect(result.emailOtpLogin?.retention).toBe('session');
      expect(result.emailOtpLogin?.warmState).toBe('ready');
      expect(result.otpCounters?.enrollChallengeCount).toBe(1);
      expect(result.otpCounters?.loginChallengeCount).toBe(1);
      expect(result.otpCounters?.exportChallengeCount).toBe(4);
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('evm');
      expect(result.firstSign?.kind).toBe('eip1559');
      expect(result.secondSign?.ok, result.secondSign?.error || '').toBe(true);
      expect(result.secondSign?.chain).toBe('evm');
      expect(result.nearSign?.ok, result.nearSign?.error || '').toBe(true);
      expect(result.nearSign?.signerId).toBe(accountId);
      expect(result.exports?.near?.ok, result.exports?.near?.error || '').toBe(true);
      expect(result.exports?.near?.exportedSchemes).toEqual(['ed25519']);
      expect(result.exports?.ecdsa?.ok, result.exports?.ecdsa?.error || '').toBe(true);
      expect(result.exports?.ecdsa?.exportedSchemes).toEqual(['secp256k1']);
    } finally {
      await harness.close();
    }
  });

  test('Google SSO Email OTP lifecycle signs Tempo transactions', async ({ page }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const nonce = Date.now();
    const accountId = `googlessotempo${nonce}.w3a-v1.testnet`;
    const googleSubject = `google:e2e-email-otp-tempo-${nonce}`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: googleSubject,
        walletId: accountId,
        email: `email-otp-tempo-e2e-${nonce}@example.com`,
        deviceId: 'google-sso-email-otp-tempo-device',
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signTwice: false,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.registration?.success).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('session');
      expect(result.emailOtpLogin?.retention).toBe('session');
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('tempo');
      expect(result.firstSign?.kind).toBe('tempoTransaction');
    } finally {
      await harness.close();
    }
  });

  test('per_operation Email OTP login signs once and then requires fresh OTP before the next sign', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpperop${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-enroll-device',
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'per_operation',
        signTwice: true,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('per_operation');
      expect(result.emailOtpLogin?.retention).toBe('single_use');
      expect(result.emailOtpLogin?.warmState).toBe('ready');
      expect(result.otpCounters?.enrollChallengeCount).toBe(1);
      expect(result.otpCounters?.loginChallengeCount).toBe(1);
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('tempo');
      expect(result.firstSign?.kind).toBe('tempoTransaction');
      expect(result.secondSign?.ok, JSON.stringify(result)).toBe(false);
      expect(String(result.secondSign?.error || '')).toContain(
        'requires fresh Email OTP verification with per_operation policy',
      );
    } finally {
      await harness.close();
    }
  });

  test('session-mode Email OTP login also signs normal EVM eip1559 transactions', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpevm${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-evm-device',
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signingKind: 'eip1559',
        signTwice: true,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('session');
      expect(result.emailOtpLogin?.retention).toBe('session');
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('evm');
      expect(result.firstSign?.kind).toBe('eip1559');
      expect(result.firstSign?.rawTxHex?.startsWith('0x')).toBe(true);
      expect(result.secondSign?.ok, result.secondSign?.error || '').toBe(true);
      expect(result.secondSign?.chain).toBe('evm');
      expect(result.secondSign?.kind).toBe('eip1559');
      expect(result.secondSign?.rawTxHex?.startsWith('0x')).toBe(true);
    } finally {
      await harness.close();
    }
  });

  test('per_operation Email OTP also forces a fresh OTP before a second EVM eip1559 sign', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpevmpop${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-evm-perop-device',
      });

      const result = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'per_operation',
        signingKind: 'eip1559',
        signTwice: true,
      });

      const failureContext = result.ok
        ? result
        : {
            result,
            enrollment: await harness.readEmailOtpEnrollment(accountId),
          };
      expect(result.ok, `${result.error || ''}\n${JSON.stringify(failureContext)}`).toBe(true);
      expect(result.emailOtpLogin?.policy).toBe('per_operation');
      expect(result.emailOtpLogin?.retention).toBe('single_use');
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('evm');
      expect(result.firstSign?.kind).toBe('eip1559');
      expect(result.secondSign?.ok).toBe(false);
      expect(String(result.secondSign?.error || '')).toContain(
        'requires fresh Email OTP verification with per_operation policy',
      );
    } finally {
      await harness.close();
    }
  });
});
