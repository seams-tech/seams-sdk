import { expect, test, type Page } from '@playwright/test';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  type EmailOtpEcdsaTempoHarness,
  type ReloadSignKind,
  runEmailOtpEcdsaTempoFlow,
  runEmailOtpReloadPhase,
  setupEmailOtpEcdsaTempoHarness,
} from '../helpers/emailOtpEcdsaTempoFlow';

async function readEmailOtpOutbox(args: {
  harness: EmailOtpEcdsaTempoHarness;
  accountId: string;
  challengeId: string;
  appSessionJwt: string;
}): Promise<string> {
  const response = await fetch(
    `${args.harness.baseUrl}/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(args.challengeId)}&walletId=${encodeURIComponent(args.accountId)}`,
    {
      headers: {
        Authorization: `Bearer ${args.appSessionJwt}`,
      },
    },
  );
  const json = (await response.json().catch(() => null)) as { otpCode?: unknown } | null;
  const otpCode = String(json?.otpCode || '').trim();
  if (!otpCode) {
    throw new Error(`missing Email OTP outbox code for ${args.challengeId}`);
  }
  return otpCode;
}

async function mountVisibleEmailOtpUnlockPrompt(
  page: Page,
  args: {
    harness: EmailOtpEcdsaTempoHarness;
    accountId: string;
    appSessionJwt: string;
  },
): Promise<void> {
  await page.evaluate(
    async ({
      relayerUrl,
      shamirPrimeB64u,
      signingSessionSealKeyVersion,
      accountId,
      appSessionJwt,
    }) => {
      await new Promise<void>((resolve, reject) => {
        if (document.querySelector('link[data-email-otp-ui-style="1"]')) {
          resolve();
          return;
        }
        const link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = '/sdk/esm/react/styles/styles.css';
        link.dataset.emailOtpUiStyle = '1';
        link.addEventListener('load', () => resolve());
        link.addEventListener('error', () => reject(new Error('Failed to load SDK React styles')));
        document.head.appendChild(link);
      });

      const mountId = 'email-otp-visible-unlock-mount';
      document.getElementById(mountId)?.remove();
      const mount = document.createElement('div');
      mount.id = mountId;
      document.body.appendChild(mount);

      const React = await import('react');
      const ReactDOMClient = await import('react-dom/client');
      const ReactDOM = await import('react-dom');
      const sdkMod = await import('/sdk/esm/index.js');
      const providerMod: any = await import('/sdk/esm/react/context/SeamsWebProvider.js');
      const menuMod: any =
        await import('/sdk/esm/react/components/PasskeyAuthMenu/public.js');

      const { SeamsWeb } = sdkMod as any;
      const Provider = providerMod.SeamsWebProvider || providerMod.default;
      const PasskeyAuthMenu = menuMod.PasskeyAuthMenu || menuMod.default;
      const AuthMenuMode = menuMod.AuthMenuMode;
      const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;
      const sdkConfig = {
        nearNetwork: 'testnet',
        nearRpcUrl: 'https://test.rpc.fastnear.com',
        relayerAccount: 'web3-authn-v4.testnet',
        relayer: {
          url: relayerUrl,
        },
        emailOtpAuthPolicy: 'session',
        signingSessionPersistenceMode: 'sealed_refresh_v1',
        signingSessionSeal: {
          keyVersion: signingSessionSealKeyVersion,
          shamirPrimeB64u,
        },
        ...(managedRegistration
          ? {
              registration: {
                mode: 'managed',
                environmentId: String(managedRegistration.environmentId || ''),
                publishableKey: String(managedRegistration.publishableKey || ''),
              },
            }
          : {}),
        iframeWallet: {
          walletOrigin: '',
          walletServicePath: '/wallet-service',
          sdkBasePath: '/sdk',
          rpIdOverride: 'example.localhost',
        },
      };
      const pm = new SeamsWeb(sdkConfig);
      await pm
        .getContext()
        .signingEngine.clearVolatileWarmSigningMaterial(toWalletId(accountId))
        .catch(() => undefined);

      (window as any).__emailOtpVisibleUnlock = {
        challengeId: '',
        submittedCode: '',
        loginSucceeded: false,
        loginWarmState: '',
        error: '',
      };

      const root = ReactDOMClient.createRoot(mount);
      ReactDOM.flushSync(() => {
        root.render(
          React.createElement(
            Provider,
            { config: sdkConfig },
            React.createElement(PasskeyAuthMenu, {
              defaultMode: AuthMenuMode.Login,
              socialLogin: {
                google: async () => {
                  const challenge = await pm.auth.requestEmailOtpChallenge({
                    nearAccountId: accountId,
                    relayUrl: relayerUrl,
                    appSessionJwt,
                  });
                  (window as any).__emailOtpVisibleUnlock.challengeId = String(
                    challenge.challengeId || '',
                  );
                  const emailHint = String(challenge.emailHint || 'alice@example.com');
                  return {
                    username: accountId,
                    otpPrompt: {
                      title: 'Check your email to unlock your wallet',
                      description: `Enter the 6-digit code we sent to ${emailHint}.`,
                      emailHint,
                      accountId,
                      submitLabel: 'Unlock wallet',
                      helperText:
                        'Google keeps you signed in. The email code unlocks wallet signing for this session.',
                      onSubmit: async (otpCode: string) => {
                        (window as any).__emailOtpVisibleUnlock.submittedCode = otpCode;
                        try {
                          const loginResult = await pm.auth.loginWithEmailOtpEcdsaCapability({
                            walletSession: {
                              walletId: accountId,
                              userId: accountId,
                            },
                            chainTarget: {
                              kind: 'tempo',
                              chainId: 42431,
                              networkSlug: 'tempo-moderato',
                            },
                            emailOtpAuthPolicy: 'session',
                            challengeId: String(challenge.challengeId || ''),
                            otpCode,
                            appSessionJwt,
                          });
                          (window as any).__emailOtpVisibleUnlock.loginSucceeded = true;
                          (window as any).__emailOtpVisibleUnlock.loginWarmState = String(
                            loginResult?.warmCapability?.state || loginResult?.state || 'ready',
                          );
                        } catch (error: unknown) {
                          (window as any).__emailOtpVisibleUnlock.error =
                            error && typeof error === 'object' && 'message' in error
                              ? String((error as { message?: unknown }).message || '')
                              : String(error || 'Email OTP UI unlock failed');
                          throw error;
                        }
                      },
                    },
                  };
                },
              },
            }),
          ),
        );
      });
    },
    {
      relayerUrl: args.harness.baseUrl,
      shamirPrimeB64u: args.harness.shamirPrimeB64u,
      signingSessionSealKeyVersion: args.harness.signingSessionSealKeyVersion,
      accountId: args.accountId,
      appSessionJwt: args.appSessionJwt,
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
      expect(result.emailOtpEnrollment?.enrollmentSealKeyVersion).toBeTruthy();
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
    } finally {
      await harness.close();
    }
  });

  test('visible Email OTP unlock prompt accepts the dev outbox code and unlocks signing', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpvisibleui${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        email: 'visible-email-otp@example.com',
        deviceId: 'email-otp-visible-ui-device',
      });

      const setupPhase = await runEmailOtpEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
        shamirPrimeB64u: harness.shamirPrimeB64u,
        accountId,
        enrollAppSessionJwt: appSessionJwt,
        loginAppSessionJwt: appSessionJwt,
        clientSecretB64u: harness.defaultClientSecretB64u,
        emailOtpAuthPolicy: 'session',
        signTwice: false,
      });

      expect(setupPhase.ok, `${setupPhase.error || ''}\n${JSON.stringify(setupPhase)}`).toBe(true);
      expect(setupPhase.ecdsaKeyBinding?.ecdsaThresholdKeyId).toBeTruthy();
      expect(setupPhase.ecdsaKeyBinding?.participantIds).toEqual([1, 2]);

      await mountVisibleEmailOtpUnlockPrompt(page, {
        harness,
        accountId,
        appSessionJwt,
      });

      const mount = page.locator('#email-otp-visible-unlock-mount');
      await mount.locator('.w3a-signup-menu-root:not(.w3a-skeleton)').waitFor({
        state: 'attached',
      });
      await mount.getByRole('button', { name: 'Sign in with Google SSO' }).click();
      await expect(mount.getByText('Check your email to unlock your wallet')).toBeVisible();
      await expect(mount.getByText(accountId)).toBeVisible();

      await expect
        .poll(async () =>
          page.evaluate(() => String((window as any).__emailOtpVisibleUnlock?.challengeId || '')),
        )
        .not.toBe('');
      const challengeId = await page.evaluate(() =>
        String((window as any).__emailOtpVisibleUnlock?.challengeId || ''),
      );
      const otpCode = await readEmailOtpOutbox({
        harness,
        accountId,
        appSessionJwt,
        challengeId,
      });

      await mount.getByLabel('Email code').fill(otpCode);
      await expect
        .poll(async () =>
          page.evaluate(() => String((window as any).__emailOtpVisibleUnlock?.submittedCode || '')),
        )
        .toBe(otpCode);
      await expect
        .poll(
          async () =>
            page.evaluate(() => Boolean((window as any).__emailOtpVisibleUnlock?.loginSucceeded)),
          { timeout: 30_000 },
        )
        .toBe(true);
      expect(
        await page.evaluate(() =>
          String((window as any).__emailOtpVisibleUnlock?.loginWarmState || ''),
        ),
      ).toBe('ready');
      await expect
        .poll(async () =>
          page.evaluate(() => String((window as any).__emailOtpVisibleUnlock?.error || '')),
        )
        .toBe('');
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
        signingSessionRemainingUses: 8,
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
      // Export prompts are fresh-auth scoped; they must not force the restored
      // transaction signing session into a false exhausted state.
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
      expect(
        reloadPhase.authPromptEvents
          ?.filter((event) => event.hasEmailOtpPrompt)
          .map((event) => event.method),
        JSON.stringify(reloadPhase.authPromptEvents || []),
      ).toEqual(['email_otp', 'email_otp']);
      expect(
        reloadPhase.authPromptEvents?.some((event) => event.method === 'passkey'),
        JSON.stringify(reloadPhase.authPromptEvents || []),
      ).toBe(false);
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
      expect(reloadPhase.results?.map((result) => [result.kind, result.ok, result.chain])).toEqual([
        ['evm', true, 'evm'],
      ]);
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

  test('post-exhaustion Email OTP signing succeeds on the first attempt with one prompt for Tempo and Arc/EVM', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    try {
      for (const signingCase of [
        { label: 'tempo', signingKind: 'tempoTransaction' as const, reloadKind: 'tempo' as const },
        { label: 'evm', signingKind: 'eip1559' as const, reloadKind: 'evm' as const },
      ]) {
        const accountId = `emailotpexhaust${signingCase.label}${Date.now()}.w3a-v1.testnet`;
        const appSessionJwt = await harness.mintAppSessionJwt({
          userId: accountId,
          deviceId: `email-otp-post-exhaustion-${signingCase.label}-device`,
        });

        const firstPhase = await runEmailOtpEcdsaTempoFlow(page, {
          relayerUrl: harness.baseUrl,
          shamirPrimeB64u: harness.shamirPrimeB64u,
          accountId,
          enrollAppSessionJwt: appSessionJwt,
          loginAppSessionJwt: appSessionJwt,
          clientSecretB64u: harness.defaultClientSecretB64u,
          emailOtpAuthPolicy: 'session',
          signingKind: signingCase.signingKind,
          signingSessionRemainingUses: 1,
          signTwice: true,
        });

        expect(
          firstPhase.ok,
          `${signingCase.label}: ${firstPhase.error || ''}\n${JSON.stringify(firstPhase)}`,
        ).toBe(true);
        expect(firstPhase.firstSign?.ok, firstPhase.firstSign?.error || '').toBe(true);
        expect(firstPhase.firstSign?.chain).toBe(signingCase.reloadKind);
        expect(firstPhase.secondSign?.ok, firstPhase.secondSign?.error || '').toBe(true);
        expect(firstPhase.secondSign?.chain).toBe(signingCase.reloadKind);
        expect(firstPhase.otpCounters?.signingChallengeCount).toBe(1);
        expect(firstPhase.webauthnCounters?.getCount).toBe(0);
      }
    } finally {
      await harness.close();
    }
  });

  test('Email OTP account matrix covers unlock, NEAR/Tempo signing, and Ed25519/ECDSA export', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpmatrix${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-account-matrix-device',
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
        exportNearWithResend: true,
        exportEcdsaWithResend: true,
      });

      expect(result.ok, `${result.error || ''}\n${JSON.stringify(result)}`).toBe(true);
      expect(result.emailOtpLogin?.warmState).toBe('ready');
      expect(result.nearSign?.ok, result.nearSign?.error || '').toBe(true);
      expect(result.nearSign?.signedCount).toBe(1);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('tempo');
      expect(result.secondSign?.ok, result.secondSign?.error || '').toBe(true);
      expect(result.secondSign?.chain).toBe('tempo');
      expect(result.exports?.near?.ok, result.exports?.near?.error || '').toBe(true);
      expect(result.exports?.near?.exportedSchemes).toContain('ed25519');
      expect(result.exports?.ecdsa?.ok, result.exports?.ecdsa?.error || '').toBe(true);
      expect(result.exports?.ecdsa?.exportedSchemes).toContain('secp256k1');
    } finally {
      await harness.close();
    }
  });

  test('Email OTP account matrix covers Arc/EVM signing', async ({ page }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    const accountId = `emailotpmatrixevm${Date.now()}.w3a-v1.testnet`;
    try {
      const appSessionJwt = await harness.mintAppSessionJwt({
        userId: accountId,
        deviceId: 'email-otp-account-matrix-evm-device',
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

      expect(result.ok, `${result.error || ''}\n${JSON.stringify(result)}`).toBe(true);
      expect(result.emailOtpLogin?.warmState).toBe('ready');
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('evm');
      expect(result.firstSign?.kind).toBe('eip1559');
      expect(result.secondSign?.ok, result.secondSign?.error || '').toBe(true);
      expect(result.secondSign?.chain).toBe('evm');
      expect(result.secondSign?.kind).toBe('eip1559');
    } finally {
      await harness.close();
    }
  });

  test('Email OTP lifecycle restores each signing curve after reload and prompts after exhaustion', async ({
    page,
  }) => {
    const harness = await setupEmailOtpEcdsaTempoHarness(page);
    try {
      const cases: Array<{
        label: 'near' | 'tempo';
        signKinds: ReloadSignKind[];
        signNearAfterLogin: boolean;
      }> = [
        {
          label: 'near',
          signKinds: ['near', 'near', 'near', 'near'],
          signNearAfterLogin: true,
        },
        {
          label: 'tempo',
          signKinds: ['tempo', 'tempo', 'tempo', 'tempo'],
          signNearAfterLogin: false,
        },
      ];

      for (const lifecycleCase of cases) {
        const accountId = `emailotplifecycle${lifecycleCase.label}${Date.now()}.w3a-v1.testnet`;
        const remainingUses = 4;
        const appSessionJwt = await harness.mintAppSessionJwt({
          userId: accountId,
          deviceId: `email-otp-lifecycle-${lifecycleCase.label}-device`,
        });

        const firstPhase = await runEmailOtpEcdsaTempoFlow(page, {
          relayerUrl: harness.baseUrl,
          shamirPrimeB64u: harness.shamirPrimeB64u,
          accountId,
          enrollAppSessionJwt: appSessionJwt,
          loginAppSessionJwt: appSessionJwt,
          clientSecretB64u: harness.defaultClientSecretB64u,
          emailOtpAuthPolicy: 'session',
          signingSessionRemainingUses: remainingUses,
          signTwice: false,
          signNearAfterLogin: lifecycleCase.signNearAfterLogin,
        });

        expect(
          firstPhase.ok,
          `${lifecycleCase.label}: ${firstPhase.error || ''}\n${JSON.stringify(firstPhase)}`,
        ).toBe(true);
        expect(firstPhase.firstSign?.ok, firstPhase.firstSign?.error || '').toBe(true);
        if (lifecycleCase.signNearAfterLogin) {
          expect(firstPhase.nearSign?.ok, firstPhase.nearSign?.error || '').toBe(true);
        }

        await page.reload();
        await page.waitForTimeout(300);

        const reloadPhase = await runEmailOtpReloadPhase(page, {
          harness,
          accountId,
          appSessionJwt,
          signKinds: lifecycleCase.signKinds,
        });

        expect(
          reloadPhase.ok,
          `${lifecycleCase.label}: ${reloadPhase.error || ''}\n${JSON.stringify(reloadPhase)}`,
        ).toBe(true);
        expect(reloadPhase.webauthnGetCount).toBe(0);

        const [firstRestoredSign, ...postRestoredSigns] = reloadPhase.results || [];
        expect(firstRestoredSign?.ok).toBe(true);
        expect(firstRestoredSign?.kind).toBe(lifecycleCase.label);
        expect(firstRestoredSign?.promptCountBefore).toBe(0);
        expect(firstRestoredSign?.promptCountAfter).toBe(0);
        expect(
          postRestoredSigns.some(
            (result) =>
              result.ok &&
              Number(result.promptCountAfter || 0) > Number(result.promptCountBefore || 0),
          ),
          `${lifecycleCase.label}: expected an Email OTP prompt after restored session exhaustion\n${JSON.stringify(reloadPhase)}`,
        ).toBe(true);
        expect(
          reloadPhase.authPromptEvents
            ?.filter((event) => event.hasEmailOtpPrompt)
            .every((event) => event.method === 'email_otp'),
          `${lifecycleCase.label}: expected Email OTP, not passkey, after exhaustion\n${JSON.stringify(
            reloadPhase.authPromptEvents || [],
          )}`,
        ).toBe(true);
      }
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

  test('per_operation Email OTP login prompts for fresh OTP before each Tempo sign', async ({
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
      expect(result.otpCounters?.signingChallengeCount).toBe(2);
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('tempo');
      expect(result.firstSign?.kind).toBe('tempoTransaction');
      expect(result.secondSign?.ok, result.secondSign?.error || '').toBe(true);
      expect(result.secondSign?.chain).toBe('tempo');
      expect(result.secondSign?.kind).toBe('tempoTransaction');
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

  test('per_operation Email OTP also prompts for fresh OTP before each EVM eip1559 sign', async ({
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
      expect(result.otpCounters?.signingChallengeCount).toBe(2);
      expect(result.webauthnCounters?.createCount).toBe(0);
      expect(result.webauthnCounters?.getCount).toBe(0);
      expect(result.firstSign?.ok, result.firstSign?.error || '').toBe(true);
      expect(result.firstSign?.chain).toBe('evm');
      expect(result.firstSign?.kind).toBe('eip1559');
      expect(result.secondSign?.ok, result.secondSign?.error || '').toBe(true);
      expect(result.secondSign?.chain).toBe('evm');
      expect(result.secondSign?.kind).toBe('eip1559');
    } finally {
      await harness.close();
    }
  });
});
