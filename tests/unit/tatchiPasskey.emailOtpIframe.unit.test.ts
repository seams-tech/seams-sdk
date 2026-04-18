import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute } from '../wallet-iframe/harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';

const WALLET_STUB_EMAIL_OTP_SCRIPT = String.raw`
  window.__emailOtpMessages = [];
  const walletMetadataKey = 'test-email-otp-wallet-account-id';
  let warmCapabilityActive = false;

  const sanitizePayload = (payload) => {
    if (Array.isArray(payload)) return payload.map((entry) => sanitizePayload(entry));
    if (!payload || typeof payload !== 'object') return payload;
    if (payload instanceof Uint8Array) {
      return { kind: 'Uint8Array', length: payload.byteLength };
    }
    if (payload instanceof ArrayBuffer) {
      return { kind: 'ArrayBuffer', length: payload.byteLength };
    }
    const out = {};
    for (const [key, value] of Object.entries(payload)) {
      out[key] = typeof value === 'bigint' ? value.toString() : sanitizePayload(value);
    }
    return out;
  };

  const rememberAccount = (nearAccountId) => {
    if (!nearAccountId) return;
    try {
      localStorage.setItem(walletMetadataKey, nearAccountId);
    } catch {}
  };

  const activeSessionFor = (nearAccountId) => {
    const accountId = nearAccountId || (() => {
      try {
        return localStorage.getItem(walletMetadataKey) || '';
      } catch {
        return '';
      }
    })();
    return {
      login: {
        isLoggedIn: !!accountId,
        nearAccountId: accountId || null,
        publicKey: null,
        userData: null,
        authMethod: accountId && warmCapabilityActive ? 'email_otp' : null,
      },
      signingSession: accountId && warmCapabilityActive
        ? {
          status: 'active',
          sessionId: 'email-otp-session-1',
          authMethod: 'email_otp',
          retention: 'session',
          thresholdEcdsa: {
            evm: { state: 'ready', sessionId: 'email-otp-session-1' },
            tempo: { state: 'ready', sessionId: 'email-otp-session-1' },
          },
        }
        : null,
      authMethod: accountId && warmCapabilityActive ? 'email_otp' : null,
      retention: accountId && warmCapabilityActive ? 'session' : null,
    };
  };

  const secretSentinel = 'email-otp-secret-must-not-cross-app-origin';

  const loginRecovery = {
    loginGrant: 'grant-1',
    challengeId: 'challenge-1',
    emailOtpKeyVersion: 'email-otp-kv-1',
    unlockChallengeId: 'unlock-challenge-1',
    unlockChallengeB64u: 'unlock-challenge-b64u',
    unlockPublicKeyB64u: 'unlock-public-key-b64u',
    unlockSignatureB64u: 'unlock-signature-b64u',
    recoveredSB64u: secretSentinel,
    clientRootShare32B64u: secretSentinel,
  };

  const bootstrapResult = {
    thresholdEcdsaKeyRef: {
      thresholdSessionId: 'threshold-session-1',
      thresholdPublicKeyB64u: 'threshold-public-key-b64u',
      thresholdPublicKeyHex: '02' + '11'.repeat(32),
      backendBinding: {
        relayerKeyId: 'relayer-key-1',
        clientVerifyingShareB64u: 'public-verifier-b64u',
        clientAdditiveShare32B64u: secretSentinel,
        clientAdditiveShareHandle: {
          kind: 'email_otp_worker_session',
          sessionId: 'email-otp-session-1',
        },
      },
    },
    thresholdEcdsaSession: {
      sessionId: 'threshold-session-1',
      kind: 'cookie',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 3,
    },
    keygen: {
      clientAdditiveShare32B64u: secretSentinel,
      clientRootShare32B64u: secretSentinel,
    },
  };

  const warmCapability = {
    capability: 'ecdsa',
    chain: 'evm',
    record: null,
    auth: null,
    prfClaim: null,
    state: 'ready',
  };

  const originalAdoptPort = adoptPort;
  adoptPort = function patchedAdoptPort(port) {
    originalAdoptPort(port);
    if (!adoptedPort) return;

    const originalHandler = adoptedPort.onmessage;
    adoptedPort.onmessage = (event) => {
      originalHandler?.(event);
      const data = event.data || {};
      if (!data || typeof data !== 'object') return;
      if (typeof data.type === 'string') {
        window.__emailOtpMessages.push({
          type: data.type,
          payload: sanitizePayload(data.payload),
        });
      }

      const requestId = data.requestId;
      if (typeof requestId !== 'string') return;

      const respond = (result) => {
        try {
          pendingRequests.delete(requestId);
          adoptedPort.postMessage({ type: 'PM_RESULT', requestId, payload: { ok: true, result } });
        } catch (err) {
          console.error('post PM_RESULT failed', err);
        }
      };
      const reject = (code, message) => {
        try {
          pendingRequests.delete(requestId);
          adoptedPort.postMessage({ type: 'ERROR', requestId, payload: { code, message } });
        } catch (err) {
          console.error('post ERROR failed', err);
        }
      };

      if (data.type === 'PM_SET_CONFIG') {
        respond(null);
      }
      if (data.type === 'PM_PREFETCH_BLOCKHEIGHT') {
        respond(null);
      }
      if (data.type === 'PM_GET_CONFIRMATION_CONFIG') {
        respond({ behavior: 'requireClick', uiMode: 'modal' });
      }
      if (data.type === 'PM_GET_WALLET_SESSION') {
        respond(activeSessionFor(data.payload?.nearAccountId || null));
      }
      if (data.type === 'PM_REQUEST_EMAIL_OTP_CHALLENGE') {
        respond({ challengeId: 'challenge-1', otpChannel: 'email_otp' });
      }
      if (data.type === 'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE') {
        respond({ challengeId: 'enrollment-challenge-1', otpChannel: 'email_otp' });
      }
      if (data.type === 'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION') {
        respond({
          session: {
            userId: 'google:subject-1',
            walletId: 'alice.testnet',
            email: 'alice@example.com',
          },
        });
      }
      if (data.type === 'PM_ENROLL_EMAIL_OTP') {
        rememberAccount(data.payload?.nearAccountId || '');
        respond({
          thresholdEcdsaClientVerifyingShareB64u: 'threshold-verifier-b64u',
          challengeId: 'enrollment-challenge-1',
          otpChannel: 'email_otp',
          emailOtpKeyVersion: 'email-otp-kv-1',
          unlockPublicKeyB64u: 'unlock-public-key-b64u',
          unlockKeyVersion: 'unlock-kv-1',
          clientRootShare32B64u: secretSentinel,
          clientSecret32: secretSentinel,
        });
      }
      if (data.type === 'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY') {
        rememberAccount(data.payload?.nearAccountId || '');
        warmCapabilityActive = true;
        respond({ recovery: loginRecovery, bootstrap: bootstrapResult, warmCapability });
      }
      if (data.type === 'PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY') {
        rememberAccount(data.payload?.nearAccountId || '');
        warmCapabilityActive = true;
        respond({
          enrollment: {
            thresholdEcdsaClientVerifyingShareB64u: 'threshold-verifier-b64u',
            challengeId: 'enrollment-challenge-1',
            otpChannel: 'email_otp',
            emailOtpKeyVersion: 'email-otp-kv-1',
            unlockPublicKeyB64u: 'unlock-public-key-b64u',
            unlockKeyVersion: 'unlock-kv-1',
            clientRootShare32B64u: secretSentinel,
            clientSecret32: secretSentinel,
          },
          bootstrap: bootstrapResult,
          warmCapability,
        });
      }
      if (data.type === 'PM_SIGN_TEMPO') {
        if (!warmCapabilityActive) {
          reject('threshold_ecdsa_session_not_ready', 'Fresh Email OTP verification required');
          return;
        }
        respond({
          chain: data.payload?.request?.chain || 'evm',
          kind: data.payload?.request?.kind || 'eip1559',
          txHashHex: '0x' + 'ab'.repeat(32),
          rawTxHex: data.payload?.request?.chain === 'tempo' ? '0x76' : '0x02',
        });
      }
      if (data.type === 'PM_SIGN_TXS_WITH_ACTIONS') {
        if (!warmCapabilityActive) {
          reject('threshold_ed25519_session_not_ready', 'Fresh Email OTP verification required');
          return;
        }
        respond([
          {
            nearAccountId: data.payload?.nearAccountId || 'alice.testnet',
            logs: ['signed-by-wallet-origin-email-otp'],
          },
        ]);
      }
    };
  };
`;

test.describe('TatchiPasskey Email OTP wallet iframe ownership', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    await registerWalletServiceRoute(
      page,
      buildWalletServiceHtml({ extraScript: WALLET_STUB_EMAIL_OTP_SCRIPT }),
      WALLET_SERVICE_ROUTE,
    );
  });

  test.afterEach(async ({ page }) => {
    await page.unroute(WALLET_SERVICE_ROUTE).catch(() => {});
    await page.unroute(WALLET_SERVICE_ROUTE.replace('wallet-service', 'service')).catch(() => {});
  });

  test('routes Email OTP challenge, enrollment, and ECDSA bootstrap through the wallet iframe', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ walletOrigin }) => {
        const mod = await import('/sdk/esm/core/TatchiPasskey/index.js');
        const { TatchiPasskey } = mod as any;
        const nearAccountId = 'alice.testnet';
        const pm = new TatchiPasskey({
          relayer: { url: 'https://relay.example' },
          signingSessionSeal: {
            keyVersion: 'email-otp-test-seal',
            shamirPrimeB64u: '_____________________________________v___C8',
          },
          iframeWallet: {
            walletOrigin,
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
          },
        });

        const challenge = await pm.auth.requestEmailOtpChallenge({
          nearAccountId,
          appSessionJwt: 'app-session-jwt',
        });
        const enrollmentChallenge = await pm.auth.requestEmailOtpEnrollmentChallenge({
          nearAccountId,
          appSessionJwt: 'app-session-jwt',
        });
        const sessionExchange = await pm.auth.exchangeGoogleEmailOtpSession({
          idToken: 'google-id-token-1',
          accountMode: 'register',
          sessionKind: 'cookie',
        });
        const enrollment = await pm.auth.enrollEmailOtp({
          nearAccountId,
          challengeId: enrollmentChallenge.challengeId,
          otpCode: '123456',
          appSessionJwt: 'app-session-jwt',
        });
        const login = await pm.auth.loginWithEmailOtpEcdsaCapability({
          nearAccountId,
          chain: 'evm',
          emailOtpAuthPolicy: 'session',
          challengeId: challenge.challengeId,
          otpCode: '123456',
          appSessionJwt: 'app-session-jwt',
          sessionKind: 'cookie',
          ecdsaThresholdKeyId: 'threshold-key-1',
          participantIds: [1, 2],
        });
        const perOperationLogin = await pm.auth.loginWithEmailOtpEcdsaCapability({
          nearAccountId,
          chain: 'evm',
          emailOtpAuthPolicy: 'per_operation',
          challengeId: challenge.challengeId,
          otpCode: '123456',
          appSessionJwt: 'app-session-jwt',
          sessionKind: 'cookie',
          ecdsaThresholdKeyId: 'threshold-key-1',
          participantIds: [1, 2],
        });
        const enrollAndLogin = await pm.auth.enrollAndLoginWithEmailOtpEcdsaCapability({
          nearAccountId,
          chain: 'evm',
          emailOtpAuthPolicy: 'session',
          challengeId: enrollmentChallenge.challengeId,
          otpCode: '123456',
          appSessionJwt: 'app-session-jwt',
          sessionKind: 'cookie',
          ecdsaThresholdKeyId: 'threshold-key-1',
          participantIds: [1, 2],
        });
        const appOriginSecretRejection = await pm.auth
          .enrollEmailOtp({
            nearAccountId,
            challengeId: enrollmentChallenge.challengeId,
            otpCode: '123456',
            clientSecret32: new Uint8Array(32),
          })
          .then(() => null)
          .catch((error: unknown) => String((error as Error)?.message || error));
        const signRequest = {
          chain: 'evm',
          kind: 'eip1559',
          senderSignatureAlgorithm: 'secp256k1',
          tx: {
            chainId: 11155111,
            nonce: 0n,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 21_000n,
            to: '0x' + '11'.repeat(20),
            value: 0n,
            data: '0x',
            accessList: [],
          },
        };
        const sessionSigned = await pm.tempo.signTempo({
          nearAccountId,
          request: signRequest,
          options: { confirmationConfig: { uiMode: 'modal' } },
        });
        const nearSigned = await pm.near.signTransactionsWithActions({
          nearAccountId,
          transactions: [
            {
              receiverId: nearAccountId,
              actions: [{ action_type: 'Transfer', deposit: '1' }],
            },
          ],
          options: { confirmationConfig: { uiMode: 'modal' } },
        });
        const walletSession = await pm.auth.getWalletSession(nearAccountId);
        const perOperationSigned = await pm.tempo.signTempo({
          nearAccountId,
          request: { ...signRequest, tx: { ...signRequest.tx, nonce: 1n } },
          options: { confirmationConfig: { uiMode: 'modal' } },
        });
        const tempoSigned = await pm.tempo.signTempo({
          nearAccountId,
          request: {
            chain: 'tempo',
            kind: 'tempoTransaction',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21_000n,
              calls: [{ to: '0x' + '22'.repeat(20), value: 0n, input: '0x' }],
              accessList: [],
              nonceKey: 1n,
              nonce: 1n,
              validBefore: null,
              validAfter: null,
              feePayerSignature: { kind: 'none' },
            },
          },
          options: { confirmationConfig: { uiMode: 'modal' } },
        });
        const { IndexedDBManager } = await import('/sdk/esm/core/indexedDB/index.js');
        const forbiddenKeys = new Set([
          'S',
          'secretS',
          'recoveredS',
          'recoveredSB64u',
          'clientSecret32',
          'clientRootShare32',
          'clientRootShare32B64u',
          'clientAdditiveShare32',
          'clientAdditiveShare32B64u',
          'clientSigningShare32',
          'clientSigningShare32B64u',
          'kShareB64u',
          'sigmaShareB64u',
        ]);
        const findForbidden = (value: unknown, path: string[] = []): string[] => {
          if (!value || typeof value !== 'object') return [];
          if (Array.isArray(value)) {
            return value.flatMap((entry, index) => findForbidden(entry, [...path, String(index)]));
          }
          const found: string[] = [];
          for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
            const nextPath = [...path, key];
            if (forbiddenKeys.has(key)) {
              found.push(nextPath.join('.'));
              continue;
            }
            found.push(...findForbidden(entry, nextPath));
          }
          return found;
        };
        const appOriginForbiddenFields = findForbidden({
          enrollment,
          login,
          perOperationLogin,
          enrollAndLogin,
          sessionSigned,
          nearSigned,
          perOperationSigned,
          tempoSigned,
        });

        return {
          challenge,
          enrollmentChallenge,
          exchangedWalletId: sessionExchange.session.walletId,
          enrollmentKeyVersion: enrollment.emailOtpKeyVersion,
          loginGrant: login.recovery.loginGrant,
          perOperationLoginGrant: perOperationLogin.recovery.loginGrant,
          enrollAndLoginKeyVersion: enrollAndLogin.enrollment.emailOtpKeyVersion,
          appOriginSecretRejection,
          sessionSignedKind: sessionSigned.kind,
          nearSignedCount: Array.isArray(nearSigned) ? nearSigned.length : 0,
          nearSignedNearAccountId: nearSigned?.[0]?.nearAccountId || null,
          perOperationSignedKind: perOperationSigned.kind,
          tempoSignedKind: tempoSigned.kind,
          tempoSignedChain: tempoSigned.chain,
          walletSessionAuthMethod: walletSession.authMethod,
          walletSessionRetention: walletSession.retention,
          loginAuthMethod: walletSession.login.authMethod,
          signingSessionAuthMethod: walletSession.signingSession?.authMethod || null,
          signingSessionRetention: walletSession.signingSession?.retention || null,
          appOriginForbiddenFields,
          clientDbDisabled: IndexedDBManager.clientDB.isDisabled(),
          accountKeyMaterialDbDisabled: IndexedDBManager.accountKeyMaterialDB.isDisabled(),
        };
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    expect(result).toEqual({
      challenge: { challengeId: 'challenge-1', otpChannel: 'email_otp' },
      enrollmentChallenge: { challengeId: 'enrollment-challenge-1', otpChannel: 'email_otp' },
      exchangedWalletId: 'alice.testnet',
      enrollmentKeyVersion: 'email-otp-kv-1',
      loginGrant: 'grant-1',
      perOperationLoginGrant: 'grant-1',
      enrollAndLoginKeyVersion: 'email-otp-kv-1',
      appOriginSecretRejection:
        '[TatchiPasskey] Wallet iframe Email OTP enrollment owns client secret generation; clientSecret32 is not accepted from the app origin.',
      sessionSignedKind: 'eip1559',
      nearSignedCount: 1,
      nearSignedNearAccountId: 'alice.testnet',
      perOperationSignedKind: 'eip1559',
      tempoSignedKind: 'tempoTransaction',
      tempoSignedChain: 'tempo',
      walletSessionAuthMethod: 'email_otp',
      walletSessionRetention: 'session',
      loginAuthMethod: 'email_otp',
      signingSessionAuthMethod: 'email_otp',
      signingSessionRetention: 'session',
      appOriginForbiddenFields: [],
      clientDbDisabled: true,
      accountKeyMaterialDbDisabled: true,
    });

    const walletFrame = page.frames().find((frame) => {
      const url = frame.url();
      return url.startsWith(WALLET_ORIGIN) && url.includes('/wallet-service');
    });
    expect(walletFrame, 'wallet iframe should be mounted').toBeTruthy();

    const messages = await walletFrame!.evaluate(() => (window as any).__emailOtpMessages || []);
    const messageTypes = messages.map((message: { type: string }) => message.type);
    expect(messageTypes).toContain('PM_REQUEST_EMAIL_OTP_CHALLENGE');
    expect(messageTypes).toContain('PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE');
    expect(messageTypes).toContain('PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION');
    expect(messageTypes).toContain('PM_ENROLL_EMAIL_OTP');
    expect(messageTypes).toContain('PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY');
    expect(messageTypes).toContain('PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY');

    const emailOtpMessages = messages.filter((message: { type: string }) =>
      message.type.includes('EMAIL_OTP'),
    );
    expect(emailOtpMessages).toHaveLength(7);
    for (const message of emailOtpMessages.filter(
      (message: { type: string }) => message.type !== 'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION',
    )) {
      expect(message.payload.nearAccountId).toBe('alice.testnet');
    }
    const exchangeMessage = emailOtpMessages.find(
      (message: { type: string }) => message.type === 'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION',
    );
    expect(exchangeMessage?.payload).toMatchObject({
      idToken: 'google-id-token-1',
      accountMode: 'register',
      sessionKind: 'cookie',
    });
    expect(
      emailOtpMessages.some((message: { payload: Record<string, unknown> }) =>
        Object.prototype.hasOwnProperty.call(message.payload, 'clientSecret32'),
      ),
    ).toBe(false);
    expect(
      emailOtpMessages.some((message: { payload: Record<string, unknown> }) =>
        [
          'S',
          'recoveredS',
          'recoveredSB64u',
          'clientRootShare32',
          'clientRootShare32B64u',
          'clientAdditiveShare32B64u',
          'clientSigningShare32',
          'clientSigningShare32B64u',
          'kShareB64u',
          'sigmaShareB64u',
        ].some((key) => Object.prototype.hasOwnProperty.call(message.payload, key)),
      ),
    ).toBe(false);

    const signMessages = messages.filter(
      (message: { type: string }) => message.type === 'PM_SIGN_TEMPO',
    );
    expect(signMessages).toHaveLength(3);
    expect(
      signMessages.map(
        (message: { payload: { nearAccountId: string } }) => message.payload.nearAccountId,
      ),
    ).toEqual(['alice.testnet', 'alice.testnet', 'alice.testnet']);
    expect(
      signMessages.map(
        (message: { payload: { request: { chain: string; kind: string } } }) =>
          `${message.payload.request.chain}:${message.payload.request.kind}`,
      ),
    ).toEqual(['evm:eip1559', 'evm:eip1559', 'tempo:tempoTransaction']);
    const nearSignMessages = messages.filter(
      (message: { type: string }) => message.type === 'PM_SIGN_TXS_WITH_ACTIONS',
    );
    expect(nearSignMessages).toHaveLength(1);
    expect(nearSignMessages[0]?.payload).toMatchObject({
      nearAccountId: 'alice.testnet',
      transactions: [
        {
          receiverId: 'alice.testnet',
          actions: [{ action_type: 'Transfer', deposit: '1' }],
        },
      ],
    });
  });

  test('reload restores nonsecret account metadata but requires fresh OTP for signing', async ({
    page,
  }) => {
    const firstLoad = await page.evaluate(
      async ({ walletOrigin }) => {
        const { TatchiPasskey } = (await import('/sdk/esm/core/TatchiPasskey/index.js')) as any;
        const nearAccountId = 'alice.testnet';
        const pm = new TatchiPasskey({
          relayer: { url: 'https://relay.example' },
          signingSessionSeal: {
            keyVersion: 'email-otp-test-seal',
            shamirPrimeB64u: '_____________________________________v___C8',
          },
          iframeWallet: {
            walletOrigin,
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
          },
        });

        await pm.auth.loginWithEmailOtpEcdsaCapability({
          nearAccountId,
          chain: 'evm',
          emailOtpAuthPolicy: 'session',
          challengeId: 'challenge-1',
          otpCode: '123456',
          appSessionJwt: 'app-session-jwt',
          sessionKind: 'cookie',
          ecdsaThresholdKeyId: 'threshold-key-1',
          participantIds: [1, 2],
        });
        const session = await pm.auth.getWalletSession(nearAccountId);
        return {
          loggedIn: !!session.login?.isLoggedIn,
          nearAccountId: session.login?.nearAccountId || null,
          signingStatus: session.signingSession?.status || null,
        };
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    expect(firstLoad).toEqual({
      loggedIn: true,
      nearAccountId: 'alice.testnet',
      signingStatus: 'active',
    });

    await page.reload({ waitUntil: 'domcontentloaded' });

    const afterReload = await page.evaluate(
      async ({ walletOrigin }) => {
        const { TatchiPasskey } = (await import('/sdk/esm/core/TatchiPasskey/index.js')) as any;
        const nearAccountId = 'alice.testnet';
        const pm = new TatchiPasskey({
          relayer: { url: 'https://relay.example' },
          signingSessionSeal: {
            keyVersion: 'email-otp-test-seal',
            shamirPrimeB64u: '_____________________________________v___C8',
          },
          iframeWallet: {
            walletOrigin,
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
          },
        });
        const session = await pm.auth.getWalletSession(nearAccountId);
        const signRequest = {
          chain: 'evm',
          kind: 'eip1559',
          senderSignatureAlgorithm: 'secp256k1',
          tx: {
            chainId: 11155111,
            nonce: 0n,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 21_000n,
            to: '0x' + '11'.repeat(20),
            value: 0n,
            data: '0x',
            accessList: [],
          },
        };
        const signError = await pm.tempo
          .signTempo({
            nearAccountId,
            request: signRequest,
            options: { confirmationConfig: { uiMode: 'modal' } },
          })
          .then(() => null)
          .catch((error: unknown) => ({
            code: String((error as { code?: unknown })?.code || ''),
            message: String((error as Error)?.message || error),
          }));
        return {
          loggedIn: !!session.login?.isLoggedIn,
          nearAccountId: session.login?.nearAccountId || null,
          signingSession: session.signingSession || null,
          signError,
        };
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    expect(afterReload.loggedIn).toBe(true);
    expect(afterReload.nearAccountId).toBe('alice.testnet');
    expect(afterReload.signingSession).toBeNull();
    expect(afterReload.signError?.message || '').toContain(
      'Threshold ECDSA signing session is not ready',
    );
  });
});
