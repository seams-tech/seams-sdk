import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { buildWalletServiceHtml, registerWalletServiceRoute } from '../wallet-iframe/harness';

const WALLET_ORIGIN = 'https://wallet.example.localhost';
const WALLET_SERVICE_ROUTE = '**://wallet.example.localhost/wallet-service*';

const WALLET_STUB_EMAIL_OTP_SCRIPT = String.raw`
  window.__emailOtpMessages = [];
  const walletMetadataKey = 'test-email-otp-wallet-id';
  const nearMetadataKey = 'test-email-otp-near-account-id';
  const warmCapabilityKey = 'test-email-otp-warm-capability-active';
  let warmCapabilityActive = (() => {
    try {
      return localStorage.getItem(warmCapabilityKey) === '1';
    } catch {
      return false;
    }
  })();

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

  const rememberWallet = (walletId) => {
    if (!walletId) return;
    try {
      localStorage.setItem(walletMetadataKey, walletId);
    } catch {}
  };

  const rememberNearAccount = (nearAccountId) => {
    if (!nearAccountId) return;
    try {
      localStorage.setItem(nearMetadataKey, nearAccountId);
    } catch {}
  };

  const setWarmCapabilityActive = (active) => {
    warmCapabilityActive = active === true;
    try {
      localStorage.setItem(warmCapabilityKey, warmCapabilityActive ? '1' : '0');
    } catch {}
  };

  const activeSessionFor = (walletId) => {
    const selectedWalletId = walletId || (() => {
      try {
        return localStorage.getItem(walletMetadataKey) || '';
      } catch {
        return '';
      }
    })();
    const selectedNearAccountId = (() => {
      try {
        return localStorage.getItem(nearMetadataKey) || 'alice.testnet';
      } catch {
        return 'alice.testnet';
      }
    })();
    return {
      login: {
        isLoggedIn: !!selectedWalletId,
        walletId: selectedWalletId || null,
        nearAccountId: selectedWalletId ? selectedNearAccountId : null,
        publicKey: null,
        userData: null,
        authMethod: selectedWalletId && warmCapabilityActive ? 'email_otp' : null,
      },
      signingSession: selectedWalletId && warmCapabilityActive
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
      authMethod: selectedWalletId && warmCapabilityActive ? 'email_otp' : null,
      retention: selectedWalletId && warmCapabilityActive ? 'session' : null,
    };
  };

  const secretSentinel = 'email-otp-secret-must-not-cross-app-origin';

  const loginRecovery = {
    challengeId: 'challenge-1',
    enrollmentSealKeyVersion: 'email-otp-kv-1',
    unlockChallengeId: 'unlock-challenge-1',
    unlockChallengeB64u: 'unlock-challenge-b64u',
    clientUnlockPublicKeyB64u: 'unlock-public-key-b64u',
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
        respond(activeSessionFor(data.payload?.walletId || data.payload?.nearAccountId || null));
      }
      if (data.type === 'PM_GET_RECENT_UNLOCKS') {
        respond({ walletIds: [], accountIds: [], accounts: [], lastUsedAccount: null });
      }
      if (data.type === 'PM_REQUEST_EMAIL_OTP_CHALLENGE') {
        respond({
          challengeId: 'challenge-1',
          otpChannel: 'email_otp',
          delivery: {
            kind: 'provider',
            status: 'sent',
            emailHint: 'a***@example.test',
          },
        });
      }
      if (data.type === 'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE') {
        respond({
          challengeId: 'enrollment-challenge-1',
          otpChannel: 'email_otp',
          delivery: {
            kind: 'provider',
            status: 'sent',
            emailHint: 'a***@example.test',
          },
        });
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
      if (data.type === 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH') {
        respond({
          ok: true,
          value: {
            kind: 'google_email_otp_wallet_auth_flow_v1',
            state: 'registration_ready',
            flowHandleId: 'google-email-otp-registration-handle-1',
            flowId: 'google-email-otp-registration:alice.testnet:attempt-1',
            requestedMode: data.payload?.mode || 'register',
            mode: 'register',
            walletId: 'alice.testnet',
            emailHint: 'alice@example.com',
            prompt: {
              title: 'Create your Email OTP wallet',
              description: 'Google verified alice@example.com.',
              submitLabel: 'Create wallet',
              helperText: 'Choose this wallet name or generate another one.',
            },
            expiresAtMs: Date.now() + 60_000,
          },
        });
      }
      if (data.type === 'PM_ENROLL_EMAIL_OTP') {
        rememberWallet(data.payload?.walletId || data.payload?.nearAccountId || '');
        rememberNearAccount(data.payload?.nearAccountId || 'alice.testnet');
        respond({
          thresholdEcdsaClientVerifyingShareB64u: 'threshold-verifier-b64u',
          challengeId: 'enrollment-challenge-1',
          otpChannel: 'email_otp',
          enrollmentSealKeyVersion: 'email-otp-kv-1',
          recoveryKeys: [secretSentinel],
          clientUnlockPublicKeyB64u: 'unlock-public-key-b64u',
          unlockKeyVersion: 'unlock-kv-1',
          clientRootShare32B64u: secretSentinel,
          clientSecret32: secretSentinel,
        });
      }
      if (data.type === 'PM_REQUEST_EMAIL_OTP_SIGNING_SESSION_CHALLENGE') {
        respond({ challengeId: 'signing-session-challenge-1', emailHint: 'alice@example.com' });
      }
      if (data.type === 'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY') {
        if (data.payload?.otpCode === '000000') {
          reject('invalid_email_otp', 'Invalid Email OTP code');
          return;
        }
        rememberWallet(data.payload?.walletSession?.walletId || '');
        rememberNearAccount(data.payload?.nearAccountId || 'alice.testnet');
        setWarmCapabilityActive(true);
        respond({ recovery: loginRecovery, bootstrap: bootstrapResult, warmCapability });
      }
      if (data.type === 'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION') {
        rememberWallet(data.payload?.walletSession?.walletId || '');
        rememberNearAccount(data.payload?.nearAccountId || 'alice.testnet');
        setWarmCapabilityActive(true);
        respond({ recovery: loginRecovery, bootstrap: bootstrapResult, warmCapability });
      }
      if (data.type === 'PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY') {
        rememberWallet(data.payload?.walletSession?.walletId || '');
        rememberNearAccount(data.payload?.nearAccountId || 'alice.testnet');
        setWarmCapabilityActive(true);
        respond({
          enrollment: {
            thresholdEcdsaClientVerifyingShareB64u: 'threshold-verifier-b64u',
            challengeId: 'enrollment-challenge-1',
            otpChannel: 'email_otp',
            enrollmentSealKeyVersion: 'email-otp-kv-1',
            recoveryKeys: [secretSentinel],
            clientUnlockPublicKeyB64u: 'unlock-public-key-b64u',
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
      if (data.type === 'PM_SIGN_TX_WITH_ACTIONS') {
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

test.describe('SeamsWeb Email OTP wallet iframe ownership', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
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
        const mod = await import('/_test-sdk/esm/SeamsWeb/index.js');
        const { SeamsWeb } = mod as any;
        const walletId = 'frost-vermillion-k7p9m2';
        const nearAccountId = 'alice.testnet';
        const pm = new SeamsWeb({
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

        const registrationEvents: Array<Record<string, unknown>> = [];
        const unlockEvents: Array<Record<string, unknown>> = [];
        const perOperationUnlockEvents: Array<Record<string, unknown>> = [];
        const failedUnlockEvents: Array<Record<string, unknown>> = [];
        const enrollAndLoginEvents: Array<Record<string, unknown>> = [];
        const secretRejectionEvents: Array<Record<string, unknown>> = [];
        const captureEvent =
          (events: Array<Record<string, unknown>>) => (event: Record<string, unknown>) => {
            events.push({
              flow: event.flow,
              phase: event.phase,
              status: event.status,
              step: event.step,
              authMethod: event.authMethod,
              interaction: event.interaction,
              error: event.error ?? null,
            });
          };

        const challenge = await pm.auth.requestEmailOtpChallenge({
          walletId,
          appSessionJwt: 'app-session-jwt',
          onEvent: captureEvent(unlockEvents),
        });
        const walletSessionRef = {
          walletId,
          walletSessionUserId: walletId,
        };
        const chainTarget = {
          kind: 'evm',
          namespace: 'eip155',
          chainId: 5042002,
          networkSlug: 'arc-testnet',
        };
        const enrollmentChallenge = await pm.registration.requestEmailOtpEnrollmentChallenge({
          walletId,
          appSessionJwt: 'app-session-jwt',
          onEvent: captureEvent(registrationEvents),
        });
        const sessionExchange = await pm.auth.exchangeGoogleEmailOtpSession({
          idToken: 'google-id-token-1',
          accountMode: 'register',
          sessionKind: 'cookie',
          onEvent: captureEvent(registrationEvents),
        });
        const googleRegistrationStart = await pm.auth.beginGoogleEmailOtpWalletAuth({
          idToken: 'google-id-token-2',
          mode: 'register',
          sessionKind: 'cookie',
          ecdsaTargets: { kind: 'configured' },
          onEvent: captureEvent(registrationEvents),
        });
        const googleRegistrationFlow = googleRegistrationStart.ok
          ? googleRegistrationStart.value
          : null;
        const enrollment = await pm.registration.enrollEmailOtp({
          walletId,
          challengeId: enrollmentChallenge.challengeId,
          otpCode: '123456',
          appSessionJwt: 'app-session-jwt',
          onEvent: captureEvent(registrationEvents),
        });
        const login = await pm.auth.loginWithEmailOtpEcdsaCapability({
          walletSession: walletSessionRef,
          chainTarget,
          emailOtpAuthPolicy: 'session',
          challengeId: challenge.challengeId,
          otpCode: '123456',
          appSessionJwt: 'app-session-jwt',
          onEvent: captureEvent(unlockEvents),
        });
        const perOperationLogin = await pm.auth.loginWithEmailOtpEcdsaCapability({
          walletSession: walletSessionRef,
          chainTarget,
          emailOtpAuthPolicy: 'per_operation',
          challengeId: challenge.challengeId,
          otpCode: '123456',
          appSessionJwt: 'app-session-jwt',
          onEvent: captureEvent(perOperationUnlockEvents),
        });
        const failedUnlockMessage = await pm.auth
          .loginWithEmailOtpEcdsaCapability({
            walletSession: walletSessionRef,
            chainTarget,
            emailOtpAuthPolicy: 'session',
            challengeId: challenge.challengeId,
            otpCode: '000000',
            appSessionJwt: 'app-session-jwt',
            onEvent: captureEvent(failedUnlockEvents),
          })
          .then(() => null)
          .catch((error: unknown) => String((error as Error)?.message || error));
        const enrollAndLogin = await pm.registration.enrollAndLoginWithEmailOtpEcdsaCapability({
          walletSession: walletSessionRef,
          chainTarget,
          emailOtpAuthPolicy: 'session',
          challengeId: enrollmentChallenge.challengeId,
          otpCode: '123456',
          appSessionJwt: 'app-session-jwt',
          onEvent: captureEvent(enrollAndLoginEvents),
        });
        const appOriginSecretRejection = await pm.registration
          .enrollEmailOtp({
            walletId,
            challengeId: enrollmentChallenge.challengeId,
            otpCode: '123456',
            clientSecret32: new Uint8Array(32),
            onEvent: captureEvent(secretRejectionEvents),
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
          walletSession: walletSessionRef,
          chainTarget,
          request: signRequest,
          options: { confirmationConfig: { uiMode: 'modal' } },
        });
        const nearSigned = await pm.near.signTransactionWithActions({
          walletSession: walletSessionRef,
          nearAccount: { accountId: nearAccountId, kind: 'near_account' },
          transaction: {
            receiverId: nearAccountId,
            actions: [{ action_type: 'Transfer', deposit: '1' }],
          },
          options: { confirmationConfig: { uiMode: 'modal' } },
        });
        const walletSession = await pm.auth.getWalletSession(walletId);
        const perOperationSigned = await pm.tempo.signTempo({
          walletSession: walletSessionRef,
          chainTarget,
          request: { ...signRequest, tx: { ...signRequest.tx, nonce: 1n } },
          options: { confirmationConfig: { uiMode: 'modal' } },
        });
        const tempoSigned = await pm.tempo.signTempo({
          walletSession: walletSessionRef,
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
        const { IndexedDBManager, seamsWalletDB } =
          await import('/_test-sdk/esm/core/indexedDB/index.js');
        const forbiddenKeys = new Set([
          'S',
          'secretS',
          'recoveredS',
          'recoveredSB64u',
          'recoveryKeys',
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
          googleRegistrationStartOk: googleRegistrationStart.ok,
          googleRegistrationStartMode: googleRegistrationFlow?.mode || null,
          googleRegistrationStartState: googleRegistrationFlow?.state || null,
          googleRegistrationStartWalletId: googleRegistrationFlow?.walletId || null,
          enrollmentKeyVersion: enrollment.enrollmentSealKeyVersion,
          enrollAndLoginKeyVersion: enrollAndLogin.enrollment.enrollmentSealKeyVersion,
          appOriginSecretRejection,
          sessionSignedKind: sessionSigned.kind,
          nearSignedCount: Array.isArray(nearSigned) ? nearSigned.length : 0,
          nearSignedNearAccountId: nearSigned?.[0]?.nearAccountId || null,
          perOperationSignedKind: perOperationSigned.kind,
          tempoSignedKind: tempoSigned.kind,
          tempoSignedChain: tempoSigned.chain,
          walletSessionWalletId: walletSession.login.walletId,
          walletSessionNearAccountId: walletSession.login.nearAccountId,
          walletSessionAuthMethod: walletSession.authMethod,
          walletSessionRetention: walletSession.retention,
          loginAuthMethod: walletSession.login.authMethod,
          signingSessionAuthMethod: walletSession.signingSession?.authMethod || null,
          signingSessionRetention: walletSession.signingSession?.retention || null,
          registrationEventPhases: registrationEvents.map((event) => event.phase),
          registrationEventSteps: registrationEvents.map((event) => event.step),
          registrationEventFlows: [...new Set(registrationEvents.map((event) => event.flow))],
          registrationEventAuthMethods: [
            ...new Set(registrationEvents.map((event) => event.authMethod)),
          ],
          unlockEventPhases: unlockEvents.map((event) => event.phase),
          unlockEventSteps: unlockEvents.map((event) => event.step),
          unlockEventFlows: [...new Set(unlockEvents.map((event) => event.flow))],
          unlockEventAuthMethods: [...new Set(unlockEvents.map((event) => event.authMethod))],
          perOperationUnlockEventPhases: perOperationUnlockEvents.map((event) => event.phase),
          perOperationUnlockEventSteps: perOperationUnlockEvents.map((event) => event.step),
          perOperationUnlockEventFlows: [
            ...new Set(perOperationUnlockEvents.map((event) => event.flow)),
          ],
          failedUnlockMessage,
          failedUnlockEventPhases: failedUnlockEvents.map((event) => event.phase),
          failedUnlockEventSteps: failedUnlockEvents.map((event) => event.step),
          failedUnlockEventStatuses: failedUnlockEvents.map((event) => event.status),
          failedUnlockEventInteractions: failedUnlockEvents.map((event) => event.interaction),
          failedUnlockEventErrors: failedUnlockEvents.map((event) => event.error),
          enrollAndLoginEventPhases: enrollAndLoginEvents.map((event) => event.phase),
          enrollAndLoginEventSteps: enrollAndLoginEvents.map((event) => event.step),
          enrollAndLoginEventFlows: [...new Set(enrollAndLoginEvents.map((event) => event.flow))],
          secretRejectionEventPhases: secretRejectionEvents.map((event) => event.phase),
          secretRejectionEventSteps: secretRejectionEvents.map((event) => event.step),
          secretRejectionEventStatuses: secretRejectionEvents.map((event) => event.status),
          secretRejectionEventInteractions: secretRejectionEvents.map((event) => event.interaction),
          secretRejectionEventErrors: secretRejectionEvents.map((event) => event.error),
          appOriginForbiddenFields,
          indexedDbDisabled: IndexedDBManager.isDisabled(),
          seamsWalletDbDisabled: seamsWalletDB.isDisabled(),
        };
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    expect(result).toEqual({
      challenge: {
        challengeId: 'challenge-1',
        otpChannel: 'email_otp',
        delivery: {
          kind: 'provider',
          status: 'sent',
          emailHint: 'a***@example.test',
        },
      },
      enrollmentChallenge: {
        challengeId: 'enrollment-challenge-1',
        otpChannel: 'email_otp',
        delivery: {
          kind: 'provider',
          status: 'sent',
          emailHint: 'a***@example.test',
        },
      },
      exchangedWalletId: 'alice.testnet',
      googleRegistrationStartOk: true,
      googleRegistrationStartMode: 'register',
      googleRegistrationStartState: 'registration_ready',
      googleRegistrationStartWalletId: 'alice.testnet',
      enrollmentKeyVersion: 'email-otp-kv-1',
      enrollAndLoginKeyVersion: 'email-otp-kv-1',
      appOriginSecretRejection:
        '[SeamsWeb] Wallet iframe Email OTP enrollment owns client secret generation; clientSecret32 is not accepted from the app origin.',
      sessionSignedKind: 'eip1559',
      nearSignedCount: 1,
      nearSignedNearAccountId: 'alice.testnet',
      perOperationSignedKind: 'eip1559',
      tempoSignedKind: 'tempoTransaction',
      tempoSignedChain: 'tempo',
      walletSessionWalletId: 'frost-vermillion-k7p9m2',
      walletSessionNearAccountId: 'alice.testnet',
      walletSessionAuthMethod: 'email_otp',
      walletSessionRetention: 'session',
      loginAuthMethod: 'email_otp',
      signingSessionAuthMethod: 'email_otp',
      signingSessionRetention: 'session',
      registrationEventPhases: [
        'registration.otp.challenge.started',
        'registration.otp.challenge.sent',
        'registration.session.exchange.started',
        'registration.session.exchange.succeeded',
        'registration.otp.verify.started',
        'registration.otp.verify.succeeded',
        'registration.signer.email_otp.enroll.started',
        'registration.signer.email_otp.enroll.succeeded',
      ],
      registrationEventSteps: [4, 4, 3, 3, 4, 4, 9, 9],
      registrationEventFlows: ['registration'],
      registrationEventAuthMethods: ['email_otp'],
      unlockEventPhases: [
        'unlock.auth.email_otp.challenge.started',
        'unlock.auth.email_otp.challenge.sent',
        'unlock.auth.email_otp.verify.started',
        'unlock.auth.email_otp.verify.succeeded',
        'unlock.signing_session.ecdsa.ready',
        'unlock.completed',
      ],
      unlockEventSteps: [3, 3, 3, 3, 5, 7],
      unlockEventFlows: ['unlock'],
      unlockEventAuthMethods: ['email_otp'],
      perOperationUnlockEventPhases: [
        'unlock.auth.email_otp.verify.started',
        'unlock.auth.email_otp.verify.succeeded',
        'unlock.signing_session.ecdsa.ready',
        'unlock.completed',
      ],
      perOperationUnlockEventSteps: [3, 3, 5, 7],
      perOperationUnlockEventFlows: ['unlock'],
      failedUnlockMessage: 'Invalid Email OTP code',
      failedUnlockEventPhases: ['unlock.auth.email_otp.verify.started', 'unlock.failed'],
      failedUnlockEventSteps: [3, 0],
      failedUnlockEventStatuses: ['running', 'failed'],
      failedUnlockEventInteractions: [
        { kind: 'otp_input', overlay: 'none' },
        { kind: 'none', overlay: 'hide' },
      ],
      failedUnlockEventErrors: [null, { message: 'Invalid Email OTP code' }],
      enrollAndLoginEventPhases: [
        'registration.otp.verify.started',
        'registration.otp.verify.succeeded',
        'registration.signer.email_otp.enroll.started',
        'registration.signer.email_otp.enroll.succeeded',
        'registration.signer.ecdsa.provision.started',
        'registration.signer.ecdsa.provision.succeeded',
        'registration.completed',
      ],
      enrollAndLoginEventSteps: [4, 4, 9, 9, 10, 10, 11],
      enrollAndLoginEventFlows: ['registration'],
      secretRejectionEventPhases: ['registration.otp.verify.started', 'registration.failed'],
      secretRejectionEventSteps: [4, 0],
      secretRejectionEventStatuses: ['running', 'failed'],
      secretRejectionEventInteractions: [
        { kind: 'otp_input', overlay: 'none' },
        { kind: 'none', overlay: 'hide' },
      ],
      secretRejectionEventErrors: [
        null,
        {
          message:
            '[SeamsWeb] Wallet iframe Email OTP enrollment owns client secret generation; clientSecret32 is not accepted from the app origin.',
        },
      ],
      appOriginForbiddenFields: [],
      indexedDbDisabled: true,
      seamsWalletDbDisabled: true,
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
    expect(messageTypes).toContain('PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH');
    expect(messageTypes).toContain('PM_ENROLL_EMAIL_OTP');
    expect(messageTypes).toContain('PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY');
    expect(messageTypes).toContain('PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY');

    const emailOtpMessages = messages.filter((message: { type: string }) =>
      message.type.includes('EMAIL_OTP'),
    );
    expect(emailOtpMessages).toHaveLength(9);
    for (const message of emailOtpMessages) {
      if (message.type === 'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION') continue;
      if (message.type === 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH') {
        expect(message.payload).toMatchObject({
          idToken: 'google-id-token-2',
          mode: 'register',
          sessionKind: 'cookie',
          ecdsaTargets: { kind: 'configured' },
        });
        continue;
      }
      if (
        message.type === 'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY' ||
        message.type === 'PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY' ||
        message.type === 'PM_REQUEST_EMAIL_OTP_SIGNING_SESSION_CHALLENGE' ||
        message.type === 'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION'
      ) {
        expect(message.payload.walletSession).toMatchObject({
          walletId: 'frost-vermillion-k7p9m2',
          walletSessionUserId: 'frost-vermillion-k7p9m2',
        });
        continue;
      }
      expect(message.payload.walletId).toBe('frost-vermillion-k7p9m2');
    }
    const exchangeMessage = emailOtpMessages.find(
      (message: { type: string }) => message.type === 'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION',
    );
    expect(exchangeMessage?.payload).toMatchObject({
      idToken: 'google-id-token-1',
      accountMode: 'register',
      sessionKind: 'cookie',
    });
    const beginGoogleMessage = emailOtpMessages.find(
      (message: { type: string }) => message.type === 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH',
    );
    expect(beginGoogleMessage?.payload).not.toHaveProperty('onEvent');
    expect(beginGoogleMessage?.payload).not.toHaveProperty('walletId');
    expect(
      emailOtpMessages.some((message: { payload: Record<string, unknown> }) =>
        Object.prototype.hasOwnProperty.call(message.payload, 'clientSecret32'),
      ),
    ).toBe(false);
    expect(
      emailOtpMessages.some((message: { payload: Record<string, unknown> }) =>
        Object.prototype.hasOwnProperty.call(message.payload, 'onEvent'),
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
        (message: { payload: { walletSession: { walletId: string } } }) =>
          message.payload.walletSession.walletId,
      ),
    ).toEqual(['frost-vermillion-k7p9m2', 'frost-vermillion-k7p9m2', 'frost-vermillion-k7p9m2']);
    expect(
      signMessages.map(
        (message: { payload: { request: { chain: string; kind: string } } }) =>
          `${message.payload.request.chain}:${message.payload.request.kind}`,
      ),
    ).toEqual(['evm:eip1559', 'evm:eip1559', 'tempo:tempoTransaction']);
    const nearSignMessages = messages.filter(
      (message: { type: string }) => message.type === 'PM_SIGN_TX_WITH_ACTIONS',
    );
    expect(nearSignMessages).toHaveLength(1);
    expect(nearSignMessages[0]?.payload).toMatchObject({
      nearAccountId: 'alice.testnet',
      transaction: {
        receiverId: 'alice.testnet',
        actions: [{ action_type: 'Transfer', deposit: '1' }],
      },
    });
  });

  test('routes Email OTP signing-session refresh with explicit ECDSA subject', async ({ page }) => {
    const result = await page.evaluate(
      async ({ walletOrigin }) => {
        const mod = await import('/_test-sdk/esm/SeamsWeb/index.js');
        const { SeamsWeb } = mod as any;
        const walletId = 'frost-refresh-k7p9m2';
        const walletSessionRef = {
          walletId,
          walletSessionUserId: walletId,
        };
        const chainTarget = {
          kind: 'tempo',
          chainId: 42431,
          networkSlug: 'tempo-moderato',
        };
        const pm = new SeamsWeb({
          relayer: { url: 'https://relay.example' },
          iframeWallet: {
            walletOrigin,
            walletServicePath: '/wallet-service',
            sdkBasePath: '/sdk',
          },
        });

        const challenge = await pm.auth.requestEmailOtpSigningSessionChallenge({
          walletSession: walletSessionRef,
          chainTarget,
        });
        await pm.auth.refreshEmailOtpSigningSession({
          walletSession: walletSessionRef,
          chainTarget,
          challengeId: challenge.challengeId,
          otpCode: '123456',
        });
        return { challengeId: challenge.challengeId };
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    expect(result).toEqual({ challengeId: 'signing-session-challenge-1' });
    const walletFrame = page.frames().find((frame) => {
      const url = frame.url();
      return url.startsWith(WALLET_ORIGIN) && url.includes('/wallet-service');
    });
    expect(walletFrame, 'wallet iframe should be mounted').toBeTruthy();

    const messages = await walletFrame!.evaluate(() => (window as any).__emailOtpMessages || []);
    const signingChallenge = messages.find(
      (message: { type: string }) =>
        message.type === 'PM_REQUEST_EMAIL_OTP_SIGNING_SESSION_CHALLENGE',
    );
    const refresh = messages.find(
      (message: { type: string }) => message.type === 'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION',
    );
    expect(signingChallenge?.payload).toMatchObject({
      walletSession: {
        walletId: 'frost-refresh-k7p9m2',
        walletSessionUserId: 'frost-refresh-k7p9m2',
      },
    });
    expect(refresh?.payload).toMatchObject({
      walletSession: {
        walletId: 'frost-refresh-k7p9m2',
        walletSessionUserId: 'frost-refresh-k7p9m2',
      },
      challengeId: 'signing-session-challenge-1',
    });
  });

  test('reload restores nonsecret account metadata and sealed signing session for signing', async ({
    page,
  }) => {
    const firstLoad = await page.evaluate(
      async ({ walletOrigin }) => {
        const { SeamsWeb } = (await import('/_test-sdk/esm/SeamsWeb/index.js')) as any;
        const walletId = 'frost-reload-k7p9m2';
        const nearAccountId = 'alice.testnet';
        const walletSessionRef = {
          walletId,
          walletSessionUserId: walletId,
        };
        const pm = new SeamsWeb({
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
          walletSession: walletSessionRef,
          chainTarget: {
            kind: 'evm',
            namespace: 'eip155',
            chainId: 5042002,
            networkSlug: 'arc-testnet',
          },
          emailOtpAuthPolicy: 'session',
          challengeId: 'challenge-1',
          otpCode: '123456',
          appSessionJwt: 'app-session-jwt',
        });
        const session = await pm.auth.getWalletSession(walletId);
        return {
          loggedIn: !!session.login?.isLoggedIn,
          walletId: session.login?.walletId || null,
          nearAccountId: session.login?.nearAccountId || null,
          signingStatus: session.signingSession?.status || null,
        };
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    expect(firstLoad).toEqual({
      loggedIn: true,
      walletId: 'frost-reload-k7p9m2',
      nearAccountId: 'alice.testnet',
      signingStatus: 'active',
    });

    await page.reload({ waitUntil: 'domcontentloaded' });

    const afterReload = await page.evaluate(
      async ({ walletOrigin }) => {
        const { SeamsWeb } = (await import('/_test-sdk/esm/SeamsWeb/index.js')) as any;
        const walletId = 'frost-reload-k7p9m2';
        const walletSession = {
          walletId,
          walletSessionUserId: walletId,
        };
        const pm = new SeamsWeb({
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
        const session = await pm.auth.getWalletSession(walletId);
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
        const signResult = await pm.tempo
          .signTempo({
            walletSession,
            chainTarget: {
              kind: 'evm',
              namespace: 'eip155',
              chainId: 5042002,
              networkSlug: 'arc-testnet',
            },
            request: signRequest,
            options: { confirmationConfig: { uiMode: 'modal' } },
          })
          .then((result: unknown) => ({
            ok: true,
            chain: String((result as { chain?: unknown })?.chain || ''),
            kind: String((result as { kind?: unknown })?.kind || ''),
          }))
          .catch((error: unknown) => ({
            ok: false,
            code: String((error as { code?: unknown })?.code || ''),
            message: String((error as Error)?.message || error),
          }));
        return {
          loggedIn: !!session.login?.isLoggedIn,
          nearAccountId: session.login?.nearAccountId || null,
          signingSession: session.signingSession || null,
          signResult,
        };
      },
      { walletOrigin: WALLET_ORIGIN },
    );

    expect(afterReload.loggedIn).toBe(true);
    expect(afterReload.nearAccountId).toBe('alice.testnet');
    expect(afterReload.signingSession?.status).toBe('active');
    expect(afterReload.signResult).toMatchObject({
      ok: true,
      chain: 'evm',
      kind: 'eip1559',
    });
  });
});
