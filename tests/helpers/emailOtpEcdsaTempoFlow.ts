import type { Page } from '@playwright/test';
import {
  createSigningSessionSealPolicyFromThresholdAuthSessionStores,
  createSigningSessionSealRoutesOptions,
  createSigningSessionSealShamir3PassCipherAdapter,
} from '@server/threshold/session/signingSessionSeal';
import {
  createInMemoryJwtSessionAdapter,
  installCreateAccountAndRegisterUserMock,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  setupManagedThresholdRegistrationHarness,
  setupThresholdE2ePage,
  TEST_RELAYER_ACCOUNT_ID,
  TEST_RELAYER_PUBLIC_KEY,
} from '../e2e/thresholdEd25519.testUtils';

const SHAMIR_PRIME_B64U = '_____________________________________v___C8';
const SIGNING_SESSION_SEAL_KEY_VERSION = 'kek-s-email-otp-test';
const SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U = 'AQAB';
const SHAMIR_SERVER_DECRYPT_EXPONENT_B64U = '6LQXS-i0F0votBdL6LQXS-i0F0votBdL6LQXSv___Ic';
const DEFAULT_EMAIL = 'alice@example.com';
export const DEFAULT_EMAIL_OTP_CLIENT_SECRET_B64U = Buffer.from(
  new Uint8Array(32).fill(0x53),
).toString('base64url');

export type EmailOtpAuthPolicy = 'session' | 'per_operation';

export type EmailOtpEcdsaTempoHarness = {
  baseUrl: string;
  shamirPrimeB64u: string;
  signingSessionSealKeyVersion: string;
  defaultClientSecretB64u: string;
  mintAppSessionJwt: (args: {
    userId: string;
    walletId?: string;
    email?: string;
    deviceId?: string;
    rotate?: boolean;
  }) => Promise<string>;
  readEmailOtpEnrollment: (walletId: string) => Promise<unknown>;
  close: () => Promise<void>;
};

export type EmailOtpEcdsaTempoFlowOptions = {
  relayerUrl: string;
  shamirPrimeB64u: string;
  enrollAppSessionJwt: string;
  loginAppSessionJwt: string;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  clientSecretB64u?: string;
  accountId?: string;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  signingKind?: 'tempoTransaction' | 'eip1559';
  skipFirstSign?: boolean;
  signTwice?: boolean;
  signNearAfterLogin?: boolean;
  resendLoginOtpBeforeSubmit?: boolean;
  exportNearWithResend?: boolean;
  exportEcdsaWithResend?: boolean;
  signingSessionTtlMs?: number;
  signingSessionRemainingUses?: number;
};

export type EmailOtpEcdsaTempoFlowResult = {
  ok: boolean;
  accountId: string;
  registration?: {
    success: boolean;
  };
  ecdsaKeyBinding?: {
    ecdsaThresholdKeyId: string;
    participantIds: number[];
  };
  emailOtpEnrollment?: {
    challengeId: string;
    enrollmentSealKeyVersion: string;
    unlockKeyVersion: string;
  };
  emailOtpLogin?: {
    retention: 'session' | 'single_use';
    policy: EmailOtpAuthPolicy;
    challengeId: string;
    enrollmentSealKeyVersion: string;
    warmState: string;
  };
  otpCounters?: {
    enrollChallengeCount: number;
    loginChallengeCount: number;
    exportChallengeCount: number;
    signingChallengeCount: number;
  };
  webauthnCounters?: {
    createCount: number;
    getCount: number;
  };
  firstSign?: {
    ok: boolean;
    chain?: string;
    kind?: string;
    rawTxHex?: string;
    error?: string;
  };
  secondSign?: {
    ok: boolean;
    chain?: string;
    kind?: string;
    rawTxHex?: string;
    error?: string;
  };
  nearSign?: {
    ok: boolean;
    signedCount?: number;
    signerId?: string;
    receiverId?: string;
    error?: string;
  };
  exports?: {
    near?: {
      ok: boolean;
      exportedSchemes?: string[];
      error?: string;
    };
    ecdsa?: {
      ok: boolean;
      exportedSchemes?: string[];
      error?: string;
    };
  };
  error?: string;
};

export async function setupEmailOtpEcdsaTempoHarness(
  page: Page,
): Promise<EmailOtpEcdsaTempoHarness> {
  await setupThresholdE2ePage(page);

  const keysOnChain = new Set<string>();
  const nonceByPublicKey = new Map<string, number>();
  const accountsOnChain = new Set<string>();
  keysOnChain.add(TEST_RELAYER_PUBLIC_KEY);
  nonceByPublicKey.set(TEST_RELAYER_PUBLIC_KEY, 0);
  accountsOnChain.add(TEST_RELAYER_ACCOUNT_ID);
  const session = createInMemoryJwtSessionAdapter();
  const { service, threshold } = makeAuthServiceForThreshold(keysOnChain, {
    THRESHOLD_NODE_ROLE: 'coordinator',
    SIGNING_SESSION_SEAL_KEY_VERSION,
    SIGNING_SESSION_SHAMIR_P_B64U: SHAMIR_PRIME_B64U,
    SIGNING_SESSION_SEAL_E_S_B64U: SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U,
    SIGNING_SESSION_SEAL_D_S_B64U: SHAMIR_SERVER_DECRYPT_EXPONENT_B64U,
  });
  await service.getRelayerAccount();
  const thresholdAuthStores = threshold as unknown as {
    authSessionStore?: unknown;
    ecdsaAuthSessionStore?: unknown;
  };
  if (!thresholdAuthStores.authSessionStore || !thresholdAuthStores.ecdsaAuthSessionStore) {
    throw new Error(
      'Missing threshold auth session stores for Email OTP signing-session seal policy',
    );
  }
  const runtimePolicyScope = {
    orgId: 'org_threshold_ecdsa_email_otp',
    projectId: 'proj_threshold_ecdsa_email_otp',
    envId: 'dev',
    signingRootVersion: 'default',
  } as const;

  const harness = await setupManagedThresholdRegistrationHarness({
    page,
    service,
    threshold,
    session,
    keyName: 'threshold-ecdsa-email-otp-browser',
    orgId: runtimePolicyScope.orgId,
    orgSlug: 'threshold-ecdsa-email-otp-org',
    orgName: 'Threshold ECDSA Email OTP Org',
    projectId: runtimePolicyScope.projectId,
    projectName: 'Threshold ECDSA Email OTP Project',
    signingSessionSeal: createSigningSessionSealRoutesOptions({
      sessionPolicy: createSigningSessionSealPolicyFromThresholdAuthSessionStores({
        stores: [
          thresholdAuthStores.authSessionStore as any,
          thresholdAuthStores.ecdsaAuthSessionStore as any,
        ],
      }),
      cipher: createSigningSessionSealShamir3PassCipherAdapter({
        currentKeyVersion: SIGNING_SESSION_SEAL_KEY_VERSION,
        keys: [
          {
            keyVersion: SIGNING_SESSION_SEAL_KEY_VERSION,
            shamirPrimeB64u: SHAMIR_PRIME_B64U,
            serverEncryptExponentB64u: SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U,
            serverDecryptExponentB64u: SHAMIR_SERVER_DECRYPT_EXPONENT_B64U,
          },
        ],
      }),
      capabilities: {
        mode: 'sealed_refresh_v1',
        keyVersion: SIGNING_SESSION_SEAL_KEY_VERSION,
        shamirPrimeB64u: SHAMIR_PRIME_B64U,
      },
    }),
  });

  await installCreateAccountAndRegisterUserMock(page, {
    relayerBaseUrl: harness.baseUrl,
    session,
    threshold,
    runtimePolicyScope,
    onNewPublicKey: (publicKey) => {
      keysOnChain.add(publicKey);
      nonceByPublicKey.set(publicKey, 0);
    },
  });
  await page.route(
    `${harness.baseUrl}/registration/threshold-ed25519/hss/finalize`,
    async (route) => {
      const req = route.request();
      if (req.method().toUpperCase() !== 'POST') {
        await route.fallback();
        return;
      }
      const response = await route.fetch();
      const body = await response.body();
      try {
        const json = JSON.parse(body.toString('utf8') || '{}');
        for (const key of [json.publicKey, json.relayerKeyId]) {
          const publicKey = String(key || '').trim();
          if (publicKey) {
            keysOnChain.add(publicKey);
            nonceByPublicKey.set(publicKey, nonceByPublicKey.get(publicKey) ?? 0);
          }
        }
      } catch {}
      await route.fulfill({
        status: response.status(),
        headers: response.headers(),
        body,
      });
    },
  );
  await installFastNearRpcMock(page, {
    keysOnChain,
    nonceByPublicKey,
    strictAccessKeyLookup: false,
    accountsOnChain,
  });

  return {
    baseUrl: harness.baseUrl,
    shamirPrimeB64u: SHAMIR_PRIME_B64U,
    signingSessionSealKeyVersion: SIGNING_SESSION_SEAL_KEY_VERSION,
    defaultClientSecretB64u: DEFAULT_EMAIL_OTP_CLIENT_SECRET_B64U,
    mintAppSessionJwt: async ({ userId, walletId, email, deviceId, rotate }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        throw new Error('mintAppSessionJwt requires userId');
      }
      const normalizedWalletId = String(walletId || normalizedUserId).trim();
      accountsOnChain.add(normalizedWalletId);
      const versionResult = rotate
        ? await service.rotateAppSessionVersion({ userId: normalizedUserId })
        : await service.getOrCreateAppSessionVersion({ userId: normalizedUserId });
      if (!versionResult.ok) {
        throw new Error(versionResult.message || 'failed to create app session version');
      }
      return await session.signJwt(normalizedUserId, {
        kind: 'app_session_v1',
        sub: normalizedUserId,
        appSessionVersion: versionResult.appSessionVersion,
        email: String(email || DEFAULT_EMAIL).trim() || DEFAULT_EMAIL,
        deviceId: String(deviceId || 'browser-email-otp').trim() || 'browser-email-otp',
        runtimePolicyScope,
        walletId: normalizedWalletId,
      });
    },
    readEmailOtpEnrollment: async (walletId) => {
      const result = await service.readEmailOtpEnrollment({
        walletId,
        orgId: runtimePolicyScope.orgId,
      });
      return result;
    },
    close: harness.close,
  };
}

export async function runEmailOtpEcdsaTempoFlow(
  page: Page,
  options: EmailOtpEcdsaTempoFlowOptions,
): Promise<EmailOtpEcdsaTempoFlowResult> {
  return await page.evaluate(async (input) => {
    const decodeBase64UrlToBytes = (value: string): Uint8Array => {
      const normalized = String(value || '').trim();
      if (!normalized) return new Uint8Array();
      const base64 = normalized.replace(/-/g, '+').replace(/_/g, '/');
      const padded = base64 + '='.repeat((4 - (base64.length % 4 || 4)) % 4);
      const binary = globalThis.atob(padded);
      const bytes = new Uint8Array(binary.length);
      for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
      }
      return bytes;
    };

    const sdkMod = await import('/sdk/esm/index.js');
    const actionsMod = await import('/sdk/esm/core/types/actions.js');
    const { TatchiPasskey } = sdkMod as any;
    const { ActionType } = actionsMod as any;

    const accountId =
      typeof input.accountId === 'string' && input.accountId.trim()
        ? input.accountId.trim()
        : `emailotp${Date.now()}.w3a-v1.testnet`;
    const confirmationConfig = {
      uiMode: 'none' as const,
      behavior: 'skipClick' as const,
      autoProceedDelay: 0,
    };
    const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;
    const emailOtpAuthPolicy =
      input.emailOtpAuthPolicy === 'per_operation' ? 'per_operation' : 'session';

    const otpState = {
      enrollChallengeCount: 0,
      loginChallengeCount: 0,
      exportChallengeCount: 0,
      signingChallengeCount: 0,
    };
    const webauthnState = {
      createCount: 0,
      getCount: 0,
    };
    const originalCredentialsCreate = globalThis.navigator?.credentials?.create?.bind(
      globalThis.navigator.credentials,
    );
    const originalCredentialsGet = globalThis.navigator?.credentials?.get?.bind(
      globalThis.navigator.credentials,
    );
    if (globalThis.navigator?.credentials && originalCredentialsCreate) {
      globalThis.navigator.credentials.create = (async (...args: unknown[]) => {
        webauthnState.createCount += 1;
        return await originalCredentialsCreate(...(args as [CredentialCreationOptions]));
      }) as CredentialsContainer['create'];
    }
    if (globalThis.navigator?.credentials && originalCredentialsGet) {
      globalThis.navigator.credentials.get = (async (...args: unknown[]) => {
        webauthnState.getCount += 1;
        return await originalCredentialsGet(...(args as [CredentialRequestOptions]));
      }) as CredentialsContainer['get'];
    }

    const relayerUrl = String(input.relayerUrl || '').trim();
    const shamirPrimeB64u = String(input.shamirPrimeB64u || '').trim();
    const enrollAppSessionJwt = String(input.enrollAppSessionJwt || '').trim();
    const loginAppSessionJwt = String(input.loginAppSessionJwt || '').trim();
    const requestedEcdsaThresholdKeyId = String(input.ecdsaThresholdKeyId || '').trim();
    const participantIds = Array.isArray(input.participantIds)
      ? input.participantIds.map((value) => Number(value)).filter(Number.isFinite)
      : [1, 2];
    const clientSecretB64u = String(input.clientSecretB64u || '').trim();

    const joinUrl = (base: string, path: string): string =>
      `${String(base || '').replace(/\/+$/, '')}/${String(path || '').replace(/^\/+/, '')}`;

    const readEmailOtpOutbox = async (args: {
      challengeId: string;
      appSessionJwt: string;
      walletId: string;
    }): Promise<string> => {
      const challengeId = String(args.challengeId || '').trim();
      if (!challengeId) {
        throw new Error('missing Email OTP challengeId for test outbox lookup');
      }
      const outbox = await fetch(
        `${joinUrl(relayerUrl, '/wallet/email-otp/dev/otp-outbox')}?challengeId=${encodeURIComponent(challengeId)}&walletId=${encodeURIComponent(args.walletId)}`,
        {
          headers: args.appSessionJwt
            ? { Authorization: `Bearer ${args.appSessionJwt}` }
            : undefined,
        },
      );
      const outboxJson = await outbox.json().catch(() => ({}));
      const otpCode = String(outboxJson?.otpCode || '').trim();
      if (!otpCode) {
        throw new Error(`missing Email OTP test outbox entry for ${challengeId}`);
      }
      return otpCode;
    };

    const requestEmailOtpChallengeWithOutbox = async (args: {
      route: '/wallet/email-otp/registration/challenge' | '/wallet/email-otp/login/challenge';
      appSessionJwt: string;
      walletId: string;
      target: 'enroll' | 'login';
    }): Promise<{ challengeId: string; otpCode: string }> => {
      const response = await fetch(joinUrl(relayerUrl, args.route), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(args.appSessionJwt ? { Authorization: `Bearer ${args.appSessionJwt}` } : {}),
        },
        body: JSON.stringify({
          walletId: args.walletId,
          otpChannel: 'email_otp',
        }),
      });
      const text = await response.text();
      if (!response.ok) {
        throw new Error(`${args.route} failed: ${text || response.status}`);
      }
      const json = text ? JSON.parse(text) : null;
      const challengeId = String(json?.challenge?.challengeId || '').trim();
      if (!challengeId) {
        throw new Error(`${args.route} did not return challengeId`);
      }
      const otpCode = await readEmailOtpOutbox({
        challengeId,
        appSessionJwt: args.appSessionJwt,
        walletId: args.walletId,
      });
      if (args.target === 'enroll') {
        otpState.enrollChallengeCount += 1;
      } else {
        otpState.loginChallengeCount += 1;
      }
      return { challengeId, otpCode };
    };

    const requestEnrollmentOtp = async () =>
      await requestEmailOtpChallengeWithOutbox({
        route: '/wallet/email-otp/registration/challenge',
        appSessionJwt: enrollAppSessionJwt,
        walletId: accountId,
        target: 'enroll',
      });

    const requestLoginOtp = async () =>
      await requestEmailOtpChallengeWithOutbox({
        route: '/wallet/email-otp/login/challenge',
        appSessionJwt: loginAppSessionJwt,
        walletId: accountId,
        target: 'login',
      });

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
      emailOtpAuthPolicy,
      signingSessionPersistenceMode: 'sealed_refresh_v1',
      signingSessionSeal: {
        keyVersion: 'kek-s-email-otp-test',
        shamirPrimeB64u,
      },
      iframeWallet: {
        walletOrigin: '',
        walletServicePath: '/wallet-service',
        sdkBasePath: '/sdk',
        rpIdOverride: 'example.localhost',
      },
    });
    try {
      const context = pm.getContext() as any;
      if (context?.configs?.signing?.sessionSeal) {
        context.configs.signing.sessionSeal.shamirPrimeB64u = shamirPrimeB64u;
      }
      if (context?.signingEngine?.tatchiPasskeyConfigs?.signing?.sessionSeal) {
        context.signingEngine.tatchiPasskeyConfigs.signing.sessionSeal.shamirPrimeB64u =
          shamirPrimeB64u;
      }
    } catch {}

    const signingKind = input.signingKind === 'eip1559' ? 'eip1559' : 'tempoTransaction';
    const bootstrapChain = signingKind === 'eip1559' ? 'evm' : 'tempo';
    const makeThresholdEcdsaRequest = (tag: string) =>
      signingKind === 'eip1559'
        ? {
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
          }
        : {
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
          };

    try {
      const signingEngine = pm.getContext().signingEngine as any;
      const enrollmentOtp = await requestEnrollmentOtp();
      const enrollmentLogin = await signingEngine.enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(
        {
          nearAccountId: accountId,
          chain: bootstrapChain,
          emailOtpAuthPolicy,
          challengeId: enrollmentOtp.challengeId,
          otpCode: enrollmentOtp.otpCode,
          appSessionJwt: enrollAppSessionJwt,
          routeAuth: { kind: 'app_session', jwt: enrollAppSessionJwt },
          sessionKind: 'jwt',
          ...(requestedEcdsaThresholdKeyId
            ? { ecdsaThresholdKeyId: requestedEcdsaThresholdKeyId }
            : {}),
          participantIds,
          ...(clientSecretB64u ? { clientSecret32: decodeBase64UrlToBytes(clientSecretB64u) } : {}),
          ...(typeof input.signingSessionTtlMs === 'number'
            ? { ttlMs: input.signingSessionTtlMs }
            : {}),
          ...(typeof input.signingSessionRemainingUses === 'number'
            ? { remainingUses: input.signingSessionRemainingUses }
            : {}),
        },
      );
      const enrolled = enrollmentLogin?.enrollment || {};
      const ecdsaThresholdKeyId = String(
        enrollmentLogin?.bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId || '',
      ).trim();
      const resolvedParticipantIds = Array.isArray(
        enrollmentLogin?.bootstrap?.thresholdEcdsaKeyRef?.participantIds,
      )
        ? enrollmentLogin.bootstrap.thresholdEcdsaKeyRef.participantIds
            .map((value: unknown) => Number(value))
            .filter(Number.isFinite)
        : participantIds;
      if (!ecdsaThresholdKeyId || resolvedParticipantIds.length === 0) {
        return {
          ok: false,
          accountId,
          emailOtpEnrollment: {
            challengeId: String(enrolled?.challengeId || ''),
            enrollmentSealKeyVersion: String(enrolled?.enrollmentSealKeyVersion || ''),
            unlockKeyVersion: String(enrolled?.unlockKeyVersion || ''),
          },
          error: 'Email OTP registration bootstrap did not return canonical ECDSA key metadata',
        };
      }

      await signingEngine.clearWarmSigningSessions(accountId).catch(() => undefined);

      const firstLoginOtp = await requestLoginOtp();
      const loginOtp =
        input.resendLoginOtpBeforeSubmit === true ? await requestLoginOtp() : firstLoginOtp;
      const loggedIn = await signingEngine.loginWithEmailOtpEcdsaCapabilityInternal({
        nearAccountId: accountId,
        chain: bootstrapChain,
        emailOtpAuthPolicy,
        challengeId: loginOtp.challengeId,
        otpCode: loginOtp.otpCode,
        appSessionJwt: loginAppSessionJwt,
        routeAuth: { kind: 'app_session', jwt: loginAppSessionJwt },
        ecdsaThresholdKeyId,
        participantIds: resolvedParticipantIds,
        sessionKind: 'jwt',
        ...(typeof input.signingSessionTtlMs === 'number'
          ? { ttlMs: input.signingSessionTtlMs }
          : {}),
        ...(typeof input.signingSessionRemainingUses === 'number'
          ? { remainingUses: input.signingSessionRemainingUses }
          : {}),
      });

      const exportOptionsRequested =
        input.exportNearWithResend === true || input.exportEcdsaWithResend === true;
      const originalRequestUserConfirmation =
        typeof signingEngine?.touchConfirm?.requestUserConfirmation === 'function'
          ? signingEngine.touchConfirm.requestUserConfirmation.bind(signingEngine.touchConfirm)
          : null;
      if (
        (exportOptionsRequested || emailOtpAuthPolicy === 'per_operation') &&
        originalRequestUserConfirmation
      ) {
        signingEngine.touchConfirm.requestUserConfirmation = async (
          request: Record<string, any>,
          requestOptions?: Record<string, any>,
        ) => {
          const requestType = String(request?.type || '');
          if (requestType === 'showSecurePrivateKeyUi') {
            return { confirmed: true };
          }
          const intentDigest = String(request?.intentDigest || '');
          const prompt =
            request?.payload?.signingAuthPlan?.emailOtpPrompt || request?.payload?.emailOtpPrompt;
          if (
            requestType === 'signIntentDigest' &&
            prompt &&
            intentDigest.startsWith(`export-keys:${accountId}:`)
          ) {
            otpState.exportChallengeCount += 1;
            let challengeId = String(prompt.challengeId || '').trim();
            const shouldResend =
              (intentDigest.includes(':near:') && input.exportNearWithResend === true) ||
              ((intentDigest.includes(':evm:') || intentDigest.includes(':tempo:')) &&
                input.exportEcdsaWithResend === true);
            if (shouldResend && typeof prompt.onResend === 'function') {
              const resent = await prompt.onResend();
              otpState.exportChallengeCount += 1;
              challengeId = String(resent?.challengeId || '').trim();
            }
            const otpCode = await readEmailOtpOutbox({
              challengeId,
              appSessionJwt: loginAppSessionJwt,
              walletId: accountId,
            });
            return {
              confirmed: true,
              otpCode,
              emailOtpChallengeId: challengeId,
            };
          }
          if (requestType === 'signIntentDigest' && prompt) {
            otpState.signingChallengeCount += 1;
            const challengeId = String(prompt.challengeId || '').trim();
            const otpCode = await readEmailOtpOutbox({
              challengeId,
              appSessionJwt: loginAppSessionJwt,
              walletId: accountId,
            });
            return {
              confirmed: true,
              otpCode,
              emailOtpChallengeId: challengeId,
            };
          }
          return await originalRequestUserConfirmation(request as any, requestOptions as any);
        };
      }

      const firstSignResult =
        input.skipFirstSign === true
          ? undefined
          : await (async () => {
              try {
                const signed = await pm.tempo.signTempo({
                  nearAccountId: accountId,
                  request: makeThresholdEcdsaRequest('a1'),
                  options: { confirmationConfig },
                });
                return {
                  ok: true,
                  chain: String(signed?.chain || ''),
                  kind: String(signed?.kind || ''),
                  rawTxHex: String(signed?.rawTxHex || ''),
                };
              } catch (error: unknown) {
                return {
                  ok: false,
                  error:
                    error && typeof error === 'object' && 'message' in error
                      ? String((error as { message?: unknown }).message || '')
                      : String(error || 'first sign failed'),
                };
              }
            })();

      const secondSignResult =
        input.skipFirstSign === true || input.signTwice === false
          ? undefined
          : await (async () => {
              try {
                const signed = await pm.tempo.signTempo({
                  nearAccountId: accountId,
                  request: makeThresholdEcdsaRequest('b2'),
                  options: { confirmationConfig },
                });
                return {
                  ok: true,
                  chain: String(signed?.chain || ''),
                  kind: String(signed?.kind || ''),
                  rawTxHex: String(signed?.rawTxHex || ''),
                };
              } catch (error: unknown) {
                return {
                  ok: false,
                  error:
                    error && typeof error === 'object' && 'message' in error
                      ? String((error as { message?: unknown }).message || '')
                      : String(error || 'second sign failed'),
                };
              }
            })();

      const nearSignResult =
        input.signNearAfterLogin === true
          ? await (async () => {
              try {
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
                const first = Array.isArray(signed) ? signed[0] : null;
                const tx = (first as any)?.signedTransaction?.transaction || {};
                return {
                  ok: Array.isArray(signed) && signed.length === 1,
                  signedCount: Array.isArray(signed) ? signed.length : 0,
                  signerId: String(tx.signerId || ''),
                  receiverId: String(tx.receiverId || ''),
                };
              } catch (error: unknown) {
                return {
                  ok: false,
                  error:
                    error && typeof error === 'object' && 'message' in error
                      ? String((error as { message?: unknown }).message || '')
                      : String(error || 'near sign failed'),
                };
              }
            })()
          : undefined;

      const exportResults =
        input.exportNearWithResend === true || input.exportEcdsaWithResend === true
          ? {
              ...(input.exportNearWithResend === true
                ? {
                    near: await (async () => {
                      try {
                        const exported = await pm.keys.exportKeypairWithUI(accountId, {
                          chain: 'near',
                          variant: 'drawer',
                        });
                        return {
                          ok: true,
                          exportedSchemes: Array.isArray(exported?.exportedSchemes)
                            ? exported.exportedSchemes.map((value: unknown) => String(value))
                            : ['ed25519'],
                        };
                      } catch (error: unknown) {
                        return {
                          ok: false,
                          error:
                            error && typeof error === 'object' && 'message' in error
                              ? String((error as { message?: unknown }).message || '')
                              : String(error || 'near export failed'),
                        };
                      }
                    })(),
                  }
                : {}),
              ...(input.exportEcdsaWithResend === true
                ? {
                    ecdsa: await (async () => {
                      try {
                        const exported = await pm.keys.exportKeypairWithUI(accountId, {
                          chain: bootstrapChain,
                          variant: 'drawer',
                        });
                        return {
                          ok: true,
                          exportedSchemes: Array.isArray(exported?.exportedSchemes)
                            ? exported.exportedSchemes.map((value: unknown) => String(value))
                            : ['secp256k1'],
                        };
                      } catch (error: unknown) {
                        return {
                          ok: false,
                          error:
                            error && typeof error === 'object' && 'message' in error
                              ? String((error as { message?: unknown }).message || '')
                              : String(error || 'ecdsa export failed'),
                        };
                      }
                    })(),
                  }
                : {}),
            }
          : undefined;

      return {
        ok: true,
        accountId,
        registration: { success: true },
        ecdsaKeyBinding: {
          ecdsaThresholdKeyId,
          participantIds: resolvedParticipantIds,
        },
        emailOtpEnrollment: {
          challengeId: String(enrolled?.challengeId || ''),
          enrollmentSealKeyVersion: String(enrolled?.enrollmentSealKeyVersion || ''),
          unlockKeyVersion: String(enrolled?.unlockKeyVersion || ''),
        },
        emailOtpLogin: {
          retention: String(loggedIn?.warmCapability?.emailOtpAuthContext?.retention || '') as
            | 'session'
            | 'single_use',
          policy: String(
            loggedIn?.warmCapability?.emailOtpAuthContext?.policy || '',
          ) as EmailOtpAuthPolicy,
          challengeId: String(loggedIn?.recovery?.challengeId || ''),
          enrollmentSealKeyVersion: String(loggedIn?.recovery?.enrollmentSealKeyVersion || ''),
          warmState: String(loggedIn?.warmCapability?.state || ''),
        },
        otpCounters: {
          enrollChallengeCount: otpState.enrollChallengeCount,
          loginChallengeCount: otpState.loginChallengeCount,
          exportChallengeCount: otpState.exportChallengeCount,
          signingChallengeCount: otpState.signingChallengeCount,
        },
        webauthnCounters: webauthnState,
        ...(firstSignResult ? { firstSign: firstSignResult } : {}),
        ...(secondSignResult ? { secondSign: secondSignResult } : {}),
        ...(nearSignResult ? { nearSign: nearSignResult } : {}),
        ...(exportResults ? { exports: exportResults } : {}),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        accountId,
        error:
          error && typeof error === 'object' && 'message' in error
            ? String((error as { message?: unknown }).message || '')
            : String(error || 'email otp ecdsa tempo flow failed'),
      };
    }
  }, options);
}
export type ReloadSignKind = 'near' | 'tempo' | 'evm' | 'exportNear' | 'exportEcdsa';

export async function runEmailOtpReloadPhase(
  page: Page,
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
  results?: Array<{
    kind: string;
    ok: boolean;
    chain?: string;
    error?: string;
    promptCountBefore?: number;
    promptCountAfter?: number;
    webauthnGetCountBefore?: number;
    webauthnGetCountAfter?: number;
  }>;
  emailOtpPromptCount?: number;
  webauthnGetCount?: number;
  sealedRecordSummaries?: Array<Record<string, unknown>>;
  runtimeDiagnostics?: Record<string, unknown>;
  promptCountBeforeExports?: number;
  promptCountAfterExports?: number;
  promptCountAfterFinalSign?: number;
  authPromptEvents?: Array<{
    requestType: string;
    kind: string;
    method: string;
    hasEmailOtpPrompt: boolean;
  }>;
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

      const readSealedRecordSummaries = async (): Promise<Array<Record<string, unknown>>> => {
        const indexedDb = globalThis.indexedDB;
        if (!indexedDb) return [];
        const openRequest = indexedDb.open('tatchi_wallet_v1');
        const db = await new Promise<IDBDatabase | null>((resolve) => {
          openRequest.onerror = () => resolve(null);
          openRequest.onsuccess = () => resolve(openRequest.result);
        });
        if (!db || !Array.from(db.objectStoreNames).includes('signing_session_seals_v1')) {
          db?.close();
          return [];
        }
        try {
          const tx = db.transaction('signing_session_seals_v1', 'readonly');
          const store = tx.objectStore('signing_session_seals_v1');
          const getAllRequest = store.getAll();
          const values = await new Promise<unknown[]>((resolve) => {
            getAllRequest.onerror = () => resolve([]);
            getAllRequest.onsuccess = () =>
              resolve(Array.isArray(getAllRequest.result) ? getAllRequest.result : []);
          });
          return values
            .map((value) =>
              value && typeof value === 'object' && !Array.isArray(value)
                ? (value as Record<string, unknown>)
                : null,
            )
            .filter((record): record is Record<string, unknown> => Boolean(record))
            .filter((record) => record.walletId === accountId || record.userId === accountId)
            .map((record) => ({
              storeKey: record.storeKey,
              walletId: record.walletId,
              userId: record.userId,
              authMethod: record.authMethod,
              curve: record.curve,
              thresholdSessionIds: record.thresholdSessionIds,
              hasRelayerUrl: Boolean(record.relayerUrl),
              hasSigningRootId: Boolean(record.signingRootId),
              ecdsaChain:
                record.ecdsaRestore &&
                typeof record.ecdsaRestore === 'object' &&
                !Array.isArray(record.ecdsaRestore)
                  ? (record.ecdsaRestore as Record<string, unknown>).chain
                  : undefined,
              hasEd25519Restore: Boolean(record.ed25519Restore),
              ed25519RestoreKeys:
                record.ed25519Restore &&
                typeof record.ed25519Restore === 'object' &&
                !Array.isArray(record.ed25519Restore)
                  ? Object.keys(record.ed25519Restore as Record<string, unknown>).sort()
                  : [],
              hasSealedSecret: Boolean(record.sealedSecretB64u),
            }));
        } finally {
          db.close();
        }
      };
      const readRuntimeDiagnostics = async (): Promise<Record<string, unknown>> => {
        const [thresholdStore, sealedStore] = await Promise.all([
          import('/sdk/esm/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.js').catch(
            () => null,
          ),
          import('/sdk/esm/core/signingEngine/session/sealedSessionStore.js').catch(() => null),
        ]);
        const ed25519Record =
          thresholdStore &&
          typeof (thresholdStore as any).getStoredThresholdEd25519SessionRecordForAccount ===
            'function'
            ? (thresholdStore as any).getStoredThresholdEd25519SessionRecordForAccount(accountId)
            : null;
        const identities =
          sealedStore && typeof (sealedStore as any).listResolvedIdentitiesForAccount === 'function'
            ? (sealedStore as any).listResolvedIdentitiesForAccount({
                walletId: accountId,
                curve: 'ed25519',
              })
            : [];
        return {
          ed25519Record: ed25519Record
            ? {
                source: ed25519Record.source,
                thresholdSessionId: ed25519Record.thresholdSessionId,
                walletSigningSessionId: ed25519Record.walletSigningSessionId,
                retention: ed25519Record.emailOtpAuthContext?.retention,
                hasJwt: Boolean(ed25519Record.thresholdSessionJwt),
                hasClientBase: Boolean(ed25519Record.xClientBaseB64u),
              }
            : null,
          ed25519Identities: Array.isArray(identities)
            ? identities.map((identity) => ({
                authMethod: identity.authMethod,
                curve: identity.curve,
                chain: identity.chain,
                thresholdSessionId: identity.thresholdSessionId,
                walletSigningSessionId: identity.walletSigningSessionId,
              }))
            : [],
        };
      };

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
        const authPromptEvents: Array<{
          requestType: string;
          kind: string;
          method: string;
          hasEmailOtpPrompt: boolean;
        }> = [];
        if (originalRequestUserConfirmation) {
          const buildNearTransactionDecisionExtras = async (
            request: Record<string, any>,
          ): Promise<Record<string, unknown>> => {
            if (String(request?.type || '') !== 'signTransaction') {
              return {};
            }
            const touchConfirmContext =
              typeof signingEngine?.touchConfirm?.getContext === 'function'
                ? signingEngine.touchConfirm.getContext()
                : null;
            if (!touchConfirmContext) {
              throw new Error('missing touchConfirm context for headless NEAR confirmation');
            }
            const [{ createConfirmTxFlowAdapters }, { nonceLeaseToRef }, readinessRegistry] =
              await Promise.all([
                import('/sdk/esm/core/signingEngine/touchConfirm/handlers/flows/adapters/adapters.js'),
                import('/sdk/esm/core/signingEngine/nonce/NonceCoordinator.js'),
                import('/sdk/esm/core/signingEngine/touchConfirm/confirmationReadinessRegistry.js').catch(
                  () => null,
                ),
              ]);

            // The production modal waits for this hook before confirming a transaction.
            // The e2e shortcut must do the same or it can race signing-session reauth.
            const readiness =
              readinessRegistry &&
              typeof (readinessRegistry as any).consumeConfirmationReadiness === 'function'
                ? (readinessRegistry as any).consumeConfirmationReadiness(
                    String(request?.requestId || ''),
                  )
                : undefined;
            if (readiness?.promise) {
              await readiness.promise;
            }

            const payload = request?.payload || {};
            const nearAccountId = String(payload?.rpcCall?.nearAccountId || accountId).trim();
            const txCount = Array.isArray(payload?.txSigningRequests)
              ? payload.txSigningRequests.length
              : 1;
            const reserveNonces = String(request?.summary?.type || '') !== 'delegateAction';
            const nearAdapters = createConfirmTxFlowAdapters(touchConfirmContext).near;
            const nearContext = await nearAdapters.fetchNearContext({
              nearAccountId,
              nearPublicKeyStr: String(payload?.nearPublicKeyStr || '').trim() || undefined,
              txCount,
              reserveNonces,
              allowFallback: false,
              operationId: String(request?.requestId || ''),
              operationFingerprint: String(
                request?.intentDigest || payload?.intentDigest || request?.requestId || '',
              ),
            });
            if (!nearContext?.transactionContext) {
              throw new Error(
                String(
                  nearContext?.details ||
                    nearContext?.error ||
                    'missing NEAR transaction context for headless confirmation',
                ),
              );
            }
            return {
              transactionContext: nearContext.transactionContext,
              ...(Array.isArray(nearContext.nonceLeases) && nearContext.nonceLeases.length
                ? {
                    nonceLeases: nearContext.nonceLeases.map((lease: unknown) =>
                      nonceLeaseToRef(lease as any),
                    ),
                  }
                : {}),
            };
          };

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
            const signingAuthPlan = request?.payload?.signingAuthPlan || null;
            if (prompt || signingAuthPlan) {
              authPromptEvents.push({
                requestType,
                kind: String(signingAuthPlan?.kind || ''),
                method: String(signingAuthPlan?.method || ''),
                hasEmailOtpPrompt: Boolean(prompt),
              });
            }
            if (prompt) {
              emailOtpPromptCount += 1;
              const challengeId = String(prompt.challengeId || '').trim();
              const otpCode = await readEmailOtpOutbox(challengeId);
              const decisionExtras = await buildNearTransactionDecisionExtras(request);
              return {
                ...decisionExtras,
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

        const results: Array<{
          kind: string;
          ok: boolean;
          chain?: string;
          error?: string;
          promptCountBefore: number;
          promptCountAfter: number;
          webauthnGetCountBefore: number;
          webauthnGetCountAfter: number;
        }> = [];
        const signOne = async (kind: ReloadSignKind, tag: string) => {
          const promptCountBefore = emailOtpPromptCount;
          const webauthnGetCountBefore = webauthnState.getCount;
          const pushResult = (result: {
            kind: string;
            ok: boolean;
            chain?: string;
            error?: string;
          }) => {
            results.push({
              ...result,
              promptCountBefore,
              promptCountAfter: emailOtpPromptCount,
              webauthnGetCountBefore,
              webauthnGetCountAfter: webauthnState.getCount,
            });
          };
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
              pushResult({
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
              pushResult({ kind, ok: signed?.kind === 'tempoTransaction', chain: signed?.chain });
              return;
            }
            if (kind === 'evm') {
              const signed = await pm.tempo.signTempo({
                nearAccountId: accountId,
                request: evmRequest(tag),
                options: { confirmationConfig },
              });
              pushResult({ kind, ok: signed?.kind === 'eip1559', chain: signed?.chain });
              return;
            }
            if (kind === 'exportNear') {
              const exported = await pm.keys.exportKeypairWithUI(accountId, {
                chain: 'near',
                variant: 'drawer',
              });
              pushResult({
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
              pushResult({
                kind,
                ok: Array.isArray(exported?.exportedSchemes)
                  ? exported.exportedSchemes.includes('secp256k1')
                  : true,
                chain: 'tempo',
              });
            }
          } catch (error: unknown) {
            pushResult({
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
          sealedRecordSummaries: await readSealedRecordSummaries(),
          runtimeDiagnostics: await readRuntimeDiagnostics(),
          promptCountBeforeExports: promptCountBeforeExports ?? emailOtpPromptCount,
          promptCountAfterExports,
          promptCountAfterFinalSign: emailOtpPromptCount,
          authPromptEvents,
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
