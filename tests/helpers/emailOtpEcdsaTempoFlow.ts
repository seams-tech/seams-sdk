import type { Page } from '@playwright/test';
import type {
  EmailOtpRegistrationAttemptStore,
  GoogleEmailOtpRegistrationAttemptRecord,
} from '@server/core/EmailOtpStores';
import type { WalletStore } from '@server/core/WalletStore';
import {
  createSigningSessionSealPolicyFromWalletSessionStores,
  createSigningSessionSealRoutesOptions,
  createSigningSessionSealShamir3PassCipherAdapter,
} from '@server/threshold/session/signingSessionSeal';
import { parseWalletId } from '@shared/utils/domainIds';
import {
  parseRouterAbPublicKeysetV2,
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
} from '@shared/utils/routerAbPublicKeyset';
import {
  createInMemoryJwtSessionAdapter,
  installRegistrationBootstrapMock,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  setupManagedThresholdRegistrationHarness,
  setupRouterAbEcdsaHssPrivateSigningWorker,
  setupThresholdE2ePage,
  TEST_RELAYER_ACCOUNT_ID,
  TEST_RELAYER_PUBLIC_KEY,
} from '../e2e/thresholdEd25519.testUtils';

const SHAMIR_PRIME_B64U = '_____________________________________v___C8';
const SIGNING_SESSION_SEAL_KEY_VERSION = 'signing-session-seal-kek-email-otp-test-r1';
const SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U = 'AQAB';
const SHAMIR_SERVER_DECRYPT_EXPONENT_B64U = '6LQXS-i0F0votBdL6LQXS-i0F0votBdL6LQXSv___Ic';
const DEFAULT_EMAIL = 'alice@example.com';
export const DEFAULT_EMAIL_OTP_CLIENT_SECRET_B64U = Buffer.from(
  new Uint8Array(32).fill(0x53),
).toString('base64url');
const TEST_ROUTER_AB_PUBLIC_KEYSET = parseRouterAbPublicKeysetV2({
  keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  signer_envelope_hpke: {
    current: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-a',
        public_key: 'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-b',
        public_key: 'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
    },
  },
  signer_peer_verifying_keys: {
    deriver_a: {
      role: 'signer_a',
      verifying_key_hex: '5afa80b305e72e02615ed1f580144a40a42a71dfcac175809ceb5d79e740d015',
    },
    deriver_b: {
      role: 'signer_b',
      verifying_key_hex: '0c700dd63695221e508f3164b528f190bed63a4437d38e882308f9a57acc1bc3',
    },
  },
  signing_worker_server_output_hpke: {
    key_epoch: 'epoch-server',
    public_key: 'x25519:3333333333333333333333333333333333333333333333333333333333333333',
  },
});

type EmailOtpRegistrationAttemptStoreAccess = {
  getEmailOtpRegistrationAttemptStore: () => EmailOtpRegistrationAttemptStore;
};

type WalletStoreAccess = {
  getWalletStore: () => WalletStore;
};

const makeFixtureId = (prefix: string): string => {
  const randomPart =
    typeof globalThis.crypto?.randomUUID === 'function'
      ? globalThis.crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${randomPart}`;
};

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
    accountMode?: 'register' | 'login';
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
  const signingWorker = await setupRouterAbEcdsaHssPrivateSigningWorker();
  const session = createInMemoryJwtSessionAdapter();
  const { service, threshold } = makeAuthServiceForThreshold(keysOnChain, {
    THRESHOLD_NODE_ROLE: 'coordinator',
    ROUTER_AB_SIGNING_WORKER_URL: signingWorker.baseUrl,
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'test-router-ab-internal-service-auth',
    SIGNING_SESSION_SEAL_KEY_VERSION,
    SIGNING_SESSION_SHAMIR_P_B64U: SHAMIR_PRIME_B64U,
    SIGNING_SESSION_SEAL_E_S_B64U: SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U,
    SIGNING_SESSION_SEAL_D_S_B64U: SHAMIR_SERVER_DECRYPT_EXPONENT_B64U,
  });
  await service.getRelayerAccount();
  const thresholdWalletSessionStores = threshold as unknown as {
    walletSessionStore?: unknown;
    ecdsaWalletSessionStore?: unknown;
  };
  if (
    !thresholdWalletSessionStores.walletSessionStore ||
    !thresholdWalletSessionStores.ecdsaWalletSessionStore
  ) {
    throw new Error(
      'Missing Wallet Session stores for Email OTP signing-session seal policy',
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
      sessionPolicy: createSigningSessionSealPolicyFromWalletSessionStores({
        ed25519Stores: [thresholdWalletSessionStores.walletSessionStore as any],
        ecdsaStores: [thresholdWalletSessionStores.ecdsaWalletSessionStore as any],
        walletBudgetStores: [thresholdWalletSessionStores.walletSessionStore as any],
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
    routerAbPublicKeyset: TEST_ROUTER_AB_PUBLIC_KEYSET,
  });

  await installRegistrationBootstrapMock(page, {
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
    `${harness.baseUrl}/v2/router-ab/ed25519/hss/finalize`,
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
        const publicKey = String(json.publicKey || '').trim();
        if (publicKey) {
          keysOnChain.add(publicKey);
          nonceByPublicKey.set(publicKey, nonceByPublicKey.get(publicKey) ?? 0);
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
    mintAppSessionJwt: async ({ userId, walletId, email, deviceId, rotate, accountMode }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        throw new Error('mintAppSessionJwt requires userId');
      }
      const normalizedWalletId = String(walletId || normalizedUserId).trim();
      const parsedWalletId = parseWalletId(normalizedWalletId);
      if (!parsedWalletId.ok) {
        throw new Error(parsedWalletId.error.message);
      }
      const normalizedEmail = String(email || DEFAULT_EMAIL).trim() || DEFAULT_EMAIL;
      const providerSubject = normalizedUserId.startsWith('google:')
        ? normalizedUserId
        : `google:${normalizedUserId}`;
      accountsOnChain.add(normalizedWalletId);
      const versionResult = rotate
        ? await service.rotateAppSessionVersion({ userId: normalizedUserId })
        : await service.getOrCreateAppSessionVersion({ userId: normalizedUserId });
      if (!versionResult.ok) {
        throw new Error(versionResult.message || 'failed to create app session version');
      }
      const walletStore = (service as unknown as WalletStoreAccess).getWalletStore();
      const existingWallet = await walletStore.getWallet({ walletId: parsedWalletId.value });
      if (!existingWallet) {
        const nowMs = Date.now();
        await walletStore.putSubject({
          version: 'wallet_v1',
          walletId: parsedWalletId.value,
          rpId: 'example.localhost',
          createdAtMs: nowMs,
          updatedAtMs: nowMs,
        });
      }
      const effectiveAccountMode = accountMode || 'register';
      let registrationAttemptId = '';
      if (effectiveAccountMode === 'register') {
        const attemptId = makeFixtureId('email-otp-registration-attempt');
        const selectedCandidateId = makeFixtureId('email-otp-offer-candidate');
        const nowMs = Date.now();
        const attempt: GoogleEmailOtpRegistrationAttemptRecord = {
          version: 'google_email_otp_registration_attempt_v1',
          attemptId,
          providerSubject,
          email: normalizedEmail,
          walletId: normalizedWalletId,
          offerId: makeFixtureId('email-otp-offer'),
          offerCandidates: [
            {
              candidateId: selectedCandidateId,
              walletId: normalizedWalletId,
              collisionCounter: 0,
            },
          ],
          selectedCandidateId,
          appSessionVersion: versionResult.appSessionVersion,
          authProvider: 'google_oidc',
          accountIdSlugVersion: 'hmac_readable_v1',
          walletIdDerivationNonce: makeFixtureId('email-otp-wallet-nonce'),
          collisionCounter: 0,
          state: 'started',
          createdAtMs: nowMs,
          updatedAtMs: nowMs,
          expiresAtMs: nowMs + 30 * 60 * 1000,
          runtimePolicyScope,
        };
        await (service as unknown as EmailOtpRegistrationAttemptStoreAccess)
          .getEmailOtpRegistrationAttemptStore()
          .put(attempt);
        registrationAttemptId = attemptId;
      }
      return await session.signJwt(normalizedUserId, {
        kind: 'app_session_v1',
        sub: normalizedUserId,
        appSessionVersion: versionResult.appSessionVersion,
        email: normalizedEmail,
        deviceId: String(deviceId || 'browser-email-otp').trim() || 'browser-email-otp',
        provider: 'oidc',
        oidcProvider: 'google',
        providerSubject,
        runtimePolicyScope,
        walletId: normalizedWalletId,
        ...(registrationAttemptId
          ? {
              googleEmailOtpRegistrationAttemptId: registrationAttemptId,
              googleEmailOtpResolutionMode: 'register_started',
            }
          : {}),
      });
    },
    readEmailOtpEnrollment: async (walletId) => {
      const result = await service.readEmailOtpEnrollment({
        walletId,
        orgId: runtimePolicyScope.orgId,
      });
      return result;
    },
    close: async () => {
      await Promise.all([harness.close(), signingWorker.close()]);
    },
  };
}

export async function runEmailOtpEcdsaTempoFlow(
  page: Page,
  options: EmailOtpEcdsaTempoFlowOptions,
): Promise<EmailOtpEcdsaTempoFlowResult> {
  return await page.evaluate(async (input: EmailOtpEcdsaTempoFlowOptions) => {
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
    const decodeJwtClaims = (jwt: string): Record<string, unknown> => {
      const payloadB64u = String(jwt || '').split('.')[1] || '';
      if (!payloadB64u) return {};
      try {
        return JSON.parse(new TextDecoder().decode(decodeBase64UrlToBytes(payloadB64u)));
      } catch {
        return {};
      }
    };
    const readRuntimePolicyScope = (
      value: unknown,
    ): {
      orgId: string;
      projectId: string;
      envId: string;
      signingRootVersion: string;
    } | null => {
      if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
      const record = value as Record<string, unknown>;
      const orgId = String(record.orgId || '').trim();
      const projectId = String(record.projectId || '').trim();
      const envId = String(record.envId || '').trim();
      const signingRootVersion = String(record.signingRootVersion || '').trim();
      if (!orgId || !projectId || !envId || !signingRootVersion) return null;
      return { orgId, projectId, envId, signingRootVersion };
    };
    const withStageTimeout = async <T>(
      stage: string,
      promise: Promise<T>,
      timeoutMs = 60_000,
    ): Promise<T> => {
      let timeoutId: ReturnType<typeof setTimeout> | undefined;
      const timeout = new Promise<never>((_, reject) => {
        timeoutId = setTimeout(() => {
          reject(new Error(`Email OTP ECDSA Tempo flow timed out during ${stage}`));
        }, timeoutMs);
      });
      try {
        return await Promise.race([promise, timeout]);
      } finally {
        if (timeoutId) clearTimeout(timeoutId);
      }
    };

    const sdkMod = await import('/sdk/esm/index.js');
    const { SeamsWeb } = sdkMod as any;
    const { ActionType } = sdkMod as any;

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
    const enrollAppSessionClaims = decodeJwtClaims(enrollAppSessionJwt);
    const loginAppSessionClaims = decodeJwtClaims(loginAppSessionJwt);
    const runtimePolicyScope =
      readRuntimePolicyScope(loginAppSessionClaims.runtimePolicyScope) ||
      readRuntimePolicyScope(enrollAppSessionClaims.runtimePolicyScope);
    const registrationAttemptId = String(
      enrollAppSessionClaims.googleEmailOtpRegistrationAttemptId || '',
    ).trim();
    const requestedKeyHandle = String(input.ecdsaThresholdKeyId || '').trim();
    const participantIds = Array.isArray(input.participantIds)
      ? input.participantIds.map((value) => Number(value)).filter(Number.isFinite)
      : [1, 2];
    const clientSecretB64u = String(input.clientSecretB64u || '').trim();

    const joinUrl = (base: string, path: string): string =>
      `${String(base || '').replace(/\/+$/, '')}/${String(path || '').replace(/^\/+/, '')}`;

    const postRegistrationHssJson = async <T>(
      path: string,
      body: Record<string, unknown>,
    ): Promise<T> => {
      const response = await fetch(joinUrl(relayerUrl, path), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${enrollAppSessionJwt}`,
        },
        credentials: 'omit',
        body: JSON.stringify(body),
      });
      const text = await response.text();
      const json = (text ? JSON.parse(text) : {}) as Record<string, any>;
      if (!response.ok || json.ok !== true) {
        throw new Error(
          `${path} failed: ${String(json.message || json.code || text || response.status)}`,
        );
      }
      return json as T;
    };

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

    const pm = new SeamsWeb({
      nearNetwork: 'testnet',
      nearRpcUrl: 'https://test.rpc.fastnear.com',
      relayerAccount: 'web3-authn-v4.testnet',
      relayer: {
        url: relayerUrl,
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
      routerAb: {
        normalSigning: {
          mode: 'enabled',
          signingWorkerId: 'local-signing-worker',
        },
      },
      signingSessionPersistenceMode: 'sealed_refresh_v1',
      signingSessionSeal: {
        keyVersion: SIGNING_SESSION_SEAL_KEY_VERSION,
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
      if (context?.signingEngine?.seamsWebConfigs?.signing?.sessionSeal) {
        context.signingEngine.seamsWebConfigs.signing.sessionSeal.shamirPrimeB64u =
          shamirPrimeB64u;
      }
    } catch {}

    const signingKind = input.signingKind === 'eip1559' ? 'eip1559' : 'tempoTransaction';
    const bootstrapChain = signingKind === 'eip1559' ? 'evm' : 'tempo';
    const tempoChainTarget = {
      kind: 'tempo' as const,
      chainId: 42431,
      networkSlug: 'tempo-moderato',
    };
    const evmChainTarget = {
      kind: 'evm' as const,
      namespace: 'eip155' as const,
      chainId: 11155111,
      networkSlug: 'ethereum-sepolia',
    };
    const signingChainTarget = signingKind === 'eip1559' ? evmChainTarget : tempoChainTarget;
    const resolveEmailOtpNearExportLaneIdentity = async () => {
      const [recordsMod, exactMod] = await Promise.all([
        import('/sdk/esm/core/signingEngine/session/persistence/records.js'),
        import('/sdk/esm/core/signingEngine/session/identity/exactSigningLaneIdentity.js'),
      ]);
      const records = (recordsMod as any)
        .listStoredThresholdEd25519SessionRecordsForWallet(accountId)
        .filter((record: Record<string, unknown>) => record.source === 'email_otp');
      const identities = records
        .map((record: Record<string, unknown>) => {
          const candidate = (recordsMod as any).thresholdEd25519LaneCandidateFromSessionRecord({
            record,
          });
          return candidate
            ? (exactMod as any).exactEd25519SigningLaneIdentity({
                walletId: candidate.walletId,
                nearAccountId: candidate.nearAccountId,
                ed25519KeyScopeId: candidate.ed25519KeyScopeId,
                auth: candidate.auth,
                signingGrantId: candidate.signingGrantId,
                thresholdSessionId: candidate.thresholdSessionId,
              })
            : null;
        })
        .filter(Boolean);
      if (identities.length !== 1) {
        throw new Error(
          `expected exactly one Email OTP NEAR export lane identity, found ${identities.length}`,
        );
      }
      const [identity] = identities;
      return identity;
    };
    const resolveEmailOtpEcdsaExportLaneIdentity = async (
      chainTarget: typeof signingChainTarget,
    ) => {
      const recordsMod = await import('/sdk/esm/core/signingEngine/session/persistence/records.js');
      const records = (recordsMod as any)
        .listStoredThresholdEcdsaSessionRecordsForWallet(accountId, {
          chainTarget,
          source: 'email_otp',
        })
        .map((record: Record<string, unknown>) =>
          (recordsMod as any).toExactEcdsaSigningLaneIdentity(record),
        )
        .filter((identity: Record<string, any>) => identity.auth?.kind === 'email_otp');
      if (records.length !== 1) {
        throw new Error(
          `expected exactly one Email OTP ECDSA export lane identity, found ${records.length}`,
        );
      }
      const [identity] = records;
      return identity;
    };
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

    type Ed25519RegistrationHssResult = {
      relayerKeyId: string;
      publicKey: string;
      keyVersion: string;
      participantIds: number[];
    };

    const registerEmailOtpEd25519HssKey = async (args: {
      signingEngine: any;
      prfFirstB64u: string;
    }): Promise<Ed25519RegistrationHssResult> => {
      const prfFirstB64u = String(args.prfFirstB64u || '').trim();
      if (!runtimePolicyScope) {
        throw new Error('Email OTP Ed25519 registration requires runtime policy scope');
      }
      if (!registrationAttemptId) {
        throw new Error('Email OTP Ed25519 registration requires registrationAttemptId');
      }
      if (!prfFirstB64u) {
        throw new Error('Email OTP enrollment did not return Ed25519 PRF material');
      }

      const hssContext = {
        signingRootId: `${runtimePolicyScope.projectId}:${runtimePolicyScope.envId}`,
        nearAccountId: accountId,
        keyPurpose: 'near-ed25519-signing',
        keyVersion: 'threshold-ed25519-hss-v1',
        participantIds: [1, 2],
        derivationVersion: 1,
      };
      const clientInputs = (await withStageTimeout(
        'prepare Ed25519 registration HSS client material',
        args.signingEngine.prepareThresholdEd25519HssClientCeremonyFromPrfFirst({
          prfFirstB64u,
          ...hssContext,
        }),
      )) as any;
      if (clientInputs?.ok !== true) {
        throw new Error(
          String(clientInputs?.message || clientInputs?.code || 'Ed25519 HSS client setup failed'),
        );
      }

      const registrationBase = {
        kind: 'email_otp_registration',
        registrationAttemptId,
        new_account_id: accountId,
        wallet_key_id: 'example.localhost',
        context: hssContext,
      };
      const prepared = await withStageTimeout(
        'prepare Ed25519 registration HSS server ceremony',
        postRegistrationHssJson<{
          ceremonyHandle: string;
          preparedSession: {
            contextBindingB64u: string;
            evaluatorDriverStateB64u: string;
          };
          clientOtOfferMessageB64u: string;
        }>('/v2/router-ab/ed25519/hss/prepare', registrationBase),
      );
      const ceremonyHandle = String(prepared.ceremonyHandle || '').trim();
      const preparedSession = prepared.preparedSession;
      const clientOtOfferMessageB64u = String(prepared.clientOtOfferMessageB64u || '').trim();
      if (
        !ceremonyHandle ||
        !preparedSession?.contextBindingB64u ||
        !preparedSession.evaluatorDriverStateB64u ||
        !clientOtOfferMessageB64u
      ) {
        throw new Error('Ed25519 registration HSS prepare returned incomplete ceremony state');
      }

      const outputMask = await withStageTimeout(
        'derive Ed25519 registration HSS output mask',
        args.signingEngine.deriveThresholdEd25519HssClientOutputMask({
          clientRecoverableSecretB64u: prfFirstB64u,
          context: {
            ...hssContext,
            contextBindingB64u: preparedSession.contextBindingB64u,
            operation: 'registration',
            relayerKeyId: `registration:${ceremonyHandle}`,
          },
        }),
      );
      const clientOutputMaskB64u = String((outputMask as any)?.clientOutputMaskB64u || '').trim();
      if (!clientOutputMaskB64u) {
        throw new Error('Ed25519 registration HSS output mask was empty');
      }

      const clientRequest = await withStageTimeout(
        'prepare Ed25519 registration HSS client request',
        args.signingEngine.prepareThresholdEd25519HssClientRequest({
          evaluatorDriverStateB64u: preparedSession.evaluatorDriverStateB64u,
          clientOtOfferMessageB64u,
          clientInputs: {
            contextBindingB64u: String(clientInputs.contextBindingB64u || '').trim(),
            yClientB64u: String(clientInputs.yClientB64u || '').trim(),
            tauClientB64u: String(clientInputs.tauClientB64u || '').trim(),
          },
        }),
      );
      const responded = await withStageTimeout(
        'respond Ed25519 registration HSS server ceremony',
        postRegistrationHssJson<{
          contextBindingB64u: string;
          serverInputDeliveryB64u: string;
        }>('/v2/router-ab/ed25519/hss/respond', {
          ...registrationBase,
          ceremonyHandle,
          clientRequest: {
            clientRequestMessageB64u: String(
              (clientRequest as any)?.clientRequestMessageB64u || '',
            ).trim(),
          },
        }),
      );
      const serverInputDeliveryB64u = String(responded.serverInputDeliveryB64u || '').trim();
      if (
        String(responded.contextBindingB64u || '').trim() !== preparedSession.contextBindingB64u ||
        !serverInputDeliveryB64u
      ) {
        throw new Error('Ed25519 registration HSS respond returned invalid server delivery');
      }

      const evaluationResult = await withStageTimeout(
        'build Ed25519 registration HSS client artifact',
        args.signingEngine.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact({
          preparedSession,
          clientRequest,
          serverInputDelivery: {
            contextBindingB64u: responded.contextBindingB64u,
            serverInputDeliveryB64u,
          },
          clientOutputMaskB64u,
        }),
      );
      const finalized = await withStageTimeout(
        'finalize Ed25519 registration HSS server ceremony',
        postRegistrationHssJson<{
          publicKey: string;
          relayerKeyId: string;
          keyVersion: string;
        }>('/v2/router-ab/ed25519/hss/finalize', {
          ...registrationBase,
          ceremonyHandle,
          evaluationResult: {
            contextBindingB64u: String(
              (evaluationResult as any)?.contextBindingB64u || '',
            ).trim(),
            stagedEvaluatorArtifactB64u: String(
              (evaluationResult as any)?.stagedEvaluatorArtifactB64u || '',
            ).trim(),
          },
        }),
      );
      const publicKey = String(finalized.publicKey || '').trim();
      const relayerKeyId = String(finalized.relayerKeyId || '').trim();
      const keyVersion = String(finalized.keyVersion || '').trim();
      if (!publicKey || !relayerKeyId || keyVersion !== hssContext.keyVersion) {
        throw new Error('Ed25519 registration HSS finalize returned incomplete key metadata');
      }
      return {
        publicKey,
        relayerKeyId,
        keyVersion,
        participantIds: [...hssContext.participantIds],
      };
    };

    let signingEngineForDebug: any = null;
    try {
      const signingEngine = pm.getContext().signingEngine as any;
      signingEngineForDebug = signingEngine;
      const enrollmentOtp = await withStageTimeout('request enrollment OTP', requestEnrollmentOtp());
      const enrollmentLogin = (await withStageTimeout(
        'enroll and login ECDSA capability',
        signingEngine.enrollAndLoginWithEmailOtpEcdsaCapabilityInternal({
          walletSession: {
            walletId: accountId,
            walletSessionUserId: accountId,
          },
          chainTarget: signingChainTarget,
          emailOtpAuthPolicy,
          challengeId: enrollmentOtp.challengeId,
          otpCode: enrollmentOtp.otpCode,
          appSessionJwt: enrollAppSessionJwt,
          routeAuth: { kind: 'app_session', jwt: enrollAppSessionJwt },
          sessionKind: 'jwt',
          registrationAttemptId,
          ...(requestedKeyHandle ? { keyHandle: requestedKeyHandle } : {}),
          participantIds,
          ...(clientSecretB64u ? { clientSecret32: decodeBase64UrlToBytes(clientSecretB64u) } : {}),
          ...(typeof input.signingSessionTtlMs === 'number'
            ? { ttlMs: input.signingSessionTtlMs }
            : {}),
          ...(typeof input.signingSessionRemainingUses === 'number'
            ? { remainingUses: input.signingSessionRemainingUses }
            : {}),
        }),
      )) as any;
      const enrolled = enrollmentLogin?.enrollment || {};
      const ecdsaThresholdKeyId = String(
        enrollmentLogin?.bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId || '',
      ).trim();
      const keyHandle = String(
        enrollmentLogin?.bootstrap?.thresholdEcdsaKeyRef?.keyHandle || '',
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
      if (!runtimePolicyScope) {
        return {
          ok: false,
          accountId,
          emailOtpEnrollment: {
            challengeId: String(enrolled?.challengeId || ''),
            enrollmentSealKeyVersion: String(enrolled?.enrollmentSealKeyVersion || ''),
            unlockKeyVersion: String(enrolled?.unlockKeyVersion || ''),
          },
          error: 'Email OTP registration bootstrap did not return runtime policy scope',
        };
      }

      const shouldReconstructEd25519 = input.signNearAfterLogin === true;
      const thresholdEd25519RecoveryCodeSecret32B64u = String(
        enrolled?.thresholdEd25519RecoveryCodeSecret32B64u || '',
      ).trim();
      const ed25519Registration = shouldReconstructEd25519
        ? await registerEmailOtpEd25519HssKey({
            signingEngine,
            prfFirstB64u: thresholdEd25519RecoveryCodeSecret32B64u,
          })
        : null;
      if (ed25519Registration) {
        const [indexedDbMod, ed25519LocalMetadataMod] = await Promise.all([
          import('/sdk/esm/core/indexedDB/index.js'),
          import('/sdk/esm/core/signingEngine/session/emailOtp/ed25519LocalMetadata.js'),
        ]);
        await withStageTimeout(
          'persist Email OTP Ed25519 registration metadata',
          (ed25519LocalMetadataMod as any).persistEmailOtpThresholdEd25519LocalMetadata(
            (indexedDbMod as any).IndexedDBManager,
            {
              nearAccountId: accountId,
              rpId: 'example.localhost',
              relayerUrl,
              publicKey: ed25519Registration.publicKey,
              relayerKeyId: ed25519Registration.relayerKeyId,
              keyVersion: ed25519Registration.keyVersion,
              participantIds: ed25519Registration.participantIds,
            },
          ),
        );
        await withStageTimeout(
          'select Email OTP Ed25519 registration metadata',
          signingEngine.setLastUser(accountId, 1),
        );
      }
      const ed25519SessionReconstruction = shouldReconstructEd25519
        ? ({
            kind: 'reconstruct',
            ed25519Key: {
              relayerKeyId: ed25519Registration!.relayerKeyId,
              keyVersion: ed25519Registration!.keyVersion,
              participantIds: ed25519Registration!.participantIds,
            },
            runtimePolicyScope,
          } as const)
        : ({
            kind: 'defer',
            reason: 'not_needed_for_ecdsa',
          } as const);

      await signingEngine.clearVolatileWarmSigningMaterial(accountId).catch(() => undefined);

      const firstLoginOtp = await withStageTimeout('request login OTP', requestLoginOtp());
      const loginOtp =
        input.resendLoginOtpBeforeSubmit === true
          ? await withStageTimeout('request resent login OTP', requestLoginOtp())
          : firstLoginOtp;
      const loggedIn = (await withStageTimeout(
        'login with ECDSA capability',
        signingEngine.loginWithEmailOtpEcdsaCapabilityInternal({
          walletSession: {
            walletId: accountId,
            walletSessionUserId: accountId,
          },
          chainTarget: signingChainTarget,
          emailOtpAuthPolicy,
          challengeId: loginOtp.challengeId,
          otpCode: loginOtp.otpCode,
          appSessionJwt: loginAppSessionJwt,
          routeAuth: { kind: 'app_session', jwt: loginAppSessionJwt },
          keyHandle: keyHandle || ecdsaThresholdKeyId,
          participantIds: resolvedParticipantIds,
          sessionKind: 'jwt',
          ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
          ed25519ReconstructionMode: shouldReconstructEd25519 ? 'await' : 'skip',
          ed25519SessionReconstruction,
          ...(typeof input.signingSessionTtlMs === 'number'
            ? { ttlMs: input.signingSessionTtlMs }
            : {}),
          ...(typeof input.signingSessionRemainingUses === 'number'
            ? { remainingUses: input.signingSessionRemainingUses }
            : {}),
        }),
      )) as any;

      const exportOptionsRequested =
        input.exportNearWithResend === true || input.exportEcdsaWithResend === true;
      const expectsPostExhaustionSigningPrompt =
        input.skipFirstSign !== true &&
        input.signTwice !== false &&
        typeof input.signingSessionRemainingUses === 'number' &&
        input.signingSessionRemainingUses <= 1;
      const originalRequestUserConfirmation =
        typeof signingEngine?.touchConfirm?.requestUserConfirmation === 'function'
          ? signingEngine.touchConfirm.requestUserConfirmation.bind(signingEngine.touchConfirm)
          : null;
      if (
        (exportOptionsRequested ||
          emailOtpAuthPolicy === 'per_operation' ||
          expectsPostExhaustionSigningPrompt) &&
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
                const signed = (await withStageTimeout(
                  'first Tempo sign',
                  pm.tempo.signTempo({
                    walletSession: {
                      walletId: accountId,
                      walletSessionUserId: accountId,
                    },
                    request: makeThresholdEcdsaRequest('a1'),
                    chainTarget: signingChainTarget,
                    options: { confirmationConfig },
                  }),
                )) as any;
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
                const signed = (await withStageTimeout(
                  'second Tempo sign',
                  pm.tempo.signTempo({
                    walletSession: {
                      walletId: accountId,
                      walletSessionUserId: accountId,
                    },
                    request: makeThresholdEcdsaRequest('b2'),
                    chainTarget: signingChainTarget,
                    options: { confirmationConfig },
                  }),
                )) as any;
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

      const runNearSign = async () => {
        try {
          const signed = await pm.near.signTransactionWithActions({
            nearAccount: { accountId },
            transaction: {
              receiverId: 'w3a-v1.testnet',
              actions: [{ type: ActionType.Transfer, amount: '1' }],
            },
            options: { confirmationConfig },
          });
          const tx = (signed as any)?.signedTransaction?.transaction || {};
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
      };
      const nearSignResult = input.signNearAfterLogin === true ? await runNearSign() : undefined;

      const exportResults =
        input.exportNearWithResend === true || input.exportEcdsaWithResend === true
          ? {
              ...(input.exportNearWithResend === true
                ? {
                    near: await (async () => {
                      try {
                        const exported = await pm.keys.exportKeypairWithUI({
                          kind: 'near',
                          nearAccount: { accountId },
                          laneIdentity: await resolveEmailOtpNearExportLaneIdentity(),
                          options: { chain: 'near', variant: 'drawer' },
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
                        const exported = await pm.keys.exportKeypairWithUI({
                          kind: 'ecdsa',
                          chainTarget: signingChainTarget,
                          walletSession: {
                            walletId: accountId,
                            walletSessionUserId: accountId,
                          },
                          laneIdentity: await resolveEmailOtpEcdsaExportLaneIdentity(
                            signingChainTarget,
                          ),
                          options: {
                            chain: bootstrapChain,
                            variant: 'drawer',
                          },
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
      let debugSuffix = '';
      try {
        const records = signingEngineForDebug.listThresholdEcdsaSessionRecordsForWalletTarget({
          walletId: accountId,
          chainTarget: signingChainTarget,
        });
        debugSuffix = `; ecdsaRecords=${JSON.stringify(
          records.map((record: Record<string, any>) => ({
            source: record.source,
            thresholdSessionKind: record.thresholdSessionKind,
            thresholdSessionId: record.thresholdSessionId,
            signingGrantId: record.signingGrantId,
            remainingUses: record.remainingUses,
            expiresAtMs: record.expiresAtMs,
            hasWalletSessionJwt: Boolean(String(record.walletSessionJwt || '').trim()),
            hasRouterAbEcdsaHssNormalSigning: Boolean(record.routerAbEcdsaHssNormalSigning),
            routerAbKind: record.routerAbEcdsaHssNormalSigning?.kind,
            chainTarget: record.chainTarget,
          })),
        )}`;
      } catch {}
      return {
        ok: false,
        accountId,
        error:
          error && typeof error === 'object' && 'message' in error
            ? `${String((error as { message?: unknown }).message || '')}${debugSuffix}`
            : `${String(error || 'email otp ecdsa tempo flow failed')}${debugSuffix}`,
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
  restoreWarnings?: string[];
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
      const { SeamsWeb } = sdkMod as any;
      const { ActionType } = sdkMod as any;
      const restoreWarnings: string[] = [];
      const originalConsoleWarn = console.warn.bind(console);
      console.warn = (...warnArgs: unknown[]) => {
        const message = warnArgs
          .map((entry) => {
            if (typeof entry === 'string') return entry;
            try {
              return JSON.stringify(entry);
            } catch {
              return String(entry);
            }
          })
          .join(' ');
        if (message.includes('EmailOtpSession') || message.includes('sealed refresh')) {
          restoreWarnings.push(message);
        }
        originalConsoleWarn(...warnArgs);
      };

      const readSealedRecordSummaries = async (): Promise<Array<Record<string, unknown>>> => {
        const indexedDb = globalThis.indexedDB;
        if (!indexedDb) return [];
        const openRequest = indexedDb.open('seams_wallet');
        const db = await new Promise<IDBDatabase | null>((resolve) => {
          openRequest.onerror = () => resolve(null);
          openRequest.onsuccess = () => resolve(openRequest.result);
        });
        if (!db || !Array.from(db.objectStoreNames).includes('signing_session_seals')) {
          db?.close();
          return [];
        }
        try {
          const tx = db.transaction('signing_session_seals', 'readonly');
          const store = tx.objectStore('signing_session_seals');
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
              ecdsaRestoreKeys:
                record.ecdsaRestore &&
                typeof record.ecdsaRestore === 'object' &&
                !Array.isArray(record.ecdsaRestore)
                  ? Object.keys(record.ecdsaRestore as Record<string, unknown>).sort()
                  : [],
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
          import('/sdk/esm/core/signingEngine/session/persistence/records.js').catch(() => null),
          import('/sdk/esm/core/signingEngine/session/persistence/sealedSessionStore.js').catch(
            () => null,
          ),
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
        const listSealedRecordsForAuth = async (
          authMethod: 'email_otp' | 'passkey',
        ): Promise<Array<Record<string, unknown>>> => {
          if (!sealedStore || typeof (sealedStore as any).listExactSealedSessionsForWallet !== 'function') {
            return [];
          }
          const records = await (sealedStore as any).listExactSealedSessionsForWallet({
            walletId: accountId,
            filter: {
              authMethod,
              curve: 'ed25519',
            },
          });
          if (!Array.isArray(records)) return [];
          return records.map((record) => ({
            storeKey: record?.storeKey,
            authMethod: record?.authMethod,
            curve: record?.curve,
            signingGrantId: record?.signingGrantId,
            thresholdSessionIds: record?.thresholdSessionIds,
            hasEd25519Restore: Boolean(record?.ed25519Restore),
            hasEcdsaRestore: Boolean(record?.ecdsaRestore),
            ed25519Restore: record?.ed25519Restore
              ? {
                  hasXClientBaseB64u: Boolean(record.ed25519Restore.xClientBaseB64u),
                  hasClientVerifyingShareB64u: Boolean(
                    record.ed25519Restore.clientVerifyingShareB64u,
                  ),
                  hasWalletSessionJwt: Boolean(record.ed25519Restore.walletSessionJwt),
                  sessionKind: record.ed25519Restore.sessionKind,
                  hasRuntimePolicyScope: Boolean(record.ed25519Restore.runtimePolicyScope),
                  hasRouterAbNormalSigning: Boolean(record.ed25519Restore.routerAbNormalSigning),
                }
              : null,
            ecdsaRestore: record?.ecdsaRestore
              ? {
                  hasChainTarget: Boolean(record.ecdsaRestore.chainTarget),
                  hasKeyHandle: Boolean(record.ecdsaRestore.keyHandle),
                  hasEcdsaThresholdKeyId: Boolean(record.ecdsaRestore.ecdsaThresholdKeyId),
                  hasEthereumAddress: Boolean(record.ecdsaRestore.ethereumAddress),
                  hasRelayerKeyId: Boolean(record.ecdsaRestore.relayerKeyId),
                  hasClientVerifyingShareB64u: Boolean(
                    record.ecdsaRestore.clientVerifyingShareB64u,
                  ),
                  hasWalletSessionJwt: Boolean(record.ecdsaRestore.walletSessionJwt),
                  sessionKind: record.ecdsaRestore.sessionKind,
                  hasRuntimePolicyScope: Boolean(record.ecdsaRestore.runtimePolicyScope),
                }
              : null,
          }));
        };
        const [emailOtpEd25519SealedRecords, passkeyEd25519SealedRecords] = await Promise.all([
          listSealedRecordsForAuth('email_otp'),
          listSealedRecordsForAuth('passkey'),
        ]);
        return {
          ed25519Record: ed25519Record
            ? {
                source: ed25519Record.source,
                thresholdSessionId: ed25519Record.thresholdSessionId,
                signingGrantId: ed25519Record.signingGrantId,
                retention: ed25519Record.emailOtpAuthContext?.retention,
                hasWalletSessionJwt: Boolean(ed25519Record.walletSessionJwt),
                hasClientBase: Boolean(ed25519Record.xClientBaseB64u),
              }
            : null,
          ed25519Identities: Array.isArray(identities)
            ? identities.map((identity) => ({
                authMethod: identity.authMethod,
                curve: identity.curve,
                chain: identity.chain,
                thresholdSessionId: identity.thresholdSessionId,
                signingGrantId: identity.signingGrantId,
              }))
            : [],
          emailOtpEd25519SealedRecords,
          passkeyEd25519SealedRecords,
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
        const pm = new SeamsWeb({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayerAccount: 'web3-authn-v4.testnet',
          relayer: {
            url: relayerUrl,
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
        pm.preferences.setConfirmationConfig(confirmationConfig as any);

        const signingEngine = pm.getContext().signingEngine as any;
        const restoreCallEvents: Array<{
          source: 'email_otp' | 'passkey';
          authMethod: string;
          curve: string;
          signingGrantId: string;
          thresholdSessionId: string;
          attempted?: number;
          restored?: number;
          deferred?: number;
          preflightMatched?: number;
          preflightRejected?: number;
          preflightNotApplicable?: number;
          preflightRejectionReasons?: string[];
        }> = [];
        if (typeof signingEngine?.emailOtpSessions?.restorePersistedSessionForSigning === 'function') {
          const originalRestore =
            signingEngine.emailOtpSessions.restorePersistedSessionForSigning.bind(
              signingEngine.emailOtpSessions,
            );
          signingEngine.emailOtpSessions.restorePersistedSessionForSigning = async (
            restoreArgs: Record<string, unknown>,
          ) => {
            let preflightMatched = 0;
            let preflightRejected = 0;
            let preflightNotApplicable = 0;
            let preflightRejectionReasons: string[] = [];
            try {
              const [sealedStoreMod, lookupMod] = await Promise.all([
                import('/sdk/esm/core/signingEngine/session/persistence/sealedSessionStore.js').catch(
                  () => null,
                ),
                import('/sdk/esm/core/signingEngine/session/sealedRecovery/exactRecordLookup.js').catch(
                  () => null,
                ),
              ]);
              if (
                sealedStoreMod &&
                lookupMod &&
                typeof (sealedStoreMod as any).listExactSealedSessionsForWallet === 'function' &&
                typeof (lookupMod as any).buildRestoreWorkItemLookupResult === 'function'
              ) {
                const exactRecords = await (sealedStoreMod as any).listExactSealedSessionsForWallet({
                  walletId: accountId,
                  filter: {
                    authMethod: 'email_otp',
                    curve: 'ed25519',
                  },
                });
                if (Array.isArray(exactRecords)) {
                  for (const record of exactRecords) {
                    const lookup = (lookupMod as any).buildRestoreWorkItemLookupResult(
                      {
                        walletId: accountId,
                        authMethod: 'email_otp',
                        curve: 'ed25519',
                        chain: 'near',
                        signingGrantId: String(
                          restoreArgs?.signingGrantId || '',
                        ),
                        thresholdSessionId: String(restoreArgs?.thresholdSessionId || ''),
                        reason: String(restoreArgs?.reason || 'transaction'),
                      },
                      record,
                    );
                    if (lookup?.kind === 'matched') preflightMatched += 1;
                    else if (lookup?.kind === 'rejected') {
                      preflightRejected += 1;
                      const reason = String(lookup?.rejection?.reason || '').trim();
                      if (reason) preflightRejectionReasons.push(reason);
                    } else preflightNotApplicable += 1;
                  }
                }
              }
            } catch {}
            const event = {
              source: 'email_otp' as const,
              authMethod: String(restoreArgs?.authMethod || ''),
              curve: String(restoreArgs?.curve || ''),
              signingGrantId: String(restoreArgs?.signingGrantId || ''),
              thresholdSessionId: String(restoreArgs?.thresholdSessionId || ''),
              preflightMatched,
              preflightRejected,
              preflightNotApplicable,
              preflightRejectionReasons,
            };
            const restoreResult = await originalRestore(restoreArgs);
            restoreCallEvents.push({
              ...event,
              attempted:
                restoreResult && typeof restoreResult === 'object'
                  ? Number((restoreResult as Record<string, unknown>).attempted ?? 0)
                  : 0,
              restored:
                restoreResult && typeof restoreResult === 'object'
                  ? Number((restoreResult as Record<string, unknown>).restored ?? 0)
                  : 0,
              deferred:
                restoreResult && typeof restoreResult === 'object'
                  ? Number((restoreResult as Record<string, unknown>).deferred ?? 0)
                  : 0,
            });
            return restoreResult;
          };
        }
        if (typeof signingEngine?.touchConfirm?.restorePersistedSessionForSigning === 'function') {
          const originalRestore =
            signingEngine.touchConfirm.restorePersistedSessionForSigning.bind(signingEngine.touchConfirm);
          signingEngine.touchConfirm.restorePersistedSessionForSigning = async (
            restoreArgs: Record<string, unknown>,
          ) => {
            const event = {
              source: 'passkey' as const,
              authMethod: String(restoreArgs?.authMethod || ''),
              curve: String(restoreArgs?.curve || ''),
              signingGrantId: String(restoreArgs?.signingGrantId || ''),
              thresholdSessionId: String(restoreArgs?.thresholdSessionId || ''),
            };
            const restoreResult = await originalRestore(restoreArgs);
            restoreCallEvents.push({
              ...event,
              attempted:
                restoreResult && typeof restoreResult === 'object'
                  ? Number((restoreResult as Record<string, unknown>).attempted ?? 0)
                  : 0,
              restored:
                restoreResult && typeof restoreResult === 'object'
                  ? Number((restoreResult as Record<string, unknown>).restored ?? 0)
                  : 0,
              deferred:
                restoreResult && typeof restoreResult === 'object'
                  ? Number((restoreResult as Record<string, unknown>).deferred ?? 0)
                  : 0,
            });
            return restoreResult;
          };
        }
        if (
          rememberAppSessionJwt !== false &&
          appSessionJwt &&
          typeof signingEngine?.emailOtpSessions?.rememberAppSessionJwt === 'function'
        ) {
          signingEngine.emailOtpSessions.rememberAppSessionJwt({
            walletSession: {
              walletId: accountId,
              walletSessionUserId: accountId,
            },
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
                import('/sdk/esm/core/signingEngine/uiConfirm/handlers/flows/adapters/adapters.js'),
                import('/sdk/esm/core/signingEngine/nonce/NonceCoordinator.js'),
                import('/sdk/esm/core/signingEngine/uiConfirm/confirmationReadinessRegistry.js').catch(
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

        const tempoChainTarget = {
          kind: 'tempo' as const,
          chainId: 42431,
          networkSlug: 'tempo-moderato',
        };
        const evmChainTarget = {
          kind: 'evm' as const,
          namespace: 'eip155' as const,
          chainId: 11155111,
          networkSlug: 'ethereum-sepolia',
        };
        const resolveEmailOtpNearExportLaneIdentity = async () => {
          const [recordsMod, exactMod] = await Promise.all([
            import('/sdk/esm/core/signingEngine/session/persistence/records.js'),
            import('/sdk/esm/core/signingEngine/session/identity/exactSigningLaneIdentity.js'),
          ]);
          const records = (recordsMod as any)
            .listStoredThresholdEd25519SessionRecordsForWallet(accountId)
            .filter((record: Record<string, unknown>) => record.source === 'email_otp');
          const identities = records
            .map((record: Record<string, unknown>) => {
              const candidate = (recordsMod as any).thresholdEd25519LaneCandidateFromSessionRecord({
                record,
              });
              return candidate
                ? (exactMod as any).exactEd25519SigningLaneIdentity({
                    walletId: candidate.walletId,
                    nearAccountId: candidate.nearAccountId,
                    ed25519KeyScopeId: candidate.ed25519KeyScopeId,
                    auth: candidate.auth,
                    signingGrantId: candidate.signingGrantId,
                    thresholdSessionId: candidate.thresholdSessionId,
                  })
                : null;
            })
            .filter(Boolean);
          if (identities.length !== 1) {
            throw new Error(
              `expected exactly one Email OTP NEAR export lane identity, found ${identities.length}`,
            );
          }
          const [identity] = identities;
          return identity;
        };
        const resolveEmailOtpEcdsaExportLaneIdentity = async (
          chainTarget: typeof tempoChainTarget | typeof evmChainTarget,
        ) => {
          const recordsMod = await import('/sdk/esm/core/signingEngine/session/persistence/records.js');
          const records = (recordsMod as any)
            .listStoredThresholdEcdsaSessionRecordsForWallet(accountId, {
              chainTarget,
              source: 'email_otp',
            })
            .map((record: Record<string, unknown>) =>
              (recordsMod as any).toExactEcdsaSigningLaneIdentity(record),
            )
            .filter((identity: Record<string, any>) => identity.auth?.kind === 'email_otp');
          if (records.length !== 1) {
            throw new Error(
              `expected exactly one Email OTP ECDSA export lane identity, found ${records.length}`,
            );
          }
          const [identity] = records;
          return identity;
        };
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
              const signed = await pm.near.signTransactionWithActions({
                nearAccount: { accountId },
                transaction: {
                  receiverId: 'w3a-v1.testnet',
                  actions: [{ type: ActionType.Transfer, amount: '1' }],
                },
                options: { confirmationConfig },
              });
              pushResult({
                kind,
                ok: Boolean(signed?.signedTransaction),
                chain: 'near',
              });
              return;
            }
            if (kind === 'tempo') {
              const signed = await pm.tempo.signTempo({
                walletSession: {
                  walletId: accountId,
                  walletSessionUserId: accountId,
                },
                request: tempoRequest(tag),
                chainTarget: tempoChainTarget,
                options: { confirmationConfig },
              });
              pushResult({ kind, ok: signed?.kind === 'tempoTransaction', chain: signed?.chain });
              return;
            }
            if (kind === 'evm') {
              const signed = await pm.tempo.signTempo({
                walletSession: {
                  walletId: accountId,
                  walletSessionUserId: accountId,
                },
                request: evmRequest(tag),
                chainTarget: evmChainTarget,
                options: { confirmationConfig },
              });
              pushResult({ kind, ok: signed?.kind === 'eip1559', chain: signed?.chain });
              return;
            }
            if (kind === 'exportNear') {
              const exported = await pm.keys.exportKeypairWithUI({
                kind: 'near',
                nearAccount: { accountId },
                laneIdentity: await resolveEmailOtpNearExportLaneIdentity(),
                options: { chain: 'near', variant: 'drawer' },
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
              const exported = await pm.keys.exportKeypairWithUI({
                kind: 'ecdsa',
                chainTarget: tempoChainTarget,
                walletSession: {
                  walletId: accountId,
                  walletSessionUserId: accountId,
                },
                laneIdentity: await resolveEmailOtpEcdsaExportLaneIdentity(tempoChainTarget),
                options: { chain: 'tempo', variant: 'drawer' },
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
          restoreCallEvents,
          promptCountBeforeExports: promptCountBeforeExports ?? emailOtpPromptCount,
          promptCountAfterExports,
          promptCountAfterFinalSign: emailOtpPromptCount,
          authPromptEvents,
          restoreWarnings,
        };
      } catch (error: unknown) {
        return {
          ok: false,
          error:
            error && typeof error === 'object' && 'message' in error
              ? String((error as { message?: unknown }).message || '')
              : String(error || 'reload phase failed'),
          restoreWarnings,
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
