import type { Page } from '@playwright/test';
import { deriveEmailOtpEcdsaClientRootShare32B64u } from './emailOtpDerivation';
import {
  createInMemoryJwtSessionAdapter,
  installCreateAccountAndRegisterUserMock,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  setupManagedThresholdRegistrationHarness,
  setupThresholdE2ePage,
} from '../e2e/thresholdEd25519.testUtils';

const DEFAULT_ECDSA_MASTER_SECRET_B64U = Buffer.from(new Uint8Array(32).fill(9)).toString(
  'base64url',
);
const SHAMIR_PRIME_B64U = '_____________________________________v___C8';
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
  defaultClientSecretB64u: string;
  mintAppSessionJwt: (args: {
    userId: string;
    email?: string;
    deviceId?: string;
    rotate?: boolean;
  }) => Promise<string>;
  bootstrapEmailOtpEcdsaKey: (args: {
    userId: string;
    walletId?: string;
    clientSecretB64u?: string;
    rpId?: string;
  }) => Promise<{
    ecdsaThresholdKeyId: string;
    participantIds: number[];
    clientVerifyingShareB64u: string;
    thresholdEcdsaPublicKeyB64u: string;
    ethereumAddress: string;
    clientRootShare32B64u: string;
  }>;
  readEmailOtpEnrollment: (walletId: string) => Promise<unknown>;
  readIntegratedEcdsaKey: (ecdsaThresholdKeyId: string) => Promise<unknown>;
  close: () => Promise<void>;
};

export type EmailOtpEcdsaTempoFlowOptions = {
  relayerUrl: string;
  shamirPrimeB64u: string;
  enrollAppSessionJwt: string;
  loginAppSessionJwt: string;
  ecdsaThresholdKeyId: string;
  participantIds: number[];
  clientSecretB64u?: string;
  accountId?: string;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  signingKind?: 'tempoTransaction' | 'eip1559';
  signTwice?: boolean;
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
    emailOtpKeyVersion: string;
    unlockKeyVersion: string;
  };
  emailOtpLogin?: {
    retention: 'session' | 'single_use';
    policy: EmailOtpAuthPolicy;
    challengeId: string;
    emailOtpKeyVersion: string;
    warmState: string;
  };
  otpCounters?: {
    enrollChallengeCount: number;
    loginChallengeCount: number;
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
  error?: string;
};

export async function setupEmailOtpEcdsaTempoHarness(
  page: Page,
): Promise<EmailOtpEcdsaTempoHarness> {
  await setupThresholdE2ePage(page);

  const keysOnChain = new Set<string>();
  const nonceByPublicKey = new Map<string, number>();
  const session = createInMemoryJwtSessionAdapter();
  const { service, threshold } = makeAuthServiceForThreshold(keysOnChain, {
    THRESHOLD_NODE_ROLE: 'coordinator',
    THRESHOLD_SECP256K1_MASTER_SECRET_B64U: DEFAULT_ECDSA_MASTER_SECRET_B64U,
    PRF_SESSION_SEAL_KEY_VERSION: 'kek-s-email-otp-test',
    SHAMIR_P_B64U: SHAMIR_PRIME_B64U,
    SHAMIR_E_S_B64U: SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U,
    SHAMIR_D_S_B64U: SHAMIR_SERVER_DECRYPT_EXPONENT_B64U,
  });
  await service.getRelayerAccount();

  const harness = await setupManagedThresholdRegistrationHarness({
    page,
    service,
    threshold,
    session,
    keyName: 'threshold-ecdsa-email-otp-browser',
    orgId: 'org_threshold_ecdsa_email_otp',
    orgSlug: 'threshold-ecdsa-email-otp-org',
    orgName: 'Threshold ECDSA Email OTP Org',
    projectId: 'proj_threshold_ecdsa_email_otp',
    projectName: 'Threshold ECDSA Email OTP Project',
  });

  await installCreateAccountAndRegisterUserMock(page, {
    relayerBaseUrl: harness.baseUrl,
    session,
    threshold,
    onNewPublicKey: (publicKey) => {
      keysOnChain.add(publicKey);
      nonceByPublicKey.set(publicKey, 0);
    },
  });
  await installFastNearRpcMock(page, {
    keysOnChain,
    nonceByPublicKey,
  });

  return {
    baseUrl: harness.baseUrl,
    shamirPrimeB64u: SHAMIR_PRIME_B64U,
    defaultClientSecretB64u: DEFAULT_EMAIL_OTP_CLIENT_SECRET_B64U,
    mintAppSessionJwt: async ({ userId, email, deviceId, rotate }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        throw new Error('mintAppSessionJwt requires userId');
      }
      const versionResult = rotate
        ? await service.rotateAppSessionVersion({ userId: normalizedUserId })
        : await service.getOrCreateAppSessionVersion({ userId: normalizedUserId });
      if (!versionResult.ok) {
        throw new Error(versionResult.error || 'failed to create app session version');
      }
      return await session.signJwt(normalizedUserId, {
        kind: 'app_session_v1',
        sub: normalizedUserId,
        appSessionVersion: versionResult.appSessionVersion,
        email: String(email || DEFAULT_EMAIL).trim() || DEFAULT_EMAIL,
        deviceId: String(deviceId || 'browser-email-otp').trim() || 'browser-email-otp',
      });
    },
    bootstrapEmailOtpEcdsaKey: async ({ userId, walletId, clientSecretB64u, rpId }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        throw new Error('bootstrapEmailOtpEcdsaKey requires userId');
      }
      const normalizedWalletId =
        String(walletId || normalizedUserId).trim() || normalizedUserId;
      const detectedRpId =
        String(
          rpId ||
            (await page
              .evaluate(() => String(globalThis.location?.hostname || '').trim())
              .catch(() => '')),
        ).trim() || 'example.localhost';
      const normalizedClientSecretB64u =
        String(clientSecretB64u || DEFAULT_EMAIL_OTP_CLIENT_SECRET_B64U).trim() ||
        DEFAULT_EMAIL_OTP_CLIENT_SECRET_B64U;
      const clientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
        clientSecretB64u: normalizedClientSecretB64u,
        walletId: normalizedWalletId,
        userId: normalizedUserId,
      });
      const sessionId = `email-otp-registration-${Date.now()}-${Math.random()
        .toString(16)
        .slice(2)}`;
      const bootstrapped = await threshold.bootstrapEcdsaFromRegistrationMaterial({
        userId: normalizedUserId,
        rpId: detectedRpId,
        clientRootShare32B64u,
        sessionPolicy: {
          version: 'threshold_session_v1',
          userId: normalizedUserId,
          rpId: detectedRpId,
          sessionId,
          participantIds: [1, 2],
          ttlMs: 120_000,
          remainingUses: 4,
        },
      });
      if (!bootstrapped.ok) {
        throw new Error(bootstrapped.message || 'Email OTP threshold bootstrap failed');
      }
      const ecdsaThresholdKeyId = String(bootstrapped.ecdsaThresholdKeyId || '').trim();
      const clientVerifyingShareB64u = String(bootstrapped.clientVerifyingShareB64u || '').trim();
      const thresholdEcdsaPublicKeyB64u = String(
        bootstrapped.thresholdEcdsaPublicKeyB64u || '',
      ).trim();
      const ethereumAddress = String(bootstrapped.ethereumAddress || '').trim();
      const participantIds = Array.isArray(bootstrapped.participantIds)
        ? bootstrapped.participantIds
            .map((value) => Number(value))
            .filter((value) => Number.isFinite(value))
        : [];
      if (
        !ecdsaThresholdKeyId ||
        !clientVerifyingShareB64u ||
        !thresholdEcdsaPublicKeyB64u ||
        !ethereumAddress ||
        participantIds.length === 0
      ) {
        throw new Error('Email OTP threshold bootstrap returned incomplete key metadata');
      }
      return {
        ecdsaThresholdKeyId,
        participantIds,
        clientVerifyingShareB64u,
        thresholdEcdsaPublicKeyB64u,
        ethereumAddress,
        clientRootShare32B64u,
      };
    },
    readEmailOtpEnrollment: async (walletId) => {
      const result = await service.readEmailOtpEnrollment({ walletId });
      return result;
    },
    readIntegratedEcdsaKey: async (ecdsaThresholdKeyId) => {
      return await (threshold as any).getEcdsaIntegratedKeyRecord(ecdsaThresholdKeyId);
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
    const { TatchiPasskey } = sdkMod as any;

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
    };

    const relayerUrl = String(input.relayerUrl || '').trim();
    const shamirPrimeB64u = String(input.shamirPrimeB64u || '').trim();
    const enrollAppSessionJwt = String(input.enrollAppSessionJwt || '').trim();
    const loginAppSessionJwt = String(input.loginAppSessionJwt || '').trim();
    const ecdsaThresholdKeyId = String(input.ecdsaThresholdKeyId || '').trim();
    const participantIds = Array.isArray(input.participantIds)
      ? input.participantIds.map((value) => Number(value)).filter(Number.isFinite)
      : [];
    const clientSecretB64u = String(input.clientSecretB64u || '').trim();

    if (!ecdsaThresholdKeyId || participantIds.length === 0) {
      return {
        ok: false,
        accountId,
        error: 'runEmailOtpEcdsaTempoFlow requires canonical ecdsaThresholdKeyId and participantIds',
      };
    }

    const joinUrl = (base: string, path: string): string =>
      `${String(base || '').replace(/\/+$/, '')}/${String(path || '').replace(/^\/+/, '')}`;

    const requestEmailOtpChallengeWithOutbox = async (args: {
      route: '/wallet/email-otp/enroll/challenge' | '/wallet/email-otp/challenge';
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
      if (args.target === 'enroll') {
        otpState.enrollChallengeCount += 1;
      } else {
        otpState.loginChallengeCount += 1;
      }
      return { challengeId, otpCode };
    };

    const requestEnrollmentOtp = async () =>
      await requestEmailOtpChallengeWithOutbox({
        route: '/wallet/email-otp/enroll/challenge',
        appSessionJwt: enrollAppSessionJwt,
        walletId: accountId,
        target: 'enroll',
      });

    const requestLoginOtp = async () =>
      await requestEmailOtpChallengeWithOutbox({
        route: '/wallet/email-otp/challenge',
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
      signing: {
        emailOtp: {
          authPolicy: emailOtpAuthPolicy,
        },
        sessionSeal: {
          shamirPrimeB64u,
        },
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
    const makeThresholdEcdsaRequest = (tag: string) =>
      signingKind === 'eip1559'
        ? ({
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
          })
        : ({
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

    try {
      const signingEngine = pm.getContext().signingEngine as any;
      const enrollmentOtp = await requestEnrollmentOtp();
      const enrolled = await signingEngine.enrollEmailOtpInternal({
        nearAccountId: accountId,
        challengeId: enrollmentOtp.challengeId,
        otpCode: enrollmentOtp.otpCode,
        appSessionJwt: enrollAppSessionJwt,
        ...(clientSecretB64u ? { clientSecret32: decodeBase64UrlToBytes(clientSecretB64u) } : {}),
      });

      const originalBootstrapEcdsaSession = signingEngine.bootstrapEcdsaSession?.bind(signingEngine);
      try {
        signingEngine.bootstrapEcdsaSession = async () => ({
          keygen: {
            ok: true,
            ecdsaThresholdKeyId,
            participantIds,
          },
          thresholdEcdsaKeyRef: {
            type: 'threshold-ecdsa-secp256k1',
            userId: accountId,
            relayerUrl,
            ecdsaThresholdKeyId,
            participantIds,
            thresholdSessionId: 'registration-bootstrap-bypassed',
            thresholdSessionKind: 'jwt',
          },
        });

        const registration = await pm.registration.registerPasskeyInternal(
          accountId,
          {
            signerOptions: {
              tempo: {
                enabled: false,
                participantIds: [1, 2],
                signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
              },
              evm: {
                enabled: false,
                participantIds: [1, 2],
                signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
              },
            },
          },
          confirmationConfig,
        );
        if (!registration?.success) {
          return {
            ok: false,
            accountId,
            emailOtpEnrollment: {
              challengeId: String(enrolled?.challengeId || ''),
              emailOtpKeyVersion: String(enrolled?.emailOtpKeyVersion || ''),
              unlockKeyVersion: String(enrolled?.unlockKeyVersion || ''),
            },
            error: String(registration?.error || 'registerPasskeyInternal failed'),
          };
        }
      } finally {
        signingEngine.bootstrapEcdsaSession = originalBootstrapEcdsaSession;
      }

      await signingEngine.clearWarmSigningSessions(accountId).catch(() => undefined);

      const loginOtp = await requestLoginOtp();
      const loggedIn = await signingEngine.loginWithEmailOtpEcdsaCapabilityInternal({
        nearAccountId: accountId,
        chain: 'tempo',
        emailOtpAuthPolicy,
        challengeId: loginOtp.challengeId,
        otpCode: loginOtp.otpCode,
        appSessionJwt: loginAppSessionJwt,
        authorizationJwt: loginAppSessionJwt,
        ecdsaThresholdKeyId,
        participantIds,
        sessionKind: 'jwt',
      });

      const firstSignResult = await (async () => {
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
        input.signTwice === false
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

      return {
        ok: true,
        accountId,
        registration: { success: true },
        ecdsaKeyBinding: {
          ecdsaThresholdKeyId,
          participantIds,
        },
        emailOtpEnrollment: {
          challengeId: String(enrolled?.challengeId || ''),
          emailOtpKeyVersion: String(enrolled?.emailOtpKeyVersion || ''),
          unlockKeyVersion: String(enrolled?.unlockKeyVersion || ''),
        },
        emailOtpLogin: {
          retention: String(loggedIn?.warmCapability?.emailOtpAuthContext?.retention || '') as
            | 'session'
            | 'single_use',
          policy: String(loggedIn?.warmCapability?.emailOtpAuthContext?.policy || '') as EmailOtpAuthPolicy,
          challengeId: String(loggedIn?.recovery?.challengeId || ''),
          emailOtpKeyVersion: String(loggedIn?.recovery?.emailOtpKeyVersion || ''),
          warmState: String(loggedIn?.warmCapability?.state || ''),
        },
        otpCounters: {
          enrollChallengeCount: otpState.enrollChallengeCount,
          loginChallengeCount: otpState.loginChallengeCount,
        },
        firstSign: firstSignResult,
        ...(secondSignResult ? { secondSign: secondSignResult } : {}),
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
