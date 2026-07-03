import type { Server } from 'node:http';
import http from 'node:http';
import { createHash } from 'node:crypto';
import expressImport from 'express';
import type { AuthService } from '@server/core/AuthService';
import type { RouterApiServiceBag } from '@server/router/authServicePort';
import type { SessionAdapter } from '@server/router/express-adaptor';
import type { CfEnv, CfExecutionContext } from '@server/router/cloudflare-adaptor';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  buildEmailOtpRecoveryWrapBinding,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '@shared/utils/emailOtpRecoveryKey';

type ExpressMiddleware = (req: unknown, res: unknown, next: (err?: unknown) => void) => unknown;
type ExpressAppLike = ((req: unknown, res: unknown) => unknown) & {
  use: (...args: unknown[]) => unknown;
};

const SESSION_COOKIE_NAME =
  String(process.env.SESSION_COOKIE_NAME || 'seams-jwt').trim() || 'seams-jwt';

// In TS `moduleResolution: bundler`, CommonJS packages like `express` can type as a
// namespace object (non-callable). Normalize to a callable factory for tests.
type ExpressLike = { (): ExpressAppLike; json: (options?: unknown) => ExpressMiddleware };

const express: ExpressLike = (() => {
  const maybeDefault = (expressImport as unknown as { default?: unknown }).default;
  if (typeof maybeDefault === 'function') return maybeDefault as ExpressLike;
  return expressImport as unknown as ExpressLike;
})();

export async function startExpressRouter(router: unknown): Promise<{
  baseUrl: string;
  close: () => Promise<void>;
}> {
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(router);

  const server: Server = http.createServer(app);

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to bind express test server');
  }

  const baseUrl = `http://127.0.0.1:${address.port}`;

  return {
    baseUrl,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

export async function fetchJson(
  url: string,
  init?: RequestInit,
): Promise<{
  status: number;
  headers: Headers;
  json: Record<string, any> | null;
  text: string;
}> {
  const res = await fetch(url, init);
  const text = await res.text();
  let json: Record<string, any> | null = null;
  try {
    const parsed: unknown = text ? JSON.parse(text) : null;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      json = parsed as Record<string, any>;
    } else {
      json = null;
    }
  } catch {
    json = null;
  }
  return { status: res.status, headers: res.headers, json, text };
}

export function makeCfCtx(): {
  ctx: CfExecutionContext;
  waited: Array<Promise<unknown>>;
} {
  const waited: Array<Promise<unknown>> = [];
  const ctx: CfExecutionContext = {
    waitUntil(p: Promise<unknown>) {
      waited.push(p);
    },
    passThroughOnException() {},
  };
  return { ctx, waited };
}

export async function callCf(
  handler: (request: Request, env?: CfEnv, ctx?: CfExecutionContext) => Promise<Response>,
  input: {
    method: string;
    path: string;
    origin?: string;
    headers?: Record<string, string>;
    body?: unknown;
    env?: CfEnv;
    ctx?: CfExecutionContext;
  },
): Promise<{
  status: number;
  headers: Headers;
  json: Record<string, any> | null;
  text: string;
}> {
  const url = new URL(input.path, 'https://relay.test');
  const headers = new Headers(input.headers || {});
  if (input.origin) headers.set('Origin', input.origin);
  let body: string | undefined;
  if (input.body !== undefined) {
    headers.set('Content-Type', headers.get('Content-Type') || 'application/json');
    body = typeof input.body === 'string' ? input.body : JSON.stringify(input.body);
  }

  const req = new Request(url.toString(), {
    method: input.method,
    headers,
    body,
  });

  const res = await handler(req, input.env, input.ctx);
  const text = await res.text();
  let json: Record<string, any> | null = null;
  try {
    const parsed: unknown = text ? JSON.parse(text) : null;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      json = parsed as Record<string, any>;
    } else {
      json = null;
    }
  } catch {
    json = null;
  }
  return { status: res.status, headers: res.headers, json, text };
}

export function getPath(json: unknown, ...path: Array<string | number>): unknown {
  let cursor: unknown = json;
  for (const key of path) {
    if (typeof key === 'number') {
      if (!Array.isArray(cursor)) return undefined;
      cursor = cursor[key];
      continue;
    }
    if (!cursor || typeof cursor !== 'object') return undefined;
    cursor = (cursor as Record<string, unknown>)[key];
  }
  return cursor;
}

export function makeGoogleEmailOtpRegistrationOffer(input: {
  walletId: string;
  candidateId?: string;
  offerId?: string;
}) {
  const candidateId = input.candidateId || 'registration-candidate-1';
  return {
    offerId: input.offerId || 'registration-offer-1',
    selectedCandidateId: candidateId,
    candidates: [{ candidateId, walletId: input.walletId }] as const,
  };
}

export function makeEmailOtpRecoveryWrappedEnrollmentEscrows(input: {
  walletId: string;
  userId: string;
  authSubjectId?: string;
  enrollmentSealKeyVersion: string;
  nowMs?: number;
}) {
  const nowMs = input.nowMs ?? Date.now();
  const authSubjectId = input.authSubjectId || input.userId;
  return Array.from({ length: EMAIL_OTP_RECOVERY_KEY_COUNT }, (_, index) => {
    const metadata = {
      walletId: input.walletId,
      userId: input.userId,
      authSubjectId,
      authMethod: 'google_sso_email_otp' as const,
      enrollmentId: `email-otp-device-enrollment-v1:${input.walletId}:${authSubjectId}`,
      enrollmentVersion: '1',
      enrollmentSealKeyVersion: input.enrollmentSealKeyVersion,
      signingRootId: 'email_otp_default_signing_root',
      signingRootVersion: 'default',
      recoveryKeyId: `recovery-key-${index + 1}`,
    };
    return {
      version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
      alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
      secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
      escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
      ...metadata,
      recoveryKeyStatus: 'active',
      nonceB64u: base64UrlEncode(Uint8Array.from(Array.from({ length: 12 }, (_, i) => i + index))),
      wrappedDeviceEnrollmentEscrowB64u: base64UrlEncode(
        Uint8Array.from(Array.from({ length: 48 }, (_, i) => i + index + 1)),
      ),
      aadHashB64u: base64UrlEncode(
        createHash('sha256')
          .update(
            encodeEmailOtpRecoveryWrappedEnrollmentAad(buildEmailOtpRecoveryWrapBinding(metadata)),
          )
          .digest(),
      ),
      issuedAtMs: nowMs,
      updatedAtMs: nowMs,
    };
  });
}

export function makeEmailOtpRecoveryRotationEscrowInputs(input: {
  walletId: string;
  userId: string;
  authSubjectId?: string;
  enrollmentSealKeyVersion: string;
  nowMs?: number;
}): Array<{
  recoveryKeyId: string;
  nonceB64u: string;
  wrappedDeviceEnrollmentEscrowB64u: string;
  aadHashB64u: string;
}> {
  return makeEmailOtpRecoveryWrappedEnrollmentEscrows(input).map((record, index) => {
    const recoveryKeyId = `rotated-recovery-key-${index + 1}`;
    const metadata = {
      walletId: record.walletId,
      userId: record.userId,
      authSubjectId: record.authSubjectId,
      authMethod: record.authMethod,
      enrollmentId: record.enrollmentId,
      enrollmentVersion: record.enrollmentVersion,
      enrollmentSealKeyVersion: record.enrollmentSealKeyVersion,
      signingRootId: record.signingRootId,
      signingRootVersion: record.signingRootVersion,
      recoveryKeyId,
    };
    return {
      recoveryKeyId,
      nonceB64u: base64UrlEncode(
        Uint8Array.from(Array.from({ length: 12 }, (_, offset) => offset + index + 32)),
      ),
      wrappedDeviceEnrollmentEscrowB64u: base64UrlEncode(
        Uint8Array.from(Array.from({ length: 48 }, (_, offset) => offset + index + 64)),
      ),
      aadHashB64u: base64UrlEncode(
        createHash('sha256')
          .update(
            encodeEmailOtpRecoveryWrappedEnrollmentAad(buildEmailOtpRecoveryWrapBinding(metadata)),
          )
          .digest(),
      ),
    };
  });
}

export function makeSessionAdapter(overrides: Partial<SessionAdapter> = {}): SessionAdapter {
  const adapter: SessionAdapter = {
    signJwt: overrides.signJwt || (async (sub: string) => `jwt-for:${sub}`),
    parse: overrides.parse || (async () => ({ ok: false }) as const),
    buildSetCookie:
      overrides.buildSetCookie ||
      ((token: string) =>
        `${SESSION_COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`),
    buildClearCookie:
      overrides.buildClearCookie || (() => `${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0`),
    refresh:
      overrides.refresh ||
      (async () => ({ ok: false, code: 'not_eligible', message: 'not eligible' })),
  };
  return adapter;
}

export function makeFakeAuthService(
  overrides: Partial<{
    getConfiguredRelayerAccount: RouterApiServiceBag['router']['getConfiguredRelayerAccount'];
    getRelayerAccount: AuthService['getRelayerAccount'];
    createRegistrationIntent: RouterApiServiceBag['walletRegistration']['createRegistrationIntent'];
    prepareWalletRegistration: RouterApiServiceBag['walletRegistration']['prepareWalletRegistration'];
    startWalletRegistration: RouterApiServiceBag['walletRegistration']['startWalletRegistration'];
    respondWalletRegistrationHss: RouterApiServiceBag['walletRegistration']['respondWalletRegistrationHss'];
    finalizeWalletRegistration: RouterApiServiceBag['walletRegistration']['finalizeWalletRegistration'];
    createAddAuthMethodIntent: RouterApiServiceBag['walletAuthMethods']['createAddAuthMethodIntent'];
    createAddSignerIntent: RouterApiServiceBag['walletAuthMethods']['createAddSignerIntent'];
    finalizeWalletAddAuthMethod: RouterApiServiceBag['walletAuthMethods']['finalizeWalletAddAuthMethod'];
    finalizeWalletAddSigner: RouterApiServiceBag['walletAuthMethods']['finalizeWalletAddSigner'];
    respondWalletAddSignerHss: RouterApiServiceBag['walletAuthMethods']['respondWalletAddSignerHss'];
    revokeWalletAuthMethod: RouterApiServiceBag['walletAuthMethods']['revokeWalletAuthMethod'];
    startWalletAddAuthMethod: RouterApiServiceBag['walletAuthMethods']['startWalletAddAuthMethod'];
    startWalletAddSigner: RouterApiServiceBag['walletAuthMethods']['startWalletAddSigner'];
    createWebAuthnLoginOptions: AuthService['createWebAuthnLoginOptions'];
    verifyWebAuthnLogin: AuthService['verifyWebAuthnLogin'];
    verifyWebAuthnAuthenticationLite: RouterApiServiceBag['webAuthn']['verifyWebAuthnAuthenticationLite'];
    listWebAuthnAuthenticatorsForUser: RouterApiServiceBag['webAuthn']['listWebAuthnAuthenticatorsForUser'];
    createEmailOtpUnlockChallenge: AuthService['createEmailOtpUnlockChallenge'];
    verifyEmailOtpUnlockProof: AuthService['verifyEmailOtpUnlockProof'];
    applyEmailOtpServerSeal: RouterApiServiceBag['emailOtp']['applyEmailOtpServerSeal'];
    createEmailOtpChallenge: AuthService['createEmailOtpChallenge'];
    createEmailOtpDeviceRecoveryChallenge: RouterApiServiceBag['emailOtp']['createEmailOtpDeviceRecoveryChallenge'];
    createEmailOtpEnrollmentChallenge: RouterApiServiceBag['emailOtp']['createEmailOtpEnrollmentChallenge'];
    consumeEmailOtpGrant: RouterApiServiceBag['emailOtp']['consumeEmailOtpGrant'];
    consumeEmailOtpRecoveryKey: RouterApiServiceBag['emailOtp']['consumeEmailOtpRecoveryKey'];
    getEmailOtpRecoveryCodeStatus: RouterApiServiceBag['emailOtp']['getEmailOtpRecoveryCodeStatus'];
    isEmailOtpStrongAuthRequired: RouterApiServiceBag['emailOtp']['isEmailOtpStrongAuthRequired'];
    readActiveEmailOtpEnrollment: RouterApiServiceBag['emailOtp']['readActiveEmailOtpEnrollment'];
    recordEmailOtpRecoveryKeyAttemptFailure: RouterApiServiceBag['emailOtp']['recordEmailOtpRecoveryKeyAttemptFailure'];
    removeEmailOtpServerSeal: RouterApiServiceBag['emailOtp']['removeEmailOtpServerSeal'];
    rotateEmailOtpRecoveryKeys: RouterApiServiceBag['emailOtp']['rotateEmailOtpRecoveryKeys'];
    validateGoogleEmailOtpRegistrationCandidateWallet: RouterApiServiceBag['emailOtp']['validateGoogleEmailOtpRegistrationCandidateWallet'];
    verifyEmailOtpChallenge: AuthService['verifyEmailOtpChallenge'];
    verifyEmailOtpDeviceRecoveryChallenge: RouterApiServiceBag['emailOtp']['verifyEmailOtpDeviceRecoveryChallenge'];
    verifyEmailOtpEnrollment: RouterApiServiceBag['emailOtp']['verifyEmailOtpEnrollment'];
    readEmailOtpEnrollment: AuthService['readEmailOtpEnrollment'];
    readEmailOtpOutboxEntry: AuthService['readEmailOtpOutboxEntry'];
    createWebAuthnSyncAccountOptions: AuthService['createWebAuthnSyncAccountOptions'];
    verifyWebAuthnSyncAccount: AuthService['verifyWebAuthnSyncAccount'];
    executeSignedDelegate: AuthService['executeSignedDelegate'];
    getOrCreateAppSessionVersion: AuthService['getOrCreateAppSessionVersion'];
    validateAppSessionVersion: AuthService['validateAppSessionVersion'];
    rotateAppSessionVersion: AuthService['rotateAppSessionVersion'];
    verifyOidcJwtExchange: AuthService['verifyOidcJwtExchange'];
    resolveOidcWalletId: AuthService['resolveOidcWalletId'];
    resolveGoogleEmailOtpSession: AuthService['resolveGoogleEmailOtpSession'];
    consumeGoogleEmailOtpRegistrationAttemptRateLimit: AuthService['consumeGoogleEmailOtpRegistrationAttemptRateLimit'];
    recordGoogleEmailOtpRegistrationAttemptPublicKey: AuthService['recordGoogleEmailOtpRegistrationAttemptPublicKey'];
    completeGoogleEmailOtpRegistrationAttempt: AuthService['completeGoogleEmailOtpRegistrationAttempt'];
    failGoogleEmailOtpRegistrationAttempt: AuthService['failGoogleEmailOtpRegistrationAttempt'];
    cleanupGoogleEmailOtpDevRegistrationState: AuthService['cleanupGoogleEmailOtpDevRegistrationState'];
    isGoogleOidcConfigured: AuthService['isGoogleOidcConfigured'];
    getGoogleOidcPublicConfig: RouterApiServiceBag['identity']['getGoogleOidcPublicConfig'];
    verifyGoogleLogin: AuthService['verifyGoogleLogin'];
    markEmailOtpStrongAuthSatisfied: AuthService['markEmailOtpStrongAuthSatisfied'];
    checkAccountExists: AuthService['checkAccountExists'];
    createAccount: AuthService['createAccount'];
    viewAccessKeyList: AuthService['viewAccessKeyList'];
    prepareEmailRecovery: AuthService['prepareEmailRecovery'];
    respondEmailRecoveryEcdsa: AuthService['respondEmailRecoveryEcdsa'];
    getRecoverySession: AuthService['getRecoverySession'];
    updateRecoverySessionStatus: AuthService['updateRecoverySessionStatus'];
    recordRecoveryExecution: AuthService['recordRecoveryExecution'];
    listRecoveryExecutions: AuthService['listRecoveryExecutions'];
    listRecoveryExecutionsByStatus: AuthService['listRecoveryExecutionsByStatus'];
    recordNearPublicKeyMetadata: AuthService['recordNearPublicKeyMetadata'];
    fundImplicitNearAccount: RouterApiServiceBag['nearFunding']['fundImplicitNearAccount'];
    listNearPublicKeysForUser: RouterApiServiceBag['nearFunding']['listNearPublicKeysForUser'];
    listIdentities: AuthService['listIdentities'];
    linkIdentity: AuthService['linkIdentity'];
    unlinkIdentity: AuthService['unlinkIdentity'];
    getThresholdSigningService: AuthService['getThresholdSigningService'];
    ecdsaHssRoleLocalBootstrap: RouterApiServiceBag['thresholdRuntime']['ecdsaHssRoleLocalBootstrap'];
    ecdsaHssRoleLocalExportShare: RouterApiServiceBag['thresholdRuntime']['ecdsaHssRoleLocalExportShare'];
    listThresholdEcdsaKeyIdentityTargetsForUser: RouterApiServiceBag['thresholdRuntime']['listThresholdEcdsaKeyIdentityTargetsForUser'];
    listWalletEcdsaKeyFactsInventory: RouterApiServiceBag['thresholdRuntime']['listWalletEcdsaKeyFactsInventory'];
    verifyEcdsaHssRoleLocalClientRootProofForExistingKey: RouterApiServiceBag['thresholdRuntime']['verifyEcdsaHssRoleLocalClientRootProofForExistingKey'];
    emailRecovery: unknown;
  }> = {},
): AuthService & RouterApiServiceBag {
  const service = {
    getConfiguredRelayerAccount:
      overrides.getConfiguredRelayerAccount || (() => 'w3a-relayer.testnet'),
    getRelayerAccount:
      overrides.getRelayerAccount ||
      (async () => ({ accountId: 'w3a-relayer.testnet', publicKey: 'ed25519:test' })),
    createRegistrationIntent:
      overrides.createRegistrationIntent ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    prepareWalletRegistration:
      overrides.prepareWalletRegistration ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    startWalletRegistration:
      overrides.startWalletRegistration ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    respondWalletRegistrationHss:
      overrides.respondWalletRegistrationHss ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    finalizeWalletRegistration:
      overrides.finalizeWalletRegistration ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    createAddAuthMethodIntent:
      overrides.createAddAuthMethodIntent ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    createAddSignerIntent:
      overrides.createAddSignerIntent ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    finalizeWalletAddAuthMethod:
      overrides.finalizeWalletAddAuthMethod ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    finalizeWalletAddSigner:
      overrides.finalizeWalletAddSigner ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    respondWalletAddSignerHss:
      overrides.respondWalletAddSignerHss ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    revokeWalletAuthMethod:
      overrides.revokeWalletAuthMethod ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    startWalletAddAuthMethod:
      overrides.startWalletAddAuthMethod ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    startWalletAddSigner:
      overrides.startWalletAddSigner ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    createWebAuthnLoginOptions:
      overrides.createWebAuthnLoginOptions ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    verifyWebAuthnLogin:
      overrides.verifyWebAuthnLogin ||
      (async () => ({
        ok: false,
        verified: false,
        code: 'not_implemented',
        message: 'not implemented',
      })),
    verifyWebAuthnAuthenticationLite:
      overrides.verifyWebAuthnAuthenticationLite ||
      (async () => ({
        success: false,
        verified: false,
        code: 'not_implemented',
        message: 'not implemented',
      })),
    listWebAuthnAuthenticatorsForUser:
      overrides.listWebAuthnAuthenticatorsForUser ||
      (async () => ({
        ok: true,
        authenticators: [],
      })),
    createEmailOtpUnlockChallenge:
      overrides.createEmailOtpUnlockChallenge ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    verifyEmailOtpUnlockProof:
      overrides.verifyEmailOtpUnlockProof ||
      (async () => ({
        ok: false,
        verified: false,
        code: 'not_implemented',
        message: 'not implemented',
      })),
    createEmailOtpChallenge:
      overrides.createEmailOtpChallenge ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    createEmailOtpDeviceRecoveryChallenge:
      overrides.createEmailOtpDeviceRecoveryChallenge ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    createEmailOtpEnrollmentChallenge:
      overrides.createEmailOtpEnrollmentChallenge ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    applyEmailOtpServerSeal:
      overrides.applyEmailOtpServerSeal ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    consumeEmailOtpGrant:
      overrides.consumeEmailOtpGrant ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    consumeEmailOtpRecoveryKey:
      overrides.consumeEmailOtpRecoveryKey ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    getEmailOtpRecoveryCodeStatus:
      overrides.getEmailOtpRecoveryCodeStatus ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    isEmailOtpStrongAuthRequired:
      overrides.isEmailOtpStrongAuthRequired ||
      (async (request) => ({
        ok: true,
        required: false,
        walletId: String(
          (request as { walletId?: unknown }).walletId || 'g-fake-oidc-wallet.testnet',
        ),
      })),
    recordEmailOtpRecoveryKeyAttemptFailure:
      overrides.recordEmailOtpRecoveryKeyAttemptFailure ||
      (async (request) => ({
        ok: true,
        walletId: String(
          (request as { walletId?: unknown }).walletId || 'g-fake-oidc-wallet.testnet',
        ),
        recordedAtMs: Date.now(),
      })),
    removeEmailOtpServerSeal:
      overrides.removeEmailOtpServerSeal ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    rotateEmailOtpRecoveryKeys:
      overrides.rotateEmailOtpRecoveryKeys ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    validateGoogleEmailOtpRegistrationCandidateWallet:
      overrides.validateGoogleEmailOtpRegistrationCandidateWallet || (async () => ({ ok: true })),
    verifyEmailOtpChallenge:
      overrides.verifyEmailOtpChallenge ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    verifyEmailOtpDeviceRecoveryChallenge:
      overrides.verifyEmailOtpDeviceRecoveryChallenge ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    verifyEmailOtpEnrollment:
      overrides.verifyEmailOtpEnrollment ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    consumeGoogleEmailOtpRegistrationAttemptRateLimit:
      overrides.consumeGoogleEmailOtpRegistrationAttemptRateLimit || (async () => ({ ok: true })),
    resolveGoogleEmailOtpSession:
      overrides.resolveGoogleEmailOtpSession ||
      (async (request) => {
        const walletId = String((request as { email?: unknown }).email || 'alice@example.com')
          .trim()
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/^-+|-+$/g, '');
        return {
          ok: true,
          mode: 'register_started',
          walletId: `${walletId || 'alice'}.testnet`,
          providerSubject: String(
            (request as { providerSubject?: unknown }).providerSubject || 'google:user.test',
          ),
          email: String((request as { email?: unknown }).email || 'alice@example.com'),
          registrationAttemptId: 'google-email-otp-attempt-test',
          expiresAtMs: Date.now() + 60_000,
        };
      }),
    completeGoogleEmailOtpRegistrationAttempt:
      overrides.completeGoogleEmailOtpRegistrationAttempt || (async () => ({ ok: true })),
    recordGoogleEmailOtpRegistrationAttemptPublicKey:
      overrides.recordGoogleEmailOtpRegistrationAttemptPublicKey || (async () => ({ ok: true })),
    failGoogleEmailOtpRegistrationAttempt:
      overrides.failGoogleEmailOtpRegistrationAttempt || (async () => undefined),
    cleanupGoogleEmailOtpDevRegistrationState:
      overrides.cleanupGoogleEmailOtpDevRegistrationState ||
      (async () => ({
        ok: true,
        providerSubject: 'google:user.test',
        expiredRegistrationAttemptsDeleted: 0,
        orphanedWalletMappingRemoved: false,
        orphanedWalletMappingSkippedReason: 'no_linked_wallet',
      })),
    readEmailOtpEnrollment:
      overrides.readEmailOtpEnrollment ||
      (async (request) => ({
        ok: true,
        enrollment: {
          walletId: String(
            (request as { walletId?: unknown }).walletId || 'g-fake-oidc-wallet.testnet',
          ),
          providerUserId: 'user.testnet',
          orgId: 'org_fake',
          verifiedEmail: 'user@example.com',
          enrollmentId: 'email-otp-device-enrollment-v1:g-fake-oidc-wallet.testnet:user.testnet',
          enrollmentVersion: '1',
          enrollmentSealKeyVersion: 'test-email-otp-key-v1',
          signingRootId: 'email_otp_default_signing_root',
          signingRootVersion: 'default',
          recoveryWrappedEnrollmentEscrowCount: 10,
          clientUnlockPublicKeyB64u: 'test-unlock-public-key',
          unlockKeyVersion: 'test-unlock-key-v1',
          thresholdEcdsaClientVerifyingShareB64u: 'test-ecdsa-client-verifying-share',
          createdAtMs: 0,
          updatedAtMs: 0,
        },
      })),
    readActiveEmailOtpEnrollment:
      overrides.readActiveEmailOtpEnrollment ||
      (async (request) => ({
        ok: true,
        enrollment: {
          walletId: String(
            (request as { walletId?: unknown }).walletId || 'g-fake-oidc-wallet.testnet',
          ),
          providerUserId: String(
            (request as { providerUserId?: unknown }).providerUserId || 'user.testnet',
          ),
          orgId: 'org_fake',
          verifiedEmail: 'user@example.com',
          enrollmentId: 'email-otp-device-enrollment-v1:g-fake-oidc-wallet.testnet:user.testnet',
          enrollmentVersion: '1',
          enrollmentSealKeyVersion: 'test-email-otp-key-v1',
          signingRootId: 'email_otp_default_signing_root',
          signingRootVersion: 'default',
          recoveryWrappedEnrollmentEscrowCount: 10,
          clientUnlockPublicKeyB64u: 'test-unlock-public-key',
          unlockKeyVersion: 'test-unlock-key-v1',
          thresholdEcdsaClientVerifyingShareB64u: 'test-ecdsa-client-verifying-share',
          createdAtMs: 0,
          updatedAtMs: 0,
        },
      })),
    readEmailOtpOutboxEntry:
      overrides.readEmailOtpOutboxEntry ||
      (async () => ({ ok: false, code: 'not_found', message: 'not found' })),
    createWebAuthnSyncAccountOptions:
      overrides.createWebAuthnSyncAccountOptions ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    verifyWebAuthnSyncAccount:
      overrides.verifyWebAuthnSyncAccount ||
      (async () => ({
        ok: false,
        verified: false,
        code: 'not_implemented',
        message: 'not implemented',
      })),
    executeSignedDelegate:
      overrides.executeSignedDelegate ||
      (async () => ({ ok: false, code: 'not_implemented', error: 'not implemented' })),
    getOrCreateAppSessionVersion:
      overrides.getOrCreateAppSessionVersion ||
      (async () => ({ ok: true, appSessionVersion: 'v1' })),
    validateAppSessionVersion: overrides.validateAppSessionVersion || (async () => ({ ok: true })),
    rotateAppSessionVersion:
      overrides.rotateAppSessionVersion || (async () => ({ ok: true, appSessionVersion: 'v2' })),
    verifyOidcJwtExchange:
      overrides.verifyOidcJwtExchange ||
      (async () => ({
        ok: false,
        verified: false,
        code: 'not_implemented',
        message: 'not implemented',
      })),
    resolveOidcWalletId:
      overrides.resolveOidcWalletId || (async () => 'g-fake-oidc-wallet.testnet'),
    isGoogleOidcConfigured: overrides.isGoogleOidcConfigured || (() => false),
    getGoogleOidcPublicConfig:
      overrides.getGoogleOidcPublicConfig ||
      (() => ({
        configured: false,
      })),
    verifyGoogleLogin:
      overrides.verifyGoogleLogin ||
      (async () => ({
        ok: false,
        verified: false,
        code: 'not_implemented',
        message: 'not implemented',
      })),
    markEmailOtpStrongAuthSatisfied:
      overrides.markEmailOtpStrongAuthSatisfied || (async () => ({ ok: true })),
    checkAccountExists: overrides.checkAccountExists || (async () => false),
    createAccount:
      overrides.createAccount || (async () => ({ success: false, error: 'not implemented' })),
    viewAccessKeyList: overrides.viewAccessKeyList || (async () => ({ keys: [] })),
    prepareEmailRecovery:
      overrides.prepareEmailRecovery ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    respondEmailRecoveryEcdsa:
      overrides.respondEmailRecoveryEcdsa ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    getRecoverySession: overrides.getRecoverySession || (async () => ({ ok: true, record: null })),
    updateRecoverySessionStatus:
      overrides.updateRecoverySessionStatus ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    recordRecoveryExecution:
      overrides.recordRecoveryExecution ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    listRecoveryExecutions:
      overrides.listRecoveryExecutions || (async () => ({ ok: true, records: [] })),
    listRecoveryExecutionsByStatus:
      overrides.listRecoveryExecutionsByStatus || (async () => ({ ok: true, records: [] })),
    recordNearPublicKeyMetadata:
      overrides.recordNearPublicKeyMetadata || (async () => ({ ok: true })),
    fundImplicitNearAccount:
      overrides.fundImplicitNearAccount ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    listNearPublicKeysForUser:
      overrides.listNearPublicKeysForUser ||
      (async () => ({
        ok: true,
        keys: [],
      })),
    listIdentities: overrides.listIdentities || (async () => ({ ok: true, subjects: [] })),
    linkIdentity:
      overrides.linkIdentity ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    unlinkIdentity:
      overrides.unlinkIdentity ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    getThresholdSigningService: overrides.getThresholdSigningService || (() => null),
    ecdsaHssRoleLocalBootstrap:
      overrides.ecdsaHssRoleLocalBootstrap ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    ecdsaHssRoleLocalExportShare:
      overrides.ecdsaHssRoleLocalExportShare ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    listThresholdEcdsaKeyIdentityTargetsForUser:
      overrides.listThresholdEcdsaKeyIdentityTargetsForUser ||
      (async (request) => ({
        records: [],
        diagnostics: {
          userId: String((request as { userId?: unknown }).userId || 'g-fake-oidc-wallet.testnet'),
          inputCount: Array.isArray((request as { keyTargets?: unknown }).keyTargets)
            ? (request as { keyTargets: unknown[] }).keyTargets.length
            : 0,
          returnedCount: 0,
          thresholdServicePresent: false,
          rejected: {},
        },
      })),
    listWalletEcdsaKeyFactsInventory:
      overrides.listWalletEcdsaKeyFactsInventory ||
      (async (request) => ({
        records: [],
        diagnostics: {
          userId: String(
            (request as { walletId?: unknown }).walletId || 'g-fake-oidc-wallet.testnet',
          ),
          inputCount: Array.isArray((request as { keyTargets?: unknown }).keyTargets)
            ? (request as { keyTargets: unknown[] }).keyTargets.length
            : 0,
          returnedCount: 0,
          thresholdServicePresent: false,
          rejected: {},
        },
      })),
    verifyEcdsaHssRoleLocalClientRootProofForExistingKey:
      overrides.verifyEcdsaHssRoleLocalClientRootProofForExistingKey ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    emailRecovery: overrides.emailRecovery ?? null,
  };
  return Object.assign(service, {
    walletRegistration: {
      createRegistrationIntent: service.createRegistrationIntent,
      prepareWalletRegistration: service.prepareWalletRegistration,
      startWalletRegistration: service.startWalletRegistration,
      respondWalletRegistrationHss: service.respondWalletRegistrationHss,
      finalizeWalletRegistration: service.finalizeWalletRegistration,
    },
    walletAuthMethods: {
      createAddAuthMethodIntent: service.createAddAuthMethodIntent,
      createAddSignerIntent: service.createAddSignerIntent,
      finalizeWalletAddAuthMethod: service.finalizeWalletAddAuthMethod,
      finalizeWalletAddSigner: service.finalizeWalletAddSigner,
      respondWalletAddSignerHss: service.respondWalletAddSignerHss,
      revokeWalletAuthMethod: service.revokeWalletAuthMethod,
      startWalletAddAuthMethod: service.startWalletAddAuthMethod,
      startWalletAddSigner: service.startWalletAddSigner,
    },
    walletUnlock: {
      createEmailOtpUnlockChallenge: service.createEmailOtpUnlockChallenge,
      createWebAuthnLoginOptions: service.createWebAuthnLoginOptions,
      markEmailOtpStrongAuthSatisfied: service.markEmailOtpStrongAuthSatisfied,
      verifyEmailOtpUnlockProof: service.verifyEmailOtpUnlockProof,
      verifyWebAuthnLogin: service.verifyWebAuthnLogin,
    },
    emailOtp: {
      applyEmailOtpServerSeal: service.applyEmailOtpServerSeal,
      cleanupGoogleEmailOtpDevRegistrationState: service.cleanupGoogleEmailOtpDevRegistrationState,
      consumeEmailOtpGrant: service.consumeEmailOtpGrant,
      consumeEmailOtpRecoveryKey: service.consumeEmailOtpRecoveryKey,
      createEmailOtpChallenge: service.createEmailOtpChallenge,
      createEmailOtpDeviceRecoveryChallenge: service.createEmailOtpDeviceRecoveryChallenge,
      createEmailOtpEnrollmentChallenge: service.createEmailOtpEnrollmentChallenge,
      getEmailOtpRecoveryCodeStatus: service.getEmailOtpRecoveryCodeStatus,
      isEmailOtpStrongAuthRequired: service.isEmailOtpStrongAuthRequired,
      markEmailOtpStrongAuthSatisfied: service.markEmailOtpStrongAuthSatisfied,
      readActiveEmailOtpEnrollment: service.readActiveEmailOtpEnrollment,
      readEmailOtpEnrollment: service.readEmailOtpEnrollment,
      readEmailOtpOutboxEntry: service.readEmailOtpOutboxEntry,
      recordEmailOtpRecoveryKeyAttemptFailure: service.recordEmailOtpRecoveryKeyAttemptFailure,
      removeEmailOtpServerSeal: service.removeEmailOtpServerSeal,
      rotateEmailOtpRecoveryKeys: service.rotateEmailOtpRecoveryKeys,
      validateGoogleEmailOtpRegistrationCandidateWallet:
        service.validateGoogleEmailOtpRegistrationCandidateWallet,
      verifyEmailOtpChallenge: service.verifyEmailOtpChallenge,
      verifyEmailOtpDeviceRecoveryChallenge: service.verifyEmailOtpDeviceRecoveryChallenge,
      verifyEmailOtpEnrollment: service.verifyEmailOtpEnrollment,
      verifyGoogleLogin: service.verifyGoogleLogin,
    },
    webAuthn: {
      createWebAuthnLoginOptions: service.createWebAuthnLoginOptions,
      createWebAuthnSyncAccountOptions: service.createWebAuthnSyncAccountOptions,
      listWebAuthnAuthenticatorsForUser: service.listWebAuthnAuthenticatorsForUser,
      verifyWebAuthnAuthenticationLite: service.verifyWebAuthnAuthenticationLite,
      verifyWebAuthnLogin: service.verifyWebAuthnLogin,
      verifyWebAuthnSyncAccount: service.verifyWebAuthnSyncAccount,
    },
    identity: {
      consumeGoogleEmailOtpRegistrationAttemptRateLimit:
        service.consumeGoogleEmailOtpRegistrationAttemptRateLimit,
      getGoogleOidcPublicConfig: service.getGoogleOidcPublicConfig,
      linkIdentity: service.linkIdentity,
      listIdentities: service.listIdentities,
      resolveGoogleEmailOtpSession: service.resolveGoogleEmailOtpSession,
      resolveOidcWalletId: service.resolveOidcWalletId,
      unlinkIdentity: service.unlinkIdentity,
      verifyGoogleLogin: service.verifyGoogleLogin,
      verifyOidcJwtExchange: service.verifyOidcJwtExchange,
    },
    sessionVersions: {
      getOrCreateAppSessionVersion: service.getOrCreateAppSessionVersion,
      rotateAppSessionVersion: service.rotateAppSessionVersion,
      validateAppSessionVersion: service.validateAppSessionVersion,
    },
    thresholdRuntime: {
      ecdsaHssRoleLocalBootstrap: service.ecdsaHssRoleLocalBootstrap,
      ecdsaHssRoleLocalExportShare: service.ecdsaHssRoleLocalExportShare,
      getThresholdSigningService: service.getThresholdSigningService,
      listThresholdEcdsaKeyIdentityTargetsForUser:
        service.listThresholdEcdsaKeyIdentityTargetsForUser,
      listWalletEcdsaKeyFactsInventory: service.listWalletEcdsaKeyFactsInventory,
      verifyEcdsaHssRoleLocalClientRootProofForExistingKey:
        service.verifyEcdsaHssRoleLocalClientRootProofForExistingKey,
    },
    nearFunding: {
      fundImplicitNearAccount: service.fundImplicitNearAccount,
      listNearPublicKeysForUser: service.listNearPublicKeysForUser,
    },
    recovery: {
      getRecoverySession: service.getRecoverySession,
      recordRecoveryExecution: service.recordRecoveryExecution,
      updateRecoverySessionStatus: service.updateRecoverySessionStatus,
    },
    router: {
      getConfiguredRelayerAccount: service.getConfiguredRelayerAccount,
      getRelayerAccount: service.getRelayerAccount,
    },
  }) as unknown as AuthService & RouterApiServiceBag;
}
