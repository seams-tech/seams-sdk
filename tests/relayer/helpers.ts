import type { Server } from 'node:http';
import http from 'node:http';
import expressImport from 'express';
import type { AuthService } from '@server/core/AuthService';
import type { SessionAdapter } from '@server/router/express-adaptor';
import type { CfEnv, CfExecutionContext } from '@server/router/cloudflare-adaptor';

type ExpressMiddleware = (req: unknown, res: unknown, next: (err?: unknown) => void) => unknown;
type ExpressAppLike = ((req: unknown, res: unknown) => unknown) & {
  use: (...args: unknown[]) => unknown;
};

const SESSION_COOKIE_NAME =
  String(process.env.SESSION_COOKIE_NAME || 'tatchi-jwt').trim() || 'tatchi-jwt';

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

export function getPath(
  json: unknown,
  ...path: Array<string | number>
): unknown {
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
    getRelayerAccount: AuthService['getRelayerAccount'];
    createWebAuthnLoginOptions: AuthService['createWebAuthnLoginOptions'];
    verifyWebAuthnLogin: AuthService['verifyWebAuthnLogin'];
    createEmailOtpUnlockChallenge: AuthService['createEmailOtpUnlockChallenge'];
    verifyEmailOtpUnlockProof: AuthService['verifyEmailOtpUnlockProof'];
    createEmailOtpChallenge: AuthService['createEmailOtpChallenge'];
    verifyEmailOtpChallenge: AuthService['verifyEmailOtpChallenge'];
    readEmailOtpEnrollment: AuthService['readEmailOtpEnrollment'];
    readEmailOtpOutboxEntry: AuthService['readEmailOtpOutboxEntry'];
    createWebAuthnSyncAccountOptions: AuthService['createWebAuthnSyncAccountOptions'];
    verifyWebAuthnSyncAccount: AuthService['verifyWebAuthnSyncAccount'];
    createAccountAndRegisterUser: AuthService['createAccountAndRegisterUser'];
    executeSignedDelegate: AuthService['executeSignedDelegate'];
    getOrCreateAppSessionVersion: AuthService['getOrCreateAppSessionVersion'];
    validateAppSessionVersion: AuthService['validateAppSessionVersion'];
    rotateAppSessionVersion: AuthService['rotateAppSessionVersion'];
    verifyOidcJwtExchange: AuthService['verifyOidcJwtExchange'];
    resolveOidcWalletId: AuthService['resolveOidcWalletId'];
    resolveGoogleEmailOtpSession: AuthService['resolveGoogleEmailOtpSession'];
    completeGoogleEmailOtpRegistrationAttempt: AuthService['completeGoogleEmailOtpRegistrationAttempt'];
    failGoogleEmailOtpRegistrationAttempt: AuthService['failGoogleEmailOtpRegistrationAttempt'];
    cleanupGoogleEmailOtpDevRegistrationState: AuthService['cleanupGoogleEmailOtpDevRegistrationState'];
    isGoogleOidcConfigured: AuthService['isGoogleOidcConfigured'];
    verifyGoogleLogin: AuthService['verifyGoogleLogin'];
    markEmailOtpStrongAuthSatisfied: AuthService['markEmailOtpStrongAuthSatisfied'];
    checkAccountExists: AuthService['checkAccountExists'];
    createAccount: AuthService['createAccount'];
    viewAccessKeyList: AuthService['viewAccessKeyList'];
    prepareEmailRecovery: AuthService['prepareEmailRecovery'];
    prepareLinkDevice: AuthService['prepareLinkDevice'];
    getRecoverySession: AuthService['getRecoverySession'];
    updateRecoverySessionStatus: AuthService['updateRecoverySessionStatus'];
    listSmartAccountRecoverySubjects: AuthService['listSmartAccountRecoverySubjects'];
    getSmartAccountRecoverySubjectByAccount: AuthService['getSmartAccountRecoverySubjectByAccount'];
    putSmartAccountRecoverySubject: AuthService['putSmartAccountRecoverySubject'];
    recordRecoveryExecution: AuthService['recordRecoveryExecution'];
    listRecoveryExecutions: AuthService['listRecoveryExecutions'];
    listRecoveryExecutionsByStatus: AuthService['listRecoveryExecutionsByStatus'];
    listAccountSignersByAccount: AuthService['listAccountSignersByAccount'];
    putAccountSigner: AuthService['putAccountSigner'];
    listIdentities: AuthService['listIdentities'];
    linkIdentity: AuthService['linkIdentity'];
    unlinkIdentity: AuthService['unlinkIdentity'];
    getThresholdSigningService: AuthService['getThresholdSigningService'];
    emailRecovery: unknown;
  }> = {},
): AuthService {
  const service = {
    getRelayerAccount:
      overrides.getRelayerAccount ||
      (async () => ({ accountId: 'w3a-relayer.testnet', publicKey: 'ed25519:test' })),
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
    verifyEmailOtpChallenge:
      overrides.verifyEmailOtpChallenge ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
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
          userId: 'user.testnet',
          otpChannel: 'email_otp',
          emailOtpEscrowBlob: 'test-escrow',
          emailOtpKeyVersion: 'test-email-otp-key-v1',
          unlockPublicKey: 'test-unlock-public-key',
          unlockKeyVersion: 'test-unlock-key-v1',
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
    createAccountAndRegisterUser:
      overrides.createAccountAndRegisterUser ||
      (async () => ({ success: false, error: 'not implemented' })),
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
      overrides.createAccount ||
      (async () => ({ success: false, error: 'not implemented' })),
    viewAccessKeyList: overrides.viewAccessKeyList || (async () => ({ keys: [] })),
    prepareEmailRecovery:
      overrides.prepareEmailRecovery ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    prepareLinkDevice:
      overrides.prepareLinkDevice ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    getRecoverySession:
      overrides.getRecoverySession ||
      (async () => ({ ok: true, record: null })),
    updateRecoverySessionStatus:
      overrides.updateRecoverySessionStatus ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    listSmartAccountRecoverySubjects:
      overrides.listSmartAccountRecoverySubjects ||
      (async () => ({ ok: true, records: [] })),
    getSmartAccountRecoverySubjectByAccount:
      overrides.getSmartAccountRecoverySubjectByAccount ||
      (async () => ({ ok: true, record: null })),
    putSmartAccountRecoverySubject:
      overrides.putSmartAccountRecoverySubject ||
      (async (record) => ({ ok: true, record })),
    recordRecoveryExecution:
      overrides.recordRecoveryExecution ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    listRecoveryExecutions:
      overrides.listRecoveryExecutions ||
      (async () => ({ ok: true, records: [] })),
    listRecoveryExecutionsByStatus:
      overrides.listRecoveryExecutionsByStatus ||
      (async () => ({ ok: true, records: [] })),
    listAccountSignersByAccount:
      overrides.listAccountSignersByAccount ||
      (async () => ({ ok: true, records: [] })),
    putAccountSigner:
      overrides.putAccountSigner ||
      (async (record) => ({ ok: true, record })),
    listIdentities: overrides.listIdentities || (async () => ({ ok: true, subjects: [] })),
    linkIdentity:
      overrides.linkIdentity ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    unlinkIdentity:
      overrides.unlinkIdentity ||
      (async () => ({ ok: false, code: 'not_implemented', message: 'not implemented' })),
    getThresholdSigningService: overrides.getThresholdSigningService || (() => null),
    emailRecovery: overrides.emailRecovery ?? null,
  };
  return service as unknown as AuthService;
}
