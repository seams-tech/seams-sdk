import type { Server } from 'node:http';
import http from 'node:http';
import { createHash } from 'node:crypto';
import expressImport from 'express';
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
