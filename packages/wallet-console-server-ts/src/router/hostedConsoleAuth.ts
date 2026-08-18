import type { CfExecutionContext, FetchHandler } from '@seams/wallet-server/cloud-host';
import { withCors } from '@seams/wallet-server/cloud-host';
import { createCloudflareD1RouterApiAuthService } from '@seams/wallet-server/cloud-host';
import type { SessionAdapter } from '@seams-internal/console-server/boundary/session';
import type { ConsoleOrganizationAccessService } from '@seams-internal/console-server/teamRbac/index';
import type { ConsoleOrgProjectEnvService } from '@seams-internal/console-server/orgProjectEnv/index';

// The /console/auth/* handler, shared by the Console Worker (console-owned
// provider identity) and the pre-cutover combined gateway (wallet identity
// service). Moved out of the combined worker so the combined entrypoint can be
// deleted at cutover without touching Console Worker auth.

export type HostedConsoleTenantScope = {
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function normalizeString(input: unknown): string {
  return String(input ?? '').trim();
}

export type HostedConsoleIdentityService = ReturnType<
  typeof createCloudflareD1RouterApiAuthService
>['identity'];

// Structural port for /console/auth/*: exactly the two provider verifications
// the handler performs. Satisfied by the Wallet identity service (combined
// worker) and by the Console-owned provider identity (Console Worker).
export interface HostedConsoleIdentityPort {
  verifyGoogleLogin(input: { idToken: string }): Promise<{
    readonly ok: boolean;
    readonly verified?: boolean;
    readonly userId?: string;
    readonly code?: string;
    readonly message?: string;
    readonly email?: string;
    readonly name?: string;
    readonly emailVerified?: boolean;
    readonly hostedDomain?: string;
  }>;
  verifyGithubOAuthCode(input: { code: string }): Promise<{
    readonly ok: boolean;
    readonly verified?: boolean;
    readonly userId?: string;
    readonly code?: string;
    readonly message?: string;
    readonly email?: string;
    readonly name?: string;
  }>;
}

type HostedConsoleLoginIdentity =
  | {
      readonly kind: 'google';
      readonly userId: string;
      readonly email: string;
      readonly name: string;
      readonly emailVerified: boolean;
      readonly hostedDomain: string;
    }
  | {
      readonly kind: 'github';
      readonly userId: string;
      readonly email: string;
      readonly name: string;
    };

export type HostedConsoleInitialOwnerPolicy =
  | {
      readonly kind: 'configured_google_email';
      readonly email: string;
    }
  | {
      readonly kind: 'first_verified_google';
    };

export interface HostedConsoleAuthHandlerOptions {
  readonly handler: FetchHandler;
  readonly identity: HostedConsoleIdentityPort;
  readonly session: SessionAdapter;
  readonly organizationAccess: ConsoleOrganizationAccessService;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly scope: HostedConsoleTenantScope;
  readonly initialOwner: HostedConsoleInitialOwnerPolicy;
  readonly corsOrigins: readonly string[];
}

function parseExactConsoleAuthBody(body: unknown, field: 'code' | 'idToken'): string | null {
  if (!isRecord(body)) return null;
  const keys = Object.keys(body);
  if (keys.length !== 1 || keys[0] !== field) return null;
  const value = normalizeString(body[field]);
  return value || null;
}

async function readJsonOrNull(request: Request): Promise<unknown> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function normalizeConsoleLoginEmail(value: unknown): string {
  const email = normalizeString(value).toLowerCase();
  const separator = email.indexOf('@');
  if (
    separator <= 0 ||
    separator === email.length - 1 ||
    email.indexOf('@', separator + 1) !== -1 ||
    /\s/u.test(email)
  ) {
    return '';
  }
  return email;
}

function isAuthoritativeGoogleEmail(
  identity: Extract<HostedConsoleLoginIdentity, { kind: 'google' }>,
): boolean {
  if (!identity.emailVerified || !identity.email) return false;
  const domain = identity.email.slice(identity.email.lastIndexOf('@') + 1);
  return domain === 'gmail.com' || identity.hostedDomain === domain;
}

function hasErrorCode(error: unknown, code: string): boolean {
  return isRecord(error) && normalizeString(error.code) === code;
}

function consoleAuthFailureStatus(code: string): 400 | 401 | 500 | 501 {
  switch (code) {
    case 'invalid_body':
      return 400;
    case 'internal':
      return 500;
    case 'not_configured':
    case 'unsupported':
      return 501;
    default:
      return 401;
  }
}

function consoleAuthJson(body: unknown, status: number, setCookie?: string): Response {
  const headers = new Headers({ 'Content-Type': 'application/json; charset=utf-8' });
  if (setCookie) headers.set('Set-Cookie', setCookie);
  return new Response(JSON.stringify(body), { status, headers });
}

export class HostedConsoleAuthHandler {
  constructor(private readonly options: HostedConsoleAuthHandlerOptions) {}

  async fetch(request: Request, env?: object, ctx?: CfExecutionContext): Promise<Response> {
    const pathname = new URL(request.url).pathname;
    if (request.method === 'OPTIONS' || !pathname.startsWith('/console/auth/')) {
      return await this.options.handler(request, env, ctx);
    }

    let response: Response;
    try {
      response = await this.handleAuthRequest(request, pathname);
    } catch {
      response = consoleAuthJson(
        { ok: false, code: 'internal', message: 'Console authentication failed' },
        500,
      );
    }
    withCors(response.headers, { corsOrigins: [...this.options.corsOrigins] }, request);
    return response;
  }

  private async handleAuthRequest(request: Request, pathname: string): Promise<Response> {
    if (request.method !== 'POST') {
      return consoleAuthJson(
        { ok: false, code: 'method_not_allowed', message: 'Method not allowed' },
        405,
      );
    }
    if (pathname === '/console/auth/google') return await this.loginWithGoogle(request);
    if (pathname === '/console/auth/github') return await this.loginWithGithub(request);
    if (pathname === '/console/auth/revoke') {
      return consoleAuthJson(
        { ok: true, revoked: true },
        200,
        this.options.session.buildClearCookie(),
      );
    }
    return consoleAuthJson({ ok: false, code: 'not_found', message: 'Not Found' }, 404);
  }

  private async loginWithGoogle(request: Request): Promise<Response> {
    const idToken = parseExactConsoleAuthBody(await readJsonOrNull(request), 'idToken');
    if (!idToken) {
      return consoleAuthJson(
        {
          ok: false,
          code: 'invalid_body',
          message: 'Console Google login requires exact idToken',
        },
        400,
      );
    }
    const verified = await this.options.identity.verifyGoogleLogin({ idToken });
    const userId = normalizeString(verified.userId);
    if (!verified.ok || verified.verified !== true || !userId) {
      const code = normalizeString(verified.code) || 'not_verified';
      return consoleAuthJson(
        {
          ok: false,
          code,
          message: normalizeString(verified.message) || 'Google login could not be verified',
        },
        consoleAuthFailureStatus(code),
      );
    }
    return await this.issueConsoleSession({
      kind: 'google',
      userId,
      email: normalizeConsoleLoginEmail(verified.email),
      name: normalizeString(verified.name) || userId,
      emailVerified: verified.emailVerified === true,
      hostedDomain: normalizeString(verified.hostedDomain).toLowerCase(),
    });
  }

  private async loginWithGithub(request: Request): Promise<Response> {
    const code = parseExactConsoleAuthBody(await readJsonOrNull(request), 'code');
    if (!code) {
      return consoleAuthJson(
        {
          ok: false,
          code: 'invalid_body',
          message: 'Console GitHub login requires exact code',
        },
        400,
      );
    }
    const verified = await this.options.identity.verifyGithubOAuthCode({ code });
    const userId = normalizeString(verified.userId);
    if (!verified.ok || verified.verified !== true || !userId) {
      const failureCode = normalizeString(verified.code) || 'not_verified';
      return consoleAuthJson(
        {
          ok: false,
          code: failureCode,
          message: normalizeString(verified.message) || 'GitHub login could not be verified',
        },
        consoleAuthFailureStatus(failureCode),
      );
    }
    return await this.issueConsoleSession({
      kind: 'github',
      userId,
      email: normalizeConsoleLoginEmail(verified.email),
      name: normalizeString(verified.name) || userId,
    });
  }

  private async issueConsoleSession(identity: HostedConsoleLoginIdentity): Promise<Response> {
    await this.bootstrapInitialOwner(identity);
    const authorization = await this.options.organizationAccess.lookupAuthorization({
      orgId: this.options.scope.orgId,
      userId: identity.userId,
    });
    if (!authorization || authorization.kind === 'denied') {
      return consoleAuthJson(
        {
          ok: false,
          code: 'forbidden',
          message: 'No active Console organization membership',
        },
        403,
      );
    }
    const token = await this.options.session.signJwt(identity.userId, {
      kind: 'console_session_v1',
      orgId: this.options.scope.orgId,
      projectId: this.options.scope.projectId,
      environmentId: this.options.scope.envId,
      provider: identity.kind,
      ...(identity.email ? { email: identity.email } : {}),
      ...(identity.name ? { name: identity.name } : {}),
    });
    return consoleAuthJson(
      { ok: true, session: { kind: 'console_session_v1' } },
      200,
      this.options.session.buildSetCookie(token),
    );
  }

  private async bootstrapInitialOwner(identity: HostedConsoleLoginIdentity): Promise<void> {
    if (identity.kind !== 'google') return;
    if (!isAuthoritativeGoogleEmail(identity)) {
      return;
    }
    if (
      this.options.initialOwner.kind === 'configured_google_email' &&
      identity.email !== normalizeConsoleLoginEmail(this.options.initialOwner.email)
    ) {
      return;
    }
    const existing = await this.options.organizationAccess.lookupAuthorization({
      orgId: this.options.scope.orgId,
      userId: identity.userId,
    });
    if (existing?.kind === 'authorized') return;
    await this.options.orgProjectEnv.upsertOrganization(
      {
        orgId: this.options.scope.orgId,
        actorUserId: identity.userId,
      },
      {},
    );
    try {
      await this.options.organizationAccess.bootstrapInitialOwner({
        orgId: this.options.scope.orgId,
        userId: identity.userId,
        email: identity.email,
        displayName: identity.name,
      });
    } catch (error: unknown) {
      if (!hasErrorCode(error, 'owner_already_exists')) throw error;
    }
  }
}

