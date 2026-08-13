import { expect, test } from '@playwright/test';
import {
  authenticationFromValidatedSessionState,
  BrowserSigningSurface,
} from '@/SeamsWeb/signingSurface/BrowserSigningSurface';
import type { WalletAuthenticationState } from '@/core/types/seams';
import { base64UrlEncode } from '@shared/utils/encoders';
import { parseWalletId } from '@shared/utils/domainIds';
import {
  activeHostedWalletAppSessionJwt,
  redeemHostedWalletSeamsSession,
} from '@/SeamsWeb/walletIframe/host/hostedWalletSeamsSession';

function walletId(value: string) {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

type RestorationTestSurface = BrowserSigningSurface;

type RestorationTestSurfaceOptions = {
  readonly initialState?: WalletAuthenticationState;
  readonly resolveAppSessionJwtForWallet?: () => Promise<string>;
};

async function noCachedEmailOtpJwt(): Promise<string> {
  return '';
}

function createRestorationTestSurface(
  options: RestorationTestSurfaceOptions = {},
): RestorationTestSurface {
  const surface = Object.create(BrowserSigningSurface.prototype) as RestorationTestSurface;
  const fields = surface as unknown as Record<string, unknown>;
  fields.walletAuthenticationState = options.initialState ?? { kind: 'signed_out' };
  fields.walletAuthenticationRestoreInFlight = new Map();
  fields.walletAuthenticationRestorationBlocked = false;
  fields.walletAuthenticationRestoreGeneration = 0;
  fields.seamsWebConfigs = { network: { relayer: { url: 'https://relay.local' } } };
  fields.userPreferencesManager = {
    initFromIndexedDB: async () => undefined,
    getCurrentWalletId: () => undefined,
  };
  fields.emailOtpSessions = {
    resolveAppSessionJwtForWallet: options.resolveAppSessionJwtForWallet ?? noCachedEmailOtpJwt,
  };
  return surface;
}

function installFetch(fetchImpl: typeof fetch): () => void {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  return () => {
    globalThis.fetch = originalFetch;
  };
}

function createDeferred<T>(): {
  readonly promise: Promise<T>;
  readonly resolve: (value: T | PromiseLike<T>) => void;
} {
  let resolvePromise: (value: T | PromiseLike<T>) => void = () => undefined;
  const promise = new Promise<T>((resolve) => {
    resolvePromise = resolve;
  });
  return { promise, resolve: resolvePromise };
}

function authenticatedPasskeyResponse(targetWalletId: string): Response {
  return new Response(
    JSON.stringify({
      authenticated: true,
      claims: {
        kind: 'app_session_v1',
        provider: 'passkey',
        sub: targetWalletId,
        authSource: { kind: 'passkey', credentialIdB64u: 'credential-id' },
      },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function appSessionJwtWithPayload(payload: Record<string, unknown>): string {
  const header = base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: 'none' })));
  const body = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  return `${header}.${body}.fixture`;
}

function emailOtpAppSessionClaims(targetWalletId: string, providerSubject: string) {
  return {
    kind: 'app_session_v1',
    provider: 'oidc',
    oidcProvider: 'google',
    providerSubject,
    sub: providerSubject,
    walletId: targetWalletId,
    authSource: {
      kind: 'oidc_provider',
      providerId: 'google_oidc',
      providerSubject,
    },
  } as const;
}

function authenticatedEmailOtpResponse(targetWalletId: string, providerSubject: string): Response {
  return new Response(
    JSON.stringify({
      authenticated: true,
      claims: emailOtpAppSessionClaims(targetWalletId, providerSubject),
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function uncorrelatedSessionResponse(providerSubject: string): Response {
  return new Response(
    JSON.stringify({
      authenticated: true,
      claims: {
        kind: 'app_session_v1',
        authSource: {
          kind: 'oidc_provider',
          providerId: 'google_oidc',
          providerSubject,
        },
      },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

function hostedWalletSessionExchangeResponse(args: {
  appSessionJwt: string;
  walletOrigin: string;
}): Response {
  const session = {
    kind: 'app_session_v1',
    tenantId: 'tenant-hosted-refresh',
    userId: 'hosted-refresh-user',
    seamsSessionId: 'hosted-refresh-session',
    deviceId: 'hosted-refresh-device',
    audience: {
      kind: 'hosted_wallet_iframe',
      appOrigin: 'https://app.example.test',
      walletOrigin: args.walletOrigin,
    },
    expiresAtMs: Date.now() + 60 * 60 * 1000,
  };
  return new Response(JSON.stringify({ ok: true, session, jwt: args.appSessionJwt }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

async function seedHostedOidcSession(args: {
  walletId: string;
  providerSubject: string;
}): Promise<{ appSessionJwt: string; cleanup: () => void }> {
  const walletOrigin = 'https://wallet.example.test';
  const appSessionJwt = appSessionJwtWithPayload({
    kind: 'app_session_v1',
    tenantId: 'tenant-hosted-refresh',
    sub: 'hosted-refresh-user',
    seamsSessionId: 'hosted-refresh-session',
    deviceId: 'hosted-refresh-device',
    provider: 'oidc',
    oidcProvider: 'google',
    providerSubject: args.providerSubject,
    walletId: args.walletId,
    authSource: {
      kind: 'oidc_provider',
      providerId: 'google_oidc',
      providerSubject: args.providerSubject,
    },
    sessionAudience: {
      kind: 'hosted_wallet_iframe',
      appOrigin: 'https://app.example.test',
      walletOrigin,
    },
    exp: Math.floor(Date.now() / 1000) + 60 * 60,
  });
  const originalWindow = Reflect.get(globalThis, 'window');
  const cleanup = (): void => {
    activeHostedWalletAppSessionJwt('https://different-relay.local');
    if (originalWindow === undefined) Reflect.deleteProperty(globalThis, 'window');
    else Reflect.set(globalThis, 'window', originalWindow);
  };
  Reflect.set(globalThis, 'window', { location: { origin: walletOrigin } });
  const exchangeFetch = installFetch(async function sessionExchangeFetch() {
    return hostedWalletSessionExchangeResponse({ appSessionJwt, walletOrigin });
  });
  try {
    await redeemHostedWalletSeamsSession(
      {
        relayUrl: 'https://relay.local',
        exchangeCode: 'hosted-refresh-code',
        nonce: 'hosted-refresh-nonce',
      },
      'https://relay.local',
    );
    return { appSessionJwt, cleanup };
  } catch (error: unknown) {
    cleanup();
    throw error;
  } finally {
    exchangeFetch();
  }
}

test.describe('authoritative wallet authentication restoration', () => {
  test('restores passkey authentication from validated app-session claims', () => {
    expect(
      authenticationFromValidatedSessionState(
        {
          authenticated: true,
          claims: {
            kind: 'app_session_v1',
            provider: 'passkey',
            sub: 'passkey-wallet',
            authSource: { kind: 'passkey', credentialIdB64u: 'credential-id' },
          },
        },
        { kind: 'derive_wallet' },
      ),
    ).toEqual({
      kind: 'authenticated',
      state: { kind: 'authenticated', walletId: 'passkey-wallet', authMethod: 'passkey' },
    });
  });

  test('restores hosted passkey authentication from its signed authority', () => {
    expect(
      authenticationFromValidatedSessionState(
        {
          authenticated: true,
          claims: {
            kind: 'app_session_v1',
            sub: 'passkey-wallet',
            authSource: { kind: 'passkey', credentialIdB64u: 'credential-id' },
          },
        },
        { kind: 'derive_wallet' },
      ),
    ).toEqual({
      kind: 'authenticated',
      state: { kind: 'authenticated', walletId: 'passkey-wallet', authMethod: 'passkey' },
    });
  });

  test('restores Google Email OTP authentication with exact wallet correlation', () => {
    expect(
      authenticationFromValidatedSessionState(
        {
          authenticated: true,
          claims: {
            kind: 'app_session_v1',
            provider: 'oidc',
            providerSubject: 'google:provider-subject',
            sub: 'linked-principal',
            walletId: 'email-wallet',
            oidcProvider: 'google',
            authSource: {
              kind: 'oidc_provider',
              providerId: 'google_oidc',
              providerSubject: 'google:provider-subject',
            },
          },
        },
        { kind: 'exact_wallet', walletId: walletId('email-wallet') },
      ),
    ).toEqual({
      kind: 'authenticated',
      state: { kind: 'authenticated', walletId: 'email-wallet', authMethod: 'email_otp' },
    });
  });

  test('restores registration-issued Google Email OTP authentication', () => {
    expect(
      authenticationFromValidatedSessionState(
        {
          authenticated: true,
          claims: {
            kind: 'app_session_v1',
            provider: 'google',
            providerSubject: 'google:provider-subject',
            sub: 'google:provider-subject',
            walletId: 'email-wallet',
            authSource: {
              kind: 'oidc_provider',
              providerId: 'google_oidc',
              providerSubject: 'google:provider-subject',
            },
          },
        },
        { kind: 'derive_wallet' },
      ),
    ).toEqual({
      kind: 'authenticated',
      state: { kind: 'authenticated', walletId: 'email-wallet', authMethod: 'email_otp' },
    });
  });

  test('rejects Email OTP authentication whose source does not match its provider claims', () => {
    expect(
      authenticationFromValidatedSessionState(
        {
          authenticated: true,
          claims: {
            kind: 'app_session_v1',
            provider: 'google',
            providerSubject: 'google:provider-subject',
            walletId: 'email-wallet',
            authSource: {
              kind: 'oidc_provider',
              providerId: 'google_oidc',
              providerSubject: 'google:other-subject',
            },
          },
        },
        { kind: 'derive_wallet' },
      ),
    ).toEqual({ kind: 'rejected' });
  });

  test('rejects unauthenticated and wallet-mismatched session state', () => {
    expect(
      authenticationFromValidatedSessionState({ authenticated: false }, { kind: 'derive_wallet' }),
    ).toEqual({ kind: 'rejected' });
    expect(
      authenticationFromValidatedSessionState(
        {
          authenticated: true,
          claims: {
            kind: 'app_session_v1',
            provider: 'passkey',
            sub: 'wallet-a',
            authSource: { kind: 'passkey', credentialIdB64u: 'credential-id' },
          },
        },
        { kind: 'exact_wallet', walletId: walletId('wallet-b') },
      ),
    ).toEqual({ kind: 'uncorrelated' });
  });
});

test.describe('wallet authentication restoration lifecycle', () => {
  test('single-flights concurrent restoration and shares the authenticated result', async () => {
    const targetWalletId = walletId('wallet-concurrent');
    const surface = createRestorationTestSurface();
    const gate = createDeferred<void>();
    let fetchCalls = 0;
    const restoreFetch = installFetch(async function restorationFetch() {
      fetchCalls += 1;
      await gate.promise;
      return authenticatedPasskeyResponse(String(targetWalletId));
    });
    try {
      const first = surface.restoreWalletAuthenticationState(targetWalletId, { kind: 'cookie' });
      const second = surface.restoreWalletAuthenticationState(targetWalletId, { kind: 'cookie' });
      await Promise.resolve();
      expect(fetchCalls).toBe(1);
      gate.resolve(undefined);
      await expect(Promise.all([first, second])).resolves.toEqual([
        {
          kind: 'authenticated',
          walletId: targetWalletId,
          authMethod: 'passkey',
        },
        {
          kind: 'authenticated',
          walletId: targetWalletId,
          authMethod: 'passkey',
        },
      ]);
    } finally {
      restoreFetch();
    }
  });

  test('removes a failed single-flight entry so a transient failure can retry', async () => {
    const targetWalletId = walletId('wallet-retry');
    const surface = createRestorationTestSurface();
    let fetchCalls = 0;
    const restoreFetch = installFetch(async function restorationFetch() {
      fetchCalls += 1;
      if (fetchCalls === 1) throw new Error('temporary transport failure');
      return authenticatedPasskeyResponse(String(targetWalletId));
    });
    try {
      await expect(
        surface.restoreWalletAuthenticationState(targetWalletId, { kind: 'cookie' }),
      ).resolves.toEqual({
        kind: 'signed_out',
      });
      await expect(
        surface.restoreWalletAuthenticationState(targetWalletId, { kind: 'cookie' }),
      ).resolves.toEqual({
        kind: 'authenticated',
        walletId: targetWalletId,
        authMethod: 'passkey',
      });
      expect(fetchCalls).toBe(2);
    } finally {
      restoreFetch();
    }
  });

  test('clears matching wallet authentication on authoritative rejection', async () => {
    const targetWalletId = walletId('wallet-rejected');
    const surface = createRestorationTestSurface({
      kind: 'authenticated',
      walletId: targetWalletId,
      authMethod: 'passkey',
    });
    const restoreFetch = installFetch(async function restorationFetch() {
      return new Response(JSON.stringify({ authenticated: false }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    try {
      await expect(
        surface.restoreWalletAuthenticationState(targetWalletId, { kind: 'cookie' }),
      ).resolves.toEqual({
        kind: 'signed_out',
      });
      expect(surface.readWalletAuthenticationState()).toEqual({ kind: 'signed_out' });
    } finally {
      restoreFetch();
    }
  });

  test('clears rejected passkey authentication when no cached Email OTP session is available', async () => {
    const targetWalletId = walletId('wallet-rejected-without-otp');
    const surface = createRestorationTestSurface({
      initialState: {
        kind: 'authenticated',
        walletId: targetWalletId,
        authMethod: 'passkey',
      },
      resolveAppSessionJwtForWallet: async () => {
        throw new Error('fresh Email OTP verification required');
      },
    });
    const restoreFetch = installFetch(async function restorationFetch() {
      return new Response(JSON.stringify({ authenticated: false }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    });
    try {
      await expect(
        surface.restoreWalletAuthenticationState(targetWalletId, { kind: 'cookie' }),
      ).resolves.toEqual({
        kind: 'signed_out',
      });
      expect(surface.readWalletAuthenticationState()).toEqual({ kind: 'signed_out' });
    } finally {
      restoreFetch();
    }
  });

  test('preserves current wallet authentication when the authority is unavailable', async () => {
    const targetWalletId = walletId('wallet-unavailable');
    const authenticatedState: WalletAuthenticationState = {
      kind: 'authenticated',
      walletId: targetWalletId,
      authMethod: 'passkey',
    };
    const surface = createRestorationTestSurface({ initialState: authenticatedState });
    const restoreFetch = installFetch(async function restorationFetch() {
      throw new Error('temporary transport failure');
    });
    try {
      await expect(
        surface.restoreWalletAuthenticationState(targetWalletId, { kind: 'cookie' }),
      ).resolves.toEqual(authenticatedState);
      expect(surface.readWalletAuthenticationState()).toEqual(authenticatedState);
    } finally {
      restoreFetch();
    }
  });

  test('falls back from an uncorrelated host-selected JWT to the exact persisted Email OTP authority', async () => {
    const targetWalletId = walletId('wallet-host-session-otp');
    const providerSubject = 'google:persisted-source';
    const hostedSession = await seedHostedOidcSession({
      walletId: String(targetWalletId),
      providerSubject,
    });
    const hostSelectedJwt = hostedSession.appSessionJwt;
    const persistedEmailOtpJwt = appSessionJwtWithPayload(
      emailOtpAppSessionClaims(String(targetWalletId), providerSubject),
    );
    let cachedJwtResolutions = 0;
    const surface = createRestorationTestSurface({
      resolveAppSessionJwtForWallet: async () => {
        cachedJwtResolutions += 1;
        return persistedEmailOtpJwt;
      },
    });
    const requestLog: Array<{ url: string; authorization: string | null }> = [];
    const restoreFetch = installFetch(async function restorationFetch(input, init) {
      const url = String(input);
      const authorization = new Headers(init?.headers).get('authorization');
      requestLog.push({ url, authorization });
      if (authorization === `Bearer ${hostSelectedJwt}`) {
        return uncorrelatedSessionResponse('google:host-selected-source');
      }
      if (authorization === `Bearer ${persistedEmailOtpJwt}`) {
        return authenticatedEmailOtpResponse(String(targetWalletId), providerSubject);
      }
      throw new Error(`unexpected restoration authorization: ${authorization || 'cookie'}`);
    });
    try {
      await expect(
        surface.restoreWalletAuthenticationStateFromHostSession(targetWalletId),
      ).resolves.toEqual({
        kind: 'authenticated',
        walletId: targetWalletId,
        authMethod: 'email_otp',
      });
      expect(cachedJwtResolutions).toBe(1);
      expect(requestLog).toEqual([
        {
          url: 'https://relay.local/session/state',
          authorization: `Bearer ${hostSelectedJwt}`,
        },
        {
          url: 'https://relay.local/session/state',
          authorization: `Bearer ${persistedEmailOtpJwt}`,
        },
      ]);
      expect(requestLog.every(({ url }) => url.endsWith('/session/state'))).toBe(true);
      expect(surface.readWalletAuthenticationState()).toEqual({
        kind: 'authenticated',
        walletId: targetWalletId,
        authMethod: 'email_otp',
      });
    } finally {
      restoreFetch();
      hostedSession.cleanup();
    }
  });

  test('rejects a cached Email OTP binding for a different host OIDC subject before a second authority read', async () => {
    const targetWalletId = walletId('wallet-host-subject-mismatch');
    const hostedSession = await seedHostedOidcSession({
      walletId: String(targetWalletId),
      providerSubject: 'google:host-source-a',
    });
    const cachedEmailOtpJwt = appSessionJwtWithPayload(
      emailOtpAppSessionClaims(String(targetWalletId), 'google:cached-source-b'),
    );
    let cachedJwtResolutions = 0;
    const surface = createRestorationTestSurface({
      resolveAppSessionJwtForWallet: async () => {
        cachedJwtResolutions += 1;
        return cachedEmailOtpJwt;
      },
    });
    const requestLog: Array<{ url: string; authorization: string | null }> = [];
    const restoreFetch = installFetch(async function restorationFetch(input, init) {
      requestLog.push({
        url: String(input),
        authorization: new Headers(init?.headers).get('authorization'),
      });
      return uncorrelatedSessionResponse('google:host-source-a');
    });
    try {
      await expect(
        surface.restoreWalletAuthenticationStateFromHostSession(targetWalletId),
      ).resolves.toEqual({ kind: 'signed_out' });
      expect(cachedJwtResolutions).toBe(1);
      expect(requestLog).toEqual([
        {
          url: 'https://relay.local/session/state',
          authorization: `Bearer ${hostedSession.appSessionJwt}`,
        },
      ]);
    } finally {
      restoreFetch();
      hostedSession.cleanup();
    }
  });

  test('rejects direct Email OTP authority for a different host OIDC subject without consulting cached OTP', async () => {
    const targetWalletId = walletId('wallet-host-direct-subject-mismatch');
    const hostedSession = await seedHostedOidcSession({
      walletId: String(targetWalletId),
      providerSubject: 'google:host-source-a',
    });
    let cachedJwtResolutions = 0;
    const surface = createRestorationTestSurface({
      resolveAppSessionJwtForWallet: async () => {
        cachedJwtResolutions += 1;
        return appSessionJwtWithPayload(
          emailOtpAppSessionClaims(String(targetWalletId), 'google:cached-source-b'),
        );
      },
    });
    const requestLog: Array<{ url: string; authorization: string | null }> = [];
    const restoreFetch = installFetch(async function restorationFetch(input, init) {
      requestLog.push({
        url: String(input),
        authorization: new Headers(init?.headers).get('authorization'),
      });
      return authenticatedEmailOtpResponse(String(targetWalletId), 'google:direct-source-b');
    });
    try {
      await expect(
        surface.restoreWalletAuthenticationStateFromHostSession(targetWalletId),
      ).resolves.toEqual({ kind: 'signed_out' });
      expect(cachedJwtResolutions).toBe(0);
      expect(requestLog).toEqual([
        {
          url: 'https://relay.local/session/state',
          authorization: `Bearer ${hostedSession.appSessionJwt}`,
        },
      ]);
    } finally {
      restoreFetch();
      hostedSession.cleanup();
    }
  });

  test('does not fall back to a cached Email OTP JWT after a caller-supplied JWT is uncorrelated', async () => {
    const targetWalletId = walletId('wallet-caller-session-rejected');
    const callerJwt = appSessionJwtWithPayload({
      kind: 'app_session_v1',
      provider: 'passkey',
      sub: String(targetWalletId),
      authSource: { kind: 'passkey', credentialIdB64u: 'caller-credential' },
    });
    const cachedEmailOtpJwt = appSessionJwtWithPayload(
      emailOtpAppSessionClaims(String(targetWalletId), 'google:cached-source'),
    );
    let cachedJwtResolutions = 0;
    const surface = createRestorationTestSurface({
      resolveAppSessionJwtForWallet: async () => {
        cachedJwtResolutions += 1;
        return cachedEmailOtpJwt;
      },
    });
    const requestLog: Array<{ url: string; authorization: string | null }> = [];
    const restoreFetch = installFetch(async function restorationFetch(input, init) {
      requestLog.push({
        url: String(input),
        authorization: new Headers(init?.headers).get('authorization'),
      });
      return authenticatedPasskeyResponse('wallet-other');
    });
    try {
      await expect(
        surface.restoreWalletAuthenticationState(targetWalletId, {
          kind: 'caller_app_session_jwt',
          appSessionJwt: callerJwt,
        }),
      ).resolves.toEqual({ kind: 'signed_out' });
      expect(cachedJwtResolutions).toBe(0);
      expect(requestLog).toEqual([
        {
          url: 'https://relay.local/session/state',
          authorization: `Bearer ${callerJwt}`,
        },
      ]);
      expect(surface.readWalletAuthenticationState()).toEqual({ kind: 'signed_out' });
    } finally {
      restoreFetch();
    }
  });

  test('fails closed when an explicit app-session JWT is invalid', async () => {
    const targetWalletId = walletId('wallet-invalid-explicit-jwt');
    const surface = createRestorationTestSurface({
      initialState: {
        kind: 'authenticated',
        walletId: targetWalletId,
        authMethod: 'passkey',
      },
    });
    let fetchCalls = 0;
    const restoreFetch = installFetch(async function restorationFetch() {
      fetchCalls += 1;
      return authenticatedPasskeyResponse(String(targetWalletId));
    });
    try {
      await expect(
        surface.restoreWalletAuthenticationState(targetWalletId, {
          kind: 'caller_app_session_jwt',
          appSessionJwt: 'invalid-app-session-jwt',
        }),
      ).resolves.toEqual({ kind: 'signed_out' });
      expect(fetchCalls).toBe(0);
      expect(surface.readWalletAuthenticationState()).toEqual({ kind: 'signed_out' });
    } finally {
      restoreFetch();
    }
  });
});
