import { expect, test } from '@playwright/test';
import {
  authenticationFromValidatedSessionState,
  BrowserSigningSurface,
} from '@/SeamsWeb/signingSurface/BrowserSigningSurface';
import type { WalletAuthenticationState } from '@/core/types/seams';
import { parseWalletId } from '@shared/utils/domainIds';

function walletId(value: string) {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

type RestorationTestSurface = BrowserSigningSurface;

function createRestorationTestSurface(
  initialState: WalletAuthenticationState = { kind: 'signed_out' },
): RestorationTestSurface {
  const surface = Object.create(BrowserSigningSurface.prototype) as RestorationTestSurface;
  const fields = surface as unknown as Record<string, unknown>;
  fields.walletAuthenticationState = initialState;
  fields.walletAuthenticationRestoreInFlight = new Map();
  fields.walletAuthenticationRestorationBlocked = false;
  fields.walletAuthenticationRestoreGeneration = 0;
  fields.seamsWebConfigs = { network: { relayer: { url: 'https://relay.local' } } };
  fields.userPreferencesManager = {
    initFromIndexedDB: async () => undefined,
    getCurrentWalletId: () => undefined,
  };
  fields.emailOtpSessions = {
    resolveAppSessionJwtForWallet: async () => '',
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
          },
        },
        { kind: 'derive_wallet' },
      ),
    ).toEqual({
      kind: 'authenticated',
      state: { kind: 'authenticated', walletId: 'email-wallet', authMethod: 'email_otp' },
    });
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
      const first = surface.restoreWalletAuthenticationState(targetWalletId);
      const second = surface.restoreWalletAuthenticationState(targetWalletId);
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
      await expect(surface.restoreWalletAuthenticationState(targetWalletId)).resolves.toEqual({
        kind: 'signed_out',
      });
      await expect(surface.restoreWalletAuthenticationState(targetWalletId)).resolves.toEqual({
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
      await expect(surface.restoreWalletAuthenticationState(targetWalletId)).resolves.toEqual({
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
      kind: 'authenticated',
      walletId: targetWalletId,
      authMethod: 'passkey',
    });
    const fields = surface as unknown as Record<string, unknown>;
    fields.emailOtpSessions = {
      resolveAppSessionJwtForWallet: async () => {
        throw new Error('fresh Email OTP verification required');
      },
    };
    const restoreFetch = installFetch(async function restorationFetch() {
      return new Response(JSON.stringify({ authenticated: false }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      });
    });
    try {
      await expect(surface.restoreWalletAuthenticationState(targetWalletId)).resolves.toEqual({
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
    const surface = createRestorationTestSurface(authenticatedState);
    const restoreFetch = installFetch(async function restorationFetch() {
      throw new Error('temporary transport failure');
    });
    try {
      await expect(surface.restoreWalletAuthenticationState(targetWalletId)).resolves.toEqual(
        authenticatedState,
      );
      expect(surface.readWalletAuthenticationState()).toEqual(authenticatedState);
    } finally {
      restoreFetch();
    }
  });

  test('fails closed when an explicit app-session JWT is invalid', async () => {
    const targetWalletId = walletId('wallet-invalid-explicit-jwt');
    const surface = createRestorationTestSurface({
      kind: 'authenticated',
      walletId: targetWalletId,
      authMethod: 'passkey',
    });
    let fetchCalls = 0;
    const restoreFetch = installFetch(async function restorationFetch() {
      fetchCalls += 1;
      return authenticatedPasskeyResponse(String(targetWalletId));
    });
    try {
      await expect(
        surface.restoreWalletAuthenticationState(targetWalletId, 'invalid-app-session-jwt'),
      ).resolves.toEqual({ kind: 'signed_out' });
      expect(fetchCalls).toBe(0);
      expect(surface.readWalletAuthenticationState()).toEqual({ kind: 'signed_out' });
    } finally {
      restoreFetch();
    }
  });
});
