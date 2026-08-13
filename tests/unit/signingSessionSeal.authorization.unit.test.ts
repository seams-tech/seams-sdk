import { expect, test } from '@playwright/test';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { SessionParseResult } from '../../packages/sdk-server-ts/src/core/sessionValidation';
import { signRouterAbEd25519WalletSessionJwt } from '../../packages/sdk-server-ts/src/router/auth/commonRouterUtils';
import {
  type SessionAdapter,
  type SessionClaims,
} from '../../packages/sdk-server-ts/src/router/framework/routerApi';
import { createSigningSessionSealRoutesOptions } from '../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/routesOptions';
import type { SigningSessionSealCipherAdapter } from '../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/signingSessionSeal.types';

const NOW_MS = 2_000_000_000_000;
const WALLET_ID = 'seal-authorization.testnet';
const THRESHOLD_SESSION_ID = 'threshold-session-seal-authorization';
const SIGNING_WORKER_ID = 'signing-worker-seal-authorization';

class WalletSessionClaimsFixture implements SessionAdapter {
  private claims: SessionClaims | null = null;

  async signJwt(_subject: string, claims: SessionClaims): Promise<string> {
    this.claims = claims;
    return 'fixture.wallet.session';
  }

  async parse(): Promise<SessionParseResult<SessionClaims>> {
    if (!this.claims) return { ok: false, reason: 'missing' };
    return { ok: true, claims: this.claims };
  }

  buildSetCookie(): string {
    return '';
  }

  buildClearCookie(): string {
    return '';
  }

  async refresh(): Promise<{ ok: false }> {
    return { ok: false };
  }
}

function successfulCipher(): SigningSessionSealCipherAdapter {
  return {
    run: async (input) => ({
      ok: true,
      ciphertext: `sealed:${input.ciphertext}`,
      keyVersion: 'seal-key-v1',
    }),
  };
}

async function walletSessionFixture(
  thresholdExpiresAtMs: number,
): Promise<WalletSessionClaimsFixture> {
  const session = new WalletSessionClaimsFixture();
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: WALLET_ID,
    rpId: 'wallet.example.test',
    credentialIdB64u: 'credential-seal-authorization',
  });
  const signed = await signRouterAbEd25519WalletSessionJwt({
    session,
    userId: WALLET_ID,
    relayerKeyId: SIGNING_WORKER_ID,
    authority,
    sessionInfo: {
      sessionKind: 'jwt',
      authorizationKind: 'owner_wallet_session',
      walletId: WALLET_ID,
      nearAccountId: WALLET_ID,
      nearEd25519SigningKeyId: 'near-ed25519-signing-key-seal-authorization',
      thresholdSessionId: THRESHOLD_SESSION_ID,
      authorizationId: 'authorization-grant-seal-authorization',
      walletSessionId: 'wallet-session-seal-authorization',
      quotaId: 'quota-seal-authorization',
      expiresAtMs: thresholdExpiresAtMs,
      participantIds: [1, 2],
      runtimePolicyScope: {
        orgId: 'org-seal-authorization',
        projectId: 'project-seal-authorization',
        envId: 'env-seal-authorization',
        signingRootVersion: 'root-version-seal-authorization',
      },
      routerAbNormalSigning: {
        kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
        signingWorkerId: SIGNING_WORKER_ID,
      },
    },
    fallbackParticipantIds: [1, 2],
    requireJwtErrorMessage: 'Wallet Session JWT is required',
    invalidPayloadErrorMessage: 'Wallet Session claims fixture is invalid',
  });
  if (!signed.ok) throw new Error(signed.message);
  return session;
}

async function authorize(input: { thresholdExpiresAtMs: number; thresholdSessionId?: string }) {
  const session = await walletSessionFixture(input.thresholdExpiresAtMs);
  const options = createSigningSessionSealRoutesOptions({
    cipher: successfulCipher(),
    nowMs: () => NOW_MS,
  });
  if (!options.authorize) throw new Error('default signing-session authorization is required');
  return {
    authorization: await options.authorize({
      headers: {},
      session,
      thresholdSessionId: input.thresholdSessionId || THRESHOLD_SESSION_ID,
    }),
    service: options.service,
  };
}

test('authorizes and seals directly from authoritative Wallet Session JWT claims', async () => {
  const { authorization, service } = await authorize({
    thresholdExpiresAtMs: NOW_MS + 60_000,
  });
  expect(authorization.ok).toBe(true);
  if (!authorization.ok) throw new Error(authorization.message);

  await expect(
    service.applyServerSeal(
      {
        thresholdSessionId: THRESHOLD_SESSION_ID,
        ciphertext: 'ciphertext',
      },
      authorization.auth,
    ),
  ).resolves.toEqual({
    ok: true,
    ciphertext: 'sealed:ciphertext',
    keyVersion: 'seal-key-v1',
    expiresAtMs: NOW_MS + 60_000,
  });
});

test('rejects an expired threshold session from the signed claims', async () => {
  const { authorization } = await authorize({
    thresholdExpiresAtMs: NOW_MS - 1,
  });
  expect(authorization).toEqual({
    ok: false,
    code: 'wallet_session_expired',
    message: 'Wallet Session expired',
    status: 401,
  });
});

test('rejects a threshold-session scope mismatch from the signed claims', async () => {
  const { authorization } = await authorize({
    thresholdExpiresAtMs: NOW_MS + 60_000,
    thresholdSessionId: 'different-threshold-session',
  });
  expect(authorization).toEqual({
    ok: false,
    code: 'wallet_session_scope_mismatch',
    message: 'Wallet Session scope does not match the request',
    status: 403,
  });
});
