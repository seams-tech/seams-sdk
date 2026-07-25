import { expect, test } from '@playwright/test';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { SessionParseResult } from '../../packages/sdk-server-ts/src/core/sessionValidation';
import { signRouterAbEd25519WalletSessionJwt } from '../../packages/sdk-server-ts/src/router/commonRouterUtils';
import {
  type SessionAdapter,
  type SessionClaims,
} from '../../packages/sdk-server-ts/src/router/routerApi';
import { createSigningSessionSealRoutesOptions } from '../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/routesOptions';
import type {
  SigningSessionSealCipherAdapter,
  SigningSessionSealThresholdSessionPolicy,
} from '../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/signingSessionSeal.types';

const NOW_MS = 2_000_000_000_000;
const WALLET_ID = 'seal-authorization.testnet';
const THRESHOLD_SESSION_ID = 'threshold-session-seal-authorization';
const SIGNING_GRANT_ID = 'signing-grant-seal-authorization';
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

function missingThresholdSessionPolicy(
  unavailable: boolean,
): SigningSessionSealThresholdSessionPolicy {
  return {
    getThresholdSession: async () => null,
    getThresholdSessionStatuses: async () => {
      if (unavailable) throw new Error('threshold session store unavailable');
      return [];
    },
  };
}

function unusedCipher(): SigningSessionSealCipherAdapter {
  return {
    run: async () => {
      throw new Error('cipher is outside the authorization test boundary');
    },
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
      walletId: WALLET_ID,
      nearAccountId: WALLET_ID,
      nearEd25519SigningKeyId: 'near-ed25519-signing-key-seal-authorization',
      thresholdSessionId: THRESHOLD_SESSION_ID,
      signingGrantId: SIGNING_GRANT_ID,
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

async function authorizeMissingThresholdSession(input: {
  thresholdExpiresAtMs: number;
  unavailable: boolean;
}) {
  const session = await walletSessionFixture(input.thresholdExpiresAtMs);
  const options = createSigningSessionSealRoutesOptions({
    sessionPolicy: missingThresholdSessionPolicy(input.unavailable),
    cipher: unusedCipher(),
    nowMs: () => NOW_MS,
  });
  if (!options.authorize) throw new Error('default signing-session authorization is required');
  return await options.authorize({
    headers: {},
    session,
    thresholdSessionId: THRESHOLD_SESSION_ID,
  });
}

test('signing-session seal authorization preserves a missing Wallet Session failure', async () => {
  await expect(
    authorizeMissingThresholdSession({
      thresholdExpiresAtMs: NOW_MS + 60_000,
      unavailable: false,
    }),
  ).resolves.toEqual({
    ok: false,
    code: 'wallet_session_missing',
    message: 'Wallet Session is missing',
    status: 401,
  });
});

test('signing-session seal authorization distinguishes expiry from missing state', async () => {
  await expect(
    authorizeMissingThresholdSession({
      thresholdExpiresAtMs: NOW_MS - 1,
      unavailable: false,
    }),
  ).resolves.toEqual({
    ok: false,
    code: 'wallet_session_expired',
    message: 'Wallet Session expired',
    status: 401,
  });
});

test('signing-session seal authorization preserves store unavailability', async () => {
  await expect(
    authorizeMissingThresholdSession({
      thresholdExpiresAtMs: NOW_MS + 60_000,
      unavailable: true,
    }),
  ).resolves.toEqual({
    ok: false,
    code: 'wallet_session_unavailable',
    message: 'Wallet Session status is unavailable',
    status: 503,
  });
});
