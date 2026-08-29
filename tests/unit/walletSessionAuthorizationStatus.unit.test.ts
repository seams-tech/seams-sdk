import { expect, test } from '@playwright/test';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { createRelayerReusableWalletSessionStatusPort } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking/parsers';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

function operationCredential(token: string, walletSessionId = 'wallet-session-1') {
  return parseWalletSessionOperationCredentialV1({
    kind: 'opaque_wallet_session_operation_credential_v1',
    token,
    walletSessionId,
  });
}

/**
 * The status route publishes the server's digest-free authorization projection
 * alongside the quota, so a stub response must carry a real one.
 */
async function activeStatusResponseBody(): Promise<{
  readonly body: Record<string, unknown>;
  readonly identity: { readonly walletSessionId: string; readonly quotaId: string };
}> {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'status-client',
    permissions: buildFullOwnerPermissionsV1(),
    provenance: 'wallet_registration',
    expiresAtMs: Date.now() + 60_000,
  });
  const identity = {
    walletSessionId: String(fixture.issuedSession.session.walletSessionId),
    quotaId: String(fixture.activeWalletSession.quotaId),
  };
  return {
    identity,
    body: {
      ok: true,
      status: 'active',
      ...identity,
      remainingUses: 2,
      expiresAtMs: fixture.activeWalletSession.expiresAtMs,
      quotaLifecycle: 'active',
      authorization: fixture.activeWalletSession,
    },
  };
}

test.describe('Wallet Session authorization status client', () => {
  test('uses the exact Wallet Session operation credential as Bearer authorization', async () => {
    const walletSessionToken = `wst_${'a'.repeat(43)}`;
    const { body, identity } = await activeStatusResponseBody();
    let requestInit: RequestInit | undefined;
    const statusPort = createRelayerReusableWalletSessionStatusPort({
      relayerUrl: 'https://relayer.example.test',
      operationCredential: operationCredential(walletSessionToken, identity.walletSessionId),
      fetchImpl: async (_input, init) => {
        requestInit = init;
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    });

    await expect(statusPort.read(identity)).resolves.toMatchObject({
      status: 'active',
      remainingUses: 2,
      authorization: { kind: 'active_wallet_session_v1' },
    });

    expect(requestInit?.credentials).toBe('omit');
    expect(new Headers(requestInit?.headers).get('authorization')).toBe(
      `Bearer ${walletSessionToken}`,
    );
    expect(new Headers(requestInit?.headers).get('cookie')).toBeNull();
  });

  test('shares only concurrent reads for the exact authorization and status identity', async () => {
    const walletSessionToken = `wst_${'b'.repeat(43)}`;
    const { body, identity } = await activeStatusResponseBody();
    let requestCount = 0;
    let releaseResponse!: () => void;
    const responseGate = new Promise<void>((resolve) => {
      releaseResponse = resolve;
    });
    const fetchImpl: typeof fetch = async () => {
      requestCount += 1;
      await responseGate;
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const firstPort = createRelayerReusableWalletSessionStatusPort({
      relayerUrl: 'https://relayer.example.test',
      operationCredential: operationCredential(walletSessionToken, identity.walletSessionId),
      fetchImpl,
    });
    const secondPort = createRelayerReusableWalletSessionStatusPort({
      relayerUrl: 'https://relayer.example.test',
      operationCredential: operationCredential(walletSessionToken, identity.walletSessionId),
      fetchImpl,
    });

    const firstRead = firstPort.read(identity);
    const secondRead = secondPort.read(identity);
    expect(requestCount).toBe(1);
    releaseResponse();
    await expect(Promise.all([firstRead, secondRead])).resolves.toHaveLength(2);

    await firstPort.read(identity);
    expect(requestCount).toBe(2);
  });
});
