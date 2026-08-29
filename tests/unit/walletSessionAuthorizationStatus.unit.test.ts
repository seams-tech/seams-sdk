import { expect, test } from '@playwright/test';
import { createRelayerReusableWalletSessionStatusPort } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking/parsers';

function operationCredential(token: string, walletSessionId = 'wallet-session-1') {
  return parseWalletSessionOperationCredentialV1({
    kind: 'opaque_wallet_session_operation_credential_v1',
    token,
    walletSessionId,
  });
}

test.describe('Wallet Session authorization status client', () => {
  test('uses the exact Wallet Session operation credential as Bearer authorization', async () => {
    const walletSessionToken = `wst_${'a'.repeat(43)}`;
    let requestInit: RequestInit | undefined;
    const statusPort = createRelayerReusableWalletSessionStatusPort({
      relayerUrl: 'https://relayer.example.test',
      operationCredential: operationCredential(walletSessionToken),
      fetchImpl: async (_input, init) => {
        requestInit = init;
        return new Response(
          JSON.stringify({
            ok: true,
            status: 'active',
            walletSessionId: 'wallet-session-1',
            quotaId: 'wallet-quota-1',
            remainingUses: 2,
            expiresAtMs: Date.now() + 60_000,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      },
    });

    await expect(
      statusPort.read({ walletSessionId: 'wallet-session-1', quotaId: 'wallet-quota-1' }),
    ).resolves.toMatchObject({ status: 'active', remainingUses: 2 });

    expect(requestInit?.credentials).toBe('omit');
    expect(new Headers(requestInit?.headers).get('authorization')).toBe(
      `Bearer ${walletSessionToken}`,
    );
    expect(new Headers(requestInit?.headers).get('cookie')).toBeNull();
  });

  test('shares only concurrent reads for the exact authorization and status identity', async () => {
    const walletSessionToken = `wst_${'b'.repeat(43)}`;
    let requestCount = 0;
    let releaseResponse!: () => void;
    const responseGate = new Promise<void>((resolve) => {
      releaseResponse = resolve;
    });
    const fetchImpl: typeof fetch = async () => {
      requestCount += 1;
      await responseGate;
      return new Response(
        JSON.stringify({
          ok: true,
          status: 'active',
          walletSessionId: 'wallet-session-1',
          quotaId: 'wallet-quota-1',
          remainingUses: 2,
          expiresAtMs: Date.now() + 60_000,
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    };
    const firstPort = createRelayerReusableWalletSessionStatusPort({
      relayerUrl: 'https://relayer.example.test',
      operationCredential: operationCredential(walletSessionToken),
      fetchImpl,
    });
    const secondPort = createRelayerReusableWalletSessionStatusPort({
      relayerUrl: 'https://relayer.example.test',
      operationCredential: operationCredential(walletSessionToken),
      fetchImpl,
    });
    const identity = {
      walletSessionId: 'wallet-session-1',
      quotaId: 'wallet-quota-1',
    } as const;

    const firstRead = firstPort.read(identity);
    const secondRead = secondPort.read(identity);
    expect(requestCount).toBe(1);
    releaseResponse();
    await expect(Promise.all([firstRead, secondRead])).resolves.toHaveLength(2);

    await firstPort.read(identity);
    expect(requestCount).toBe(2);
  });
});
