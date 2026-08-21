import { expect, test } from '@playwright/test';
import { parseRecoveryCodeReservationId } from '../../packages/shared-ts/src/wallet-recovery/recoveryCodeReservation';
import { deriveRecoveryCodeLocatorV1FromBytes } from '../../packages/shared-ts/src/wallet-recovery/recoveryCodeLocator';
import { createD1PasskeyCustodyRouteService } from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyRouteService';

test('recovery refuses when more than one owner auth method is active', async () => {
  const locator = await deriveRecoveryCodeLocatorV1FromBytes(new Uint8Array(20));
  const service = createD1PasskeyCustodyRouteService({
    passkeyCustodyEnvelopes: {} as never,
    walletCustodyCommits: {
      readRecoveryCodeLocator: async () => ({
        locatorB64u: locator,
        walletId: 'alice.testnet' as never,
        recoveryKeyId: 'wallet-rkid-v1-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' as never,
      }),
      listWalletAuthMethods: async () =>
        [
          {
            version: 'wallet_auth_method_v1',
            kind: 'passkey',
            status: 'active',
            walletId: 'alice.testnet',
            rpId: 'example.localhost',
            credentialIdB64u: 'source-credential',
            credentialPublicKeyB64u: 'source-public-key',
            counter: 0,
            createdAtMs: 1,
            updatedAtMs: 1,
          },
          {
            version: 'wallet_auth_method_v1',
            kind: 'passkey',
            status: 'active',
            walletId: 'alice.testnet',
            rpId: 'other.example.localhost',
            credentialIdB64u: 'other-credential',
            credentialPublicKeyB64u: 'other-public-key',
            counter: 0,
            createdAtMs: 2,
            updatedAtMs: 2,
          },
        ] as never,
    } as never,
    walletStore: {} as never,
    webAuthnStore: {} as never,
    logger: {} as never,
  });

  const result = await service.prepareRecovery({
    rpId: 'example.localhost',
    origin: 'https://example.localhost',
    recoveryCodeBytes: new Uint8Array(20),
    reservationId: parseRecoveryCodeReservationId('recovery-operation-1'),
  });

  expect(result).toEqual({ kind: 'refused', reason: 'that recovery code cannot be used' });
});
