import { expect, test } from '@playwright/test';
import { parseWalletId } from '@shared/utils/domainIds';
import { createWalletHostOwnerAuthoritiesV1 } from '@/SeamsWeb/operations/devices/walletHostOwnerAuthority';

const walletId = parseWalletId('wallet:r103').value;

test('blocks linked-device sessions before owner management session lookup', async () => {
  const authorities = createWalletHostOwnerAuthoritiesV1({
    http: {
      kind: 'http_transport',
      request: async () => {
        throw new Error('linked-device management must stop before HTTP');
      },
    },
    relayerUrl: 'https://relay.example.test',
    startOwnerEnrollmentCeremonyV1: async () => {
      throw new Error('owner enrollment ceremony is not exercised by this test');
    },
    walletSessions: {
      read: async () => {
        throw new Error('linked-device management must stop before session lookup');
      },
      readActiveForWallet: async () => {
        throw new Error('linked-device management must stop before session lookup');
      },
    },
    readWalletAuthenticationState: () => ({
      kind: 'authenticated',
      walletId,
      authMethod: 'passkey',
    }),
    hasLinkedDeviceSigningSession: () => true,
    readOwnerSourceLaneHintsV1: async () => {
      throw new Error('linked-device management must stop before source lookup');
    },
  });

  await expect(
    authorities.managementRequest.request({
      walletId,
      method: 'GET',
      canonicalPath: '/wallet/device-linking/v1/devices',
    }),
  ).rejects.toThrow('Signing-only linked-device sessions cannot manage devices');
});
