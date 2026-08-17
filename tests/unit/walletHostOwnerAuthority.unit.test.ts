import { expect, test } from '@playwright/test';
import { parseWalletId } from '@shared/utils/domainIds';
import { parseLinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { createWalletHostOwnerAuthoritiesV1 } from '@/SeamsWeb/operations/devices/walletHostOwnerAuthority';
import type { LinkedDeviceOwnerCustodyHoldV1 } from '@/SeamsWeb/operations/devices/deviceLinkingOwnerCustody';
import { buildR103OwnerEnrollmentCeremonyV1 } from './helpers/deviceLinkContracts.fixtures';

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

test('evicts released owner custody holds before a ceremony retry', async () => {
  let startCalls = 0;
  const sessionId = parseLinkDeviceSessionId('link-session:retry');
  if (!sessionId.ok) throw new Error(sessionId.error.message);
  const hold = (): LinkedDeviceOwnerCustodyHoldV1 => ({
    sealOnceV1: async () => undefined,
    discardV1: () => undefined,
  });
  const authorities = createWalletHostOwnerAuthoritiesV1({
    http: {
      kind: 'http_transport',
      request: async () => ({ status: 200, body: {} }),
    },
    relayerUrl: 'https://relay.example.test',
    startOwnerEnrollmentCeremonyV1: async () => {
      startCalls += 1;
      return { ceremony: buildR103OwnerEnrollmentCeremonyV1(), custodyHold: hold() };
    },
    walletSessions: {
      read: async () => ({ kind: 'missing' }),
      readActiveForWallet: async () => ({ kind: 'missing' }),
    },
    readWalletAuthenticationState: () => ({
      kind: 'authenticated',
      walletId,
      authMethod: 'passkey',
    }),
    hasLinkedDeviceSigningSession: () => false,
    readOwnerSourceLaneHintsV1: async () => {
      throw new Error('owner lane hints are not exercised by this test');
    },
  });
  const request = {
    linkSessionId: sessionId.value,
    walletId,
    requestedAtMs: Date.now(),
  } as const;

  const first = await authorities.ownerAuthorization.startOwnerEnrollmentCeremonyV1(request);
  first.custodyHold.discardV1();
  const second = await authorities.ownerAuthorization.startOwnerEnrollmentCeremonyV1(request);

  expect(startCalls).toBe(2);
  expect(second.custodyHold).not.toBe(first.custodyHold);
});
