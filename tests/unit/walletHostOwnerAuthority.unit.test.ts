import { expect, test } from '@playwright/test';
import { parseWalletId } from '@shared/utils/domainIds';
import { parseLinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { createWalletHostOwnerAuthoritiesV1 } from '@/SeamsWeb/operations/devices/walletHostOwnerAuthority';
import {
  selectWalletHostOwnerSourceLaneCandidatesV1,
} from '@/SeamsWeb/signingSurface/BrowserSigningSurface';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import {
  buildR103DeviceLinkFixture,
  buildR103OwnerEnrollmentCeremonyV1,
} from './helpers/deviceLinkContracts.fixtures';
import { buildUnlockedCustodyCapabilityFixtureV1 } from './helpers/linkedDeviceCustodyTransfer.fixtures';
import {
  authorizedPasskeyEd25519AvailableLane,
  availableEd25519Inventory,
  availableLaneEd25519Authorization,
} from './helpers/availableSigningLanes.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

const walletId = parseWalletId('wallet:r103').value;

/**
 * R103 zero-prompt handoff: linking on Device 1 either proceeds silently from
 * the unlocked state or fails closed with the exact `wallet_unlock_required`
 * result. These tests own the fail-closed half — every missing-precondition
 * arm must stop before HTTP, and therefore before any claim, approval,
 * credential, recipient package, or prompt could exist.
 */

type AuthorityOverrides = Partial<Parameters<typeof createWalletHostOwnerAuthoritiesV1>[0]>;

function stopBeforeHttp(overrides: AuthorityOverrides = {}) {
  return createWalletHostOwnerAuthoritiesV1({
    http: {
      kind: 'http_transport',
      request: async () => {
        throw new Error('device linking must stop before HTTP');
      },
    },
    relayerUrl: 'https://relay.example.test',
    startOwnerEnrollmentCeremonyV1: async () => {
      throw new Error('owner enrollment ceremony is not exercised by this test');
    },
    walletSessions: {
      read: async () => ({ kind: 'missing' as const }),
      readActiveForWallet: async () => ({ kind: 'missing' as const }),
    },
    readWalletAuthenticationState: () => ({
      kind: 'authenticated',
      walletId,
      authMethod: 'passkey',
    }),
    readOwnerSourceLaneHintsV1: async () => {
      throw new Error('owner lane hints are not exercised by this test');
    },
    readUnlockedCustodyCapabilityV1: () => undefined,
    ...overrides,
  });
}

async function expectWalletUnlockRequired(authorities: ReturnType<typeof stopBeforeHttp>) {
  const payload = buildR103DeviceLinkFixture().payload;
  let failure: unknown;
  try {
    await authorities.ownerAuthorization.authenticateOwnerForLinkingV1({
      payload,
      requestedAtMs: Date.now(),
    });
  } catch (error: unknown) {
    failure = error;
  }
  expect(failure).toBeInstanceOf(DeviceLinkingError);
  const linkingError = failure as DeviceLinkingError;
  // The exact result, by code and by message: consumers branch on the code,
  // and the message is the machine-readable result name, not prose.
  expect(linkingError.code).toBe(DeviceLinkingErrorCode.WALLET_UNLOCK_REQUIRED);
  expect(linkingError.message).toBe('wallet_unlock_required');
  expect(linkingError.phase).toBe('authorization');
}

test('a locked wallet fails with wallet_unlock_required before any lookup', async () => {
  await expectWalletUnlockRequired(
    stopBeforeHttp({
      readWalletAuthenticationState: () => ({ kind: 'signed_out' }),
      walletSessions: {
        read: async () => {
          throw new Error('device linking must stop before session lookup');
        },
        readActiveForWallet: async () => {
          throw new Error('device linking must stop before session lookup');
        },
      },
    }),
  );
});

test('a missing owner Wallet Session fails with wallet_unlock_required', async () => {
  await expectWalletUnlockRequired(
    stopBeforeHttp({
      readUnlockedCustodyCapabilityV1: () => {
        throw new Error('the session gate precedes the capability read');
      },
    }),
  );
});

test('an expired owner Wallet Session fails with wallet_unlock_required', async () => {
  const projection = availableLaneEd25519Authorization({
    walletId: String(walletId),
    identitySeed: 'expired-session',
    authMethod: 'passkey',
    expiresAtMs: Date.now() - 1,
  });
  await expectWalletUnlockRequired(
    stopBeforeHttp({
      walletSessions: {
        read: async () => ({ kind: 'missing' as const }),
        readActiveForWallet: async () => ({ kind: 'found' as const, projection }),
      },
      readWalletAuthenticationState: () => ({
        kind: 'authenticated',
        walletId: projection.walletId,
        authMethod: 'passkey',
      }),
    }),
  );
});

test('a missing, mismatched, or expired capability fails with wallet_unlock_required', async () => {
  const projection = availableLaneEd25519Authorization({
    walletId: String(walletId),
    identitySeed: 'capability-preflight',
    authMethod: 'passkey',
  });
  const aligned = () =>
    buildUnlockedCustodyCapabilityFixtureV1({
      walletId: String(projection.walletId),
      walletSessionId: String(projection.walletSessionId),
      expiresAtMs: projection.expiresAtMs,
    });
  const arms: Array<[string, AuthorityOverrides['readUnlockedCustodyCapabilityV1']]> = [
    ['absent', () => undefined],
    ['another wallet', () => ({ ...aligned(), walletId: 'wallet:other' })],
    ['another session', () => ({ ...aligned(), walletSessionId: 'wallet-session:other' })],
    ['expired', () => ({ ...aligned(), expiresAtMs: Date.now() - 1 })],
  ];
  for (const [label, readCapability] of arms) {
    await expectWalletUnlockRequired(
      stopBeforeHttp({
        walletSessions: {
          read: async () => ({ kind: 'missing' as const }),
          readActiveForWallet: async () => ({ kind: 'found' as const, projection }),
        },
        readWalletAuthenticationState: () => ({
          kind: 'authenticated',
          walletId: projection.walletId,
          authMethod: 'passkey',
        }),
        readUnlockedCustodyCapabilityV1: readCapability,
      }),
    ).catch((error: unknown) => {
      throw new Error(`${label}: ${String(error)}`);
    });
  }
});

test('reuses an unexpired owner enrollment ceremony and restarts an expired one', async () => {
  let startCalls = 0;
  const sessionId = parseLinkDeviceSessionId('link-session:retry');
  if (!sessionId.ok) throw new Error(sessionId.error.message);
  let expiresAtMs = Date.now() + 150;
  const authorities = stopBeforeHttp({
    startOwnerEnrollmentCeremonyV1: async () => {
      startCalls += 1;
      return { ceremony: buildR103OwnerEnrollmentCeremonyV1({ expiresAtMs }) };
    },
  });
  const request = {
    linkSessionId: sessionId.value,
    walletId,
    requestedAtMs: Date.now(),
  } as const;

  const first = await authorities.ownerAuthorization.startOwnerEnrollmentCeremonyV1(request);
  const reused = await authorities.ownerAuthorization.startOwnerEnrollmentCeremonyV1(request);
  expect(startCalls).toBe(1);
  expect(reused.ceremony).toBe(first.ceremony);

  // Zero-prompt makes retries cheap, but an expired ceremony can never be
  // finalized, so the cache must not keep serving it once its time passes.
  await new Promise((resolve) => setTimeout(resolve, 200));
  expiresAtMs = Date.now() + 60_000;
  const third = await authorities.ownerAuthorization.startOwnerEnrollmentCeremonyV1(request);
  expect(startCalls).toBe(2);
  expect(third.ceremony).not.toBe(first.ceremony);
});

test('device-link owner handoff excludes historical Ed25519 candidates', async () => {
  const currentAuthorization = availableLaneEd25519Authorization({
    walletId: String(walletId),
    identitySeed: 'device-link-current-owner',
    authMethod: 'passkey',
  });
  const current = authorizedPasskeyEd25519AvailableLane({
    authorization: currentAuthorization,
    materialActivation: buildMpcMaterialActivationRefFixture(
      'device-link-current-owner',
      String(walletId),
    ),
  });
  const historical = authorizedPasskeyEd25519AvailableLane({
    authorization: currentAuthorization,
    materialActivation: buildMpcMaterialActivationRefFixture(
      'device-link-historical-owner',
      String(walletId),
    ),
  });
  const available = availableEd25519Inventory({
    primary: current,
    candidates: [historical, current],
  });

  const selected = selectWalletHostOwnerSourceLaneCandidatesV1(
    available,
    currentAuthorization,
  );

  expect(selected).toEqual([
    {
      curve: 'ed25519',
      materialActivation: current.materialActivation,
    },
  ]);
});
