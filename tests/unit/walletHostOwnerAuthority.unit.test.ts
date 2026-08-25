import { expect, test } from '@playwright/test';
import { parseWalletId } from '@shared/utils/domainIds';
import { buildFullOwnerDelegatedWalletAuthorityV1 } from '@shared/authorization/delegatedAuthority';
import { createWalletHostOwnerAuthoritiesV1 } from '@/SeamsWeb/operations/devices/walletHostOwnerAuthority';
import type { UnlockedWalletEd25519ExportRootCapabilityV1 } from '@/core/signingEngine/workerManager/workerTypes';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { availableLaneEd25519Authorization } from './helpers/availableSigningLanes.fixtures';
import type { HttpTransport } from '@/core/platform/http';

const walletId = parseWalletId('wallet:r103').value;

/**
 * R103 zero-prompt handoff: linking on Device 1 either proceeds silently from
 * the unlocked state or fails closed with the exact `wallet_unlock_required`
 * result. These tests own the fail-closed half — every missing-precondition
 * arm must stop before HTTP, and therefore before any claim, approval,
 * credential, recipient package, or prompt could exist.
 */

type AuthorityOverrides = Partial<Parameters<typeof createWalletHostOwnerAuthoritiesV1>[0]>;

function buildUnlockedEd25519ExportRootCapabilityFixtureV1(
  overrides: Partial<UnlockedWalletEd25519ExportRootCapabilityV1> = {},
): UnlockedWalletEd25519ExportRootCapabilityV1 {
  return {
    kind: 'unlocked_wallet_ed25519_export_root_capability_v1',
    capabilityHandleId: 'export-root-capability-fixture',
    walletId: String(walletId),
    walletAuthMethodId: 'passkey:wallet.example.test:credential-fixture',
    walletSessionId: 'wallet-session:fixture',
    expiresAtMs: Date.now() + 60_000,
    ...overrides,
  };
}

function stopBeforeHttp(overrides: AuthorityOverrides = {}) {
  return createWalletHostOwnerAuthoritiesV1({
    http: {
      kind: 'http_transport',
      request: async () => {
        throw new Error('device linking must stop before HTTP');
      },
    },
    relayerUrl: 'https://relay.example.test',
    walletSessions: {
      read: async () => ({ kind: 'missing' as const }),
      readActiveForWallet: async () => ({ kind: 'missing' as const }),
    },
    readWalletAuthenticationState: () => ({
      kind: 'authenticated',
      walletId,
      authMethod: 'passkey',
    }),
    readUnlockedEd25519ExportRootCapabilityV1: () => undefined,
    ...overrides,
  });
}

function authorizedOwnerHttp(
  projection: ReturnType<typeof availableLaneEd25519Authorization>,
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
): HttpTransport {
  if (projection.walletSessionTokens.kind !== 'near_ed25519') {
    throw new Error('owner authorization fixture requires an Ed25519 token');
  }
  const source = {
    kind: 'wallet_session' as const,
    walletSessionId: projection.walletSessionId,
    authorizationId: projection.walletSessionTokens.ed25519.authorizationId,
  };
  return {
    kind: 'http_transport',
    request: async () => ({
      ok: true,
      value: {
        status: 200,
        body: {
          authentication: {
            kind: 'link_session_authenticated_request_v1',
            source,
            proofDigestB64u: fixture.packageSetDigestB64u,
          },
          walletId: projection.walletId,
          ownerAuthorization: source,
          sourceSignerManifest: fixture.sourceSignerManifest,
          expiresAtMs: projection.expiresAtMs,
        },
      },
    }),
  };
}

async function expectWalletUnlockRequired(
  authorities: ReturnType<typeof stopBeforeHttp>,
  payload = buildR103DeviceLinkFixture().payload,
) {
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
      readUnlockedEd25519ExportRootCapabilityV1: () => {
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

test('an export_keys owner request requires a matching unexpired export-root capability', async () => {
  const projection = availableLaneEd25519Authorization({
    walletId: String(walletId),
    identitySeed: 'capability-preflight',
    authMethod: 'passkey',
  });
  const fixture = buildR103DeviceLinkFixture();
  const payload = {
    ...fixture.payload,
    requestedPermission: buildFullOwnerDelegatedWalletAuthorityV1(),
  };
  const aligned = () =>
    buildUnlockedEd25519ExportRootCapabilityFixtureV1({
      walletId: String(projection.walletId),
      walletSessionId: String(projection.walletSessionId),
      expiresAtMs: projection.expiresAtMs,
    });
  const arms: Array<[string, AuthorityOverrides['readUnlockedEd25519ExportRootCapabilityV1']]> = [
    ['absent', () => undefined],
    ['another wallet', () => ({ ...aligned(), walletId: 'wallet:other' })],
    ['another session', () => ({ ...aligned(), walletSessionId: 'wallet-session:other' })],
    ['expired', () => ({ ...aligned(), expiresAtMs: Date.now() - 1 })],
  ];
  for (const [label, readCapability] of arms) {
    await expectWalletUnlockRequired(
      stopBeforeHttp({
        http: authorizedOwnerHttp(projection, fixture),
        walletSessions: {
          read: async () => ({ kind: 'missing' as const }),
          readActiveForWallet: async () => ({ kind: 'found' as const, projection }),
        },
        readWalletAuthenticationState: () => ({
          kind: 'authenticated',
          walletId: projection.walletId,
          authMethod: 'passkey',
        }),
        readUnlockedEd25519ExportRootCapabilityV1: readCapability,
      }),
      payload,
    ).catch((error: unknown) => {
      throw new Error(`${label}: ${String(error)}`);
    });
  }
});
