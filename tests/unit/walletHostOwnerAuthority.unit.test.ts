import { expect, test } from '@playwright/test';
import { parseWalletId } from '@shared/utils/domainIds';
import { buildFullOwnerDelegatedWalletAuthorityV1 } from '@shared/authorization/delegatedAuthority';
import { createWalletHostOwnerAuthoritiesV1 } from '@/SeamsWeb/operations/devices/walletHostOwnerAuthority';
import type { UnlockedWalletEd25519ExportRootCapabilityV1 } from '@/core/signingEngine/workerManager/workerTypes';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';
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
type ExactOwnerFixture = Awaited<ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>>;

async function exactOwnerFixture(label: string, expiresAtMs: number): Promise<ExactOwnerFixture> {
  return await buildLinkedDeviceManagementAuthorityFixture({
    label,
    permissions: buildFullOwnerDelegatedWalletAuthorityV1().permissions,
    provenance: 'wallet_registration',
    keyFamily: 'ed25519',
    expiresAtMs,
    identity: {
      walletId: String(walletId),
      authorityId: `authority:${label}`,
      walletAuthMethodId: `auth-method:${label}`,
      rpId: 'wallet.example.test',
    },
  });
}

function resolvedOwnerSelection(fixture: ExactOwnerFixture) {
  return {
    kind: 'resolved' as const,
    selection: {
      kind: 'wallet_selection_v1' as const,
      walletId: fixture.authority.walletId,
      walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
      lockGeneration: 0,
      lockState: 'unlocked' as const,
      updatedAtMs: 1,
    },
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: [],
    exportRoot: null,
  };
}

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

function stopBeforeHttp(fixture: ExactOwnerFixture, overrides: AuthorityOverrides = {}) {
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
      readExactWithOperationCredential: async () => ({ kind: 'missing' as const }),
    },
    resolveSelectedWalletAuthority: async () => resolvedOwnerSelection(fixture),
    readWalletAuthenticationState: () => ({
      kind: 'authenticated',
      walletId: fixture.authority.walletId,
      authMethod: 'passkey',
    }),
    readUnlockedEd25519ExportRootCapabilityV1: () => undefined,
    ...overrides,
  });
}

function authorizedOwnerHttp(
  owner: ExactOwnerFixture,
  deviceLink: ReturnType<typeof buildR103DeviceLinkFixture>,
): HttpTransport {
  const source = {
    kind: 'wallet_session' as const,
    walletSessionId: owner.operationCredential.walletSessionId,
    authorizationId: owner.activeWalletSession.authorizationId,
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
            proofDigestB64u: deviceLink.packageSetDigestB64u,
          },
          walletId: owner.authority.walletId,
          ownerAuthorization: source,
          sourceSignerManifest: deviceLink.sourceSignerManifest,
          expiresAtMs: owner.activeWalletSession.expiresAtMs,
        },
      },
    }),
  };
}

async function expectWalletUnlockRequired(
  authorities: ReturnType<typeof createWalletHostOwnerAuthoritiesV1>,
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
  const fixture = await exactOwnerFixture('locked-owner', Date.now() + 60_000);
  await expectWalletUnlockRequired(
    stopBeforeHttp(fixture, {
      resolveSelectedWalletAuthority: async () => {
        throw new Error('device linking must stop before authority lookup');
      },
      readWalletAuthenticationState: () => ({ kind: 'signed_out' }),
      walletSessions: {
        read: async () => {
          throw new Error('device linking must stop before session lookup');
        },
        readExactWithOperationCredential: async () => {
          throw new Error('device linking must stop before session lookup');
        },
      },
    }),
  );
});

test('a missing owner Wallet Session fails with wallet_unlock_required', async () => {
  const fixture = await exactOwnerFixture('missing-owner-session', Date.now() + 60_000);
  await expectWalletUnlockRequired(
    stopBeforeHttp(fixture, {
      readUnlockedEd25519ExportRootCapabilityV1: () => {
        throw new Error('the session gate precedes the capability read');
      },
    }),
  );
});

test('an expired owner Wallet Session fails with wallet_unlock_required', async () => {
  const fixture = await exactOwnerFixture('expired-owner-session', Date.now() - 1);
  await expectWalletUnlockRequired(
    stopBeforeHttp(fixture, {
      walletSessions: {
        read: async () => ({ kind: 'missing' as const }),
        readExactWithOperationCredential: async () => ({
          kind: 'found' as const,
          record: fixture.activeWalletSession,
          operationCredential: fixture.operationCredential,
        }),
      },
      readWalletAuthenticationState: () => ({
        kind: 'authenticated',
        walletId: fixture.authority.walletId,
        authMethod: 'passkey',
      }),
    }),
  );
});

test('an export_keys owner request requires a matching unexpired export-root capability', async () => {
  const owner = await exactOwnerFixture('capability-preflight', Date.now() + 60_000);
  const fixture = buildR103DeviceLinkFixture();
  const payload = {
    ...fixture.payload,
    requestedPermission: buildFullOwnerDelegatedWalletAuthorityV1(),
  };
  const aligned = () =>
    buildUnlockedEd25519ExportRootCapabilityFixtureV1({
      walletId: String(owner.authority.walletId),
      walletSessionId: String(owner.operationCredential.walletSessionId),
      expiresAtMs: owner.activeWalletSession.expiresAtMs,
    });
  const arms: Array<[string, AuthorityOverrides['readUnlockedEd25519ExportRootCapabilityV1']]> = [
    ['absent', () => undefined],
    ['another wallet', () => ({ ...aligned(), walletId: 'wallet:other' })],
    ['another session', () => ({ ...aligned(), walletSessionId: 'wallet-session:other' })],
    ['expired', () => ({ ...aligned(), expiresAtMs: Date.now() - 1 })],
  ];
  for (const [label, readCapability] of arms) {
    await expectWalletUnlockRequired(
      stopBeforeHttp(owner, {
        http: authorizedOwnerHttp(owner, fixture),
        walletSessions: {
          read: async () => ({ kind: 'missing' as const }),
          readExactWithOperationCredential: async () => ({
            kind: 'found' as const,
            record: owner.activeWalletSession,
            operationCredential: owner.operationCredential,
          }),
        },
        readWalletAuthenticationState: () => ({
          kind: 'authenticated',
          walletId: owner.authority.walletId,
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
