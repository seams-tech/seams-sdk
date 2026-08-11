import { expect, test } from '@playwright/test';
import { parseWalletSessionAuthorizationId, parseWalletSessionId } from '@shared/authorization/capabilityKinds';
import {
  parseWalletAuthMethodId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  buildLinkedDeviceApprovalV1,
  buildWalletSessionLinkedDeviceOwnerAuthorizationV1,
} from '@shared/device-linking/parsers';
import { buildR103DeviceLinkFixture } from './helpers/deviceLinkContracts.fixtures';
import { buildR103ActiveLinkedDeviceSessionRecordV1 } from './helpers/deviceLinkingServer.fixtures';
import type { DeviceLinkingOwnerWalletSessionContextV1 } from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/deviceLinkingOwnerAuthorization';
import { createD1LinkedDeviceOwnerAuthorizationProviderV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerAuthorizationProvider';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function ownerFor(
  walletId: DeviceLinkingOwnerWalletSessionContextV1['walletId'],
): DeviceLinkingOwnerWalletSessionContextV1 {
  const rpId = required(parseWebAuthnRpId('wallet.example.test'));
  const credentialIdB64u = required(parseWebAuthnCredentialIdB64u('owner-provider-test'));
  return {
    walletId,
    walletSessionId: required(parseWalletSessionId('wallet-session:owner-provider')),
    authorizationId: required(
      parseWalletSessionAuthorizationId('wallet-authorization:owner-provider'),
    ),
    expiresAtMs: 9_000,
    curve: 'ed25519',
    authority: {
      walletId,
      factor: { kind: 'passkey', credentialIdB64u },
      verifier: { kind: 'webauthn', rpId },
      bindingId: required(parseWalletAuthMethodId(`passkey:${rpId}:${credentialIdB64u}`)),
    },
    authorityScope: { kind: 'passkey_rp', rpId },
  };
}

test('binds claims deterministically and returns only authoritative owner metadata', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const owner = ownerFor(fixture.approval.walletId);
  const provider = createD1LinkedDeviceOwnerAuthorizationProviderV1({
    walletRegistration: {
      resolveActiveOwnerWalletExecutionLane: async () => ({
        kind: 'refused',
        reason: 'signer_missing',
      }),
    },
    metadata: {
      readOwnerAuthorizationMetadataV1: async () => ({
        walletId: fixture.approval.walletId,
        policyDigestB64u: fixture.approval.policyDigestB64u,
        operationId: fixture.approval.operationId,
        idempotencyKey: fixture.approval.idempotencyKey,
        orderedKeyBindings: fixture.approval.orderedKeyBindings,
        protocolVersions: fixture.approval.protocolVersions,
        expiresAtMs: 8_000,
      }),
      readApprovedOwnerContextV1: async () => owner,
      readOwnerSourceChildV1: async () => null,
    },
    targetPlanner: {
      rpId: required(parseWebAuthnRpId('wallet.example.test')),
    },
    nowV1: () => 2_000,
  });

  const firstClaim = await provider.ownerAuthorization.authorizeOwnerClaimV1({
    payload: fixture.payload,
    requestedAtMs: 2_000,
    owner,
  });
  const secondClaim = await provider.ownerAuthorization.authorizeOwnerClaimV1({
    payload: fixture.payload,
    requestedAtMs: 2_000,
    owner,
  });
  expect(firstClaim).toEqual(secondClaim);
  expect(firstClaim.kind).toBe('authorized');

  const response = await provider.ownerAuthorizationRoute.authorizeOwnerForLinkingV1({
    payload: fixture.payload,
    requestedAtMs: 2_000,
    bodyDigestB64u: parseDigestB64u(fixture.approval.policyDigestB64u),
    owner,
  });
  expect(response.walletId).toBe(fixture.approval.walletId);
  expect(response.operationId).toBe(fixture.approval.operationId);
  expect(response.ownerAuthorization).toEqual({
    kind: 'wallet_session',
    walletSessionId: owner.walletSessionId,
    authorizationId: owner.authorizationId,
  });
  expect(response.expiresAtMs).toBe(8_000);
});

test('fails closed when authoritative source projection is unavailable', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const owner = ownerFor(fixture.approval.walletId);
  const session = await buildR103ActiveLinkedDeviceSessionRecordV1(fixture);
  const approval = buildLinkedDeviceApprovalV1({
    ...fixture.approval,
    ownerAuthorization: buildWalletSessionLinkedDeviceOwnerAuthorizationV1({
      walletSessionId: owner.walletSessionId,
      authorizationId: owner.authorizationId,
    }),
  });
  const provider = createD1LinkedDeviceOwnerAuthorizationProviderV1({
    walletRegistration: {
      resolveActiveOwnerWalletExecutionLane: async () => ({
        kind: 'refused',
        reason: 'signer_missing',
      }),
    },
    metadata: {
      readOwnerAuthorizationMetadataV1: async () => null,
      readApprovedOwnerContextV1: async () => owner,
      readOwnerSourceChildV1: async () => null,
    },
    targetPlanner: {
      rpId: required(parseWebAuthnRpId('wallet.example.test')),
    },
    nowV1: () => 2_000,
  });

  await expect(
    provider.ownerSourceResolver.resolveOwnerSourceChildV1({
      kind: 'preparation',
      session,
      approval,
      binding: approval.orderedKeyBindings[0]!,
      childIndex: 0,
    }),
  ).rejects.toThrow('authoritative linked-device source facts are unavailable');
});
