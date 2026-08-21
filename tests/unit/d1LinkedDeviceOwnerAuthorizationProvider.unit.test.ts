import { expect, test } from '@playwright/test';
import {
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  buildFullOwnerDelegatedWalletAuthorityV1,
  buildSigningOnlyDelegatedWalletAuthorityV1,
  parseDelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';
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
import type { DeviceLinkingOwnerWalletSessionContextV1 } from '../../packages/wallet-server/src/router/transport/fetch/routes/deviceLinkingOwnerAuthorization';
import {
  createD1LinkedDeviceOwnerAuthorizationProviderV1,
  type D1LinkedDeviceOwnerAuthorizationMetadataSourceV1,
} from '../../packages/wallet-server/src/router/cloudflare/d1/deviceLinking/d1LinkedDeviceOwnerAuthorizationProvider';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function ownerFor(
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
  permission: DeviceLinkingOwnerWalletSessionContextV1['permission'],
): DeviceLinkingOwnerWalletSessionContextV1 {
  const walletId = fixture.approval.walletId;
  const rpId = required(parseWebAuthnRpId('wallet.example.test'));
  const credentialIdB64u = required(parseWebAuthnCredentialIdB64u('owner-provider-test'));
  return {
    walletId,
    walletSessionId: required(parseWalletSessionId('wallet-session:owner-provider')),
    authorizationId: required(
      parseWalletSessionAuthorizationId('wallet-authorization:owner-provider'),
    ),
    expiresAtMs: 9_000,
    permission,
    keyManifestDigestB64u: fixture.receipt.manifestDigestB64u,
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

function approvalForOwner(
  fixture: ReturnType<typeof buildR103DeviceLinkFixture>,
  owner: DeviceLinkingOwnerWalletSessionContextV1,
) {
  return buildLinkedDeviceApprovalV1({
    ...fixture.approval,
    ownerAuthorization: buildWalletSessionLinkedDeviceOwnerAuthorizationV1({
      walletSessionId: owner.walletSessionId,
      authorizationId: owner.authorizationId,
    }),
  });
}

function sourceResolverProviderFor(
  owner: DeviceLinkingOwnerWalletSessionContextV1,
  readOwnerSourceChildV1: D1LinkedDeviceOwnerAuthorizationMetadataSourceV1['readOwnerSourceChildV1'],
) {
  return createD1LinkedDeviceOwnerAuthorizationProviderV1({
    walletRegistration: {
      resolveActiveOwnerWalletExecutionLane: async () => ({
        kind: 'refused',
        reason: 'signer_missing',
      }),
    },
    metadata: {
      readApprovedOwnerContextV1: async () => owner,
      readOwnerSourceChildV1,
    },
    targetPlanner: {
      rpId: required(parseWebAuthnRpId('wallet.example.test')),
      targetDeploymentDescriptorProvider: {
        resolveTargetDeploymentDescriptorV1: async () => {
          throw new Error('target descriptor is outside this owner-source test');
        },
      },
    },
    planningWriter: {
      writeV1: async () => ({ outcome: 'conflict' }),
    },
    nowV1: () => 2_000,
  });
}

test('binds claims deterministically and returns only authoritative owner metadata', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const owner = ownerFor(fixture, buildFullOwnerDelegatedWalletAuthorityV1());
  const provider = createD1LinkedDeviceOwnerAuthorizationProviderV1({
    walletRegistration: {
      resolveActiveOwnerWalletExecutionLane: async () => ({
        kind: 'refused',
        reason: 'signer_missing',
      }),
    },
    metadata: {
      readApprovedOwnerContextV1: async () => owner,
      readOwnerSourceChildV1: async () => null,
    },
    targetPlanner: {
      rpId: required(parseWebAuthnRpId('wallet.example.test')),
      targetDeploymentDescriptorProvider: {
        resolveTargetDeploymentDescriptorV1: async () => {
          throw new Error('target descriptor is outside this owner-authorization test');
        },
      },
    },
    planningWriter: {
      writeV1: async () => ({
        outcome: 'applied',
        snapshot: {
          metadata: {
            walletId: fixture.approval.walletId,
            policyDigestB64u: fixture.approval.policyDigestB64u,
            operationId: fixture.approval.operationId,
            idempotencyKey: fixture.approval.idempotencyKey,
            orderedKeyBindings: fixture.approval.orderedKeyBindings,
            protocolVersions: fixture.approval.protocolVersions,
            expiresAtMs: 8_000,
          },
        },
      }),
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

  const linkOnlyAuthority = required(
    parseDelegatedWalletAuthorityV1({
      kind: 'delegated_wallet_authority_v1',
      permissions: ['link_devices'],
    }),
  );
  const limitedOwner = ownerFor(fixture, linkOnlyAuthority);
  const escalatedClaim = await provider.ownerAuthorization.authorizeOwnerClaimV1({
    payload: fixture.payload,
    requestedAtMs: 2_000,
    owner: limitedOwner,
  });
  expect(escalatedClaim).toEqual({
    kind: 'denied',
    code: 'unauthorized',
    message: 'delegated authority cannot grant sign outside its parent authority',
  });
  await expect(
    provider.ownerAuthorizationRoute.authorizeOwnerForLinkingV1({
      payload: fixture.payload,
      requestedAtMs: 2_000,
      bodyDigestB64u: parseDigestB64u(fixture.approval.policyDigestB64u),
      owner: limitedOwner,
    }),
  ).rejects.toThrow('delegated authority cannot grant sign outside its parent authority');
});

test('fails closed when authoritative source projection is unavailable', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const owner = ownerFor(fixture, buildFullOwnerDelegatedWalletAuthorityV1());
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
      readApprovedOwnerContextV1: async () => owner,
      readOwnerSourceChildV1: async () => null,
    },
    targetPlanner: {
      rpId: required(parseWebAuthnRpId('wallet.example.test')),
      targetDeploymentDescriptorProvider: {
        resolveTargetDeploymentDescriptorV1: async () => {
          throw new Error('target descriptor is outside this owner-source test');
        },
      },
    },
    planningWriter: {
      writeV1: async () => ({ outcome: 'conflict' }),
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

test('requires source link authority and attenuates the approved child permission', async () => {
  const fixture = buildR103DeviceLinkFixture();
  const session = await buildR103ActiveLinkedDeviceSessionRecordV1(fixture);
  const sourceReadMustNotRun: D1LinkedDeviceOwnerAuthorizationMetadataSourceV1['readOwnerSourceChildV1'] =
    async () => {
      throw new Error('source child reader should not run');
    };

  const ownerWithoutLinkPermission = ownerFor(
    fixture,
    buildSigningOnlyDelegatedWalletAuthorityV1(),
  );
  const approvalWithoutLinkPermission = approvalForOwner(fixture, ownerWithoutLinkPermission);
  const providerWithoutLinkPermission = sourceResolverProviderFor(
    ownerWithoutLinkPermission,
    sourceReadMustNotRun,
  );

  await expect(
    providerWithoutLinkPermission.ownerSourceResolver.resolveOwnerSourceChildV1({
      kind: 'preparation',
      session,
      approval: approvalWithoutLinkPermission,
      binding: approvalWithoutLinkPermission.orderedKeyBindings[0]!,
      childIndex: 0,
    }),
  ).rejects.toThrow('approved owner Wallet Session authority does not contain link_devices');

  const linkOnlyAuthority = required(
    parseDelegatedWalletAuthorityV1({
      kind: 'delegated_wallet_authority_v1',
      permissions: ['link_devices'],
    }),
  );
  const linkOnlyOwner = ownerFor(fixture, linkOnlyAuthority);
  const linkOnlyApproval = approvalForOwner(fixture, linkOnlyOwner);
  const providerWithUnattenuatedChild = sourceResolverProviderFor(
    linkOnlyOwner,
    sourceReadMustNotRun,
  );

  await expect(
    providerWithUnattenuatedChild.ownerSourceResolver.resolveOwnerSourceChildV1({
      kind: 'preparation',
      session,
      approval: linkOnlyApproval,
      binding: linkOnlyApproval.orderedKeyBindings[0]!,
      childIndex: 0,
    }),
  ).rejects.toThrow('delegated authority cannot grant sign outside its parent authority');
});
