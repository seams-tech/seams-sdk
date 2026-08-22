import { expect, test } from '@playwright/test';
import { parseLinkedDeviceRevokeRequestV1 } from '../../packages/shared-ts/src/device-linking/parsers';
import {
  unknownWebAuthnAuthenticatorDeviceInfo,
} from '../../packages/shared-ts/src/utils/webauthnDeviceInfo';
import {
  LinkedDeviceManagementServiceV1,
  type LinkedDeviceManagementSourceV1,
} from '../../packages/wallet-server/src/core/deviceLinking/linkedDeviceManagement';
import {
  buildLinkedDeviceManagementAuthorityFixture,
  buildRevokedLinkedDeviceAuthMethodV1,
  buildRevokedLinkedDeviceAuthorityV1,
  fullOwnerPermissionsForManagementFixture,
  linkedDevicePermissionsForManagementFixture,
} from './helpers/linkedDeviceManagement.fixtures';

test('rejects a WalletAuthorityId in the exact-method revocation boundary', () => {
  expect(() =>
    parseLinkedDeviceRevokeRequestV1({
      kind: 'linked_device_revoke_request_v1',
      walletId: 'wallet:management',
      walletAuthMethodId: 'wallet-authority:management-target',
      requestedAtMs: 4_000,
    }),
  ).toThrow('must identify a WalletAuthMethodId');
});

test('lists active wallet authorities and hides non-linked owner records after source resolution', async () => {
  const owner = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'owner',
    permissions: fullOwnerPermissionsForManagementFixture(),
    provenance: 'wallet_registration',
  });
  const target = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'target',
    permissions: linkedDevicePermissionsForManagementFixture(),
    provenance: 'device_link',
    keyFamily: 'ecdsa_secp256k1',
    sourceAuthorityId: owner.authority.authorityId,
  });
  const authorities = [owner.authority, target.authority];
  const authMethods = [owner.authMethod, target.authMethod];
  const service = new LinkedDeviceManagementServiceV1({
    tenantId: owner.issuedSession.session.tenantId,
    authenticator: {
      readWalletSessionAuthorizationV2ByIdentity: async ({ authorizationId }) =>
        authorizationId === owner.issuedSession.session.authorizationId
          ? owner.issuedSession
          : null,
    },
    authority: {
      listActiveForWalletV1: async () => ({ records: authorities, nextCursor: null }),
      readByIdV1: async (authorityId) =>
        authorities.find((authority) => authority.authorityId === authorityId) ?? null,
      revokeWalletAuthMethodV1: async () => {
        throw new Error('unexpected authority revocation');
      },
    },
    authMethod: {
      listForAuthorityV1: async ({ authorityId }) =>
        authMethods.filter((method) => method.walletAuthorityId === authorityId),
      readByIdV1: async ({ walletAuthMethodId }) =>
        authMethods.find((method) => method.walletAuthMethodId === walletAuthMethodId) ?? null,
    },
    sessions: {
      revokeReusableWalletSessionsForAuthMethod: async () => {
        throw new Error('unexpected session revocation');
      },
    },
    credentials: {
      readPasskeyDeviceInfoV1: async () => unknownWebAuthnAuthenticatorDeviceInfo(),
    },
  });
  const result = await service.listLinkedDevicesV1(
    {
      kind: 'linked_device_list_request_v1',
      walletId: owner.authority.walletId,
      limit: 10,
      cursor: null,
    },
    sourceFor(owner),
    4_000,
  );

  expect(result).toEqual({
    devices: [
      expect.objectContaining({
        deviceId: target.authority.principal.deviceId,
        walletId: target.authority.walletId,
        state: 'active',
      }),
    ],
    ownerDevices: [
      expect.objectContaining({
        walletId: owner.authority.walletId,
      }),
    ],
    nextCursor: null,
  });
});

test('revokes one exact linked auth method, fences sessions, and disables its ordinary refs', async () => {
  const owner = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'owner',
    permissions: fullOwnerPermissionsForManagementFixture(),
    provenance: 'wallet_registration',
  });
  const target = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'target',
    permissions: linkedDevicePermissionsForManagementFixture(),
    provenance: 'device_link',
    keyFamily: 'ecdsa_secp256k1',
    sourceAuthorityId: owner.authority.authorityId,
  });
  const revokedAuthority = buildRevokedLinkedDeviceAuthorityV1(target.authority, 4_000);
  const revokedMethod = buildRevokedLinkedDeviceAuthMethodV1(target.authMethod, 4_000);
  let revocationInput: {
    readonly walletAuthMethodId: typeof target.authMethod.walletAuthMethodId;
    readonly authorityId: typeof target.authority.authorityId;
    readonly expectedAuthorityRevocationEpoch: number;
  } | null = null;
  let fencedMethodId: typeof target.authMethod.walletAuthMethodId | null = null;
  const deactivatedRefs: Array<{ readonly keyFamily: string; readonly activationId: string }> = [];
  const service = new LinkedDeviceManagementServiceV1({
    tenantId: owner.issuedSession.session.tenantId,
    authenticator: {
      readWalletSessionAuthorizationV2ByIdentity: async ({ authorizationId }) =>
        authorizationId === owner.issuedSession.session.authorizationId
          ? owner.issuedSession
          : null,
    },
    authority: {
      listActiveForWalletV1: async () => ({ records: [], nextCursor: null }),
      readByIdV1: async (authorityId) =>
        authorityId === owner.authority.authorityId
          ? owner.authority
          : authorityId === target.authority.authorityId
            ? target.authority
            : null,
      revokeWalletAuthMethodV1: async (input) => {
        revocationInput = {
          walletAuthMethodId: input.walletAuthMethodId,
          authorityId: input.authorityId,
          expectedAuthorityRevocationEpoch: input.expectedAuthorityRevocationEpoch,
        };
        return { kind: 'revoked_method', authMethod: revokedMethod, authority: revokedAuthority };
      },
    },
    authMethod: {
      listForAuthorityV1: async () => [],
      readByIdV1: async ({ walletAuthMethodId }) =>
        walletAuthMethodId === owner.authMethod.walletAuthMethodId
          ? owner.authMethod
          : walletAuthMethodId === target.authMethod.walletAuthMethodId
            ? target.authMethod
            : null,
    },
    sessions: {
      revokeReusableWalletSessionsForAuthMethod: async ({ walletAuthMethodId }) => {
        fencedMethodId = walletAuthMethodId;
      },
    },
    credentials: {
      readPasskeyDeviceInfoV1: async () => unknownWebAuthnAuthenticatorDeviceInfo(),
    },
    materialDeactivation: {
      deactivateOrdinarySignerMaterialV1: async ({ keyFamily, materialActivation }) => {
        deactivatedRefs.push({
          keyFamily,
          activationId: String(materialActivation.activationId),
        });
      },
    },
  });
  const result = await service.revokeLinkedDeviceV1(
    {
      kind: 'linked_device_revoke_request_v1',
      walletId: target.authority.walletId,
      walletAuthMethodId: target.authMethod.walletAuthMethodId,
      requestedAtMs: 4_000,
    },
    sourceFor(owner),
  );

  expect(result).toEqual({
    kind: 'revoked',
    walletAuthMethodId: target.authMethod.walletAuthMethodId,
    authorityId: target.authority.authorityId,
    revocationEpoch: revokedAuthority.revocationEpoch,
  });
  expect(revocationInput).toEqual({
    walletAuthMethodId: target.authMethod.walletAuthMethodId,
    authorityId: target.authority.authorityId,
    expectedAuthorityRevocationEpoch: target.authority.revocationEpoch,
  });
  expect(fencedMethodId).toBe(target.authMethod.walletAuthMethodId);
  if (target.authority.signerActivations.keyFamilies[0] !== 'ecdsa_secp256k1') {
    throw new Error('ECDSA management fixture is missing its key family');
  }
  if (!target.authority.signerActivations.ecdsa) {
    throw new Error('ECDSA management fixture is missing its activation');
  }
  expect(deactivatedRefs).toEqual([
    {
      keyFamily: 'ecdsa_secp256k1',
      activationId: String(target.authority.signerActivations.ecdsa.materialActivation.activationId),
    },
  ]);
});

test('replays a durable revocation and retries terminal material deactivation', async () => {
  const owner = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'owner',
    permissions: fullOwnerPermissionsForManagementFixture(),
    provenance: 'wallet_registration',
  });
  const target = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'target',
    permissions: linkedDevicePermissionsForManagementFixture(),
    provenance: 'device_link',
    sourceAuthorityId: owner.authority.authorityId,
  });
  const revokedAuthority = buildRevokedLinkedDeviceAuthorityV1(target.authority, 4_000);
  const revokedMethod = buildRevokedLinkedDeviceAuthMethodV1(target.authMethod, 4_000);
  let sessionFenceCalls = 0;
  let deactivationCalls = 0;
  const service = new LinkedDeviceManagementServiceV1({
    tenantId: owner.issuedSession.session.tenantId,
    authenticator: {
      readWalletSessionAuthorizationV2ByIdentity: async ({ authorizationId }) =>
        authorizationId === owner.issuedSession.session.authorizationId
          ? owner.issuedSession
          : null,
    },
    authority: {
      listActiveForWalletV1: async () => ({ records: [], nextCursor: null }),
      readByIdV1: async (authorityId) =>
        authorityId === owner.authority.authorityId
          ? owner.authority
          : authorityId === revokedAuthority.authorityId
            ? revokedAuthority
            : null,
      revokeWalletAuthMethodV1: async () => {
        throw new Error('replay must not issue a second authority CAS');
      },
    },
    authMethod: {
      listForAuthorityV1: async () => [],
      readByIdV1: async ({ walletAuthMethodId }) =>
        walletAuthMethodId === owner.authMethod.walletAuthMethodId
          ? owner.authMethod
          : walletAuthMethodId === revokedMethod.walletAuthMethodId
            ? revokedMethod
            : null,
    },
    sessions: {
      revokeReusableWalletSessionsForAuthMethod: async () => {
        sessionFenceCalls += 1;
      },
    },
    credentials: {
      readPasskeyDeviceInfoV1: async () => unknownWebAuthnAuthenticatorDeviceInfo(),
    },
    materialDeactivation: {
      deactivateOrdinarySignerMaterialV1: async () => {
        deactivationCalls += 1;
      },
    },
  });

  const result = await service.revokeLinkedDeviceV1(
    {
      kind: 'linked_device_revoke_request_v1',
      walletId: target.authority.walletId,
      walletAuthMethodId: target.authMethod.walletAuthMethodId,
      requestedAtMs: 5_000,
    },
    sourceFor(owner),
  );

  expect(result).toEqual({
    kind: 'revoked',
    walletAuthMethodId: revokedMethod.walletAuthMethodId,
    authorityId: revokedAuthority.authorityId,
    revocationEpoch: revokedAuthority.revocationEpoch,
  });
  expect(sessionFenceCalls).toBe(1);
  expect(deactivationCalls).toBe(1);
});

function sourceFor(
  fixture: Awaited<ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>>,
): LinkedDeviceManagementSourceV1 {
  return {
    walletId: fixture.issuedSession.session.walletId,
    walletSessionId: fixture.issuedSession.session.walletSessionId,
    authorizationId: fixture.issuedSession.session.authorizationId,
    expiresAtMs: fixture.issuedSession.session.expiresAtMs,
  };
}
