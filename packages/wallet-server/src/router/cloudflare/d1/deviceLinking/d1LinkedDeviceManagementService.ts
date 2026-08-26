import type {
  ActiveWalletAuthorityV1,
  WalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import type { TenantId } from '@shared/authorization/capabilityKinds';
import type { WalletAuthorityId, WalletAuthMethodId } from '@shared/utils/domainIds';
import type { AuthorizationService } from '../../../../authorization/service';
import type {
  OpaqueWalletSessionCurve,
  ResolvedOpaqueWalletSessionToken,
} from '../../../../authorization/service';
import type { D1WalletAuthMethodStore } from '../../../../core/d1WalletAuthMethodStore';
import { LinkedDeviceManagementServiceV1 } from '../../../../core/deviceLinking/linkedDeviceManagement';
import type { LinkedDeviceManagementAuthorityPageV1 } from '../../../../core/deviceLinking/linkedDeviceManagement';
import type { OrdinaryInactiveSignerMaterialDeactivationPortV1 } from '../../../../core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import {
  D1WalletAuthorityStore,
  type D1WalletAuthorityStoreScope,
} from '../wallet/d1WalletAuthorityStore';
import { CloudflareD1WebAuthnStore } from '../webauthn/d1WebAuthnStore';
import type { CloudflareD1AuthorizationStore } from '../authorization/d1AuthorizationStore';

export function createD1LinkedDeviceManagementServiceV1(input: {
  readonly scope: D1WalletAuthorityStoreScope;
  readonly tenantId: TenantId;
  readonly authorityStore: D1WalletAuthorityStore;
  readonly authMethodStore: D1WalletAuthMethodStore;
  readonly authorizationService: AuthorizationService;
  readonly ordinaryWalletSessions: Pick<
    CloudflareD1AuthorizationStore,
    'readOpaqueWalletSessionTokenByIdentity'
  >;
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly materialDeactivation?: OrdinaryInactiveSignerMaterialDeactivationPortV1;
}): LinkedDeviceManagementServiceV1 {
  return new LinkedDeviceManagementServiceV1({
    tenantId: input.tenantId,
    authenticator: ownerSessionPortV1(input.ordinaryWalletSessions),
    authority: authorityPortV1(input.authorityStore),
    authMethod: authMethodPortV1(input.authMethodStore),
    sessions: input.authorizationService,
    credentials: {
      readPasskeyDeviceInfoV1: async ({ walletId, credentialIdB64u }) => {
        const record = await input.webAuthnStore.readAuthenticator({
          userId: String(walletId),
          credentialIdB64u,
        });
        return record?.deviceInfo ?? null;
      },
    },
    ...(input.materialDeactivation === undefined
      ? {}
      : { materialDeactivation: input.materialDeactivation }),
  });
}

function ownerSessionPortV1(
  store: Pick<CloudflareD1AuthorizationStore, 'readOpaqueWalletSessionTokenByIdentity'>,
): ConstructorParameters<typeof LinkedDeviceManagementServiceV1>[0]['authenticator'] {
  return {
    readActiveOwnerWalletSessionV1: async (identity) => {
      for (const curve of ['ed25519', 'ecdsa'] as const) {
        const resolved = await store.readOpaqueWalletSessionTokenByIdentity({
          tenantId: identity.tenantId,
          walletSessionId: identity.walletSessionId,
          curve,
          nowMs: identity.nowMs,
        });
        const session = normalizeOwnerSessionV1(resolved, identity, curve);
        if (session) return session;
      }
      return null;
    },
  };
}

function normalizeOwnerSessionV1(
  resolved: ResolvedOpaqueWalletSessionToken | null,
  identity: {
    readonly walletId: import('@shared/utils/domainIds').WalletId;
    readonly walletSessionId: import('@shared/authorization/capabilityKinds').WalletSessionId;
    readonly authorizationId: import('@shared/authorization/capabilityKinds').WalletSessionAuthorizationId;
  },
  curve: OpaqueWalletSessionCurve,
) {
  if (
    !resolved ||
    resolved.curve !== curve ||
    resolved.authorization.walletId !== identity.walletId ||
    resolved.authorization.walletSessionId !== identity.walletSessionId ||
    resolved.authorization.authorizationId !== identity.authorizationId ||
    resolved.authorization.walletAuthMethodId === null
  ) {
    return null;
  }
  return {
    walletId: resolved.authorization.walletId,
    walletSessionId: resolved.authorization.walletSessionId,
    authorizationId: resolved.authorization.authorizationId,
    walletAuthMethodId: resolved.authorization.walletAuthMethodId,
    authorityDigestB64u: resolved.authorization.authorityDigest,
    expiresAtMs: resolved.authorization.expiresAtMs,
  };
}

function authorityPortV1(
  store: D1WalletAuthorityStore,
): ConstructorParameters<typeof LinkedDeviceManagementServiceV1>[0]['authority'] {
  return {
    listActiveForWalletV1: async ({ walletId, limit, cursor }) => {
      const page = await store.listForWallet({
        walletId,
        lifecycleState: 'active',
        limit,
        cursor: cursor
          ? { updatedAtMs: cursor.updatedAtMs, authorityId: cursor.authorityId }
          : null,
      });
      const records: ActiveWalletAuthorityV1[] = [];
      for (const authority of page.records) {
        if (authority.state !== 'active') {
          throw new Error('active wallet authority query returned a non-active authority');
        }
        records.push(authority);
      }
      return {
        records,
        nextCursor: page.nextCursor
          ? {
              kind: 'wallet_authority_v1',
              updatedAtMs: page.nextCursor.updatedAtMs,
              authorityId: page.nextCursor.authorityId,
            }
          : null,
      } satisfies LinkedDeviceManagementAuthorityPageV1;
    },
    readByIdV1: async (authorityId: WalletAuthorityId): Promise<WalletAuthorityV1 | null> =>
      await store.readById(authorityId),
    revokeWalletAuthMethodV1: async (request) => await store.revokeWalletAuthMethod(request),
  };
}

function authMethodPortV1(
  store: D1WalletAuthMethodStore,
): ConstructorParameters<typeof LinkedDeviceManagementServiceV1>[0]['authMethod'] {
  return {
    listForAuthorityV1: async ({ walletId, authorityId }) =>
      await store.listForWalletV2({ walletId, walletAuthorityId: authorityId }),
    readByIdV1: async ({
      walletAuthMethodId,
    }: {
      readonly walletAuthMethodId: WalletAuthMethodId;
    }) => await store.readByIdV2({ walletAuthMethodId }),
  };
}
