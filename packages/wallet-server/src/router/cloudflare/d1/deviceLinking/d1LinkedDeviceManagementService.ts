import type {
  ActiveWalletAuthorityV1,
  WalletAuthorityV1,
} from '@shared/authorization/walletAuthority';
import type { TenantId } from '@shared/authorization/capabilityKinds';
import type {
  WalletAuthorityId,
  WalletAuthMethodId,
} from '@shared/utils/domainIds';
import type { AuthorizationService } from '../../../../authorization/service';
import type { D1WalletAuthMethodStore } from '../../../../core/d1WalletAuthMethodStore';
import { LinkedDeviceManagementServiceV1 } from '../../../../core/deviceLinking/linkedDeviceManagement';
import type {
  LinkedDeviceManagementAuthorityPageV1,
} from '../../../../core/deviceLinking/linkedDeviceManagement';
import type { OrdinaryInactiveSignerMaterialDeactivationPortV1 } from '../../../../core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import {
  D1WalletAuthorityStore,
  type D1WalletAuthorityStoreScope,
} from '../wallet/d1WalletAuthorityStore';
import { CloudflareD1WebAuthnStore } from '../webauthn/d1WebAuthnStore';

export function createD1LinkedDeviceManagementServiceV1(input: {
  readonly scope: D1WalletAuthorityStoreScope;
  readonly tenantId: TenantId;
  readonly authorityStore: D1WalletAuthorityStore;
  readonly authMethodStore: D1WalletAuthMethodStore;
  readonly authorizationService: AuthorizationService;
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly materialDeactivation?: OrdinaryInactiveSignerMaterialDeactivationPortV1;
}): LinkedDeviceManagementServiceV1 {
  return new LinkedDeviceManagementServiceV1({
    tenantId: input.tenantId,
    authenticator: input.authorizationService,
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
    readByIdV1: async ({ walletAuthMethodId }: { readonly walletAuthMethodId: WalletAuthMethodId }) =>
      await store.readByIdV2({ walletAuthMethodId }),
  };
}
