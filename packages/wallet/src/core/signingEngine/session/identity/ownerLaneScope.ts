import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { walletAuthMethodRecordId } from '@shared/utils/registrationIntent';
import { parseSignerSlot } from '@shared/utils/signerSlot';
import type { LocalWalletAuthMethodRecord } from '@/core/indexedDB/passkeyClientDB.types';
import { toRpId } from './evmFamilyEcdsaIdentity';
import type { OwnerLaneScope } from './signingLaneAuthBinding';

export type OwnerLaneScopeStores = {
  listWalletAuthMethodsForWallet(
    walletId: string,
  ): Promise<readonly LocalWalletAuthMethodRecord[]>;
  getWalletPasskeyAuthenticator(args: {
    walletId: string;
    credentialId: string;
  }): Promise<{ readonly credentialId: string; readonly signerSlot: number } | null>;
};

export class OwnerLaneScopeIntegrityError extends Error {
  constructor(message: string) {
    super(`[OwnerLaneScope] ${message}`);
    this.name = 'OwnerLaneScopeIntegrityError';
  }
}

/**
 * R103C owner derivation chain: active Wallet Session authority -> one active
 * wallet auth method -> exact credential -> exact local authenticator and
 * signer slot (Passkey only). Every value comes from the previous link.
 * Missing or duplicate records are integrity failures — timestamps, labels,
 * and slot searches never select another owner.
 */
export async function resolveOwnerLaneScope(args: {
  readonly authorityRef: WalletAuthAuthorityRef;
  readonly stores: OwnerLaneScopeStores;
}): Promise<OwnerLaneScope> {
  const walletId = String(args.authorityRef.walletId);
  const expectedAuthMethodId = String(args.authorityRef.walletAuthMethodId);
  const authMethods = await args.stores.listWalletAuthMethodsForWallet(walletId);
  const matches = authMethods.filter(
    (record) =>
      record.status === 'active' &&
      String(record.walletId) === walletId &&
      String(walletAuthMethodRecordId(record)) === expectedAuthMethodId,
  );
  const [authMethod] = matches;
  if (!authMethod) {
    throw new OwnerLaneScopeIntegrityError(
      `active authority has no active wallet auth method (${expectedAuthMethodId})`,
    );
  }
  if (matches.length > 1) {
    throw new OwnerLaneScopeIntegrityError(
      `active authority resolves ${matches.length} wallet auth methods (${expectedAuthMethodId})`,
    );
  }
  if (authMethod.kind === 'email_otp') {
    return {
      auth: {
        kind: 'email_otp',
        providerSubjectId: String(authMethod.authority.factor.providerUserId),
      },
    };
  }
  const authenticator = await args.stores.getWalletPasskeyAuthenticator({
    walletId,
    credentialId: authMethod.credentialIdB64u,
  });
  if (!authenticator || authenticator.credentialId !== authMethod.credentialIdB64u) {
    throw new OwnerLaneScopeIntegrityError(
      'active Passkey auth method has no exact local authenticator',
    );
  }
  const signerSlot = parseSignerSlot(authenticator.signerSlot, { min: 1 });
  if (signerSlot === null) {
    throw new OwnerLaneScopeIntegrityError('local authenticator signer slot is invalid');
  }
  return {
    auth: {
      kind: 'passkey',
      rpId: toRpId(authMethod.rpId),
      credentialIdB64u: authMethod.credentialIdB64u,
    },
    signerSlot,
  };
}
