import type { WalletKeyId, WalletKeyRecord } from '@shared/signing-lanes';
import type { WalletId } from '@shared/utils/domainIds';

export type WalletKeyLookup = {
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
};

export interface WalletKeyStore {
  getWalletKey(lookup: WalletKeyLookup): Promise<WalletKeyRecord | null>;
  listWalletKeys(input: { readonly walletId: WalletId }): Promise<readonly WalletKeyRecord[]>;
}
