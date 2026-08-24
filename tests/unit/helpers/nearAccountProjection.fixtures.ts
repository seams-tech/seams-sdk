import type { ClientUserData } from '@/core/accountData/near/nearAccountData.types';
import { toAccountId } from '@/core/types/accountIds';

export function nearPasskeyAccountProjectionFixture(args: {
  walletId: string;
  nearAccountId: string;
  operationalPublicKey: string;
  credentialId: string;
}): ClientUserData {
  return {
    walletId: args.walletId,
    nearAccountId: toAccountId(args.nearAccountId),
    loginDisplayName: args.walletId,
    signerSlot: 1,
    operationalPublicKey: args.operationalPublicKey,
    nearEd25519SigningKeyId: `near-ed25519:${args.nearAccountId}`,
    passkeyCredential: {
      id: args.credentialId,
      rawId: args.credentialId,
    },
    authMethod: 'passkey',
  };
}
