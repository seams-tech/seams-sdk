import type { AccountId } from '@/core/types/accountIds';
import type { TransactionContext } from '@/core/types/rpc';
import type { WalletId } from '../interfaces/ecdsaChainTarget';
import type { NonceLeaseRef } from '../interfaces/nonceLease';
import type { PreparedNonceOperationContext } from './nonceTypes';

export type NearFundingSubject = Readonly<{
  walletId: WalletId;
  nearAccountId: AccountId;
  nearPublicKeyStr: string;
}>;

export type NearFundingRequest = Readonly<{
  subject: NearFundingSubject;
  operation: PreparedNonceOperationContext;
  signatureUses: number;
}>;

export type NearTransactionReadiness =
  | {
      kind: 'context_ready';
      transactionContext: TransactionContext;
      nonceLeases: NonceLeaseRef[];
      request?: never;
    }
  | {
      kind: 'funding_required';
      request: NearFundingRequest;
      transactionContext?: never;
      nonceLeases?: never;
    };
