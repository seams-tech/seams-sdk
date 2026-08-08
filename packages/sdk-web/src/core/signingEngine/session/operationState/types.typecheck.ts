import type { AccountId } from '@/core/types/accountIds';
import type {
  EvmEip155ChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaTransactionSigningIntent,
  NearEd25519TransactionSigningIntent,
} from './transactionState';

declare const walletId: WalletId;
declare const accountId: AccountId;
declare const ecdsaWalletId: WalletId;
declare const chainTarget: EvmEip155ChainTarget;

const validNearTransactionIntent: NearEd25519TransactionSigningIntent = {
  walletId,
  curve: 'ed25519',
  chain: 'near',
  signerSelection: { kind: 'near_account', nearAccountId: accountId },
  authSelectionPolicy: { kind: 'explicit', authMethod: 'passkey' },
  operationUsesNeeded: 1,
};
void validNearTransactionIntent;

const validEcdsaTransactionIntent: EvmFamilyEcdsaTransactionSigningIntent = {
  walletId: ecdsaWalletId,
  curve: 'ecdsa',
  chain: 'evm',
  chainTarget,
  authSelectionPolicy: { kind: 'explicit', authMethod: 'passkey' },
  operationUsesNeeded: 1,
};
void validEcdsaTransactionIntent;

const validAuthNeutralEcdsaTransactionIntent: EvmFamilyEcdsaTransactionSigningIntent = {
  walletId: ecdsaWalletId,
  curve: 'ecdsa',
  chain: 'evm',
  chainTarget,
  authSelectionPolicy: { kind: 'any' },
  operationUsesNeeded: 1,
};
void validAuthNeutralEcdsaTransactionIntent;

const invalidAuthNeutralEcdsaTransactionIntent: EvmFamilyEcdsaTransactionSigningIntent = {
  walletId: ecdsaWalletId,
  curve: 'ecdsa',
  chain: 'evm',
  chainTarget,
  authSelectionPolicy: {
    kind: 'any',
    // @ts-expect-error auth-neutral selection cannot carry a concrete auth method.
    authMethod: 'passkey',
  },
  operationUsesNeeded: 1,
};
void invalidAuthNeutralEcdsaTransactionIntent;

const invalidEcdsaTransactionIntent: EvmFamilyEcdsaTransactionSigningIntent = {
  // @ts-expect-error ECDSA transaction intents require WalletId.
  walletId: accountId,
  curve: 'ecdsa',
  chain: 'evm',
  chainTarget,
  authSelectionPolicy: { kind: 'explicit', authMethod: 'passkey' },
  operationUsesNeeded: 1,
};
void invalidEcdsaTransactionIntent;
