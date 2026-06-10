import type { AccountId } from '@/core/types/accountIds';
import type {
  EvmEip155ChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
} from '../identity/evmFamilyEcdsaIdentity';
import type {
  EvmFamilyEcdsaTransactionSigningIntent,
  NearEd25519TransactionSigningIntent,
} from './transactionState';
import { SigningSessionIds } from './types';
import type { EcdsaSigningSessionPlanningLane } from './types';

declare const walletId: AccountId;
declare const ecdsaWalletId: WalletId;
declare const chainTarget: EvmEip155ChainTarget;
declare const key: EvmFamilyEcdsaKeyIdentity;
declare const keyHandle: EvmFamilyEcdsaKeyHandle;

const validPlanningLane = {
  authMethod: 'passkey',
  curve: 'ecdsa',
  keyKind: 'threshold_ecdsa_secp256k1',
  chainFamily: chainTarget.kind,
  key,
  keyHandle,
  walletId,
  walletSigningSessionId: SigningSessionIds.walletSigningSession('wallet-signing-session-id'),
  thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('threshold-session-id'),
  sessionOrigin: 'login',
  storageSource: 'login',
  retention: 'session',
  chainTarget,
} satisfies EcdsaSigningSessionPlanningLane;
void validPlanningLane;

const invalidPlanningLaneWithSubjectId = {
  authMethod: 'passkey',
  curve: 'ecdsa',
  keyKind: 'threshold_ecdsa_secp256k1',
  chainFamily: chainTarget.kind,
  key,
  keyHandle,
  walletId,
  walletSigningSessionId: SigningSessionIds.walletSigningSession('wallet-signing-session-id'),
  thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('threshold-session-id'),
  sessionOrigin: 'login',
  storageSource: 'login',
  retention: 'session',
  // @ts-expect-error Base ECDSA planning lanes derive subject from key identity.
  subjectId: 'alice.testnet',
  chainTarget,
} satisfies EcdsaSigningSessionPlanningLane;
void invalidPlanningLaneWithSubjectId;

const validNearTransactionIntent: NearEd25519TransactionSigningIntent = {
  walletId,
  curve: 'ed25519',
  chain: 'near',
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
  walletId,
  curve: 'ecdsa',
  chain: 'evm',
  chainTarget,
  authSelectionPolicy: { kind: 'explicit', authMethod: 'passkey' },
  operationUsesNeeded: 1,
};
void invalidEcdsaTransactionIntent;
