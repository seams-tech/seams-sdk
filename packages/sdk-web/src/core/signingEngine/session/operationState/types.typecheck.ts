import type { AccountId } from '@/core/types/accountIds';
import type {
  EvmEip155ChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EvmFamilyEcdsaKeyHandle,
  EvmFamilyEcdsaKeyIdentity,
} from '../identity/evmFamilyEcdsaIdentity';
import type { ExactEcdsaSigningLaneIdentity } from '../identity/exactSigningLaneIdentity';
import { toRpId } from '../identity/evmFamilyEcdsaIdentity';
import type {
  EvmFamilyEcdsaTransactionSigningIntent,
  NearEd25519TransactionSigningIntent,
} from './transactionState';
import { SigningSessionIds } from './types';
import type { EcdsaSigningSessionPlanningLane } from './types';

declare const walletId: WalletId;
declare const accountId: AccountId;
declare const ecdsaWalletId: WalletId;
declare const chainTarget: EvmEip155ChainTarget;
declare const key: EvmFamilyEcdsaKeyIdentity;
declare const keyHandle: EvmFamilyEcdsaKeyHandle;
declare const exactEcdsaIdentity: ExactEcdsaSigningLaneIdentity;

const validPlanningLane = {
  identity: exactEcdsaIdentity,
  auth: {
    kind: 'passkey',
    rpId: toRpId('localhost'),
    credentialIdB64u: 'credential-id',
  },
  curve: 'ecdsa',
  keyKind: 'threshold_ecdsa_secp256k1',
  chainFamily: chainTarget.kind,
	  signingGrantId: SigningSessionIds.signingGrant('signing-grant-id'),
	  thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('threshold-session-id'),
	  runtimeState: 'no_runtime_material',
	  sessionOrigin: 'login',
  storageSource: 'login',
  retention: 'session',
} satisfies EcdsaSigningSessionPlanningLane;
void validPlanningLane;

const invalidPlanningLaneWithSubjectId = {
  identity: exactEcdsaIdentity,
  auth: {
    kind: 'passkey',
    rpId: toRpId('localhost'),
    credentialIdB64u: 'credential-id',
  },
  curve: 'ecdsa',
  keyKind: 'threshold_ecdsa_secp256k1',
  chainFamily: chainTarget.kind,
  signingGrantId: SigningSessionIds.signingGrant('signing-grant-id'),
  thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('threshold-session-id'),
  runtimeState: 'no_runtime_material',
  sessionOrigin: 'login',
  storageSource: 'login',
  retention: 'session',
  // @ts-expect-error Base ECDSA planning lanes derive subject from key identity.
  subjectId: 'alice.testnet',
} satisfies EcdsaSigningSessionPlanningLane;
void invalidPlanningLaneWithSubjectId;

const invalidPlanningLaneWithRootKey = {
  ...validPlanningLane,
  // @ts-expect-error ECDSA planning lanes read key identity from identity.signer.
  key,
} satisfies EcdsaSigningSessionPlanningLane;
void invalidPlanningLaneWithRootKey;

const invalidPlanningLaneWithRootChainTarget = {
  ...validPlanningLane,
  // @ts-expect-error ECDSA planning lanes read chain target from identity.signer.
  chainTarget,
} satisfies EcdsaSigningSessionPlanningLane;
void invalidPlanningLaneWithRootChainTarget;

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
