import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SelectedEcdsaLaneInput } from './laneIdentity';
import type { EvmFamilyEcdsaKeyIdentity } from './evmFamilyEcdsaIdentity';

declare const walletId: AccountId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const key: EvmFamilyEcdsaKeyIdentity;

const validSelectedLane = {
  key,
  keyHandle: 'test-key-handle',
  walletId,
  authMethod: 'passkey',
  walletSigningSessionId: 'wallet-signing-session-id',
  thresholdSessionId: 'threshold-session-id',
  chainTarget,
} satisfies SelectedEcdsaLaneInput;
void validSelectedLane;

const invalidSelectedLaneWithSubjectId = {
  key,
  keyHandle: 'test-key-handle',
  walletId,
  authMethod: 'passkey',
  walletSigningSessionId: 'wallet-signing-session-id',
  thresholdSessionId: 'threshold-session-id',
  // @ts-expect-error Base ECDSA selected lanes derive subject from key identity.
  subjectId: 'alice.testnet',
  chainTarget,
} satisfies SelectedEcdsaLaneInput;
void invalidSelectedLaneWithSubjectId;
