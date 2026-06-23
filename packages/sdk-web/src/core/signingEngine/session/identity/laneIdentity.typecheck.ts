import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SelectedEcdsaLaneInput } from './laneIdentity';
import type { EvmFamilyEcdsaKeyIdentity } from './evmFamilyEcdsaIdentity';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const key: EvmFamilyEcdsaKeyIdentity;

const validSelectedLane = {
  key,
  keyHandle: 'test-key-handle',
  walletId,
  authMethod: 'passkey',
  signingGrantId: 'signing-grant-id',
  thresholdSessionId: 'threshold-session-id',
  chainTarget,
} satisfies SelectedEcdsaLaneInput;
void validSelectedLane;

const invalidSelectedLaneWithSubjectId = {
  key,
  keyHandle: 'test-key-handle',
  walletId,
  authMethod: 'passkey',
  signingGrantId: 'signing-grant-id',
  thresholdSessionId: 'threshold-session-id',
  // @ts-expect-error Base ECDSA selected lanes derive subject from key identity.
  subjectId: 'alice.testnet',
  chainTarget,
} satisfies SelectedEcdsaLaneInput;
void invalidSelectedLaneWithSubjectId;
