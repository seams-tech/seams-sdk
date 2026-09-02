import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { SelectedEcdsaLaneInput } from './laneIdentity';
import { toRpId, type EvmFamilyEcdsaKeyIdentity } from './evmFamilyEcdsaIdentity';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { ExactEvmFamilyWalletSessionAuthorization } from '../material/ecdsaSigningCapability';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const key: EvmFamilyEcdsaKeyIdentity;
declare const materialActivation: MpcMaterialActivationRef;
declare const authorization: ExactEvmFamilyWalletSessionAuthorization;

const validSelectedLane = {
  key,
  materialActivation,
  keyHandle: 'test-key-handle',
  walletId,
  auth: {
    kind: 'passkey',
    rpId: toRpId('localhost'),
    credentialIdB64u: 'credential-id',
  },
  authorization,
  chainTarget,
} satisfies SelectedEcdsaLaneInput;
void validSelectedLane;

const invalidSelectedLaneWithSubjectId = {
  key,
  materialActivation,
  keyHandle: 'test-key-handle',
  walletId,
  auth: {
    kind: 'passkey',
    rpId: toRpId('localhost'),
    credentialIdB64u: 'credential-id',
  },
  authorization,
  // @ts-expect-error Base ECDSA selected lanes derive subject from key identity.
  subjectId: 'alice.testnet',
  chainTarget,
} satisfies SelectedEcdsaLaneInput;
void invalidSelectedLaneWithSubjectId;
