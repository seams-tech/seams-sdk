import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { SigningSessionSealAuthMethod } from '@shared/utils/signingSessionSeal';

export type EcdsaSealedRecordKeyInput = {
  walletId: string;
  authMethod: SigningSessionSealAuthMethod;
  chainTarget: ThresholdEcdsaChainTarget;
  materialActivation: MpcMaterialActivationRef;
};

export function ecdsaSealedRecordStoreKey(args: EcdsaSealedRecordKeyInput): string {
  return [
    'ecdsa-material-v2',
    args.walletId,
    args.authMethod,
    thresholdEcdsaChainTargetKey(args.chainTarget),
    args.materialActivation.activationId,
    args.materialActivation.capability,
    args.materialActivation.materialOwner,
    args.materialActivation.keyBinding,
    args.materialActivation.lifecycleBinding,
    args.materialActivation.signingWorker,
  ]
    .map((part) => encodeURIComponent(String(part)))
    .join(':');
}
