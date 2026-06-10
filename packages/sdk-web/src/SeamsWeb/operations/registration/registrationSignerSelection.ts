import { THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1 } from '@shared/threshold/secp256k1';
import { THRESHOLD_ED25519_2P_PARTICIPANT_IDS } from '@shared/threshold/participants';
import type { RegistrationSignerSelection } from '@shared/utils/registrationIntent';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { RegistrationHooksOptions } from '@/core/types/sdkSentEvents';
import {
  THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1,
} from '@/SeamsWeb/operations/session/thresholdWarmSessionBootstrap';
import {
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from '@/core/signingEngine/threshold/ed25519/hssClientBase';
import { listThresholdEcdsaProvisionTargets } from '@/SeamsWeb/operations/session/thresholdEcdsaProvisioning';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export function buildNearWalletRegistrationSignerSelection(args: {
  configs: SeamsConfigsReadonly;
  nearAccountId: string;
  options: RegistrationHooksOptions;
  ecdsaChainTargets?: readonly ThresholdEcdsaChainTarget[];
}): RegistrationSignerSelection {
  const ed25519 = {
    nearAccountId: args.nearAccountId,
    signerSlot: 1,
    participantIds: [...THRESHOLD_ED25519_2P_PARTICIPANT_IDS],
    keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
    keyVersion: THRESHOLD_ED25519_SINGLE_KEY_HSS_KEY_VERSION_V1,
    derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
    createNearAccount: true,
  };
  const ecdsaChainTargets =
    args.ecdsaChainTargets ??
    listThresholdEcdsaProvisionTargets({
      signerOptions:
        args.options.signerOptions ?? args.configs.signing.thresholdEcdsa.provisioningDefaults,
      chains: args.configs.network.chains,
    }).map((target) => target.chainTarget);

  if (!ecdsaChainTargets.length) {
    return {
      mode: 'ed25519_only',
      ed25519,
    };
  }

  return {
    mode: 'ed25519_and_ecdsa',
    ed25519,
    ecdsa: {
      chainTargets: [...ecdsaChainTargets],
      participantIds: [...THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1.participantIds],
    },
  };
}
