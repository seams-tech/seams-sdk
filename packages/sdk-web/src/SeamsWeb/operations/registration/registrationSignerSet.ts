import { THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1 } from '@shared/threshold/secp256k1';
import { THRESHOLD_ED25519_2P_PARTICIPANT_IDS } from '@shared/threshold/participants';
import {
  implicitNearAccountProvisioning,
  sponsoredNamedNearAccountProvisioning,
  type RegistrationNearAccountProvisioning,
  type RegistrationSignerSetSelection,
} from '@shared/utils/registrationIntent';
import { parseNamedNearAccountId } from '@shared/utils/near';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { RegistrationHooksOptions } from '@/core/types/sdkSentEvents';
import { THRESHOLD_ED25519_HSS_DERIVATION_VERSION } from '@/core/signingEngine/threshold/ed25519/hssClientBase';
import { listThresholdEcdsaProvisionTargets } from '@/SeamsWeb/operations/session/thresholdEcdsaProvisioning';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export function buildNearWalletRegistrationSignerSetSelection(args: {
  configs: SeamsConfigsReadonly;
  accountProvisioning?: RegistrationNearAccountProvisioning;
  options: RegistrationHooksOptions;
  ecdsaChainTargets?: readonly ThresholdEcdsaChainTarget[];
}): RegistrationSignerSetSelection {
  const ed25519 = {
    kind: 'near_ed25519' as const,
    accountProvisioning: args.accountProvisioning ?? implicitNearAccountProvisioning(),
    signerSlot: 1,
    participantIds: [...THRESHOLD_ED25519_2P_PARTICIPANT_IDS],
    derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
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
      kind: 'signer_set',
      signers: [ed25519],
    };
  }

  return {
    kind: 'signer_set',
    signers: [
      ed25519,
      {
        kind: 'evm_family_ecdsa',
        chainTargets: [...ecdsaChainTargets],
        participantIds: [...THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1.participantIds],
      },
    ],
  };
}

export function sponsoredNamedRegistrationProvisioningFromAccountId(
  nearAccountId: string,
): RegistrationNearAccountProvisioning {
  const parsed = parseNamedNearAccountId(nearAccountId);
  if (!parsed.ok) {
    throw new Error(parsed.message);
  }
  return sponsoredNamedNearAccountProvisioning(parsed.value);
}
