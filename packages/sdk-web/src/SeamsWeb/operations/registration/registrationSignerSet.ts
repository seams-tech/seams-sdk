import { THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1 } from '@shared/threshold/secp256k1';
import { THRESHOLD_ED25519_2P_PARTICIPANT_IDS } from '@shared/threshold/participants';
import {
  implicitNearAccountProvisioning,
  sponsoredNamedNearAccountProvisioning,
  type RegisterWalletInput,
  type RegistrationNearAccountProvisioning,
  type RegistrationSignerSetSelection,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { parseNamedNearAccountId } from '@shared/utils/near';
import type {
  SeamsConfigsReadonly,
  SeamsRegistrationNearAccountProvisioning,
} from '@/core/types/seams';
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

export function relayerNamedSubaccountProvisioningFromWalletId(args: {
  walletId: WalletId | string;
  relayerAccountId: string;
}): RegistrationNearAccountProvisioning {
  const walletId = String(args.walletId || '').trim();
  const relayerAccountId = String(args.relayerAccountId || '').trim();
  if (!walletId) throw new Error('Relayer named NEAR registration requires walletId');
  if (!relayerAccountId) {
    throw new Error('Relayer named NEAR registration requires relayer accountId');
  }
  return sponsoredNamedRegistrationProvisioningFromAccountId(`${walletId}.${relayerAccountId}`);
}

export function resolvePasskeyRegistrationAccountProvisioning(args: {
  configs: SeamsConfigsReadonly;
  wallet: RegisterWalletInput;
  preference?: SeamsRegistrationNearAccountProvisioning;
}): RegistrationNearAccountProvisioning {
  const preference = args.preference ?? args.configs.registration.nearAccountProvisioning;
  switch (preference.kind) {
    case 'implicit_account':
      return implicitNearAccountProvisioning();
    case 'relayer_named_subaccount':
      if (args.wallet.kind !== 'provided') {
        throw new Error('Relayer named NEAR registration requires a provided walletId');
      }
      return relayerNamedSubaccountProvisioningFromWalletId({
        walletId: args.wallet.walletId,
        relayerAccountId: args.configs.network.relayer.accountId,
      });
    default: {
      const exhaustive: never = preference;
      return exhaustive;
    }
  }
}
