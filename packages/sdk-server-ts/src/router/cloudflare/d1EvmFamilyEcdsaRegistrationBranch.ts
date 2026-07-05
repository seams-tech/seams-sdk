import {
  computeEcdsaHssRoleLocalRelayerKeyId,
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import type { WalletId } from '@shared/utils/registrationIntent';
import type {
  ThresholdEcdsaChainTarget,
  ThresholdRuntimePolicyScope
} from '../../core/types';
import type {
  RegistrationPreparationId,
  WalletRegistrationEcdsaPreparePayload
} from '../../core/registrationContracts';
import { deriveEvmFamilySigningKeySlotId } from './d1RegistrationCeremonyRecords';
import { thresholdEcdsaChainTargetKey } from '../../core/thresholdEcdsaChainTarget';

const REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES = 3;

export async function buildD1EvmFamilyEcdsaRegistrationPrepare(input: {
  readonly registrationCeremonyId: string;
  readonly registrationPreparationId?: RegistrationPreparationId;
  readonly walletId: WalletId;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly chainTargets: readonly ThresholdEcdsaChainTarget[] | null;
  readonly participantIds: readonly number[];
  readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): Promise<
  | { ok: true; ecdsa: WalletRegistrationEcdsaPreparePayload }
  | { ok: false; code: string; message: string }
> {
  if (!input.chainTargets) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ECDSA registration contains an invalid chain target',
    };
  }
  if (input.chainTargets.length === 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ECDSA registration requires at least one chain target',
    };
  }
  const targets: WalletRegistrationEcdsaPreparePayload['targets'] = [];
  for (const chainTarget of input.chainTargets) {
    const chainTargetKey = thresholdEcdsaChainTargetKey(chainTarget);
    const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
      walletId: input.walletId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
      chainTargetKey,
    });
    const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
      walletId: input.walletId,
      evmFamilySigningKeySlotId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    });
    const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
      walletId: input.walletId,
      evmFamilySigningKeySlotId,
    });
    targets.push({
      chainTarget,
      prepare: {
        formatVersion: 'ecdsa-hss-role-local',
        walletId: input.walletId,
        evmFamilySigningKeySlotId,
        ecdsaThresholdKeyId,
        signingRootId: input.signingRootId,
        signingRootVersion: input.signingRootVersion,
        keyScope: 'evm-family',
        relayerKeyId,
        ...(input.registrationPreparationId
          ? { registrationPreparationId: input.registrationPreparationId }
          : {}),
        requestId: `${input.registrationCeremonyId}:ecdsa:${encodeURIComponent(chainTargetKey)}`,
        thresholdSessionId: `tehss_${secureRandomBase64Url(24)}`,
        signingGrantId: `wss_${secureRandomBase64Url(24)}`,
        ttlMs: 10 * 60_000,
        remainingUses: REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES,
        participantIds: [...input.participantIds],
        ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
      },
    });
  }
  return {
    ok: true,
    ecdsa: {
      kind: 'evm_family_ecdsa_keygen',
      targets,
    },
  };
}
