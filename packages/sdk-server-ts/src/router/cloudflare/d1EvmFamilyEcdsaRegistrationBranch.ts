import {
  computeSdkEcdsaDerivationApplicationBindingDigestB64u,
  computeEcdsaDerivationRoleLocalRelayerKeyId,
  computeEcdsaDerivationRoleLocalThresholdKeyId,
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
  parseSdkEcdsaDerivationThresholdKeyId,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
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
import type { RouterAbEcdsaStrictRegistrationPort } from '../routerAbEcdsaStrictRegistration';

const REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES = 3;

export async function buildD1EvmFamilyEcdsaRegistrationPrepare(input: {
  readonly registrationCeremonyId: string;
  readonly registrationPreparationId: RegistrationPreparationId;
  readonly walletId: WalletId;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly chainTargets: readonly ThresholdEcdsaChainTarget[] | null;
  readonly participantIds: readonly number[];
  readonly runtimePolicyScope: ThresholdRuntimePolicyScope;
  readonly strictRegistration: RouterAbEcdsaStrictRegistrationPort;
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
  const firstChainTarget = input.chainTargets[0];
  if (!firstChainTarget) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ECDSA registration requires at least one chain target',
    };
  }
  const chainTargets: readonly [
    ThresholdEcdsaChainTarget,
    ...ThresholdEcdsaChainTarget[],
  ] = [firstChainTarget, ...input.chainTargets.slice(1)];
  if (
    input.participantIds.length !== 2 ||
    input.participantIds[0] !== 1 ||
    input.participantIds[1] !== 2
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ECDSA registration requires participant pair [1, 2]',
    };
  }
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: input.walletId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
  });
  const ecdsaThresholdKeyId = await computeEcdsaDerivationRoleLocalThresholdKeyId({
    walletId: input.walletId,
    evmFamilySigningKeySlotId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
  });
  const relayerKeyId = await computeEcdsaDerivationRoleLocalRelayerKeyId({
    walletId: input.walletId,
    evmFamilySigningKeySlotId,
  });
  const signingGrantId = `wss_${secureRandomBase64Url(24)}`;
  const thresholdSessionId = `tederivation_${secureRandomBase64Url(24)}`;
  const ttlMs = 10 * 60_000;
  const requestId = `${input.registrationCeremonyId}:ecdsa:evm-family`;
  const prepare = {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: input.walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    keyScope: 'evm-family',
    relayerKeyId,
    registrationPreparationId: input.registrationPreparationId,
    requestId,
    thresholdSessionId,
    signingGrantId,
    ttlMs,
    remainingUses: REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES,
    participantIds: [1, 2],
    runtimePolicyScope: input.runtimePolicyScope,
  } satisfies WalletRegistrationEcdsaPreparePayload['prepare'];
  const topology = input.strictRegistration.topology();
  const applicationBindingDigestB64u =
    await computeSdkEcdsaDerivationApplicationBindingDigestB64u({
      walletId: input.walletId,
      ecdsaThresholdKeyId: parseSdkEcdsaDerivationThresholdKeyId(ecdsaThresholdKeyId),
      signingRootId: parseSdkEcdsaDerivationSigningRootId(input.signingRootId),
      signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(
        input.signingRootVersion,
      ),
    });
  return {
    ok: true,
    ecdsa: {
      kind: 'evm_family_ecdsa_keygen',
      chainTargets,
      prepare,
      strictRegistration: {
        registration_purpose: 'wallet_registration',
        context: {
          application_binding_digest_b64u: applicationBindingDigestB64u,
        },
        lifecycle: {
          lifecycle_id: input.registrationCeremonyId,
          work_kind: 'registration_prepare',
          primitive_request_kind: 'registration',
          root_share_epoch: input.signingRootVersion,
          account_id: String(input.walletId),
          session_id: thresholdSessionId,
          signer_set_id: topology.signerSet.signer_set_id,
          selected_server_id: topology.signerSet.selected_server.server_id,
        },
        signer_set: topology.signerSet,
        router_id: topology.routerId,
        client_id: String(input.walletId),
        replay_nonce: secureRandomBase64Url(24),
        expires_at_ms: Date.now() + ttlMs,
        deriver_recipient_keys: topology.deriverRecipientKeys,
      },
    },
  };
}
