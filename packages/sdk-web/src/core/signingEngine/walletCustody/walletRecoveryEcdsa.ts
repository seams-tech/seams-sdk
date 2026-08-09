import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  closeRouterAbEcdsaPostRegistrationCeremonyWasm,
  createRouterAbEcdsaPostRegistrationCeremonyWasm,
  verifyRouterAbEcdsaPostRegistrationProofsWasm,
} from '@/core/signingEngine/threshold/crypto/ecdsaDerivationClientWasm';
import {
  routerAbEcdsaActivationRefresh,
  routerAbEcdsaRecovery,
} from '@/core/rpcClients/relayer/thresholdEcdsa';
import type { WalletRecoveryPreparationKeyManifestEntry } from '@/core/rpcClients/relayer/walletRecoveryPrepare';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  buildMpcMaterialActivationRef,
  parseMpcLifecycleBindingRef,
  parseMpcMaterialActivationId,
  parseRootShareEpoch,
} from '@shared/utils/domainIds';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { SigningSessionIds } from '@shared/utils/signingSessionIds';
import {
  deriveWalletRecoveryKeyLifecycleId,
  parseRecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import type {
  RouterAbEcdsaDerivationPublicCapabilityV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { parseRouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';

type EcdsaRecoveryEntry = Extract<
  WalletRecoveryPreparationKeyManifestEntry,
  { readonly kind: 'evm_family_ecdsa' }
>;

export type WalletRecoveryEcdsaActivation = {
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly relayerPublicIdentityJson: string;
};

async function recoveryBindingDigest(input: {
  readonly reservationId: string;
  readonly keySetId: string;
  readonly operation: 'recovery' | 'refresh';
}): Promise<string> {
  return base64UrlEncode(
    await sha256BytesUtf8(
      alphabetizeStringify({
        domain: 'seams/wallet-recovery/ecdsa-authorization/v1',
        reservationId: input.reservationId,
        keySetId: input.keySetId,
        operation: input.operation,
      }),
    ),
  );
}

function freshMaterialActivation(input: {
  readonly lifecycleId: string;
  readonly current: RouterAbEcdsaDerivationPublicCapabilityV1['material_activation'];
}): RouterAbEcdsaDerivationPublicCapabilityV1['material_activation'] {
  const activationId = parseMpcMaterialActivationId(
    secureRandomId(
      'wallet-recovery-ecdsa-material-activation',
      32,
      'wallet recovery ECDSA activation identities',
    ),
  );
  const lifecycleBinding = parseMpcLifecycleBindingRef(
    `${input.lifecycleId}:material-activation`,
  );
  if (!activationId.ok || !lifecycleBinding.ok) {
    throw new Error('wallet recovery ECDSA material activation identity is invalid');
  }
  const activation = buildMpcMaterialActivationRef({
    activationId: activationId.value,
    capability: input.current.capability,
    materialOwner: input.current.material_owner,
    keyBinding: input.current.key_binding,
    lifecycleBinding: lifecycleBinding.value,
    signingWorker: input.current.signing_worker,
  });
  return {
    kind: activation.kind,
    activation_id: activation.activationId,
    capability: activation.capability,
    material_owner: activation.materialOwner,
    key_binding: activation.keyBinding,
    lifecycle_binding: activation.lifecycleBinding,
    signing_worker: activation.signingWorker,
  };
}

function refreshedPublicCapability(input: {
  readonly current: RouterAbEcdsaDerivationPublicCapabilityV1;
  readonly activationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly proofTranscriptDigestB64u: string;
}): RouterAbEcdsaDerivationPublicCapabilityV1 {
  return parseRouterAbEcdsaDerivationPublicCapabilityV1({
    ...input.current,
    material_activation: input.activationReceipt.ecdsa_activation.material_activation,
    activation_epoch: input.activationReceipt.ecdsa_activation.activation_epoch,
    proof_transcript_digest_b64u: input.proofTranscriptDigestB64u,
  });
}

function sharedProofTranscriptDigest(input: {
  readonly signerA: { readonly transcriptDigestB64u: string };
  readonly signerB: { readonly transcriptDigestB64u: string };
}): string {
  if (input.signerA.transcriptDigestB64u !== input.signerB.transcriptDigestB64u) {
    throw new Error('wallet recovery ECDSA proof bundles changed the transcript');
  }
  return input.signerA.transcriptDigestB64u;
}

function ethereumAddressFromAddress20B64u(value: string): `0x${string}` {
  const address = base64UrlDecode(value);
  if (address.length !== 20) {
    throw new Error('wallet recovery ECDSA identity has an invalid address');
  }
  return `0x${Array.from(address, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

async function closeWalletRecoveryEcdsaCeremony(input: {
  readonly workerCtx: WorkerOperationContext;
  readonly ceremonyId: string;
}): Promise<void> {
  await closeRouterAbEcdsaPostRegistrationCeremonyWasm({
    workerCtx: input.workerCtx,
    command: {
      kind: 'close_router_ab_ecdsa_post_registration_ceremony_v1',
      ceremonyId: input.ceremonyId,
    },
  });
}

export async function recoverAndRefreshWalletCustodyEcdsaV1(input: {
  readonly entry: EcdsaRecoveryEntry;
  readonly reservationId: string;
  readonly reservationExpiresAtMs: number;
  readonly relayUrl: string;
  readonly recoveryAuthorizationJwt: string;
  readonly workerCtx: WorkerOperationContext;
}): Promise<WalletRecoveryEcdsaActivation> {
  const reservationId = parseRecoveryCodeReservationId(input.reservationId);
  const lifecycleId = await deriveWalletRecoveryKeyLifecycleId({
    reservationId,
    keySetId: input.entry.keySetId,
  });
  const current = input.entry.recoveryBasis.publicCapability;
  const sessionId = SigningSessionIds.thresholdEcdsaSession(String(lifecycleId));
  const recoveryNonce = secureRandomId(
    'wallet-recovery-ecdsa-recovery',
    24,
    'wallet recovery ECDSA request nonces',
  );
  const auth = {
    kind: 'wallet_recovery' as const,
    jwt: input.recoveryAuthorizationJwt,
    reservationId: String(reservationId),
    keySetId: input.entry.keySetId,
  };
  const recovery = await createRouterAbEcdsaPostRegistrationCeremonyWasm({
    workerCtx: input.workerCtx,
    command: {
      kind: 'create_router_ab_ecdsa_recovery_ceremony_v1',
      ceremonyId: `${lifecycleId}:recovery`,
      request: {
        context: current.context,
        lifecycle: {
          lifecycle_id: lifecycleId,
          work_kind: 'recovery',
          primitive_request_kind: 'recovery',
          root_share_epoch: current.activation_epoch,
          account_id: current.client_id,
          session_id: sessionId,
          signer_set_id: current.signer_set.signer_set_id,
          selected_server_id: current.signer_set.selected_server.server_id,
        },
        public_identity: current.public_identity,
        signer_set: current.signer_set,
        router_id: current.router_id,
        client_id: current.client_id,
        recovery_authorization_digest_b64u: await recoveryBindingDigest({
          reservationId,
          keySetId: input.entry.keySetId,
          operation: 'recovery',
        }),
        recovery_nonce: recoveryNonce,
        expires_at_ms: input.reservationExpiresAtMs,
        deriver_recipient_keys: current.deriver_recipient_keys,
      },
    },
  });
  if (recovery.kind !== 'router_ab_ecdsa_recovery_ceremony_created_v1') {
    throw new Error('wallet recovery created the wrong ECDSA ceremony');
  }
  try {
    const forwarded = await routerAbEcdsaRecovery(input.relayUrl, {
      request: recovery.request,
      requestDigestB64u: recovery.requestDigestB64u,
      auth,
    });
    if (!forwarded.ok) {
      throw new Error(
        forwarded.error || forwarded.message || forwarded.code || 'ECDSA recovery failed',
      );
    }
    await verifyRouterAbEcdsaPostRegistrationProofsWasm({
      workerCtx: input.workerCtx,
      command: {
        kind: 'verify_router_ab_ecdsa_post_registration_proofs_v1',
        ceremonyId: recovery.ceremonyId,
        clientProofFinalization: {
          kind: 'finalize_encrypted_client_proof_bundles_v1',
          bundles: forwarded.value.response.bundles,
        },
      },
    });
  } catch (error) {
    await closeWalletRecoveryEcdsaCeremony({
      workerCtx: input.workerCtx,
      ceremonyId: recovery.ceremonyId,
    }).catch(() => undefined);
    throw error;
  }
  await closeWalletRecoveryEcdsaCeremony({
    workerCtx: input.workerCtx,
    ceremonyId: recovery.ceremonyId,
  });

  const nextEpoch = parseRootShareEpoch(
    secureRandomId(
      'wallet-recovery-ecdsa-activation-epoch',
      24,
      'wallet recovery ECDSA activation epochs',
    ),
  );
  if (!nextEpoch.ok) throw new Error('wallet recovery ECDSA activation epoch is invalid');
  const refreshNonce = secureRandomId(
    'wallet-recovery-ecdsa-refresh',
    24,
    'wallet recovery ECDSA refresh nonces',
  );
  const nextMaterialActivation = freshMaterialActivation({
    lifecycleId,
    current: current.material_activation,
  });
  const refresh = await createRouterAbEcdsaPostRegistrationCeremonyWasm({
    workerCtx: input.workerCtx,
    command: {
      kind: 'create_router_ab_ecdsa_activation_refresh_ceremony_v1',
      ceremonyId: `${lifecycleId}:refresh`,
      publicCapability: current,
      request: {
        context: current.context,
        lifecycle: {
          lifecycle_id: lifecycleId,
          work_kind: 'server_share_refresh',
          primitive_request_kind: 'refresh',
          root_share_epoch: nextEpoch.value,
          account_id: current.client_id,
          session_id: sessionId,
          signer_set_id: current.signer_set.signer_set_id,
          selected_server_id: current.signer_set.selected_server.server_id,
        },
        public_identity: current.public_identity,
        signer_set: current.signer_set,
        router_id: current.router_id,
        client_id: current.client_id,
        refresh_authorization_digest_b64u: await recoveryBindingDigest({
          reservationId,
          keySetId: input.entry.keySetId,
          operation: 'refresh',
        }),
        refresh_nonce: refreshNonce,
        previous_activation_epoch: current.activation_epoch,
        next_activation_epoch: nextEpoch.value,
        material_activation: nextMaterialActivation,
        expires_at_ms: input.reservationExpiresAtMs,
        deriver_recipient_keys: current.deriver_recipient_keys,
      },
    },
  });
  if (refresh.kind !== 'router_ab_ecdsa_activation_refresh_ceremony_created_v1') {
    throw new Error('wallet recovery created the wrong ECDSA refresh ceremony');
  }
  try {
    const forwarded = await routerAbEcdsaActivationRefresh(input.relayUrl, {
      request: {
        activation_correlation_id: lifecycleId,
        expected_server_generation: input.entry.recoveryBasis.serverGeneration,
        refresh_request: refresh.request,
      },
      requestDigestB64u: refresh.requestDigestB64u,
      auth,
    });
    if (!forwarded.ok) {
      throw new Error(
        forwarded.error || forwarded.message || forwarded.code || 'ECDSA refresh failed',
      );
    }
    if (forwarded.value.result !== 'forwarded') {
      throw new Error(`ECDSA refresh did not return fresh proof bundles (${forwarded.value.result})`);
    }
    sharedProofTranscriptDigest(forwarded.value.response.bundles);
    await verifyRouterAbEcdsaPostRegistrationProofsWasm({
      workerCtx: input.workerCtx,
      command: {
        kind: 'verify_router_ab_ecdsa_post_registration_proofs_v1',
        ceremonyId: refresh.ceremonyId,
        clientProofFinalization: {
          kind: 'finalize_encrypted_client_proof_bundles_v1',
          bundles: forwarded.value.response.bundles,
        },
      },
    });
    const activationReceipt = forwarded.value.signing_worker_activation;
    const publicCapability = refreshedPublicCapability({
      current,
      activationReceipt,
      proofTranscriptDigestB64u: base64UrlEncode(
        Uint8Array.from(activationReceipt.transcript_digest.bytes),
      ),
    });
    const identity = activationReceipt.ecdsa_activation.public_identity;
    const activation = {
      activationReceipt,
      publicCapability,
      relayerPublicIdentityJson: JSON.stringify({
        relayerKeyId: current.signer_set.selected_server.server_id,
        relayerPublicKey33B64u: identity.server_public_key33_b64u,
        groupPublicKey33B64u: identity.threshold_public_key33_b64u,
        ethereumAddress: ethereumAddressFromAddress20B64u(identity.ethereum_address20_b64u),
        relayerShareRetryCounter: identity.server_share_retry_counter,
      }),
    };
    await closeWalletRecoveryEcdsaCeremony({
      workerCtx: input.workerCtx,
      ceremonyId: refresh.ceremonyId,
    });
    return activation;
  } catch (error) {
    await closeWalletRecoveryEcdsaCeremony({
      workerCtx: input.workerCtx,
      ceremonyId: refresh.ceremonyId,
    }).catch(() => undefined);
    throw error;
  }
}
