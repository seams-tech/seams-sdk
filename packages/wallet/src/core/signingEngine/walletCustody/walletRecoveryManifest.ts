import type { WorkerOperationContext } from '../workerManager/executeWorkerOperation';
import type { WalletCustodyCeremonyStepRunner } from './ceremonyDriver';
import {
  recoverEvmFamilyCustodyV1,
  recoverNearEd25519CustodyV1,
  type RecoveryFactorReplacement,
} from './registrationCeremony';
import {
  activateWalletRecoveryEd25519V1,
  admitWalletRecoveryEd25519V1,
  buildWalletRecoveryEd25519AdmissionRequestV1,
  executeWalletRecoveryEd25519RoundV1,
} from './walletRecoveryEd25519';
import {
  signRecoveredWalletCustodyEcdsa,
  type WalletRecoveryEcdsaActivation,
} from './walletRecoveryEcdsa';
import { walletRecoveryEd25519ActiveClientMetadataV1 } from './ceremonyActiveClientMetadata';
import { buildRecoveredCustodyEnvelopeRecord } from './recoveryReplacementEnvelope';
import type {
  PreparedWalletRecovery,
  WalletRecoveryPreparationKeyManifestEntry,
} from '@/core/rpcClients/relayer/walletRecoveryPrepare';
import {
  RouterAbEd25519YaoHttpActivationTransportV1,
  type RouterAbEd25519YaoActiveClientMetadataV1,
} from '../threshold/ed25519/yaoClient';
import type {
  PasskeyCustodyEnvelopeRecord,
  RecoveryReplacementEnvelopePayload,
  WalletCustodyEnvelopeFactor,
  WalletCustodyEvmFamilyPublicFacts,
} from '@shared/passkey-custody';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import type {
  WalletAuthMethodId,
  WalletId,
} from '@shared/utils/domainIds';

type NearRecoveryEntry = Extract<
  WalletRecoveryPreparationKeyManifestEntry,
  { readonly kind: 'near_ed25519' }
>;

type EcdsaRecoveryEntry = Extract<
  WalletRecoveryPreparationKeyManifestEntry,
  { readonly kind: 'evm_family_ecdsa' }
>;

export type RecoveredWalletCustodyNearKeySetV1 = {
  readonly entry: NearRecoveryEntry;
  readonly metadata: RouterAbEd25519YaoActiveClientMetadataV1;
  readonly localMaterial: {
    readonly b64u: string;
    readonly nonceB64u: string;
    readonly applicationBindingDigestB64u: string;
  };
};

export type RecoveredWalletCustodyEcdsaKeySetV1 = {
  readonly entry: EcdsaRecoveryEntry;
  readonly activation: WalletRecoveryEcdsaActivation;
  readonly readyStateBlobB64u: string;
  readonly publicFacts: WalletCustodyEvmFamilyPublicFacts;
};

export type RecoveredWalletCustodyManifestV1 = {
  readonly replacementEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly nearKeySets: readonly RecoveredWalletCustodyNearKeySetV1[];
  readonly ecdsaKeySets: readonly RecoveredWalletCustodyEcdsaKeySetV1[];
};

export type WalletRecoveryReplacementFactorInput = {
  readonly replacementId: string;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly factor: WalletCustodyEnvelopeFactor;
  readonly factorSecret: ArrayBuffer;
};

function replacementForEntry(input: {
  readonly entryIndex: number;
  readonly replacementFactor: WalletRecoveryReplacementFactorInput;
}): RecoveryFactorReplacement {
  if (input.entryIndex !== 0) return { kind: 'preserve_existing' };
  return {
    kind: 'reseal_replacement_factor',
    factorJson: JSON.stringify({
      envelopeId: input.replacementFactor.replacementId,
      walletAuthMethodId: input.replacementFactor.walletAuthMethodId,
      factor: input.replacementFactor.factor,
    }),
    factorSecret: input.replacementFactor.factorSecret.slice(0),
  };
}

function recoveryCodeBuffer(bytes: Uint8Array): ArrayBuffer {
  return Uint8Array.from(bytes).buffer;
}

function zeroizeFactorReplacement(replacement: RecoveryFactorReplacement): void {
  if (replacement.kind === 'reseal_replacement_factor') {
    new Uint8Array(replacement.factorSecret).fill(0);
  }
}

function ethereumAddressFromAddress20B64u(value: string): `0x${string}` {
  const address = base64UrlDecode(value);
  if (address.length !== 20)
    throw new Error('wallet recovery ECDSA identity has an invalid address');
  return `0x${Array.from(address, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

function requireMatchingEcdsaBootstrap(input: {
  readonly entry: EcdsaRecoveryEntry;
  readonly bootstrap: {
    readonly contextBinding32B64u: string;
    readonly clientSharePublicKey33B64u: string;
    readonly clientShareRetryCounter: number;
  };
}): void {
  const identity = input.entry.recoveryBasis.publicCapability.public_identity;
  if (
    input.bootstrap.contextBinding32B64u !== identity.context_binding_b64u ||
    input.bootstrap.clientSharePublicKey33B64u !==
      identity.derivation_client_share_public_key33_b64u ||
    input.bootstrap.clientShareRetryCounter !== identity.client_share_retry_counter
  ) {
    throw new Error(`wallet recovery changed ECDSA identity for ${input.entry.keySetId}`);
  }
}

function recordReplacementEnvelope(input: {
  readonly current: RecoveryReplacementEnvelopePayload | null;
  readonly candidate: RecoveryReplacementEnvelopePayload | null;
}): RecoveryReplacementEnvelopePayload | null {
  if (!input.candidate) return input.current;
  if (input.current) {
    throw new Error('wallet recovery produced more than one replacement envelope');
  }
  return input.candidate;
}

export async function recoverWalletCustodyManifestV1(input: {
  readonly walletId: WalletId;
  readonly prepared: PreparedWalletRecovery;
  readonly custodyJson: string;
  readonly recoveryCodeBytes: Uint8Array;
  readonly replacementFactor: WalletRecoveryReplacementFactorInput;
  readonly recoveryChallengeId: string;
  readonly relayUrl: string;
  readonly runStep: WalletCustodyCeremonyStepRunner;
  readonly workerCtx: WorkerOperationContext;
  readonly nowMs?: () => number;
}): Promise<RecoveredWalletCustodyManifestV1> {
  const nearKeySets: RecoveredWalletCustodyNearKeySetV1[] = [];
  const ecdsaKeySets: RecoveredWalletCustodyEcdsaKeySetV1[] = [];
  let replacementEnvelope: RecoveryReplacementEnvelopePayload | null = null;

  for (const [entryIndex, entry] of input.prepared.keyManifest.entries.entries()) {
    let copiedRecoveryCode: ArrayBuffer | null = null;
    let factorReplacement: RecoveryFactorReplacement | null = null;
    try {
      const recoveryCode = recoveryCodeBuffer(input.recoveryCodeBytes);
      copiedRecoveryCode = recoveryCode;
      const replacement = replacementForEntry({
        entryIndex,
        replacementFactor: input.replacementFactor,
      });
      factorReplacement = replacement;
      switch (entry.kind) {
        case 'near_ed25519': {
          const transport = new RouterAbEd25519YaoHttpActivationTransportV1({
            routerOrigin: new URL(input.relayUrl).origin,
            authorization: {
              kind: 'recovery_challenge',
              challengeId: input.recoveryChallengeId,
            },
            fetch: globalThis.fetch,
          });
          const request = await buildWalletRecoveryEd25519AdmissionRequestV1({
            reservationId: input.prepared.reservationId,
            entry,
          });
          const admitted = await admitWalletRecoveryEd25519V1({ request, transport });
          const recovered = await recoverNearEd25519CustodyV1({
            runStep: input.runStep,
            walletId: input.walletId,
            custodyJson: input.custodyJson,
            recoveryCode,
            recordedKeyManifestDigestB64u: entry.recordedKeyManifestDigestB64u,
            factorReplacement: replacement,
            nearEd25519SigningKeyId:
              entry.recoveryBasis.applicationBinding.near_ed25519_signing_key_id,
            recoveryLifecycleId: request.scope.lifecycle_id,
            yaoAdmission: admitted.receipt,
            yaoApplication: admitted.request.application_binding,
            participantIds: admitted.request.participant_ids,
            registeredPublicKeyB64u: base64UrlEncode(
              Uint8Array.from(entry.recoveryBasis.registeredPublicKey),
            ),
            runRouterRound: (executeRequestJson) =>
              executeWalletRecoveryEd25519RoundV1({ executeRequestJson, transport }),
            activateRouterRecovery: (protocolResultJson) =>
              activateWalletRecoveryEd25519V1({ request, protocolResultJson, transport }),
          });
          if (!recovered.localMaterial) {
            throw new Error('wallet recovery produced no NEAR local material');
          }
          replacementEnvelope = recordReplacementEnvelope({
            current: replacementEnvelope,
            candidate: recovered.recoveryReplacementEnvelope,
          });
          nearKeySets.push({
            entry,
            metadata: walletRecoveryEd25519ActiveClientMetadataV1({
              admissionRequest: request,
              activationResultJson: recovered.activationResultJson,
              activationReceipt: recovered.activationReceipt,
            }),
            localMaterial: recovered.localMaterial,
          });
          break;
        }
        case 'evm_family_ecdsa': {
          const recovered = await recoverEvmFamilyCustodyV1({
            runStep: input.runStep,
            walletId: input.walletId,
            custodyJson: input.custodyJson,
            recoveryCode,
            recordedKeyManifestDigestB64u: entry.recordedKeyManifestDigestB64u,
            factorReplacement: replacement,
            evmFamilySigningKeySlotId: entry.evmFamilySigningKeySlotId,
            applicationBindingDigestB64u:
              entry.recoveryBasis.publicCapability.context.application_binding_digest_b64u,
            registeredClientRootPublicKey33B64u: entry.recoveryBasis.clientRootPublicKey33B64u,
            resolveRelayerPublicIdentity: async (bootstrap) => {
              requireMatchingEcdsaBootstrap({ entry, bootstrap });
              return JSON.stringify({
                relayerKeyId:
                  entry.recoveryBasis.publicCapability.signer_set.selected_server.server_id,
                relayerPublicKey33B64u:
                  entry.recoveryBasis.publicCapability.public_identity.server_public_key33_b64u,
                groupPublicKey33B64u:
                  entry.recoveryBasis.publicCapability.public_identity.threshold_public_key33_b64u,
                ethereumAddress: ethereumAddressFromAddress20B64u(
                  entry.recoveryBasis.publicCapability.public_identity.ethereum_address20_b64u,
                ),
                relayerShareRetryCounter:
                  entry.recoveryBasis.publicCapability.public_identity.server_share_retry_counter,
              });
            },
          });
          const completedActivation = await signRecoveredWalletCustodyEcdsa({
            entry,
            walletId: input.walletId,
            reservationId: input.prepared.reservationId,
            replacementId: input.replacementFactor.replacementId,
            readyStateBlobB64u: recovered.readyStateBlobB64u,
            publicFacts: recovered.publicFacts,
            workerCtx: input.workerCtx,
          });
          replacementEnvelope = recordReplacementEnvelope({
            current: replacementEnvelope,
            candidate: recovered.recoveryReplacementEnvelope,
          });
          ecdsaKeySets.push({
            entry,
            activation: completedActivation,
            readyStateBlobB64u: recovered.readyStateBlobB64u,
            publicFacts: recovered.publicFacts,
          });
          break;
        }
      }
    } finally {
      if (factorReplacement) zeroizeFactorReplacement(factorReplacement);
      if (copiedRecoveryCode) new Uint8Array(copiedRecoveryCode).fill(0);
    }
  }

  if (!replacementEnvelope) {
    throw new Error('wallet recovery produced no replacement custody envelope');
  }
  return {
    replacementEnvelope: buildRecoveredCustodyEnvelopeRecord({
      expectedWalletId: input.walletId,
      replacement: replacementEnvelope,
      activatedAtMs: (input.nowMs ?? Date.now)(),
    }),
    nearKeySets,
    ecdsaKeySets,
  };
}
