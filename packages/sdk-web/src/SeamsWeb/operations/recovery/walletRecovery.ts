import type { EmailRecoveryWebContext } from '@/SeamsWeb/signingSurface/ports';
import {
  buildWalletRecoveryCeremonyCustodyJson,
  prepareWalletRecovery,
  type WalletRecoveryPrepareResult,
} from '@/core/rpcClients/relayer/walletRecoveryPrepare';
import {
  finalizeWalletRecovery,
  type WalletRecoveryFinalizeResult,
} from '@/core/rpcClients/relayer/walletRecoveryFinalize';
import type { WalletRecoveryReplacementCredential } from '@/core/signingEngine/walletCustody/walletRecoveryCredential';
import type {
  RecoveredWalletCustodyEcdsaKeySetV1,
  RecoveredWalletCustodyManifestV1,
  RecoveredWalletCustodyNearKeySetV1,
} from '@/core/signingEngine/walletCustody/walletRecoveryManifest';
import { WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND } from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import { base64UrlEncode } from '@shared/utils/encoders';
import { decodeWalletRecoveryCode } from '@shared/wallet-recovery/recoveryCodes';
import {
  parseRecoveryCodeReservationId,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import { secureRandomId } from '@shared/utils/secureRandomId';

export type PrepareWalletWithCodeInput = {
  readonly walletId: string;
  readonly relayUrl: string;
  readonly sessionToken: string;
  readonly challengeId: string;
  readonly otpCode: string;
  readonly recoveryCode: string;
};

export type PrepareWalletWithCodeResult =
  | {
      readonly kind: 'ready_for_passkey';
      readonly recoveryOperationId: string;
      readonly walletId: string;
      readonly reservationExpiresAtMs: number;
      readonly rpId: string;
    }
  | Exclude<WalletRecoveryPrepareResult, { readonly kind: 'prepared' }>
  | { readonly kind: 'failed'; readonly message: string };

export type CompleteWalletRecoveryResult =
  | {
      readonly kind: 'recovered';
      readonly walletId: string;
      readonly storeVersion: string;
      readonly retiredEnvelopeIds: readonly string[];
      readonly retireFailures: readonly string[];
      readonly recoveredKeySetIds: readonly string[];
      readonly localContinuity: 'restored' | 'unlock_required';
    }
  | Exclude<WalletRecoveryFinalizeResult, { readonly kind: 'promoted' }>
  | { readonly kind: 'failed'; readonly message: string };

type RecoveryOperationCommon = {
  readonly recoveryOperationId: string;
  readonly walletId: string;
  readonly prepared: Extract<WalletRecoveryPrepareResult, { readonly kind: 'prepared' }>;
  readonly custodyJson: string;
  readonly recoveryCodeBytes: Uint8Array;
};

type RecoveryOperation =
  | (RecoveryOperationCommon & {
      readonly stage: 'prepared';
      readonly replacement?: never;
      readonly recovered?: never;
    })
  | (RecoveryOperationCommon & {
      readonly stage: 'credential_created';
      readonly replacement: WalletRecoveryReplacementCredential;
      readonly recovered?: never;
    })
  | (RecoveryOperationCommon & {
      readonly stage: 'manifest_recovered';
      readonly replacement: WalletRecoveryReplacementCredential;
      readonly recovered: RecoveredWalletCustodyManifestV1;
    });

function createReservationId(): RecoveryCodeReservationId {
  return parseRecoveryCodeReservationId(
    secureRandomId(
      'wallet-recovery-reservation',
      32,
      'wallet recovery operation reservations',
    ),
  );
}

function zeroizeBuffer(buffer: ArrayBuffer | null): void {
  if (buffer && buffer.byteLength > 0) new Uint8Array(buffer).fill(0);
}

async function persistRecoveredNearKeySet(input: {
  readonly context: EmailRecoveryWebContext;
  readonly walletId: string;
  readonly recovered: RecoveredWalletCustodyNearKeySetV1;
}): Promise<void> {
  const basis = input.recovered.entry.recoveryBasis;
  const application = basis.applicationBinding;
  const metadata = input.recovered.metadata;
  await input.context.signingEngine.persistWalletCustodyEd25519Material({
    binding: {
      kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
      applicationBindingDigestB64u: input.recovered.localMaterial.applicationBindingDigestB64u,
      registeredPublicKeyB64u: base64UrlEncode(metadata.registeredPublicKey),
      participantIds: metadata.participantIds,
      stateEpoch: String(metadata.stateEpoch),
      walletId: input.walletId,
      nearAccountId: input.recovered.entry.nearAccountId,
      nearEd25519SigningKeyId: application.near_ed25519_signing_key_id,
      signerSlot: application.key_creation_signer_slot,
      signingWorkerId: metadata.scope.signing_worker_id,
      signingWorkerVerifyingShareB64u: base64UrlEncode(
        metadata.signingWorkerVerifyingShare,
      ),
    },
    sealed: {
      ciphertextB64u: input.recovered.localMaterial.b64u,
      nonceB64u: input.recovered.localMaterial.nonceB64u,
    },
  });
}

async function persistRecoveredEcdsaKeySet(input: {
  readonly context: EmailRecoveryWebContext;
  readonly walletId: string;
  readonly authorityRef: Parameters<
    EmailRecoveryWebContext['signingEngine']['restoreWalletCustodyEcdsaContinuity']
  >[0]['authority'];
  readonly recovered: RecoveredWalletCustodyEcdsaKeySetV1;
}): Promise<void> {
  const basis = input.recovered.entry.recoveryBasis;
  await input.context.signingEngine.restoreWalletCustodyEcdsaContinuity({
    authority: input.authorityRef,
    chainTargets: basis.chainTargets,
    walletId: input.walletId,
    keyHandle: input.recovered.entry.keyHandle,
    ecdsaThresholdKeyId: basis.ecdsaThresholdKeyId,
    signingRootId: basis.signingRootId,
    signingRootVersion: basis.signingRootVersion,
    relayerKeyId: input.recovered.activation.activationReceipt.ecdsa_activation.signing_worker
      .server_id,
    participantIds: basis.participantIds,
    publicCapability: input.recovered.activation.publicCapability,
    activationReceipt: input.recovered.activation.activationReceipt,
    runtimePolicyScope: basis.runtimePolicyScope,
    readyStateBlobB64u: input.recovered.readyStateBlobB64u,
    publicFacts: input.recovered.publicFacts,
  });
}

async function persistRecoveredLocalContinuity(input: {
  readonly context: EmailRecoveryWebContext;
  readonly walletId: string;
  readonly authorityRef: Parameters<
    EmailRecoveryWebContext['signingEngine']['restoreWalletCustodyEcdsaContinuity']
  >[0]['authority'];
  readonly recovered: RecoveredWalletCustodyManifestV1;
}): Promise<'restored' | 'unlock_required'> {
  let complete = true;
  for (const near of input.recovered.nearKeySets) {
    try {
      await persistRecoveredNearKeySet({
        context: input.context,
        walletId: input.walletId,
        recovered: near,
      });
    } catch {
      complete = false;
    }
  }
  for (const ecdsa of input.recovered.ecdsaKeySets) {
    try {
      await persistRecoveredEcdsaKeySet({
        context: input.context,
        walletId: input.walletId,
        authorityRef: input.authorityRef,
        recovered: ecdsa,
      });
    } catch {
      complete = false;
    }
  }
  return complete ? 'restored' : 'unlock_required';
}

function disposeRecoveryOperation(operation: RecoveryOperation): void {
  operation.recoveryCodeBytes.fill(0);
  if (operation.stage !== 'prepared') {
    zeroizeBuffer(operation.replacement.factorSecret);
  }
}

export class WalletRecoveryCoordinator {
  readonly #operations = new Map<string, RecoveryOperation>();

  async prepare(input: PrepareWalletWithCodeInput): Promise<PrepareWalletWithCodeResult> {
    this.#pruneExpired();
    let recoveryCodeBytes: Uint8Array | null = null;
    try {
      recoveryCodeBytes = decodeWalletRecoveryCode(input.recoveryCode);
      const prepared = await prepareWalletRecovery({
        relayUrl: input.relayUrl,
        walletId: input.walletId,
        sessionToken: input.sessionToken,
        challengeId: input.challengeId,
        otpCode: input.otpCode,
        recoveryCode: base64UrlEncode(recoveryCodeBytes),
        reservationId: createReservationId(),
      });
      if (prepared.kind !== 'prepared') return prepared;
      const recoveryOperationId = secureRandomId(
        'wallet-recovery-operation',
        24,
        'wallet recovery client operation handles',
      );
      this.#operations.set(recoveryOperationId, {
        stage: 'prepared',
        recoveryOperationId,
        walletId: input.walletId,
        prepared,
        custodyJson: buildWalletRecoveryCeremonyCustodyJson({
          walletId: input.walletId,
          prepared,
        }),
        recoveryCodeBytes,
      });
      return {
        kind: 'ready_for_passkey',
        recoveryOperationId,
        walletId: input.walletId,
        reservationExpiresAtMs: prepared.reservationExpiresAtMs,
        rpId: prepared.registration.rpId,
      };
    } catch (error: unknown) {
      recoveryCodeBytes?.fill(0);
      return {
        kind: 'failed',
        message: error instanceof Error ? error.message : 'wallet recovery preparation failed',
      };
    }
  }

  async complete(input: {
    readonly context: EmailRecoveryWebContext;
    readonly recoveryOperationId: string;
    readonly walletId: string;
    readonly relayUrl: string;
    readonly sessionToken: string;
  }): Promise<CompleteWalletRecoveryResult> {
    this.#pruneExpired();
    let operation = this.#operations.get(input.recoveryOperationId);
    if (!operation || operation.walletId !== input.walletId) {
      return { kind: 'failed', message: 'wallet recovery operation is unavailable or expired' };
    }
    try {
      if (operation.stage === 'prepared') {
        const replacement =
          await input.context.signingEngine.createWalletRecoveryReplacementCredential({
            walletId: operation.walletId,
            registration: operation.prepared.registration,
          });
        operation = { ...operation, stage: 'credential_created', replacement };
        this.#operations.set(operation.recoveryOperationId, operation);
      }
      if (operation.stage === 'credential_created') {
        const recovered = await input.context.signingEngine.recoverWalletCustodyManifest({
          walletId: operation.walletId,
          prepared: operation.prepared,
          custodyJson: operation.custodyJson,
          recoveryCodeBytes: operation.recoveryCodeBytes,
          replacementCredentialIdB64u: operation.replacement.credentialIdB64u,
          replacementFactorSecret: operation.replacement.factorSecret,
          relayUrl: input.relayUrl,
          sessionToken: input.sessionToken,
        });
        operation = { ...operation, stage: 'manifest_recovered', recovered };
        this.#operations.set(operation.recoveryOperationId, operation);
      }
      const finalized = await finalizeWalletRecovery({
        relayUrl: input.relayUrl,
        walletId: operation.walletId,
        sessionToken: input.sessionToken,
        reservationId: operation.prepared.reservationId,
        challengeId: operation.prepared.registration.challengeId,
        replacementId: operation.prepared.registration.replacementId,
        webauthnRegistration: operation.replacement.registration,
        replacementEnvelope: operation.recovered.replacementEnvelope,
      });
      if (finalized.kind !== 'promoted') return finalized;
      const localContinuity = await persistRecoveredLocalContinuity({
        context: input.context,
        walletId: operation.walletId,
        authorityRef: operation.prepared.authorityRef,
        recovered: operation.recovered,
      });
      const result: CompleteWalletRecoveryResult = {
        kind: 'recovered',
        walletId: operation.walletId,
        storeVersion: finalized.storeVersion,
        retiredEnvelopeIds: finalized.retiredEnvelopeIds,
        retireFailures: finalized.retireFailures,
        recoveredKeySetIds: operation.prepared.keyManifest.entries.map(
          (entry) => entry.keySetId,
        ),
        localContinuity,
      };
      this.#operations.delete(operation.recoveryOperationId);
      disposeRecoveryOperation(operation);
      return result;
    } catch (error: unknown) {
      return {
        kind: 'failed',
        message: error instanceof Error ? error.message : 'wallet recovery failed',
      };
    }
  }

  #pruneExpired(): void {
    const nowMs = Date.now();
    for (const [operationId, operation] of this.#operations) {
      if (operation.prepared.reservationExpiresAtMs > nowMs) continue;
      this.#operations.delete(operationId);
      disposeRecoveryOperation(operation);
    }
  }
}
