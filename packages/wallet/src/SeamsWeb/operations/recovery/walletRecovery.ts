import type { WalletRecoveryWebContext } from '@/SeamsWeb/signingSurface/ports';
import {
  buildWalletRecoveryCeremonyCustodyJson,
  prepareWalletRecoveryWithCode,
  type PreparedWalletRecovery,
  type WalletRecoveryAttemptFailure,
} from '@/core/rpcClients/relayer/walletRecoveryPrepare';
import {
  finalizeWalletRecovery,
  type WalletRecoveryFinalizeResult,
} from '@/core/rpcClients/relayer/walletRecoveryFinalize';
import { persistRecoveredPasskeyAuthMethodProjectionV1 } from '@/SeamsWeb/operations/authMethods/passkey/localPasskeyProjection';
import type { WalletRecoveryReplacementCredential } from '@/core/signingEngine/walletCustody/walletRecoveryCredential';
import type {
  RecoveredWalletCustodyEcdsaKeySetV1,
  RecoveredWalletCustodyManifestV1,
  RecoveredWalletCustodyNearKeySetV1,
} from '@/core/signingEngine/walletCustody/walletRecoveryManifest';
import { WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND } from '@/core/signingEngine/walletCustody/ed25519SeedMaterial';
import { base58Encode, base64UrlEncode } from '@shared/utils/encoders';
import { toAccountId } from '@/core/types/accountIds';
import {
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WalletId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import {
  walletAuthAuthorityRef,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { decodeWalletRecoveryCode } from '@shared/wallet-recovery/recoveryCodes';
import {
  parseRecoveryCodeReservationId,
  type RecoveryCodeReservationId,
} from '@shared/wallet-recovery/recoveryCodeReservation';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { sha256Bytes } from '@shared/utils/digests';
import { NEAR_ED25519_YAO_KEY_VERSION_V1 } from '@shared/utils/registrationIntent';

const RECOVERY_PREPARE_RETRY_TTL_MS = 5 * 60 * 1000;
// ECDSA-only registration establishes its wallet-scoped passkey at slot 1.
const ECDSA_ONLY_WALLET_SIGNER_SLOT = 1;

export type WalletRecoveryPreparedHandle = {
  readonly kind: 'prepared';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
};

export type WalletRecoveryCredentialCreatedHandle = {
  readonly kind: 'credential_created';
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
};

export type WalletRecoveryCoordinatorResult<T> = T | WalletRecoveryAttemptFailure;

export type WalletRecoveryCredentialCreationResult =
  | WalletRecoveryCredentialCreatedHandle
  | { readonly kind: 'dismissed' }
  | { readonly kind: 'refused' };

export type WalletRecoveryFinalizeCoordinatorResult =
  | { readonly kind: 'ready_for_sign_in'; readonly walletId: WalletId }
  | WalletRecoveryAttemptFailure;

type RecoveryOperationCommon = {
  readonly recoveryOperationId: string;
  readonly walletId: WalletId;
  readonly relayUrl: string;
  readonly prepared: PreparedWalletRecovery;
  readonly custodyJson: string;
  readonly recoveryCodeBytes: Uint8Array;
};

type CommittedRecoveryPromotion = Extract<
  WalletRecoveryFinalizeResult,
  { readonly kind: 'promoted' }
>;

type RecoveryOperation =
  | (RecoveryOperationCommon & {
      readonly stage: 'prepared';
      readonly replacement?: never;
      readonly recovered?: never;
      readonly committedCredential?: never;
    })
  | (RecoveryOperationCommon & {
      readonly stage: 'credential_created';
      readonly replacement: WalletRecoveryReplacementCredential;
      readonly recovered?: never;
      readonly committedCredential?: never;
    })
  | (RecoveryOperationCommon & {
      readonly stage: 'manifest_recovered';
      readonly replacement: WalletRecoveryReplacementCredential;
      readonly recovered: RecoveredWalletCustodyManifestV1;
      readonly committedCredential?: never;
    })
  | (RecoveryOperationCommon & {
      readonly stage: 'promoted_pending_continuity';
      readonly replacement: WalletRecoveryReplacementCredential;
      readonly recovered: RecoveredWalletCustodyManifestV1;
      readonly committedPromotion: CommittedRecoveryPromotion;
    });

function createReservationId(): RecoveryCodeReservationId {
  return parseRecoveryCodeReservationId(
    secureRandomId('wallet-recovery-reservation', 32, 'wallet recovery operation reservations'),
  );
}

function pendingPrepareKey(recoveryCodeDigestB64u: string): string {
  return recoveryCodeDigestB64u;
}

function zeroizeBuffer(buffer: ArrayBuffer | null): void {
  if (buffer && buffer.byteLength > 0) new Uint8Array(buffer).fill(0);
}

function disposeRecoveryOperation(operation: RecoveryOperation): void {
  operation.recoveryCodeBytes.fill(0);
  if (operation.stage !== 'prepared') zeroizeBuffer(operation.replacement.factorSecret);
}

function refused(): WalletRecoveryAttemptFailure {
  return { kind: 'refused' };
}

function isCredentialDismissal(error: unknown): boolean {
  if (typeof error !== 'object' || error === null) return false;
  const name = Reflect.get(error, 'name');
  return name === 'NotAllowedError' || name === 'AbortError';
}

function credentialCreatedOperation(
  current: Extract<RecoveryOperation, { stage: 'prepared' }>,
  replacement: WalletRecoveryReplacementCredential,
): Extract<RecoveryOperation, { stage: 'credential_created' }> {
  return {
    stage: 'credential_created',
    recoveryOperationId: current.recoveryOperationId,
    walletId: current.walletId,
    relayUrl: current.relayUrl,
    prepared: current.prepared,
    custodyJson: current.custodyJson,
    recoveryCodeBytes: current.recoveryCodeBytes,
    replacement,
  };
}

function manifestRecoveredOperation(
  current: Extract<RecoveryOperation, { stage: 'credential_created' }>,
  recovered: RecoveredWalletCustodyManifestV1,
): Extract<RecoveryOperation, { stage: 'manifest_recovered' }> {
  return {
    stage: 'manifest_recovered',
    recoveryOperationId: current.recoveryOperationId,
    walletId: current.walletId,
    relayUrl: current.relayUrl,
    prepared: current.prepared,
    custodyJson: current.custodyJson,
    recoveryCodeBytes: current.recoveryCodeBytes,
    replacement: current.replacement,
    recovered,
  };
}

function promotedPendingContinuityOperation(
  current: Extract<RecoveryOperation, { stage: 'manifest_recovered' }>,
  committedPromotion: CommittedRecoveryPromotion,
): Extract<RecoveryOperation, { stage: 'promoted_pending_continuity' }> {
  return {
    stage: 'promoted_pending_continuity',
    recoveryOperationId: current.recoveryOperationId,
    walletId: current.walletId,
    relayUrl: current.relayUrl,
    prepared: current.prepared,
    custodyJson: current.custodyJson,
    recoveryCodeBytes: current.recoveryCodeBytes,
    replacement: current.replacement,
    recovered: current.recovered,
    committedPromotion,
  };
}

function recoveredPasskeyWalletAuthAuthority(input: {
  readonly walletId: WalletId;
  readonly rpId: WebAuthnRpId;
  readonly credentialIdB64u: CommittedRecoveryPromotion['authMethod']['credentialIdB64u'];
  readonly walletAuthMethodId: WalletAuthMethodId;
}): PasskeyWalletAuthAuthority {
  return {
    walletId: input.walletId,
    factor: { kind: 'passkey', credentialIdB64u: input.credentialIdB64u },
    verifier: { kind: 'webauthn', rpId: input.rpId },
    bindingId: input.walletAuthMethodId,
  };
}

async function persistRecoveredNearKeySet(input: {
  readonly context: WalletRecoveryWebContext;
  readonly walletId: WalletId;
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
      signingWorkerVerifyingShareB64u: base64UrlEncode(metadata.signingWorkerVerifyingShare),
    },
    sealed: {
      ciphertextB64u: input.recovered.localMaterial.b64u,
      nonceB64u: input.recovered.localMaterial.nonceB64u,
    },
  });
}

async function persistRecoveredEcdsaKeySet(input: {
  readonly context: WalletRecoveryWebContext;
  readonly walletId: WalletId;
  readonly authority: WalletAuthAuthorityRef;
  readonly recovered: RecoveredWalletCustodyEcdsaKeySetV1;
}): Promise<void> {
  const basis = input.recovered.entry.recoveryBasis;
  await input.context.signingEngine.restoreWalletCustodyEcdsaContinuity({
    authority: input.authority,
    chainTargets: basis.chainTargets,
    walletId: input.walletId,
    keyHandle: input.recovered.entry.keyHandle,
    ecdsaThresholdKeyId: basis.ecdsaThresholdKeyId,
    signingRootId: basis.signingRootId,
    signingRootVersion: basis.signingRootVersion,
    relayerKeyId:
      input.recovered.activation.activationReceipt.ecdsa_activation.signing_worker.server_id,
    participantIds: basis.participantIds,
    publicCapability: input.recovered.activation.publicCapability,
    activationReceipt: input.recovered.activation.activationReceipt,
    runtimePolicyScope: basis.runtimePolicyScope,
    readyStateBlobB64u: input.recovered.readyStateBlobB64u,
    publicFacts: input.recovered.publicFacts,
  });
}

async function persistRecoveredLocalContinuity(input: {
  readonly context: WalletRecoveryWebContext;
  readonly operation: Extract<RecoveryOperation, { stage: 'promoted_pending_continuity' }>;
}): Promise<void> {
  const committedAuthMethod = input.operation.committedPromotion.authMethod;
  const authority = await walletAuthAuthorityRef({
    authority: recoveredPasskeyWalletAuthAuthority({
      walletId: input.operation.walletId,
      rpId: input.operation.prepared.registration.rpId,
      credentialIdB64u: committedAuthMethod.credentialIdB64u,
      walletAuthMethodId: committedAuthMethod.walletAuthMethodId,
    }),
  });

  const replacement = input.operation.replacement;
  const nearProjection = input.operation.recovered.nearKeySets;
  if (nearProjection.length > 0) {
    for (const recovered of nearProjection) {
      const application = recovered.entry.recoveryBasis.applicationBinding;
      await input.context.signingEngine.storeWalletEd25519RecoveryRegistrationData({
        walletId: input.operation.walletId,
        nearAccountId: toAccountId(recovered.entry.nearAccountId),
        signerSlot: application.key_creation_signer_slot,
        nearEd25519SigningKeyId: application.near_ed25519_signing_key_id,
        operationalPublicKey: `ed25519:${base58Encode(recovered.metadata.registeredPublicKey)}`,
        rpId: input.operation.prepared.registration.rpId,
        credential: replacement.registration,
        credentialPublicKeyB64u: committedAuthMethod.credentialPublicKeyB64u,
        relayerKeyId: recovered.metadata.scope.signing_worker_id,
        keyVersion: NEAR_ED25519_YAO_KEY_VERSION_V1,
        participantIds: [...recovered.metadata.participantIds],
      });
    }
    await persistRecoveredPasskeyAuthMethodProjectionV1({
      kind: 'near',
      authority: input.operation.committedPromotion.authority,
      authMethod: committedAuthMethod,
      credential: {
        id: replacement.registration.id,
        rawId: replacement.registration.rawId,
      },
    });
  } else {
    await persistRecoveredPasskeyAuthMethodProjectionV1({
      kind: 'wallet_only',
      authority: input.operation.committedPromotion.authority,
      authMethod: committedAuthMethod,
      signerSlot: ECDSA_ONLY_WALLET_SIGNER_SLOT,
      credential: {
        id: replacement.registration.id,
        rawId: replacement.registration.rawId,
      },
    });
  }

  await Promise.all([
    ...input.operation.recovered.nearKeySets.map((recovered) =>
      persistRecoveredNearKeySet({
        context: input.context,
        walletId: input.operation.walletId,
        recovered,
      }),
    ),
    ...input.operation.recovered.ecdsaKeySets.map((recovered) =>
      persistRecoveredEcdsaKeySet({
        context: input.context,
        walletId: input.operation.walletId,
        authority,
        recovered,
      }),
    ),
  ]);
}

export class WalletRecoveryCoordinator {
  readonly #operations = new Map<string, RecoveryOperation>();
  readonly #credentialPrompts = new Map<string, AbortController>();
  readonly #pendingPrepareReservations = new Map<
    string,
    { readonly reservationId: RecoveryCodeReservationId; readonly expiresAtMs: number }
  >();
  async prepareWithCode(input: {
    readonly context: WalletRecoveryWebContext;
    readonly relayUrl: string;
    readonly recoveryCode: string;
    readonly signal: AbortSignal;
  }): Promise<WalletRecoveryCoordinatorResult<WalletRecoveryPreparedHandle>> {
    this.#pruneExpired();
    const rpId = parseWebAuthnRpId(input.context.signingEngine.getRpId());
    if (!rpId.ok || input.signal.aborted) return refused();

    let recoveryCodeBytes: Uint8Array | null = null;
    try {
      recoveryCodeBytes = decodeWalletRecoveryCode(input.recoveryCode);
      const recoveryCodeDigestB64u = base64UrlEncode(await sha256Bytes(recoveryCodeBytes));
      const retryKey = pendingPrepareKey(recoveryCodeDigestB64u);
      const pending = this.#pendingPrepareReservations.get(retryKey);
      const reservationId =
        pending?.expiresAtMs && pending.expiresAtMs > Date.now()
          ? pending.reservationId
          : createReservationId();
      const prepared = await prepareWalletRecoveryWithCode({
        relayUrl: input.relayUrl,
        rpId: rpId.value,
        recoveryCodeB64u: base64UrlEncode(recoveryCodeBytes),
        reservationId,
      });
      if (prepared.kind !== 'prepared') {
        if (prepared.kind === 'retryable_conflict' || prepared.kind === 'transport_uncertain') {
          this.#pendingPrepareReservations.set(retryKey, {
            reservationId,
            expiresAtMs: Date.now() + RECOVERY_PREPARE_RETRY_TTL_MS,
          });
        } else {
          this.#pendingPrepareReservations.delete(retryKey);
        }
        return prepared;
      }
      this.#pendingPrepareReservations.delete(retryKey);
      if (input.signal.aborted) return refused();

      const recoveryOperationId = secureRandomId(
        'wallet-recovery-operation',
        24,
        'wallet recovery client operation handles',
      );
      this.#operations.set(recoveryOperationId, {
        stage: 'prepared',
        recoveryOperationId,
        walletId: prepared.walletId,
        relayUrl: input.relayUrl,
        prepared,
        custodyJson: buildWalletRecoveryCeremonyCustodyJson({
          walletId: prepared.walletId,
          prepared,
        }),
        recoveryCodeBytes,
      });
      recoveryCodeBytes = null;
      return { kind: 'prepared', recoveryOperationId, walletId: prepared.walletId };
    } catch {
      return refused();
    } finally {
      recoveryCodeBytes?.fill(0);
    }
  }

  createPasskey(input: {
    readonly context: WalletRecoveryWebContext;
    readonly operation: WalletRecoveryPreparedHandle;
  }): Promise<WalletRecoveryCredentialCreationResult> {
    this.#pruneExpired();
    const current = this.#operations.get(input.operation.recoveryOperationId);
    if (
      !current ||
      current.stage !== 'prepared' ||
      current.walletId !== input.operation.walletId ||
      this.#credentialPrompts.has(current.recoveryOperationId)
    ) {
      return Promise.resolve({ kind: 'refused' });
    }

    const promptController = new AbortController();
    this.#credentialPrompts.set(current.recoveryOperationId, promptController);
    let credentialPromise: Promise<WalletRecoveryReplacementCredential>;
    try {
      credentialPromise = input.context.signingEngine.createWalletRecoveryReplacementCredential({
        walletId: current.walletId,
        registration: current.prepared.registration,
        cancellation: { kind: 'abort_signal', signal: promptController.signal },
      });
    } catch {
      this.cancel(current.recoveryOperationId);
      return Promise.resolve({ kind: 'refused' });
    }
    return this.#finishCredentialCreation({ current, credentialPromise, promptController });
  }

  async finalize(input: {
    readonly context: WalletRecoveryWebContext;
    readonly operation: WalletRecoveryCredentialCreatedHandle;
  }): Promise<WalletRecoveryFinalizeCoordinatorResult> {
    this.#pruneExpired();
    let current = this.#operations.get(input.operation.recoveryOperationId);
    if (!current || current.stage === 'prepared' || current.walletId !== input.operation.walletId) {
      return refused();
    }

    try {
      if (current.stage === 'credential_created') {
        const recovered = await input.context.signingEngine.recoverWalletCustodyManifest({
          walletId: current.walletId,
          prepared: current.prepared,
          custodyJson: current.custodyJson,
          recoveryCodeBytes: current.recoveryCodeBytes,
          replacementCredentialIdB64u: current.replacement.credentialIdB64u,
          replacementFactorSecret: current.replacement.factorSecret,
          relayUrl: current.relayUrl,
        });
        if (this.#operations.get(current.recoveryOperationId) !== current) {
          disposeRecoveryOperation(current);
          return refused();
        }
        if (current.prepared.reservationExpiresAtMs <= Date.now()) {
          this.cancel(current.recoveryOperationId);
          return refused();
        }
        current.recoveryCodeBytes.fill(0);
        zeroizeBuffer(current.replacement.factorSecret);
        current = manifestRecoveredOperation(current, recovered);
        this.#operations.set(current.recoveryOperationId, current);
      }

      if (current.stage === 'manifest_recovered') {
        const finalized = await finalizeWalletRecovery({
          relayUrl: current.relayUrl,
          walletId: current.walletId,
          reservationId: current.prepared.reservationId,
          challengeId: current.prepared.registration.challengeId,
          replacementId: current.prepared.registration.replacementId,
          webauthnRegistration: current.replacement.registration,
          replacementEnvelope: current.recovered.replacementEnvelope,
          ecdsaMaterialPossessionProofs: current.recovered.ecdsaKeySets.map((keySet) => ({
            keySetId: keySet.entry.keySetId,
            proof: keySet.activation.possessionProof,
          })),
        });
        if (this.#operations.get(current.recoveryOperationId) !== current) {
          return finalized.kind === 'promoted' ? { kind: 'transport_uncertain' } : finalized;
        }
        if (finalized.kind === 'refused') {
          this.cancel(current.recoveryOperationId);
          return finalized;
        }
        if (finalized.kind !== 'promoted') return finalized;
        if (finalized.authMethod.credentialIdB64u !== current.replacement.credentialIdB64u) {
          return { kind: 'transport_uncertain' };
        }
        current = promotedPendingContinuityOperation(current, finalized);
        this.#operations.set(current.recoveryOperationId, current);
      }

      await persistRecoveredLocalContinuity({ context: input.context, operation: current });
      this.#operations.delete(current.recoveryOperationId);
      disposeRecoveryOperation(current);
      return { kind: 'ready_for_sign_in', walletId: current.walletId };
    } catch {
      const retained = this.#operations.get(input.operation.recoveryOperationId);
      if (retained?.stage === 'promoted_pending_continuity') {
        return { kind: 'transport_uncertain' };
      }
      this.cancel(input.operation.recoveryOperationId);
      return refused();
    }
  }

  async #finishCredentialCreation(input: {
    readonly current: Extract<RecoveryOperation, { stage: 'prepared' }>;
    readonly credentialPromise: Promise<WalletRecoveryReplacementCredential>;
    readonly promptController: AbortController;
  }): Promise<WalletRecoveryCredentialCreationResult> {
    try {
      const replacement = await input.credentialPromise;
      const active = this.#operations.get(input.current.recoveryOperationId);
      if (active !== input.current || input.promptController.signal.aborted) {
        zeroizeBuffer(replacement.factorSecret);
        return { kind: 'dismissed' };
      }
      if (input.current.prepared.reservationExpiresAtMs <= Date.now()) {
        zeroizeBuffer(replacement.factorSecret);
        this.cancel(input.current.recoveryOperationId);
        return { kind: 'refused' };
      }
      const next = credentialCreatedOperation(input.current, replacement);
      this.#operations.set(next.recoveryOperationId, next);
      return {
        kind: 'credential_created',
        recoveryOperationId: next.recoveryOperationId,
        walletId: next.walletId,
      };
    } catch (error: unknown) {
      if (input.promptController.signal.aborted || isCredentialDismissal(error)) {
        return { kind: 'dismissed' };
      }
      this.cancel(input.current.recoveryOperationId);
      return { kind: 'refused' };
    } finally {
      const activePrompt = this.#credentialPrompts.get(input.current.recoveryOperationId);
      if (activePrompt === input.promptController) {
        this.#credentialPrompts.delete(input.current.recoveryOperationId);
      }
    }
  }

  cancel(recoveryOperationId: string): void {
    this.#credentialPrompts.get(recoveryOperationId)?.abort();
    this.#credentialPrompts.delete(recoveryOperationId);
    const operation = this.#operations.get(recoveryOperationId);
    if (!operation) return;
    this.#operations.delete(recoveryOperationId);
    disposeRecoveryOperation(operation);
  }

  #pruneExpired(): void {
    const nowMs = Date.now();
    for (const [retryKey, pending] of this.#pendingPrepareReservations) {
      if (pending.expiresAtMs <= nowMs) this.#pendingPrepareReservations.delete(retryKey);
    }
    for (const [operationId, operation] of this.#operations) {
      if (operation.stage === 'promoted_pending_continuity') continue;
      if (operation.prepared.reservationExpiresAtMs > nowMs) continue;
      this.#credentialPrompts.get(operationId)?.abort();
      this.#credentialPrompts.delete(operationId);
      this.#operations.delete(operationId);
      disposeRecoveryOperation(operation);
    }
  }
}
