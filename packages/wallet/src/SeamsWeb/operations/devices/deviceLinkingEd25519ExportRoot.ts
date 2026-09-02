/** Browser-side adapter for the Ed25519 Yao Client export-root relay. */
import {
  buildLinkedDeviceEd25519ExportRootTransferBindingV1,
  LINKED_DEVICE_ED25519_EXPORT_ROOT_TRANSFER_ALG_V1,
  parseLinkedDeviceEd25519ExportRootRecipientPublicKeyB64u,
  parseLinkedDeviceEd25519ExportRootRecipientV1,
  serializeLinkedDeviceEd25519ExportRootTransferBindingV1,
  type LinkedDeviceEd25519ExportRootPackageV1,
  type LinkedDeviceEd25519ExportRootRecipientV1,
} from '@shared/device-linking/ed25519ExportRoot';
import type { LinkedDeviceTargetFactorV1 } from '@shared/device-linking/contracts';
import {
  buildActiveEnvelopeLifecycle,
  buildPasskeyCustodyEnvelopeRecord,
  custodyEnvelopeBindingJsonV1,
  parseDigestField,
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseEnvelopeRevision,
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import type {
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  LinkDeviceSessionId,
  WalletKeyId,
} from '@shared/signing-lanes/ids';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { Ed25519PublicKeyB64u } from '@shared/passkey-custody/primitives';
import type { WalletId } from '@shared/utils/domainIds';
import type { WalletCustodyCeremonyTransportPort } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
import type { UnlockedWalletEd25519ExportRootCapabilityV1 } from '@/core/signingEngine/workerManager/workerTypes';
import type { WalletCustodyCeremonyWorkerOperationMap } from '@/core/signingEngine/workerManager/workerTypes';

export type DeviceLinkingEd25519ExportRootIdentityV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly applicationBindingDigestB64u: DigestB64u;
  readonly registeredPublicKeyB64u: Ed25519PublicKeyB64u;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  readonly revocationEpoch: number;
};

export type DeviceLinkingEd25519ExportRootRecipientHandleV1 = {
  readonly recipientHandleId: string;
  readonly registration: LinkedDeviceEd25519ExportRootRecipientV1;
};

export type DeviceLinkingResealedEd25519ExportRootV1 = {
  readonly envelope: PasskeyCustodyEnvelopeRecord;
};

export type DeviceLinkingEd25519ExportRootReplacementEnvelopeV1 = Pick<
  PasskeyCustodyEnvelopeRecord,
  'envelopeId' | 'walletId' | 'binding' | 'factor' | 'ownership'
> & {
  readonly createdAtMs: number;
};

export function buildDeviceLinkingEd25519ExportRootReplacementEnvelopeV1(
  input: DeviceLinkingEd25519ExportRootReplacementEnvelopeV1,
): DeviceLinkingEd25519ExportRootReplacementEnvelopeV1 {
  if (input.binding.kind !== 'ed25519_yao_client_root_v1') {
    throw new Error('Ed25519 export-root replacement binding has the wrong custody kind');
  }
  if (!Number.isSafeInteger(input.createdAtMs) || input.createdAtMs < 0) {
    throw new Error('Ed25519 export-root replacement timestamp is invalid');
  }
  return {
    envelopeId: input.envelopeId,
    walletId: input.walletId,
    ownership: input.ownership,
    binding: input.binding,
    factor: input.factor,
    createdAtMs: input.createdAtMs,
  };
}

export type DeviceLinkingEd25519ExportRootPortV1 = {
  readonly createRecipientV1: (input: {
    readonly identity: DeviceLinkingEd25519ExportRootIdentityV1;
    readonly registeredAtMs: number;
  }) => Promise<DeviceLinkingEd25519ExportRootRecipientHandleV1>;
  readonly sealForLinkedDeviceV1: (input: {
    readonly recipient: LinkedDeviceEd25519ExportRootRecipientV1;
    readonly capability: UnlockedWalletEd25519ExportRootCapabilityV1;
    readonly sealedAtMs: number;
  }) => Promise<LinkedDeviceEd25519ExportRootPackageV1>;
  readonly acceptTransferV1: (input: {
    readonly recipient: DeviceLinkingEd25519ExportRootRecipientHandleV1;
    readonly transferPackage: LinkedDeviceEd25519ExportRootPackageV1;
    readonly replacementEnvelope: DeviceLinkingEd25519ExportRootReplacementEnvelopeV1;
    readonly replacementFactorSecret: Uint8Array;
  }) => Promise<DeviceLinkingResealedEd25519ExportRootV1>;
  readonly discardRecipientV1: (
    recipient: DeviceLinkingEd25519ExportRootRecipientHandleV1,
  ) => Promise<void>;
};

type WorkerResult<TType extends keyof WalletCustodyCeremonyWorkerOperationMap> =
  WalletCustodyCeremonyWorkerOperationMap[TType]['result'];

export function createDeviceLinkingEd25519ExportRootPortV1(
  worker: WalletCustodyCeremonyTransportPort,
): DeviceLinkingEd25519ExportRootPortV1 {
  return {
    async createRecipientV1(input) {
      const created = requireRecord(
        await worker.requestOperation({
          kind: 'walletCustodyCeremony',
          request: {
            type: 'createLinkedDeviceEd25519ExportRootRecipient',
            payload: {},
          },
        }),
        'Ed25519 export-root recipient',
      ) as WorkerResult<'createLinkedDeviceEd25519ExportRootRecipient'>;
      return {
        recipientHandleId: requireHandleId(created.recipientHandleId),
        registration: parseLinkedDeviceEd25519ExportRootRecipientV1({
          kind: 'linked_device_ed25519_export_root_recipient_v1',
          linkSessionId: input.identity.linkSessionId,
          walletId: input.identity.walletId,
          walletKeyId: input.identity.walletKeyId,
          enrollmentId: input.identity.enrollmentId,
          deviceId: input.identity.deviceId,
          transferAlg: LINKED_DEVICE_ED25519_EXPORT_ROOT_TRANSFER_ALG_V1,
          applicationBindingDigestB64u: input.identity.applicationBindingDigestB64u,
          registeredPublicKeyB64u: input.identity.registeredPublicKeyB64u,
          targetFactor: input.identity.targetFactor,
          revocationEpoch: input.identity.revocationEpoch,
          recipientPublicKeyB64u: parseLinkedDeviceEd25519ExportRootRecipientPublicKeyB64u(
            created.recipientPublicKeyB64u,
          ),
          registeredAtMs: input.registeredAtMs,
        }),
      };
    },

    async sealForLinkedDeviceV1(input) {
      const recipient = input.recipient;
      if (input.capability.walletId !== String(recipient.walletId)) {
        throw new Error('Ed25519 export-root capability names another wallet');
      }
      const binding = buildLinkedDeviceEd25519ExportRootTransferBindingV1({
        linkSessionId: recipient.linkSessionId,
        walletId: recipient.walletId,
        walletKeyId: recipient.walletKeyId,
        targetFactor: recipient.targetFactor,
        enrollmentId: recipient.enrollmentId,
        deviceId: recipient.deviceId,
        revocationEpoch: recipient.revocationEpoch,
        applicationBindingDigestB64u: recipient.applicationBindingDigestB64u,
        registeredPublicKeyB64u: recipient.registeredPublicKeyB64u,
        recipientPublicKeyB64u: recipient.recipientPublicKeyB64u,
      });
      const sealed = requireRecord(
        await worker.requestOperation({
          kind: 'walletCustodyCeremony',
          request: {
            type: 'sealEd25519ExportRootForLinkedDevice',
            payload: {
              capability: input.capability,
              transferBindingJson: serializeLinkedDeviceEd25519ExportRootTransferBindingV1(binding),
            },
          },
        }),
        'Ed25519 export-root seal',
      ) as WorkerResult<'sealEd25519ExportRootForLinkedDevice'>;
      return {
        kind: 'linked_device_ed25519_export_root_package_v1',
        linkSessionId: recipient.linkSessionId,
        walletId: recipient.walletId,
        walletKeyId: recipient.walletKeyId,
        enrollmentId: recipient.enrollmentId,
        deviceId: recipient.deviceId,
        transferAlg: LINKED_DEVICE_ED25519_EXPORT_ROOT_TRANSFER_ALG_V1,
        applicationBindingDigestB64u: recipient.applicationBindingDigestB64u,
        registeredPublicKeyB64u: recipient.registeredPublicKeyB64u,
        targetFactor: recipient.targetFactor,
        revocationEpoch: recipient.revocationEpoch,
        recipientPublicKeyB64u: recipient.recipientPublicKeyB64u,
        ephemeralPublicKeyB64u: parseLinkedDeviceEd25519ExportRootRecipientPublicKeyB64u(
          sealed.ephemeralPublicKeyB64u,
          'Ed25519 export-root ephemeralPublicKeyB64u',
        ),
        nonceB64u: parseEnvelopeNonceB64u(sealed.nonceB64u, 'Ed25519 export-root nonceB64u'),
        sealedExportRootB64u: parseEnvelopeCiphertextB64u(
          sealed.sealedExportRootB64u,
          'Ed25519 export-root sealedExportRootB64u',
        ),
        bindingDigestB64u: parseDigestField(
          sealed.bindingDigestB64u,
          'Ed25519 export-root bindingDigestB64u',
        ),
        ciphertextDigestB64u: parseDigestField(
          sealed.ciphertextDigestB64u,
          'Ed25519 export-root ciphertextDigestB64u',
        ),
        sealedAtMs: input.sealedAtMs,
      };
    },

    async acceptTransferV1(input) {
      const registration = input.recipient.registration;
      const transferPackage = input.transferPackage;
      if (!rootPackageMatchesRecipient(transferPackage, registration)) {
        throw new Error('Ed25519 export-root package is addressed to another device');
      }
      const binding = buildLinkedDeviceEd25519ExportRootTransferBindingV1({
        linkSessionId: registration.linkSessionId,
        walletId: registration.walletId,
        walletKeyId: registration.walletKeyId,
        targetFactor: registration.targetFactor,
        enrollmentId: registration.enrollmentId,
        deviceId: registration.deviceId,
        revocationEpoch: registration.revocationEpoch,
        applicationBindingDigestB64u: registration.applicationBindingDigestB64u,
        registeredPublicKeyB64u: registration.registeredPublicKeyB64u,
        recipientPublicKeyB64u: registration.recipientPublicKeyB64u,
      });
      const replacementEnvelope = input.replacementEnvelope;
      if (
        replacementEnvelope.walletId !== registration.walletId ||
        replacementEnvelope.binding.kind !== 'ed25519_yao_client_root_v1' ||
        replacementEnvelope.binding.walletKeyId !== registration.walletKeyId ||
        replacementEnvelope.binding.linkSessionId !== registration.linkSessionId ||
        replacementEnvelope.binding.enrollmentId !== registration.enrollmentId ||
        replacementEnvelope.binding.deviceId !== registration.deviceId ||
        replacementEnvelope.binding.applicationBindingDigestB64u !==
          registration.applicationBindingDigestB64u ||
        replacementEnvelope.binding.registeredPublicKeyB64u !==
          registration.registeredPublicKeyB64u ||
        replacementEnvelope.binding.revocationEpoch !== registration.revocationEpoch ||
        !replacementEnvelopeFactorMatchesTargetFactor(
          registration.targetFactor,
          replacementEnvelope.factor,
        )
      ) {
        throw new Error('Ed25519 export-root replacement envelope identity is invalid');
      }
      const replacementEnvelopeBindingJson = custodyEnvelopeBindingJsonV1({
        walletId: replacementEnvelope.walletId,
        envelopeId: replacementEnvelope.envelopeId,
        factor: replacementEnvelope.factor,
        envelopeRevision: parseEnvelopeRevision(1),
        binding: replacementEnvelope.binding,
        ownership: replacementEnvelope.ownership,
      });
      const replacementFactorSecret = input.replacementFactorSecret.slice();
      try {
        const resealed = requireRecord(
          await worker.requestOperation({
            kind: 'walletCustodyCeremony',
            request: {
              type: 'acceptLinkedDeviceEd25519ExportRoot',
              payload: {
                recipientHandleId: input.recipient.recipientHandleId,
                transferBindingJson:
                  serializeLinkedDeviceEd25519ExportRootTransferBindingV1(binding),
                ephemeralPublicKeyB64u: String(transferPackage.ephemeralPublicKeyB64u),
                nonceB64u: String(transferPackage.nonceB64u),
                sealedExportRootB64u: String(transferPackage.sealedExportRootB64u),
                bindingDigestB64u: String(transferPackage.bindingDigestB64u),
                ciphertextDigestB64u: String(transferPackage.ciphertextDigestB64u),
                replacementEnvelopeBindingJson,
                replacementFactorSecret: replacementFactorSecret.buffer,
              },
              transfer: [replacementFactorSecret.buffer],
            },
          }),
          'Ed25519 export-root acceptance',
        ) as WorkerResult<'acceptLinkedDeviceEd25519ExportRoot'>;
        return {
          envelope: parsePasskeyCustodyEnvelopeRecord(
            buildPasskeyCustodyEnvelopeRecord({
              envelopeId: replacementEnvelope.envelopeId,
              walletId: replacementEnvelope.walletId,
              ownership: replacementEnvelope.ownership,
              binding: replacementEnvelope.binding,
              factor: replacementEnvelope.factor,
              envelopeRevision: parseEnvelopeRevision(1),
              nonceB64u: parseEnvelopeNonceB64u(
                resealed.nonceB64u,
                'Ed25519 export-root resealed nonceB64u',
              ),
              sealedCustodySecretB64u: parseEnvelopeCiphertextB64u(
                resealed.sealedExportRootB64u,
                'Ed25519 export-root resealed ciphertext',
              ),
              aadHashB64u: parseDigestField(
                resealed.aadHashB64u,
                'Ed25519 export-root resealed aadHashB64u',
              ),
              ciphertextDigestB64u: parseDigestField(
                resealed.ciphertextDigestB64u,
                'Ed25519 export-root resealed ciphertextDigestB64u',
              ),
              lifecycle: buildActiveEnvelopeLifecycle({
                activatedAtMs: replacementEnvelope.createdAtMs,
              }),
              createdAtMs: replacementEnvelope.createdAtMs,
              updatedAtMs: replacementEnvelope.createdAtMs,
            }),
          ),
        };
      } finally {
        // The worker transfer detaches this view after taking ownership.
        if (replacementFactorSecret.byteLength > 0) replacementFactorSecret.fill(0);
      }
    },

    async discardRecipientV1(recipient) {
      await worker.requestOperation({
        kind: 'walletCustodyCeremony',
        request: {
          type: 'discardLinkedDeviceEd25519ExportRootRecipient',
          payload: { recipientHandleId: recipient.recipientHandleId },
        },
      });
    },
  };
}

function rootPackageMatchesRecipient(
  transferPackage: LinkedDeviceEd25519ExportRootPackageV1,
  recipient: LinkedDeviceEd25519ExportRootRecipientV1,
): boolean {
  return (
    transferPackage.linkSessionId === recipient.linkSessionId &&
    transferPackage.walletId === recipient.walletId &&
    transferPackage.walletKeyId === recipient.walletKeyId &&
    transferPackage.enrollmentId === recipient.enrollmentId &&
    transferPackage.deviceId === recipient.deviceId &&
    transferPackage.applicationBindingDigestB64u === recipient.applicationBindingDigestB64u &&
    transferPackage.registeredPublicKeyB64u === recipient.registeredPublicKeyB64u &&
    transferPackage.targetFactor.kind === recipient.targetFactor.kind &&
    transferPackage.revocationEpoch === recipient.revocationEpoch &&
    transferPackage.recipientPublicKeyB64u === recipient.recipientPublicKeyB64u
  );
}

function replacementEnvelopeFactorMatchesTargetFactor(
  targetFactor: LinkedDeviceTargetFactorV1,
  replacementFactor: PasskeyCustodyEnvelopeRecord['factor'],
): boolean {
  switch (targetFactor.kind) {
    case 'passkey_prf':
      return replacementFactor.kind === 'passkey';
    case 'email_otp':
      return replacementFactor.kind === 'email_otp';
  }
  return assertNeverLinkedDeviceTargetFactor(targetFactor);
}

function assertNeverLinkedDeviceTargetFactor(value: never): never {
  throw new Error(`Unsupported linked-device target factor kind: ${String(value)}`);
}

function requireRecord<T extends Record<string, unknown> = Record<string, unknown>>(
  value: unknown,
  label: string,
): T {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} returned no result`);
  }
  return value as T;
}

function requireHandleId(value: unknown): string {
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error('Ed25519 export-root recipient handle is invalid');
  }
  return value;
}
