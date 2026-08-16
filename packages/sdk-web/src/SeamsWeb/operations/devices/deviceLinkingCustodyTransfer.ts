/**
 * Refactor 103 Phase 8 — the browser half of the cross-device custody
 * transfer.
 *
 * Three steps, split across two machines:
 *
 *   Device 2  createRecipientV1        publish where to seal
 *   Device 1  sealForLinkedDeviceV1    open own envelope, seal the seed
 *   Device 2  acceptTransferV1         open the seal, reseal under new passkey
 *
 * Every one of them routes into the wallet custody ceremony worker. The wallet
 * custody seed, the owner PRF, the new device's PRF, the recipient private
 * key, and the derived transfer key exist only inside that worker's wasm; this
 * module moves ciphertext and public routing facts.
 */
import {
  buildLinkedDeviceCustodyTransferBindingV1,
  parseLinkedDeviceCustodyTransferPublicKeyB64u,
  parseLinkedDeviceCustodyTransferRecipientV1,
  parseLinkedDeviceCustodyTransferSecretBindingV1,
  serializeLinkedDeviceCustodyTransferBindingV1,
  LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
  type LinkedDeviceCustodyTransferPackageV1,
  type LinkedDeviceCustodyTransferRecipientV1,
} from '@shared/device-linking/custodyTransfer';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '@shared/signing-lanes/ids';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import {
  parseEnvelopeCiphertextB64u,
  parseEnvelopeNonceB64u,
  parseDigestField,
} from '@shared/passkey-custody';
import type { WalletId } from '@shared/utils/domainIds';
import type { WalletCustodyCeremonyTransportPort } from '@/core/signingEngine/walletCustody/ceremonyStepRunner';
import type { WalletCustodyCeremonyWorkerOperationMap } from '@/core/signingEngine/workerManager/workerTypes';

/** Identity shared by both halves; reconstructed independently on each device. */
export type DeviceLinkingCustodyTransferIdentityV1 = {
  readonly linkSessionId: string;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
};

/**
 * Device 2's live recipient. The handle names a key inside the worker, so this
 * value is only meaningful for the session that created it.
 */
export type DeviceLinkingCustodyTransferRecipientHandleV1 = {
  readonly recipientHandleId: string;
  readonly registration: LinkedDeviceCustodyTransferRecipientV1;
};

/** The resealed envelope ciphertext Device 2 persists as its own factor. */
export type DeviceLinkingResealedCustodyEnvelopeV1 = {
  readonly nonceB64u: ReturnType<typeof parseEnvelopeNonceB64u>;
  readonly sealedCustodySecretB64u: ReturnType<typeof parseEnvelopeCiphertextB64u>;
  readonly aadHashB64u: ReturnType<typeof parseDigestField>;
  readonly ciphertextDigestB64u: ReturnType<typeof parseDigestField>;
};

export type DeviceLinkingCustodyTransferPortV1 = {
  /** Device 2. */
  readonly createRecipientV1: (input: {
    readonly identity: DeviceLinkingCustodyTransferIdentityV1;
    readonly registeredAtMs: number;
  }) => Promise<DeviceLinkingCustodyTransferRecipientHandleV1>;
  /** Device 1. */
  readonly sealForLinkedDeviceV1: (input: {
    readonly recipient: LinkedDeviceCustodyTransferRecipientV1;
    readonly existingEnvelope: PasskeyCustodyEnvelopeRecord;
    readonly existingFactorSecret: Uint8Array;
    readonly sealedAtMs: number;
  }) => Promise<LinkedDeviceCustodyTransferPackageV1>;
  /** Device 2. */
  readonly acceptTransferV1: (input: {
    readonly recipient: DeviceLinkingCustodyTransferRecipientHandleV1;
    readonly transferPackage: LinkedDeviceCustodyTransferPackageV1;
    readonly replacementEnvelopeBindingJson: string;
    readonly replacementFactorSecret: Uint8Array;
  }) => Promise<DeviceLinkingResealedCustodyEnvelopeV1>;
  /** Device 2, on cancel or failure. */
  readonly discardRecipientV1: (
    recipient: DeviceLinkingCustodyTransferRecipientHandleV1,
  ) => Promise<void>;
};

type CustodyTransferWorkerResult<
  TType extends keyof WalletCustodyCeremonyWorkerOperationMap,
> = WalletCustodyCeremonyWorkerOperationMap[TType]['result'];

export function createDeviceLinkingCustodyTransferPortV1(
  worker: WalletCustodyCeremonyTransportPort,
): DeviceLinkingCustodyTransferPortV1 {
  return {
    async createRecipientV1(input) {
      const created = requireRecord(
        await worker.requestOperation({
          kind: 'walletCustodyCeremony',
          request: { type: 'createLinkedDeviceCustodyTransferRecipient', payload: {} },
        }),
        'linked-device custody transfer recipient',
      ) as CustodyTransferWorkerResult<'createLinkedDeviceCustodyTransferRecipient'>;
      const recipientHandleId = requireHandleId(created.recipientHandleId);
      return {
        recipientHandleId,
        registration: parseLinkedDeviceCustodyTransferRecipientV1({
          kind: 'linked_device_custody_transfer_recipient_v1',
          linkSessionId: input.identity.linkSessionId,
          walletId: String(input.identity.walletId),
          enrollmentId: String(input.identity.enrollmentId),
          deviceId: String(input.identity.deviceId),
          transferAlg: LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
          recipientPublicKeyB64u: parseLinkedDeviceCustodyTransferPublicKeyB64u(
            created.recipientPublicKeyB64u,
          ),
          registeredAtMs: input.registeredAtMs,
        }),
      };
    },

    async sealForLinkedDeviceV1(input) {
      // Device 1 rebuilds the binding from its own view of the enrollment
      // rather than echoing a server-supplied one: the binding is the AAD, so
      // accepting it from the relay would let the relay choose what the seal
      // authenticates.
      const transferBinding = buildLinkedDeviceCustodyTransferBindingV1({
        walletId: input.recipient.walletId,
        enrollmentId: input.recipient.enrollmentId,
        deviceId: input.recipient.deviceId,
        recipientPublicKeyB64u: input.recipient.recipientPublicKeyB64u,
        binding: parseLinkedDeviceCustodyTransferSecretBindingV1(
          input.existingEnvelope.binding,
          'linked-device custody transfer existing envelope binding',
        ),
      });
      if (input.existingEnvelope.walletId !== input.recipient.walletId) {
        throw new Error('linked-device custody transfer envelope names another wallet');
      }
      // The worker transfers this buffer, so hand it a copy and zeroize ours.
      const workerFactorSecret = input.existingFactorSecret.slice();
      let sealed: CustodyTransferWorkerResult<'sealWalletCustodySeedForLinkedDevice'>;
      try {
        sealed = requireRecord(
          await worker.requestOperation({
            kind: 'walletCustodyCeremony',
            request: {
              type: 'sealWalletCustodySeedForLinkedDevice',
              payload: {
                existingEnvelope: input.existingEnvelope,
                existingFactorSecret: workerFactorSecret.buffer,
                transferBindingJson:
                  serializeLinkedDeviceCustodyTransferBindingV1(transferBinding),
              },
              transfer: [workerFactorSecret.buffer],
            },
          }),
          'linked-device custody transfer seal',
        ) as CustodyTransferWorkerResult<'sealWalletCustodySeedForLinkedDevice'>;
      } finally {
        zeroize(workerFactorSecret);
      }
      return {
        kind: 'linked_device_custody_transfer_package_v1',
        walletId: input.recipient.walletId,
        enrollmentId: input.recipient.enrollmentId,
        deviceId: input.recipient.deviceId,
        transferAlg: LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
        recipientPublicKeyB64u: input.recipient.recipientPublicKeyB64u,
        ephemeralPublicKeyB64u: parseLinkedDeviceCustodyTransferPublicKeyB64u(
          sealed.ephemeralPublicKeyB64u,
          'linked-device custody transfer ephemeralPublicKeyB64u',
        ),
        nonceB64u: parseEnvelopeNonceB64u(
          sealed.nonceB64u,
          'linked-device custody transfer nonceB64u',
        ),
        sealedCustodySecretB64u: parseEnvelopeCiphertextB64u(
          sealed.sealedCustodySecretB64u,
          'linked-device custody transfer sealedCustodySecretB64u',
        ),
        aadHashB64u: parseDigestField(
          sealed.aadHashB64u,
          'linked-device custody transfer aadHashB64u',
        ),
        ciphertextDigestB64u: parseDigestField(
          sealed.ciphertextDigestB64u,
          'linked-device custody transfer ciphertextDigestB64u',
        ),
        sealedAtMs: input.sealedAtMs,
      };
    },

    async acceptTransferV1(input) {
      const registration = input.recipient.registration;
      const transferPackage = input.transferPackage;
      // Rebuild the binding locally for the same reason Device 1 does: this is
      // the AAD, and taking it from the relay would let the relay pick what the
      // open authenticates against.
      const transferBinding = buildLinkedDeviceCustodyTransferBindingV1({
        walletId: registration.walletId,
        enrollmentId: registration.enrollmentId,
        deviceId: registration.deviceId,
        recipientPublicKeyB64u: registration.recipientPublicKeyB64u,
        binding: parseLinkedDeviceCustodyTransferSecretBindingV1(
          {
            kind: 'wallet_custody_seed_v1',
            derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
          },
          'linked-device custody transfer accepted binding',
        ),
      });
      if (
        transferPackage.walletId !== registration.walletId ||
        transferPackage.enrollmentId !== registration.enrollmentId ||
        transferPackage.deviceId !== registration.deviceId ||
        transferPackage.recipientPublicKeyB64u !== registration.recipientPublicKeyB64u
      ) {
        throw new Error('linked-device custody transfer package is addressed to another device');
      }
      const workerFactorSecret = input.replacementFactorSecret.slice();
      let resealed: CustodyTransferWorkerResult<'acceptLinkedDeviceCustodyTransfer'>;
      try {
        resealed = requireRecord(
          await worker.requestOperation({
            kind: 'walletCustodyCeremony',
            request: {
              type: 'acceptLinkedDeviceCustodyTransfer',
              payload: {
                recipientHandleId: input.recipient.recipientHandleId,
                transferBindingJson:
                  serializeLinkedDeviceCustodyTransferBindingV1(transferBinding),
                ephemeralPublicKeyB64u: String(transferPackage.ephemeralPublicKeyB64u),
                nonceB64u: String(transferPackage.nonceB64u),
                sealedCustodySecretB64u: String(transferPackage.sealedCustodySecretB64u),
                aadHashB64u: String(transferPackage.aadHashB64u),
                ciphertextDigestB64u: String(transferPackage.ciphertextDigestB64u),
                replacementEnvelopeBindingJson: input.replacementEnvelopeBindingJson,
                replacementFactorSecret: workerFactorSecret.buffer,
              },
              transfer: [workerFactorSecret.buffer],
            },
          }),
          'linked-device custody transfer accept',
        ) as CustodyTransferWorkerResult<'acceptLinkedDeviceCustodyTransfer'>;
      } finally {
        zeroize(workerFactorSecret);
      }
      return {
        nonceB64u: parseEnvelopeNonceB64u(
          resealed.nonceB64u,
          'linked-device resealed envelope nonceB64u',
        ),
        sealedCustodySecretB64u: parseEnvelopeCiphertextB64u(
          resealed.sealedCustodySecretB64u,
          'linked-device resealed envelope sealedCustodySecretB64u',
        ),
        aadHashB64u: parseDigestField(
          resealed.aadHashB64u,
          'linked-device resealed envelope aadHashB64u',
        ),
        ciphertextDigestB64u: parseDigestField(
          resealed.ciphertextDigestB64u,
          'linked-device resealed envelope ciphertextDigestB64u',
        ),
      };
    },

    async discardRecipientV1(recipient) {
      await worker.requestOperation({
        kind: 'walletCustodyCeremony',
        request: {
          type: 'discardLinkedDeviceCustodyTransferRecipient',
          payload: { recipientHandleId: recipient.recipientHandleId },
        },
      });
    },
  };
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} returned no result`);
  }
  return value as Record<string, unknown>;
}

function requireHandleId(value: unknown): string {
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error('linked-device custody transfer recipient handle is invalid');
  }
  return value;
}

function zeroize(value: Uint8Array): void {
  if (value.byteLength > 0) value.fill(0);
}
