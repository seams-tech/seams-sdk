/**
 * Refactor 103 Phase 8 — Device 2's half of the wallet custody transfer.
 *
 * Two steps with the passkey prompt between them:
 *
 *   publish   name a recipient key for Device 1 to seal the wallet seed to
 *   accept    open that seal and reseal the seed under the new passkey
 *
 * The publish comes first deliberately. Device 1 cannot seal until a recipient
 * exists, and the owner is already waiting at that point, so publishing before
 * the prompt lets Device 1 seal while Device 2's user is still deciding. It is
 * started rather than awaited at the call site, because the prompt has to keep
 * the click's transient user activation.
 *
 * Only ciphertext and routing facts pass through here. The recipient private
 * key lives in the custody worker behind an opaque handle, the wallet custody
 * seed never leaves it, and the new passkey's PRF is copied in and wiped.
 */
import {
  buildPasskeyCustodyEnvelopeRecord,
  buildPasskeyEnvelopeFactor,
  buildEmailOtpEnvelopeFactor,
  parseEnvelopeRevision,
  parseEnvelopeNonceB64u,
  parseEnvelopeCiphertextB64u,
  parseDigestField,
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
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
import type {
  LinkedDeviceEmailOtpVerificationResultV1,
  LinkedDeviceTargetHolderRegistrationV1,
  LinkedDeviceTargetPreparationV1,
} from '@shared/device-linking';
import {
  parseLinkDeviceSessionId,
  parsePasskeyEnvelopeId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import type {
  DeviceLinkingCustodyTransferIdentityV1,
  DeviceLinkingCustodyTransferPortV1,
  DeviceLinkingCustodyTransferRecipientHandleV1,
} from './deviceLinkingCustodyTransfer';
import type {
  DeviceLinkingAuthenticatedTransportPortV1,
  DeviceLinkingKeyMaterialHandleV1,
  DeviceLinkingKeyMaterialPortV1,
} from './deviceLinkingPorts';

export async function publishLinkedDeviceCustodyRecipientV1(input: {
  readonly custodyTransfer: DeviceLinkingCustodyTransferPortV1;
  readonly transport: DeviceLinkingAuthenticatedTransportPortV1;
  readonly identity: DeviceLinkingCustodyTransferIdentityV1;
  readonly registeredAtMs: number;
}): Promise<DeviceLinkingCustodyTransferRecipientHandleV1> {
  const recipient = await input.custodyTransfer.createRecipientV1({
    identity: input.identity,
    registeredAtMs: input.registeredAtMs,
  });
  try {
    await input.transport.registerCustodyTransferRecipientV1({
      recipient: recipient.registration,
    });
  } catch (error: unknown) {
    // A key nobody can seal to is only a live private key in the worker.
    await discardLinkedDeviceCustodyRecipientV1(input.custodyTransfer, recipient);
    throw error;
  }
  return recipient;
}

export async function publishLinkedDeviceEmailOtpCustodyRecipientV1(input: {
  readonly keyMaterial: DeviceLinkingKeyMaterialPortV1;
  readonly keyHandle: DeviceLinkingKeyMaterialHandleV1;
  readonly transport: DeviceLinkingAuthenticatedTransportPortV1;
  readonly identity: DeviceLinkingCustodyTransferIdentityV1;
  readonly registeredAtMs: number;
}): Promise<LinkedDeviceCustodyTransferRecipientV1> {
  const created = await input.keyMaterial.createEmailOtpCustodyRecipientV1({
    handle: input.keyHandle,
  });
  const recipient = parseLinkedDeviceCustodyTransferRecipientV1({
    kind: 'linked_device_custody_transfer_recipient_v1',
    linkSessionId: input.identity.linkSessionId,
    walletId: input.identity.walletId,
    enrollmentId: input.identity.enrollmentId,
    deviceId: input.identity.deviceId,
    transferAlg: LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
    recipientPublicKeyB64u: parseLinkedDeviceCustodyTransferPublicKeyB64u(
      created.recipientPublicKeyB64u,
    ),
    registeredAtMs: input.registeredAtMs,
  });
  await input.transport.registerCustodyTransferRecipientV1({ recipient });
  return recipient;
}

export async function acceptLinkedDeviceEmailOtpCustodyTransferV1(input: {
  readonly keyMaterial: DeviceLinkingKeyMaterialPortV1;
  readonly keyHandle: DeviceLinkingKeyMaterialHandleV1;
  readonly transport: DeviceLinkingAuthenticatedTransportPortV1;
  readonly recipient: LinkedDeviceCustodyTransferRecipientV1;
  readonly preparation: Extract<
    LinkedDeviceTargetPreparationV1,
    { readonly targetFactor: { readonly kind: 'email_otp' } }
  >;
  readonly verification: LinkedDeviceEmailOtpVerificationResultV1;
  readonly expiresAtMs: number;
  readonly assertCurrentRun: () => void;
  readonly waitForPollV1: (attempt: number) => Promise<void>;
  readonly nowMs?: () => number;
}): Promise<{
  readonly custodyEnvelope: PasskeyCustodyEnvelopeRecord;
  readonly orderedHolderRegistrations: readonly [
    LinkedDeviceTargetHolderRegistrationV1,
    ...LinkedDeviceTargetHolderRegistrationV1[],
  ];
}> {
  const now = input.nowMs ?? Date.now;
  const transferPackage = await awaitSealedPackageForRecipientV1({
    transport: input.transport,
    recipient: input.recipient,
    expiresAtMs: input.expiresAtMs,
    assertCurrentRun: input.assertCurrentRun,
    waitForPollV1: input.waitForPollV1,
    now,
  });
  const envelopeId = parsePasskeyEnvelopeId(
    secureRandomId('wallet-custody-envelope', 24, 'wallet custody envelope ids'),
  );
  if (!envelopeId.ok) throw new Error(envelopeId.error.message);
  const release = input.verification.factorRelease;
  const factor = buildEmailOtpEnvelopeFactor({
    enrollmentId: release.enrollmentId,
    enrollmentSealKeyVersion: release.enrollmentSealKeyVersion,
  });
  const binding = {
    kind: 'wallet_custody_seed_v1',
    derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
  } as const;
  const transferBinding = buildLinkedDeviceCustodyTransferBindingV1({
    walletId: input.recipient.walletId,
    enrollmentId: input.recipient.enrollmentId,
    deviceId: input.recipient.deviceId,
    recipientPublicKeyB64u: input.recipient.recipientPublicKeyB64u,
    binding: parseLinkedDeviceCustodyTransferSecretBindingV1(
      binding,
      'linked-device Email OTP transfer binding',
    ),
  });
  const prepared = await input.keyMaterial.prepareEmailOtpTargetV1({
    handle: input.keyHandle,
    preparation: input.preparation,
    verification: input.verification,
    transferBindingJson: serializeLinkedDeviceCustodyTransferBindingV1(transferBinding),
    transferPackage,
    replacementEnvelopeBindingJson: JSON.stringify({
      walletId: input.recipient.walletId,
      envelopeId: envelopeId.value,
      factor,
      envelopeRevision: 1,
      binding,
    }),
  });
  const nowMs = now();
  return {
    custodyEnvelope: parsePasskeyCustodyEnvelopeRecord(
      buildPasskeyCustodyEnvelopeRecord({
        envelopeId: envelopeId.value,
        walletId: input.recipient.walletId,
        binding,
        factor,
        envelopeRevision: parseEnvelopeRevision(1),
        nonceB64u: parseEnvelopeNonceB64u(prepared.resealedCustodyEnvelope.nonceB64u),
        sealedCustodySecretB64u: parseEnvelopeCiphertextB64u(
          prepared.resealedCustodyEnvelope.sealedCustodySecretB64u,
        ),
        ciphertextDigestB64u: parseDigestField(
          prepared.resealedCustodyEnvelope.ciphertextDigestB64u,
          'linked-device Email OTP custody ciphertext digest',
        ),
        aadHashB64u: parseDigestField(
          prepared.resealedCustodyEnvelope.aadHashB64u,
          'linked-device Email OTP custody AAD hash',
        ),
        lifecycle: { state: 'active', activatedAtMs: nowMs },
        createdAtMs: nowMs,
        updatedAtMs: nowMs,
      }),
    ),
    orderedHolderRegistrations: prepared.orderedHolderRegistrations,
  };
}

/**
 * Collects the sealed package and reseals the wallet custody seed under this
 * device's new passkey.
 *
 * Bounded by `expiresAtMs` rather than by attempts: the wait is for a human on
 * the other device, and past that deadline the enrollment this seed is for can
 * no longer be finalized.
 */
export async function acceptLinkedDeviceCustodyTransferV1(input: {
  readonly custodyTransfer: DeviceLinkingCustodyTransferPortV1;
  readonly transport: DeviceLinkingAuthenticatedTransportPortV1;
  readonly recipient: DeviceLinkingCustodyTransferRecipientHandleV1;
  readonly rpId: WebAuthnRpId;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly replacementFactorSecret: Uint8Array;
  readonly expiresAtMs: number;
  /** Throws if this linking run has been superseded. Checked between polls. */
  readonly assertCurrentRun: () => void;
  readonly waitForPollV1: (attempt: number) => Promise<void>;
  readonly nowMs?: () => number;
}): Promise<PasskeyCustodyEnvelopeRecord> {
  const now = input.nowMs ?? Date.now;
  const registration = input.recipient.registration;
  const transferPackage = await awaitSealedPackageV1(input, now);

  const envelopeId = parsePasskeyEnvelopeId(
    secureRandomId('wallet-custody-envelope', 24, 'wallet custody envelope ids'),
  );
  if (!envelopeId.ok) throw new Error(envelopeId.error.message);
  const factor = buildPasskeyEnvelopeFactor({
    rpId: input.rpId,
    credentialIdB64u: input.credentialIdB64u,
  });
  // The binding is the AAD the reseal authenticates under, and it is built here
  // rather than echoed from the package for the same reason Device 1 builds its
  // own: taking it from the relay would let the relay choose what the new
  // envelope claims to be.
  const binding = {
    kind: 'wallet_custody_seed_v1',
    derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
  } as const;
  const resealed = await input.custodyTransfer.acceptTransferV1({
    recipient: input.recipient,
    transferPackage,
    replacementEnvelopeBindingJson: JSON.stringify({
      walletId: registration.walletId,
      envelopeId: envelopeId.value,
      factor,
      envelopeRevision: 1,
      binding,
    }),
    replacementFactorSecret: input.replacementFactorSecret,
  });

  const nowMs = now();
  return parsePasskeyCustodyEnvelopeRecord(
    buildPasskeyCustodyEnvelopeRecord({
      envelopeId: envelopeId.value,
      walletId: registration.walletId,
      binding,
      factor,
      envelopeRevision: parseEnvelopeRevision(1),
      nonceB64u: resealed.nonceB64u,
      sealedCustodySecretB64u: resealed.sealedCustodySecretB64u,
      ciphertextDigestB64u: resealed.ciphertextDigestB64u,
      aadHashB64u: resealed.aadHashB64u,
      lifecycle: { state: 'active', activatedAtMs: nowMs },
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
    }),
  );
}

/** Best-effort: a failed discard must not mask the failure that caused it. */
export async function discardLinkedDeviceCustodyRecipientV1(
  custodyTransfer: DeviceLinkingCustodyTransferPortV1,
  recipient: DeviceLinkingCustodyTransferRecipientHandleV1,
): Promise<void> {
  try {
    await custodyTransfer.discardRecipientV1(recipient);
  } catch {
    // The handle is worker-local and dies with the worker either way.
  }
}

async function awaitSealedPackageV1(
  input: Parameters<typeof acceptLinkedDeviceCustodyTransferV1>[0],
  now: () => number,
): Promise<LinkedDeviceCustodyTransferPackageV1> {
  const registration = input.recipient.registration;
  const linkSessionId = parseLinkDeviceSessionId(registration.linkSessionId);
  if (!linkSessionId.ok) throw new Error(linkSessionId.error.message);
  let attempt = 0;
  while (now() < input.expiresAtMs) {
    input.assertCurrentRun();
    const transferPackage = await input.transport.getCustodyTransferPackageV1({
      linkSessionId: linkSessionId.value,
    });
    if (transferPackage) {
      // The port checks the package against this recipient before opening it;
      // this is the same check one step earlier, so a package addressed
      // elsewhere fails as a link-device error rather than a worker error.
      if (
        transferPackage.walletId !== registration.walletId ||
        transferPackage.enrollmentId !== registration.enrollmentId ||
        transferPackage.deviceId !== registration.deviceId ||
        transferPackage.recipientPublicKeyB64u !== registration.recipientPublicKeyB64u
      ) {
        throw new DeviceLinkingError(
          'Device-link custody transfer package is addressed to another device',
          DeviceLinkingErrorCode.REGISTRATION_FAILED,
          'registration',
        );
      }
      return transferPackage;
    }
    await input.waitForPollV1(attempt);
    attempt += 1;
  }
  throw new DeviceLinkingError(
    'Device-link session expired before the wallet custody transfer was sealed',
    DeviceLinkingErrorCode.SESSION_EXPIRED,
    'registration',
  );
}

async function awaitSealedPackageForRecipientV1(input: {
  readonly transport: DeviceLinkingAuthenticatedTransportPortV1;
  readonly recipient: LinkedDeviceCustodyTransferRecipientV1;
  readonly expiresAtMs: number;
  readonly assertCurrentRun: () => void;
  readonly waitForPollV1: (attempt: number) => Promise<void>;
  readonly now: () => number;
}): Promise<LinkedDeviceCustodyTransferPackageV1> {
  const linkSessionId = parseLinkDeviceSessionId(input.recipient.linkSessionId);
  if (!linkSessionId.ok) throw new Error(linkSessionId.error.message);
  let attempt = 0;
  while (input.now() < input.expiresAtMs) {
    input.assertCurrentRun();
    const transferPackage = await input.transport.getCustodyTransferPackageV1({
      linkSessionId: linkSessionId.value,
    });
    if (transferPackage) {
      if (
        transferPackage.walletId !== input.recipient.walletId ||
        transferPackage.enrollmentId !== input.recipient.enrollmentId ||
        transferPackage.deviceId !== input.recipient.deviceId ||
        transferPackage.recipientPublicKeyB64u !== input.recipient.recipientPublicKeyB64u
      ) {
        throw new DeviceLinkingError(
          'Device-link custody transfer package is addressed to another device',
          DeviceLinkingErrorCode.REGISTRATION_FAILED,
          'registration',
        );
      }
      return transferPackage;
    }
    await input.waitForPollV1(attempt);
    attempt += 1;
  }
  throw new DeviceLinkingError(
    'Device-link session expired before the wallet custody transfer was sealed',
    DeviceLinkingErrorCode.SESSION_EXPIRED,
    'registration',
  );
}
