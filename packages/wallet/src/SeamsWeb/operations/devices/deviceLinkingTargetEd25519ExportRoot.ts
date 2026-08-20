import type {
  LinkedDeviceEmailOtpVerificationResultV1,
  LinkedDeviceTargetPreparationV1,
} from '@shared/device-linking';
import type {
  LinkedDeviceEd25519ExportRootPackageV1,
  LinkedDeviceEd25519ExportRootRecipientV1,
} from '@shared/device-linking/ed25519ExportRoot';
import {
  buildLinkedDeviceEd25519ExportRootTransferBindingV1,
  parseLinkedDeviceEd25519ExportRootRecipientPublicKeyB64u,
  parseLinkedDeviceEd25519ExportRootRecipientV1,
  serializeLinkedDeviceEd25519ExportRootTransferBindingV1,
} from '@shared/device-linking/ed25519ExportRoot';
import { parseLinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import type {
  DeviceLinkingEd25519ExportRootIdentityV1,
  DeviceLinkingEd25519ExportRootPortV1,
  DeviceLinkingEd25519ExportRootRecipientHandleV1,
} from './deviceLinkingEd25519ExportRoot';
import type {
  DeviceLinkingAuthenticatedTransportPortV1 as DeviceLinkingAuthenticatedTransportPort,
  DeviceLinkingKeyMaterialHandleV1,
  DeviceLinkingKeyMaterialPortV1,
} from './deviceLinkingPorts';

export async function publishLinkedDeviceEmailOtpEd25519ExportRootRecipientV1(input: {
  readonly keyMaterial: DeviceLinkingKeyMaterialPortV1;
  readonly keyHandle: DeviceLinkingKeyMaterialHandleV1;
  readonly transport: DeviceLinkingAuthenticatedTransportPort;
  readonly identity: DeviceLinkingEd25519ExportRootIdentityV1;
  readonly registeredAtMs: number;
}): Promise<LinkedDeviceEd25519ExportRootRecipientV1> {
  const created = await input.keyMaterial.createEmailOtpEd25519ExportRootRecipientV1({
    handle: input.keyHandle,
  });
  const recipient = parseLinkedDeviceEd25519ExportRootRecipientV1({
    kind: 'linked_device_ed25519_export_root_recipient_v1',
    linkSessionId: input.identity.linkSessionId,
    walletId: input.identity.walletId,
    walletKeyId: input.identity.walletKeyId,
    enrollmentId: input.identity.enrollmentId,
    deviceId: input.identity.deviceId,
    transferAlg: 'x25519-hkdf-sha256-chacha20poly1305-v1',
    applicationBindingDigestB64u: input.identity.applicationBindingDigestB64u,
    registeredPublicKeyB64u: input.identity.registeredPublicKeyB64u,
    targetFactor: input.identity.targetFactor,
    revocationEpoch: input.identity.revocationEpoch,
    recipientPublicKeyB64u: parseLinkedDeviceEd25519ExportRootRecipientPublicKeyB64u(
      created.recipientPublicKeyB64u,
    ),
    registeredAtMs: input.registeredAtMs,
  });
  await input.transport.registerEd25519ExportRootRecipientV1({ recipient });
  return recipient;
}

export async function publishLinkedDeviceEd25519ExportRootRecipientV1(input: {
  readonly ed25519ExportRoot: DeviceLinkingEd25519ExportRootPortV1;
  readonly transport: DeviceLinkingAuthenticatedTransportPort;
  readonly identity: DeviceLinkingEd25519ExportRootIdentityV1;
  readonly registeredAtMs: number;
}): Promise<DeviceLinkingEd25519ExportRootRecipientHandleV1> {
  const recipient = await input.ed25519ExportRoot.createRecipientV1({
    identity: input.identity,
    registeredAtMs: input.registeredAtMs,
  });
  try {
    await input.transport.registerEd25519ExportRootRecipientV1({
      recipient: recipient.registration,
    });
  } catch (error) {
    await discardLinkedDeviceEd25519ExportRootRecipientV1(input.ed25519ExportRoot, recipient);
    throw error;
  }
  return recipient;
}

export async function acceptLinkedDeviceEd25519ExportRootV1(input: {
  readonly ed25519ExportRoot: DeviceLinkingEd25519ExportRootPortV1;
  readonly transport: DeviceLinkingAuthenticatedTransportPort;
  readonly recipient: DeviceLinkingEd25519ExportRootRecipientHandleV1;
  readonly replacementEnvelopeBindingJson: string;
  readonly replacementFactorSecret: Uint8Array;
  readonly expiresAtMs: number;
  readonly assertCurrentRun: () => void;
  readonly waitForPollV1: (attempt: number) => Promise<void>;
  readonly nowMs?: () => number;
}): Promise<Awaited<ReturnType<DeviceLinkingEd25519ExportRootPortV1['acceptTransferV1']>>> {
  const now = input.nowMs ?? Date.now;
  const transferPackage = await awaitEd25519ExportRootPackageForRecipientV1({
    transport: input.transport,
    recipient: input.recipient.registration,
    expiresAtMs: input.expiresAtMs,
    assertCurrentRun: input.assertCurrentRun,
    waitForPollV1: input.waitForPollV1,
    now,
  });
  return await input.ed25519ExportRoot.acceptTransferV1({
    recipient: input.recipient,
    transferPackage,
    replacementEnvelopeBindingJson: input.replacementEnvelopeBindingJson,
    replacementFactorSecret: input.replacementFactorSecret,
  });
}

export async function acceptLinkedDeviceEmailOtpEd25519ExportRootV1(input: {
  readonly keyMaterial: DeviceLinkingKeyMaterialPortV1;
  readonly keyHandle: DeviceLinkingKeyMaterialHandleV1;
  readonly transport: DeviceLinkingAuthenticatedTransportPort;
  readonly recipient: LinkedDeviceEd25519ExportRootRecipientV1;
  readonly preparation: Extract<
    LinkedDeviceTargetPreparationV1,
    { readonly targetFactor: { readonly kind: 'email_otp' } }
  >;
  readonly verification: LinkedDeviceEmailOtpVerificationResultV1;
  readonly replacementEnvelopeBindingJson: string;
  readonly expiresAtMs: number;
  readonly assertCurrentRun: () => void;
  readonly waitForPollV1: (attempt: number) => Promise<void>;
  readonly nowMs?: () => number;
}): Promise<{
  readonly orderedHolderRegistrations: Awaited<
    ReturnType<DeviceLinkingKeyMaterialPortV1['prepareEmailOtpTargetV1']>
  >['orderedHolderRegistrations'];
  readonly resealedExportRootEnvelope: {
    readonly nonceB64u: string;
    readonly sealedExportRootB64u: string;
    readonly aadHashB64u: string;
    readonly ciphertextDigestB64u: string;
  };
}> {
  const now = input.nowMs ?? Date.now;
  const transferPackage = await awaitEd25519ExportRootPackageForRecipientV1({
    transport: input.transport,
    recipient: input.recipient,
    expiresAtMs: input.expiresAtMs,
    assertCurrentRun: input.assertCurrentRun,
    waitForPollV1: input.waitForPollV1,
    now,
  });
  const binding = buildLinkedDeviceEd25519ExportRootTransferBindingV1({
    linkSessionId: input.recipient.linkSessionId,
    walletId: input.recipient.walletId,
    walletKeyId: input.recipient.walletKeyId,
    targetFactor: input.recipient.targetFactor,
    enrollmentId: input.recipient.enrollmentId,
    deviceId: input.recipient.deviceId,
    revocationEpoch: input.recipient.revocationEpoch,
    applicationBindingDigestB64u: input.recipient.applicationBindingDigestB64u,
    registeredPublicKeyB64u: input.recipient.registeredPublicKeyB64u,
    recipientPublicKeyB64u: input.recipient.recipientPublicKeyB64u,
  });
  const prepared = await input.keyMaterial.prepareEmailOtpTargetV1({
    handle: input.keyHandle,
    preparation: input.preparation,
    verification: input.verification,
    exportRoot: {
      kind: 'required',
      transferBindingJson: serializeLinkedDeviceEd25519ExportRootTransferBindingV1(binding),
      package: transferPackage,
      replacementEnvelopeBindingJson: input.replacementEnvelopeBindingJson,
    },
  });
  if (prepared.exportRootRequirement.kind !== 'required') {
    throw new Error('Email OTP export-root preparation returned no export-root envelope');
  }
  return {
    orderedHolderRegistrations: prepared.orderedHolderRegistrations,
    resealedExportRootEnvelope:
      prepared.exportRootRequirement.resealedExportRootEnvelope,
  };
}

export async function discardLinkedDeviceEd25519ExportRootRecipientV1(
  ed25519ExportRoot: DeviceLinkingEd25519ExportRootPortV1,
  recipient: DeviceLinkingEd25519ExportRootRecipientHandleV1,
): Promise<void> {
  try {
    await ed25519ExportRoot.discardRecipientV1(recipient);
  } catch {
    // A worker reset releases the private recipient even if this cleanup races it.
  }
}

async function awaitEd25519ExportRootPackageForRecipientV1(input: {
  readonly transport: DeviceLinkingAuthenticatedTransportPort;
  readonly recipient: LinkedDeviceEd25519ExportRootRecipientV1;
  readonly expiresAtMs: number;
  readonly assertCurrentRun: () => void;
  readonly waitForPollV1: (attempt: number) => Promise<void>;
  readonly now: () => number;
}): Promise<LinkedDeviceEd25519ExportRootPackageV1> {
  const linkSessionId = parseLinkDeviceSessionId(input.recipient.linkSessionId);
  if (!linkSessionId.ok) throw new Error(linkSessionId.error.message);
  let attempt = 0;
  while (input.now() < input.expiresAtMs) {
    input.assertCurrentRun();
    const transferPackage = await input.transport.getEd25519ExportRootPackageV1({
      linkSessionId: linkSessionId.value,
    });
    if (transferPackage) {
      if (!rootPackageMatchesRecipient(transferPackage, input.recipient)) {
        throw new DeviceLinkingError(
          'Device-link Ed25519 export-root package is addressed to another device',
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
    'Device-link session expired before the Ed25519 export root was sealed',
    DeviceLinkingErrorCode.SESSION_EXPIRED,
    'registration',
  );
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
