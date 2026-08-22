import type { LinkDeviceResult, ScanAndLinkDeviceOptionsDevice1 } from '@/core/types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import {
  buildLinkedDeviceApprovalV1,
  buildLinkedDeviceSessionClaimRequestV1,
  parseQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
import type {
  LinkedDeviceOwnerAuthorizationSourceV1,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
import type { LinkedDeviceEd25519ExportRootPackageV1 } from '@shared/device-linking/ed25519ExportRoot';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '@shared/signing-lanes/ids';
import type { WalletId } from '@shared/utils/domainIds';
import {
  createLinkDeviceFlowEvent,
  LinkDeviceEventPhase,
  type CreateLinkDeviceFlowEventInput,
} from '@/core/types/sdkSentEvents';
import type {
  Device1LinkingFlowPortsV1,
  LinkSessionOwnerTransportPortV1,
} from './deviceLinkingPorts';
import { errorMessage } from '@shared/utils/errors';
import type { UnlockedWalletEd25519ExportRootCapabilityV1 } from '@/core/signingEngine/workerManager/workerTypes';
import { nextLinkedDevicePollingDelayMsV1 } from './deviceLinkingHttpTransport';
import { LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1 } from '@shared/device-linking/requestProof';

type EmitLinkDeviceEventInput = Omit<CreateLinkDeviceFlowEventInput, 'flowId' | 'accountId'> & {
  readonly accountId?: string;
};

function createFlowId(qrData: QrLinkedDeviceSessionPayloadV5 | null): string {
  return qrData ? String(qrData.linkSessionId) : 'link-device-scan';
}

function createInvalidQrError(message: string): DeviceLinkingError {
  return new DeviceLinkingError(message, DeviceLinkingErrorCode.INVALID_QR_DATA, 'authorization');
}

function notifyError(callback: ((error: Error) => void) | undefined, error: Error): void {
  try {
    callback?.(error);
  } catch {
    // Consumer callback failures do not replace the domain error.
  }
}

function emitScannerEvent(
  onEvent: ScanAndLinkDeviceOptionsDevice1['onEvent'] | undefined,
  qrData: QrLinkedDeviceSessionPayloadV5 | null,
  event: EmitLinkDeviceEventInput,
): void {
  onEvent?.(
    createLinkDeviceFlowEvent({
      flowId: createFlowId(qrData),
      ...event,
      data: { role: 'scanner', ...(event.data ?? {}) },
    }),
  );
}

function assertAuthorizationSourcesMatch(
  left: LinkedDeviceOwnerAuthorizationSourceV1,
  right: LinkedDeviceOwnerAuthorizationSourceV1,
): void {
  if (left.kind !== right.kind) {
    throw new Error('owner authorization selected more than one source');
  }
  switch (left.kind) {
    case 'wallet_session':
      if (
        right.kind !== 'wallet_session' ||
        left.walletSessionId !== right.walletSessionId ||
        left.authorizationId !== right.authorizationId
      ) {
        throw new Error('wallet-session authorization source changed during linking');
      }
      return;
    case 'step_up':
      if (right.kind !== 'step_up' || left.evidenceSetId !== right.evidenceSetId) {
        throw new Error('step-up authorization source changed during linking');
      }
      return;
    default: {
      const exhaustive: never = left;
      throw new Error(`unsupported owner authorization source: ${String(exhaustive)}`);
    }
  }
}

function classifyFailure(error: unknown): DeviceLinkingError {
  if (error instanceof DeviceLinkingError) return error;
  const message = errorMessage(error) || 'Device linking failed';
  if (/expired|expiry/i.test(message)) {
    return new DeviceLinkingError(message, DeviceLinkingErrorCode.SESSION_EXPIRED, 'authorization');
  }
  return new DeviceLinkingError(
    message,
    DeviceLinkingErrorCode.REGISTRATION_FAILED,
    'registration',
  );
}

/** Strictly parse the only QR payload accepted by this browser. */
export function validateQrLinkedDeviceSessionPayloadV5(
  raw: unknown,
): QrLinkedDeviceSessionPayloadV5 {
  let parsed: QrLinkedDeviceSessionPayloadV5;
  try {
    parsed = parseQrLinkedDeviceSessionPayloadV5(raw);
  } catch (error: unknown) {
    throw createInvalidQrError(errorMessage(error) || 'Invalid linked-device QR payload');
  }
  const now = Date.now();
  if (parsed.issuedAtMs > now + LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1) {
    throw createInvalidQrError('QR payload was issued in the future');
  }
  if (parsed.expiresAtMs <= now) {
    throw new DeviceLinkingError(
      'QR code expired',
      DeviceLinkingErrorCode.SESSION_EXPIRED,
      'authorization',
    );
  }
  return parsed;
}

export async function scanAndLinkDevice(
  _context: unknown,
  qrData: QrLinkedDeviceSessionPayloadV5,
  options: ScanAndLinkDeviceOptionsDevice1,
  ports: Device1LinkingFlowPortsV1,
): Promise<LinkDeviceResult> {
  let parsedQrData: QrLinkedDeviceSessionPayloadV5 | null = null;
  emitScannerEvent(options.onEvent, parsedQrData, {
    phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
    status: 'started',
    message: 'Scanning QR code',
    interaction: { kind: 'qr_scan', overlay: 'none' },
  });

  try {
    parsedQrData = validateQrLinkedDeviceSessionPayloadV5(qrData);
    const owner = await ports.ownerAuthorization.authenticateOwnerForLinkingV1({
      payload: parsedQrData,
      requestedAtMs: Date.now(),
    });
    assertAuthorizationSourcesMatch(owner.ownerAuthorization, owner.authentication.source);
    const claim = await ports.transport.claimSessionV1({
      request: buildLinkedDeviceSessionClaimRequestV1(parsedQrData),
      authentication: owner.authentication,
    });
    if (
      claim.linkSessionId !== parsedQrData.linkSessionId ||
      claim.devicePublicKeyB64u !== parsedQrData.devicePublicKeyB64u ||
      claim.walletId !== owner.walletId
    ) {
      throw new Error('linked-device claim does not match the scanned QR payload');
    }
    const approval = buildLinkedDeviceApprovalV1({
      linkSessionId: claim.linkSessionId,
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
      linkPublicKeyB64u: parsedQrData.linkPublicKeyB64u,
      devicePublicKeyB64u: claim.devicePublicKeyB64u,
      targetFactor: parsedQrData.targetFactor,
      permission: parsedQrData.requestedPermission,
      ownerAuthorization: owner.ownerAuthorization,
      policyDigestB64u: owner.policyDigestB64u,
      operationId: owner.operationId,
      idempotencyKey: owner.idempotencyKey,
      orderedKeyBindings: owner.orderedKeyBindings,
      protocolVersions: owner.protocolVersions,
      approvedAtMs: Date.now(),
      expiresAtMs: Math.min(owner.expiresAtMs, claim.claimExpiresAtMs),
    });
    const recorded = await ports.transport.recordOwnerApprovalV1({
      approval,
      authentication: owner.authentication,
    });
    assertApprovalRecordedV1(recorded);
    await submitEd25519ExportRootIfRequiredV1({
      transport: ports.transport,
      linkSessionId: claim.linkSessionId,
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
      expiresAtMs: Math.min(owner.expiresAtMs, claim.claimExpiresAtMs),
      exportRootRequirement: owner.exportRootRequirement,
      ed25519ExportRootCapability:
        owner.exportRootRequirement === 'required' ? owner.ed25519ExportRootCapability : undefined,
      ed25519ExportRoot: ports.ed25519ExportRoot,
      authentication: owner.authentication,
    });
    const result: LinkDeviceResult = {
      success: true,
      kind: 'approval_recorded',
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
    };
    emitScannerEvent(options.onEvent, parsedQrData, {
      phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
      status: 'succeeded',
      message: 'Device-link approval recorded',
      walletId: String(claim.walletId),
      data: { enrollmentId: String(claim.enrollmentId) },
      interaction: { kind: 'qr_scan', overlay: 'none' },
    });
    await options.afterCall?.(true, result);
    return result;
  } catch (error: unknown) {
    const failure = classifyFailure(error);
    emitScannerEvent(options.onEvent, parsedQrData, {
      phase: LinkDeviceEventPhase.FAILED,
      status: 'failed',
      message: failure.message,
      interaction: { kind: 'qr_scan', overlay: 'none' },
      error: {
        code: failure.code,
        message: failure.message,
        retryable: failure.code !== DeviceLinkingErrorCode.SESSION_EXPIRED,
      },
    });
    notifyError(options.onError, failure);
    await options.afterCall?.(false, undefined, failure);
    throw failure;
  }
}

function assertApprovalRecordedV1(
  result: Awaited<ReturnType<LinkSessionOwnerTransportPortV1['recordOwnerApprovalV1']>>,
): void {
  switch (result.outcome) {
    case 'pending':
      return;
    case 'replayed':
      if (result.replay.state === 'pending') return;
      throw new Error('linked-device approval replay returned an unsupported session state');
    default: {
      const exhaustive: never = result;
      throw new Error(`unsupported linked-device approval result: ${String(exhaustive)}`);
    }
  }
}

async function submitEd25519ExportRootIfRequiredV1(input: {
  readonly transport: LinkSessionOwnerTransportPortV1;
  readonly linkSessionId: QrLinkedDeviceSessionPayloadV5['linkSessionId'];
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly expiresAtMs: number;
  readonly exportRootRequirement: 'required' | 'not_required';
  readonly ed25519ExportRootCapability?: UnlockedWalletEd25519ExportRootCapabilityV1;
  readonly ed25519ExportRoot: Device1LinkingFlowPortsV1['ed25519ExportRoot'];
  readonly authentication: Parameters<
    LinkSessionOwnerTransportPortV1['getApprovalV1']
  >[0]['authentication'];
}): Promise<void> {
  if (input.exportRootRequirement === 'not_required') return;
  if (!input.ed25519ExportRootCapability) {
    throw new Error('Ed25519 export-root capability is required for this authority');
  }
  let sealedPackage: LinkedDeviceEd25519ExportRootPackageV1 | null = null;
  let attempt = 0;
  while (Date.now() < input.expiresAtMs) {
    if (!sealedPackage) {
      const recipient = await input.transport.getEd25519ExportRootRecipientV1({
        linkSessionId: input.linkSessionId,
        authentication: input.authentication,
      });
      if (recipient) {
        if (
          String(recipient.linkSessionId) !== String(input.linkSessionId) ||
          String(recipient.walletId) !== String(input.walletId) ||
          String(recipient.enrollmentId) !== String(input.enrollmentId) ||
          String(recipient.deviceId) !== String(input.deviceId)
        ) {
          throw new Error(
            'Ed25519 export-root recipient differs from the approved linked-device session',
          );
        }
        sealedPackage = await input.ed25519ExportRoot.sealForLinkedDeviceV1({
          recipient,
          capability: input.ed25519ExportRootCapability,
          sealedAtMs: Date.now(),
        });
      }
    }
    if (sealedPackage) {
      try {
        await input.transport.submitEd25519ExportRootPackageV1({
          submission: {
            kind: 'linked_device_ed25519_export_root_submission_v1',
            linkSessionId: input.linkSessionId,
            package: sealedPackage,
          },
          authentication: input.authentication,
        });
        return;
      } catch (error: unknown) {
        const status = readErrorStatusV1(error);
        if (status !== null && status !== 408 && status !== 429 && status < 500) throw error;
      }
    }
    await waitForApprovalPollV1(attempt);
    attempt += 1;
  }
  throw new DeviceLinkingError(
    'Device-link approval expired before the export root recipient was published',
    DeviceLinkingErrorCode.SESSION_EXPIRED,
    'registration',
  );
}

function readErrorStatusV1(error: unknown): number | null {
  if (typeof error !== 'object' || error === null || Array.isArray(error)) return null;
  const status = Reflect.get(error, 'status');
  return typeof status === 'number' && Number.isSafeInteger(status) ? status : null;
}

function resolveApprovalPollV1(resolve: () => void, attempt: number): void {
  setTimeout(resolve, nextLinkedDevicePollingDelayMsV1(250, attempt));
}

async function waitForApprovalPollV1(attempt: number): Promise<void> {
  await new Promise<void>((resolve) => resolveApprovalPollV1(resolve, attempt));
}
