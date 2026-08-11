import type { LinkDeviceResult, ScanAndLinkDeviceOptionsDevice1 } from '@/core/types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import {
  buildLinkedDeviceApprovalV1,
  buildLinkedDeviceSessionClaimRequestV1,
  parseLinkedDeviceProvisioningDeliveriesSubmissionV1,
  parseQrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';
import type {
  LinkedDeviceOwnerAuthorizationSourceV1,
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';
import {
  createLinkDeviceFlowEvent,
  LinkDeviceEventPhase,
  type CreateLinkDeviceFlowEventInput,
} from '@/core/types/sdkSentEvents';
import type {
  Device1LinkingFlowPortsV1,
  Device1TargetReadySourceInputV1,
  LinkedDeviceApprovalResultV1,
  LinkSessionOwnerTransportPortV1,
  LinkSessionSubscriptionV1,
} from './deviceLinkingPorts';
import { errorMessage } from '@shared/utils/errors';
import { computeLaneEnrollmentManifestDigestV1 } from '@shared/signing-lanes/rotationDigests';
import { alphabetizeStringify } from '@shared/utils/digests';

const QR_CLOCK_SKEW_MS = 60 * 1000;

type EmitLinkDeviceEventInput = Omit<CreateLinkDeviceFlowEventInput, 'flowId' | 'accountId'> & {
  readonly accountId?: string;
};

function createFlowId(qrData: QrLinkedDeviceSessionPayloadV4 | null): string {
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
  qrData: QrLinkedDeviceSessionPayloadV4 | null,
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
  if (left.kind !== right.kind)
    throw new Error('owner authorization selected more than one source');
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
export function validateQrLinkedDeviceSessionPayloadV4(
  raw: unknown,
): QrLinkedDeviceSessionPayloadV4 {
  let parsed: QrLinkedDeviceSessionPayloadV4;
  try {
    parsed = parseQrLinkedDeviceSessionPayloadV4(raw);
  } catch (error: unknown) {
    throw createInvalidQrError(errorMessage(error) || 'Invalid linked-device QR payload');
  }
  const now = Date.now();
  if (parsed.issuedAtMs > now + QR_CLOCK_SKEW_MS) {
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
  qrData: QrLinkedDeviceSessionPayloadV4,
  options: ScanAndLinkDeviceOptionsDevice1,
  ports: Device1LinkingFlowPortsV1,
): Promise<LinkDeviceResult> {
  let parsedQrData: QrLinkedDeviceSessionPayloadV4 | null = null;
  emitScannerEvent(options.onEvent, parsedQrData, {
    phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
    status: 'started',
    message: 'Scanning QR code',
    interaction: { kind: 'qr_scan', overlay: 'none' },
  });

  try {
    parsedQrData = validateQrLinkedDeviceSessionPayloadV4(qrData);
    const now = Date.now();
    const owner = await ports.ownerAuthorization.authenticateOwnerForLinkingV1({
      payload: parsedQrData,
      requestedAtMs: now,
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
    const approvedAtMs = Date.now();
    const approval = buildLinkedDeviceApprovalV1({
      linkSessionId: claim.linkSessionId,
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
      linkPublicKeyB64u: parsedQrData.linkPublicKeyB64u,
      devicePublicKeyB64u: claim.devicePublicKeyB64u,
      permission: parsedQrData.requestedPermission,
      ownerAuthorization: owner.ownerAuthorization,
      policyDigestB64u: owner.policyDigestB64u,
      operationId: owner.operationId,
      idempotencyKey: owner.idempotencyKey,
      orderedKeyBindings: owner.orderedKeyBindings,
      protocolVersions: owner.protocolVersions,
      approvedAtMs,
      expiresAtMs: Math.min(owner.expiresAtMs, claim.claimExpiresAtMs),
    });
    const recorded = await ports.transport.recordOwnerApprovalV1({
      approval,
      authentication: owner.authentication,
    });
    const activeApproval = await awaitActiveApprovalResult({
      result: recorded,
      transport: ports.transport,
      linkSessionId: claim.linkSessionId,
      authentication: owner.authentication,
      expiresAtMs: Math.min(owner.expiresAtMs, claim.claimExpiresAtMs),
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
      sourcePreparation: ports.sourcePreparation,
    });
    const result: LinkDeviceResult = {
      success: true,
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
      manifestDigestB64u: activeApproval.manifestDigestB64u,
      receipt: activeApproval.receipt,
    };
    emitScannerEvent(options.onEvent, parsedQrData, {
      phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
      status: 'succeeded',
      message: 'Device link approved',
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

type ActiveApprovalResult = Extract<LinkedDeviceApprovalResultV1, { readonly outcome: 'active' }>;

function activeApprovalFromResult(
  result: LinkedDeviceApprovalResultV1,
): ActiveApprovalResult | null {
  switch (result.outcome) {
    case 'active':
      return {
        ...result,
        manifestDigestB64u: result.receipt.manifestDigestB64u,
      };
    case 'pending':
      return null;
    case 'replayed':
      if (result.replay.state === 'active') {
        return {
          outcome: 'active',
          state: result.replay.session,
          manifestDigestB64u: result.replay.receipt.manifestDigestB64u,
          receipt: result.replay.receipt,
        };
      }
      return null;
    default: {
      const exhaustive: never = result;
      throw new Error(`unsupported approval result: ${String(exhaustive)}`);
    }
  }
}

async function awaitActiveApprovalResult(input: {
  readonly result: LinkedDeviceApprovalResultV1;
  readonly transport: LinkSessionOwnerTransportPortV1;
  readonly linkSessionId: QrLinkedDeviceSessionPayloadV4['linkSessionId'];
  readonly authentication: Parameters<
    LinkSessionOwnerTransportPortV1['getApprovalV1']
  >[0]['authentication'];
  readonly expiresAtMs: number;
  readonly walletId: Device1TargetReadySourceInputV1['walletId'];
  readonly enrollmentId: Device1TargetReadySourceInputV1['enrollmentId'];
  readonly deviceId: Device1TargetReadySourceInputV1['deviceId'];
  readonly sourcePreparation: Device1LinkingFlowPortsV1['sourcePreparation'];
}): Promise<ActiveApprovalResult> {
  const immediate = activeApprovalFromResult(input.result);
  if (immediate) return immediate;
  let latestResult: LinkedDeviceApprovalResultV1 | null = input.result;
  let sourceHandoffComplete = false;
  const onApprovalResult = (result: LinkedDeviceApprovalResultV1): void => {
    latestResult = result;
  };
  let subscription: LinkSessionSubscriptionV1 | null = null;
  try {
    subscription = await input.transport.subscribeApprovalV1({
      linkSessionId: input.linkSessionId,
      authentication: input.authentication,
      onResult: onApprovalResult,
    });
    while (Date.now() < input.expiresAtMs) {
      const observed =
        latestResult ??
        (await input.transport.getApprovalV1({
          linkSessionId: input.linkSessionId,
          authentication: input.authentication,
        }));
      latestResult = null;
      const active = activeApprovalFromResult(observed);
      if (active) return active;
      if (!sourceHandoffComplete) {
        sourceHandoffComplete = await preparePendingSourceHandoffV1(input, observed);
      }
      await waitForApprovalPollV1();
    }
    throw approvalWaitExpired();
  } finally {
    await subscription?.close();
  }
}

async function preparePendingSourceHandoffV1(
  input: Parameters<typeof awaitActiveApprovalResult>[0],
  result: LinkedDeviceApprovalResultV1,
): Promise<boolean> {
  const state = pendingApprovalStateV1(result);
  if (!state || state === 'awaiting_target_passkey') return false;
  const targetReady = await input.transport.getTargetReadyV1({
    linkSessionId: input.linkSessionId,
    authentication: input.authentication,
  });
  if (!targetReady) return false;
  if (
    targetReady.linkSessionId !== input.linkSessionId ||
    targetReady.walletId !== input.walletId ||
    targetReady.enrollmentId !== input.enrollmentId ||
    targetReady.deviceId !== input.deviceId
  ) {
    throw new Error('R102 target-ready input differs from the approved linked-device session');
  }
  const deliveries = await input.sourcePreparation.prepareTargetReadyDeliveriesV1(targetReady);
  const submission = parseLinkedDeviceProvisioningDeliveriesSubmissionV1({
    kind: 'linked_device_provisioning_deliveries_submission_v1',
    linkSessionId: targetReady.linkSessionId,
    walletId: targetReady.walletId,
    enrollmentId: targetReady.enrollmentId,
    deviceId: targetReady.deviceId,
    manifestDigestB64u: await computeLaneEnrollmentManifestDigestV1(targetReady.manifest),
    deliveries,
  });
  const persisted = await input.transport.submitPreparedProvisioningDeliveriesV1({
    submission,
    authentication: input.authentication,
  });
  if (alphabetizeStringify(persisted) !== alphabetizeStringify(submission)) {
    throw new Error('persisted R102 deliveries differ from the prepared source handoff');
  }
  return true;
}

function pendingApprovalStateV1(
  result: LinkedDeviceApprovalResultV1,
):
  | 'awaiting_target_passkey'
  | 'provisioning'
  | 'awaiting_aggregate_receipt'
  | 'committed_completion_required'
  | null {
  if (result.outcome === 'pending') return result.state.state;
  if (result.outcome === 'replayed' && result.replay.state === 'pending') {
    return result.replay.session.state;
  }
  return null;
}

function resolveApprovalPollV1(resolve: () => void): void {
  setTimeout(resolve, 250);
}

async function waitForApprovalPollV1(): Promise<void> {
  await new Promise<void>(resolveApprovalPollV1);
}

function approvalWaitExpired(): DeviceLinkingError {
  return new DeviceLinkingError(
    'Device-link approval expired before target provisioning completed',
    DeviceLinkingErrorCode.SESSION_EXPIRED,
    'registration',
  );
}
