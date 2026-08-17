import type { LinkDeviceResult, ScanAndLinkDeviceOptionsDevice1 } from '@/core/types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import {
  buildLinkedDeviceApprovalV1,
  buildLinkedDeviceSessionClaimRequestV1,
  parseLinkedDeviceProvisioningDeliveriesSubmissionV1,
  parseQrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';
import type {
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceCustodyTransferPackageV1,
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
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
import type { UnlockedWalletCustodyTransferCapabilityV1 } from '@/core/signingEngine/workerManager/workerTypes';
import { computeLaneEnrollmentManifestDigestV1 } from '@shared/signing-lanes/rotationDigests';
import { alphabetizeStringify } from '@shared/utils/digests';
import { nextLinkedDevicePollingDelayMsV1 } from './deviceLinkingHttpTransport';
import { LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1 } from '@shared/device-linking/requestProof';

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
    // Started here, under Device 1's owner authority, so the approval that
    // authorizes this enrollment and the ceremony that will mint its owner
    // credential are the same decision rather than two that could diverge.
    // Zero-prompt: the start is authorized by the same owner Wallet Session
    // that authorized the claim, and it produces no custody material to hold.
    const ownerEnrollment = await ports.ownerAuthorization.startOwnerEnrollmentCeremonyV1({
      linkSessionId: claim.linkSessionId,
      walletId: claim.walletId,
      requestedAtMs: Date.now(),
    });
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
      ownerEnrollment: ownerEnrollment.ceremony,
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
    emitScannerEvent(options.onEvent, parsedQrData, {
      phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
      status: 'succeeded',
      message: 'QR code scanned',
      interaction: { kind: 'qr_scan', overlay: 'none' },
    });
    const completion = await awaitApprovalCompletionV1({
      result: recorded,
      transport: ports.transport,
      linkSessionId: claim.linkSessionId,
      authentication: owner.authentication,
      // Also bounded by the ceremony: past its expiry the seed could still be
      // sealed but the credential it is for could never be minted, so waiting
      // on beyond that point only keeps key material alive for nothing.
      expiresAtMs: Math.min(
        owner.expiresAtMs,
        claim.claimExpiresAtMs,
        ownerEnrollment.ceremony.expiresAtMs,
      ),
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
      sourcePreparation: ports.sourcePreparation,
      custodyTransfer: ports.custodyTransfer,
      custodyTransferCapability: owner.custodyTransferCapability,
    });
    const identity = {
      success: true,
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
    } as const;
    const result: LinkDeviceResult =
      completion.kind === 'owner_handoff_complete'
        ? { ...identity, kind: 'owner_handoff_complete' }
        : {
            ...identity,
            kind: 'lane_enrollment_complete',
            manifestDigestB64u: completion.manifestDigestB64u,
            receipt: completion.receipt,
          };
    emitScannerEvent(options.onEvent, parsedQrData, {
      phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
      status: 'succeeded',
      message: 'Device linked',
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

/**
 * How the enrollment this scanner authorized finished.
 *
 * Refactor 103 Phase 8: the canonical owner finalize commits Device 2's
 * credential and advances the link session in one transaction, so the moment
 * the session leaves `awaiting_target_passkey` the handoff is done. Device 1
 * has nothing left to contribute and must not wait on the R102 lane enrollment
 * that used to follow — on the canonical path it never runs, so waiting on it
 * would hold the scanner open until the session expired.
 *
 * The lane variant remains reachable only by a session resumed from before the
 * cutover, which still completes through the aggregate receipt.
 */
type CompletedApprovalResult =
  | { readonly kind: 'owner_handoff_complete' }
  | {
      readonly kind: 'lane_enrollment_complete';
      readonly manifestDigestB64u: DigestB64u;
      readonly receipt: LinkedDeviceEnrollmentReceiptV1;
    };

function completedApprovalFromResult(
  result: LinkedDeviceApprovalResultV1,
): CompletedApprovalResult | null {
  switch (result.outcome) {
    case 'active':
      return {
        kind: 'lane_enrollment_complete',
        manifestDigestB64u: result.receipt.manifestDigestB64u,
        receipt: result.receipt,
      };
    case 'pending':
      return ownerHandoffFromPendingState(result.state);
    case 'replayed':
      if (result.replay.state === 'active') {
        return {
          kind: 'lane_enrollment_complete',
          manifestDigestB64u: result.replay.receipt.manifestDigestB64u,
          receipt: result.replay.receipt,
        };
      }
      return ownerHandoffFromPendingState(result.replay.session);
    default: {
      const exhaustive: never = result;
      throw new Error(`unsupported approval result: ${String(exhaustive)}`);
    }
  }
}

/**
 * A session still reported as pending, read for whether the owner finalize has
 * already landed. `provisioning` is the state that finalize advances to, and it
 * is only reachable through it.
 */
function ownerHandoffFromPendingState(
  state: Extract<LinkedDeviceApprovalResultV1, { readonly outcome: 'pending' }>['state'],
): CompletedApprovalResult | null {
  switch (state.state) {
    case 'provisioning':
      return { kind: 'owner_handoff_complete' };
    case 'awaiting_target_passkey':
      return null;
    // A resumed pre-cutover session that already committed its lanes. It still
    // finishes through the aggregate receipt, so this keeps waiting for one.
    case 'committed_completion_required':
      return null;
    default: {
      const exhaustive: never = state;
      throw new Error(`unsupported pending session state: ${String(exhaustive)}`);
    }
  }
}

async function awaitApprovalCompletionV1(input: {
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
  readonly custodyTransfer: Device1LinkingFlowPortsV1['custodyTransfer'];
  readonly custodyTransferCapability: UnlockedWalletCustodyTransferCapabilityV1;
}): Promise<CompletedApprovalResult> {
  const immediate = completedApprovalFromResult(input.result);
  if (immediate) return immediate;
  let latestResult: LinkedDeviceApprovalResultV1 | null = input.result;
  let sourceHandoffComplete = false;
  let custodyTransferSubmitted = false;
  let sealedCustodyPackage: LinkedDeviceCustodyTransferPackageV1 | null = null;
  let pollAttempt = 0;
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
      const observed = latestResult;
      latestResult = null;
      let completed: CompletedApprovalResult | null = null;
      if (observed) {
        pollAttempt = 0;
        completed = completedApprovalFromResult(observed);
        if (!completed && !sourceHandoffComplete) {
          sourceHandoffComplete = await preparePendingSourceHandoffV1(input, observed);
        }
      }
      // Independent of the approval state: Device 2 publishes its recipient
      // before prompting for its own passkey, so this is ready to seal while
      // the target device is still waiting on its user.
      if (!custodyTransferSubmitted) {
        if (!sealedCustodyPackage) {
          sealedCustodyPackage = await sealCustodyForPublishedRecipientV1(input);
        }
        if (sealedCustodyPackage) {
          try {
            await submitCustodyTransferPackageV1(input, sealedCustodyPackage);
            custodyTransferSubmitted = true;
          } catch (error: unknown) {
            if (!isRetryableCustodyTransferSubmissionFailureV1(error)) throw error;
          }
        }
      }
      if (completed && custodyTransferSubmitted) return completed;
      await waitForApprovalPollV1(pollAttempt);
      pollAttempt += 1;
    }
    throw approvalWaitExpired();
  } finally {
    await subscription?.close();
  }
}

/**
 * Seals the wallet custody seed to the device that published a recipient for
 * it, from the worker-held unlocked capability — no prompt, no envelope, no
 * factor secret at this layer.
 *
 * The recipient is read back from the session rather than taken on trust: it
 * has to name the same wallet, enrollment, device, and session the owner
 * approved. A relay that answered with someone else's recipient would otherwise
 * get the seed sealed to a key the owner never approved. The recipient key
 * itself is authenticated one step earlier — Device 2 registers it under the
 * device key whose public half was in the scanned QR.
 *
 * Returns null while no recipient has been published yet, which is the normal
 * state for as long as the target device is still preparing.
 */
async function sealCustodyForPublishedRecipientV1(
  input: Parameters<typeof awaitApprovalCompletionV1>[0],
): Promise<LinkedDeviceCustodyTransferPackageV1 | null> {
  const recipient = await input.transport.getCustodyTransferRecipientV1({
    linkSessionId: input.linkSessionId,
    authentication: input.authentication,
  });
  if (!recipient) return null;
  if (
    String(recipient.linkSessionId) !== String(input.linkSessionId) ||
    String(recipient.walletId) !== String(input.walletId) ||
    String(recipient.enrollmentId) !== String(input.enrollmentId) ||
    String(recipient.deviceId) !== String(input.deviceId)
  ) {
    throw new Error('custody transfer recipient differs from the approved linked-device session');
  }
  return await input.custodyTransfer.sealForLinkedDeviceV1({
    recipient,
    capability: input.custodyTransferCapability,
    sealedAtMs: Date.now(),
  });
}

async function submitCustodyTransferPackageV1(
  input: Parameters<typeof awaitApprovalCompletionV1>[0],
  sealedPackage: LinkedDeviceCustodyTransferPackageV1,
): Promise<void> {
  await input.transport.submitCustodyTransferPackageV1({
    submission: {
      kind: 'linked_device_custody_transfer_submission_v1',
      linkSessionId: String(input.linkSessionId),
      package: sealedPackage,
    },
    authentication: input.authentication,
  });
}

function isRetryableCustodyTransferSubmissionFailureV1(error: unknown): boolean {
  const status = readErrorStatusV1(error);
  if (status === null) return true;
  return status === 408 || status === 429 || status >= 500;
}

function readErrorStatusV1(error: unknown): number | null {
  if (typeof error !== 'object' || error === null || Array.isArray(error)) return null;
  const status = Reflect.get(error, 'status');
  return typeof status === 'number' && Number.isSafeInteger(status) ? status : null;
}

async function preparePendingSourceHandoffV1(
  input: Parameters<typeof awaitApprovalCompletionV1>[0],
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
): 'awaiting_target_passkey' | 'provisioning' | 'committed_completion_required' | null {
  if (result.outcome === 'pending') return result.state.state;
  if (result.outcome === 'replayed' && result.replay.state === 'pending') {
    return result.replay.session.state;
  }
  return null;
}

function resolveApprovalPollV1(resolve: () => void, attempt: number): void {
  setTimeout(resolve, nextLinkedDevicePollingDelayMsV1(250, attempt));
}

async function waitForApprovalPollV1(attempt: number): Promise<void> {
  await new Promise<void>((resolve) => resolveApprovalPollV1(resolve, attempt));
}

function approvalWaitExpired(): DeviceLinkingError {
  return new DeviceLinkingError(
    'Device-link approval expired before target provisioning completed',
    DeviceLinkingErrorCode.SESSION_EXPIRED,
    'registration',
  );
}
