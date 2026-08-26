import type { LinkDeviceResult, ScanAndLinkDeviceOptionsDevice1 } from '@/core/types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import {
  buildLinkedDeviceApprovalV1,
  buildLinkedDeviceSessionClaimRequestV1,
  parseQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
import type {
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceApprovalV1,
  LinkedDeviceApprovedTargetFactorV1,
  LinkedDeviceEd25519SourceContributionPreparationV1,
  LinkedDeviceEcdsaSourceContributionPreparationV1,
  LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1,
  LinkedDeviceOrdinaryMaterialSourceContributionTupleV1,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
import type { LinkedDeviceEd25519ExportRootPackageV1 } from '@shared/device-linking/ed25519ExportRoot';
import type {
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  LinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import {
  parseWalletAuthMethodId,
  type WalletAuthMethodId,
  type WalletId,
} from '@shared/utils/domainIds';
import {
  createLinkDeviceFlowEvent,
  LinkDeviceEventPhase,
  type CreateLinkDeviceFlowEventInput,
} from '@/core/types/sdkSentEvents';
import type {
  Device1LinkingFlowPortsV1,
  LinkSessionAuthenticationV1,
  LinkSessionOwnerTransportPortV1,
  DeviceLinkingSourceContributionPortV1,
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
  if (
    left.walletSessionId !== right.walletSessionId ||
    left.authorizationId !== right.authorizationId
  ) {
    throw new Error('wallet-session authorization source changed during linking');
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
  let claimedSessionCancellation: ClaimedSessionCancellationV1 | null = null;
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
    claimedSessionCancellation = {
      linkSessionId: claim.linkSessionId,
      expectedRevision: claim.sessionRevision,
      authentication: owner.authentication,
    };
    const targetFactor = await resolveApprovedTargetFactorV1({
      targetFactor: parsedQrData.targetFactor,
      linkSessionId: claim.linkSessionId,
      sessionRevision: claim.sessionRevision,
      transport: ports.transport,
      authentication: owner.authentication,
      selectedBaseWalletAuthMethodId: parseSelectedEmailOtpBaseMethodV1(
        options.emailOtpBaseWalletAuthMethodId,
      ),
    });
    const approval = buildLinkedDeviceApprovalV1({
      linkSessionId: claim.linkSessionId,
      walletId: claim.walletId,
      enrollmentId: claim.enrollmentId,
      deviceId: claim.deviceId,
      linkPublicKeyB64u: parsedQrData.linkPublicKeyB64u,
      devicePublicKeyB64u: claim.devicePublicKeyB64u,
      targetFactor,
      permission: parsedQrData.requestedPermission,
      ownerAuthorization: owner.ownerAuthorization,
      approvedAtMs: Date.now(),
      expiresAtMs: Math.min(owner.expiresAtMs, claim.claimExpiresAtMs),
    });
    const recorded = await ports.transport.recordOwnerApprovalV1({
      approval,
      authentication: owner.authentication,
    });
    assertApprovalRecordedV1(recorded);
    claimedSessionCancellation = null;
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
    await submitSourceContributionsV1({
      transport: ports.transport,
      sourceContribution: ports.sourceContribution,
      ed25519ExportRootCapability:
        owner.exportRootRequirement === 'required' ? owner.ed25519ExportRootCapability : undefined,
      initialApproval: approval,
      authentication: owner.authentication,
      expiresAtMs: Math.min(owner.expiresAtMs, claim.claimExpiresAtMs),
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
    await cancelClaimedSessionAfterOwnerAbortV1(ports.transport, claimedSessionCancellation);
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

type ClaimedSessionCancellationV1 = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expectedRevision: number;
  readonly authentication: LinkSessionAuthenticationV1;
};

async function cancelClaimedSessionAfterOwnerAbortV1(
  transport: LinkSessionOwnerTransportPortV1,
  cancellation: ClaimedSessionCancellationV1 | null,
): Promise<void> {
  if (!cancellation) return;
  await transport.cancelClaimedSessionV1(cancellation).catch(() => undefined);
}

type ResolveApprovedTargetFactorInputV1 = {
  readonly targetFactor: QrLinkedDeviceSessionPayloadV5['targetFactor'];
  readonly linkSessionId: QrLinkedDeviceSessionPayloadV5['linkSessionId'];
  readonly sessionRevision: number;
  readonly transport: LinkSessionOwnerTransportPortV1;
  readonly authentication: Parameters<
    LinkSessionOwnerTransportPortV1['resolveEmailOtpBaseFactorV1']
  >[0]['authentication'];
  readonly selectedBaseWalletAuthMethodId: WalletAuthMethodId | null;
};

async function resolveApprovedTargetFactorV1(
  input: ResolveApprovedTargetFactorInputV1,
): Promise<LinkedDeviceApprovedTargetFactorV1> {
  if (input.targetFactor.kind === 'passkey_prf') return { kind: 'passkey_prf' };
  const result = await input.transport.resolveEmailOtpBaseFactorV1({
    linkSessionId: input.linkSessionId,
    request: { kind: 'resolve', expectedRevision: input.sessionRevision },
    authentication: input.authentication,
  });
  switch (result.resolution.kind) {
    case 'selected':
      if (
        input.selectedBaseWalletAuthMethodId !== null &&
        input.selectedBaseWalletAuthMethodId !== result.resolution.choice.baseWalletAuthMethodId
      ) {
        throw new Error('The selected Email OTP method is unavailable for this linked device');
      }
      return {
        kind: 'email_otp',
        baseWalletAuthMethodId: result.resolution.choice.baseWalletAuthMethodId,
      };
    case 'selection_required':
      return await selectRequiredEmailOtpBaseFactorV1(input, result.resolution.choices);
    case 'unavailable':
      throw new Error('No active Email OTP method can authorize this linked device');
  }
}

function parseSelectedEmailOtpBaseMethodV1(raw: string | undefined): WalletAuthMethodId | null {
  if (raw === undefined) return null;
  const parsed = parseWalletAuthMethodId(raw);
  if (!parsed.ok) throw new Error(`Selected Email OTP method: ${parsed.error.message}`);
  return parsed.value;
}

async function selectRequiredEmailOtpBaseFactorV1(
  input: ResolveApprovedTargetFactorInputV1,
  choices: Extract<
    Awaited<
      ReturnType<LinkSessionOwnerTransportPortV1['resolveEmailOtpBaseFactorV1']>
    >['resolution'],
    { readonly kind: 'selection_required' }
  >['choices'],
): Promise<LinkedDeviceApprovedTargetFactorV1> {
  const selected = input.selectedBaseWalletAuthMethodId;
  if (selected === null) {
    throw new Error('Choose the Email OTP method to use for the linked device');
  }
  if (!emailOtpBaseFactorChoicesIncludeV1(choices, selected)) {
    throw new Error('The selected Email OTP method is unavailable for this linked device');
  }
  const result = await input.transport.resolveEmailOtpBaseFactorV1({
    linkSessionId: input.linkSessionId,
    request: {
      kind: 'select',
      expectedRevision: input.sessionRevision,
      baseWalletAuthMethodId: selected,
    },
    authentication: input.authentication,
  });
  if (
    result.resolution.kind !== 'selected' ||
    result.resolution.choice.baseWalletAuthMethodId !== selected
  ) {
    throw new Error('The selected Email OTP method is unavailable for this linked device');
  }
  return { kind: 'email_otp', baseWalletAuthMethodId: selected };
}

function emailOtpBaseFactorChoicesIncludeV1(
  choices: Extract<
    Awaited<
      ReturnType<LinkSessionOwnerTransportPortV1['resolveEmailOtpBaseFactorV1']>
    >['resolution'],
    { readonly kind: 'selection_required' }
  >['choices'],
  selected: WalletAuthMethodId,
): boolean {
  for (const choice of choices) {
    if (choice.baseWalletAuthMethodId === selected) return true;
  }
  return false;
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

async function submitSourceContributionsV1(input: {
  readonly transport: LinkSessionOwnerTransportPortV1;
  readonly sourceContribution: DeviceLinkingSourceContributionPortV1;
  readonly ed25519ExportRootCapability: UnlockedWalletEd25519ExportRootCapabilityV1 | undefined;
  readonly initialApproval: LinkedDeviceApprovalV1;
  readonly authentication: Parameters<
    LinkSessionOwnerTransportPortV1['getApprovalV1']
  >[0]['authentication'];
  readonly expiresAtMs: number;
}): Promise<void> {
  let preparation: LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1 | null = null;
  let attempt = 0;
  while (Date.now() < input.expiresAtMs) {
    preparation = await input.transport.getSourceContributionPreparationV1({
      linkSessionId: input.initialApproval.linkSessionId,
      authentication: input.authentication,
    });
    if (preparation) break;
    await waitForApprovalPollV1(attempt);
    attempt += 1;
  }
  if (!preparation) {
    throw new DeviceLinkingError(
      'Device-link approval expired before target source preparation was published',
      DeviceLinkingErrorCode.SESSION_EXPIRED,
      'registration',
    );
  }
  const sourceContribution = await produceSourceContributionTupleV1({
    preparation,
    ports: input.sourceContribution,
    ed25519ExportRootCapability: input.ed25519ExportRootCapability,
    authentication: input.authentication,
  });
  const finalApproval = buildFinalLinkedDeviceApprovalV1(input.initialApproval, sourceContribution);
  const result = await input.transport.recordSourceContributionV1({
    approval: finalApproval,
    authentication: input.authentication,
  });
  assertSourceContributionRecordedV1(result);
}

function buildFinalLinkedDeviceApprovalV1(
  initialApproval: LinkedDeviceApprovalV1,
  sourceContribution: LinkedDeviceOrdinaryMaterialSourceContributionTupleV1,
): LinkedDeviceApprovalV1 {
  if (initialApproval.targetFactor.kind === 'passkey_prf') {
    return buildLinkedDeviceApprovalV1({
      linkSessionId: initialApproval.linkSessionId,
      walletId: initialApproval.walletId,
      enrollmentId: initialApproval.enrollmentId,
      deviceId: initialApproval.deviceId,
      linkPublicKeyB64u: initialApproval.linkPublicKeyB64u,
      devicePublicKeyB64u: initialApproval.devicePublicKeyB64u,
      targetFactor: initialApproval.targetFactor,
      permission: initialApproval.permission,
      ownerAuthorization: initialApproval.ownerAuthorization,
      approvedAtMs: initialApproval.approvedAtMs,
      expiresAtMs: initialApproval.expiresAtMs,
      sourceContribution,
    });
  }
  return buildLinkedDeviceApprovalV1({
    linkSessionId: initialApproval.linkSessionId,
    walletId: initialApproval.walletId,
    enrollmentId: initialApproval.enrollmentId,
    deviceId: initialApproval.deviceId,
    linkPublicKeyB64u: initialApproval.linkPublicKeyB64u,
    devicePublicKeyB64u: initialApproval.devicePublicKeyB64u,
    targetFactor: initialApproval.targetFactor,
    permission: initialApproval.permission,
    ownerAuthorization: initialApproval.ownerAuthorization,
    approvedAtMs: initialApproval.approvedAtMs,
    expiresAtMs: initialApproval.expiresAtMs,
    sourceContribution,
  });
}

async function produceSourceContributionTupleV1(input: {
  readonly preparation: LinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1;
  readonly ports: DeviceLinkingSourceContributionPortV1;
  readonly ed25519ExportRootCapability: UnlockedWalletEd25519ExportRootCapabilityV1 | undefined;
  readonly authentication: Parameters<
    LinkSessionOwnerTransportPortV1['getApprovalV1']
  >[0]['authentication'];
}): Promise<LinkedDeviceOrdinaryMaterialSourceContributionTupleV1> {
  const first = input.preparation[0];
  if (!first) throw new Error('source contribution preparation is empty');
  if (isEd25519SourceContributionPreparationV1(first)) {
    if (!input.ed25519ExportRootCapability) {
      throw new Error('Ed25519 export-root capability is required for source contribution');
    }
    const ed25519 = await input.ports.ed25519.produceSourceContributionV1({
      preparation: first,
      capability: input.ed25519ExportRootCapability,
      authentication: input.authentication,
    });
    const second = input.preparation[1];
    if (!second) return [ed25519];
    if (isEd25519SourceContributionPreparationV1(second)) {
      throw new Error('source contribution preparation repeats Ed25519');
    }
    const ecdsa = await input.ports.ecdsa.produceSourceContributionV1({
      preparation: second,
    });
    return [ed25519, ecdsa];
  }
  if (input.preparation.length !== 1) {
    throw new Error('ECDSA source contribution preparation is out of order');
  }
  const ecdsa = await input.ports.ecdsa.produceSourceContributionV1({
    preparation: first,
  });
  return [ecdsa];
}

function isEd25519SourceContributionPreparationV1(
  preparation:
    | LinkedDeviceEd25519SourceContributionPreparationV1
    | LinkedDeviceEcdsaSourceContributionPreparationV1,
): preparation is LinkedDeviceEd25519SourceContributionPreparationV1 {
  return 'kind' in preparation;
}

function assertSourceContributionRecordedV1(
  result: Awaited<ReturnType<LinkSessionOwnerTransportPortV1['recordSourceContributionV1']>>,
): void {
  if (result.state.state !== 'authority_pending_local_install' && result.state.state !== 'active') {
    throw new Error('source contribution acknowledgement did not commit the linked device');
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
