import QRCode from 'qrcode';
import type { DeviceLinkingWebContext } from '@/SeamsWeb/signingSurface/types';
import type {
  DeviceLinkingSession,
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
} from '@/core/types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import {
  buildCancelledClaimedPrecommitLinkedDeviceSessionState,
  buildCancelledUnclaimedLinkedDeviceSessionState,
  buildQrLinkedDeviceSessionPayloadV4,
  buildLinkedDeviceReceiptAcknowledgementV1,
  buildLinkedDeviceProvisioningCommandV1,
  buildLinkedDeviceSessionCancelClaimedRequestV1,
  buildLinkedDeviceSessionCancelUnclaimedRequestV1,
  buildLinkedDeviceSessionRetryCommittedDeliveryRequestV1,
  buildLinkedDeviceTargetCredentialRegistrationV1,
  buildDisplayingQrLinkedDeviceSessionState,
  assertNeverLinkedDeviceSessionState,
} from '@shared/device-linking';
import type {
  LinkedDeviceSessionState,
  LinkedDeviceSessionTransportEventV1,
  LinkedDeviceHolderDeliveryAcknowledgementV1,
  LinkedDeviceEnrollmentReceiptV1,
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';
import { parseLinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { errorMessage } from '@shared/utils/errors';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import { scanAndLinkDevice as scanAndLinkDeviceDevice1 } from '@/SeamsWeb/operations/devices/scanDevice';
import type {
  Device2LinkingFlowPortsV1,
  DeviceLinkingAuthenticatedTransportPortV1,
  DeviceLinkingFlowPortsV1,
  DeviceLinkingKeyMaterialHandleV1,
  LinkSessionSubscriptionV1,
} from './deviceLinkingPorts';
import { createDeviceLinkingLaneProvisioningHandoffV1 } from './deviceLinkingPorts';
import { LinkDeviceEventPhase, createLinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import type { CreateLinkDeviceFlowEventInput } from '@/core/types/sdkSentEvents';

type EmitLinkDeviceEventInput = Omit<CreateLinkDeviceFlowEventInput, 'flowId' | 'accountId'> & {
  readonly accountId?: string;
};
function createLinkSessionId(): import('@shared/signing-lanes/ids').LinkDeviceSessionId {
  const parsed = parseLinkDeviceSessionId(secureRandomId('link-session', 32));
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function createFlowId(): string {
  return secureRandomId('link-flow', 16);
}

function notifyError(callback: ((error: Error) => void) | undefined, error: Error): void {
  try {
    callback?.(error);
  } catch {
    // Consumer callback failures do not replace the domain error.
  }
}

function phaseForState(state: LinkedDeviceSessionState): LinkDeviceEventPhase {
  switch (state.state) {
    case 'displaying_qr':
    case 'expired_unclaimed':
    case 'cancelled_unclaimed':
      return LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED;
    case 'claimed_by_owner':
    case 'awaiting_target_passkey':
    case 'provisioning':
    case 'awaiting_aggregate_receipt':
    case 'active':
    case 'expired_claimed':
    case 'cancelled_claimed_precommit':
    case 'committed_completion_required':
      return LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED;
    default:
      return assertNeverLinkedDeviceSessionState(state);
  }
}

function errorForFailure(error: unknown, phase: DeviceLinkingError['phase']): DeviceLinkingError {
  if (error instanceof DeviceLinkingError) return error;
  return new DeviceLinkingError(
    errorMessage(error) || 'Device linking failed',
    DeviceLinkingErrorCode.REGISTRATION_FAILED,
    phase,
  );
}

class LinkDeviceFlowSupersededError extends Error {
  constructor() {
    super('Device-link flow was cancelled or reset');
    this.name = 'LinkDeviceFlowSupersededError';
  }
}

export class LinkDeviceFlow {
  private readonly options: StartDevice2LinkingFlowArgs;
  private readonly ports: Device2LinkingFlowPortsV1;
  private readonly flowId: string;
  private session: DeviceLinkingSession | null = null;
  private keyMaterialHandle: DeviceLinkingKeyMaterialHandleV1 | null = null;
  private authenticatedTransport: DeviceLinkingAuthenticatedTransportPortV1 | null = null;
  private subscription: LinkSessionSubscriptionV1 | null = null;
  private error?: Error;
  private cancelled = false;
  private runEpoch = 0;
  private generationInProgress = false;
  private discardInProgress: Promise<void> | null = null;
  private readonly handledStates = new Set<LinkedDeviceSessionState['state']>();

  constructor(
    _context: unknown,
    options: StartDevice2LinkingFlowArgs = {},
    ports: Device2LinkingFlowPortsV1,
  ) {
    this.options = options;
    this.flowId = createFlowId();
    this.ports = ports;
  }

  async generateQR(): Promise<StartDevice2LinkingFlowResults> {
    if (
      this.generationInProgress ||
      this.keyMaterialHandle ||
      this.subscription ||
      (this.session && !this.cancelled)
    ) {
      throw new Error('Device-link QR flow is already running');
    }
    const runEpoch = this.startRun();
    const ports = this.ports;
    this.emit({
      phase: LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED,
      status: 'started',
      message: 'Preparing device link',
      data: { role: 'display' },
      interaction: { kind: 'qr_display', overlay: 'show' },
    });

    try {
      const keyMaterial = await ports.keyMaterial.createBootstrapKeyMaterialV1();
      if (!this.isCurrentRun(runEpoch)) {
        this.keyMaterialHandle = keyMaterial.handle;
        await this.discardKeyMaterial();
        throw new LinkDeviceFlowSupersededError();
      }
      this.keyMaterialHandle = keyMaterial.handle;
      const issuedAtMs = Date.now();
      const linkSessionId = createLinkSessionId();
      const qrData = buildQrLinkedDeviceSessionPayloadV4({
        linkSessionId,
        linkPublicKeyB64u: keyMaterial.linkPublicKeyB64u,
        devicePublicKeyB64u: keyMaterial.devicePublicKeyB64u,
        issuedAtMs,
        expiresAtMs: issuedAtMs + 15 * 60 * 1000,
      });
      const state = buildDisplayingQrLinkedDeviceSessionState({
        linkSessionId,
        expiresAtMs: qrData.expiresAtMs,
      });
      const authenticatedTransport = ports.transport.createAuthenticatedSessionTransportV1({
        keyMaterial: keyMaterial.handle,
        devicePublicKeyB64u: keyMaterial.devicePublicKeyB64u,
      });
      this.authenticatedTransport = authenticatedTransport;
      this.session = { linkSessionId, state, qrData };
      await authenticatedTransport.createUnclaimedSessionV1({
        payload: qrData,
        state,
      });
      this.assertCurrentRun(runEpoch);
      const subscription = await authenticatedTransport.subscribeSessionV1({
        linkSessionId,
        onEvent: this.handleSessionTransportEvent.bind(this),
      });
      if (!this.isCurrentRun(runEpoch)) {
        await subscription.close();
        throw new LinkDeviceFlowSupersededError();
      }
      this.subscription = subscription;
      const qrCodeDataURL = await QRCode.toDataURL(JSON.stringify(qrData), {
        errorCorrectionLevel: 'M',
        margin: 2,
      });
      this.assertCurrentRun(runEpoch);
      const result = { qrData, qrCodeDataURL } satisfies StartDevice2LinkingFlowResults;
      this.emit({
        phase: LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED,
        status: 'succeeded',
        message: 'Device-link QR ready',
        data: { role: 'display' },
        interaction: { kind: 'qr_display', overlay: 'show' },
      });
      await this.options.options?.afterCall?.(true, result);
      return result;
    } catch (error: unknown) {
      try {
        await this.cleanupLocalResources();
      } catch {
        // The retained handle lets cancel/reset retry cleanup.
      }
      if (error instanceof LinkDeviceFlowSupersededError) throw error;
      this.session = null;
      this.authenticatedTransport = null;
      this.handledStates.clear();
      const failure = errorForFailure(error, 'generation');
      this.error = failure;
      this.emitFailure(failure, 'generation');
      notifyError(this.options.options?.onError, failure);
      await this.options.options?.afterCall?.(false, undefined, failure);
      throw failure;
    } finally {
      this.generationInProgress = false;
    }
  }

  getState(): {
    readonly phase: LinkDeviceEventPhase;
    readonly session: DeviceLinkingSession | null;
    readonly error?: Error;
    readonly cancelled: boolean;
  } {
    return {
      phase: this.session
        ? phaseForState(this.session.state)
        : LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED,
      session: this.session,
      ...(this.error ? { error: this.error } : {}),
      cancelled: this.cancelled,
    };
  }

  async cancel(): Promise<void> {
    if (this.cancelled) {
      await this.cleanupLocalResources();
      return;
    }
    this.cancelled = true;
    this.runEpoch += 1;
    const session = this.session;
    const keyMaterialHandle = this.keyMaterialHandle;
    const authenticatedTransport = this.authenticatedTransport;
    try {
      if (session && keyMaterialHandle && authenticatedTransport) {
        const now = Date.now();
        switch (session.state.state) {
          case 'displaying_qr':
            await authenticatedTransport.cancelSessionV1({
              request: buildLinkedDeviceSessionCancelUnclaimedRequestV1({
                linkSessionId: session.linkSessionId,
                requestedAtMs: now,
              }),
            });
            this.session = {
              ...session,
              state: buildCancelledUnclaimedLinkedDeviceSessionState({
                linkSessionId: session.linkSessionId,
                cancelledAtMs: now,
              }),
            };
            break;
          case 'claimed_by_owner':
          case 'awaiting_target_passkey':
          case 'provisioning':
            await authenticatedTransport.cancelSessionV1({
              request: buildLinkedDeviceSessionCancelClaimedRequestV1({
                linkSessionId: session.linkSessionId,
                enrollmentId: session.state.enrollmentId,
                deviceId: await this.requireDeviceId(session.state),
                reason: 'user_cancelled',
                requestedAtMs: now,
              }),
            });
            this.session = {
              ...session,
              state: buildCancelledClaimedPrecommitLinkedDeviceSessionState({
                linkSessionId: session.linkSessionId,
                walletId: session.state.walletId,
                enrollmentId: session.state.enrollmentId,
                cancelledAtMs: now,
              }),
            };
            break;
          case 'committed_completion_required':
            // Once protocol commitment exists, cancellation is completion recovery.
            break;
          case 'awaiting_aggregate_receipt':
          case 'active':
          case 'expired_unclaimed':
          case 'expired_claimed':
          case 'cancelled_unclaimed':
          case 'cancelled_claimed_precommit':
            break;
          default:
            assertNeverLinkedDeviceSessionState(session.state);
        }
      }
    } finally {
      await this.cleanupLocalResources();
    }
    this.emit({
      phase: LinkDeviceEventPhase.CANCELLED,
      status: 'cancelled',
      message: 'Device-link flow cancelled',
      interaction: { kind: 'qr_display', overlay: 'hide' },
    });
  }

  async reset(): Promise<void> {
    this.runEpoch += 1;
    this.cancelled = true;
    await this.cleanupLocalResources();
    this.session = null;
    this.error = undefined;
    this.cancelled = false;
    this.handledStates.clear();
  }

  private async requireDeviceId(
    session: Extract<
      DeviceLinkingSession['state'],
      {
        state:
          | 'claimed_by_owner'
          | 'awaiting_target_passkey'
          | 'provisioning'
          | 'committed_completion_required';
      }
    >,
  ): Promise<import('@shared/signing-lanes/ids').LinkedDeviceId> {
    if (!this.session) throw new Error('device-link session is unavailable');
    const authenticatedTransport = this.requireAuthenticatedTransport();
    const snapshot = await authenticatedTransport.getSessionV1({
      linkSessionId: session.linkSessionId,
    });
    switch (snapshot.state.state) {
      case 'displaying_qr':
      case 'expired_unclaimed':
      case 'cancelled_unclaimed':
        throw new Error('claimed device identity is unavailable');
      default:
        if (!snapshot.deviceId) throw new Error('claimed device identity is unavailable');
        return snapshot.deviceId;
    }
  }

  private async handleSessionEvent(event: LinkedDeviceSessionTransportEventV1): Promise<void> {
    if (this.cancelled || !this.session || event.linkSessionId !== this.session.linkSessionId)
      return;
    const runEpoch = this.runEpoch;
    this.session = { ...this.session, state: event.state };
    if (this.handledStates.has(event.state.state)) return;
    this.handledStates.add(event.state.state);
    switch (event.state.state) {
      case 'displaying_qr':
        return;
      case 'claimed_by_owner':
        this.emit({
          phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
          status: 'running',
          message: 'Device link claimed by owner',
          data: { role: 'display' },
          interaction: { kind: 'qr_display', overlay: 'show' },
        });
        return;
      case 'awaiting_target_passkey':
        await this.createTargetCredential(event.state, runEpoch);
        return;
      case 'provisioning':
      case 'awaiting_aggregate_receipt':
        return;
      case 'committed_completion_required':
        await this.resumeCommittedDelivery(event.state, runEpoch);
        return;
      case 'active':
        this.emit({
          phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
          status: 'succeeded',
          message: 'Linked device active',
          data: { role: 'display' },
          interaction: { kind: 'qr_display', overlay: 'hide' },
        });
        this.runEpoch += 1;
        await this.cleanupLocalResources();
        return;
      case 'expired_unclaimed':
      case 'expired_claimed': {
        const error = new DeviceLinkingError(
          'Device-link session expired',
          DeviceLinkingErrorCode.SESSION_EXPIRED,
          'registration',
        );
        this.error = error;
        this.emitFailure(error, 'registration');
        notifyError(this.options.options?.onError, error);
        this.runEpoch += 1;
        await this.cleanupLocalResources();
        return;
      }
      case 'cancelled_unclaimed':
      case 'cancelled_claimed_precommit':
        this.cancelled = true;
        this.runEpoch += 1;
        await this.cleanupLocalResources();
        return;
      default:
        return assertNeverLinkedDeviceSessionState(event.state);
    }
  }

  private async createTargetCredential(
    state: Extract<LinkedDeviceSessionState, { state: 'awaiting_target_passkey' }>,
    runEpoch: number,
  ): Promise<void> {
    if (!this.keyMaterialHandle || !this.session)
      throw new Error('device-link key material is unavailable');
    const authenticatedTransport = this.requireAuthenticatedTransport();
    const deviceId = await this.requireDeviceId(state);
    this.assertCurrentRun(runEpoch);
    const credential = await this.ports.targetCredential.createTargetCredentialV1({
      walletId: state.walletId,
      enrollmentId: state.enrollmentId,
      deviceId,
      keyMaterial: this.keyMaterialHandle,
    });
    this.assertCurrentRun(runEpoch);
    await authenticatedTransport.registerTargetCredentialV1({
      registration: buildLinkedDeviceTargetCredentialRegistrationV1({
        linkSessionId: state.linkSessionId,
        walletId: state.walletId,
        enrollmentId: state.enrollmentId,
        deviceId,
        credentialIdB64u: credential.credentialIdB64u,
        registeredAtMs: Date.now(),
      }),
    });
    this.assertCurrentRun(runEpoch);
    await this.ports.laneProvisioning.installAuthorizedLaneHolderWorkerV1({
      walletId: state.walletId,
      enrollmentId: state.enrollmentId,
      deviceId,
      credentialIdB64u: credential.credentialIdB64u,
    });
    this.assertCurrentRun(runEpoch);
    const approval = await authenticatedTransport.getApprovalV1({
      linkSessionId: state.linkSessionId,
    });
    this.assertCurrentRun(runEpoch);
    this.assertProvisioningApprovalMatchesSession({ approval, state, deviceId });
    const deliveries = await authenticatedTransport.requestProvisioningDeliveriesV1({
      command: buildLinkedDeviceProvisioningCommandV1({
        linkSessionId: state.linkSessionId,
        enrollmentId: state.enrollmentId,
        deviceId,
      }),
    });
    this.assertCurrentRun(runEpoch);
    const receipt = await this.ports.laneProvisioning.prepareLinkedDeviceLanesV1(
      createDeviceLinkingLaneProvisioningHandoffV1({
        approval,
        deliveries,
        keyMaterial: this.keyMaterialHandle,
        acknowledgeHolderDeliveriesV1: this.acknowledgeHolderDeliveries.bind(this, runEpoch),
      }),
    );
    this.assertCurrentRun(runEpoch);
    await authenticatedTransport.acknowledgeReceiptV1({
      acknowledgement: buildLinkedDeviceReceiptAcknowledgementV1({
        linkSessionId: state.linkSessionId,
        enrollmentId: state.enrollmentId,
        deviceId,
        receipt,
        acknowledgedAtMs: Date.now(),
      }),
    });
    this.assertCurrentRun(runEpoch);
  }

  private async acknowledgeHolderDeliveries(
    runEpoch: number,
    acknowledgement: LinkedDeviceHolderDeliveryAcknowledgementV1,
  ): Promise<LinkedDeviceEnrollmentReceiptV1> {
    this.assertCurrentRun(runEpoch);
    const receipt = await this.requireAuthenticatedTransport().acknowledgeHolderDeliveriesV1({
      acknowledgement,
    });
    this.assertCurrentRun(runEpoch);
    return receipt;
  }

  private assertProvisioningApprovalMatchesSession(input: {
    readonly approval: import('@shared/device-linking').LinkedDeviceApprovalV1;
    readonly state: Extract<LinkedDeviceSessionState, { state: 'awaiting_target_passkey' }>;
    readonly deviceId: import('@shared/signing-lanes/ids').LinkedDeviceId;
  }): void {
    if (!this.session) throw new Error('device-link session is unavailable');
    if (
      input.approval.linkSessionId !== input.state.linkSessionId ||
      input.approval.walletId !== input.state.walletId ||
      input.approval.enrollmentId !== input.state.enrollmentId ||
      input.approval.deviceId !== input.deviceId ||
      input.approval.linkPublicKeyB64u !== this.session.qrData.linkPublicKeyB64u ||
      input.approval.devicePublicKeyB64u !== this.session.qrData.devicePublicKeyB64u
    ) {
      throw new Error('linked-device approval does not match the claimed session');
    }
  }

  private async resumeCommittedDelivery(
    state: Extract<LinkedDeviceSessionState, { state: 'committed_completion_required' }>,
    runEpoch: number,
  ): Promise<void> {
    if (!this.keyMaterialHandle) {
      throw new DeviceLinkingError(
        'Lane provisioning port is not configured',
        DeviceLinkingErrorCode.UNSUPPORTED,
        'registration',
      );
    }
    const authenticatedTransport = this.requireAuthenticatedTransport();
    const deviceId = await this.requireDeviceId(state);
    this.assertCurrentRun(runEpoch);
    await authenticatedTransport.retryCommittedDeliveryV1({
      request: buildLinkedDeviceSessionRetryCommittedDeliveryRequestV1({
        linkSessionId: state.linkSessionId,
        enrollmentId: state.enrollmentId,
        deviceId,
        requestedAtMs: Date.now(),
      }),
    });
    this.assertCurrentRun(runEpoch);
    const receipt = await this.ports.laneProvisioning.resumeCommittedDeliveryV1({
      state,
      keyMaterial: this.keyMaterialHandle,
    });
    this.assertCurrentRun(runEpoch);
    if (!receipt || !this.session) return;
    await authenticatedTransport.acknowledgeReceiptV1({
      acknowledgement: buildLinkedDeviceReceiptAcknowledgementV1({
        linkSessionId: state.linkSessionId,
        enrollmentId: state.enrollmentId,
        deviceId,
        receipt,
        acknowledgedAtMs: Date.now(),
      }),
    });
    this.assertCurrentRun(runEpoch);
  }

  private requireAuthenticatedTransport(): DeviceLinkingAuthenticatedTransportPortV1 {
    if (!this.authenticatedTransport) {
      throw new DeviceLinkingError(
        'Authenticated link-session transport is unavailable',
        DeviceLinkingErrorCode.UNSUPPORTED,
        'registration',
      );
    }
    return this.authenticatedTransport;
  }

  private startRun(): number {
    this.runEpoch += 1;
    this.generationInProgress = true;
    this.cancelled = false;
    this.error = undefined;
    this.handledStates.clear();
    return this.runEpoch;
  }

  private isCurrentRun(runEpoch: number): boolean {
    return !this.cancelled && this.runEpoch === runEpoch;
  }

  private assertCurrentRun(runEpoch: number): void {
    if (!this.isCurrentRun(runEpoch)) throw new LinkDeviceFlowSupersededError();
  }

  private handleSessionTransportEvent(event: LinkedDeviceSessionTransportEventV1): void {
    void this.handleSessionEvent(event).catch(this.handleSessionTransportFailure.bind(this, event));
  }

  private async handleSessionTransportFailure(
    event: LinkedDeviceSessionTransportEventV1,
    error: unknown,
  ): Promise<void> {
    if (error instanceof LinkDeviceFlowSupersededError) return;
    this.handledStates.delete(event.state.state);
    const failure = errorForFailure(error, 'registration');
    this.error = failure;
    this.emitFailure(failure, 'registration');
    notifyError(this.options.options?.onError, failure);
    this.runEpoch += 1;
    try {
      await this.cleanupLocalResources();
    } catch {
      // A later cancel/reset retries any retained subscription or key handle.
    }
  }

  private async cleanupLocalResources(): Promise<void> {
    let failure: unknown;
    const subscription = this.subscription;
    if (subscription) {
      try {
        await subscription.close();
        if (this.subscription === subscription) this.subscription = null;
      } catch (error: unknown) {
        failure = error;
      }
    }
    try {
      await this.discardKeyMaterial();
    } catch (error: unknown) {
      failure ??= error;
    }
    if (failure) throw failure;
  }

  private async discardKeyMaterial(): Promise<void> {
    const handle = this.keyMaterialHandle;
    if (!handle) return;
    if (this.discardInProgress) return await this.discardInProgress;
    const discard = this.ports.keyMaterial.discardKeyMaterialV1({ handle });
    this.discardInProgress = discard;
    try {
      await discard;
      if (this.keyMaterialHandle === handle) {
        this.keyMaterialHandle = null;
        this.authenticatedTransport = null;
      }
    } finally {
      if (this.discardInProgress === discard) this.discardInProgress = null;
    }
  }

  private emitFailure(error: DeviceLinkingError, phase: DeviceLinkingError['phase']): void {
    this.emit({
      phase:
        phase === 'generation'
          ? LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED
          : LinkDeviceEventPhase.FAILED,
      status: 'failed',
      message: error.message,
      data: { role: 'display' },
      interaction: { kind: 'qr_display', overlay: 'hide' },
      error: {
        code: error.code,
        message: error.message,
        retryable: error.code !== DeviceLinkingErrorCode.UNSUPPORTED,
      },
    });
  }

  private emit(event: EmitLinkDeviceEventInput): void {
    this.options.options?.onEvent?.(createLinkDeviceFlowEvent({ flowId: this.flowId, ...event }));
  }
}

export type DeviceLinkingDomainDeps =
  | {
      readonly kind: 'iframe';
      readonly getContext: () => DeviceLinkingWebContext;
      readonly walletIframe: Pick<
        WalletIframeCoordinator,
        'shouldUseWalletIframe' | 'requireRouter'
      >;
    }
  | {
      readonly kind: 'direct';
      readonly getContext: () => DeviceLinkingWebContext;
      readonly walletIframe: Pick<
        WalletIframeCoordinator,
        'shouldUseWalletIframe' | 'requireRouter'
      >;
      readonly ports: DeviceLinkingFlowPortsV1;
    };

export class DeviceLinkingDomain {
  private readonly deps: DeviceLinkingDomainDeps;
  private activeDeviceLinkFlow: LinkDeviceFlow | null = null;

  constructor(deps: DeviceLinkingDomainDeps) {
    this.deps = deps;
  }

  async startDevice2LinkingFlow(
    args: StartDevice2LinkingFlowArgs = {},
  ): Promise<StartDevice2LinkingFlowResults> {
    if (this.deps.kind === 'direct' && !this.deps.walletIframe.shouldUseWalletIframe()) {
      const flow = new LinkDeviceFlow(this.deps.getContext(), args, this.deps.ports);
      this.activeDeviceLinkFlow = flow;
      return await flow.generateQR();
    }
    const router = await this.deps.walletIframe.requireRouter();
    return await router.startDevice2LinkingFlow(args);
  }

  async cancelDeviceLinking(): Promise<void> {
    if (this.deps.kind === 'direct' && !this.deps.walletIframe.shouldUseWalletIframe()) {
      await this.activeDeviceLinkFlow?.cancel();
      this.activeDeviceLinkFlow = null;
      return;
    }
    const router = await this.deps.walletIframe.requireRouter();
    await router.cancelDeviceLinking();
  }

  async scanAndLinkDevice(
    qrData: QrLinkedDeviceSessionPayloadV4,
    options: ScanAndLinkDeviceOptionsDevice1,
  ): Promise<LinkDeviceResult> {
    if (this.deps.kind === 'direct' && !this.deps.walletIframe.shouldUseWalletIframe()) {
      return await scanAndLinkDeviceDevice1(
        this.deps.getContext(),
        qrData,
        options,
        this.deps.ports,
      );
    }
    const router = await this.deps.walletIframe.requireRouter();
    return await router.scanAndLinkDevice({ qrData, options });
  }
}
