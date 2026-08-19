import type { DeviceLinkingWebContext } from '@/SeamsWeb/signingSurface/types';
import type {
  DeviceLinkingSession,
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
  LinkedDeviceTargetEmailOtpActivationV1,
  LinkedDeviceTargetPasskeyActivationV1,
} from '@/core/types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import {
  buildCancelledClaimedPrecommitLinkedDeviceSessionState,
  buildCancelledUnclaimedLinkedDeviceSessionState,
  buildQrLinkedDeviceSessionPayloadV5,
  buildLinkedDeviceReceiptAcknowledgementV1,
  buildLinkedDeviceProvisioningCommandV1,
  buildLinkedDeviceSessionCancelClaimedRequestV1,
  buildLinkedDeviceSessionCancelUnclaimedRequestV1,
  buildLinkedDeviceSessionRetryCommittedDeliveryRequestV1,
  buildLinkedDeviceTargetCredentialRegistrationV1,
  buildDisplayingQrLinkedDeviceSessionState,
  assertNeverLinkedDeviceSessionState,
  serializeQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
import { computeLinkedDeviceTargetPreparationDigestV1 } from '@shared/device-linking';
import type {
  LinkedDeviceSessionState,
  LinkedDeviceSessionTransportEventV1,
  LinkedDeviceHolderDeliveryAcknowledgementV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceApprovalV1,
  LinkedDeviceProvisioningDeliveriesV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDeviceEmailOtpChallengeResultV1,
  LinkedDeviceEmailOtpVerificationResultV1,
  LinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  LinkedDeviceWalletSessionDeliveryV1,
  LinkedDeviceOwnerFinalizeRequestV1,
  QrLinkedDeviceSessionPayloadV5,
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
  LinkedDeviceSigningSessionActivationV1,
  EmailOtpCustodyEnvelopeRecordV1,
  DeviceLinkingTargetCredentialPortV1,
  LinkSessionSubscriptionV1,
} from './deviceLinkingPorts';
import { createDeviceLinkingLaneProvisioningHandoffV1 } from './deviceLinkingPorts';
import { LinkDeviceEventPhase, createLinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import type { CreateLinkDeviceFlowEventInput } from '@/core/types/sdkSentEvents';
import { buildLinkedDeviceProvisionedExecutionEvidenceV1 } from '@/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import { nextLinkedDevicePollingDelayMsV1 } from './deviceLinkingHttpTransport';
import {
  acceptLinkedDeviceCustodyTransferV1,
  acceptLinkedDeviceEmailOtpCustodyTransferV1,
  discardLinkedDeviceCustodyRecipientV1,
  publishLinkedDeviceCustodyRecipientV1,
  publishLinkedDeviceEmailOtpCustodyRecipientV1,
} from './deviceLinkingTargetCustodyTransfer';
import type { DeviceLinkingCustodyTransferRecipientHandleV1 } from './deviceLinkingCustodyTransfer';
import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import type { LinkedDeviceCustodyTransferRecipientV1 } from '@shared/device-linking/custodyTransfer';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import {
  persistFinalizedLinkedOwnerPasskeyV1,
  type FinalizedPasskeyAuthMethodV1,
} from '../authMethods/passkey/localPasskeyProjection';

type EmitLinkDeviceEventInput = Omit<CreateLinkDeviceFlowEventInput, 'flowId' | 'accountId'> & {
  readonly accountId?: string;
};

type AwaitingTargetFactorStateV1 = Extract<
  LinkedDeviceSessionState,
  { readonly state: 'awaiting_target_factor' }
>;
type AwaitingTargetPasskeyStateV1 = Extract<
  AwaitingTargetFactorStateV1,
  { readonly targetFactor: { readonly kind: 'passkey_prf' } }
>;
type AwaitingTargetEmailOtpStateV1 = Extract<
  AwaitingTargetFactorStateV1,
  { readonly targetFactor: { readonly kind: 'email_otp' } }
>;
type PasskeyTargetPreparationV1 = Extract<
  LinkedDeviceTargetPreparationV1,
  { readonly targetFactor: { readonly kind: 'passkey_prf' } }
>;
type EmailOtpTargetPreparationV1 = Extract<
  LinkedDeviceTargetPreparationV1,
  { readonly targetFactor: { readonly kind: 'email_otp' } }
>;

function isPasskeyTargetPreparation(
  preparation: LinkedDeviceTargetPreparationV1,
): preparation is PasskeyTargetPreparationV1 {
  return (
    preparation.targetFactor.kind === 'passkey_prf' &&
    preparation.ownerEnrollment.kind === 'linked_device_passkey_owner_enrollment_v1'
  );
}

function isEmailOtpTargetPreparation(
  preparation: LinkedDeviceTargetPreparationV1,
): preparation is EmailOtpTargetPreparationV1 {
  return (
    preparation.targetFactor.kind === 'email_otp' &&
    preparation.ownerEnrollment.kind === 'linked_device_email_otp_owner_enrollment_v1'
  );
}

function isAwaitingTargetPasskeyState(
  state: AwaitingTargetFactorStateV1,
): state is AwaitingTargetPasskeyStateV1 {
  return state.targetFactor.kind === 'passkey_prf';
}

function isAwaitingTargetEmailOtpState(
  state: AwaitingTargetFactorStateV1,
): state is AwaitingTargetEmailOtpStateV1 {
  return state.targetFactor.kind === 'email_otp';
}

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

function logDevice2LinkingStageV1(input: {
  readonly flowId: string;
  readonly linkSessionId: string;
  readonly stage: string;
  readonly details?: Readonly<Record<string, unknown>>;
}): void {
  console.info('[Device2Linking]', {
    flowId: input.flowId,
    linkSessionId: input.linkSessionId,
    stage: input.stage,
    ...input.details,
  });
}

function logDevice2LinkingFailureV1(input: {
  readonly flowId: string;
  readonly linkSessionId: string;
  readonly state: LinkedDeviceSessionState['state'];
  readonly error: unknown;
}): void {
  console.error('[Device2Linking] failed', {
    flowId: input.flowId,
    linkSessionId: input.linkSessionId,
    state: input.state,
    error: errorMessage(input.error),
  });
}

function resolveSessionStateRetry(resolve: () => void, attempt: number): void {
  setTimeout(resolve, nextLinkedDevicePollingDelayMsV1(250, attempt));
}

async function waitForSessionStateRetry(attempt: number): Promise<void> {
  await new Promise<void>((resolve) => resolveSessionStateRetry(resolve, attempt));
}

function phaseForState(state: LinkedDeviceSessionState): LinkDeviceEventPhase {
  switch (state.state) {
    case 'displaying_qr':
    case 'expired_unclaimed':
    case 'cancelled_unclaimed':
      return LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED;
    case 'claimed_by_owner':
    case 'awaiting_target_factor':
    case 'provisioning':
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

async function generateQrCodeDataUrlV1(payload: string): Promise<string> {
  let qrcode: typeof import('qrcode');
  try {
    qrcode = await import('qrcode');
  } catch {
    throw new DeviceLinkingError(
      'Device-link QR generation requires the optional qrcode package',
      DeviceLinkingErrorCode.UNSUPPORTED,
      'generation',
    );
  }
  return await qrcode.toDataURL(payload, {
    errorCorrectionLevel: 'M',
    margin: 2,
  });
}

type TargetCredentialActivationState =
  | {
      readonly kind: 'idle';
    }
  | {
      readonly kind: 'in_progress';
      readonly runEpoch: number;
      readonly promise: Promise<void>;
    }
  | {
      readonly kind: 'factor_ready';
      readonly runEpoch: number;
      readonly factorSecret: Uint8Array;
    }
  | {
      readonly kind: 'consuming';
      readonly runEpoch: number;
      readonly factorSecret: Uint8Array;
    };

type EmailOtpTargetActivationBaseContextV1 = {
  readonly event: LinkedDeviceSessionTransportEventV1;
  readonly state: AwaitingTargetEmailOtpStateV1;
  readonly runEpoch: number;
  readonly deviceId: import('@shared/signing-lanes/ids').LinkedDeviceId;
  readonly preparation: EmailOtpTargetPreparationV1;
  readonly recipient: LinkedDeviceCustodyTransferRecipientV1;
};

type EmailOtpTargetActivationContextV1 = EmailOtpTargetActivationBaseContextV1 & {
  readonly challenge: LinkedDeviceEmailOtpChallengeResultV1;
};

function emailOtpTargetActivationBaseContextV1(
  context: EmailOtpTargetActivationContextV1,
): EmailOtpTargetActivationBaseContextV1 {
  return {
    event: context.event,
    state: context.state,
    runEpoch: context.runEpoch,
    deviceId: context.deviceId,
    preparation: context.preparation,
    recipient: context.recipient,
  };
}

type EmailOtpTargetActivationStateV1 =
  | { readonly kind: 'idle' }
  | { readonly kind: 'available'; readonly context: EmailOtpTargetActivationBaseContextV1 }
  | {
      readonly kind: 'starting';
      readonly context: EmailOtpTargetActivationBaseContextV1;
      readonly promise: Promise<void>;
    }
  | { readonly kind: 'awaiting_code'; readonly context: EmailOtpTargetActivationContextV1 }
  | {
      readonly kind: 'resending';
      readonly context: EmailOtpTargetActivationContextV1;
      readonly promise: Promise<void>;
    }
  | {
      readonly kind: 'submitting';
      readonly context: EmailOtpTargetActivationContextV1;
      readonly promise: Promise<void>;
    }
  | { readonly kind: 'failed'; readonly runEpoch: number; readonly message: string }
  | {
      readonly kind: 'completed';
      readonly runEpoch: number;
      readonly resealedCustodyEnvelope: EmailOtpCustodyEnvelopeRecordV1;
      readonly verificationGrant: LinkedDeviceEmailOtpVerificationResultV1['verificationGrant'];
      readonly factorRelease: LinkedDeviceEmailOtpFactorReleaseEnvelopeV1;
    };

function requireEmailOtpCustodyEnvelopeV1(
  envelope: PasskeyCustodyEnvelopeRecord,
): EmailOtpCustodyEnvelopeRecordV1 {
  if (envelope.factor.kind !== 'email_otp') {
    throw new Error('linked-device Email OTP custody transfer returned a Passkey envelope');
  }
  return {
    ...envelope,
    factor: envelope.factor,
  };
}

function assertNeverEmailOtpTargetActivationState(value: never): never {
  throw new Error(`Unknown Email OTP target activation state: ${String(value)}`);
}

function assertNeverTargetCredentialActivationState(value: never): never {
  throw new Error(`Unknown target credential activation state: ${String(value)}`);
}

function zeroizeLiveBytes(value: Uint8Array): void {
  if (value.byteLength > 0) value.fill(0);
}

/**
 * How many times the local writes are retried before the flow gives up.
 *
 * Small on purpose. A transient IndexedDB failure clears in a moment; a durable
 * one (quota, private browsing) will not clear by being asked again, and the
 * retained finalize is what protects the credential in that case, not the loop.
 */
const LINKED_OWNER_ENROLLMENT_PERSIST_ATTEMPTS_V1 = 3;

/** A committed owner finalize, held until its local writes have landed. */
type RetainedLinkedOwnerFinalizeV1 = {
  readonly request: LinkedDeviceOwnerFinalizeRequestV1;
  readonly finalized: Awaited<
    ReturnType<DeviceLinkingAuthenticatedTransportPortV1['finalizeOwnerAuthMethodV1']>
  >;
};

/**
 * Checks a finalize response against the credential it was supposed to register
 * and returns exactly the fields the local projection needs.
 *
 * Returning the projection rather than asserting in place keeps the narrowing
 * where the check is: the caller cannot reach the passkey fields without having
 * proved the response is a passkey for this wallet and this credential.
 */
function requireFinalizedOwnerPasskeyV1(
  finalized: RetainedLinkedOwnerFinalizeV1['finalized']['response'],
  expected: {
    readonly state: AwaitingTargetPasskeyStateV1;
    readonly preparation: PasskeyTargetPreparationV1;
    readonly credential: Awaited<
      ReturnType<DeviceLinkingTargetCredentialPortV1['createTargetCredentialV1']>
    >;
  },
): FinalizedPasskeyAuthMethodV1 {
  const authMethod = finalized.authMethod;
  if (authMethod.kind !== 'passkey' || authMethod.status !== 'active') {
    throw new Error('linked-device owner finalize returned a non-passkey auth method');
  }
  if (typeof finalized.rpId !== 'string') {
    throw new Error('linked-device owner finalize omitted the passkey relying party');
  }
  if (
    String(finalized.walletId) !== String(expected.state.walletId) ||
    String(finalized.rpId) !== String(expected.preparation.ownerEnrollment.registration.rpId) ||
    String(authMethod.credentialIdB64u) !==
      String(expected.credential.webauthnRegistration.credentialIdB64u)
  ) {
    throw new Error('linked-device owner finalize returned a mismatched auth method');
  }
  return {
    walletId: finalized.walletId,
    rpId: finalized.rpId,
    credentialIdB64u: authMethod.credentialIdB64u,
    credentialPublicKeyB64u: authMethod.credentialPublicKeyB64u,
    counter: authMethod.counter,
  };
}

/** The relying party the owner ceremony will verify this credential against. */
function requireTargetRpIdV1(preparation: PasskeyTargetPreparationV1): WebAuthnRpId {
  const rpId = parseWebAuthnRpId(preparation.ownerEnrollment.registration.rpId);
  if (!rpId.ok) throw new Error(rpId.error.message);
  return rpId.value;
}

export class LinkDeviceFlow {
  private readonly options: StartDevice2LinkingFlowArgs;
  private readonly ports: Device2LinkingFlowPortsV1;
  private readonly flowId: string;
  private session: DeviceLinkingSession | null = null;
  private keyMaterialHandle: DeviceLinkingKeyMaterialHandleV1 | null = null;
  private emailOtpReleasePublicKey65B64u: string | null = null;
  /**
   * Refactor 103 Phase 8. The wallet custody seed resealed under this device's
   * new passkey, waiting for the canonical finalize that registers it as an
   * owner auth method.
   */
  private resealedCustodyEnvelope: PasskeyCustodyEnvelopeRecord | null = null;
  private authenticatedTransport: DeviceLinkingAuthenticatedTransportPortV1 | null = null;
  private subscription: LinkSessionSubscriptionV1 | null = null;
  private error?: Error;
  private cancelled = false;
  private runEpoch = 0;
  private generationInProgress = false;
  private discardInProgress: Promise<void> | null = null;
  private walletSessionDeliveryInProgress: Promise<void> | null = null;
  private walletSessionDeliveryPersisted = false;
  private targetCredentialActivationState: TargetCredentialActivationState = { kind: 'idle' };
  private emailOtpTargetActivationState: EmailOtpTargetActivationStateV1 = { kind: 'idle' };
  private provisioningApproval: LinkedDeviceApprovalV1 | null = null;
  private aggregateReceipt: LinkedDeviceEnrollmentReceiptV1 | null = null;
  private targetPreparationForProvisioning: LinkedDeviceTargetPreparationV1 | null = null;
  private targetCredentialRegistrationForProvisioning:
    | LinkedDeviceTargetCredentialRegistrationV1
    | null = null;
  private readonly handledStates = new Set<LinkedDeviceSessionState['state']>();
  private sessionEventQueue: Promise<void> = Promise.resolve();

  constructor(options: StartDevice2LinkingFlowArgs, ports: Device2LinkingFlowPortsV1) {
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
      this.emailOtpReleasePublicKey65B64u = keyMaterial.emailOtpReleasePublicKey65B64u;
      const issuedAtMs = Date.now();
      const linkSessionId = createLinkSessionId();
      const qrData = buildQrLinkedDeviceSessionPayloadV5({
        linkSessionId,
        linkPublicKeyB64u: keyMaterial.linkPublicKeyB64u,
        devicePublicKeyB64u: keyMaterial.devicePublicKeyB64u,
        targetFactor: this.options.targetFactor,
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
      logDevice2LinkingStageV1({
        flowId: this.flowId,
        linkSessionId,
        stage: 'session_create_started',
      });
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
      logDevice2LinkingStageV1({
        flowId: this.flowId,
        linkSessionId,
        stage: 'session_subscription_ready',
      });
      const qrCodeDataURL = await generateQrCodeDataUrlV1(
        serializeQrLinkedDeviceSessionPayloadV5(qrData),
      );
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
          case 'awaiting_target_factor':
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
          case 'provisioning':
            // Refactor 103 Phase 8: the canonical finalize has committed — the
            // owner credential and its local records exist. Cancelling the
            // session now would record a cancelled enrollment around a live
            // credential; undoing a completed enrollment is revocation, not
            // cancellation. Local teardown only.
            break;
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
          | 'awaiting_target_factor'
          | 'provisioning'
          | 'committed_completion_required'
          | 'active';
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
    logDevice2LinkingStageV1({
      flowId: this.flowId,
      linkSessionId: event.linkSessionId,
      stage: 'session_event_received',
      details: {
        state: event.state.state,
        emittedAtMs: event.emittedAtMs,
        runEpoch: this.runEpoch,
      },
    });
    const runEpoch = this.runEpoch;
    if (event.state.state !== 'active') {
      if (this.session.state.state === 'active') return;
      this.session = { ...this.session, state: event.state };
    }
    if (this.handledStates.has(event.state.state)) {
      logDevice2LinkingStageV1({
        flowId: this.flowId,
        linkSessionId: event.linkSessionId,
        stage: 'session_event_already_handled',
        details: { state: event.state.state },
      });
      return;
    }
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
      case 'awaiting_target_factor':
        await this.prepareTargetCredentialActivation(event, runEpoch);
        return;
      // The canonical owner finalize advances the session to provisioning.
      // Lane preparation continues from the target-credential activation and
      // the session reaches active only after its aggregate receipt lands.
      case 'provisioning':
        await this.waitForTargetCredentialActivation();
        this.assertCurrentRun(runEpoch);
        await this.provisionLinkedDeviceLanesV1(event.state, runEpoch);
        return;
      case 'committed_completion_required':
        // Polling can skip the short provisioning state. A live flow still
        // owns the recipient key and must seal any missing holder records
        // before durable recovery can reconcile them.
        if (this.handledStates.has('provisioning')) return;
        await this.waitForTargetCredentialActivation();
        this.assertCurrentRun(runEpoch);
        if (
          this.keyMaterialHandle &&
          this.targetPreparationForProvisioning &&
          this.targetCredentialRegistrationForProvisioning
        ) {
          await this.provisionLinkedDeviceLanesV1(event.state, runEpoch);
          return;
        }
        await this.resumeCommittedDelivery(event.state, runEpoch);
        return;
      case 'active': {
        await this.waitForTargetCredentialActivation();
        this.assertCurrentRun(runEpoch);
        if (!this.session) throw new Error('device-link session is unavailable');
        this.session = { ...this.session, state: event.state };
        await this.ensureWalletSessionDeliveryPersistedV1({ state: event.state, runEpoch });
        const activation = this.claimSigningSessionActivationV1(runEpoch);
        try {
          await this.ports.sessionActivation.activateLinkedDeviceSigningSessionV1({
            walletId: event.state.walletId,
            enrollmentId: event.state.enrollmentId,
            activation,
          });
        } finally {
          this.clearTargetCredentialActivationState();
          this.emailOtpTargetActivationState = { kind: 'idle' };
          this.resealedCustodyEnvelope = null;
        }
        this.emit({
          phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
          status: 'succeeded',
          message: 'Linked device active',
          walletId: event.state.walletId,
          data: { role: 'display', enrollmentId: event.state.enrollmentId },
          interaction: { kind: 'qr_display', overlay: 'hide' },
        });
        this.runEpoch += 1;
        await this.cleanupLocalResources();
        return;
      }
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

  private async prepareTargetCredentialActivation(
    event: LinkedDeviceSessionTransportEventV1,
    runEpoch: number,
  ): Promise<void> {
    if (event.state.state !== 'awaiting_target_factor') {
      throw new Error('target passkey activation requires an awaiting session');
    }
    const state = event.state;
    if (!this.keyMaterialHandle || !this.session)
      throw new Error('device-link key material is unavailable');
    const authenticatedTransport = this.requireAuthenticatedTransport();
    const deviceId = await this.requireDeviceId(state);
    this.assertCurrentRun(runEpoch);
    const preparation = await authenticatedTransport.getTargetPreparationV1({
      linkSessionId: state.linkSessionId,
    });
    this.assertCurrentRun(runEpoch);
    this.assertTargetPreparationMatchesSession({ preparation, state, deviceId });
    if (isAwaitingTargetEmailOtpState(state)) {
      await this.prepareTargetEmailOtpActivation({
        event,
        state,
        runEpoch,
        deviceId,
        preparation,
      });
      return;
    }
    if (!isAwaitingTargetPasskeyState(state)) throw new Error('Unsupported target factor');
    if (!isPasskeyTargetPreparation(preparation)) {
      throw new Error('Passkey session returned a non-Passkey target preparation');
    }
    const onTargetFactorRequired = this.options.options?.onTargetFactorRequired;
    if (!onTargetFactorRequired) {
      throw new DeviceLinkingError(
        'Confirm passkey creation on Device 2 to continue linking',
        DeviceLinkingErrorCode.UNSUPPORTED,
        'registration',
      );
    }
    const activation: LinkedDeviceTargetPasskeyActivationV1 = {
      kind: 'linked_device_target_passkey_activation_v1',
      createPasskey: this.activateTargetCredential.bind(this, {
        event,
        state,
        runEpoch,
        deviceId,
        preparation,
      }),
    };
    onTargetFactorRequired(activation);
  }

  private async prepareTargetEmailOtpActivation(input: {
    readonly event: LinkedDeviceSessionTransportEventV1;
    readonly state: AwaitingTargetEmailOtpStateV1;
    readonly runEpoch: number;
    readonly deviceId: import('@shared/signing-lanes/ids').LinkedDeviceId;
    readonly preparation: LinkedDeviceTargetPreparationV1;
  }): Promise<void> {
    if (!isEmailOtpTargetPreparation(input.preparation)) {
      throw new Error('Email OTP session returned a non-Email OTP target preparation');
    }
    if (!this.keyMaterialHandle || !this.session || !this.emailOtpReleasePublicKey65B64u) {
      throw new Error('Email OTP target key material is unavailable');
    }
    if (!this.options.options?.onTargetFactorRequired) {
      throw new DeviceLinkingError(
        'Enter the Email OTP on Device 2 to continue linking',
        DeviceLinkingErrorCode.UNSUPPORTED,
        'registration',
      );
    }
    const authenticatedTransport = this.requireAuthenticatedTransport();
    const recipient = await publishLinkedDeviceEmailOtpCustodyRecipientV1({
      keyMaterial: this.ports.keyMaterial,
      keyHandle: this.keyMaterialHandle,
      transport: authenticatedTransport,
      identity: {
        linkSessionId: String(input.state.linkSessionId),
        walletId: input.state.walletId,
        enrollmentId: input.state.enrollmentId,
        deviceId: input.deviceId,
      },
      registeredAtMs: Date.now(),
    });
    this.assertCurrentRun(input.runEpoch);
    const baseContext: EmailOtpTargetActivationBaseContextV1 = {
      event: input.event,
      state: input.state,
      runEpoch: input.runEpoch,
      deviceId: input.deviceId,
      preparation: input.preparation,
      recipient,
    };
    if (input.state.emailOtpChallenge.state === 'available') {
      this.emailOtpTargetActivationState = { kind: 'available', context: baseContext };
      this.notifyEmailOtpActivationV1({
        kind: 'sending',
        maskedEmailHint: input.state.emailOtpChallenge.maskedEmailHint,
      });
      return;
    }
    const challenge: LinkedDeviceEmailOtpChallengeResultV1 = {
      kind: 'linked_device_email_otp_challenge_result_v1',
      challengeId: input.state.emailOtpChallenge.challengeId,
      maskedEmailHint: input.state.emailOtpChallenge.maskedEmailHint,
      expiresAtMs: input.state.emailOtpChallenge.expiresAtMs,
      resendAvailableAtMs: input.state.emailOtpChallenge.resendAvailableAtMs,
    };
    const context: EmailOtpTargetActivationContextV1 = { ...baseContext, challenge };
    this.emailOtpTargetActivationState = { kind: 'awaiting_code', context };
    this.notifyEmailOtpActivationV1({
      kind: 'code_input',
      maskedEmailHint: challenge.maskedEmailHint,
      expiresAtMs: challenge.expiresAtMs,
      resendAvailableAtMs: challenge.resendAvailableAtMs,
    });
  }

  private notifyEmailOtpActivationV1(
    state: LinkedDeviceTargetEmailOtpActivationV1['state'],
  ): void {
    const onTargetFactorRequired = this.options.options?.onTargetFactorRequired;
    if (!onTargetFactorRequired) return;
    onTargetFactorRequired({
      kind: 'linked_device_target_email_otp_activation_v1',
      state,
      sendCode: this.sendTargetEmailOtpCodeV1.bind(this),
      submitCode: this.submitTargetEmailOtpCodeV1.bind(this),
      resendCode: this.resendTargetEmailOtpCodeV1.bind(this),
    });
  }

  private sendTargetEmailOtpCodeV1(): Promise<void> {
    const state = this.emailOtpTargetActivationState;
    switch (state.kind) {
      case 'available': {
        const promise = this.startTargetEmailOtpChallengeV1(state.context);
        this.emailOtpTargetActivationState = {
          kind: 'starting',
          context: state.context,
          promise,
        };
        return promise;
      }
      case 'starting':
        return state.promise;
      case 'resending':
        return state.promise;
      case 'awaiting_code':
      case 'submitting':
      case 'completed':
        return Promise.resolve();
      case 'failed':
        return Promise.reject(new Error(state.message));
      case 'idle':
        return Promise.reject(new Error('Email OTP activation is unavailable'));
      default:
        return assertNeverEmailOtpTargetActivationState(state);
    }
  }

  private async startTargetEmailOtpChallengeV1(
    context: EmailOtpTargetActivationBaseContextV1,
  ): Promise<void> {
    try {
      this.assertCurrentRun(context.runEpoch);
      const workerEphemeralPublicKey65B64u = this.emailOtpReleasePublicKey65B64u;
      if (!workerEphemeralPublicKey65B64u) {
        throw new Error('Email OTP factor-release recipient is unavailable');
      }
      const challenge =
        await this.requireAuthenticatedTransport().startTargetEmailOtpChallengeV1({
          request: {
            kind: 'linked_device_email_otp_challenge_start_request_v1',
            linkSessionId: context.state.linkSessionId,
            workerEphemeralPublicKey65B64u,
          },
        });
      this.assertCurrentRun(context.runEpoch);
      const nextContext: EmailOtpTargetActivationContextV1 = {
        event: context.event,
        state: context.state,
        runEpoch: context.runEpoch,
        deviceId: context.deviceId,
        preparation: context.preparation,
        recipient: context.recipient,
        challenge,
      };
      this.emailOtpTargetActivationState = { kind: 'awaiting_code', context: nextContext };
      this.notifyEmailOtpActivationV1({
        kind: 'code_input',
        maskedEmailHint: challenge.maskedEmailHint,
        expiresAtMs: challenge.expiresAtMs,
        resendAvailableAtMs: challenge.resendAvailableAtMs,
      });
    } catch (error: unknown) {
      if (this.isCurrentRun(context.runEpoch)) {
        this.emailOtpTargetActivationState = { kind: 'available', context };
        this.notifyEmailOtpActivationV1({
          kind: 'unavailable',
          message: errorMessage(error),
        });
      }
      throw error;
    }
  }

  private resendTargetEmailOtpCodeV1(): Promise<void> {
    const state = this.emailOtpTargetActivationState;
    if (state.kind === 'resending') return state.promise;
    if (state.kind !== 'awaiting_code') {
      return Promise.reject(new Error('Email OTP challenge is not ready to resend'));
    }
    try {
      this.assertCurrentRun(state.context.runEpoch);
    } catch (error: unknown) {
      return Promise.reject(error);
    }
    const promise = this.runTargetEmailOtpResendV1(state.context);
    this.emailOtpTargetActivationState = {
      kind: 'resending',
      context: state.context,
      promise,
    };
    this.notifyEmailOtpActivationV1({
      kind: 'resending',
      maskedEmailHint: state.context.challenge.maskedEmailHint,
    });
    return promise;
  }

  private async runTargetEmailOtpResendV1(
    context: EmailOtpTargetActivationContextV1,
  ): Promise<void> {
    try {
      const challenge =
        await this.requireAuthenticatedTransport().resendTargetEmailOtpChallengeV1({
          request: {
            kind: 'linked_device_email_otp_challenge_resend_request_v1',
            linkSessionId: context.state.linkSessionId,
            challengeId: context.challenge.challengeId,
          },
        });
      this.assertCurrentRun(context.runEpoch);
      const nextContext: EmailOtpTargetActivationContextV1 = {
        event: context.event,
        state: context.state,
        runEpoch: context.runEpoch,
        deviceId: context.deviceId,
        preparation: context.preparation,
        recipient: context.recipient,
        challenge,
      };
      this.emailOtpTargetActivationState = { kind: 'awaiting_code', context: nextContext };
      this.notifyEmailOtpActivationV1({
        kind: 'code_input',
        maskedEmailHint: challenge.maskedEmailHint,
        expiresAtMs: challenge.expiresAtMs,
        resendAvailableAtMs: challenge.resendAvailableAtMs,
      });
    } catch (error: unknown) {
      if (this.isCurrentRun(context.runEpoch)) {
        const message = errorMessage(error) || 'Email OTP resend is unavailable';
        this.emailOtpTargetActivationState = {
          kind: 'available',
          context: emailOtpTargetActivationBaseContextV1(context),
        };
        this.notifyEmailOtpActivationV1({ kind: 'unavailable', message });
      }
      throw error;
    }
  }

  private submitTargetEmailOtpCodeV1(otpCode: string): Promise<void> {
    const state = this.emailOtpTargetActivationState;
    if (state.kind !== 'awaiting_code') {
      return Promise.reject(new Error('Email OTP challenge is not ready for verification'));
    }
    this.assertCurrentRun(state.context.runEpoch);
    const promise = this.completeTargetEmailOtpActivationV1(state.context, otpCode);
    this.emailOtpTargetActivationState = {
      kind: 'submitting',
      context: state.context,
      promise,
    };
    this.notifyEmailOtpActivationV1({
      kind: 'submitting',
      maskedEmailHint: state.context.challenge.maskedEmailHint,
      expiresAtMs: state.context.challenge.expiresAtMs,
      resendAvailableAtMs: state.context.challenge.resendAvailableAtMs,
    });
    return promise;
  }

  private async completeTargetEmailOtpActivationV1(
    context: EmailOtpTargetActivationContextV1,
    otpCode: string,
  ): Promise<void> {
    let verification: LinkedDeviceEmailOtpVerificationResultV1;
    try {
      verification = await this.requireAuthenticatedTransport().verifyTargetEmailOtpChallengeV1({
        request: {
          kind: 'linked_device_email_otp_challenge_verify_request_v1',
          linkSessionId: context.state.linkSessionId,
          challengeId: context.challenge.challengeId,
          otpCode,
        },
      });
    } catch (error: unknown) {
      if (this.isCurrentRun(context.runEpoch)) {
        this.emailOtpTargetActivationState = { kind: 'awaiting_code', context };
        if (Date.now() >= context.challenge.expiresAtMs) {
          this.notifyEmailOtpActivationV1({
            kind: 'expired',
            maskedEmailHint: context.challenge.maskedEmailHint,
            message: errorMessage(error),
          });
        } else {
          this.notifyEmailOtpActivationV1({
            kind: 'incorrect',
            maskedEmailHint: context.challenge.maskedEmailHint,
            expiresAtMs: context.challenge.expiresAtMs,
            resendAvailableAtMs: context.challenge.resendAvailableAtMs,
            message: errorMessage(error),
          });
        }
      }
      throw error;
    }
    this.assertCurrentRun(context.runEpoch);
    try {
      const accepted = await acceptLinkedDeviceEmailOtpCustodyTransferV1({
        keyMaterial: this.ports.keyMaterial,
        keyHandle: this.requireKeyMaterialHandleV1(),
        transport: this.requireAuthenticatedTransport(),
        recipient: context.recipient,
        preparation: context.preparation,
        verification,
        expiresAtMs: Math.min(
          context.preparation.ownerEnrollment.expiresAtMs,
          this.requireSessionV1().qrData.expiresAtMs,
        ),
        assertCurrentRun: this.assertCurrentRun.bind(this, context.runEpoch),
        waitForPollV1: waitForSessionStateRetry,
      });
      this.assertCurrentRun(context.runEpoch);
      const targetPreparationDigestB64u =
        await computeLinkedDeviceTargetPreparationDigestV1(context.preparation);
      const registration = buildLinkedDeviceTargetCredentialRegistrationV1({
        linkSessionId: context.state.linkSessionId,
        walletId: context.state.walletId,
        enrollmentId: context.state.enrollmentId,
        deviceId: context.deviceId,
        targetFactor: { kind: 'email_otp' },
        targetPreparationDigestB64u,
        emailOtpVerificationGrant: verification.verificationGrant,
        orderedHolderRegistrations: accepted.orderedHolderRegistrations,
        registeredAtMs: Date.now(),
      });
      this.targetPreparationForProvisioning = context.preparation;
      this.targetCredentialRegistrationForProvisioning = registration;
      await this.requireAuthenticatedTransport().registerTargetCredentialV1({ registration });
      this.assertCurrentRun(context.runEpoch);
      this.emailOtpTargetActivationState = {
        kind: 'completed',
        runEpoch: context.runEpoch,
        resealedCustodyEnvelope: requireEmailOtpCustodyEnvelopeV1(accepted.custodyEnvelope),
        verificationGrant: verification.verificationGrant,
        factorRelease: verification.factorRelease,
      };
    } catch (error: unknown) {
      if (this.isCurrentRun(context.runEpoch)) {
        const message = errorMessage(error) || 'Email OTP activation is unavailable';
        this.emailOtpTargetActivationState = {
          kind: 'failed',
          runEpoch: context.runEpoch,
          message,
        };
        this.notifyEmailOtpActivationV1({ kind: 'unavailable', message });
      }
      throw error;
    }
    this.notifyEmailOtpActivationV1({
      kind: 'completed',
      maskedEmailHint: context.challenge.maskedEmailHint,
    });
  }

  private activateTargetCredential(input: {
    readonly event: LinkedDeviceSessionTransportEventV1;
    readonly state: AwaitingTargetPasskeyStateV1;
    readonly runEpoch: number;
    readonly deviceId: import('@shared/signing-lanes/ids').LinkedDeviceId;
    readonly preparation: PasskeyTargetPreparationV1;
  }): Promise<void> {
    if (!this.isCurrentRun(input.runEpoch)) {
      return Promise.reject(new LinkDeviceFlowSupersededError());
    }
    switch (this.targetCredentialActivationState.kind) {
      case 'idle':
        break;
      case 'in_progress':
        if (this.targetCredentialActivationState.runEpoch === input.runEpoch) {
          return this.targetCredentialActivationState.promise;
        }
        return Promise.reject(new LinkDeviceFlowSupersededError());
      case 'factor_ready':
        if (this.targetCredentialActivationState.runEpoch === input.runEpoch) {
          return Promise.reject(
            new Error('Device-link target passkey activation has already completed'),
          );
        }
        return Promise.reject(new LinkDeviceFlowSupersededError());
      case 'consuming':
        if (this.targetCredentialActivationState.runEpoch === input.runEpoch) {
          return Promise.reject(
            new Error('Device-link target passkey activation is already being consumed'),
          );
        }
        return Promise.reject(new LinkDeviceFlowSupersededError());
      default:
        return assertNeverTargetCredentialActivationState(this.targetCredentialActivationState);
    }
    const activation = this.runTargetCredentialActivation(input);
    this.targetCredentialActivationState = {
      kind: 'in_progress',
      runEpoch: input.runEpoch,
      promise: activation,
    };
    return activation;
  }

  private async runTargetCredentialActivation(input: {
    readonly event: LinkedDeviceSessionTransportEventV1;
    readonly state: AwaitingTargetPasskeyStateV1;
    readonly runEpoch: number;
    readonly deviceId: import('@shared/signing-lanes/ids').LinkedDeviceId;
    readonly preparation: PasskeyTargetPreparationV1;
  }): Promise<void> {
    try {
      const factorSecret = await this.createTargetCredential(input);
      const state = this.targetCredentialActivationState;
      if (
        !this.isCurrentRun(input.runEpoch) ||
        state.kind !== 'in_progress' ||
        state.runEpoch !== input.runEpoch
      ) {
        zeroizeLiveBytes(factorSecret);
        throw new LinkDeviceFlowSupersededError();
      }
      this.targetCredentialActivationState = {
        kind: 'factor_ready',
        runEpoch: input.runEpoch,
        factorSecret,
      };
    } catch (error: unknown) {
      if (this.isCurrentRun(input.runEpoch)) {
        await this.handleSessionTransportFailure(input.event, error);
      }
      throw error;
    } finally {
      const state = this.targetCredentialActivationState;
      if (state.kind === 'in_progress' && state.runEpoch === input.runEpoch) {
        this.targetCredentialActivationState = { kind: 'idle' };
      }
    }
  }

  private async waitForTargetCredentialActivation(): Promise<void> {
    const targetFactor = this.requireSessionTargetFactorV1();
    switch (targetFactor.kind) {
      case 'passkey_prf': {
        const state = this.targetCredentialActivationState;
        if (state.kind === 'in_progress') await state.promise;
        if (this.targetCredentialActivationState.kind !== 'factor_ready') {
          throw new Error('linked-device target Passkey activation is incomplete');
        }
        return;
      }
      case 'email_otp': {
        const state = this.emailOtpTargetActivationState;
        if (state.kind === 'submitting') await state.promise;
        if (this.emailOtpTargetActivationState.kind !== 'completed') {
          throw new Error('linked-device target Email OTP activation is incomplete');
        }
        return;
      }
      default:
        targetFactor satisfies never;
        throw new Error('linked-device target factor is unsupported');
    }
  }

  private claimTargetCredentialFactorSecret(runEpoch: number): Uint8Array | null {
    switch (this.targetCredentialActivationState.kind) {
      case 'idle':
        return null;
      case 'in_progress':
        throw new Error('Device-link target passkey activation is still in progress');
      case 'factor_ready': {
        if (this.targetCredentialActivationState.runEpoch !== runEpoch) {
          throw new LinkDeviceFlowSupersededError();
        }
        const factorSecret = this.targetCredentialActivationState.factorSecret;
        this.targetCredentialActivationState = {
          kind: 'consuming',
          runEpoch,
          factorSecret,
        };
        return factorSecret;
      }
      case 'consuming':
        throw new Error('Device-link target passkey activation is already being consumed');
      default:
        return assertNeverTargetCredentialActivationState(this.targetCredentialActivationState);
    }
  }

  private claimSigningSessionActivationV1(
    runEpoch: number,
  ): LinkedDeviceSigningSessionActivationV1 {
    const targetFactor = this.requireSessionTargetFactorV1();
    switch (targetFactor.kind) {
      case 'passkey_prf': {
        const factorSecret = this.claimTargetCredentialFactorSecret(runEpoch);
        return factorSecret
          ? { kind: 'target_passkey_creation', factorSecret }
          : { kind: 'existing_target_passkey' };
      }
      case 'email_otp': {
        const activationState = this.emailOtpTargetActivationState;
        if (activationState.kind !== 'completed' || activationState.runEpoch !== runEpoch) {
          throw new Error('linked-device target Email OTP activation is incomplete');
        }
        const registration = this.targetCredentialRegistrationForProvisioning;
        if (!registration || registration.targetFactor.kind !== 'email_otp') {
          throw new Error('linked-device Email OTP registration is unavailable');
        }
        const registrationGrant = registration.emailOtpVerificationGrant;
        if (!registrationGrant) {
          throw new Error('linked-device Email OTP verification grant is unavailable');
        }
        if (
          registrationGrant.grantId !== activationState.verificationGrant.grantId ||
          registrationGrant.grantToken !== activationState.verificationGrant.grantToken
        ) {
          throw new Error('linked-device Email OTP registration authority changed');
        }
        return {
          kind: 'target_email_otp_activation',
          keyMaterial: this.requireKeyMaterialHandleV1(),
          holderMaterial: this.ports.keyMaterial,
          resealedCustodyEnvelope: activationState.resealedCustodyEnvelope,
          verificationGrant: activationState.verificationGrant,
          factorRelease: activationState.factorRelease,
        };
      }
      default:
        targetFactor satisfies never;
        throw new Error('linked-device target factor is unsupported');
    }
  }

  private clearTargetCredentialActivationState(): void {
    const state = this.targetCredentialActivationState;
    if (state.kind === 'factor_ready' || state.kind === 'consuming') {
      zeroizeLiveBytes(state.factorSecret);
    }
    this.targetCredentialActivationState = { kind: 'idle' };
  }

  private async createTargetCredential(input: {
    readonly state: AwaitingTargetPasskeyStateV1;
    readonly runEpoch: number;
    readonly deviceId: import('@shared/signing-lanes/ids').LinkedDeviceId;
    readonly preparation: PasskeyTargetPreparationV1;
  }): Promise<Uint8Array> {
    const { state, runEpoch, deviceId, preparation } = input;
    if (!this.keyMaterialHandle || !this.session)
      throw new Error('device-link key material is unavailable');
    const authenticatedTransport = this.requireAuthenticatedTransport();
    logDevice2LinkingStageV1({
      flowId: this.flowId,
      linkSessionId: state.linkSessionId,
      stage: 'target_passkey_prompt_started',
    });
    // Started, not awaited. Device 1 cannot seal the wallet custody seed until
    // a recipient exists, and the owner is already waiting there, so publishing
    // one now lets that seal happen while this device's user is still at the
    // passkey prompt. Awaiting it here would spend the click's transient user
    // activation on a worker call and a POST before WebAuthn ever sees it.
    const recipientPublish = publishLinkedDeviceCustodyRecipientV1({
      custodyTransfer: this.ports.custodyTransfer,
      transport: authenticatedTransport,
      identity: {
        linkSessionId: String(state.linkSessionId),
        walletId: state.walletId,
        enrollmentId: state.enrollmentId,
        deviceId,
      },
      registeredAtMs: Date.now(),
    });
    // Nothing awaits it until after the prompt; this keeps an early rejection
    // from being reported as unhandled. It is re-raised at the await below.
    recipientPublish.catch(() => undefined);
    let credential: Awaited<
      ReturnType<DeviceLinkingTargetCredentialPortV1['createTargetCredentialV1']>
    > | null = null;
    let recipient: DeviceLinkingCustodyTransferRecipientHandleV1 | null = null;
    try {
      // This is the first operation after the UI click so WebAuthn receives transient user activation.
      credential = await this.ports.targetCredential.createTargetCredentialV1({
        preparation,
        keyMaterial: this.keyMaterialHandle,
      });
      logDevice2LinkingStageV1({
        flowId: this.flowId,
        linkSessionId: state.linkSessionId,
        stage: 'target_passkey_created',
      });
      this.emit({
        phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
        status: 'running',
        message: 'Finishing linked-device setup',
        data: { role: 'display' },
        interaction: { kind: 'qr_display', overlay: 'show' },
      });
      recipient = await recipientPublish;
      logDevice2LinkingStageV1({
        flowId: this.flowId,
        linkSessionId: state.linkSessionId,
        stage: 'custody_recipient_published',
      });
      this.assertCurrentRun(runEpoch);
      // The wallet custody seed is resealed under the passkey just created.
      // The canonical finalize registers that credential as a peer owner before
      // the additive lane path consumes its factor for the local session.
      this.resealedCustodyEnvelope = await acceptLinkedDeviceCustodyTransferV1({
        custodyTransfer: this.ports.custodyTransfer,
        transport: authenticatedTransport,
        recipient,
        rpId: requireTargetRpIdV1(preparation),
        credentialIdB64u: credential.webauthnRegistration.credentialIdB64u,
        replacementFactorSecret: credential.factorSecret,
        // Whichever deadline comes first: past the ceremony the credential this
        // seed is for can never be minted, and past the session there is no
        // authenticated channel left to finalize it through.
        expiresAtMs: Math.min(
          preparation.ownerEnrollment.expiresAtMs,
          this.session.qrData.expiresAtMs,
        ),
        assertCurrentRun: () => this.assertCurrentRun(runEpoch),
        waitForPollV1: waitForSessionStateRetry,
      });
      logDevice2LinkingStageV1({
        flowId: this.flowId,
        linkSessionId: state.linkSessionId,
        stage: 'custody_transfer_accepted',
      });
      // The worker consumes and frees the recipient during every accept attempt.
      recipient = null;
      this.assertCurrentRun(runEpoch);
      const targetPreparationDigestB64u =
        await computeLinkedDeviceTargetPreparationDigestV1(preparation);
      const registration = buildLinkedDeviceTargetCredentialRegistrationV1({
        linkSessionId: state.linkSessionId,
        walletId: state.walletId,
        enrollmentId: state.enrollmentId,
        deviceId,
        targetFactor: { kind: 'passkey_prf' },
        targetPreparationDigestB64u,
        webauthnRegistration: credential.webauthnRegistration,
        orderedHolderRegistrations: credential.orderedHolderRegistrations,
        registeredAtMs: Date.now(),
      });
      this.targetPreparationForProvisioning = preparation;
      this.targetCredentialRegistrationForProvisioning = registration;
      const resealedCustodyEnvelope = this.resealedCustodyEnvelope;
      if (!resealedCustodyEnvelope) {
        throw new Error('linked-device custody transfer did not produce a resealed envelope');
      }
      // Commits the credential and lands both local writes as one recoverable
      // unit, so neither can be left behind by a failure in the other.
      await this.commitLinkedOwnerEnrollmentV1({
        authenticatedTransport,
        state,
        preparation,
        credential,
        custodyEnvelope: resealedCustodyEnvelope,
        registration,
        runEpoch,
      });
      logDevice2LinkingStageV1({
        flowId: this.flowId,
        linkSessionId: state.linkSessionId,
        stage: 'owner_enrollment_committed',
      });
      this.resealedCustodyEnvelope = null;
      this.assertCurrentRun(runEpoch);
      // The canonical owner finalize and target-credential registration are
      // committed. The provisioning state handler continues with R102 lane
      // provisioning, execution evidence, and Wallet Session delivery.
      return credential.factorSecret;
    } catch (error: unknown) {
      if (credential) zeroizeLiveBytes(credential.factorSecret);
      // If WebAuthn rejected before returning a credential, the publication
      // still owns a worker recipient. Await it so that cancellation cannot
      // strand that handle after this method exits.
      if (!recipient) {
        try {
          recipient = await recipientPublish;
        } catch {
          // Publication failure already discards its own worker recipient.
        }
      }
      // A recipient nobody will seal to is a live private key in the worker.
      if (recipient) {
        await discardLinkedDeviceCustodyRecipientV1(this.ports.custodyTransfer, recipient);
      }
      throw error;
    }
  }

  /**
   * Commits the owner credential, then lands the local writes that depend on it.
   *
   * The server half of this is irreversible: one successful finalize registers
   * the passkey, the custody envelope, and the owner binding in a single
   * transaction. Everything after it is local, and a local failure must never
   * be recovered by minting a second credential — the wallet would carry two
   * owner factors for one device, only one of which anything knows about.
   *
   * So the canonical response is retained the moment the server commits and
   * reused for every subsequent attempt, rather than the flow unwinding to
   * somewhere that would prompt again. The finalize is replayable rather than
   * repeatable — the server answers an identical request with the original
   * response — but the retained copy means the retry does not even need to ask.
   *
   * If the writes still cannot land, this throws and the flow tears itself
   * down: `handleSessionTransportFailure` advances the run epoch and releases
   * the local resources, so nothing reaches the authenticator a second time.
   */
  private async commitLinkedOwnerEnrollmentV1(input: {
    readonly authenticatedTransport: DeviceLinkingAuthenticatedTransportPortV1;
    readonly state: AwaitingTargetPasskeyStateV1;
    readonly preparation: PasskeyTargetPreparationV1;
    readonly credential: Awaited<
      ReturnType<DeviceLinkingTargetCredentialPortV1['createTargetCredentialV1']>
    >;
    readonly custodyEnvelope: PasskeyCustodyEnvelopeRecord;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly runEpoch: number;
  }): Promise<void> {
    const request: LinkedDeviceOwnerFinalizeRequestV1 = {
      kind: 'linked_device_owner_finalize_request_v1',
      addAuthMethodCeremonyId: input.preparation.ownerEnrollment.addAuthMethodCeremonyId,
      webauthnRegistration: input.credential.webauthnRegistration,
      custodyEnvelope: input.custodyEnvelope,
    };
    // One server call, retained for the whole commit. Replaying it would return
    // this same response — the point of retaining it is that the retry below
    // never has to unwind far enough to ask.
    const retained: RetainedLinkedOwnerFinalizeV1 = {
      request,
      finalized: await input.authenticatedTransport.finalizeOwnerAuthMethodV1({
        linkSessionId: input.state.linkSessionId,
        request,
      }),
    };
    this.assertCurrentRun(input.runEpoch);
    const credential = requireFinalizedOwnerPasskeyV1(retained.finalized.response, input);
    let attempt = 0;
    for (;;) {
      try {
        this.assertCurrentRun(input.runEpoch);
        // All three local records this device needs to unlock as an ordinary
        // owner, inside the retried unit: a partial set reads as a revoked
        // device rather than an incomplete write.
        await persistFinalizedLinkedOwnerPasskeyV1({
          credential,
          localAccount: retained.finalized.localAccount,
        });
        // The canonical owner finalize advances the session to provisioning.
        // The R102 credential registration is deliberately replay-safe in that
        // state and records the same target preparation binding.
        await input.authenticatedTransport.registerTargetCredentialV1({
          registration: input.registration,
        });
        this.assertCurrentRun(input.runEpoch);
        return;
      } catch (error: unknown) {
        if (error instanceof LinkDeviceFlowSupersededError) throw error;
        if (attempt >= LINKED_OWNER_ENROLLMENT_PERSIST_ATTEMPTS_V1) {
          // The credential exists on the server, so this says what is actually
          // true rather than implying nothing happened. The flow tears down
          // from here; it does not fall back to making another one.
          throw new DeviceLinkingError(
            `Device-link owner credential was registered but could not be stored locally: ${errorMessage(error)}`,
            DeviceLinkingErrorCode.REGISTRATION_FAILED,
            'registration',
          );
        }
        await waitForSessionStateRetry(attempt);
        attempt += 1;
      }
    }
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

  private assertTargetPreparationMatchesSession(input: {
    readonly preparation: import('@shared/device-linking').LinkedDeviceTargetPreparationV1;
    readonly state: Extract<LinkedDeviceSessionState, { state: 'awaiting_target_factor' }>;
    readonly deviceId: import('@shared/signing-lanes/ids').LinkedDeviceId;
  }): void {
    if (
      input.preparation.linkSessionId !== input.state.linkSessionId ||
      input.preparation.walletId !== input.state.walletId ||
      input.preparation.enrollmentId !== input.state.enrollmentId ||
      input.preparation.deviceId !== input.deviceId ||
      input.preparation.targetFactor.kind !== input.state.targetFactor.kind ||
      input.preparation.expiresAtMs <= Date.now()
    ) {
      throw new Error('linked-device target preparation does not match the claimed session');
    }
  }

  private async resumeCommittedDelivery(
    state: Extract<LinkedDeviceSessionState, { state: 'committed_completion_required' }>,
    runEpoch: number,
  ): Promise<void> {
    const authenticatedTransport = this.requireAuthenticatedTransport();
    logDevice2LinkingStageV1({
      flowId: this.flowId,
      linkSessionId: state.linkSessionId,
      stage: 'committed_delivery_retry_started',
    });
    const deviceId = await this.requireDeviceId(state);
    const keyMaterial = this.keyMaterialHandle;
    if (!keyMaterial) {
      throw new Error(
        'committed linked-device delivery cannot recover without its live recipient key handle',
      );
    }
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
    let replayApproval: LinkedDeviceApprovalV1 | null = null;
    let replayDeliveries: LinkedDeviceProvisioningDeliveriesV1 | null = null;
    const receipt = await this.ports.laneProvisioning.resumeCommittedDeliveryV1({
      state,
      keyMaterial,
      refetchApprovalV1: async () => {
        const approval = await authenticatedTransport.getApprovalV1({
          linkSessionId: state.linkSessionId,
        });
        this.assertCurrentRun(runEpoch);
        this.assertCommittedApprovalMatchesSession({ approval, state, deviceId });
        this.provisioningApproval = approval;
        replayApproval = approval;
        return approval;
      },
      refetchProvisioningDeliveriesV1: async () => {
        const deliveries = await authenticatedTransport.requestProvisioningDeliveriesV1({
          command: buildLinkedDeviceProvisioningCommandV1({
            linkSessionId: state.linkSessionId,
            enrollmentId: state.enrollmentId,
            deviceId,
            targetFactor: this.requireSessionTargetFactorV1(),
          }),
        });
        this.assertCurrentRun(runEpoch);
        replayDeliveries = deliveries;
        return deliveries;
      },
      acknowledgeHolderDeliveriesV1: this.acknowledgeHolderDeliveries.bind(this, runEpoch),
    });
    this.assertCurrentRun(runEpoch);
    this.aggregateReceipt = receipt;
    if (!replayApproval || !replayDeliveries) {
      throw new Error('committed linked-device delivery did not refetch exact R102 evidence');
    }
    await this.revalidatePersistedExecutionEvidenceV1({
      approval: replayApproval,
      deliveries: replayDeliveries,
      receipt,
      enrollmentId: state.enrollmentId,
      runEpoch,
    });
    if (!this.session) return;
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
    await this.ensureWalletSessionDeliveryPersistedV1({ state, runEpoch, deviceId });
    logDevice2LinkingStageV1({
      flowId: this.flowId,
      linkSessionId: state.linkSessionId,
      stage: 'committed_delivery_retry_completed',
    });
  }

  private async provisionLinkedDeviceLanesV1(
    state: Extract<
      LinkedDeviceSessionState,
      { readonly state: 'provisioning' | 'committed_completion_required' }
    >,
    runEpoch: number,
  ): Promise<void> {
    const authenticatedTransport = this.requireAuthenticatedTransport();
    logDevice2LinkingStageV1({
      flowId: this.flowId,
      linkSessionId: state.linkSessionId,
      stage: 'lane_provisioning_started',
    });
    const deviceId = await this.requireDeviceId(state);
    this.assertCurrentRun(runEpoch);
    const approval = await authenticatedTransport.getApprovalV1({
      linkSessionId: state.linkSessionId,
    });
    this.assertCurrentRun(runEpoch);
    this.assertCommittedApprovalMatchesSession({ approval, state, deviceId });
    this.provisioningApproval = approval;
    logDevice2LinkingStageV1({
      flowId: this.flowId,
      linkSessionId: state.linkSessionId,
      stage: 'lane_provisioning_approval_loaded',
    });
    if (!this.session) throw new Error('device-link session is unavailable');
    const deliveryState = await this.waitForPreparedDeliveryCommitV1({
      authenticatedTransport,
      linkSessionId: state.linkSessionId,
      expiresAtMs: this.session.qrData.expiresAtMs,
      runEpoch,
    });
    logDevice2LinkingStageV1({
      flowId: this.flowId,
      linkSessionId: state.linkSessionId,
      stage: 'source_delivery_commit_observed',
      details: { state: deliveryState },
    });
    if (deliveryState === 'active') return;
    const deliveries = await authenticatedTransport.requestProvisioningDeliveriesV1({
      command: buildLinkedDeviceProvisioningCommandV1({
        linkSessionId: state.linkSessionId,
        enrollmentId: state.enrollmentId,
        deviceId,
        targetFactor: this.requireSessionTargetFactorV1(),
      }),
    });
    this.assertCurrentRun(runEpoch);
    const keyMaterial = this.keyMaterialHandle;
    const preparation = this.targetPreparationForProvisioning;
    const registration = this.targetCredentialRegistrationForProvisioning;
    if (!keyMaterial || !preparation || !registration) {
      throw new Error('linked-device target provisioning inputs are unavailable');
    }
    const receipt = await this.ports.laneProvisioning.prepareLinkedDeviceLanesV1(
      createDeviceLinkingLaneProvisioningHandoffV1({
        approval,
        deliveries,
        keyMaterial,
        acknowledgeHolderDeliveriesV1: this.acknowledgeHolderDeliveries.bind(this, runEpoch),
      }),
    );
    this.assertCurrentRun(runEpoch);
    this.aggregateReceipt = receipt;
    await this.persistProvisionedExecutionEvidenceV1({
      approval,
      preparation,
      registration,
      deliveries,
      receipt,
      runEpoch,
    });
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
    await this.ensureWalletSessionDeliveryPersistedV1({ state, runEpoch, deviceId });
  }

  private async waitForPreparedDeliveryCommitV1(input: {
    readonly authenticatedTransport: DeviceLinkingAuthenticatedTransportPortV1;
    readonly linkSessionId: import('@shared/signing-lanes/ids').LinkDeviceSessionId;
    readonly expiresAtMs: number;
    readonly runEpoch: number;
  }): Promise<'committed' | 'active'> {
    let attempt = 0;
    while (Date.now() < input.expiresAtMs) {
      this.assertCurrentRun(input.runEpoch);
      const snapshot = await input.authenticatedTransport.getSessionV1({
        linkSessionId: input.linkSessionId,
      });
      logDevice2LinkingStageV1({
        flowId: this.flowId,
        linkSessionId: input.linkSessionId,
        stage: 'source_delivery_commit_poll',
        details: {
          attempt,
          state: snapshot.state.state,
          revision: snapshot.revision,
          updatedAtMs: snapshot.updatedAtMs,
        },
      });
      switch (snapshot.state.state) {
        case 'committed_completion_required':
          return 'committed';
        case 'active':
          return 'active';
        case 'claimed_by_owner':
        case 'awaiting_target_factor':
        case 'provisioning':
          break;
        case 'expired_unclaimed':
        case 'expired_claimed':
          throw new DeviceLinkingError(
            'Device-link session expired before source deliveries were committed',
            DeviceLinkingErrorCode.SESSION_EXPIRED,
            'registration',
          );
        case 'cancelled_unclaimed':
        case 'cancelled_claimed_precommit':
          throw new DeviceLinkingError(
            'Device-link session was cancelled before source deliveries were committed',
            DeviceLinkingErrorCode.REGISTRATION_FAILED,
            'registration',
          );
        case 'displaying_qr':
          throw new Error('linked-device session regressed after target credential registration');
        default:
          assertNeverLinkedDeviceSessionState(snapshot.state);
      }
      await waitForSessionStateRetry(attempt);
      attempt += 1;
    }
    throw new DeviceLinkingError(
      'Device-link session expired before source deliveries were committed',
      DeviceLinkingErrorCode.SESSION_EXPIRED,
      'registration',
    );
  }

  private async persistProvisionedExecutionEvidenceV1(input: {
    readonly approval: LinkedDeviceApprovalV1;
    readonly preparation: LinkedDeviceTargetPreparationV1;
    readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
    readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
    readonly receipt: LinkedDeviceEnrollmentReceiptV1;
    readonly runEpoch: number;
  }): Promise<void> {
    const evidence = await buildLinkedDeviceProvisionedExecutionEvidenceV1({
      approval: input.approval,
      targetPreparation: input.preparation,
      targetCredentialRegistration: input.registration,
      provisioningDeliveries: input.deliveries,
      enrollmentReceipt: input.receipt,
    });
    this.assertCurrentRun(input.runEpoch);
    await this.ports.executionEvidence.putExactProvisionedEvidenceV1(evidence);
    this.assertCurrentRun(input.runEpoch);
  }

  private async revalidatePersistedExecutionEvidenceV1(input: {
    readonly approval: LinkedDeviceApprovalV1;
    readonly deliveries: LinkedDeviceProvisioningDeliveriesV1;
    readonly receipt: LinkedDeviceEnrollmentReceiptV1;
    readonly enrollmentId: LinkedDeviceApprovalV1['enrollmentId'];
    readonly runEpoch: number;
  }): Promise<void> {
    const stored = await this.ports.executionEvidence.readForEnrollmentV1(input.enrollmentId);
    this.assertCurrentRun(input.runEpoch);
    if (stored.kind !== 'found') {
      throw new Error(`linked-device execution evidence is ${stored.kind}`);
    }
    await this.persistProvisionedExecutionEvidenceV1({
      approval: input.approval,
      preparation: stored.evidence.targetPreparation,
      registration: stored.evidence.targetCredentialRegistration,
      deliveries: input.deliveries,
      receipt: input.receipt,
      runEpoch: input.runEpoch,
    });
  }

  private async ensureWalletSessionDeliveryPersistedV1(input: {
    readonly state: Extract<
      LinkedDeviceSessionState,
      {
        readonly state:
          | 'awaiting_target_factor'
          | 'provisioning'
          | 'committed_completion_required'
          | 'active';
      }
    >;
    readonly runEpoch: number;
    readonly deviceId?: import('@shared/signing-lanes/ids').LinkedDeviceId;
  }): Promise<void> {
    if (this.walletSessionDeliveryPersisted) return;
    if (this.walletSessionDeliveryInProgress) {
      await this.walletSessionDeliveryInProgress;
      return;
    }
    const persistence = this.fetchAndPersistWalletSessionDeliveryV1(input);
    this.walletSessionDeliveryInProgress = persistence;
    try {
      await persistence;
      this.walletSessionDeliveryPersisted = true;
    } finally {
      if (this.walletSessionDeliveryInProgress === persistence) {
        this.walletSessionDeliveryInProgress = null;
      }
    }
  }

  private async fetchAndPersistWalletSessionDeliveryV1(input: {
    readonly state: Extract<
      LinkedDeviceSessionState,
      {
        readonly state:
          | 'awaiting_target_factor'
          | 'provisioning'
          | 'committed_completion_required'
          | 'active';
      }
    >;
    readonly runEpoch: number;
    readonly deviceId?: import('@shared/signing-lanes/ids').LinkedDeviceId;
  }): Promise<void> {
    await Promise.resolve();
    const transport = this.requireAuthenticatedTransport();
    const deviceId = input.deviceId ?? (await this.requireDeviceId(input.state));
    this.assertCurrentRun(input.runEpoch);
    const approval =
      this.provisioningApproval ??
      (await transport.getApprovalV1({ linkSessionId: input.state.linkSessionId }));
    this.provisioningApproval = approval;
    const delivery = await transport.getWalletSessionDeliveryV1({
      linkSessionId: input.state.linkSessionId,
    });
    this.assertCurrentRun(input.runEpoch);
    this.assertWalletSessionDeliveryMatchesV1({
      delivery,
      approval,
      receipt: this.aggregateReceipt,
      state: input.state,
      deviceId,
    });
    await this.ports.walletSessions.putExactActiveDeliveryV1(delivery);
    this.assertCurrentRun(input.runEpoch);
  }

  private assertWalletSessionDeliveryMatchesV1(input: {
    readonly delivery: LinkedDeviceWalletSessionDeliveryV1;
    readonly approval: LinkedDeviceApprovalV1;
    readonly receipt: LinkedDeviceEnrollmentReceiptV1 | null;
    readonly state: Extract<
      LinkedDeviceSessionState,
      {
        readonly state:
          | 'awaiting_target_factor'
          | 'provisioning'
          | 'committed_completion_required'
          | 'active';
      }
    >;
    readonly deviceId: import('@shared/signing-lanes/ids').LinkedDeviceId;
  }): void {
    const { delivery, approval, receipt, state, deviceId } = input;
    if (
      delivery.walletId !== state.walletId ||
      delivery.enrollmentId !== state.enrollmentId ||
      delivery.deviceId !== deviceId ||
      approval.walletId !== state.walletId ||
      approval.enrollmentId !== state.enrollmentId ||
      approval.deviceId !== deviceId ||
      delivery.permission.kind !== approval.permission.kind ||
      delivery.permission.administrationScope !== approval.permission.administrationScope ||
      delivery.permission.localUserPresence !== approval.permission.localUserPresence ||
      delivery.orderedTokens.length !== approval.orderedKeyBindings.length ||
      approval.orderedKeyBindings.some(
        (binding, index) =>
          delivery.orderedTokens[index]?.walletKeyId !== binding.walletKeyId ||
          delivery.orderedTokens[index]?.keyFamily !== binding.keyFamily ||
          delivery.orderedTokens[index]?.revocationEpoch !== binding.sourceRevocationEpoch,
      ) ||
      (receipt !== null &&
        (delivery.keyManifestDigestB64u !== receipt.manifestDigestB64u ||
          delivery.issuedAtMs !== receipt.activatedAtMs))
    ) {
      throw new Error('linked-device Wallet Session delivery does not match activation');
    }
  }

  private assertCommittedApprovalMatchesSession(input: {
    readonly approval: import('@shared/device-linking').LinkedDeviceApprovalV1;
    readonly state: Extract<
      LinkedDeviceSessionState,
      { state: 'provisioning' | 'committed_completion_required' }
    >;
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
      throw new Error('refetched linked-device approval does not match its session');
    }
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

  private requireSessionTargetFactorV1(): QrLinkedDeviceSessionPayloadV5['targetFactor'] {
    if (!this.session) throw new Error('device-link session is unavailable');
    return this.session.qrData.targetFactor;
  }

  private requireSessionV1(): DeviceLinkingSession {
    if (!this.session) throw new Error('device-link session is unavailable');
    return this.session;
  }

  private requireKeyMaterialHandleV1(): DeviceLinkingKeyMaterialHandleV1 {
    if (!this.keyMaterialHandle) throw new Error('device-link key material is unavailable');
    return this.keyMaterialHandle;
  }

  private startRun(): number {
    this.clearTargetCredentialActivationState();
    this.emailOtpTargetActivationState = { kind: 'idle' };
    this.resealedCustodyEnvelope = null;
    this.runEpoch += 1;
    this.generationInProgress = true;
    this.cancelled = false;
    this.error = undefined;
    this.walletSessionDeliveryInProgress = null;
    this.walletSessionDeliveryPersisted = false;
    this.provisioningApproval = null;
    this.aggregateReceipt = null;
    this.targetPreparationForProvisioning = null;
    this.targetCredentialRegistrationForProvisioning = null;
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
    const processing = this.sessionEventQueue.then(this.handleSessionEvent.bind(this, event));
    this.sessionEventQueue = processing.catch(this.handleSessionTransportFailure.bind(this, event));
  }

  private async handleSessionTransportFailure(
    event: LinkedDeviceSessionTransportEventV1,
    error: unknown,
  ): Promise<void> {
    if (error instanceof LinkDeviceFlowSupersededError) return;
    logDevice2LinkingFailureV1({
      flowId: this.flowId,
      linkSessionId: event.linkSessionId,
      state: event.state.state,
      error,
    });
    this.handledStates.delete(event.state.state);
    const failure = errorForFailure(error, 'registration');
    this.error = failure;
    this.emitFailure(failure, 'registration');
    notifyError(this.options.options?.onError, failure);
    await this.cancelFailedPrecommitSession(event).catch(() => undefined);
    this.runEpoch += 1;
    try {
      await this.cleanupLocalResources();
    } catch {
      // A later cancel/reset retries any retained subscription or key handle.
    }
  }

  private async cancelFailedPrecommitSession(
    event: LinkedDeviceSessionTransportEventV1,
  ): Promise<void> {
    const transport = this.authenticatedTransport;
    if (!transport) return;
    switch (event.state.state) {
      case 'claimed_by_owner':
      case 'awaiting_target_factor': {
        const cancelledAtMs = Date.now();
        await transport.cancelSessionV1({
          request: buildLinkedDeviceSessionCancelClaimedRequestV1({
            linkSessionId: event.state.linkSessionId,
            enrollmentId: event.state.enrollmentId,
            deviceId: await this.requireDeviceId(event.state),
            reason: 'user_cancelled',
            requestedAtMs: cancelledAtMs,
          }),
        });
        if (this.session?.linkSessionId === event.state.linkSessionId) {
          this.session = {
            ...this.session,
            state: buildCancelledClaimedPrecommitLinkedDeviceSessionState({
              linkSessionId: event.state.linkSessionId,
              walletId: event.state.walletId,
              enrollmentId: event.state.enrollmentId,
              cancelledAtMs,
            }),
          };
        }
        return;
      }
      case 'displaying_qr':
      case 'provisioning':
      case 'committed_completion_required':
      case 'active':
      case 'expired_unclaimed':
      case 'expired_claimed':
      case 'cancelled_unclaimed':
      case 'cancelled_claimed_precommit':
        return;
      default:
        assertNeverLinkedDeviceSessionState(event.state);
    }
  }

  private async cleanupLocalResources(): Promise<void> {
    this.clearTargetCredentialActivationState();
    this.emailOtpTargetActivationState = { kind: 'idle' };
    this.resealedCustodyEnvelope = null;
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
        this.emailOtpReleasePublicKey65B64u = null;
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
    args: StartDevice2LinkingFlowArgs,
  ): Promise<StartDevice2LinkingFlowResults> {
    if (this.deps.kind === 'direct' && !this.deps.walletIframe.shouldUseWalletIframe()) {
      if (this.activeDeviceLinkFlow) {
        throw new Error('Device-link QR flow is already running');
      }
      const flow = new LinkDeviceFlow(args, this.deps.ports);
      this.activeDeviceLinkFlow = flow;
      try {
        return await flow.generateQR();
      } catch (error: unknown) {
        if (this.activeDeviceLinkFlow === flow) this.activeDeviceLinkFlow = null;
        throw error;
      }
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
    qrData: QrLinkedDeviceSessionPayloadV5,
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
