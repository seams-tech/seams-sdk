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
import {
  DeviceLinkingError,
  DeviceLinkingErrorCode,
  normalizeLinkedDeviceTargetEmailAddressV1,
} from '@/core/types/linkDevice';
import {
  buildQrLinkedDeviceSessionPayloadV5,
  buildLinkedDeviceSessionCancelClaimedRequestV1,
  buildLinkedDeviceSessionCancelUnclaimedRequestV1,
  buildLinkedDeviceTargetCredentialRegistrationV1,
  assertNeverLinkSessionStateV1,
  serializeQrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
import { computeLinkedDeviceTargetPreparationDigestV1 } from '@shared/device-linking';
import {
  computeWalletSessionInstallationReceiptDigestB64u,
  computeWalletSessionOperationCredentialDigestB64u,
} from '@shared/device-linking/digests';
import type {
  LinkedDeviceTargetCredentialRegistrationResultV1,
  LinkSessionStateV1,
  LinkSessionTransportEventV1,
  LinkedDeviceTargetPreparationV1,
  LinkedDevicePasskeyCreationOptionsV1,
  LinkedDeviceEmailOtpChallengeResultV1,
  ActiveWalletSessionV1,
  CommittedAuthorityPackagesV1,
  QrLinkedDeviceSessionPayloadV5,
  OrdinarySignerMaterialRecipientRequestV1,
  LocalAuthorityActivationFinalAckV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking';
import type { WalletEmailOtpEnrollmentMaterialV1 } from '@shared/utils/registrationIntent';
import { parseLinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { errorMessage } from '@shared/utils/errors';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import {
  scanAndLinkDevice as scanAndLinkDeviceDevice1,
  type Device1OwnerLinkCancellationV1,
} from '@/SeamsWeb/operations/devices/scanDevice';
import type {
  Device2LinkingFlowPortsV1,
  DeviceLinkingAuthenticatedTransportPortV1,
  DeviceLinkingFlowPortsV1,
  DeviceLinkingKeyMaterialHandleV1,
  DeviceLinkingTargetCredentialPortV1,
  LinkSessionSubscriptionV1,
} from './deviceLinkingPorts';
import { LinkDeviceEventPhase, createLinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import type { CreateLinkDeviceFlowEventInput } from '@/core/types/sdkSentEvents';
import type { WalletAuthenticationState } from '@/core/types/seams';
import { nextLinkedDevicePollingDelayMsV1 } from './deviceLinkingHttpTransport';
import {
  acceptLinkedDeviceEd25519ExportRootV1,
  discardLinkedDeviceEd25519ExportRootRecipientV1,
  publishLinkedDeviceEd25519ExportRootRecipientV1,
} from './deviceLinkingTargetEd25519ExportRoot';
import {
  buildDeviceLinkingEd25519ExportRootReplacementEnvelopeV1,
  type DeviceLinkingEd25519ExportRootRecipientHandleV1,
} from './deviceLinkingEd25519ExportRoot';
import type { DeviceLinkingOrdinarySignerMaterialRecipientPreparationV1 } from './deviceLinkingOrdinaryMaterialWorker';
import { activateLinkedAuthorityV1 } from './deviceLinkingAuthorityInstallation';
import { buildFullOwnerDelegatedWalletAuthorityV1 } from '@shared/authorization/delegatedAuthority';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import {
  buildEmailOtpEnvelopeFactor,
  buildMethodBoundEnvelopeOwnership,
  buildEd25519YaoClientRootBinding,
  buildPasskeyEnvelopeFactor,
} from '@shared/passkey-custody';
import { parsePasskeyEnvelopeId, type PasskeyEnvelopeId } from '@shared/utils/domainIds';
import { WALLET_AUTH_METHODS } from '@shared/utils/signerDomain';
import { activateLinkedDeviceSignerRuntimesAfterLink } from '../auth/login';

type EmitLinkDeviceEventInput = Omit<CreateLinkDeviceFlowEventInput, 'flowId' | 'accountId'> & {
  readonly accountId?: string;
};

type GetLinkedDeviceAuthenticationContext = () => DeviceLinkingWebContext;

function linkedDeviceWalletAuthenticationState(
  walletSession: ActiveWalletSessionV1,
  registration: LinkedDeviceTargetCredentialRegistrationResultV1,
): Extract<WalletAuthenticationState, { readonly kind: 'authenticated' }> {
  switch (registration.targetFactor.kind) {
    case 'verified_passkey_target_v1':
      return {
        kind: 'authenticated',
        walletId: walletSession.walletId,
        authMethod: WALLET_AUTH_METHODS.passkey,
      };
    case 'verified_email_otp_target_v1':
      return {
        kind: 'authenticated',
        walletId: walletSession.walletId,
        authMethod: WALLET_AUTH_METHODS.emailOtp,
      };
    default:
      return registration.targetFactor satisfies never;
  }
}

type AwaitingTargetFactorStateV1 = Extract<
  LinkSessionStateV1,
  { readonly state: 'awaiting_target_factor' }
>;
type AwaitingTargetPasskeyStateV1 = Extract<
  AwaitingTargetFactorStateV1,
  { readonly state: 'awaiting_target_factor' }
>;
type AwaitingTargetEmailOtpStateV1 = Extract<
  AwaitingTargetFactorStateV1,
  { readonly state: 'awaiting_target_factor' }
>;
type PasskeyTargetPreparationV1 = Extract<
  LinkedDeviceTargetPreparationV1,
  {
    readonly targetFactor: { readonly kind: 'passkey_prf' };
    readonly passkeyCreationOptions: LinkedDevicePasskeyCreationOptionsV1;
  }
>;
type EmailOtpTargetPreparationV1 = Extract<
  LinkedDeviceTargetPreparationV1,
  { readonly targetFactor: { readonly kind: 'email_otp' } }
>;

function isPasskeyTargetPreparation(
  preparation: LinkedDeviceTargetPreparationV1,
): preparation is PasskeyTargetPreparationV1 {
  return preparation.targetFactor.kind === 'passkey_prf';
}

function isEmailOtpTargetPreparation(
  preparation: LinkedDeviceTargetPreparationV1,
): preparation is EmailOtpTargetPreparationV1 {
  return preparation.targetFactor.kind === 'email_otp';
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
  readonly state: LinkSessionStateV1['state'];
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

function phaseForState(state: LinkSessionStateV1): LinkDeviceEventPhase {
  switch (state.state) {
    case 'displaying_qr':
    case 'expired':
    case 'cancelled':
      return LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED;
    case 'claimed':
    case 'awaiting_target_factor':
    case 'awaiting_source_contribution':
    case 'provisioning':
    case 'authority_pending_local_install':
    case 'active':
      return LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED;
    case 'failed_before_commit':
      return LinkDeviceEventPhase.FAILED;
    default:
      return assertNeverLinkSessionStateV1(state);
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

export type LinkedDeviceDeliveryRecoveryReasonV1 =
  | 'recipient_private_handle_lost'
  | 'sealed_delivery_expired';

/**
 * These failures happen after the server has committed the linked authority.
 * The original delivery is intentionally abandoned; exact-method unlock uses
 * the durable local installation to obtain a successor Wallet Session.
 */
export function classifyLinkedDeviceDeliveryFailureV1(
  error: unknown,
): LinkedDeviceDeliveryRecoveryReasonV1 | null {
  const message = errorMessage(error).toLowerCase();
  if (
    message.includes('device-linking key handle is unknown or discarded') ||
    message.includes('recipient handle lost')
  ) {
    return 'recipient_private_handle_lost';
  }
  if (message.includes('linked-device wallet session credential delivery is expired')) {
    return 'sealed_delivery_expired';
  }
  return null;
}

function linkedDeviceDeliveryRecoveryMessageV1(
  reason: LinkedDeviceDeliveryRecoveryReasonV1,
): string {
  switch (reason) {
    case 'recipient_private_handle_lost':
    case 'sealed_delivery_expired':
      return 'The linked device is ready. Return to sign in and unlock the new method to finish setup.';
    default:
      return reason satisfies never;
  }
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
  readonly event: LinkSessionTransportEventV1;
  readonly state: AwaitingTargetEmailOtpStateV1;
  readonly runEpoch: number;
  readonly deviceId: import('@shared/signing-lanes/ids').LinkedDeviceId;
  readonly preparation: EmailOtpTargetPreparationV1;
  readonly ordinarySignerMaterialRecipientRequests: readonly [
    OrdinarySignerMaterialRecipientRequestV1,
    ...OrdinarySignerMaterialRecipientRequestV1[],
  ];
  readonly exportRoot:
    | {
        readonly kind: 'required';
        readonly recipient: DeviceLinkingEd25519ExportRootRecipientHandleV1;
      }
    | {
        readonly kind: 'not_required';
        readonly recipient?: never;
      };
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
    ordinarySignerMaterialRecipientRequests: context.ordinarySignerMaterialRecipientRequests,
    exportRoot: context.exportRoot,
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
      readonly enrollment:
        | { readonly kind: 'existing_enrollment' }
        | { readonly kind: 'new_enrollment' };
      readonly factorSecret: Uint8Array;
      readonly providerUserId: string;
      readonly exportRootRequirement?: never;
      readonly verificationGrant?: never;
      readonly factorRelease?: never;
    };

type CompletedEmailOtpTargetActivationStateV1 = Extract<
  EmailOtpTargetActivationStateV1,
  { readonly kind: 'completed' }
>;

function requireCompletedEmailOtpTargetActivationStateV1(
  state: EmailOtpTargetActivationStateV1,
): CompletedEmailOtpTargetActivationStateV1 {
  if (
    state.kind !== 'completed' ||
    !state.factorSecret ||
    typeof state.providerUserId !== 'string'
  ) {
    throw new Error('linked-device Email OTP factor runtime is unavailable');
  }
  return {
    kind: 'completed',
    runEpoch: state.runEpoch,
    enrollment: state.enrollment,
    factorSecret: state.factorSecret,
    providerUserId: state.providerUserId,
  };
}

function assertNeverEmailOtpTargetActivationState(value: never): never {
  throw new Error(`Unknown Email OTP target activation state: ${String(value)}`);
}

function assertNeverTargetCredentialActivationState(value: never): never {
  throw new Error(`Unknown target credential activation state: ${String(value)}`);
}

type PostLinkActivationV1 =
  | {
      readonly factor: {
        readonly kind: 'passkey';
        readonly walletId: ActiveWalletSessionV1['walletId'];
      };
      readonly factorSecret32: Uint8Array;
    }
  | {
      readonly factor: {
        readonly kind: 'email_otp';
        readonly walletId: ActiveWalletSessionV1['walletId'];
        readonly walletAuthMethodId: LinkedDeviceTargetCredentialRegistrationResultV1['walletAuthMethodId'];
        readonly emailHashHex: string;
        readonly providerIdentity: {
          readonly provider: 'google' | 'email';
          readonly providerSubjectId: string;
        };
      };
      readonly factorSecret32: Uint8Array;
    };

function resolvePostLinkActivationV1(input: {
  readonly targetFactor: LinkedDeviceTargetCredentialRegistrationResultV1['targetFactor'];
  readonly walletAuthMethodId: LinkedDeviceTargetCredentialRegistrationResultV1['walletAuthMethodId'];
  readonly targetCredentialActivationState: TargetCredentialActivationState;
  readonly emailOtpTargetActivationState: EmailOtpTargetActivationStateV1;
  readonly walletId: ActiveWalletSessionV1['walletId'];
  readonly runEpoch: number;
}): PostLinkActivationV1 {
  switch (input.targetFactor.kind) {
    case 'verified_passkey_target_v1': {
      const activation = input.targetCredentialActivationState;
      if (
        (activation.kind !== 'factor_ready' && activation.kind !== 'consuming') ||
        activation.runEpoch !== input.runEpoch
      ) {
        throw new Error('linked-device Passkey factor runtime is unavailable');
      }
      return {
        factor: {
          kind: 'passkey',
          walletId: input.walletId,
        },
        factorSecret32: activation.factorSecret,
      };
    }
    case 'verified_email_otp_target_v1': {
      const activation = requireCompletedEmailOtpTargetActivationStateV1(
        input.emailOtpTargetActivationState,
      );
      if (activation.runEpoch !== input.runEpoch) {
        throw new Error('linked-device Email OTP factor runtime is unavailable');
      }
      return {
        factor: {
          kind: 'email_otp',
          walletId: input.walletId,
          walletAuthMethodId: input.walletAuthMethodId,
          emailHashHex: input.targetFactor.authMethod.emailHashHex,
          providerIdentity: {
            provider: emailOtpProviderForLinkedEnrollment(activation.enrollment),
            providerSubjectId: activation.providerUserId,
          },
        },
        factorSecret32: activation.factorSecret,
      };
    }
    default:
      return assertNeverVerifiedTargetFactor(input.targetFactor);
  }
}

function assertNeverVerifiedTargetFactor(value: never): never {
  throw new Error(`Unknown verified target factor kind: ${String(value)}`);
}

function zeroizeLiveBytes(value: Uint8Array): void {
  if (value.byteLength > 0) value.fill(0);
}

function emailOtpProviderForLinkedEnrollment(
  enrollment: CompletedEmailOtpTargetActivationStateV1['enrollment'],
): 'google' | 'email' {
  return enrollment.kind === 'existing_enrollment' ? 'google' : 'email';
}

function requireTargetRpIdV1(preparation: PasskeyTargetPreparationV1): WebAuthnRpId {
  return preparation.passkeyCreationOptions.rpId;
}

function requireEmailOtpTargetPreparationV1(
  preparation: LinkedDeviceTargetPreparationV1,
): EmailOtpTargetPreparationV1 {
  if (!isEmailOtpTargetPreparation(preparation)) {
    throw new Error('linked-device Email OTP preparation is unavailable');
  }
  return preparation;
}

function createExportRootEnvelopeIdV1(): PasskeyEnvelopeId {
  const parsed = parsePasskeyEnvelopeId(
    secureRandomId('linked-device-ed25519-export-root-envelope', 24, 'export-root envelope ids'),
  );
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function createEmailOtpFactorSecretV1(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

async function prepareNewEmailOtpEnrollmentMaterialV1(input: {
  readonly context: DeviceLinkingWebContext;
  readonly walletId: EmailOtpTargetPreparationV1['walletId'];
  readonly targetEmail: EmailOtpTargetPreparationV1['targetEmail'];
  readonly factorSecret: Uint8Array;
}): Promise<{
  readonly enrollmentId: string;
  readonly enrollment: WalletEmailOtpEnrollmentMaterialV1;
}> {
  const disposableSecret = input.factorSecret.slice();
  try {
    const material =
      await input.context.signingEngine.prepareEmailOtpRegistrationEnrollmentMaterialInternal({
        relayUrl: String(input.context.configs.network.relayer.url || '').trim(),
        walletId: input.walletId,
        userId: input.targetEmail,
        clientSecret32: disposableSecret,
      });
    if (material.emailOtpSessionHandle.kind !== 'not_requested') {
      throw new Error('Strict linked-device Email OTP enrollment received obsolete ECDSA material');
    }
    return {
      enrollmentId: material.enrollmentId,
      enrollment: material.emailOtpEnrollment,
    };
  } finally {
    zeroizeLiveBytes(disposableSecret);
  }
}

function buildDevice2QrSessionPayloadV1(input: {
  readonly linkSessionId: import('@shared/signing-lanes/ids').LinkDeviceSessionId;
  readonly linkPublicKeyB64u: import('@shared/device-linking').LinkDevicePublicKeyB64u;
  readonly devicePublicKeyB64u: import('@shared/device-linking').LinkDevicePublicKeyB64u;
  readonly target: StartDevice2LinkingFlowArgs;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): QrLinkedDeviceSessionPayloadV5 {
  const requestedPermission = buildFullOwnerDelegatedWalletAuthorityV1();
  if (input.target.targetFactor.kind === 'email_otp') {
    return buildQrLinkedDeviceSessionPayloadV5({
      linkSessionId: input.linkSessionId,
      linkPublicKeyB64u: input.linkPublicKeyB64u,
      devicePublicKeyB64u: input.devicePublicKeyB64u,
      requestedPermission,
      targetFactor: { kind: 'email_otp' },
      targetEmail: normalizeLinkedDeviceTargetEmailAddressV1(input.target.targetEmail),
      issuedAtMs: input.issuedAtMs,
      expiresAtMs: input.expiresAtMs,
    });
  }
  return buildQrLinkedDeviceSessionPayloadV5({
    linkSessionId: input.linkSessionId,
    linkPublicKeyB64u: input.linkPublicKeyB64u,
    devicePublicKeyB64u: input.devicePublicKeyB64u,
    requestedPermission,
    targetFactor: { kind: 'passkey_prf' },
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  });
}

function requireNewEmailOtpEnrollmentMaterialV1(
  value: WalletEmailOtpEnrollmentMaterialV1 | null,
): WalletEmailOtpEnrollmentMaterialV1 {
  if (!value) {
    throw new Error('new linked-device Email OTP enrollment material is unavailable');
  }
  return value;
}

export class LinkDeviceFlow {
  private readonly options: StartDevice2LinkingFlowArgs;
  private readonly ports: Device2LinkingFlowPortsV1;
  private readonly getAuthenticationContext: GetLinkedDeviceAuthenticationContext | null;
  private readonly flowId: string;
  private session: DeviceLinkingSession | null = null;
  private keyMaterialHandle: DeviceLinkingKeyMaterialHandleV1 | null = null;
  private deliveryRecipientPublicKey65B64u: string | null = null;
  private resealedExportRoot:
    | import('./deviceLinkingEd25519ExportRoot').DeviceLinkingResealedEd25519ExportRootV1
    | null = null;
  private targetCredentialRegistrationResult: LinkedDeviceTargetCredentialRegistrationResultV1 | null =
    null;
  // This boundary is the server commit. Cleanup and retry keep its exact identity intact.
  private committedAuthorityPackages: CommittedAuthorityPackagesV1 | null = null;
  private deliveryRecoveryReason: LinkedDeviceDeliveryRecoveryReasonV1 | null = null;
  private ordinarySignerMaterialRecipientPreparation: DeviceLinkingOrdinarySignerMaterialRecipientPreparationV1 | null =
    null;
  private authenticatedTransport: DeviceLinkingAuthenticatedTransportPortV1 | null = null;
  private subscription: LinkSessionSubscriptionV1 | null = null;
  private error?: Error;
  private cancelled = false;
  private runEpoch = 0;
  private generationInProgress = false;
  private discardInProgress: Promise<void> | null = null;
  private targetCredentialActivationState: TargetCredentialActivationState = { kind: 'idle' };
  private emailOtpTargetActivationState: EmailOtpTargetActivationStateV1 = { kind: 'idle' };
  private readonly handledStates = new Set<LinkSessionStateV1['state']>();
  private sessionEventQueue: Promise<void> = Promise.resolve();

  constructor(
    options: StartDevice2LinkingFlowArgs,
    ports: Device2LinkingFlowPortsV1,
    getAuthenticationContext: GetLinkedDeviceAuthenticationContext | null = null,
  ) {
    this.options = options;
    this.flowId = createFlowId();
    this.ports = ports;
    this.getAuthenticationContext = getAuthenticationContext;
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
      this.deliveryRecipientPublicKey65B64u = keyMaterial.deliveryRecipientPublicKey65B64u;
      const issuedAtMs = Date.now();
      const linkSessionId = createLinkSessionId();
      const qrData = buildDevice2QrSessionPayloadV1({
        linkSessionId,
        linkPublicKeyB64u: keyMaterial.linkPublicKeyB64u,
        devicePublicKeyB64u: keyMaterial.devicePublicKeyB64u,
        target: this.options,
        issuedAtMs,
        expiresAtMs: issuedAtMs + 15 * 60 * 1000,
      });
      const state: Extract<LinkSessionStateV1, { readonly state: 'displaying_qr' }> = {
        state: 'displaying_qr',
      };
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
    if (this.hasCommittedDeliveryState()) {
      throw new Error('Device-link authority delivery is committed and must be resumed');
    }
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
              state: { state: 'cancelled', cancelledAtMs: now },
            };
            break;
          case 'claimed':
          case 'awaiting_target_factor':
          case 'awaiting_source_contribution':
          case 'provisioning': {
            const identity = await this.resolveLinkIdentityV1(session.linkSessionId);
            await authenticatedTransport.cancelSessionV1({
              request: buildLinkedDeviceSessionCancelClaimedRequestV1({
                linkSessionId: session.linkSessionId,
                enrollmentId: identity.enrollmentId,
                deviceId: identity.deviceId,
                reason: 'user_cancelled',
                requestedAtMs: now,
              }),
            });
            this.session = {
              ...session,
              state: { state: 'cancelled', cancelledAtMs: now },
            };
            break;
          }
          case 'authority_pending_local_install':
            break;
          case 'active':
          case 'expired':
          case 'cancelled':
          case 'failed_before_commit':
            break;
          default:
            assertNeverLinkSessionStateV1(session.state);
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
    if (this.hasCommittedDeliveryState()) {
      throw new Error('Device-link authority delivery is committed and must be resumed');
    }
    this.runEpoch += 1;
    this.cancelled = true;
    await this.cleanupLocalResources();
    this.session = null;
    this.error = undefined;
    this.cancelled = false;
    this.handledStates.clear();
  }

  private async resolveLinkIdentityV1(
    linkSessionId: import('@shared/signing-lanes/ids').LinkDeviceSessionId,
  ): Promise<{
    readonly walletId: LinkedDeviceTargetPreparationV1['walletId'];
    readonly enrollmentId: LinkedDeviceTargetPreparationV1['enrollmentId'];
    readonly deviceId: LinkedDeviceTargetPreparationV1['deviceId'];
  }> {
    const cached = this.targetCredentialRegistrationResult;
    if (cached && cached.linkSessionId === linkSessionId) {
      return {
        walletId: cached.walletId,
        enrollmentId: cached.enrollmentId,
        deviceId: cached.deviceId,
      };
    }
    const preparation = await this.requireAuthenticatedTransport().getTargetPreparationV1({
      linkSessionId,
      deliveryRecipientPublicKey65B64u: this.requireDeliveryRecipientPublicKey65B64u(),
    });
    return {
      walletId: preparation.walletId,
      enrollmentId: preparation.enrollmentId,
      deviceId: preparation.deviceId,
    };
  }

  private async handleSessionEvent(event: LinkSessionTransportEventV1): Promise<void> {
    if (
      this.cancelled ||
      this.deliveryRecoveryReason !== null ||
      !this.session ||
      event.linkSessionId !== this.session.linkSessionId
    )
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
    if (this.handledStates.has(event.state.state)) {
      /* A replayed event for an already-handled state must not regress the
         linear local session state, so the handled check precedes the write. */
      logDevice2LinkingStageV1({
        flowId: this.flowId,
        linkSessionId: event.linkSessionId,
        stage: 'session_event_already_handled',
        details: { state: event.state.state },
      });
      return;
    }
    this.session = { ...this.session, state: event.state };
    this.handledStates.add(event.state.state);
    switch (event.state.state) {
      case 'displaying_qr':
        return;
      case 'claimed':
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
      case 'awaiting_source_contribution':
        return;
      case 'provisioning':
      case 'authority_pending_local_install': {
        const result = await this.activateAuthorityForStateV1(event.state, runEpoch);
        if (result.kind === 'pending_local_install') return;
        if (result.kind === 'integrity_error') {
          throw new DeviceLinkingError(
            `Linked-device authority installation failed: ${result.reason}`,
            DeviceLinkingErrorCode.REGISTRATION_FAILED,
            'registration',
          );
        }
        if (result.kind === 'failed_before_commit' || result.kind === 'relink_required') {
          throw new DeviceLinkingError(
            'Linked-device authority activation cannot continue',
            DeviceLinkingErrorCode.REGISTRATION_FAILED,
            'registration',
          );
        }
        await this.finishActiveAuthorityV1(
          event.state,
          result.session,
          result.operationCredential,
          runEpoch,
        );
        return;
      }
      case 'active': {
        const result = await this.activateAuthorityForStateV1(event.state, runEpoch);
        if (result.kind === 'pending_local_install') return;
        if (result.kind === 'integrity_error') {
          throw new DeviceLinkingError(
            `Linked-device authority replay failed: ${result.reason}`,
            DeviceLinkingErrorCode.REGISTRATION_FAILED,
            'registration',
          );
        }
        if (result.kind === 'failed_before_commit' || result.kind === 'relink_required') {
          throw new DeviceLinkingError(
            'Linked-device authority replay cannot continue',
            DeviceLinkingErrorCode.REGISTRATION_FAILED,
            'registration',
          );
        }
        await this.finishActiveAuthorityV1(
          event.state,
          result.session,
          result.operationCredential,
          runEpoch,
        );
        return;
      }
      case 'expired': {
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
      case 'cancelled':
        this.cancelled = true;
        this.emit({
          phase: LinkDeviceEventPhase.CANCELLED,
          status: 'cancelled',
          message: 'The other device cancelled this linking request.',
          interaction: { kind: 'qr_display', overlay: 'show' },
        });
        this.runEpoch += 1;
        await this.cleanupLocalResources();
        return;
      case 'failed_before_commit':
        this.cancelled = true;
        this.runEpoch += 1;
        await this.cleanupLocalResources();
        return;
      default:
        return assertNeverLinkSessionStateV1(event.state);
    }
  }

  private async prepareTargetCredentialActivation(
    event: LinkSessionTransportEventV1,
    runEpoch: number,
  ): Promise<void> {
    if (event.state.state !== 'awaiting_target_factor') {
      throw new Error('target passkey activation requires an awaiting session');
    }
    const state = event.state;
    if (!this.keyMaterialHandle || !this.session)
      throw new Error('device-link key material is unavailable');
    const authenticatedTransport = this.requireAuthenticatedTransport();
    this.assertCurrentRun(runEpoch);
    const preparation = await authenticatedTransport.getTargetPreparationV1({
      linkSessionId: event.linkSessionId,
      deliveryRecipientPublicKey65B64u: this.requireDeliveryRecipientPublicKey65B64u(),
    });
    this.assertCurrentRun(runEpoch);
    this.assertTargetPreparationMatchesSession({
      preparation,
      state,
      linkSessionId: event.linkSessionId,
    });
    const deviceId = preparation.deviceId;
    this.ordinarySignerMaterialRecipientPreparation =
      await this.ports.keyMaterial.createOrdinarySignerMaterialRecipientRequestsV1({
        keyMaterial: this.keyMaterialHandle,
        requirements: preparation.ordinarySignerMaterialRecipientRequirements,
      });
    this.assertCurrentRun(runEpoch);
    if (this.requireSessionTargetFactorV1().kind === 'email_otp') {
      await this.prepareTargetEmailOtpActivation({
        event,
        state,
        runEpoch,
        deviceId,
        preparation,
      });
      return;
    }
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
    readonly event: LinkSessionTransportEventV1;
    readonly state: AwaitingTargetEmailOtpStateV1;
    readonly runEpoch: number;
    readonly deviceId: import('@shared/signing-lanes/ids').LinkedDeviceId;
    readonly preparation: LinkedDeviceTargetPreparationV1;
  }): Promise<void> {
    if (!isEmailOtpTargetPreparation(input.preparation)) {
      throw new Error('Email OTP session returned a non-Email OTP target preparation');
    }
    if (!this.keyMaterialHandle || !this.session || !this.deliveryRecipientPublicKey65B64u) {
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
    const exportRoot = input.preparation.ed25519ExportRoot;
    const exportRootContext: EmailOtpTargetActivationBaseContextV1['exportRoot'] =
      exportRoot === null
        ? { kind: 'not_required' }
        : {
            kind: 'required',
            recipient: await publishLinkedDeviceEd25519ExportRootRecipientV1({
              ed25519ExportRoot: this.ports.ed25519ExportRoot,
              transport: authenticatedTransport,
              identity: {
                linkSessionId: input.event.linkSessionId,
                walletId: input.preparation.walletId,
                walletKeyId: exportRoot.walletKeyId,
                enrollmentId: input.preparation.enrollmentId,
                deviceId: input.deviceId,
                applicationBindingDigestB64u: exportRoot.applicationBindingDigestB64u,
                registeredPublicKeyB64u: exportRoot.registeredPublicKeyB64u,
                targetFactor: input.preparation.targetFactor,
                revocationEpoch: exportRoot.revocationEpoch,
              },
              registeredAtMs: Date.now(),
            }),
          };
    this.assertCurrentRun(input.runEpoch);
    const baseContext: EmailOtpTargetActivationBaseContextV1 = {
      event: input.event,
      state: input.state,
      runEpoch: input.runEpoch,
      deviceId: input.deviceId,
      preparation: input.preparation,
      ordinarySignerMaterialRecipientRequests:
        this.requireOrdinarySignerMaterialRecipientPreparationV1().recipientRequests,
      exportRoot: exportRootContext,
    };
    this.emailOtpTargetActivationState = { kind: 'available', context: baseContext };
    await this.startTargetEmailOtpChallengeV1(baseContext);
  }

  private notifyEmailOtpActivationV1(state: LinkedDeviceTargetEmailOtpActivationV1['state']): void {
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
      const workerEphemeralPublicKey65B64u = this.deliveryRecipientPublicKey65B64u;
      if (!workerEphemeralPublicKey65B64u) {
        throw new Error('Email OTP factor-release recipient is unavailable');
      }
      const challenge = await this.requireAuthenticatedTransport().startTargetEmailOtpChallengeV1({
        request: {
          kind: 'linked_device_email_otp_challenge_start_request_v1',
          linkSessionId: context.event.linkSessionId,
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
        ordinarySignerMaterialRecipientRequests: context.ordinarySignerMaterialRecipientRequests,
        exportRoot: context.exportRoot,
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
      const challenge = await this.requireAuthenticatedTransport().resendTargetEmailOtpChallengeV1({
        request: {
          kind: 'linked_device_email_otp_challenge_resend_request_v1',
          linkSessionId: context.event.linkSessionId,
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
        ordinarySignerMaterialRecipientRequests: context.ordinarySignerMaterialRecipientRequests,
        exportRoot: context.exportRoot,
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
    let verification: Awaited<
      ReturnType<DeviceLinkingAuthenticatedTransportPortV1['verifyTargetEmailOtpChallengeV1']>
    >;
    try {
      verification = await this.requireAuthenticatedTransport().verifyTargetEmailOtpChallengeV1({
        request: {
          kind: 'linked_device_email_otp_challenge_verify_request_v1',
          linkSessionId: context.event.linkSessionId,
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
    const preparation = requireEmailOtpTargetPreparationV1(context.preparation);
    let recipient = context.exportRoot.kind === 'required' ? context.exportRoot.recipient : null;
    let factorSecret: ArrayBuffer | null = null;
    let retainedFactorSecret: Uint8Array | null = null;
    let verificationGrant:
      | Awaited<
          ReturnType<DeviceLinkingAuthenticatedTransportPortV1['verifyTargetEmailOtpChallengeV1']>
        >['verificationGrant']
      | null = null;
    let emailOtpEnrollmentId: string | null = null;
    let emailOtpEnrollmentSealKeyVersion: string | null = null;
    let emailOtpEnrollmentMaterial: WalletEmailOtpEnrollmentMaterialV1 | null = null;
    const existingEnrollment = preparation.enrollment.kind === 'existing_enrollment';
    try {
      const targetPreparationDigestB64u =
        await computeLinkedDeviceTargetPreparationDigestV1(preparation);
      if (verification.verificationGrant.targetEmail !== preparation.targetEmail) {
        throw new Error('linked-device Email OTP verification target email changed');
      }
      if (existingEnrollment) {
        const existingVerificationGrant = verification.verificationGrant;
        if (existingVerificationGrant.enrollment.kind !== 'existing_enrollment') {
          throw new Error('linked-device Email OTP verification enrollment changed');
        }
        const baseWalletAuthMethodId = existingVerificationGrant.baseWalletAuthMethodId;
        if (!baseWalletAuthMethodId) {
          throw new Error('linked-device Email OTP base auth method is unavailable');
        }
        const factorRelease = verification.factorRelease;
        if (!factorRelease) {
          throw new Error('linked-device Email OTP factor release is unavailable');
        }
        const opened = await this.ports.keyMaterial.openEmailOtpFactorReleaseV1({
          keyMaterial: this.requireKeyMaterialHandleV1(),
          walletId: preparation.walletId,
          linkSessionId: preparation.linkSessionId,
          enrollmentId: preparation.enrollmentId,
          deviceId: preparation.deviceId,
          walletAuthMethodId: preparation.walletAuthMethodId,
          baseWalletAuthMethodId,
          targetPreparationDigestB64u,
          expectedChallengeId: context.challenge.challengeId,
          verificationGrant: existingVerificationGrant,
          factorRelease,
        });
        factorSecret = opened.factorSecret;
        verificationGrant = opened.verificationGrant;
        emailOtpEnrollmentId = factorRelease.enrollmentId;
        emailOtpEnrollmentSealKeyVersion = factorRelease.enrollmentSealKeyVersion;
      } else {
        const newVerificationGrant = verification.verificationGrant;
        if (newVerificationGrant.enrollment.kind !== 'new_enrollment') {
          throw new Error('linked-device Email OTP verification enrollment changed');
        }
        if (verification.factorRelease !== null) {
          throw new Error('new linked-device Email OTP enrollment returned a factor release');
        }
        const authenticationContext = this.getAuthenticationContext?.();
        if (!authenticationContext) {
          throw new Error('linked-device authentication context is unavailable');
        }
        const freshFactorSecret = createEmailOtpFactorSecretV1();
        factorSecret = freshFactorSecret.buffer;
        const enrollment = await prepareNewEmailOtpEnrollmentMaterialV1({
          context: authenticationContext,
          walletId: preparation.walletId,
          targetEmail: preparation.targetEmail,
          factorSecret: freshFactorSecret,
        });
        emailOtpEnrollmentId = enrollment.enrollmentId;
        emailOtpEnrollmentSealKeyVersion = enrollment.enrollment.enrollmentSealKeyVersion;
        emailOtpEnrollmentMaterial = enrollment.enrollment;
        verificationGrant = newVerificationGrant;
      }
      if (
        !factorSecret ||
        !verificationGrant ||
        !emailOtpEnrollmentId ||
        !emailOtpEnrollmentSealKeyVersion
      ) {
        throw new Error('linked-device Email OTP factor material is unavailable');
      }
      this.assertCurrentRun(context.runEpoch);
      if (context.exportRoot.kind === 'required') {
        if (!recipient) {
          throw new Error('linked-device Ed25519 export-root recipient is unavailable');
        }
        const exportRoot = preparation.ed25519ExportRoot;
        if (!exportRoot) {
          throw new Error('linked-device Ed25519 export-root preparation is unavailable');
        }
        const envelopeId = createExportRootEnvelopeIdV1();
        const factor = buildEmailOtpEnvelopeFactor({
          enrollmentId: emailOtpEnrollmentId,
          enrollmentSealKeyVersion: emailOtpEnrollmentSealKeyVersion,
        });
        const binding = buildEd25519YaoClientRootBinding({
          linkSessionId: preparation.linkSessionId,
          walletKeyId: exportRoot.walletKeyId,
          targetFactor: preparation.targetFactor,
          applicationBindingDigestB64u: exportRoot.applicationBindingDigestB64u,
          registeredPublicKeyB64u: exportRoot.registeredPublicKeyB64u,
          enrollmentId: preparation.enrollmentId,
          deviceId: preparation.deviceId,
          revocationEpoch: exportRoot.revocationEpoch,
        });
        const resealed = await acceptLinkedDeviceEd25519ExportRootV1({
          ed25519ExportRoot: this.ports.ed25519ExportRoot,
          transport: this.requireAuthenticatedTransport(),
          recipient,
          replacementEnvelope: buildDeviceLinkingEd25519ExportRootReplacementEnvelopeV1({
            walletId: preparation.walletId,
            ownership: buildMethodBoundEnvelopeOwnership(preparation.walletAuthMethodId),
            envelopeId,
            factor,
            binding,
            createdAtMs: Date.now(),
          }),
          replacementFactorSecret: new Uint8Array(factorSecret),
          expiresAtMs: Math.min(
            preparation.expiresAtMs,
            this.requireSessionV1().qrData.expiresAtMs,
          ),
          assertCurrentRun: () => this.assertCurrentRun(context.runEpoch),
          waitForPollV1: waitForSessionStateRetry,
        });
        this.resealedExportRoot = resealed;
        recipient = null;
      }
      const registration = existingEnrollment
        ? buildLinkedDeviceTargetCredentialRegistrationV1({
            linkSessionId: preparation.linkSessionId,
            walletId: preparation.walletId,
            enrollmentId: preparation.enrollmentId,
            deviceId: preparation.deviceId,
            walletAuthMethodId: preparation.walletAuthMethodId,
            targetFactor: { kind: 'email_otp' },
            targetEmail: preparation.targetEmail,
            emailOtpVerificationGrant: verificationGrant,
            targetPreparationDigestB64u,
            ordinarySignerMaterialRecipientRequests:
              context.ordinarySignerMaterialRecipientRequests,
            registeredAtMs: Date.now(),
          })
        : buildLinkedDeviceTargetCredentialRegistrationV1({
            linkSessionId: preparation.linkSessionId,
            walletId: preparation.walletId,
            enrollmentId: preparation.enrollmentId,
            deviceId: preparation.deviceId,
            walletAuthMethodId: preparation.walletAuthMethodId,
            targetFactor: { kind: 'email_otp' },
            targetEmail: preparation.targetEmail,
            emailOtpVerificationGrant: verificationGrant,
            emailOtpEnrollment: requireNewEmailOtpEnrollmentMaterialV1(emailOtpEnrollmentMaterial),
            targetPreparationDigestB64u,
            ordinarySignerMaterialRecipientRequests:
              context.ordinarySignerMaterialRecipientRequests,
            registeredAtMs: Date.now(),
          });
      const registrationResult =
        await this.requireAuthenticatedTransport().registerTargetCredentialV1({ registration });
      this.assertCurrentRun(context.runEpoch);
      this.targetCredentialRegistrationResult = registrationResult;
      retainedFactorSecret = new Uint8Array(factorSecret).slice();
      await this.ports.keyMaterial.prepareOrdinarySignerMaterialV1({
        keyMaterial: this.requireKeyMaterialHandleV1(),
        targetFactor: registrationResult.targetFactor,
        preparations: registrationResult.ordinarySignerMaterialPreparations,
        recipientRequests: registrationResult.ordinarySignerMaterialRecipientRequests,
        recipientInputs: this.requireOrdinarySignerMaterialRecipientPreparationV1().recipientInputs,
        factorSecret,
      });
      factorSecret = null;
      this.assertCurrentRun(context.runEpoch);
      logDevice2LinkingStageV1({
        flowId: this.flowId,
        linkSessionId: context.preparation.linkSessionId,
        stage: 'ordinary_signer_material_prepared',
      });
      if (!retainedFactorSecret) {
        throw new Error('linked-device Email OTP factor runtime is unavailable');
      }
      this.emailOtpTargetActivationState = {
        kind: 'completed',
        runEpoch: context.runEpoch,
        enrollment: existingEnrollment
          ? { kind: 'existing_enrollment' }
          : { kind: 'new_enrollment' },
        factorSecret: retainedFactorSecret,
        providerUserId: verificationGrant.providerUserId,
      };
      retainedFactorSecret = null;
      this.notifyEmailOtpActivationV1({
        kind: 'completed',
        maskedEmailHint: context.challenge.maskedEmailHint,
      });
    } catch (error: unknown) {
      if (factorSecret && factorSecret.byteLength > 0) {
        new Uint8Array(factorSecret).fill(0);
      }
      retainedFactorSecret?.fill(0);
      if (recipient) {
        await discardLinkedDeviceEd25519ExportRootRecipientV1(
          this.ports.ed25519ExportRoot,
          recipient,
        );
      }
      if (this.isCurrentRun(context.runEpoch)) {
        const message = errorMessage(error) || 'Email OTP activation is unavailable';
        this.emailOtpTargetActivationState = {
          kind: 'failed',
          runEpoch: context.runEpoch,
          message,
        };
        this.notifyEmailOtpActivationV1({ kind: 'unavailable', message });
        await this.cancelFailedPrecommitSession(context.event).catch(() => undefined);
      }
      throw error;
    }
  }

  private activateTargetCredential(input: {
    readonly event: LinkSessionTransportEventV1;
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
    readonly event: LinkSessionTransportEventV1;
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
    const { runEpoch, deviceId, preparation } = input;
    if (!this.keyMaterialHandle || !this.session)
      throw new Error('device-link key material is unavailable');
    const authenticatedTransport = this.requireAuthenticatedTransport();
    logDevice2LinkingStageV1({
      flowId: this.flowId,
      linkSessionId: preparation.linkSessionId,
      stage: 'target_passkey_prompt_started',
    });
    const exportRoot = preparation.ed25519ExportRoot;
    // Started, not awaited. Device 1 can seal the export root as soon as
    // a recipient exists, and the owner is already waiting there, so publishing
    // one now lets that seal happen while this device's user is still at the
    // passkey prompt. Awaiting it here would spend the click's transient user
    // activation on a worker call and a POST before WebAuthn ever sees it.
    const recipientPublish =
      exportRoot === null
        ? Promise.resolve<DeviceLinkingEd25519ExportRootRecipientHandleV1 | null>(null)
        : publishLinkedDeviceEd25519ExportRootRecipientV1({
            ed25519ExportRoot: this.ports.ed25519ExportRoot,
            transport: authenticatedTransport,
            identity: {
              linkSessionId: preparation.linkSessionId,
              walletId: preparation.walletId,
              walletKeyId: exportRoot.walletKeyId,
              enrollmentId: preparation.enrollmentId,
              deviceId,
              applicationBindingDigestB64u: exportRoot.applicationBindingDigestB64u,
              registeredPublicKeyB64u: exportRoot.registeredPublicKeyB64u,
              targetFactor: preparation.targetFactor,
              revocationEpoch: exportRoot.revocationEpoch,
            },
            registeredAtMs: Date.now(),
          });
    // Nothing awaits it until after the prompt; this keeps an early rejection
    // from being reported as unhandled. It is re-raised at the await below.
    recipientPublish.catch(() => undefined);
    let credential: Awaited<
      ReturnType<DeviceLinkingTargetCredentialPortV1['createTargetCredentialV1']>
    > | null = null;
    let recipient: DeviceLinkingEd25519ExportRootRecipientHandleV1 | null = null;
    try {
      // This is the first operation after the UI click so WebAuthn receives transient user activation.
      credential = await this.ports.targetCredential.createTargetCredentialV1({
        preparation,
        keyMaterial: this.keyMaterialHandle,
      });
      if (credential.walletAuthMethodId !== preparation.walletAuthMethodId) {
        throw new Error('linked-device target credential returned a different auth method');
      }
      logDevice2LinkingStageV1({
        flowId: this.flowId,
        linkSessionId: preparation.linkSessionId,
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
      if (recipient) {
        logDevice2LinkingStageV1({
          flowId: this.flowId,
          linkSessionId: preparation.linkSessionId,
          stage: 'export_root_recipient_published',
        });
      }
      this.assertCurrentRun(runEpoch);
      if (exportRoot !== null) {
        if (!recipient) {
          throw new Error('linked-device Ed25519 export-root recipient is unavailable');
        }
        const envelopeId = createExportRootEnvelopeIdV1();
        const factor = buildPasskeyEnvelopeFactor({
          rpId: requireTargetRpIdV1(preparation),
          credentialIdB64u: credential.webauthnRegistration.credentialIdB64u,
        });
        const binding = buildEd25519YaoClientRootBinding({
          linkSessionId: preparation.linkSessionId,
          walletKeyId: exportRoot.walletKeyId,
          targetFactor: preparation.targetFactor,
          applicationBindingDigestB64u: exportRoot.applicationBindingDigestB64u,
          registeredPublicKeyB64u: exportRoot.registeredPublicKeyB64u,
          enrollmentId: preparation.enrollmentId,
          deviceId: preparation.deviceId,
          revocationEpoch: exportRoot.revocationEpoch,
        });
        const resealed = await acceptLinkedDeviceEd25519ExportRootV1({
          ed25519ExportRoot: this.ports.ed25519ExportRoot,
          transport: authenticatedTransport,
          recipient,
          replacementEnvelope: buildDeviceLinkingEd25519ExportRootReplacementEnvelopeV1({
            walletId: preparation.walletId,
            ownership: buildMethodBoundEnvelopeOwnership(preparation.walletAuthMethodId),
            envelopeId,
            factor,
            binding,
            createdAtMs: Date.now(),
          }),
          replacementFactorSecret: credential.factorSecret,
          expiresAtMs: Math.min(preparation.expiresAtMs, this.session.qrData.expiresAtMs),
          assertCurrentRun: () => this.assertCurrentRun(runEpoch),
          waitForPollV1: waitForSessionStateRetry,
        });
        logDevice2LinkingStageV1({
          flowId: this.flowId,
          linkSessionId: preparation.linkSessionId,
          stage: 'export_root_accepted',
        });
        this.resealedExportRoot = resealed;
        // The worker consumes and frees the recipient during every accept attempt.
        recipient = null;
      }
      this.assertCurrentRun(runEpoch);
      const targetPreparationDigestB64u =
        await computeLinkedDeviceTargetPreparationDigestV1(preparation);
      const registration = buildLinkedDeviceTargetCredentialRegistrationV1({
        linkSessionId: preparation.linkSessionId,
        walletId: preparation.walletId,
        enrollmentId: preparation.enrollmentId,
        deviceId: preparation.deviceId,
        walletAuthMethodId: credential.walletAuthMethodId,
        targetFactor: { kind: 'passkey_prf' },
        targetPreparationDigestB64u,
        webauthnRegistration: credential.webauthnRegistration,
        ordinarySignerMaterialRecipientRequests:
          this.requireOrdinarySignerMaterialRecipientPreparationV1().recipientRequests,
        registeredAtMs: Date.now(),
      });
      const registrationResult = await authenticatedTransport.registerTargetCredentialV1({
        registration,
      });
      this.assertCurrentRun(runEpoch);
      this.targetCredentialRegistrationResult = registrationResult;
      await this.ports.keyMaterial.prepareOrdinarySignerMaterialV1({
        keyMaterial: this.requireKeyMaterialHandleV1(),
        targetFactor: registrationResult.targetFactor,
        preparations: registrationResult.ordinarySignerMaterialPreparations,
        recipientRequests: registrationResult.ordinarySignerMaterialRecipientRequests,
        recipientInputs: this.requireOrdinarySignerMaterialRecipientPreparationV1().recipientInputs,
        factorSecret: credential.factorSecret.slice().buffer,
      });
      this.assertCurrentRun(runEpoch);
      logDevice2LinkingStageV1({
        flowId: this.flowId,
        linkSessionId: preparation.linkSessionId,
        stage: 'ordinary_signer_material_prepared',
      });
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
        await discardLinkedDeviceEd25519ExportRootRecipientV1(
          this.ports.ed25519ExportRoot,
          recipient,
        );
      }
      throw error;
    }
  }

  private assertTargetPreparationMatchesSession(input: {
    readonly preparation: import('@shared/device-linking').LinkedDeviceTargetPreparationV1;
    readonly state: AwaitingTargetFactorStateV1;
    readonly linkSessionId: import('@shared/signing-lanes/ids').LinkDeviceSessionId;
  }): void {
    const sessionTargetFactor = this.requireSessionTargetFactorV1();
    const qrData = this.requireSessionV1().qrData;
    if (
      input.preparation.linkSessionId !== input.linkSessionId ||
      String(input.preparation.deviceId) !== String(input.state.deviceId) ||
      input.preparation.targetFactor.kind !== sessionTargetFactor.kind ||
      input.preparation.deliveryRecipientPublicKey65B64u !==
        this.requireDeliveryRecipientPublicKey65B64u() ||
      input.preparation.expiresAtMs <= Date.now()
    ) {
      throw new Error('linked-device target preparation does not match the claimed session');
    }
    if (
      sessionTargetFactor.kind === 'email_otp' &&
      qrData.targetFactor.kind === 'email_otp' &&
      input.preparation.targetFactor.kind === 'email_otp' &&
      input.preparation.targetEmail !== qrData.targetEmail
    ) {
      throw new Error('linked-device target preparation email does not match the QR session');
    }
  }

  private async activateAuthorityForStateV1(
    state: Extract<
      LinkSessionStateV1,
      { readonly state: 'provisioning' | 'authority_pending_local_install' | 'active' }
    >,
    runEpoch: number,
  ): Promise<Awaited<ReturnType<typeof activateLinkedAuthorityV1>>> {
    this.assertCurrentRun(runEpoch);
    await this.waitForTargetCredentialActivation();
    this.assertCurrentRun(runEpoch);
    const registration = this.targetCredentialRegistrationResult;
    if (!registration) {
      throw new Error('linked-device target credential registration is unavailable');
    }
    const keyMaterial = this.requireKeyMaterialHandleV1();
    const transport = this.requireAuthenticatedTransport();
    const expectedLockGeneration = await this.ports.readExpectedLockGenerationV1(
      registration.walletId,
    );
    this.assertCurrentRun(runEpoch);
    const committed =
      this.committedAuthorityPackages ||
      (await transport.receiveCommittedAuthorityPackagesV1({
        linkSessionId: this.requireSessionV1().linkSessionId,
      }));
    this.committedAuthorityPackages = committed;
    await this.ports.authorityInstallation.persistCommittedDeliveryResumeV1({
      linkSessionId: this.requireSessionV1().linkSessionId,
      committed,
      targetFactor: registration.targetFactor,
      committedAtMs: Date.now(),
    });
    this.assertCurrentRun(runEpoch);
    const activationDeadlineMs = this.requireSessionV1().qrData.expiresAtMs;
    let attempt = 0;
    while (Date.now() < activationDeadlineMs) {
      const result = await activateLinkedAuthorityV1({
        transport,
        committed,
        installation: this.ports.authorityInstallation,
        sessionState: state,
        linkSessionId: this.requireSessionV1().linkSessionId,
        targetFactor: registration.targetFactor,
        keyMaterialPort: this.ports.keyMaterial,
        keyMaterial,
        deliveryRecipientPublicKey65B64u: this.requireDeliveryRecipientPublicKey65B64u(),
        resealedExportRoot: this.resealedExportRoot,
        expectedLockGeneration,
        nowMs: () => Date.now(),
      });
      if (result.kind !== 'pending_local_install') return result;
      await waitForSessionStateRetry(attempt);
      this.assertCurrentRun(runEpoch);
      attempt += 1;
    }
    throw new DeviceLinkingError(
      'Linked-device authority activation did not complete before the link session expired',
      DeviceLinkingErrorCode.REGISTRATION_FAILED,
      'registration',
    );
  }

  private async finishActiveAuthorityV1(
    state: Extract<
      LinkSessionStateV1,
      { readonly state: 'provisioning' | 'authority_pending_local_install' | 'active' }
    >,
    walletSession: ActiveWalletSessionV1,
    operationCredential: WalletSessionOperationCredentialV1,
    runEpoch: number,
  ): Promise<void> {
    this.assertCurrentRun(runEpoch);
    const session = this.requireSessionV1();
    const registration = this.targetCredentialRegistrationResult;
    if (!registration || registration.walletId !== walletSession.walletId) {
      throw new Error('linked-device activation identity is unavailable');
    }
    const activeSession: DeviceLinkingSession = {
      ...session,
      state: {
        state: 'active',
        deviceId: state.deviceId,
        authorityId: walletSession.authorityId,
        activatedAtMs: walletSession.issuedAtMs,
      },
    };
    /* Activation can complete from any delivery-state event; the transport may
       still deliver the remaining queued transitions afterwards. Those events
       must acknowledge the finished activation instead of re-entering it
       against the consumed one-shot factor state. */
    this.handledStates.add('provisioning');
    this.handledStates.add('authority_pending_local_install');
    this.handledStates.add('active');
    const authenticationContext = this.getAuthenticationContext?.();
    if (!authenticationContext) {
      throw new Error('linked-device authentication context is unavailable');
    }
    const postLinkActivation = resolvePostLinkActivationV1({
      targetFactor: registration.targetFactor,
      walletAuthMethodId: registration.walletAuthMethodId,
      targetCredentialActivationState: this.targetCredentialActivationState,
      emailOtpTargetActivationState: this.emailOtpTargetActivationState,
      walletId: walletSession.walletId,
      runEpoch,
    });
    await activateLinkedDeviceSignerRuntimesAfterLink({
      context: authenticationContext,
      factor: postLinkActivation.factor,
      walletSession,
      operationCredential,
      factorSecret32: postLinkActivation.factorSecret32,
    });
    const committed = this.committedAuthorityPackages;
    if (!committed) {
      throw new Error(
        'linked-device committed authority packages are unavailable for acknowledgement',
      );
    }
    const installationReceipt =
      await this.ports.authorityInstallation.readLocalAuthorityInstallationReceiptV1({
        authorityId: walletSession.authorityId,
      });
    if (!installationReceipt) {
      throw new Error('linked-device installation receipt is unavailable for acknowledgement');
    }
    const acknowledgement: LocalAuthorityActivationFinalAckV1 = {
      kind: 'local_authority_activation_final_ack_v1',
      linkSessionId: session.qrData.linkSessionId,
      authorityId: walletSession.authorityId,
      packageSetDigestB64u: committed.packageSetDigestB64u,
      authorizationId: walletSession.authorizationId,
      walletSessionId: operationCredential.walletSessionId,
      credentialDigestB64u:
        await computeWalletSessionOperationCredentialDigestB64u(operationCredential),
      installationReceiptDigestB64u:
        await computeWalletSessionInstallationReceiptDigestB64u(installationReceipt),
      acknowledgedAtMs: Date.now(),
    };
    await this.ports.authorityInstallation.persistPendingActivationAcknowledgementV1({
      acknowledgement,
    });
    /* The acknowledgement commits the server's cleanup batch, which deletes
       the link session. The poller must already be closed by then, or its next
       tick reads the deleted session as a spurious not_found. The durable
       pending acknowledgement above keeps replay possible without it. */
    await this.closeSessionSubscriptionV1();
    await this.requireAuthenticatedTransport().acknowledgeLocalAuthorityActivationV1({
      acknowledgement,
    });
    await this.ports.authorityInstallation.clearPendingActivationAcknowledgementV1({
      authorityId: acknowledgement.authorityId,
    });
    await this.ports.authorityInstallation.clearCommittedDeliveryResumeV1({
      authorityId: acknowledgement.authorityId,
    });
    this.session = activeSession;
    authenticationContext.signingEngine.setWalletAuthenticated(
      linkedDeviceWalletAuthenticationState(walletSession, registration),
    );
    await this.cleanupCompletedLocalResources();
    logDevice2LinkingStageV1({
      flowId: this.flowId,
      linkSessionId: session.qrData.linkSessionId,
      stage: 'post_link_runtime_ready',
    });
    this.emit({
      phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
      status: 'succeeded',
      message: 'Device link active',
      walletId: String(walletSession.walletId),
      data: {
        role: 'display',
        enrollmentId: String(registration.enrollmentId),
      },
      interaction: { kind: 'qr_display', overlay: 'hide' },
    });
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

  private requireDeliveryRecipientPublicKey65B64u(): string {
    if (!this.deliveryRecipientPublicKey65B64u) {
      throw new Error('device-link delivery recipient is unavailable');
    }
    return this.deliveryRecipientPublicKey65B64u;
  }

  private requireOrdinarySignerMaterialRecipientPreparationV1(): DeviceLinkingOrdinarySignerMaterialRecipientPreparationV1 {
    const preparation = this.ordinarySignerMaterialRecipientPreparation;
    if (!preparation) {
      throw new Error('ordinary signer material recipient preparation is unavailable');
    }
    return preparation;
  }

  private startRun(): number {
    this.clearTargetCredentialActivationState();
    this.clearEmailOtpTargetActivationState();
    this.resealedExportRoot = null;
    this.targetCredentialRegistrationResult = null;
    this.committedAuthorityPackages = null;
    this.deliveryRecoveryReason = null;
    this.ordinarySignerMaterialRecipientPreparation = null;
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

  private handleSessionTransportEvent(event: LinkSessionTransportEventV1): void {
    const processing = this.sessionEventQueue.then(this.handleSessionEvent.bind(this, event));
    this.sessionEventQueue = processing.catch(this.handleSessionTransportFailure.bind(this, event));
  }

  private async handleSessionTransportFailure(
    event: LinkSessionTransportEventV1,
    error: unknown,
  ): Promise<void> {
    if (error instanceof LinkDeviceFlowSupersededError) return;
    if (this.hasCommittedDeliveryState()) {
      await this.handleCommittedDeliveryFailureV1(event, error);
      return;
    }
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

  private async handleCommittedDeliveryFailureV1(
    event: LinkSessionTransportEventV1,
    error: unknown,
  ): Promise<void> {
    const recoveryReason = classifyLinkedDeviceDeliveryFailureV1(error);
    if (recoveryReason) {
      await this.requireExactMethodUnlockForCommittedDeliveryV1(event, recoveryReason);
      return;
    }
    logDevice2LinkingStageV1({
      flowId: this.flowId,
      linkSessionId: event.linkSessionId,
      stage: 'committed_delivery_retry_started',
      details: { state: event.state.state, error: errorMessage(error) },
    });
    this.handledStates.delete(event.state.state);
    try {
      await this.retryCommittedDeliveryV1(event);
    } catch (retryError: unknown) {
      const retryRecoveryReason = classifyLinkedDeviceDeliveryFailureV1(retryError);
      if (retryRecoveryReason) {
        await this.requireExactMethodUnlockForCommittedDeliveryV1(event, retryRecoveryReason);
        return;
      }
      logDevice2LinkingFailureV1({
        flowId: this.flowId,
        linkSessionId: event.linkSessionId,
        state: event.state.state,
        error: retryError,
      });
    }
  }

  private async requireExactMethodUnlockForCommittedDeliveryV1(
    event: LinkSessionTransportEventV1,
    reason: LinkedDeviceDeliveryRecoveryReasonV1,
  ): Promise<void> {
    this.deliveryRecoveryReason = reason;
    this.handledStates.clear();
    this.runEpoch += 1;
    const failure = new DeviceLinkingError(
      linkedDeviceDeliveryRecoveryMessageV1(reason),
      DeviceLinkingErrorCode.DELIVERY_RECOVERY_REQUIRED,
      'registration',
    );
    this.error = failure;
    try {
      await this.cleanupCompletedLocalResources();
    } catch (cleanupError: unknown) {
      logDevice2LinkingFailureV1({
        flowId: this.flowId,
        linkSessionId: event.linkSessionId,
        state: event.state.state,
        error: cleanupError,
      });
    }
    this.clearTargetCredentialActivationState();
    this.clearEmailOtpTargetActivationState();
    this.resealedExportRoot = null;
    this.targetCredentialRegistrationResult = null;
    this.committedAuthorityPackages = null;
    this.ordinarySignerMaterialRecipientPreparation = null;
    this.keyMaterialHandle = null;
    this.deliveryRecipientPublicKey65B64u = null;
    this.authenticatedTransport = null;
    this.subscription = null;
    this.emitFailure(failure, 'registration');
    notifyError(this.options.options?.onError, failure);
  }

  private async retryCommittedDeliveryV1(event: LinkSessionTransportEventV1): Promise<void> {
    if (await this.replayPendingActivationAcknowledgementV1()) return;
    switch (event.state.state) {
      case 'provisioning':
      case 'authority_pending_local_install':
      case 'active': {
        const runEpoch = this.runEpoch;
        const result = await this.activateAuthorityForStateV1(event.state, runEpoch);
        if (result.kind === 'pending_local_install') return;
        if (result.kind === 'integrity_error') {
          throw new DeviceLinkingError(
            `Linked-device authority replay failed: ${result.reason}`,
            DeviceLinkingErrorCode.REGISTRATION_FAILED,
            'registration',
          );
        }
        if (result.kind === 'failed_before_commit' || result.kind === 'relink_required') {
          throw new DeviceLinkingError(
            'Linked-device authority replay cannot continue',
            DeviceLinkingErrorCode.REGISTRATION_FAILED,
            'registration',
          );
        }
        await this.finishActiveAuthorityV1(
          event.state,
          result.session,
          result.operationCredential,
          runEpoch,
        );
        return;
      }
      default:
        throw new Error(`committed link delivery cannot resume from ${event.state.state}`);
    }
  }

  private async replayPendingActivationAcknowledgementV1(): Promise<boolean> {
    const committed = this.committedAuthorityPackages;
    if (!committed) return false;
    const pending = await this.ports.authorityInstallation.readPendingActivationAcknowledgementV1({
      authorityId: committed.authority.authorityId,
    });
    if (!pending) return false;
    const session = this.requireSessionV1();
    if (
      pending.linkSessionId !== session.qrData.linkSessionId ||
      pending.authorityId !== committed.authority.authorityId ||
      pending.packageSetDigestB64u !== committed.packageSetDigestB64u
    ) {
      throw new Error('pending linked-device acknowledgement identity is inconsistent');
    }
    await this.closeSessionSubscriptionV1();
    await this.requireAuthenticatedTransport().acknowledgeLocalAuthorityActivationV1({
      acknowledgement: pending,
    });
    await this.ports.authorityInstallation.clearPendingActivationAcknowledgementV1({
      authorityId: pending.authorityId,
    });
    await this.ports.authorityInstallation.clearCommittedDeliveryResumeV1({
      authorityId: pending.authorityId,
    });
    return true;
  }

  private async cancelFailedPrecommitSession(event: LinkSessionTransportEventV1): Promise<void> {
    const transport = this.authenticatedTransport;
    if (!transport) return;
    switch (event.state.state) {
      case 'claimed':
      case 'awaiting_target_factor':
      case 'awaiting_source_contribution':
      case 'provisioning': {
        const cancelledAtMs = Date.now();
        const identity = await this.resolveLinkIdentityV1(event.linkSessionId);
        await transport.cancelSessionV1({
          request: buildLinkedDeviceSessionCancelClaimedRequestV1({
            linkSessionId: event.linkSessionId,
            enrollmentId: identity.enrollmentId,
            deviceId: identity.deviceId,
            reason: 'user_cancelled',
            requestedAtMs: cancelledAtMs,
          }),
        });
        if (this.session?.linkSessionId === event.linkSessionId) {
          this.session = {
            ...this.session,
            state: { state: 'cancelled', cancelledAtMs },
          };
        }
        return;
      }
      case 'displaying_qr':
      case 'authority_pending_local_install':
      case 'active':
      case 'expired':
      case 'cancelled':
      case 'failed_before_commit':
        return;
      default:
        assertNeverLinkSessionStateV1(event.state);
    }
  }

  private async cleanupLocalResources(force = false): Promise<void> {
    if (!force && this.hasCommittedDeliveryState()) return;
    const preserveCommittedState = force && this.hasCommittedDeliveryState();
    if (!preserveCommittedState) {
      this.clearTargetCredentialActivationState();
      this.clearEmailOtpTargetActivationState();
      this.resealedExportRoot = null;
      this.targetCredentialRegistrationResult = null;
      this.ordinarySignerMaterialRecipientPreparation = null;
    }
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
    if (!failure) {
      try {
        await this.discardKeyMaterial();
      } catch (error: unknown) {
        failure = error;
      }
    }
    if (failure) throw failure;
    if (preserveCommittedState) {
      this.clearTargetCredentialActivationState();
      this.clearEmailOtpTargetActivationState();
      this.resealedExportRoot = null;
      this.targetCredentialRegistrationResult = null;
      this.ordinarySignerMaterialRecipientPreparation = null;
      this.committedAuthorityPackages = null;
    }
  }

  private async closeSessionSubscriptionV1(): Promise<void> {
    const subscription = this.subscription;
    if (!subscription) return;
    await subscription.close();
    if (this.subscription === subscription) this.subscription = null;
  }

  private async cleanupCompletedLocalResources(): Promise<void> {
    await this.cleanupLocalResources(true);
  }

  private clearEmailOtpTargetActivationState(): void {
    const state = this.emailOtpTargetActivationState;
    if (state.kind === 'completed') {
      const completedState = requireCompletedEmailOtpTargetActivationStateV1(state);
      completedState.factorSecret.fill(0);
    }
    this.emailOtpTargetActivationState = { kind: 'idle' };
  }

  private hasCommittedDeliveryState(): boolean {
    return (
      this.committedAuthorityPackages !== null ||
      (this.keyMaterialHandle !== null &&
        (this.session?.state.state === 'authority_pending_local_install' ||
          this.session?.state.state === 'active'))
    );
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
        this.deliveryRecipientPublicKey65B64u = null;
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
        retryable:
          error.code !== DeviceLinkingErrorCode.UNSUPPORTED &&
          error.code !== DeviceLinkingErrorCode.DELIVERY_RECOVERY_REQUIRED,
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

function isFinishedDeviceLinkFlow(flow: LinkDeviceFlow): boolean {
  const state = flow.getState();
  if (state.cancelled || state.error || !state.session) return true;
  switch (state.session.state.state) {
    case 'active':
    case 'expired':
    case 'cancelled':
    case 'failed_before_commit':
      return true;
    case 'displaying_qr':
    case 'claimed':
    case 'awaiting_target_factor':
    case 'awaiting_source_contribution':
    case 'provisioning':
    case 'authority_pending_local_install':
      return false;
    default:
      return assertNeverLinkSessionStateV1(state.session.state);
  }
}

export class DeviceLinkingDomain {
  private readonly deps: DeviceLinkingDomainDeps;
  private activeDeviceLinkFlow: LinkDeviceFlow | null = null;
  private activeOwnerLinkCancellation: Device1OwnerLinkCancellationV1 | null = null;

  constructor(deps: DeviceLinkingDomainDeps) {
    this.deps = deps;
  }

  async startDevice2LinkingFlow(
    args: StartDevice2LinkingFlowArgs,
  ): Promise<StartDevice2LinkingFlowResults> {
    if (this.deps.kind === 'direct' && !this.deps.walletIframe.shouldUseWalletIframe()) {
      if (this.activeDeviceLinkFlow && isFinishedDeviceLinkFlow(this.activeDeviceLinkFlow)) {
        this.activeDeviceLinkFlow = null;
      }
      if (this.activeDeviceLinkFlow) {
        throw new Error('Device-link QR flow is already running');
      }
      const flow = new LinkDeviceFlow(args, this.deps.ports, this.deps.getContext);
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
      if (this.activeDeviceLinkFlow && isFinishedDeviceLinkFlow(this.activeDeviceLinkFlow)) {
        this.activeDeviceLinkFlow = null;
      }
      if (this.activeDeviceLinkFlow) {
        await this.activeDeviceLinkFlow.cancel();
        this.activeDeviceLinkFlow = null;
        return;
      }
      const ownerCancellation = this.activeOwnerLinkCancellation;
      if (ownerCancellation) {
        await this.deps.ports.transport.cancelClaimedSessionV1(ownerCancellation);
        if (this.activeOwnerLinkCancellation === ownerCancellation) {
          this.activeOwnerLinkCancellation = null;
        }
      }
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
        this.registerOwnerLinkCancellationV1.bind(this),
      );
    }
    const router = await this.deps.walletIframe.requireRouter();
    return await router.scanAndLinkDevice({ qrData, options });
  }

  private registerOwnerLinkCancellationV1(
    cancellation: Device1OwnerLinkCancellationV1 | null,
  ): void {
    this.activeOwnerLinkCancellation = cancellation;
  }
}
