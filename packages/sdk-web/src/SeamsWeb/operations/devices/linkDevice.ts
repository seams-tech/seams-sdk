import type { DeviceLinkingWebContext } from '@/SeamsWeb/signingSurface/types';
import type {
  DeviceLinkingSession,
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
  DeviceLinkingQRData,
} from '@/core/types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import {
  createLinkDeviceFlowEvent,
  LinkDeviceEventPhase,
  type CreateLinkDeviceFlowEventInput,
} from '@/core/types/sdkSentEvents';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import { linkDeviceWithScannedQRData as linkDeviceWithScannedQRDataDevice1 } from '@/SeamsWeb/operations/devices/scanDevice';
import { errorMessage } from '@shared/utils/errors';

const LINK_DEVICE_REFACTOR_84_MESSAGE =
  'Linked-device lane creation is disabled until refactor 84 lands';
const LINK_DEVICE_STUB_FLOW_ID = 'link-device:refactor-84-stub';

type EmitLinkDeviceEventInput = Omit<CreateLinkDeviceFlowEventInput, 'flowId' | 'accountId'> & {
  accountId?: string;
};
type StartDevice2LinkingCallbacks = NonNullable<StartDevice2LinkingFlowArgs['options']>;

function createUnsupportedLinkDeviceError(
  phase: DeviceLinkingError['phase'],
): DeviceLinkingError {
  return new DeviceLinkingError(
    LINK_DEVICE_REFACTOR_84_MESSAGE,
    DeviceLinkingErrorCode.UNSUPPORTED,
    phase,
  );
}

function emitLinkDeviceStubEvent(
  onEvent: StartDevice2LinkingCallbacks['onEvent'] | undefined,
  event: EmitLinkDeviceEventInput,
): void {
  onEvent?.(
    createLinkDeviceFlowEvent({
      flowId: LINK_DEVICE_STUB_FLOW_ID,
      ...(event.accountId ? { accountId: event.accountId } : {}),
      ...event,
    }),
  );
}

function notifyLinkDeviceError(
  onError: StartDevice2LinkingCallbacks['onError'] | undefined,
  error: Error,
): void {
  try {
    onError?.(error);
  } catch {
    // Callback failures must not replace the link-device stub error.
  }
}

function createStubSession(): DeviceLinkingSession {
  const createdAt = Date.now();
  return {
    sessionId: LINK_DEVICE_STUB_FLOW_ID,
    phase: LinkDeviceEventPhase.FAILED,
    createdAt,
    expiresAt: createdAt,
  };
}

export class LinkDeviceFlow {
  private readonly options: StartDevice2LinkingFlowArgs;
  private session: DeviceLinkingSession | null = null;
  private error?: Error;
  private cancelled = false;

  constructor(_context: DeviceLinkingWebContext, options: StartDevice2LinkingFlowArgs = {}) {
    this.options = options;
  }

  async generateQR(): Promise<StartDevice2LinkingFlowResults> {
    const error = createUnsupportedLinkDeviceError('generation');
    this.error = error;
    this.session = createStubSession();
    this.emit({
      phase: LinkDeviceEventPhase.FAILED,
      status: 'failed',
      message: error.message,
      data: {
        role: 'display',
      },
      interaction: {
        kind: 'qr_display',
        overlay: 'hide',
      },
      error: {
        code: error.code,
        message: error.message,
        retryable: false,
      },
    });
    notifyLinkDeviceError(this.options.options?.onError, error);
    throw error;
  }

  getState(): {
    phase: LinkDeviceEventPhase;
    session: DeviceLinkingSession | null;
    error?: Error;
    cancelled: boolean;
  } {
    return {
      phase: this.session?.phase ?? LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED,
      session: this.session,
      ...(this.error ? { error: this.error } : {}),
      cancelled: this.cancelled,
    };
  }

  cancel(): void {
    if (this.cancelled) return;
    this.cancelled = true;
    this.session = this.session
      ? { ...this.session, phase: LinkDeviceEventPhase.CANCELLED }
      : null;
    this.emit({
      phase: LinkDeviceEventPhase.CANCELLED,
      status: 'cancelled',
      message: 'Link-device flow cancelled',
      interaction: {
        kind: 'qr_display',
        overlay: 'hide',
      },
    });
  }

  reset(): void {
    this.session = null;
    this.error = undefined;
    this.cancelled = false;
  }

  private emit(event: EmitLinkDeviceEventInput): void {
    emitLinkDeviceStubEvent(this.options.options?.onEvent, event);
  }
}

export type DeviceLinkingDomainDeps = {
  getContext: () => DeviceLinkingWebContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
};

export class DeviceLinkingDomain {
  private readonly getContext: () => DeviceLinkingWebContext;
  private activeDeviceLinkFlow: LinkDeviceFlow | null = null;

  constructor(deps: DeviceLinkingDomainDeps) {
    this.getContext = deps.getContext;
  }

  async startDevice2LinkingFlow(
    args: StartDevice2LinkingFlowArgs = {},
  ): Promise<StartDevice2LinkingFlowResults> {
    const flow = new LinkDeviceFlow(this.getContext(), args);
    this.activeDeviceLinkFlow = flow;
    return await flow.generateQR();
  }

  async stopDevice2LinkingFlow(): Promise<void> {
    this.activeDeviceLinkFlow?.cancel();
    this.activeDeviceLinkFlow = null;
  }

  async linkDeviceWithScannedQRData(
    qrData: DeviceLinkingQRData,
    options: ScanAndLinkDeviceOptionsDevice1,
  ): Promise<LinkDeviceResult> {
    return await linkDeviceWithScannedQRDataDevice1(this.getContext(), qrData, options);
  }
}

export async function linkDeviceErrorResult(message: string, err?: unknown): Promise<never> {
  const detail = err ? `: ${errorMessage(err)}` : '';
  throw new Error(`${message}${detail}`);
}
