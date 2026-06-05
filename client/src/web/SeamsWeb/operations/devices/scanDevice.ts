import type { DeviceLinkingWebContext } from '@/web/SeamsWeb/signingSurface/types';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { errorMessage } from '@shared/utils/errors';
import { validateNearAccountId } from '@shared/utils/validation';
import { getWalletSession } from '@/web/SeamsWeb/operations/auth/login';
import type {
  DeviceLinkingQRData,
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
} from '@/core/types/linkDevice';
import {
  createLinkDeviceFlowEvent,
  LinkDeviceEventPhase,
  type CreateLinkDeviceFlowEventInput,
} from '@/core/types/sdkSentEvents';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import { DEVICE_LINKING_CONFIG } from '@/config.js';
import { executeDeviceLinkingContractCalls } from '@/core/rpcClients/near/rpcCalls';
import { ensureEd25519Prefix } from '@shared/utils/validation';

type EmitLinkDeviceEventInput = Omit<CreateLinkDeviceFlowEventInput, 'flowId' | 'accountId'> & {
  accountId?: string;
};

function emitScannerLinkDeviceEvent(
  onEvent: ScanAndLinkDeviceOptionsDevice1['onEvent'] | undefined,
  qrData: DeviceLinkingQRData,
  event: EmitLinkDeviceEventInput,
): void {
  const sessionId = String(qrData?.sessionId || '').trim();
  const device2PublicKey = String(qrData?.device2PublicKey || '').trim();
  onEvent?.(
    createLinkDeviceFlowEvent({
      flowId: sessionId || `link-device-scan:${device2PublicKey || 'unknown'}`,
      ...(event.accountId ? { accountId: event.accountId } : {}),
      ...event,
      data: {
        role: 'scanner',
        ...(event.data || {}),
      },
    }),
  );
}

/**
 * Device1 (original device): Link device using pre-scanned QR data
 */
export async function linkDeviceWithScannedQRData(
  context: DeviceLinkingWebContext,
  qrData: DeviceLinkingQRData,
  options: ScanAndLinkDeviceOptionsDevice1,
): Promise<LinkDeviceResult> {
  const { onEvent, onError } = options || {};

  try {
    emitScannerLinkDeviceEvent(onEvent, qrData, {
      phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
      status: 'running',
      interaction: {
        kind: 'qr_scan',
        overlay: 'none',
      },
    });

    // Validate QR data
    validateDeviceLinkingQRData(qrData);

    emitScannerLinkDeviceEvent(onEvent, qrData, {
      phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_SUCCEEDED,
      status: 'succeeded',
      interaction: {
        kind: 'qr_scan',
        overlay: 'none',
      },
    });

    // 3. Get Device1's current account (the account that will receive the new key)
    const { login: device1LoginState } = await getWalletSession(context);

    if (!device1LoginState.isLoggedIn || !device1LoginState.nearAccountId) {
      throw new Error('Device1 must be logged in to authorize device linking');
    }

    const device1AccountId = device1LoginState.nearAccountId;

    // 4. Execute batched transaction: AddKey + Contract notification
    const fundingAmount = options.fundingAmount;

    // Parse the device public key for AddKey action
    const device2PublicKey = ensureEd25519Prefix(String(qrData?.device2PublicKey || '').trim());
    if (!device2PublicKey || !/^ed25519:/i.test(device2PublicKey)) {
      throw new Error('Invalid device public key format');
    }

    emitScannerLinkDeviceEvent(onEvent, qrData, {
      phase: LinkDeviceEventPhase.STEP_03_AUTHORIZATION_STARTED,
      status: 'waiting_for_user',
      accountId: String(device1AccountId),
      interaction: {
        kind: 'transaction_confirmation',
        overlay: 'show',
      },
    });

    emitScannerLinkDeviceEvent(onEvent, qrData, {
      phase: LinkDeviceEventPhase.STEP_04_LINK_REQUEST_SUBMITTED,
      status: 'running',
      accountId: String(device1AccountId),
      data: {
        device2PublicKey,
      },
      interaction: {
        kind: 'transaction_confirmation',
        overlay: 'hide',
      },
    });

    // Execute device linking transactions using the centralized RPC function
    const { addKeyTxResult } = await executeDeviceLinkingContractCalls({
      deps: {
        nearClient: context.nearClient,
        chains: context.configs.network.chains,
        signNear: (request) => context.signingEngine.signNear(request),
      },
      device1AccountId,
      device2PublicKey,
      onEvent,
      confirmationConfigOverride: options?.confirmationConfig,
      confirmerText: options?.confirmerText,
    });

    // Best-effort: claim the link-device session on the relay so Device2 can discover
    // the accountId without on-chain polling.
    const sessionId = String(qrData?.sessionId || '').trim();
    const relayerUrl = String(context?.configs?.network.relayer?.url || '').trim();
    const addKeyTxHash = String(addKeyTxResult?.transaction?.hash || '').trim() || undefined;
    if (sessionId && relayerUrl) {
      try {
        const resp = await fetch(joinNormalizedUrl(relayerUrl, '/link-device/session/claim'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            session_id: sessionId,
            account_id: String(device1AccountId),
            device2_public_key: device2PublicKey,
            ...(addKeyTxHash ? { add_key_tx_hash: addKeyTxHash } : {}),
          }),
        });
        const json: unknown = await resp.json().catch(() => ({}));
        const response = json && typeof json === 'object' ? (json as Record<string, unknown>) : {};
        if (!resp.ok || response.ok !== true) {
          const message =
            typeof response.message === 'string' ? response.message : `HTTP ${resp.status}`;
          console.warn('[link-device] relay claim failed:', message);
        }
      } catch (err) {
        console.warn('[link-device] relay claim error:', err);
      }
    }

    const result = {
      success: true,
      device2PublicKey,
      transactionId: addKeyTxResult?.transaction?.hash || 'unknown',
      fundingAmount,
      linkedToAccount: device1AccountId, // Include which account the key was added to
    };

    emitScannerLinkDeviceEvent(onEvent, qrData, {
      phase: LinkDeviceEventPhase.STEP_08_COMPLETED,
      status: 'succeeded',
      accountId: String(device1AccountId),
      data: {
        device2PublicKey,
        transactionId: result.transactionId,
      },
    });

    return result;
  } catch (error: unknown) {
    console.error('LinkDeviceFlow: linkDeviceWithQRData caught error:', error);

    const message = `Failed to scan and link device: ${errorMessage(error)}`;
    emitScannerLinkDeviceEvent(onEvent, qrData, {
      phase: LinkDeviceEventPhase.FAILED,
      status: 'failed',
      message,
      interaction: {
        kind: 'transaction_confirmation',
        overlay: 'hide',
      },
      error: {
        code: DeviceLinkingErrorCode.AUTHORIZATION_TIMEOUT,
        message,
        retryable: true,
      },
    });
    onError?.(new Error(message));

    throw new DeviceLinkingError(
      message,
      DeviceLinkingErrorCode.AUTHORIZATION_TIMEOUT,
      'authorization',
    );
  }
}

export function validateDeviceLinkingQRData(qrData: DeviceLinkingQRData): void {
  if (qrData.sessionId) {
    const sid = String(qrData.sessionId || '').trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sid)) {
      throw new DeviceLinkingError(
        'Invalid sessionId',
        DeviceLinkingErrorCode.INVALID_QR_DATA,
        'authorization',
      );
    }
  }

  const publicKey = String(qrData?.device2PublicKey || '').trim();
  if (!publicKey) {
    throw new DeviceLinkingError(
      'Missing device public key',
      DeviceLinkingErrorCode.INVALID_QR_DATA,
      'authorization',
    );
  }
  const normalized = ensureEd25519Prefix(publicKey);
  if (!/^ed25519:/i.test(normalized)) {
    throw new DeviceLinkingError(
      'Invalid device public key format',
      DeviceLinkingErrorCode.INVALID_QR_DATA,
      'authorization',
    );
  }

  if (!qrData.timestamp) {
    throw new DeviceLinkingError(
      'Missing timestamp',
      DeviceLinkingErrorCode.INVALID_QR_DATA,
      'authorization',
    );
  }

  // Check timestamp is not too old (max 15 minutes)
  const maxAge = DEVICE_LINKING_CONFIG.TIMEOUTS.QR_CODE_MAX_AGE_MS;
  if (Date.now() - qrData.timestamp > maxAge) {
    throw new DeviceLinkingError(
      'QR code expired',
      DeviceLinkingErrorCode.SESSION_EXPIRED,
      'authorization',
    );
  }

  // Account ID is optional - Device2 discovers it from contract logs
  if (qrData.accountId) {
    validateNearAccountId(qrData.accountId);
  }
}
