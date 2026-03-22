import type { PasskeyManagerContext } from './index';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { validateNearAccountId } from '@shared/utils/validation';
import { getWalletSession } from './login';
import type {
  DeviceLinkingQRData,
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
} from '../types/linkDevice';
import { DeviceLinkingPhase, DeviceLinkingStatus } from '../types/sdkSentEvents';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '../types/linkDevice';
import { DEVICE_LINKING_CONFIG } from '../../config.js';
import { executeDeviceLinkingContractCalls } from '../rpcClients/near/rpcCalls';
import { ensureEd25519Prefix } from '@shared/utils/validation';
import { errorMessage } from '@shared/utils/errors';
import { IndexedDBManager } from '../indexedDB';
import { persistPreparedLinkDeviceSmartAccountSigners } from './near/linkDevicePreparedEcdsa';
import { createLocalDeployedSignerMutationRuntime } from './near/linkDeviceOwnerManagement';

/**
 * Device1 (original device): Link device using pre-scanned QR data
 */
export async function linkDeviceWithScannedQRData(
  context: PasskeyManagerContext,
  qrData: DeviceLinkingQRData,
  options: ScanAndLinkDeviceOptionsDevice1,
): Promise<LinkDeviceResult> {
  const { onEvent, onError } = options || {};

  try {
    onEvent?.({
      step: 2,
      phase: DeviceLinkingPhase.STEP_2_SCANNING,
      status: DeviceLinkingStatus.PROGRESS,
      message: 'Validating QR data...',
    });

    // Validate QR data
    validateDeviceLinkingQRData(qrData);

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

    onEvent?.({
      step: 3,
      phase: DeviceLinkingPhase.STEP_3_AUTHORIZATION,
      status: DeviceLinkingStatus.PROGRESS,
      message: `Performing TouchID authentication for device linking...`,
    });

    onEvent?.({
      step: 6,
      phase: DeviceLinkingPhase.STEP_6_REGISTRATION,
      status: DeviceLinkingStatus.PROGRESS,
      message: 'TouchID successful! Signing AddKey transaction...',
    });

    // Execute device linking transactions using the centralized RPC function
    const { addKeyTxResult } = await executeDeviceLinkingContractCalls({
      context,
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
        } else {
          const session = response.session && typeof response.session === 'object'
            ? (response.session as Record<string, unknown>)
            : {};
          const deviceNumber = Math.floor(Number(session.deviceNumber));
          if (Number.isFinite(deviceNumber) && deviceNumber > 0) {
            try {
              await persistPreparedLinkDeviceSmartAccountSigners({
                context,
                indexedDB: IndexedDBManager,
                accountId: String(device1AccountId),
                sessionId,
                deviceNumber,
              });
              await IndexedDBManager.repairSignerMutationSagasWithRuntime({
                limit: 64,
                runtime: createLocalDeployedSignerMutationRuntime({
                  context,
                  confirmationConfig: options?.confirmationConfig,
                }),
              });
            } catch (preparedError) {
              console.warn(
                '[link-device] prepared EVM signer sync skipped:',
                errorMessage(preparedError),
              );
            }
          }
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

    onEvent?.({
      step: 6,
      phase: DeviceLinkingPhase.STEP_6_REGISTRATION,
      status: DeviceLinkingStatus.SUCCESS,
      message: `Device2's key added to ${device1AccountId} successfully!`,
    });

    return result;
  } catch (error: unknown) {
    console.error('LinkDeviceFlow: linkDeviceWithQRData caught error:', error);

    const message = `Failed to scan and link device: ${errorMessage(error)}`;
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
