import { showWalletRecoveryCodesUi } from '@/SeamsWeb/operations/recovery/walletRecoveryCodeBackup';
import { pendingWalletRecoveryCodeBackupRepository } from '@/core/indexedDB/seamsWalletDB/pendingWalletRecoveryCodeBackup';
import {
  acknowledgeWalletRecoveryBackup,
  readWalletRecoveryCodeStatus,
  type WalletRecoveryCodeStatusResult,
} from '@/core/rpcClients/relayer/walletRecoveryRotate';
import type { WalletRecoveryCodeBackupRequestV1 } from '@/core/types/sdkSentEvents';
import { walletIframeRequestIdFromBoundary } from '@/core/types/walletIframeIdentity';
import type { WalletIframeSurfaceMeasurement } from '../shared/messages';
import type { WalletHostRuntimeRequest } from './runtimeContext';

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} is required`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, label: string): string {
  const normalized = typeof value === 'string' ? value.trim() : '';
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requireWalletId(payload: unknown): string {
  const record = requireRecord(payload, 'Recovery-code request payload');
  if (Object.prototype.hasOwnProperty.call(record, 'walletSessionToken')) {
    throw new Error('wallet iframe requests must not carry walletSessionToken');
  }
  return requireString(record.walletId, 'Recovery-code walletId');
}

function requireRelayerUrl(input: WalletHostRuntimeRequest): string {
  return requireString(input.state.walletConfigs?.relayer?.url, 'Recovery-code relayer URL');
}

function postSurfaceMeasurement(
  input: WalletHostRuntimeRequest,
  measurement: WalletIframeSurfaceMeasurement,
): void {
  input.post({ type: 'SURFACE_MEASUREMENT', payload: measurement });
}

async function loadRecoveryCodeStatus(
  relayUrl: string,
  walletId: string,
): Promise<WalletRecoveryCodeStatusResult> {
  const [status, pendingLocalBackup] = await Promise.all([
    readWalletRecoveryCodeStatus({ relayUrl, walletId }),
    pendingWalletRecoveryCodeBackupRepository.has(walletId),
  ]);
  return status.kind === 'ready' ? { ...status, pendingLocalBackup } : status;
}

async function loadPendingRecoveryCodeBackup(
  walletId: string,
): Promise<WalletRecoveryCodeBackupRequestV1 | null> {
  const pending = await pendingWalletRecoveryCodeBackupRepository.read(walletId);
  return pending
    ? {
        kind: 'wallet_recovery_code_backup_request_v1',
        walletId: pending.walletId,
        recoveryCodes: pending.recoveryCodes,
        continuation: 'pending_backup_must_finish',
      }
    : null;
}

export async function handleWalletHostRuntimeRequest(
  input: WalletHostRuntimeRequest,
): Promise<void> {
  if (input.req.type !== 'PM_ACKNOWLEDGE_WALLET_RECOVERY_CODE_BACKUP') {
    throw new Error(`Unsupported recovery-code request type: ${input.req.type}`);
  }
  const requestId = walletIframeRequestIdFromBoundary(input.req.requestId);
  if (input.respondIfCancelled(requestId)) return;

  const walletId = requireWalletId(input.req.payload);
  const relayUrl = requireRelayerUrl(input);
  const acknowledgement = await showWalletRecoveryCodesUi(
    {
      walletId,
      loadStatus: loadRecoveryCodeStatus.bind(null, relayUrl, walletId),
      loadPendingBackup: loadPendingRecoveryCodeBackup.bind(null, walletId),
    },
    {
      kind: 'wallet_iframe',
      requestId,
      postMeasurement: postSurfaceMeasurement.bind(null, input),
    },
  );
  if (acknowledgement.kind !== 'wallet_recovery_codes_backed_up_v1') {
    throw new Error('Pending wallet recovery-code backup was not completed');
  }

  const result = await acknowledgeWalletRecoveryBackup({ relayUrl, walletId });
  if (result.kind === 'acknowledged') {
    await pendingWalletRecoveryCodeBackupRepository.delete(walletId);
  }
  input.post({ type: 'PM_RESULT', requestId, payload: { ok: true, result } });
}
