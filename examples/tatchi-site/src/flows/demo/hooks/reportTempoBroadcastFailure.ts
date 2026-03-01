import type { useTatchi } from '@tatchi-xyz/sdk/react';
import { normalizeLowercaseString } from '../../../../../../shared/src/utils/normalize';

type ReportTempoBroadcastFailureArgs = {
  tatchi: ReturnType<typeof useTatchi>['tatchi'];
  nearAccountId?: string | null;
  signedResult: Awaited<ReturnType<ReturnType<typeof useTatchi>['tatchi']['tempo']['signTempo']>> | null;
  error: unknown;
  flow: string;
  broadcastAccepted?: boolean;
  txHash?: `0x${string}`;
};

function normalizeToken(value: unknown): string {
  return normalizeLowercaseString(value).replace(/[\s-]+/g, '_');
}

function hasErrorCode(error: unknown, expected: string): boolean {
  if (!error || typeof error !== 'object') return false;
  const normalized = normalizeToken((error as { code?: unknown }).code);
  return normalized === normalizeToken(expected);
}

function messageIncludesNonceLaneBlocked(error: unknown): boolean {
  const message = normalizeLowercaseString(
    error instanceof Error
      ? error.message
      : error && typeof error === 'object' && 'message' in error
        ? (error as { message?: unknown }).message
        : error,
  );
  return message.includes('nonce lane blocked');
}

function extractDroppedOrReplacedReason(error: unknown): 'dropped' | 'replaced' | null {
  if (!error || typeof error !== 'object') return null;
  if (!hasErrorCode(error, 'tx_dropped_or_replaced')) return null;
  const reason = normalizeToken((error as { reason?: unknown }).reason);
  if (reason === 'replaced') return 'replaced';
  return 'dropped';
}

export async function reportTempoBroadcastFailure(args: ReportTempoBroadcastFailureArgs) {
  const { tatchi, nearAccountId, signedResult, error, flow, broadcastAccepted, txHash } = args;
  if (!signedResult || !nearAccountId) return;

  try {
    if (broadcastAccepted) {
      const droppedOrReplacedReason = extractDroppedOrReplacedReason(error);
      if (droppedOrReplacedReason) {
        await tatchi.tempo.reportDroppedOrReplaced({
          nearAccountId,
          signedResult,
          reason: droppedOrReplacedReason,
          ...(txHash ? { txHash } : {}),
        });
        return;
      }
      try {
        await tatchi.tempo.reconcileNonceLane({
          nearAccountId,
          signedResult,
        });
      } catch (reconcileError: unknown) {
        if (
          hasErrorCode(reconcileError, 'nonce_lane_blocked') ||
          messageIncludesNonceLaneBlocked(reconcileError)
        ) {
          await tatchi.tempo.reportDroppedOrReplaced({
            nearAccountId,
            signedResult,
            reason: 'dropped',
            ...(txHash ? { txHash } : {}),
          });
          return;
        }
        throw reconcileError;
      }
      return;
    }
    await tatchi.tempo.reportBroadcastRejected({
      nearAccountId,
      signedResult,
      error,
    });
  } catch (reportError: unknown) {
    console.error('[DemoPage][BroadcastReportError]', {
      atIso: new Date().toISOString(),
      flow,
      originalError: error,
      txHash,
      reportError,
    });
  }
}
