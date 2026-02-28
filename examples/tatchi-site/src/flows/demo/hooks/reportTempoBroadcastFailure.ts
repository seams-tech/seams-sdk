import type { useTatchi } from '@tatchi-xyz/sdk/react';

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
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
}

function hasErrorCode(error: unknown, expected: string): boolean {
  if (!error || typeof error !== 'object') return false;
  const normalized = normalizeToken((error as { code?: unknown }).code);
  return normalized === normalizeToken(expected);
}

function messageIncludesNonceLaneBlocked(error: unknown): boolean {
  const message = String(
    error instanceof Error
      ? error.message
      : error && typeof error === 'object' && 'message' in error
        ? (error as { message?: unknown }).message
        : error,
  )
    .trim()
    .toLowerCase();
  return message.includes('nonce lane blocked');
}

export async function reportTempoBroadcastFailure(args: ReportTempoBroadcastFailureArgs) {
  const { tatchi, nearAccountId, signedResult, error, flow, broadcastAccepted, txHash } = args;
  if (!signedResult || !nearAccountId) return;

  try {
    if (broadcastAccepted) {
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
