import type { useTatchi } from '@tatchi-xyz/sdk/react';

type ReportTempoBroadcastFailureArgs = {
  tatchi: ReturnType<typeof useTatchi>['tatchi'];
  nearAccountId?: string | null;
  signedResult: Awaited<ReturnType<ReturnType<typeof useTatchi>['tatchi']['tempo']['signTempo']>> | null;
  error: unknown;
  flow: string;
};

export async function reportTempoBroadcastFailure(args: ReportTempoBroadcastFailureArgs) {
  const { tatchi, nearAccountId, signedResult, error, flow } = args;
  if (!signedResult || !nearAccountId) return;

  try {
    await tatchi.tempo.reportBroadcastResult({
      nearAccountId,
      signedResult,
      status: 'failure',
      error,
    });
  } catch (reportError: unknown) {
    console.error('[DemoPage][BroadcastReportError]', {
      atIso: new Date().toISOString(),
      flow,
      originalError: error,
      reportError,
    });
  }
}
