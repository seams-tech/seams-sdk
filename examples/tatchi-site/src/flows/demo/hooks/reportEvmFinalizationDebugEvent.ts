import { toast } from 'sonner';

import { compactHex, type EvmFinalizationDebugEvent } from '../demoEvmHelpers';

type ReportEvmFinalizationDebugEventArgs = {
  flowLabel: string;
  event: EvmFinalizationDebugEvent;
};

export function reportEvmFinalizationDebugEvent(args: ReportEvmFinalizationDebugEventArgs): void {
  const flowLabel = String(args.flowLabel || '').trim() || 'EVM tx';
  const branch = args.event.branch;
  const txHash = compactHex(args.event.txHash);
  const message = String(args.event.message || '').trim();
  const description = message ? `tx: ${txHash} · ${message}` : `tx: ${txHash}`;
  toast(`[debug] ${flowLabel} finalization branch: ${branch}`, {
    description,
    duration: 4_500,
  });
}
