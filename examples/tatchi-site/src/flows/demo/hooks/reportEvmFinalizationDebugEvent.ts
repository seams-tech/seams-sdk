import { toast } from 'sonner';
import { normalizeTrimmedString } from '../../../../../../shared/src/utils/normalize';

import { compactHex, type EvmFinalizationDebugEvent } from '../demoEvmHelpers';

type ReportEvmFinalizationDebugEventArgs = {
  flowLabel: string;
  event: EvmFinalizationDebugEvent;
};

export function reportEvmFinalizationDebugEvent(args: ReportEvmFinalizationDebugEventArgs): void {
  const flowLabel = normalizeTrimmedString(args.flowLabel || '') || 'EVM tx';
  const event = args.event;
  const branch = event.branch;
  const txHash = compactHex(event.txHash);
  const message = normalizeTrimmedString(event.message || '');
  const chainTag = event.chain
    ? event.chainId != null
      ? `${event.chain}:${String(event.chainId)}`
      : event.chain
    : '';
  const details: string[] = [];
  details.push(`tx: ${txHash}`);
  if (chainTag) details.push(`chain: ${chainTag}`);
  if (event.nonce) details.push(`nonce: ${event.nonce}`);
  if (event.reason) details.push(`reason: ${event.reason}`);
  if (event.errorCode) details.push(`code: ${event.errorCode}`);
  if (message) details.push(message);
  toast(`[debug] ${flowLabel} finalization branch: ${branch}`, {
    description: details.join(' · '),
    duration: 4_500,
  });
}
