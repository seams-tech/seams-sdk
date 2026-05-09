import type { WarmSessionStatusResult } from '../../uiConfirm/types';
import type { RestoreSealedRecordForAccountResult } from './types';

export type RestoredWarmSessionStatus = {
  ok: true;
  remainingUses: number;
  expiresAtMs: number;
};

export async function recordAndVerifyRestoredWarmSessions(args: {
  sessionIds: readonly string[];
  restoredStatus: RestoredWarmSessionStatus;
  recordSessionMaterialRestored: (
    sessionId: string,
    status: RestoredWarmSessionStatus,
  ) => Promise<void>;
  verifySessionId: string;
  readWarmSessionStatus: (sessionId: string) => Promise<WarmSessionStatusResult>;
}): Promise<RestoreSealedRecordForAccountResult> {
  const normalizedSessionIds = [...new Set(args.sessionIds.map((value) => String(value || '').trim()))]
    .filter(Boolean);
  for (const sessionId of normalizedSessionIds) {
    await args.recordSessionMaterialRestored(sessionId, args.restoredStatus);
  }
  const verifySessionId = String(args.verifySessionId || '').trim();
  if (!verifySessionId) return 'deferred';
  const status = await args.readWarmSessionStatus(verifySessionId).catch(() => null);
  return status?.ok ? 'restored' : 'deferred';
}
