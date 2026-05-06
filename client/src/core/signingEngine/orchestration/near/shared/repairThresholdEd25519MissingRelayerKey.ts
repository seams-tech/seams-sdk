import type { SigningRuntimeDeps } from '@/core/signingEngine/interfaces/runtime';
import { ensureThresholdEd25519HssClientBase } from './ensureThresholdEd25519HssClientBase';

export async function repairThresholdEd25519MissingRelayerKey(args: {
  ctx: SigningRuntimeDeps;
  operationLabel: 'transactions' | 'delegate' | 'nep413';
  thresholdSessionId: string;
  thresholdSessionAuthToken?: string;
  relayerUrl: string;
  relayerKeyId: string;
  nearAccountId: string;
  keyVersion: string;
  participantIds: number[];
  prfFirstB64u: string;
  onProgress?: (message: string) => void;
}): Promise<string | undefined> {
  const startedAt = Date.now();
  console.warn(`[SigningEngine][near][${args.operationLabel}] relayer share cache missing`, {
    nearAccountId: args.nearAccountId,
    relayerKeyId: args.relayerKeyId,
    thresholdSessionId: args.thresholdSessionId,
  });

  const xClientBaseB64u = await ensureThresholdEd25519HssClientBase({
    ctx: args.ctx,
    thresholdSessionId: args.thresholdSessionId,
    thresholdSessionAuthToken: args.thresholdSessionAuthToken,
    relayerUrl: args.relayerUrl,
    relayerKeyId: args.relayerKeyId,
    nearAccountId: args.nearAccountId,
    keyVersion: args.keyVersion,
    participantIds: args.participantIds,
    prfFirstB64u: args.prfFirstB64u,
    forceRefresh: true,
    onProgress: args.onProgress,
  });

  console.info(
    `[SigningEngine][near][${args.operationLabel}] relayer share cache repair completed`,
    {
      nearAccountId: args.nearAccountId,
      relayerKeyId: args.relayerKeyId,
      thresholdSessionId: args.thresholdSessionId,
      repaired: Boolean(String(xClientBaseB64u || '').trim()),
      durationMs: Date.now() - startedAt,
    },
  );

  return xClientBaseB64u;
}
