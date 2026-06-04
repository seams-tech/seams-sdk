import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { WarmSessionMaterialWriter } from '@/core/signingEngine/session/passkey/warmSessionMaterialWriter';
import { cacheSigningSessionPrfFirst } from '@/core/signingEngine/session/passkey/prfCache';

export type HydrateWarmSigningSessionInput = {
  sessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  transport?: WarmSessionSealTransportInput;
};

export type WarmSessionHydrationService = {
  hydrateSigningSession(input: HydrateWarmSigningSessionInput): Promise<void>;
};

export function createWarmSessionHydrationService(deps: {
  getWarmSessionMaterialWriter: () => WarmSessionMaterialWriter;
}): WarmSessionHydrationService {
  return {
    hydrateSigningSession: (input) =>
      cacheSigningSessionPrfFirst(deps.getWarmSessionMaterialWriter(), input),
  };
}
