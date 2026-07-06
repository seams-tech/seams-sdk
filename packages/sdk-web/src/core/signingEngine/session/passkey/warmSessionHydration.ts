import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type {
  WarmSessionMaterialWriter,
  WarmSessionMaterialWriteDiagnostics,
} from '@/core/signingEngine/session/passkey/warmSessionMaterialWriter';
import { cacheCredentialBoundarySetupExportPrfFirst } from '@/core/signingEngine/session/passkey/prfCache';

export type HydrateWarmSigningSessionInput = {
  sessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  transport?: WarmSessionSealTransportInput;
  diagnostics?: WarmSessionMaterialWriteDiagnostics;
};

export type WarmSessionHydrationService = {
  hydrateSigningSession(input: HydrateWarmSigningSessionInput): Promise<void>;
};

export function createWarmSessionHydrationService(deps: {
  getWarmSessionMaterialWriter: () => WarmSessionMaterialWriter;
}): WarmSessionHydrationService {
  return {
    hydrateSigningSession: (input) =>
      cacheCredentialBoundarySetupExportPrfFirst(deps.getWarmSessionMaterialWriter(), input),
  };
}
