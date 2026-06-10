import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';

export interface WarmSessionMaterialWriter {
  putWarmSessionMaterial(args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
  }): Promise<void>;
}
