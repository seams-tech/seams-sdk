import type {
  RouterAbEcdsaHssPoolFillInitRequest,
  RouterAbEcdsaHssPoolFillInitResponse,
  RouterAbEcdsaHssPoolFillStepRequest,
  RouterAbEcdsaHssPoolFillStepResponse,
} from '../../types';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from './schemeIds';
import type { ThresholdSecp256k1Ecdsa2pSchemeModule } from './thresholdServiceSchemes.types';
import type { ThresholdEcdsaSessionClaims } from '../validation';

export type ThresholdSecp256k1Ecdsa2pSchemeModuleDeps = {
  healthz?: () => Promise<{ ok: boolean; code?: string; message?: string }>;
  poolFill: {
    init(input: {
      claims: ThresholdEcdsaSessionClaims;
      request: RouterAbEcdsaHssPoolFillInitRequest;
    }): Promise<RouterAbEcdsaHssPoolFillInitResponse>;
    step(input: {
      claims: ThresholdEcdsaSessionClaims;
      request: RouterAbEcdsaHssPoolFillStepRequest;
      transport?: {
        authorizationHeader?: string;
        cookieHeader?: string;
        forwardedHop?: number;
        forwardedByInstanceId?: string;
      };
    }): Promise<RouterAbEcdsaHssPoolFillStepResponse>;
  };
  protocol: ThresholdSecp256k1Ecdsa2pSchemeModule['protocol'];
};

export function createThresholdSecp256k1Ecdsa2pSchemeModule(
  deps: ThresholdSecp256k1Ecdsa2pSchemeModuleDeps,
): ThresholdSecp256k1Ecdsa2pSchemeModule {
  return {
    schemeId: THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID,
    async healthz() {
      return deps.healthz ? await deps.healthz() : { ok: true };
    },
    poolFill: deps.poolFill,
    protocol: deps.protocol,
  };
}
