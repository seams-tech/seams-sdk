import type {
  ThresholdEcdsaAuthorizeResponse,
  ThresholdEcdsaAuthorizeWithSessionRequest,
  ThresholdEcdsaHssFinalizeRequest,
  ThresholdEcdsaHssFinalizeResponse,
  ThresholdEcdsaHssPrepareRequest,
  ThresholdEcdsaHssPrepareResponse,
  ThresholdEcdsaHssRespondRequest,
  ThresholdEcdsaHssRespondResponse,
  ThresholdEcdsaPresignInitRequest,
  ThresholdEcdsaPresignInitResponse,
  ThresholdEcdsaPresignStepRequest,
  ThresholdEcdsaPresignStepResponse,
} from '../../types';
import { THRESHOLD_SECP256K1_ECDSA_2P_V1_SCHEME_ID } from './schemeIds';
import type { ThresholdSecp256k1Ecdsa2pSchemeModule } from './types';
import type { ThresholdEcdsaSessionClaims } from '../validation';

export type ThresholdSecp256k1Ecdsa2pSchemeModuleDeps = {
  healthz?: () => Promise<{ ok: boolean; code?: string; message?: string }>;
  hss?: {
    prepare(
      request: ThresholdEcdsaHssPrepareRequest,
    ): Promise<ThresholdEcdsaHssPrepareResponse>;
    respond(
      request: ThresholdEcdsaHssRespondRequest,
    ): Promise<ThresholdEcdsaHssRespondResponse>;
    finalize(
      request: ThresholdEcdsaHssFinalizeRequest,
    ): Promise<ThresholdEcdsaHssFinalizeResponse>;
  };
  authorize(input: {
    claims: ThresholdEcdsaSessionClaims;
    request: ThresholdEcdsaAuthorizeWithSessionRequest;
  }): Promise<ThresholdEcdsaAuthorizeResponse>;
  presign: {
    init(input: {
      claims: ThresholdEcdsaSessionClaims;
      request: ThresholdEcdsaPresignInitRequest;
    }): Promise<ThresholdEcdsaPresignInitResponse>;
    step(input: {
      claims: ThresholdEcdsaSessionClaims;
      request: ThresholdEcdsaPresignStepRequest;
      transport?: {
        authorizationHeader?: string;
        cookieHeader?: string;
        forwardedHop?: number;
        forwardedByInstanceId?: string;
      };
    }): Promise<ThresholdEcdsaPresignStepResponse>;
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
    ...(deps.hss ? { hss: deps.hss } : {}),
    authorize: deps.authorize,
    presign: deps.presign,
    protocol: deps.protocol,
  };
}
