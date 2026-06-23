import type {
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignFinalizeResponse,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519CosignInitResponse,
  ThresholdEcdsaCosignFinalizeRequest,
  ThresholdEcdsaCosignFinalizeResponse,
  ThresholdEcdsaCosignInitRequest,
  ThresholdEcdsaCosignInitResponse,
  RouterAbEcdsaHssPoolFillInitRequest,
  RouterAbEcdsaHssPoolFillInitResponse,
  RouterAbEcdsaHssPoolFillStepRequest,
  RouterAbEcdsaHssPoolFillStepResponse,
  ThresholdEd25519SessionRequest,
  ThresholdEd25519SessionResponse,
} from '../../types';
import type { ThresholdEd25519SessionClaims, ThresholdEcdsaSessionClaims } from '../validation';
import type { ThresholdSchemeId } from './schemeIds';

export interface ThresholdEd25519PrivateCosignProtocolDriver {
  internalCosignInit?: (
    request: ThresholdEd25519CosignInitRequest,
  ) => Promise<ThresholdEd25519CosignInitResponse>;
  internalCosignFinalize?: (
    request: ThresholdEd25519CosignFinalizeRequest,
  ) => Promise<ThresholdEd25519CosignFinalizeResponse>;
}

export type ThresholdEd25519RegistrationKeygenRequest = {
  walletId: string;
  nearAccountId: string;
  ed25519KeyScopeId: string;
  rpId: string;
  keyVersion: string;
  recoveryExportCapable: true;
  publicKey: string;
  relayerKeyId: string;
};

export type ThresholdEd25519RegistrationKeygenResult =
  | {
      ok: true;
      clientParticipantId: number;
      relayerParticipantId: number;
      participantIds: number[];
      relayerKeyId: string;
      publicKey: string;
      keyVersion: string;
      recoveryExportCapable: true;
      relayerVerifyingShareB64u: string;
    }
  | { ok: false; code: string; message: string };

export type ThresholdEd25519Frost2pSchemeModule = {
  schemeId: 'threshold-ed25519-frost-2p-v1';
  protocol: ThresholdEd25519PrivateCosignProtocolDriver;
  healthz(): Promise<{ ok: boolean; code?: string; message?: string }>;
  session(request: ThresholdEd25519SessionRequest): Promise<ThresholdEd25519SessionResponse>;
  registration: {
    keygenFromRegistrationMaterial(
      request: ThresholdEd25519RegistrationKeygenRequest,
    ): Promise<ThresholdEd25519RegistrationKeygenResult>;
  };
};

export interface ThresholdEcdsaPrivateCosignProtocolDriver {
  internalCosignInit?: (
    request: ThresholdEcdsaCosignInitRequest,
  ) => Promise<ThresholdEcdsaCosignInitResponse>;
  internalCosignFinalize?: (
    request: ThresholdEcdsaCosignFinalizeRequest,
  ) => Promise<ThresholdEcdsaCosignFinalizeResponse>;
}

export type ThresholdSecp256k1Ecdsa2pSchemeModule = {
  schemeId: 'threshold-secp256k1-ecdsa-2p-v1';
  protocol: ThresholdEcdsaPrivateCosignProtocolDriver;
  healthz(): Promise<{ ok: boolean; code?: string; message?: string }>;
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
};

export type ThresholdAnySchemeModule =
  | ThresholdEd25519Frost2pSchemeModule
  | ThresholdSecp256k1Ecdsa2pSchemeModule;
