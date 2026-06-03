import type {
  ThresholdEd25519AuthorizeResponse,
  ThresholdEd25519AuthorizeWithSessionRequest,
  ThresholdEd25519CosignFinalizeRequest,
  ThresholdEd25519CosignFinalizeResponse,
  ThresholdEd25519CosignInitRequest,
  ThresholdEd25519CosignInitResponse,
  ThresholdEd25519FinalizeAndDispatchRequest,
  ThresholdEd25519FinalizeAndDispatchResponse,
  ThresholdEd25519PresignRefillRequest,
  ThresholdEd25519PresignRefillResponse,
  ThresholdEcdsaAuthorizeResponse,
  ThresholdEcdsaAuthorizeWithSessionRequest,
  ThresholdEcdsaCosignFinalizeRequest,
  ThresholdEcdsaCosignFinalizeResponse,
  ThresholdEcdsaCosignInitRequest,
  ThresholdEcdsaCosignInitResponse,
  ThresholdEcdsaPresignInitRequest,
  ThresholdEcdsaPresignInitResponse,
  ThresholdEcdsaPresignStepRequest,
  ThresholdEcdsaPresignStepResponse,
  ThresholdEcdsaSignFinalizeRequest,
  ThresholdEcdsaSignFinalizeResponse,
  ThresholdEcdsaSignInitRequest,
  ThresholdEcdsaSignInitResponse,
  ThresholdEd25519SessionRequest,
  ThresholdEd25519SessionResponse,
  ThresholdEd25519SignFinalizeRequest,
  ThresholdEd25519SignFinalizeResponse,
  ThresholdEd25519SignInitRequest,
  ThresholdEd25519SignInitResponse,
} from '../../types';
import type { ThresholdEd25519SessionClaims, ThresholdEcdsaSessionClaims } from '../validation';
import type { ThresholdSchemeId } from './schemeIds';

export interface ThresholdProtocolDriver<
  SignInitReq,
  SignInitRes,
  SignFinalizeReq,
  SignFinalizeRes,
  CosignInitReq = never,
  CosignInitRes = never,
  CosignFinalizeReq = never,
  CosignFinalizeRes = never,
> {
  signInit(request: SignInitReq): Promise<SignInitRes>;
  signFinalize(request: SignFinalizeReq): Promise<SignFinalizeRes>;
  internalCosignInit?: (request: CosignInitReq) => Promise<CosignInitRes>;
  internalCosignFinalize?: (request: CosignFinalizeReq) => Promise<CosignFinalizeRes>;
}

export interface ThresholdSchemeModule<
  SchemeId extends ThresholdSchemeId,
  KeygenReq,
  KeygenRes,
  SessionReq,
  SessionRes,
  AuthorizeClaims,
  AuthorizeReq,
  AuthorizeRes,
  SignInitReq,
  SignInitRes,
  SignFinalizeReq,
  SignFinalizeRes,
  CosignInitReq = never,
  CosignInitRes = never,
  CosignFinalizeReq = never,
  CosignFinalizeRes = never,
> {
  schemeId: SchemeId;
  protocol: ThresholdProtocolDriver<
    SignInitReq,
    SignInitRes,
    SignFinalizeReq,
    SignFinalizeRes,
    CosignInitReq,
    CosignInitRes,
    CosignFinalizeReq,
    CosignFinalizeRes
  >;

  healthz(): Promise<{ ok: boolean; code?: string; message?: string }>;

  keygen(request: KeygenReq): Promise<KeygenRes>;
  session(request: SessionReq): Promise<SessionRes>;
  authorize(input: { claims: AuthorizeClaims; request: AuthorizeReq }): Promise<AuthorizeRes>;
}

export type ThresholdEd25519RegistrationKeygenRequest = {
  nearAccountId: string;
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
  protocol: ThresholdProtocolDriver<
    ThresholdEd25519SignInitRequest,
    ThresholdEd25519SignInitResponse,
    ThresholdEd25519SignFinalizeRequest,
    ThresholdEd25519SignFinalizeResponse,
    ThresholdEd25519CosignInitRequest,
    ThresholdEd25519CosignInitResponse,
    ThresholdEd25519CosignFinalizeRequest,
    ThresholdEd25519CosignFinalizeResponse
  >;
  healthz(): Promise<{ ok: boolean; code?: string; message?: string }>;
  session(request: ThresholdEd25519SessionRequest): Promise<ThresholdEd25519SessionResponse>;
  authorize(input: {
    claims: ThresholdEd25519SessionClaims;
    request: ThresholdEd25519AuthorizeWithSessionRequest;
  }): Promise<ThresholdEd25519AuthorizeResponse>;
  presign: {
    refill(input: {
      claims: ThresholdEd25519SessionClaims;
      request: ThresholdEd25519PresignRefillRequest;
      requestOriginRateLimitKey?: string;
    }): Promise<ThresholdEd25519PresignRefillResponse>;
    finalizeAndDispatch(input: {
      claims: ThresholdEd25519SessionClaims;
      request: ThresholdEd25519FinalizeAndDispatchRequest;
    }): Promise<ThresholdEd25519FinalizeAndDispatchResponse>;
  };
  registration: {
    keygenFromRegistrationMaterial(
      request: ThresholdEd25519RegistrationKeygenRequest,
    ): Promise<ThresholdEd25519RegistrationKeygenResult>;
  };
};

export type ThresholdSecp256k1Ecdsa2pSchemeModule = {
  schemeId: 'threshold-secp256k1-ecdsa-2p-v1';
  protocol: ThresholdProtocolDriver<
    ThresholdEcdsaSignInitRequest,
    ThresholdEcdsaSignInitResponse,
    ThresholdEcdsaSignFinalizeRequest,
    ThresholdEcdsaSignFinalizeResponse,
    ThresholdEcdsaCosignInitRequest,
    ThresholdEcdsaCosignInitResponse,
    ThresholdEcdsaCosignFinalizeRequest,
    ThresholdEcdsaCosignFinalizeResponse
  >;
  healthz(): Promise<{ ok: boolean; code?: string; message?: string }>;
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
};

export type ThresholdAnySchemeModule =
  | ThresholdEd25519Frost2pSchemeModule
  | ThresholdSecp256k1Ecdsa2pSchemeModule;
