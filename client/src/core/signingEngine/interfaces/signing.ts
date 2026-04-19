import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';

export type ChainNamespace = 'near' | 'evm' | 'tempo';

export type SignatureAlgorithm = 'ed25519' | 'secp256k1' | 'webauthnP256';

export type SignatureBytes = Uint8Array;

export type ThresholdEcdsaCanonicalExportArtifact = {
  artifactKind: 'ecdsa-hss-secp256k1-key-v1';
  chain: 'evm' | 'tempo';
  signingRootId: string;
  signingRootVersion?: string;
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
};

export type EcdsaThresholdKeyId = string;

export type ThresholdEcdsaClientAdditiveShareHandle = {
  kind: 'email_otp_worker_session';
  sessionId: string;
};

export type ThresholdEcdsaBackendBinding = {
  /**
   * Backend integration identifier for the current threshold-signatures signer
   * path. This is not part of the public threshold identity seam.
   */
  relayerKeyId: string;
  /**
   * Backend integration detail for the current threshold-signatures signer
   * path. This is not part of the public threshold identity seam.
   */
  clientVerifyingShareB64u: string;
  /**
   * Canonical client additive share for integrated ecdsa-hss signing.
   * This remains an internal signer binding, not a public identity field.
   */
  clientAdditiveShare32B64u?: string;
  /**
   * Opaque handle for Email OTP-derived signing material owned by the Email OTP worker.
   * The handle is not secret material; callers must ask the worker for a one-time byte handoff.
   */
  clientAdditiveShareHandle?: ThresholdEcdsaClientAdditiveShareHandle;
};

export type KeyRef =
  | { type: 'local-secp256k1'; privateKey: Uint8Array }
  | {
      type: 'threshold-ecdsa-secp256k1';
      userId: string;
      relayerUrl: string;
      /**
       * Canonical product-facing identity for the integrated ecdsa-hss key.
       */
      ecdsaThresholdKeyId: EcdsaThresholdKeyId;
      signingRootId: string;
      signingRootVersion?: string;
      backendBinding?: ThresholdEcdsaBackendBinding;
      ecdsaHssExportArtifact?: ThresholdEcdsaCanonicalExportArtifact;
      participantIds?: number[];
      thresholdEcdsaPublicKeyB64u?: string;
      ethereumAddress?: string;
      relayerVerifyingShareB64u?: string;
      thresholdSessionKind?: 'jwt' | 'cookie';
      thresholdSessionJwt?: string;
      thresholdSessionId?: string;
      walletSigningSessionId?: string;
      mpcSessionId?: string;
    }
  | {
      type: 'webauthnP256';
      credentialId: Uint8Array;
      pubKeyX: Uint8Array;
      pubKeyY: Uint8Array;
      rpId?: string;
    };

export type ThresholdEcdsaSecp256k1KeyRef = Extract<KeyRef, { type: 'threshold-ecdsa-secp256k1' }>;

export type SignRequest =
  | {
      kind: 'digest';
      algorithm: Exclude<SignatureAlgorithm, 'webauthnP256'>;
      digest32: Uint8Array;
      label?: string;
    }
  | {
      kind: 'webauthn';
      algorithm: 'webauthnP256';
      challenge32: Uint8Array;
      rpId?: string;
      label?: string;
      /**
       * Optional serialized WebAuthn credential collected by touchConfirm.
       * When present, engines must not call `navigator.credentials.get`.
       */
      credential?: WebAuthnAuthenticationCredential;
    };

export interface SigningIntent<
  UiModel = unknown,
  Result = unknown,
  Request = SignRequest,
  Signed = SignatureBytes,
> {
  chain: ChainNamespace;
  uiModel: UiModel;
  signRequests: Request[];
  finalize: (signatures: Signed[]) => Promise<Result>;
}

export interface ChainAdapter<
  Request = unknown,
  UiModel = unknown,
  Result = unknown,
  SignRequestType = SignRequest,
  Signed = SignatureBytes,
> {
  readonly chain: ChainNamespace;
  buildIntent: (
    request: Request,
  ) => Promise<SigningIntent<UiModel, Result, SignRequestType, Signed>>;
}

export interface Signer<Request = SignRequest, Key = KeyRef, Signed = SignatureBytes> {
  readonly algorithm: SignatureAlgorithm;
  sign: (req: Request, keyRef: Key) => Promise<Signed>;
}

export type SignerMap<
  Request extends { algorithm: string } = SignRequest,
  Key = KeyRef,
  Signed = SignatureBytes,
> = Partial<Record<Request['algorithm'] & string, Signer<Request, Key, Signed>>>;
