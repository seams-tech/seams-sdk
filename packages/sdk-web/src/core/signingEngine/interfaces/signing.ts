import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaThresholdKeyId } from '../session/identity/laneIdentity';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type {
  EcdsaRoleLocalBindingDigest,
  EcdsaRoleLocalMaterialHandle,
} from '../session/keyMaterialBrands';
import type {
  EcdsaRoleLocalPublicFacts,
  EcdsaRoleLocalReadyRecord,
  EcdsaRoleLocalReadyStateBlob,
} from '@/core/platform/types';

export type ChainNamespace = 'near' | 'evm' | 'tempo';

export type SignatureAlgorithm = 'ed25519' | 'secp256k1' | 'webauthnP256';

export type SignatureBytes = Uint8Array;

export type ThresholdEcdsaCanonicalExportArtifact = {
  artifactKind: 'ecdsa-derivation-secp256k1-export';
  chainTarget: ThresholdEcdsaChainTarget;
  signingRootId: string;
  signingRootVersion?: string;
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
};

export type { EcdsaThresholdKeyId };

export type ThresholdEcdsaClientAdditiveShareHandle = {
  kind: 'email_otp_worker_session';
  sessionId: string;
};

export type ThresholdEcdsaRoleLocalWorkerShareHandle = {
  kind: 'role_local_worker_session';
  materialHandle: EcdsaRoleLocalMaterialHandle;
  bindingDigest: EcdsaRoleLocalBindingDigest;
};

export type ThresholdEcdsaDerivationRoleLocalClientState = {
  kind: 'role_local_ready';
  artifactKind: 'ecdsa-derivation-role-local-client-state';
  stateBlob: EcdsaRoleLocalReadyStateBlob;
  publicFacts: EcdsaRoleLocalPublicFacts;
};

export type ThresholdEcdsaBackendBindingCommon = {
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
};

export type ThresholdEcdsaEmailOtpWorkerBackendBinding = ThresholdEcdsaBackendBindingCommon & {
  materialKind: 'email_otp_worker_handle';
  /**
   * Opaque handle for Email OTP-derived signing material owned by the Email OTP worker.
   * The handle is not secret material; callers must ask the worker for a one-time byte handoff.
   */
  clientAdditiveShareHandle: ThresholdEcdsaClientAdditiveShareHandle;
  ecdsaRoleLocalReadyRecord: EcdsaRoleLocalReadyRecord;
  stateBlob?: never;
  ecdsaDerivationRoleLocalClientState?: never;
};

export type ThresholdEcdsaRoleLocalReadyStateBlobBackendBinding =
  ThresholdEcdsaBackendBindingCommon & {
    materialKind: 'role_local_ready_state_blob';
    stateBlob: EcdsaRoleLocalReadyStateBlob;
    ecdsaRoleLocalReadyRecord: EcdsaRoleLocalReadyRecord;
    clientAdditiveShareHandle?: never;
    ecdsaDerivationRoleLocalClientState?: never;
  };

export type ThresholdEcdsaRoleLocalWorkerHandleBackendBinding =
  ThresholdEcdsaBackendBindingCommon & {
    materialKind: 'role_local_worker_handle';
    roleLocalMaterialHandle: ThresholdEcdsaRoleLocalWorkerShareHandle;
    ecdsaRoleLocalReadyRecord: EcdsaRoleLocalReadyRecord;
    stateBlob?: never;
    clientAdditiveShareHandle?: never;
    ecdsaDerivationRoleLocalClientState?: never;
  };

export type ThresholdEcdsaMetadataOnlyBackendBinding = ThresholdEcdsaBackendBindingCommon & {
  materialKind: 'metadata_only';
  stateBlob?: never;
  clientAdditiveShareHandle?: never;
  ecdsaRoleLocalReadyRecord?: never;
  ecdsaDerivationRoleLocalClientState?: never;
};

export type ThresholdEcdsaBackendBinding =
  | ThresholdEcdsaEmailOtpWorkerBackendBinding
  | ThresholdEcdsaRoleLocalWorkerHandleBackendBinding
  | ThresholdEcdsaRoleLocalReadyStateBlobBackendBinding
  | ThresholdEcdsaMetadataOnlyBackendBinding;

export type KeyRef =
  | {
      type: 'threshold-ecdsa-secp256k1';
      userId: string;
      chainTarget: ThresholdEcdsaChainTarget;
      relayerUrl: string;
      /**
       * Canonical product-facing identity for the integrated ecdsa-derivation key.
       */
      keyHandle?: string;
      evmFamilySigningKeySlotId: string;
      ecdsaThresholdKeyId: EcdsaThresholdKeyId;
      signingRootId?: never;
      signingRootVersion?: never;
      backendBinding?: ThresholdEcdsaBackendBinding;
      ecdsaDerivationExportArtifact?: ThresholdEcdsaCanonicalExportArtifact;
      participantIds?: number[];
      thresholdEcdsaPublicKeyB64u?: string;
      ethereumAddress?: string;
      relayerVerifyingShareB64u?: string;
      routerAbEcdsaDerivationNormalSigning?: RouterAbEcdsaDerivationNormalSigningStateV1;
      thresholdSessionKind?: 'jwt' | 'cookie';
      walletSessionJwt?: string;
      thresholdSessionId: string;
      signingGrantId: string;
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
       * When present, engines must use it instead of collecting another credential.
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
