import type { WebAuthnAuthenticationCredential } from '../../types/webauthn';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaThresholdKeyId } from '../session/identity/laneIdentity';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type {
  EcdsaRoleLocalPersistedMaterialRef,
  EcdsaRoleLocalWorkerHandle,
} from '../session/keyMaterialBrands';
import type {
  EcdsaRoleLocalAuthMethod,
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

export type ThresholdEcdsaDerivationRoleLocalClientState = {
  kind: 'role_local_ready';
  artifactKind: 'ecdsa-derivation-role-local-client-state';
  stateBlob: EcdsaRoleLocalReadyStateBlob;
  publicFacts: EcdsaRoleLocalPublicFacts;
};

export type ThresholdEcdsaBackendBindingCommon = {
  /**
   * SigningWorker key identifier for the fixed Router A/B ECDSA path. This is
   * separate from the public threshold identity seam.
   */
  relayerKeyId: string;
  /** Client public share used to bind the fixed Router A/B signing scope. */
  clientVerifyingShareB64u: string;
};

export type ThresholdEcdsaRoleLocalReadyStateBlobBackendBinding =
  ThresholdEcdsaBackendBindingCommon & {
    materialKind: 'role_local_ready_state_blob';
    stateBlob: EcdsaRoleLocalReadyStateBlob;
    ecdsaRoleLocalReadyRecord: EcdsaRoleLocalReadyRecord;
    ecdsaDerivationRoleLocalClientState?: never;
  };

export type ThresholdEcdsaRoleLocalWorkerHandleBackendBinding =
  ThresholdEcdsaBackendBindingCommon & {
    materialKind: 'role_local_worker_handle';
    roleLocalMaterialHandle: EcdsaRoleLocalWorkerHandle;
    roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
    publicFacts: EcdsaRoleLocalPublicFacts;
    authMethod: EcdsaRoleLocalAuthMethod;
    ecdsaRoleLocalReadyRecord?: never;
    stateBlob?: never;
    ecdsaDerivationRoleLocalClientState?: never;
  };

export type ThresholdEcdsaRoleLocalDurablePublicAnchorBackendBinding =
  ThresholdEcdsaBackendBindingCommon & {
    materialKind: 'role_local_durable_public_anchor';
    publicFacts: EcdsaRoleLocalPublicFacts;
    roleLocalMaterialHandle?: never;
    ecdsaRoleLocalReadyRecord?: never;
    stateBlob?: never;
    ecdsaDerivationRoleLocalClientState?: never;
  };

export type ThresholdEcdsaRoleLocalDurableSealedBackendBinding =
  ThresholdEcdsaBackendBindingCommon & {
    materialKind: 'role_local_durable_sealed_ref';
    roleLocalMaterialRef: EcdsaRoleLocalPersistedMaterialRef;
    publicFacts: EcdsaRoleLocalPublicFacts;
    roleLocalMaterialHandle?: never;
    ecdsaRoleLocalReadyRecord?: never;
    stateBlob?: never;
    ecdsaDerivationRoleLocalClientState?: never;
  };

export type ThresholdEcdsaMetadataOnlyBackendBinding = ThresholdEcdsaBackendBindingCommon & {
  materialKind: 'metadata_only';
  stateBlob?: never;
  ecdsaRoleLocalReadyRecord?: never;
  ecdsaDerivationRoleLocalClientState?: never;
};

export type ThresholdEcdsaBackendBinding =
  | ThresholdEcdsaRoleLocalWorkerHandleBackendBinding
  | ThresholdEcdsaRoleLocalDurableSealedBackendBinding
  | ThresholdEcdsaRoleLocalDurablePublicAnchorBackendBinding
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
