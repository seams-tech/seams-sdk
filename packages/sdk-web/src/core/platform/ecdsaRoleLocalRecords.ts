import type {
  EcdsaThresholdKeyId,
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
  SigningRootId,
  SigningRootVersion,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { WalletId } from '@shared/utils/domainIds';
import type { EvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type { PlatformResult } from './http';

export type {
  EcdsaThresholdKeyId,
  SigningRootId,
  SigningRootVersion,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
export type { WalletId } from '@shared/utils/domainIds';

export type EvmEip155ChainTarget = {
  kind: 'evm';
  namespace: 'eip155';
  chainId: number;
  networkSlug: string;
};

export type TempoChainTarget = {
  kind: 'tempo';
  chainId: number;
  networkSlug: string;
};

export type ThresholdEcdsaChainTarget = EvmEip155ChainTarget | TempoChainTarget;

export type CredentialIdB64u = string & { readonly __brand: 'CredentialIdB64u' };
export type RpId = string & { readonly __brand: 'RpId' };
export type EmailOtpAuthSubjectId = string & {
  readonly __brand: 'EmailOtpAuthSubjectId';
};
export type EcdsaGroupPublicKey33B64u = string & {
  readonly __brand: 'EcdsaGroupPublicKey33B64u';
};
export type RelayerKeyId = string & { readonly __brand: 'RelayerKeyId' };

export type EcdsaRoleLocalPendingStateBlob = {
  kind: 'ecdsa_role_local_pending_state_blob_v1';
  curve: 'secp256k1';
  encoding: 'base64url';
  producer: 'signer_core';
  stateBlobB64u: string;
};

export type EcdsaRoleLocalReadyStateBlob = {
  kind: 'ecdsa_role_local_state_blob_v1';
  curve: 'secp256k1';
  encoding: 'base64url';
  producer: 'signer_core';
  stateBlobB64u: string;
};

export type EcdsaRoleLocalPublicFacts = {
  walletId: WalletId;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  applicationBindingDigestB64u: string;
  clientParticipantId: 1;
  relayerParticipantId: 2;
  participantIds: readonly [1, 2];
  contextBinding32B64u: string;
  hssClientSharePublicKey33B64u: EcdsaHssClientSharePublicKey33B64u;
  relayerPublicKey33B64u: EcdsaRelayerHssPublicKey33B64u;
  groupPublicKey33B64u: EcdsaGroupPublicKey33B64u;
  ethereumAddress: `0x${string}`;
};

export type EcdsaRoleLocalAuthMethod =
  | {
      kind: 'passkey';
      credentialIdB64u: CredentialIdB64u;
      rpId: RpId;
      authSubjectId?: never;
    }
  | {
      kind: 'email_otp';
      authSubjectId: EmailOtpAuthSubjectId;
      credentialIdB64u?: never;
      rpId?: never;
    };

export type EcdsaRoleLocalReadyRecord =
  | {
      kind: 'ecdsa_role_local_ready_passkey_v1';
      stateBlob: EcdsaRoleLocalReadyStateBlob;
      publicFacts: EcdsaRoleLocalPublicFacts;
      authMethod: Extract<EcdsaRoleLocalAuthMethod, { kind: 'passkey' }>;
    }
  | {
      kind: 'ecdsa_role_local_ready_email_otp_v1';
      stateBlob: EcdsaRoleLocalReadyStateBlob;
      publicFacts: EcdsaRoleLocalPublicFacts;
      authMethod: Extract<EcdsaRoleLocalAuthMethod, { kind: 'email_otp' }>;
    };

export type EcdsaRoleLocalMaterialState =
  | {
      kind: 'ready';
      record: EcdsaRoleLocalReadyRecord;
      reauth?: never;
      cleanup?: never;
    }
  | {
      kind: 'reauth_required';
      walletId: WalletId;
      rpId: RpId;
      chainTarget: ThresholdEcdsaChainTarget;
      keyHandle: string;
      authMethod: EcdsaRoleLocalAuthMethod;
      reason: 'missing_session' | 'expired_session' | 'sealed_session_unavailable';
      record?: never;
      cleanup?: never;
    }
  | {
      kind: 'invalid_cleanup_required';
      cleanup: CleanupMalformedEcdsaRoleLocalRecordInput;
      reason: string;
      record?: never;
      reauth?: never;
    };

export type EcdsaRoleLocalEmailOtpWorkerShare = {
  kind: 'email_otp_worker_share';
  workerSessionId: string;
};

export type EcdsaRoleLocalReadyStateBlobSigningMaterial = {
  kind: 'role_local_ready_state_blob';
  stateBlob: EcdsaRoleLocalReadyStateBlob;
  workerSessionId?: never;
};

export type EcdsaRoleLocalSessionRecordState =
  | {
      kind: 'ready_passkey_role_local_material_v1';
      authMethod: Extract<EcdsaRoleLocalAuthMethod, { kind: 'passkey' }>;
      readyRecord: Extract<EcdsaRoleLocalReadyRecord, { authMethod: { kind: 'passkey' } }>;
      inlineSigningMaterial: EcdsaRoleLocalReadyStateBlobSigningMaterial;
      reauth?: never;
      cleanup?: never;
    }
  | {
      kind: 'ready_email_otp_role_local_material_v1';
      authMethod: Extract<EcdsaRoleLocalAuthMethod, { kind: 'email_otp' }>;
      readyRecord: Extract<EcdsaRoleLocalReadyRecord, { authMethod: { kind: 'email_otp' } }>;
      inlineSigningMaterial:
        | EcdsaRoleLocalEmailOtpWorkerShare
        | EcdsaRoleLocalReadyStateBlobSigningMaterial;
      reauth?: never;
      cleanup?: never;
    }
  | {
      kind: 'reauth_required_role_local_material_v1';
      authMethod: EcdsaRoleLocalAuthMethod;
      readyRecord: EcdsaRoleLocalReadyRecord;
      reason:
        | 'missing_worker_share'
        | 'expired'
        | 'exhausted'
        | 'unsupported_material_owner';
      inlineSigningMaterial?: never;
      cleanup?: never;
    }
  | {
      kind: 'cleanup_only_raw_role_local_record_v1';
      reason: 'malformed_record' | 'legacy_after_reset' | 'identity_mismatch';
      message: string;
      authMethod?: never;
      readyRecord?: never;
      inlineSigningMaterial?: never;
      reauth?: never;
    };

export type EcdsaRoleLocalRecordParseResult =
  | {
      ok: true;
      source: 'ready_record';
      state: Extract<EcdsaRoleLocalMaterialState, { kind: 'ready' | 'reauth_required' }>;
      code?: never;
      message?: never;
      cleanup?: never;
    }
  | {
      ok: false;
      code: 'malformed_record';
      message: string;
      cleanup: CleanupMalformedEcdsaRoleLocalRecordInput;
      source?: never;
      state?: never;
    };

export type LoadEcdsaRoleLocalReadyRecordInput = {
  walletId: WalletId;
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  participantIds: readonly [1, 2];
  authMethod: EcdsaRoleLocalAuthMethod;
};

export type LoadEcdsaRoleLocalReadyRecordResult = PlatformResult<
  | { kind: 'found'; record: EcdsaRoleLocalReadyRecord }
  | { kind: 'not_found'; record?: never }
  | {
      kind: 'reauth_required';
      state: Extract<EcdsaRoleLocalMaterialState, { kind: 'reauth_required' }>;
      record?: never;
    }
  | {
      kind: 'malformed';
      cleanup: CleanupMalformedEcdsaRoleLocalRecordInput;
      message: string;
      record?: never;
    },
  'unavailable'
>;

export type PersistEcdsaRoleLocalReadyRecordInput = {
  record: EcdsaRoleLocalReadyRecord;
  storageKeyFacts: LoadEcdsaRoleLocalReadyRecordInput;
};

export type PersistEcdsaRoleLocalReadyRecordResult = PlatformResult<
  { kind: 'persisted' },
  'unavailable' | 'invalid_record'
>;

export type CleanupMalformedEcdsaRoleLocalRecordInput = LoadEcdsaRoleLocalReadyRecordInput & {
  reason: string;
};

export type CleanupMalformedEcdsaRoleLocalRecordResult = PlatformResult<
  { kind: 'deleted' } | { kind: 'not_found' },
  'unavailable'
>;
