import type {
  DomainId,
  MpcMaterialActivationRef,
  WalletAuthMethodId,
  WalletId,
} from '../utils/domainIds';
import type { KeyCreationSignerSlot } from '../passkey-custody/primitives';
import type {
  Ed25519PublicKeyB64u,
  Secp256k1CompressedPublicKeyB64u,
} from '../passkey-custody/primitives';
import type { NearEd25519SigningKeyId } from '../utils/registrationIntent';
import type {
  LaneHolderParticipantRecordV1,
  LaneParticipantBindingDigestB64u,
  SigningWorkerParticipantRecordV1,
} from './participants';
import type { LaneShareEpoch, LinkedDeviceId, SigningLaneId, WalletKeyId } from './ids';
import type { EvmFamilySigningKeySlotId } from './evmFamilySigningKeySlotId';
import type { OwnerLaneParticipantContinuityV1 } from './ownerContinuity';

export type WalletKeyVersion = DomainId<'WalletKeyVersion'>;

export type WalletKeyLifecycle =
  | {
      readonly state: 'active';
      readonly activatedAtMs: number;
    }
  | {
      readonly state: 'retired';
      readonly retiredAtMs: number;
    }
  | {
      readonly state: 'compromised';
      readonly compromisedAtMs: number;
    };

export type Ed25519WalletKeyRecord = {
  readonly kind: 'wallet_key_record_v1';
  readonly keyFamily: 'ed25519';
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly walletKeyVersion: WalletKeyVersion;
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly keyCreationSignerSlot: KeyCreationSignerSlot;
  readonly registeredPublicKeyB64u: Ed25519PublicKeyB64u;
  readonly lifecycle: WalletKeyLifecycle;
  readonly evmFamilySigningKeySlotId?: never;
  readonly thresholdPublicKey33B64u?: never;
  readonly evmAddress?: never;
};

export type EvmFamilyWalletKeyRecord = {
  readonly kind: 'wallet_key_record_v1';
  readonly keyFamily: 'ecdsa_secp256k1';
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly walletKeyVersion: WalletKeyVersion;
  readonly evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  readonly thresholdPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
  readonly evmAddress: string;
  readonly lifecycle: WalletKeyLifecycle;
  readonly nearEd25519SigningKeyId?: never;
  readonly keyCreationSignerSlot?: never;
  readonly registeredPublicKeyB64u?: never;
};

export type WalletKeyRecord = Ed25519WalletKeyRecord | EvmFamilyWalletKeyRecord;

export type SigningLaneKind =
  | 'owner_passkey'
  | 'owner_email_otp'
  | 'linked_device'
  | 'delegated_execution'
  | 'recovery'
  | 'break_glass';

export type SigningLaneReference = {
  readonly kind: 'signing_lane_reference_v1';
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly laneId: SigningLaneId;
  readonly laneKind: SigningLaneKind;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly participantBindingDigestB64u: LaneParticipantBindingDigestB64u;
};

export type SigningLaneLifecycle =
  | {
      readonly state: 'provisioning';
      readonly revocationEpoch: number;
      readonly startedAtMs: number;
    }
  | {
      readonly state: 'pending_receipt';
      readonly revocationEpoch: number;
      readonly startedAtMs: number;
      readonly deliveryDigestB64u: string;
    }
  | {
      readonly state: 'active';
      readonly revocationEpoch: number;
      readonly activatedAtMs: number;
      readonly activationReceiptDigestB64u: string;
    }
  | {
      readonly state: 'revoked';
      readonly revocationEpoch: number;
      readonly revokedAtMs: number;
      readonly revokeReason: 'user_revoked' | 'device_compromise' | 'agent_compromise' | 'rotation';
    };

export type ActiveSigningLaneReference = SigningLaneReference & {
  readonly lifecycle: Extract<SigningLaneLifecycle, { readonly state: 'active' }>;
  readonly materialActivation: MpcMaterialActivationRef;
};

type SigningLaneRecordBase = SigningLaneReference & {
  readonly lifecycle: SigningLaneLifecycle;
};

type OwnerAuthSigningLaneRecordBase = SigningLaneRecordBase & {
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly ownerParticipantContinuity: OwnerLaneParticipantContinuityV1;
  readonly holderParticipant?: never;
  readonly serverParticipant?: never;
};

type PrivilegedOwnerSigningLaneRecordBase = SigningLaneRecordBase & {
  readonly ownerParticipantContinuity: OwnerLaneParticipantContinuityV1;
  readonly walletAuthMethodId?: never;
  readonly holderParticipant?: never;
  readonly serverParticipant?: never;
};

type RotatableSigningLaneRecordBase = SigningLaneRecordBase & {
  readonly holderParticipant: LaneHolderParticipantRecordV1;
  readonly serverParticipant: SigningWorkerParticipantRecordV1;
  readonly ownerParticipantContinuity?: never;
  readonly walletAuthMethodId?: never;
};

export type OwnerPasskeySigningLaneRecord = OwnerAuthSigningLaneRecordBase & {
  readonly laneKind: 'owner_passkey';
  readonly linkedDeviceId?: never;
  readonly authorizationId?: never;
  readonly agentIdentityKeyId?: never;
  readonly custodyBindingId?: never;
  readonly authorizationBindingDigestB64u?: never;
};

export type OwnerEmailOtpSigningLaneRecord = OwnerAuthSigningLaneRecordBase & {
  readonly laneKind: 'owner_email_otp';
  readonly linkedDeviceId?: never;
  readonly authorizationId?: never;
  readonly agentIdentityKeyId?: never;
  readonly custodyBindingId?: never;
  readonly authorizationBindingDigestB64u?: never;
};

export type LinkedDeviceSigningLaneRecord = RotatableSigningLaneRecordBase & {
  readonly laneKind: 'linked_device';
  readonly linkedDeviceId: LinkedDeviceId;
  readonly authorizationId?: never;
  readonly agentIdentityKeyId?: never;
  readonly custodyBindingId?: never;
  readonly authorizationBindingDigestB64u?: never;
};

export type DelegatedSpendAuthorizationId = DomainId<'DelegatedSpendAuthorizationId'>;
export type AgentIdentityKeyId = DomainId<'AgentIdentityKeyId'>;
export type AgentCustodyBindingId = DomainId<'AgentCustodyBindingId'>;

export type DelegatedExecutionSigningLaneRecord = RotatableSigningLaneRecordBase & {
  readonly laneKind: 'delegated_execution';
  readonly authorizationId: DelegatedSpendAuthorizationId;
  readonly agentIdentityKeyId: AgentIdentityKeyId;
  readonly custodyBindingId: AgentCustodyBindingId;
  readonly authorizationBindingDigestB64u: string;
  readonly linkedDeviceId?: never;
};

export type RecoverySigningLaneRecord = PrivilegedOwnerSigningLaneRecordBase & {
  readonly laneKind: 'recovery';
  readonly linkedDeviceId?: never;
  readonly authorizationId?: never;
  readonly agentIdentityKeyId?: never;
  readonly custodyBindingId?: never;
  readonly authorizationBindingDigestB64u?: never;
};

export type BreakGlassSigningLaneRecord = PrivilegedOwnerSigningLaneRecordBase & {
  readonly laneKind: 'break_glass';
  readonly linkedDeviceId?: never;
  readonly authorizationId?: never;
  readonly agentIdentityKeyId?: never;
  readonly custodyBindingId?: never;
  readonly authorizationBindingDigestB64u?: never;
};

export type SigningLaneRecord =
  | OwnerPasskeySigningLaneRecord
  | OwnerEmailOtpSigningLaneRecord
  | LinkedDeviceSigningLaneRecord
  | DelegatedExecutionSigningLaneRecord
  | RecoverySigningLaneRecord
  | BreakGlassSigningLaneRecord;

export function assertNeverSigningLane(value: never): never {
  throw new Error(`[SigningLaneRecord] unsupported lane: ${String(value)}`);
}
