import type {
  ActiveSigningLaneReference,
  AgentCustodyBindingId,
  AgentIdentityKeyId,
  DelegatedExecutionSigningLaneRecord,
  DelegatedSpendAuthorizationId,
  Ed25519WalletKeyRecord,
  EvmFamilyWalletKeyRecord,
  LinkedDeviceSigningLaneRecord,
  OwnerPasskeySigningLaneRecord,
  SigningLaneRecord,
  WalletKeyRecord,
} from './records';
import type {
  LaneHolderParticipantRecordV1,
  LaneParticipantBindingDigestB64u,
  SigningWorkerParticipantRecordV1,
} from './participants';
import type { LaneShareEpoch, LinkedDeviceId, SigningLaneId, WalletKeyId } from './ids';
import type { DomainId, MpcMaterialActivationRef, WalletId } from '../utils/domainIds';
import type {
  Ed25519PublicKeyB64u,
  KeyCreationSignerSlot,
  Secp256k1CompressedPublicKeyB64u,
} from '../passkey-custody/primitives';
import type { NearEd25519SigningKeyId } from '../utils/registrationIntent';
import type { EvmFamilySigningKeySlotId } from './evmFamilySigningKeySlotId';
import {
  buildActiveWalletKeyLifecycle,
  buildActiveSigningLaneLifecycle,
  buildActiveSigningLaneReference,
  buildBreakGlassSigningLaneRecord,
  buildDelegatedExecutionSigningLaneRecord,
  buildEd25519WalletKeyRecord,
  buildEvmFamilyWalletKeyRecord,
  buildLinkedDeviceSigningLaneRecord,
  buildOwnerEmailOtpSigningLaneRecord,
  buildOwnerPasskeySigningLaneRecord,
  buildProvisioningSigningLaneLifecycle,
  buildRecoverySigningLaneRecord,
  buildRetiredWalletKeyLifecycle,
} from './recordParsers';

declare const walletId: WalletId;
declare const walletKeyId: WalletKeyId;
declare const laneId: SigningLaneId;
declare const linkedDeviceId: LinkedDeviceId;
declare const laneShareEpoch: LaneShareEpoch;
declare const participantBindingDigestB64u: LaneParticipantBindingDigestB64u;
declare const holderParticipant: LaneHolderParticipantRecordV1;
declare const serverParticipant: SigningWorkerParticipantRecordV1;
declare const materialActivation: MpcMaterialActivationRef;
declare const nearEd25519SigningKeyId: NearEd25519SigningKeyId;
declare const keyCreationSignerSlot: KeyCreationSignerSlot;
declare const registeredPublicKeyB64u: Ed25519PublicKeyB64u;
declare const evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
declare const thresholdPublicKey33B64u: Secp256k1CompressedPublicKeyB64u;
declare const walletKeyVersion: DomainId<'WalletKeyVersion'>;
declare const authorizationId: DelegatedSpendAuthorizationId;
declare const agentIdentityKeyId: AgentIdentityKeyId;
declare const custodyBindingId: AgentCustodyBindingId;
declare const linkedDeviceEnrollmentId: DomainId<'LinkedDeviceEnrollmentId'>;

const activeWalletKeyLifecycle = buildActiveWalletKeyLifecycle({ activatedAtMs: 1 });
const retiredWalletKeyLifecycle = buildRetiredWalletKeyLifecycle({ retiredAtMs: 2 });
const activeLaneLifecycle = buildActiveSigningLaneLifecycle({
  revocationEpoch: 1,
  activatedAtMs: 3,
  activationReceiptDigestB64u: 'digest',
});
const provisioningLaneLifecycle = buildProvisioningSigningLaneLifecycle({
  revocationEpoch: 1,
  startedAtMs: 4,
});

const ed25519WalletKey: Ed25519WalletKeyRecord = buildEd25519WalletKeyRecord({
  walletId,
  walletKeyId,
  walletKeyVersion,
  nearEd25519SigningKeyId,
  keyCreationSignerSlot,
  registeredPublicKeyB64u,
  lifecycle: activeWalletKeyLifecycle,
});

const evmWalletKey: EvmFamilyWalletKeyRecord = buildEvmFamilyWalletKeyRecord({
  walletId,
  walletKeyId,
  walletKeyVersion,
  evmFamilySigningKeySlotId,
  thresholdPublicKey33B64u,
  evmAddress: '0x1111111111111111111111111111111111111111',
  lifecycle: retiredWalletKeyLifecycle,
});

const ownerBase = {
  walletId,
  walletKeyId,
  laneId,
  laneShareEpoch,
  participantBindingDigestB64u,
  holderParticipant,
  serverParticipant,
  lifecycle: activeLaneLifecycle,
} as const;

const ownerPasskeyLane: OwnerPasskeySigningLaneRecord =
  buildOwnerPasskeySigningLaneRecord(ownerBase);
const ownerEmailOtpLane = buildOwnerEmailOtpSigningLaneRecord(ownerBase);
const linkedDeviceLane: LinkedDeviceSigningLaneRecord = buildLinkedDeviceSigningLaneRecord({
  ...ownerBase,
  linkedDeviceId,
});
const delegatedLane: DelegatedExecutionSigningLaneRecord = buildDelegatedExecutionSigningLaneRecord(
  {
    ...ownerBase,
    authorizationId,
    agentIdentityKeyId,
    custodyBindingId,
    authorizationBindingDigestB64u: 'digest',
  },
);
const recoveryLane = buildRecoverySigningLaneRecord(ownerBase);
const breakGlassLane = buildBreakGlassSigningLaneRecord(ownerBase);

const allLaneRecords: SigningLaneRecord[] = [
  ownerPasskeyLane,
  ownerEmailOtpLane,
  linkedDeviceLane,
  delegatedLane,
  recoveryLane,
  breakGlassLane,
];
void allLaneRecords;
void ed25519WalletKey;
void evmWalletKey;

const activeReference: ActiveSigningLaneReference = buildActiveSigningLaneReference({
  walletId,
  walletKeyId,
  laneId,
  laneShareEpoch,
  laneKind: 'owner_passkey',
  participantBindingDigestB64u,
  lifecycle: activeLaneLifecycle,
  materialActivation,
});
void activeReference;
void linkedDeviceEnrollmentId;

const invalidEd25519WalletKey: Ed25519WalletKeyRecord = {
  ...ed25519WalletKey,
  // @ts-expect-error EVM-family identity cannot be attached to an Ed25519 key.
  evmAddress: '0x1111111111111111111111111111111111111111',
};
void invalidEd25519WalletKey;

const invalidAgentWalletKey: WalletKeyRecord = {
  ...ed25519WalletKey,
  // @ts-expect-error Agent identity keys are not wallet-key identities.
  agentIdentityKeyId,
};
void invalidAgentWalletKey;

const invalidOwnerPasskeyLane: OwnerPasskeySigningLaneRecord = {
  ...ownerPasskeyLane,
  // @ts-expect-error Owner lanes cannot carry delegated authorization fields.
  authorizationId,
};
void invalidOwnerPasskeyLane;

const invalidLinkedDeviceLane: LinkedDeviceSigningLaneRecord = {
  ...linkedDeviceLane,
  // @ts-expect-error Linked-device lanes cannot carry delegated authorization fields.
  custodyBindingId,
};
void invalidLinkedDeviceLane;

const invalidDelegatedLane: DelegatedExecutionSigningLaneRecord = {
  ...delegatedLane,
  // @ts-expect-error Delegated lanes require an authorization identity.
  authorizationId: undefined,
};
void invalidDelegatedLane;

const invalidInactiveReference: ActiveSigningLaneReference = buildActiveSigningLaneReference({
  walletId,
  walletKeyId,
  laneId,
  laneShareEpoch,
  laneKind: 'owner_passkey',
  participantBindingDigestB64u,
  // @ts-expect-error Provisioning lanes cannot satisfy an active execution reference.
  lifecycle: provisioningLaneLifecycle,
  materialActivation,
});
void invalidInactiveReference;

export {};
