import type { WalletId } from '../utils/domainIds';
import type {
  AgentPrincipalId,
  LaneShareEpoch,
  LinkedDeviceId,
  SigningLaneId,
  WalletKeyId,
} from './ids';
import type {
  AgentCustodyRuntime,
  DelegatedMandatePolicy,
  LinkedDevicePermissionPolicy,
} from './policies';

export type WalletPublicIdentity = {
  kind: 'wallet_public_identity_v1';
  address: string;
};

export type WalletKeyRecord = {
  kind: 'wallet_key_record_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  walletKeyVersion: string;
  keyFamily: 'ecdsa_secp256k1' | 'ed25519';
  publicIdentity: WalletPublicIdentity;
  status: 'active' | 'retired';
};

export type SigningLaneKind =
  | 'owner_passkey'
  | 'owner_email_otp'
  | 'linked_device'
  | 'delegated_agent'
  | 'recovery'
  | 'break_glass';

export type SigningLaneReference = {
  kind: 'signing_lane_reference_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneKind: SigningLaneKind;
  laneShareEpoch: LaneShareEpoch;
};

export type ActiveLaneRevocationState = {
  status: 'active';
  revocationEpoch: number;
  revokedAtMs?: never;
  revokedReason?: never;
};

export type RevokedLaneRevocationState = {
  status: 'revoked';
  revocationEpoch: number;
  revokedAtMs: number;
  revokedReason: 'user_revoked' | 'policy_revoked' | 'agent_compromise' | 'rotation';
};

export type OwnerPasskeySigningLaneRecord = SigningLaneReference & {
  laneKind: 'owner_passkey';
  holderPrincipal: {
    kind: 'passkey_credential';
    rpId: string;
    credentialIdB64u: string;
  };
  devicePrincipal?: never;
  delegatePrincipal?: never;
  permissionPolicy?: never;
  mandatePolicy?: never;
  revocation: ActiveLaneRevocationState;
};

export type OwnerEmailOtpSigningLaneRecord = SigningLaneReference & {
  laneKind: 'owner_email_otp';
  holderPrincipal: {
    kind: 'email_otp_holder';
    providerSubjectId: string;
  };
  devicePrincipal?: never;
  delegatePrincipal?: never;
  permissionPolicy?: never;
  mandatePolicy?: never;
  revocation: ActiveLaneRevocationState;
};

export type LinkedDeviceSigningLaneRecord = SigningLaneReference & {
  laneKind: 'linked_device';
  holderPrincipal: {
    kind: 'linked_device_passkey';
    deviceId: LinkedDeviceId;
    rpId: string;
    credentialIdB64u: string;
    devicePublicKeyB64u: string;
  };
  devicePrincipal: {
    deviceId: LinkedDeviceId;
    displayName: string;
    platform: 'ios' | 'android' | 'macos' | 'windows' | 'linux' | 'web' | 'unknown';
  };
  permissionPolicy: LinkedDevicePermissionPolicy;
  delegatePrincipal?: never;
  mandatePolicy?: never;
  revocation: ActiveLaneRevocationState | RevokedLaneRevocationState;
};

export type DelegatedAgentSigningLaneRecord = SigningLaneReference & {
  laneKind: 'delegated_agent';
  holderPrincipal: {
    kind: 'agent_custody_boundary';
    agentId: AgentPrincipalId;
    custodyKeyId: string;
    custodyRuntime: AgentCustodyRuntime;
  };
  delegatePrincipal: {
    agentId: AgentPrincipalId;
    displayName: string;
    operatorId: string | null;
  };
  mandatePolicy: DelegatedMandatePolicy;
  devicePrincipal?: never;
  permissionPolicy?: never;
  revocation: ActiveLaneRevocationState | RevokedLaneRevocationState;
};

export type RecoverySigningLaneRecord = SigningLaneReference & {
  laneKind: 'recovery';
  holderPrincipal: {
    kind: 'recovery_authority';
    recoveryAuthorityId: string;
  };
  devicePrincipal?: never;
  delegatePrincipal?: never;
  permissionPolicy?: never;
  mandatePolicy?: never;
  revocation: ActiveLaneRevocationState;
};

export type BreakGlassSigningLaneRecord = SigningLaneReference & {
  laneKind: 'break_glass';
  holderPrincipal: {
    kind: 'break_glass_authority';
    authorityId: string;
  };
  devicePrincipal?: never;
  delegatePrincipal?: never;
  permissionPolicy?: never;
  mandatePolicy?: never;
  revocation: ActiveLaneRevocationState;
};

export type SigningLaneRecord =
  | OwnerPasskeySigningLaneRecord
  | OwnerEmailOtpSigningLaneRecord
  | LinkedDeviceSigningLaneRecord
  | DelegatedAgentSigningLaneRecord
  | RecoverySigningLaneRecord
  | BreakGlassSigningLaneRecord;

export function assertNeverSigningLane(value: never): never {
  throw new Error(`[SigningLaneRecord] unsupported lane: ${String(value)}`);
}
