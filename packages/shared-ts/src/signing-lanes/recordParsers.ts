import type {
  DomainId,
  DomainIdParseResult,
  MpcMaterialActivationRef,
  WalletId,
} from '../utils/domainIds';
import {
  hasWhitespaceOrControlCharacters,
  parseMpcMaterialActivationRef,
  parseWalletAuthMethodId,
  parseWalletId,
} from '../utils/domainIds';
import {
  parseDigestField,
  parseEd25519PublicKeyB64u,
  parseKeyCreationSignerSlot,
  parseSecp256k1CompressedPublicKeyB64u,
  parseUnixMs,
  rejectUnknownFields,
  requireRecord,
} from '../passkey-custody/primitives';
import { parseNearEd25519SigningKeyId } from '../utils/registrationIntent';
import {
  requireEvmFamilySigningKeySlotId,
  type EvmFamilySigningKeySlotId,
} from './evmFamilySigningKeySlotId';
import {
  parseLaneHolderParticipantRecordV1,
  parseLaneParticipantBindingDigestB64u,
  parseSigningWorkerParticipantRecordV1,
  type LaneHolderParticipantRecordV1,
  type LaneParticipantBindingDigestB64u,
  type SigningWorkerParticipantRecordV1,
} from './participants';
import {
  parseLaneShareEpoch,
  parseLinkedDeviceId,
  parseSigningLaneId,
  parseWalletKeyId,
  type LaneShareEpoch,
  type LinkedDeviceId,
  type SigningLaneId,
  type WalletKeyId,
} from './ids';
import type {
  ActiveSigningLaneReference,
  AgentCustodyBindingId,
  AgentIdentityKeyId,
  BreakGlassSigningLaneRecord,
  DelegatedExecutionSigningLaneRecord,
  DelegatedSpendAuthorizationId,
  Ed25519WalletKeyRecord,
  EvmFamilyWalletKeyRecord,
  LinkedDeviceSigningLaneRecord,
  OwnerEmailOtpSigningLaneRecord,
  OwnerPasskeySigningLaneRecord,
  RecoverySigningLaneRecord,
  SigningLaneKind,
  SigningLaneLifecycle,
  SigningLaneRecord,
  SigningLaneReference,
  WalletKeyLifecycle,
  WalletKeyRecord,
  WalletKeyVersion,
} from './records';
import {
  parseOwnerLaneParticipantContinuityV1,
  type OwnerLaneParticipantContinuityV1,
} from './ownerContinuity';

type ActiveSigningLaneLifecycle = Extract<SigningLaneLifecycle, { readonly state: 'active' }>;

export type WalletKeyReferenceBuilderArgs = {
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly walletKeyVersion: WalletKeyVersion;
  readonly lifecycle: WalletKeyLifecycle;
};

export type SigningLaneReferenceBuilderArgs = {
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly participantBindingDigestB64u: LaneParticipantBindingDigestB64u;
};

type SigningLaneRecordBuilderCommonArgs = SigningLaneReferenceBuilderArgs & {
  readonly lifecycle: SigningLaneLifecycle;
};

export type RotatableSigningLaneRecordBuilderArgs = SigningLaneRecordBuilderCommonArgs & {
  readonly holderParticipant: LaneHolderParticipantRecordV1;
  readonly serverParticipant: SigningWorkerParticipantRecordV1;
};

export type OwnerAuthSigningLaneRecordBuilderArgs = SigningLaneRecordBuilderCommonArgs & {
  readonly walletAuthMethodId: NonNullable<OwnerPasskeySigningLaneRecord['walletAuthMethodId']>;
  readonly ownerParticipantContinuity: OwnerLaneParticipantContinuityV1;
};

export type PrivilegedOwnerSigningLaneRecordBuilderArgs = SigningLaneRecordBuilderCommonArgs & {
  readonly ownerParticipantContinuity: OwnerLaneParticipantContinuityV1;
};

export type ActiveSigningLaneReferenceBuilderArgs = SigningLaneReferenceBuilderArgs & {
  readonly lifecycle: ActiveSigningLaneLifecycle;
  readonly materialActivation: MpcMaterialActivationRef;
};

const WALLET_KEY_COMMON_FIELDS = [
  'kind',
  'keyFamily',
  'walletId',
  'walletKeyId',
  'walletKeyVersion',
  'lifecycle',
] as const;
const ED25519_WALLET_KEY_FIELDS = [
  ...WALLET_KEY_COMMON_FIELDS,
  'nearEd25519SigningKeyId',
  'keyCreationSignerSlot',
  'registeredPublicKeyB64u',
] as const;
const EVM_WALLET_KEY_FIELDS = [
  ...WALLET_KEY_COMMON_FIELDS,
  'evmFamilySigningKeySlotId',
  'thresholdPublicKey33B64u',
  'evmAddress',
] as const;
const ALL_WALLET_KEY_FIELDS: readonly string[] = Array.from(
  new Set([...ED25519_WALLET_KEY_FIELDS, ...EVM_WALLET_KEY_FIELDS]),
);

const WALLET_KEY_LIFECYCLE_FIELDS = [
  'state',
  'activatedAtMs',
  'retiredAtMs',
  'compromisedAtMs',
] as const;

const SIGNING_LANE_REFERENCE_FIELDS = [
  'kind',
  'walletId',
  'walletKeyId',
  'laneId',
  'laneKind',
  'laneShareEpoch',
  'participantBindingDigestB64u',
] as const;
const ACTIVE_SIGNING_LANE_REFERENCE_FIELDS = [
  ...SIGNING_LANE_REFERENCE_FIELDS,
  'lifecycle',
  'materialActivation',
] as const;
const SIGNING_LANE_RECORD_BASE_FIELDS = [...SIGNING_LANE_REFERENCE_FIELDS, 'lifecycle'] as const;
const OWNER_AUTH_SIGNING_LANE_FIELDS = [
  ...SIGNING_LANE_RECORD_BASE_FIELDS,
  'walletAuthMethodId',
  'ownerParticipantContinuity',
] as const;
const PRIVILEGED_OWNER_SIGNING_LANE_FIELDS = [
  ...SIGNING_LANE_RECORD_BASE_FIELDS,
  'ownerParticipantContinuity',
] as const;
const ROTATABLE_SIGNING_LANE_FIELDS = [
  ...SIGNING_LANE_RECORD_BASE_FIELDS,
  'holderParticipant',
  'serverParticipant',
] as const;
const DELEGATED_SIGNING_LANE_FIELDS = [
  ...ROTATABLE_SIGNING_LANE_FIELDS,
  'authorizationId',
  'agentIdentityKeyId',
  'custodyBindingId',
  'authorizationBindingDigestB64u',
] as const;
const LINKED_DEVICE_SIGNING_LANE_FIELDS = [
  ...ROTATABLE_SIGNING_LANE_FIELDS,
  'linkedDeviceId',
] as const;
const ALL_SIGNING_LANE_RECORD_FIELDS: readonly string[] = Array.from(
  new Set([
    ...OWNER_AUTH_SIGNING_LANE_FIELDS,
    ...PRIVILEGED_OWNER_SIGNING_LANE_FIELDS,
    ...DELEGATED_SIGNING_LANE_FIELDS,
    ...LINKED_DEVICE_SIGNING_LANE_FIELDS,
  ]),
);

const ALL_SIGNING_LANE_LIFECYCLE_FIELDS = [
  'state',
  'revocationEpoch',
  'startedAtMs',
  'deliveryDigestB64u',
  'activatedAtMs',
  'activationReceiptDigestB64u',
  'revokedAtMs',
  'revokeReason',
] as const;

function signingLaneRecordFields(laneKind: SigningLaneKind): readonly string[] {
  switch (laneKind) {
    case 'owner_passkey':
    case 'owner_email_otp':
      return OWNER_AUTH_SIGNING_LANE_FIELDS;
    case 'recovery':
    case 'break_glass':
      return PRIVILEGED_OWNER_SIGNING_LANE_FIELDS;
    case 'linked_device':
      return LINKED_DEVICE_SIGNING_LANE_FIELDS;
    case 'delegated_execution':
      return DELEGATED_SIGNING_LANE_FIELDS;
  }
}

function requireResult<T>(result: DomainIdParseResult<T>, label: string): T {
  if (result.ok) return result.value;
  throw new Error(`${label} ${result.error.message}`);
}

function parseRequiredDomainId<TName extends string>(raw: unknown, label: string): DomainId<TName> {
  if (raw === undefined || raw === null) throw new Error(`${label} is required`);
  if (typeof raw !== 'string') throw new Error(`${label} must be a string`);
  const value = raw.trim();
  if (!value) throw new Error(`${label} is required`);
  if (hasWhitespaceOrControlCharacters(value)) {
    throw new Error(`${label} must not contain whitespace or control characters`);
  }
  return value as DomainId<TName>;
}

function parseNonEmptyString(raw: unknown, label: string): string {
  if (typeof raw !== 'string') throw new Error(`${label} must be a string`);
  const value = raw.trim();
  if (!value) throw new Error(`${label} is required`);
  if (hasWhitespaceOrControlCharacters(value)) {
    throw new Error(`${label} must not contain whitespace or control characters`);
  }
  return value;
}

function parseNonNegativeSafeInteger(raw: unknown, label: string): number {
  if (typeof raw !== 'number' || !Number.isSafeInteger(raw) || raw < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return raw;
}

export function parseWalletKeyVersion(raw: unknown, label = 'walletKeyVersion'): WalletKeyVersion {
  return parseRequiredDomainId<'WalletKeyVersion'>(raw, label);
}

function parseAgentIdentityKeyId(raw: unknown, label: string): AgentIdentityKeyId {
  return parseRequiredDomainId<'AgentIdentityKeyId'>(raw, label);
}

function parseAgentCustodyBindingId(raw: unknown, label: string): AgentCustodyBindingId {
  return parseRequiredDomainId<'AgentCustodyBindingId'>(raw, label);
}

function parseDelegatedSpendAuthorizationId(
  raw: unknown,
  label: string,
): DelegatedSpendAuthorizationId {
  return parseRequiredDomainId<'DelegatedSpendAuthorizationId'>(raw, label);
}

function parseSigningLaneKind(raw: unknown, label: string): SigningLaneKind {
  switch (raw) {
    case 'owner_passkey':
    case 'owner_email_otp':
    case 'linked_device':
    case 'delegated_execution':
    case 'recovery':
    case 'break_glass':
      return raw;
    default:
      throw new Error(`${label} must be a known signing lane kind`);
  }
}

function parseWalletKeyLifecycleState(raw: unknown, label: string): WalletKeyLifecycle {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, WALLET_KEY_LIFECYCLE_FIELDS, label, WALLET_KEY_LIFECYCLE_FIELDS);
  switch (record.state) {
    case 'active': {
      if (record.retiredAtMs !== undefined || record.compromisedAtMs !== undefined) {
        throw new Error(`${label} cannot be active and carry a retired or compromised timestamp`);
      }
      return buildActiveWalletKeyLifecycle({
        activatedAtMs: parseUnixMs(record.activatedAtMs, `${label}.activatedAtMs`),
      });
    }
    case 'retired': {
      if (record.activatedAtMs !== undefined || record.compromisedAtMs !== undefined) {
        throw new Error(`${label} cannot be retired and carry an active or compromised timestamp`);
      }
      return buildRetiredWalletKeyLifecycle({
        retiredAtMs: parseUnixMs(record.retiredAtMs, `${label}.retiredAtMs`),
      });
    }
    case 'compromised': {
      if (record.activatedAtMs !== undefined || record.retiredAtMs !== undefined) {
        throw new Error(`${label} cannot be compromised and carry an active or retired timestamp`);
      }
      return buildCompromisedWalletKeyLifecycle({
        compromisedAtMs: parseUnixMs(record.compromisedAtMs, `${label}.compromisedAtMs`),
      });
    }
    default:
      throw new Error(`${label}.state must be active, retired, or compromised`);
  }
}

function parseSigningLaneLifecycleState(raw: unknown, label: string): SigningLaneLifecycle {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, ALL_SIGNING_LANE_LIFECYCLE_FIELDS, label);
  const revocationEpoch = parseNonNegativeSafeInteger(
    record.revocationEpoch,
    `${label}.revocationEpoch`,
  );
  switch (record.state) {
    case 'provisioning':
      if (
        record.deliveryDigestB64u !== undefined ||
        record.activatedAtMs !== undefined ||
        record.activationReceiptDigestB64u !== undefined ||
        record.revokedAtMs !== undefined ||
        record.revokeReason !== undefined
      ) {
        throw new Error(`${label} provisioning state carries fields from another lifecycle state`);
      }
      return buildProvisioningSigningLaneLifecycle({
        revocationEpoch,
        startedAtMs: parseUnixMs(record.startedAtMs, `${label}.startedAtMs`),
      });
    case 'pending_receipt':
      if (
        record.activatedAtMs !== undefined ||
        record.activationReceiptDigestB64u !== undefined ||
        record.revokedAtMs !== undefined ||
        record.revokeReason !== undefined
      ) {
        throw new Error(
          `${label} pending_receipt state carries fields from another lifecycle state`,
        );
      }
      return buildPendingReceiptSigningLaneLifecycle({
        revocationEpoch,
        startedAtMs: parseUnixMs(record.startedAtMs, `${label}.startedAtMs`),
        deliveryDigestB64u: parseDigestField(
          record.deliveryDigestB64u,
          `${label}.deliveryDigestB64u`,
        ),
      });
    case 'active':
      if (
        record.startedAtMs !== undefined ||
        record.deliveryDigestB64u !== undefined ||
        record.revokedAtMs !== undefined ||
        record.revokeReason !== undefined
      ) {
        throw new Error(`${label} active state carries fields from another lifecycle state`);
      }
      return buildActiveSigningLaneLifecycle({
        revocationEpoch,
        activatedAtMs: parseUnixMs(record.activatedAtMs, `${label}.activatedAtMs`),
        activationReceiptDigestB64u: parseDigestField(
          record.activationReceiptDigestB64u,
          `${label}.activationReceiptDigestB64u`,
        ),
      });
    case 'revoked': {
      if (
        record.startedAtMs !== undefined ||
        record.deliveryDigestB64u !== undefined ||
        record.activatedAtMs !== undefined ||
        record.activationReceiptDigestB64u !== undefined
      ) {
        throw new Error(`${label} revoked state carries fields from another lifecycle state`);
      }
      const revokeReason = record.revokeReason;
      if (
        revokeReason !== 'user_revoked' &&
        revokeReason !== 'device_compromise' &&
        revokeReason !== 'agent_compromise' &&
        revokeReason !== 'rotation'
      ) {
        throw new Error(`${label}.revokeReason is invalid`);
      }
      return buildRevokedSigningLaneLifecycle({
        revocationEpoch,
        revokedAtMs: parseUnixMs(record.revokedAtMs, `${label}.revokedAtMs`),
        revokeReason,
      });
    }
    default:
      throw new Error(`${label}.state must be provisioning, pending_receipt, active, or revoked`);
  }
}

function parseSigningLaneReferenceFields(
  record: Record<string, unknown>,
  label: string,
): SigningLaneReference {
  if (record.kind !== 'signing_lane_reference_v1') {
    throw new Error(`${label}.kind must be signing_lane_reference_v1`);
  }
  const walletId = requireResult(parseWalletId(record.walletId), `${label}.walletId`);
  const walletKeyId = requireResult(parseWalletKeyId(record.walletKeyId), `${label}.walletKeyId`);
  const laneId = requireResult(parseSigningLaneId(record.laneId), `${label}.laneId`);
  const laneShareEpoch = requireResult(
    parseLaneShareEpoch(record.laneShareEpoch),
    `${label}.laneShareEpoch`,
  );
  return buildSigningLaneReference({
    walletId,
    walletKeyId,
    laneId,
    laneShareEpoch,
    laneKind: parseSigningLaneKind(record.laneKind, `${label}.laneKind`),
    participantBindingDigestB64u: requireResult(
      parseLaneParticipantBindingDigestB64u(record.participantBindingDigestB64u),
      `${label}.participantBindingDigestB64u`,
    ),
  });
}

function parseSigningLaneRecordCommon(
  record: Record<string, unknown>,
  label: string,
): SigningLaneRecordBuilderCommonArgs {
  const reference = parseSigningLaneReferenceFields(record, label);
  return {
    walletId: reference.walletId,
    walletKeyId: reference.walletKeyId,
    laneId: reference.laneId,
    laneShareEpoch: reference.laneShareEpoch,
    participantBindingDigestB64u: reference.participantBindingDigestB64u,
    lifecycle: parseSigningLaneLifecycleState(record.lifecycle, `${label}.lifecycle`),
  };
}

function parseOwnerAuthSigningLaneRecordBase(
  record: Record<string, unknown>,
  label: string,
): OwnerAuthSigningLaneRecordBuilderArgs {
  const common = parseSigningLaneRecordCommon(record, label);
  const walletAuthMethodId = parseWalletAuthMethodId(record.walletAuthMethodId);
  return {
    ...common,
    walletAuthMethodId: requireResult(walletAuthMethodId, `${label}.walletAuthMethodId`),
    ownerParticipantContinuity: parseOwnerLaneParticipantContinuityV1(
      record.ownerParticipantContinuity,
      `${label}.ownerParticipantContinuity`,
    ),
  };
}

function parsePrivilegedOwnerSigningLaneRecordBase(
  record: Record<string, unknown>,
  label: string,
): PrivilegedOwnerSigningLaneRecordBuilderArgs {
  return {
    ...parseSigningLaneRecordCommon(record, label),
    ownerParticipantContinuity: parseOwnerLaneParticipantContinuityV1(
      record.ownerParticipantContinuity,
      `${label}.ownerParticipantContinuity`,
    ),
  };
}

function parseRotatableSigningLaneRecordBase(
  record: Record<string, unknown>,
  label: string,
): RotatableSigningLaneRecordBuilderArgs {
  return {
    ...parseSigningLaneRecordCommon(record, label),
    holderParticipant: parseLaneHolderParticipantRecordV1(
      record.holderParticipant,
      `${label}.holderParticipant`,
    ),
    serverParticipant: parseSigningWorkerParticipantRecordV1(
      record.serverParticipant,
      `${label}.serverParticipant`,
    ),
  };
}

export function buildActiveWalletKeyLifecycle(args: {
  readonly activatedAtMs: number;
}): Extract<WalletKeyLifecycle, { readonly state: 'active' }> {
  return { state: 'active', activatedAtMs: args.activatedAtMs };
}

export function buildRetiredWalletKeyLifecycle(args: {
  readonly retiredAtMs: number;
}): Extract<WalletKeyLifecycle, { readonly state: 'retired' }> {
  return { state: 'retired', retiredAtMs: args.retiredAtMs };
}

export function buildCompromisedWalletKeyLifecycle(args: {
  readonly compromisedAtMs: number;
}): Extract<WalletKeyLifecycle, { readonly state: 'compromised' }> {
  return { state: 'compromised', compromisedAtMs: args.compromisedAtMs };
}

export function buildEd25519WalletKeyRecord(args: {
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly walletKeyVersion: WalletKeyVersion;
  readonly nearEd25519SigningKeyId: Ed25519WalletKeyRecord['nearEd25519SigningKeyId'];
  readonly keyCreationSignerSlot: Ed25519WalletKeyRecord['keyCreationSignerSlot'];
  readonly registeredPublicKeyB64u: Ed25519WalletKeyRecord['registeredPublicKeyB64u'];
  readonly lifecycle: WalletKeyLifecycle;
}): Ed25519WalletKeyRecord {
  return {
    kind: 'wallet_key_record_v1',
    keyFamily: 'ed25519',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    walletKeyVersion: args.walletKeyVersion,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    keyCreationSignerSlot: args.keyCreationSignerSlot,
    registeredPublicKeyB64u: args.registeredPublicKeyB64u,
    lifecycle: args.lifecycle,
  };
}

export function buildEvmFamilyWalletKeyRecord(args: {
  readonly walletId: WalletId;
  readonly walletKeyId: WalletKeyId;
  readonly walletKeyVersion: WalletKeyVersion;
  readonly evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  readonly thresholdPublicKey33B64u: EvmFamilyWalletKeyRecord['thresholdPublicKey33B64u'];
  readonly evmAddress: string;
  readonly lifecycle: WalletKeyLifecycle;
}): EvmFamilyWalletKeyRecord {
  return {
    kind: 'wallet_key_record_v1',
    keyFamily: 'ecdsa_secp256k1',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    walletKeyVersion: args.walletKeyVersion,
    evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId,
    thresholdPublicKey33B64u: args.thresholdPublicKey33B64u,
    evmAddress: args.evmAddress,
    lifecycle: args.lifecycle,
  };
}

export function buildSigningLaneReference(
  args: SigningLaneReferenceBuilderArgs & {
    readonly laneKind: SigningLaneKind;
  },
): SigningLaneReference {
  return {
    kind: 'signing_lane_reference_v1',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneKind: args.laneKind,
    laneShareEpoch: args.laneShareEpoch,
    participantBindingDigestB64u: args.participantBindingDigestB64u,
  };
}

export function buildProvisioningSigningLaneLifecycle(args: {
  readonly revocationEpoch: number;
  readonly startedAtMs: number;
}): Extract<SigningLaneLifecycle, { readonly state: 'provisioning' }> {
  return {
    state: 'provisioning',
    revocationEpoch: args.revocationEpoch,
    startedAtMs: args.startedAtMs,
  };
}

export function buildPendingReceiptSigningLaneLifecycle(args: {
  readonly revocationEpoch: number;
  readonly startedAtMs: number;
  readonly deliveryDigestB64u: string;
}): Extract<SigningLaneLifecycle, { readonly state: 'pending_receipt' }> {
  return {
    state: 'pending_receipt',
    revocationEpoch: args.revocationEpoch,
    startedAtMs: args.startedAtMs,
    deliveryDigestB64u: args.deliveryDigestB64u,
  };
}

export function buildActiveSigningLaneLifecycle(args: {
  readonly revocationEpoch: number;
  readonly activatedAtMs: number;
  readonly activationReceiptDigestB64u: string;
}): ActiveSigningLaneLifecycle {
  return {
    state: 'active',
    revocationEpoch: args.revocationEpoch,
    activatedAtMs: args.activatedAtMs,
    activationReceiptDigestB64u: args.activationReceiptDigestB64u,
  };
}

export function buildRevokedSigningLaneLifecycle(args: {
  readonly revocationEpoch: number;
  readonly revokedAtMs: number;
  readonly revokeReason: Extract<
    SigningLaneLifecycle,
    { readonly state: 'revoked' }
  >['revokeReason'];
}): Extract<SigningLaneLifecycle, { readonly state: 'revoked' }> {
  return {
    state: 'revoked',
    revocationEpoch: args.revocationEpoch,
    revokedAtMs: args.revokedAtMs,
    revokeReason: args.revokeReason,
  };
}

export function buildOwnerPasskeySigningLaneRecord(
  args: OwnerAuthSigningLaneRecordBuilderArgs,
): OwnerPasskeySigningLaneRecord {
  return {
    kind: 'signing_lane_reference_v1',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneKind: 'owner_passkey',
    laneShareEpoch: args.laneShareEpoch,
    participantBindingDigestB64u: args.participantBindingDigestB64u,
    walletAuthMethodId: args.walletAuthMethodId,
    ownerParticipantContinuity: args.ownerParticipantContinuity,
    lifecycle: args.lifecycle,
  };
}

export function buildOwnerEmailOtpSigningLaneRecord(
  args: OwnerAuthSigningLaneRecordBuilderArgs,
): OwnerEmailOtpSigningLaneRecord {
  return {
    kind: 'signing_lane_reference_v1',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneKind: 'owner_email_otp',
    laneShareEpoch: args.laneShareEpoch,
    participantBindingDigestB64u: args.participantBindingDigestB64u,
    walletAuthMethodId: args.walletAuthMethodId,
    ownerParticipantContinuity: args.ownerParticipantContinuity,
    lifecycle: args.lifecycle,
  };
}

export function buildLinkedDeviceSigningLaneRecord(
  args: RotatableSigningLaneRecordBuilderArgs & { readonly linkedDeviceId: LinkedDeviceId },
): LinkedDeviceSigningLaneRecord {
  return {
    kind: 'signing_lane_reference_v1',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneKind: 'linked_device',
    laneShareEpoch: args.laneShareEpoch,
    participantBindingDigestB64u: args.participantBindingDigestB64u,
    holderParticipant: args.holderParticipant,
    serverParticipant: args.serverParticipant,
    lifecycle: args.lifecycle,
    linkedDeviceId: args.linkedDeviceId,
  };
}

export function buildDelegatedExecutionSigningLaneRecord(
  args: RotatableSigningLaneRecordBuilderArgs & {
    readonly authorizationId: DelegatedSpendAuthorizationId;
    readonly agentIdentityKeyId: AgentIdentityKeyId;
    readonly custodyBindingId: AgentCustodyBindingId;
    readonly authorizationBindingDigestB64u: string;
  },
): DelegatedExecutionSigningLaneRecord {
  return {
    kind: 'signing_lane_reference_v1',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneKind: 'delegated_execution',
    laneShareEpoch: args.laneShareEpoch,
    participantBindingDigestB64u: args.participantBindingDigestB64u,
    holderParticipant: args.holderParticipant,
    serverParticipant: args.serverParticipant,
    lifecycle: args.lifecycle,
    authorizationId: args.authorizationId,
    agentIdentityKeyId: args.agentIdentityKeyId,
    custodyBindingId: args.custodyBindingId,
    authorizationBindingDigestB64u: args.authorizationBindingDigestB64u,
  };
}

export function buildRecoverySigningLaneRecord(
  args: PrivilegedOwnerSigningLaneRecordBuilderArgs,
): RecoverySigningLaneRecord {
  return {
    kind: 'signing_lane_reference_v1',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneKind: 'recovery',
    laneShareEpoch: args.laneShareEpoch,
    participantBindingDigestB64u: args.participantBindingDigestB64u,
    ownerParticipantContinuity: args.ownerParticipantContinuity,
    lifecycle: args.lifecycle,
  };
}

export function buildBreakGlassSigningLaneRecord(
  args: PrivilegedOwnerSigningLaneRecordBuilderArgs,
): BreakGlassSigningLaneRecord {
  return {
    kind: 'signing_lane_reference_v1',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneKind: 'break_glass',
    laneShareEpoch: args.laneShareEpoch,
    participantBindingDigestB64u: args.participantBindingDigestB64u,
    ownerParticipantContinuity: args.ownerParticipantContinuity,
    lifecycle: args.lifecycle,
  };
}

export function buildActiveSigningLaneReference(
  args: ActiveSigningLaneReferenceBuilderArgs & { readonly laneKind: SigningLaneKind },
): ActiveSigningLaneReference {
  return {
    kind: 'signing_lane_reference_v1',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneKind: args.laneKind,
    laneShareEpoch: args.laneShareEpoch,
    participantBindingDigestB64u: args.participantBindingDigestB64u,
    lifecycle: args.lifecycle,
    materialActivation: args.materialActivation,
  };
}

export function parseWalletKeyLifecycle(
  raw: unknown,
  label = 'walletKeyLifecycle',
): WalletKeyLifecycle {
  return parseWalletKeyLifecycleState(raw, label);
}

export function parseSigningLaneLifecycle(
  raw: unknown,
  label = 'signingLaneLifecycle',
): SigningLaneLifecycle {
  return parseSigningLaneLifecycleState(raw, label);
}

export function parseWalletKeyRecord(raw: unknown, label = 'walletKeyRecord'): WalletKeyRecord {
  const record = requireRecord(raw, label);
  if (record.kind !== 'wallet_key_record_v1') {
    throw new Error(`${label}.kind must be wallet_key_record_v1`);
  }
  if (record.keyFamily === 'ed25519') {
    rejectUnknownFields(record, ED25519_WALLET_KEY_FIELDS, label, ALL_WALLET_KEY_FIELDS);
    return buildEd25519WalletKeyRecord({
      walletId: requireResult(parseWalletId(record.walletId), `${label}.walletId`),
      walletKeyId: requireResult(parseWalletKeyId(record.walletKeyId), `${label}.walletKeyId`),
      walletKeyVersion: parseWalletKeyVersion(record.walletKeyVersion, `${label}.walletKeyVersion`),
      nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(record.nearEd25519SigningKeyId),
      keyCreationSignerSlot: parseKeyCreationSignerSlot(
        record.keyCreationSignerSlot,
        `${label}.keyCreationSignerSlot`,
      ),
      registeredPublicKeyB64u: parseEd25519PublicKeyB64u(
        record.registeredPublicKeyB64u,
        `${label}.registeredPublicKeyB64u`,
      ),
      lifecycle: parseWalletKeyLifecycleState(record.lifecycle, `${label}.lifecycle`),
    });
  }
  if (record.keyFamily === 'ecdsa_secp256k1') {
    rejectUnknownFields(record, EVM_WALLET_KEY_FIELDS, label, ALL_WALLET_KEY_FIELDS);
    return buildEvmFamilyWalletKeyRecord({
      walletId: requireResult(parseWalletId(record.walletId), `${label}.walletId`),
      walletKeyId: requireResult(parseWalletKeyId(record.walletKeyId), `${label}.walletKeyId`),
      walletKeyVersion: parseWalletKeyVersion(record.walletKeyVersion, `${label}.walletKeyVersion`),
      evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
        record.evmFamilySigningKeySlotId,
        `${label}.evmFamilySigningKeySlotId`,
      ),
      thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
        record.thresholdPublicKey33B64u,
        `${label}.thresholdPublicKey33B64u`,
      ),
      evmAddress: parseNonEmptyString(record.evmAddress, `${label}.evmAddress`),
      lifecycle: parseWalletKeyLifecycleState(record.lifecycle, `${label}.lifecycle`),
    });
  }
  throw new Error(`${label}.keyFamily must be ed25519 or ecdsa_secp256k1`);
}

export function parseSigningLaneReference(
  raw: unknown,
  label = 'signingLaneReference',
): SigningLaneReference {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, SIGNING_LANE_REFERENCE_FIELDS, label);
  return parseSigningLaneReferenceFields(record, label);
}

export function parseSigningLaneRecord(
  raw: unknown,
  label = 'signingLaneRecord',
): SigningLaneRecord {
  const record = requireRecord(raw, label);
  if (record.kind !== 'signing_lane_reference_v1') {
    throw new Error(`${label}.kind must be signing_lane_reference_v1`);
  }
  const laneKind = parseSigningLaneKind(record.laneKind, `${label}.laneKind`);
  const allowedFields = signingLaneRecordFields(laneKind);
  rejectUnknownFields(record, allowedFields, label, ALL_SIGNING_LANE_RECORD_FIELDS);
  switch (laneKind) {
    case 'owner_passkey':
      return buildOwnerPasskeySigningLaneRecord(parseOwnerAuthSigningLaneRecordBase(record, label));
    case 'owner_email_otp':
      return buildOwnerEmailOtpSigningLaneRecord(
        parseOwnerAuthSigningLaneRecordBase(record, label),
      );
    case 'linked_device': {
      const base = parseRotatableSigningLaneRecordBase(record, label);
      return buildLinkedDeviceSigningLaneRecord({
        walletId: base.walletId,
        walletKeyId: base.walletKeyId,
        laneId: base.laneId,
        laneShareEpoch: base.laneShareEpoch,
        participantBindingDigestB64u: base.participantBindingDigestB64u,
        holderParticipant: base.holderParticipant,
        serverParticipant: base.serverParticipant,
        lifecycle: base.lifecycle,
        linkedDeviceId: requireResult(
          parseLinkedDeviceId(record.linkedDeviceId),
          `${label}.linkedDeviceId`,
        ),
      });
    }
    case 'delegated_execution': {
      const base = parseRotatableSigningLaneRecordBase(record, label);
      return buildDelegatedExecutionSigningLaneRecord({
        walletId: base.walletId,
        walletKeyId: base.walletKeyId,
        laneId: base.laneId,
        laneShareEpoch: base.laneShareEpoch,
        participantBindingDigestB64u: base.participantBindingDigestB64u,
        holderParticipant: base.holderParticipant,
        serverParticipant: base.serverParticipant,
        lifecycle: base.lifecycle,
        authorizationId: parseDelegatedSpendAuthorizationId(
          record.authorizationId,
          `${label}.authorizationId`,
        ),
        agentIdentityKeyId: parseAgentIdentityKeyId(
          record.agentIdentityKeyId,
          `${label}.agentIdentityKeyId`,
        ),
        custodyBindingId: parseAgentCustodyBindingId(
          record.custodyBindingId,
          `${label}.custodyBindingId`,
        ),
        authorizationBindingDigestB64u: parseDigestField(
          record.authorizationBindingDigestB64u,
          `${label}.authorizationBindingDigestB64u`,
        ),
      });
    }
    case 'recovery':
      return buildRecoverySigningLaneRecord(
        parsePrivilegedOwnerSigningLaneRecordBase(record, label),
      );
    case 'break_glass':
      return buildBreakGlassSigningLaneRecord(
        parsePrivilegedOwnerSigningLaneRecordBase(record, label),
      );
  }
}

export function parseActiveSigningLaneReference(
  raw: unknown,
  label = 'activeSigningLaneReference',
): ActiveSigningLaneReference {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, ACTIVE_SIGNING_LANE_REFERENCE_FIELDS, label);
  const reference = parseSigningLaneReferenceFields(record, label);
  const lifecycle = parseSigningLaneLifecycleState(record.lifecycle, `${label}.lifecycle`);
  if (lifecycle.state !== 'active') {
    throw new Error(`${label}.lifecycle must be active`);
  }
  const materialActivation = requireResult(
    parseMpcMaterialActivationRef(record.materialActivation),
    `${label}.materialActivation`,
  );
  return buildActiveSigningLaneReference({
    walletId: reference.walletId,
    walletKeyId: reference.walletKeyId,
    laneId: reference.laneId,
    laneShareEpoch: reference.laneShareEpoch,
    participantBindingDigestB64u: reference.participantBindingDigestB64u,
    laneKind: reference.laneKind,
    lifecycle,
    materialActivation,
  });
}
