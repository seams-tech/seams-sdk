import { keccak256Bytes } from '@shared/utils/keccak';
import type {
  UndeployedSmartAccountSigner,
  UndeployedSmartAccountSignerSet,
} from '@shared/utils/undeployedSmartAccountSignerSet';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { AccountSignerRecord, AccountSignerStatus } from './AccountSignerStore';
import type { SmartAccountRecoverySubjectRecord } from './SmartAccountRecoverySubjectStore';
import { normalizeSmartAccountHexLike } from './smartAccountRegistrationRecords';

export type CanonicalSmartAccountDeploymentManifestOwner = {
  signerId: string;
  signerType: string;
  status: AccountSignerStatus;
  signerSlot?: number;
  relayerKeyId?: string;
  thresholdEcdsaPublicKeyB64u?: string;
  participantIds?: number[];
  credentialIdB64u?: string;
  rpId?: string;
};

export type CanonicalSmartAccountDeploymentManifest = {
  version: 'smart_account_deployment_manifest_v1';
  chainIdKey: string;
  accountAddress: string;
  nearAccountIdHash: `0x${string}`;
  chain: 'evm' | 'tempo';
  chainId: number;
  accountModel: 'erc4337' | 'tempo-native';
  deployed: boolean;
  ownerAddresses: string[];
  activeOwnerAddresses: string[];
  pendingOwnerAddresses: string[];
  owners: CanonicalSmartAccountDeploymentManifestOwner[];
  undeployedSignerSet: UndeployedSmartAccountSignerSet;
  materializedAtMs: number;
  source: 'canonical_account_signer';
  factory?: string;
  entryPoint?: string;
  recoveryAuthority?: string;
  salt?: string;
  counterfactualAddress?: string;
  sponsorshipScope?: {
    orgId: string;
    environmentId: string;
    projectId?: string;
  };
};

function coerceChain(value: unknown): 'evm' | 'tempo' | null {
  const normalized = toOptionalTrimmedString(value)?.toLowerCase() || '';
  if (normalized === 'evm' || normalized === 'tempo') return normalized;
  return null;
}

function coerceChainId(value: unknown): number | null {
  const parsed = Math.floor(Number(value));
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return parsed;
}

function coerceAccountModel(value: unknown, chain: 'evm' | 'tempo'): 'erc4337' | 'tempo-native' {
  const normalized = toOptionalTrimmedString(value);
  if (normalized === 'erc4337' || normalized === 'tempo-native') return normalized;
  return chain === 'evm' ? 'erc4337' : 'tempo-native';
}

function asObject(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? { ...(value as Record<string, unknown>) }
    : {};
}

function normalizeSignerId(value: unknown): string {
  const normalized = normalizeSmartAccountHexLike(value);
  return normalized || toOptionalTrimmedString(value) || '';
}

function normalizePositiveInteger(value: unknown): number | null {
  const parsed = Math.floor(Number(value));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
}

function statusPriority(status: AccountSignerStatus): number {
  switch (status) {
    case 'active':
      return 0;
    case 'pending':
      return 1;
    case 'revoked':
      return 2;
    default:
      return 3;
  }
}

function signerSlot(record: AccountSignerRecord): number | null {
  const metadata = asObject(record.metadata);
  return normalizePositiveInteger(metadata.signerSlot);
}

function compareManifestSignerOrder(left: AccountSignerRecord, right: AccountSignerRecord): number {
  const statusDelta = statusPriority(left.status) - statusPriority(right.status);
  if (statusDelta !== 0) return statusDelta;

  const leftSignerSlot = signerSlot(left);
  const rightSignerSlot = signerSlot(right);
  if (leftSignerSlot !== rightSignerSlot) {
    if (leftSignerSlot === null) return 1;
    if (rightSignerSlot === null) return -1;
    return leftSignerSlot - rightSignerSlot;
  }

  if (left.createdAtMs !== right.createdAtMs) {
    return left.createdAtMs - right.createdAtMs;
  }

  const signerIdDelta = normalizeSignerId(left.signerId).localeCompare(
    normalizeSignerId(right.signerId),
  );
  if (signerIdDelta !== 0) return signerIdDelta;

  if (left.updatedAtMs !== right.updatedAtMs) {
    return left.updatedAtMs - right.updatedAtMs;
  }

  return (toOptionalTrimmedString(left.signerType) || '').localeCompare(
    toOptionalTrimmedString(right.signerType) || '',
  );
}

function toManifestOwner(
  signer: AccountSignerRecord,
): CanonicalSmartAccountDeploymentManifestOwner | null {
  const signerId = normalizeSignerId(signer.signerId);
  if (!signerId || signer.status === 'revoked') return null;
  const metadata = asObject(signer.metadata);
  const participantIds = Array.isArray(metadata.participantIds)
    ? metadata.participantIds
        .map((value) => Math.floor(Number(value)))
        .filter((value) => Number.isFinite(value) && value > 0)
    : [];
  return {
    signerId,
    signerType: toOptionalTrimmedString(signer.signerType) || 'threshold',
    status: signer.status,
    ...(Number.isFinite(Number(metadata.signerSlot)) && Number(metadata.signerSlot) > 0
      ? { signerSlot: Math.floor(Number(metadata.signerSlot)) }
      : {}),
    ...(toOptionalTrimmedString(metadata.relayerKeyId)
      ? { relayerKeyId: toOptionalTrimmedString(metadata.relayerKeyId)! }
      : {}),
    ...(toOptionalTrimmedString(metadata.thresholdEcdsaPublicKeyB64u)
      ? { thresholdEcdsaPublicKeyB64u: toOptionalTrimmedString(metadata.thresholdEcdsaPublicKeyB64u)! }
      : {}),
    ...(participantIds.length > 0 ? { participantIds } : {}),
    ...(toOptionalTrimmedString(metadata.credentialIdB64u)
      ? { credentialIdB64u: toOptionalTrimmedString(metadata.credentialIdB64u)! }
      : {}),
    ...(toOptionalTrimmedString(metadata.rpId)
      ? { rpId: toOptionalTrimmedString(metadata.rpId)! }
      : {}),
  };
}

function dedupeAddresses(values: string[]): string[] {
  const seen = new Set<string>();
  const next: string[] = [];
  for (const value of values) {
    const normalized = normalizeSignerId(value);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    next.push(normalized);
  }
  return next;
}

function toUndeployedSmartAccountSignerSet(input: {
  ownerAddresses: string[];
  activeOwnerAddresses: string[];
  pendingOwnerAddresses: string[];
  owners: CanonicalSmartAccountDeploymentManifestOwner[];
}): UndeployedSmartAccountSignerSet {
  const owners: UndeployedSmartAccountSigner[] = input.owners.map((owner) => ({
    signerId: owner.signerId,
    signerType: owner.signerType,
    status: owner.status === 'pending' ? 'pending' : 'active',
    ...(typeof owner.signerSlot === 'number' ? { signerSlot: owner.signerSlot } : {}),
    ...(owner.relayerKeyId ? { relayerKeyId: owner.relayerKeyId } : {}),
    ...(owner.thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u: owner.thresholdEcdsaPublicKeyB64u } : {}),
    ...(Array.isArray(owner.participantIds) && owner.participantIds.length
      ? { participantIds: owner.participantIds }
      : {}),
    ...(owner.credentialIdB64u ? { credentialIdB64u: owner.credentialIdB64u } : {}),
    ...(owner.rpId ? { rpId: owner.rpId } : {}),
  }));
  return {
    version: 'undeployed_smart_account_signer_set_v1',
    ownerAddresses: input.ownerAddresses,
    activeOwnerAddresses: input.activeOwnerAddresses,
    pendingOwnerAddresses: input.pendingOwnerAddresses,
    owners,
  };
}

function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes)
    .map((entry) => entry.toString(16).padStart(2, '0'))
    .join('')}` as `0x${string}`;
}

function utf8KeccakHex(value: string): `0x${string}` {
  return bytesToHex(keccak256Bytes(new TextEncoder().encode(value)));
}

export function buildCanonicalSmartAccountDeploymentManifest(input: {
  recoverySubject: SmartAccountRecoverySubjectRecord;
  signers?: AccountSignerRecord[];
  materializedAtMs?: number;
}): CanonicalSmartAccountDeploymentManifest | null {
  const subject = input.recoverySubject;
  const chainIdKey = toOptionalTrimmedString(subject.chainIdKey)?.toLowerCase() || '';
  const accountAddress = normalizeSmartAccountHexLike(subject.accountAddress);
  const nearAccountId = toOptionalTrimmedString(subject.nearAccountId);
  const metadata = asObject(subject.metadata);
  const chain = coerceChain(metadata.chain);
  const chainId = coerceChainId(metadata.chainId);
  if (!chainIdKey || !accountAddress || !nearAccountId || !chain || !chainId) return null;

  const owners = [...(input.signers || [])]
    .sort(compareManifestSignerOrder)
    .map((record) => toManifestOwner(record))
    .filter(Boolean) as CanonicalSmartAccountDeploymentManifestOwner[];

  const activeOwnerAddresses = dedupeAddresses(
    owners.filter((owner) => owner.status === 'active').map((owner) => owner.signerId),
  );
  const pendingOwnerAddresses = dedupeAddresses(
    owners.filter((owner) => owner.status === 'pending').map((owner) => owner.signerId),
  );
  const ownerAddresses = dedupeAddresses([...activeOwnerAddresses, ...pendingOwnerAddresses]);

  const sponsorshipScope = asObject(metadata.sponsorshipScope);
  const sponsorshipOrgId = toOptionalTrimmedString(sponsorshipScope.orgId);
  const sponsorshipEnvironmentId = toOptionalTrimmedString(sponsorshipScope.environmentId);
  const sponsorshipProjectId = toOptionalTrimmedString(sponsorshipScope.projectId);

  return {
    version: 'smart_account_deployment_manifest_v1',
    chainIdKey,
    accountAddress,
    nearAccountIdHash: utf8KeccakHex(nearAccountId),
    chain,
    chainId,
    accountModel: coerceAccountModel(metadata.accountModel, chain),
    deployed: metadata.deployed === true,
    ownerAddresses,
    activeOwnerAddresses,
    pendingOwnerAddresses,
    owners,
    undeployedSignerSet: toUndeployedSmartAccountSignerSet({
      ownerAddresses,
      activeOwnerAddresses,
      pendingOwnerAddresses,
      owners,
    }),
    materializedAtMs: Number.isFinite(Number(input.materializedAtMs))
      ? Math.floor(Number(input.materializedAtMs))
      : Date.now(),
    source: 'canonical_account_signer',
    ...(normalizeSmartAccountHexLike(metadata.factory)
      ? { factory: normalizeSmartAccountHexLike(metadata.factory) }
      : {}),
    ...(normalizeSmartAccountHexLike(metadata.entryPoint)
      ? { entryPoint: normalizeSmartAccountHexLike(metadata.entryPoint) }
      : {}),
    ...(normalizeSmartAccountHexLike(metadata.recoveryAuthority)
      ? { recoveryAuthority: normalizeSmartAccountHexLike(metadata.recoveryAuthority) }
      : {}),
    ...(toOptionalTrimmedString(metadata.salt)
      ? { salt: toOptionalTrimmedString(metadata.salt)! }
      : {}),
    ...(normalizeSmartAccountHexLike(metadata.counterfactualAddress)
      ? { counterfactualAddress: normalizeSmartAccountHexLike(metadata.counterfactualAddress) }
      : {}),
    ...(sponsorshipOrgId && sponsorshipEnvironmentId
      ? {
          sponsorshipScope: {
            orgId: sponsorshipOrgId,
            environmentId: sponsorshipEnvironmentId,
            ...(sponsorshipProjectId ? { projectId: sponsorshipProjectId } : {}),
          },
        }
      : {}),
  };
}
