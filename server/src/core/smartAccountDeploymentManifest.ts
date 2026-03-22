import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { AccountSignerRecord, AccountSignerStatus } from './AccountSignerStore';
import type { SmartAccountRecoverySubjectRecord } from './SmartAccountRecoverySubjectStore';
import { normalizeSmartAccountHexLike } from './smartAccountRegistrationRecords';

export type CanonicalSmartAccountDeploymentManifestOwner = {
  signerId: string;
  signerType: string;
  status: AccountSignerStatus;
  deviceNumber?: number;
  relayerKeyId?: string;
  groupPublicKeyB64u?: string;
  participantIds?: number[];
  credentialIdB64u?: string;
  rpId?: string;
};

export type CanonicalSmartAccountDeploymentManifest = {
  version: 'smart_account_deployment_manifest_v1';
  chainIdKey: string;
  accountAddress: string;
  chain: 'evm' | 'tempo';
  chainId: number;
  accountModel: 'erc4337' | 'tempo-native';
  deployed: boolean;
  ownerAddresses: string[];
  activeOwnerAddresses: string[];
  pendingOwnerAddresses: string[];
  owners: CanonicalSmartAccountDeploymentManifestOwner[];
  materializedAtMs: number;
  source: 'canonical_account_signer';
  factory?: string;
  entryPoint?: string;
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
  return normalized || (toOptionalTrimmedString(value) || '');
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
    ...(Number.isFinite(Number(metadata.deviceNumber)) && Number(metadata.deviceNumber) > 0
      ? { deviceNumber: Math.floor(Number(metadata.deviceNumber)) }
      : {}),
    ...(toOptionalTrimmedString(metadata.relayerKeyId)
      ? { relayerKeyId: toOptionalTrimmedString(metadata.relayerKeyId)! }
      : {}),
    ...(toOptionalTrimmedString(metadata.groupPublicKeyB64u)
      ? { groupPublicKeyB64u: toOptionalTrimmedString(metadata.groupPublicKeyB64u)! }
      : {}),
    ...(participantIds.length > 0 ? { participantIds } : {}),
    ...(toOptionalTrimmedString(metadata.credentialIdB64u)
      ? { credentialIdB64u: toOptionalTrimmedString(metadata.credentialIdB64u)! }
      : {}),
    ...(toOptionalTrimmedString(metadata.rpId) ? { rpId: toOptionalTrimmedString(metadata.rpId)! } : {}),
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

export function buildCanonicalSmartAccountDeploymentManifest(input: {
  recoverySubject: SmartAccountRecoverySubjectRecord;
  signers?: AccountSignerRecord[];
  materializedAtMs?: number;
}): CanonicalSmartAccountDeploymentManifest | null {
  const subject = input.recoverySubject;
  const chainIdKey = toOptionalTrimmedString(subject.chainIdKey)?.toLowerCase() || '';
  const accountAddress = normalizeSmartAccountHexLike(subject.accountAddress);
  const metadata = asObject(subject.metadata);
  const chain = coerceChain(metadata.chain);
  const chainId = coerceChainId(metadata.chainId);
  if (!chainIdKey || !accountAddress || !chain || !chainId) return null;

  const owners = (input.signers || [])
    .map((record) => toManifestOwner(record))
    .filter(Boolean) as CanonicalSmartAccountDeploymentManifestOwner[];
  owners.sort((left, right) => left.signerId.localeCompare(right.signerId));

  const activeOwnerAddresses = dedupeAddresses(
    owners.filter((owner) => owner.status === 'active').map((owner) => owner.signerId),
  );
  const pendingOwnerAddresses = dedupeAddresses(
    owners.filter((owner) => owner.status === 'pending').map((owner) => owner.signerId),
  );
  const ownerAddresses = dedupeAddresses([
    ...activeOwnerAddresses,
    ...pendingOwnerAddresses,
  ]);

  const sponsorshipScope = asObject(metadata.sponsorshipScope);
  const sponsorshipOrgId = toOptionalTrimmedString(sponsorshipScope.orgId);
  const sponsorshipEnvironmentId = toOptionalTrimmedString(sponsorshipScope.environmentId);
  const sponsorshipProjectId = toOptionalTrimmedString(sponsorshipScope.projectId);

  return {
    version: 'smart_account_deployment_manifest_v1',
    chainIdKey,
    accountAddress,
    chain,
    chainId,
    accountModel: coerceAccountModel(metadata.accountModel, chain),
    deployed: metadata.deployed === true,
    ownerAddresses,
    activeOwnerAddresses,
    pendingOwnerAddresses,
    owners,
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
    ...(toOptionalTrimmedString(metadata.salt) ? { salt: toOptionalTrimmedString(metadata.salt)! } : {}),
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
