import {
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
  type EcdsaThresholdKeyId,
  type SigningRootId,
  type SigningRootVersion,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  parseCapabilityInstanceRef,
  parseMpcMaterialActivationId,
  parseMpcMaterialOwnerRef,
  type DomainIdParseResult,
} from '@shared/utils/domainIds';
import {
  parseCorrelationId,
  parseDigestB64u,
  parseIsoTimestamp,
  type CorrelationId,
  type DigestB64u,
  type IsoTimestamp,
} from '@shared/utils/canonicalPrimitives';
import {
  parseCanonicalEcdsaServerActivationRequest,
  parseEcdsaCapabilityManifestId,
  parseEcdsaCapabilityManifestRevision,
  parseEvmFamilyEcdsaSignerId,
  type CanonicalEcdsaServerActivationRequest,
} from '@shared/utils/ecdsaCapabilityActivation';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { ThresholdEcdsaChainTarget } from '@/core/platform/types';
import { toParticipantId, type ParticipantId } from '../identity/evmFamilyEcdsaIdentity';
import {
  parseEcdsaClientVerifyingPublicKey33B64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaThresholdKeyId,
  type EcdsaClientVerifyingPublicKey33B64u,
  type EcdsaRelayerKeyId,
  type EcdsaRoleLocalBindingDigest,
} from '../keyMaterialBrands';
import {
  buildEcdsaActivationBinding,
  buildEcdsaCapabilityScope,
  buildEcdsaManifestIdentity,
  buildEcdsaRoleLocalMaterialBinding,
  buildNoCurrentEcdsaManifestExpectation,
  buildNoCurrentEcdsaServerGenerationExpectation,
  buildPreparedEvmFamilySigner,
  type EcdsaActivationBinding,
  type NoCurrentEcdsaManifestExpectation,
  type NoCurrentEcdsaServerGenerationExpectation,
} from './ecdsaCapabilityManifest';

type PlannerOwnedIdentityExclusions = {
  readonly capability?: never;
  readonly signerId?: never;
  readonly materialOwner?: never;
  readonly manifestId?: never;
  readonly manifestRevision?: never;
  readonly activationId?: never;
  readonly durableMaterialRef?: never;
  readonly thresholdSessionId?: never;
  readonly walletSessionId?: never;
  readonly signingGrantId?: never;
  readonly materialHandle?: never;
  readonly pendingPayloadB64u?: never;
};

export type InitialEcdsaCapabilityActivationPlanInput = {
  readonly authority: WalletAuthAuthorityRef;
  readonly targetMemberships: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  readonly ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  readonly signingRootId: SigningRootId;
  readonly signingRootVersion: SigningRootVersion;
  readonly clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
  readonly participantIds: readonly [ParticipantId, ...ParticipantId[]];
  readonly relayerKeyId: EcdsaRelayerKeyId;
  readonly bindingDigest: EcdsaRoleLocalBindingDigest;
  readonly journalId: CorrelationId;
  readonly requestDigest: DigestB64u;
  readonly canonicalRequest: CanonicalEcdsaServerActivationRequest;
  readonly createdAt: IsoTimestamp;
} & PlannerOwnedIdentityExclusions;

export type InitialEcdsaCapabilityActivationPlan = {
  readonly journalId: CorrelationId;
  readonly expectedManifest: NoCurrentEcdsaManifestExpectation;
  readonly expectedGeneration: NoCurrentEcdsaServerGenerationExpectation;
  readonly activationBinding: EcdsaActivationBinding;
  readonly requestDigest: DigestB64u;
  readonly canonicalRequest: CanonicalEcdsaServerActivationRequest;
  readonly createdAt: IsoTimestamp;
  readonly pendingPayloadB64u?: never;
};

function unwrapDomainId<T>(result: DomainIdParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function requireAuthority(authority: WalletAuthAuthorityRef): WalletAuthAuthorityRef {
  const parsed = parseWalletAuthAuthorityRef(authority);
  if (!parsed) throw new Error('Initial ECDSA activation requires an exact wallet authority');
  return parsed;
}

function freshCapabilityRef() {
  return unwrapDomainId(
    parseCapabilityInstanceRef(
      secureRandomId('ecdsa-capability', 32, 'initial ECDSA capability identities'),
    ),
  );
}

function freshSignerId() {
  return parseEvmFamilyEcdsaSignerId(
    secureRandomId('ecdsa-signer', 32, 'initial ECDSA signer identities'),
  );
}

function freshMaterialOwnerRef() {
  return unwrapDomainId(
    parseMpcMaterialOwnerRef(
      secureRandomId('ecdsa-material-owner', 32, 'initial ECDSA material owner identities'),
    ),
  );
}

function freshManifestIdentity() {
  return buildEcdsaManifestIdentity({
    manifestId: parseEcdsaCapabilityManifestId(
      secureRandomId('ecdsa-manifest', 32, 'initial ECDSA manifest identities'),
    ),
    manifestRevision: parseEcdsaCapabilityManifestRevision(1),
  });
}

function freshActivationId() {
  return unwrapDomainId(
    parseMpcMaterialActivationId(
      secureRandomId('ecdsa-activation', 32, 'initial ECDSA material activation identities'),
    ),
  );
}

function freshDurableMaterialRef() {
  return parseEcdsaRoleLocalDurableMaterialRef(
    secureRandomId('ecdsa-role-local-material', 32, 'initial ECDSA durable material identities'),
  );
}

function normalizeParticipantIds(
  participantIds: readonly [ParticipantId, ...ParticipantId[]],
): readonly [ParticipantId, ...ParticipantId[]] {
  const [first, ...rest] = participantIds;
  const normalizedRest: ParticipantId[] = [];
  for (const participantId of rest) normalizedRest.push(toParticipantId(participantId));
  return [toParticipantId(first), ...normalizedRest];
}

export async function buildInitialEcdsaCapabilityActivationPlan(
  input: InitialEcdsaCapabilityActivationPlanInput,
): Promise<InitialEcdsaCapabilityActivationPlan> {
  const authority = requireAuthority(input.authority);
  const signingRootId = parseSdkEcdsaDerivationSigningRootId(input.signingRootId);
  const signingRootVersion = parseSdkEcdsaDerivationSigningRootVersion(input.signingRootVersion);
  const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId(input.ecdsaThresholdKeyId);
  const roleLocalBinding = buildEcdsaRoleLocalMaterialBinding({
    keyHandle: parseEcdsaKeyHandle(
      await deriveThresholdEcdsaKeyHandle({
        ecdsaThresholdKeyId,
        signingRootId,
        signingRootVersion,
      }),
    ),
    ecdsaThresholdKeyId,
    clientVerifyingPublicKey33B64u: parseEcdsaClientVerifyingPublicKey33B64u(
      input.clientVerifyingPublicKey33B64u,
    ),
    participantIds: normalizeParticipantIds(input.participantIds),
    relayerKeyId: parseEcdsaRelayerKeyId(input.relayerKeyId),
  });
  const signer = buildPreparedEvmFamilySigner({
    capability: freshCapabilityRef(),
    signerId: freshSignerId(),
    authority,
    scope: buildEcdsaCapabilityScope({
      targetMemberships: input.targetMemberships,
    }),
    materialOwner: freshMaterialOwnerRef(),
    signingRootId,
    signingRootVersion,
  });
  const activationBinding = buildEcdsaActivationBinding({
    targetManifest: freshManifestIdentity(),
    signer,
    activationId: freshActivationId(),
    roleLocalBinding,
    bindingDigest: parseEcdsaRoleLocalBindingDigest(input.bindingDigest),
    durableMaterialRef: freshDurableMaterialRef(),
  });
  return {
    journalId: parseCorrelationId(input.journalId),
    expectedManifest: buildNoCurrentEcdsaManifestExpectation(),
    expectedGeneration: buildNoCurrentEcdsaServerGenerationExpectation(),
    activationBinding,
    requestDigest: parseDigestB64u(input.requestDigest),
    canonicalRequest: parseCanonicalEcdsaServerActivationRequest(input.canonicalRequest),
    createdAt: parseIsoTimestamp(input.createdAt),
  };
}
