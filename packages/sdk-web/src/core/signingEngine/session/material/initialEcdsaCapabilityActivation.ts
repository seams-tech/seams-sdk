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
import { base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify } from '@shared/utils/digests';
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
import type { EvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  parseRouterAbEcdsaVerifiedClientActivationFactsV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
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
  readonly materialHandle?: never;
  readonly pendingPayloadB64u?: never;
};

export type InitialEcdsaCapabilityActivationPlanInput = {
  readonly authority: WalletAuthAuthorityRef;
  readonly targetMemberships: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  readonly evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  readonly ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  readonly signingRootId: SigningRootId;
  readonly signingRootVersion: SigningRootVersion;
  readonly runtimePolicyScope: RuntimePolicyScope;
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

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(
  record: Record<string, unknown>,
  label: string,
  keys: readonly string[],
): void {
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} fields are invalid`);
  }
}

function digestFromActivationCommitWire(value: unknown): DigestB64u {
  const record = requireRecord(value, 'ECDSA activation commit request digest');
  requireExactKeys(record, 'ECDSA activation commit request digest', ['bytes']);
  if (
    !Array.isArray(record.bytes) ||
    record.bytes.length !== 32 ||
    record.bytes.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)
  ) {
    throw new Error('ECDSA activation commit request digest bytes are invalid');
  }
  return parseDigestB64u(base64UrlEncode(Uint8Array.from(record.bytes)));
}

function activationCommitCeremonyId(record: Record<string, unknown>): string {
  if (record.operation === 'wallet_registration_activate_v2') {
    requireExactKeys(record, 'ECDSA activation operation', [
      'operation',
      'registrationCeremonyId',
      'activationCorrelationId',
      'idempotencyKey',
      'publicFacts',
    ]);
    const ceremonyId = String(record.registrationCeremonyId || '').trim();
    if (!ceremonyId) throw new Error('ECDSA activation operation ceremony identity is invalid');
    return ceremonyId;
  }
  if (record.operation === 'wallet_add_signer_activate_v2') {
    requireExactKeys(record, 'ECDSA activation operation', [
      'operation',
      'addSignerCeremonyId',
      'activationCorrelationId',
      'publicFacts',
    ]);
    const ceremonyId = String(record.addSignerCeremonyId || '').trim();
    if (!ceremonyId) throw new Error('ECDSA activation operation ceremony identity is invalid');
    return ceremonyId;
  }
  const hasRegistrationId = Object.hasOwn(record, 'registrationCeremonyId');
  const hasAddSignerId = Object.hasOwn(record, 'addSignerCeremonyId');
  if (hasRegistrationId === hasAddSignerId) {
    throw new Error('ECDSA activation commit request requires one ceremony identity');
  }
  const field = hasRegistrationId ? 'registrationCeremonyId' : 'addSignerCeremonyId';
  requireExactKeys(record, 'ECDSA activation commit request', [field, 'ecdsa']);
  const ceremonyId = String(record[field] || '').trim();
  if (!ceremonyId) throw new Error('ECDSA activation commit ceremony identity is invalid');
  return ceremonyId;
}

function assertCanonicalRequestMatchesVerifiedCeremony(input: {
  readonly ceremonyId: string;
  readonly planInput: InitialEcdsaCapabilityActivationPlanInput;
  readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
}): void {
  const request = requireRecord(
    JSON.parse(input.planInput.canonicalRequest),
    'ECDSA activation commit request',
  );
  if (activationCommitCeremonyId(request) !== input.ceremonyId) {
    throw new Error('ECDSA activation commit request changed the ceremony identity');
  }
  if (request.operation === 'wallet_registration_activate_v2') {
    if (parseCorrelationId(request.activationCorrelationId) !== input.planInput.journalId) {
      throw new Error('ECDSA activation operation changed the activation correlation');
    }
    if (!String(request.idempotencyKey || '').trim()) {
      throw new Error('ECDSA activation operation requires an idempotency key');
    }
    const publicFacts = parseRouterAbEcdsaVerifiedClientActivationFactsV1(request.publicFacts);
    if (alphabetizeStringify(publicFacts) !== alphabetizeStringify(input.clientActivation)) {
      throw new Error('ECDSA activation operation changed the verified client facts');
    }
    return;
  }
  if (request.operation === 'wallet_add_signer_activate_v2') {
    if (parseCorrelationId(request.activationCorrelationId) !== input.planInput.journalId) {
      throw new Error('ECDSA activation operation changed the activation correlation');
    }
    const publicFacts = parseRouterAbEcdsaVerifiedClientActivationFactsV1(request.publicFacts);
    if (alphabetizeStringify(publicFacts) !== alphabetizeStringify(input.clientActivation)) {
      throw new Error('ECDSA activation operation changed the verified client facts');
    }
    return;
  }
  const ecdsa = requireRecord(request.ecdsa, 'ECDSA activation commit request ecdsa');
  requireExactKeys(ecdsa, 'ECDSA activation commit request ecdsa', [
    'kind',
    'activationCorrelationId',
    'publicFacts',
    'expectedActivationRequestDigest',
  ]);
  if (ecdsa.kind !== 'router_ab_ecdsa_registration_activation_v1') {
    throw new Error('ECDSA activation commit request kind is invalid');
  }
  if (parseCorrelationId(ecdsa.activationCorrelationId) !== input.planInput.journalId) {
    throw new Error('ECDSA activation commit request changed the activation correlation');
  }
  if (
    digestFromActivationCommitWire(ecdsa.expectedActivationRequestDigest) !==
    input.planInput.requestDigest
  ) {
    throw new Error('ECDSA activation commit request changed the prepared request digest');
  }
  const publicFacts = parseRouterAbEcdsaVerifiedClientActivationFactsV1(ecdsa.publicFacts);
  if (alphabetizeStringify(publicFacts) !== alphabetizeStringify(input.clientActivation)) {
    throw new Error('ECDSA activation commit request changed the verified client facts');
  }
}

export function assertInitialEcdsaActivationPlanMatchesVerifiedCeremony(input: {
  readonly ceremonyId: string;
  readonly planInput: InitialEcdsaCapabilityActivationPlanInput;
  readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
}): void {
  const clientActivation = parseRouterAbEcdsaVerifiedClientActivationFactsV1(
    input.clientActivation,
  );
  if (
    input.planInput.journalId !== parseCorrelationId(input.ceremonyId) ||
    input.planInput.bindingDigest !== clientActivation.contextBinding32B64u ||
    input.planInput.clientVerifyingPublicKey33B64u !==
      clientActivation.derivationClientSharePublicKey33B64u ||
    input.planInput.participantIds.length !== 2 ||
    input.planInput.participantIds[0] !== toParticipantId(1) ||
    input.planInput.participantIds[1] !== toParticipantId(2)
  ) {
    throw new Error('Initial canonical ECDSA activation plan does not match the live ceremony');
  }
  assertCanonicalRequestMatchesVerifiedCeremony({
    ceremonyId: input.ceremonyId,
    planInput: input.planInput,
    clientActivation,
  });
}

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

function materialOwnerRefForAuthority(authority: WalletAuthAuthorityRef) {
  return unwrapDomainId(parseMpcMaterialOwnerRef(authority.walletId));
}

function freshManifestIdentity() {
  return buildEcdsaManifestIdentity({
    manifestId: parseEcdsaCapabilityManifestId(
      secureRandomId('ecdsa-manifest', 32, 'initial ECDSA manifest identities'),
    ),
    manifestRevision: parseEcdsaCapabilityManifestRevision(1),
  });
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
    materialOwner: materialOwnerRefForAuthority(authority),
    signingRootId,
    signingRootVersion,
  });
  const activationBinding = buildEcdsaActivationBinding({
    targetManifest: freshManifestIdentity(),
    signer,
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
