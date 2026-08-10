import type {
  EcdsaCapabilitySelector,
  EcdsaCapabilityManifestLookup,
  PrepareEcdsaCapabilityActivationInput,
  SealEcdsaCapabilityActivationInput,
} from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import {
  buildActiveEcdsaCapabilityManifest,
  buildEcdsaActivationBinding,
  buildEcdsaCapabilityScope,
  buildEcdsaServerActivationCommit,
  buildDurableEcdsaMaterialBinding,
  buildEcdsaManifestIdentity,
  buildEcdsaRoleLocalMaterialBinding,
  buildExactEcdsaManifestExpectation,
  buildExactEcdsaServerGenerationExpectation,
  buildNoCurrentEcdsaManifestExpectation,
  buildNoCurrentEcdsaServerGenerationExpectation,
  buildPreparedEvmFamilySigner,
  buildReplacedEcdsaCapabilityManifest,
  buildValidatedEncryptedEcdsaReadyMaterial,
  type ServerReturnedEcdsaActivationCommit,
} from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import {
  buildVerifiedEcdsaPublicFacts,
  toEvmFamilyEcdsaKeyHandle,
  toParticipantId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  parseEcdsaClientVerifyingPublicKey33B64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaThresholdKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { ActiveEvmFamilyWalletSessionAuthorization } from '@/core/signingEngine/session/material/ecdsaSigningCapability';
import type {
  ActiveEcdsaCapabilityManifest,
  EcdsaActivationBinding,
} from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import { buildActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  parseMpcWalletSigningQuotaId,
  parseSeamsSessionId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { base64UrlEncode } from '@shared/utils/base64';
import { ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  parseCorrelationId,
  parseDigestB64u,
  parseIsoTimestamp,
} from '@shared/utils/canonicalPrimitives';
import {
  parseCanonicalEcdsaServerActivationRequest,
  parseEcdsaCapabilityManifestId,
  parseEcdsaCapabilityManifestRevision,
  parseEcdsaCiphertextB64u,
  parseEcdsaCiphertextDigest,
  parseEcdsaIv12B64u,
  parseEcdsaMaterialSealingKeyId,
  parseEcdsaServerGeneration,
  parseEvmFamilyEcdsaSignerId,
} from '@shared/utils/ecdsaCapabilityActivation';
import {
  parseCapabilityInstanceRef,
  parseMpcMaterialOwnerRef,
  parseRootShareEpoch,
  parseWalletAuthorityBindingDigest,
  type DomainIdParseResult,
} from '@shared/utils/domainIds';
import type {
  RouterAbEcdsaDerivationNormalSigningStateV1,
  RouterAbEcdsaRegistrationActivationReceiptV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { buildRouterAbEcdsaDerivationPublicCapabilityV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { buildEcdsaRoleLocalPublicFacts } from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildPersistedEcdsaRoleLocalMaterial } from '@/core/signingEngine/session/material/ecdsaRoleLocalMaterialResolver';
import {
  buildCanonicalEvmFamilyEcdsaSigningCapability,
  type CanonicalEvmFamilyEcdsaSigningCapability,
} from '@/core/signingEngine/session/material/ecdsaSigningCapability';
import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { routerAbEcdsaRegistrationPendingFinalizationFixture } from './routerAbEcdsaRegistrationPendingFinalization.fixtures';

const DIGEST_B64U = base64UrlEncode(new Uint8Array(32).fill(12));
const APPLICATION_BINDING_DIGEST_B64U = 'VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU';
const CONTEXT_BINDING_B64U = 'ga29uobW2Hvkz8FnDn3rLhxE_AIFuZDDdtIDnelsibc';
const CLIENT_PUBLIC_KEY_B64U = 'Atwt5jXVelj7TRZgVnmNBX0EQ2GY6bQrhRtfKfqOiuZq';
const SERVER_PUBLIC_KEY_B64U = 'A6tbOC71wOA6nkWqZtdKpJ-LGiCSJANkUOpy2v8eYxYO';
const GROUP_PUBLIC_KEY_B64U = 'A40b71OnjHXDpAfjpNrmDton5rtQ-s2b9iiVXT93TtAM';
const ETHEREUM_ADDRESS_B64U = 'FgKUBDfhuhPgbFpFKDPa3wga0fI';
const THRESHOLD_OWNER_ADDRESS = '0x1602940437e1ba13e06c5a452833dadf081ad1f2';
const REPLACEMENT_DIGEST_B64U = base64UrlEncode(new Uint8Array(32).fill(13));
const REPLACEMENT_CLIENT_PUBLIC_KEY_B64U = base64UrlEncode(
  Uint8Array.from([2, ...new Array<number>(32).fill(9)]),
);
const REPLACEMENT_SERVER_PUBLIC_KEY_B64U = base64UrlEncode(
  Uint8Array.from([3, ...new Array<number>(32).fill(10)]),
);

function unwrap<T>(result: DomainIdParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export type EcdsaCapabilityActivationFixture = {
  readonly prepareInput: PrepareEcdsaCapabilityActivationInput;
  readonly serverCommit: ServerReturnedEcdsaActivationCommit;
  readonly sealInput: Omit<SealEcdsaCapabilityActivationInput, 'committedJournal'>;
  readonly serverGeneration: ReturnType<typeof parseEcdsaServerGeneration>;
  readonly differentPublicKeyB64u: string;
};

export type EcdsaCapabilityReplacementFixture = {
  readonly prior: EcdsaCapabilityActivationFixture;
  readonly replacement: EcdsaCapabilityActivationFixture;
};

export type EcdsaCapabilityLookupOutcomeFixture = {
  readonly replacement: EcdsaCapabilityReplacementFixture;
  readonly selectors: {
    readonly active: EcdsaCapabilitySelector;
    readonly missing: EcdsaCapabilitySelector;
    readonly exactBindingMismatch: EcdsaCapabilitySelector;
  };
};

export type EcdsaCapabilityHydrationLookupFixture = {
  readonly active: Extract<EcdsaCapabilityManifestLookup, { readonly kind: 'active' }>;
  readonly retired: Extract<EcdsaCapabilityManifestLookup, { readonly kind: 'retired' }>;
  readonly selectors: EcdsaCapabilityLookupOutcomeFixture['selectors'];
};

function fixtureStateBlob(label: string): string {
  return base64UrlEncode(new TextEncoder().encode(label));
}

function normalSigningFixture(args: {
  activationBinding: EcdsaActivationBinding;
  receipt: RouterAbEcdsaRegistrationActivationReceiptV1;
}): RouterAbEcdsaDerivationNormalSigningStateV1 {
  const activation = args.receipt.ecdsa_activation;
  return {
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_id: String(args.activationBinding.signer.walletId),
      ecdsa_threshold_key_id: String(args.activationBinding.roleLocalBinding.ecdsaThresholdKeyId),
      signing_root_id: String(args.activationBinding.signer.signingRootId),
      signing_root_version: String(args.activationBinding.signer.signingRootVersion),
      context: activation.context,
      public_identity: activation.public_identity,
      material_activation: activation.material_activation,
      signing_worker: activation.signing_worker,
      activation_epoch: activation.activation_epoch,
    },
  };
}

export function ecdsaCapabilityActivationFixture(args?: {
  authority?: WalletAuthAuthorityRef;
  manifestRevision?: number;
  walletId?: ReturnType<typeof walletIdFromString>;
  chainTarget?: ThresholdEcdsaChainTarget;
  targetMemberships?: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  keyHandle?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  ecdsaThresholdKeyId?: string;
  thresholdOwnerAddress?: string;
}): EcdsaCapabilityActivationFixture {
  const walletId = args?.walletId ?? walletIdFromString('ecdsa-manifest-fixture-wallet');
  const authority: WalletAuthAuthorityRef = args?.authority ?? {
    kind: 'wallet_auth_authority_ref',
    walletId,
    authorityDigest: unwrap(parseWalletAuthorityBindingDigest('authority-fixture')),
  };
  const roleLocalBinding = buildEcdsaRoleLocalMaterialBinding({
    keyHandle: parseEcdsaKeyHandle(args?.keyHandle ?? 'ecdsa-key-handle-fixture'),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(
      args?.ecdsaThresholdKeyId ?? 'ecdsa-threshold-key-fixture',
    ),
    clientVerifyingPublicKey33B64u:
      parseEcdsaClientVerifyingPublicKey33B64u(CLIENT_PUBLIC_KEY_B64U),
    participantIds: [toParticipantId(1), toParticipantId(2)],
    relayerKeyId: parseEcdsaRelayerKeyId('relayer-key-fixture'),
  });
  const activationBinding = buildEcdsaActivationBinding({
    targetManifest: buildEcdsaManifestIdentity({
      manifestId: parseEcdsaCapabilityManifestId('ecdsa-manifest-fixture'),
      manifestRevision: parseEcdsaCapabilityManifestRevision(args?.manifestRevision ?? 1),
    }),
    signer: buildPreparedEvmFamilySigner({
      capability: unwrap(parseCapabilityInstanceRef('ecdsa-capability-fixture')),
      signerId: parseEvmFamilyEcdsaSignerId('ecdsa-signer-fixture'),
      authority,
      scope: buildEcdsaCapabilityScope({
        targetMemberships: args?.targetMemberships ?? [
          args?.chainTarget ?? {
            kind: 'evm',
            namespace: 'eip155',
            chainId: 1,
            networkSlug: 'ethereum',
          },
        ],
      }),
      materialOwner: unwrap(parseMpcMaterialOwnerRef(String(walletId))),
      signingRootId: parseSdkEcdsaDerivationSigningRootId(args?.signingRootId ?? 'fixture:dev'),
      signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(
        args?.signingRootVersion ?? 'v1',
      ),
    }),
    roleLocalBinding,
    bindingDigest: parseEcdsaRoleLocalBindingDigest(CONTEXT_BINDING_B64U),
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef('ecdsa-material-fixture'),
  });
  const journalId = parseCorrelationId('ecdsa-activation-correlation-fixture');
  const requestDigest = parseDigestB64u(DIGEST_B64U);
  const serverGeneration = parseEcdsaServerGeneration('ecdsa-server-generation-fixture');
  const protocolReceipt: RouterAbEcdsaRegistrationActivationReceiptV1 = {
    activation_correlation_id: journalId,
    activation_request_digest: { bytes: new Array<number>(32).fill(12) },
    server_generation: serverGeneration,
    ecdsa_activation: {
      context: { application_binding_digest_b64u: APPLICATION_BINDING_DIGEST_B64U },
      public_identity: {
        context_binding_b64u: CONTEXT_BINDING_B64U,
        derivation_client_share_public_key33_b64u: CLIENT_PUBLIC_KEY_B64U,
        server_public_key33_b64u: SERVER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: GROUP_PUBLIC_KEY_B64U,
        ethereum_address20_b64u: base64UrlEncode(
          Uint8Array.from(
            Buffer.from(
              (args?.thresholdOwnerAddress ?? THRESHOLD_OWNER_ADDRESS).replace(/^0x/, ''),
              'hex',
            ),
          ),
        ),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-fixture',
        key_epoch: 'key-epoch-fixture',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      material_activation: {
        kind: 'mpc_material_activation_ref',
        activation_id: 'ecdsa-activation-fixture',
        capability: 'ecdsa-capability-fixture',
        material_owner: String(walletId),
        key_binding: CONTEXT_BINDING_B64U,
        lifecycle_binding: 'ecdsa-lifecycle-fixture',
        signing_worker: 'signing-worker-fixture',
      },
      activation_epoch: unwrap(parseRootShareEpoch('activation-epoch-fixture')),
      activation_digest_b64u: DIGEST_B64U,
      activated_at_ms: 1_753_574_400_000,
    },
    lifecycle_id: 'ecdsa-lifecycle-fixture',
    transcript_digest: { bytes: new Array<number>(32).fill(8) },
  };
  const pendingFixture = routerAbEcdsaRegistrationPendingFinalizationFixture();
  const publicCapability = buildRouterAbEcdsaDerivationPublicCapabilityV1({
    registrationFacts: pendingFixture.payload.registrationFacts,
    registrationRequest: pendingFixture.payload.registrationRequest,
    clientActivation: pendingFixture.payload.clientActivation,
    activationReceipt: protocolReceipt,
  });
  const roleLocalPublicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId,
    chainTarget: activationBinding.signer.scope.targetMemberships[0],
    keyHandle: roleLocalBinding.keyHandle,
    ecdsaThresholdKeyId: roleLocalBinding.ecdsaThresholdKeyId,
    signingRootId: activationBinding.signer.signingRootId,
    signingRootVersion: activationBinding.signer.signingRootVersion,
    applicationBindingDigestB64u: APPLICATION_BINDING_DIGEST_B64U,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    participantIds: [1, 2],
    contextBinding32B64u: CONTEXT_BINDING_B64U,
    derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
    relayerPublicKey33B64u: SERVER_PUBLIC_KEY_B64U,
    groupPublicKey33B64u: GROUP_PUBLIC_KEY_B64U,
    ethereumAddress: args?.thresholdOwnerAddress ?? THRESHOLD_OWNER_ADDRESS,
    publicCapability,
  });
  const routerAbEcdsaDerivationNormalSigning = normalSigningFixture({
    activationBinding,
    receipt: protocolReceipt,
  });
  return {
    prepareInput: {
      journalId,
      expectedManifest: buildNoCurrentEcdsaManifestExpectation(),
      expectedGeneration: buildNoCurrentEcdsaServerGenerationExpectation(),
      activationBinding,
      requestDigest,
      canonicalRequest: parseCanonicalEcdsaServerActivationRequest('{"kind":"fixture"}'),
      createdAt: parseIsoTimestamp('2026-07-27T00:00:00.000Z'),
      pendingPayloadB64u: pendingFixture.encoded,
    },
    serverCommit: {
      correlationId: journalId,
      activationRequestDigest: requestDigest,
      serverGeneration,
      protocolReceipt,
    },
    sealInput: {
      readyStateBlobB64u: fixtureStateBlob('ready-state-fixture'),
      registeredPublicFacts: buildVerifiedEcdsaPublicFacts({
        keyHandle: toEvmFamilyEcdsaKeyHandle(roleLocalBinding.keyHandle),
        publicKeyB64u: GROUP_PUBLIC_KEY_B64U,
        participantIds: roleLocalBinding.participantIds,
        thresholdOwnerAddress: args?.thresholdOwnerAddress ?? THRESHOLD_OWNER_ADDRESS,
      }),
      roleLocalPublicFacts,
      routerAbEcdsaDerivationNormalSigning,
      runtimePolicyScope: {
        orgId: 'fixture-org',
        projectId: (args?.signingRootId ?? 'fixture:dev').split(':')[0]!,
        envId: (args?.signingRootId ?? 'fixture:dev').split(':')[1]!,
        signingRootVersion: args?.signingRootVersion ?? 'v1',
      },
      committedAt: parseIsoTimestamp('2026-07-27T00:01:00.000Z'),
    },
    serverGeneration,
    differentPublicKeyB64u: SERVER_PUBLIC_KEY_B64U,
  };
}

export function ecdsaCapabilityReplacementFixture(): EcdsaCapabilityReplacementFixture {
  return buildEcdsaCapabilityReplacementFixture('matching_generation');
}

export function ecdsaCapabilityGenerationMismatchReplacementFixture(): EcdsaCapabilityReplacementFixture {
  return buildEcdsaCapabilityReplacementFixture('mismatched_generation');
}

function activeLookupFromFixture(
  fixture: EcdsaCapabilityActivationFixture,
): Extract<EcdsaCapabilityManifestLookup, { readonly kind: 'active' }> {
  const serverActivation = buildEcdsaServerActivationCommit({
    activationBinding: fixture.prepareInput.activationBinding,
    serverCommit: fixture.serverCommit,
  });
  const durableMaterial = buildDurableEcdsaMaterialBinding({
    activationBinding: fixture.prepareInput.activationBinding,
    serverActivation,
    routerAbEcdsaDerivationNormalSigning: fixture.sealInput.routerAbEcdsaDerivationNormalSigning,
    roleLocalPublicFacts: fixture.sealInput.roleLocalPublicFacts,
    ciphertextDigest: parseEcdsaCiphertextDigest(DIGEST_B64U),
    runtimePolicyScope: fixture.sealInput.runtimePolicyScope,
  });
  return {
    kind: 'active',
    manifest: buildActiveEcdsaCapabilityManifest({
      activationBinding: fixture.prepareInput.activationBinding,
      serverActivation,
      registeredPublicFacts: fixture.sealInput.registeredPublicFacts,
      durableMaterial,
      committedAt: fixture.sealInput.committedAt,
    }),
    material: buildValidatedEncryptedEcdsaReadyMaterial({
      binding: durableMaterial,
      sealingKeyId: parseEcdsaMaterialSealingKeyId('ecdsa-sealing-key-fixture'),
      iv12B64u: parseEcdsaIv12B64u(base64UrlEncode(new Uint8Array(12).fill(4))),
      ciphertextB64u: parseEcdsaCiphertextB64u(base64UrlEncode(new Uint8Array(32).fill(5))),
    }),
  };
}

/** The active lookup for a first activation, whose public capability is built
 * from its own activation receipt.
 *
 * Prefer this for anything that exercises the signing path.
 * `ecdsaCapabilityHydrationLookupFixture().active` is the *replacement*
 * manifest, which inherits the prior registration's public capability and so
 * names a different signing worker than its own material activation. That is
 * harmless for lookup and selection tests, but production refuses to prepare an
 * operation step-up against a manifest whose scope and activation disagree on
 * the signing worker. */
export function ecdsaCapabilityActivationLookupFixture(args?: {
  authority?: WalletAuthAuthorityRef;
  manifestRevision?: number;
  walletId?: ReturnType<typeof walletIdFromString>;
  chainTarget?: ThresholdEcdsaChainTarget;
  targetMemberships?: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  keyHandle?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  ecdsaThresholdKeyId?: string;
  thresholdOwnerAddress?: string;
}): Extract<EcdsaCapabilityManifestLookup, { readonly kind: 'active' }> {
  return activeLookupFromFixture(ecdsaCapabilityActivationFixture(args));
}

export async function canonicalEvmFamilyEcdsaSigningCapabilityFixture(
  factor: 'passkey' | 'email_otp',
  overrides?: {
    walletId?: ReturnType<typeof walletIdFromString>;
    chainTarget?: ThresholdEcdsaChainTarget;
    targetMemberships?: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
    keyHandle?: string;
    signingRootId?: string;
    signingRootVersion?: string;
  },
): Promise<{
  readonly authority: WalletAuthAuthority;
  readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
  readonly manifest: ActiveEcdsaCapabilityManifest;
}> {
  const walletId = overrides?.walletId ?? walletIdFromString('ecdsa-manifest-fixture-wallet');
  const authority =
    factor === 'passkey'
      ? buildPasskeyWalletAuthAuthority({
          walletId,
          rpId: 'example.localhost',
          credentialIdB64u: 'credential-passkey-fixture',
        })
      : buildEmailOtpWalletAuthAuthority({
          walletId,
          provider: 'google',
          providerUserId: `google:${String(walletId)}`,
          emailHashHex: 'email-hash',
        });
  const authorityRef = await walletAuthAuthorityRef({ authority });
  const lookup = activeLookupFromFixture(
    ecdsaCapabilityActivationFixture({ authority: authorityRef, ...overrides }),
  );
  const manifest = lookup.manifest;
  const material = buildPersistedEcdsaRoleLocalMaterial({
    authority: manifest.signer.authority,
    materialActivation: manifest.durableMaterial.materialActivation,
    publicFacts: manifest.durableMaterial.roleLocalPublicFacts,
  });
  return {
    authority,
    manifest,
    capability: await buildCanonicalEvmFamilyEcdsaSigningCapability({
      authority,
      manifest,
      material,
    }),
  };
}

export function ecdsaWalletSessionRefFixture(
  manifest: ActiveEcdsaCapabilityManifest,
): WalletSessionRef {
  return walletSessionRefFixture(manifest.signer.walletId);
}

export function walletSessionRefFixture(walletId: unknown): WalletSessionRef {
  return {
    walletId: walletIdFromString(String(walletId)),
    walletSessionUserId: 'ecdsa-fixture-wallet-session-user',
  };
}

export function ecdsaCapabilityHydrationLookupFixture(): EcdsaCapabilityHydrationLookupFixture {
  const replacement = ecdsaCapabilityReplacementFixture();
  const activePrior = activeLookupFromFixture(replacement.prior);
  const activeReplacement = activeLookupFromFixture(replacement.replacement);
  const selectors = ecdsaCapabilityLookupOutcomeFixture().selectors;
  return {
    active: activeReplacement,
    retired: {
      kind: 'retired',
      manifest: buildReplacedEcdsaCapabilityManifest({
        activeManifest: activePrior.manifest,
        replacementManifest: activeReplacement.manifest,
      }),
    },
    selectors,
  };
}

export function ecdsaCapabilityLookupOutcomeFixture(): EcdsaCapabilityLookupOutcomeFixture {
  const replacement = ecdsaCapabilityReplacementFixture();
  const signer = replacement.prior.prepareInput.activationBinding.signer;
  return {
    replacement,
    selectors: {
      active: {
        capability: signer.capability,
        authority: signer.authority,
      },
      missing: {
        capability: unwrap(parseCapabilityInstanceRef('ecdsa-capability-missing-fixture')),
        authority: signer.authority,
      },
      exactBindingMismatch: {
        capability: signer.capability,
        authority: {
          kind: 'wallet_auth_authority_ref',
          walletId: signer.authority.walletId,
          authorityDigest: unwrap(parseWalletAuthorityBindingDigest('authority-mismatch-fixture')),
        },
      },
    },
  };
}

function buildEcdsaCapabilityReplacementFixture(
  generationExpectation: 'matching_generation' | 'mismatched_generation',
): EcdsaCapabilityReplacementFixture {
  const prior = ecdsaCapabilityActivationFixture();
  const priorSigner = prior.prepareInput.activationBinding.signer;
  const roleLocalBinding = buildEcdsaRoleLocalMaterialBinding({
    keyHandle: parseEcdsaKeyHandle('ecdsa-key-handle-replacement-fixture'),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ecdsa-threshold-key-replacement-fixture'),
    clientVerifyingPublicKey33B64u: parseEcdsaClientVerifyingPublicKey33B64u(
      REPLACEMENT_CLIENT_PUBLIC_KEY_B64U,
    ),
    participantIds: [toParticipantId(1), toParticipantId(2)],
    relayerKeyId: parseEcdsaRelayerKeyId('relayer-key-replacement-fixture'),
  });
  const activationBinding = buildEcdsaActivationBinding({
    targetManifest: buildEcdsaManifestIdentity({
      manifestId: parseEcdsaCapabilityManifestId('ecdsa-manifest-replacement-fixture'),
      manifestRevision: parseEcdsaCapabilityManifestRevision(2),
    }),
    signer: buildPreparedEvmFamilySigner({
      capability: priorSigner.capability,
      signerId: priorSigner.signerId,
      authority: priorSigner.authority,
      scope: priorSigner.scope,
      materialOwner: priorSigner.materialOwner,
      signingRootId: priorSigner.signingRootId,
      signingRootVersion: priorSigner.signingRootVersion,
    }),
    roleLocalBinding,
    bindingDigest: parseEcdsaRoleLocalBindingDigest(REPLACEMENT_DIGEST_B64U),
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef('ecdsa-material-replacement-fixture'),
  });
  const journalId = parseCorrelationId('ecdsa-activation-correlation-replacement-fixture');
  const requestDigest = parseDigestB64u(REPLACEMENT_DIGEST_B64U);
  const serverGeneration = parseEcdsaServerGeneration(
    'ecdsa-server-generation-replacement-fixture',
  );
  const protocolReceipt: RouterAbEcdsaRegistrationActivationReceiptV1 = {
    activation_correlation_id: journalId,
    activation_request_digest: { bytes: new Array<number>(32).fill(13) },
    server_generation: serverGeneration,
    ecdsa_activation: {
      context: { application_binding_digest_b64u: REPLACEMENT_DIGEST_B64U },
      public_identity: {
        context_binding_b64u: REPLACEMENT_DIGEST_B64U,
        derivation_client_share_public_key33_b64u: REPLACEMENT_CLIENT_PUBLIC_KEY_B64U,
        server_public_key33_b64u: REPLACEMENT_SERVER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: REPLACEMENT_CLIENT_PUBLIC_KEY_B64U,
        ethereum_address20_b64u: base64UrlEncode(new Uint8Array(20).fill(15)),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-replacement-fixture',
        key_epoch: 'key-epoch-replacement-fixture',
        recipient_encryption_key:
          'x25519:2222222222222222222222222222222222222222222222222222222222222222',
      },
      material_activation: {
        kind: 'mpc_material_activation_ref',
        activation_id: 'ecdsa-activation-replacement-fixture',
        capability: 'ecdsa-capability-fixture',
        material_owner: 'ecdsa-manifest-fixture-wallet',
        key_binding: REPLACEMENT_DIGEST_B64U,
        lifecycle_binding: 'ecdsa-lifecycle-replacement-fixture',
        signing_worker: 'signing-worker-replacement-fixture',
      },
      activation_epoch: unwrap(parseRootShareEpoch('activation-epoch-replacement-fixture')),
      activation_digest_b64u: REPLACEMENT_DIGEST_B64U,
      activated_at_ms: 1_753_578_000_000,
    },
    lifecycle_id: 'ecdsa-lifecycle-replacement-fixture',
    transcript_digest: { bytes: new Array<number>(32).fill(16) },
  };
  return {
    prior,
    replacement: {
      prepareInput: {
        journalId,
        expectedManifest: buildExactEcdsaManifestExpectation(
          prior.prepareInput.activationBinding.targetManifest,
        ),
        expectedGeneration: buildExactEcdsaServerGenerationExpectation(
          generationExpectation === 'matching_generation'
            ? prior.serverGeneration
            : parseEcdsaServerGeneration('ecdsa-server-generation-stale-fixture'),
        ),
        activationBinding,
        requestDigest,
        canonicalRequest: parseCanonicalEcdsaServerActivationRequest(
          '{"kind":"replacement-fixture"}',
        ),
        createdAt: parseIsoTimestamp('2026-07-27T01:00:00.000Z'),
        pendingPayloadB64u: fixtureStateBlob('pending-state-replacement-fixture'),
      },
      serverCommit: {
        correlationId: journalId,
        activationRequestDigest: requestDigest,
        serverGeneration,
        protocolReceipt,
      },
      sealInput: {
        readyStateBlobB64u: fixtureStateBlob('ready-state-replacement-fixture'),
        registeredPublicFacts: buildVerifiedEcdsaPublicFacts({
          keyHandle: toEvmFamilyEcdsaKeyHandle(roleLocalBinding.keyHandle),
          publicKeyB64u: REPLACEMENT_CLIENT_PUBLIC_KEY_B64U,
          participantIds: roleLocalBinding.participantIds,
          thresholdOwnerAddress: '0x2222222222222222222222222222222222222222',
        }),
        roleLocalPublicFacts: buildEcdsaRoleLocalPublicFacts({
          ...prior.sealInput.roleLocalPublicFacts,
          keyHandle: roleLocalBinding.keyHandle,
          ecdsaThresholdKeyId: roleLocalBinding.ecdsaThresholdKeyId,
          contextBinding32B64u: REPLACEMENT_DIGEST_B64U,
          derivationClientSharePublicKey33B64u: REPLACEMENT_CLIENT_PUBLIC_KEY_B64U,
          relayerPublicKey33B64u: REPLACEMENT_SERVER_PUBLIC_KEY_B64U,
          groupPublicKey33B64u: REPLACEMENT_CLIENT_PUBLIC_KEY_B64U,
          ethereumAddress: '0x2222222222222222222222222222222222222222',
        }),
        routerAbEcdsaDerivationNormalSigning: normalSigningFixture({
          activationBinding,
          receipt: protocolReceipt,
        }),
        runtimePolicyScope: prior.sealInput.runtimePolicyScope,
        committedAt: parseIsoTimestamp('2026-07-27T01:01:00.000Z'),
      },
      serverGeneration,
      differentPublicKeyB64u: CLIENT_PUBLIC_KEY_B64U,
    },
  };
}

/** An active reusable Wallet Session authorizing the fixture manifest's wallet.
 * Authorization is the independent second proof, so it is built separately from
 * the manifest rather than derived from it -- only the wallet and authority are
 * shared, which is exactly what the two halves must agree on. */
export function activeEvmFamilyWalletSessionAuthorizationFixture(args: {
  /** Either supply the manifest this authorization pairs with, or the wallet
   * and authority directly for callers that have no manifest. Only those two
   * facts are shared between the halves. */
  manifest?: ActiveEcdsaCapabilityManifest;
  walletId?: ActiveEcdsaCapabilityManifest['signer']['walletId'];
  authority?: ActiveEcdsaCapabilityManifest['signer']['authority'];
  walletSessionId?: string;
  quotaId?: string;
  walletSessionJwt?: string;
  authMethod?: 'passkey' | 'email_otp';
  expiresAtMs?: number;
  remainingUses?: number;
}): ActiveEvmFamilyWalletSessionAuthorization {
  const walletId = args.walletId ?? args.manifest?.signer.walletId;
  const authority = args.authority ?? args.manifest?.signer.authority;
  if (!walletId || !authority) {
    throw new Error('[fixture] authorization requires a manifest or walletId + authority');
  }
  const signer = { walletId, authority };
  const walletSessionId = requireFixtureId(
    parseWalletSessionId(args.walletSessionId || 'ecdsa-fixture-wallet-session'),
    'walletSessionId',
  );
  const quotaId = requireFixtureId(
    parseMpcWalletSigningQuotaId(args.quotaId || 'ecdsa-fixture-quota'),
    'quotaId',
  );
  const seamsSessionId = requireFixtureId(
    parseSeamsSessionId('ecdsa-fixture-authorization-session'),
    'authorizationSessionId',
  );
  const authorizationId = requireFixtureId(
    parseWalletSessionAuthorizationId('ecdsa-fixture-authorization'),
    'authorizationId',
  );
  const expiresAtMs = args.expiresAtMs ?? 1_900_000_000_000;
  const remainingUses = args.remainingUses ?? 5;
  const walletSessionJwt =
    args.walletSessionJwt ??
    [
      base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: 'none', typ: 'JWT' }))),
      base64UrlEncode(
        new TextEncoder().encode(
          JSON.stringify({
            kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
            authorizationKind: 'owner_wallet_session',
            sub: String(walletId),
            walletId: String(walletId),
            authorizationId,
            authorizationSessionId: seamsSessionId,
            sid: seamsSessionId,
            walletSessionId,
            quotaId,
            thresholdExpiresAtMs: expiresAtMs,
            exp: Math.floor(expiresAtMs / 1_000),
          }),
        ),
      ),
      'fixture',
    ].join('.');
  return {
    kind: 'active_reusable_wallet_session_authorization',
    projection: buildActiveWalletSessionAuthorizationProjection({
      walletId: signer.walletId,
      seamsSessionId,
      authorizationId,
      walletSessionId,
      quotaId,
      authMethod: args.authMethod ?? 'passkey',
      authority: signer.authority,
      expiresAtMs,
      walletSessionTokens: {
        kind: 'evm_family_ecdsa',
        ecdsa: { walletSessionJwt },
      },
    }),
    status: {
      walletSessionId,
      quotaId,
      status: 'active',
      remainingUses,
      expiresAtMs,
    },
  };
}

function requireFixtureId<T>(result: { ok: true; value: T } | { ok: false }, label: string): T {
  if (!result.ok) throw new Error(`[fixture] invalid ${label}`);
  return result.value;
}
