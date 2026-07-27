import type {
  EcdsaCapabilitySelector,
  PrepareEcdsaCapabilityActivationInput,
  SealEcdsaCapabilityActivationInput,
} from '@/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore';
import {
  buildEcdsaActivationBinding,
  buildEcdsaCapabilityScope,
  buildEcdsaManifestIdentity,
  buildEcdsaRoleLocalMaterialBinding,
  buildExactEcdsaManifestExpectation,
  buildExactEcdsaServerGenerationExpectation,
  buildNoCurrentEcdsaManifestExpectation,
  buildNoCurrentEcdsaServerGenerationExpectation,
  buildPreparedEvmFamilySigner,
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
import { base64UrlEncode } from '@shared/utils/base64';
import {
  parseCorrelationId,
  parseDigestB64u,
  parseIsoTimestamp,
} from '@shared/utils/canonicalPrimitives';
import {
  parseCanonicalEcdsaServerActivationRequest,
  parseEcdsaCapabilityManifestId,
  parseEcdsaCapabilityManifestRevision,
  parseEcdsaServerGeneration,
  parseEvmFamilyEcdsaSignerId,
} from '@shared/utils/ecdsaCapabilityActivation';
import {
  parseCapabilityInstanceRef,
  parseMpcMaterialActivationId,
  parseMpcMaterialOwnerRef,
  parseRootShareEpoch,
  parseWalletAuthorityBindingDigest,
  type DomainIdParseResult,
} from '@shared/utils/domainIds';
import type { RouterAbEcdsaRegistrationActivationReceiptV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { walletIdFromString } from '@shared/utils/registrationIntent';

const DIGEST_B64U = base64UrlEncode(new Uint8Array(32).fill(12));
const CLIENT_PUBLIC_KEY_B64U = base64UrlEncode(
  Uint8Array.from([2, ...new Array<number>(32).fill(1)]),
);
const SERVER_PUBLIC_KEY_B64U = base64UrlEncode(
  Uint8Array.from([3, ...new Array<number>(32).fill(2)]),
);
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

function fixtureStateBlob(label: string): string {
  return base64UrlEncode(new TextEncoder().encode(label));
}

export function ecdsaCapabilityActivationFixture(): EcdsaCapabilityActivationFixture {
  const walletId = walletIdFromString('ecdsa-manifest-fixture-wallet');
  const authority: WalletAuthAuthorityRef = {
    kind: 'wallet_auth_authority_ref',
    walletId,
    authorityDigest: unwrap(parseWalletAuthorityBindingDigest('authority-fixture')),
  };
  const roleLocalBinding = buildEcdsaRoleLocalMaterialBinding({
    keyHandle: parseEcdsaKeyHandle('ecdsa-key-handle-fixture'),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ecdsa-threshold-key-fixture'),
    clientVerifyingPublicKey33B64u:
      parseEcdsaClientVerifyingPublicKey33B64u(CLIENT_PUBLIC_KEY_B64U),
    participantIds: [toParticipantId(1)],
    relayerKeyId: parseEcdsaRelayerKeyId('relayer-key-fixture'),
  });
  const activationBinding = buildEcdsaActivationBinding({
    targetManifest: buildEcdsaManifestIdentity({
      manifestId: parseEcdsaCapabilityManifestId('ecdsa-manifest-fixture'),
      manifestRevision: parseEcdsaCapabilityManifestRevision(1),
    }),
    signer: buildPreparedEvmFamilySigner({
      capability: unwrap(parseCapabilityInstanceRef('ecdsa-capability-fixture')),
      signerId: parseEvmFamilyEcdsaSignerId('ecdsa-signer-fixture'),
      authority,
      scope: buildEcdsaCapabilityScope({
        targetMemberships: [
          {
            kind: 'evm',
            namespace: 'eip155',
            chainId: 1,
            networkSlug: 'ethereum',
          },
        ],
      }),
      materialOwner: unwrap(parseMpcMaterialOwnerRef('ecdsa-material-owner-fixture')),
      signingRootId: parseSdkEcdsaDerivationSigningRootId('signing-root-fixture'),
      signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion('v1'),
    }),
    activationId: unwrap(parseMpcMaterialActivationId('ecdsa-activation-fixture')),
    roleLocalBinding,
    bindingDigest: parseEcdsaRoleLocalBindingDigest(DIGEST_B64U),
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
      context: { application_binding_digest_b64u: DIGEST_B64U },
      public_identity: {
        context_binding_b64u: DIGEST_B64U,
        derivation_client_share_public_key33_b64u: CLIENT_PUBLIC_KEY_B64U,
        server_public_key33_b64u: SERVER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: CLIENT_PUBLIC_KEY_B64U,
        ethereum_address20_b64u: base64UrlEncode(new Uint8Array(20).fill(7)),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-fixture',
        key_epoch: 'key-epoch-fixture',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      activation_epoch: unwrap(parseRootShareEpoch('activation-epoch-fixture')),
      activation_digest_b64u: DIGEST_B64U,
      activated_at_ms: 1_753_574_400_000,
    },
    lifecycle_id: 'ecdsa-lifecycle-fixture',
    transcript_digest: { bytes: new Array<number>(32).fill(8) },
  };
  return {
    prepareInput: {
      journalId,
      expectedManifest: buildNoCurrentEcdsaManifestExpectation(),
      expectedGeneration: buildNoCurrentEcdsaServerGenerationExpectation(),
      activationBinding,
      requestDigest,
      canonicalRequest: parseCanonicalEcdsaServerActivationRequest('{"kind":"fixture"}'),
      createdAt: parseIsoTimestamp('2026-07-27T00:00:00.000Z'),
      pendingPayloadB64u: fixtureStateBlob('pending-state-fixture'),
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
        publicKeyB64u: CLIENT_PUBLIC_KEY_B64U,
        participantIds: roleLocalBinding.participantIds,
        thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
      }),
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
    participantIds: [toParticipantId(1)],
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
    activationId: unwrap(parseMpcMaterialActivationId('ecdsa-activation-replacement-fixture')),
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
        committedAt: parseIsoTimestamp('2026-07-27T01:01:00.000Z'),
      },
      serverGeneration,
      differentPublicKeyB64u: CLIENT_PUBLIC_KEY_B64U,
    },
  };
}
