import {
  buildEcdsaActivationBinding,
  buildActiveEcdsaCapabilityManifest,
  buildEcdsaCapabilityScope,
  buildDurableEcdsaMaterialBinding,
  buildEcdsaManifestIdentity,
  buildEcdsaRoleLocalMaterialBinding,
  buildEncryptedEcdsaPendingCandidate,
  buildExactEcdsaManifestExpectation,
  buildExactEcdsaServerGenerationExpectation,
  buildNoCurrentEcdsaManifestExpectation,
  buildNoCurrentEcdsaServerGenerationExpectation,
  buildPreparedEcdsaActivationCandidate,
  buildPreparedEcdsaActivationJournal,
  buildPreparedEvmFamilySigner,
  buildServerCommittedEcdsaActivationJournal,
  buildValidatedEncryptedEcdsaReadyMaterial,
  type ActiveEcdsaCapabilityManifest,
  type PreparedEcdsaActivationJournal,
  type ServerCommittedEcdsaActivationJournal,
  type ValidatedEncryptedEcdsaReadyMaterial,
} from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import {
  parseEcdsaClientVerifyingPublicKey33B64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaThresholdKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  buildVerifiedEcdsaPublicFacts,
  toEvmFamilyEcdsaKeyHandle,
  toParticipantId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
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
  parseEcdsaCiphertextB64u,
  parseEcdsaCiphertextDigest,
  parseEcdsaIv12B64u,
  parseEcdsaMaterialSealingKeyId,
  parseEcdsaPendingCiphertextDigest,
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
  readonly preparedJournal: PreparedEcdsaActivationJournal;
  readonly committedJournal: ServerCommittedEcdsaActivationJournal;
  readonly readyMaterial: ValidatedEncryptedEcdsaReadyMaterial;
  readonly activeManifest: ActiveEcdsaCapabilityManifest;
  readonly protocolReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly requestDigest: ReturnType<typeof parseDigestB64u>;
  readonly serverGeneration: ReturnType<typeof parseEcdsaServerGeneration>;
};

export type EcdsaCapabilityReplacementFixture = {
  readonly prior: EcdsaCapabilityActivationFixture;
  readonly replacement: EcdsaCapabilityActivationFixture;
};

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
  const preparedSigner = buildPreparedEvmFamilySigner({
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
  });
  const activationBinding = buildEcdsaActivationBinding({
    targetManifest: buildEcdsaManifestIdentity({
      manifestId: parseEcdsaCapabilityManifestId('ecdsa-manifest-fixture'),
      manifestRevision: parseEcdsaCapabilityManifestRevision(1),
    }),
    signer: preparedSigner,
    activationId: unwrap(parseMpcMaterialActivationId('ecdsa-activation-fixture')),
    roleLocalBinding,
    bindingDigest: parseEcdsaRoleLocalBindingDigest(DIGEST_B64U),
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef('ecdsa-material-fixture'),
  });
  const requestDigest = parseDigestB64u(DIGEST_B64U);
  const preparedJournal = buildPreparedEcdsaActivationJournal({
    journalId: parseCorrelationId('ecdsa-activation-correlation-fixture'),
    expectedManifest: buildNoCurrentEcdsaManifestExpectation(),
    expectedGeneration: buildNoCurrentEcdsaServerGenerationExpectation(),
    candidate: buildPreparedEcdsaActivationCandidate({
      activationBinding,
      encryptedPending: buildEncryptedEcdsaPendingCandidate({
        sealingKeyId: parseEcdsaMaterialSealingKeyId('ecdsa-sealing-key-fixture'),
        iv12B64u: parseEcdsaIv12B64u(base64UrlEncode(new Uint8Array(12).fill(3))),
        ciphertextB64u: parseEcdsaCiphertextB64u(base64UrlEncode(new Uint8Array([4, 5, 6]))),
        ciphertextDigest: parseEcdsaPendingCiphertextDigest(DIGEST_B64U),
      }),
    }),
    requestDigest,
    canonicalRequest: parseCanonicalEcdsaServerActivationRequest('{"kind":"fixture"}'),
    createdAt: parseIsoTimestamp('2026-07-27T00:00:00.000Z'),
  });
  const serverGeneration = parseEcdsaServerGeneration('ecdsa-server-generation-fixture');
  const protocolReceipt: RouterAbEcdsaRegistrationActivationReceiptV1 = {
    activation_correlation_id: preparedJournal.journalId,
    activation_request_digest: { bytes: new Array<number>(32).fill(12) },
    server_generation: serverGeneration,
    ecdsa_activation: {
      context: {
        application_binding_digest_b64u: DIGEST_B64U,
      },
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
  const committedJournal = buildServerCommittedEcdsaActivationJournal({
    preparedJournal,
    serverCommit: {
      correlationId: preparedJournal.journalId,
      activationRequestDigest: requestDigest,
      serverGeneration,
      protocolReceipt,
    },
  });
  const durableMaterial = buildDurableEcdsaMaterialBinding({
    activationBinding,
    serverActivation: committedJournal.serverActivation,
    ciphertextDigest: parseEcdsaCiphertextDigest(DIGEST_B64U),
  });
  const readyMaterial = buildValidatedEncryptedEcdsaReadyMaterial({
    binding: durableMaterial,
    sealingKeyId: preparedJournal.candidate.encryptedPending.sealingKeyId,
    iv12B64u: preparedJournal.candidate.encryptedPending.iv12B64u,
    ciphertextB64u: preparedJournal.candidate.encryptedPending.ciphertextB64u,
  });
  const activeManifest = buildActiveEcdsaCapabilityManifest({
    activationBinding,
    serverActivation: committedJournal.serverActivation,
    registeredPublicFacts: buildVerifiedEcdsaPublicFacts({
      keyHandle: toEvmFamilyEcdsaKeyHandle(roleLocalBinding.keyHandle),
      publicKeyB64u: CLIENT_PUBLIC_KEY_B64U,
      participantIds: roleLocalBinding.participantIds,
      thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
    }),
    durableMaterial,
    committedAt: parseIsoTimestamp('2026-07-27T00:01:00.000Z'),
  });
  return {
    preparedJournal,
    committedJournal,
    readyMaterial,
    activeManifest,
    requestDigest,
    serverGeneration,
    protocolReceipt,
  };
}

export function ecdsaCapabilityReplacementFixture(): EcdsaCapabilityReplacementFixture {
  return buildEcdsaCapabilityReplacementFixture('matching_generation');
}

export function ecdsaCapabilityGenerationMismatchReplacementFixture(): EcdsaCapabilityReplacementFixture {
  return buildEcdsaCapabilityReplacementFixture('mismatched_generation');
}

function buildEcdsaCapabilityReplacementFixture(
  generationExpectation: 'matching_generation' | 'mismatched_generation',
): EcdsaCapabilityReplacementFixture {
  const prior = ecdsaCapabilityActivationFixture();
  const priorSigner = prior.activeManifest.signer;
  const roleLocalBinding = buildEcdsaRoleLocalMaterialBinding({
    keyHandle: parseEcdsaKeyHandle('ecdsa-key-handle-replacement-fixture'),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId('ecdsa-threshold-key-replacement-fixture'),
    clientVerifyingPublicKey33B64u: parseEcdsaClientVerifyingPublicKey33B64u(
      REPLACEMENT_CLIENT_PUBLIC_KEY_B64U,
    ),
    participantIds: [toParticipantId(1)],
    relayerKeyId: parseEcdsaRelayerKeyId('relayer-key-replacement-fixture'),
  });
  const preparedSigner = buildPreparedEvmFamilySigner({
    capability: priorSigner.capability,
    signerId: priorSigner.signerId,
    authority: priorSigner.authority,
    scope: priorSigner.scope,
    materialOwner: priorSigner.materialOwner,
    signingRootId: priorSigner.signingRootId,
    signingRootVersion: priorSigner.signingRootVersion,
  });
  const activationBinding = buildEcdsaActivationBinding({
    targetManifest: buildEcdsaManifestIdentity({
      manifestId: parseEcdsaCapabilityManifestId('ecdsa-manifest-replacement-fixture'),
      manifestRevision: parseEcdsaCapabilityManifestRevision(2),
    }),
    signer: preparedSigner,
    activationId: unwrap(parseMpcMaterialActivationId('ecdsa-activation-replacement-fixture')),
    roleLocalBinding,
    bindingDigest: parseEcdsaRoleLocalBindingDigest(REPLACEMENT_DIGEST_B64U),
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef('ecdsa-material-replacement-fixture'),
  });
  const requestDigest = parseDigestB64u(REPLACEMENT_DIGEST_B64U);
  const preparedJournal = buildPreparedEcdsaActivationJournal({
    journalId: parseCorrelationId('ecdsa-activation-correlation-replacement-fixture'),
    expectedManifest: buildExactEcdsaManifestExpectation(prior.activeManifest.identity),
    expectedGeneration: buildExactEcdsaServerGenerationExpectation(
      generationExpectation === 'matching_generation'
        ? prior.serverGeneration
        : parseEcdsaServerGeneration('ecdsa-server-generation-stale-fixture'),
    ),
    candidate: buildPreparedEcdsaActivationCandidate({
      activationBinding,
      encryptedPending: buildEncryptedEcdsaPendingCandidate({
        sealingKeyId: parseEcdsaMaterialSealingKeyId('ecdsa-sealing-key-replacement-fixture'),
        iv12B64u: parseEcdsaIv12B64u(base64UrlEncode(new Uint8Array(12).fill(11))),
        ciphertextB64u: parseEcdsaCiphertextB64u(base64UrlEncode(new Uint8Array([12, 13, 14]))),
        ciphertextDigest: parseEcdsaPendingCiphertextDigest(REPLACEMENT_DIGEST_B64U),
      }),
    }),
    requestDigest,
    canonicalRequest: parseCanonicalEcdsaServerActivationRequest('{"kind":"replacement-fixture"}'),
    createdAt: parseIsoTimestamp('2026-07-27T01:00:00.000Z'),
  });
  const serverGeneration = parseEcdsaServerGeneration(
    'ecdsa-server-generation-replacement-fixture',
  );
  const protocolReceipt: RouterAbEcdsaRegistrationActivationReceiptV1 = {
    activation_correlation_id: preparedJournal.journalId,
    activation_request_digest: { bytes: new Array<number>(32).fill(13) },
    server_generation: serverGeneration,
    ecdsa_activation: {
      context: {
        application_binding_digest_b64u: REPLACEMENT_DIGEST_B64U,
      },
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
  const committedJournal = buildServerCommittedEcdsaActivationJournal({
    preparedJournal,
    serverCommit: {
      correlationId: preparedJournal.journalId,
      activationRequestDigest: requestDigest,
      serverGeneration,
      protocolReceipt,
    },
  });
  const durableMaterial = buildDurableEcdsaMaterialBinding({
    activationBinding,
    serverActivation: committedJournal.serverActivation,
    ciphertextDigest: parseEcdsaCiphertextDigest(REPLACEMENT_DIGEST_B64U),
  });
  const readyMaterial = buildValidatedEncryptedEcdsaReadyMaterial({
    binding: durableMaterial,
    sealingKeyId: preparedJournal.candidate.encryptedPending.sealingKeyId,
    iv12B64u: preparedJournal.candidate.encryptedPending.iv12B64u,
    ciphertextB64u: preparedJournal.candidate.encryptedPending.ciphertextB64u,
  });
  const activeManifest = buildActiveEcdsaCapabilityManifest({
    activationBinding,
    serverActivation: committedJournal.serverActivation,
    registeredPublicFacts: buildVerifiedEcdsaPublicFacts({
      keyHandle: toEvmFamilyEcdsaKeyHandle(roleLocalBinding.keyHandle),
      publicKeyB64u: REPLACEMENT_CLIENT_PUBLIC_KEY_B64U,
      participantIds: roleLocalBinding.participantIds,
      thresholdOwnerAddress: '0x2222222222222222222222222222222222222222',
    }),
    durableMaterial,
    committedAt: parseIsoTimestamp('2026-07-27T01:01:00.000Z'),
  });

  return {
    prior,
    replacement: {
      preparedJournal,
      committedJournal,
      readyMaterial,
      activeManifest,
      requestDigest,
      serverGeneration,
      protocolReceipt,
    },
  };
}
