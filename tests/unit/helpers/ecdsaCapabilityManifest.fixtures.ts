import {
  buildEcdsaActivationBinding,
  buildEcdsaCapabilityScope,
  buildEcdsaManifestIdentity,
  buildEcdsaRoleLocalMaterialBinding,
  buildEncryptedEcdsaPendingCandidate,
  buildNoCurrentEcdsaManifestExpectation,
  buildNoCurrentEcdsaServerGenerationExpectation,
  buildPreparedEcdsaActivationCandidate,
  buildPreparedEcdsaActivationJournal,
  buildPreparedEvmFamilySigner,
  type PreparedEcdsaActivationJournal,
} from '@/core/signingEngine/session/material/ecdsaCapabilityManifest';
import {
  parseEcdsaClientVerifyingPublicKey33B64u,
  parseEcdsaKeyHandle,
  parseEcdsaRelayerKeyId,
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaThresholdKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';
import { toParticipantId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
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

function unwrap<T>(result: DomainIdParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export type EcdsaCapabilityActivationFixture = {
  readonly preparedJournal: PreparedEcdsaActivationJournal;
  readonly protocolReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
  readonly requestDigest: ReturnType<typeof parseDigestB64u>;
  readonly serverGeneration: ReturnType<typeof parseEcdsaServerGeneration>;
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
  return {
    preparedJournal,
    requestDigest,
    serverGeneration,
    protocolReceipt: {
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
    },
  };
}
