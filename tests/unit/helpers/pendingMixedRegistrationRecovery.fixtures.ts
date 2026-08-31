import { buildPendingWalletRegistrationCommitV1 } from '@/core/indexedDB/pendingWalletRegistrationCommit';
import {
  parseWalletRegistrationFinalizeResponse,
  type WalletRegistrationNearProvisioningResponseV2,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  isMixedEcdsaRegistrationCommit,
  type PendingMixedEcdsaRegistrationCommit,
} from '@/SeamsWeb/operations/registration/pendingEcdsaRegistrationRecoveryValidation';
import { base58Encode } from '@shared/utils/base58';
import { base64UrlDecode } from '@shared/utils/base64';
import { deriveImplicitNearAccountIdFromEd25519PublicKey } from '@shared/utils/near';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { parseRegistrationEstablishedSessionResultV2 } from '@shared/utils/registrationEstablishedSession';
import { buildPendingEcdsaRegistrationRecoveryFixture } from './pendingEcdsaRegistrationRecovery.fixtures';
import { buildMixedActivationPublicationFixture } from './pendingWalletRegistrationPublication.fixtures';

function normalSigningState(signingWorkerId: string) {
  const parsed = parseRouterAbEd25519NormalSigningState({
    kind: 'router_ab_ed25519_normal_signing_v1',
    signingWorkerId,
  });
  if (!parsed) throw new Error('mixed recovery fixture normal-signing state is invalid');
  return parsed;
}

export async function buildPendingMixedRegistrationRecoveryFixture() {
  const ecdsa = await buildPendingEcdsaRegistrationRecoveryFixture();
  const mixedPublication = await buildMixedActivationPublicationFixture();
  if (!isMixedEcdsaRegistrationCommit(mixedPublication.input.pending)) {
    throw new Error('mixed recovery fixture source is not a mixed pending commit');
  }
  const sourceEd25519 = mixedPublication.input.pending.localMaterial.ed25519;
  const pendingCandidate = buildPendingWalletRegistrationCommitV1({
    ...ecdsa.pending,
    signerPlanKind: 'near_ed25519_and_evm_family_ecdsa',
    localMaterial: {
      keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
      custodyCommit: ecdsa.pending.localMaterial.custodyCommit,
      ecdsa: ecdsa.pending.localMaterial.ecdsa,
      ed25519: {
        ...sourceEd25519,
        custodyCommit: {
          ...sourceEd25519.custodyCommit,
          walletId: String(ecdsa.pending.walletId),
          registeredPublicKeyB64u: sourceEd25519.metadata.registeredPublicKeyB64u,
        },
      },
    },
  });
  if (!isMixedEcdsaRegistrationCommit(pendingCandidate)) {
    throw new Error('mixed recovery fixture did not build a mixed pending commit');
  }
  const pending: PendingMixedEcdsaRegistrationCommit = pendingCandidate;
  const activateResponse = {
    ...ecdsa.response,
    nearProvisioning: { status: 'near_pending' as const },
  };
  const initialSession = activateResponse.registrationEstablishedSession.session;
  if (initialSession.tokens.kind !== 'evm_family_ecdsa') {
    throw new Error('mixed recovery fixture has no initial ECDSA projection');
  }
  const metadata = pending.localMaterial.ed25519.metadata;
  const registeredPublicKeyBytes = base64UrlDecode(metadata.registeredPublicKeyB64u);
  if (registeredPublicKeyBytes.length !== 32) {
    throw new Error('mixed recovery fixture registered public key is invalid');
  }
  const registeredPublicKey = `ed25519:${base58Encode(registeredPublicKeyBytes)}`;
  const nearAccountId = deriveImplicitNearAccountIdFromEd25519PublicKey(registeredPublicKey);
  const ed25519Projection = {
    sessionKind: 'credential_free_projection_v2' as const,
    thresholdSessionId: 'threshold-ed25519:mixed-recovery',
    nearAccountId,
    nearEd25519SigningKeyId: metadata.nearEd25519SigningKeyId,
    runtimePolicyScope: {
      orgId: 'org:mixed-recovery',
      projectId: 'project:mixed-recovery',
      envId: 'env:mixed-recovery',
      signingRootVersion: 'root:mixed-recovery:v1',
    },
    materialActivation: metadata.materialActivation,
    routerAbNormalSigning: normalSigningState(metadata.signingWorkerId),
  };
  const sessionProjection = parseRegistrationEstablishedSessionResultV2({
    kind: 'already_committed',
    session: {
      ...initialSession,
      kind: 'registration_established_wallet_session_projection_v2',
      walletSession: {
        ...initialSession.walletSession,
        capabilitySubjects: [
          ...initialSession.walletSession.capabilitySubjects,
          {
            kind: 'sign',
            keyFamily: 'ed25519',
            materialActivation: metadata.materialActivation,
          },
        ],
      },
      tokens: {
        kind: 'near_ed25519_and_evm_family_ecdsa',
        ecdsa: initialSession.tokens.ecdsa,
        ed25519: ed25519Projection,
      },
    },
    next: 'unlock_exact_method',
  });
  if (!sessionProjection || sessionProjection.kind !== 'already_committed') {
    throw new Error('mixed recovery fixture final session projection is invalid');
  }
  const finalized = parseWalletRegistrationFinalizeResponse({
    expectedKind: 'near_ed25519',
    value: {
      ok: true,
      walletId: pending.walletId,
      authority: activateResponse.authority,
      foundingAuthority: activateResponse.foundingAuthority,
      foundingAuthMethod: activateResponse.foundingAuthMethod,
      walletCustody: {
        status: 'joined',
        keyManifestDigestB64u: pending.localMaterial.ed25519.custodyCommit.keyManifestDigestB64u,
      },
      custodyKeyManifestDigestB64u:
        pending.localMaterial.ed25519.custodyCommit.keyManifestDigestB64u,
      kind: 'near_ed25519',
      rpId: pending.auth.kind === 'passkey' ? pending.auth.rpId : undefined,
      authMethod: activateResponse.authMethod,
      authorityScope:
        pending.auth.kind === 'passkey'
          ? { kind: 'passkey_rp', rpId: pending.auth.rpId }
          : undefined,
      accountProvisioning: {
        kind: 'implicit_account',
        accountIdSource: 'ed25519_public_key',
      },
      resolvedAccount: {
        kind: 'implicit_account',
        nearAccountId,
        nearEd25519SigningKeyId: metadata.nearEd25519SigningKeyId,
      },
      ed25519: {
        signerSlot: metadata.signerSlot,
        nearAccountId,
        nearEd25519SigningKeyId: metadata.nearEd25519SigningKeyId,
        publicKey: registeredPublicKey,
        relayerKeyId: metadata.signingWorkerId,
        keyVersion: 'mixed-recovery-v1',
        recoveryExportCapable: true,
        participantIds: metadata.participantIds,
        thresholdSessionId: ed25519Projection.thresholdSessionId,
        runtimePolicyScope: ed25519Projection.runtimePolicyScope,
        routerAbNormalSigning: ed25519Projection.routerAbNormalSigning,
      },
    },
  });
  if (finalized.kind !== 'near_ed25519') {
    throw new Error('mixed recovery fixture final response is not NEAR');
  }
  const nearResponse: WalletRegistrationNearProvisioningResponseV2 = {
    ...finalized,
    nearProvisioning: { status: 'near_ready' },
    registrationEstablishedSession: sessionProjection,
  };
  return {
    pending,
    activateResponse,
    nearResponse,
    unlock: ecdsa.unlock,
    exactMethod: ecdsa.exactMethod,
  };
}
