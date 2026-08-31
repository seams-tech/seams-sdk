import { isEcdsaRegistrationCommit } from '../../../packages/wallet/src/SeamsWeb/operations/registration/pendingRegistrationRecovery';
import type {
  PendingEcdsaOnlyRegistrationCommit,
  PendingEcdsaRegistrationUnlockInput,
  PendingEcdsaRegistrationUnlockMaterial,
} from '../../../packages/wallet/src/SeamsWeb/operations/registration/pendingEcdsaRegistrationRecoveryValidation';
import { buildPendingWalletRegistrationCommitV1 } from '../../../packages/wallet/src/core/indexedDB/pendingWalletRegistrationCommit';
import type { WalletRegistrationActivateResponseV2 } from '../../../packages/wallet/src/core/rpcClients/relayer/walletRegistration';
import {
  buildActiveWalletAuthorityV1,
  buildWalletSignerActivationSetV1,
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
} from '@shared/authorization/walletAuthority';
import { buildFullOwnerPermissionsV1 } from '@shared/authorization/delegatedAuthority';
import { buildExactAdministeredSignerManifestV1 } from '@shared/device-linking/delegatedActivationPlan';
import { parseSecp256k1CompressedPublicKeyB64u } from '@shared/passkey-custody/primitives';
import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking/parsers';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  parseEcdsaAuthorizationSessionId,
  parsePrincipalId,
  parseTenantId,
} from '@shared/authorization/capabilityKinds';
import {
  parseRouterAbEcdsaRegistrationActivationReceiptV1,
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  parseRouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256HexUtf8 } from '@shared/utils/digests';
import {
  parseEmailOtpChallengeId,
  parseThresholdEcdsaSessionId,
  parseWalletId,
  parseWalletKeyId,
  parseVerifiedEmailAddress,
} from '@shared/utils/domainIds';
import { parseRegistrationEstablishedSessionResultV2 } from '@shared/utils/registrationEstablishedSession';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { parseThresholdEcdsaDerivationRoleLocalBootstrapValue } from '../../../packages/wallet/src/core/rpcClients/relayer/thresholdEcdsa';
import { projectActiveWalletSession } from '../../../packages/wallet-server/src/authorization/domain';
import { ecdsaCapabilityActivationFixture } from './ecdsaCapabilityManifest.fixtures';
import { buildExactWalletSessionAuthorizationFixture } from './exactWalletSessionAuthorization.fixtures';
import { buildEmailOtpEcdsaWalletSessionFixture } from './linkedDeviceManagement.fixtures';
import { buildEcdsaActivationPublicationFixture } from './pendingWalletRegistrationPublication.fixtures';
import { buildWalletCustodyCommitPayloadFixture } from './passkeyCustodyEnvelope.fixtures';

function required<T>(result: { readonly ok: true; readonly value: T } | { readonly ok: false }): T {
  if (!result.ok) throw new Error('ECDSA recovery fixture value is invalid');
  return result.value;
}

function bytesB64u(bytes: readonly number[]): string {
  return base64UrlEncode(Uint8Array.from(bytes));
}

export type PendingEcdsaRegistrationRecoveryFixture = {
  readonly pending: PendingEcdsaOnlyRegistrationCommit;
  readonly response: Extract<
    WalletRegistrationActivateResponseV2,
    { readonly ok: true; readonly kind: 'evm_family_ecdsa' }
  >;
  readonly unlock: PendingEcdsaRegistrationUnlockMaterial;
  readonly exactMethod: PendingEcdsaRegistrationUnlockInput['exactMethod'];
};

export async function buildPendingEcdsaRegistrationRecoveryFixture(
  args: {
    readonly authKind?: 'passkey' | 'email_otp';
  } = {},
): Promise<PendingEcdsaRegistrationRecoveryFixture> {
  const authKind = args.authKind ?? 'passkey';
  const publication = await buildEcdsaActivationPublicationFixture();
  if (!isEcdsaRegistrationCommit(publication.input.pending)) {
    throw new Error('ECDSA publication fixture did not build an ECDSA pending commit');
  }
  const basePending = publication.input.pending;
  if (basePending.auth.kind !== 'passkey') {
    throw new Error('ECDSA recovery fixture requires a Passkey pending factor');
  }
  const expiresAtMs = Date.now() + 120_000;
  const recoveryEmail = required(parseVerifiedEmailAddress('recovery@example.test'));
  const emailSession =
    authKind === 'email_otp'
      ? await buildEmailOtpEcdsaWalletSessionFixture({
          label: 'pending-registration-recovery',
          expiresAtMs,
          emailHashHex: await sha256HexUtf8(recoveryEmail),
        })
      : undefined;
  const walletId = required(
    parseWalletId(String(emailSession?.authMethod.walletId ?? basePending.walletId)),
  );
  const walletAuthMethodId =
    emailSession?.authMethod.walletAuthMethodId ?? basePending.walletAuthMethodId;
  const factorAuthority = emailSession?.exactFactorAuthority ?? publication.input.authority;
  const pendingAuth = emailSession
    ? {
        kind: 'email_otp' as const,
        email: recoveryEmail,
        registrationAuthorityId: required(
          parseEmailOtpChallengeId(String(emailSession.authMethod.registrationAuthorityId)),
        ),
        providerSubject: emailSession.exactFactorAuthority.factor.providerUserId,
        enrollment: {
          enrollmentSealKeyVersion: 'enrollment-key-v1',
          serverSealedFactorCiphertextB64u: 'sealed-factor-recovery',
          clientUnlockPublicKeyB64u: 'unlock-key-recovery',
          unlockKeyVersion: 'unlock-key-v1',
        },
      }
    : basePending.auth;
  const activationFixture = ecdsaCapabilityActivationFixture({
    walletId,
    authority: await walletAuthAuthorityRef({ authority: factorAuthority }),
  });
  const activationReceipt = parseRouterAbEcdsaRegistrationActivationReceiptV1(
    activationFixture.serverCommit.protocolReceipt,
  );
  const activation = activationReceipt.ecdsa_activation;
  const materialActivation = routerAbMpcMaterialActivationRefFromWire(
    activation.material_activation,
  );
  const roleLocalBinding = activationFixture.prepareInput.activationBinding.roleLocalBinding;
  const signer = activationFixture.prepareInput.activationBinding.signer;
  const chainTarget = signer.scope.targetMemberships[0];
  if (!chainTarget) throw new Error('ECDSA recovery fixture has no chain target');
  const publicCapability = parseRouterAbEcdsaDerivationPublicCapabilityV1({
    ...activationFixture.sealInput.roleLocalPublicFacts.publicCapability,
    client_id: String(walletId),
  });
  const ownerAddress = '0x1602940437e1ba13e06c5a452833dadf081ad1f2';
  const keyHandle = 'ederivation-key-recovery';
  const activationRequestDigestB64u = bytesB64u(activationReceipt.activation_request_digest.bytes);
  const clientActivation = parseRouterAbEcdsaVerifiedClientActivationFactsV1({
    registrationRequestDigestB64u: activationRequestDigestB64u,
    proofTranscriptDigestB64u: bytesB64u(activationReceipt.transcript_digest.bytes),
    contextBinding32B64u: activation.public_identity.context_binding_b64u,
    derivationClientSharePublicKey33B64u:
      activation.public_identity.derivation_client_share_public_key33_b64u,
    clientShareRetryCounter: activation.public_identity.client_share_retry_counter,
    participantId: 1,
  });
  const pending = buildPendingWalletRegistrationCommitV1({
    ...basePending,
    walletId,
    walletAuthMethodId,
    auth: pendingAuth,
    localMaterial: {
      keyFamilies: ['ecdsa_secp256k1'] as const,
      custodyCommit: emailSession
        ? {
            ...buildWalletCustodyCommitPayloadFixture({
              walletId: String(walletId),
              keySet: 'evm_family_ecdsa_v1',
              origin: 'join',
            }),
            keySet: 'evm_family_ecdsa_v1' as const,
          }
        : basePending.localMaterial.custodyCommit,
      ecdsa: {
        activationJournalId: activationReceipt.activation_correlation_id,
        clientActivation,
        activationRequestDigestB64u: parseDigestB64u(activationRequestDigestB64u),
      },
    },
  });
  if (!isEcdsaRegistrationCommit(pending)) {
    throw new Error('ECDSA recovery fixture built the wrong pending plan');
  }
  const slotId = 'wallet-key:evm-family:recovery:v1';
  const thresholdSessionId = 'threshold-ecdsa:recovery';
  const bootstrap = parseThresholdEcdsaDerivationRoleLocalBootstrapValue({
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: String(walletId),
    evmFamilySigningKeySlotId: slotId,
    ecdsaThresholdKeyId: String(roleLocalBinding.ecdsaThresholdKeyId),
    relayerKeyId: String(roleLocalBinding.relayerKeyId),
    applicationBindingDigestB64u: activation.context.application_binding_digest_b64u,
    contextBinding32B64u: activation.public_identity.context_binding_b64u,
    publicIdentity: {
      derivationClientSharePublicKey33B64u:
        activation.public_identity.derivation_client_share_public_key33_b64u,
      relayerPublicKey33B64u: activation.public_identity.server_public_key33_b64u,
      groupPublicKey33B64u: activation.public_identity.threshold_public_key33_b64u,
      ethereumAddress: ownerAddress,
    },
    clientShareRetryCounter: activation.public_identity.client_share_retry_counter,
    relayerShareRetryCounter: activation.public_identity.server_share_retry_counter,
    publicTranscriptDigest32B64u: bytesB64u(activationReceipt.transcript_digest.bytes),
    keyHandle,
    signingRootId: String(signer.signingRootId),
    signingRootVersion: String(signer.signingRootVersion),
    thresholdEcdsaPublicKeyB64u: activation.public_identity.threshold_public_key33_b64u,
    ethereumAddress: ownerAddress,
    relayerVerifyingShareB64u: activation.public_identity.server_public_key33_b64u,
    participantIds: [1, 2],
    thresholdSessionId,
    activationEpoch: String(activation.activation_epoch),
    expiresAtMs,
    expiresAt: new Date(expiresAtMs).toISOString(),
    remainingUses: 5,
    routerAbEcdsaDerivationNormalSigning:
      activationFixture.sealInput.routerAbEcdsaDerivationNormalSigning,
  });
  const walletKey = {
    keyScope: 'evm-family' as const,
    chainTarget,
    walletId: String(walletId),
    evmFamilySigningKeySlotId: slotId,
    keyHandle,
    ecdsaThresholdKeyId: String(roleLocalBinding.ecdsaThresholdKeyId),
    signingRootId: String(signer.signingRootId),
    signingRootVersion: String(signer.signingRootVersion),
    thresholdEcdsaPublicKeyB64u: activation.public_identity.threshold_public_key33_b64u,
    thresholdOwnerAddress: ownerAddress,
    relayerKeyId: String(roleLocalBinding.relayerKeyId),
    relayerVerifyingShareB64u: activation.public_identity.server_public_key33_b64u,
    contextBinding32B64u: activation.public_identity.context_binding_b64u,
    derivationClientSharePublicKey33B64u:
      activation.public_identity.derivation_client_share_public_key33_b64u,
    clientShareRetryCounter: activation.public_identity.client_share_retry_counter,
    relayerShareRetryCounter: activation.public_identity.server_share_retry_counter,
    participantIds: [1, 2] as const,
    publicCapability,
  } satisfies Extract<
    WalletRegistrationActivateResponseV2,
    { readonly ok: true; readonly kind: 'evm_family_ecdsa' }
  >['ecdsa']['walletKeys'][number];
  const signerActivationSet = buildWalletSignerActivationSetV1({
    manifest: buildExactAdministeredSignerManifestV1([
      {
        kind: 'exact_administered_ecdsa_signer_v1',
        keyFamily: 'ecdsa_secp256k1',
        walletId,
        walletKeyId: required(parseWalletKeyId('wallet-key:recovery')),
        thresholdPublicKey33B64u: parseSecp256k1CompressedPublicKeyB64u(
          activation.public_identity.threshold_public_key33_b64u,
        ),
        evmAddress: ownerAddress,
      },
    ]),
    materialActivations: { keyFamilies: ['ecdsa_secp256k1'], ecdsa: materialActivation },
  });
  const foundingAuthoritySource =
    emailSession?.authority ?? publication.input.foundingAuthority.authority;
  const foundingAuthMethod =
    emailSession?.authMethod ?? publication.input.foundingAuthority.authMethod;
  const authorityDraft = {
    kind: 'wallet_authority_v1' as const,
    authorityId: foundingAuthoritySource.authorityId,
    walletId,
    principal: foundingAuthoritySource.principal,
    provenance: { kind: 'wallet_registration' as const },
    permissions: buildFullOwnerPermissionsV1(),
    signerActivations: signerActivationSet,
    signerActivationSetDigestB64u:
      await computeWalletSignerActivationSetDigestB64u(signerActivationSet),
    authorityDigestB64u: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9))),
    revocationEpoch: 0,
    createdAtMs: 10,
    updatedAtMs: 20,
    state: 'active' as const,
    activatedAtMs: 20,
  };
  const foundingAuthority = buildActiveWalletAuthorityV1({
    ...authorityDraft,
    authorityDigestB64u: await computeWalletAuthorityDigestB64u(authorityDraft),
  });
  const session = buildExactWalletSessionAuthorizationFixture({
    label: 'ecdsa-recovery-coordinator',
    tenantId: required(parseTenantId('tenant:ecdsa-recovery-coordinator')),
    principalId: required(parsePrincipalId('principal:ecdsa-recovery-coordinator')),
    authority: foundingAuthority,
    walletAuthMethodId,
    issuedAtMs: 10,
    expiresAtMs,
    remainingUses: 5,
  });
  const projectionTokens = {
    kind: 'evm_family_ecdsa' as const,
    ecdsa: {
      sessionKind: 'credential_free_projection_v2' as const,
      thresholdSessionId: required(parseThresholdEcdsaSessionId(thresholdSessionId)),
      keyHandle: bootstrap.keyHandle,
      runtimePolicyScope: activationFixture.sealInput.runtimePolicyScope,
      materialActivation,
      routerAbEcdsaDerivationNormalSigning:
        activationFixture.sealInput.routerAbEcdsaDerivationNormalSigning,
    },
  };
  const establishedSession = parseRegistrationEstablishedSessionResultV2({
    kind: 'already_committed',
    session: {
      kind: 'registration_established_wallet_session_projection_v2',
      walletId: session.session.walletId,
      authorizationId: session.session.authorizationId,
      walletSessionId: session.session.walletSessionId,
      quotaId: session.session.quotaId,
      expiresAtMs,
      remainingUses: session.quota.remainingUses,
      walletSession: projectActiveWalletSession(session),
      tokens: projectionTokens,
    },
    next: 'unlock_exact_method',
  });
  if (!establishedSession || establishedSession.kind !== 'already_committed') {
    throw new Error('ECDSA recovery fixture established session is invalid');
  }
  const responseAuth =
    pending.auth.kind === 'passkey'
      ? {
          rpId: pending.auth.rpId,
          authMethod: {
            kind: 'passkey' as const,
            credentialIdB64u: pending.auth.credentialIdB64u,
            credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(23)),
          },
        }
      : {
          authMethod: {
            kind: 'email_otp' as const,
            registrationAuthorityId: pending.auth.registrationAuthorityId,
          },
        };
  const response = {
    ok: true as const,
    walletId,
    authority: factorAuthority,
    foundingAuthority,
    foundingAuthMethod,
    walletCustody: { status: 'committed' as const },
    custodyKeyManifestDigestB64u: pending.localMaterial.custodyCommit.keyManifestDigestB64u,
    ...responseAuth,
    kind: 'evm_family_ecdsa' as const,
    ecdsa: {
      walletKeys: [walletKey],
      activation: activationReceipt,
      bootstrap,
    },
    registrationEstablishedSession: establishedSession,
  } satisfies Extract<
    WalletRegistrationActivateResponseV2,
    { readonly ok: true; readonly kind: 'evm_family_ecdsa' }
  >;
  const unlockSession = parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1({
    kind: 'router_ab_ecdsa_post_registration_session_activated_v1',
    public_capability: publicCapability,
    session: {
      authorization_session_id: required(
        parseEcdsaAuthorizationSessionId('ecdsa-authorization-session:recovery'),
      ),
      authorization_id: session.session.authorizationId,
      threshold_session_id: bootstrap.thresholdSessionId,
      wallet_session_id: session.session.walletSessionId,
      quota_id: session.session.quotaId,
      expires_at_ms: expiresAtMs,
      remaining_uses: 5,
      wallet_session: projectActiveWalletSession(session),
      operation_credential: parseWalletSessionOperationCredentialV1({
        kind: 'opaque_wallet_session_operation_credential_v1',
        token: `wst_${base64UrlEncode(new Uint8Array(32).fill(46))}`,
        walletSessionId: session.session.walletSessionId,
      }),
    },
    normal_signing: activationFixture.sealInput.routerAbEcdsaDerivationNormalSigning,
  });
  const publicFacts = {
    contextBinding32B64u: activation.public_identity.context_binding_b64u,
    derivationClientSharePublicKey33B64u:
      activation.public_identity.derivation_client_share_public_key33_b64u,
    clientVerifyingShare33B64u:
      activation.public_identity.derivation_client_share_public_key33_b64u,
    relayerPublicKey33B64u: activation.public_identity.server_public_key33_b64u,
    groupPublicKey33B64u: activation.public_identity.threshold_public_key33_b64u,
    ethereumAddress: ownerAddress,
    clientShareRetryCounter: activation.public_identity.client_share_retry_counter,
    relayerShareRetryCounter: activation.public_identity.server_share_retry_counter,
  };
  return {
    pending,
    response,
    unlock: {
      session: unlockSession,
      readyStateBlobB64u: activationFixture.sealInput.readyStateBlobB64u,
      publicFacts,
    },
    exactMethod:
      pending.auth.kind === 'passkey'
        ? { kind: 'passkey', expectedOrigin: 'https://recovery.example.test' }
        : {
            kind: 'email_otp',
            challengeId: String(pending.auth.registrationAuthorityId),
            otpCode: '123456',
          },
  };
}
