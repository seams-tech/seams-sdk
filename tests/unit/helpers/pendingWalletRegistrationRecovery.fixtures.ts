import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking/parsers';
import { projectActiveWalletSession } from '../../../packages/wallet-server/src/authorization/domain';
import { parsePrincipalId, parseTenantId } from '@shared/authorization/capabilityKinds';
import { deriveImplicitNearAccountIdFromEd25519PublicKey } from '@shared/utils/near';
import {
  parseRegistrationEstablishedSessionResultV2,
  type RegistrationEstablishedSessionResultV2,
} from '@shared/utils/registrationEstablishedSession';
import { base64UrlEncode } from '@shared/utils/base64';
import { base58Encode } from '@shared/utils/base58';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import {
  parseWalletRegistrationFinalizeResponse,
  type WalletRegistrationNearProvisioningResponseV2,
} from '@/core/rpcClients/relayer/walletRegistration';
import type { PendingWalletRegistrationLocalMaterialV1 } from '@/core/indexedDB/pendingWalletRegistrationCommit';
import { isEmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { buildExactWalletSessionAuthorizationFixture } from './exactWalletSessionAuthorization.fixtures';
import {
  buildEmailNearProvisioningPublicationFixture,
  buildPasskeyNearProvisioningPublicationFixture,
} from './pendingWalletRegistrationPublication.fixtures';
import type { PendingNearProvisioningCommit } from '../../../packages/wallet/src/SeamsWeb/operations/registration/pendingRegistrationRecovery';

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function isEd25519LocalMaterial(
  value: PendingWalletRegistrationLocalMaterialV1,
): value is Extract<
  PendingWalletRegistrationLocalMaterialV1,
  { readonly keyFamilies: readonly ['ed25519'] }
> {
  return value.keyFamilies.length === 1 && value.keyFamilies[0] === 'ed25519';
}

function pendingNearProvisioningCommit(
  value: Awaited<
    ReturnType<typeof buildPasskeyNearProvisioningPublicationFixture>
  >['input']['pending'],
): PendingNearProvisioningCommit {
  const localMaterial = value.localMaterial;
  if (value.operation !== 'near_provisioning' || !isEd25519LocalMaterial(localMaterial)) {
    throw new Error('pending recovery fixture is not an Ed25519 NEAR provisioning commit');
  }
  return { ...value, localMaterial };
}

function normalSigningState(signingWorkerId: string) {
  const parsed = parseRouterAbEd25519NormalSigningState({
    kind: 'router_ab_ed25519_normal_signing_v1',
    signingWorkerId,
  });
  if (!parsed) throw new Error('pending recovery fixture normal-signing state is invalid');
  return parsed;
}

function sessionTokens(args: {
  readonly pending: PendingNearProvisioningCommit;
  readonly nearAccountId: string;
  readonly thresholdSessionId: string;
}) {
  const metadata = args.pending.localMaterial.ed25519.metadata;
  return {
    kind: 'near_ed25519' as const,
    ed25519: {
      sessionKind: 'credential_free_projection_v2' as const,
      thresholdSessionId: args.thresholdSessionId,
      nearAccountId: args.nearAccountId,
      nearEd25519SigningKeyId: metadata.nearEd25519SigningKeyId,
      runtimePolicyScope: {
        orgId: 'org:r103f-recovery',
        projectId: 'project:r103f-recovery',
        envId: 'env:r103f-recovery',
        signingRootVersion: 'root-r103f-recovery-v1',
      },
      materialActivation: metadata.materialActivation,
      routerAbNormalSigning: normalSigningState(metadata.signingWorkerId),
    },
  };
}

type PendingWalletRegistrationRecoveryFixture = {
  readonly pending: PendingNearProvisioningCommit;
  readonly firstResponse: WalletRegistrationNearProvisioningResponseV2;
  readonly replayResponse: WalletRegistrationNearProvisioningResponseV2;
};

async function buildRecoveryFixture(
  authKind: 'passkey' | 'email_otp',
): Promise<PendingWalletRegistrationRecoveryFixture> {
  const publication =
    authKind === 'passkey'
      ? await buildPasskeyNearProvisioningPublicationFixture()
      : await buildEmailNearProvisioningPublicationFixture();
  const pendingBase = pendingNearProvisioningCommit(publication.input.pending);
  const pending: PendingNearProvisioningCommit = {
    ...pendingBase,
    localMaterial: {
      ...pendingBase.localMaterial,
      custodyCommit: {
        ...pendingBase.localMaterial.custodyCommit,
        registeredPublicKeyB64u: pendingBase.localMaterial.ed25519.metadata.registeredPublicKeyB64u,
      },
    },
  };
  const metadata = pending.localMaterial.ed25519.metadata;
  const registeredPublicKeyBytes = new Uint8Array(32).fill(17);
  const registeredPublicKey = `ed25519:${base58Encode(registeredPublicKeyBytes)}`;
  const nearAccountId = deriveImplicitNearAccountIdFromEd25519PublicKey(registeredPublicKey);
  const thresholdSessionId = 'threshold-ed25519:pending-recovery';
  const tokens = sessionTokens({ pending, nearAccountId, thresholdSessionId });
  const issued = buildExactWalletSessionAuthorizationFixture({
    label: 'pending-recovery',
    tenantId: required(parseTenantId('tenant:pending-recovery')),
    principalId: required(parsePrincipalId('principal:pending-recovery')),
    authority: publication.input.foundingAuthority.authority,
    walletAuthMethodId: publication.input.foundingAuthority.authMethod.walletAuthMethodId,
    issuedAtMs: 100,
    expiresAtMs: 10_000,
    remainingUses: 3,
  });
  const operationCredential = parseWalletSessionOperationCredentialV1({
    kind: 'opaque_wallet_session_operation_credential_v1',
    token: `wst_${base64UrlEncode(new Uint8Array(32).fill(29))}`,
    walletSessionId: issued.session.walletSessionId,
  });
  const issuedResult = parseRegistrationEstablishedSessionResultV2({
    kind: 'issued',
    session: {
      kind: 'registration_established_wallet_session_v2',
      walletId: issued.session.walletId,
      authorizationId: issued.session.authorizationId,
      walletSessionId: issued.session.walletSessionId,
      quotaId: issued.session.quotaId,
      expiresAtMs: issued.session.expiresAtMs,
      remainingUses: issued.quota.remainingUses,
      walletSession: projectActiveWalletSession(issued),
      operationCredential,
      tokens,
    },
  });
  if (!issuedResult || issuedResult.kind !== 'issued') {
    throw new Error('pending recovery fixture issued session is invalid');
  }
  const replayResult = parseRegistrationEstablishedSessionResultV2({
    kind: 'already_committed',
    session: {
      kind: 'registration_established_wallet_session_projection_v2',
      walletId: issued.session.walletId,
      authorizationId: issued.session.authorizationId,
      walletSessionId: issued.session.walletSessionId,
      quotaId: issued.session.quotaId,
      expiresAtMs: issued.session.expiresAtMs,
      remainingUses: issued.quota.remainingUses,
      tokens,
    },
    next: 'unlock_exact_method',
  });
  if (!replayResult || replayResult.kind !== 'already_committed') {
    throw new Error('pending recovery fixture projection is invalid');
  }
  const authority = publication.input.authority;
  const finalizedBase = {
    ok: true as const,
    walletId: publication.input.request.walletId,
    authority,
    foundingAuthority: publication.input.foundingAuthority.authority,
    foundingAuthMethod: publication.input.foundingAuthority.authMethod,
    walletCustody: { status: 'committed' as const },
    custodyKeyManifestDigestB64u: pending.localMaterial.custodyCommit.keyManifestDigestB64u,
    kind: 'near_ed25519' as const,
    accountProvisioning: {
      kind: 'implicit_account' as const,
      accountIdSource: 'ed25519_public_key' as const,
    },
    resolvedAccount: {
      kind: 'implicit_account' as const,
      nearAccountId,
      nearEd25519SigningKeyId: metadata.nearEd25519SigningKeyId,
    },
    ed25519: {
      signerSlot: metadata.signerSlot,
      nearAccountId,
      nearEd25519SigningKeyId: metadata.nearEd25519SigningKeyId,
      publicKey: registeredPublicKey,
      relayerKeyId: metadata.signingWorkerId,
      keyVersion: 'r103f-recovery-v1',
      recoveryExportCapable: true as const,
      participantIds: metadata.participantIds,
      thresholdSessionId,
      runtimePolicyScope: tokens.ed25519.runtimePolicyScope,
      routerAbNormalSigning: tokens.ed25519.routerAbNormalSigning,
    },
  };
  let finalizedInput: Record<string, unknown>;
  if (pending.auth.kind === 'passkey') {
    finalizedInput = {
      ...finalizedBase,
      rpId: pending.auth.rpId,
      authMethod: {
        kind: 'passkey' as const,
        credentialIdB64u: pending.auth.credentialIdB64u,
        credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(23)),
      },
      authorityScope: { kind: 'passkey_rp' as const, rpId: pending.auth.rpId },
    };
  } else {
    if (!isEmailOtpWalletAuthAuthority(authority)) {
      throw new Error('Email OTP recovery fixture has a non-Email OTP authority');
    }
    finalizedInput = {
      ...finalizedBase,
      authMethod: {
        kind: 'email_otp' as const,
        registrationAuthorityId: pending.auth.registrationAuthorityId,
      },
      authorityScope: {
        kind: 'email_otp' as const,
        provider: authority.factor.provider,
        providerUserId: authority.factor.providerUserId,
      },
    };
  }
  const parsedFinalized = parseWalletRegistrationFinalizeResponse({
    expectedKind: 'near_ed25519',
    value: finalizedInput,
  });
  if (parsedFinalized.kind !== 'near_ed25519') {
    throw new Error('pending recovery fixture final response is not a NEAR response');
  }
  const finalized = parsedFinalized;
  return {
    pending,
    firstResponse: {
      ...finalized,
      nearProvisioning: { status: 'near_ready' },
      registrationEstablishedSession: issuedResult,
    },
    replayResponse: {
      ...finalized,
      nearProvisioning: { status: 'near_ready' },
      registrationEstablishedSession: replayResult,
    },
  };
}

export function buildPendingWalletRegistrationRecoveryFixture(): Promise<PendingWalletRegistrationRecoveryFixture> {
  return buildRecoveryFixture('passkey');
}

export function buildEmailOtpWalletRegistrationRecoveryFixture(): Promise<PendingWalletRegistrationRecoveryFixture> {
  return buildRecoveryFixture('email_otp');
}
