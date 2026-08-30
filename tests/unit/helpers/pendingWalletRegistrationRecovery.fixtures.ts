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
import { buildExactWalletSessionAuthorizationFixture } from './exactWalletSessionAuthorization.fixtures';
import { buildPasskeyNearProvisioningPublicationFixture } from './pendingWalletRegistrationPublication.fixtures';
import type { PendingPasskeyNearProvisioningCommit } from '../../../packages/wallet/src/SeamsWeb/operations/registration/pendingRegistrationRecovery';

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

function pendingPasskeyCommit(
  value: Awaited<
    ReturnType<typeof buildPasskeyNearProvisioningPublicationFixture>
  >['input']['pending'],
): PendingPasskeyNearProvisioningCommit {
  const auth = value.auth;
  const localMaterial = value.localMaterial;
  if (
    value.operation !== 'near_provisioning' ||
    auth.kind !== 'passkey' ||
    !isEd25519LocalMaterial(localMaterial)
  ) {
    throw new Error('pending recovery fixture is not a Passkey NEAR provisioning commit');
  }
  return { ...value, auth, localMaterial };
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
  readonly pending: PendingPasskeyNearProvisioningCommit;
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

export async function buildPendingWalletRegistrationRecoveryFixture(): Promise<{
  readonly pending: PendingPasskeyNearProvisioningCommit;
  readonly firstResponse: WalletRegistrationNearProvisioningResponseV2;
  readonly replayResponse: WalletRegistrationNearProvisioningResponseV2;
}> {
  const publication = await buildPasskeyNearProvisioningPublicationFixture();
  const pendingBase = pendingPasskeyCommit(publication.input.pending);
  const pending: PendingPasskeyNearProvisioningCommit = {
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
  const parsedFinalized = parseWalletRegistrationFinalizeResponse({
    expectedKind: 'near_ed25519',
    value: {
      ok: true,
      walletId: publication.input.request.walletId,
      authority: publication.input.authority,
      foundingAuthority: publication.input.foundingAuthority.authority,
      foundingAuthMethod: publication.input.foundingAuthority.authMethod,
      rpId: pending.auth.rpId,
      authMethod: {
        kind: 'passkey',
        credentialIdB64u: pending.auth.credentialIdB64u,
        credentialPublicKeyB64u: base64UrlEncode(new Uint8Array(32).fill(23)),
      },
      walletCustody: { status: 'committed' },
      custodyKeyManifestDigestB64u: pending.localMaterial.custodyCommit.keyManifestDigestB64u,
      kind: 'near_ed25519',
      authorityScope: { kind: 'passkey_rp', rpId: pending.auth.rpId },
      accountProvisioning: { kind: 'implicit_account', accountIdSource: 'ed25519_public_key' },
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
        keyVersion: 'r103f-recovery-v1',
        recoveryExportCapable: true,
        participantIds: metadata.participantIds,
        thresholdSessionId,
        runtimePolicyScope: tokens.ed25519.runtimePolicyScope,
        routerAbNormalSigning: tokens.ed25519.routerAbNormalSigning,
      },
    },
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
