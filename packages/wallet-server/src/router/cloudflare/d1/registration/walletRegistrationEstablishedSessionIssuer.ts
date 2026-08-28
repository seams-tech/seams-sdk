import type {
  WalletRegistrationEd25519YaoPublicResult,
  WalletRegistrationFinalizeAuthMethod,
} from '../../../../core/registrationContracts';
import { parseSessionOrigin, parseVerifiedOwnerProofId } from '../../../../authorization/domain';
import {
  buildVerifiedOwnerProof,
  buildVerifiedWalletSessionEmailOtpFactorResult,
  buildVerifiedWalletSessionPasskeyFactorResult,
  type VerifiedOwnerProof,
} from '../../../../authorization/factorEvidence';
import type {
  AuthorizationService,
  IssuedReusableWalletSession,
  OpaqueOwnerWalletSessionBinding,
} from '../../../../authorization/service';
import {
  issueRouterAbEd25519OpaqueWalletSessionToken,
  issueRouterAbEcdsaDerivationOpaqueWalletSessionToken,
} from '../../../auth/commonRouterUtils';
import type { EcdsaDerivationServerBootstrapResponse } from '../../../../core/types';
import type { WalletRegistrationSessionCommitReceiptV2 } from '../../../../core/threeRouteRegistrationContracts';
import type { StoredRegistrationAuthority } from '../../../../core/RegistrationCeremonyStore';
import {
  parseAuthFactorId,
  parseEcdsaAuthorizationSessionId,
  parsePrincipalId,
  type PrincipalId,
  type TenantId,
  type WalletSessionAuthorizationId,
} from '@shared/authorization/capabilityKinds';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  parseEmailOtpChallengeId,
  parseProviderSubject,
  parseWebAuthnCredentialIdB64u,
  type WalletAuthMethodId,
} from '@shared/utils/domainIds';
import {
  isEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  walletIdFromString,
  nearEd25519SigningKeyIdFromString,
} from '@shared/utils/registrationIntent';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { parseImplicitNearAccountId, parseNamedNearAccountId } from '@shared/utils/near';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import type { RegistrationEstablishedSession } from '@shared/utils/registrationEstablishedSession';
import { registrationEstablishedMintId } from './walletRegistrationSessionCommitReceipt';

export type RegistrationEstablishedSessionIssuerAuthorizationService = Pick<
  AuthorizationService,
  | 'issueReusableWalletSession'
  | 'issueWalletSessionAuthorizationV2FromReusableSession'
  | 'refreshWalletSessionAuthorizationV2FromReusableSession'
  | 'readWalletSessionAuthorizationByMint'
  | 'issueOpaqueWalletSessionToken'
>;

export type RegistrationEstablishedSessionIssuerWalletAuthMethodReader = {
  readonly readActiveRegistrationAuthority: (authority: StoredRegistrationAuthority) => Promise<{
    readonly authority: ActiveWalletAuthorityV1;
    readonly walletAuthMethodId: WalletAuthMethodId;
  } | null>;
};

type RegistrationEstablishedSessionIssuanceDependencies = {
  readonly authorizationService: RegistrationEstablishedSessionIssuerAuthorizationService;
  readonly authorizationTenantId: TenantId;
  readonly walletAuthMethods: RegistrationEstablishedSessionIssuerWalletAuthMethodReader;
};

type RegistrationEstablishedSessionReplayDependencies = {
  readonly authorizationService: RegistrationEstablishedSessionIssuerAuthorizationService;
  readonly authorizationTenantId: TenantId;
};

function requireReusableWalletSessionPrincipalId(value: string): PrincipalId {
  const parsed = parsePrincipalId(value);
  if (!parsed.ok) {
    throw new Error(`Reusable Wallet Session principal is invalid: ${parsed.error.message}`);
  }
  return parsed.value;
}

export function reusableWalletSessionPrincipalId(authority: WalletAuthAuthority): PrincipalId {
  return requireReusableWalletSessionPrincipalId(
    isEmailOtpWalletAuthAuthority(authority)
      ? String(authority.factor.providerUserId)
      : String(authority.walletId),
  );
}

export async function buildRegistrationOwnerProof(input: {
  readonly registrationCeremonyId: string;
  readonly authMethod: WalletRegistrationFinalizeAuthMethod;
  readonly authority: WalletAuthAuthority;
  readonly tenantId: TenantId;
  readonly expectedOrigin: string;
  readonly expiresAtMs: number;
}): Promise<Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>> {
  const factorId = parseAuthFactorId(`registration:${input.registrationCeremonyId}`);
  if (!factorId.ok) throw new Error(factorId.error.message);
  const authorityRef = await walletAuthAuthorityRef({ authority: input.authority });
  const principalId = reusableWalletSessionPrincipalId(input.authority);
  const origin = parseSessionOrigin(input.expectedOrigin);
  const verifiedAtMs = Date.now();
  const evidenceDigest = parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        alphabetizeStringify({
          kind: 'wallet_registration_owner_proof_v1',
          registrationCeremonyId: input.registrationCeremonyId,
          authMethod: input.authMethod,
          authority: authorityRef,
        }),
      ),
    ),
  );
  const common = {
    tenantId: input.tenantId,
    principalId,
    walletId: input.authority.walletId,
    authorityRef,
    requestOrigin: origin,
    audience: origin,
    factorId: factorId.value,
    verifiedAtMs,
    expiresAtMs: input.expiresAtMs,
  } as const;
  if (input.authMethod.kind === 'passkey') {
    const credentialId = parseWebAuthnCredentialIdB64u(input.authMethod.credentialIdB64u);
    if (!credentialId.ok) throw new Error(credentialId.error.message);
    return await buildVerifiedOwnerProof({
      purpose: 'wallet_session',
      proofId: parseVerifiedOwnerProofId(`registration:${input.registrationCeremonyId}`),
      factor: buildVerifiedWalletSessionPasskeyFactorResult({
        ...common,
        credentialIdB64u: credentialId.value,
        assertionDigest: evidenceDigest,
      }),
    });
  }
  return await buildVerifiedOwnerProof({
    purpose: 'wallet_session',
    proofId: parseVerifiedOwnerProofId(`registration:${input.registrationCeremonyId}`),
    factor: buildVerifiedWalletSessionEmailOtpFactorResult({
      ...common,
      challengeId: requireEmailOtpChallengeId(input.authMethod.registrationAuthorityId),
      verificationReceiptDigest: evidenceDigest,
    }),
  });
}

function requireEmailOtpChallengeId(value: string) {
  const parsed = parseEmailOtpChallengeId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function walletSessionAuthSourceFromAuthority(
  authority: WalletAuthAuthority,
): Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }>['authSource'] {
  if (authority.factor.kind === 'passkey') {
    return {
      kind: 'passkey',
      credentialIdB64u: authority.factor.credentialIdB64u,
    };
  }
  const providerSubject = parseProviderSubject(authority.factor.providerUserId);
  if (!providerSubject.ok) throw new Error(providerSubject.error.message);
  return {
    kind: 'oidc_provider',
    providerId: authority.factor.provider === 'google' ? 'google_oidc' : 'oidc',
    providerSubject: providerSubject.value,
  };
}

function registrationEstablishedEcdsaAuthorizationSessionId(
  authorizationId: WalletSessionAuthorizationId,
) {
  const parsed = parseEcdsaAuthorizationSessionId(authorizationId);
  if (!parsed.ok) {
    throw new Error(
      `Registration-established ECDSA authorization session id is invalid: ${parsed.error.message}`,
    );
  }
  return parsed.value;
}

async function issueRegistrationEstablishedGrant(
  input: RegistrationEstablishedSessionIssuanceDependencies & {
    readonly registrationCeremonyId: string;
    readonly authority: WalletAuthAuthority;
    readonly registrationAuthority: StoredRegistrationAuthority;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly expiresAtMs: number;
    readonly remainingUses: number;
  },
): Promise<IssuedReusableWalletSession> {
  const issuedAtMs = Date.now();
  if (!Number.isSafeInteger(input.remainingUses) || input.remainingUses <= 0) {
    throw new Error('Registration-established session remaining uses is invalid');
  }
  if (!Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= issuedAtMs) {
    throw new Error('Registration-established session expiry is invalid');
  }
  const expiresAtMs = Math.min(input.expiresAtMs, issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS);
  const remainingUses = Math.min(DEFAULT_WALLET_SESSION_REMAINING_USES, input.remainingUses);
  const activeRegistration = await input.walletAuthMethods.readActiveRegistrationAuthority(
    input.registrationAuthority,
  );
  if (
    !activeRegistration ||
    activeRegistration.authority.walletId !== input.authority.walletId ||
    activeRegistration.walletAuthMethodId !== input.walletAuthMethodId
  ) {
    throw new Error('Registration founding authority is unavailable after commit');
  }
  const authorityRef = await walletAuthAuthorityRef({ authority: input.authority });
  const reusableWalletSession = await input.authorizationService.issueReusableWalletSession({
    tenantId: input.authorizationTenantId,
    principalId: reusableWalletSessionPrincipalId(input.authority),
    walletId: walletIdFromString(String(input.authority.walletId)),
    authority: authorityRef,
    mintId: registrationEstablishedMintId(input.registrationCeremonyId),
    remainingUses,
    issuedAtMs,
    expiresAtMs,
  });
  await input.authorizationService.issueWalletSessionAuthorizationV2FromReusableSession({
    reusableWalletSession,
    authority: activeRegistration.authority,
    walletAuthMethodId: activeRegistration.walletAuthMethodId,
  });
  return reusableWalletSession;
}

async function readRegistrationEstablishedGrant(input: {
  readonly authorizationService: RegistrationEstablishedSessionIssuerAuthorizationService;
  readonly authorizationTenantId: TenantId;
  readonly registrationCeremonyId: string;
  readonly authority: WalletAuthAuthority;
}): Promise<IssuedReusableWalletSession | null> {
  const authorityRef = await walletAuthAuthorityRef({ authority: input.authority });
  return await input.authorizationService.readWalletSessionAuthorizationByMint({
    tenantId: input.authorizationTenantId,
    principalId: reusableWalletSessionPrincipalId(input.authority),
    walletId: walletIdFromString(String(input.authority.walletId)),
    authority: authorityRef,
    mintId: registrationEstablishedMintId(input.registrationCeremonyId),
    nowMs: Date.now(),
  });
}

function registrationEstablishedSessionBase(
  authority: WalletAuthAuthority,
  reusableWalletSession: IssuedReusableWalletSession,
) {
  return {
    walletId: walletIdFromString(String(authority.walletId)),
    authorizationId: reusableWalletSession.session.authorizationId,
    walletSessionId: reusableWalletSession.quota.walletSessionId,
    quotaId: reusableWalletSession.quota.quotaId,
    expiresAtMs: reusableWalletSession.quota.expiresAtMs,
    remainingUses: reusableWalletSession.quota.remainingUses,
  } as const;
}

export async function issueRegistrationEstablishedEcdsaSession(
  input: RegistrationEstablishedSessionIssuanceDependencies & {
    readonly registrationCeremonyId: string;
    readonly authority: WalletAuthAuthority;
    readonly registrationAuthority: StoredRegistrationAuthority;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly expiresAtMs: number;
    readonly remainingUses: number;
    readonly bootstrap: EcdsaDerivationServerBootstrapResponse;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
    readonly keyManifestDigestB64u: DigestB64u;
  },
): Promise<{ readonly session: RegistrationEstablishedSession; readonly issuedAtMs: number }> {
  const reusableWalletSession = await issueRegistrationEstablishedGrant(input);
  const issuedAtMs = reusableWalletSession.session.createdAtMs;
  const base = registrationEstablishedSessionBase(input.authority, reusableWalletSession);
  const bootstrap = input.bootstrap;
  const thresholdSessionId = parseThresholdEcdsaSessionId(bootstrap.thresholdSessionId);
  if (!thresholdSessionId.ok) throw new Error(thresholdSessionId.error.message);
  const keyHandle = await deriveThresholdEcdsaKeyHandle({
    ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
    signingRootId: bootstrap.signingRootId,
    signingRootVersion: bootstrap.signingRootVersion,
  });
  if (keyHandle !== bootstrap.keyHandle) {
    throw new Error('Registration ECDSA bootstrap key handle is inconsistent');
  }
  const signed = await issueRouterAbEcdsaDerivationOpaqueWalletSessionToken({
    opaqueWalletSessions: input.authorizationService,
    tenantId: input.authorizationTenantId,
    proof: input.proof,
    walletAuthAuthorityRef: await walletAuthAuthorityRef({ authority: input.authority }),
    authSource: walletSessionAuthSourceFromAuthority(input.authority),
    userId: bootstrap.walletId,
    relayerKeyId: bootstrap.relayerKeyId,
    fallbackParticipantIds: bootstrap.participantIds,
    invalidPayloadErrorMessage: 'Registration-established ECDSA Wallet Session is invalid',
    sessionInfo: {
      sessionKind: 'opaque',
      authorizationKind: 'owner_wallet_session',
      thresholdSessionId: thresholdSessionId.value,
      authorizationId: base.authorizationId,
      walletSessionId: base.walletSessionId,
      quotaId: base.quotaId,
      expiresAtMs: base.expiresAtMs,
      participantIds: bootstrap.participantIds,
      runtimePolicyScope: input.runtimePolicyScope,
      keyManifestDigestB64u: input.keyManifestDigestB64u,
      authorizationSessionId: registrationEstablishedEcdsaAuthorizationSessionId(
        base.authorizationId,
      ),
      keyHandle,
      stableKeyContext: {
        walletId: bootstrap.walletId,
        keyScope: 'evm-family',
        ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
        signingRootId: bootstrap.signingRootId,
        signingRootVersion: bootstrap.signingRootVersion,
        applicationBindingDigestB64u: bootstrap.applicationBindingDigestB64u,
        contextBinding32B64u: bootstrap.contextBinding32B64u,
      },
      publicIdentity: bootstrap.publicIdentity,
      activationEpoch: bootstrap.activationEpoch,
      signingWorkerId:
        bootstrap.routerAbEcdsaDerivationNormalSigning.scope.signing_worker.server_id,
      routerAbEcdsaDerivationNormalSigning: bootstrap.routerAbEcdsaDerivationNormalSigning,
    },
  });
  if (!signed.ok) throw new Error(signed.message);
  if (signed.authorizationKind !== 'owner_wallet_session') {
    throw new Error('Registration ECDSA owner Wallet Session issuance failed');
  }
  return {
    session: {
      kind: 'registration_established_wallet_session_v1',
      ...base,
      tokens: {
        kind: 'evm_family_ecdsa',
        ecdsa: {
          sessionKind: 'opaque',
          walletSessionToken: signed.token,
          thresholdSessionId: thresholdSessionId.value,
          keyHandle,
          runtimePolicyScope: input.runtimePolicyScope,
          routerAbEcdsaDerivationNormalSigning: bootstrap.routerAbEcdsaDerivationNormalSigning,
        },
      },
    },
    issuedAtMs,
  };
}

export async function issueOrReuseRegistrationEstablishedEd25519Session(
  input: RegistrationEstablishedSessionIssuanceDependencies & {
    readonly registrationCeremonyId: string;
    readonly authority: WalletAuthAuthority;
    readonly activeAuthority: ActiveWalletAuthorityV1;
    readonly registrationAuthority: StoredRegistrationAuthority;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly expiresAtMs: number;
    readonly remainingUses: number;
    readonly publicResult: WalletRegistrationEd25519YaoPublicResult;
    readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
    readonly keyManifestDigestB64u: DigestB64u;
  },
): Promise<{ readonly session: RegistrationEstablishedSession; readonly issuedAtMs: number }> {
  const existingWalletSession = await readRegistrationEstablishedGrant({
    authorizationService: input.authorizationService,
    authorizationTenantId: input.authorizationTenantId,
    registrationCeremonyId: input.registrationCeremonyId,
    authority: input.authority,
  });
  const reusableWalletSession =
    existingWalletSession ?? (await issueRegistrationEstablishedGrant(input));
  if (existingWalletSession) {
    await input.authorizationService.refreshWalletSessionAuthorizationV2FromReusableSession({
      reusableWalletSession,
      authority: input.activeAuthority,
      walletAuthMethodId: input.walletAuthMethodId,
    });
  }
  const base = registrationEstablishedSessionBase(input.authority, reusableWalletSession);
  const publicResult = input.publicResult;
  const thresholdSessionId = parseThresholdEd25519SessionId(publicResult.thresholdSessionId);
  if (!thresholdSessionId.ok) throw new Error(thresholdSessionId.error.message);
  const signed = await issueRouterAbEd25519OpaqueWalletSessionToken({
    opaqueWalletSessions: input.authorizationService,
    tenantId: input.authorizationTenantId,
    proof: input.proof,
    userId: input.authority.walletId,
    relayerKeyId: publicResult.relayerKeyId,
    authority: input.authority,
    fallbackParticipantIds: publicResult.participantIds,
    invalidPayloadErrorMessage: 'Registration-established Ed25519 Wallet Session is invalid',
    sessionInfo: {
      sessionKind: 'opaque',
      authorizationKind: 'owner_wallet_session',
      walletId: input.authority.walletId,
      nearAccountId: publicResult.nearAccountId,
      nearEd25519SigningKeyId: publicResult.nearEd25519SigningKeyId,
      authorizationId: base.authorizationId,
      thresholdSessionId: thresholdSessionId.value,
      walletSessionId: base.walletSessionId,
      quotaId: base.quotaId,
      expiresAtMs: base.expiresAtMs,
      participantIds: publicResult.participantIds,
      runtimePolicyScope: publicResult.runtimePolicyScope,
      routerAbNormalSigning: publicResult.routerAbNormalSigning,
      keyManifestDigestB64u: input.keyManifestDigestB64u,
    },
  });
  if (!signed.ok) throw new Error(signed.message);
  if (signed.authorizationKind !== 'owner_wallet_session') {
    throw new Error('Registration Ed25519 owner Wallet Session issuance failed');
  }
  const nearAccount = parseImplicitNearAccountId(publicResult.nearAccountId);
  const namedNearAccount = parseNamedNearAccountId(publicResult.nearAccountId);
  const nearAccountId = nearAccount.ok
    ? nearAccount.value
    : namedNearAccount.ok
      ? namedNearAccount.value
      : null;
  if (!nearAccountId) throw new Error('Registration Ed25519 near account identity is invalid');
  return {
    session: {
      kind: 'registration_established_wallet_session_v1',
      ...base,
      tokens: {
        kind: 'near_ed25519',
        ed25519: {
          sessionKind: 'opaque',
          walletSessionToken: signed.token,
          thresholdSessionId: thresholdSessionId.value,
          nearAccountId,
          nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
            publicResult.nearEd25519SigningKeyId,
          ),
          runtimePolicyScope: publicResult.runtimePolicyScope,
          routerAbNormalSigning: publicResult.routerAbNormalSigning,
        },
      },
    },
    issuedAtMs: reusableWalletSession.session.createdAtMs,
  };
}

export async function replayRegistrationEstablishedEcdsaSession(input: {
  readonly authorizationService: RegistrationEstablishedSessionReplayDependencies['authorizationService'];
  readonly authorizationTenantId: TenantId;
  readonly receipt: Extract<
    WalletRegistrationSessionCommitReceiptV2,
    { readonly committed: { readonly kind: 'ecdsa_ready' } }
  >;
}): Promise<RegistrationEstablishedSession> {
  const receipt = input.receipt;
  const projected = receipt.committed.session;
  if (projected.tokens.kind !== 'evm_family_ecdsa') {
    throw new Error('Registration ECDSA receipt contains a different session branch');
  }
  const bootstrap = receipt.committed.ecdsa.bootstrap;
  const proof = await buildRegistrationOwnerProof({
    registrationCeremonyId: receipt.registrationCeremonyId,
    authMethod: receipt.authMethod,
    authority: receipt.authority,
    tenantId: input.authorizationTenantId,
    expectedOrigin: receipt.expectedOrigin,
    expiresAtMs: receipt.expiresAtMs,
  });
  const signed = await issueRouterAbEcdsaDerivationOpaqueWalletSessionToken({
    opaqueWalletSessions: input.authorizationService,
    tenantId: input.authorizationTenantId,
    proof,
    walletAuthAuthorityRef: await walletAuthAuthorityRef({ authority: receipt.authority }),
    authSource: walletSessionAuthSourceFromAuthority(receipt.authority),
    userId: bootstrap.walletId,
    relayerKeyId: bootstrap.relayerKeyId,
    fallbackParticipantIds: bootstrap.participantIds,
    invalidPayloadErrorMessage: 'Registration replay ECDSA Wallet Session is invalid',
    sessionInfo: {
      sessionKind: 'opaque',
      authorizationKind: 'owner_wallet_session',
      thresholdSessionId: projected.tokens.ecdsa.thresholdSessionId,
      authorizationId: projected.authorizationId,
      walletSessionId: projected.walletSessionId,
      quotaId: projected.quotaId,
      expiresAtMs: projected.expiresAtMs,
      participantIds: bootstrap.participantIds,
      runtimePolicyScope: projected.tokens.ecdsa.runtimePolicyScope,
      keyManifestDigestB64u: receipt.custodyKeyManifestDigestB64u,
      authorizationSessionId: registrationEstablishedEcdsaAuthorizationSessionId(
        projected.authorizationId,
      ),
      keyHandle: projected.tokens.ecdsa.keyHandle,
      stableKeyContext: {
        walletId: bootstrap.walletId,
        keyScope: 'evm-family',
        ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
        signingRootId: bootstrap.signingRootId,
        signingRootVersion: bootstrap.signingRootVersion,
        applicationBindingDigestB64u: bootstrap.applicationBindingDigestB64u,
        contextBinding32B64u: bootstrap.contextBinding32B64u,
      },
      publicIdentity: bootstrap.publicIdentity,
      activationEpoch: bootstrap.activationEpoch,
      signingWorkerId:
        bootstrap.routerAbEcdsaDerivationNormalSigning.scope.signing_worker.server_id,
      routerAbEcdsaDerivationNormalSigning:
        projected.tokens.ecdsa.routerAbEcdsaDerivationNormalSigning,
    },
  });
  if (!signed.ok || signed.authorizationKind !== 'owner_wallet_session') {
    throw new Error(
      signed.ok ? 'Registration replay ECDSA owner session is invalid' : signed.message,
    );
  }
  return {
    kind: 'registration_established_wallet_session_v1',
    walletId: projected.walletId,
    authorizationId: projected.authorizationId,
    walletSessionId: projected.walletSessionId,
    quotaId: projected.quotaId,
    expiresAtMs: projected.expiresAtMs,
    remainingUses: projected.remainingUses,
    tokens: {
      kind: 'evm_family_ecdsa',
      ecdsa: {
        sessionKind: 'opaque',
        walletSessionToken: signed.token,
        thresholdSessionId: projected.tokens.ecdsa.thresholdSessionId,
        keyHandle: projected.tokens.ecdsa.keyHandle,
        runtimePolicyScope: projected.tokens.ecdsa.runtimePolicyScope,
        routerAbEcdsaDerivationNormalSigning:
          projected.tokens.ecdsa.routerAbEcdsaDerivationNormalSigning,
      },
    },
  };
}

export async function replayRegistrationEstablishedEd25519Session(input: {
  readonly authorizationService: RegistrationEstablishedSessionReplayDependencies['authorizationService'];
  readonly authorizationTenantId: TenantId;
  readonly receipt: Extract<
    WalletRegistrationSessionCommitReceiptV2,
    { readonly committed: { readonly kind: 'near_ready' } }
  >;
}): Promise<RegistrationEstablishedSession> {
  const receipt = input.receipt;
  const projected = receipt.committed.session;
  if (projected.tokens.kind !== 'near_ed25519') {
    throw new Error('Registration NEAR receipt contains a different session branch');
  }
  const publicResult = receipt.committed.ed25519;
  const proof = await buildRegistrationOwnerProof({
    registrationCeremonyId: receipt.registrationCeremonyId,
    authMethod: receipt.authMethod,
    authority: receipt.authority,
    tenantId: input.authorizationTenantId,
    expectedOrigin: receipt.expectedOrigin,
    expiresAtMs: receipt.expiresAtMs,
  });
  const signed = await issueRouterAbEd25519OpaqueWalletSessionToken({
    opaqueWalletSessions: input.authorizationService,
    tenantId: input.authorizationTenantId,
    proof,
    userId: receipt.authority.walletId,
    relayerKeyId: publicResult.relayerKeyId,
    authority: receipt.authority,
    fallbackParticipantIds: publicResult.participantIds,
    invalidPayloadErrorMessage: 'Registration replay Ed25519 Wallet Session is invalid',
    sessionInfo: {
      sessionKind: 'opaque',
      authorizationKind: 'owner_wallet_session',
      walletId: receipt.authority.walletId,
      nearAccountId: projected.tokens.ed25519.nearAccountId,
      nearEd25519SigningKeyId: projected.tokens.ed25519.nearEd25519SigningKeyId,
      authorizationId: projected.authorizationId,
      thresholdSessionId: projected.tokens.ed25519.thresholdSessionId,
      walletSessionId: projected.walletSessionId,
      quotaId: projected.quotaId,
      expiresAtMs: projected.expiresAtMs,
      participantIds: publicResult.participantIds,
      runtimePolicyScope: projected.tokens.ed25519.runtimePolicyScope,
      routerAbNormalSigning: projected.tokens.ed25519.routerAbNormalSigning,
      keyManifestDigestB64u: receipt.custodyKeyManifestDigestB64u,
    },
  });
  if (!signed.ok || signed.authorizationKind !== 'owner_wallet_session') {
    throw new Error(
      signed.ok ? 'Registration replay Ed25519 owner session is invalid' : signed.message,
    );
  }
  return {
    kind: 'registration_established_wallet_session_v1',
    walletId: projected.walletId,
    authorizationId: projected.authorizationId,
    walletSessionId: projected.walletSessionId,
    quotaId: projected.quotaId,
    expiresAtMs: projected.expiresAtMs,
    remainingUses: projected.remainingUses,
    tokens: {
      kind: 'near_ed25519',
      ed25519: {
        sessionKind: 'opaque',
        walletSessionToken: signed.token,
        thresholdSessionId: projected.tokens.ed25519.thresholdSessionId,
        nearAccountId: projected.tokens.ed25519.nearAccountId,
        nearEd25519SigningKeyId: projected.tokens.ed25519.nearEd25519SigningKeyId,
        runtimePolicyScope: projected.tokens.ed25519.runtimePolicyScope,
        routerAbNormalSigning: projected.tokens.ed25519.routerAbNormalSigning,
      },
    },
  };
}
