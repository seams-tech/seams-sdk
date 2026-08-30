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
import type { AuthorizationService } from '../../../../authorization/service';
import type {
  DirectV2IssueResult,
  IssuedWalletSessionAuthorizationV2,
} from '../../../../authorization/domain';
import type { EcdsaDerivationServerBootstrapResponse } from '../../../../core/types';
import type { WalletRegistrationSessionCommitReceiptV2 } from '../../../../core/threeRouteRegistrationContracts';
import type { StoredRegistrationAuthority } from '../../../../core/RegistrationCeremonyStore';
import {
  parseAuthFactorId,
  parsePrincipalId,
  type PrincipalId,
  type TenantId,
} from '@shared/authorization/capabilityKinds';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  parseEmailOtpChallengeId,
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
import type {
  RegistrationEstablishedSessionProjectionTokensV2,
  RegistrationEstablishedSessionProjectionV2,
  RegistrationEstablishedSessionResultV2,
  RegistrationEstablishedSessionV2,
} from '@shared/utils/registrationEstablishedSession';
import type {
  ActiveWalletSessionV1,
  WalletCapabilitySubjectV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking/contracts';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { registrationEstablishedMintId } from './walletRegistrationSessionCommitReceipt';

export type RegistrationEstablishedSessionIssuerAuthorizationService = Pick<
  AuthorizationService,
  | 'issueDirectWalletSessionAuthorizationV2'
  | 'issueDirectRegistrationPromotedWalletSessionAuthorizationV2'
  | 'readWalletSessionAuthorizationV2ByMint'
  | 'readWalletSessionAuthorizationV2ByAuthorizationId'
  | 'refreshWalletSessionAuthorizationV2AuthorityProjection'
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

function requireWalletSessionPrincipalId(value: string): PrincipalId {
  const parsed = parsePrincipalId(value);
  if (!parsed.ok) {
    throw new Error(`Wallet Session principal is invalid: ${parsed.error.message}`);
  }
  return parsed.value;
}

export function walletSessionPrincipalId(authority: WalletAuthAuthority): PrincipalId {
  return requireWalletSessionPrincipalId(
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
  const principalId = walletSessionPrincipalId(input.authority);
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

export type RegistrationEstablishedSessionIssuanceResultV2 =
  | {
      readonly kind: 'issued';
      readonly session: RegistrationEstablishedSessionV2;
      readonly issuedAtMs: number;
    }
  | {
      readonly kind: 'already_committed';
      readonly session: RegistrationEstablishedSessionProjectionV2;
      readonly next: 'unlock_exact_method';
      readonly issuedAtMs: number;
    };

async function readDirectRegistrationAuthorization(input: {
  readonly authorizationService: RegistrationEstablishedSessionIssuerAuthorizationService;
  readonly authorizationTenantId: TenantId;
  readonly authority: WalletAuthAuthority;
  readonly registrationCeremonyId: string;
  readonly committed: Extract<DirectV2IssueResult, { readonly kind: 'already_committed' }>;
}): Promise<IssuedWalletSessionAuthorizationV2> {
  const mintRead = await input.authorizationService.readWalletSessionAuthorizationV2ByMint({
    tenantId: input.authorizationTenantId,
    principalId: walletSessionPrincipalId(input.authority),
    walletId: walletIdFromString(String(input.authority.walletId)),
    authorityId: input.committed.authorityId,
    walletAuthMethodId: input.committed.walletAuthMethodId,
    mintId: input.committed.mintId,
  });
  if (!mintRead) throw new Error('Direct registration Wallet Session commit is unavailable');
  if (
    mintRead.session.authorizationId !== input.committed.authorizationId ||
    mintRead.session.walletSessionId !== input.committed.walletSessionId ||
    mintRead.session.quotaId !== input.committed.quotaId
  ) {
    throw new Error('Direct registration Wallet Session commit identity changed');
  }
  const persisted =
    await input.authorizationService.readWalletSessionAuthorizationV2ByAuthorizationId({
      expected: mintRead.session,
      nowMs: Date.now(),
    });
  if (!persisted) throw new Error('Direct registration Wallet Session quota is unavailable');
  return persisted;
}

function walletSessionSubjectForClient(
  subject: import('../../../../authorization/domain').WalletSessionCapabilitySubjectV1,
): WalletCapabilitySubjectV1 {
  switch (subject.kind) {
    case 'sign':
    case 'export_keys':
      return {
        kind: subject.kind,
        keyFamily: subject.keyFamily,
        materialActivation: subject.materialActivation,
      };
    case 'link_devices':
    case 'revoke_devices':
      return { kind: subject.kind };
    default:
      return assertNeverRegistrationCapabilitySubject(subject);
  }
}

function assertNeverRegistrationCapabilitySubject(value: never): never {
  throw new Error(`Unsupported registration Wallet Session capability subject: ${String(value)}`);
}

function activeWalletSessionFromAuthorization(
  issued: IssuedWalletSessionAuthorizationV2,
): ActiveWalletSessionV1 {
  const authorization = issued.session;
  const subjects = authorization.capabilitySubjects.map(walletSessionSubjectForClient);
  const [first, ...remaining] = subjects;
  if (!first) throw new Error('Direct registration Wallet Session has no capability subjects');
  return {
    kind: 'active_wallet_session_v1',
    walletId: authorization.walletId,
    authorityId: authorization.authorityId,
    authMethodId: authorization.walletAuthMethodId,
    authorizationId: authorization.authorizationId,
    quotaId: issued.quota.quotaId,
    authorityDigestB64u: authorization.authorityDigestB64u,
    authorityRevocationEpoch: authorization.authorityRevocationEpoch,
    capabilitySubjects: [first, ...remaining],
    issuedAtMs: authorization.createdAtMs,
    expiresAtMs: authorization.expiresAtMs,
  };
}

function registrationSignMaterialActivation(
  authorization: IssuedWalletSessionAuthorizationV2['session'],
  keyFamily: 'ed25519' | 'ecdsa_secp256k1',
): MpcMaterialActivationRef {
  const subject = authorization.capabilitySubjects.find(
    (candidate) => candidate.kind === 'sign' && candidate.keyFamily === keyFamily,
  );
  if (!subject || subject.kind !== 'sign') {
    throw new Error(
      `Direct registration Wallet Session is missing ${keyFamily} signing capability`,
    );
  }
  return subject.materialActivation;
}

function registrationSessionPolicy(input: {
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly issuedAtMs: number;
}): { readonly expiresAtMs: number; readonly remainingUses: number } {
  if (!Number.isSafeInteger(input.remainingUses) || input.remainingUses <= 0) {
    throw new Error('Registration-established session remaining uses is invalid');
  }
  if (!Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= input.issuedAtMs) {
    throw new Error('Registration-established session expiry is invalid');
  }
  return {
    expiresAtMs: Math.min(input.expiresAtMs, input.issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS),
    remainingUses: Math.min(DEFAULT_WALLET_SESSION_REMAINING_USES, input.remainingUses),
  };
}

function directRegistrationSession(
  authorization: IssuedWalletSessionAuthorizationV2,
  tokens: RegistrationEstablishedSessionProjectionTokensV2,
  operationCredential: WalletSessionOperationCredentialV1,
): RegistrationEstablishedSessionV2 {
  const walletSession = activeWalletSessionFromAuthorization(authorization);
  if (operationCredential.walletSessionId !== authorization.session.walletSessionId) {
    throw new Error('Direct registration operation credential identity does not match the session');
  }
  return {
    kind: 'registration_established_wallet_session_v2',
    walletId: walletSession.walletId,
    authorizationId: walletSession.authorizationId,
    walletSessionId: authorization.session.walletSessionId,
    quotaId: authorization.quota.quotaId,
    expiresAtMs: authorization.session.expiresAtMs,
    remainingUses: authorization.quota.remainingUses,
    walletSession,
    operationCredential,
    tokens,
  };
}

function projectDirectRegistrationSession(
  authorization: IssuedWalletSessionAuthorizationV2,
  tokens: RegistrationEstablishedSessionProjectionTokensV2,
): RegistrationEstablishedSessionProjectionV2 {
  const walletSession = activeWalletSessionFromAuthorization(authorization);
  return {
    kind: 'registration_established_wallet_session_projection_v2',
    walletId: walletSession.walletId,
    authorizationId: walletSession.authorizationId,
    walletSessionId: authorization.session.walletSessionId,
    quotaId: walletSession.quotaId,
    expiresAtMs: walletSession.expiresAtMs,
    remainingUses: authorization.quota.remainingUses,
    walletSession,
    tokens,
  };
}

function ecdsaRegistrationSessionTokens(input: {
  readonly authorization: IssuedWalletSessionAuthorizationV2['session'];
  readonly bootstrap: EcdsaDerivationServerBootstrapResponse;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly keyHandle: ReturnType<typeof deriveThresholdEcdsaKeyHandle> extends Promise<infer T>
    ? T
    : never;
}): RegistrationEstablishedSessionProjectionTokensV2 {
  const thresholdSessionId = parseThresholdEcdsaSessionId(input.bootstrap.thresholdSessionId);
  if (!thresholdSessionId.ok) throw new Error(thresholdSessionId.error.message);
  const materialActivation = registrationSignMaterialActivation(
    input.authorization,
    'ecdsa_secp256k1',
  );
  const bootstrapMaterialActivation = routerAbMpcMaterialActivationRefFromWire(
    input.bootstrap.routerAbEcdsaDerivationNormalSigning.scope.material_activation,
  );
  if (!mpcMaterialActivationRefsEqual(materialActivation, bootstrapMaterialActivation)) {
    throw new Error('Registration ECDSA bootstrap material activation is inconsistent');
  }
  return {
    kind: 'evm_family_ecdsa',
    ecdsa: {
      sessionKind: 'credential_free_projection_v2',
      thresholdSessionId: thresholdSessionId.value,
      keyHandle: input.keyHandle,
      runtimePolicyScope: input.runtimePolicyScope,
      materialActivation,
      routerAbEcdsaDerivationNormalSigning: input.bootstrap.routerAbEcdsaDerivationNormalSigning,
    },
  };
}

function ed25519RegistrationSessionTokens(input: {
  readonly authorization: IssuedWalletSessionAuthorizationV2['session'];
  readonly publicResult: WalletRegistrationEd25519YaoPublicResult;
}): Extract<RegistrationEstablishedSessionProjectionTokensV2, { readonly kind: 'near_ed25519' }> {
  const thresholdSessionId = parseThresholdEd25519SessionId(input.publicResult.thresholdSessionId);
  if (!thresholdSessionId.ok) throw new Error(thresholdSessionId.error.message);
  const nearAccount = parseImplicitNearAccountId(input.publicResult.nearAccountId);
  const namedNearAccount = parseNamedNearAccountId(input.publicResult.nearAccountId);
  const nearAccountId = nearAccount.ok
    ? nearAccount.value
    : namedNearAccount.ok
      ? namedNearAccount.value
      : null;
  if (!nearAccountId) throw new Error('Registration Ed25519 near account identity is invalid');
  return {
    kind: 'near_ed25519',
    ed25519: {
      sessionKind: 'credential_free_projection_v2',
      thresholdSessionId: thresholdSessionId.value,
      nearAccountId,
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
        input.publicResult.nearEd25519SigningKeyId,
      ),
      runtimePolicyScope: input.publicResult.runtimePolicyScope,
      materialActivation: registrationSignMaterialActivation(input.authorization, 'ed25519'),
      routerAbNormalSigning: input.publicResult.routerAbNormalSigning,
    },
  };
}

export type Ed25519RegistrationSessionPredecessor =
  | { readonly kind: 'ed25519_only' }
  | {
      readonly kind: 'mixed';
      readonly ecdsa: Extract<
        RegistrationEstablishedSessionProjectionTokensV2,
        { readonly kind: 'evm_family_ecdsa' }
      >['ecdsa'];
    };

function completeEd25519RegistrationSessionTokens(input: {
  readonly ed25519: Extract<
    RegistrationEstablishedSessionProjectionTokensV2,
    { readonly kind: 'near_ed25519' }
  >['ed25519'];
  readonly predecessor: Ed25519RegistrationSessionPredecessor;
}): RegistrationEstablishedSessionProjectionTokensV2 {
  switch (input.predecessor.kind) {
    case 'ed25519_only':
      return { kind: 'near_ed25519', ed25519: input.ed25519 };
    case 'mixed':
      return {
        kind: 'near_ed25519_and_evm_family_ecdsa',
        ecdsa: input.predecessor.ecdsa,
        ed25519: input.ed25519,
      };
    default:
      return assertNeverEd25519RegistrationSessionPredecessor(input.predecessor);
  }
}

function assertNeverEd25519RegistrationSessionPredecessor(value: never): never {
  throw new Error(`Unsupported Ed25519 registration predecessor: ${String(value)}`);
}

function directRegistrationResultFromIssue(input: {
  readonly directIssue: DirectV2IssueResult;
  readonly authorization: IssuedWalletSessionAuthorizationV2;
  readonly tokens: RegistrationEstablishedSessionProjectionTokensV2;
}): RegistrationEstablishedSessionIssuanceResultV2 {
  switch (input.directIssue.kind) {
    case 'issued':
      return {
        kind: 'issued',
        session: directRegistrationSession(
          input.authorization,
          input.tokens,
          input.directIssue.operationCredential,
        ),
        issuedAtMs: input.authorization.session.createdAtMs,
      };
    case 'already_committed':
      return {
        kind: 'already_committed',
        session: projectDirectRegistrationSession(input.authorization, input.tokens),
        next: input.directIssue.next,
        issuedAtMs: input.authorization.session.createdAtMs,
      };
    default:
      return assertNeverDirectRegistrationIssue(input.directIssue);
  }
}

function assertNeverDirectRegistrationIssue(value: never): never {
  throw new Error(`Unsupported direct registration Wallet Session result: ${String(value)}`);
}

export async function assertDirectWalletSessionOwnerProof(input: {
  readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
  readonly tenantId: TenantId;
  readonly authority: WalletAuthAuthority;
  readonly activeAuthority: ActiveWalletAuthorityV1;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly nowMs: number;
}): Promise<void> {
  const authorityRef = await walletAuthAuthorityRef({ authority: input.authority });
  if (
    input.proof.tenantId !== input.tenantId ||
    input.proof.walletId !== input.authority.walletId ||
    input.proof.principalId !== walletSessionPrincipalId(input.authority) ||
    input.proof.authority.walletId !== authorityRef.walletId ||
    input.proof.authority.authorityDigest !== authorityRef.authorityDigest ||
    input.proof.authority.walletAuthMethodId !== authorityRef.walletAuthMethodId ||
    input.activeAuthority.walletId !== input.authority.walletId ||
    input.activeAuthority.state !== 'active' ||
    input.walletAuthMethodId !== authorityRef.walletAuthMethodId ||
    input.proof.verifiedAtMs > input.nowMs ||
    input.proof.expiresAtMs <= input.nowMs
  ) {
    throw new Error('Owner proof does not authorize direct Wallet Session issuance');
  }
}

export async function issueDirectRegistrationEstablishedEcdsaSession(
  input: RegistrationEstablishedSessionIssuanceDependencies & {
    readonly registrationCeremonyId: string;
    readonly authority: WalletAuthAuthority;
    readonly registrationAuthority: StoredRegistrationAuthority;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly expiresAtMs: number;
    readonly remainingUses: number;
    readonly bootstrap: EcdsaDerivationServerBootstrapResponse;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly keyManifestDigestB64u: DigestB64u;
    readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
  },
): Promise<RegistrationEstablishedSessionIssuanceResultV2> {
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
  const issuedAtMs = Date.now();
  await assertDirectWalletSessionOwnerProof({
    proof: input.proof,
    tenantId: input.authorizationTenantId,
    authority: input.authority,
    activeAuthority: activeRegistration.authority,
    walletAuthMethodId: activeRegistration.walletAuthMethodId,
    nowMs: issuedAtMs,
  });
  const policy = registrationSessionPolicy({
    issuedAtMs,
    expiresAtMs: input.expiresAtMs,
    remainingUses: input.remainingUses,
  });
  const directIssue = await input.authorizationService.issueDirectWalletSessionAuthorizationV2({
    tenantId: input.authorizationTenantId,
    principalId: walletSessionPrincipalId(input.authority),
    walletId: walletIdFromString(String(input.authority.walletId)),
    authority: activeRegistration.authority,
    walletAuthMethodId: activeRegistration.walletAuthMethodId,
    mintId: registrationEstablishedMintId(input.registrationCeremonyId),
    remainingUses: policy.remainingUses,
    issuedAtMs,
    expiresAtMs: policy.expiresAtMs,
  });
  let authorization: IssuedWalletSessionAuthorizationV2;
  switch (directIssue.kind) {
    case 'issued':
      authorization = { session: directIssue.session, quota: directIssue.quota };
      break;
    case 'already_committed':
      authorization = await readDirectRegistrationAuthorization({
        authorizationService: input.authorizationService,
        authorizationTenantId: input.authorizationTenantId,
        authority: input.authority,
        registrationCeremonyId: input.registrationCeremonyId,
        committed: directIssue,
      });
      break;
    default:
      return assertNeverDirectRegistrationIssue(directIssue);
  }
  const keyHandle = await deriveThresholdEcdsaKeyHandle({
    ecdsaThresholdKeyId: input.bootstrap.ecdsaThresholdKeyId,
    signingRootId: input.bootstrap.signingRootId,
    signingRootVersion: input.bootstrap.signingRootVersion,
  });
  if (keyHandle !== input.bootstrap.keyHandle) {
    throw new Error('Registration ECDSA bootstrap key handle is inconsistent');
  }
  const tokens = ecdsaRegistrationSessionTokens({
    authorization: authorization.session,
    bootstrap: input.bootstrap,
    runtimePolicyScope: input.runtimePolicyScope,
    keyHandle,
  });
  return directRegistrationResultFromIssue({ directIssue, authorization, tokens });
}

export async function issueDirectRegistrationEstablishedEd25519Session(
  input: RegistrationEstablishedSessionIssuanceDependencies & {
    readonly registrationCeremonyId: string;
    readonly authority: WalletAuthAuthority;
    readonly registrationAuthority: StoredRegistrationAuthority;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly expiresAtMs: number;
    readonly remainingUses: number;
    readonly publicResult: WalletRegistrationEd25519YaoPublicResult;
    readonly predecessor: Ed25519RegistrationSessionPredecessor;
    readonly keyManifestDigestB64u: DigestB64u;
    readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
  },
): Promise<RegistrationEstablishedSessionIssuanceResultV2> {
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
  const issuedAtMs = Date.now();
  await assertDirectWalletSessionOwnerProof({
    proof: input.proof,
    tenantId: input.authorizationTenantId,
    authority: input.authority,
    activeAuthority: activeRegistration.authority,
    walletAuthMethodId: activeRegistration.walletAuthMethodId,
    nowMs: issuedAtMs,
  });
  const policy = registrationSessionPolicy({
    issuedAtMs,
    expiresAtMs: input.expiresAtMs,
    remainingUses: input.remainingUses,
  });
  const directIssue =
    await input.authorizationService.issueDirectRegistrationPromotedWalletSessionAuthorizationV2({
      tenantId: input.authorizationTenantId,
      principalId: walletSessionPrincipalId(input.authority),
      walletId: walletIdFromString(String(input.authority.walletId)),
      authority: activeRegistration.authority,
      walletAuthMethodId: activeRegistration.walletAuthMethodId,
      mintId: registrationEstablishedMintId(input.registrationCeremonyId),
      remainingUses: policy.remainingUses,
      issuedAtMs,
      expiresAtMs: policy.expiresAtMs,
    });
  let authorization: IssuedWalletSessionAuthorizationV2;
  switch (directIssue.kind) {
    case 'issued':
      authorization = { session: directIssue.session, quota: directIssue.quota };
      break;
    case 'already_committed': {
      const existing = await readDirectRegistrationAuthorization({
        authorizationService: input.authorizationService,
        authorizationTenantId: input.authorizationTenantId,
        authority: input.authority,
        registrationCeremonyId: input.registrationCeremonyId,
        committed: directIssue,
      });
      authorization =
        await input.authorizationService.refreshWalletSessionAuthorizationV2AuthorityProjection({
          existing,
          authority: activeRegistration.authority,
          walletAuthMethodId: activeRegistration.walletAuthMethodId,
        });
      break;
    }
    default:
      return assertNeverDirectRegistrationIssue(directIssue);
  }
  const ed25519Tokens = ed25519RegistrationSessionTokens({
    authorization: authorization.session,
    publicResult: input.publicResult,
  });
  const tokens = completeEd25519RegistrationSessionTokens({
    ed25519: ed25519Tokens.ed25519,
    predecessor: input.predecessor,
  });
  return directRegistrationResultFromIssue({ directIssue, authorization, tokens });
}

export function replayDirectRegistrationEstablishedEcdsaSession(
  receipt: Extract<
    WalletRegistrationSessionCommitReceiptV2,
    { readonly committed: { readonly kind: 'ecdsa_ready' } }
  >,
): RegistrationEstablishedSessionResultV2 {
  if (receipt.committed.session.tokens.kind !== 'evm_family_ecdsa') {
    throw new Error('Registration ECDSA receipt contains a different session branch');
  }
  return {
    kind: 'already_committed',
    session: receipt.committed.session,
    next: 'unlock_exact_method',
  };
}

export function replayDirectRegistrationEstablishedEd25519Session(
  receipt: Extract<
    WalletRegistrationSessionCommitReceiptV2,
    { readonly committed: { readonly kind: 'near_ready' } }
  >,
): RegistrationEstablishedSessionResultV2 {
  if (
    receipt.committed.session.tokens.kind !== 'near_ed25519' &&
    receipt.committed.session.tokens.kind !== 'near_ed25519_and_evm_family_ecdsa'
  ) {
    throw new Error('Registration NEAR receipt contains a different session branch');
  }
  return {
    kind: 'already_committed',
    session: receipt.committed.session,
    next: 'unlock_exact_method',
  };
}
