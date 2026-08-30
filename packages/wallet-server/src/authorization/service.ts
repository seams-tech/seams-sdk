import type { WalletAuthMethodId, WalletId } from '@shared/utils/domainIds';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import type {
  ActiveWalletSessionQuota,
  AuthorizedOperation,
  AuthorizedOperationInput,
  AuthorizedOperationReplayResponse,
  CompletedCapabilityOperationResult,
  HostedWalletSeamsSessionExchangeCode,
  HostedWalletSeamsSessionExchangeDeliveryV2,
  HostedWalletSeamsSessionExchangeNonce,
  IssuedHostedWalletSeamsSessionExchangeV2,
  PersistedHostedWalletSeamsSessionExchangeV2Result,
  RedeemHostedWalletSeamsSessionExchangeV2Input,
  RedeemHostedWalletSeamsSessionExchangeV2Result,
  ExactWalletSessionStatusV2,
  ResolvedHostedWalletSessionOperationCredentialV2,
  SessionOrigin,
  VerifiedAuthorizationEvidenceSet,
  IssuedWalletSessionAuthorizationV2,
  DirectV2CommitResult,
  DirectV2IssueResult,
  PersistedActiveWalletSessionAuthorizationV2,
  WalletSessionAuthorizationV2MintLookup,
  WalletSessionAuthorizationV2MintRead,
  WalletSessionAuthorizationV2,
  VerifiedOwnerProof,
} from './domain';
import {
  buildActiveWalletSessionQuota,
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
  buildPersistedActiveWalletSessionAuthorizationV2,
  parseHostedWalletSeamsSessionExchangeCode,
  parseHostedWalletSeamsSessionExchangeNonce,
  parseHostedWalletSessionCredentialId,
  parseHostedWalletSessionOperationCredentialV1,
  parsePrimaryWalletSessionOperationCredentialToken,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from './domain';
import {
  parseHostedWalletSessionExchangeCodeId,
  parseWalletSessionAuthorizationId,
  type MpcWalletSigningQuotaId,
  type AuthorizedOperationId,
  type PrincipalId,
  type WalletSessionMintId,
  type TenantId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  buildVerifiedWalletOperationFactorEvidenceSet,
  buildVerifiedOwnerProof,
  type VerifiedWalletOperationFactorEvidenceSetInput,
  type VerifiedOwnerProofInput,
} from './factorEvidence';
import type {
  CapabilityPolicyPort,
  AuthorizationEvidenceRequirementEvaluation,
  ParseAuthorizationEvidenceRequirementResult,
} from './capabilityPolicy';
import type { AuthorizationEvidenceRequirement } from '@shared/authorization/capabilityKinds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { WalletSessionOperationCredentialV1 } from '@shared/device-linking/contracts';
import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking/parsers';
import type { CapabilityOperationFingerprintDigest } from '@shared/authorization/operationFingerprint';

export interface AuthorizationSessionPort {
  putIssuedHostedWalletSeamsSessionExchange(
    exchange: IssuedHostedWalletSeamsSessionExchangeV2,
  ): Promise<void>;
  redeemHostedWalletSeamsSessionExchange(
    input: RedeemHostedWalletSeamsSessionExchangeV2Input,
  ): Promise<PersistedHostedWalletSeamsSessionExchangeV2Result>;
  readHostedWalletSessionOperationCredentialV2(input: {
    readonly tenantId: TenantId;
    readonly tokenHash: DigestB64u;
    readonly requestOrigin: SessionOrigin;
    readonly nowMs: number;
  }): Promise<ResolvedHostedWalletSessionOperationCredentialV2 | null>;
}

export interface AuthorizationEvidencePort {
  putVerifiedEvidenceSet(evidenceSet: VerifiedAuthorizationEvidenceSet): Promise<void>;
  consumeVerifiedOwnerProof(
    proof: VerifiedOwnerProof,
    consumedAtMs: number,
    consumptionScopeId: string,
  ): Promise<boolean>;
}

export interface AuthorizationGrantPort {
  retireWalletSessionAuthorizationsForAuthMethod(input: {
    readonly tenantId: TenantId;
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly nowMs: number;
  }): Promise<void>;
  replaceWalletSessionAuthorizationV2AuthorityProjection(input: {
    readonly session: WalletSessionAuthorizationV2;
    readonly quota: ActiveWalletSessionQuota;
  }): Promise<void>;
  readWalletSessionAuthorizationV2ByMint(
    input: WalletSessionAuthorizationV2MintLookup,
  ): Promise<WalletSessionAuthorizationV2MintRead | null>;
  commitDirectWalletSessionAuthorizationV2(input: {
    readonly persisted: PersistedActiveWalletSessionAuthorizationV2;
  }): Promise<DirectV2CommitResult>;
  readWalletSessionAuthorizationV2ByAuthorizationId(input: {
    readonly expected: WalletSessionAuthorizationV2;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null>;
  readWalletSessionAuthorizationV2ByIdentity(input: {
    readonly tenantId: TenantId;
    readonly walletId: WalletId;
    readonly walletSessionId: WalletSessionId;
    readonly authorizationId: WalletSessionAuthorizationId;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null>;
  readWalletSessionAuthorizationV2ByOperationCredential(input: {
    readonly tenantId: TenantId;
    readonly tokenHash: DigestB64u;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null>;
  readExactWalletSessionStatusByOperationCredential(input: {
    readonly tenantId: TenantId;
    readonly tokenHash: DigestB64u;
    readonly nowMs: number;
  }): Promise<ExactWalletSessionStatusV2>;
}

export interface AuthorizedOperationPort {
  readAuthorizedOperationById(input: {
    readonly tenantId: TenantId;
    readonly authorizedOperationId: AuthorizedOperationId;
  }): Promise<AuthorizedOperation | null>;
  readAuthorizedOperation(input: {
    readonly tenantId: TenantId;
    readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  }): Promise<AuthorizedOperation | null>;
  admitAuthorizedOperation(input: {
    readonly operation: AuthorizedOperationInput;
    readonly material?: AuthorizedOperationMaterialScope;
  }): Promise<AuthorizedOperationAdmissionResult>;
  completeAuthorizedOperation(input: {
    readonly operation: AuthorizedOperation;
    readonly result: CompletedCapabilityOperationResult;
    readonly response: AuthorizedOperationReplayResponse;
    readonly completedAtMs: number;
  }): Promise<AuthorizedOperation>;
}

export type AuthorizedOperationAdmissionResult =
  | { readonly kind: 'claimed'; readonly operation: AuthorizedOperation }
  | { readonly kind: 'replayed'; readonly operation: AuthorizedOperation }
  | { readonly kind: 'operation_in_progress'; readonly operation: AuthorizedOperation }
  | {
      readonly kind:
        | 'authorization_grant_rejected'
        | 'verified_step_up_rejected'
        | 'wallet_session_quota_exhausted'
        | 'material_mismatch';
    };

export type EcdsaMaterialActivationScope = Readonly<{
  readonly walletId: WalletId;
  readonly keyHandle: string;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
}>;

export type AuthorizedOperationMaterialScope = EcdsaMaterialActivationScope & {
  readonly kind?: 'ecdsa_material_activation';
};

export type AuthorizationServicePorts = {
  readonly policy: CapabilityPolicyPort;
  readonly sessions: AuthorizationSessionPort;
  readonly evidence: AuthorizationEvidencePort;
  readonly grants: AuthorizationGrantPort;
  readonly authorizedOperations: AuthorizedOperationPort;
  readonly audit: object;
};

export type IssueWalletSessionAuthorizationV2Input = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authority: import('@shared/authorization/walletAuthority').ActiveWalletAuthorityV1;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly mintId: WalletSessionMintId;
  readonly remainingUses: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type PreparedWalletSessionAuthorizationV2 = {
  readonly session: WalletSessionAuthorizationV2;
  readonly quota: ActiveWalletSessionQuota;
};

export class AuthorizationService {
  constructor(private readonly ports: AuthorizationServicePorts) {}

  async retireWalletSessionAuthorizationsForAuthMethod(input: {
    readonly tenantId: TenantId;
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly nowMs: number;
  }): Promise<void> {
    await this.ports.grants.retireWalletSessionAuthorizationsForAuthMethod(input);
  }

  async mintHostedWalletSeamsSessionExchange(input: {
    readonly authorization: IssuedWalletSessionAuthorizationV2;
    readonly appOrigin: SessionOrigin;
    readonly walletOrigin: SessionOrigin;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<HostedWalletSeamsSessionExchangeDeliveryV2> {
    const expiresAtMs = Math.min(
      input.expiresAtMs,
      input.authorization.session.expiresAtMs,
      input.authorization.quota.expiresAtMs,
    );
    if (
      !Number.isSafeInteger(input.issuedAtMs) ||
      input.issuedAtMs <= 0 ||
      !Number.isSafeInteger(expiresAtMs) ||
      expiresAtMs <= input.issuedAtMs
    ) {
      throw new Error('hosted-wallet Seams session exchange expiry must follow issuance');
    }
    const exchangeCode = parseHostedWalletSeamsSessionExchangeCode(
      secureRandomBase64Url(32, 'hosted-wallet Seams session exchange codes'),
    );
    const nonce = parseHostedWalletSeamsSessionExchangeNonce(
      secureRandomBase64Url(32, 'hosted-wallet Seams session exchange nonces'),
    );
    const exchangeCodeId = parseRequired(
      `hwx_${secureRandomBase64Url(18, 'hosted-wallet Seams session exchange identifiers')}`,
      parseHostedWalletSessionExchangeCodeId,
    );
    await this.ports.sessions.putIssuedHostedWalletSeamsSessionExchange({
      kind: 'issued_hosted_wallet_session_exchange_v2',
      tenantId: input.authorization.session.tenantId,
      exchangeCodeId,
      authorizationId: input.authorization.session.authorizationId,
      walletSessionId: input.authorization.session.walletSessionId,
      quotaId: input.authorization.session.quotaId,
      principalId: input.authorization.session.principalId,
      walletId: input.authorization.session.walletId,
      authorityId: input.authorization.session.authorityId,
      walletAuthMethodId: input.authorization.session.walletAuthMethodId,
      codeHash: await digestOpaqueValue(exchangeCode),
      nonceDigest: await digestOpaqueValue(nonce),
      appOrigin: input.appOrigin,
      walletOrigin: input.walletOrigin,
      issuedAtMs: input.issuedAtMs,
      expiresAtMs,
    });
    return {
      kind: 'hosted_wallet_session_exchange_delivery_v2',
      exchangeCode,
      nonce,
      appOrigin: input.appOrigin,
      walletOrigin: input.walletOrigin,
      expiresAtMs,
    };
  }

  async redeemHostedWalletSeamsSessionExchange(input: {
    readonly exchangeCode: HostedWalletSeamsSessionExchangeCode;
    readonly nonce: HostedWalletSeamsSessionExchangeNonce;
    readonly appOrigin: SessionOrigin;
    readonly walletOrigin: SessionOrigin;
    readonly redeemedAtMs: number;
  }): Promise<RedeemHostedWalletSeamsSessionExchangeV2Result> {
    const hostedCredentialToken = `wsh_${secureRandomBase64Url(
      32,
      'hosted-wallet exchanged child credentials',
    )}`;
    const hostedCredentialId = parseHostedWalletSessionCredentialId(
      `hcr_${secureRandomBase64Url(18, 'hosted-wallet child credential identifiers')}`,
    );
    const persisted = await this.ports.sessions.redeemHostedWalletSeamsSessionExchange({
      codeHash: await digestOpaqueValue(input.exchangeCode),
      nonceDigest: await digestOpaqueValue(input.nonce),
      appOrigin: input.appOrigin,
      walletOrigin: input.walletOrigin,
      tokenHash: await digestOpaqueValue(hostedCredentialToken),
      hostedCredentialId,
      redeemedAtMs: input.redeemedAtMs,
    });
    if (persisted.kind !== 'redeemed') return persisted;
    const operationCredential = parseHostedWalletSessionOperationCredentialV1({
      kind: 'opaque_hosted_wallet_session_operation_credential_v1',
      token: hostedCredentialToken,
      walletSessionId: persisted.walletSessionId,
    });
    return {
      kind: 'redeemed',
      walletSessionId: persisted.walletSessionId,
      operationCredential,
      expiresAtMs: persisted.expiresAtMs,
    };
  }

  async recordVerifiedWalletOperationFactorEvidenceSet(
    input: VerifiedWalletOperationFactorEvidenceSetInput,
  ): Promise<VerifiedAuthorizationEvidenceSet> {
    const evidenceSet = await buildVerifiedWalletOperationFactorEvidenceSet(input);
    await this.ports.evidence.putVerifiedEvidenceSet(evidenceSet);
    return evidenceSet;
  }

  async buildVerifiedOwnerProof(input: VerifiedOwnerProofInput): Promise<VerifiedOwnerProof> {
    return await buildVerifiedOwnerProof(input);
  }

  async readAuthorizedOperation(input: {
    readonly tenantId: TenantId;
    readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  }): Promise<AuthorizedOperation | null> {
    return await this.ports.authorizedOperations.readAuthorizedOperation(input);
  }

  async readAuthorizedOperationById(input: {
    readonly tenantId: TenantId;
    readonly authorizedOperationId: AuthorizedOperationId;
  }): Promise<AuthorizedOperation | null> {
    return await this.ports.authorizedOperations.readAuthorizedOperationById(input);
  }

  async admitAuthorizedOperation(input: {
    readonly operation: AuthorizedOperationInput;
    readonly material?: AuthorizedOperationMaterialScope;
  }): Promise<AuthorizedOperationAdmissionResult> {
    return await this.ports.authorizedOperations.admitAuthorizedOperation(input);
  }

  async completeAuthorizedOperation(input: {
    readonly operation: AuthorizedOperation;
    readonly result: CompletedCapabilityOperationResult;
    readonly response: AuthorizedOperationReplayResponse;
    readonly completedAtMs: number;
  }): Promise<AuthorizedOperation> {
    return await this.ports.authorizedOperations.completeAuthorizedOperation(input);
  }

  /**
   * Issues one exact Wallet Session and its primary credential in the same
   * persistence transition. The replay branch is credential-free because a
   * committed digest cannot reproduce plaintext.
   */
  async issueDirectWalletSessionAuthorizationV2(
    input: IssueWalletSessionAuthorizationV2Input,
  ): Promise<DirectV2IssueResult> {
    if (input.authority.walletId !== input.walletId) {
      throw new Error('Wallet Session authorization authority does not identify the wallet');
    }
    const lookup: WalletSessionAuthorizationV2MintLookup = {
      tenantId: input.tenantId,
      principalId: input.principalId,
      walletId: input.walletId,
      authorityId: input.authority.authorityId,
      walletAuthMethodId: input.walletAuthMethodId,
      mintId: input.mintId,
    };
    const prepared = await this.prepareWalletSessionAuthorizationV2(input);
    const alreadyCommitted = await this.ports.grants.readWalletSessionAuthorizationV2ByMint(lookup);
    if (alreadyCommitted) {
      return directV2AlreadyCommitted(prepared.session, alreadyCommitted.session);
    }

    const token = `wst_${secureRandomBase64Url(32, 'direct V2 Wallet Session operation credentials')}`;
    const operationCredential = parseWalletSessionOperationCredentialV1({
      kind: 'opaque_wallet_session_operation_credential_v1',
      token,
      walletSessionId: prepared.session.walletSessionId,
    });
    const persisted = buildPersistedActiveWalletSessionAuthorizationV2({
      session: prepared.session,
      quota: prepared.quota,
      primaryOperationCredentialDigestB64u: await digestOpaqueValue(token),
    });
    const commit = await this.ports.grants.commitDirectWalletSessionAuthorizationV2({ persisted });
    if (commit.kind === 'already_committed') {
      return directV2AlreadyCommitted(prepared.session, commit.committed.session);
    }
    const committed = await this.ports.grants.readWalletSessionAuthorizationV2ByMint(lookup);
    if (!committed) {
      throw new Error('Direct V2 Wallet Session authorization was not persisted');
    }
    if (
      committed.primaryOperationCredentialDigestB64u !==
      persisted.primaryOperationCredentialDigestB64u
    ) {
      throw new Error('Direct V2 Wallet Session credential digest does not match its commit');
    }
    return {
      kind: 'issued',
      session: prepared.session,
      quota: prepared.quota,
      operationCredential,
    };
  }

  async refreshWalletSessionAuthorizationV2AuthorityProjection(input: {
    readonly existing: IssuedWalletSessionAuthorizationV2;
    readonly authority: ActiveWalletAuthorityV1;
    readonly walletAuthMethodId: WalletAuthMethodId;
  }): Promise<IssuedWalletSessionAuthorizationV2> {
    const current = input.existing.session;
    if (
      current.walletId !== input.authority.walletId ||
      current.authorityId !== input.authority.authorityId ||
      current.walletAuthMethodId !== input.walletAuthMethodId
    ) {
      throw new Error('Direct V2 Wallet Session authority projection identity does not match');
    }
    const session = buildWalletSessionAuthorizationV2({
      tenantId: current.tenantId,
      principalId: current.principalId,
      walletId: current.walletId,
      authorityId: current.authorityId,
      walletAuthMethodId: current.walletAuthMethodId,
      authorityDigestB64u: input.authority.authorityDigestB64u,
      authorityRevocationEpoch: input.authority.revocationEpoch,
      mintId: current.mintId,
      authorizationId: current.authorizationId,
      walletSessionId: current.walletSessionId,
      quotaId: current.quotaId,
      capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(input.authority),
      createdAtMs: current.createdAtMs,
      expiresAtMs: current.expiresAtMs,
    });
    const persisted = await this.ports.grants.readWalletSessionAuthorizationV2ByAuthorizationId({
      expected: current,
      nowMs: Date.now(),
    });
    if (!persisted) {
      throw new Error('Direct V2 Wallet Session authority projection is unavailable');
    }
    await this.ports.grants.replaceWalletSessionAuthorizationV2AuthorityProjection({
      session,
      quota: persisted.quota,
    });
    const refreshed = await this.ports.grants.readWalletSessionAuthorizationV2ByAuthorizationId({
      expected: session,
      nowMs: Date.now(),
    });
    if (!refreshed) {
      throw new Error('Direct V2 Wallet Session authority projection was not refreshed');
    }
    return refreshed;
  }

  async prepareWalletSessionAuthorizationV2(
    input: IssueWalletSessionAuthorizationV2Input,
  ): Promise<PreparedWalletSessionAuthorizationV2> {
    if (input.authority.walletId !== input.walletId) {
      throw new Error('Wallet Session authorization authority does not identify the wallet');
    }
    const authorizationId = parseRequired(
      await deriveWalletSessionAuthorizationV2Id(input, 'authorization'),
      parseWalletSessionAuthorizationId,
    );
    const walletSessionId = parseRequired(
      await deriveWalletSessionAuthorizationV2Id(input, 'wallet_session'),
      parseWalletSessionId,
    );
    const quotaId = parseRequired(
      await deriveWalletSessionAuthorizationV2Id(input, 'quota'),
      parseMpcWalletSigningQuotaId,
    );
    const session = buildWalletSessionAuthorizationV2({
      tenantId: input.tenantId,
      principalId: input.principalId,
      walletId: input.walletId,
      authorityId: input.authority.authorityId,
      walletAuthMethodId: input.walletAuthMethodId,
      authorityDigestB64u: input.authority.authorityDigestB64u,
      authorityRevocationEpoch: input.authority.revocationEpoch,
      mintId: input.mintId,
      authorizationId,
      walletSessionId,
      quotaId,
      capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(input.authority),
      createdAtMs: input.issuedAtMs,
      expiresAtMs: input.expiresAtMs,
    });
    const quota = buildActiveWalletSessionQuota({
      tenantId: session.tenantId,
      principalId: session.principalId,
      walletSessionId,
      quotaId,
      remainingUses: input.remainingUses,
      expiresAtMs: session.expiresAtMs,
    });
    return { session, quota };
  }

  async readWalletSessionAuthorizationV2ByMint(
    input: WalletSessionAuthorizationV2MintLookup,
  ): Promise<WalletSessionAuthorizationV2MintRead | null> {
    return await this.ports.grants.readWalletSessionAuthorizationV2ByMint(input);
  }

  async readWalletSessionAuthorizationV2ByAuthorizationId(input: {
    readonly expected: WalletSessionAuthorizationV2;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null> {
    return await this.ports.grants.readWalletSessionAuthorizationV2ByAuthorizationId(input);
  }

  async readWalletSessionAuthorizationV2ByIdentity(input: {
    readonly tenantId: TenantId;
    readonly walletId: WalletId;
    readonly walletSessionId: WalletSessionId;
    readonly authorizationId: WalletSessionAuthorizationId;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null> {
    return await this.ports.grants.readWalletSessionAuthorizationV2ByIdentity(input);
  }

  async readWalletSessionAuthorizationV2ByOperationCredential(input: {
    readonly tenantId: TenantId;
    readonly token: string;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null> {
    return await this.ports.grants.readWalletSessionAuthorizationV2ByOperationCredential({
      tenantId: input.tenantId,
      tokenHash: await digestOpaqueValue(input.token),
      nowMs: input.nowMs,
    });
  }

  /**
   * Resolves the exact `/wallet/session/status` lifecycle. A credential from
   * another family never reaches persistence: only the primary `wst_` token
   * names a V2 authorization, so anything else is absent by construction.
   */
  async readExactWalletSessionStatusByOperationCredential(input: {
    readonly tenantId: TenantId;
    readonly token: string;
    readonly nowMs: number;
  }): Promise<ExactWalletSessionStatusV2> {
    let token: ReturnType<typeof parsePrimaryWalletSessionOperationCredentialToken>;
    try {
      token = parsePrimaryWalletSessionOperationCredentialToken(input.token);
    } catch {
      return { kind: 'missing' };
    }
    return await this.ports.grants.readExactWalletSessionStatusByOperationCredential({
      tenantId: input.tenantId,
      tokenHash: await digestOpaqueValue(token),
      nowMs: input.nowMs,
    });
  }

  async readHostedWalletSessionOperationCredentialV2(input: {
    readonly tenantId: TenantId;
    readonly token: string;
    readonly requestOrigin: SessionOrigin;
    readonly nowMs: number;
  }): Promise<ResolvedHostedWalletSessionOperationCredentialV2 | null> {
    if (!/^wsh_[A-Za-z0-9_-]{43}$/.test(input.token)) return null;
    return await this.ports.sessions.readHostedWalletSessionOperationCredentialV2({
      tenantId: input.tenantId,
      tokenHash: await digestOpaqueValue(input.token),
      requestOrigin: input.requestOrigin,
      nowMs: input.nowMs,
    });
  }

  parseEvidenceRequirement(value: unknown): ParseAuthorizationEvidenceRequirementResult {
    return this.ports.policy.parseEvidenceRequirement(value);
  }

  evaluateEvidenceRequirement(
    requirement: AuthorizationEvidenceRequirement,
    evidenceSet: VerifiedAuthorizationEvidenceSet,
  ): AuthorizationEvidenceRequirementEvaluation {
    return this.ports.policy.evaluateEvidenceRequirement(requirement, evidenceSet);
  }
}

async function deriveWalletSessionAuthorizationV2Id(
  input: IssueWalletSessionAuthorizationV2Input,
  kind: 'authorization' | 'wallet_session' | 'quota',
): Promise<string> {
  const digest = base64UrlEncode(
    await sha256BytesUtf8(
      [
        'seams:wallet-session-authorization-v2-issuance:v1',
        kind,
        input.tenantId,
        input.principalId,
        input.walletId,
        input.authority.authorityId,
        input.walletAuthMethodId,
        input.authority.authorityDigestB64u,
        String(input.authority.revocationEpoch),
        input.mintId,
      ].join('\0'),
    ),
  );
  const prefix = kind === 'authorization' ? 'wlt' : kind === 'wallet_session' ? 'wls' : 'wsq';
  return `${prefix}_${digest}`;
}

export async function digestOpaqueValue(value: string) {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(value)));
}

function directV2AlreadyCommitted(
  prepared: WalletSessionAuthorizationV2,
  committed: WalletSessionAuthorizationV2,
): Extract<DirectV2IssueResult, { readonly kind: 'already_committed' }> {
  if (alphabetizeStringify(prepared) !== alphabetizeStringify(committed)) {
    throw new Error('Direct V2 Wallet Session mint replay does not match its committed session');
  }
  return {
    kind: 'already_committed',
    walletId: committed.walletId,
    authorityId: committed.authorityId,
    walletAuthMethodId: committed.walletAuthMethodId,
    mintId: committed.mintId,
    authorizationId: committed.authorizationId,
    walletSessionId: committed.walletSessionId,
    quotaId: committed.quotaId,
    next: 'unlock_exact_method',
  };
}

function parseRequired<T>(
  value: unknown,
  parser: (raw: unknown) => { readonly ok: true; readonly value: T } | { readonly ok: false },
): T {
  const parsed = parser(value);
  if (!parsed.ok) throw new Error('generated authorization identifier was invalid');
  return parsed.value;
}

function requirePositiveTimestamp(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${label} must be positive`);
  return value;
}
