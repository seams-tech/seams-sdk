import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  parseWalletAuthMethodRecordV2,
  type RegistrationAuthority,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import { alphabetizeStringify } from '@shared/utils/digests';
import { parseWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  prepareD1WalletAuthMethodV2PutStatement,
  type D1WalletAuthMethodStoreScope,
} from '../../../../core/d1WalletAuthMethodStore';
import {
  prepareD1WalletPutSignerStatement,
  prepareD1WalletPutSubjectStatement,
  type D1WalletStoreScope,
} from '../../../../core/d1WalletStore';
import type { WalletRecord, WalletSignerRecord } from '../../../../core/WalletStore';
import {
  prepareD1WebAuthnCredentialBindingPutStatement,
  type WebAuthnCredentialBindingRecord,
} from '../../../../core/WebAuthnCredentialBindingStore';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../../../storage/tenantRoute';
import {
  parseD1JsonColumn,
} from '../../../../storage/d1Sql';
import {
  prepareD1WalletAuthorityPutStatement,
} from '../wallet/d1WalletAuthorityStore';
import {
  prepareD1WebAuthnAuthenticatorPutStatement,
  type D1WebAuthnStoreScope,
} from '../webauthn/d1WebAuthnStore';
import type { D1EmailOtpRegistrationCommitPlan } from '../emailOtp/d1EmailOtpRegistrationEnrollmentFinalizer';

type D1WalletRegistrationCommitBase = {
  readonly wallet: WalletRecord;
  readonly walletSigners: readonly WalletSignerRecord[];
  readonly now: number;
};

type D1WalletRegistrationFoundingFields =
  | {
      readonly foundingAuthority?: never;
      readonly foundingAuthMethod?: never;
    }
  | {
      readonly foundingAuthority: ActiveWalletAuthorityV1;
      readonly foundingAuthMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
    };

export type D1WalletRegistrationCommitInput =
  | (D1WalletRegistrationCommitBase & D1WalletRegistrationFoundingFields & {
      readonly kind: 'passkey_wallet_registration_commit_v1';
      readonly authority: Extract<RegistrationAuthority, { readonly kind: 'passkey' }>;
      readonly emailOtp?: never;
    })
  | (D1WalletRegistrationCommitBase & D1WalletRegistrationFoundingFields & {
      readonly kind: 'email_otp_wallet_registration_commit_v1';
      readonly authority: Extract<RegistrationAuthority, { readonly kind: 'email_otp' }>;
      readonly emailOtp: D1EmailOtpRegistrationCommitPlan;
    });

export interface D1WalletRegistrationCommitStore {
  commit(input: D1WalletRegistrationCommitInput): Promise<void>;
}

type D1WalletRegistrationCommitScope = D1WalletStoreScope &
  D1WalletAuthMethodStoreScope &
  D1WebAuthnStoreScope;

function requireScopeString(value: string, field: string): string {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized) throw new Error(`${field} is required for D1 wallet registration commit`);
  return normalized;
}

function normalizeScope(input: D1WalletRegistrationCommitScope): D1WalletRegistrationCommitScope {
  return {
    namespace: requireScopeString(input.namespace, 'namespace'),
    orgId: requireScopeString(input.orgId, 'orgId'),
    projectId: requireScopeString(input.projectId, 'projectId'),
    envId: requireScopeString(input.envId, 'envId'),
  };
}

function assertCommitWalletIdentity(input: D1WalletRegistrationCommitInput): void {
  if (input.authority.walletId !== input.wallet.walletId) {
    throw new Error('Registration authority walletId does not match wallet record');
  }
  if (input.foundingAuthority) {
    if (!input.foundingAuthMethod) {
      throw new Error('Founding wallet authority is missing its auth method');
    }
    if (
      input.foundingAuthority.walletId !== input.wallet.walletId ||
      input.foundingAuthMethod.walletId !== input.wallet.walletId ||
      input.foundingAuthMethod.walletAuthorityId !== input.foundingAuthority.authorityId
    ) {
      throw new Error('Founding authority identities do not match wallet registration');
    }
    if (input.foundingAuthority.state !== 'active' || input.foundingAuthMethod.status !== 'active') {
      throw new Error('Founding wallet authority and auth method must be active');
    }
  } else if (input.foundingAuthMethod) {
    throw new Error('Founding wallet auth method is missing its authority');
  }
  /* No signer-count floor. An Ed25519-only wallet is committed pending, with
     its sole signer arriving later from deferred Yao — the wallet legitimately
     exists before any signer does (94C). What must hold is that every signer
     present belongs to this wallet, which the loop below enforces. */
  for (const signer of input.walletSigners) {
    if (signer.walletId !== input.wallet.walletId) {
      throw new Error('Wallet signer walletId does not match wallet record');
    }
  }
}

function prepareAuthorityStatements(input: {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletRegistrationCommitScope;
  readonly authority: RegistrationAuthority;
  readonly walletSigners: readonly WalletSignerRecord[];
  readonly foundingAuthority: ActiveWalletAuthorityV1 | undefined;
  readonly foundingAuthMethod:
    | Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>
    | undefined;
  readonly foundingStatements: readonly D1PreparedStatementLike[];
  readonly now: number;
}): readonly D1PreparedStatementLike[] {
  const foundingStatements = input.foundingStatements;
  switch (input.authority.kind) {
    case 'passkey': {
      const ed25519Signers = input.walletSigners.filter(
        (signer) => signer.version === 'wallet_signer_ed25519_v1',
      );
      if (ed25519Signers.length > 1) {
        throw new Error('Wallet registration commit received multiple Ed25519 signers');
      }
      const statements: D1PreparedStatementLike[] = [
        prepareD1WebAuthnAuthenticatorPutStatement({
          database: input.database,
          scope: input.scope,
          userId: input.authority.walletId,
          record: {
            credentialIdB64u: input.authority.credentialIdB64u,
            credentialPublicKeyB64u: input.authority.credentialPublicKeyB64u,
            counter: input.authority.counter,
            createdAtMs: input.now,
            updatedAtMs: input.now,
            deviceInfo: input.authority.device,
          },
        }),
      ];
      // The credential binding is what login resolves a passkey against, so it
      // must be written even when no Ed25519 signer exists yet — otherwise a
      // wallet whose Yao ceremony has not settled fails the next login with
      // `unknown_credential`. The Ed25519 facts are filled in when that signer
      // is committed.
      const ed25519Signer = ed25519Signers[0];
      const credentialBindingBase = {
        version: 'webauthn_credential_binding_v1',
        rpId: input.authority.rpId,
        credentialIdB64u: input.authority.credentialIdB64u,
        userId: input.authority.walletId,
        createdAtMs: input.now,
        updatedAtMs: input.now,
      } as const;
      // The Ed25519 facts are a union branch, not four independent optionals:
      // spreading them all selects the present branch, omitting them selects
      // the absent one. A partial set cannot be constructed.
      const credentialBinding: WebAuthnCredentialBindingRecord = ed25519Signer
        ? {
            ...credentialBindingBase,
            nearAccountId: ed25519Signer.nearAccountId,
            nearEd25519SigningKeyId: ed25519Signer.nearEd25519SigningKeyId,
            signerSlot: ed25519Signer.signerSlot,
            publicKey: ed25519Signer.publicKey,
            relayerKeyId: ed25519Signer.signingWorkerId,
            keyVersion: ed25519Signer.keyVersion,
            recoveryExportCapable: ed25519Signer.recoveryExportCapable,
            participantIds: [...ed25519Signer.participantIds],
            runtimePolicyScope: ed25519Signer.runtimePolicyScope,
          }
        : credentialBindingBase;
      statements.push(
        prepareD1WebAuthnCredentialBindingPutStatement({
          database: input.database,
          scope: input.scope,
          record: credentialBinding,
        }),
      );
      statements.push(...foundingStatements);
      return statements;
    }
    case 'email_otp':
      return foundingStatements;
  }
}

function requireFoundingAuthMethod(
  value: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }> | undefined,
): Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }> {
  if (!value) throw new Error('Founding wallet authority is missing its auth method');
  return value;
}

function foundingAuthorityIdentityMatches(
  left: ActiveWalletAuthorityV1,
  right: ActiveWalletAuthorityV1,
): boolean {
  return (
    alphabetizeStringify({
      kind: left.kind,
      authorityId: left.authorityId,
      walletId: left.walletId,
      principal: left.principal,
      provenance: left.provenance,
      permissions: left.permissions,
      revocationEpoch: left.revocationEpoch,
      createdAtMs: left.createdAtMs,
      state: left.state,
      activatedAtMs: left.activatedAtMs,
    }) ===
    alphabetizeStringify({
      kind: right.kind,
      authorityId: right.authorityId,
      walletId: right.walletId,
      principal: right.principal,
      provenance: right.provenance,
      permissions: right.permissions,
      revocationEpoch: right.revocationEpoch,
      createdAtMs: right.createdAtMs,
      state: right.state,
      activatedAtMs: right.activatedAtMs,
    })
  );
}

function canExtendFoundingAuthorityWithEd25519(
  existing: ActiveWalletAuthorityV1,
  next: ActiveWalletAuthorityV1,
): boolean {
  const existingEcdsa = existing.signerActivations.ecdsa;
  const nextEcdsa = next.signerActivations.ecdsa;
  return (
    existing.signerActivations.keyFamilies.length === 1 &&
    existing.signerActivations.keyFamilies[0] === 'ecdsa_secp256k1' &&
    next.signerActivations.keyFamilies.length === 2 &&
    next.signerActivations.keyFamilies[0] === 'ed25519' &&
    next.signerActivations.keyFamilies[1] === 'ecdsa_secp256k1' &&
    existingEcdsa !== undefined &&
    nextEcdsa !== undefined &&
    alphabetizeStringify(existingEcdsa) === alphabetizeStringify(nextEcdsa) &&
    foundingAuthorityIdentityMatches(existing, next) &&
    next.updatedAtMs >= existing.updatedAtMs
  );
}

function prepareFoundingAuthorityExtensionStatement(input: {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletRegistrationCommitScope;
  readonly expected: ActiveWalletAuthorityV1;
  readonly next: ActiveWalletAuthorityV1;
}): D1PreparedStatementLike {
  return input.database
    .prepare(
      `UPDATE wallet_authorities
          SET signer_activations_json = ?,
              signer_activation_set_digest_b64u = ?,
              authority_digest_b64u = ?,
              record_json = ?,
              updated_at_ms = ?
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND authority_id = ?
          AND wallet_id = ?
          AND lifecycle_state = 'active'
          AND signer_activation_set_digest_b64u = ?
          AND authority_digest_b64u = ?
          AND revocation_epoch = ?
          AND created_at_ms = ?
          AND updated_at_ms = ?
          AND activated_at_ms = ?`,
    )
    .bind(
      JSON.stringify(input.next.signerActivations),
      String(input.next.signerActivationSetDigestB64u),
      String(input.next.authorityDigestB64u),
      JSON.stringify(input.next),
      input.next.updatedAtMs,
      input.scope.namespace,
      input.scope.orgId,
      input.scope.projectId,
      input.scope.envId,
      String(input.expected.authorityId),
      String(input.expected.walletId),
      String(input.expected.signerActivationSetDigestB64u),
      String(input.expected.authorityDigestB64u),
      input.expected.revocationEpoch,
      input.expected.createdAtMs,
      input.expected.updatedAtMs,
      input.expected.activatedAtMs,
    );
}

function prepareFoundingAuthorityExtensionCasGuard(
  database: D1DatabaseLike,
): D1PreparedStatementLike {
  return database.prepare(`
    INSERT INTO wallet_authority_cas_guard (guard_id)
    SELECT 1
     WHERE changes() = 0
  `);
}

type D1RegistrationRecordJsonRow = {
  readonly record_json?: unknown;
};

async function prepareFoundingStatements(input: {
  readonly database: D1DatabaseLike;
  readonly scope: D1WalletRegistrationCommitScope;
  readonly foundingAuthority: ActiveWalletAuthorityV1 | undefined;
  readonly foundingAuthMethod:
    | Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>
    | undefined;
}): Promise<readonly D1PreparedStatementLike[]> {
  if (!input.foundingAuthority) return [];
  const foundingAuthMethod = requireFoundingAuthMethod(input.foundingAuthMethod);
  const authorityRow = await input.database
    .prepare(
      `SELECT record_json
         FROM wallet_authorities
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND authority_id = ?
        LIMIT 1`,
    )
    .bind(
      input.scope.namespace,
      input.scope.orgId,
      input.scope.projectId,
      input.scope.envId,
      String(input.foundingAuthority.authorityId),
    )
    .first<D1RegistrationRecordJsonRow>();
  const authMethodRow = await input.database
    .prepare(
      `SELECT record_json
         FROM wallet_auth_methods
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_auth_method_id = ?
        LIMIT 1`,
    )
    .bind(
      input.scope.namespace,
      input.scope.orgId,
      input.scope.projectId,
      input.scope.envId,
      String(foundingAuthMethod.walletAuthMethodId),
    )
    .first<D1RegistrationRecordJsonRow>();
  let persistedAuthority: ActiveWalletAuthorityV1 | null = null;
  if (authorityRow) {
    const parsedAuthority = parseWalletAuthorityV1(
      parseD1JsonColumn(authorityRow.record_json),
    );
    if (!parsedAuthority.ok || parsedAuthority.value.state !== 'active') {
      throw new Error('Founding wallet authority replay conflicts with the persisted record');
    }
    persistedAuthority = parsedAuthority.value;
  }
  const foundingAuthorityNeedsExtension =
    persistedAuthority !== null &&
    alphabetizeStringify(persistedAuthority) !== alphabetizeStringify(input.foundingAuthority);
  if (
    foundingAuthorityNeedsExtension &&
    (!persistedAuthority ||
      persistedAuthority.state !== 'active' ||
      !canExtendFoundingAuthorityWithEd25519(persistedAuthority, input.foundingAuthority))
  ) {
    throw new Error('Founding wallet authority replay conflicts with the persisted record');
  }
  if (authMethodRow) {
    const parsedAuthMethod = parseWalletAuthMethodRecordV2(
      parseD1JsonColumn(authMethodRow.record_json),
    );
    if (
      !parsedAuthMethod ||
      alphabetizeStringify(parsedAuthMethod) !== alphabetizeStringify(foundingAuthMethod)
    ) {
      throw new Error('Founding wallet auth method replay conflicts with the persisted record');
    }
  }
  const statements: D1PreparedStatementLike[] = [];
  if (!authorityRow) {
    statements.push(
      prepareD1WalletAuthorityPutStatement({
        database: input.database,
        scope: input.scope,
        authority: input.foundingAuthority,
      }),
    );
  } else if (persistedAuthority && foundingAuthorityNeedsExtension) {
    statements.push(
      prepareFoundingAuthorityExtensionStatement({
        database: input.database,
        scope: input.scope,
        expected: persistedAuthority,
        next: input.foundingAuthority,
      }),
      prepareFoundingAuthorityExtensionCasGuard(input.database),
    );
  }
  if (!authMethodRow) {
    statements.push(
      prepareD1WalletAuthMethodV2PutStatement({
        database: input.database,
        scope: input.scope,
        record: foundingAuthMethod,
      }),
    );
  }
  return statements;
}

function assertBatchSucceeded(input: {
  readonly expectedStatementCount: number;
  readonly results: readonly D1ResultLike[];
}): void {
  if (input.results.length !== input.expectedStatementCount) {
    throw new Error('D1 wallet registration commit returned an incomplete batch result');
  }
  for (const result of input.results) {
    if (!result.success) throw new Error('D1 wallet registration commit batch failed');
  }
}

function emailOtpCommitStatements(
  input: D1WalletRegistrationCommitInput,
): readonly D1PreparedStatementLike[] {
  switch (input.kind) {
    case 'passkey_wallet_registration_commit_v1':
      return [];
    case 'email_otp_wallet_registration_commit_v1':
      return input.emailOtp.statements;
  }
}

export class CloudflareD1WalletRegistrationCommitStore
  implements D1WalletRegistrationCommitStore
{
  private readonly database: D1DatabaseLike;
  private readonly scope: D1WalletRegistrationCommitScope;

  constructor(input: {
    readonly database: D1DatabaseLike;
    readonly namespace: string;
    readonly orgId: string;
    readonly projectId: string;
    readonly envId: string;
  }) {
    this.database = input.database;
    this.scope = normalizeScope(input);
  }

  async commit(input: D1WalletRegistrationCommitInput): Promise<void> {
    assertCommitWalletIdentity(input);
    const foundingStatements = await prepareFoundingStatements({
      database: this.database,
      scope: this.scope,
      foundingAuthority: input.foundingAuthority,
      foundingAuthMethod: input.foundingAuthMethod,
    });
    const statements: D1PreparedStatementLike[] = [
      prepareD1WalletPutSubjectStatement({
        database: this.database,
        scope: this.scope,
        record: input.wallet,
      }),
    ];
    for (const signer of input.walletSigners) {
      statements.push(
        prepareD1WalletPutSignerStatement({
          database: this.database,
          scope: this.scope,
          record: signer,
        }),
      );
    }
    statements.push(
      ...prepareAuthorityStatements({
        database: this.database,
        scope: this.scope,
        authority: input.authority,
        walletSigners: input.walletSigners,
        foundingAuthority: input.foundingAuthority,
        foundingAuthMethod: input.foundingAuthMethod,
        foundingStatements,
        now: input.now,
      }),
    );
    statements.push(...emailOtpCommitStatements(input));
    const results = await this.database.batch<D1ResultLike>(statements);
    assertBatchSucceeded({
      expectedStatementCount: statements.length,
      results,
    });
  }
}
