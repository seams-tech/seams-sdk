import type { RegistrationAuthority } from '@shared/utils/registrationIntent';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  prepareD1WalletAuthMethodPutStatement,
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
import { walletAuthMethodRecordFromRegistrationAuthority } from '../wallet/d1WalletAuthMethodBoundary';
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

export type D1WalletRegistrationCommitInput =
  | (D1WalletRegistrationCommitBase & {
      readonly kind: 'passkey_wallet_registration_commit_v1';
      readonly authority: Extract<RegistrationAuthority, { readonly kind: 'passkey' }>;
      readonly emailOtp?: never;
    })
  | (D1WalletRegistrationCommitBase & {
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
  readonly now: number;
}): readonly D1PreparedStatementLike[] {
  const authMethod = walletAuthMethodRecordFromRegistrationAuthority({
    authority: input.authority,
    now: input.now,
  });
  const authMethodStatement = prepareD1WalletAuthMethodPutStatement({
    database: input.database,
    scope: input.scope,
    record: authMethod,
  });
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
      statements.push(authMethodStatement);
      return statements;
    }
    case 'email_otp':
      return [authMethodStatement];
  }
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
