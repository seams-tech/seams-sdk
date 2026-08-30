export type WalletSessionCleanupLegacyRow = {
  readonly record_version:
    | 'wallet_session_authorization_v3'
    | 'wallet_session_authorization_v4'
    | 'wallet_session_authorization_v5';
  readonly wallet_session_id: string;
  readonly wallet_id: string;
  readonly wallet_authority_id: string;
  readonly wallet_auth_method_id: string;
  readonly record: {
    readonly status: 'retired';
    readonly marker: 'v3' | 'v4' | 'v5';
  };
};

export type WalletSessionCleanupPreservedRows = {
  readonly wallet: {
    readonly wallet_id: string;
    readonly rp_id: 'wallet.example.test';
    readonly status: 'active';
    readonly updated_at: 1;
    readonly record: { readonly marker: 'wallet' };
  };
  readonly authority: {
    readonly authority_id: string;
    readonly wallet_id: string;
    readonly state: 'active';
    readonly device_id: 'device:cleanup';
    readonly updated_at: 1;
    readonly record: { readonly marker: 'authority' };
  };
  readonly authMethod: {
    readonly wallet_auth_method_id: 'wallet-auth-method:cleanup';
    readonly wallet_id: string;
    readonly wallet_authority_id: string;
    readonly kind: 'email_otp';
    readonly auth_method: 'email_otp';
    readonly rp_id: 'wallet.example.test';
    readonly auth_identifier_key: 'email:cleanup';
    readonly credential_id_b64u: 'credential-cleanup';
    readonly status: 'active';
    readonly updated_at: 1;
    readonly record: { readonly marker: 'auth-method' };
  };
  readonly signerMaterial: {
    readonly wallet_authority_id: string;
    readonly wallet_auth_method_id: 'wallet-auth-method:cleanup';
    readonly activation_id: 'activation:cleanup';
    readonly key_family: 'ed25519';
    readonly sealed_material_b64u: 'sealed-material-cleanup';
    readonly sealed_material_digest_b64u: 'digest-cleanup';
    readonly record: { readonly marker: 'signer-material' };
  };
  readonly exportRoot: {
    readonly wallet_authority_id: string;
    readonly wallet_auth_method_id: 'wallet-auth-method:cleanup';
    readonly wallet_key_id: 'wallet-key:cleanup';
    readonly sealed_root_b64u: 'sealed-root-cleanup';
    readonly sealed_root_digest_b64u: 'digest-cleanup';
    readonly record: { readonly marker: 'export-root' };
  };
  readonly recoveryCode: {
    readonly record_version: 1;
    readonly wallet_id: string;
    readonly enrollment_id: 'wallet_recovery_codes_v1';
    readonly recovery_codes_issued_at_ms: 1;
    readonly status: 'pending';
    readonly key: 'recovery-key-cleanup';
    readonly iv: Uint8Array;
    readonly ciphertext: Uint8Array;
  };
  readonly appState: {
    readonly key: 'cleanup-preserve';
    readonly value: { readonly marker: 'app-state' };
  };
};

export type WalletSessionCleanupReadbackKeys = {
  readonly authMethod: 'wallet-auth-method:cleanup';
  readonly signerMaterial: readonly [string, 'wallet-auth-method:cleanup', 'activation:cleanup'];
  readonly exportRoot: readonly [string, 'wallet-auth-method:cleanup', 'wallet-key:cleanup'];
  readonly recoveryCode: readonly [string, 'wallet_recovery_codes_v1'];
  readonly appState: 'cleanup-preserve';
};

export type WalletSessionCleanupPersistenceFixture = {
  readonly legacyRows: readonly WalletSessionCleanupLegacyRow[];
  readonly preservedRows: WalletSessionCleanupPreservedRows;
  readonly readbackKeys: WalletSessionCleanupReadbackKeys;
};

export function buildWalletSessionCleanupPersistenceFixture(input: {
  readonly walletId: string;
  readonly authorityId: string;
}): WalletSessionCleanupPersistenceFixture {
  const legacyRows: readonly WalletSessionCleanupLegacyRow[] = [
    {
      record_version: 'wallet_session_authorization_v3',
      wallet_session_id: 'wallet-session:cleanup-v3',
      wallet_id: input.walletId,
      wallet_authority_id: input.authorityId,
      wallet_auth_method_id: 'wallet-auth-method:cleanup',
      record: { status: 'retired', marker: 'v3' },
    },
    {
      record_version: 'wallet_session_authorization_v4',
      wallet_session_id: 'wallet-session:cleanup-v4',
      wallet_id: input.walletId,
      wallet_authority_id: input.authorityId,
      wallet_auth_method_id: 'wallet-auth-method:cleanup',
      record: { status: 'retired', marker: 'v4' },
    },
    {
      record_version: 'wallet_session_authorization_v5',
      wallet_session_id: 'wallet-session:cleanup-v5',
      wallet_id: input.walletId,
      wallet_authority_id: input.authorityId,
      wallet_auth_method_id: 'wallet-auth-method:cleanup',
      record: { status: 'retired', marker: 'v5' },
    },
  ];
  const preservedRows: WalletSessionCleanupPreservedRows = {
    wallet: {
      wallet_id: input.walletId,
      rp_id: 'wallet.example.test',
      status: 'active',
      updated_at: 1,
      record: { marker: 'wallet' },
    },
    authority: {
      authority_id: input.authorityId,
      wallet_id: input.walletId,
      state: 'active',
      device_id: 'device:cleanup',
      updated_at: 1,
      record: { marker: 'authority' },
    },
    authMethod: {
      wallet_auth_method_id: 'wallet-auth-method:cleanup',
      wallet_id: input.walletId,
      wallet_authority_id: input.authorityId,
      kind: 'email_otp',
      auth_method: 'email_otp',
      rp_id: 'wallet.example.test',
      auth_identifier_key: 'email:cleanup',
      credential_id_b64u: 'credential-cleanup',
      status: 'active',
      updated_at: 1,
      record: { marker: 'auth-method' },
    },
    signerMaterial: {
      wallet_authority_id: input.authorityId,
      wallet_auth_method_id: 'wallet-auth-method:cleanup',
      activation_id: 'activation:cleanup',
      key_family: 'ed25519',
      sealed_material_b64u: 'sealed-material-cleanup',
      sealed_material_digest_b64u: 'digest-cleanup',
      record: { marker: 'signer-material' },
    },
    exportRoot: {
      wallet_authority_id: input.authorityId,
      wallet_auth_method_id: 'wallet-auth-method:cleanup',
      wallet_key_id: 'wallet-key:cleanup',
      sealed_root_b64u: 'sealed-root-cleanup',
      sealed_root_digest_b64u: 'digest-cleanup',
      record: { marker: 'export-root' },
    },
    recoveryCode: {
      record_version: 1,
      wallet_id: input.walletId,
      enrollment_id: 'wallet_recovery_codes_v1',
      recovery_codes_issued_at_ms: 1,
      status: 'pending',
      key: 'recovery-key-cleanup',
      iv: new Uint8Array([1, 2, 3]),
      ciphertext: new Uint8Array([4, 5, 6]),
    },
    appState: {
      key: 'cleanup-preserve',
      value: { marker: 'app-state' },
    },
  };
  return {
    legacyRows,
    preservedRows,
    readbackKeys: {
      authMethod: 'wallet-auth-method:cleanup',
      signerMaterial: [input.authorityId, 'wallet-auth-method:cleanup', 'activation:cleanup'],
      exportRoot: [input.authorityId, 'wallet-auth-method:cleanup', 'wallet-key:cleanup'],
      recoveryCode: [input.walletId, 'wallet_recovery_codes_v1'],
      appState: 'cleanup-preserve',
    },
  };
}
