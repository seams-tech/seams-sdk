import type { WebAuthnCredentialBindingRecord } from './WebAuthnCredentialBindingStore';

/*
 * A credential binding carries its Ed25519 identity as a set or not at all. A
 * passkey wallet exists before its Ed25519 Yao ceremony settles (non-blocking
 * provisioning), so absence is a valid durable state — but a partial identity
 * is a corrupt record and must not be constructible.
 */

const BASE = {
  version: 'webauthn_credential_binding_v1',
  rpId: 'example.com',
  credentialIdB64u: 'credential-a',
  userId: 'amber-atlas-abcdef',
  createdAtMs: 1_900_000_000_000,
  updatedAtMs: 1_900_000_000_000,
} as const;

/** Valid: Ed25519 not provisioned yet. */
export const ED25519_ABSENT: WebAuthnCredentialBindingRecord = BASE;

/** Valid: Ed25519 committed, full identity present. */
export const ED25519_PRESENT: WebAuthnCredentialBindingRecord = {
  ...BASE,
  nearAccountId: 'amber-atlas-abcdef.testnet',
  nearEd25519SigningKeyId: 'near-ed25519-key-1',
  signerSlot: 1,
  publicKey: 'ed25519:abcdef',
};

/** Non-Ed25519 optionals stay independent of the union branch. */
export const ABSENT_WITH_OPTIONALS: WebAuthnCredentialBindingRecord = {
  ...BASE,
  keyVersion: 'yao-key-v1',
  recoveryExportCapable: true,
};

// @ts-expect-error a NEAR account id without the rest of the Ed25519 identity
export const PARTIAL_ACCOUNT_ONLY: WebAuthnCredentialBindingRecord = {
  ...BASE,
  nearAccountId: 'amber-atlas-abcdef.testnet',
};

// @ts-expect-error a signer slot without the rest of the Ed25519 identity
export const PARTIAL_SLOT_ONLY: WebAuthnCredentialBindingRecord = {
  ...BASE,
  signerSlot: 1,
};

// @ts-expect-error a public key without its account and signing key id
export const PARTIAL_PUBLIC_KEY_ONLY: WebAuthnCredentialBindingRecord = {
  ...BASE,
  publicKey: 'ed25519:abcdef',
};

// @ts-expect-error three of four Ed25519 facts is still a partial identity
export const PARTIAL_MISSING_PUBLIC_KEY: WebAuthnCredentialBindingRecord = {
  ...BASE,
  nearAccountId: 'amber-atlas-abcdef.testnet',
  nearEd25519SigningKeyId: 'near-ed25519-key-1',
  signerSlot: 1,
};

// @ts-expect-error an explicitly undefined fact does not satisfy the present branch
export const PARTIAL_EXPLICIT_UNDEFINED: WebAuthnCredentialBindingRecord = {
  ...BASE,
  nearAccountId: 'amber-atlas-abcdef.testnet',
  nearEd25519SigningKeyId: 'near-ed25519-key-1',
  signerSlot: 1,
  publicKey: undefined,
};
