import {
  D1WebAuthnAuthenticatorStore,
  type WebAuthnAuthenticatorRecord,
} from '../../../packages/wallet-server/src/core/WebAuthnAuthenticatorStore';
import {
  D1WebAuthnCredentialBindingStore,
  type WebAuthnCredentialBindingRecord,
} from '../../../packages/wallet-server/src/core/WebAuthnCredentialBindingStore';
import { deriveWebAuthnAuthenticatorDeviceInfo } from '../../../packages/shared-ts/src/utils/webauthnDeviceInfo';
import {
  createTemporaryD1Database,
  type TemporaryD1Database,
} from '../../helpers/sqliteD1';

/** User agents the production derivation recognizes, kept next to the browser
 * and OS each one is expected to produce. */
export const WEBAUTHN_DEVICE_USER_AGENTS = {
  safariOnIos:
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
  chromeOnMacos:
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
} as const;

export const ICLOUD_KEYCHAIN_AAGUID = 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd';

/**
 * One canonical authenticator row. Device metadata is produced by the same
 * production derivation the registration verifier uses, so the fixture cannot
 * describe a device the server would never derive.
 */
export function testWebAuthnAuthenticatorRecord(input: {
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u?: string;
  readonly counter?: number;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
  readonly userAgent?: string;
  readonly aaguid?: string;
  readonly backedUp?: boolean;
  readonly transports?: readonly string[];
}): WebAuthnAuthenticatorRecord {
  return {
    version: 'webauthn_authenticator_v1',
    credentialIdB64u: input.credentialIdB64u,
    credentialPublicKeyB64u: input.credentialPublicKeyB64u ?? `public-key-${input.credentialIdB64u}`,
    counter: input.counter ?? 0,
    createdAtMs: input.createdAtMs ?? 1_000,
    updatedAtMs: input.updatedAtMs ?? 2_000,
    deviceInfo: deriveWebAuthnAuthenticatorDeviceInfo({
      userAgent: input.userAgent ?? '',
      aaguid: input.aaguid ?? '',
      backedUp: input.backedUp ?? false,
      transports: input.transports ?? [],
    }),
  };
}

/** One credential binding carrying committed Ed25519 signer facts. */
export function testWebAuthnCredentialBindingRecord(input: {
  readonly credentialIdB64u: string;
  readonly userId: string;
  readonly rpId?: string;
  readonly signerSlot?: number;
  readonly publicKey?: string;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
}): WebAuthnCredentialBindingRecord {
  return {
    version: 'webauthn_credential_binding_v1',
    rpId: input.rpId ?? 'wallet.example.test',
    credentialIdB64u: input.credentialIdB64u,
    userId: input.userId,
    nearAccountId: `${input.userId}`,
    nearEd25519SigningKeyId: `signing-key-${input.credentialIdB64u}`,
    signerSlot: input.signerSlot ?? 2,
    publicKey: input.publicKey ?? `ed25519:public-${input.credentialIdB64u}`,
    createdAtMs: input.createdAtMs ?? 500,
    updatedAtMs: input.updatedAtMs ?? 600,
  };
}

export type WebAuthnAuthenticatorListingStores = {
  readonly temporaryDatabase: TemporaryD1Database;
  readonly authenticatorStore: D1WebAuthnAuthenticatorStore;
  readonly credentialBindingStore: D1WebAuthnCredentialBindingStore;
};

/** The two D1-backed stores the canonical authenticator listing reads. */
export function createWebAuthnAuthenticatorListingStores(): WebAuthnAuthenticatorListingStores {
  const temporaryDatabase = createTemporaryD1Database();
  const scope = {
    database: temporaryDatabase.database,
    namespace: 'seams-authenticator-listing-test',
    orgId: 'org-a',
    projectId: 'project-a',
    envId: 'env-a',
  };
  return {
    temporaryDatabase,
    authenticatorStore: new D1WebAuthnAuthenticatorStore(scope),
    credentialBindingStore: new D1WebAuthnCredentialBindingStore(scope),
  };
}
