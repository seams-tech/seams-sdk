import {
  parseCapabilityId,
  parseTenantId,
  parseVaultId,
  parseVaultItemId,
  type AuthorizationParseResult,
} from '@shared/authorization/capabilityKinds';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify } from '@shared/utils/digests';
import type {
  VaultProxySecretRef,
  VaultProxySecretStore,
} from '../../../../authorization/vaultProxyUse';
import { parseVaultProxyDestination } from '../../../../authorization/vaultProxyUse';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';

const VAULT_PROXY_SECRET_AAD_DOMAIN_V1 = 'seams:vault:proxy-secret:v1';
const AES_GCM_NONCE_BYTES = 12;
const AES_GCM_KEY_BYTES = 32;

export class CloudflareD1VaultProxyStore implements VaultProxySecretStore {
  private readonly key: Promise<CryptoKey>;

  constructor(
    private readonly database: D1DatabaseLike,
    private readonly namespace: string,
    encryptionKey: Uint8Array,
  ) {
    if (!namespace.trim()) throw new Error('vault proxy namespace is required');
    if (encryptionKey.byteLength !== AES_GCM_KEY_BYTES) {
      throw new Error('vault proxy encryption key must be 32 bytes');
    }
    this.key = importEncryptionKey(new Uint8Array(encryptionKey));
  }

  async putSecret(input: VaultProxySecretRef & { readonly secret: string }): Promise<void> {
    if (!input.secret) throw new Error('vault proxy secret is required');
    const plaintext = new TextEncoder().encode(input.secret);
    const nonce = crypto.getRandomValues(new Uint8Array(AES_GCM_NONCE_BYTES));
    try {
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: toArrayBuffer(nonce),
          additionalData: toArrayBuffer(aad(input)),
          tagLength: 128,
        },
        await this.key,
        toArrayBuffer(plaintext),
      );
      await this.database
        .prepare(
          `INSERT INTO vault_proxy_secrets (
            namespace,
            tenant_id,
            capability_id,
            vault_id,
            item_id,
            destination,
            sealed_secret_b64u,
            nonce_b64u,
            created_at_ms
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(namespace, tenant_id, vault_id, item_id)
          DO UPDATE SET
            capability_id = excluded.capability_id,
            destination = excluded.destination,
            sealed_secret_b64u = excluded.sealed_secret_b64u,
            nonce_b64u = excluded.nonce_b64u,
            created_at_ms = excluded.created_at_ms`,
        )
        .bind(
          this.namespace,
          input.tenantId,
          input.capabilityId,
          input.vaultId,
          input.itemId,
          input.destination,
          base64UrlEncode(ciphertext),
          base64UrlEncode(nonce),
          Date.now(),
        )
        .run();
    } finally {
      plaintext.fill(0);
      nonce.fill(0);
    }
  }

  async openSecret(input: VaultProxySecretRef): Promise<Uint8Array | null> {
    const row = await this.database
      .prepare(
        `SELECT tenant_id, capability_id, vault_id, item_id, destination,
                sealed_secret_b64u, nonce_b64u
           FROM vault_proxy_secrets
          WHERE namespace = ?
            AND tenant_id = ?
            AND vault_id = ?
            AND item_id = ?
          LIMIT 1`,
      )
      .bind(this.namespace, input.tenantId, input.vaultId, input.itemId)
      .first<Record<string, unknown>>();
    if (!row) return null;
    const record = parseVaultProxySecretRow(row);
    if (
      record.tenantId !== input.tenantId ||
      record.capabilityId !== input.capabilityId ||
      record.vaultId !== input.vaultId ||
      record.itemId !== input.itemId ||
      record.destination !== input.destination
    ) {
      return null;
    }
    const nonce = base64UrlDecode(record.nonceB64u);
    const ciphertext = base64UrlDecode(record.sealedSecretB64u);
    try {
      return new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: toArrayBuffer(nonce),
            additionalData: toArrayBuffer(aad(input)),
            tagLength: 128,
          },
          await this.key,
          toArrayBuffer(ciphertext),
        ),
      );
    } finally {
      nonce.fill(0);
      ciphertext.fill(0);
    }
  }
}

async function importEncryptionKey(bytes: Uint8Array): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(bytes),
      { name: 'AES-GCM' },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    bytes.fill(0);
  }
}

function aad(input: VaultProxySecretRef): Uint8Array {
  return new TextEncoder().encode(
    `${VAULT_PROXY_SECRET_AAD_DOMAIN_V1}|${alphabetizeStringify({
      tenantId: input.tenantId,
      capabilityId: input.capabilityId,
      vaultId: input.vaultId,
      itemId: input.itemId,
      destination: input.destination,
    })}`,
  );
}

function parseVaultProxySecretRow(row: Record<string, unknown>) {
  return {
    tenantId: requireId(row.tenant_id, parseTenantId),
    capabilityId: requireId(row.capability_id, parseCapabilityId),
    vaultId: requireId(row.vault_id, parseVaultId),
    itemId: requireId(row.item_id, parseVaultItemId),
    destination: parseVaultProxyDestination(row.destination),
    sealedSecretB64u: requireCompactString(row.sealed_secret_b64u, 'sealed secret'),
    nonceB64u: requireCompactString(row.nonce_b64u, 'secret nonce'),
  };
}

function requireId<T>(
  value: unknown,
  parser: (raw: unknown) => AuthorizationParseResult<T>,
): T {
  const parsed = parser(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function requireCompactString(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error(`vault proxy ${label} is invalid`);
  }
  return value;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(copy).set(bytes);
  return copy;
}
