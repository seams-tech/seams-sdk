import type {
  CloudflareDurableObjectNamespaceLike,
  EcdsaHssServerBootstrapResponse,
  AddSignerIntentGrant,
  AddSignerIntentV1,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  WalletAddSignerStartResponse,
  WalletRegistrationEcdsaWalletKey,
  WalletRegistrationStartResponse,
  WalletSubjectId,
} from './types';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';
import type { NormalizedLogger } from './logger';
import { THRESHOLD_DO_OBJECT_NAME_DEFAULT } from './defaultConfigsServer';

export type StoredRegistrationIntent = {
  kind: 'intent_allocated';
  grant: RegistrationIntentGrant;
  intent: RegistrationIntentV1;
  digestB64u: string;
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expectedOrigin?: string;
  expiresAtMs: number;
  consumedAtMs?: never;
  failedAtMs?: never;
  failure?: never;
};

export type ConsumedRegistrationIntent = Omit<StoredRegistrationIntent, 'kind' | 'consumedAtMs'> & {
  kind: 'intent_consumed';
  consumedAtMs: number;
};

export type FailedRegistrationIntent = Omit<
  StoredRegistrationIntent,
  'kind' | 'failedAtMs' | 'failure'
> & {
  kind: 'intent_failed';
  failedAtMs: number;
  failure: {
    code: string;
    message: string;
  };
};

export type StoredAddSignerIntent = {
  kind: 'add_signer_intent_allocated';
  grant: AddSignerIntentGrant;
  intent: AddSignerIntentV1;
  digestB64u: string;
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expectedOrigin?: string;
  expiresAtMs: number;
  consumedAtMs?: never;
};

export type ConsumedAddSignerIntent = Omit<StoredAddSignerIntent, 'kind' | 'consumedAtMs'> & {
  kind: 'add_signer_intent_consumed';
  consumedAtMs: number;
};

export type StoredRegistrationWebAuthnCredential = {
  credentialIdB64u: string;
  credentialPublicKeyB64u: string;
  counter: number;
};

type WalletRegistrationEd25519StartPayload = NonNullable<
  Extract<WalletRegistrationStartResponse, { ok: true }>['ed25519']
>;

type WalletRegistrationEcdsaStartPayload = NonNullable<
  Extract<WalletRegistrationStartResponse, { ok: true }>['ecdsa']
>;

type WalletAddSignerEd25519StartPayload = NonNullable<
  Extract<WalletAddSignerStartResponse, { ok: true }>['ed25519']
>;

type WalletAddSignerEcdsaStartPayload = NonNullable<
  Extract<WalletAddSignerStartResponse, { ok: true }>['ecdsa']
>;

export type StoredEd25519RegistrationPrepared = WalletRegistrationEd25519StartPayload & {
  kind: 'ed25519_prepared';
  responded?: never;
};

export type StoredEd25519RegistrationResponded = WalletRegistrationEd25519StartPayload & {
  kind: 'ed25519_responded';
  responded: {
    contextBindingB64u: string;
    serverInputDeliveryB64u: string;
  };
};

export type StoredEd25519RegistrationFinalizing = WalletRegistrationEd25519StartPayload & {
  kind: 'ed25519_finalizing';
  responded: StoredEd25519RegistrationResponded['responded'];
  finalizingAtMs: number;
};

export type StoredEd25519RegistrationCompleted = WalletRegistrationEd25519StartPayload & {
  kind: 'ed25519_completed';
  responded: StoredEd25519RegistrationResponded['responded'];
  completedAtMs: number;
  walletSubjectId: WalletSubjectId;
};

type StoredEcdsaRegistrationBase = Omit<WalletRegistrationEcdsaStartPayload, 'kind'> & {
  hssKind: WalletRegistrationEcdsaStartPayload['kind'];
};

export type StoredEcdsaRegistrationPrepared = StoredEcdsaRegistrationBase & {
  kind: 'ecdsa_prepared';
  responded?: never;
  completed?: never;
};

export type StoredEcdsaRegistrationResponded = StoredEcdsaRegistrationBase & {
  kind: 'ecdsa_responded';
  responded: {
    bootstrap: EcdsaHssServerBootstrapResponse;
  };
  completed?: never;
};

export type StoredEcdsaRegistrationCompleted = StoredEcdsaRegistrationBase & {
  kind: 'ecdsa_completed';
  responded: StoredEcdsaRegistrationResponded['responded'];
  completedAtMs: number;
  walletSubjectId: WalletSubjectId;
  walletKeys: WalletRegistrationEcdsaWalletKey[];
};

export type StoredCombinedRegistrationState = {
  kind: 'combined_registration';
  ed25519: StoredEd25519RegistrationPrepared | StoredEd25519RegistrationResponded;
  ecdsa: StoredEcdsaRegistrationPrepared | StoredEcdsaRegistrationResponded;
};

export type StoredWalletRegistrationFailed = {
  kind: 'registration_failed';
  failedAtMs: number;
  failure: {
    code: string;
    message: string;
  };
  ceremonyHandle?: never;
  preparedSession?: never;
  clientOtOfferMessageB64u?: never;
  prepare?: never;
  walletKeys?: never;
  responded?: never;
  completed?: never;
};

export type StoredWalletRegistrationSignerState =
  | StoredEd25519RegistrationPrepared
  | StoredEd25519RegistrationResponded
  | StoredEd25519RegistrationFinalizing
  | StoredEd25519RegistrationCompleted
  | StoredEcdsaRegistrationPrepared
  | StoredEcdsaRegistrationResponded
  | StoredEcdsaRegistrationCompleted
  | StoredCombinedRegistrationState
  | StoredWalletRegistrationFailed;

type StoredWalletRegistrationCeremonyBase = {
  registrationCeremonyId: string;
  intent: RegistrationIntentV1;
  digestB64u: string;
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expectedOrigin?: string;
  expiresAtMs: number;
  webauthn: StoredRegistrationWebAuthnCredential;
};

export type StoredWalletRegistrationCeremony = StoredWalletRegistrationCeremonyBase & {
  signerState: StoredWalletRegistrationSignerState;
};

export type StoredEd25519AddSignerPrepared = WalletAddSignerEd25519StartPayload & {
  kind: 'ed25519_add_signer_prepared';
  responded?: never;
};

export type StoredEd25519AddSignerResponded = WalletAddSignerEd25519StartPayload & {
  kind: 'ed25519_add_signer_responded';
  responded: {
    contextBindingB64u: string;
    serverInputDeliveryB64u: string;
  };
};

type StoredEcdsaAddSignerBase = Omit<WalletAddSignerEcdsaStartPayload, 'kind'> & {
  hssKind: WalletAddSignerEcdsaStartPayload['kind'];
};

export type StoredEcdsaAddSignerPrepared = StoredEcdsaAddSignerBase & {
  kind: 'ecdsa_add_signer_prepared';
  responded?: never;
  completed?: never;
};

export type StoredEcdsaAddSignerResponded = StoredEcdsaAddSignerBase & {
  kind: 'ecdsa_add_signer_responded';
  responded: {
    bootstrap: EcdsaHssServerBootstrapResponse;
  };
  completed?: never;
};

export type StoredEcdsaAddSignerCompleted = StoredEcdsaAddSignerBase & {
  kind: 'ecdsa_add_signer_completed';
  responded: StoredEcdsaAddSignerResponded['responded'];
  completedAtMs: number;
  walletSubjectId: WalletSubjectId;
  walletKeys: WalletRegistrationEcdsaWalletKey[];
};

export type StoredWalletAddSignerSignerState =
  | StoredEd25519AddSignerPrepared
  | StoredEd25519AddSignerResponded
  | StoredEcdsaAddSignerPrepared
  | StoredEcdsaAddSignerResponded
  | StoredEcdsaAddSignerCompleted;

export type StoredWalletAddSignerCeremony = {
  addSignerCeremonyId: string;
  intent: AddSignerIntentV1;
  digestB64u: string;
  orgId: string;
  signingRootId?: string;
  signingRootVersion?: string;
  expiresAtMs: number;
  auth:
    | {
        kind: 'webauthn_assertion';
        credentialIdB64u: string;
      }
    | {
        kind: 'app_session';
      };
  signerState: StoredWalletAddSignerSignerState;
};

export interface RegistrationCeremonyStore {
  putIntent(intent: StoredRegistrationIntent): Promise<void>;
  getIntent(grant: RegistrationIntentGrant): Promise<StoredRegistrationIntent | null>;
  takeIntent(grant: RegistrationIntentGrant): Promise<ConsumedRegistrationIntent | null>;
  putAddSignerIntent(intent: StoredAddSignerIntent): Promise<void>;
  getAddSignerIntent(grant: AddSignerIntentGrant): Promise<StoredAddSignerIntent | null>;
  takeAddSignerIntent(grant: AddSignerIntentGrant): Promise<ConsumedAddSignerIntent | null>;
  putCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void>;
  getCeremony(registrationCeremonyId: string): Promise<StoredWalletRegistrationCeremony | null>;
  updateCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void>;
  takeCeremony(registrationCeremonyId: string): Promise<StoredWalletRegistrationCeremony | null>;
  putAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void>;
  getAddSignerCeremony(addSignerCeremonyId: string): Promise<StoredWalletAddSignerCeremony | null>;
  updateAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void>;
  takeAddSignerCeremony(addSignerCeremonyId: string): Promise<StoredWalletAddSignerCeremony | null>;
}

export class MemoryRegistrationCeremonyStore implements RegistrationCeremonyStore {
  private readonly intents = new Map<string, StoredRegistrationIntent>();
  private readonly addSignerIntents = new Map<string, StoredAddSignerIntent>();
  private readonly ceremonies = new Map<string, StoredWalletRegistrationCeremony>();
  private readonly addSignerCeremonies = new Map<string, StoredWalletAddSignerCeremony>();

  async putIntent(intent: StoredRegistrationIntent): Promise<void> {
    this.pruneExpired();
    this.intents.set(intent.grant, intent);
  }

  async getIntent(grant: RegistrationIntentGrant): Promise<StoredRegistrationIntent | null> {
    this.pruneExpired();
    const intent = this.intents.get(String(grant || '').trim()) || null;
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeIntent(grant: RegistrationIntentGrant): Promise<ConsumedRegistrationIntent | null> {
    this.pruneExpired();
    const key = String(grant || '').trim();
    const intent = this.intents.get(key) || null;
    if (!intent) return null;
    this.intents.delete(key);
    if (intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'intent_consumed', consumedAtMs: Date.now() };
  }

  async putAddSignerIntent(intent: StoredAddSignerIntent): Promise<void> {
    this.pruneExpired();
    this.addSignerIntents.set(intent.grant, intent);
  }

  async getAddSignerIntent(grant: AddSignerIntentGrant): Promise<StoredAddSignerIntent | null> {
    this.pruneExpired();
    const intent = this.addSignerIntents.get(String(grant || '').trim()) || null;
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddSignerIntent(grant: AddSignerIntentGrant): Promise<ConsumedAddSignerIntent | null> {
    this.pruneExpired();
    const key = String(grant || '').trim();
    const intent = this.addSignerIntents.get(key) || null;
    if (!intent) return null;
    this.addSignerIntents.delete(key);
    if (intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'add_signer_intent_consumed', consumedAtMs: Date.now() };
  }

  async putCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    this.pruneExpired();
    this.ceremonies.set(ceremony.registrationCeremonyId, ceremony);
  }

  async getCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    this.pruneExpired();
    const ceremony = this.ceremonies.get(String(registrationCeremonyId || '').trim()) || null;
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    this.pruneExpired();
    if (ceremony.expiresAtMs <= Date.now()) return;
    this.ceremonies.set(ceremony.registrationCeremonyId, ceremony);
  }

  async takeCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    this.pruneExpired();
    const key = String(registrationCeremonyId || '').trim();
    const ceremony = this.ceremonies.get(key) || null;
    this.ceremonies.delete(key);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async putAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    this.pruneExpired();
    this.addSignerCeremonies.set(ceremony.addSignerCeremonyId, ceremony);
  }

  async getAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    this.pruneExpired();
    const ceremony = this.addSignerCeremonies.get(String(addSignerCeremonyId || '').trim()) || null;
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    this.pruneExpired();
    if (ceremony.expiresAtMs <= Date.now()) return;
    this.addSignerCeremonies.set(ceremony.addSignerCeremonyId, ceremony);
  }

  async takeAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    this.pruneExpired();
    const key = String(addSignerCeremonyId || '').trim();
    const ceremony = this.addSignerCeremonies.get(key) || null;
    this.addSignerCeremonies.delete(key);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  private pruneExpired(): void {
    const now = Date.now();
    for (const [key, intent] of this.intents) {
      if (intent.expiresAtMs <= now) this.intents.delete(key);
    }
    for (const [key, intent] of this.addSignerIntents) {
      if (intent.expiresAtMs <= now) this.addSignerIntents.delete(key);
    }
    for (const [key, ceremony] of this.ceremonies) {
      if (ceremony.expiresAtMs <= now) this.ceremonies.delete(key);
    }
    for (const [key, ceremony] of this.addSignerCeremonies) {
      if (ceremony.expiresAtMs <= now) this.addSignerCeremonies.delete(key);
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function trimString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function parseJsonValue(value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function parseStoredRegistrationIntent(value: unknown): StoredRegistrationIntent | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (value.kind !== 'intent_allocated') return null;
  if (typeof value.grant !== 'string' || !value.grant.trim()) return null;
  if (!isRecord(value.intent)) return null;
  if (typeof value.digestB64u !== 'string' || !value.digestB64u.trim()) return null;
  if (typeof value.orgId !== 'string') return null;
  if (!Number.isFinite(Number(value.expiresAtMs))) return null;
  return value as StoredRegistrationIntent;
}

function parseStoredAddSignerIntent(value: unknown): StoredAddSignerIntent | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (value.kind !== 'add_signer_intent_allocated') return null;
  if (typeof value.grant !== 'string' || !value.grant.trim()) return null;
  if (!isRecord(value.intent)) return null;
  if (typeof value.digestB64u !== 'string' || !value.digestB64u.trim()) return null;
  if (typeof value.orgId !== 'string') return null;
  if (!Number.isFinite(Number(value.expiresAtMs))) return null;
  return value as StoredAddSignerIntent;
}

function parseStoredWalletRegistrationCeremony(
  value: unknown,
): StoredWalletRegistrationCeremony | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (typeof value.registrationCeremonyId !== 'string' || !value.registrationCeremonyId.trim()) {
    return null;
  }
  if (!isRecord(value.intent)) return null;
  if (typeof value.digestB64u !== 'string' || !value.digestB64u.trim()) return null;
  if (typeof value.orgId !== 'string') return null;
  if (!Number.isFinite(Number(value.expiresAtMs))) return null;
  if (!isRecord(value.webauthn) || !isRecord(value.signerState)) return null;
  return value as StoredWalletRegistrationCeremony;
}

function parseStoredWalletAddSignerCeremony(value: unknown): StoredWalletAddSignerCeremony | null {
  value = parseJsonValue(value);
  if (!isRecord(value)) return null;
  if (typeof value.addSignerCeremonyId !== 'string' || !value.addSignerCeremonyId.trim()) {
    return null;
  }
  if (!isRecord(value.intent)) return null;
  if (typeof value.digestB64u !== 'string' || !value.digestB64u.trim()) return null;
  if (typeof value.orgId !== 'string') return null;
  if (!Number.isFinite(Number(value.expiresAtMs))) return null;
  if (!isRecord(value.auth) || !isRecord(value.signerState)) return null;
  return value as StoredWalletAddSignerCeremony;
}

function parseJsonRecord<T>(row: unknown, parser: (value: unknown) => T | null): T | null {
  if (!isRecord(row)) return null;
  return parser(row.record_json);
}

class PostgresRegistrationCeremonyStore implements RegistrationCeremonyStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async putIntent(intent: StoredRegistrationIntent): Promise<void> {
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO wallet_registration_intents
          (namespace, intent_grant, record_json, expires_at_ms)
        VALUES ($1, $2, $3::jsonb, $4)
        ON CONFLICT (namespace, intent_grant) DO UPDATE SET
          record_json = EXCLUDED.record_json,
          expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [this.namespace, intent.grant, JSON.stringify(intent), intent.expiresAtMs],
    );
  }

  async getIntent(grant: RegistrationIntentGrant): Promise<StoredRegistrationIntent | null> {
    const pool = await this.poolPromise;
    const key = String(grant || '').trim();
    if (!key) return null;
    const result = await pool.query(
      `
        SELECT record_json
        FROM wallet_registration_intents
        WHERE namespace = $1 AND intent_grant = $2 AND expires_at_ms > $3
      `,
      [this.namespace, key, Date.now()],
    );
    return parseJsonRecord(result.rows[0], parseStoredRegistrationIntent);
  }

  async takeIntent(grant: RegistrationIntentGrant): Promise<ConsumedRegistrationIntent | null> {
    const pool = await this.poolPromise;
    const key = String(grant || '').trim();
    if (!key) return null;
    const result = await pool.query(
      `
        DELETE FROM wallet_registration_intents
        WHERE namespace = $1 AND intent_grant = $2 AND expires_at_ms > $3
        RETURNING record_json
      `,
      [this.namespace, key, Date.now()],
    );
    const intent = parseJsonRecord(result.rows[0], parseStoredRegistrationIntent);
    if (!intent) return null;
    return { ...intent, kind: 'intent_consumed', consumedAtMs: Date.now() };
  }

  async putAddSignerIntent(intent: StoredAddSignerIntent): Promise<void> {
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO wallet_registration_intents
          (namespace, intent_grant, record_json, expires_at_ms)
        VALUES ($1, $2, $3::jsonb, $4)
        ON CONFLICT (namespace, intent_grant) DO UPDATE SET
          record_json = EXCLUDED.record_json,
          expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [this.namespace, intent.grant, JSON.stringify(intent), intent.expiresAtMs],
    );
  }

  async getAddSignerIntent(grant: AddSignerIntentGrant): Promise<StoredAddSignerIntent | null> {
    const pool = await this.poolPromise;
    const key = String(grant || '').trim();
    if (!key) return null;
    const result = await pool.query(
      `
        SELECT record_json
        FROM wallet_registration_intents
        WHERE namespace = $1 AND intent_grant = $2 AND expires_at_ms > $3
      `,
      [this.namespace, key, Date.now()],
    );
    return parseJsonRecord(result.rows[0], parseStoredAddSignerIntent);
  }

  async takeAddSignerIntent(grant: AddSignerIntentGrant): Promise<ConsumedAddSignerIntent | null> {
    const pool = await this.poolPromise;
    const key = String(grant || '').trim();
    if (!key) return null;
    const result = await pool.query(
      `
        DELETE FROM wallet_registration_intents
        WHERE namespace = $1 AND intent_grant = $2 AND expires_at_ms > $3
        RETURNING record_json
      `,
      [this.namespace, key, Date.now()],
    );
    const intent = parseJsonRecord(result.rows[0], parseStoredAddSignerIntent);
    if (!intent) return null;
    return { ...intent, kind: 'add_signer_intent_consumed', consumedAtMs: Date.now() };
  }

  async putCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO wallet_registration_ceremonies
          (namespace, registration_ceremony_id, record_json, expires_at_ms)
        VALUES ($1, $2, $3::jsonb, $4)
        ON CONFLICT (namespace, registration_ceremony_id) DO UPDATE SET
          record_json = EXCLUDED.record_json,
          expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [
        this.namespace,
        ceremony.registrationCeremonyId,
        JSON.stringify(ceremony),
        ceremony.expiresAtMs,
      ],
    );
  }

  async getCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    const pool = await this.poolPromise;
    const key = String(registrationCeremonyId || '').trim();
    if (!key) return null;
    const result = await pool.query(
      `
        SELECT record_json
        FROM wallet_registration_ceremonies
        WHERE namespace = $1 AND registration_ceremony_id = $2 AND expires_at_ms > $3
      `,
      [this.namespace, key, Date.now()],
    );
    return parseJsonRecord(result.rows[0], parseStoredWalletRegistrationCeremony);
  }

  async updateCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    const pool = await this.poolPromise;
    if (ceremony.expiresAtMs <= Date.now()) return;
    await pool.query(
      `
        UPDATE wallet_registration_ceremonies
        SET record_json = $3::jsonb, expires_at_ms = $4
        WHERE namespace = $1 AND registration_ceremony_id = $2 AND expires_at_ms > $5
      `,
      [
        this.namespace,
        ceremony.registrationCeremonyId,
        JSON.stringify(ceremony),
        ceremony.expiresAtMs,
        Date.now(),
      ],
    );
  }

  async takeCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    const pool = await this.poolPromise;
    const key = String(registrationCeremonyId || '').trim();
    if (!key) return null;
    const result = await pool.query(
      `
        DELETE FROM wallet_registration_ceremonies
        WHERE namespace = $1 AND registration_ceremony_id = $2 AND expires_at_ms > $3
        RETURNING record_json
      `,
      [this.namespace, key, Date.now()],
    );
    return parseJsonRecord(result.rows[0], parseStoredWalletRegistrationCeremony);
  }

  async putAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO wallet_registration_ceremonies
          (namespace, registration_ceremony_id, record_json, expires_at_ms)
        VALUES ($1, $2, $3::jsonb, $4)
        ON CONFLICT (namespace, registration_ceremony_id) DO UPDATE SET
          record_json = EXCLUDED.record_json,
          expires_at_ms = EXCLUDED.expires_at_ms
      `,
      [
        this.namespace,
        ceremony.addSignerCeremonyId,
        JSON.stringify(ceremony),
        ceremony.expiresAtMs,
      ],
    );
  }

  async getAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    const pool = await this.poolPromise;
    const key = String(addSignerCeremonyId || '').trim();
    if (!key) return null;
    const result = await pool.query(
      `
        SELECT record_json
        FROM wallet_registration_ceremonies
        WHERE namespace = $1 AND registration_ceremony_id = $2 AND expires_at_ms > $3
      `,
      [this.namespace, key, Date.now()],
    );
    return parseJsonRecord(result.rows[0], parseStoredWalletAddSignerCeremony);
  }

  async updateAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    const pool = await this.poolPromise;
    if (ceremony.expiresAtMs <= Date.now()) return;
    await pool.query(
      `
        UPDATE wallet_registration_ceremonies
        SET record_json = $3::jsonb, expires_at_ms = $4
        WHERE namespace = $1 AND registration_ceremony_id = $2 AND expires_at_ms > $5
      `,
      [
        this.namespace,
        ceremony.addSignerCeremonyId,
        JSON.stringify(ceremony),
        ceremony.expiresAtMs,
        Date.now(),
      ],
    );
  }

  async takeAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    const pool = await this.poolPromise;
    const key = String(addSignerCeremonyId || '').trim();
    if (!key) return null;
    const result = await pool.query(
      `
        DELETE FROM wallet_registration_ceremonies
        WHERE namespace = $1 AND registration_ceremony_id = $2 AND expires_at_ms > $3
        RETURNING record_json
      `,
      [this.namespace, key, Date.now()],
    );
    return parseJsonRecord(result.rows[0], parseStoredWalletAddSignerCeremony);
  }
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };
type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;

type DoRequest =
  | { op: 'get'; key: string }
  | { op: 'set'; key: string; value: unknown; ttlMs?: number }
  | { op: 'getdel'; key: string };

function isDurableObjectNamespaceLike(
  value: unknown,
): value is CloudflareDurableObjectNamespaceLike {
  return (
    isRecord(value) && typeof value.idFromName === 'function' && typeof value.get === 'function'
  );
}

function resolveDoNamespaceFromConfig(
  config: Record<string, unknown>,
): CloudflareDurableObjectNamespaceLike | null {
  const direct = config.namespace;
  if (isDurableObjectNamespaceLike(direct)) return direct;

  const durableObjectNamespace = config.durableObjectNamespace;
  if (isDurableObjectNamespaceLike(durableObjectNamespace)) return durableObjectNamespace;

  const envStyle = config.THRESHOLD_DO_NAMESPACE;
  if (isDurableObjectNamespaceLike(envStyle)) return envStyle;

  return null;
}

function resolveDoStub(input: {
  namespace: CloudflareDurableObjectNamespaceLike;
  objectName: string;
}): DurableObjectStubLike {
  const id = input.namespace.idFromName(input.objectName);
  return input.namespace.get(id) as unknown as DurableObjectStubLike;
}

async function callDo<T>(stub: DurableObjectStubLike, request: DoRequest): Promise<DoResp<T>> {
  const response = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(request),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`Registration ceremony DO store HTTP ${response.status}: ${text}`);
  }
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(
      `Registration ceremony DO store returned non-JSON response: ${text.slice(0, 200)}`,
    );
  }
  if (!isRecord(json)) {
    throw new Error('Registration ceremony DO store returned invalid JSON shape');
  }
  if (json.ok === true) return json as DoOk<T>;
  const code = trimString(json.code);
  const message = trimString(json.message);
  return {
    ok: false,
    code: code || 'internal',
    message: message || 'Registration ceremony DO store error',
  };
}

class CloudflareDurableObjectRegistrationCeremonyStore implements RegistrationCeremonyStore {
  private readonly stub: DurableObjectStubLike;
  private readonly prefix: string;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    prefix: string;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.prefix = input.prefix;
  }

  private key(
    scope: 'intent' | 'add-signer-intent' | 'ceremony' | 'add-signer',
    id: string,
  ): string {
    return `${this.prefix}${scope}:${id}`;
  }

  async putIntent(intent: StoredRegistrationIntent): Promise<void> {
    const parsed = parseStoredRegistrationIntent(intent);
    if (!parsed) throw new Error('Invalid registration intent record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('intent', parsed.grant),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getIntent(grant: RegistrationIntentGrant): Promise<StoredRegistrationIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredRegistrationIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeIntent(grant: RegistrationIntentGrant): Promise<ConsumedRegistrationIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredRegistrationIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'intent_consumed', consumedAtMs: Date.now() };
  }

  async putAddSignerIntent(intent: StoredAddSignerIntent): Promise<void> {
    const parsed = parseStoredAddSignerIntent(intent);
    if (!parsed) throw new Error('Invalid add-signer intent record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-signer-intent', parsed.grant),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getAddSignerIntent(grant: AddSignerIntentGrant): Promise<StoredAddSignerIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('add-signer-intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredAddSignerIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddSignerIntent(grant: AddSignerIntentGrant): Promise<ConsumedAddSignerIntent | null> {
    const key = trimString(grant);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('add-signer-intent', key),
    });
    if (!response.ok) return null;
    const intent = parseStoredAddSignerIntent(response.value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return { ...intent, kind: 'add_signer_intent_consumed', consumedAtMs: Date.now() };
  }

  async putCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    const parsed = parseStoredWalletRegistrationCeremony(ceremony);
    if (!parsed) throw new Error('Invalid registration ceremony record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('ceremony', parsed.registrationCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    const key = trimString(registrationCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('ceremony', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletRegistrationCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    const parsed = parseStoredWalletRegistrationCeremony(ceremony);
    if (!parsed) throw new Error('Invalid registration ceremony record');
    if (parsed.expiresAtMs <= Date.now()) return;
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('ceremony', parsed.registrationCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async takeCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    const key = trimString(registrationCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('ceremony', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletRegistrationCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async putAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    const parsed = parseStoredWalletAddSignerCeremony(ceremony);
    if (!parsed) throw new Error('Invalid add-signer ceremony record');
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-signer', parsed.addSignerCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async getAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    const key = trimString(addSignerCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key('add-signer', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletAddSignerCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    const parsed = parseStoredWalletAddSignerCeremony(ceremony);
    if (!parsed) throw new Error('Invalid add-signer ceremony record');
    if (parsed.expiresAtMs <= Date.now()) return;
    const ttlMs = Math.max(1, parsed.expiresAtMs - Date.now());
    const response = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key('add-signer', parsed.addSignerCeremonyId),
      value: parsed,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message);
  }

  async takeAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    const key = trimString(addSignerCeremonyId);
    if (!key) return null;
    const response = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key('add-signer', key),
    });
    if (!response.ok) return null;
    const ceremony = parseStoredWalletAddSignerCeremony(response.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }
}

function resolveRegistrationDoPrefix(config: Record<string, unknown>): string {
  const explicit =
    trimString(config.WALLET_REGISTRATION_PREFIX) || trimString(config.walletRegistrationPrefix);
  const base = explicit || trimString(config.keyPrefix) || trimString(config.THRESHOLD_PREFIX);
  if (!base) return 'wallet-registration:';
  return base.endsWith(':') ? `${base}wallet-registration:` : `${base}:wallet-registration:`;
}

export function resolveRegistrationCeremonyPostgresNamespace(
  config: Record<string, unknown>,
): string {
  return typeof config.keyPrefix === 'string' && config.keyPrefix.trim()
    ? config.keyPrefix.trim()
    : '';
}

export function createRegistrationCeremonyStore(
  input: {
    config?: unknown;
    logger?: NormalizedLogger;
    isNode?: boolean;
  } = {},
): RegistrationCeremonyStore {
  const config = (input.config || {}) as Record<string, unknown>;
  const kind = typeof config.kind === 'string' ? config.kind.trim() : '';
  if (kind === 'cloudflare-do') {
    const namespace = resolveDoNamespaceFromConfig(config);
    if (!namespace) {
      throw new Error(
        'cloudflare-do registration ceremony store selected but no Durable Object namespace was provided (expected config.namespace)',
      );
    }
    const objectName =
      trimString(config.objectName) || trimString(config.name) || THRESHOLD_DO_OBJECT_NAME_DEFAULT;
    input.logger?.info(
      '[wallet-registration] Using Cloudflare Durable Object store for registration ceremonies',
    );
    return new CloudflareDurableObjectRegistrationCeremonyStore({
      namespace,
      objectName,
      prefix: resolveRegistrationDoPrefix(config),
    });
  }
  if (kind === 'postgres' || (!kind && input.isNode)) {
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (postgresUrl) {
      const namespace = resolveRegistrationCeremonyPostgresNamespace(config);
      return new PostgresRegistrationCeremonyStore({ postgresUrl, namespace });
    }
    if (kind === 'postgres') {
      throw new Error('Postgres registration ceremony store selected but POSTGRES_URL is not set');
    }
  }
  input.logger?.warn?.(
    '[wallet-registration] Using in-memory registration ceremony store; configure Postgres for durable registration ceremonies',
  );
  return new MemoryRegistrationCeremonyStore();
}

export function createWalletSubjectId(): WalletSubjectId {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  const encoded = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `wallet_${encoded}` as WalletSubjectId;
}
