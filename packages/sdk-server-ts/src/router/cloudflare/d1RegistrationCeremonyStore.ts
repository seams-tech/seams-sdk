import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { ServerAllocatedWalletId } from '@shared/utils/registrationIntent';
import type { CloudflareDurableObjectStubLike } from '../../core/types';
import {
  storedRegistrationAuthoritiesMatch,
  storedEd25519RegistrationPrepareScopesMatch,
  type ConsumeRegistrationIntentForPreparationInput,
  type ConsumeRegistrationIntentForPreparationResult,
  StoredAddAuthMethodIntent,
  StoredAddSignerIntent,
  StoredRegistrationIntent,
  StoredWalletRegistrationHssPreparation,
  StoredWalletAddAuthMethodCeremony,
  StoredWalletAddSignerCeremony,
  StoredWalletRegistrationCeremony,
  StoredWalletRegistrationFinalizeReplay,
} from '../../core/RegistrationCeremonyStore';
import {
  callRegistrationCeremonyDo,
  resolveRegistrationCeremonyDoStub,
  type RegistrationCeremonyDoConfig,
} from './d1RegistrationCeremonyDo';
import {
  parseD1StoredAddAuthMethodIntent,
  parseD1StoredAddSignerIntent,
  parseD1StoredRegistrationIntent,
  parseD1StoredWalletRegistrationHssPreparation,
  parseD1StoredWalletAddAuthMethodCeremony,
  parseD1StoredWalletAddSignerCeremony,
  parseD1StoredWalletRegistrationCeremony,
  parseD1StoredWalletRegistrationFinalizeReplay,
} from './d1RegistrationCeremonyRecords';

type RegistrationCeremonyIntentScope =
  | 'intent'
  | 'preparation'
  | 'ceremony'
  | 'finalize-replay'
  | 'add-auth-method-intent'
  | 'add-signer-intent'
  | 'add-auth-method'
  | 'add-signer'
  | 'server-allocated-wallet-reservation';

type RegistrationIntentDoPutInput =
  | StoredRegistrationIntent
  | StoredWalletRegistrationHssPreparation
  | StoredWalletRegistrationCeremony
  | StoredWalletRegistrationFinalizeReplay
  | StoredAddSignerIntent
  | StoredWalletAddSignerCeremony
  | StoredAddAuthMethodIntent
  | StoredWalletAddAuthMethodCeremony;

export class CloudflareD1RegistrationCeremonyIntentStore {
  private readonly stub: CloudflareDurableObjectStubLike;
  private readonly prefix: string;

  constructor(input: RegistrationCeremonyDoConfig) {
    this.stub = resolveRegistrationCeremonyDoStub(input);
    this.prefix = input.prefix;
  }

  async reserveServerAllocatedWalletId(input: {
    readonly walletId: ServerAllocatedWalletId;
    readonly expiresAtMs: number;
  }): Promise<boolean> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const expiresAtMs = Math.floor(Number(input.expiresAtMs));
    if (!walletId || !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
      return false;
    }
    const response = await callRegistrationCeremonyDo<{ readonly reserved: true }>(this.stub, {
      op: 'authReserveReplayGuard',
      key: this.key(
        'server-allocated-wallet-reservation',
        serverAllocatedWalletReservationKey(input),
      ),
      expiresAtMs,
    });
    return response.ok;
  }

  async putIntent(intent: StoredRegistrationIntent): Promise<void> {
    await this.put({
      scope: 'intent',
      id: intent.grant,
      record: intent,
      expiresAtMs: intent.expiresAtMs,
    });
  }

  async getIntent(grant: string): Promise<StoredRegistrationIntent | null> {
    const id = toOptionalTrimmedString(grant);
    if (!id) return null;
    const value = await this.get('intent', id);
    const intent = parseD1StoredRegistrationIntent(value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeIntent(grant: string): Promise<StoredRegistrationIntent | null> {
    const id = toOptionalTrimmedString(grant);
    if (!id) return null;
    const value = await this.getDel('intent', id);
    const intent = parseD1StoredRegistrationIntent(value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async putPreparation(preparation: StoredWalletRegistrationHssPreparation): Promise<void> {
    await this.put({
      scope: 'preparation',
      id: preparation.registrationPreparationId,
      record: preparation,
      expiresAtMs: preparation.expiresAtMs,
    });
  }

  async getPreparation(
    registrationPreparationId: string,
  ): Promise<StoredWalletRegistrationHssPreparation | null> {
    const id = toOptionalTrimmedString(registrationPreparationId);
    if (!id) return null;
    const value = await this.get('preparation', id);
    const preparation = parseD1StoredWalletRegistrationHssPreparation(value);
    if (!preparation || preparation.expiresAtMs <= Date.now()) return null;
    return preparation;
  }

  async updatePreparation(preparation: StoredWalletRegistrationHssPreparation): Promise<void> {
    await this.put({
      scope: 'preparation',
      id: preparation.registrationPreparationId,
      record: preparation,
      expiresAtMs: preparation.expiresAtMs,
    });
  }

  async takePreparation(
    registrationPreparationId: string,
  ): Promise<StoredWalletRegistrationHssPreparation | null> {
    const id = toOptionalTrimmedString(registrationPreparationId);
    if (!id) return null;
    const value = await this.getDel('preparation', id);
    const preparation = parseD1StoredWalletRegistrationHssPreparation(value);
    if (!preparation || preparation.expiresAtMs <= Date.now()) return null;
    return preparation;
  }

  async consumeRegistrationIntentForPreparation(
    input: ConsumeRegistrationIntentForPreparationInput,
  ): Promise<ConsumeRegistrationIntentForPreparationResult> {
    const intent = await this.takeIntent(input.registrationIntentGrant);
    if (!intent || intent.digestB64u !== input.registrationIntentDigestB64u) {
      return { ok: false, code: 'invalid_grant', message: 'registration intent grant expired' };
    }
    const preparation = await this.getPreparation(input.registrationPreparationId);
    if (
      !preparation ||
      preparation.kind !== 'hss_prepare_prepared' ||
      preparation.registrationIntentGrant !== input.registrationIntentGrant ||
      preparation.registrationIntentDigestB64u !== input.registrationIntentDigestB64u ||
      !storedRegistrationAuthoritiesMatch(preparation.authority, input.authority) ||
      !storedEd25519RegistrationPrepareScopesMatch(
        preparation.ed25519Scope,
        input.ed25519Scope,
      )
    ) {
      return {
        ok: false,
        code: 'scope_mismatch',
        message: 'registration preparation does not match registration intent',
      };
    }
    return {
      ok: true,
      intent: {
        ...intent,
        kind: 'intent_consumed',
        consumedAtMs: Date.now(),
      },
    };
  }

  async putCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    await this.put({
      scope: 'ceremony',
      id: ceremony.registrationCeremonyId,
      record: ceremony,
      expiresAtMs: ceremony.expiresAtMs,
    });
  }

  async getCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    const id = toOptionalTrimmedString(registrationCeremonyId);
    if (!id) return null;
    const value = await this.get('ceremony', id);
    const ceremony = parseD1StoredWalletRegistrationCeremony(value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateCeremony(ceremony: StoredWalletRegistrationCeremony): Promise<void> {
    await this.put({
      scope: 'ceremony',
      id: ceremony.registrationCeremonyId,
      record: ceremony,
      expiresAtMs: ceremony.expiresAtMs,
    });
  }

  async takeCeremony(
    registrationCeremonyId: string,
  ): Promise<StoredWalletRegistrationCeremony | null> {
    const id = toOptionalTrimmedString(registrationCeremonyId);
    if (!id) return null;
    const value = await this.getDel('ceremony', id);
    const ceremony = parseD1StoredWalletRegistrationCeremony(value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async deleteCeremony(registrationCeremonyId: string): Promise<boolean> {
    const id = toOptionalTrimmedString(registrationCeremonyId);
    if (!id) return false;
    return await this.del('ceremony', id);
  }

  async putFinalizeReplay(replay: StoredWalletRegistrationFinalizeReplay): Promise<void> {
    await this.put({
      scope: 'finalize-replay',
      id: registrationFinalizeReplayKey(replay),
      record: replay,
      expiresAtMs: replay.expiresAtMs,
    });
  }

  async getFinalizeReplay(input: {
    readonly registrationCeremonyId: string;
    readonly idempotencyKey: string;
  }): Promise<StoredWalletRegistrationFinalizeReplay | null> {
    const key = registrationFinalizeReplayKey(input);
    if (!key) return null;
    const value = await this.get('finalize-replay', key);
    const replay = parseD1StoredWalletRegistrationFinalizeReplay(value);
    if (!replay || replay.expiresAtMs <= Date.now()) return null;
    return replay;
  }

  async putAddSignerIntent(intent: StoredAddSignerIntent): Promise<void> {
    await this.put({
      scope: 'add-signer-intent',
      id: intent.grant,
      record: intent,
      expiresAtMs: intent.expiresAtMs,
    });
  }

  async getAddSignerIntent(grant: string): Promise<StoredAddSignerIntent | null> {
    const id = toOptionalTrimmedString(grant);
    if (!id) return null;
    const value = await this.get('add-signer-intent', id);
    const intent = parseD1StoredAddSignerIntent(value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddSignerIntent(grant: string): Promise<StoredAddSignerIntent | null> {
    const id = toOptionalTrimmedString(grant);
    if (!id) return null;
    const value = await this.getDel('add-signer-intent', id);
    const intent = parseD1StoredAddSignerIntent(value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async putAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    await this.put({
      scope: 'add-signer',
      id: ceremony.addSignerCeremonyId,
      record: ceremony,
      expiresAtMs: ceremony.expiresAtMs,
    });
  }

  async getAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    const id = toOptionalTrimmedString(addSignerCeremonyId);
    if (!id) return null;
    const value = await this.get('add-signer', id);
    const ceremony = parseD1StoredWalletAddSignerCeremony(value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async updateAddSignerCeremony(ceremony: StoredWalletAddSignerCeremony): Promise<void> {
    await this.put({
      scope: 'add-signer',
      id: ceremony.addSignerCeremonyId,
      record: ceremony,
      expiresAtMs: ceremony.expiresAtMs,
    });
  }

  async takeAddSignerCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerCeremony | null> {
    const id = toOptionalTrimmedString(addSignerCeremonyId);
    if (!id) return null;
    const value = await this.getDel('add-signer', id);
    const ceremony = parseD1StoredWalletAddSignerCeremony(value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async putAddAuthMethodIntent(intent: StoredAddAuthMethodIntent): Promise<void> {
    await this.put({
      scope: 'add-auth-method-intent',
      id: intent.grant,
      record: intent,
      expiresAtMs: intent.expiresAtMs,
    });
  }

  async getAddAuthMethodIntent(grant: string): Promise<StoredAddAuthMethodIntent | null> {
    const id = toOptionalTrimmedString(grant);
    if (!id) return null;
    const value = await this.get('add-auth-method-intent', id);
    const intent = parseD1StoredAddAuthMethodIntent(value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async takeAddAuthMethodIntent(grant: string): Promise<StoredAddAuthMethodIntent | null> {
    const id = toOptionalTrimmedString(grant);
    if (!id) return null;
    const value = await this.getDel('add-auth-method-intent', id);
    const intent = parseD1StoredAddAuthMethodIntent(value);
    if (!intent || intent.expiresAtMs <= Date.now()) return null;
    return intent;
  }

  async putAddAuthMethodCeremony(ceremony: StoredWalletAddAuthMethodCeremony): Promise<void> {
    await this.put({
      scope: 'add-auth-method',
      id: ceremony.addAuthMethodCeremonyId,
      record: ceremony,
      expiresAtMs: ceremony.expiresAtMs,
    });
  }

  async getAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null> {
    const id = toOptionalTrimmedString(addAuthMethodCeremonyId);
    if (!id) return null;
    const value = await this.get('add-auth-method', id);
    const ceremony = parseD1StoredWalletAddAuthMethodCeremony(value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  async takeAddAuthMethodCeremony(
    addAuthMethodCeremonyId: string,
  ): Promise<StoredWalletAddAuthMethodCeremony | null> {
    const id = toOptionalTrimmedString(addAuthMethodCeremonyId);
    if (!id) return null;
    const value = await this.getDel('add-auth-method', id);
    const ceremony = parseD1StoredWalletAddAuthMethodCeremony(value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return ceremony;
  }

  private async put(input: {
    readonly scope: RegistrationCeremonyIntentScope;
    readonly id: string;
    readonly record: RegistrationIntentDoPutInput;
    readonly expiresAtMs: number;
  }): Promise<void> {
    const id = toOptionalTrimmedString(input.id);
    if (!id) throw new Error('Registration ceremony intent id is required');
    const ttlMs = Math.max(1, input.expiresAtMs - Date.now());
    const response = await callRegistrationCeremonyDo<boolean>(this.stub, {
      op: 'set',
      key: this.key(input.scope, id),
      value: input.record,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message || 'Registration ceremony DO write failed');
  }

  private async get(scope: RegistrationCeremonyIntentScope, id: string): Promise<unknown | null> {
    const response = await callRegistrationCeremonyDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.key(scope, id),
    });
    return response.ok ? response.value : null;
  }

  private async getDel(
    scope: RegistrationCeremonyIntentScope,
    id: string,
  ): Promise<unknown | null> {
    const response = await callRegistrationCeremonyDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.key(scope, id),
    });
    return response.ok ? response.value : null;
  }

  private async del(scope: RegistrationCeremonyIntentScope, id: string): Promise<boolean> {
    const response = await callRegistrationCeremonyDo<boolean>(this.stub, {
      op: 'del',
      key: this.key(scope, id),
    });
    return response.ok && response.value === true;
  }

  private key(scope: RegistrationCeremonyIntentScope, id: string): string {
    return `${this.prefix}${scope}:${id}`;
  }
}

export function missingRegistrationCeremonyDoStore(): {
  readonly ok: false;
  readonly code: 'configuration';
  readonly message: string;
} {
  return {
    ok: false,
    code: 'configuration',
    message: 'Cloudflare D1 Router API registration intents require thresholdStore.kind cloudflare-do',
  };
}

function serverAllocatedWalletReservationKey(input: {
  readonly walletId: ServerAllocatedWalletId;
}): string {
  const walletId = toOptionalTrimmedString(input.walletId);
  if (!walletId) return '';
  return walletId;
}

function registrationFinalizeReplayKey(input: {
  readonly registrationCeremonyId: string;
  readonly idempotencyKey: string;
}): string {
  const registrationCeremonyId = toOptionalTrimmedString(input.registrationCeremonyId);
  const idempotencyKey = toOptionalTrimmedString(input.idempotencyKey);
  if (!registrationCeremonyId || !idempotencyKey) return '';
  return `${encodeURIComponent(registrationCeremonyId)}:${encodeURIComponent(idempotencyKey)}`;
}
