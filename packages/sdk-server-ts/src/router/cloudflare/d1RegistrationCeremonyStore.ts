import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import {
  parseServerAllocatedWalletId,
  type ServerAllocatedWalletId,
} from '@shared/utils/registrationIntent';
import type { CloudflareDurableObjectStubLike } from '../../core/types';
import {
  StoredAddAuthMethodIntent,
  StoredAddSignerIntent,
  StoredRegistrationIntent,
  StoredWalletAddAuthMethodCeremony,
  StoredWalletAddSignerCeremony,
  StoredWalletAddSignerFinalizeReplay,
  StoredWalletRegistrationCeremony,
  StoredWalletRegistrationFinalizeReplay,
  parseTerminalRegistrationCeremonyCancellationResult,
  type TerminalRegistrationCeremonyCancellationResult,
} from '../../core/RegistrationCeremonyStore';
import type { WalletId } from '../../core/registrationContracts';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import {
  callRegistrationCeremonyDo,
  resolveRegistrationCeremonyDoStub,
  type RegistrationCeremonyDoConfig,
} from './d1RegistrationCeremonyDo';
import {
  parseD1StoredAddAuthMethodIntent,
  parseD1StoredAddSignerIntent,
  parseD1StoredRegistrationIntent,
  parseD1StoredWalletAddAuthMethodCeremony,
  parseD1StoredWalletAddSignerCeremony,
  parseD1StoredWalletAddSignerFinalizeReplay,
  parseD1StoredWalletRegistrationCeremony,
  parseD1StoredWalletRegistrationFinalizeReplay,
} from './d1RegistrationCeremonyRecords';
import {
  D1RegistrationCeremonyRecordConflictError,
  D1RegistrationCeremonyRecordStore,
  type D1RegistrationCeremonyRecordScope,
} from './d1RegistrationCeremonyRecordStore';

type RegistrationCeremonyIntentScope =
  | 'intent'
  | 'ceremony'
  | 'finalize-replay'
  | 'add-signer-finalize-replay'
  | 'add-signer-finalize-claim'
  | 'add-auth-method-intent'
  | 'add-signer-intent'
  | 'add-auth-method'
  | 'add-signer'
  | 'server-allocated-wallet-reservation';

type RegistrationIntentDoPutInput =
  | StoredRegistrationIntent
  | StoredWalletRegistrationCeremony
  | StoredWalletRegistrationFinalizeReplay
  | StoredWalletAddSignerFinalizeReplay
  | StoredAddSignerIntent
  | StoredWalletAddSignerCeremony
  | StoredAddAuthMethodIntent
  | StoredWalletAddAuthMethodCeremony;

export type RegistrationCeremonyIntentStoreConfig =
  | {
      readonly kind: 'partitioned_d1';
      readonly database: D1DatabaseLike;
      readonly scope: D1RegistrationCeremonyRecordScope;
      readonly keyPrefix: string;
    }
  | {
      readonly kind: 'legacy_threshold_do';
      readonly config: RegistrationCeremonyDoConfig;
    };

type RegistrationCeremonyIntentStorage =
  | {
      readonly kind: 'partitioned_d1';
      readonly store: D1RegistrationCeremonyRecordStore;
    }
  | {
      readonly kind: 'legacy_threshold_do';
      readonly stub: CloudflareDurableObjectStubLike;
      readonly prefix: string;
    };

export class CloudflareD1RegistrationCeremonyIntentStore {
  private readonly storage: RegistrationCeremonyIntentStorage;

  constructor(input: RegistrationCeremonyIntentStoreConfig) {
    this.storage = createRegistrationCeremonyIntentStorage(input);
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
    if (this.storage.kind === 'partitioned_d1') {
      try {
        return await this.storage.store.reserveExclusive({
          scope: 'server-allocated-wallet-reservation',
          id: serverAllocatedWalletReservationKey(input),
          value: {
            kind: 'registration_wallet_reservation_v1',
            walletId,
            expiresAtMs,
          },
          expiresAtMs,
        });
      } catch {
        return false;
      }
    }
    const response = await callRegistrationCeremonyDo<unknown>(this.storage.stub, {
      op: 'registrationReserveWalletId',
      key: this.key(
        'server-allocated-wallet-reservation',
        serverAllocatedWalletReservationKey(input),
      ),
      walletId,
      expiresAtMs,
    });
    return response.ok;
  }

  async releaseServerAllocatedWalletId(input: {
    readonly walletId: ServerAllocatedWalletId;
  }): Promise<boolean> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return false;
    return await this.del(
      'server-allocated-wallet-reservation',
      serverAllocatedWalletReservationKey(input),
    );
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

  async updateCeremony(input: {
    readonly expected: StoredWalletRegistrationCeremony;
    readonly next: StoredWalletRegistrationCeremony;
  }): Promise<void> {
    if (input.expected.registrationCeremonyId !== input.next.registrationCeremonyId) {
      throw new Error('Registration ceremony update cannot change its identity');
    }
    if (this.storage.kind === 'partitioned_d1') {
      await this.storage.store.updateExpected({
        scope: 'ceremony',
        id: input.next.registrationCeremonyId,
        expected: encodeRecord(input.expected),
        next: encodeRecord(input.next),
        expiresAtMs: input.next.expiresAtMs,
      });
      return;
    }
    await this.updateExpected({
      scope: 'ceremony',
      id: input.next.registrationCeremonyId,
      expected: input.expected,
      next: input.next,
      expiresAtMs: input.next.expiresAtMs,
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

  async cancelTerminalCeremony(input: {
    readonly registrationCeremonyId: string;
    readonly walletId: WalletId;
  }): Promise<TerminalRegistrationCeremonyCancellationResult> {
    const registrationCeremonyId = toOptionalTrimmedString(input.registrationCeremonyId);
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!registrationCeremonyId || !walletId) {
      throw new Error('Terminal registration cancellation requires ceremony and wallet IDs');
    }
    const serverAllocatedWalletId = parseServerAllocatedWalletId(input.walletId);
    if (this.storage.kind === 'partitioned_d1') {
      const ceremony = await this.getCeremony(registrationCeremonyId);
      if (!ceremony) {
        return { kind: 'not_found', ceremonyDeleted: false, walletReservationReleased: false };
      }
      if (
        ceremony.registrationCeremonyId !== registrationCeremonyId ||
        ceremony.intent.walletId !== walletId
      ) {
        throw new Error('Terminal registration cancellation does not match the stored ceremony');
      }
      let reservation:
        | { readonly kind: 'none' }
        | {
            readonly kind: 'server_allocated_wallet';
            readonly scope: 'server-allocated-wallet-reservation';
            readonly id: string;
            readonly expected: Record<string, unknown>;
          } = { kind: 'none' };
      if (serverAllocatedWalletId.ok) {
        const reservationId = serverAllocatedWalletReservationKey({
          walletId: serverAllocatedWalletId.value,
        });
        const storedReservation = await this.storage.store.get(
          'server-allocated-wallet-reservation',
          reservationId,
        );
        if (storedReservation) {
          if (
            storedReservation.value.kind !== 'registration_wallet_reservation_v1' ||
            storedReservation.value.walletId !== walletId ||
            !Number.isSafeInteger(storedReservation.value.expiresAtMs)
          ) {
            throw new Error('Terminal registration cancellation found a mismatched reservation');
          }
          reservation = {
            kind: 'server_allocated_wallet',
            scope: 'server-allocated-wallet-reservation',
            id: reservationId,
            expected: storedReservation.value,
          };
        }
      }
      const deleted = await this.storage.store.deleteCeremonyAndReservation({
        ceremonyScope: 'ceremony',
        ceremonyId: registrationCeremonyId,
        expectedCeremony: encodeRecord(ceremony),
        reservation,
      });
      return deleted.ceremonyDeleted
        ? {
            kind: 'cancelled',
            ceremonyDeleted: true,
            walletReservationReleased: deleted.reservationDeleted,
          }
        : { kind: 'not_found', ceremonyDeleted: false, walletReservationReleased: false };
    }
    const response = await callRegistrationCeremonyDo<unknown>(this.storage.stub, {
      op: 'registrationCancelTerminal',
      ceremonyKey: this.key('ceremony', registrationCeremonyId),
      registrationCeremonyId,
      walletId,
      reservation: serverAllocatedWalletId.ok
        ? {
            kind: 'server_allocated_wallet',
            key: this.key(
              'server-allocated-wallet-reservation',
              serverAllocatedWalletReservationKey({
                walletId: serverAllocatedWalletId.value,
              }),
            ),
          }
        : { kind: 'none' },
    });
    if (!response.ok) throw new Error(response.message);
    const result = parseTerminalRegistrationCeremonyCancellationResult(response.value);
    if (!result) throw new Error('Terminal registration cancellation returned an invalid result');
    return result;
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

  async putAddSignerFinalizeReplay(replay: StoredWalletAddSignerFinalizeReplay): Promise<void> {
    if (this.storage.kind === 'partitioned_d1') {
      const record = encodeRecord(replay);
      await this.storage.store.putManyExact([
        {
          scope: 'add-signer-finalize-replay',
          id: addSignerFinalizeReplayKey(replay),
          value: record,
          expiresAtMs: replay.expiresAtMs,
        },
        {
          scope: 'add-signer-finalize-claim',
          id: replay.addSignerCeremonyId,
          value: record,
          expiresAtMs: replay.expiresAtMs,
        },
      ]);
      return;
    }
    await this.put({
      scope: 'add-signer-finalize-replay',
      id: addSignerFinalizeReplayKey(replay),
      record: replay,
      expiresAtMs: replay.expiresAtMs,
    });
    await this.put({
      scope: 'add-signer-finalize-claim',
      id: replay.addSignerCeremonyId,
      record: replay,
      expiresAtMs: replay.expiresAtMs,
    });
  }

  async getAddSignerFinalizeReplay(input: {
    readonly addSignerCeremonyId: string;
    readonly idempotencyKey: string;
  }): Promise<StoredWalletAddSignerFinalizeReplay | null> {
    const key = addSignerFinalizeReplayKey(input);
    if (!key) return null;
    const value = await this.get('add-signer-finalize-replay', key);
    const replay = parseD1StoredWalletAddSignerFinalizeReplay(value);
    if (!replay || replay.expiresAtMs <= Date.now()) return null;
    return replay;
  }

  async getAddSignerFinalizeReplayForCeremony(
    addSignerCeremonyId: string,
  ): Promise<StoredWalletAddSignerFinalizeReplay | null> {
    const ceremonyId = toOptionalTrimmedString(addSignerCeremonyId);
    if (!ceremonyId) return null;
    const value = await this.get('add-signer-finalize-claim', ceremonyId);
    const replay = parseD1StoredWalletAddSignerFinalizeReplay(value);
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

  async updateAddSignerCeremony(input: {
    readonly expected: StoredWalletAddSignerCeremony;
    readonly next: StoredWalletAddSignerCeremony;
  }): Promise<void> {
    if (input.expected.addSignerCeremonyId !== input.next.addSignerCeremonyId) {
      throw new Error('Add-signer ceremony update cannot change its identity');
    }
    if (this.storage.kind === 'partitioned_d1') {
      await this.storage.store.updateExpected({
        scope: 'add-signer',
        id: input.next.addSignerCeremonyId,
        expected: encodeRecord(input.expected),
        next: encodeRecord(input.next),
        expiresAtMs: input.next.expiresAtMs,
      });
      return;
    }
    await this.updateExpected({
      scope: 'add-signer',
      id: input.next.addSignerCeremonyId,
      expected: input.expected,
      next: input.next,
      expiresAtMs: input.next.expiresAtMs,
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
    if (this.storage.kind === 'partitioned_d1') {
      await this.storage.store.putExact({
        scope: input.scope,
        id,
        value: encodeRecord(input.record),
        expiresAtMs: input.expiresAtMs,
      });
      return;
    }
    const ttlMs = Math.max(1, input.expiresAtMs - Date.now());
    const response = await callRegistrationCeremonyDo<boolean>(this.storage.stub, {
      op: 'set',
      key: this.key(input.scope, id),
      value: input.record,
      ttlMs,
    });
    if (!response.ok) throw new Error(response.message || 'Registration ceremony DO write failed');
  }

  private async updateExpected(input: {
    readonly scope: 'ceremony' | 'add-signer';
    readonly id: string;
    readonly expected: StoredWalletRegistrationCeremony | StoredWalletAddSignerCeremony;
    readonly next: StoredWalletRegistrationCeremony | StoredWalletAddSignerCeremony;
    readonly expiresAtMs: number;
  }): Promise<void> {
    if (this.storage.kind !== 'legacy_threshold_do') {
      throw new Error('Registration ceremony Durable Object update requires legacy storage');
    }
    const ttlMs = Math.max(1, input.expiresAtMs - Date.now());
    const response = await callRegistrationCeremonyDo<boolean>(this.storage.stub, {
      op: 'registrationUpdateExpected',
      key: this.key(input.scope, input.id),
      expected: input.expected,
      next: input.next,
      ttlMs,
    });
    if (response.ok) return;
    if (response.code === 'registration_ceremony_conflict') {
      throw new D1RegistrationCeremonyRecordConflictError(
        response.message || 'Registration ceremony record changed before update',
      );
    }
    throw new Error(response.message || 'Registration ceremony DO update failed');
  }

  private async get(scope: RegistrationCeremonyIntentScope, id: string): Promise<unknown | null> {
    if (this.storage.kind === 'partitioned_d1') {
      return (await this.storage.store.get(scope, id))?.value ?? null;
    }
    const response = await callRegistrationCeremonyDo<unknown | null>(this.storage.stub, {
      op: 'get',
      key: this.key(scope, id),
    });
    return response.ok ? response.value : null;
  }

  private async getDel(
    scope: RegistrationCeremonyIntentScope,
    id: string,
  ): Promise<unknown | null> {
    if (this.storage.kind === 'partitioned_d1') {
      return await this.storage.store.take(scope, id);
    }
    const response = await callRegistrationCeremonyDo<unknown | null>(this.storage.stub, {
      op: 'getdel',
      key: this.key(scope, id),
    });
    return response.ok ? response.value : null;
  }

  private async del(scope: RegistrationCeremonyIntentScope, id: string): Promise<boolean> {
    if (this.storage.kind === 'partitioned_d1') {
      return await this.storage.store.delete(scope, id);
    }
    const response = await callRegistrationCeremonyDo<boolean>(this.storage.stub, {
      op: 'del',
      key: this.key(scope, id),
    });
    return response.ok && response.value === true;
  }

  private key(scope: RegistrationCeremonyIntentScope, id: string): string {
    if (this.storage.kind !== 'legacy_threshold_do') {
      throw new Error('Registration ceremony Durable Object key requested for D1 storage');
    }
    return `${this.storage.prefix}${scope}:${id}`;
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
    message:
      'Cloudflare D1 Router API registration intents require thresholdStore.kind cloudflare-do',
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

function addSignerFinalizeReplayKey(input: {
  readonly addSignerCeremonyId: string;
  readonly idempotencyKey: string;
}): string {
  const addSignerCeremonyId = toOptionalTrimmedString(input.addSignerCeremonyId);
  const idempotencyKey = toOptionalTrimmedString(input.idempotencyKey);
  if (!addSignerCeremonyId || !idempotencyKey) return '';
  return `${encodeURIComponent(addSignerCeremonyId)}:${encodeURIComponent(idempotencyKey)}`;
}

function encodeRecord(value: unknown): Record<string, unknown> {
  if (!isPlainObject(value)) throw new Error('Registration ceremony record must be an object');
  return value;
}

function assertNeverStoreConfig(value: never): never {
  throw new Error(`Unhandled registration ceremony store config: ${JSON.stringify(value)}`);
}

function createRegistrationCeremonyIntentStorage(
  input: RegistrationCeremonyIntentStoreConfig,
): RegistrationCeremonyIntentStorage {
  switch (input.kind) {
    case 'partitioned_d1':
      return {
        kind: 'partitioned_d1',
        store: new D1RegistrationCeremonyRecordStore(input),
      };
    case 'legacy_threshold_do':
      return {
        kind: 'legacy_threshold_do',
        stub: resolveRegistrationCeremonyDoStub(input.config),
        prefix: input.config.prefix,
      };
    default:
      return assertNeverStoreConfig(input);
  }
}
