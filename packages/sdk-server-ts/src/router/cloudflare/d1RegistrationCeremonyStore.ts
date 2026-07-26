import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import {
  parseServerAllocatedWalletId,
  type ServerAllocatedWalletId,
} from '@shared/utils/registrationIntent';
import {
  StoredAddAuthMethodIntent,
  StoredAddSignerIntent,
  StoredRegistrationIntent,
  StoredWalletAddAuthMethodCeremony,
  StoredWalletAddSignerCeremony,
  StoredWalletAddSignerFinalizeReplay,
  StoredWalletRegistrationCeremony,
  StoredWalletRegistrationFinalizeReplay,
  type TerminalRegistrationCeremonyCancellationResult,
} from '../../core/RegistrationCeremonyStore';
import type { WalletId } from '../../core/registrationContracts';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
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

type RegistrationIntentPutInput =
  | StoredRegistrationIntent
  | StoredWalletRegistrationCeremony
  | StoredWalletRegistrationFinalizeReplay
  | StoredWalletAddSignerFinalizeReplay
  | StoredAddSignerIntent
  | StoredWalletAddSignerCeremony
  | StoredAddAuthMethodIntent
  | StoredWalletAddAuthMethodCeremony;

export type RegistrationCeremonyIntentStoreConfig = {
  readonly kind: 'partitioned_d1';
  readonly database: D1DatabaseLike;
  readonly scope: D1RegistrationCeremonyRecordScope;
  readonly keyPrefix: string;
};

export class CloudflareD1RegistrationCeremonyIntentStore {
  private readonly storage: D1RegistrationCeremonyRecordStore;

  constructor(input: RegistrationCeremonyIntentStoreConfig) {
    this.storage = new D1RegistrationCeremonyRecordStore(input);
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
    try {
      return await this.storage.reserveExclusive({
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
    await this.storage.updateExpected({
      scope: 'ceremony',
      id: input.next.registrationCeremonyId,
      expected: encodeRecord(input.expected),
      next: encodeRecord(input.next),
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
      const storedReservation = await this.storage.get(
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
    const deleted = await this.storage.deleteCeremonyAndReservation({
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
    const record = encodeRecord(replay);
    await this.storage.putManyExact([
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
    await this.storage.updateExpected({
      scope: 'add-signer',
      id: input.next.addSignerCeremonyId,
      expected: encodeRecord(input.expected),
      next: encodeRecord(input.next),
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
    readonly record: RegistrationIntentPutInput;
    readonly expiresAtMs: number;
  }): Promise<void> {
    const id = toOptionalTrimmedString(input.id);
    if (!id) throw new Error('Registration ceremony intent id is required');
    await this.storage.putExact({
      scope: input.scope,
      id,
      value: encodeRecord(input.record),
      expiresAtMs: input.expiresAtMs,
    });
  }

  private async get(scope: RegistrationCeremonyIntentScope, id: string): Promise<unknown | null> {
    return (await this.storage.get(scope, id))?.value ?? null;
  }

  private async getDel(
    scope: RegistrationCeremonyIntentScope,
    id: string,
  ): Promise<unknown | null> {
    return await this.storage.take(scope, id);
  }

  private async del(scope: RegistrationCeremonyIntentScope, id: string): Promise<boolean> {
    return await this.storage.delete(scope, id);
  }
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
