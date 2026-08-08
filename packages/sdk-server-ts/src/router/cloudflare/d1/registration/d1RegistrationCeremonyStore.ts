import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import {
  StoredAddAuthMethodIntent,
  StoredAddSignerIntent,
  StoredWalletAddAuthMethodCeremony,
  StoredWalletAddSignerCeremony,
  StoredWalletAddSignerFinalizeReplay,
  StoredWalletRegistrationCeremony,
  type StoredWalletRegistrationEvmFamilyEcdsaActivationClaimedBranch,
  type StoredWalletRegistrationEvmFamilyEcdsaResponseClaimedBranch,
  type TerminalRegistrationCeremonyCancellationResult,
} from '../../../../core/RegistrationCeremonyStore';
import type { WalletId } from '../../../../core/registrationContracts';
import type { D1DatabaseLike } from '../../../../storage/tenantRoute';
import {
  parseD1StoredAddAuthMethodIntent,
  parseD1StoredAddSignerIntent,
  parseD1StoredWalletAddAuthMethodCeremony,
  parseD1StoredWalletAddSignerCeremony,
  parseD1StoredWalletAddSignerFinalizeReplay,
  parseD1StoredWalletRegistrationCeremony,
} from './d1RegistrationCeremonyRecords';
import {
  D1RegistrationCeremonyRecordStore,
  type D1RegistrationCeremonyRecordScope,
} from './d1RegistrationCeremonyRecordStore';

type RegistrationCeremonyIntentScope =
  | 'ceremony'
  | 'add-signer-finalize-replay'
  | 'add-signer-finalize-claim'
  | 'add-auth-method-intent'
  | 'add-signer-intent'
  | 'add-auth-method'
  | 'add-signer';

type RegistrationIntentPutInput =
  | StoredWalletRegistrationCeremony
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

export type D1WalletRegistrationEcdsaCeremonyClaimV1 = {
  readonly ceremony: StoredWalletRegistrationCeremony;
  readonly version: number;
};

export class CloudflareD1RegistrationCeremonyIntentStore {
  private readonly storage: D1RegistrationCeremonyRecordStore;

  constructor(input: RegistrationCeremonyIntentStoreConfig) {
    this.storage = new D1RegistrationCeremonyRecordStore(input);
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
    return (await this.getCeremonySnapshot(registrationCeremonyId))?.ceremony ?? null;
  }

  async getCeremonySnapshot(
    registrationCeremonyId: string,
  ): Promise<D1WalletRegistrationEcdsaCeremonyClaimV1 | null> {
    const id = toOptionalTrimmedString(registrationCeremonyId);
    if (!id) return null;
    const stored = await this.storage.get('ceremony', id);
    if (!stored) return null;
    const ceremony = parseD1StoredWalletRegistrationCeremony(stored.value);
    if (!ceremony || ceremony.expiresAtMs <= Date.now()) return null;
    return { ceremony, version: stored.version };
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

  async claimEcdsaRespond(input: {
    readonly registrationCeremonyId: string;
    readonly strictRegistrationBindingJson: string;
    readonly registrationRequest: StoredWalletRegistrationEvmFamilyEcdsaResponseClaimedBranch['registrationRequest'];
  }): Promise<D1WalletRegistrationEcdsaCeremonyClaimV1 | null> {
    return await this.claimEcdsaBranch({
      registrationCeremonyId: input.registrationCeremonyId,
      expectedKind: 'evm_family_ecdsa_prepared',
      binding: {
        kind: 'strict_registration',
        strictRegistrationBindingJson: input.strictRegistrationBindingJson,
      },
      patch: {
        kind: 'evm_family_ecdsa_response_claimed',
        registrationRequest: input.registrationRequest,
      },
    });
  }

  async claimEcdsaActivation(input: {
    readonly registrationCeremonyId: string;
    readonly publicFacts: StoredWalletRegistrationEvmFamilyEcdsaActivationClaimedBranch['publicFacts'];
    readonly activationRequestDigestB64u: string;
    readonly activationOwner: string;
  }): Promise<D1WalletRegistrationEcdsaCeremonyClaimV1 | null> {
    return await this.claimEcdsaBranch({
      registrationCeremonyId: input.registrationCeremonyId,
      expectedKind: 'evm_family_ecdsa_pending_activation',
      binding: { kind: 'pending_activation' },
      patch: {
        kind: 'evm_family_ecdsa_activation_claimed',
        publicFacts: input.publicFacts,
        activationRequestDigestB64u: input.activationRequestDigestB64u,
        activationOwner: input.activationOwner,
      },
    });
  }

  async commitEcdsaClaim(input: {
    readonly expected: D1WalletRegistrationEcdsaCeremonyClaimV1;
    readonly next: StoredWalletRegistrationCeremony;
  }): Promise<void> {
    if (
      input.expected.ceremony.registrationCeremonyId !== input.next.registrationCeremonyId
    ) {
      throw new Error('ECDSA registration claim commit cannot change its ceremony identity');
    }
    await this.storage.updateExpectedVersion({
      scope: 'ceremony',
      id: input.next.registrationCeremonyId,
      expectedVersion: input.expected.version,
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
    const ceremony = await this.getCeremony(registrationCeremonyId);
    if (!ceremony) {
      return { kind: 'not_found', ceremonyDeleted: false };
    }
    if (
      ceremony.registrationCeremonyId !== registrationCeremonyId ||
      ceremony.intent.walletId !== walletId
    ) {
      throw new Error('Terminal registration cancellation does not match the stored ceremony');
    }
    return (await this.storage.delete('ceremony', registrationCeremonyId))
      ? { kind: 'cancelled', ceremonyDeleted: true }
      : { kind: 'not_found', ceremonyDeleted: false };
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

  private async claimEcdsaBranch(input: {
    readonly registrationCeremonyId: string;
    readonly expectedKind:
      | 'evm_family_ecdsa_prepared'
      | 'evm_family_ecdsa_pending_activation';
    readonly binding:
      | {
          readonly kind: 'strict_registration';
          readonly strictRegistrationBindingJson: string;
        }
      | { readonly kind: 'pending_activation' };
    readonly patch: Record<string, unknown>;
  }): Promise<D1WalletRegistrationEcdsaCeremonyClaimV1 | null> {
    const registrationCeremonyId = toOptionalTrimmedString(input.registrationCeremonyId);
    if (!registrationCeremonyId) return null;
    const claimed = await this.storage.claimEcdsaRegistrationBranch({
      scope: 'ceremony',
      id: registrationCeremonyId,
      expectedKind: input.expectedKind,
      binding: input.binding,
      patch: input.patch,
    });
    if (!claimed) return null;
    const ceremony = parseD1StoredWalletRegistrationCeremony(claimed.value);
    if (
      !ceremony ||
      ceremony.registrationCeremonyId !== registrationCeremonyId ||
      ceremony.expiresAtMs <= Date.now()
    ) {
      throw new Error('Claimed ECDSA registration ceremony is invalid');
    }
    return { ceremony, version: claimed.version };
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
