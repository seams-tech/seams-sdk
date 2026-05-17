import type { IDBPDatabase } from 'idb';
import { toTrimmedString } from '@shared/utils/validation';
import type {
  AccountModel,
  AccountModelCapabilities,
  AccountSignerRecord,
  AccountSignerStatus,
  AccountSignerType,
  ChainAccountRecord,
  DBConstraintErrorCode,
  SignerAuthMethod,
  SignerKind,
  SignerSource,
  UpsertAccountSignerInput,
} from '../passkeyClientDB.types';
import {
  normalizeIndexedDbAccountAddress as normalizeAccountAddress,
  normalizeIndexedDbChainIdKey as normalizeChainIdKey,
} from '../normalization';

type CreateConstraintError = (
  code: DBConstraintErrorCode,
  message: string,
  details?: Record<string, unknown>,
) => Error;

export const ALLOWED_SIGNER_STATUS_TRANSITIONS: Record<
  AccountSignerStatus,
  ReadonlySet<AccountSignerStatus>
> = {
  pending: new Set<AccountSignerStatus>(['pending', 'active', 'revoked']),
  active: new Set<AccountSignerStatus>(['active', 'revoked']),
  revoked: new Set<AccountSignerStatus>(['revoked']),
};

const DEFAULT_ACCOUNT_MODEL_CAPABILITIES: AccountModelCapabilities = {
  supportsMultiSigner: true,
  supportsAddRemoveSigner: true,
  supportsSessionSigner: true,
  supportsRecoverySigner: true,
};

const ACCOUNT_MODEL_CAPABILITY_MATRIX: Record<string, AccountModelCapabilities> = {
  'near-native': {
    supportsMultiSigner: true,
    supportsAddRemoveSigner: true,
    supportsSessionSigner: true,
    supportsRecoverySigner: true,
  },
  'threshold-ecdsa': {
    supportsMultiSigner: true,
    supportsAddRemoveSigner: true,
    supportsSessionSigner: true,
    supportsRecoverySigner: true,
  },
  'tempo-native': {
    supportsMultiSigner: true,
    supportsAddRemoveSigner: true,
    supportsSessionSigner: true,
    supportsRecoverySigner: true,
  },
};

export type BuildAccountSignerRecordInput = {
  profileId: string;
  chainIdKey: string;
  accountAddress: string;
  signerId: string;
  signerSlot: number;
  signerType: AccountSignerType;
  signerKind: SignerKind;
  signerAuthMethod: SignerAuthMethod;
  signerSource: SignerSource;
  status: AccountSignerStatus;
  existing?: AccountSignerRecord;
  now: number;
  removedAt?: number;
  revocationReason?: string;
  metadata?: Record<string, unknown>;
};

export type AssertSignerWriteInvariantsInput = {
  next: AccountSignerRecord;
  accountModel: AccountModel;
  existingSignerId?: string;
  existingStatus?: AccountSignerStatus;
};

export type AccountSignerRepository = {
  buildAccountSignerRecord(args: BuildAccountSignerRecordInput): AccountSignerRecord;
  assertSignerWriteInvariants(store: any, args: AssertSignerWriteInvariantsInput): Promise<void>;
  putPreparedAccountSignerInTransaction(args: {
    store: any;
    next: AccountSignerRecord;
    accountModel: AccountModel;
    existingSignerId?: string;
    existingStatus?: AccountSignerStatus;
  }): Promise<AccountSignerRecord>;
  upsertAccountSignerDirect(input: UpsertAccountSignerInput): Promise<AccountSignerRecord>;
  listAccountSignersByProfile(args: {
    profileId: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]>;
  listAccountSigners(args: {
    chainIdKey: string;
    accountAddress: string;
    status?: AccountSignerStatus;
  }): Promise<AccountSignerRecord[]>;
  getAccountSigner(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }): Promise<AccountSignerRecord | null>;
  setAccountSignerStatusDirect(args: {
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
    status: AccountSignerStatus;
    removedAt?: number;
    revocationReason?: string;
  }): Promise<AccountSignerRecord | null>;
};

export function createAccountSignerRepository(args: {
  getDB: () => Promise<IDBPDatabase>;
  accountSignersStore: string;
  chainAccountsStore: string;
  createConstraintError: CreateConstraintError;
}): AccountSignerRepository {
  function getAccountModelCapabilities(accountModel: AccountModel): AccountModelCapabilities {
    const normalized = String(accountModel || '').trim();
    return ACCOUNT_MODEL_CAPABILITY_MATRIX[normalized] || DEFAULT_ACCOUNT_MODEL_CAPABILITIES;
  }

  function assertSignerTypeCapability(
    signerType: AccountSignerType,
    accountModel: AccountModel,
    details: Record<string, unknown>,
  ): void {
    const normalizedSignerType = toTrimmedString(signerType || '').toLowerCase();
    const capabilities = getAccountModelCapabilities(accountModel);
    if (normalizedSignerType === 'session' && !capabilities.supportsSessionSigner) {
      throw args.createConstraintError(
        'SESSION_SIGNER_NOT_SUPPORTED',
        `Signer type "session" is not supported for account model ${String(accountModel || '')}`,
        { ...details, signerType: normalizedSignerType, accountModel },
      );
    }
    if (normalizedSignerType === 'recovery' && !capabilities.supportsRecoverySigner) {
      throw args.createConstraintError(
        'RECOVERY_SIGNER_NOT_SUPPORTED',
        `Signer type "recovery" is not supported for account model ${String(accountModel || '')}`,
        { ...details, signerType: normalizedSignerType, accountModel },
      );
    }
  }

  function assertSignerStatusTransition(input: {
    previousStatus: AccountSignerStatus;
    nextStatus: AccountSignerStatus;
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }): void {
    const allowed = ALLOWED_SIGNER_STATUS_TRANSITIONS[input.previousStatus];
    if (allowed?.has(input.nextStatus)) return;
    throw args.createConstraintError(
      'INVALID_SIGNER_STATUS_TRANSITION',
      `Invalid signer status transition ${input.previousStatus} -> ${input.nextStatus}`,
      {
        chainIdKey: input.chainIdKey,
        accountAddress: input.accountAddress,
        signerId: input.signerId,
        previousStatus: input.previousStatus,
        nextStatus: input.nextStatus,
      },
    );
  }

  function ensureRevokedSignerHasRemovedAt(input: {
    status: AccountSignerStatus;
    removedAt?: number;
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }): number | undefined {
    if (input.status !== 'revoked') return undefined;
    if (typeof input.removedAt === 'number' && Number.isFinite(input.removedAt)) {
      return input.removedAt;
    }
    const removedAt = Date.now();
    if (!Number.isFinite(removedAt)) {
      throw args.createConstraintError(
        'REVOKED_SIGNER_REQUIRES_REMOVED_AT',
        'Revoked signer requires removedAt timestamp',
        {
          chainIdKey: input.chainIdKey,
          accountAddress: input.accountAddress,
          signerId: input.signerId,
        },
      );
    }
    return removedAt;
  }

  return {
    buildAccountSignerRecord(input: BuildAccountSignerRecordInput): AccountSignerRecord {
      const removedAt = ensureRevokedSignerHasRemovedAt({
        status: input.status,
        removedAt: input.removedAt ?? input.existing?.removedAt,
        chainIdKey: input.chainIdKey,
        accountAddress: input.accountAddress,
        signerId: input.signerId,
      });
      return {
        profileId: input.profileId,
        chainIdKey: input.chainIdKey,
        accountAddress: input.accountAddress,
        signerId: input.signerId,
        signerSlot: input.signerSlot,
        signerType: input.signerType,
        signerKind: toTrimmedString(input.signerKind) as SignerKind,
        signerAuthMethod: toTrimmedString(input.signerAuthMethod) as SignerAuthMethod,
        signerSource: toTrimmedString(input.signerSource) as SignerSource,
        status: input.status,
        addedAt: input.existing?.addedAt ?? input.now,
        updatedAt: input.now,
        ...(removedAt != null ? { removedAt } : {}),
        ...(input.revocationReason
          ? { revocationReason: toTrimmedString(input.revocationReason) }
          : input.existing?.revocationReason
            ? { revocationReason: input.existing.revocationReason }
            : {}),
        ...(input.metadata != null
          ? { metadata: input.metadata }
          : input.existing?.metadata != null
            ? { metadata: input.existing.metadata }
            : {}),
      };
    },

    async assertSignerWriteInvariants(
      store: any,
      input: AssertSignerWriteInvariantsInput,
    ): Promise<void> {
      if (input.next.status !== 'revoked') {
        if (!input.next.signerKind || !input.next.signerAuthMethod || !input.next.signerSource) {
          throw args.createConstraintError(
            'MISSING_SIGNER_KIND',
            'Active and pending account signers require signerKind, signerAuthMethod, and signerSource',
            {
              chainIdKey: input.next.chainIdKey,
              accountAddress: input.next.accountAddress,
              signerId: input.next.signerId,
              status: input.next.status,
            },
          );
        }
      }

      if (input.next.status === 'revoked' && input.next.removedAt == null) {
        throw args.createConstraintError(
          'REVOKED_SIGNER_REQUIRES_REMOVED_AT',
          `Revoked signer ${input.next.signerId} must include removedAt`,
          {
            chainIdKey: input.next.chainIdKey,
            accountAddress: input.next.accountAddress,
            signerId: input.next.signerId,
          },
        );
      }

      const accountModel = input.accountModel;
      const capabilities = getAccountModelCapabilities(accountModel);
      const accountSigners = (await store
        .index('chainIdKey_accountAddress')
        .getAll([input.next.chainIdKey, input.next.accountAddress])) as AccountSignerRecord[];
      const otherSigners = accountSigners.filter((row) => row.signerId !== input.next.signerId);
      if (!capabilities.supportsMultiSigner && otherSigners.length > 0) {
        throw args.createConstraintError(
          'MULTI_SIGNER_NOT_SUPPORTED',
          `Account model ${String(accountModel || '')} does not support additional signers`,
          {
            accountModel,
            chainIdKey: input.next.chainIdKey,
            accountAddress: input.next.accountAddress,
            signerId: input.next.signerId,
          },
        );
      }

      if (
        !capabilities.supportsAddRemoveSigner &&
        !input.existingSignerId &&
        otherSigners.length > 0
      ) {
        throw args.createConstraintError(
          'SIGNER_MUTATION_NOT_SUPPORTED',
          `Account model ${String(accountModel || '')} does not support signer mutations`,
          {
            accountModel,
            chainIdKey: input.next.chainIdKey,
            accountAddress: input.next.accountAddress,
            signerId: input.next.signerId,
          },
        );
      }

      if (input.next.status === 'active') {
        const activeRows = (await store
          .index('chainIdKey_accountAddress_status')
          .getAll([
            input.next.chainIdKey,
            input.next.accountAddress,
            'active',
          ])) as AccountSignerRecord[];
        const conflictingSlot = activeRows.find(
          (row) => row.signerId !== input.next.signerId && row.signerSlot === input.next.signerSlot,
        );
        if (conflictingSlot) {
          throw args.createConstraintError(
            'DUPLICATE_ACTIVE_SIGNER_SLOT',
            `Active signer slot ${input.next.signerSlot} is already used for ${input.next.chainIdKey}/${input.next.accountAddress}`,
            {
              chainIdKey: input.next.chainIdKey,
              accountAddress: input.next.accountAddress,
              signerId: input.next.signerId,
              signerSlot: input.next.signerSlot,
              conflictingSignerId: conflictingSlot.signerId,
            },
          );
        }
      }

      if (input.existingStatus && input.existingStatus !== input.next.status) {
        assertSignerStatusTransition({
          previousStatus: input.existingStatus,
          nextStatus: input.next.status,
          chainIdKey: input.next.chainIdKey,
          accountAddress: input.next.accountAddress,
          signerId: input.next.signerId,
        });
      }
    },

    async putPreparedAccountSignerInTransaction(input: {
      store: any;
      next: AccountSignerRecord;
      accountModel: AccountModel;
      existingSignerId?: string;
      existingStatus?: AccountSignerStatus;
    }): Promise<AccountSignerRecord> {
      await this.assertSignerWriteInvariants(input.store, {
        next: input.next,
        accountModel: input.accountModel,
        existingSignerId: input.existingSignerId,
        existingStatus: input.existingStatus,
      });
      await input.store.put(input.next);
      return input.next;
    },

    async upsertAccountSignerDirect(input: UpsertAccountSignerInput): Promise<AccountSignerRecord> {
      const profileId = toTrimmedString(input.profileId || '');
      const chainIdKey = normalizeChainIdKey(input.chainIdKey);
      const accountAddress = normalizeAccountAddress(input.accountAddress);
      const signerId = toTrimmedString(input.signerId || '');
      if (!profileId || !chainIdKey || !accountAddress || !signerId) {
        throw new Error(
          'PasskeyClientDB: profileId, chainIdKey, accountAddress, and signerId are required',
        );
      }
      if (!Number.isSafeInteger(input.signerSlot) || input.signerSlot < 1) {
        throw new Error('PasskeyClientDB: signerSlot must be an integer >= 1');
      }
      const db = await args.getDB();
      const chainAccount = (await db.get(args.chainAccountsStore, [
        profileId,
        chainIdKey,
        accountAddress,
      ])) as ChainAccountRecord | undefined;
      if (!chainAccount) {
        throw args.createConstraintError(
          'MISSING_CHAIN_ACCOUNT',
          `Cannot upsert signer without chain account row: ${profileId}/${chainIdKey}/${accountAddress}`,
          { profileId, chainIdKey, accountAddress, signerId },
        );
      }
      if (chainAccount.profileId !== profileId) {
        throw args.createConstraintError(
          'CHAIN_ACCOUNT_PROFILE_MISMATCH',
          `Chain account profile mismatch for ${chainIdKey}/${accountAddress}`,
          {
            expectedProfileId: profileId,
            chainAccountProfileId: chainAccount.profileId,
            chainIdKey,
            accountAddress,
            signerId,
          },
        );
      }
      assertSignerTypeCapability(input.signerType, chainAccount.accountModel, {
        chainIdKey,
        accountAddress,
      });

      const tx = db.transaction(args.accountSignersStore, 'readwrite');
      const store = tx.store;
      const now = Date.now();
      const existing = (await store.get([chainIdKey, accountAddress, signerId])) as
        | AccountSignerRecord
        | undefined;
      if (existing && existing.profileId !== profileId) {
        throw args.createConstraintError(
          'CHAIN_ACCOUNT_PROFILE_MISMATCH',
          `Signer row belongs to a different profile for ${chainIdKey}/${accountAddress}/${signerId}`,
          {
            expectedProfileId: profileId,
            existingProfileId: existing.profileId,
            chainIdKey,
            accountAddress,
            signerId,
          },
        );
      }
      const next = this.buildAccountSignerRecord({
        profileId,
        chainIdKey,
        accountAddress,
        signerId,
        signerSlot: input.signerSlot,
        signerType: input.signerType,
        signerKind: input.signerKind,
        signerAuthMethod: input.signerAuthMethod,
        signerSource: input.signerSource,
        status: input.status,
        existing,
        now,
        ...(input.removedAt != null ? { removedAt: input.removedAt } : {}),
        ...(input.revocationReason ? { revocationReason: input.revocationReason } : {}),
        ...(input.metadata != null ? { metadata: input.metadata } : {}),
      });
      await this.putPreparedAccountSignerInTransaction({
        store,
        next,
        accountModel: chainAccount.accountModel,
        existingSignerId: existing?.signerId,
        existingStatus: existing?.status,
      });
      await tx.done;
      return next;
    },

    async listAccountSignersByProfile(input: {
      profileId: string;
      status?: AccountSignerStatus;
    }): Promise<AccountSignerRecord[]> {
      const profileId = toTrimmedString(input.profileId || '');
      if (!profileId) return [];
      const db = await args.getDB();
      const tx = db.transaction(args.accountSignersStore, 'readonly');
      const rows = (await tx.store.index('profileId').getAll(profileId)) as AccountSignerRecord[];
      await tx.done;
      if (!input.status) return rows || [];
      return (rows || []).filter((row) => row.status === input.status);
    },

    async listAccountSigners(input: {
      chainIdKey: string;
      accountAddress: string;
      status?: AccountSignerStatus;
    }): Promise<AccountSignerRecord[]> {
      const chainIdKey = normalizeChainIdKey(input.chainIdKey);
      const accountAddress = normalizeAccountAddress(input.accountAddress);
      if (!chainIdKey || !accountAddress) return [];
      const db = await args.getDB();
      const tx = db.transaction(args.accountSignersStore, 'readonly');
      const store = tx.store;
      if (input.status) {
        const rows = await store
          .index('chainIdKey_accountAddress_status')
          .getAll([chainIdKey, accountAddress, input.status]);
        await tx.done;
        return (rows as AccountSignerRecord[]) || [];
      }
      const rows = await store
        .index('chainIdKey_accountAddress')
        .getAll([chainIdKey, accountAddress]);
      await tx.done;
      return (rows as AccountSignerRecord[]) || [];
    },

    async getAccountSigner(input: {
      chainIdKey: string;
      accountAddress: string;
      signerId: string;
    }): Promise<AccountSignerRecord | null> {
      const chainIdKey = normalizeChainIdKey(input.chainIdKey);
      const accountAddress = normalizeAccountAddress(input.accountAddress);
      const signerId = toTrimmedString(input.signerId || '');
      if (!chainIdKey || !accountAddress || !signerId) return null;
      const db = await args.getDB();
      const row = (await db.get(args.accountSignersStore, [
        chainIdKey,
        accountAddress,
        signerId,
      ])) as AccountSignerRecord | undefined;
      return row || null;
    },

    async setAccountSignerStatusDirect(input: {
      chainIdKey: string;
      accountAddress: string;
      signerId: string;
      status: AccountSignerStatus;
      removedAt?: number;
      revocationReason?: string;
    }): Promise<AccountSignerRecord | null> {
      const chainIdKey = normalizeChainIdKey(input.chainIdKey);
      const accountAddress = normalizeAccountAddress(input.accountAddress);
      const signerId = toTrimmedString(input.signerId || '');
      if (!chainIdKey || !accountAddress || !signerId) return null;
      const db = await args.getDB();
      const existing = (await db.get(args.accountSignersStore, [
        chainIdKey,
        accountAddress,
        signerId,
      ])) as AccountSignerRecord | undefined;
      if (!existing) return null;
      const chainAccount = (await db.get(args.chainAccountsStore, [
        existing.profileId,
        chainIdKey,
        accountAddress,
      ])) as ChainAccountRecord | undefined;
      if (!chainAccount) {
        throw args.createConstraintError(
          'MISSING_CHAIN_ACCOUNT',
          `Cannot update signer status without chain account row: ${existing.profileId}/${chainIdKey}/${accountAddress}`,
          {
            profileId: existing.profileId,
            chainIdKey,
            accountAddress,
            signerId,
          },
        );
      }

      const removedAt = ensureRevokedSignerHasRemovedAt({
        status: input.status,
        removedAt: input.removedAt ?? existing.removedAt,
        chainIdKey,
        accountAddress,
        signerId,
      });

      const tx = db.transaction(args.accountSignersStore, 'readwrite');
      const store = tx.store;
      const latest = (await store.get([chainIdKey, accountAddress, signerId])) as
        | AccountSignerRecord
        | undefined;
      if (!latest) {
        await tx.done;
        return null;
      }

      const updated: AccountSignerRecord = {
        ...latest,
        status: input.status,
        updatedAt: Date.now(),
        ...(removedAt != null ? { removedAt } : {}),
        ...(input.revocationReason
          ? { revocationReason: toTrimmedString(input.revocationReason) }
          : {}),
      };
      await this.putPreparedAccountSignerInTransaction({
        store,
        next: updated,
        accountModel: chainAccount.accountModel,
        existingSignerId: latest.signerId,
        existingStatus: latest.status,
      });
      await tx.done;
      return updated;
    },
  };
}
