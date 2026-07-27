import type { KeyMaterialRecord } from '@/core/indexedDB/keyMaterial.types';
import { normalizeStoredPayloadRecord } from '@/core/indexedDB/keyMaterialEnvelope';
import type { Ed25519YaoRecoverySourceLocatorV1 } from './ed25519YaoRecoverySource';
import { parseMpcMaterialOwnerRef, type MpcMaterialOwnerRef } from '@shared/utils/domainIds';
import {
  parseRouterAbEd25519YaoRecoveryActivationReceiptV1,
  parseRouterAbEd25519YaoRecoveryAdmissionRequestV1,
  type RouterAbEd25519YaoRecoveryActivationReceiptV1,
  type RouterAbEd25519YaoRecoveryAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import { secureRandomId } from '@shared/utils/secureRandomId';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';

const RECOVERY_JOURNAL_APP_STATE_PREFIX = 'near_ed25519_yao_recovery_journal_v1';

export type NearEd25519YaoRecoveryCorrelationV1 = {
  correlationId: string;
  admissionRequest: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
};

export type NearEd25519YaoRecoveryFinalizationV1 = {
  replacement: KeyMaterialRecord;
  retireSource: Ed25519YaoRecoverySourceLocatorV1;
};

export type NearEd25519YaoRecoveryCommitJournalV1 =
  | {
      kind: 'prepared';
      recoveryId: string;
      authority: WalletAuthAuthorityRef;
      materialOwner: MpcMaterialOwnerRef;
      source: Ed25519YaoRecoverySourceLocatorV1;
      correlation: NearEd25519YaoRecoveryCorrelationV1;
      disposition: 'continue' | 'cancel_requested';
    }
  | {
      kind: 'promotion_committed';
      recoveryId: string;
      authority: WalletAuthAuthorityRef;
      materialOwner: MpcMaterialOwnerRef;
      promotionReceipt: RouterAbEd25519YaoRecoveryActivationReceiptV1;
      finalization: NearEd25519YaoRecoveryFinalizationV1;
    };

export type NearEd25519YaoRecoveryJournalStorePort = {
  getAppState<T = unknown>(key: string): Promise<T | undefined>;
  compareAndSwapAppState(input: {
    key: string;
    expected: unknown | null;
    replacement: unknown;
  }): Promise<boolean>;
  finalizeKeyMaterialRecovery(input: {
    journalKey: string;
    expectedJournal: unknown;
    replacement: KeyMaterialRecord;
    retire: {
      profileId: string;
      signerSlot: number;
      chainIdKey: string;
      keyKind: string;
    };
  }): Promise<void>;
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(
  record: Record<string, unknown>,
  label: string,
  expected: readonly string[],
): void {
  const keys = Object.keys(record).sort();
  const sortedExpected = [...expected].sort();
  if (
    keys.length !== sortedExpected.length ||
    keys.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new Error(`${label} has invalid fields`);
  }
}

function requireString(value: unknown, label: string): string {
  const parsed = typeof value === 'string' ? value.trim() : '';
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

function journalKey(input: { walletId: string; signerSlot: number }): string {
  const walletId = requireString(input.walletId, 'recovery journal walletId');
  if (!Number.isSafeInteger(input.signerSlot) || input.signerSlot < 1) {
    throw new Error('recovery journal signerSlot must be a positive integer');
  }
  return `${RECOVERY_JOURNAL_APP_STATE_PREFIX}:${walletId}:${input.signerSlot}`;
}

function parseSource(raw: unknown): Ed25519YaoRecoverySourceLocatorV1 {
  const record = requireRecord(raw, 'recovery source reference');
  requireExactKeys(record, 'recovery source reference', [
    'kind',
    'profileId',
    'signerSlot',
    'chainIdKey',
    'recoveryId',
  ]);
  if (
    record.kind !== 'router_ab_ed25519_yao_recovery_source_v1' ||
    !Number.isSafeInteger(record.signerSlot) ||
    Number(record.signerSlot) < 1
  ) {
    throw new Error('recovery source reference is invalid');
  }
  return {
    kind: 'router_ab_ed25519_yao_recovery_source_v1',
    profileId: requireString(record.profileId, 'recovery source profileId'),
    signerSlot: Number(record.signerSlot),
    chainIdKey: requireString(record.chainIdKey, 'recovery source chainIdKey'),
    recoveryId: requireString(record.recoveryId, 'recovery source recoveryId'),
  };
}

function parseCorrelation(raw: unknown): NearEd25519YaoRecoveryCorrelationV1 {
  const record = requireRecord(raw, 'recovery correlation');
  requireExactKeys(record, 'recovery correlation', ['correlationId', 'admissionRequest']);
  const admissionRequest = parseRouterAbEd25519YaoRecoveryAdmissionRequestV1(
    record.admissionRequest,
  );
  if (!admissionRequest.ok) throw new Error(admissionRequest.message);
  return {
    correlationId: requireString(record.correlationId, 'recovery correlationId'),
    admissionRequest: admissionRequest.value,
  };
}

function parseAuthorityAndOwner(record: Record<string, unknown>): {
  authority: WalletAuthAuthorityRef;
  materialOwner: MpcMaterialOwnerRef;
} {
  const authority = parseWalletAuthAuthorityRef(record.authority);
  const materialOwner = parseMpcMaterialOwnerRef(record.materialOwner);
  if (!authority || !materialOwner.ok) {
    throw new Error('recovery journal authority or material owner is invalid');
  }
  return { authority, materialOwner: materialOwner.value };
}

export function parseNearEd25519YaoRecoveryCommitJournalV1(
  raw: unknown,
): NearEd25519YaoRecoveryCommitJournalV1 {
  const record = requireRecord(raw, 'Near recovery journal');
  const identity = parseAuthorityAndOwner(record);
  switch (record.kind) {
    case 'prepared': {
      requireExactKeys(record, 'prepared Near recovery journal', [
        'kind',
        'recoveryId',
        'authority',
        'materialOwner',
        'source',
        'correlation',
        'disposition',
      ]);
      if (record.disposition !== 'continue' && record.disposition !== 'cancel_requested') {
        throw new Error('prepared Near recovery disposition is invalid');
      }
      const source = parseSource(record.source);
      const correlation = parseCorrelation(record.correlation);
      const recoveryId = requireString(record.recoveryId, 'Near recoveryId');
      if (
        source.recoveryId !== recoveryId ||
        correlation.admissionRequest.scope.lifecycle_id !== recoveryId
      ) {
        throw new Error('prepared Near recovery references do not match');
      }
      return {
        kind: 'prepared',
        recoveryId,
        ...identity,
        source,
        correlation,
        disposition: record.disposition,
      };
    }
    case 'promotion_committed': {
      requireExactKeys(record, 'committed Near recovery journal', [
        'kind',
        'recoveryId',
        'authority',
        'materialOwner',
        'promotionReceipt',
        'finalization',
      ]);
      const promotionReceipt = parseRouterAbEd25519YaoRecoveryActivationReceiptV1(
        record.promotionReceipt,
      );
      if (!promotionReceipt.ok) throw new Error(promotionReceipt.message);
      const finalizationRecord = requireRecord(record.finalization, 'recovery finalization');
      requireExactKeys(finalizationRecord, 'recovery finalization', [
        'replacement',
        'retireSource',
      ]);
      const replacement = normalizeStoredPayloadRecord(
        finalizationRecord.replacement as KeyMaterialRecord,
      );
      if (!replacement) throw new Error('recovery replacement material is invalid');
      const recoveryId = requireString(record.recoveryId, 'Near recoveryId');
      const retireSource = parseSource(finalizationRecord.retireSource);
      if (
        promotionReceipt.value.binding.lifecycle.lifecycle_id !== recoveryId ||
        retireSource.recoveryId !== recoveryId
      ) {
        throw new Error('committed Near recovery receipt or source does not match');
      }
      return {
        kind: 'promotion_committed',
        recoveryId,
        ...identity,
        promotionReceipt: promotionReceipt.value,
        finalization: {
          replacement,
          retireSource,
        },
      };
    }
    default:
      throw new Error('Near recovery journal kind is invalid');
  }
}

export function buildPreparedNearEd25519YaoRecoveryJournalV1(input: {
  authority: WalletAuthAuthorityRef;
  materialOwner: MpcMaterialOwnerRef;
  source: Ed25519YaoRecoverySourceLocatorV1;
  request: RouterAbEd25519YaoRecoveryAdmissionRequestV1;
}): Extract<NearEd25519YaoRecoveryCommitJournalV1, { kind: 'prepared' }> {
  if (input.source.recoveryId !== input.request.scope.lifecycle_id) {
    throw new Error('Near recovery source does not match its admission request');
  }
  return {
    kind: 'prepared',
    recoveryId: input.source.recoveryId,
    authority: input.authority,
    materialOwner: input.materialOwner,
    source: input.source,
    correlation: {
      correlationId: secureRandomId(
        'near-ed25519-yao-recovery-correlation',
        32,
        'Near recovery correlations',
      ),
      admissionRequest: input.request,
    },
    disposition: 'continue',
  };
}

export async function readNearEd25519YaoRecoveryJournalV1(input: {
  store: NearEd25519YaoRecoveryJournalStorePort;
  walletId: string;
  signerSlot: number;
}): Promise<NearEd25519YaoRecoveryCommitJournalV1 | null> {
  const raw = await input.store.getAppState<unknown>(journalKey(input));
  return raw === undefined ? null : parseNearEd25519YaoRecoveryCommitJournalV1(raw);
}

export async function persistPreparedNearEd25519YaoRecoveryJournalV1(input: {
  store: NearEd25519YaoRecoveryJournalStorePort;
  walletId: string;
  signerSlot: number;
  journal: Extract<NearEd25519YaoRecoveryCommitJournalV1, { kind: 'prepared' }>;
}): Promise<void> {
  const stored = await input.store.compareAndSwapAppState({
    key: journalKey(input),
    expected: null,
    replacement: input.journal,
  });
  if (!stored) throw new Error('A Near recovery journal already exists for this signer');
}

export async function requestCancelNearEd25519YaoRecoveryV1(input: {
  store: NearEd25519YaoRecoveryJournalStorePort;
  walletId: string;
  signerSlot: number;
}): Promise<boolean> {
  const current = await readNearEd25519YaoRecoveryJournalV1(input);
  if (!current || current.kind !== 'prepared') return false;
  if (current.disposition === 'cancel_requested') return true;
  return input.store.compareAndSwapAppState({
    key: journalKey(input),
    expected: current,
    replacement: { ...current, disposition: 'cancel_requested' },
  });
}

export async function persistPromotionCommittedNearEd25519YaoRecoveryV1(input: {
  store: NearEd25519YaoRecoveryJournalStorePort;
  walletId: string;
  signerSlot: number;
  prepared: Extract<NearEd25519YaoRecoveryCommitJournalV1, { kind: 'prepared' }>;
  promotionReceipt: RouterAbEd25519YaoRecoveryActivationReceiptV1;
  replacement: KeyMaterialRecord;
}): Promise<Extract<NearEd25519YaoRecoveryCommitJournalV1, { kind: 'promotion_committed' }>> {
  if (
    input.promotionReceipt.binding.lifecycle.lifecycle_id !== input.prepared.recoveryId ||
    input.prepared.source.recoveryId !== input.prepared.recoveryId
  ) {
    throw new Error('Near recovery promotion receipt or source does not match the journal');
  }
  const committed: Extract<NearEd25519YaoRecoveryCommitJournalV1, { kind: 'promotion_committed' }> =
    {
      kind: 'promotion_committed',
      recoveryId: input.prepared.recoveryId,
      authority: input.prepared.authority,
      materialOwner: input.prepared.materialOwner,
      promotionReceipt: input.promotionReceipt,
      finalization: {
        replacement: input.replacement,
        retireSource: input.prepared.source,
      },
    };
  const stored = await input.store.compareAndSwapAppState({
    key: journalKey(input),
    expected: input.prepared,
    replacement: committed,
  });
  if (!stored) throw new Error('Near recovery journal changed before promotion commit');
  return committed;
}

export async function finalizePromotionCommittedNearEd25519YaoRecoveryV1(input: {
  store: NearEd25519YaoRecoveryJournalStorePort;
  walletId: string;
  signerSlot: number;
  journal: Extract<NearEd25519YaoRecoveryCommitJournalV1, { kind: 'promotion_committed' }>;
}): Promise<void> {
  const source = input.journal.finalization.retireSource;
  await input.store.finalizeKeyMaterialRecovery({
    journalKey: journalKey(input),
    expectedJournal: input.journal,
    replacement: input.journal.finalization.replacement,
    retire: {
      profileId: source.profileId,
      signerSlot: source.signerSlot,
      chainIdKey: source.chainIdKey,
      keyKind: source.kind,
    },
  });
}

export async function finalizeCancelledPromotedNearEd25519YaoRecoveryV1(input: {
  store: NearEd25519YaoRecoveryJournalStorePort;
  walletId: string;
  signerSlot: number;
  journal: Extract<NearEd25519YaoRecoveryCommitJournalV1, { kind: 'prepared' }>;
  promotionReceipt: RouterAbEd25519YaoRecoveryActivationReceiptV1;
  replacement: KeyMaterialRecord;
}): Promise<void> {
  if (
    input.journal.disposition !== 'cancel_requested' ||
    input.promotionReceipt.binding.lifecycle.lifecycle_id !== input.journal.recoveryId ||
    input.journal.source.recoveryId !== input.journal.recoveryId
  ) {
    throw new Error('Cancelled Near recovery promotion does not match the journal');
  }
  const source = input.journal.source;
  await input.store.finalizeKeyMaterialRecovery({
    journalKey: journalKey(input),
    expectedJournal: input.journal,
    replacement: input.replacement,
    retire: {
      profileId: source.profileId,
      signerSlot: source.signerSlot,
      chainIdKey: source.chainIdKey,
      keyKind: source.kind,
    },
  });
}
