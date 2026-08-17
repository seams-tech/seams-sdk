import { alphabetizeStringify } from '@shared/utils/digests';
import type { LinkedDeviceEnrollmentId } from '@shared/signing-lanes/ids';
import {
  buildActiveLinkedDeviceExecutionBundleFromEvidenceV1,
  parseLinkedDeviceProvisionedExecutionEvidenceV1,
  type ActiveLinkedDeviceExecutionBundleV1,
  type LinkedDeviceProvisionedExecutionEvidenceV1,
} from '../../signingEngine/session/lanes/linkedDeviceExecutionBundle';
import { SEAMS_WALLET_STORES } from '../schemaNames';
import { seamsWalletDB } from '../singletons';
import type { SeamsWalletDBManager } from './manager';
import type { LinkedDeviceWalletSessionRepositoryV1 } from './linkedDeviceWalletSessionStore';

type StoredLinkedDeviceExecutionEvidenceRowV1 = {
  readonly enrollment_id: string;
  readonly wallet_id: string;
  readonly device_id: string;
  readonly manifest_digest_b64u: string;
  readonly evidence: LinkedDeviceProvisionedExecutionEvidenceV1;
};

export type LinkedDeviceExecutionEvidenceReadResultV1 =
  | {
      readonly kind: 'found';
      readonly evidence: LinkedDeviceProvisionedExecutionEvidenceV1;
    }
  | {
      readonly kind: 'missing' | 'corrupt' | 'persistence_unavailable';
      readonly evidence?: never;
    };

export type ActiveLinkedDeviceExecutionBundleReadResultV1 =
  | {
      readonly kind: 'found';
      readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
    }
  | {
      readonly kind: 'missing' | 'expired' | 'corrupt' | 'ambiguous' | 'persistence_unavailable';
      readonly bundle?: never;
    };

const STORE = SEAMS_WALLET_STORES.linkedDeviceExecutionEvidence;
const STORED_ROW_FIELDS = [
  'enrollment_id',
  'wallet_id',
  'device_id',
  'manifest_digest_b64u',
  'evidence',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactFields(record: Record<string, unknown>, fields: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === fields.length && actual.every((field) => fields.includes(field));
}

async function parseEvidence(
  raw: unknown,
): Promise<LinkedDeviceProvisionedExecutionEvidenceV1 | null> {
  try {
    return await parseLinkedDeviceProvisionedExecutionEvidenceV1(raw);
  } catch {
    return null;
  }
}

async function parseStoredRow(
  raw: unknown,
): Promise<LinkedDeviceProvisionedExecutionEvidenceV1 | null> {
  if (!isRecord(raw) || !hasExactFields(raw, STORED_ROW_FIELDS)) return null;
  const evidence = await parseEvidence(raw.evidence);
  if (
    !evidence ||
    raw.enrollment_id !== evidence.approval.enrollmentId ||
    raw.wallet_id !== evidence.approval.walletId ||
    raw.device_id !== evidence.approval.deviceId ||
    raw.manifest_digest_b64u !== evidence.enrollmentReceipt.manifestDigestB64u
  ) {
    return null;
  }
  return evidence;
}

function toStoredRow(
  evidence: LinkedDeviceProvisionedExecutionEvidenceV1,
): StoredLinkedDeviceExecutionEvidenceRowV1 {
  return {
    enrollment_id: evidence.approval.enrollmentId,
    wallet_id: evidence.approval.walletId,
    device_id: evidence.approval.deviceId,
    manifest_digest_b64u: evidence.enrollmentReceipt.manifestDigestB64u,
    evidence,
  };
}

function evidenceEqual(
  left: LinkedDeviceProvisionedExecutionEvidenceV1,
  right: LinkedDeviceProvisionedExecutionEvidenceV1,
): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

export class LinkedDeviceExecutionEvidenceRepositoryV1 {
  constructor(private readonly manager: SeamsWalletDBManager = seamsWalletDB) {}

  async putExactProvisionedEvidenceV1(
    raw: LinkedDeviceProvisionedExecutionEvidenceV1,
  ): Promise<LinkedDeviceProvisionedExecutionEvidenceV1> {
    const evidence = await parseEvidence(raw);
    if (!evidence) throw new Error('Linked-device execution evidence is invalid');
    const db = await this.manager.getDB();
    const tx = db.transaction(STORE, 'readwrite');
    const store = tx.objectStore(STORE);
    try {
      const existingRaw = await store.get(evidence.approval.enrollmentId);
      if (existingRaw !== undefined) {
        const existing = await parseStoredRow(existingRaw);
        if (!existing) throw new Error('Stored linked-device execution evidence is corrupt');
        if (!evidenceEqual(existing, evidence)) {
          throw new Error('Linked-device execution evidence replay does not match');
        }
        await tx.done;
        return existing;
      }
      await store.put(toStoredRow(evidence));
      await tx.done;
      return evidence;
    } catch (error) {
      try {
        tx.abort();
      } catch {}
      await tx.done.catch(() => undefined);
      throw error;
    }
  }

  async readForEnrollmentV1(
    enrollmentId: LinkedDeviceEnrollmentId,
  ): Promise<LinkedDeviceExecutionEvidenceReadResultV1> {
    try {
      const db = await this.manager.getDB();
      const raw = await db.get(STORE, enrollmentId);
      if (raw === undefined) return { kind: 'missing' };
      const evidence = await parseStoredRow(raw);
      return evidence ? { kind: 'found', evidence } : { kind: 'corrupt' };
    } catch {
      return { kind: 'persistence_unavailable' };
    }
  }

  async clearEnrollmentV1(enrollmentId: LinkedDeviceEnrollmentId): Promise<void> {
    const db = await this.manager.getDB();
    await db.delete(STORE, enrollmentId);
  }
}

export const linkedDeviceExecutionEvidence = new LinkedDeviceExecutionEvidenceRepositoryV1();

export async function resolveActiveLinkedDeviceExecutionBundleV1(input: {
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly nowMs: number;
  readonly evidenceRepository: Pick<
    LinkedDeviceExecutionEvidenceRepositoryV1,
    'readForEnrollmentV1'
  >;
  readonly walletSessionRepository: Pick<
    LinkedDeviceWalletSessionRepositoryV1,
    'readActiveForEnrollmentV1'
  >;
}): Promise<ActiveLinkedDeviceExecutionBundleReadResultV1> {
  const [evidenceResult, walletSessionResult] = await Promise.all([
    input.evidenceRepository.readForEnrollmentV1(input.enrollmentId),
    input.walletSessionRepository.readActiveForEnrollmentV1({
      enrollmentId: input.enrollmentId,
      nowMs: input.nowMs,
    }),
  ]);
  if (evidenceResult.kind !== 'found') return evidenceResult;
  if (walletSessionResult.kind !== 'found') return walletSessionResult;
  try {
    return {
      kind: 'found',
      bundle: await buildActiveLinkedDeviceExecutionBundleFromEvidenceV1({
        evidence: evidenceResult.evidence,
        walletSessionDelivery: walletSessionResult.delivery,
      }),
    };
  } catch {
    return { kind: 'corrupt' };
  }
}

export async function resolveLinkedDeviceExecutionBundleV1(input: {
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly evidenceRepository: Pick<
    LinkedDeviceExecutionEvidenceRepositoryV1,
    'readForEnrollmentV1'
  >;
  readonly walletSessionRepository: Pick<
    LinkedDeviceWalletSessionRepositoryV1,
    'readForEnrollmentV1'
  >;
}): Promise<ActiveLinkedDeviceExecutionBundleReadResultV1> {
  const [evidenceResult, walletSessionResult] = await Promise.all([
    input.evidenceRepository.readForEnrollmentV1(input.enrollmentId),
    input.walletSessionRepository.readForEnrollmentV1(input.enrollmentId),
  ]);
  if (evidenceResult.kind !== 'found') return evidenceResult;
  if (walletSessionResult.kind !== 'found') return walletSessionResult;
  try {
    return {
      kind: 'found',
      bundle: await buildActiveLinkedDeviceExecutionBundleFromEvidenceV1({
        evidence: evidenceResult.evidence,
        walletSessionDelivery: walletSessionResult.delivery,
      }),
    };
  } catch {
    return { kind: 'corrupt' };
  }
}

export async function resolveUniqueActiveLinkedDeviceExecutionBundleV1(input: {
  readonly walletId?: string;
  readonly nowMs: number;
  readonly evidenceRepository: Pick<
    LinkedDeviceExecutionEvidenceRepositoryV1,
    'readForEnrollmentV1'
  >;
  readonly walletSessionRepository: Pick<
    LinkedDeviceWalletSessionRepositoryV1,
    'readUniqueActiveForWalletV1'
  >;
}): Promise<ActiveLinkedDeviceExecutionBundleReadResultV1> {
  const walletSessionResult = await input.walletSessionRepository.readUniqueActiveForWalletV1({
    ...(input.walletId ? { walletId: input.walletId } : {}),
    nowMs: input.nowMs,
  });
  if (walletSessionResult.kind !== 'found') return walletSessionResult;
  const evidenceResult = await input.evidenceRepository.readForEnrollmentV1(
    walletSessionResult.delivery.enrollmentId,
  );
  if (evidenceResult.kind !== 'found') return evidenceResult;
  try {
    return {
      kind: 'found',
      bundle: await buildActiveLinkedDeviceExecutionBundleFromEvidenceV1({
        evidence: evidenceResult.evidence,
        walletSessionDelivery: walletSessionResult.delivery,
      }),
    };
  } catch {
    return { kind: 'corrupt' };
  }
}

export async function resolveUniqueLinkedDeviceExecutionBundleV1(input: {
  readonly walletId?: string;
  readonly evidenceRepository: Pick<
    LinkedDeviceExecutionEvidenceRepositoryV1,
    'readForEnrollmentV1'
  >;
  readonly walletSessionRepository: Pick<
    LinkedDeviceWalletSessionRepositoryV1,
    'readUniqueForWalletV1'
  >;
}): Promise<ActiveLinkedDeviceExecutionBundleReadResultV1> {
  const walletSessionResult = await input.walletSessionRepository.readUniqueForWalletV1({
    ...(input.walletId ? { walletId: input.walletId } : {}),
  });
  if (walletSessionResult.kind !== 'found') return walletSessionResult;
  const evidenceResult = await input.evidenceRepository.readForEnrollmentV1(
    walletSessionResult.delivery.enrollmentId,
  );
  if (evidenceResult.kind !== 'found') return evidenceResult;
  try {
    return {
      kind: 'found',
      bundle: await buildActiveLinkedDeviceExecutionBundleFromEvidenceV1({
        evidence: evidenceResult.evidence,
        walletSessionDelivery: walletSessionResult.delivery,
      }),
    };
  } catch {
    return { kind: 'corrupt' };
  }
}
