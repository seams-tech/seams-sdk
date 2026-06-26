import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  normalizeSigningRootSecretShareId,
  type SealedSigningRootSecretShare,
  type SigningRootSecretShareId,
} from '../signingRootSecretShareWires';

const DEFAULT_SIGNING_ROOT_VERSION_KEY = '';

export type ResolveSigningRootSecretSharesInput = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
};

export type SigningRootSecretShareSource = {
  readonly listSealedSigningRootSecretShares: (
    input: ResolveSigningRootSecretSharesInput,
  ) => Promise<readonly SealedSigningRootSecretShare[]>;
  readonly adapterKind?: string;
};

export type PutSigningRootSecretShareInput = {
  readonly signingRootId: string;
  readonly shareId: SigningRootSecretShareId;
  readonly sealedShare: Uint8Array;
  readonly signingRootVersion?: string;
  readonly storageId?: string;
  readonly kekId?: string;
};

export type DeleteSigningRootSecretSharesInput = {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
};

export interface SigningRootSecretStore extends SigningRootSecretShareSource {
  listSealedSigningRootSecretShares(
    input: ResolveSigningRootSecretSharesInput,
  ): Promise<readonly SealedSigningRootSecretShare[]>;
  putSealedSigningRootSecretShare(input: PutSigningRootSecretShareInput): Promise<void>;
  deleteSigningRootSecretShares(input: DeleteSigningRootSecretSharesInput): Promise<void>;
}

export function requireSigningRootId(signingRootId: unknown): string {
  const normalized = toOptionalTrimmedString(signingRootId);
  if (!normalized) throw new Error('signingRootId is required');
  return normalized;
}

export function normalizeSigningRootVersionKey(signingRootVersion: unknown): string {
  return toOptionalTrimmedString(signingRootVersion) || DEFAULT_SIGNING_ROOT_VERSION_KEY;
}

export function signingRootVersionFromKey(signingRootVersionKey: string): string | undefined {
  return signingRootVersionKey || undefined;
}

function copySealedShare(sealedShare: unknown): Uint8Array {
  if (!(sealedShare instanceof Uint8Array)) {
    throw new Error('sealedShare must be a Uint8Array');
  }
  if (sealedShare.length === 0) {
    throw new Error('sealedShare must be non-empty');
  }
  return new Uint8Array(sealedShare);
}

export function normalizePutInput(input: PutSigningRootSecretShareInput): {
  readonly signingRootId: string;
  readonly shareId: SigningRootSecretShareId;
  readonly sealedShare: Uint8Array;
  readonly signingRootVersionKey: string;
  readonly signingRootVersion?: string;
  readonly storageId?: string;
  readonly kekId?: string;
} {
  const signingRootId = requireSigningRootId(input.signingRootId);
  const shareId = normalizeSigningRootSecretShareId(input.shareId);
  if (!shareId) throw new Error('shareId must be 1, 2, or 3');
  const signingRootVersionKey = normalizeSigningRootVersionKey(input.signingRootVersion);
  return {
    signingRootId,
    shareId,
    sealedShare: copySealedShare(input.sealedShare),
    signingRootVersionKey,
    signingRootVersion: signingRootVersionFromKey(signingRootVersionKey),
    ...(toOptionalTrimmedString(input.storageId)
      ? { storageId: toOptionalTrimmedString(input.storageId) }
      : {}),
    ...(toOptionalTrimmedString(input.kekId)
      ? { kekId: toOptionalTrimmedString(input.kekId) }
      : {}),
  };
}

export function storedRecordKey(input: {
  readonly signingRootId: string;
  readonly signingRootVersionKey: string;
  readonly shareId: SigningRootSecretShareId;
}): string {
  return `${input.signingRootId}\0${input.signingRootVersionKey}\0${input.shareId}`;
}

export function cloneRecord(record: SealedSigningRootSecretShare): SealedSigningRootSecretShare {
  return {
    signingRootId: record.signingRootId,
    shareId: record.shareId,
    sealedShare: new Uint8Array(record.sealedShare),
    ...(record.signingRootVersion ? { signingRootVersion: record.signingRootVersion } : {}),
    ...(record.storageId ? { storageId: record.storageId } : {}),
    ...(record.kekId ? { kekId: record.kekId } : {}),
  };
}
