import { base64UrlDecode } from '@shared/utils/base64';
import { normalizeInteger, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';

export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_RECORD_VERSION = 1 as const;
export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_DB_NAME =
  'seams_email_otp_device_enrollment_escrows_v1' as const;
export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_DB_VERSION = 1 as const;
export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME =
  'email_otp_device_enrollment_escrows_v1' as const;
export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORAGE_SCOPE = 'iframe_origin_indexeddb' as const;
export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_ALG = 'shamir3pass-v1' as const;
export const EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_SECRET_KIND =
  'email_otp_device_enrollment_escrow_enc_s' as const;

export type EmailOtpDeviceEnrollmentEscrowRecord = {
  v: typeof EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_RECORD_VERSION;
  alg: typeof EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_ALG;
  storageScope: typeof EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORAGE_SCOPE;
  secretKind: typeof EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_SECRET_KIND;
  walletId: string;
  userId?: string;
  authSubjectId: string;
  authMethod: 'google_sso_email_otp';
  enrollmentId: string;
  enrollmentVersion: string;
  enrollmentSealKeyVersion: string;
  signingRootId: string;
  signingRootVersion: string;
  shamirPrimeB64u?: string;
  encSB64u: string;
  issuedAtMs: number;
  updatedAtMs: number;
};

const PLAINTEXT_OR_WRONG_STORE_FIELDS = [
  'S',
  'secretS',
  'plaintextS',
  'emailOtpSecretS',
  'clientSecret',
  'clientSecret32',
  'clientSecretB64u',
  'clientSecret32B64u',
  'signingSessionSecretB64u',
  'sealedSecretB64u',
  'thresholdSessionAuthToken',
  'recoveryKey',
  'recoveryKeys',
  'recoveryKek',
  'K_recovery_i',
] as const;

function getIndexedDbSafe(): IDBFactory | null {
  return (globalThis as { indexedDB?: IDBFactory }).indexedDB || null;
}

function requestToPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('IndexedDB request failed'));
  });
}

function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
    tx.onerror = () => reject(tx.error || new Error('IndexedDB transaction failed'));
  });
}

function createStoreIndexes(store: IDBObjectStore): void {
  const indexes: Array<[string, string | string[]]> = [
    ['walletId', 'walletId'],
    ['authSubjectId', 'authSubjectId'],
    ['enrollmentId', 'enrollmentId'],
    ['wallet_authSubject', ['walletId', 'authSubjectId']],
    ['wallet_authSubject_enrollment', ['walletId', 'authSubjectId', 'enrollmentId']],
    ['signingRootId', 'signingRootId'],
  ];
  for (const [name, keyPath] of indexes) {
    try {
      store.createIndex(name, keyPath, { unique: name === 'wallet_authSubject_enrollment' });
    } catch {}
  }
}

function ensureEmailOtpDeviceEnrollmentEscrowStore(db: IDBDatabase): void {
  const store = !db.objectStoreNames.contains(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME)
    ? db.createObjectStore(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME, {
        keyPath: ['walletId', 'authSubjectId', 'enrollmentId'],
      })
    : null;
  if (store) createStoreIndexes(store);
}

function openEmailOtpDeviceEnrollmentEscrowDb(): Promise<IDBDatabase | null> {
  const indexedDBFactory = getIndexedDbSafe();
  if (!indexedDBFactory) return Promise.resolve(null);
  return new Promise((resolve) => {
    let request: IDBOpenDBRequest;
    try {
      request = indexedDBFactory.open(
        EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_DB_NAME,
        EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_DB_VERSION,
      );
    } catch {
      resolve(null);
      return;
    }
    request.onupgradeneeded = () => {
      ensureEmailOtpDeviceEnrollmentEscrowStore(request.result);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => resolve(null);
    request.onblocked = () => resolve(null);
  });
}

function isValidBase64UrlBytes(value: string): boolean {
  try {
    return base64UrlDecode(value).byteLength > 0;
  } catch {
    return false;
  }
}

export function normalizeEmailOtpDeviceEnrollmentEscrowRecord(
  value: unknown,
): EmailOtpDeviceEnrollmentEscrowRecord | null {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return null;
  for (const field of PLAINTEXT_OR_WRONG_STORE_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(obj, field)) return null;
  }
  if (Number(obj.v) !== EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_RECORD_VERSION) return null;
  if (String(obj.alg || '').trim() !== EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_ALG) return null;
  if (String(obj.storageScope || '').trim() !== EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORAGE_SCOPE) {
    return null;
  }
  if (String(obj.secretKind || '').trim() !== EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_SECRET_KIND) {
    return null;
  }
  if (String(obj.authMethod || '').trim() !== 'google_sso_email_otp') return null;

  const walletId = normalizeOptionalNonEmptyString(obj.walletId);
  const userId = normalizeOptionalNonEmptyString(obj.userId);
  const authSubjectId = normalizeOptionalNonEmptyString(obj.authSubjectId);
  const enrollmentId = normalizeOptionalNonEmptyString(obj.enrollmentId);
  const enrollmentVersion = normalizeOptionalNonEmptyString(obj.enrollmentVersion);
  const enrollmentSealKeyVersion = normalizeOptionalNonEmptyString(obj.enrollmentSealKeyVersion);
  const signingRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const signingRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(obj.shamirPrimeB64u);
  const encSB64u = normalizeOptionalNonEmptyString(obj.encSB64u);
  const issuedAtMs = normalizeInteger(obj.issuedAtMs);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs);

  if (
    !walletId ||
    !authSubjectId ||
    !enrollmentId ||
    !enrollmentVersion ||
    !enrollmentSealKeyVersion ||
    !signingRootId ||
    !signingRootVersion ||
    !encSB64u
  ) {
    return null;
  }
  if (!isValidBase64UrlBytes(encSB64u)) return null;
  if (shamirPrimeB64u && !isValidBase64UrlBytes(shamirPrimeB64u)) return null;
  if (issuedAtMs == null || issuedAtMs <= 0) return null;
  if (updatedAtMs == null || updatedAtMs <= 0) return null;

  return {
    v: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_RECORD_VERSION,
    alg: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_ALG,
    storageScope: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORAGE_SCOPE,
    secretKind: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_SECRET_KIND,
    walletId,
    ...(userId ? { userId } : {}),
    authSubjectId,
    authMethod: 'google_sso_email_otp',
    enrollmentId,
    enrollmentVersion,
    enrollmentSealKeyVersion,
    signingRootId,
    signingRootVersion,
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
    encSB64u,
    issuedAtMs,
    updatedAtMs,
  };
}

export async function readEmailOtpDeviceEnrollmentEscrowRecord(args: {
  walletId: string;
  authSubjectId: string;
  enrollmentId: string;
}): Promise<EmailOtpDeviceEnrollmentEscrowRecord | null> {
  const walletId = normalizeOptionalNonEmptyString(args.walletId);
  const authSubjectId = normalizeOptionalNonEmptyString(args.authSubjectId);
  const enrollmentId = normalizeOptionalNonEmptyString(args.enrollmentId);
  if (!walletId || !authSubjectId || !enrollmentId) return null;
  const db = await openEmailOtpDeviceEnrollmentEscrowDb();
  if (!db) return null;
  try {
    const tx = db.transaction(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME, 'readonly');
    const value = await requestToPromise(
      tx
        .objectStore(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME)
        .get([walletId, authSubjectId, enrollmentId]),
    );
    return normalizeEmailOtpDeviceEnrollmentEscrowRecord(value);
  } finally {
    db.close();
  }
}

export async function readSingleEmailOtpDeviceEnrollmentEscrowRecordForWallet(args: {
  walletId: string;
}): Promise<EmailOtpDeviceEnrollmentEscrowRecord | null> {
  const walletId = normalizeOptionalNonEmptyString(args.walletId);
  if (!walletId) return null;
  const db = await openEmailOtpDeviceEnrollmentEscrowDb();
  if (!db) return null;
  try {
    const tx = db.transaction(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME, 'readonly');
    const index = tx.objectStore(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME).index('walletId');
    const values = await requestToPromise(index.getAll(walletId));
    const records = values
      .map((value) => normalizeEmailOtpDeviceEnrollmentEscrowRecord(value))
      .filter((record): record is EmailOtpDeviceEnrollmentEscrowRecord => !!record);
    return records.length === 1 ? records[0] : null;
  } finally {
    db.close();
  }
}

export async function writeEmailOtpDeviceEnrollmentEscrowRecord(
  args: Omit<
    EmailOtpDeviceEnrollmentEscrowRecord,
    'v' | 'alg' | 'storageScope' | 'secretKind' | 'authMethod' | 'issuedAtMs' | 'updatedAtMs'
  > & {
    issuedAtMs?: number;
    updatedAtMs?: number;
  },
): Promise<void> {
  const nowMs = Date.now();
  const record = normalizeEmailOtpDeviceEnrollmentEscrowRecord({
    v: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_RECORD_VERSION,
    alg: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_ALG,
    storageScope: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORAGE_SCOPE,
    secretKind: EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_SECRET_KIND,
    walletId: args.walletId,
    userId: args.userId,
    authSubjectId: args.authSubjectId,
    authMethod: 'google_sso_email_otp',
    enrollmentId: args.enrollmentId,
    enrollmentVersion: args.enrollmentVersion,
    enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
    signingRootId: args.signingRootId,
    signingRootVersion: args.signingRootVersion,
    shamirPrimeB64u: args.shamirPrimeB64u,
    encSB64u: args.encSB64u,
    issuedAtMs: args.issuedAtMs ?? nowMs,
    updatedAtMs: args.updatedAtMs ?? nowMs,
  });
  if (!record) {
    throw new Error('Invalid Email OTP device enrollment escrow record');
  }

  const db = await openEmailOtpDeviceEnrollmentEscrowDb();
  if (!db) {
    throw new Error('Email OTP device enrollment escrow IndexedDB is unavailable');
  }
  try {
    const tx = db.transaction(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME, 'readwrite');
    const done = transactionDone(tx);
    await requestToPromise(
      tx.objectStore(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME).put(record),
    );
    await done;
  } finally {
    db.close();
  }
}

export async function deleteEmailOtpDeviceEnrollmentEscrowRecord(args: {
  walletId: string;
  authSubjectId: string;
  enrollmentId: string;
}): Promise<void> {
  const walletId = normalizeOptionalNonEmptyString(args.walletId);
  const authSubjectId = normalizeOptionalNonEmptyString(args.authSubjectId);
  const enrollmentId = normalizeOptionalNonEmptyString(args.enrollmentId);
  if (!walletId || !authSubjectId || !enrollmentId) return;
  const db = await openEmailOtpDeviceEnrollmentEscrowDb();
  if (!db) return;
  try {
    const tx = db.transaction(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME, 'readwrite');
    tx.objectStore(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME).delete([
      walletId,
      authSubjectId,
      enrollmentId,
    ]);
    await transactionDone(tx).catch(() => undefined);
  } finally {
    db.close();
  }
}

export async function clearAllEmailOtpDeviceEnrollmentEscrowRecords(): Promise<void> {
  const db = await openEmailOtpDeviceEnrollmentEscrowDb();
  if (!db) return;
  try {
    const tx = db.transaction(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME, 'readwrite');
    tx.objectStore(EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME).clear();
    await transactionDone(tx).catch(() => undefined);
  } finally {
    db.close();
  }
}
