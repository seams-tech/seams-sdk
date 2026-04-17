export const SIGNING_ROOT_SECRET_SHARE_WIRE_V1_LENGTH = 33;

export type SigningRootSecretShareId = 1 | 2 | 3;

export type SigningRootSecretShareWireV1 = Uint8Array & {
  readonly __signingRootSecretShareWireV1: 'SigningRootSecretShareWireV1';
};

export type SigningRootSecretShare = SigningRootSecretShareWireV1;

export type SigningRootSecretShareWirePair = readonly [SigningRootSecretShareWireV1, SigningRootSecretShareWireV1];

export type SealedSigningRootSecretShare = {
  readonly signingRootId: string;
  readonly shareId: SigningRootSecretShareId;
  readonly sealedShare: Uint8Array;
  readonly signingRootVersion?: string;
  readonly storageId?: string;
  readonly kekId?: string;
};

export type SigningRootSecretShareDecryptor = (
  record: SealedSigningRootSecretShare,
) => Promise<Uint8Array>;

export type SigningRootSecretShareWireErrorCode =
  | 'duplicate_share'
  | 'decrypt_failed'
  | 'derive_failed'
  | 'invalid_signing_root_id'
  | 'invalid_share_id'
  | 'invalid_share_record'
  | 'invalid_share_wire'
  | 'missing_share'
  | 'resolver_failed';

export type SigningRootSecretShareWireResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: SigningRootSecretShareWireErrorCode; message: string };

export type ResolveSigningRootSecretShareWirePairInput = {
  readonly signingRootId: string;
  readonly records: readonly SealedSigningRootSecretShare[];
  readonly decryptShare: SigningRootSecretShareDecryptor;
  readonly preferredShareIds?: readonly SigningRootSecretShareId[];
};

type SigningRootSecretShareRecordPair = readonly [
  SealedSigningRootSecretShare,
  SealedSigningRootSecretShare,
];

function ok<T>(value: T): SigningRootSecretShareWireResult<T> {
  return { ok: true, value };
}

function err<T>(
  code: SigningRootSecretShareWireErrorCode,
  message: string,
): SigningRootSecretShareWireResult<T> {
  return { ok: false, code, message };
}

function isUint8Array(input: unknown): input is Uint8Array {
  return input instanceof Uint8Array;
}

export function zeroizeBytes(bytes: Uint8Array): void {
  bytes.fill(0);
}

export function normalizeSigningRootSecretShareId(input: unknown): SigningRootSecretShareId | null {
  if (!Number.isInteger(input)) return null;
  if (input !== 1 && input !== 2 && input !== 3) return null;
  return input;
}

export function signingRootSecretShareIdFromWire(wire: SigningRootSecretShareWireV1): SigningRootSecretShareId {
  return wire[0] as SigningRootSecretShareId;
}

// This host boundary validates transport shape and share-id consistency only.
// Canonical scalar validation remains in the Rust/WASM SigningRootSecretShareWireV1 parser.
export function parseSigningRootSecretShareWireV1(
  input: unknown,
): SigningRootSecretShareWireResult<SigningRootSecretShareWireV1> {
  if (!isUint8Array(input)) {
    return err('invalid_share_wire', 'SigningRootSecretShareWireV1 must be a Uint8Array');
  }
  if (input.length !== SIGNING_ROOT_SECRET_SHARE_WIRE_V1_LENGTH) {
    return err(
      'invalid_share_wire',
      `SigningRootSecretShareWireV1 must be ${SIGNING_ROOT_SECRET_SHARE_WIRE_V1_LENGTH} bytes`,
    );
  }

  const shareId = normalizeSigningRootSecretShareId(input[0]);
  if (!shareId) {
    return err('invalid_share_id', 'SigningRootSecretShareWireV1 share id must be 1, 2, or 3');
  }

  return ok(new Uint8Array(input) as SigningRootSecretShareWireV1);
}

export function copySigningRootSecretShareWireV1(wire: SigningRootSecretShareWireV1): SigningRootSecretShareWireV1 {
  return new Uint8Array(wire) as SigningRootSecretShareWireV1;
}

export function zeroizeSigningRootSecretShareWireV1(wire: SigningRootSecretShareWireV1): void {
  zeroizeBytes(wire);
}

function normalizePreferredShareIds(
  preferredShareIds: readonly SigningRootSecretShareId[] | undefined,
): SigningRootSecretShareWireResult<readonly [SigningRootSecretShareId, SigningRootSecretShareId] | null> {
  if (preferredShareIds === undefined) return ok(null);
  if (preferredShareIds.length !== 2) {
    return err('missing_share', 'preferredShareIds must contain exactly two share ids');
  }

  const first = normalizeSigningRootSecretShareId(preferredShareIds[0]);
  const second = normalizeSigningRootSecretShareId(preferredShareIds[1]);
  if (!first || !second) {
    return err('invalid_share_id', 'preferredShareIds must contain only share ids 1, 2, or 3');
  }
  if (first === second) {
    return err('duplicate_share', 'preferredShareIds must identify two distinct shares');
  }

  return ok([first, second] as const);
}

function selectSigningRootSecretShareRecords(
  input: ResolveSigningRootSecretShareWirePairInput,
): SigningRootSecretShareWireResult<SigningRootSecretShareRecordPair> {
  if (typeof input.signingRootId !== 'string' || input.signingRootId.trim() === '') {
    return err('invalid_signing_root_id', 'signingRootId is required');
  }

  const preferred = normalizePreferredShareIds(input.preferredShareIds);
  if (!preferred.ok) return preferred;

  const byShareId = new Map<SigningRootSecretShareId, SealedSigningRootSecretShare>();
  for (const record of input.records) {
    if (!record || typeof record !== 'object') {
      return err('invalid_share_record', 'sealed signing-root share record is required');
    }
    if (record.signingRootId !== input.signingRootId) {
      return err('invalid_signing_root_id', 'sealed signing-root share record signingRootId mismatch');
    }
    const shareId = normalizeSigningRootSecretShareId(record.shareId);
    if (!shareId) {
      return err('invalid_share_id', 'sealed signing-root share record has invalid shareId');
    }
    if (!isUint8Array(record.sealedShare)) {
      return err('invalid_share_record', 'sealed signing-root share bytes must be a Uint8Array');
    }
    if (byShareId.has(shareId)) {
      return err(
        'duplicate_share',
        'sealed signing-root share records contain a duplicate shareId',
      );
    }
    byShareId.set(shareId, record);
  }

  const selectedShareIds =
    preferred.value ??
    ([...byShareId.keys()].sort((a, b) => a - b).slice(0, 2) as SigningRootSecretShareId[]);
  if (selectedShareIds.length !== 2) {
    return err('missing_share', 'at least two signing-root shares are required');
  }

  const first = byShareId.get(selectedShareIds[0]);
  const second = byShareId.get(selectedShareIds[1]);
  if (!first || !second) {
    return err('missing_share', 'requested signing-root shares are not available');
  }

  return ok([first, second] as const);
}

async function decryptSigningRootSecretShareWire(
  record: SealedSigningRootSecretShare,
  decryptShare: SigningRootSecretShareDecryptor,
): Promise<SigningRootSecretShareWireResult<SigningRootSecretShareWireV1>> {
  let decrypted: Uint8Array | null = null;
  try {
    decrypted = await decryptShare(record);
    const parsed = parseSigningRootSecretShareWireV1(decrypted);
    if (!parsed.ok) return parsed;
    if (signingRootSecretShareIdFromWire(parsed.value) !== record.shareId) {
      return err('invalid_share_id', 'decrypted signing-root share id does not match its record');
    }
    return parsed;
  } catch {
    return err('decrypt_failed', 'sealed signing-root share decrypt failed');
  } finally {
    if (decrypted) zeroizeBytes(decrypted);
  }
}

export async function resolveSigningRootSecretShareWirePair(
  input: ResolveSigningRootSecretShareWirePairInput,
): Promise<SigningRootSecretShareWireResult<SigningRootSecretShareWirePair>> {
  const selected = selectSigningRootSecretShareRecords(input);
  if (!selected.ok) return selected;

  const first = await decryptSigningRootSecretShareWire(selected.value[0], input.decryptShare);
  if (!first.ok) return first;

  const second = await decryptSigningRootSecretShareWire(selected.value[1], input.decryptShare);
  if (!second.ok) {
    zeroizeSigningRootSecretShareWireV1(first.value);
    return second;
  }

  // The returned wires contain root-share plaintext. Callers must zeroize them
  // after the threshold-prf/WASM derivation step has copied what it needs.
  return ok([first.value, second.value] as const);
}
