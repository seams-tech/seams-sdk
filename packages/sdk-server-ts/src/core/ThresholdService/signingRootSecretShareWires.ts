export const SIGNING_ROOT_SECRET_SHARE_WIRE_V1_LENGTH = 34;

export type SigningRootSecretShareId = 1 | 2 | 3;

export type SigningRootSecretShareWireV1 = Uint8Array & {
  readonly __signingRootSecretShareWireV1: 'SigningRootSecretShareWireV1';
};

export const MISSING_SIGNING_ROOT_KEK_CODE = 'missing_signing_root_kek' as const;

export type SealedSigningRootSecretShare = {
  readonly signingRootId: string;
  readonly shareId: SigningRootSecretShareId;
  readonly sealedShare: Uint8Array;
  readonly signingRootVersion?: string;
  readonly storageId?: string;
  readonly kekId?: string;
};

export type SigningRootSecretShareWireErrorCode =
  | 'invalid_share_id'
  | 'invalid_share_wire'
  | 'resolver_failed'
  | typeof MISSING_SIGNING_ROOT_KEK_CODE;

export type SigningRootSecretShareWireResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: SigningRootSecretShareWireErrorCode; message: string };

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

export function signingRootSecretShareWireV1ShareId(
  input: Uint8Array,
): SigningRootSecretShareId | null {
  if (input.byteLength < 2) return null;
  return normalizeSigningRootSecretShareId((input[0] << 8) | input[1]);
}

// Server SDK persistence boundary for existing sealed-share records.
// This parser validates fixed width and share-id consistency only.
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

  const shareId = signingRootSecretShareWireV1ShareId(input);
  if (!shareId) {
    return err('invalid_share_id', 'SigningRootSecretShareWireV1 share id must be u16 1, 2, or 3');
  }

  return ok(new Uint8Array(input) as SigningRootSecretShareWireV1);
}

export function copySigningRootSecretShareWireV1(wire: SigningRootSecretShareWireV1): SigningRootSecretShareWireV1 {
  return new Uint8Array(wire) as SigningRootSecretShareWireV1;
}

export function zeroizeSigningRootSecretShareWireV1(wire: SigningRootSecretShareWireV1): void {
  zeroizeBytes(wire);
}
