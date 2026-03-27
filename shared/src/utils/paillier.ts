import { base64UrlDecode, base64UrlEncode } from './base64';

export const RECOVERY_SHARE_DOMAIN_MODULUS = 1n << 256n;
export const PAILLIER_MIN_KEY_BITS = 2048;

export type PaillierPublicKey = {
  n: bigint;
  g: bigint;
  nSquared: bigint;
  modulusBits: number;
};

export type PaillierPrivateKey = {
  lambda: bigint;
  mu: bigint;
};

export type PaillierKeyPair = {
  publicKey: PaillierPublicKey;
  privateKey: PaillierPrivateKey;
};

type RandomBytesFn = (length: number) => Uint8Array;

function requireCryptoGetRandomValues(): Crypto['getRandomValues'] {
  const getRandomValues = globalThis.crypto?.getRandomValues?.bind(globalThis.crypto);
  if (typeof getRandomValues !== 'function') {
    throw new Error('crypto.getRandomValues is required for Paillier operations');
  }
  return getRandomValues;
}

function defaultRandomBytes(length: number): Uint8Array {
  const size = Math.max(0, Math.floor(Number(length) || 0));
  const out = new Uint8Array(size);
  requireCryptoGetRandomValues()(out);
  return out;
}

function bitLength(value: bigint): number {
  if (value < 0n) throw new Error('bitLength expects a non-negative bigint');
  if (value === 0n) return 0;
  return value.toString(2).length;
}

function mod(value: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) throw new Error('modulus must be positive');
  const out = value % modulus;
  return out >= 0n ? out : out + modulus;
}

function gcd(a: bigint, b: bigint): bigint {
  let x = a < 0n ? -a : a;
  let y = b < 0n ? -b : b;
  while (y !== 0n) {
    const next = x % y;
    x = y;
    y = next;
  }
  return x;
}

function lcm(a: bigint, b: bigint): bigint {
  if (a === 0n || b === 0n) return 0n;
  return (a / gcd(a, b)) * b;
}

function extendedGcd(a: bigint, b: bigint): { gcd: bigint; x: bigint; y: bigint } {
  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  let oldT = 0n;
  let t = 1n;
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }
  return { gcd: oldR, x: oldS, y: oldT };
}

function modInv(value: bigint, modulus: bigint): bigint {
  const result = extendedGcd(mod(value, modulus), modulus);
  if (result.gcd !== 1n) {
    throw new Error('value is not invertible modulo modulus');
  }
  return mod(result.x, modulus);
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) throw new Error('modulus must be positive');
  if (exponent < 0n) throw new Error('exponent must be non-negative');
  let result = 1n;
  let factor = mod(base, modulus);
  let power = exponent;
  while (power > 0n) {
    if ((power & 1n) === 1n) {
      result = mod(result * factor, modulus);
    }
    factor = mod(factor * factor, modulus);
    power >>= 1n;
  }
  return result;
}

function randomBigInt(bits: number, randomBytes: RandomBytesFn): bigint {
  const normalizedBits = Math.max(2, Math.floor(Number(bits) || 0));
  const byteLength = Math.ceil(normalizedBits / 8);
  const bytes = randomBytes(byteLength);
  const leadingBits = normalizedBits % 8;
  if (leadingBits !== 0) {
    bytes[0] &= (1 << leadingBits) - 1;
  }
  bytes[0] |= 1 << ((leadingBits || 8) - 1);
  bytes[bytes.length - 1] |= 1;
  return bytesToBigIntBE(bytes);
}

function randomBigIntBelow(upperExclusive: bigint, randomBytes: RandomBytesFn): bigint {
  if (upperExclusive <= 1n) {
    throw new Error('upperExclusive must be > 1');
  }
  const bits = bitLength(upperExclusive - 1n);
  const byteLength = Math.max(1, Math.ceil(bits / 8));
  while (true) {
    const candidate = bytesToBigIntBE(randomBytes(byteLength));
    if (candidate < upperExclusive) return candidate;
  }
}

function randomBetween(minInclusive: bigint, maxInclusive: bigint, randomBytes: RandomBytesFn): bigint {
  if (maxInclusive < minInclusive) {
    throw new Error('maxInclusive must be >= minInclusive');
  }
  const span = maxInclusive - minInclusive + 1n;
  return minInclusive + randomBigIntBelow(span, randomBytes);
}

function isProbablePrime(candidate: bigint, rounds: number, randomBytes: RandomBytesFn): boolean {
  if (candidate === 2n || candidate === 3n) return true;
  if (candidate < 2n || (candidate & 1n) === 0n) return false;

  let d = candidate - 1n;
  let s = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    s += 1;
  }

  const checks = Math.max(8, Math.floor(Number(rounds) || 0));
  for (let i = 0; i < checks; i++) {
    const a = randomBetween(2n, candidate - 2n, randomBytes);
    let x = modPow(a, d, candidate);
    if (x === 1n || x === candidate - 1n) continue;
    let witnessComposite = true;
    for (let j = 1; j < s; j++) {
      x = modPow(x, 2n, candidate);
      if (x === candidate - 1n) {
        witnessComposite = false;
        break;
      }
    }
    if (witnessComposite) return false;
  }

  return true;
}

async function generateProbablePrime(bits: number, rounds: number, randomBytes: RandomBytesFn): Promise<bigint> {
  let attempts = 0;
  while (true) {
    attempts += 1;
    const candidate = randomBigInt(bits, randomBytes);
    if (isProbablePrime(candidate, rounds, randomBytes)) {
      return candidate;
    }
    if ((attempts & 0x7) === 0) {
      await Promise.resolve();
    }
  }
}

function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let out = 0n;
  for (const byte of bytes) {
    out = (out << 8n) | BigInt(byte);
  }
  return out;
}

function bytesToBigIntLE(bytes: Uint8Array): bigint {
  let out = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    out = (out << 8n) | BigInt(bytes[i] || 0);
  }
  return out;
}

function bigintToMinimalBytesBE(value: bigint): Uint8Array {
  if (value < 0n) throw new Error('bigint must be non-negative');
  if (value === 0n) return new Uint8Array([0]);
  const byteLength = Math.ceil(bitLength(value) / 8);
  const out = new Uint8Array(byteLength);
  let remaining = value;
  for (let i = byteLength - 1; i >= 0; i--) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

function bigintToFixedBytesLE(value: bigint, length: number): Uint8Array {
  const normalizedLength = Math.max(0, Math.floor(Number(length) || 0));
  if (value < 0n) throw new Error('bigint must be non-negative');
  const out = new Uint8Array(normalizedLength);
  let remaining = value;
  for (let i = 0; i < normalizedLength; i++) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) {
    throw new Error(`bigint does not fit in ${normalizedLength} bytes`);
  }
  return out;
}

function assertPaillierPlaintext(publicKey: PaillierPublicKey, plaintext: bigint): bigint {
  if (plaintext < 0n) {
    throw new Error('Paillier plaintext must be non-negative');
  }
  if (plaintext >= publicKey.n) {
    throw new Error('Paillier plaintext must be < n');
  }
  return plaintext;
}

function assertPaillierCiphertext(publicKey: PaillierPublicKey, ciphertext: bigint): bigint {
  if (ciphertext <= 0n || ciphertext >= publicKey.nSquared) {
    throw new Error('Paillier ciphertext must be in the range [1, n^2)');
  }
  return ciphertext;
}

function derivePaillierPublicKey(n: bigint): PaillierPublicKey {
  if (n <= RECOVERY_SHARE_DOMAIN_MODULUS) {
    throw new Error('Paillier modulus must be > 2^256');
  }
  return {
    n,
    g: n + 1n,
    nSquared: n * n,
    modulusBits: bitLength(n),
  };
}

export async function generatePaillierKeyPair(input?: {
  bits?: number;
  rounds?: number;
  randomBytes?: RandomBytesFn;
}): Promise<PaillierKeyPair> {
  const bits = Math.max(PAILLIER_MIN_KEY_BITS, Math.floor(Number(input?.bits) || PAILLIER_MIN_KEY_BITS));
  const rounds = Math.max(8, Math.floor(Number(input?.rounds) || 16));
  const randomBytes = input?.randomBytes || defaultRandomBytes;
  const primeBits = Math.floor(bits / 2);

  while (true) {
    const p = await generateProbablePrime(primeBits, rounds, randomBytes);
    const q = await generateProbablePrime(bits - primeBits, rounds, randomBytes);
    if (p === q) continue;
    const n = p * q;
    if (bitLength(n) < bits) continue;
    const publicKey = derivePaillierPublicKey(n);
    const lambda = lcm(p - 1n, q - 1n);
    const mu = modInv(lambda, n);
    return {
      publicKey,
      privateKey: { lambda, mu },
    };
  }
}

export function serializePaillierPublicKeyB64u(publicKey: PaillierPublicKey): string {
  return base64UrlEncode(bigintToMinimalBytesBE(publicKey.n));
}

export function parsePaillierPublicKeyB64u(value: string): PaillierPublicKey {
  const bytes = base64UrlDecode(String(value || '').trim());
  if (!bytes.length) {
    throw new Error('Paillier public key is required');
  }
  return derivePaillierPublicKey(bytesToBigIntBE(bytes));
}

export function serializePaillierCiphertextB64u(publicKey: PaillierPublicKey, ciphertext: bigint): string {
  return base64UrlEncode(bigintToMinimalBytesBE(assertPaillierCiphertext(publicKey, ciphertext)));
}

export function parsePaillierCiphertextB64u(publicKey: PaillierPublicKey, value: string): bigint {
  const bytes = base64UrlDecode(String(value || '').trim());
  if (!bytes.length) {
    throw new Error('Paillier ciphertext is required');
  }
  return assertPaillierCiphertext(publicKey, bytesToBigIntBE(bytes));
}

function randomUnitModN(publicKey: PaillierPublicKey, randomBytes: RandomBytesFn): bigint {
  while (true) {
    const candidate = randomBetween(1n, publicKey.n - 1n, randomBytes);
    if (gcd(candidate, publicKey.n) === 1n) {
      return candidate;
    }
  }
}

export function paillierEncrypt(
  publicKey: PaillierPublicKey,
  plaintext: bigint,
  input?: { randomBytes?: RandomBytesFn },
): bigint {
  const randomBytes = input?.randomBytes || defaultRandomBytes;
  const m = assertPaillierPlaintext(publicKey, plaintext);
  const r = randomUnitModN(publicKey, randomBytes);
  const gm = mod(1n + m * publicKey.n, publicKey.nSquared);
  const rn = modPow(r, publicKey.n, publicKey.nSquared);
  return mod(gm * rn, publicKey.nSquared);
}

export function paillierAddConst(
  publicKey: PaillierPublicKey,
  ciphertext: bigint,
  addend: bigint,
): bigint {
  const c = assertPaillierCiphertext(publicKey, ciphertext);
  const k = mod(addend, publicKey.n);
  const encoded = mod(1n + k * publicKey.n, publicKey.nSquared);
  return mod(c * encoded, publicKey.nSquared);
}

export function paillierDecrypt(keyPair: PaillierKeyPair, ciphertext: bigint): bigint {
  const c = assertPaillierCiphertext(keyPair.publicKey, ciphertext);
  const u = modPow(c, keyPair.privateKey.lambda, keyPair.publicKey.nSquared);
  const l = (u - 1n) / keyPair.publicKey.n;
  return mod(l * keyPair.privateKey.mu, keyPair.publicKey.n);
}

export function destroyPaillierPrivateKey(privateKey: PaillierPrivateKey | null | undefined): void {
  if (!privateKey) return;
  privateKey.lambda = 0n;
  privateKey.mu = 0n;
}

export function destroyPaillierKeyPair(keyPair: PaillierKeyPair | null | undefined): void {
  if (!keyPair) return;
  destroyPaillierPrivateKey(keyPair.privateKey);
}

export function decodeU256Le(bytes: Uint8Array): bigint {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) {
    throw new Error('u256 share must be exactly 32 bytes');
  }
  return bytesToBigIntLE(bytes);
}

export function encodeU256Le(value: bigint): Uint8Array {
  return bigintToFixedBytesLE(mod(value, RECOVERY_SHARE_DOMAIN_MODULUS), 32);
}
