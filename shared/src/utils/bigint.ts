export function bytesToNumberBE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

export function numberToBytesBE(n: number | bigint, len: number): Uint8Array {
  if (!Number.isInteger(len) || len < 0) {
    throw new Error('len must be a non-negative integer');
  }
  let value = typeof n === 'bigint' ? n : BigInt(n);
  if (value < 0n) {
    throw new Error('n must be non-negative');
  }
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  if (value !== 0n) {
    throw new Error(`number does not fit in ${len} bytes`);
  }
  return out;
}
