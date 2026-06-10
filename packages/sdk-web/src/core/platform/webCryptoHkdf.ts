export async function deriveWebCryptoHkdfSha256Bits256(args: {
  ikm32: Uint8Array;
  salt: Uint8Array;
  info: Uint8Array;
  unavailableMessage: string;
}): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) {
    throw new Error(args.unavailableMessage);
  }
  const hkdfKey = await subtle.importKey('raw', toArrayBufferCopy(args.ikm32), 'HKDF', false, [
    'deriveBits',
  ]);
  const bits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: toArrayBufferCopy(args.salt),
      info: toArrayBufferCopy(args.info),
    },
    hkdfKey,
    256,
  );
  return new Uint8Array(bits);
}

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}
