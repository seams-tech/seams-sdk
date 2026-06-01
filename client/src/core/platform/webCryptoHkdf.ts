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
  const hkdfKey = await subtle.importKey('raw', args.ikm32, 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: args.salt,
      info: args.info,
    },
    hkdfKey,
    256,
  );
  return new Uint8Array(bits);
}
