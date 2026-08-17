export const base64Encode = (value: ArrayBufferLike | ArrayBufferView): string => {
  const bytes = ArrayBuffer.isView(value)
    ? new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
    : new Uint8Array(value);
  let binary = '';
  // Built incrementally: spreading large arrays into String.fromCharCode overflows the stack.
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
};

export function base64Decode(base64: string): Uint8Array {
  const normalized = String(base64 || '').trim();
  if (!normalized) return new Uint8Array();

  if (typeof atob === 'function') {
    const binaryString = atob(normalized);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
  }

  if (typeof Buffer !== 'undefined') {
    return Uint8Array.from(Buffer.from(normalized, 'base64'));
  }

  throw new Error('base64Decode is unavailable in this runtime');
}

export const base64UrlEncode = (value: ArrayBufferLike | ArrayBufferView): string => {
  return base64Encode(value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

export function base64UrlDecode(base64Url: string): Uint8Array {
  const normalized = String(base64Url || '')
    .trim()
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  if (!normalized) return new Uint8Array();
  const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
  return base64Decode(normalized + padding);
}
