import { base64UrlEncode } from '@shared/utils/encoders';

export function randomBase64Url(bytes: number): string {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return base64UrlEncode(data);
}

export function randomOpaqueId(byteLength = 16): string {
  return randomBase64Url(byteLength);
}

export function randomNumericCode(length: number): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let code = '';
  for (const byte of bytes) code += String(byte % 10);
  return code;
}
