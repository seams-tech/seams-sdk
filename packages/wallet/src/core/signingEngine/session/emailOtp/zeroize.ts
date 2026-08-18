export function zeroizeBytes(bytes: Uint8Array | null | undefined): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}
