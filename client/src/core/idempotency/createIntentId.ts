export function createIntentId(prefix: string): string {
  const normalizedPrefix = String(prefix || '').trim() || 'intent';
  if (typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.randomUUID === 'function') {
    return `${normalizedPrefix}:${globalThis.crypto.randomUUID()}`;
  }
  return `${normalizedPrefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}
