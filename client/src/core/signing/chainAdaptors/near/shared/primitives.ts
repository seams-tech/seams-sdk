export const DUMMY_WRAP_KEY_SALT_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

export function generateSessionId(): string {
  return `sess-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}
