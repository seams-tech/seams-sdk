export function normalizePolicyScopeType(input: string): string {
  return String(input || '')
    .trim()
    .toUpperCase();
}

export function policyScopeKey(scopeType: string, scopeId: string): string {
  return `${normalizePolicyScopeType(scopeType)}:${String(scopeId || '').trim()}`;
}
