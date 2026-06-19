export function walletSigningBudgetSessionId(walletSigningSessionId: string): string {
  const id = String(walletSigningSessionId || '').trim();
  return id ? `wallet-signing:${id}` : '';
}
