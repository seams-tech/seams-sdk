export function walletSigningBudgetSessionId(signingGrantId: string): string {
  const id = String(signingGrantId || '').trim();
  return id ? `wallet-signing:${id}` : '';
}
