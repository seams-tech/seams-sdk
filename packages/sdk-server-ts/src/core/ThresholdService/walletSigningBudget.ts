export function walletSigningBudgetSessionId(input: {
  signingGrantId: string;
}): string {
  const id = String(input.signingGrantId || '').trim();
  return id ? `wallet-signing:${id}` : '';
}
