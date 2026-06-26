export function walletSigningBudgetSessionId(input: {
  curve: 'ed25519' | 'ecdsa';
  signingGrantId: string;
}): string {
  const curve = input.curve;
  const id = String(input.signingGrantId || '').trim();
  return id ? `wallet-signing:${curve}:${id}` : '';
}
