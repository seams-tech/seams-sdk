export function walletSigningBudgetSessionId(walletSigningSessionId: string): string {
  const id = String(walletSigningSessionId || '').trim();
  return id ? `wallet-signing:${id}` : '';
}

export function signerBoundWalletSigningBudgetSessionId(input: {
  walletSigningSessionId: string;
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionId: string;
}): string {
  const walletSigningSessionId = String(input.walletSigningSessionId || '').trim();
  const thresholdSessionId = String(input.thresholdSessionId || '').trim();
  if (!walletSigningSessionId || !thresholdSessionId) return '';
  return `wallet-signing:${walletSigningSessionId}:signer:${input.curve}:${thresholdSessionId}`;
}
