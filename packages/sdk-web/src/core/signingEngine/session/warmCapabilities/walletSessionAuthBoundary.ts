type PersistedWarmSessionWalletSessionRecord = {
  thresholdSessionKind?: unknown;
  walletSessionJwt?: unknown;
};

export function walletSessionJwtFromPersistedWarmSessionRecord(
  record: PersistedWarmSessionWalletSessionRecord | null | undefined,
): string {
  return String(record?.walletSessionJwt || '').trim();
}

export function persistedWarmSessionRecordRequiresWalletSessionJwt(args: {
  capability: 'ed25519' | 'ecdsa';
  record: PersistedWarmSessionWalletSessionRecord | null | undefined;
}): boolean {
  return Boolean(args.record) && (args.capability === 'ed25519' || args.capability === 'ecdsa');
}
