import type {
  SigningSessionSealedStoreRecord,
  WriteExactSealedSessionBaseInput,
} from '../persistence/sealedSessionStore';

export type SealedSessionCompanionCurve = 'ed25519' | 'ecdsa';

export function buildCompanionThresholdSessionIds(args: {
  existingRecord: SigningSessionSealedStoreRecord;
  companionCurve: SealedSessionCompanionCurve;
  companionThresholdSessionId: string;
}): NonNullable<WriteExactSealedSessionBaseInput['thresholdSessionIds']> {
  const companionThresholdSessionId = String(args.companionThresholdSessionId || '').trim();
  if (!companionThresholdSessionId) {
    throw new Error('Companion threshold session id is required');
  }
  return {
    ...args.existingRecord.thresholdSessionIds,
    [args.companionCurve]: companionThresholdSessionId,
  };
}

export function buildCompanionSealedSessionUpdate(args: {
  existingRecord: SigningSessionSealedStoreRecord;
  companionCurve: SealedSessionCompanionCurve;
  companionThresholdSessionId: string;
  subjectId: string;
  updatedAtMs?: number;
  ecdsaRestore?: WriteExactSealedSessionBaseInput['ecdsaRestore'];
  ed25519Restore?: WriteExactSealedSessionBaseInput['ed25519Restore'];
}): WriteExactSealedSessionBaseInput & { curve: 'ed25519' | 'ecdsa' } {
  const subjectId = String(args.subjectId || '').trim();
  if (!subjectId) {
    throw new Error('Companion sealed-session update requires subjectId');
  }
  return {
    thresholdSessionId:
      args.existingRecord.curve === 'ecdsa'
        ? String(args.existingRecord.thresholdSessionIds.ecdsa || '').trim()
        : String(args.existingRecord.thresholdSessionIds.ed25519 || '').trim(),
    sealedSecretB64u: args.existingRecord.sealedSecretB64u,
    curve: args.existingRecord.curve,
    authMethod: args.existingRecord.authMethod,
    walletSigningSessionId: args.existingRecord.walletSigningSessionId,
    thresholdSessionIds: buildCompanionThresholdSessionIds({
      existingRecord: args.existingRecord,
      companionCurve: args.companionCurve,
      companionThresholdSessionId: args.companionThresholdSessionId,
    }),
    subjectId,
    walletId: args.existingRecord.walletId,
    userId: args.existingRecord.userId,
    signingRootId: args.existingRecord.signingRootId,
    signingRootVersion: args.existingRecord.signingRootVersion,
    relayerUrl: args.existingRecord.relayerUrl,
    keyVersion: args.existingRecord.keyVersion,
    shamirPrimeB64u: args.existingRecord.shamirPrimeB64u,
    ecdsaRestore: args.ecdsaRestore || args.existingRecord.ecdsaRestore,
    ed25519Restore: args.ed25519Restore || args.existingRecord.ed25519Restore,
    issuedAtMs: args.existingRecord.issuedAtMs,
    expiresAtMs: args.existingRecord.expiresAtMs,
    remainingUses: args.existingRecord.remainingUses,
    updatedAtMs: Math.floor(Number(args.updatedAtMs) || Date.now()),
  };
}
