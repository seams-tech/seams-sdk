import type { WarmSessionSealAndPersistResult } from '@/core/types/secure-confirm-worker';
import type { NearResolvedEd25519SigningSessionState } from '../../interfaces/near';
import type { HydrateSigningSessionInput } from '../warmCapabilities/public';

export type PasskeyEd25519YaoSessionPersistencePort = {
  hydrateSigningSession(input: HydrateSigningSessionInput): Promise<void>;
  persistSigningSessionSealForThresholdSession(input: {
    sessionId: string;
    transport: NonNullable<HydrateSigningSessionInput['transport']>;
  }): Promise<WarmSessionSealAndPersistResult>;
};

export type PersistPasskeyEd25519YaoSessionForRefreshInput = {
  persistence: PasskeyEd25519YaoSessionPersistencePort;
  session: NearResolvedEd25519SigningSessionState;
  prfFirstB64u: string;
};

export async function persistPasskeyEd25519YaoSessionForRefresh(
  input: PersistPasskeyEd25519YaoSessionForRefreshInput,
): Promise<void> {
  const sessionId = String(input.session.thresholdSessionId || '').trim();
  const signingGrantId = String(input.session.signingGrantId || '').trim();
  const walletSessionJwt = String(input.session.walletSessionAuth.walletSessionJwt || '').trim();
  const walletId = String(
    input.session.signingLane.identity.signer.account.wallet.walletId || '',
  ).trim();
  const prfFirstB64u = String(input.prfFirstB64u || '').trim();
  const expiresAtMs = Math.floor(Number(input.session.signingWalletSession.expiresAtMs) || 0);
  const remainingUses = Math.floor(Number(input.session.remainingUses));
  const laneAuth = input.session.signingLane.identity.auth;
  if (laneAuth.kind !== 'passkey') {
    throw new Error('Ed25519 Yao sealed refresh persistence requires a passkey lane');
  }
  if (
    !sessionId ||
    !signingGrantId ||
    !walletSessionJwt ||
    !walletId ||
    !prfFirstB64u ||
    expiresAtMs <= 0 ||
    !Number.isSafeInteger(remainingUses) ||
    remainingUses < 0
  ) {
    throw new Error('Ed25519 Yao sealed refresh persistence received an invalid session');
  }
  const transport = {
    curve: 'ed25519',
    authMethod: 'passkey',
    walletId,
    relayerUrl: input.session.relayerUrl,
    signingGrantId,
    walletSessionJwt,
  } as const;
  await input.persistence.hydrateSigningSession({
    sessionId,
    prfFirstB64u,
    expiresAtMs,
    remainingUses,
    transport,
  });
  const persisted = await input.persistence.persistSigningSessionSealForThresholdSession({
    sessionId,
    transport,
  });
  if (!persisted.ok) {
    throw new Error(
      `Ed25519 Yao sealed refresh persistence failed (${persisted.code}): ${persisted.message}`,
    );
  }
}
