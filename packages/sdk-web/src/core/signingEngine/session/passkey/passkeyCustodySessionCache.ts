import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';

type PasskeyCustodySessionKey = `${string}:${string}`;

const activePasskeyCustodyEnvelopes = new Map<
  PasskeyCustodySessionKey,
  PasskeyCustodyEnvelopeRecord
>();

function sessionKey(walletId: string, credentialIdB64u: string): PasskeyCustodySessionKey {
  const wallet = String(walletId || '').trim();
  const credential = String(credentialIdB64u || '').trim();
  if (!wallet || !credential) {
    throw new Error('passkey custody session identity is required');
  }
  return `${wallet}:${credential}`;
}

/**
 * Keeps the opaque envelope returned by the authenticated session exchange in
 * this page's memory. The export worker receives it only for the matching
 * wallet/credential and opens it with the fresh PRF output it collected.
 */
export function rememberPasskeyCustodySessionEnvelope(args: {
  readonly walletId: string;
  readonly credentialIdB64u: string;
  readonly envelope: PasskeyCustodyEnvelopeRecord;
}): void {
  if (args.envelope.lifecycle.state !== 'active') {
    throw new Error('passkey custody session envelope is not active');
  }
  if (
    String(args.envelope.walletId) !== String(args.walletId) ||
    args.envelope.factor.kind !== 'passkey' ||
    String(args.envelope.factor.credentialIdB64u) !== String(args.credentialIdB64u)
  ) {
    throw new Error('passkey custody session envelope identity changed');
  }
  activePasskeyCustodyEnvelopes.set(
    sessionKey(String(args.walletId), String(args.credentialIdB64u)),
    args.envelope,
  );
}

export function readPasskeyCustodySessionEnvelope(args: {
  readonly walletId: string;
  readonly credentialIdB64u: string;
}): PasskeyCustodyEnvelopeRecord | null {
  return (
    activePasskeyCustodyEnvelopes.get(
      sessionKey(String(args.walletId), String(args.credentialIdB64u)),
    ) || null
  );
}
