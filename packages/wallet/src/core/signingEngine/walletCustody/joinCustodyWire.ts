/**
 * Turning a fetched custody envelope into the wire the ceremony joins with.
 *
 * Two things make this more than a rename.
 *
 * **`envelopeBinding` is a composite, not the record's `binding`.** It is
 * `{walletId, envelopeId, factor, envelopeRevision, binding}` — the values the
 * envelope was sealed against. Passing the inner binding alone would send a
 * wire that decrypts against the wrong AAD, and the failure would read as a
 * bad passkey rather than a bad projection.
 *
 * **The wasm side parses with `deny_unknown_fields`.** Handing it the stored
 * record, or a superset, fails at the boundary. So this projects exactly the
 * five fields `JoinCustodyWireV1` declares, and the test that pins the key set
 * is load-bearing rather than decorative.
 *
 * Lifecycle is checked here as well as on the server. The server gates what it
 * serves, but this also runs against the same-device continuity cache, and a
 * revoked envelope read from local storage must not open custody either.
 */

import {
  custodyEnvelopeOwnershipWireV1,
  parseWalletCustodyEnvelopeOwnership,
} from '@shared/passkey-custody';

export type JoinCustodyWireResult =
  | { readonly ok: true; readonly custodyJson: string }
  | { readonly ok: false; readonly reason: string };

export function joinCustodyWireFromEnvelopeRecord(record: unknown): JoinCustodyWireResult {
  if (!isRecord(record)) return { ok: false, reason: 'custody envelope must be an object' };

  const lifecycle = isRecord(record.lifecycle) ? record.lifecycle : null;
  const state = lifecycle ? String(lifecycle.state || '').trim() : '';
  if (state !== 'active') {
    /* Named rather than generic: "revoked" and "retired" mean different things
       to the person holding the device, and the caller decides which to say. */
    return { ok: false, reason: `custody envelope is ${state || 'in an unknown state'}` };
  }

  const walletId = trimmed(record.walletId);
  const envelopeId = trimmed(record.envelopeId);
  const nonceB64u = trimmed(record.nonceB64u);
  const sealedCustodySecretB64u = trimmed(record.sealedCustodySecretB64u);
  const aadHashB64u = trimmed(record.aadHashB64u);
  const ciphertextDigestB64u = trimmed(record.ciphertextDigestB64u);
  if (
    !walletId ||
    !envelopeId ||
    !nonceB64u ||
    !sealedCustodySecretB64u ||
    !aadHashB64u ||
    !ciphertextDigestB64u
  ) {
    return { ok: false, reason: 'custody envelope is missing sealed material' };
  }

  const factor = record.factor;
  const binding = record.binding;
  if (!isRecord(factor) || !isRecord(binding)) {
    return { ok: false, reason: 'custody envelope is missing its binding' };
  }
  if (binding.kind !== 'wallet_custody_seed_v1') {
    return { ok: false, reason: 'generic custody wire rejects non-seed envelopes' };
  }

  const envelopeRevision = record.envelopeRevision;
  if (typeof envelopeRevision !== 'number' || !Number.isInteger(envelopeRevision)) {
    /* Part of the AAD: a wrong revision does not fail loudly, it fails to
       decrypt, so it is checked rather than defaulted. */
    return { ok: false, reason: 'custody envelope has no revision' };
  }

  /* Part of the AAD, exactly like the revision above: an envelope that names no
     owner decodes as the pre-109C `unbound` shape, and one that names the wrong
     owner fails to decrypt. Neither is defaulted here. */
  let ownership: unknown;
  try {
    ownership = custodyEnvelopeOwnershipWireV1(
      parseWalletCustodyEnvelopeOwnership(record.ownership, 'custody envelope ownership'),
    );
  } catch {
    return { ok: false, reason: 'custody envelope has no readable ownership' };
  }

  return {
    ok: true,
    custodyJson: JSON.stringify({
      envelopeBinding: { walletId, envelopeId, factor, envelopeRevision, binding, ownership },
      nonceB64u,
      sealedCustodySecretB64u,
      aadHashB64u,
      ciphertextDigestB64u,
    }),
  };
}

function trimmed(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
