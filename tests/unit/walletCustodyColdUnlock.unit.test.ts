import { expect, test } from '@playwright/test';
import { coldUnlockNearEd25519CustodyV1 } from '../../packages/wallet/src/core/signingEngine/walletCustody/coldUnlock';
import type { PasskeyCustodyEnvelopeFetchResult } from '../../packages/wallet/src/core/rpcClients/relayer/passkeyCustodyEnvelope';

/**
 * The cold unlock composition: fetch, project, rejoin, persist.
 *
 * Two properties are worth pinning here and nowhere else.
 *
 * **Order.** The ceremony cannot run before the envelope arrives, and the
 * material cannot be persisted before the ceremony produces it. A refactor
 * that reordered either for latency would break custody in a way no
 * single-step test would notice.
 *
 * **Failures stay distinguishable.** A revoked credential, a wallet with no
 * envelope, and a corrupt record are three different conversations with the
 * user. The retrieval already separates them; this seam must not undo that.
 */

const B64U_32 = 'A'.repeat(43);

function activeEnvelope(): PasskeyCustodyEnvelopeFetchResult {
  return {
    kind: 'active',
    storeVersion: 'v3',
    envelope: {
      kind: 'wallet_custody_envelope_v2',
      envelopeId: 'envelope-1',
      walletId: 'alice.testnet',
      binding: { kind: 'wallet_custody_seed_v1' },
      factor: { kind: 'passkey', rpId: 'example.localhost', credentialIdB64u: 'credential-1' },
      envelopeRevision: 2,
      nonceB64u: 'B'.repeat(16),
      sealedCustodySecretB64u: 'C'.repeat(64),
      ciphertextDigestB64u: B64U_32,
      aadHashB64u: B64U_32,
      lifecycle: { state: 'active' },
    },
  };
}

function rejoinInput(trace: string[]) {
  return {
    runStep: (() => {
      throw new Error('the ceremony must not run in these tests');
    }) as never,
    walletId: 'alice.testnet',
    factorSecret: new ArrayBuffer(32),
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    registrationCeremonyId: 'lifecycle-1',
    yaoAdmission: {},
    yaoApplication: {},
    participantIds: [1, 2] as const,
    runRouterRound: async () => {
      trace.push('router');
      return '{}';
    },
    registeredPublicKeyB64u: B64U_32,
  } as never;
}

test('a refused envelope never reaches the ceremony', async () => {
  const trace: string[] = [];
  const result = await coldUnlockNearEd25519CustodyV1({
    fetchEnvelope: async () => {
      trace.push('fetch');
      return { kind: 'missing', message: 'no custody envelope for this credential' };
    },
    rejoin: rejoinInput(trace),
    persistMaterial: async () => {
      trace.push('persist');
    },
  });

  expect(result.kind).toBe('envelope_unavailable');
  if (result.kind !== 'envelope_unavailable') return;
  expect(result.code).toBe('envelope_missing');
  // Nothing after the fetch ran: no Router round for a wallet that has no
  // envelope to join.
  expect(trace).toEqual(['fetch']);
});

test('each retrieval failure keeps its own code', async () => {
  const cases: Array<[PasskeyCustodyEnvelopeFetchResult, string]> = [
    [{ kind: 'missing', message: 'm' }, 'envelope_missing'],
    [{ kind: 'retired', message: 'm' }, 'envelope_retired'],
    [{ kind: 'corrupt', message: 'm' }, 'envelope_corrupt'],
    [{ kind: 'transport_failed', message: 'm' }, 'transport_failed'],
    [{ kind: 'credential_rejected', code: 'envelope_revoked', message: 'm' }, 'envelope_revoked'],
  ];
  for (const [fetched, expected] of cases) {
    const result = await coldUnlockNearEd25519CustodyV1({
      fetchEnvelope: async () => fetched,
      rejoin: rejoinInput([]),
      persistMaterial: async () => {},
    });
    expect(result.kind).toBe('envelope_unavailable');
    if (result.kind !== 'envelope_unavailable') continue;
    expect(result.code, `${fetched.kind} must keep its code`).toBe(expected);
  }
});

test('an envelope that fails projection is reported apart from a refusal', async () => {
  // The server serves only active envelopes, so this means the record
  // disagrees with itself — nothing the user does differently will help.
  const broken = activeEnvelope();
  const result = await coldUnlockNearEd25519CustodyV1({
    fetchEnvelope: async () => ({
      ...(broken as { kind: 'active'; envelope: Record<string, unknown>; storeVersion: string }),
      envelope: { ...broken.envelope, envelopeRevision: 'two' },
    }),
    rejoin: rejoinInput([]),
    persistMaterial: async () => {},
  });
  expect(result.kind).toBe('envelope_rejected');
});
