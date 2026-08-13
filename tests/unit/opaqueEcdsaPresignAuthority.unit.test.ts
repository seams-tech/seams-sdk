import { expect, test } from '@playwright/test';
import {
  OpaqueEcdsaPresignAuthorityV1,
  type OpaqueEcdsaPresignSessionV1,
} from '../../packages/sdk-web/src/core/signingEngine/workerManager/workers/opaqueEcdsaPresignAuthority';
import {
  FIXED_ECDSA_PRESIGN_PROTOCOL_ID,
  parseEcdsaClientPresignPoolIdentity,
} from '../../packages/sdk-web/src/core/signingEngine/workerManager/ecdsaPresignPoolIdentity';

function poolIdentity() {
  return parseEcdsaClientPresignPoolIdentity({
    poolKey: 'pool-1',
    materialActivationId: 'activation-1',
    capability: 'capability-1',
    keyBinding: 'binding-1',
    walletId: 'wallet-1',
    signingScopeB64u: 'scope-1',
    pairRole: 'client',
    keyEpoch: 'epoch-1',
    activationEpoch: '1',
    protocolId: FIXED_ECDSA_PRESIGN_PROTOCOL_ID,
  });
}

function completedSession(onFree: () => void): OpaqueEcdsaPresignSessionV1 {
  return {
    stage: () => 'done',
    poll: () => ({ stage: 'done', event: 'presign_done', outgoing: [] }),
    message: () => undefined,
    start_presign: () => undefined,
    presignature_big_r_33: () => new Uint8Array(33).fill(7),
    compute_signature_share: () => new Uint8Array(32).fill(9),
    free: onFree,
  };
}

test.describe('opaque ECDSA presign authority', () => {
  test('keeps completed shares opaque and rejects a mismatched group binding before use', async () => {
    let freeCount = 0;
    const authority = new OpaqueEcdsaPresignAuthorityV1();
    const groupPublicKey33 = new Uint8Array(33).fill(2);
    const progress = await authority.initialize({
      sessionId: 'session-1',
      session: completedSession(() => {
        freeCount += 1;
      }),
      poolIdentity: poolIdentity(),
      groupPublicKey33,
      expiresAtMs: Date.now() + 60_000,
    });

    expect(progress.event).toBe('presign_done');
    expect(Object.keys(progress).sort()).toEqual([
      'event',
      'outgoingMessages',
      'presignatureBigR33',
      'presignatureHandle',
      'stage',
    ]);
    await expect(
      authority.computeSignatureShare({
        materialHandle: progress.presignatureHandle!,
        groupPublicKey33: new Uint8Array(33).fill(3).buffer,
        expectedPresignBigR33: progress.presignatureBigR33!,
        digest32: new Uint8Array(32).buffer,
        clientRerandomizationContribution32: new Uint8Array(32).buffer,
        signingWorkerRerandomizationContribution32: new Uint8Array(32).buffer,
      }),
    ).rejects.toThrow('group public key binding mismatch');
    expect(freeCount).toBe(1);
  });

  test('computes one public online share and consumes the retained material', async () => {
    let freeCount = 0;
    const authority = new OpaqueEcdsaPresignAuthorityV1();
    const groupPublicKey33 = new Uint8Array(33).fill(2);
    const progress = await authority.initialize({
      sessionId: 'session-online',
      session: completedSession(() => {
        freeCount += 1;
      }),
      poolIdentity: poolIdentity(),
      groupPublicKey33,
      expiresAtMs: Date.now() + 60_000,
    });
    const input = {
      materialHandle: progress.presignatureHandle!,
      groupPublicKey33: groupPublicKey33.buffer,
      expectedPresignBigR33: progress.presignatureBigR33!,
      digest32: new Uint8Array(32).buffer,
      clientRerandomizationContribution32: new Uint8Array(32).buffer,
      signingWorkerRerandomizationContribution32: new Uint8Array(32).buffer,
    };

    expect(new Uint8Array(await authority.computeSignatureShare(input))).toEqual(
      new Uint8Array(32).fill(9),
    );
    await expect(authority.computeSignatureShare(input)).rejects.toThrow('material is unknown');
    expect(freeCount).toBe(1);
  });

  test('frees an initialization queued before authority close', async () => {
    let freeCount = 0;
    const authority = new OpaqueEcdsaPresignAuthorityV1();
    const initializing = authority.initialize({
      sessionId: 'session-close-race',
      session: completedSession(() => {
        freeCount += 1;
      }),
      poolIdentity: poolIdentity(),
      groupPublicKey33: new Uint8Array(33).fill(2),
      expiresAtMs: Date.now() + 60_000,
    });
    authority.close();

    await expect(initializing).rejects.toThrow('authority was closed');
    expect(freeCount).toBe(1);
  });

  test('rejects and frees an already expired active session', async () => {
    let freeCount = 0;
    const authority = new OpaqueEcdsaPresignAuthorityV1();

    await expect(
      authority.initialize({
        sessionId: 'session-expired',
        session: completedSession(() => {
          freeCount += 1;
        }),
        poolIdentity: poolIdentity(),
        groupPublicKey33: new Uint8Array(33).fill(2),
        expiresAtMs: Date.now() - 1,
      }),
    ).rejects.toThrow('session expired');
    expect(freeCount).toBe(1);
  });
});
