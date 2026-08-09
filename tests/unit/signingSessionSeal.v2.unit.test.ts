import { expect, test } from '@playwright/test';
import {
  createSigningSessionSealShamir3PassCipherAdapter,
  encodeSigningSessionSealServerLockContext,
  type SigningSessionSealShamir3PassRuntime,
} from '../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/crypto/cipher';
import { parseSigningSessionSealRootConfig } from '../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/options';
import {
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_GROUP_ID,
} from '@shared/utils/signingSessionSeal';

const ROOT_SECRET_B64U = Buffer.alloc(32, 0x42).toString('base64url');

test.describe('signing-session seal v2 root configuration', () => {
  test('accepts exactly 32 root bytes and rejects invalid lengths', () => {
    const config = parseSigningSessionSealRootConfig({
      rootSecretB64u: ROOT_SECRET_B64U,
      currentKeyVersion: 'seal-r2',
    });

    expect(Array.from(config.rootSecret32)).toEqual(Array(32).fill(0x42));
    expect(config.currentKeyVersion).toBe('seal-r2');
    expect(config.acceptedWarmKeyVersions).toEqual(['seal-r2']);
    expect(config.protocol).toEqual({
      algorithm: SIGNING_SESSION_SEAL_ALG,
      groupId: SIGNING_SESSION_SEAL_GROUP_ID,
    });

    for (const rootSecretB64u of [
      '',
      Buffer.alloc(31, 0x42).toString('base64url'),
      Buffer.alloc(33, 0x42).toString('base64url'),
    ]) {
      expect(() =>
        parseSigningSessionSealRootConfig({
          rootSecretB64u,
          currentKeyVersion: 'seal-r2',
        }),
      ).toThrow();
    }
  });

  test('derives only accepted versions and routes apply/remove by record version', async () => {
    const derivations: Array<{
      groupId: string;
      root: number[];
      context: number[];
    }> = [];
    let nextHandle = 10;
    const runtime: SigningSessionSealShamir3PassRuntime = {
      deriveLockKeyHandle: async (input) => {
        derivations.push({
          groupId: input.groupId,
          root: Array.from(input.rootSecret32),
          context: Array.from(input.context),
        });
        nextHandle += 1;
        return nextHandle;
      },
      addLock: async ({ handle, ciphertextB64u }) => `add:${handle}:${ciphertextB64u}`,
      removeLock: async ({ handle, ciphertextB64u }) => `remove:${handle}:${ciphertextB64u}`,
      destroyLockKeyHandle: () => true,
    };
    const config = parseSigningSessionSealRootConfig({
      rootSecretB64u: ROOT_SECRET_B64U,
      currentKeyVersion: 'seal-r2',
      acceptedWarmKeyVersions: ['seal-r1', 'seal-r2'],
    });
    const adapter = createSigningSessionSealShamir3PassCipherAdapter({ config, runtime });

    expect(Array.from(config.rootSecret32)).toEqual(Array(32).fill(0));
    expect(derivations).toHaveLength(0);

    const applied = await adapter.run({
      operation: 'apply-server-seal',
      thresholdSessionId: 'session-1',
      ciphertext: 'client-lock',
      auth: { userId: 'user-1', claims: {} },
    });
    const removed = await adapter.run({
      operation: 'remove-server-seal',
      thresholdSessionId: 'session-1',
      ciphertext: 'temporary-lock',
      keyVersion: 'seal-r1',
      auth: { userId: 'user-1', claims: {} },
    });

    expect(applied).toEqual({ ok: true, ciphertext: 'add:12:client-lock', keyVersion: 'seal-r2' });
    expect(removed).toEqual({
      ok: true,
      ciphertext: 'remove:11:temporary-lock',
      keyVersion: 'seal-r1',
    });
    expect(derivations).toHaveLength(2);
    expect(derivations.map(({ groupId }) => groupId)).toEqual([
      SIGNING_SESSION_SEAL_GROUP_ID,
      SIGNING_SESSION_SEAL_GROUP_ID,
    ]);
    expect(derivations.map(({ root }) => root)).toEqual([
      Array(32).fill(0x42),
      Array(32).fill(0x42),
    ]);
    expect(derivations[0].context).not.toEqual(derivations[1].context);

    const unknown = await adapter.run({
      operation: 'remove-server-seal',
      thresholdSessionId: 'session-1',
      ciphertext: 'temporary-lock',
      keyVersion: 'seal-unknown',
      auth: { userId: 'user-1', claims: {} },
    });
    expect(unknown).toMatchObject({ ok: false, code: 'invalid_key_version' });
  });

  test('uses a stable length-delimited derivation context', () => {
    const context = encodeSigningSessionSealServerLockContext({
      protocol: {
        algorithm: SIGNING_SESSION_SEAL_ALG,
        groupId: SIGNING_SESSION_SEAL_GROUP_ID,
      },
      keyVersion: 'seal-r2',
    });
    expect(context).toEqual(
      new Uint8Array([
        0, 0, 0, 36,
        ...new TextEncoder().encode('seams/router-ab/signing-session-seal'),
        0, 0, 0, 14,
        ...new TextEncoder().encode('shamir3pass-v2'),
        0, 0, 0, 14,
        ...new TextEncoder().encode('rfc2409-group2'),
        0, 0, 0, 7,
        ...new TextEncoder().encode('seal-r2'),
        0, 0, 0, 14,
        ...new TextEncoder().encode('server-lock/v1'),
      ]),
    );
  });
});
