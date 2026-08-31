import { expect, test } from '@playwright/test';
import {
  configurePasskeyCustodySessionCachePersistence,
  readPasskeyCustodySessionEnvelope,
  rememberPasskeyCustodySessionEnvelope,
  type PasskeyCustodySessionCachePersistencePort,
} from '../../packages/wallet/src/core/signingEngine/session/passkey/passkeyCustodySessionCache';
import { buildActiveMethodBoundPasskeyCustodyEnvelopeFixture } from './helpers/passkeyCustodyEnvelope.fixtures';

class InMemoryPasskeyCustodySessionCachePersistence implements PasskeyCustodySessionCachePersistencePort {
  readonly values = new Map<string, unknown>();
  readonly writtenKeys: string[] = [];

  async readCacheEntry(key: string): Promise<unknown | undefined> {
    return this.values.get(key);
  }

  async writeCacheEntry(key: string, value: unknown): Promise<void> {
    this.writtenKeys.push(key);
    this.values.set(key, value);
  }
}

test('persists a passkey custody session envelope through the injected cache port', async () => {
  const persistence = new InMemoryPasskeyCustodySessionCachePersistence();
  configurePasskeyCustodySessionCachePersistence(persistence);
  const walletId = 'passkey-cache-port-wallet';
  const credentialIdB64u = 'passkey-cache-port-credential';
  const envelope = buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
    walletId,
    envelopeId: 'passkey-cache-port-envelope',
    rpId: 'wallet.example.test',
    credentialIdB64u,
    walletAuthMethodId: 'passkey-cache-port-method',
  });

  await rememberPasskeyCustodySessionEnvelope({
    walletId,
    credentialIdB64u,
    envelope,
  });

  expect(persistence.writtenKeys).toEqual(['passkeyCustodyEnvelopeCacheV1']);
  await expect(
    readPasskeyCustodySessionEnvelope({ walletId, credentialIdB64u }),
  ).resolves.toEqual(envelope);
});
