import { expect, test } from '@playwright/test';
import {
  buildActiveMethodBoundPasskeyCustodyEnvelopeFixture,
  buildLinkedDevicePasskeyEd25519ExportRootEnvelopeFixture,
  CREDENTIAL_ID_B64U,
  ED25519_PUBLIC_KEY_B64U,
  ED25519_WALLET_KEY_ID,
  RP_ID,
  WALLET_ID,
} from './helpers/passkeyCustodyEnvelope.fixtures';
import { buildUnlockedWalletEd25519ExportRootCapabilityFixture } from './helpers/unlockedEd25519ExportRootCapability.fixtures';
import {
  dropUnlockedWalletEd25519ExportRootCapabilityReferenceV1,
  establishUnlockedWalletEd25519ExportRootCapabilityV1,
} from '../../packages/wallet/src/core/signingEngine/walletCustody/unlockedEd25519ExportRootCapability';
import type { WalletCustodyCeremonyTransportPort } from '../../packages/wallet/src/core/signingEngine/walletCustody/ceremonyStepRunner';

class RecordingCeremonyTransport implements WalletCustodyCeremonyTransportPort {
  readonly requests: unknown[] = [];

  constructor(private readonly result: unknown) {}

  requestOperation(args: {
    readonly kind: 'walletCustodyCeremony';
    readonly request: unknown;
  }): Promise<unknown> {
    this.requests.push(args);
    return Promise.resolve(this.result);
  }
}

class FailingCeremonyTransport implements WalletCustodyCeremonyTransportPort {
  requestOperation(): Promise<unknown> {
    throw new Error('client-root envelopes must not use the seed opener');
  }
}

test.afterEach(() => {
  dropUnlockedWalletEd25519ExportRootCapabilityReferenceV1();
});

test('establishes a zero-prompt capability for a wallet-custody seed envelope', async () => {
  const envelope = buildActiveMethodBoundPasskeyCustodyEnvelopeFixture({
    walletId: WALLET_ID,
    envelopeId: 'envelope:unlocked-seed',
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID_B64U,
    walletAuthMethodId: 'wallet-auth-method:seed',
  });
  const capability = buildUnlockedWalletEd25519ExportRootCapabilityFixture({
    walletId: WALLET_ID,
    walletAuthMethodId: 'wallet-auth-method:seed',
    walletSessionId: 'wallet-session:seed',
  });
  const transport = new RecordingCeremonyTransport(capability);

  const established = await establishUnlockedWalletEd25519ExportRootCapabilityV1(transport, {
    existingEnvelope: envelope,
    existingFactorSecret: new Uint8Array(32).fill(7),
    walletId: WALLET_ID,
    walletAuthMethodId: 'wallet-auth-method:seed',
    walletSessionId: 'wallet-session:seed',
    expiresAtMs: capability.expiresAtMs,
  });

  expect(established).toEqual(capability);
  expect(transport.requests).toHaveLength(1);
  expect(transport.requests[0]).toMatchObject({
    request: { type: 'establishUnlockedWalletEd25519ExportRootCapability' },
  });
});

test('skips capability establishment for a linked Client-root envelope', async () => {
  const envelope = buildLinkedDevicePasskeyEd25519ExportRootEnvelopeFixture({
    tag: 'unlocked-client-root',
    walletId: WALLET_ID,
    walletKeyId: ED25519_WALLET_KEY_ID,
    registeredPublicKeyB64u: ED25519_PUBLIC_KEY_B64U,
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID_B64U,
    deviceId: 'device:client-root',
    sealedFill: 31,
  });

  const established = await establishUnlockedWalletEd25519ExportRootCapabilityV1(
    new FailingCeremonyTransport(),
    {
      existingEnvelope: envelope,
      existingFactorSecret: new Uint8Array(32).fill(11),
      walletId: WALLET_ID,
      walletAuthMethodId: 'wallet-auth-method:client-root',
      walletSessionId: 'wallet-session:client-root',
      expiresAtMs: Date.now() + 60_000,
    },
  );

  expect(established).toBeUndefined();
});
