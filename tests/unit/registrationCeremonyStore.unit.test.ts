import { expect, test } from '@playwright/test';
import {
  createRegistrationCeremonyStore,
  type StoredWalletAddSignerCeremony,
  type StoredRegistrationIntent,
  type StoredWalletRegistrationCeremony,
} from '@server/core/RegistrationCeremonyStore';
import type { CloudflareDurableObjectNamespaceLike } from '@server/core/types';
import {
  registrationIntentGrantFromString,
  walletSubjectIdFromString,
  type AddSignerIntentV1,
  type RegistrationIntentV1,
  type RegistrationSignerSelection,
} from '@shared/utils/registrationIntent';

class FakeDurableObjectStub {
  private readonly records = new Map<string, { value: unknown; expiresAtMs?: number }>();

  async fetch(_input: RequestInfo, init?: RequestInit): Promise<Response> {
    const request = JSON.parse(String(init?.body || '{}')) as {
      op?: string;
      key?: string;
      value?: unknown;
      ttlMs?: number;
    };
    const key = String(request.key || '');
    if (!key) return Response.json({ ok: false, code: 'invalid_key', message: 'missing key' });

    if (request.op === 'set') {
      this.records.set(key, {
        value: request.value,
        ...(typeof request.ttlMs === 'number' ? { expiresAtMs: Date.now() + request.ttlMs } : {}),
      });
      return Response.json({ ok: true, value: null });
    }

    const record = this.records.get(key) || null;
    const value =
      record && (!record.expiresAtMs || record.expiresAtMs > Date.now()) ? record.value : null;
    if (request.op === 'getdel') this.records.delete(key);
    if (request.op === 'get' || request.op === 'getdel') {
      return Response.json({ ok: true, value });
    }

    return Response.json({ ok: false, code: 'invalid_op', message: 'invalid op' });
  }
}

class FakeDurableObjectNamespace implements CloudflareDurableObjectNamespaceLike {
  readonly stub = new FakeDurableObjectStub();

  idFromName(name: string): unknown {
    return name;
  }

  get(): FakeDurableObjectStub {
    return this.stub;
  }
}

const SIGNER_SELECTION = {
  mode: 'ed25519_only',
  ed25519: {
    nearAccountId: 'registration-store.testnet',
    signerSlot: 1,
    participantIds: [1, 2],
    keyPurpose: 'near_tx',
    keyVersion: 'threshold-ed25519-hss-v1',
    derivationVersion: 1,
    createNearAccount: true,
  },
} satisfies RegistrationSignerSelection;

const INTENT = {
  version: 'registration_intent_v1',
  walletSubjectId: walletSubjectIdFromString('wallet_subject_registration_store'),
  rpId: 'wallet.example.test',
  authMethod: { kind: 'passkey' },
  signerSelection: SIGNER_SELECTION,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1;

const ADD_SIGNER_INTENT = {
  version: 'add_signer_intent_v1',
  walletSubjectId: INTENT.walletSubjectId,
  rpId: INTENT.rpId,
  signerSelection: {
    mode: 'ecdsa',
    ecdsa: {
      chainTargets: [{ kind: 'tempo', chainId: 42431 }],
      participantIds: [1, 2],
    },
  },
  nonceB64u: 'add-signer-nonce',
} satisfies AddSignerIntentV1;

function makeIntent(expiresAtMs = Date.now() + 60_000): StoredRegistrationIntent {
  return {
    kind: 'intent_allocated',
    grant: registrationIntentGrantFromString('rig_registration_store_test'),
    intent: INTENT,
    digestB64u: 'digest',
    orgId: 'org_registration_store',
    expiresAtMs,
  };
}

function makeCeremony(expiresAtMs = Date.now() + 60_000): StoredWalletRegistrationCeremony {
  return {
    registrationCeremonyId: 'wrc_registration_store_test',
    intent: INTENT,
    digestB64u: 'digest',
    orgId: 'org_registration_store',
    expiresAtMs,
    authority: {
      kind: 'passkey',
      walletSubjectId: INTENT.walletSubjectId,
      rpId: INTENT.rpId,
      credentialIdB64u: 'credential',
      credentialPublicKeyB64u: 'public-key',
      counter: 0,
      registrationIntentDigestB64u: 'digest',
    },
    signerState: {
      kind: 'ed25519_prepared',
      ceremonyHandle: 'ceremony-handle',
      preparedSession: {
        contextBindingB64u: 'context-binding',
        evaluatorDriverStateB64u: 'driver-state',
      },
      clientOtOfferMessageB64u: 'client-ot-offer',
    },
  };
}

function makeAddSignerCeremony(expiresAtMs = Date.now() + 60_000): StoredWalletAddSignerCeremony {
  return {
    addSignerCeremonyId: 'wasc_registration_store_test',
    intent: ADD_SIGNER_INTENT,
    digestB64u: 'add-signer-digest',
    orgId: 'org_registration_store',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    expiresAtMs,
    auth: { kind: 'webauthn_assertion', credentialIdB64u: 'credential-id' },
    signerState: {
      kind: 'ecdsa_add_signer_prepared',
      hssKind: 'evm_family_ecdsa_keygen',
      chainTargets: [{ kind: 'tempo', chainId: 42431 }],
      prepare: {
        formatVersion: 'ecdsa-hss-role-local',
        walletId: String(INTENT.walletSubjectId),
        rpId: INTENT.rpId,
        ecdsaThresholdKeyId: 'ek_add_signer',
        signingRootId: 'project:dev',
        signingRootVersion: 'default',
        keyScope: 'evm-family',
        relayerKeyId: 'rk_add_signer',
        requestId: 'request-add-signer',
        sessionId: 'session-add-signer',
        walletSigningSessionId: 'wallet-session-add-signer',
        ttlMs: 300_000,
        remainingUses: 1,
        participantIds: [1, 2],
      },
    },
  };
}

test('Cloudflare Durable Object registration ceremony store consumes grants and ceremonies once', async () => {
  const namespace = new FakeDurableObjectNamespace();
  const store = createRegistrationCeremonyStore({
    config: {
      kind: 'cloudflare-do',
      namespace,
      name: 'registration-store-test',
      keyPrefix: 'test-prefix',
    },
    logger: undefined,
    isNode: false,
  });

  const intent = makeIntent();
  await store.putIntent(intent);
  await expect(store.takeIntent(intent.grant)).resolves.toMatchObject({
    kind: 'intent_consumed',
    grant: intent.grant,
  });
  await expect(store.takeIntent(intent.grant)).resolves.toBeNull();

  const ceremony = makeCeremony();
  await store.putCeremony(ceremony);
  await expect(store.getCeremony(ceremony.registrationCeremonyId)).resolves.toMatchObject({
    registrationCeremonyId: ceremony.registrationCeremonyId,
    signerState: { kind: 'ed25519_prepared' },
  });
  await expect(store.takeCeremony(ceremony.registrationCeremonyId)).resolves.toMatchObject({
    registrationCeremonyId: ceremony.registrationCeremonyId,
  });
  await expect(store.takeCeremony(ceremony.registrationCeremonyId)).resolves.toBeNull();

  const addSignerCeremony = makeAddSignerCeremony();
  await store.putAddSignerCeremony(addSignerCeremony);
  await expect(
    store.getAddSignerCeremony(addSignerCeremony.addSignerCeremonyId),
  ).resolves.toMatchObject({
    addSignerCeremonyId: addSignerCeremony.addSignerCeremonyId,
    signerState: { kind: 'ecdsa_add_signer_prepared' },
  });
  await expect(
    store.takeAddSignerCeremony(addSignerCeremony.addSignerCeremonyId),
  ).resolves.toMatchObject({
    addSignerCeremonyId: addSignerCeremony.addSignerCeremonyId,
  });
  await expect(
    store.takeAddSignerCeremony(addSignerCeremony.addSignerCeremonyId),
  ).resolves.toBeNull();
});

test('registration ceremony store rejects mixed raw authority branches', async () => {
  const namespace = new FakeDurableObjectNamespace();
  const store = createRegistrationCeremonyStore({
    config: {
      kind: 'cloudflare-do',
      namespace,
      name: 'registration-store-test',
      keyPrefix: 'test-prefix',
    },
    logger: undefined,
    isNode: false,
  });

  const ceremony = makeCeremony();
  const mixedAuthorityCeremony = {
    ...ceremony,
    authority: {
      ...ceremony.authority,
      emailHashHex: 'abcd',
      challengeId: 'challenge',
    },
  };
  await namespace.stub.fetch('https://durable-object.test', {
    method: 'POST',
    body: JSON.stringify({
      op: 'set',
      key: `test-prefix:wallet-registration:ceremony:${ceremony.registrationCeremonyId}`,
      value: mixedAuthorityCeremony,
      ttlMs: 60_000,
    }),
  });

  await expect(store.getCeremony(ceremony.registrationCeremonyId)).resolves.toBeNull();
});
