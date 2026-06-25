import { expect, test } from '@playwright/test';
import {
  buildStoredWalletRegistrationHssPreparationFailed,
  buildStoredWalletRegistrationHssPreparationPrepared,
  buildStoredWalletRegistrationHssPreparationPreparing,
  createRegistrationCeremonyStore,
  type StoredWalletRegistrationHssPreparationBase,
  type StoredWalletAddSignerCeremony,
  type StoredRegistrationIntent,
  type StoredWalletRegistrationHssPreparation,
  type StoredWalletRegistrationCeremony,
} from '@server/core/RegistrationCeremonyStore';
import {
  registrationPreparationIdFromString,
  type CloudflareDurableObjectNamespaceLike,
} from '@server/core/types';
import {
  nearEd25519SigningKeyIdFromWalletId,
  registrationIntentGrantFromString,
  requireGeneratedImplicitWalletId,
  sponsoredNamedNearAccountProvisioning,
  walletIdFromString,
  type AddSignerIntentV1,
  type RegistrationIntentV1,
  type RegistrationSignerSelection,
} from '@shared/utils/registrationIntent';
import { parseNamedNearAccountId } from '@shared/utils/near';

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
    if (request.op === 'getdelIfRelatedMatches') {
      const relatedKey = String((request as { relatedKey?: unknown }).relatedKey || '');
      const related = this.records.get(relatedKey) || null;
      const relatedValue =
        related && (!related.expiresAtMs || related.expiresAtMs > Date.now())
          ? related.value
          : null;
      const matched = jsonValueContains(
        relatedValue,
        (request as { expectedRelated?: unknown }).expectedRelated,
      );
      if (!matched) {
        return Response.json({ ok: true, value: { matched: false, value: null } });
      }
      const record = this.records.get(key) || null;
      const value =
        record && (!record.expiresAtMs || record.expiresAtMs > Date.now()) ? record.value : null;
      this.records.delete(key);
      return Response.json({ ok: true, value: { matched: true, value } });
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

function jsonValueContains(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(expected)) {
    return (
      Array.isArray(actual) &&
      actual.length === expected.length &&
      expected.every((value, index) => jsonValueContains(actual[index], value))
    );
  }
  if (expected && typeof expected === 'object' && !Array.isArray(expected)) {
    if (!actual || typeof actual !== 'object' || Array.isArray(actual)) return false;
    return Object.entries(expected).every(([key, value]) =>
      jsonValueContains((actual as Record<string, unknown>)[key], value),
    );
  }
  return Object.is(actual, expected);
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

function namedProvisioning(accountId: string) {
  return sponsoredNamedNearAccountProvisioning(namedAccountId(accountId));
}

function namedAccountId(accountId: string) {
  const parsed = parseNamedNearAccountId(accountId);
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

const SIGNER_SELECTION = {
  mode: 'ed25519_only',
  ed25519: {
    accountProvisioning: namedProvisioning('registration-store.testnet'),
    signerSlot: 1,
    participantIds: [1, 2],
    keyPurpose: 'near_tx',
    keyVersion: 'threshold-ed25519-hss-v1',
    derivationVersion: 1,
  },
} satisfies RegistrationSignerSelection;

const INTENT = {
  version: 'registration_intent_v1',
  walletId: walletIdFromString('wallet_registration_store'),
  rpId: 'wallet.example.test',
  authMethod: { kind: 'passkey' },
  signerSelection: SIGNER_SELECTION,
  nonceB64u: 'nonce',
} satisfies RegistrationIntentV1;

const ADD_SIGNER_INTENT = {
  version: 'add_signer_intent_v1',
  walletId: INTENT.walletId,
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
      walletId: INTENT.walletId,
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

function makePreparationBase(
  expiresAtMs = Date.now() + 60_000,
): StoredWalletRegistrationHssPreparationBase {
  const registrationPreparationId = registrationPreparationIdFromString(
    'wrp_registration_store_test',
  );
  const registrationIntentGrant = registrationIntentGrantFromString('rig_registration_store_test');
  return {
    registrationPreparationId,
    registrationIntentGrant,
    registrationIntentDigestB64u: 'digest',
    intent: INTENT,
    orgId: 'org_registration_store',
    expectedOrigin: 'https://wallet.example.test',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    ed25519Scope: {
      walletId: String(INTENT.walletId),
      rpId: INTENT.rpId,
      authMethodKind: INTENT.authMethod.kind,
      expectedOrigin: 'https://wallet.example.test',
      orgId: 'org_registration_store',
      signingRootId: 'project:dev',
      signingRootVersion: 'default',
      registrationIntentDigestB64u: 'digest',
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromWalletId(INTENT.walletId),
      signerSlot: SIGNER_SELECTION.ed25519.signerSlot,
      keyPurpose: SIGNER_SELECTION.ed25519.keyPurpose,
      keyVersion: SIGNER_SELECTION.ed25519.keyVersion,
      derivationVersion: SIGNER_SELECTION.ed25519.derivationVersion,
      participantIds: [...SIGNER_SELECTION.ed25519.participantIds],
    },
    createdAtMs: Date.now(),
    expiresAtMs,
  };
}

function makePreparation(
  expiresAtMs = Date.now() + 60_000,
): StoredWalletRegistrationHssPreparation {
  return buildStoredWalletRegistrationHssPreparationPrepared({
    ...makePreparationBase(expiresAtMs),
    prepared: {
      kind: 'ed25519_prepared',
      ceremonyHandle: 'prepared-handle',
      preparedSession: {
        contextBindingB64u: 'context-binding',
        evaluatorDriverStateB64u: 'driver-state',
      },
      clientOtOfferMessageB64u: 'client-ot-offer',
    },
  });
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
        walletId: String(INTENT.walletId),
        walletKeyId: `wallet-key-${String(INTENT.walletId)}`,
        ecdsaThresholdKeyId: 'ek_add_signer',
        signingRootId: 'project:dev',
        signingRootVersion: 'default',
        keyScope: 'evm-family',
        relayerKeyId: 'rk_add_signer',
        requestId: 'request-add-signer',
        thresholdSessionId: 'session-add-signer',
        signingGrantId: 'wallet-session-add-signer',
        ttlMs: 300_000,
        remainingUses: 1,
        participantIds: [1, 2],
      },
    },
  };
}

test('registration ceremony store scopes generated wallet reservations by RP ID', async () => {
  const store = createRegistrationCeremonyStore({
    config: null,
    logger: undefined,
    isNode: false,
  });
  const walletId = requireGeneratedImplicitWalletId('frost-vermillion-k7p9m2');
  const expiresAtMs = Date.now() + 60_000;

  await expect(
    store.reserveGeneratedWalletId({
      rpId: 'wallet.example.test',
      walletId,
      expiresAtMs,
    }),
  ).resolves.toBe(true);
  await expect(
    store.reserveGeneratedWalletId({
      rpId: 'wallet.example.test',
      walletId,
      expiresAtMs,
    }),
  ).resolves.toBe(false);
  await expect(
    store.reserveGeneratedWalletId({
      rpId: 'other-wallet.example.test',
      walletId,
      expiresAtMs,
    }),
  ).resolves.toBe(true);
});

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

  const preparation = makePreparation();
  await store.putPreparation(preparation);
  await expect(store.getPreparation(preparation.registrationPreparationId)).resolves.toMatchObject({
    kind: 'hss_prepare_prepared',
    registrationPreparationId: preparation.registrationPreparationId,
    prepared: { kind: 'ed25519_prepared', ceremonyHandle: 'prepared-handle' },
  });
  await expect(store.takePreparation(preparation.registrationPreparationId)).resolves.toMatchObject(
    {
      kind: 'hss_prepare_prepared',
      registrationPreparationId: preparation.registrationPreparationId,
    },
  );
  await expect(store.takePreparation(preparation.registrationPreparationId)).resolves.toBeNull();

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

  await store.putFinalizeReplay({
    kind: 'wallet_registration_finalize_replay_v1',
    registrationCeremonyId: ceremony.registrationCeremonyId,
    idempotencyKey: 'finalize-idempotency-1',
    createdAtMs: Date.now(),
    expiresAtMs: Date.now() + 60_000,
    response: {
      ok: true,
      walletId: INTENT.walletId,
      rpId: INTENT.rpId,
      accountProvisioning: namedProvisioning('registration-store.testnet'),
      resolvedAccount: {
        kind: 'sponsored_named_account',
        nearAccountId: namedAccountId('registration-store.testnet'),
        nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromWalletId(INTENT.walletId),
        transactionHash: 'create-account-tx',
      },
      ed25519: {
        nearAccountId: 'registration-store.testnet',
        nearEd25519SigningKeyId: String(nearEd25519SigningKeyIdFromWalletId(INTENT.walletId)),
        publicKey: 'ed25519-public-key',
        relayerKeyId: 'relayer-key',
        keyVersion: 'threshold-ed25519-hss-v1',
        recoveryExportCapable: true,
      },
    },
  });
  await expect(
    store.getFinalizeReplay({
      registrationCeremonyId: ceremony.registrationCeremonyId,
      idempotencyKey: 'finalize-idempotency-1',
    }),
  ).resolves.toMatchObject({
    kind: 'wallet_registration_finalize_replay_v1',
    response: {
      ok: true,
      walletId: INTENT.walletId,
      ed25519: {
        publicKey: 'ed25519-public-key',
      },
    },
  });
  await expect(
    store.getFinalizeReplay({
      registrationCeremonyId: ceremony.registrationCeremonyId,
      idempotencyKey: 'finalize-idempotency-miss',
    }),
  ).resolves.toBeNull();

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

test('registration ceremony store rejects finalize replay records with Ed25519 sessions', async () => {
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
  await expect(
    store.putFinalizeReplay({
      kind: 'wallet_registration_finalize_replay_v1',
      registrationCeremonyId: ceremony.registrationCeremonyId,
      idempotencyKey: 'finalize-idempotency-with-session',
      createdAtMs: Date.now(),
      expiresAtMs: Date.now() + 60_000,
      response: {
        ok: true,
        walletId: INTENT.walletId,
        rpId: INTENT.rpId,
        accountProvisioning: namedProvisioning('registration-store.testnet'),
        resolvedAccount: {
          kind: 'sponsored_named_account',
          nearAccountId: namedAccountId('registration-store.testnet'),
          nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromWalletId(INTENT.walletId),
          transactionHash: 'create-account-tx',
        },
        ed25519: {
          nearAccountId: 'registration-store.testnet',
          nearEd25519SigningKeyId: String(nearEd25519SigningKeyIdFromWalletId(INTENT.walletId)),
          publicKey: 'ed25519-public-key',
          relayerKeyId: 'relayer-key',
          keyVersion: 'threshold-ed25519-hss-v1',
          recoveryExportCapable: true,
          session: {
            sessionKind: 'jwt',
            walletId: INTENT.walletId,
            nearAccountId: 'registration-store.testnet',
            nearEd25519SigningKeyId: String(nearEd25519SigningKeyIdFromWalletId(INTENT.walletId)),
            thresholdSessionId: 'session',
            signingGrantId: 'wallet-session',
            expiresAtMs: Date.now() + 60_000,
            jwt: 'secret-jwt',
          },
        },
      },
    }),
  ).rejects.toThrow('Invalid wallet registration finalize replay record');
});

test('registration ceremony store preserves preparation lifecycle branches', async () => {
  const store = createRegistrationCeremonyStore({
    config: { kind: 'memory' },
    logger: undefined,
    isNode: true,
  });

  const preparing = buildStoredWalletRegistrationHssPreparationPreparing({
    ...makePreparationBase(),
    registrationPreparationId: registrationPreparationIdFromString('wrp_preparing'),
  });
  await store.putPreparation(preparing);
  await expect(store.getPreparation(preparing.registrationPreparationId)).resolves.toMatchObject({
    kind: 'hss_prepare_preparing',
    registrationPreparationId: preparing.registrationPreparationId,
  });

  const failedFromPreparing = buildStoredWalletRegistrationHssPreparationFailed({
    ...makePreparationBase(),
    registrationPreparationId: preparing.registrationPreparationId,
    failure: {
      code: 'hss_prepare_failed',
      message: 'prepare failed after start',
    },
  });
  await store.updatePreparation(failedFromPreparing);
  await expect(store.getPreparation(preparing.registrationPreparationId)).resolves.toMatchObject({
    kind: 'hss_prepare_failed',
    failure: {
      code: 'hss_prepare_failed',
      message: 'prepare failed after start',
    },
  });

  const failed = buildStoredWalletRegistrationHssPreparationFailed({
    ...makePreparationBase(),
    registrationPreparationId: registrationPreparationIdFromString('wrp_failed'),
    failure: {
      code: 'hss_prepare_failed',
      message: 'prepare failed',
    },
  });
  await store.putPreparation(failed);
  await expect(store.getPreparation(failed.registrationPreparationId)).resolves.toMatchObject({
    kind: 'hss_prepare_failed',
    failure: {
      code: 'hss_prepare_failed',
      message: 'prepare failed',
    },
  });
});

test('registration ceremony store consumes an intent only when the preparation scope matches', async () => {
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

  const mismatchedIntent = makeIntent();
  const mismatchedPreparation = makePreparation();
  await store.putIntent(mismatchedIntent);
  await store.putPreparation(mismatchedPreparation);
  await expect(
    store.consumeRegistrationIntentForPreparation({
      registrationIntentGrant: mismatchedIntent.grant,
      registrationIntentDigestB64u: mismatchedIntent.digestB64u,
      registrationPreparationId: mismatchedPreparation.registrationPreparationId,
      ed25519Scope: {
        ...mismatchedPreparation.ed25519Scope,
        nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromWalletId(walletIdFromString('different-wallet')),
      },
    }),
  ).resolves.toMatchObject({
    ok: false,
    code: 'scope_mismatch',
  });
  await expect(store.getIntent(mismatchedIntent.grant)).resolves.toMatchObject({
    kind: 'intent_allocated',
    grant: mismatchedIntent.grant,
  });

  const matchedPreparation = makePreparation();
  await expect(
    store.consumeRegistrationIntentForPreparation({
      registrationIntentGrant: mismatchedIntent.grant,
      registrationIntentDigestB64u: mismatchedIntent.digestB64u,
      registrationPreparationId: matchedPreparation.registrationPreparationId,
      ed25519Scope: matchedPreparation.ed25519Scope,
    }),
  ).resolves.toMatchObject({
    ok: true,
    intent: {
      kind: 'intent_consumed',
      grant: mismatchedIntent.grant,
    },
  });
  await expect(store.getIntent(mismatchedIntent.grant)).resolves.toBeNull();
});

test('registration ceremony store rejects mixed preparation lifecycle records', async () => {
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

  const preparation = makePreparation();
  await namespace.stub.fetch('https://durable-object.test', {
    method: 'POST',
    body: JSON.stringify({
      op: 'set',
      key: `test-prefix:wallet-registration:preparation:${preparation.registrationPreparationId}`,
      value: {
        ...preparation,
        failure: {
          code: 'mixed',
          message: 'mixed lifecycle state',
        },
      },
      ttlMs: 60_000,
    }),
  });

  await expect(store.getPreparation(preparation.registrationPreparationId)).resolves.toBeNull();
});

test('registration ceremony store prunes expired preparation records', async () => {
  const store = createRegistrationCeremonyStore({
    config: { kind: 'memory' },
    logger: undefined,
    isNode: true,
  });
  const preparation = makePreparation(Date.now() - 1_000);
  await store.putPreparation(preparation);

  await expect(store.getPreparation(preparation.registrationPreparationId)).resolves.toBeNull();
  await expect(store.takePreparation(preparation.registrationPreparationId)).resolves.toBeNull();
});
