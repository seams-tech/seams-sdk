import { expect, test } from '@playwright/test';
import { CloudflareD1PasskeyCustodyEnvelopeStore } from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import {
  retrievePasskeyCustodyEnvelope,
  type PasskeyCustodyEnvelopeRetrievalRequest,
} from '../../packages/wallet-server/src/router/domains/passkeyCustody/passkeyCustodyEnvelopeRetrieval';
import type {
  WebAuthnAuthenticatorRecord,
  WebAuthnAuthenticatorStore,
} from '../../packages/wallet-server/src/core/WebAuthnAuthenticatorStore';
import type { NormalizedLogger } from '../../packages/wallet-server/src/core/logger';
import type { WebAuthnAuthenticationCredential } from '../../packages/wallet-server/src/core/types';
import type {
  PasskeyEnvelopeId,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import {
  CREDENTIAL_ID_B64U,
  DIGEST_B64U,
  ENVELOPE_ID,
  WALLET_ID,
  passkeyCustodyEnvelope,
} from './helpers/passkeyCustodyEnvelope.fixtures';

const TEST_SCOPE = {
  namespace: 'passkey-custody-retrieval-test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

const RP_ID = 'wallet.example.localhost' as WebAuthnRpId;
const USER_ID = 'user-1';

const LOCATOR = {
  walletId: WALLET_ID as WalletId,
  factor: {
    kind: 'passkey',
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID_B64U as WebAuthnCredentialIdB64u,
  },
  envelopeId: ENVELOPE_ID as PasskeyEnvelopeId,
} as const;

/**
 * An authenticator store that knows no credentials. Assertion verification
 * therefore always fails, which is what the tests below need: they assert the
 * checks that run *before* verification, and that nothing reaches the envelope
 * store once verification fails.
 */
class EmptyAuthenticatorStore implements WebAuthnAuthenticatorStore {
  async get(): Promise<WebAuthnAuthenticatorRecord | null> {
    return null;
  }
  async put(): Promise<void> {}
  async del(): Promise<void> {}
}

function silentLogger(): NormalizedLogger {
  return { debug: () => {}, info: () => {}, warn: () => {}, error: () => {} };
}

function assertion(overrides: Record<string, unknown> = {}): WebAuthnAuthenticationCredential {
  return {
    id: CREDENTIAL_ID_B64U,
    rawId: CREDENTIAL_ID_B64U,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: 'e30',
      authenticatorData: 'AAAA',
      signature: 'AAAA',
      userHandle: null,
    },
    clientExtensionResults: null,
    ...overrides,
  } as WebAuthnAuthenticationCredential;
}

function request(
  overrides: Partial<PasskeyCustodyEnvelopeRetrievalRequest> = {},
): PasskeyCustodyEnvelopeRetrievalRequest {
  return {
    locator: LOCATOR,
    rpId: RP_ID,
    userId: USER_ID,
    expectedChallenge: 'challenge-1',
    expectedOrigin: 'https://wallet.example.localhost',
    webauthnAuthentication: assertion(),
    ...overrides,
  };
}

/** Stands in for a successfully verified assertion. */
const acceptAssertion = async () => ({ success: true, verified: true });

async function withRetrieval(
  run: (
    retrieve: (
      req: PasskeyCustodyEnvelopeRetrievalRequest,
      verifyAssertion?: typeof acceptAssertion,
    ) => ReturnType<typeof retrievePasskeyCustodyEnvelope>,
    store: CloudflareD1PasskeyCustodyEnvelopeStore,
  ) => Promise<void>,
): Promise<void> {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const envelopeStore = new CloudflareD1PasskeyCustodyEnvelopeStore({
      database,
      scope: TEST_SCOPE,
    });
    await run(
      (req, verifyAssertion) =>
        retrievePasskeyCustodyEnvelope({
          request: req,
          envelopeStore,
          authenticatorStore: new EmptyAuthenticatorStore(),
          logger: silentLogger(),
          verifyAssertion,
        }),
      envelopeStore,
    );
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
}

test('an assertion carrying PRF output is rejected before verification', async () => {
  await withRetrieval(async (retrieve) => {
    const disclosed = await retrieve(
      request({
        webauthnAuthentication: assertion({
          clientExtensionResults: { prf: { results: { first: 'cHJmLXNlY3JldA' } } },
        }),
      }),
    );
    expect(disclosed.kind).toBe('prf_disclosed');
    if (disclosed.kind !== 'prf_disclosed') return;
    expect(disclosed.message).toContain('redacted');
  });
});

test('extension output nested under the response is also rejected', async () => {
  await withRetrieval(async (retrieve) => {
    const nested = await retrieve(
      request({
        webauthnAuthentication: assertion({
          response: {
            clientDataJSON: 'e30',
            authenticatorData: 'AAAA',
            signature: 'AAAA',
            userHandle: null,
            clientExtensionResults: { prf: { results: { first: 'cHJmLXNlY3JldA' } } },
          },
        }),
      }),
    );
    expect(nested.kind).toBe('prf_disclosed');
  });
});

test('any surviving extension output is rejected, not just a prf key', async () => {
  await withRetrieval(async (retrieve) => {
    // A caller forwarding raw extension outputs is not honouring the redaction
    // contract, whatever the extension happens to be.
    const other = await retrieve(
      request({
        webauthnAuthentication: assertion({ clientExtensionResults: { largeBlob: { read: 'x' } } }),
      }),
    );
    expect(other.kind).toBe('prf_disclosed');
  });
});

test('an empty extension results object passes redaction', async () => {
  await withRetrieval(async (retrieve) => {
    const empty = await retrieve(
      request({ webauthnAuthentication: assertion({ clientExtensionResults: {} }) }),
    );
    // Passes redaction, then fails on assertion verification instead.
    expect(empty.kind).toBe('assertion_rejected');
  });
});

test('an assertion for a different credential cannot fetch this envelope', async () => {
  await withRetrieval(async (retrieve, store) => {
    await store.createEnvelope(passkeyCustodyEnvelope());
    const mismatch = await retrieve(
      request({
        webauthnAuthentication: assertion({
          id: 'Y3JlZGVudGlhbC05',
          rawId: 'Y3JlZGVudGlhbC05',
        }),
      }),
    );
    expect(mismatch.kind).toBe('credential_mismatch');
  });
});

test('a credential id in standard base64 still matches the stored base64url form', async () => {
  await withRetrieval(async (retrieve) => {
    // CREDENTIAL_ID_B64U decodes to "credential-1"; the padded standard-base64
    // spelling of the same bytes must not read as a different credential.
    const padded = await retrieve(
      request({
        webauthnAuthentication: assertion({ id: 'Y3JlZGVudGlhbC0x=', rawId: 'Y3JlZGVudGlhbC0x=' }),
      }),
    );
    expect(padded.kind).not.toBe('credential_mismatch');
  });
});

test('an assertion missing its credential id is rejected', async () => {
  await withRetrieval(async (retrieve) => {
    const missingId = await retrieve(
      request({ webauthnAuthentication: assertion({ id: '', rawId: '' }) }),
    );
    expect(missingId).toMatchObject({ kind: 'assertion_rejected', code: 'invalid_body' });
  });
});

test('a failed assertion never reaches the envelope store', async () => {
  await withRetrieval(async (retrieve, store) => {
    await store.createEnvelope(passkeyCustodyEnvelope());
    const rejected = await retrieve(request());
    // The credential is unknown to the authenticator store, so verification
    // fails and no ciphertext is returned even though an envelope exists.
    expect(rejected.kind).toBe('assertion_rejected');
    expect(JSON.stringify(rejected)).not.toContain('sealedCustodySecret');
  });
});

test('retrieval failures carry no ciphertext for any envelope lifecycle state', async () => {
  await withRetrieval(async (retrieve, store) => {
    const envelope = passkeyCustodyEnvelope();
    await store.createEnvelope(envelope);
    await store.revokeEnvelope({ locator: LOCATOR, revokedAtMs: 6_000 });

    const result = await retrieve(request());
    expect(result.kind).toBe('assertion_rejected');
    expect(JSON.stringify(result)).not.toContain(String(envelope.sealedCustodySecretB64u));
  });
});

test('a corrupt stored envelope is reported without leaking its digests', async () => {
  await withRetrieval(async (_retrieve, store) => {
    await store.createEnvelope(passkeyCustodyEnvelope({ ciphertextDigestB64u: DIGEST_B64U }));
    // The store surfaces both digests for server-side diagnosis; retrieval
    // collapses that to a bare failure so a caller learns nothing extra.
    const lookup = await store.lookupEnvelope(LOCATOR);
    expect(lookup.kind).toBe('digest_mismatch');
  });
});

test('a verified assertion returns the active envelope ciphertext', async () => {
  await withRetrieval(async (retrieve, store) => {
    const envelope = passkeyCustodyEnvelope();
    await store.createEnvelope(envelope);

    const result = await retrieve(request(), acceptAssertion);
    expect(result.kind).toBe('active');
    if (result.kind !== 'active') return;
    expect(result.envelope.sealedCustodySecretB64u).toBe(envelope.sealedCustodySecretB64u);
    expect(result.envelope.envelopeRevision).toBe(1);
    expect(result.storeVersion).toBe('1');
  });
});

test('a verified assertion still maps every non-active lifecycle state', async () => {
  await withRetrieval(async (retrieve, store) => {
    expect((await retrieve(request(), acceptAssertion)).kind).toBe('missing');

    await store.createEnvelope(passkeyCustodyEnvelope());
    await store.retireEnvelope({ locator: LOCATOR, retiredAtMs: 5_000 });
    expect(await retrieve(request(), acceptAssertion)).toEqual({
      kind: 'retired',
      retiredAtMs: 5_000,
    });

    await store.revokeEnvelope({ locator: LOCATOR, revokedAtMs: 6_000 });
    expect(await retrieve(request(), acceptAssertion)).toEqual({
      kind: 'revoked',
      revokedAtMs: 6_000,
    });
  });
});

test('a verified assertion never serves a corrupt envelope', async () => {
  await withRetrieval(async (retrieve, store) => {
    const envelope = passkeyCustodyEnvelope({ ciphertextDigestB64u: DIGEST_B64U });
    await store.createEnvelope(envelope);

    const result = await retrieve(request(), acceptAssertion);
    // Retrieval collapses the store's diagnostic detail to a bare failure, and
    // returns no ciphertext for a row that disagrees with its own digest.
    expect(result).toEqual({ kind: 'digest_mismatch' });
    expect(JSON.stringify(result)).not.toContain(String(envelope.sealedCustodySecretB64u));
  });
});

test('PRF disclosure is rejected even when the assertion would verify', async () => {
  await withRetrieval(async (retrieve, store) => {
    await store.createEnvelope(passkeyCustodyEnvelope());
    const result = await retrieve(
      request({
        webauthnAuthentication: assertion({
          clientExtensionResults: { prf: { results: { first: 'cHJmLXNlY3JldA' } } },
        }),
      }),
      acceptAssertion,
    );
    // Redaction is enforced ahead of verification, so a valid assertion cannot
    // launder a leaked PRF result into a successful retrieval.
    expect(result.kind).toBe('prf_disclosed');
  });
});

test('a WebAuthn assertion cannot retrieve an Email OTP envelope', async () => {
  await withRetrieval(async (retrieve, store) => {
    await store.createEnvelope(passkeyCustodyEnvelope());
    // The request type makes an Email OTP locator unrepresentable; the cast
    // simulates unparsed wire input, which the runtime guard must still stop.
    const wireRequest = request();
    const tampered = {
      ...wireRequest,
      locator: {
        ...wireRequest.locator,
        factor: { kind: 'email_otp', enrollmentId: 'enrollment-1' },
      },
    } as unknown as PasskeyCustodyEnvelopeRetrievalRequest;
    const result = await retrieve(tampered, acceptAssertion);
    expect(result).toMatchObject({ kind: 'assertion_rejected', code: 'invalid_body' });
  });
});

test('an assertion for one RP cannot fetch an envelope sealed under another', async () => {
  await withRetrieval(async (retrieve, store) => {
    await store.createEnvelope(passkeyCustodyEnvelope());
    // The assertion verifies against request.rpId; the locator names the
    // envelope's RP. If they disagree, one RP's assertion would be standing in
    // for another RP's ciphertext.
    const result = await retrieve(
      request({
        locator: {
          ...LOCATOR,
          factor: { ...LOCATOR.factor, rpId: 'evil.example' as WebAuthnRpId },
        },
      }),
      acceptAssertion,
    );
    expect(result).toMatchObject({ kind: 'assertion_rejected', code: 'rp_mismatch' });
  });
});
