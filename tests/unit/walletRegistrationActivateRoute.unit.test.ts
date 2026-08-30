import { expect, test } from '@playwright/test';
import { alphabetizeStringify } from '../../packages/shared-ts/src/utils/digests';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import { secp256k1PrivateKey32ToPublicKey33 } from '../../packages/wallet-server/src/core/ThresholdService/evmCryptoWasm';
import type { WalletRegistrationActivateResponseV2 } from '../../packages/wallet-server/src/core/threeRouteRegistrationContracts';
import { createCloudflareD1RouterApiAuthService } from '../../packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService';
import { projectRegistrationEstablishedSessionV2 } from '../../packages/wallet-server/src/router/cloudflare/d1/registration/walletRegistrationSessionCommitReceipt';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  parseAuthFactorId,
  parsePrincipalId,
  parseTenantId,
  parseWalletSessionMintId,
} from '../../packages/shared-ts/src/authorization/capabilityKinds';
import { implicitNearAccountProvisioning } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseRegistrationEstablishedSessionResultV2 } from '../../packages/shared-ts/src/utils/registrationEstablishedSession';
import { buildVerifiedWalletSessionPasskeyFactorResult } from '../../packages/wallet-server/src/authorization/factorEvidence';
import { parseVerifiedOwnerProofId } from '../../packages/wallet-server/src/authorization/domain';
import { parseDigestB64u } from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  buildPasskeyWalletAuthAuthority,
  isPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import {
  buildFixtureRouterAbEcdsaStrictRegistrationRequest,
  createRouterAbSigningRuntimesForUnitTests,
  fixtureRouterAbEcdsaActivationFacts,
  SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort,
} from '../helpers/routerAbSigningRuntimeTestUtils';
import { createActivatedFinalizeYaoRuntimeFixture } from './helpers/d1WalletRegistrationFinalizeConvergence.fixtures';
import { CloudflareD1WalletCustodyCommitStore } from '../../packages/wallet-server/src/router/cloudflare/d1/passkeyCustody/d1WalletCustodyCommitStore';
import {
  buildAcknowledgedWalletCustodyCommitPayloadFixture,
  buildWalletCustodyCommitPayloadFixture,
} from './helpers/passkeyCustodyEnvelope.fixtures';
import {
  applySignerMigrations,
  createWebAuthnRegistrationCredential,
  insertWalletAuthMethod,
  readWalletAuthMethodRecord,
  RecordingDurableObjectNamespace,
  requireParsedDomainId,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';

type RegistrationTestDatabase = ReturnType<typeof createTemporaryD1Database>['database'];

type RegistrationJournalScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

const PERSISTED_REGISTRATION_CREDENTIAL_FIELDS = [
  'walletSessionToken',
  'primaryOperationCredential',
  'childOperationCredential',
  'operationCredential',
  'clientRootProof',
  'passkeyBootstrapAuthorization',
  'response',
] as const;

async function readRegistrationJournalRecord(input: {
  readonly database: RegistrationTestDatabase;
  readonly scope: RegistrationJournalScope;
  readonly recordKey: string;
}): Promise<unknown> {
  const row = await input.database
    .prepare(
      `SELECT record_json
         FROM router_ab_yao_versioned_json_records
        WHERE namespace = ?1
          AND org_id = ?2
          AND project_id = ?3
          AND env_id = ?4
          AND record_key = ?5`,
    )
    .bind(
      input.scope.namespace,
      input.scope.orgId,
      input.scope.projectId,
      input.scope.envId,
      input.recordKey,
    )
    .first<{ readonly record_json?: unknown }>();
  if (typeof row?.record_json !== 'string') {
    throw new Error(`registration journal row is missing: ${input.recordKey}`);
  }
  return JSON.parse(row.record_json);
}

function isRecordValue(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function collectObjectFieldNames(value: unknown, fieldNames: Set<string>): void {
  if (Array.isArray(value)) {
    for (const entry of value) collectObjectFieldNames(entry, fieldNames);
    return;
  }
  if (!isRecordValue(value)) return;
  for (const [key, child] of Object.entries(value)) {
    fieldNames.add(key);
    collectObjectFieldNames(child, fieldNames);
  }
}

function expectCredentialFreeRegistrationJournal(
  raw: unknown,
  operation: 'registration_activate' | 'near_provisioning',
  ephemeralBearer: string,
): void {
  if (!isRecordValue(raw) || !isRecordValue(raw.receipt)) {
    throw new Error('registration journal row is not a completion receipt');
  }
  expect(raw.kind).toBe('router_ab_ed25519_yao_registration_side_effect_completion_v2');
  expect(raw.operation).toBe(operation);
  expect(raw.receipt.kind).toBe('wallet_registration_session_commit_receipt_v2');
  expect(raw.receipt.operation).toBe(operation);

  const fieldNames = new Set<string>();
  collectObjectFieldNames(raw, fieldNames);
  for (const field of PERSISTED_REGISTRATION_CREDENTIAL_FIELDS) {
    expect(fieldNames.has(field), `persisted registration field: ${field}`).toBe(false);
  }
  const serialized = JSON.stringify(raw);
  expect(serialized).not.toContain(ephemeralBearer);
  expect(serialized).not.toMatch(/"(?:wst|wsh)_[A-Za-z0-9_-]+"/);
}

function expectCredentialFreeRegistrationReplay(raw: unknown, ephemeralBearer: string): void {
  const fieldNames = new Set<string>();
  collectObjectFieldNames(raw, fieldNames);
  for (const field of PERSISTED_REGISTRATION_CREDENTIAL_FIELDS) {
    expect(fieldNames.has(field), `registration replay field: ${field}`).toBe(false);
  }
  const serialized = JSON.stringify(raw);
  expect(serialized).not.toContain(ephemeralBearer);
  expect(serialized).not.toMatch(/"(?:wst|wsh)_[A-Za-z0-9_-]+"/);
}

/**
 * Refactor 94C. `/wallets/register/activate` folds activation and
 * finalization into one irreversible step behind a single Gateway operation
 * row.
 *
 * Previously three records guarded this one commit: the activation branch CAS,
 * finalize's side-effect journal, and finalize's separate replay cache. The
 * operation row is now the only one — its claim is the activation claim and
 * its completion record holds the committed credential-free projection and
 * request fingerprint. These tests pin the properties that made the other
 * two records seem necessary: identical retries return that stable projection
 * with fresh bounded bearers without repeating custody, and a conflicting
 * retry fails before any custody effect.
 */

const SCOPE = {
  namespace: 'registration-activate',
  orgId: 'org-activate',
  projectId: 'project-activate',
  envId: 'env-activate',
};

let fakeSignerInstances = 0;

function fakeGatewaySigner() {
  const issued = new Map<string, Record<string, unknown>>();
  const instance = (fakeSignerInstances += 1);
  let counter = 0;
  return {
    signJwt: async (sub: string, extra?: Record<string, unknown>) => {
      counter += 1;
      const header = base64UrlEncode(
        new TextEncoder().encode(JSON.stringify({ alg: 'none', typ: 'JWT' })),
      );
      const payload = base64UrlEncode(
        new TextEncoder().encode(
          JSON.stringify({
            sub,
            exp: Math.floor(Date.now() / 1000) + 900,
            ...(extra || {}),
          }),
        ),
      );
      const token = `${header}.${payload}.test-signature-${instance}-${counter}`;
      issued.set(token, { sub, ...(extra || {}) });
      return token;
    },
    verifyJwt: async (token: string) => {
      const payload = issued.get(token);
      return payload ? ({ valid: true, payload } as const) : ({ valid: false } as const);
    },
  };
}

type EcdsaActivateSuccess = Extract<
  WalletRegistrationActivateResponseV2,
  { readonly ok: true; readonly kind: 'evm_family_ecdsa' }
>;

function requireEcdsaActivateSuccess(
  response: WalletRegistrationActivateResponseV2,
): EcdsaActivateSuccess {
  if (!response.ok || response.kind !== 'evm_family_ecdsa') {
    throw new Error(`expected an ECDSA activation success: ${JSON.stringify(response)}`);
  }
  return response;
}

function stableRegistrationCommitIdentity(response: EcdsaActivateSuccess): string {
  const { registrationEstablishedSession, ...committed } = response;
  const projection =
    registrationEstablishedSession.kind === 'issued'
      ? projectRegistrationEstablishedSessionV2(registrationEstablishedSession.session)
      : registrationEstablishedSession.session;
  const { expiresAtMs: ignoredSessionExpiry, ...stableProjection } = projection;
  void ignoredSessionExpiry;
  return alphabetizeStringify({ committed, session: stableProjection });
}

function requireIssuedRegistrationSession(response: EcdsaActivateSuccess) {
  if (response.registrationEstablishedSession.kind !== 'issued') {
    throw new Error('expected the first registration response to issue its Wallet Session');
  }
  return response.registrationEstablishedSession.session;
}

function requireCommittedRegistrationProjection(response: EcdsaActivateSuccess) {
  if (response.registrationEstablishedSession.kind !== 'already_committed') {
    throw new Error('expected the replay to return a committed Wallet Session projection');
  }
  return response.registrationEstablishedSession;
}

function clonedRecord(value: unknown): Record<string, unknown> {
  const clone: unknown = JSON.parse(JSON.stringify(value));
  if (!isRecordValue(clone)) throw new Error('expected a record clone');
  return clone;
}

function changedOpaqueId(value: string): string {
  const replacement = value.endsWith('A') ? 'B' : 'A';
  return `${value.slice(0, -1)}${replacement}`;
}

/** Counts custody-affecting Router calls so a replay that skips them is visible. */
class CountingStrictRegistrationPort extends SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort {
  registerCalls = 0;
  activateCalls = 0;
  override async register(
    ...args: Parameters<SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort['register']>
  ): ReturnType<SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort['register']> {
    this.registerCalls += 1;
    return await super.register(...args);
  }
  override async activate(
    ...args: Parameters<SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort['activate']>
  ): ReturnType<SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort['activate']> {
    this.activateCalls += 1;
    return await super.activate(...args);
  }
}

/** Drives a ceremony through setup and respond, ready to activate. */
async function respondedCeremony(database: unknown, strictRegistration: unknown) {
  const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
    config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-activate' },
  });
  const thresholdStore = new RecordingDurableObjectNamespace();
  const service = createCloudflareD1RouterApiAuthService({
    database: database as never,
    ...SCOPE,
    routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
    ecdsaStrictRegistration: strictRegistration,
    thresholdStore: {
      kind: 'cloudflare-do',
      namespace: thresholdStore,
      THRESHOLD_PREFIX: 'registration-activate-test',
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-activate',
    },
  } as never);
  const signer = fakeGatewaySigner();
  const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
  const setup = await service.walletRegistration.setupWalletRegistration({
    request: {
      signerSelection: {
        kind: 'signer_set',
        signers: [
          {
            kind: 'evm_family_ecdsa',
            participantIds: [1, 2],
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
          },
        ],
      },
      authMethod: { kind: 'passkey', rpId },
    },
    orgId: SCOPE.orgId,
    expectedOrigin: 'https://app.example.com',
    signer,
    signingRootId: `${SCOPE.projectId}:${SCOPE.envId}`,
    signingRootVersion: 'root-activate-v1',
  } as never);
  if (!setup.ok) throw new Error(`setup: ${setup.code}: ${setup.message}`);

  const responded = await service.walletRegistration.respondWalletRegistration({
    registrationCeremonyId: setup.registrationCeremonyId,
    signedSetup: setup.signedSetup,
    authority: {
      kind: 'passkey',
      webauthnRegistration: await createWebAuthnRegistrationCredential({
        rpId,
        challengeB64u: setup.registrationIntentDigestB64u,
        origin: 'https://app.example.com',
      }),
    },
    ecdsa: {
      kind: 'router_ab_ecdsa_registration_v1',
      strictRegistration: buildFixtureRouterAbEcdsaStrictRegistrationRequest(
        setup.ecdsa.strictRegistration,
      ),
    },
    verifier: signer,
    minter: signer,
  } as never);
  if (!responded.ok) throw new Error(`respond: ${responded.code}: ${responded.message}`);

  const activateRequest = {
    registrationCeremonyId: setup.registrationCeremonyId,
    signedSetup: setup.signedSetup,
    idempotencyKey: 'activate-key-1',
    planKind: 'evm_family_ecdsa',
    session: signer,
    ecdsa: {
      activationCorrelationId: setup.registrationCeremonyId,
      activationRequestDigestB64u: base64UrlEncode(new Uint8Array(32)),
      clientActivation: fixtureRouterAbEcdsaActivationFacts(),
    },
    walletCustodyCommit: buildAcknowledgedWalletCustodyCommitPayloadFixture({
      walletId: setup.walletId,
    }),
    verifier: signer,
    minter: signer,
  };
  return { service, signer, setup, activateRequest, thresholdStore };
}

test('a conflicting activate retry is refused before any custody effect', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const strictRegistration = new CountingStrictRegistrationPort();
    const { service, setup, activateRequest } = await respondedCeremony(
      database,
      strictRegistration,
    );

    const first = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    /* The conflict case is only meaningful against a landed first activation. */
    if (!first.ok) throw new Error(`first activate: ${first.code}: ${first.message}`);
    const activateCallsAfterFirst = strictRegistration.activateCalls;

    /* Same idempotency key, different request bytes. The operation row must
       refuse this on fingerprint before invoking custody again — that is the
       whole point of binding the key to the digest. */
    const conflicting = await service.walletRegistration.activateWalletRegistration({
      ...activateRequest,
      /* Same key, different request bytes. */
      ecdsa: {
        ...activateRequest.ecdsa,
        clientActivation: {
          ...activateRequest.ecdsa.clientActivation,
          clientShareRetryCounter: 7,
        },
      },
    } as never);

    expect(conflicting, JSON.stringify(conflicting)).toMatchObject({
      ok: false,
      code: 'idempotency_conflict',
    });
    expect(strictRegistration.activateCalls).toBe(activateCallsAfterFirst);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('identical activate retries return one credential-free committed projection', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const strictRegistration = new CountingStrictRegistrationPort();
    const { service, setup, activateRequest, thresholdStore } = await respondedCeremony(
      database,
      strictRegistration,
    );

    const first = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    const firstSuccess = requireEcdsaActivateSuccess(first);
    const firstSession = requireIssuedRegistrationSession(firstSuccess);
    const custodyCallsAfterFirst = strictRegistration.activateCalls;

    const completion = await readRegistrationJournalRecord({
      database,
      scope: SCOPE,
      recordKey: `wallet-registration-activate:registration-activate:${setup.registrationCeremonyId}:${activateRequest.idempotencyKey}`,
    });
    expectCredentialFreeRegistrationJournal(
      completion,
      'registration_activate',
      firstSession.operationCredential.token,
    );
    if (!isRecordValue(completion) || !isRecordValue(completion.receipt)) {
      throw new Error('activation completion receipt is missing');
    }
    const requestFingerprint = completion.requestFingerprint;
    const receipt = completion.receipt;
    if (typeof requestFingerprint !== 'string' || !isRecordValue(receipt.committed)) {
      throw new Error('activation completion identity is missing');
    }
    if (!isRecordValue(receipt.committed.session)) {
      throw new Error('activation completion session projection is missing');
    }
    expect(completion.receipt.operationFingerprint).toBe(completion.requestFingerprint);
    expect(receipt.committed.session.expiresAtMs).toBe(
      firstSession.expiresAtMs,
    );

    const replayed = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    const replayedSuccess = requireEcdsaActivateSuccess(replayed);
    const replayedProjection = requireCommittedRegistrationProjection(replayedSuccess);
    const replayedAgain = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    const replayedAgainSuccess = requireEcdsaActivateSuccess(replayedAgain);
    const replayedAgainProjection = requireCommittedRegistrationProjection(replayedAgainSuccess);

    /* The receipt owns the committed identity. Replay carries no bearer and
       names the exact-method unlock required to obtain a successor. */
    expect(stableRegistrationCommitIdentity(replayedSuccess)).toBe(
      stableRegistrationCommitIdentity(firstSuccess),
    );
    expect(stableRegistrationCommitIdentity(replayedAgainSuccess)).toBe(
      stableRegistrationCommitIdentity(firstSuccess),
    );
    expect(replayedProjection.next).toBe('unlock_exact_method');
    expect(replayedProjection.session).toEqual(
      projectRegistrationEstablishedSessionV2(firstSession),
    );
    expect(replayedAgainProjection.session).toEqual(replayedProjection.session);
    expect('operationCredential' in replayedProjection).toBe(false);

    const parentRows = await database
      .prepare(
        `SELECT session.retired_at_ms AS session_retired_at_ms,
                quota.lifecycle_kind AS quota_lifecycle_kind,
                quota.remaining_uses AS quota_remaining_uses
           FROM wallet_session_authorizations_v2 AS session
           JOIN authorization_wallet_session_quotas AS quota
             ON quota.namespace = session.namespace
            AND quota.tenant_id = session.tenant_id
            AND quota.quota_id = session.quota_id
          WHERE session.namespace = ?1
            AND session.tenant_id = ?2
            AND session.wallet_session_id = ?3`,
      )
      .bind(
        SCOPE.namespace,
        service.authorizationSessions.tenantId,
        firstSession.walletSessionId,
      )
      .first<{
        readonly session_retired_at_ms?: unknown;
        readonly quota_lifecycle_kind?: unknown;
        readonly quota_remaining_uses?: unknown;
      }>();
    expect(parentRows).toMatchObject({
      session_retired_at_ms: null,
      quota_lifecycle_kind: 'active',
    });
    expect(Number(parentRows?.quota_remaining_uses)).toBe(3);

    /* No repeated custody effect. */
    expect(strictRegistration.activateCalls).toBe(custodyCallsAfterFirst);
    /* Both legs merged: the commit half's wallet keys plus the activation
       half's receipt and bootstrap. Returning only the commit half would
       leave the client unable to bring the wallet online. */
    expect(firstSuccess.ecdsa.walletKeys.length).toBeGreaterThan(0);
    expect(firstSuccess.ecdsa.activation).toBeTruthy();
    expect(firstSuccess.ecdsa.bootstrap).toBeTruthy();
    expect(replayedSuccess.ecdsa.activation).toBeTruthy();
    expect(thresholdStore.objectNames).toEqual([]);
    expect(replayedSuccess.ecdsa.bootstrap).toBeTruthy();
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('V2 registration parser rejects mismatched identity, signing capability, material, and family', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const { service, activateRequest } = await respondedCeremony(
      database,
      new CountingStrictRegistrationPort(),
    );
    const activated = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    const success = requireEcdsaActivateSuccess(activated);
    const issued = requireIssuedRegistrationSession(success);

    const mismatchedIdentity = clonedRecord(success.registrationEstablishedSession);
    const mismatchedIdentitySession = clonedRecord(mismatchedIdentity.session);
    const mismatchedWalletSession = clonedRecord(mismatchedIdentitySession.walletSession);
    if (typeof mismatchedWalletSession.authorizationId !== 'string') {
      throw new Error('fixture Wallet Session authorization id is missing');
    }
    mismatchedWalletSession.authorizationId = changedOpaqueId(
      mismatchedWalletSession.authorizationId,
    );
    mismatchedIdentitySession.walletSession = mismatchedWalletSession;
    mismatchedIdentity.session = mismatchedIdentitySession;
    expect(parseRegistrationEstablishedSessionResultV2(mismatchedIdentity)).toBeNull();

    const exportOnly = clonedRecord(success.registrationEstablishedSession);
    const exportOnlySession = clonedRecord(exportOnly.session);
    const exportOnlyWalletSession = clonedRecord(exportOnlySession.walletSession);
    if (!Array.isArray(exportOnlyWalletSession.capabilitySubjects)) {
      throw new Error('fixture capability subjects are missing');
    }
    const signingIndex = exportOnlyWalletSession.capabilitySubjects.findIndex(
      (subject) => isRecordValue(subject) && subject.kind === 'sign',
    );
    if (signingIndex < 0) throw new Error('fixture signing capability is missing');
    exportOnlyWalletSession.capabilitySubjects = exportOnlyWalletSession.capabilitySubjects.map(
      (subject, index) =>
        index === signingIndex && isRecordValue(subject)
          ? { ...subject, kind: 'export_keys' }
          : subject,
    );
    exportOnlySession.walletSession = exportOnlyWalletSession;
    exportOnly.session = exportOnlySession;
    expect(parseRegistrationEstablishedSessionResultV2(exportOnly)).toBeNull();

    const mismatchedMaterial = clonedRecord(success.registrationEstablishedSession);
    const mismatchedMaterialSession = clonedRecord(mismatchedMaterial.session);
    const mismatchedTokens = clonedRecord(mismatchedMaterialSession.tokens);
    const mismatchedEcdsa = clonedRecord(mismatchedTokens.ecdsa);
    const mismatchedActivation = clonedRecord(mismatchedEcdsa.materialActivation);
    if (typeof mismatchedActivation.activationId !== 'string') {
      throw new Error('fixture material activation id is missing');
    }
    mismatchedActivation.activationId = changedOpaqueId(mismatchedActivation.activationId);
    mismatchedEcdsa.materialActivation = mismatchedActivation;
    mismatchedTokens.ecdsa = mismatchedEcdsa;
    mismatchedMaterialSession.tokens = mismatchedTokens;
    mismatchedMaterial.session = mismatchedMaterialSession;
    expect(parseRegistrationEstablishedSessionResultV2(mismatchedMaterial)).toBeNull();

    const extraFamily = clonedRecord(success.registrationEstablishedSession);
    const extraFamilySession = clonedRecord(extraFamily.session);
    const extraFamilyWalletSession = clonedRecord(extraFamilySession.walletSession);
    if (!Array.isArray(extraFamilyWalletSession.capabilitySubjects)) {
      throw new Error('fixture capability subjects are missing');
    }
    const existingSigningSubject = extraFamilyWalletSession.capabilitySubjects.find(
      (subject) => isRecordValue(subject) && subject.kind === 'sign',
    );
    if (!isRecordValue(existingSigningSubject)) {
      throw new Error('fixture signing capability is missing');
    }
    extraFamilyWalletSession.capabilitySubjects = [
      ...extraFamilyWalletSession.capabilitySubjects,
      { ...existingSigningSubject, keyFamily: 'ed25519' },
    ];
    extraFamilySession.walletSession = extraFamilyWalletSession;
    extraFamily.session = extraFamilySession;
    expect(parseRegistrationEstablishedSessionResultV2(extraFamily)).toBeNull();

    expect(issued.operationCredential.token).toMatch(/^wst_/);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('activate refuses a ceremony whose authority proof is not yet verified', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const strictRegistration = new CountingStrictRegistrationPort();
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-activate' },
    });
    const service = createCloudflareD1RouterApiAuthService({
      database: database as never,
      ...SCOPE,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ecdsaStrictRegistration: strictRegistration,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'registration-activate-unverified',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-activate',
      },
    } as never);
    const signer = fakeGatewaySigner();
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    /* Setup only — respond never runs, so the ceremony is awaiting_proof. */
    const setup = await service.walletRegistration.setupWalletRegistration({
      request: {
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'evm_family_ecdsa',
              participantIds: [1, 2],
              chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
            },
          ],
        },
        authMethod: { kind: 'passkey', rpId },
      },
      orgId: SCOPE.orgId,
      expectedOrigin: 'https://app.example.com',
      signer,
      signingRootId: `${SCOPE.projectId}:${SCOPE.envId}`,
      signingRootVersion: 'root-activate-v1',
    } as never);
    if (!setup.ok) throw new Error(`${setup.code}: ${setup.message}`);

    const activated = await service.walletRegistration.activateWalletRegistration({
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      idempotencyKey: 'activate-unverified',
      ecdsa: { clientActivation: fixtureRouterAbEcdsaActivationFacts() },
      verifier: signer,
      minter: signer,
    } as never);

    expect(activated).toMatchObject({
      ok: false,
      code: 'invalid_state',
      message: 'registration ceremony has not verified its authority proof',
    });
    /* Refused before custody. */
    expect(strictRegistration.activateCalls).toBe(0);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('activate refuses a signedSetup that does not belong to the ceremony', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const strictRegistration = new CountingStrictRegistrationPort();
    const first = await respondedCeremony(database, strictRegistration);
    const other = await respondedCeremony(database, strictRegistration);
    const custodyCallsBefore = strictRegistration.activateCalls;

    const crossed = await first.service.walletRegistration.activateWalletRegistration({
      ...first.activateRequest,
      signedSetup: other.setup.signedSetup,
    } as never);

    expect(crossed).toMatchObject({ ok: false, code: 'invalid_grant' });
    expect(strictRegistration.activateCalls).toBe(custodyCallsBefore);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

/**
 * Refactor 94C. Ed25519-only registration on the three-route system.
 *
 * Its defining property is that it stays asynchronous: Yao is the wallet's
 * only signer, and that is deliberately not a reason to block. The wallet is
 * created in `near_pending` with no signer at all, and becomes signable when
 * the deferred computation completes.
 */

/** The commit validates a real curve point, not merely 33 bytes. */
async function compressedSecp256k1PubkeyB64u(): Promise<string> {
  const privateKey32 = new Uint8Array(32);
  privateKey32[31] = 7;
  return base64UrlEncode(await secp256k1PrivateKey32ToPublicKey33(privateKey32));
}

const ED_SCOPE = {
  namespace: 'registration-ed25519',
  orgId: 'org-ed25519',
  projectId: 'project-ed25519',
  envId: 'env-ed25519',
};

const ED25519_ONLY_PLAN = {
  kind: 'signer_set' as const,
  signers: [
    {
      kind: 'near_ed25519' as const,
      accountProvisioning: implicitNearAccountProvisioning(),
      signerSlot: 1,
      participantIds: [1, 2],
      derivationVersion: 1,
    },
  ],
};

async function ed25519OnlyCeremony(database: unknown) {
  const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
    config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519' },
  });
  const service = createCloudflareD1RouterApiAuthService({
    database: database as never,
    ...ED_SCOPE,
    routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
    ecdsaStrictRegistration: new CountingStrictRegistrationPort(),
    thresholdStore: {
      kind: 'cloudflare-do',
      namespace: new RecordingDurableObjectNamespace(),
      THRESHOLD_PREFIX: 'registration-ed25519-test',
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519',
    },
  } as never);
  const signer = fakeGatewaySigner();
  const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
  const setup = await service.walletRegistration.setupWalletRegistration({
    request: { signerSelection: ED25519_ONLY_PLAN, authMethod: { kind: 'passkey', rpId } },
    orgId: ED_SCOPE.orgId,
    expectedOrigin: 'https://app.example.com',
    signer,
    signingRootId: `${ED_SCOPE.projectId}:${ED_SCOPE.envId}`,
    signingRootVersion: 'root-ed25519-v1',
  } as never);
  return { service, signer, setup, rpId };
}

test('Ed25519-only setup skips ECDSA preparation entirely', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const { setup } = await ed25519OnlyCeremony(database);
    if (!setup.ok) throw new Error(`${setup.code}: ${setup.message}`);

    expect(setup.kind).toBe('near_ed25519');
    /* Not an empty preparation — no preparation at all. */
    expect('ecdsa' in setup).toBe(false);
    /* The challenge still exists: setup's job is the ceremony and the proof
       challenge, which this plan needs exactly as much as any other. */
    expect(setup.registrationIntentDigestB64u).toBeTruthy();
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

/**
 * A Yao runtime that admits whatever ceremony arrives.
 *
 * The convergence fixture mints against its own fixed ids, so it can only
 * satisfy its own ceremony. The receipt binding mirrors the admission request
 * scope, so building the fixture lazily from the first incoming request lets
 * one runtime serve a freshly generated ceremony — which is what makes a real
 * Ed25519-only path testable rather than only its error branches.
 */
function derivingYaoRuntime(capture?: {
  registrationBearerToken: string | null;
  /** The session the deferred leg must present to claim the Yao result. */
  activationSessionId?: readonly number[] | null;
  /** The public identity the deferred custody join must bind to. */
  registeredPublicKeyB64u?: string | null;
}) {
  let delegate: Awaited<ReturnType<typeof createActivatedFinalizeYaoRuntimeFixture>> | null = null;
  const runtime = {
    kind: 'router_ab_ed25519_yao_product_registration_runtime_v1' as const,
    signingWorkerId: 'signing-worker-ed25519',
    async bindAndAdmitVerifiedRegistration(input: {
      admissionRequest: never;
      registrationIntentGrant: unknown;
    }) {
      if (capture) capture.registrationBearerToken = String(input.registrationIntentGrant);
      /* The fixture admits and executes during construction, so its receipt
         is already the admitted one — re-admitting would collide with itself. */
      delegate = await createActivatedFinalizeYaoRuntimeFixture({
        admissionRequest: input.admissionRequest,
      });
      if (capture) {
        capture.activationSessionId = delegate.activationResult.binding.session_id;
        capture.registeredPublicKeyB64u = base64UrlEncode(
          Uint8Array.from(delegate.activationResult.public_receipt.registered_public_key),
        );
      }
      return { ok: true as const, value: delegate.admissionReceipt };
    },
    async consumeActivated(request: never) {
      if (!delegate) throw new Error('consumeActivated before admission');
      return await delegate.runtime.consumeActivated(request);
    },
  };
  return new Proxy(runtime, {
    get(target, prop, receiver) {
      if (prop in target) return Reflect.get(target, prop, receiver);
      /* Everything else (capability install/resolve, session minting) is the
         delegate's once it exists. */
      const current = delegate?.runtime as Record<string | symbol, unknown> | undefined;
      const value = current?.[prop];
      return typeof value === 'function' ? value.bind(current) : value;
    },
  });
}

test('Ed25519-only registration replay unlocks an exact successor and retires its predecessor', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519' },
    });
    const signer = fakeGatewaySigner();
    const yaoCredential = {
      registrationBearerToken: null as string | null,
      activationSessionId: null as readonly number[] | null,
      registeredPublicKeyB64u: null as string | null,
    };
    const service = createCloudflareD1RouterApiAuthService({
      database: database as never,
      ...ED_SCOPE,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ed25519YaoProductRegistration: derivingYaoRuntime(yaoCredential),
      ecdsaStrictRegistration: new CountingStrictRegistrationPort(),
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'registration-ed25519-e2e',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519',
      },
    } as never);
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));

    const setup = await service.walletRegistration.setupWalletRegistration({
      request: { signerSelection: ED25519_ONLY_PLAN, authMethod: { kind: 'passkey', rpId } },
      orgId: ED_SCOPE.orgId,
      expectedOrigin: 'https://app.example.com',
      signer,
      signingRootId: `${ED_SCOPE.projectId}:${ED_SCOPE.envId}`,
      signingRootVersion: 'root-ed25519-v1',
    } as never);
    if (!setup.ok) throw new Error(`setup: ${setup.code}: ${setup.message}`);
    expect(setup.kind).toBe('near_ed25519');
    expect('ecdsa' in setup).toBe(false);

    const responded = await service.walletRegistration.respondWalletRegistration({
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      planKind: 'near_ed25519',
      authority: {
        kind: 'passkey',
        webauthnRegistration: await createWebAuthnRegistrationCredential({
          rpId,
          challengeB64u: setup.registrationIntentDigestB64u,
          origin: 'https://app.example.com',
        }),
      },
      verifier: signer,
      minter: signer,
    } as never);
    if (!responded.ok) throw new Error(`respond: ${responded.code}: ${responded.message}`);
    /* Execute uses signedSetup as its Bearer credential, so admission must be
       bound to those exact bytes rather than the ceremony id it replaced. */
    expect(yaoCredential.registrationBearerToken).toBe(setup.signedSetup);
    /* Deferred, not blocking — the client starts Yao and moves on. */
    expect(responded.ed25519).toMatchObject({ status: 'deferred' });
    expect('ecdsa' in responded).toBe(false);

    const activateRequest = {
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      idempotencyKey: 'ed25519-e2e-activate',
      planKind: 'near_ed25519',
      session: signer,
      verifier: signer,
      minter: signer,
    };
    /* Yao has not resolved. Activate must still return a wallet. */
    const activated = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    if (!activated.ok) throw new Error(`activate: ${activated.code}: ${activated.message}`);
    expect(activated.nearProvisioning).toEqual({ status: 'near_pending' });
    expect('ecdsa' in activated).toBe(false);
    expect('resolvedAccount' in activated).toBe(false);

    /* Exact replay returns the same pending terminal. */
    const replayed = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    expect(replayed).toEqual(activated);

    const activationCompletion = await readRegistrationJournalRecord({
      database,
      scope: ED_SCOPE,
      recordKey: `wallet-registration-activate:registration-activate:${setup.registrationCeremonyId}:${activateRequest.idempotencyKey}`,
    });
    expectCredentialFreeRegistrationJournal(
      activationCompletion,
      'registration_activate',
      setup.signedSetup,
    );

    if (!yaoCredential.activationSessionId || !yaoCredential.registeredPublicKeyB64u) {
      throw new Error('Yao activation result is missing its deferred provisioning identity');
    }
    const custodyJoinFixture = buildWalletCustodyCommitPayloadFixture({
      walletId: setup.walletId,
      keySet: 'near_ed25519_v1',
    });
    const nearProvisioningRequest = {
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      idempotencyKey: 'ed25519-e2e-provisioning',
      ed25519: {
        activationReference: {
          lifecycle_id: setup.registrationCeremonyId,
          session_id: yaoCredential.activationSessionId,
        },
      },
      walletCustodyCommit: {
        walletId: custodyJoinFixture.walletId,
        keySet: custodyJoinFixture.keySet,
        keyManifestDigestB64u: custodyJoinFixture.keyManifestDigestB64u,
        registeredPublicKeyB64u: yaoCredential.registeredPublicKeyB64u,
      },
      verifier: signer,
      session: signer,
    };
    const provisioned = await service.walletRegistration.completeWalletRegistrationNearProvisioning(
      nearProvisioningRequest as never,
    );
    if (!provisioned.ok) {
      throw new Error(`near provisioning: ${provisioned.code}: ${provisioned.message}`);
    }
    expect(provisioned.nearProvisioning).toEqual({ status: 'near_ready' });

    const provisioningCompletion = await readRegistrationJournalRecord({
      database,
      scope: ED_SCOPE,
      recordKey: `wallet-registration-near-provisioning:near-provisioning:${setup.registrationCeremonyId}:ed25519-e2e-provisioning`,
    });
    if (provisioned.registrationEstablishedSession.kind !== 'issued') {
      throw new Error('deferred provisioning did not issue a Wallet Session');
    }
    const issuedProvisioningSession = provisioned.registrationEstablishedSession.session;
    const provisioningTokens = issuedProvisioningSession.tokens;
    if (provisioningTokens.kind !== 'near_ed25519') {
      throw new Error('deferred provisioning did not issue a NEAR session');
    }
    expectCredentialFreeRegistrationJournal(
      provisioningCompletion,
      'near_provisioning',
      issuedProvisioningSession.operationCredential.token,
    );

    const replayedProvisioning =
      await service.walletRegistration.completeWalletRegistrationNearProvisioning(
        nearProvisioningRequest as never,
      );
    if (!replayedProvisioning.ok) {
      throw new Error(
        `near provisioning replay: ${replayedProvisioning.code}: ${replayedProvisioning.message}`,
      );
    }
    if (replayedProvisioning.registrationEstablishedSession.kind !== 'already_committed') {
      throw new Error('deferred provisioning replay did not return its committed projection');
    }
    expect(replayedProvisioning.registrationEstablishedSession).toEqual({
      kind: 'already_committed',
      session: projectRegistrationEstablishedSessionV2(issuedProvisioningSession),
      next: 'unlock_exact_method',
    });
    expectCredentialFreeRegistrationReplay(
      replayedProvisioning.registrationEstablishedSession,
      issuedProvisioningSession.operationCredential.token,
    );

    /* A lost registration response leaves only this committed projection. The
       exact-method unlock must mint a successor directly, retiring the
       unreachable registration credential's session and quota in the same
       transaction. */
    const authority = replayedProvisioning.authority;
    if (!isPasskeyWalletAuthAuthority(authority)) {
      throw new Error('Ed25519-only passkey registration returned a non-passkey authority');
    }
    expect(String(replayedProvisioning.foundingAuthMethod.walletAuthMethodId)).toBe(
      String(authority.bindingId),
    );
    const siblingAuthority = buildPasskeyWalletAuthAuthority({
      walletId: authority.walletId,
      rpId,
      credentialIdB64u: 'registration-sibling-credential',
    });
    await insertWalletAuthMethod({
      database,
      ...ED_SCOPE,
      record: {
        kind: 'passkey',
        walletAuthMethodId: String(siblingAuthority.bindingId),
        walletAuthorityId: String(replayedProvisioning.foundingAuthority.authorityId),
        walletId: String(authority.walletId),
        rpId: String(rpId),
        credentialIdB64u: String(siblingAuthority.factor.credentialIdB64u),
        credentialPublicKeyB64u: 'registration-sibling-public-key',
        counter: 0,
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
      },
    });
    const siblingMethodBefore = await readWalletAuthMethodRecord({
      database,
      ...ED_SCOPE,
      walletAuthMethodId: String(siblingAuthority.bindingId),
    });
    const tenantId = requireParsedDomainId(parseTenantId(ED_SCOPE.orgId));
    const principalId = requireParsedDomainId(parsePrincipalId(String(authority.walletId)));
    const siblingMintId = requireParsedDomainId(
      parseWalletSessionMintId('wallet-mint:registration-sibling'),
    );
    const siblingIssuedAtMs = Date.now();
    const sibling = await service.authorizationSessions.issueDirectWalletSessionAuthorizationV2({
      tenantId,
      principalId,
      walletId: authority.walletId,
      authority: replayedProvisioning.foundingAuthority,
      walletAuthMethodId: siblingAuthority.bindingId,
      mintId: siblingMintId,
      remainingUses: 7,
      issuedAtMs: siblingIssuedAtMs,
      expiresAtMs: siblingIssuedAtMs + 300_000,
    });
    if (sibling.kind !== 'issued') {
      throw new Error('sibling Wallet Session fixture did not issue');
    }
    const siblingAuthorizationBefore =
      await service.authorizationSessions.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId,
        token: sibling.operationCredential.token,
        nowMs: siblingIssuedAtMs,
      });
    expect(siblingAuthorizationBefore).not.toBeNull();

    const unlockChallengeId = 'unlock:registration-replay-successor';
    const unlockVerifiedAtMs = Date.now();
    const unlockProof = await service.authorizedOperations.buildVerifiedOwnerProof({
      purpose: 'wallet_session',
      proofId: parseVerifiedOwnerProofId(`owner-proof:${unlockChallengeId}`),
      factor: buildVerifiedWalletSessionPasskeyFactorResult({
        tenantId,
        principalId,
        walletId: authority.walletId,
        authorityRef: await walletAuthAuthorityRef({ authority }),
        requestOrigin: 'https://wallet.example.test',
        audience: 'https://wallet.example.test',
        factorId: requireParsedDomainId(
          parseAuthFactorId(`passkey:${authority.factor.credentialIdB64u}`),
        ),
        credentialIdB64u: authority.factor.credentialIdB64u,
        assertionDigest: parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(9))),
        verifiedAtMs: unlockVerifiedAtMs,
        expiresAtMs: unlockVerifiedAtMs + 300_000,
      }),
    });
    const unlocked = await service.walletRegistration.provisionEd25519YaoWalletSession({
      walletId: String(authority.walletId),
      signerSlot: replayedProvisioning.ed25519.signerSlot,
      remainingUses: 1,
      verifiedChallengeId: unlockChallengeId,
      authority,
      walletSessionIdentity: { kind: 'new_wallet_session' },
      proof: unlockProof,
    } as never);
    expect(unlocked, JSON.stringify(unlocked)).toMatchObject({
      ok: true,
      session: {
        sessionKind: 'issued_exact_wallet_session',
        walletId: authority.walletId,
        remainingUses: 1,
      },
    });
    if (!unlocked.ok) throw new Error(unlocked.message);
    if (unlocked.session.sessionKind !== 'issued_exact_wallet_session') {
      throw new Error('exact-method unlock did not issue a successor Wallet Session');
    }
    expect(unlocked.session.operationCredential.walletSessionId).toBe(
      unlocked.session.walletSessionId,
    );
    expect(unlocked.session.walletSessionId).not.toBe(issuedProvisioningSession.walletSessionId);
    expect(unlocked.session.walletSessionId).not.toBe(sibling.session.walletSessionId);

    const predecessorState = await database
      .prepare(
        `SELECT session.wallet_auth_method_id, session.retired_at_ms,
                quota.remaining_uses, quota.lifecycle_kind
           FROM wallet_session_authorizations_v2 AS session
           JOIN authorization_wallet_session_quotas AS quota
             ON quota.namespace = session.namespace
            AND quota.tenant_id = session.tenant_id
            AND quota.quota_id = session.quota_id
          WHERE session.namespace = ?
            AND session.tenant_id = ?
            AND session.wallet_session_id = ?`,
      )
      .bind(ED_SCOPE.namespace, tenantId, String(issuedProvisioningSession.walletSessionId))
      .first<{
        readonly wallet_auth_method_id: string;
        readonly retired_at_ms: number | null;
        readonly remaining_uses: number;
        readonly lifecycle_kind: string;
      }>();
    expect(predecessorState).toMatchObject({
      wallet_auth_method_id: String(authority.bindingId),
      retired_at_ms: expect.any(Number),
      remaining_uses: 0,
      lifecycle_kind: 'exhausted',
    });

    const successorState = await database
      .prepare(
        `SELECT session.wallet_auth_method_id, session.retired_at_ms,
                quota.remaining_uses, quota.lifecycle_kind
           FROM wallet_session_authorizations_v2 AS session
           JOIN authorization_wallet_session_quotas AS quota
             ON quota.namespace = session.namespace
            AND quota.tenant_id = session.tenant_id
            AND quota.quota_id = session.quota_id
          WHERE session.namespace = ?
            AND session.tenant_id = ?
            AND session.wallet_session_id = ?`,
      )
      .bind(ED_SCOPE.namespace, tenantId, String(unlocked.session.walletSessionId))
      .first<{
        readonly wallet_auth_method_id: string;
        readonly retired_at_ms: number | null;
        readonly remaining_uses: number;
        readonly lifecycle_kind: string;
      }>();
    expect(successorState).toEqual({
      wallet_auth_method_id: String(authority.bindingId),
      retired_at_ms: null,
      remaining_uses: 1,
      lifecycle_kind: 'active',
    });

    const siblingAuthorizationAfter =
      await service.authorizationSessions.readWalletSessionAuthorizationV2ByOperationCredential({
        tenantId,
        token: sibling.operationCredential.token,
        nowMs: siblingIssuedAtMs,
      });
    const siblingMethodAfter = await readWalletAuthMethodRecord({
      database,
      ...ED_SCOPE,
      walletAuthMethodId: String(siblingAuthority.bindingId),
    });
    expect(siblingAuthorizationAfter).toEqual(siblingAuthorizationBefore);
    expect(siblingMethodAfter).toEqual(siblingMethodBefore);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Email OTP + Ed25519-only: enrollment persists with the pending wallet, before any signer', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519' },
    });
    const signer = fakeGatewaySigner();
    const service = createCloudflareD1RouterApiAuthService({
      database: database as never,
      ...ED_SCOPE,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ed25519YaoProductRegistration: derivingYaoRuntime(),
      ecdsaStrictRegistration: new CountingStrictRegistrationPort(),
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'registration-ed25519-otp',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519',
      },
      emailOtpDeliveryMode: 'dev_d1_outbox',
    } as never);

    const unlockPublicKeyB64u = await compressedSecp256k1PubkeyB64u();
    const email = 'ed25519-otp@example.test';
    const providerSubject = 'google:ed25519-otp-user';

    const setup = await service.walletRegistration.setupWalletRegistration({
      request: {
        signerSelection: ED25519_ONLY_PLAN,
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          providerSubject,
          otpCode: 'intent-otp-placeholder',
        },
      },
      orgId: ED_SCOPE.orgId,
      expectedOrigin: 'https://app.example.com',
      signer,
      signingRootId: `${ED_SCOPE.projectId}:${ED_SCOPE.envId}`,
      signingRootVersion: 'root-ed25519-v1',
    } as never);
    if (!setup.ok) throw new Error(`setup: ${setup.code}: ${setup.message}`);
    expect(setup.kind).toBe('near_ed25519');

    /* The challenge binds the digest setup issued, exactly as the passkey
       flow binds it into the WebAuthn create. */
    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: setup.walletId,
      orgId: ED_SCOPE.orgId,
      email,
      otpChannel: 'email_otp',
      ownerProofBindingDigest: setup.registrationIntentDigestB64u,
    });
    if (!challenge.ok) throw new Error(`challenge: ${challenge.message}`);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: setup.walletId,
    });
    if (!outbox.ok) throw new Error(`outbox: ${outbox.message}`);

    const responded = await service.walletRegistration.respondWalletRegistration({
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      planKind: 'near_ed25519',
      authority: {
        kind: 'email_otp',
        emailOtpRegistrationProof: {
          version: 'email_otp_registration_proof_v1',
          proofKind: 'otp_challenge',
          providerSubject,
          email,
          challengeId: challenge.challenge.challengeId,
          otpCode: outbox.otpCode,
          otpChannel: 'email_otp',
          registrationIntentDigestB64u: setup.registrationIntentDigestB64u,
        },
      },
      verifier: signer,
      minter: signer,
    } as never);
    if (!responded.ok) throw new Error(`respond: ${responded.code}: ${responded.message}`);
    expect(responded.ed25519).toMatchObject({ status: 'deferred' });

    const activateRequest = {
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      idempotencyKey: 'ed25519-otp-activate',
      planKind: 'near_ed25519',
      emailOtpEnrollment: {
        enrollmentSealKeyVersion: 'seal-v1',
        serverSealedFactorCiphertextB64u: 'sealed-factor-ed25519-otp',
        clientUnlockPublicKeyB64u: unlockPublicKeyB64u,
        unlockKeyVersion: 'unlock-v1',
      },
      session: signer,
      verifier: signer,
      minter: signer,
    };

    /* Yao is unresolved. The wallet must still be created, with its
       recovery-critical enrollment committed in the same transaction. */
    const activated = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    if (!activated.ok) throw new Error(`activate: ${activated.code}: ${activated.message}`);
    expect(activated.nearProvisioning).toEqual({ status: 'near_pending' });
    expect('ecdsa' in activated).toBe(false);
    expect('resolvedAccount' in activated).toBe(false);

    /* Enrollment landed even though no signer exists yet. */
    const enrollmentRows = (await database
      .prepare(`SELECT COUNT(*) AS count FROM email_otp_wallet_enrollments WHERE wallet_id = ?1`)
      .bind(setup.walletId)
      .first()) as { count?: number } | null;
    expect(Number(enrollmentRows?.count || 0)).toBeGreaterThan(0);

    const signerRows = (await database
      .prepare(`SELECT COUNT(*) AS count FROM wallet_signers WHERE wallet_id = ?1`)
      .bind(setup.walletId)
      .first()) as { count?: number } | null;
    expect(Number(signerRows?.count || 0)).toBe(0);

    /* Exact pending replay. */
    const replayed = await service.walletRegistration.activateWalletRegistration(
      activateRequest as never,
    );
    expect(replayed).toEqual(activated);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

/**
 * Refactor 100. The wallet custody commit rides the registration leg rather
 * than a route of its own: what may establish custody for a wallet is exactly
 * what may create that wallet, and a separate endpoint would be a second,
 * weaker way in.
 *
 * These pin where that commit actually happens, which is the thing easiest to
 * get wrong — an Ed25519-only wallet has no key set at activate, so wiring the
 * commit there alone would silently never fire for it.
 */

test('an activate carrying a custody payload commits it under the registered wallet', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const { service, setup, activateRequest } = await respondedCeremony(
      database,
      new CountingStrictRegistrationPort(),
    );

    const activated = await service.walletRegistration.activateWalletRegistration({
      ...activateRequest,
      walletCustodyCommit: buildAcknowledgedWalletCustodyCommitPayloadFixture({
        walletId: setup.walletId,
      }),
    } as never);
    if (!activated.ok) throw new Error(`activate: ${activated.code}: ${activated.message}`);

    expect(activated.walletCustody).toEqual({ status: 'committed' });

    /* The response is not the evidence — the stored recovery set is. A wallet
       whose codes never landed is a wallet nobody can recover. */
    const custodyStore = new CloudflareD1WalletCustodyCommitStore({
      database: database as never,
      scope: SCOPE,
    });
    const recoverySet = await custodyStore.readRecoveryEnvelopeSet(setup.walletId as never);
    expect(recoverySet?.record.manifestKekWraps).toHaveLength(10);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('an Ed25519-only wallet establishes custody on the deferred NEAR leg, not at activate', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519' },
    });
    const signer = fakeGatewaySigner();
    const yaoCapture = {
      registrationBearerToken: null as string | null,
      activationSessionId: null as readonly number[] | null,
      registeredPublicKeyB64u: null as string | null,
    };
    const service = createCloudflareD1RouterApiAuthService({
      database: database as never,
      ...ED_SCOPE,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ed25519YaoProductRegistration: derivingYaoRuntime(yaoCapture),
      ecdsaStrictRegistration: new CountingStrictRegistrationPort(),
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'registration-ed25519-custody',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-ed25519',
      },
    } as never);
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));

    const setup = await service.walletRegistration.setupWalletRegistration({
      request: { signerSelection: ED25519_ONLY_PLAN, authMethod: { kind: 'passkey', rpId } },
      orgId: ED_SCOPE.orgId,
      expectedOrigin: 'https://app.example.com',
      signer,
      signingRootId: `${ED_SCOPE.projectId}:${ED_SCOPE.envId}`,
      signingRootVersion: 'root-ed25519-v1',
    } as never);
    if (!setup.ok) throw new Error(`setup: ${setup.code}: ${setup.message}`);

    const responded = await service.walletRegistration.respondWalletRegistration({
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      planKind: 'near_ed25519',
      authority: {
        kind: 'passkey',
        webauthnRegistration: await createWebAuthnRegistrationCredential({
          rpId,
          challengeB64u: setup.registrationIntentDigestB64u,
          origin: 'https://app.example.com',
        }),
      },
      verifier: signer,
      minter: signer,
    } as never);
    if (!responded.ok) throw new Error(`respond: ${responded.code}: ${responded.message}`);

    /* Activate returns `near_pending`: the Yao computation has not resolved, so
       this wallet has no key set to seal custody against yet. */
    const activated = await service.walletRegistration.activateWalletRegistration({
      registrationCeremonyId: setup.registrationCeremonyId,
      signedSetup: setup.signedSetup,
      idempotencyKey: 'ed25519-custody-activate',
      planKind: 'near_ed25519',
      session: signer,
      verifier: signer,
      minter: signer,
    } as never);
    if (!activated.ok) throw new Error(`activate: ${activated.code}: ${activated.message}`);
    expect(activated.nearProvisioning).toEqual({ status: 'near_pending' });
    expect(activated.walletCustody).toBeUndefined();

    const custodyStore = new CloudflareD1WalletCustodyCommitStore({
      database: database as never,
      scope: ED_SCOPE,
    });
    expect(await custodyStore.readRecoveryEnvelopeSet(setup.walletId as never)).toBeNull();

    if (!yaoCapture.activationSessionId || !yaoCapture.registeredPublicKeyB64u) {
      throw new Error('Yao activation result is missing its deferred custody facts');
    }

    /* The deferred leg. This is the first point at which an Ed25519-only
       wallet has a key set at all, so it is where its custody is established —
       a commit wired only into activate would never fire for this wallet. */
    const provisioned = await service.walletRegistration.completeWalletRegistrationNearProvisioning(
      {
        registrationCeremonyId: setup.registrationCeremonyId,
        signedSetup: setup.signedSetup,
        idempotencyKey: 'ed25519-custody-provisioning',
        ed25519: {
          activationReference: {
            lifecycle_id: setup.registrationCeremonyId,
            session_id: yaoCapture.activationSessionId,
          },
        },
        walletCustodyCommit: buildAcknowledgedWalletCustodyCommitPayloadFixture({
          walletId: setup.walletId,
          keySet: 'near_ed25519_v1',
          registeredPublicKeyB64u: yaoCapture.registeredPublicKeyB64u,
        }),
        verifier: signer,
        session: signer,
      } as never,
    );
    if (!provisioned.ok) {
      throw new Error(`near provisioning: ${provisioned.code}: ${provisioned.message}`);
    }

    expect(provisioned.walletCustody).toEqual({ status: 'committed' });
    const recoverySet = await custodyStore.readRecoveryEnvelopeSet(setup.walletId as never);
    expect(recoverySet?.record.manifestKekWraps).toHaveLength(10);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
