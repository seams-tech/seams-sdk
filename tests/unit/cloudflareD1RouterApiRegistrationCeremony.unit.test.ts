import { expect, test } from '@playwright/test';
import { parseCorrelationId } from '@shared/utils/canonicalPrimitives';
import type {
  CreateRegistrationIntentRequest,
  CreateRegistrationIntentResponse,
  WalletRegistrationStartRequest,
} from '../../packages/sdk-server-ts/src/core/registrationContracts';
import {
  buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch,
  findStoredWalletRegistrationEvmFamilyEcdsaBranch,
  type StoredWalletRegistrationCeremony,
} from '../../packages/sdk-server-ts/src/core/RegistrationCeremonyStore';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { buildRegistrationIntent } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords';
import { CloudflareD1RegistrationCeremonyIntentStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyStore';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  implicitNearAccountProvisioning,
  parseServerAllocatedWalletId,
  registrationNearEd25519BranchKey,
  registrationSignerPlanFromSelection,
  walletIdFromString,
  type RegistrationSignerSetSelection,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import {
  buildFixtureRouterAbEcdsaStrictRegistrationRequest,
  createRouterAbSigningRuntimesForUnitTests,
  fixtureRouterAbEcdsaActivationFacts,
  FixtureRouterAbEcdsaStrictRegistrationPort,
  SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort,
} from '../helpers/routerAbSigningRuntimeTestUtils';
import {
  createWebAuthnRegistrationCredential,
  fakeWebAuthnRegistrationCredential,
  requireParsedDomainId,
  RecordingDurableObjectNamespace,
  countD1VersionedJsonRecords,
  applySignerMigrations,
  readSignerWalletRecord,
  readWalletAuthMethodRecord,
  readWalletSignerRecord,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import { createActivatedFinalizeYaoRuntimeFixture } from './helpers/d1WalletRegistrationFinalizeConvergence.fixtures';

class StartClaimFaultD1PreparedStatement implements D1PreparedStatementLike {
  constructor(
    private readonly owner: StartClaimFaultD1Database,
    readonly delegate: D1PreparedStatementLike,
    readonly query: string,
    private readonly values: readonly unknown[],
  ) {}

  bind(...values: readonly unknown[]): D1PreparedStatementLike {
    return new StartClaimFaultD1PreparedStatement(
      this.owner,
      this.delegate.bind(...values),
      this.query,
      values,
    );
  }

  async first<T = unknown>(columnName?: string): Promise<T | null> {
    return await this.delegate.first<T>(columnName);
  }

  async all<T = unknown>(): Promise<D1ResultLike<T>> {
    return await this.delegate.all<T>();
  }

  async run<T = unknown>(): Promise<D1ResultLike<T>> {
    if (this.owner.consumeStartClaimFailure(this.query, this.values)) {
      throw new Error('Injected registration start-claim write failure');
    }
    return await this.delegate.run<T>();
  }
}

class StartClaimFaultD1Database implements D1DatabaseLike {
  private failNextStartClaim = false;
  private loseNextReceiptBatchResponse = false;

  constructor(private readonly delegate: D1DatabaseLike) {}

  armStartClaimFailure(): void {
    this.failNextStartClaim = true;
  }

  armReceiptBatchResponseLoss(): void {
    this.loseNextReceiptBatchResponse = true;
  }

  consumeStartClaimFailure(query: string, values: readonly unknown[]): boolean {
    if (!this.failNextStartClaim) return false;
    if (!query.includes('INSERT OR IGNORE INTO router_ab_yao_versioned_json_records')) return false;
    let targetsStartClaim = false;
    for (const value of values) {
      if (typeof value === 'string' && value.startsWith('wallet-registration-start:')) {
        targetsStartClaim = true;
        break;
      }
    }
    if (!targetsStartClaim) return false;
    this.failNextStartClaim = false;
    return true;
  }

  prepare(query: string): D1PreparedStatementLike {
    return new StartClaimFaultD1PreparedStatement(this, this.delegate.prepare(query), query, []);
  }

  async batch<T = unknown>(statements: readonly D1PreparedStatementLike[]): Promise<readonly T[]> {
    const delegates: D1PreparedStatementLike[] = [];
    let isReceiptBatch = false;
    for (const statement of statements) {
      if (!(statement instanceof StartClaimFaultD1PreparedStatement)) {
        throw new Error('Start-claim fault database received an unknown prepared statement');
      }
      delegates.push(statement.delegate);
      if (
        statement.query.includes('INSERT OR IGNORE INTO registration_ceremony_records') &&
        statement.query.includes('FROM email_otp_challenges')
      ) {
        isReceiptBatch = true;
      }
    }
    const results = await this.delegate.batch<T>(delegates);
    if (isReceiptBatch && this.loseNextReceiptBatchResponse) {
      this.loseNextReceiptBatchResponse = false;
      throw new Error('Injected Email OTP verification receipt batch response loss');
    }
    return results;
  }

  async exec(query: string): Promise<unknown> {
    return await this.delegate.exec(query);
  }
}

function emailOtpRegistrationStartRequest(input: {
  readonly registration: Extract<CreateRegistrationIntentResponse, { readonly ok: true }>;
  readonly providerSubject: string;
  readonly email: string;
  readonly challengeId: string;
  readonly otpCode: string;
  readonly appSessionVersion: string;
}): WalletRegistrationStartRequest {
  return {
    registrationIntentGrant: input.registration.registrationIntentGrant,
    registrationIntentDigestB64u: input.registration.registrationIntentDigestB64u,
    intent: input.registration.intent,
    authority: {
      kind: 'email_otp',
      emailOtpRegistrationProof: {
        version: 'email_otp_registration_proof_v1',
        proofKind: 'otp_challenge',
        providerSubject: input.providerSubject,
        email: input.email,
        challengeId: input.challengeId,
        otpCode: input.otpCode,
        otpChannel: 'email_otp',
        registrationIntentDigestB64u: input.registration.registrationIntentDigestB64u,
        appSessionVersion: input.appSessionVersion,
      },
    },
  };
}

function passkeyRegistrationStartRequest(input: {
  readonly registration: Extract<CreateRegistrationIntentResponse, { readonly ok: true }>;
  readonly webauthnRegistration: unknown;
}): WalletRegistrationStartRequest {
  return {
    registrationIntentGrant: input.registration.registrationIntentGrant,
    registrationIntentDigestB64u: input.registration.registrationIntentDigestB64u,
    intent: input.registration.intent,
    authority: {
      kind: 'passkey',
      webauthnRegistration: input.webauthnRegistration,
    },
  };
}

async function countPartitionedRegistrationRecords(input: {
  readonly database: D1DatabaseLike;
  readonly scope: {
    readonly namespace: string;
    readonly orgId: string;
    readonly projectId: string;
    readonly envId: string;
  };
  readonly recordScope: string;
}): Promise<number> {
  const row = await input.database
    .prepare(
      `SELECT COUNT(*) AS count
         FROM registration_ceremony_records
        WHERE namespace = ?1
          AND org_id = ?2
          AND project_id = ?3
          AND env_id = ?4
          AND record_scope = ?5`,
    )
    .bind(
      input.scope.namespace,
      input.scope.orgId,
      input.scope.projectId,
      input.scope.envId,
      input.recordScope,
    )
    .first<{ readonly count?: unknown }>();
  return Number(row?.count || 0);
}

test('partitioned D1 rejects invalid passkey registration authority before claiming the grant', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-passkey-authority-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = walletIdFromString('passkey-authority-wallet.testnet');
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const service = createCloudflareD1RouterApiAuthService({
      database,
      ...scope,
      ecdsaStrictRegistration: new FixtureRouterAbEcdsaStrictRegistrationPort(),
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'passkey-authority-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example.com',
      request: {
        wallet: { kind: 'provided', walletId },
        authMethod: { kind: 'passkey', rpId },
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
      },
    });
    if (!registration.ok) throw new Error(registration.message);
    await expect(
      service.walletRegistration.startWalletRegistration(
        passkeyRegistrationStartRequest({
          registration,
          webauthnRegistration: fakeWebAuthnRegistrationCredential({
            challengeB64u: 'wrong-registration-challenge',
            origin: 'https://app.example.com',
          }),
        }),
      ),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_mismatch' });
    await expect(
      countD1VersionedJsonRecords({
        database,
        ...scope,
        recordKeyPrefix: 'wallet-registration-start:',
      }),
    ).resolves.toBe(0);
    await expect(
      countPartitionedRegistrationRecords({ database, scope, recordScope: 'intent' }),
    ).resolves.toBe(1);

    await expect(
      service.walletRegistration.startWalletRegistration(
        passkeyRegistrationStartRequest({
          registration,
          webauthnRegistration: fakeWebAuthnRegistrationCredential({
            challengeB64u: registration.registrationIntentDigestB64u,
            origin: 'https://attacker.example.net',
          }),
        }),
      ),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_origin' });
    await expect(
      countD1VersionedJsonRecords({
        database,
        ...scope,
        recordKeyPrefix: 'wallet-registration-start:',
      }),
    ).resolves.toBe(0);
    await expect(
      countPartitionedRegistrationRecords({ database, scope, recordScope: 'intent' }),
    ).resolves.toBe(1);

    const started = await service.walletRegistration.startWalletRegistration(
      passkeyRegistrationStartRequest({
        registration,
        webauthnRegistration: await createWebAuthnRegistrationCredential({
          rpId,
          challengeB64u: registration.registrationIntentDigestB64u,
          origin: 'https://app.example.com',
        }),
      }),
    );
    if (!started.ok) throw new Error(JSON.stringify(started));
    expect(started.intent).toEqual(registration.intent);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

/**
 * Strips instrumentation before comparing a replay to its original. Timing
 * metrics are wall-clock and a replay does strictly less work, so they differ
 * by design; the registration payload must not.
 */
function withoutServerTimings<T>(value: T): T {
  if (Array.isArray(value)) return value.map(withoutServerTimings) as unknown as T;
  if (!value || typeof value !== 'object') return value;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([key]) => key !== 'gatewayServerTiming' && key !== 'registrationDiagnostics')
    .map(([key, entry]) => [key, withoutServerTimings(entry)]);
  return Object.fromEntries(entries) as T;
}

test('partitioned D1 completes and replays strict ECDSA wallet registration', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-strict-registration-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = walletIdFromString('strict-registration-wallet.testnet');
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const strictRegistration = new SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort();
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker' },
    });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      ...scope,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ecdsaStrictRegistration: strictRegistration,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'strict-registration-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example.com',
      request: {
        wallet: { kind: 'provided', walletId },
        authMethod: { kind: 'passkey', rpId },
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
      },
    });
    if (!registration.ok) throw new Error(registration.message);
    const startRequest = passkeyRegistrationStartRequest({
      registration,
      webauthnRegistration: await createWebAuthnRegistrationCredential({
        rpId,
        challengeB64u: registration.registrationIntentDigestB64u,
        origin: 'https://app.example.com',
      }),
    });
    const started = await service.walletRegistration.startWalletRegistration(startRequest);
    if (!started.ok) throw new Error(JSON.stringify(started));
    if (!started.ecdsa) throw new Error('Expected ECDSA registration start');
    expect(started.ecdsa.strictRegistration.registration_purpose).toBe('wallet_registration');
    await expect(service.walletRegistration.startWalletRegistration(startRequest)).resolves.toEqual(
      started,
    );

    const strictRequest = buildFixtureRouterAbEcdsaStrictRegistrationRequest(
      started.ecdsa.strictRegistration,
    );
    await expect(
      service.walletRegistration.respondWalletRegistrationEcdsaDerivation({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_v1',
          strictRegistration: {
            ...strictRequest,
            client_id: 'different-wallet.testnet',
          },
        },
      }),
    ).resolves.toMatchObject({ ok: false, code: 'scope_mismatch' });
    const responded = await service.walletRegistration.respondWalletRegistrationEcdsaDerivation({
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_v1',
        strictRegistration: strictRequest,
      },
    });
    if (!responded.ok) throw new Error(responded.message);
    expect(strictRegistration.registrationRequest).toEqual(strictRequest);
    const respondedReplay =
      await service.walletRegistration.respondWalletRegistrationEcdsaDerivation({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_v1',
          strictRegistration: strictRequest,
        },
      });
    /* The replay must return the same registration payload, but not the same
       timings: it reconciles instead of doing router and commit work, and the
       durations are wall-clock. Comparing those for equality made this assert
       both over-strict and flaky. */
    expect(withoutServerTimings(respondedReplay)).toEqual(withoutServerTimings(responded));

    const activationFacts = fixtureRouterAbEcdsaActivationFacts();
    const unconfiguredSigningService = createCloudflareD1RouterApiAuthService({
      database,
      ...scope,
      routerAbSigningRuntimes: null,
      ecdsaStrictRegistration: strictRegistration,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'strict-registration-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const activationRequest = {
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_activation_v1' as const,
        activationCorrelationId: parseCorrelationId('activation-correlation-registration'),
        publicFacts: activationFacts,
      },
    };
    const preparedActivation =
      await service.walletRegistration.prepareWalletRegistrationEcdsaActivation(activationRequest);
    if (!preparedActivation.ok) throw new Error(preparedActivation.message);
    const expectedActivationRequestDigest =
      preparedActivation.ecdsa.preparation.activation_request_digest;
    const activationCommitRequest = {
      registrationCeremonyId: activationRequest.registrationCeremonyId,
      ecdsa: {
        kind: activationRequest.ecdsa.kind,
        activationCorrelationId: activationRequest.ecdsa.activationCorrelationId,
        publicFacts: activationRequest.ecdsa.publicFacts,
        expectedActivationRequestDigest,
      },
    };
    await expect(
      service.walletRegistration.queryWalletRegistrationEcdsaActivation(activationCommitRequest),
    ).resolves.toMatchObject({
      ok: true,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_activation_queried_v1',
        result: { kind: 'not_committed' },
      },
    });
    await expect(
      service.walletRegistration.activateWalletRegistrationEcdsa({
        registrationCeremonyId: activationCommitRequest.registrationCeremonyId,
        ecdsa: {
          ...activationCommitRequest.ecdsa,
          expectedActivationRequestDigest: { bytes: new Array<number>(32).fill(13) },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'activation_digest_mismatch',
    });
    await expect(
      unconfiguredSigningService.walletRegistration.activateWalletRegistrationEcdsa(
        activationCommitRequest,
      ),
    ).resolves.toMatchObject({
      ok: false,
      code: 'ecdsa_activation_terminal_failure',
    });
    await expect(
      service.walletRegistration.queryWalletRegistrationEcdsaActivation(activationCommitRequest),
    ).resolves.toMatchObject({
      ok: true,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_activation_queried_v1',
        result: { kind: 'committed' },
      },
    });
    const activated =
      await service.walletRegistration.activateWalletRegistrationEcdsa(activationCommitRequest);
    if (!activated.ok) throw new Error(activated.message);
    expect(strictRegistration.activationPrepareCalls).toBe(4);
    const activatedReplay =
      await service.walletRegistration.activateWalletRegistrationEcdsa(activationCommitRequest);
    expect(withoutServerTimings(activatedReplay)).toEqual(withoutServerTimings(activated));
    expect(strictRegistration.activationPrepareCalls).toBe(4);

    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        kind: 'evm_family_ecdsa',
        registrationCeremonyId: started.registrationCeremonyId,
        idempotencyKey: 'strict-registration-wrong-key',
        ecdsa: { expectedKeyHandles: ['wrong-key-handle'] },
      }),
    ).resolves.toMatchObject({ ok: false, code: 'key_handle_mismatch' });

    const finalizeRequest = {
      kind: 'evm_family_ecdsa' as const,
      registrationCeremonyId: started.registrationCeremonyId,
      idempotencyKey: 'strict-registration-finalize',
      ecdsa: { expectedKeyHandles: [activated.ecdsa.bootstrap.keyHandle] },
    };
    const finalized = await service.walletRegistration.finalizeWalletRegistration(finalizeRequest);
    if (!finalized.ok || finalized.authMethod.kind !== 'passkey') {
      throw new Error('Expected passkey ECDSA registration result');
    }
    expect(finalized).toMatchObject({
      kind: 'evm_family_ecdsa',
      walletId,
      rpId,
      ecdsa: {
        walletKeys: [
          {
            walletId,
            keyHandle: activated.ecdsa.bootstrap.keyHandle,
            chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
          },
        ],
      },
    });
    /* Exact replay of the ECDSA finalize: same ceremony, same idempotency key,
       same body. It must converge on the identical result and must not commit
       a second effect — the replay record count below is what proves that. */
    /* Refactor 94B Phase 0. Whatever the role legs return, the gateway's own
       metric list stays fixed identifiers — a forwarded Server-Timing value
       carries role and span names and must never appear verbatim here. */
    const respondTimings = (
      responded as { gatewayServerTiming?: readonly (readonly [string, number])[] }
    ).gatewayServerTiming;
    expect(respondTimings).toBeDefined();
    const respondMetricNames = (respondTimings ?? []).map(([name]) => name);
    expect(respondMetricNames.length).toBeGreaterThan(0);
    for (const name of respondMetricNames) {
      /* Fixed identifiers only: no durations, separators, or quoting that a
         forwarded header value would have carried in with it. */
      expect(name).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(name).not.toContain('dur=');
    }

    const finalizedReplay =
      await service.walletRegistration.finalizeWalletRegistration(finalizeRequest);
    expect(withoutServerTimings(finalizedReplay)).toEqual(withoutServerTimings(finalized));
    await expect(
      countPartitionedRegistrationRecords({ database, scope, recordScope: 'ceremony' }),
    ).resolves.toBe(0);
    await expect(
      countPartitionedRegistrationRecords({ database, scope, recordScope: 'finalize-replay' }),
    ).resolves.toBe(1);
    await expect(readSignerWalletRecord({ database, ...scope, walletId })).resolves.toMatchObject({
      version: 'wallet_v1',
      walletId,
    });
    await expect(
      readWalletAuthMethodRecord({
        database,
        ...scope,
        walletAuthMethodId: `passkey:${rpId}:${finalized.authMethod.credentialIdB64u}`,
      }),
    ).resolves.toMatchObject({
      version: 'wallet_auth_method_v1',
      kind: 'passkey',
      status: 'active',
      walletId,
      rpId,
      credentialIdB64u: finalized.authMethod.credentialIdB64u,
    });
    await expect(
      readWalletSignerRecord({
        database,
        ...scope,
        walletId,
        signerFamily: 'ecdsa',
        signerId: 'ecdsa:evm:eip155:8453',
      }),
    ).resolves.toMatchObject({
      version: 'wallet_signer_ecdsa_v1',
      walletId,
      walletKey: { keyHandle: activated.ecdsa.bootstrap.keyHandle },
    });
    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        ...finalizeRequest,
        idempotencyKey: 'strict-registration-after-cleanup',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'not_found' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('mixed registration preserves deferred Ed25519 finalize across exact ECDSA replay', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'registration-finalize-convergence',
      orgId: 'org-finalize',
      projectId: 'project-finalize',
      envId: 'env-finalize',
    };
    const yao = await createActivatedFinalizeYaoRuntimeFixture();
    const walletId = walletIdFromString(yao.admissionRequest.application_binding.wallet_id);
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const strictRegistration = new SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort();
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-finalize' },
    });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      ...scope,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ed25519YaoProductRegistration: yao.runtime,
      ecdsaStrictRegistration: strictRegistration,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'mixed-finalize-replay-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-finalize',
      },
    });
    const ecdsaSigner = {
      kind: 'evm_family_ecdsa' as const,
      participantIds: [1, 2] as const,
      chainTargets: [{ kind: 'evm' as const, namespace: 'eip155' as const, chainId: 8453 }],
    };
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-finalize-v1',
      expectedOrigin: 'https://app.example.com',
      request: {
        wallet: { kind: 'provided', walletId },
        authMethod: { kind: 'passkey', rpId },
        signerSelection: { kind: 'signer_set', signers: [ecdsaSigner] },
      },
    });
    if (!registration.ok) throw new Error(registration.message);
    const started = await service.walletRegistration.startWalletRegistration(
      passkeyRegistrationStartRequest({
        registration,
        webauthnRegistration: await createWebAuthnRegistrationCredential({
          rpId,
          challengeB64u: registration.registrationIntentDigestB64u,
          origin: 'https://app.example.com',
        }),
      }),
    );
    if (!started.ok || !started.ecdsa) throw new Error('Expected mixed fixture ECDSA start');
    const strictRequest = buildFixtureRouterAbEcdsaStrictRegistrationRequest(
      started.ecdsa.strictRegistration,
    );
    const responded = await service.walletRegistration.respondWalletRegistrationEcdsaDerivation({
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: { kind: 'router_ab_ecdsa_registration_v1', strictRegistration: strictRequest },
    });
    if (!responded.ok) throw new Error(responded.message);
    const activationFacts = fixtureRouterAbEcdsaActivationFacts();
    const activationCorrelationId = parseCorrelationId('mixed-finalize-replay-activation');
    const activationPreparation =
      await service.walletRegistration.prepareWalletRegistrationEcdsaActivation({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activation_v1',
          activationCorrelationId,
          publicFacts: activationFacts,
        },
      });
    if (!activationPreparation.ok) throw new Error(activationPreparation.message);
    const activated = await service.walletRegistration.activateWalletRegistrationEcdsa({
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_activation_v1',
        activationCorrelationId,
        publicFacts: activationFacts,
        expectedActivationRequestDigest:
          activationPreparation.ecdsa.preparation.activation_request_digest,
      },
    });
    if (!activated.ok) throw new Error(activated.message);

    const mixedSelection: RegistrationSignerSetSelection = {
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: implicitNearAccountProvisioning(),
          signerSlot: 1,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
        ecdsaSigner,
      ],
    };
    const mixedPlan = registrationSignerPlanFromSelection(mixedSelection);
    if (!mixedPlan.ok) throw new Error(mixedPlan.message);
    const ceremonyStore = new CloudflareD1RegistrationCeremonyIntentStore({
      kind: 'partitioned_d1',
      database,
      scope,
      keyPrefix: 'gateway-registration:',
    });
    const ceremony = await ceremonyStore.getCeremony(started.registrationCeremonyId);
    if (!ceremony || ceremony.signerState.kind !== 'signer_set_registration') {
      throw new Error('Expected activated ECDSA ceremony');
    }
    if (!ceremony.intent.runtimePolicyScope || !ceremony.expectedOrigin) {
      throw new Error('Expected mixed fixture ceremony scope');
    }
    const mixedCeremony: StoredWalletRegistrationCeremony = {
      registrationCeremonyId: ceremony.registrationCeremonyId,
      intent: buildRegistrationIntent({
        walletId,
        authMethod: { kind: 'passkey', rpId },
        signerSelection: mixedSelection,
        runtimePolicyScope: ceremony.intent.runtimePolicyScope,
      }),
      digestB64u: ceremony.digestB64u,
      signerPlan: mixedPlan.value,
      preparedContext: ceremony.preparedContext,
      orgId: ceremony.orgId,
      signingRootId: ceremony.signingRootId,
      signingRootVersion: ceremony.signingRootVersion,
      expectedOrigin: ceremony.expectedOrigin,
      expiresAtMs: ceremony.expiresAtMs,
      authorityState: ceremony.authorityState,
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          buildStoredWalletRegistrationNearEd25519YaoAuthorizedBranch({
            branchKey: registrationNearEd25519BranchKey(1),
            admissionRequest: yao.admissionRequest,
            admissionReceipt: yao.admissionReceipt,
          }),
          ...ceremony.signerState.branches,
        ],
      },
    };
    await ceremonyStore.updateCeremony({ expected: ceremony, next: mixedCeremony });

    const ecdsaFinalizeRequest = {
      kind: 'evm_family_ecdsa' as const,
      registrationCeremonyId: started.registrationCeremonyId,
      idempotencyKey: 'mixed-registration-ecdsa-finalize',
      ecdsa: { expectedKeyHandles: [activated.ecdsa.bootstrap.keyHandle] },
    };
    const ecdsaFinalized =
      await service.walletRegistration.finalizeWalletRegistration(ecdsaFinalizeRequest);
    if (!ecdsaFinalized.ok) throw new Error(JSON.stringify(ecdsaFinalized));
    expect(ecdsaFinalized).toMatchObject({ kind: 'evm_family_ecdsa' });
    await database
      .prepare(
        `UPDATE registration_ceremony_records
            SET record_json = json_remove(
              json_set(
                record_json,
                '$.signerState.branches[1].kind',
                'evm_family_ecdsa_activated'
              ),
              '$.signerState.branches[1].finalizedAtMs'
            )
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_scope = 'ceremony'`,
      )
      .bind(scope.namespace, scope.orgId, scope.projectId, scope.envId)
      .run();
    const interruptedCeremony = await ceremonyStore.getCeremony(started.registrationCeremonyId);
    if (!interruptedCeremony || interruptedCeremony.signerState.kind !== 'signer_set_registration') {
      throw new Error('Expected interrupted mixed registration ceremony');
    }
    expect(
      findStoredWalletRegistrationEvmFamilyEcdsaBranch(interruptedCeremony.signerState)?.kind,
    ).toBe('evm_family_ecdsa_activated');
    await database
      .prepare(
        `DELETE FROM router_ab_yao_versioned_json_records
          WHERE record_key LIKE 'wallet-registration-finalize:%'`,
      )
      .run();
    const ecdsaReplay =
      await service.walletRegistration.finalizeWalletRegistration(ecdsaFinalizeRequest);
    expect(withoutServerTimings(ecdsaReplay)).toEqual(withoutServerTimings(ecdsaFinalized));
    const reconciledCeremony = await ceremonyStore.getCeremony(started.registrationCeremonyId);
    if (!reconciledCeremony || reconciledCeremony.signerState.kind !== 'signer_set_registration') {
      throw new Error('Expected reconciled mixed registration ceremony');
    }
    expect(
      findStoredWalletRegistrationEvmFamilyEcdsaBranch(reconciledCeremony.signerState)?.kind,
    ).toBe('evm_family_ecdsa_finalized');
    await expect(
      countPartitionedRegistrationRecords({ database, scope, recordScope: 'ceremony' }),
    ).resolves.toBe(1);

    const ed25519Finalized = await service.walletRegistration.finalizeWalletRegistration({
      kind: 'near_ed25519',
      registrationCeremonyId: started.registrationCeremonyId,
      idempotencyKey: 'mixed-registration-ed25519-finalize',
      ed25519: {
        activationReference: {
          kind: 'router_ab_ed25519_yao_activation_reference_v1',
          lifecycle_id: yao.admissionRequest.scope.lifecycle_id,
          session_id: yao.activationResult.binding.session_id,
        },
      },
    });
    if (!ed25519Finalized.ok) throw new Error(JSON.stringify(ed25519Finalized));
    expect(ed25519Finalized).toMatchObject({ kind: 'near_ed25519' });
    await expect(
      countPartitionedRegistrationRecords({ database, scope, recordScope: 'ceremony' }),
    ).resolves.toBe(0);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('partitioned D1 resumes Email OTP registration after verification precedes the start claim', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const faultDatabase = new StartClaimFaultD1Database(database);
    const scope = {
      namespace: 'seams-otp-receipt-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = walletIdFromString('otp-receipt-wallet.testnet');
    const providerSubject = 'google:otp-receipt-user';
    const email = 'receipt.user@example.test';
    const appSessionVersion = 'otp-receipt-session-v1';
    const service = createCloudflareD1RouterApiAuthService({
      database: faultDatabase,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      emailOtpMaxAttempts: 4,
      ecdsaStrictRegistration: new FixtureRouterAbEcdsaStrictRegistrationPort(),
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'otp-receipt-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'provided', walletId },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
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
      },
    });
    if (!registration.ok) throw new Error(registration.message);
    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId,
    });
    if (!outbox.ok) throw new Error(outbox.message);
    const wrongOtpCode = outbox.otpCode === '000000' ? '111111' : '000000';
    const wrongRequest = emailOtpRegistrationStartRequest({
      registration,
      providerSubject,
      email,
      challengeId: challenge.challenge.challengeId,
      otpCode: wrongOtpCode,
      appSessionVersion,
    });
    await expect(
      service.walletRegistration.startWalletRegistration(wrongRequest),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_otp' });
    await expect(
      countD1VersionedJsonRecords({
        database,
        ...scope,
        recordKeyPrefix: 'wallet-registration-start:',
      }),
    ).resolves.toBe(0);
    const receiptBeforeSuccess = await database
      .prepare(
        `SELECT COUNT(*) AS count
           FROM registration_ceremony_records
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_scope = 'email-otp-registration-verification-v1'`,
      )
      .bind(scope.namespace, scope.orgId, scope.projectId, scope.envId)
      .first<{ readonly count?: unknown }>();
    expect(Number(receiptBeforeSuccess?.count || 0)).toBe(0);

    const exactRequest = emailOtpRegistrationStartRequest({
      registration,
      providerSubject,
      email,
      challengeId: challenge.challenge.challengeId,
      otpCode: outbox.otpCode,
      appSessionVersion,
    });
    faultDatabase.armReceiptBatchResponseLoss();
    faultDatabase.armStartClaimFailure();
    await expect(
      service.walletRegistration.startWalletRegistration(exactRequest),
    ).resolves.toMatchObject({ ok: false, code: 'internal' });
    await expect(
      countD1VersionedJsonRecords({
        database,
        ...scope,
        recordKeyPrefix: 'wallet-registration-start:',
      }),
    ).resolves.toBe(0);
    const receiptRow = await database
      .prepare(
        `SELECT record_json
           FROM registration_ceremony_records
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_scope = 'email-otp-registration-verification-v1'
            AND record_id = ?5`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        challenge.challenge.challengeId,
      )
      .first<{ readonly record_json?: unknown }>();
    expect(typeof receiptRow?.record_json).toBe('string');
    const receiptJson = String(receiptRow?.record_json || '');
    expect(receiptJson).not.toContain(outbox.otpCode);
    expect(receiptJson).not.toContain(registration.registrationIntentGrant);
    const consumedChallenge = await database
      .prepare(
        `SELECT challenge_id
           FROM email_otp_challenges
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND challenge_id = ?5`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        challenge.challenge.challengeId,
      )
      .first();
    expect(consumedChallenge).toBeNull();

    await expect(
      service.walletRegistration.startWalletRegistration(wrongRequest),
    ).resolves.toMatchObject({ ok: false, code: 'verification_receipt_conflict' });
    const started = await service.walletRegistration.startWalletRegistration(exactRequest);
    if (!started.ok) throw new Error(started.message);
    expect(started.intent).toEqual(registration.intent);
    await expect(service.walletRegistration.startWalletRegistration(exactRequest)).resolves.toEqual(
      started,
    );
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service cancels unconsumed registration intent wallet reservations', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-cancel-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const providedWalletId = walletIdFromString('frost-vermillion-k7p9m2');
    const request = {
      wallet: { kind: 'provided', walletId: providedWalletId },
      authMethod: { kind: 'passkey', rpId },
      signerSelection: {
        kind: 'signer_set',
        signers: [
          {
            kind: 'near_ed25519',
            accountProvisioning: implicitNearAccountProvisioning(),
            signerSlot: 1,
            participantIds: [1, 2, 3],
            derivationVersion: 1,
          },
        ],
      },
    } satisfies CreateRegistrationIntentRequest;
    const createInput = {
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request,
    };

    const registration = await service.walletRegistration.createRegistrationIntent(createInput);
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);
    expect(parseServerAllocatedWalletId(registration.intent.walletId).ok).toBe(true);

    await expect(
      service.walletRegistration.createRegistrationIntent(createInput),
    ).resolves.toMatchObject({
      ok: false,
      message: 'walletId is already reserved',
    });

    await expect(
      service.walletRegistration.cancelRegistrationIntent({
        request: {
          registrationIntentGrant: registration.registrationIntentGrant,
          registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        },
      }),
    ).resolves.toEqual({
      ok: true,
      cancelled: true,
      releasedServerAllocatedWalletId: true,
    });

    const recreated = await service.walletRegistration.createRegistrationIntent(createInput);
    expect(recreated.ok).toBe(true);
    if (!recreated.ok) throw new Error(recreated.message);
    expect(recreated.intent.walletId).toBe(providedWalletId);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

/**
 * Refactor 94C. `/wallets/register/setup` creates the ceremony before the
 * client's WebAuthn create runs, because setup issues the challenge that
 * create must sign. The stored authority is therefore a two-arm state, and
 * every leg that persists wallet identity has to refuse the arm that has not
 * been proved. This asserts the refusal directly: a ceremony rewritten back to
 * `awaiting_proof` cannot be finalized even though its ECDSA branch is fully
 * activated and would otherwise commit.
 */
test('finalize refuses a registration ceremony that is still awaiting its authority proof', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'registration-awaiting-proof',
      orgId: 'org-awaiting',
      projectId: 'project-awaiting',
      envId: 'env-awaiting',
    };
    const walletId = walletIdFromString('awaiting-proof-wallet');
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-awaiting' },
    });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      ...scope,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ecdsaStrictRegistration: new SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort(),
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new RecordingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'awaiting-proof-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker-awaiting',
      },
    });
    const ecdsaSigner = {
      kind: 'evm_family_ecdsa' as const,
      participantIds: [1, 2] as const,
      chainTargets: [{ kind: 'evm' as const, namespace: 'eip155' as const, chainId: 8453 }],
    };
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-awaiting-v1',
      expectedOrigin: 'https://app.example.com',
      request: {
        wallet: { kind: 'provided', walletId },
        authMethod: { kind: 'passkey', rpId },
        signerSelection: { kind: 'signer_set', signers: [ecdsaSigner] },
      },
    });
    if (!registration.ok) throw new Error(registration.message);
    const started = await service.walletRegistration.startWalletRegistration(
      passkeyRegistrationStartRequest({
        registration,
        webauthnRegistration: await createWebAuthnRegistrationCredential({
          rpId,
          challengeB64u: registration.registrationIntentDigestB64u,
          origin: 'https://app.example.com',
        }),
      }),
    );
    if (!started.ok || !started.ecdsa) throw new Error('Expected ECDSA start');
    const responded = await service.walletRegistration.respondWalletRegistrationEcdsaDerivation({
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_v1',
        strictRegistration: buildFixtureRouterAbEcdsaStrictRegistrationRequest(
          started.ecdsa.strictRegistration,
        ),
      },
    });
    if (!responded.ok) throw new Error(responded.message);
    const activated = await service.walletRegistration.activateWalletRegistrationEcdsa({
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_activation_v1',
        publicFacts: fixtureRouterAbEcdsaActivationFacts(),
      },
    });
    if (!activated.ok) throw new Error(activated.message);

    const ceremonyStore = new CloudflareD1RegistrationCeremonyIntentStore({
      kind: 'partitioned_d1',
      database,
      scope,
      keyPrefix: 'gateway-registration:',
    });
    const ceremony = await ceremonyStore.getCeremony(started.registrationCeremonyId);
    if (!ceremony) throw new Error('Expected activated ECDSA ceremony');
    expect(ceremony.authorityState.kind).toBe('verified');
    await ceremonyStore.updateCeremony({
      expected: ceremony,
      next: {
        ...ceremony,
        authorityState: { kind: 'awaiting_proof', authMethod: { kind: 'passkey', rpId } },
      },
    });
    /* The awaiting arm must survive a storage round trip as itself; a parser
       that silently dropped it would make this test pass for the wrong
       reason by making the ceremony unreadable. */
    const reloaded = await ceremonyStore.getCeremony(started.registrationCeremonyId);
    expect(reloaded?.authorityState).toEqual({
      kind: 'awaiting_proof',
      authMethod: { kind: 'passkey', rpId },
    });

    const finalized = await service.walletRegistration.finalizeWalletRegistration({
      kind: 'evm_family_ecdsa',
      registrationCeremonyId: started.registrationCeremonyId,
      idempotencyKey: 'awaiting-proof-finalize',
      ecdsa: { expectedKeyHandles: [activated.ecdsa.bootstrap.keyHandle] },
    });
    /* Finalize has other `invalid_state` paths (Email OTP enrollment
       mismatches); pin the message so this asserts the authority guard and
       not one of those. */
    expect(finalized).toMatchObject({
      ok: false,
      code: 'invalid_state',
      message: 'registration ceremony has not verified its authority proof',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
