import { expect, test } from '@playwright/test';
import type {
  CreateRegistrationIntentRequest,
  CreateRegistrationIntentResponse,
  WalletRegistrationStartRequest,
} from '../../packages/sdk-server-ts/src/core/registrationContracts';
import {
  createCloudflareD1RouterApiAuthService as createPartitionedCloudflareD1RouterApiAuthService,
  createLegacyCloudflareD1RouterApiAuthService as createCloudflareD1RouterApiAuthService,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import { parseD1RegistrationIntent } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  implicitNearAccountProvisioning,
  parseServerAllocatedWalletId,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { FixtureRouterAbEcdsaStrictRegistrationPort } from '../helpers/routerAbSigningRuntimeTestUtils';
import {
  requireParsedDomainId,
  RecordingDurableObjectNamespace,
  isRecordingDurableObjectReplayReservationRequest,
  recordingDurableObjectRequestKey,
  countRecordingDurableObjectRequests,
  countD1VersionedJsonRecords,
  recordingDurableObjectRequestsIncludeKey,
  applySignerMigrations,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';

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

test('Cloudflare D1 Router API auth service stores wallet registration intents in Durable Objects', async () => {
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
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
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
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);
    expect(registration.intent.signerSelection).toEqual({
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
    });
    expect(parseServerAllocatedWalletId(registration.intent.walletId).ok).toBe(true);
    expect(String(registration.intent.walletId)).not.toMatch(/^seams-wallet-/);
    expect(Object.prototype.hasOwnProperty.call(registration.intent, 'rpId')).toBe(false);
    expect(registration.intent.authMethod).toMatchObject({ kind: 'passkey', rpId: 'example.com' });
    expect(registration.intent.runtimePolicyScope).toEqual({
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      signingRootVersion: 'root-v1',
    });
    const parsedStoredSignerSetIntent = parseD1RegistrationIntent({
      version: 'registration_intent_v1',
      walletId: registration.intent.walletId,
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
      runtimePolicyScope: registration.intent.runtimePolicyScope,
      nonceB64u: 'stored-nonce',
    });
    expect(parsedStoredSignerSetIntent?.signerSelection).toEqual(
      registration.intent.signerSelection,
    );

    const addSigner = await service.walletAuthMethods.createAddSignerIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId: registration.intent.walletId,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            participantIds: [3, 2, 1],
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
          },
        },
      },
    });
    expect(addSigner.ok).toBe(true);
    if (!addSigner.ok) throw new Error(addSigner.message);

    const addAuthMethod = await service.walletAuthMethods.createAddAuthMethodIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId: registration.intent.walletId,
        authMethod: { kind: 'email_otp', email: 'owner@example.test' },
      },
    });
    expect(addAuthMethod.ok).toBe(true);
    if (!addAuthMethod.ok) throw new Error(addAuthMethod.message);

    const prefix = 'intent-test:wallet-registration:';
    const registrationRecord = durableObjects.stub.values.get(
      `${prefix}intent:${registration.registrationIntentGrant}`,
    );
    expect(registrationRecord).toMatchObject({
      kind: 'intent_allocated',
      digestB64u: registration.registrationIntentDigestB64u,
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      intent: registration.intent,
    });
    const serverAllocatedWalletReservationRequest = durableObjects.stub.requests.find(
      isRecordingDurableObjectReplayReservationRequest,
    );
    expect(recordingDurableObjectRequestKey(serverAllocatedWalletReservationRequest || {})).toBe(
      `${prefix}server-allocated-wallet-reservation:${registration.intent.walletId}`,
    );

    const providedWalletId = walletIdFromString('frost-fjord-rgcmpa');
    const providedRegistration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
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
      },
    });
    expect(providedRegistration.ok).toBe(true);
    if (!providedRegistration.ok) throw new Error(providedRegistration.message);
    expect(providedRegistration.intent.walletId).toBe(providedWalletId);
    expect(parseServerAllocatedWalletId(providedRegistration.intent.walletId).ok).toBe(true);
    expect(
      recordingDurableObjectRequestsIncludeKey(
        durableObjects.stub.requests,
        `${prefix}server-allocated-wallet-reservation:${providedWalletId}`,
      ),
    ).toBe(true);

    const addSignerRecord = durableObjects.stub.values.get(
      `${prefix}add-signer-intent:${addSigner.addSignerIntentGrant}`,
    );
    expect(addSignerRecord).toMatchObject({
      kind: 'add_signer_intent_allocated',
      digestB64u: addSigner.addSignerIntentDigestB64u,
      orgId: scope.orgId,
      intent: addSigner.intent,
    });
    expect(addSigner.intent.signerSelection).toEqual({
      mode: 'ecdsa',
      ecdsa: {
        participantIds: [3, 2, 1],
        chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
      },
    });

    const addAuthMethodRecord = durableObjects.stub.values.get(
      `${prefix}add-auth-method-intent:${addAuthMethod.addAuthMethodIntentGrant}`,
    );
    expect(addAuthMethodRecord).toMatchObject({
      kind: 'add_auth_method_intent_allocated',
      digestB64u: addAuthMethod.addAuthMethodIntentDigestB64u,
      orgId: scope.orgId,
      intent: addAuthMethod.intent,
    });
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
    const service = createPartitionedCloudflareD1RouterApiAuthService({
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

    const prefix = 'intent-cancel-test:wallet-registration:';
    expect(
      countRecordingDurableObjectRequests({
        requests: durableObjects.stub.requests,
        op: 'del',
        key: `${prefix}server-allocated-wallet-reservation:${providedWalletId}`,
      }),
    ).toBe(1);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
