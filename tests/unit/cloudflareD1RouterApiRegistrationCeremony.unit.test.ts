import { expect, test } from '@playwright/test';
import type { CreateRegistrationIntentRequest } from '../../packages/sdk-server-ts/src/core/registrationContracts';
import { createLegacyCloudflareD1RouterApiAuthService as createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { parseD1RegistrationIntent } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  implicitNearAccountProvisioning,
  parseServerAllocatedWalletId,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import {
  requireParsedDomainId,
  RecordingDurableObjectNamespace,
  isRecordingDurableObjectReplayReservationRequest,
  recordingDurableObjectRequestKey,
  countRecordingDurableObjectRequests,
  recordingDurableObjectRequestsIncludeKey,
  applySignerMigrations,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';

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
