import { expect, test } from '@playwright/test';
import {
  resumePendingPasskeyNearRegistrations,
  type PendingRegistrationRecoveryPorts,
} from '../../packages/wallet/src/SeamsWeb/operations/registration/pendingRegistrationRecovery';
import type { PublishPendingWalletRegistrationCommitInputV1 } from '../../packages/wallet/src/core/indexedDB/seamsWalletDB/repositories';
import { buildEcdsaActivationPublicationFixture } from './helpers/pendingWalletRegistrationPublication.fixtures';
import { buildPendingWalletRegistrationRecoveryFixture } from './helpers/pendingWalletRegistrationRecovery.fixtures';

test.describe('pending Passkey registration reload', () => {
  test('publishes a freshly issued session with the exact Route 4 request', async () => {
    const fixture = await buildPendingWalletRegistrationRecoveryFixture();
    const requests: unknown[] = [];
    const publications: PublishPendingWalletRegistrationCommitInputV1[] = [];
    const ports: PendingRegistrationRecoveryPorts = {
      listPendingWalletRegistrationCommits: async () => [fixture.pending],
      completeWalletRegistrationNearProvisioning: async (request) => {
        requests.push(request);
        return fixture.firstResponse;
      },
      publishPendingWalletRegistrationCommit: async (publication) => {
        publications.push(publication);
        return { signerActivations: [] };
      },
    };

    const results = await resumePendingPasskeyNearRegistrations({
      relayerUrl: 'https://relayer.example.test',
      ports,
    });

    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      kind: 'published',
      registrationCeremonyId: fixture.pending.registrationCeremonyId,
      walletId: fixture.pending.walletId,
      sessionResult: 'issued',
    });
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({
      relayerUrl: 'https://relayer.example.test',
      registrationCeremonyId: fixture.pending.registrationCeremonyId,
      signedSetup: fixture.pending.signedSetup,
      idempotencyKey: fixture.pending.idempotencyKey,
      ed25519: { activationReference: fixture.pending.localMaterial.ed25519.activationReference },
      auth: { kind: 'passkey' },
    });
    expect(publications).toHaveLength(1);
    expect(publications[0]).toMatchObject({
      pending: fixture.pending,
      request: {
        operation: 'near_provisioning',
        registrationCeremonyId: fixture.pending.registrationCeremonyId,
        idempotencyKey: fixture.pending.idempotencyKey,
        walletId: fixture.pending.walletId,
        walletAuthMethodId: fixture.pending.walletAuthMethodId,
      },
      walletSessionPublication: {
        kind: 'issued',
        walletSession: fixture.firstResponse.registrationEstablishedSession.session.walletSession,
        operationCredential:
          fixture.firstResponse.registrationEstablishedSession.session.operationCredential,
      },
      registration: {
        initialAuthMethod: {
          kind: 'passkey',
          rpId: fixture.pending.auth.rpId,
          credentialIdB64u: fixture.pending.auth.credentialIdB64u,
        },
      },
    });
    expect(publications[0]?.registration.authenticators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ credentialId: fixture.pending.auth.credentialIdB64u }),
      ]),
    );
  });

  test('retains a credential-free replay for exact-method unlock', async () => {
    const fixture = await buildPendingWalletRegistrationRecoveryFixture();
    const publications: PublishPendingWalletRegistrationCommitInputV1[] = [];
    const ports: PendingRegistrationRecoveryPorts = {
      listPendingWalletRegistrationCommits: async () => [fixture.pending],
      completeWalletRegistrationNearProvisioning: async () => fixture.replayResponse,
      publishPendingWalletRegistrationCommit: async (publication) => {
        publications.push(publication);
        return { signerActivations: [] };
      },
    };

    const results = await resumePendingPasskeyNearRegistrations({
      relayerUrl: 'https://relayer.example.test',
      ports,
    });

    expect(results[0]).toMatchObject({ kind: 'published', sessionResult: 'already_committed' });
    expect(publications).toHaveLength(1);
    expect(publications[0]?.walletSessionPublication).toEqual({
      kind: 'credential_free_projection',
    });
  });

  test('leaves non-NEAR and failed pending rows untouched', async () => {
    const fixture = await buildPendingWalletRegistrationRecoveryFixture();
    const ecdsa = await buildEcdsaActivationPublicationFixture();
    let completeCalls = 0;
    let publicationCalls = 0;
    const ports: PendingRegistrationRecoveryPorts = {
      listPendingWalletRegistrationCommits: async () => [fixture.pending, ecdsa.input.pending],
      completeWalletRegistrationNearProvisioning: async () => {
        completeCalls += 1;
        return { ok: false, code: 'temporary_failure', message: 'retry later' };
      },
      publishPendingWalletRegistrationCommit: async () => {
        publicationCalls += 1;
        return { signerActivations: [] };
      },
    };

    const results = await resumePendingPasskeyNearRegistrations({
      relayerUrl: 'https://relayer.example.test',
      ports,
    });

    expect(completeCalls).toBe(1);
    expect(publicationCalls).toBe(0);
    expect(results).toHaveLength(1);
    expect(results[0]).toMatchObject({
      kind: 'failed',
      registrationCeremonyId: fixture.pending.registrationCeremonyId,
      error: { message: 'pending Passkey registration replay failed: temporary_failure' },
    });
  });
});
