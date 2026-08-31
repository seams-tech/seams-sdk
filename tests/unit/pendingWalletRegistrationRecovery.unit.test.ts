import { expect, test } from '@playwright/test';
import {
  resumePendingEcdsaRegistration,
  resumePendingMixedRegistration,
  resumePendingNearRegistrations,
  type PendingMixedRegistrationRecoveryPorts,
  type PendingRegistrationRecoveryPorts,
} from '../../packages/wallet/src/SeamsWeb/operations/registration/pendingRegistrationRecovery';
import {
  pendingEcdsaActivateRequest,
  type PendingEcdsaOnlyRegistrationCommit,
  type PendingEcdsaRegistrationRecoveryPorts,
  type PendingEcdsaRegistrationUnlockInput,
  type PendingRegistrationRecoverySigningSurface,
} from '../../packages/wallet/src/SeamsWeb/operations/registration/pendingEcdsaRegistrationRecoveryValidation';
import { finalizeWalletRegistrationEcdsaSessions } from '../../packages/wallet/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import type { PublishPendingWalletRegistrationCommitInputV1 } from '../../packages/wallet/src/core/indexedDB/seamsWalletDB/repositories';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  buildEcdsaActivationPublicationFixture,
  buildMixedActivationPublicationFixture,
} from './helpers/pendingWalletRegistrationPublication.fixtures';
import { buildPendingEcdsaRegistrationRecoveryFixture } from './helpers/pendingEcdsaRegistrationRecovery.fixtures';
import { buildPendingMixedRegistrationRecoveryFixture } from './helpers/pendingMixedRegistrationRecovery.fixtures';
import { deriveNearProvisioningIdempotencyKey } from '../../packages/wallet/src/SeamsWeb/operations/registration/registration';
import {
  buildEmailOtpWalletRegistrationRecoveryFixture,
  buildPendingWalletRegistrationRecoveryFixture,
} from './helpers/pendingWalletRegistrationRecovery.fixtures';

const signingSurfaceForUnlockDispatch: PendingRegistrationRecoverySigningSurface = {
  finalizeWalletRegistrationEcdsaSessions: async () => {
    throw new Error('Email OTP dispatch test must stop at the unlock port');
  },
  rejoinWalletCustodyEvmFamilyKeySet: async () => {
    throw new Error('Email OTP dispatch test must stop at the unlock port');
  },
  getAuthenticationCredentialsSerialized: async () => {
    throw new Error('Email OTP dispatch test must stop at the unlock port');
  },
  getSignerWorkerContext: () => {
    throw new Error('Email OTP dispatch test must stop at the unlock port');
  },
};

const signingSurfaceForInjectedUnlock: PendingRegistrationRecoverySigningSurface = {
  finalizeWalletRegistrationEcdsaSessions: finalizeWalletRegistrationEcdsaSessions,
  rejoinWalletCustodyEvmFamilyKeySet: async () => {
    throw new Error('pending registration recovery test should use the injected unlock port');
  },
  getAuthenticationCredentialsSerialized: async () => {
    throw new Error('pending registration recovery test should use the injected unlock port');
  },
  getSignerWorkerContext: () => {
    throw new Error('pending registration recovery test should use the injected unlock port');
  },
};

test.describe('pending registration reload', () => {
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

    const results = await resumePendingNearRegistrations({
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

  test('replays Email OTP enrollment and publishes the issued session', async () => {
    const fixture = await buildEmailOtpWalletRegistrationRecoveryFixture();
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

    const results = await resumePendingNearRegistrations({
      relayerUrl: 'https://relayer.example.test',
      ports,
    });

    expect(results).toMatchObject([
      {
        kind: 'published',
        registrationCeremonyId: fixture.pending.registrationCeremonyId,
        walletId: fixture.pending.walletId,
        sessionResult: 'issued',
      },
    ]);
    expect(requests).toEqual([
      expect.objectContaining({
        registrationCeremonyId: fixture.pending.registrationCeremonyId,
        signedSetup: fixture.pending.signedSetup,
        idempotencyKey: fixture.pending.idempotencyKey,
        ed25519: { activationReference: fixture.pending.localMaterial.ed25519.activationReference },
        auth: {
          kind: 'email_otp',
          enrollment:
            fixture.pending.auth.kind === 'email_otp' ? fixture.pending.auth.enrollment : null,
        },
      }),
    ]);
    expect(publications).toMatchObject([
      {
        walletSessionPublication: {
          kind: 'issued',
          walletSession: fixture.firstResponse.registrationEstablishedSession.session.walletSession,
          operationCredential:
            fixture.firstResponse.registrationEstablishedSession.session.operationCredential,
        },
        registration: {
          initialAuthMethod: {
            kind: 'email_otp',
            registrationAuthorityId:
              fixture.pending.auth.kind === 'email_otp'
                ? fixture.pending.auth.registrationAuthorityId
                : null,
          },
          authenticators: [],
        },
      },
    ]);
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

    const results = await resumePendingNearRegistrations({
      relayerUrl: 'https://relayer.example.test',
      ports,
    });

    expect(results[0]).toMatchObject({ kind: 'published', sessionResult: 'already_committed' });
    expect(publications).toHaveLength(1);
    expect(publications[0]?.walletSessionPublication).toEqual({
      kind: 'credential_free_projection',
      walletSession: fixture.replayResponse.registrationEstablishedSession.session.walletSession,
    });
  });

  test('reports ECDSA pending rows as exact-method unlock continuations', async () => {
    const fixture = await buildPendingWalletRegistrationRecoveryFixture();
    const ecdsa = await buildEcdsaActivationPublicationFixture();
    const mixed = await buildMixedActivationPublicationFixture();
    let completeCalls = 0;
    let publicationCalls = 0;
    const ports: PendingRegistrationRecoveryPorts = {
      listPendingWalletRegistrationCommits: async () => [
        fixture.pending,
        ecdsa.input.pending,
        mixed.input.pending,
      ],
      completeWalletRegistrationNearProvisioning: async () => {
        completeCalls += 1;
        return { ok: false, code: 'temporary_failure', message: 'retry later' };
      },
      publishPendingWalletRegistrationCommit: async () => {
        publicationCalls += 1;
        return { signerActivations: [] };
      },
    };

    const results = await resumePendingNearRegistrations({
      relayerUrl: 'https://relayer.example.test',
      ports,
    });

    expect(completeCalls).toBe(1);
    expect(publicationCalls).toBe(0);
    expect(results).toHaveLength(3);
    expect(results[0]).toMatchObject({
      kind: 'failed',
      registrationCeremonyId: fixture.pending.registrationCeremonyId,
      error: { message: 'pending registration replay failed: temporary_failure' },
    });
    expect(results.slice(1)).toEqual([
      {
        kind: 'unlock_required',
        registrationCeremonyId: ecdsa.input.pending.registrationCeremonyId,
        walletId: ecdsa.input.pending.walletId,
        keyFamilies: ['ecdsa_secp256k1'],
        activationJournalId: ecdsa.input.pending.localMaterial.ecdsa.activationJournalId,
        activationRequestDigestB64u:
          ecdsa.input.pending.localMaterial.ecdsa.activationRequestDigestB64u,
        clientActivation: ecdsa.input.pending.localMaterial.ecdsa.clientActivation,
        walletAuthMethodId: ecdsa.input.pending.walletAuthMethodId,
        next: 'unlock_exact_method',
        reason: 'ecdsa_local_finalization',
      },
      {
        kind: 'unlock_required',
        registrationCeremonyId: mixed.input.pending.registrationCeremonyId,
        walletId: mixed.input.pending.walletId,
        keyFamilies: ['ed25519', 'ecdsa_secp256k1'],
        activationJournalId: mixed.input.pending.localMaterial.ecdsa.activationJournalId,
        activationRequestDigestB64u:
          mixed.input.pending.localMaterial.ecdsa.activationRequestDigestB64u,
        clientActivation: mixed.input.pending.localMaterial.ecdsa.clientActivation,
        walletAuthMethodId: mixed.input.pending.walletAuthMethodId,
        next: 'unlock_exact_method',
        reason: 'ecdsa_local_finalization',
      },
    ]);
  });

  test('replays ECDSA activation through unlock, continuity, and publication', async () => {
    const fixture = await buildPendingEcdsaRegistrationRecoveryFixture();
    const activationRequests: unknown[] = [];
    const unlockInputs: PendingEcdsaRegistrationUnlockInput[] = [];
    const finalizationInputs: unknown[] = [];
    const publicationInputs: PublishPendingWalletRegistrationCommitInputV1[] = [];
    let retainedPending: PendingEcdsaOnlyRegistrationCommit | null = fixture.pending;
    const signingSurface: PendingRegistrationRecoverySigningSurface = {
      finalizeWalletRegistrationEcdsaSessions: async (input) => {
        finalizationInputs.push(input);
        return await finalizeWalletRegistrationEcdsaSessions(input);
      },
      rejoinWalletCustodyEvmFamilyKeySet: async () => {
        throw new Error('ECDSA recovery test should use the injected unlock port');
      },
      getAuthenticationCredentialsSerialized: async () => {
        throw new Error('ECDSA recovery test should use the injected unlock port');
      },
      getSignerWorkerContext: () => {
        throw new Error('ECDSA recovery test should use the injected unlock port');
      },
    };
    const ports: PendingEcdsaRegistrationRecoveryPorts = {
      activateWalletRegistration: async (request) => {
        activationRequests.push(request);
        return fixture.response;
      },
      unlockPendingEcdsaRegistration: async (input) => {
        unlockInputs.push(input);
        return fixture.unlock;
      },
      publishPendingWalletRegistrationCommit: async (publication) => {
        publicationInputs.push(publication);
        retainedPending = null;
        return { signerActivations: [] };
      },
    };

    const result = await resumePendingEcdsaRegistration({
      relayerUrl: 'https://relayer.example.test',
      pending: fixture.pending,
      exactMethod: fixture.exactMethod,
      signingSurface,
      ports,
    });

    expect(result).toEqual({
      kind: 'published',
      registrationCeremonyId: fixture.pending.registrationCeremonyId,
      walletId: fixture.response.walletId,
      sessionResult: 'already_committed',
    });
    expect(activationRequests).toEqual([
      pendingEcdsaActivateRequest('https://relayer.example.test', fixture.pending),
    ]);
    expect(unlockInputs).toHaveLength(1);
    expect(unlockInputs[0]).toMatchObject({
      relayerUrl: 'https://relayer.example.test',
      pending: fixture.pending,
      response: fixture.response,
      walletKeys: fixture.response.ecdsa.walletKeys,
      exactMethod: fixture.exactMethod,
    });
    expect(finalizationInputs).toHaveLength(1);
    expect(finalizationInputs[0]).toMatchObject({
      walletId: String(fixture.pending.walletId),
      session: {
        chainTargets: [fixture.response.ecdsa.walletKeys[0]?.chainTarget],
        bootstrap: {
          applicationBindingDigestB64u:
            fixture.response.ecdsa.bootstrap.applicationBindingDigestB64u,
        },
        materialActivation: routerAbMpcMaterialActivationRefFromWire(
          fixture.response.ecdsa.activation.ecdsa_activation.material_activation,
        ),
        clientPublicFacts: {
          contextBinding32B64u: fixture.unlock.publicFacts.contextBinding32B64u,
          derivationClientSharePublicKey33B64u:
            fixture.unlock.publicFacts.derivationClientSharePublicKey33B64u,
          clientVerifyingShareB64u: fixture.unlock.publicFacts.clientVerifyingShare33B64u,
          relayerPublicKey33B64u: fixture.unlock.publicFacts.relayerPublicKey33B64u,
          groupPublicKey33B64u: fixture.unlock.publicFacts.groupPublicKey33B64u,
          ethereumAddress: fixture.unlock.publicFacts.ethereumAddress,
        },
        publicCapability: fixture.response.ecdsa.walletKeys[0]?.publicCapability,
      },
      walletKeys: fixture.response.ecdsa.walletKeys,
    });
    expect(publicationInputs).toHaveLength(1);
    expect(publicationInputs[0]).toMatchObject({
      pending: fixture.pending,
      request: {
        operation: 'registration_activate',
        registrationCeremonyId: fixture.pending.registrationCeremonyId,
        idempotencyKey: fixture.pending.idempotencyKey,
        walletId: fixture.pending.walletId,
        walletAuthMethodId: fixture.pending.walletAuthMethodId,
      },
      walletSessionPublication: {
        kind: 'issued',
        walletSession: fixture.unlock.session.session.wallet_session,
        operationCredential: fixture.unlock.session.session.operation_credential,
      },
      ecdsaContinuity: [expect.any(Object)],
    });
    expect(publicationInputs[0]?.walletSessionPublication).not.toEqual(
      fixture.response.registrationEstablishedSession.session,
    );
    expect(retainedPending).toBeNull();
  });

  test('passes an Email OTP exact method through the ECDSA unlock port', async () => {
    const fixture = await buildPendingEcdsaRegistrationRecoveryFixture({ authKind: 'email_otp' });
    let unlockInput: PendingEcdsaRegistrationUnlockInput | undefined;
    const ports: PendingEcdsaRegistrationRecoveryPorts = {
      activateWalletRegistration: async () => fixture.response,
      unlockPendingEcdsaRegistration: async (input) => {
        unlockInput = input;
        throw new Error('Email OTP unlock port reached');
      },
      publishPendingWalletRegistrationCommit: async () => {
        throw new Error('Email OTP dispatch test must stop at the unlock port');
      },
    };

    await expect(
      resumePendingEcdsaRegistration({
        relayerUrl: 'https://relayer.example.test',
        pending: fixture.pending,
        exactMethod: fixture.exactMethod,
        signingSurface: signingSurfaceForUnlockDispatch,
        ports,
      }),
    ).rejects.toThrow('Email OTP unlock port reached');
    expect(unlockInput).toMatchObject({
      pending: fixture.pending,
      response: fixture.response,
      exactMethod: fixture.exactMethod,
    });
    expect(unlockInput?.pending.auth.kind).toBe('email_otp');
  });

  test('recovers mixed registration through retained ECDSA publication and terminal Route 4', async () => {
    const fixture = await buildPendingMixedRegistrationRecoveryFixture();
    const events: string[] = [];
    const activationRequests: unknown[] = [];
    const nearRequests: unknown[] = [];
    const publications: PublishPendingWalletRegistrationCommitInputV1[] = [];
    const ports: PendingMixedRegistrationRecoveryPorts = {
      activateWalletRegistration: async (request) => {
        events.push('route_3');
        activationRequests.push(request);
        return fixture.activateResponse;
      },
      unlockPendingEcdsaRegistration: async () => {
        events.push('exact_unlock');
        return fixture.unlock;
      },
      completeWalletRegistrationNearProvisioning: async (request) => {
        events.push('route_4');
        nearRequests.push(request);
        return fixture.nearResponse;
      },
      publishPendingWalletRegistrationCommitAndRetain: async (publication) => {
        events.push(publications.length === 0 ? 'ecdsa_retain' : 'mixed_retain');
        publications.push(publication);
        return { signerActivations: [] };
      },
      deletePendingWalletRegistrationCommit: async () => {
        events.push('delete_pending');
      },
    };

    const result = await resumePendingMixedRegistration({
      relayerUrl: 'https://relayer.example.test',
      pending: fixture.pending,
      exactMethod: fixture.exactMethod,
      signingSurface: signingSurfaceForInjectedUnlock,
      ports,
    });

    expect(result).toMatchObject({
      kind: 'published',
      registrationCeremonyId: fixture.pending.registrationCeremonyId,
      walletId: fixture.pending.walletId,
    });
    expect(events).toEqual([
      'route_3',
      'exact_unlock',
      'ecdsa_retain',
      'route_4',
      'mixed_retain',
      'delete_pending',
    ]);
    expect(activationRequests).toEqual([
      pendingEcdsaActivateRequest('https://relayer.example.test', fixture.pending),
    ]);
    expect(nearRequests).toEqual([
      expect.objectContaining({
        registrationCeremonyId: fixture.pending.registrationCeremonyId,
        signedSetup: fixture.pending.signedSetup,
        idempotencyKey: await deriveNearProvisioningIdempotencyKey({
          registrationCeremonyId: fixture.pending.registrationCeremonyId,
          activationReference: fixture.pending.localMaterial.ed25519.activationReference,
        }),
        ed25519: {
          activationReference: fixture.pending.localMaterial.ed25519.activationReference,
        },
        walletCustodyCommit: fixture.pending.localMaterial.ed25519.custodyCommit,
      }),
    ]);
    expect(publications).toHaveLength(2);
    expect(publications[0]).toMatchObject({
      pending: fixture.pending,
      walletSessionPublication: {
        kind: 'issued',
        walletSession: fixture.unlock.session.session.wallet_session,
        operationCredential: fixture.unlock.session.session.operation_credential,
      },
      ecdsaContinuity: [expect.any(Object)],
    });
    expect(publications[1]).toMatchObject({
      pending: fixture.pending,
      walletSessionPublication: {
        kind: 'credential_free_projection',
        walletSession: fixture.nearResponse.ok
          ? fixture.nearResponse.registrationEstablishedSession.session.walletSession
          : null,
      },
      ecdsaContinuity: [],
    });
    expect(publications[1]?.registration.signerActivations).toEqual(
      expect.arrayContaining([expect.any(Object)]),
    );
    expect(publications[1]?.registration.keyMaterials).toEqual(
      expect.arrayContaining([expect.any(Object)]),
    );
  });

  test('retains mixed pending state when Route 4 fails after ECDSA publication', async () => {
    const fixture = await buildPendingMixedRegistrationRecoveryFixture();
    let retainedPublications = 0;
    let deleteCalls = 0;
    const ports: PendingMixedRegistrationRecoveryPorts = {
      activateWalletRegistration: async () => fixture.activateResponse,
      unlockPendingEcdsaRegistration: async () => fixture.unlock,
      completeWalletRegistrationNearProvisioning: async () => ({
        ok: false,
        code: 'temporary_failure',
        message: 'retry later',
      }),
      publishPendingWalletRegistrationCommitAndRetain: async () => {
        retainedPublications += 1;
        return { signerActivations: [] };
      },
      deletePendingWalletRegistrationCommit: async () => {
        deleteCalls += 1;
      },
    };

    await expect(
      resumePendingMixedRegistration({
        relayerUrl: 'https://relayer.example.test',
        pending: fixture.pending,
        exactMethod: fixture.exactMethod,
        signingSurface: signingSurfaceForInjectedUnlock,
        ports,
      }),
    ).rejects.toThrow('pending registration replay failed: temporary_failure');
    expect(retainedPublications).toBe(1);
    expect(deleteCalls).toBe(0);
  });
});
