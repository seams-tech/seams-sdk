import { expect, test } from '@playwright/test';
import {
  createCloudflareLinkedDeviceEd25519SourcePreservingRouterEndpointV1,
  createCloudflareOrdinaryInactiveSignerMaterialActivationEndpointV1,
  createCloudflareOrdinaryInactiveSignerMaterialReservationEndpointV1,
  createCloudflareOrdinaryInactiveSignerMaterialReservationServiceV1,
} from '../../packages/wallet-server/src/router/cloudflare/signingLanes/cloudflareOrdinaryInactiveSignerMaterialReservation';
import { parseOrdinaryEcdsaSignerMaterialWorkerReservationV1 } from '../../packages/wallet-server/src/core/signingMaterial/ordinaryInactiveSignerMaterialReservation';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  buildSourcePreservingEcdsaReservationRequestFixture,
  buildSourcePreservingEd25519ReservationRequestFixture,
} from './helpers/ordinarySourcePreservingReservation.fixtures';
import {
  buildOrdinaryEd25519ReservationPreparationFixture,
  buildOrdinaryMaterialActivationFixture,
} from './helpers/ordinarySignerMaterialReservation.fixtures';

type RecordedRequestV1 = {
  readonly url: string;
  readonly method: string;
  readonly auth: string | null;
  readonly body: unknown;
};

test('source-preserving reservation and activation endpoints emit exact worker wires', async () => {
  const calls: RecordedRequestV1[] = [];
  const ed25519 = buildSourcePreservingEd25519ReservationRequestFixture();
  const ecdsa = buildSourcePreservingEcdsaReservationRequestFixture();
  const responses: unknown[] = [
    { ok: true },
    {
      state: 'inactive',
      reservation_id: 'ecdsa-http-reservation',
      material_activation: routerAbMpcMaterialActivationRefToWire(
        ecdsa.preparation.sourceContribution.binding.target.activation,
      ),
      binding: ecdsa.preparation.sourceContribution.binding,
      source_derivation: {
        application_binding_digest_b64u:
          ecdsa.preparation.sourceDerivation.applicationBindingDigestB64u,
        client_share_retry_counter: ecdsa.preparation.sourceDerivation.clientShareRetryCounter,
      },
      target_relayer_public_key33_b64u:
        ecdsa.preparation.sourceContribution.binding.source.relayerPublicKey33B64u,
      threshold_public_key33_b64u: ecdsa.signer.thresholdPublicKey33B64u,
      threshold_ethereum_address20_b64u:
        ecdsa.preparation.sourceContribution.binding.source.thresholdEthereumAddress20B64u,
      encrypted_target_client_share:
        ecdsa.preparation.sourceContribution.encryptedTargetClientShare,
      encrypted_target_server_share: ecdsa.preparation.sourceContribution.encryptedDelta,
    },
    { ok: true },
  ];
  const responseFetch = createRecordingFetch(calls, responses);
  const responseReservationEndpoint =
    createCloudflareOrdinaryInactiveSignerMaterialReservationEndpointV1({
      fetch: responseFetch,
      internalServiceAuthSecret: 'internal-secret',
    });
  const responseActivationEndpoint =
    createCloudflareOrdinaryInactiveSignerMaterialActivationEndpointV1({
      fetch: responseFetch,
      internalServiceAuthSecret: 'internal-secret',
    });
  const reservationService = createCloudflareOrdinaryInactiveSignerMaterialReservationServiceV1({
    endpoint: responseReservationEndpoint,
  });

  const ed25519Reservation =
    await reservationService.reserveOrdinaryInactiveSignerMaterialV1(ed25519);
  await responseActivationEndpoint.activateInactiveEd25519SignerMaterialV1({
    sourceContribution: ed25519.preparation.sourceContribution,
    reservationId: 'ed25519-reservation',
  });
  const ecdsaReservation =
    await responseReservationEndpoint.reserveInactiveEcdsaSignerMaterialV1(ecdsa);
  const parsedEcdsaReservation = parseOrdinaryEcdsaSignerMaterialWorkerReservationV1(
    ecdsa,
    ecdsaReservation,
  );
  await responseActivationEndpoint.activateInactiveEcdsaSignerMaterialV1({
    preparation: ecdsa.preparation,
    reservationId: 'ecdsa-reservation',
  });

  expect(parsedEcdsaReservation.activationReceipt.normalSigning.scope).toEqual(
    expect.objectContaining({
      wallet_id: ecdsa.preparation.sourceDerivation.sourceNormalSigning.scope.wallet_id,
      ecdsa_threshold_key_id:
        ecdsa.preparation.sourceDerivation.sourceNormalSigning.scope.ecdsa_threshold_key_id,
      signing_root_id: ecdsa.preparation.sourceDerivation.sourceNormalSigning.scope.signing_root_id,
      signing_root_version:
        ecdsa.preparation.sourceDerivation.sourceNormalSigning.scope.signing_root_version,
      context: ecdsa.preparation.sourceDerivation.sourceNormalSigning.scope.context,
      activation_epoch:
        ecdsa.preparation.sourceDerivation.sourceNormalSigning.scope.activation_epoch,
    }),
  );
  expect(ed25519Reservation.serverMaterial.reservationId).toBe(
    ed25519.preparation.sourceContribution.reservationId,
  );
  expect(calls).toHaveLength(3);
  expect(calls.map((call) => call.url)).toEqual([
    'https://signing-worker.router-ab.internal/router-ab/signing-worker/ed25519-yao/activate-reservation',
    'https://signing-worker.router-ab.internal/router-ab/signing-worker/ecdsa-derivation/reserve-inactive-source-preserving',
    'https://signing-worker.router-ab.internal/router-ab/signing-worker/ecdsa-derivation/activate-reservation',
  ]);
  for (const call of calls) {
    expect(call.method).toBe('POST');
    expect(call.auth).toBe('internal-secret');
  }

  expect(calls[0]?.body).toEqual({
    binding: ed25519.preparation.sourceContribution.targetBinding,
    reservation_id: 'ed25519-reservation',
  });
  expect(calls[1]?.body).toEqual({
    source_derivation: {
      application_binding_digest_b64u:
        ecdsa.preparation.sourceDerivation.applicationBindingDigestB64u,
      client_share_retry_counter: ecdsa.preparation.sourceDerivation.clientShareRetryCounter,
    },
    source_contribution: ecdsa.preparation.sourceContribution,
  });
  expect(calls[2]?.body).toEqual({
    material_activation: routerAbMpcMaterialActivationRefToWire(
      ecdsa.preparation.sourceContribution.binding.target.activation,
    ),
    reservation_id: 'ecdsa-reservation',
  });
});

test('Ed25519 source-preserving execution uses the MPC Router service binding', async () => {
  const calls: RecordedRequestV1[] = [];
  const source = buildSourcePreservingEd25519ReservationRequestFixture('http-router-execute');
  const sourceContribution = source.preparation.sourceContribution;
  const targetPreparation = buildOrdinaryEd25519ReservationPreparationFixture(
    'http-router-execute-target',
    buildOrdinaryMaterialActivationFixture('http-router-execute-target'),
  );
  const rawReservation = {
    state: 'inactive',
    reservation_id: sourceContribution.reservationId,
    participant_ids: targetPreparation.participantIds,
    activation_receipt: sourceContribution.activationReceipt,
    deriver_a_client_package: sourceContribution.deriver_a_client_package,
    deriver_b_client_package: sourceContribution.deriver_b_client_package,
  };
  const responseFetch = createRecordingFetch(calls, [rawReservation]);
  const endpoint = createCloudflareLinkedDeviceEd25519SourcePreservingRouterEndpointV1({
    fetch: responseFetch,
    internalServiceAuthSecret: 'internal-secret',
  });

  const result = await endpoint.executeEd25519SourcePreservingV1({
    sourceBinding: sourceContribution.sourceBinding,
    targetRequest: targetPreparation.activationRequest,
    participantIds: targetPreparation.participantIds,
  });

  expect(result).toEqual(rawReservation);
  expect(calls).toHaveLength(1);
  expect(calls[0]?.url).toBe(
    'https://mpc-router.router-ab.internal/router-ab/router/ed25519-yao/execute-source-preserving',
  );
  expect(calls[0]?.auth).toBe('internal-secret');
  expect(calls[0]?.body).toEqual({
    source_binding: sourceContribution.sourceBinding,
    target: {
      operation: 'registration',
      binding: targetPreparation.activationRequest.binding,
      deriver_a_input: targetPreparation.activationRequest.deriver_a_input,
      deriver_b_input: targetPreparation.activationRequest.deriver_b_input,
    },
    participant_ids: targetPreparation.participantIds,
  });
});

function createRecordingFetch(
  calls: RecordedRequestV1[],
  responses: readonly unknown[] = [{ ok: true }],
): typeof fetch {
  let responseIndex = 0;
  return async (input, init) => {
    const request = new Request(input, init);
    calls.push({
      url: request.url,
      method: request.method,
      auth: request.headers.get('x-router-ab-internal-service-auth'),
      body: JSON.parse(await request.text()),
    });
    const responseBody = responses[responseIndex] ?? { ok: true };
    responseIndex += 1;
    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
}
